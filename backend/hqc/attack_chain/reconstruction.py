"""Deterministic correlation and order-preserving attack-chain reconstruction.

Observations are processed in ARRIVAL ORDER and are never sorted. An observation joins an
open chain only through a documented rule (``CorrelationPolicy.version``), checked in order:

1. ``incident_id``     equal explicit incident IDs (decisive: different IDs never join);
2. ``session_id``      equal explicit session IDs;
3. ``shared_resource`` a host / entity / target host in common with the chain;
4. ``shared_account``  a user account in common with the chain.

and only if the chain's last observation is at most ``window_minutes`` earlier. IP addresses
are recorded as context but never correlate on their own (NAT and shared addresses).

- No matching chain: a new chain (``STANDALONE`` if nothing ever joins it).
- Several matching chains: a new chain marked ``AMBIGUOUS``; chains are never merged and an
  event is never forced into one.
- A matching chain whose last timestamp is LATER than the observation: ``ChainOrderError``
  (the Milestone 1 ``AttackChain`` contract rejects non-chronological chains; nothing is
  re-sorted to make a chain valid).
- Observations without technique evidence produce no step (nothing is fabricated); they are
  reported as unmapped.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from pydantic import Field

from hqc.attack_chain.catalog import TechniqueCatalog
from hqc.attack_chain.evidence import check_evidence
from hqc.common.schemas.attack import AttackChain, AttackStep, TechniqueCandidate
from hqc.common.schemas.base import DataOrigin, HQCModel, StepProvenance, utc_now
from hqc.common.schemas.intelligence import (
    CorrelationDecision,
    CorrelationStatus,
    EvidenceSource,
    IncidentChain,
    Observation,
    TechniqueEvidence,
)

CORRELATION_POLICY_VERSION = "correlation-v1"
SOURCE_PRECEDENCE = (
    EvidenceSource.EXPLICIT_RULE,
    EvidenceSource.SYNTHETIC_SCENARIO,
    EvidenceSource.CLASSICAL_DETECTOR,
    EvidenceSource.QUANTUM_SECOND_OPINION,
    EvidenceSource.ATTACK_FLOW,
)


class ChainOrderError(ValueError):
    """An observation is older than the chain it correlates with (no re-sorting is done)."""


class CorrelationPolicy(HQCModel):
    version: str = CORRELATION_POLICY_VERSION
    window_minutes: float = Field(default=120.0, gt=0.0)
    use_accounts: bool = True


@dataclass(frozen=True)
class ObservationKeys:
    incident_id: str | None
    session_id: str | None
    resources: frozenset[str]
    accounts: frozenset[str]
    addresses: frozenset[str]


def observation_keys(obs: Observation) -> ObservationKeys:
    event = obs.event
    resources = {event.entity_id}
    for name in ("host", "target_host"):
        value = getattr(event, name, None)
        if value:
            resources.add(str(value))
    user = getattr(event, "user", None)
    accounts = {str(user)} if user else set()
    addresses = {
        str(v) for name in ("src_ip", "dst_ip") if (v := getattr(event, name, None)) is not None
    }
    return ObservationKeys(
        obs.hints.incident_id,
        obs.hints.session_id,
        frozenset(resources),
        frozenset(accounts),
        frozenset(addresses),
    )


@dataclass
class _OpenChain:
    chain_id: str
    observations: list[Observation] = field(default_factory=list)
    decisions: list[CorrelationDecision] = field(default_factory=list)
    incident_ids: set[str] = field(default_factory=set)
    session_ids: set[str] = field(default_factory=set)
    resources: set[str] = field(default_factory=set)
    accounts: set[str] = field(default_factory=set)
    ambiguous: bool = False

    @property
    def last_time(self) -> datetime:
        return self.observations[-1].event.timestamp

    def add(self, obs: Observation, keys: ObservationKeys, decision: CorrelationDecision) -> None:
        self.observations.append(obs)
        self.decisions.append(decision)
        if keys.incident_id:
            self.incident_ids.add(keys.incident_id)
        if keys.session_id:
            self.session_ids.add(keys.session_id)
        self.resources |= keys.resources
        self.accounts |= keys.accounts


def _match(
    chain: _OpenChain, keys: ObservationKeys, policy: CorrelationPolicy
) -> tuple[str, list[str]] | None:
    if keys.incident_id and chain.incident_ids:
        if keys.incident_id in chain.incident_ids:
            return "incident_id", [keys.incident_id]
        return None  # explicit, different incidents never join
    if keys.session_id and keys.session_id in chain.session_ids:
        return "session_id", [keys.session_id]
    shared = sorted(keys.resources & chain.resources)
    if shared:
        return "shared_resource", shared
    if policy.use_accounts:
        accounts = sorted(keys.accounts & chain.accounts)
        if accounts:
            return "shared_account", accounts
    return None


class ChainReconstruction(HQCModel):
    chains: list[IncidentChain]
    unmapped_event_ids: list[str] = Field(
        default_factory=list, description="Observed events with no technique evidence (no step)."
    )
    correlation_policy: CorrelationPolicy


class AttackChainService:
    """Evidence -> correlated, order-preserving incident chains (no HTTP; M8 wraps it)."""

    def __init__(self, catalog: TechniqueCatalog, policy: CorrelationPolicy | None = None) -> None:
        self.catalog = catalog
        self.policy = policy or CorrelationPolicy()

    def reconstruct(
        self, observations: Sequence[Observation], as_of: datetime | None = None
    ) -> ChainReconstruction:
        window = timedelta(minutes=self.policy.window_minutes)
        chains: list[_OpenChain] = []
        unmapped: list[str] = []
        for obs in observations:  # arrival order; never sorted
            for ev in obs.techniques:
                check_evidence(ev, self.catalog)
            if not obs.techniques:
                unmapped.append(obs.event.event_id)
                continue
            keys = observation_keys(obs)
            matches: list[tuple[_OpenChain, str, list[str]]] = []
            for chain in chains:
                hit = _match(chain, keys, self.policy)
                if hit is None:
                    continue
                if obs.event.timestamp < chain.last_time:
                    raise ChainOrderError(
                        f"Event {obs.event.event_id} ({obs.event.timestamp.isoformat()}) is older "
                        f"than chain {chain.chain_id} ({chain.last_time.isoformat()}); "
                        "observations are not re-sorted"
                    )
                if obs.event.timestamp - chain.last_time <= window:
                    matches.append((chain, *hit))
            eid = obs.event.event_id
            if len(matches) == 1:
                chain, rule, matched = matches[0]
                chain.add(
                    obs,
                    keys,
                    CorrelationDecision(
                        event_id=eid, chain_id=chain.chain_id, rule=rule, matched_keys=matched
                    ),
                )
                continue
            new = _OpenChain(chain_id=f"chain-{eid}", ambiguous=len(matches) > 1)
            rule = "ambiguous" if new.ambiguous else "new_chain"
            matched = sorted(c.chain_id for c, _, _ in matches)
            new.add(
                obs,
                keys,
                CorrelationDecision(
                    event_id=eid, chain_id=new.chain_id, rule=rule, matched_keys=matched
                ),
            )
            chains.append(new)
        created = as_of or utc_now()
        return ChainReconstruction(
            chains=[self._build(c, created) for c in chains],
            unmapped_event_ids=unmapped,
            correlation_policy=self.policy,
        )

    # --- building ---------------------------------------------------------------------

    def _primary(self, evidence: Sequence[TechniqueEvidence]) -> TechniqueEvidence:
        def key(ev: TechniqueEvidence) -> tuple[float, int, str]:
            return (-ev.confidence, SOURCE_PRECEDENCE.index(ev.source), ev.technique_id)

        return sorted(evidence, key=key)[0]

    def _step(self, obs: Observation) -> AttackStep:
        primary = self._primary(obs.techniques)
        tactic = primary.tactic_id
        if tactic is None:
            tactics = self.catalog.tactics(primary.technique_id)
            tactic = tactics[0].tactic_id if len(tactics) == 1 else None
        alternatives = [
            TechniqueCandidate(
                technique_id=ev.technique_id,
                confidence=ev.confidence,
                evidence=list(ev.evidence),
                mapping_source=f"{ev.source.value}:{ev.reference}",
            )
            for ev in obs.techniques
            if ev is not primary
        ]
        return AttackStep(
            technique_id=primary.technique_id,
            tactic_id=tactic,
            timestamp=obs.event.timestamp,
            event_id=obs.event.event_id,
            confidence=primary.confidence,
            source=f"{primary.source.value}:{primary.reference}",
            provenance=StepProvenance.OBSERVED,
            alternative_candidates=alternatives,
            evidence=list(primary.evidence),
        )

    def _build(self, chain: _OpenChain, created: datetime) -> IncidentChain:
        steps = [self._step(o) for o in chain.observations]
        synthetic = any(o.event.data_origin is DataOrigin.SYNTHETIC for o in chain.observations)
        origin = DataOrigin.SYNTHETIC if synthetic else DataOrigin.REAL
        if chain.ambiguous:
            status = CorrelationStatus.AMBIGUOUS
        elif len(chain.observations) == 1:
            status = CorrelationStatus.STANDALONE
        else:
            status = CorrelationStatus.CORRELATED
        return IncidentChain(
            chain_id=chain.chain_id,
            status=status,
            chain=AttackChain(
                chain_id=chain.chain_id,
                entity_ids=sorted({o.event.entity_id for o in chain.observations}),
                steps=steps,
                data_origin=origin,
                attack_version=self.catalog.attack_version,
                created_at=created,
            ),
            decisions=chain.decisions,
            resources=sorted(chain.resources),
            detections=[o.detection for o in chain.observations if o.detection is not None],
            out_of_vocabulary_technique_ids=[
                s.technique_id for s in steps if not self.catalog.is_active(s.technique_id)
            ],
            data_origin=origin,
        )

    def attach_documented(
        self, incident: IncidentChain, documented: Sequence[TechniqueEvidence]
    ) -> IncidentChain:
        """Add DOCUMENTED reference steps (Attack Flow); they never become observed steps."""
        steps = list(incident.documented_steps)
        for ev in documented:
            if ev.source is not EvidenceSource.ATTACK_FLOW:
                raise ValueError("Only ATTACK_FLOW evidence can be attached as documented steps")
            check_evidence(ev, self.catalog)
            steps.append(
                AttackStep(
                    technique_id=ev.technique_id,
                    tactic_id=ev.tactic_id,
                    confidence=ev.confidence,
                    source=f"{ev.source.value}:{ev.reference}",
                    provenance=StepProvenance.DOCUMENTED,
                    evidence=list(ev.evidence),
                )
            )
        return incident.model_copy(update={"documented_steps": steps})
