"""Prediction service for incident chains (Milestone 7). Reuses Milestone 3/4 models; no training.

Context = the chain's OBSERVED technique IDs in order; IDs that are not active vocabulary
techniques become ``<UNK>`` (allowed in history, never a prediction target). Documented and
predicted steps are never part of the context.

Outputs:
- NEXT-STEP PROBABILITY: P(next | history) from each model (top-k), primary model = HYBRID.
- PATH SCORE: beam search over the primary model; each path's joint probability. Summed
  path scores are a LOWER BOUND on reaching a tactic and are not calibrated (Milestone 4).

``from_artifacts`` loads the stored artifacts: B1 and M1 (Milestone 3, fitted on all
groups) and one Milestone 4 LSTM fold checkpoint with that fold's own inner-validation
fusion alpha. That composed configuration is a deployment choice; it was not separately
evaluated (generalisation estimates are the Milestone 3/4 nested LOGO results).
"""

from __future__ import annotations

import json
import math
from collections.abc import Mapping, Sequence
from datetime import datetime
from pathlib import Path

from pydantic import Field

from hqc.attack_chain.catalog import TechniqueCatalog, vocabulary_token
from hqc.common.schemas.base import HQCModel, utc_now
from hqc.common.schemas.intelligence import IncidentChain, NextTechniquePrediction
from hqc.common.schemas.prediction import (
    NextTechniqueProbability,
    PredictedPath,
    PredictionResult,
)
from hqc.prediction.base import NextTechniqueModel, OutputSpace, check_distribution
from hqc.prediction.beam_search import beam_search
from hqc.prediction.fusion import HybridModel
from hqc.prediction.lstm import LSTMPredictor, load_checkpoint
from hqc.prediction.markov import MarkovModelArtifact
from hqc.prediction.vocabulary import TechniqueVocabulary


class PredictionConfig(HQCModel):
    markov_run_id: str
    baseline_model: str = "B1"
    markov_model: str = "M1"
    lstm_run_id: str
    lstm_fold: str = "fold-00"
    primary_model: str = "HYBRID"
    top_k: int = Field(default=5, ge=1)
    beam_width: int = Field(default=10, ge=1)
    horizon: int = Field(default=3, ge=1)


class PredictionService:
    def __init__(
        self,
        models: Mapping[str, NextTechniqueModel],
        primary: str,
        vocabulary: TechniqueVocabulary,
        model_versions: Mapping[str, str],
        top_k: int = 5,
        beam_width: int = 10,
        horizon: int = 3,
    ) -> None:
        if primary not in models:
            raise ValueError(f"Primary model {primary!r} is not among {sorted(models)}")
        spaces = {m.space.tokens for m in models.values()}
        if len(spaces) != 1:
            raise ValueError("All models must share one output space")
        if models[primary].space.vocabulary_version != vocabulary.vocabulary_version:
            raise ValueError("Models and vocabulary versions differ")
        self.models = dict(models)
        self.primary = primary
        self.vocabulary = vocabulary
        self.model_versions = dict(model_versions)
        self.top_k = top_k
        self.beam_width = beam_width
        self.horizon = horizon

    @property
    def space(self) -> OutputSpace:
        return self.models[self.primary].space

    def context(self, incident: IncidentChain) -> list[str]:
        return [vocabulary_token(t, self.vocabulary) for t in incident.observed_technique_ids]

    def _top_k(self, distribution: Sequence[float]) -> list[tuple[str, float]]:
        check_distribution(distribution, self.space)
        order = sorted(range(len(distribution)), key=lambda i: (-distribution[i], i))
        return [(self.space.tokens[i], float(distribution[i])) for i in order[: self.top_k]]

    def predict(
        self, incident: IncidentChain, as_of: datetime | None = None
    ) -> NextTechniquePrediction:
        context = self.context(incident)
        per_model = {name: self._top_k(m.distribution(context)) for name, m in self.models.items()}
        paths = beam_search(self.models[self.primary], context, self.horizon, self.beam_width)
        result = PredictionResult(
            prediction_id=f"pred-{incident.chain_id}",
            chain_id=incident.chain_id,
            observed_prefix=incident.observed_technique_ids,
            next_step=[
                NextTechniqueProbability(technique_id=t, probability=p)
                for t, p in per_model[self.primary]
            ],
            paths=[
                PredictedPath(
                    technique_ids=list(p.technique_ids),
                    probability=p.probability,
                    cumulative_log_score=min(0.0, p.log_probability),
                    length=p.length,
                )
                for p in paths
            ],
            horizon=self.horizon,
            model_id=self.primary,
            vocabulary_version=self.vocabulary.vocabulary_version,
            attack_version=self.vocabulary.attack_version,
            created_at=as_of or utc_now(),
        )
        return NextTechniquePrediction(
            chain_id=incident.chain_id,
            result=result,
            context_tokens=context,
            model_versions=self.model_versions,
            beam_width=self.beam_width,
            per_model_top_k=per_model,
        )

    def tactic_probability(
        self, incident: IncidentChain, tactic_ids: Sequence[str], catalog: TechniqueCatalog
    ) -> float:
        """Primary-model P(next technique has one of ``tactic_ids``) over the FULL distribution."""
        wanted = set(tactic_ids)
        distribution = self.models[self.primary].distribution(self.context(incident))
        total = math.fsum(
            p
            for token, p in zip(self.space.tokens, distribution, strict=True)
            if wanted & {t.tactic_id for t in catalog.tactics(token)}
        )
        return min(1.0, max(0.0, total))

    # --- stored artifacts ------------------------------------------------------------------

    @classmethod
    def from_artifacts(
        cls,
        config: PredictionConfig,
        vocabulary: TechniqueVocabulary,
        models_dir: Path,
        reports_dir: Path,
    ) -> PredictionService:
        space = OutputSpace(vocabulary)
        markov_dir = models_dir / "generated" / "attack_prediction" / config.markov_run_id
        b1_artifact = MarkovModelArtifact.load(markov_dir / f"{config.baseline_model}.json")
        m_artifact = MarkovModelArtifact.load(markov_dir / f"{config.markov_model}.json")
        b1, markov = b1_artifact.to_model(space), m_artifact.to_model(space)

        metrics = json.loads(
            (reports_dir / "runs" / config.lstm_run_id / "metrics.json").read_text()
        )
        fold = next(f for f in metrics["folds"] if f["fold_id"] == config.lstm_fold)
        if fold["final_markov"] != config.markov_model:
            raise ValueError(
                f"{config.lstm_fold} fused {fold['final_markov']}, not {config.markov_model}"
            )
        alpha = float(fold["selected_alpha"])
        ckpt = (
            models_dir
            / "generated"
            / "attack_prediction"
            / config.lstm_run_id
            / "lstm"
            / config.lstm_fold
        )
        network, meta = load_checkpoint(ckpt, vocabulary, space)
        lstm = LSTMPredictor(network, meta.hyperparameters, vocabulary, space)
        hybrid = HybridModel(
            markov, lstm, alpha, context_window=meta.hyperparameters.context_length
        )
        versions = {
            config.baseline_model: f"{config.markov_run_id}/{config.baseline_model}.json "
            f"(trained {b1_artifact.metadata.trained_at.isoformat()})",
            config.markov_model: f"{config.markov_run_id}/{config.markov_model}.json "
            f"(trained {m_artifact.metadata.trained_at.isoformat()})",
            "LSTM": f"{config.lstm_run_id}/lstm/{config.lstm_fold} (held-out group "
            f"{meta.test_group!r}; trained {meta.trained_at.isoformat()})",
            "HYBRID": f"alpha={alpha} x LSTM + (1-alpha) x {config.markov_model} "
            f"(alpha = {config.lstm_fold} inner-validation choice)",
            "vocabulary": vocabulary.vocabulary_version,
        }
        models: dict[str, NextTechniqueModel] = {
            config.baseline_model: b1,
            config.markov_model: markov,
            "LSTM": lstm,
            "HYBRID": hybrid,
        }
        return cls(
            models,
            config.primary_model,
            vocabulary,
            versions,
            top_k=config.top_k,
            beam_width=config.beam_width,
            horizon=config.horizon,
        )
