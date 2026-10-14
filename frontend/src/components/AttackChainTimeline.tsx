import type { AttackStep, IncidentAssessment } from "../api/types";
import { pct, sci, when } from "../lib/format";
import { Chip, TacticId, TechniqueId } from "./ui";

function ObservedNode({ step, index, detected }: { step: AttackStep; index: number; detected: boolean }) {
  return (
    <li className="timeline__node timeline__node--observed" data-testid="step-observed">
      <div className="timeline__marker" aria-hidden="true" />
      <div className="timeline__content">
        <div className="timeline__head">
          <Chip tone="observed">OBSERVED #{index + 1}</Chip>
          <TechniqueId id={step.technique_id} />
          <TacticId id={step.tactic_id} />
          <span className="timeline__time">{when(step.timestamp)}</span>
        </div>
        <dl className="step-facts">
          <div>
            <dt>Evidence confidence</dt>
            <dd className="num">{pct(step.confidence)}</dd>
          </div>
          <div>
            <dt>Event</dt>
            <dd>
              <code>{step.event_id ?? "n/a"}</code>
              {detected ? null : <span className="muted"> (no detector evidence)</span>}
            </dd>
          </div>
          <div>
            <dt>Evidence source</dt>
            <dd>
              <code className="wrap-anywhere">{step.source}</code>
            </dd>
          </div>
        </dl>
        {step.evidence && step.evidence.length > 0 ? (
          <ul className="evidence-list">
            {step.evidence.map((e) => (
              <li key={e}>{e}</li>
            ))}
          </ul>
        ) : null}
        {step.alternative_candidates && step.alternative_candidates.length > 0 ? (
          <p className="muted small mt-3">
            Alternative candidates:{" "}
            {step.alternative_candidates.map((c) => `${c.technique_id} (${pct(c.confidence, 0)})`).join(", ")}
          </p>
        ) : null}
      </div>
    </li>
  );
}

function PredictedNode({
  techniqueId,
  position,
  nextStepProbability,
}: {
  techniqueId: string;
  position: number;
  nextStepProbability: number | null;
}) {
  return (
    <li className="timeline__node timeline__node--predicted" data-testid="step-predicted">
      <div className="timeline__marker" aria-hidden="true" />
      <div className="timeline__content">
        <div className="timeline__head">
          <Chip tone="predicted">PREDICTED +{position}</Chip>
          <TechniqueId id={techniqueId} />
          <span className="muted small">tactic not returned for predictions</span>
        </div>
        <p className="timeline__forecast">
          Not observed, not confirmed — a model forecast.
          {nextStepProbability === null ? null : (
            <>
              {" "}
              Next-step probability: <strong className="num">{pct(nextStepProbability)}</strong>
            </>
          )}
        </p>
      </div>
    </li>
  );
}

/** Observed steps (solid) followed by the top beam-search continuation (dashed, PREDICTED). */
export function AttackChainTimeline({ incident }: { incident: IncidentAssessment }) {
  const steps = incident.chain.chain.steps;
  const detectedEvents = new Set((incident.chain.detections ?? []).map((d) => d.event_id));
  const result = incident.prediction.result;
  const topPath = result.paths?.[0];
  const firstProbability = new Map((result.next_step ?? []).map((n) => [n.technique_id, n.probability]));
  return (
    <div className="timeline" data-testid="attack-chain">
      <p className="legend">
        <Chip tone="observed">OBSERVED</Chip> evidence-backed steps in arrival order
        <span aria-hidden="true">·</span>
        <Chip tone="predicted">PREDICTED</Chip> model forecast, not an attack that happened. Technique names are not
        returned by the API; IDs link to the public ATT&amp;CK pages.
      </p>
      <ol className="timeline__list">
        {steps.map((step, i) => (
          <ObservedNode
            key={`${step.event_id ?? "doc"}-${String(i)}`}
            step={step}
            index={i}
            detected={step.event_id ? detectedEvents.has(step.event_id) : false}
          />
        ))}
        {topPath
          ? topPath.technique_ids.map((t, i) => (
              <PredictedNode
                key={`pred-${String(i)}-${t}`}
                techniqueId={t}
                position={i + 1}
                nextStepProbability={i === 0 ? (firstProbability.get(t) ?? null) : null}
              />
            ))
          : null}
      </ol>
      {topPath ? (
        <p className="path-score" data-testid="path-score">
          Predicted continuation = top beam path (model {result.model_id}). PATH SCORE{" "}
          <span className="num">{sci(topPath.probability)}</span> (joint model probability of this exact path; not
          calibrated; not a probability of attack).
        </p>
      ) : (
        <p className="path-score">No predicted path returned.</p>
      )}
    </div>
  );
}
