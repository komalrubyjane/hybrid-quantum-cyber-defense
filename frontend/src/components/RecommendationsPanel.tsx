import type { DecisionRecord, RecommendationView } from "../api/types";
import { ACTION_LABELS, num, pct, when } from "../lib/format";
import { DecisionControls } from "./DecisionControls";
import { Chip, Empty, IdList, MitigationId, Panel, RecommendationOnlyNotice, RiskBadge, TechniqueId } from "./ui";

function decisionTone(decision: string): string {
  if (decision === "APPROVED") return "accent";
  if (decision === "REJECTED") return "danger";
  return "neutral";
}

function DecisionHistory({ decisions }: { decisions: DecisionRecord[] }) {
  if (decisions.length === 0) return <p className="muted small">No analyst decision recorded.</p>;
  return (
    <ol className="decision-history" data-testid="decision-history">
      {decisions.map((d) => (
        <li key={d.decision_id}>
          <Chip tone={decisionTone(d.decision)}>{d.decision}</Chip>
          <span className="muted">
            by {d.analyst} · {when(d.recorded_at)}
          </span>
          <code>executed: {String(d.executed)}</code>
          {d.note ? <span className="muted">— {d.note}</span> : null}
        </li>
      ))}
    </ol>
  );
}

function RecommendationCard({
  assessmentId,
  view,
  onRecorded,
}: {
  assessmentId: string;
  view: RecommendationView;
  onRecorded: (record: DecisionRecord) => void;
}) {
  const rec = view.recommendation;
  const techniques = rec.addresses_technique_ids ?? [];
  const mitigations = rec.attack_mitigation_ids ?? [];
  return (
    <article className={`rec rec--${rec.disruption.toLowerCase()}`} data-testid="recommendation">
      <header className="rec__header">
        <div className="rec__chips">
          <Chip tone="proposal">PROPOSAL · {rec.status}</Chip>
          <Chip tone="approval">Human approval required: {String(rec.requires_human_approval)}</Chip>
          <Chip tone="neutral">executed: {String(view.executed)}</Chip>
        </div>
        <h3 className="rec__action">{ACTION_LABELS[rec.action]}</h3>
        <p className="small muted">
          <code>{rec.action}</code> · target <code>{rec.target}</code>
        </p>
      </header>
      <p className="rec__reason">{rec.reason}</p>
      <dl className="rec__facts">
        <div>
          <dt>Priority (urgency)</dt>
          <dd>{num(rec.priority, 1)}</dd>
        </div>
        <div>
          <dt>Confidence</dt>
          <dd>{pct(rec.confidence)}</dd>
        </div>
        <div>
          <dt>Disruption</dt>
          <dd>{rec.disruption}</dd>
        </div>
        <div>
          <dt>Reversible</dt>
          <dd>{rec.reversible ? "yes" : "no"}</dd>
        </div>
        <div>
          <dt>Risk</dt>
          <dd>
            <RiskBadge level={rec.risk_level} score={rec.risk_score} />
          </dd>
        </div>
        <div>
          <dt>Latest decision</dt>
          <dd>{view.latest_decision ?? "none"}</dd>
        </div>
      </dl>
      {techniques.length > 0 || mitigations.length > 0 ? (
        <details>
          <summary>
            ATT&amp;CK context · {techniques.length} technique(s), {mitigations.length} mitigation(s)
          </summary>
          <div className="details__body">
            {techniques.length > 0 ? (
              <div className="row row--top">
                <span className="muted">Addresses:</span>
                <IdList>
                  {techniques.map((t) => (
                    <TechniqueId key={t} id={t} />
                  ))}
                </IdList>
              </div>
            ) : null}
            {mitigations.length > 0 ? (
              <div className="row row--top">
                <span className="muted">ATT&amp;CK mitigations:</span>
                <IdList>
                  {mitigations.map((m) => (
                    <MitigationId key={m} id={m} />
                  ))}
                </IdList>
              </div>
            ) : null}
          </div>
        </details>
      ) : null}
      <details>
        <summary>Supporting evidence ({rec.triggering_evidence.length})</summary>
        <div className="details__body">
          <ul>
            {rec.triggering_evidence.map((e, i) => (
              <li key={`${e.kind}-${e.ref_id}-${String(i)}`}>
                <code>{e.kind}</code> <code>{e.ref_id}</code> — {e.description}
              </li>
            ))}
          </ul>
        </div>
      </details>
      <div>
        <p className="eyebrow">Decision history</p>
        <div className="mt-3">
          <DecisionHistory decisions={view.decisions} />
        </div>
      </div>
      <DecisionControls assessmentId={assessmentId} view={view} onRecorded={onRecorded} />
      <p className="rec__footer">Recommendation only — no action has been executed.</p>
    </article>
  );
}

export function RecommendationsPanel({
  assessmentId,
  views,
  onRecorded,
}: {
  assessmentId: string;
  views: RecommendationView[];
  onRecorded: (record: DecisionRecord) => void;
}) {
  return (
    <Panel
      title="Adaptive defense recommendations"
      subtitle="Proposals for a human analyst. Approval records a decision; it does not execute anything."
      testId="recommendations-panel"
    >
      <RecommendationOnlyNotice />
      {views.length === 0 ? (
        <Empty>No recommendations for this incident.</Empty>
      ) : (
        <div className="grid grid--recs mt-3">
          {views.map((v) => (
            <RecommendationCard key={v.recommendation.recommendation_id} assessmentId={assessmentId} view={v} onRecorded={onRecorded} />
          ))}
        </div>
      )}
    </Panel>
  );
}
