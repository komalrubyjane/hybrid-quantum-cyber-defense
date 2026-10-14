import { useState } from "react";
import { Link, useParams } from "react-router";

import { useApi } from "../api/useApi";
import type { AssessmentRecord, IncidentAssessment, RecommendationView } from "../api/types";
import { AttackChainTimeline } from "../components/AttackChainTimeline";
import { PredictionPanel } from "../components/PredictionPanel";
import { QuantumPanel } from "../components/QuantumPanel";
import { RecommendationsPanel } from "../components/RecommendationsPanel";
import { RiskPanel } from "../components/RiskPanel";
import {
  Chip,
  ErrorView,
  Loading,
  OriginChip,
  PageHero,
  Panel,
  RecommendationOnlyNotice,
  RiskBadge,
} from "../components/ui";
import { useAsync } from "../hooks/useAsync";
import { when } from "../lib/format";

/** Correlation rules in the order returned, with repeats collapsed to a count (display only). */
function ruleSummary(rules: string[]): string {
  const counts = new Map<string, number>();
  for (const r of rules) counts.set(r, (counts.get(r) ?? 0) + 1);
  return [...counts.entries()].map(([r, n]) => (n > 1 ? `${r} ×${String(n)}` : r)).join(", ");
}

function anchorFor(chainId: string): string {
  return `incident-${chainId.replace(/[^A-Za-z0-9_-]/g, "-")}`;
}

function IncidentSection({
  assessmentId,
  incident,
  views,
  onRecorded,
}: {
  assessmentId: string;
  incident: IncidentAssessment;
  views: RecommendationView[];
  onRecorded: () => void;
}) {
  const chain = incident.chain;
  const mine = views.filter((v) => v.recommendation.chain_id === chain.chain_id);
  const outOfVocabulary = chain.out_of_vocabulary_technique_ids ?? [];
  return (
    <section className="incident" data-testid="incident" id={anchorFor(chain.chain_id)} aria-labelledby={`${anchorFor(chain.chain_id)}-title`}>
      <header className="incident__header">
        <div>
          <p className="eyebrow">Incident</p>
          <h2 className="incident__title mt-3" id={`${anchorFor(chain.chain_id)}-title`}>
            <code>{chain.chain_id}</code>
          </h2>
        </div>
        <div className="incident__chips">
          <Chip tone="neutral">{chain.status}</Chip>
          <OriginChip origin={chain.data_origin} />
          <RiskBadge level={incident.risk.level} score={incident.risk.score} />
          {incident.risk.evidence_status === "NEEDS ADDITIONAL EVIDENCE" ? (
            <Chip tone="warn">NEEDS ADDITIONAL EVIDENCE</Chip>
          ) : null}
        </div>
      </header>
      <p className="incident__meta">
        Resources: {(chain.resources ?? []).join(", ") || "n/a"} · correlation rules:{" "}
        {ruleSummary(chain.decisions.map((d) => d.rule))}
        {outOfVocabulary.length > 0
          ? ` · not active in ATT&CK (<UNK> for prediction): ${outOfVocabulary.join(", ")}`
          : ""}
      </p>
      <div className="grid grid--split">
        <Panel
          title="Attack chain: observed → predicted"
          subtitle="Solid steps were observed with evidence. Dashed steps are forecasts that have not happened."
          testId="chain-panel"
        >
          <AttackChainTimeline incident={incident} />
        </Panel>
        <div className="sticky">
          <RiskPanel risk={incident.risk} />
        </div>
      </div>
      <PredictionPanel incident={incident} />
      <QuantumPanel detections={chain.detections ?? []} />
      <RecommendationsPanel assessmentId={assessmentId} views={mine} onRecorded={onRecorded} />
    </section>
  );
}

function Detail({ record, initialViews }: { record: AssessmentRecord; initialViews: RecommendationView[] }) {
  const api = useApi();
  const out = record.output;
  const [views, setViews] = useState(initialViews);
  const [refreshError, setRefreshError] = useState(false);
  // After a decision is recorded, re-read the decision history from the API (no local edits).
  const refreshViews = () => {
    api.recommendations(record.assessment_id).then(
      (v) => {
        setViews(v);
        setRefreshError(false);
      },
      () => {
        setRefreshError(true);
      },
    );
  };
  return (
    <>
      <Panel title="Assessment summary" testId="assessment-header">
        <p className="small muted">
          Assessment <code>{record.assessment_id}</code>
        </p>
        <dl className="facts mt-3">
          <div>
            <dt>Created</dt>
            <dd className="num">{when(record.created_at)}</dd>
          </div>
          <div>
            <dt>Evidence as of</dt>
            <dd className="num">{when(out.as_of)}</dd>
          </div>
          <div>
            <dt>Data origin</dt>
            <dd>
              <OriginChip origin={record.data_origin} />
            </dd>
          </div>
          <div>
            <dt>Incidents</dt>
            <dd>{out.incidents.length}</dd>
          </div>
          <div>
            <dt>Events without technique evidence</dt>
            <dd>{out.unmapped_event_ids.join(", ") || "none"}</dd>
          </div>
          <div>
            <dt>Policies</dt>
            <dd className="small">
              {Object.entries(out.policy_versions)
                .map(([k, v]) => `${k}: ${v}`)
                .join(" · ")}
            </dd>
          </div>
        </dl>
        {record.notice ? <p className="small muted mt-3">{record.notice}</p> : null}
        <div className="mt-3">
          <RecommendationOnlyNotice />
        </div>
        {refreshError ? (
          <p role="alert" className="small decision__error mt-3">
            Could not refresh the decision history.
          </p>
        ) : null}
      </Panel>
      {out.incidents.length > 1 ? (
        <nav aria-label="Incidents in this assessment" className="section">
          <p className="eyebrow">Jump to incident</p>
          <div className="jump">
            {out.incidents.map((i) => (
              <a key={i.chain.chain_id} className="jump__link" href={`#${anchorFor(i.chain.chain_id)}`}>
                <code>{i.chain.chain_id}</code>
                <RiskBadge level={i.risk.level} score={i.risk.score} />
              </a>
            ))}
          </div>
        </nav>
      ) : null}
      {out.incidents.map((incident) => (
        <IncidentSection
          key={incident.chain.chain_id}
          assessmentId={record.assessment_id}
          incident={incident}
          views={views}
          onRecorded={refreshViews}
        />
      ))}
    </>
  );
}

export function AssessmentDetailPage() {
  const api = useApi();
  const { assessmentId = "" } = useParams();
  const { state, reload } = useAsync(
    async () => {
      const [record, views] = await Promise.all([api.assessment(assessmentId), api.recommendations(assessmentId)]);
      return { record, views };
    },
    `assessment:${assessmentId}`,
  );
  return (
    <div className="page">
      <PageHero
        compact
        eyebrow={
          <>
            <Link to="/assessments">Assessments</Link> / investigation
          </>
        }
        title={
          <>
            Incident <span className="accent">investigation</span>
            <code>{assessmentId}</code>
          </>
        }
      />
      {state.status === "loading" ? <Loading label="Loading assessment" /> : null}
      {state.status === "error" ? (
        <ErrorView
          error={state.error}
          onRetry={reload}
          action={
            state.error.kind === "not_found" ? (
              <Link className="btn btn--ghost btn--small" to="/assessments">
                Back to assessments
              </Link>
            ) : undefined
          }
        />
      ) : null}
      {state.status === "ready" ? <Detail record={state.data.record} initialViews={state.data.views} /> : null}
    </div>
  );
}
