import { Link } from "react-router";

import { useApi } from "../api/useApi";
import { RISK_LEVELS, type IncidentAssessment, type RiskLevel } from "../api/types";
import {
  Chip,
  Empty,
  ErrorView,
  Loading,
  OriginChip,
  PageHero,
  Panel,
  RiskBadge,
  SectionHead,
  Stat,
  TableWrap,
} from "../components/ui";
import { useAsync } from "../hooks/useAsync";
import { when } from "../lib/format";
import { loadRecent, type RecentAssessments } from "../lib/recent";

const RECENT = 10;

function Versions() {
  const api = useApi();
  const { state, reload } = useAsync(() => api.meta(), "static");
  if (state.status === "loading") return <Loading label="Loading versions" />;
  if (state.status === "error") return <ErrorView error={state.error} onRetry={reload} />;
  const m = state.data;
  return (
    <dl className="kv" data-testid="versions">
      <dt>ATT&amp;CK knowledge base</dt>
      <dd>
        Enterprise <strong>{m.attack_version}</strong>
      </dd>
      <dt>Technique vocabulary</dt>
      <dd>
        <code>{m.vocabulary_version}</code>
      </dd>
      {Object.entries(m.policy_versions).map(([k, v]) => (
        <div key={`p-${k}`} className="kv__row">
          <dt>{k} policy</dt>
          <dd>
            <code>{v}</code>
          </dd>
        </div>
      ))}
      {Object.entries(m.model_versions).map(([k, v]) => (
        <div key={`m-${k}`} className="kv__row">
          <dt>model {k}</dt>
          <dd className="small">{v}</dd>
        </div>
      ))}
      <dt>Claim policy</dt>
      <dd className="small">{m.claim_policy}</dd>
    </dl>
  );
}

function Health() {
  const api = useApi();
  const { state, reload } = useAsync(() => api.health(), "static");
  if (state.status === "loading") return <Loading label="Checking API" />;
  if (state.status === "error") return <ErrorView error={state.error} onRetry={reload} />;
  const h = state.data;
  return (
    <dl className="kv" data-testid="health">
      <dt>Status</dt>
      <dd>
        <Chip tone="accent">{h.status}</Chip>
      </dd>
      <dt>Service version</dt>
      <dd>
        {h.service} {h.version} (schema {h.schema_version})
      </dd>
      <dt>Defense mode</dt>
      <dd>
        <Chip tone="approval">{h.defense_mode}</Chip>
      </dd>
      <dt>ATT&amp;CK</dt>
      <dd>Enterprise {h.attack_version}</dd>
      <dt>Environment</dt>
      <dd>{h.environment}</dd>
      <dt>Checked</dt>
      <dd className="num">{when(h.time)}</dd>
    </dl>
  );
}

function Runs() {
  const api = useApi();
  const { state, reload } = useAsync(() => api.runs(), "static");
  if (state.status === "loading") return <Loading label="Loading runs" />;
  if (state.status === "error") return <ErrorView error={state.error} onRetry={reload} />;
  if (state.data.length === 0) return <Empty>No stored evaluation runs.</Empty>;
  return (
    <div className="grid grid--cards" data-testid="runs-overview">
      {state.data.map((r) => (
        <article key={r.run_id} className="card run-card">
          <div className="row">
            <Chip tone="neutral">{r.task}</Chip>
            <OriginChip origin={r.data_origin} />
          </div>
          <code className="run-card__id">{r.run_id}</code>
          {r.notes ? <p className="run-card__notes">{r.notes}</p> : null}
          <p className="small muted">
            {r.status} · {Object.keys(r.metrics).length} stored metrics · {when(r.created_at)}
          </p>
        </article>
      ))}
    </div>
  );
}

interface Top {
  incident: IncidentAssessment;
  assessmentId: string;
  origin: string;
}

function highest(data: RecentAssessments): Top | null {
  let top: Top | null = null;
  for (const record of data.records)
    for (const incident of record.output.incidents)
      if (top === null || incident.risk.score > top.incident.risk.score)
        top = { incident, assessmentId: record.assessment_id, origin: record.data_origin };
  return top;
}

function Headline({ data }: { data: RecentAssessments }) {
  const top = highest(data);
  if (top === null)
    return (
      <Empty>
        The highest model-derived risk appears here once an assessment exists.{" "}
        <Link to="/assessments">Run the SYNTHETIC example →</Link>
      </Empty>
    );
  const { incident, assessmentId, origin } = top;
  return (
    <section className="panel panel--accent headline" data-testid="headline" aria-labelledby="headline-title">
      <div className="headline__score num">
        {incident.risk.score.toFixed(2)}
        <small>/ 100</small>
      </div>
      <div className="headline__body">
        <p className="headline__label" id="headline-title">
          Highest {incident.risk.label} · {data.records.length} most recent assessment(s)
        </p>
        <p className="headline__text">
          Incident <code>{incident.chain.chain_id}</code> in assessment{" "}
          <Link to={`/assessments/${encodeURIComponent(assessmentId)}`}>{assessmentId}</Link>:{" "}
          {incident.chain.chain.steps.length} observed step(s), {incident.recommendations.length} recommendation(s) awaiting a
          human decision.
        </p>
        <div className="row">
          <RiskBadge level={incident.risk.level} />
          {incident.risk.evidence_status ? (
            <Chip tone={incident.risk.evidence_status === "NEEDS ADDITIONAL EVIDENCE" ? "warn" : "neutral"}>
              {incident.risk.evidence_status}
            </Chip>
          ) : null}
          <OriginChip origin={origin} />
        </div>
        <p className="small muted">
          An engineering score from a documented policy — not a probability or a confirmed compromise.
        </p>
      </div>
    </section>
  );
}

function RecentIntelligence() {
  const api = useApi();
  const { state, reload } = useAsync(() => loadRecent(api, RECENT), "static");
  if (state.status === "loading") return <Loading label="Loading assessments" />;
  if (state.status === "error") return <ErrorView error={state.error} onRetry={reload} />;
  const { records, views, decisions } = state.data;
  const counts: Record<RiskLevel, number> = { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 };
  for (const r of records) for (const i of r.output.incidents) counts[i.risk.level] += 1;
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  const recommendationCount = [...views.values()].reduce((n, list) => n + list.length, 0);
  const scope = `in the ${String(records.length)} most recent assessment(s)`;
  return (
    <>
      <Headline data={state.data} />
      <div className="grid grid--stats" data-testid="overview-stats">
        <Stat label="Assessments" value={records.length} note={`most recent, up to ${String(RECENT)}`} />
        <Stat label="Incidents" value={total} note={scope} />
        <Stat label="Recommendations" value={recommendationCount} note="proposals only — none executed" />
        <Stat label="Analyst decisions" value={decisions.length} note="recorded for audit" />
      </div>
      <div className="grid grid--split">
        <Panel
          title="Recent assessments"
          subtitle={`${String(records.length)} most recent · incidents with their model-derived risk`}
          testId="assessment-summaries"
          actions={
            <Link className="btn btn--ghost btn--small" to="/assessments">
              All assessments
            </Link>
          }
        >
          {records.length === 0 ? (
            <Empty>
              No assessments yet. <Link to="/assessments">Submit one →</Link>
            </Empty>
          ) : (
            <TableWrap label="Recent assessments">
              <table className="table">
                <thead>
                  <tr>
                    <th scope="col">Assessment</th>
                    <th scope="col">Origin</th>
                    <th scope="col">Incidents (model-derived risk)</th>
                  </tr>
                </thead>
                <tbody>
                  {records.map((r) => (
                    <tr key={r.assessment_id}>
                      <td>
                        <Link className="mono" to={`/assessments/${encodeURIComponent(r.assessment_id)}`}>
                          {r.assessment_id}
                        </Link>
                        <span className="cell-sub num">{when(r.created_at)}</span>
                      </td>
                      <td>
                        <OriginChip origin={r.data_origin} />
                      </td>
                      <td>
                        <div className="row">
                          {r.output.incidents.map((i) => (
                            <RiskBadge key={i.chain.chain_id} level={i.risk.level} score={i.risk.score} />
                          ))}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </TableWrap>
          )}
        </Panel>
        <div className="stack">
          <Panel title="Risk distribution" subtitle={`Model-derived risk levels of incidents ${scope}`} testId="risk-distribution">
            {total === 0 ? (
              <Empty>No incidents.</Empty>
            ) : (
              <ul className="dist">
                {RISK_LEVELS.map((level) => (
                  <li key={level} className="dist__row">
                    <RiskBadge level={level} />
                    <span className="dist__bar" aria-hidden="true">
                      <span
                        className={`dist__fill dist__fill--${level.toLowerCase()}`}
                        style={{ width: `${String((counts[level] / total) * 100)}%` }}
                      />
                    </span>
                    <span className="dist__count">{counts[level]}</span>
                  </li>
                ))}
              </ul>
            )}
          </Panel>
          <Panel title="Recent analyst decisions" subtitle="Recorded for audit — never executed" testId="recent-decisions">
            {decisions.length === 0 ? (
              <Empty>No analyst decisions recorded.</Empty>
            ) : (
              <ul className="decision-history">
                {decisions.slice(0, 10).map((d) => (
                  <li key={d.decision_id}>
                    <Chip tone="neutral">{d.decision}</Chip> <code>{d.recommendation_id}</code>
                    <span className="muted">
                      by {d.analyst} · {when(d.recorded_at)}
                    </span>
                    <code>executed: {String(d.executed)}</code>
                  </li>
                ))}
              </ul>
            )}
          </Panel>
        </div>
      </div>
    </>
  );
}

export function OverviewPage() {
  return (
    <div className="page">
      <PageHero
        eyebrow="Threat intelligence"
        title={
          <>
            Intelligence <span className="accent">overview</span>
          </>
        }
        lead="Observed ATT&CK techniques, model forecasts of what may come next, and recommendation-only defense guidance — drawn from the stored assessments. Every score is model-derived and nothing is executed."
      />
      <RecentIntelligence />
      <section className="section" aria-labelledby="system-title">
        <SectionHead title={<span id="system-title">System &amp; knowledge base</span>} sub="Live API health and the versions currently being served." />
        <div className="grid grid--split">
          <Panel title="Knowledge base, models & policies" subtitle="From GET /api/v1/meta — the current serving configuration">
            <Versions />
          </Panel>
          <Panel title="System / API health">
            <Health />
          </Panel>
        </div>
      </section>
      <section className="section" aria-labelledby="runs-title">
        <SectionHead
          title={<span id="runs-title">Evaluation runs</span>}
          sub="Stored experiment records (read-only summaries)."
          actions={
            <Link className="btn btn--ghost btn--small" to="/evaluation">
              Open evaluation runs →
            </Link>
          }
        />
        <Runs />
      </section>
    </div>
  );
}
