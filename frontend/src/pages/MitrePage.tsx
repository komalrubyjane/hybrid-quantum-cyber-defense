import { Link } from "react-router";

import { useApi } from "../api/useApi";
import {
  Empty,
  ErrorView,
  IdList,
  Loading,
  MitigationId,
  PageHero,
  Panel,
  Stat,
  TableWrap,
  TacticId,
  TechniqueId,
} from "../components/ui";
import { useAsync } from "../hooks/useAsync";
import { loadRecent } from "../lib/recent";

interface TechniqueRow {
  id: string;
  tactics: Set<string>;
  observed: number;
  predicted: number;
}

const MAX_DOTS = 6;

/** Count shown as dots (solid = observed, dashed = predicted) plus the exact number. */
function Dots({ count, kind }: { count: number; kind: "observed" | "predicted" }) {
  if (count === 0) return <span className="faint">0</span>;
  return (
    <span className="dots">
      <span className="dots" aria-hidden="true">
        {Array.from({ length: Math.min(count, MAX_DOTS) }, (_, i) => (
          <span key={i} className={`dot dot--${kind}`} />
        ))}
      </span>
      <span className="num">{count}</span>
    </span>
  );
}

/**
 * ATT&CK view built ONLY from identifiers the API returns. The Milestone 8 API exposes no
 * technique-lookup endpoint (names, descriptions), and the dashboard does not download or
 * recreate the knowledge base; IDs link to the public ATT&CK pages instead.
 */
export function MitrePage() {
  const api = useApi();
  const meta = useAsync(() => api.meta(), "static");
  const recent = useAsync(() => loadRecent(api, 20), "static");

  const rows = new Map<string, TechniqueRow>();
  const tactics = new Map<string, number>();
  const mitigations = new Set<string>();
  if (recent.state.status === "ready") {
    for (const record of recent.state.data.records) {
      for (const incident of record.output.incidents) {
        for (const step of incident.chain.chain.steps) {
          const row = rows.get(step.technique_id) ?? { id: step.technique_id, tactics: new Set(), observed: 0, predicted: 0 };
          row.observed += 1;
          if (step.tactic_id) {
            row.tactics.add(step.tactic_id);
            tactics.set(step.tactic_id, (tactics.get(step.tactic_id) ?? 0) + 1);
          }
          rows.set(step.technique_id, row);
        }
        for (const n of incident.prediction.result.next_step ?? []) {
          const row = rows.get(n.technique_id) ?? { id: n.technique_id, tactics: new Set(), observed: 0, predicted: 0 };
          row.predicted += 1;
          rows.set(n.technique_id, row);
        }
        for (const rec of incident.recommendations) for (const m of rec.attack_mitigation_ids ?? []) mitigations.add(m);
      }
    }
  }
  const sorted = [...rows.values()].sort((a, b) => a.id.localeCompare(b.id));
  const observedCount = sorted.filter((r) => r.observed > 0).length;
  const predictedOnly = sorted.filter((r) => r.observed === 0).length;

  return (
    <div className="page">
      <PageHero
        eyebrow="Knowledge base"
        title={
          <>
            MITRE <span className="accent">ATT&amp;CK</span>
          </>
        }
        lead="Techniques, tactics and mitigations that appear in stored assessments — observed with evidence, or forecast by a model. IDs open the public ATT&CK site in a new tab; nothing is fetched by the dashboard."
      />
      <Panel
        title="Knowledge base"
        subtitle="The API reports the ATT&CK version; it exposes no technique-detail endpoint, so names and descriptions are not shown here."
      >
        {meta.state.status === "loading" ? <Loading /> : null}
        {meta.state.status === "error" ? <ErrorView error={meta.state.error} onRetry={meta.reload} /> : null}
        {meta.state.status === "ready" ? (
          <p data-testid="attack-version" className="headline__text">
            ATT&amp;CK Enterprise <strong>{meta.state.data.attack_version}</strong> · vocabulary{" "}
            <code>{meta.state.data.vocabulary_version}</code>
          </p>
        ) : null}
        <p className="small muted mt-3">
          Technique and tactic IDs below come from stored assessments. CIC-IDS2017 labels are never shown as techniques.
        </p>
      </Panel>
      {recent.state.status === "loading" ? <Loading label="Loading techniques from assessments" /> : null}
      {recent.state.status === "error" ? <ErrorView error={recent.state.error} onRetry={recent.reload} /> : null}
      {recent.state.status === "ready" ? (
        <>
          <div className="grid grid--stats">
            <Stat label="Techniques" value={sorted.length} note="observed or forecast" />
            <Stat label="Observed" value={observedCount} note="with evidence in a chain" />
            <Stat label="Forecast only" value={predictedOnly} note="in a top-k, never observed" />
            <Stat label="Tactics" value={tactics.size} note="attributed to observed steps" />
          </div>
          <div className="grid grid--split">
            <Panel
              title="Techniques in recent assessments"
              subtitle="Solid dots: observed steps. Dashed rings: appearances in a model's next-step top-k (not observed)."
              testId="technique-list"
            >
              {sorted.length === 0 ? (
                <Empty>
                  No techniques yet — <Link to="/assessments">submit an assessment</Link>.
                </Empty>
              ) : (
                <TableWrap label="Techniques in recent assessments">
                  <table className="table table--compact">
                    <thead>
                      <tr>
                        <th scope="col">Technique</th>
                        <th scope="col">Attributed tactics (observed)</th>
                        <th scope="col">Observed steps</th>
                        <th scope="col">Predicted (top-k)</th>
                      </tr>
                    </thead>
                    <tbody>
                      {sorted.map((r) => (
                        <tr key={r.id}>
                          <td>
                            <TechniqueId id={r.id} />
                          </td>
                          <td>
                            {r.tactics.size === 0 ? (
                              <span className="faint">—</span>
                            ) : (
                              <IdList>
                                {[...r.tactics].map((t) => (
                                  <TacticId key={t} id={t} />
                                ))}
                              </IdList>
                            )}
                          </td>
                          <td>
                            <Dots count={r.observed} kind="observed" />
                          </td>
                          <td>
                            <Dots count={r.predicted} kind="predicted" />
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </TableWrap>
              )}
            </Panel>
            <div className="stack">
              <Panel title="Tactics (observed)" testId="tactic-list">
                {tactics.size === 0 ? (
                  <Empty>No attributed tactics.</Empty>
                ) : (
                  <ul className="tiles">
                    {[...tactics.entries()].sort().map(([t, n]) => (
                      <li key={t} className="tile">
                        <TacticId id={t} />
                        <span className="tile__count">{n}</span>
                        <span className="micro muted">observed step(s)</span>
                      </li>
                    ))}
                  </ul>
                )}
              </Panel>
              <Panel title="ATT&CK mitigations referenced by recommendations">
                {mitigations.size === 0 ? (
                  <Empty>None.</Empty>
                ) : (
                  <IdList>
                    {[...mitigations].sort().map((m) => (
                      <MitigationId key={m} id={m} />
                    ))}
                  </IdList>
                )}
              </Panel>
            </div>
          </div>
        </>
      ) : null}
    </div>
  );
}
