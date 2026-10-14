import { useState } from "react";

import { useApi } from "../api/useApi";
import type { RunSummary } from "../api/types";
import { Chip, Empty, ErrorView, Loading, Meter, OriginChip, PageHero, Panel, SectionHead, TableWrap } from "../components/ui";
import { useAsync } from "../hooks/useAsync";
import { num, when } from "../lib/format";
import { headlineValue, isProportion, pivotMetrics, type MetricCell } from "../lib/metrics";

function Cell({ row, metric, cell }: { row: string; metric: string; cell: MetricCell | undefined }) {
  const value = headlineValue(cell);
  if (cell === undefined || value === undefined) return <span className="faint">—</span>;
  return (
    <span className="metric-cell">
      <span className="num">
        {num(value, 4)}
        {cell.value === undefined && cell.mean !== undefined ? <span className="ci"> mean</span> : null}
        {cell.std !== undefined ? <span className="ci"> ± {num(cell.std, 4)}</span> : null}
      </span>
      {isProportion(row, metric, value) ? <Meter value={value} tone="neutral" /> : null}
      {cell.ci_low !== undefined && cell.ci_high !== undefined ? (
        <span className="ci">
          CI [{num(cell.ci_low, 3)}, {num(cell.ci_high, 3)}]
        </span>
      ) : null}
    </span>
  );
}

function Metrics({ run }: { run: RunSummary }) {
  const [filter, setFilter] = useState("");
  const entries = Object.entries(run.metrics)
    .filter(([k]) => k.toLowerCase().includes(filter.toLowerCase()))
    .sort(([a], [b]) => a.localeCompare(b));
  const pivot = pivotMetrics(entries);
  return (
    <div data-testid="run-metrics" className="stack">
      <div className="field field--narrow">
        <label htmlFor="metric-filter">Filter {Object.keys(run.metrics).length} metrics</label>
        <input
          id="metric-filter"
          value={filter}
          autoComplete="off"
          placeholder="e.g. top1, roc_auc, B1, random_forest"
          onChange={(e) => {
            setFilter(e.target.value);
          }}
        />
      </div>
      {entries.length === 0 ? (
        <Empty>No metrics match.</Empty>
      ) : (
        <>
          <div>
            <h3 className="h3">Comparison · {pivot.rows.length} row(s) × {pivot.columns.length} metric(s)</h3>
            <p className="small muted">
              Rows and columns come from the stored metric names. Confidence intervals and means are shown only where
              the run stored them; bars mark values that are proportions (0–1) and imply no ranking.
            </p>
            <TableWrap label="Metric comparison" tall>
              <table className="table table--compact table--sticky pivot mt-3">
                <thead>
                  <tr>
                    <th scope="col">Group</th>
                    {pivot.columns.map((c) => (
                      <th key={c} scope="col">
                        {c}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {pivot.rows.map((row) => (
                    <tr key={row}>
                      <th scope="row">
                        {row}
                      </th>
                      {pivot.columns.map((c) => (
                        <td key={c}>
                          <Cell row={row} metric={c} cell={pivot.cells.get(row)?.get(c)} />
                        </td>
                      ))}
                    </tr>
                  ))}
                </tbody>
              </table>
            </TableWrap>
          </div>
          <details>
            <summary>All {entries.length} stored metric keys (raw)</summary>
            <div className="details__body">
              <TableWrap label="All stored metrics" tall>
                <table className="table table--compact">
                  <thead>
                    <tr>
                      <th scope="col">Metric</th>
                      <th scope="col" className="td-num">
                        Value
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {entries.map(([k, v]) => (
                      <tr key={k}>
                        <td>
                          <code>{k}</code>
                        </td>
                        <td className="td-num">{num(v, 4)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </TableWrap>
            </div>
          </details>
        </>
      )}
    </div>
  );
}

export function EvaluationPage() {
  const api = useApi();
  const { state, reload } = useAsync(() => api.runs(), "static");
  const meta = useAsync(() => api.meta(), "static");
  const [selected, setSelected] = useState<string | null>(null);
  const selectedRun = state.status === "ready" && selected ? state.data.find((r) => r.run_id === selected) : undefined;
  return (
    <div className="page">
      <PageHero
        eyebrow="Research record"
        title={
          <>
            Evaluation <span className="accent">runs</span>
          </>
        }
        lead="Stored experiment records and their metrics exactly as saved. Per-run records are kept separate from the versions the API is serving now."
      />
      <section className="section" aria-labelledby="stored-runs-title">
        <SectionHead
          title={<span id="stored-runs-title">Stored experiment records</span>}
          sub="Summaries from GET /api/v1/runs. The API omits per-run configuration, environment and paths, so per-run model/policy versions are not available here."
        />
        <Panel title="Runs" subtitle="Select a run to compare its stored metrics.">
          {state.status === "loading" ? <Loading /> : null}
          {state.status === "error" ? <ErrorView error={state.error} onRetry={reload} /> : null}
          {state.status === "ready" && state.data.length === 0 ? <Empty>No stored runs.</Empty> : null}
          {state.status === "ready" && state.data.length > 0 ? (
            <TableWrap label="Stored runs">
              <table className="table" data-testid="runs-table">
                <thead>
                  <tr>
                    <th scope="col">Run</th>
                    <th scope="col">Task</th>
                    <th scope="col">Dataset / source</th>
                    <th scope="col">Origin</th>
                    <th scope="col">Status</th>
                    <th scope="col">Timestamp</th>
                    <th scope="col">Metrics</th>
                  </tr>
                </thead>
                <tbody>
                  {state.data.map((r) => (
                    <tr key={r.run_id} className={selected === r.run_id ? "is-selected" : ""}>
                      <td className="col-wide">
                        <code className="run-id">{r.run_id}</code>
                        {r.notes ? <span className="cell-sub">{r.notes}</span> : null}
                      </td>
                      <td>
                        <Chip tone="neutral">{r.task}</Chip>
                      </td>
                      <td>
                        {r.dataset_id}
                        <span className="cell-sub">{r.dataset_version}</span>
                      </td>
                      <td>
                        <OriginChip origin={r.data_origin} />
                      </td>
                      <td>
                        {r.status}
                        {r.git_dirty ? <span className="cell-sub">uncommitted code</span> : null}
                      </td>
                      <td className="num nowrap">{when(r.created_at)}</td>
                      <td>
                        <button
                          type="button"
                          className={`btn btn--small ${selected === r.run_id ? "btn--primary" : "btn--ghost"}`}
                          aria-pressed={selected === r.run_id}
                          aria-controls="run-metrics-panel"
                          onClick={() => {
                            setSelected(selected === r.run_id ? null : r.run_id);
                          }}
                        >
                          {Object.keys(r.metrics).length} metrics
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </TableWrap>
          ) : null}
        </Panel>
        {selectedRun ? (
          <Panel
            id="run-metrics-panel"
            className="panel--accent"
            title={
              <>
                Metrics · <code className="run-id">{selectedRun.run_id}</code>
              </>
            }
            subtitle={`${selectedRun.task} · ${selectedRun.dataset_id} · ${selectedRun.data_origin} · stored ${when(selectedRun.created_at)}`}
          >
            <Metrics run={selectedRun} />
          </Panel>
        ) : null}
      </section>
      <section className="section" aria-labelledby="serving-title">
        <SectionHead
          title={<span id="serving-title">Current serving versions</span>}
          sub="From GET /api/v1/meta — the configuration the API is serving now, not the configuration of any individual run."
        />
        <Panel title="Current deployment versions" subtitle="From GET /api/v1/meta (the serving configuration, not per run)">
          {meta.state.status === "loading" ? <Loading /> : null}
          {meta.state.status === "error" ? <ErrorView error={meta.state.error} onRetry={meta.reload} /> : null}
          {meta.state.status === "ready" ? (
            <dl className="kv">
              {Object.entries({ ...meta.state.data.model_versions, ...meta.state.data.policy_versions }).map(([k, v]) => (
                <div key={k} className="kv__row">
                  <dt>{k}</dt>
                  <dd className="small">{v}</dd>
                </div>
              ))}
            </dl>
          ) : null}
        </Panel>
      </section>
    </div>
  );
}
