import type { DetectionEvidence } from "../api/types";
import { num, pct } from "../lib/format";
import { Chip, Empty, Panel, TableWrap } from "./ui";

function statusTone(status: string | undefined): string {
  if (status === "NEEDS ADDITIONAL EVIDENCE") return "warn";
  if (status === "CORROBORATED BY INDEPENDENT EVIDENCE") return "info";
  return "neutral";
}

/** Counts of the per-event flags exactly as returned by the API (no new rule). */
function Tally({ detections }: { detections: DetectionEvidence[] }) {
  const triggered = detections.filter((d) => d.quantum?.gate_triggered === true);
  const items = [
    { label: "Detections", value: detections.length },
    { label: "Second opinions", value: triggered.length },
    { label: "Disagreements", value: triggered.filter((d) => d.quantum_disagreement).length },
    { label: "Need more evidence", value: detections.filter((d) => d.evidence_status === "NEEDS ADDITIONAL EVIDENCE").length },
  ];
  return (
    <dl className="tally">
      {items.map((i) => (
        <div key={i.label} className="tally__item">
          <dt className="tally__label">{i.label}</dt>
          <dd className="tally__value">{i.value}</dd>
        </div>
      ))}
    </dl>
  );
}

/** Classical verdict next to the optional quantum second opinion, exactly as returned. */
export function QuantumPanel({ detections }: { detections: DetectionEvidence[] }) {
  return (
    <Panel
      title={
        <>
          Classical detection &amp; quantum second opinion <Chip tone="experimental">EXPERIMENTAL</Chip>
        </>
      }
      subtitle="The quantum second opinion never overrides the classical verdict. Disagreement only requests additional evidence. No quantum advantage is claimed."
      testId="quantum-panel"
    >
      {detections.length === 0 ? (
        <Empty>No detector evidence for this chain.</Empty>
      ) : (
        <>
          <Tally detections={detections} />
          <TableWrap label="Classical and quantum opinions per event">
            <table className="table">
              <thead>
                <tr>
                  <th scope="col">Event</th>
                  <th scope="col">Classical verdict (decision)</th>
                  <th scope="col">Quantum second opinion</th>
                  <th scope="col">Agreement</th>
                  <th scope="col">Evidence status</th>
                </tr>
              </thead>
              <tbody>
                {detections.map((d) => {
                  const q = d.quantum;
                  const triggered = q?.gate_triggered === true;
                  return (
                    <tr key={d.event_id} data-testid="detection-row">
                      <td>
                        <code>{d.event_id}</code>
                        <span className="cell-sub">
                          {d.classical_model} · {d.origin === "SYNTHETIC_FIXTURE" ? "synthetic fixture score" : "model output"}
                        </span>
                      </td>
                      <td>
                        <Chip tone={d.verdict === "MALICIOUS" ? "danger" : "ok"}>{d.verdict}</Chip>
                        <span className="cell-sub num">
                          P(malicious) {pct(d.p_malicious)} · threshold {num(d.threshold, 2)}
                        </span>
                      </td>
                      <td>
                        {triggered ? (
                          <>
                            <Chip tone="quantum">{q.verdict ?? "n/a"}</Chip>
                            <span className="cell-sub num">
                              P(malicious) {pct(q.p_malicious)} · confidence {pct(q.confidence)}
                              {q.latency_ms === null || q.latency_ms === undefined ? null : ` · ${num(q.latency_ms, 2)} ms`}
                            </span>
                            <span className="cell-sub">{q.backend ?? ""}</span>
                          </>
                        ) : (
                          <span className="muted">not triggered</span>
                        )}
                      </td>
                      <td>
                        {!triggered ? (
                          <span className="muted">—</span>
                        ) : d.quantum_disagreement ? (
                          <Chip tone="warn">DISAGREES (classical verdict kept)</Chip>
                        ) : (
                          <Chip tone="ok">agrees</Chip>
                        )}
                      </td>
                      <td>
                        <Chip tone={statusTone(d.evidence_status)}>{d.evidence_status}</Chip>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </TableWrap>
        </>
      )}
    </Panel>
  );
}
