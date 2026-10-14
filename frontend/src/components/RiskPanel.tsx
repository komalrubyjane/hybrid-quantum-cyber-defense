import type { RiskAssessment } from "../api/types";
import { num, when } from "../lib/format";
import { Chip, IdList, Meter, ModelDerivedNotice, Panel, RiskBadge, RiskGauge, TableWrap, TechniqueId } from "./ui";

/** Displays the API's risk assessment. The frontend never computes or re-weights a score. */
export function RiskPanel({ risk }: { risk: RiskAssessment }) {
  return (
    <Panel
      title={
        <>
          <span className="risk-label">{risk.label}</span> <RiskBadge level={risk.level} />
        </>
      }
      subtitle={`policy ${risk.policy_version ?? "n/a"} · assessed ${when(risk.created_at)}`}
      testId="risk-panel"
    >
      <div className="risk-head">
        <RiskGauge score={risk.score} level={risk.level}>
          <div className="risk-score" aria-label={`Model-derived risk score ${risk.score.toFixed(2)} of 100`}>
            <div className="risk-score__value">{risk.score.toFixed(2)}</div>
            <div className="risk-score__max">/ 100 · {risk.level}</div>
          </div>
        </RiskGauge>
        <div className="risk-head__body">
          <ModelDerivedNotice />
          <dl className="kv kv--stack">
            <dt>Evidence status</dt>
            <dd>
              {risk.evidence_status ? (
                <Chip tone={risk.evidence_status === "NEEDS ADDITIONAL EVIDENCE" ? "warn" : "neutral"}>
                  {risk.evidence_status}
                </Chip>
              ) : (
                "no detector evidence"
              )}
            </dd>
            <dt>Quantum disagreement</dt>
            <dd>{risk.quantum_disagreement ? "yes — recorded; does not raise risk" : "no"}</dd>
            <dt>Uncertainty</dt>
            <dd className="num">{num(risk.uncertainty, 3)}</dd>
          </dl>
        </div>
      </div>
      <hr className="divider" />
      <dl className="kv">
        <dt>Affected assets</dt>
        <dd>{(risk.affected_assets ?? []).join(", ") || "n/a"}</dd>
        <dt>Observed techniques</dt>
        <dd>
          <IdList>
            {(risk.observed_technique_ids ?? []).map((t) => (
              <TechniqueId key={`o-${t}`} id={t} />
            ))}
          </IdList>
        </dd>
        <dt>Predicted (top) techniques</dt>
        <dd>
          <IdList>
            {(risk.predicted_technique_ids ?? []).map((t) => (
              <TechniqueId key={`p-${t}`} id={t} />
            ))}
          </IdList>
        </dd>
      </dl>
      <h3 className="h3">Contributing factors</h3>
      <TableWrap label="Contributing risk factors">
        <table className="table table--compact" data-testid="risk-components">
          <caption className="small muted">Contributing factors as returned by the API</caption>
          <thead>
            <tr>
              <th scope="col">Factor · reason</th>
              <th scope="col">Value</th>
              <th scope="col" className="td-num">
                Weight
              </th>
              <th scope="col" className="td-num">
                Points
              </th>
            </tr>
          </thead>
          <tbody>
            {risk.components.map((c) => (
              <tr key={c.name}>
                <td>
                  <code>{c.name}</code>
                  <span className="cell-sub">{c.reason}</span>
                </td>
                <td>
                  <span className="metric-cell">
                    <span className="num">{num(c.value, 3)}</span>
                    <Meter value={c.value} tone="neutral" />
                  </span>
                </td>
                <td className="td-num">{num(c.weight, 0)}</td>
                <td className="td-num">
                  <strong>{num(c.contribution, 2)}</strong>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </TableWrap>
    </Panel>
  );
}
