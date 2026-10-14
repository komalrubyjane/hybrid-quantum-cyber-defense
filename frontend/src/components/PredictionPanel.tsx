import type { IncidentAssessment } from "../api/types";
import { pct, sci } from "../lib/format";
import { Chip, Meter, Panel, TableWrap, TechniqueId } from "./ui";

export function PredictionPanel({ incident }: { incident: IncidentAssessment }) {
  const prediction = incident.prediction;
  const result = prediction.result;
  const perModel = prediction.per_model_top_k ?? {};
  return (
    <Panel
      title={
        <>
          Predicted next techniques <Chip tone="predicted">PREDICTED</Chip>
        </>
      }
      subtitle={prediction.next_step_semantics}
      testId="prediction-panel"
    >
      <p className="small muted">
        Primary model <strong className="chip chip--predicted">{result.model_id}</strong> · history used:{" "}
        <code className="wrap-anywhere">{prediction.context_tokens.join(" → ")}</code> · horizon {result.horizon} · beam
        width {prediction.beam_width}
      </p>
      <div className="grid grid--split mt-3">
        <div>
          <h3 className="h3">Next step · primary model</h3>
          <TableWrap label="Next-step probabilities">
            <table className="table table--compact">
              <caption className="sr-only">Next-step probabilities of the primary model</caption>
              <thead>
                <tr>
                  <th scope="col">#</th>
                  <th scope="col">Technique</th>
                  <th scope="col">Next-step probability</th>
                </tr>
              </thead>
              <tbody>
                {(result.next_step ?? []).map((n, i) => (
                  <tr key={n.technique_id}>
                    <td className="num muted">{i + 1}</td>
                    <td>
                      <TechniqueId id={n.technique_id} />
                    </td>
                    <td>
                      <span className="bar-cell">
                        <Meter value={n.probability} tone="predicted" />
                        <span className="num">{pct(n.probability, 2)}</span>
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
          <p className="small mt-3">
            P(next technique has an Exfiltration/Impact tactic):{" "}
            <strong className="num">{pct(incident.high_impact_next_step_probability, 2)}</strong>{" "}
            <span className="muted">(next-step probability, not calibrated)</span>
          </p>
        </div>
        <div>
          <h3 className="h3">Per-model top-k</h3>
          <div className="grid grid--models">
            {Object.entries(perModel).map(([model, rows]) => (
              <div key={model} className="mini-card">
                <div className="mini-card__title">
                  <span>{model}</span>
                  {model === result.model_id ? <span className="micro muted">primary</span> : null}
                </div>
                <ol className="compact">
                  {rows.map(([technique, p]) => (
                    <li key={`${model}-${technique}`}>
                      <span className="row">
                        <TechniqueId id={technique} /> <span className="num small">{pct(p, 2)}</span>
                      </span>
                    </li>
                  ))}
                </ol>
              </div>
            ))}
          </div>
        </div>
      </div>

      <h3 className="h3">Beam-search paths (PATH SCORE)</h3>
      <p className="small muted">{prediction.path_score_semantics}</p>
      <TableWrap label="Beam-search paths">
        <table className="table table--compact mt-3">
          <thead>
            <tr>
              <th scope="col">Rank</th>
              <th scope="col">Predicted path (not observed)</th>
              <th scope="col" className="td-num">
                Path score
              </th>
            </tr>
          </thead>
          <tbody>
            {(result.paths ?? []).map((p, i) => (
              <tr key={`${p.technique_ids.join("-")}-${String(i)}`}>
                <td className="num muted">{i + 1}</td>
                <td>
                  <span className="path">
                    {p.technique_ids.map((t, j) => (
                      <span key={`${t}-${String(j)}`} className="row">
                        {j > 0 ? (
                          <span className="path__arrow" aria-hidden="true">
                            →
                          </span>
                        ) : null}
                        <span className="chip chip--predicted">{t}</span>
                      </span>
                    ))}
                  </span>
                </td>
                <td className="td-num">{sci(p.probability)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </TableWrap>
    </Panel>
  );
}
