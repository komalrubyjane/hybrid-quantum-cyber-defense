import { useRef, useState, type ChangeEvent, type SyntheticEvent } from "react";
import { Link, useNavigate } from "react-router";

import { ApiError, messageOf } from "../api/client";
import { useApi } from "../api/useApi";
import { Empty, ErrorView, Loading, Meter, OriginChip, PageHero, Panel, TableWrap } from "../components/ui";
import syntheticRequest from "../fixtures/synthetic-assessment-request.json";
import { useAsync } from "../hooks/useAsync";
import { num, when } from "../lib/format";

const MAX_BYTES = 5 * 1024 * 1024;

/** Key names read from the bundled SYNTHETIC example (descriptive only; the API validates). */
function exampleKeys(): { observation: string[]; event: string[]; resource: string[] } {
  const first = syntheticRequest.observations[0];
  return {
    observation: first ? Object.keys(first) : [],
    event: first ? Object.keys(first.event).slice(0, 4) : [],
    resource: syntheticRequest.resources[0] ? Object.keys(syntheticRequest.resources[0]).slice(0, 3) : [],
  };
}

function FormatGuide() {
  const keys = exampleKeys();
  return (
    <div className="stack">
      <p className="notice notice--info small">
        <span className="notice__icon" aria-hidden="true" />
        <span>
          <strong>The example is demonstration data.</strong> It is a hand-authored SYNTHETIC multi-stage scenario, not
          real network traffic, and every result it produces is labelled SYNTHETIC.
        </span>
      </p>
      <div>
        <p className="eyebrow">Expected input · AssessmentRequest JSON</p>
        <pre className="schema" aria-label="Outline of the AssessmentRequest structure, taken from the example">
          {"{\n  "}
          <span className="c">{`// one entry per security event (${String(syntheticRequest.observations.length)} in the example)`}</span>
          {"\n  "}
          <span className="k">"observations"</span>
          {": [\n    { "}
          {keys.observation.map((k, i) => (
            <span key={k}>
              <span className="k">{k}</span>
              {i < keys.observation.length - 1 ? ", " : ""}
            </span>
          ))}
          {" }\n  ],\n  "}
          <span className="k">"resources"</span>
          {`: [ { ${keys.resource.join(", ")}, … } ],  `}
          <span className="c">// optional</span>
          {"\n  "}
          <span className="k">"as_of"</span>
          {': "ISO-8601 timestamp"\n}'}
        </pre>
        <p className="small muted mt-3">
          Each event carries fields such as <code>{keys.event.join(", ")}</code>, its detector output and
          evidence-backed ATT&amp;CK technique annotations.
        </p>
      </div>
      <p className="notice notice--model small">
        <span className="notice__icon" aria-hidden="true" />
        <span>
          Raw network logs, packet captures or CIC-IDS2017 CSV rows are <strong>not accepted directly</strong>. Convert
          them into this structure first. The API checks every field and lists any problem; the dashboard does not
          re-implement those rules.
        </span>
      </p>
    </div>
  );
}

function SubmitForm() {
  const api = useApi();
  const navigate = useNavigate();
  const [text, setText] = useState("");
  const [source, setSource] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const [hint, setHint] = useState<string | null>(null);
  // Guards against a second submission before React re-renders the disabled button.
  const inFlight = useRef(false);

  function fail(e: ApiError, extra: string | null = null) {
    setError(e);
    setHint(extra);
  }

  function loadExample() {
    setError(null);
    setText(JSON.stringify(syntheticRequest, null, 2));
    setSource("SYNTHETIC example (bundled)");
  }

  function onFile(event: ChangeEvent<HTMLInputElement>) {
    const file = event.target.files?.[0];
    event.target.value = "";
    if (!file) return;
    if (file.size > MAX_BYTES) {
      fail(new ApiError("validation", "File is larger than 5 MB."), "Split the observations into smaller requests.");
      return;
    }
    setError(null);
    file.text().then(
      (content) => {
        setText(content);
        setSource(`uploaded file ${file.name}`);
      },
      () => {
        fail(new ApiError("validation", "The file could not be read."));
      },
    );
  }

  async function submit(event: SyntheticEvent) {
    event.preventDefault();
    if (inFlight.current) return;
    setError(null);
    let body: unknown;
    try {
      body = JSON.parse(text);
    } catch (e) {
      const detail = e instanceof SyntaxError ? e.message.slice(0, 160) : "";
      fail(
        new ApiError("validation", "The request is not valid JSON."),
        `Check for a missing comma, quote or bracket.${detail ? ` Parser: ${detail}` : ""}`,
      );
      return;
    }
    inFlight.current = true;
    setBusy(true);
    try {
      const record = await api.createAssessment(body);
      void navigate(`/assessments/${encodeURIComponent(record.assessment_id)}`);
    } catch (e) {
      const apiError = e instanceof ApiError ? e : new ApiError("http", messageOf(e));
      fail(
        apiError,
        apiError.kind === "validation"
          ? "The API compared the request with the AssessmentRequest schema. Fix the fields listed above and run it again."
          : null,
      );
    } finally {
      inFlight.current = false;
      setBusy(false);
    }
  }

  const hasText = text.trim().length > 0;
  const step = busy ? 3 : hasText ? 2 : 1;
  return (
    <Panel
      title="Run an assessment"
      subtitle="POST /api/v1/assessments — the API validates the request and runs the existing pipeline. Nothing is executed; the result is a stored, read-only assessment."
      testId="submit-assessment"
      className="panel--accent"
    >
      <div className="grid grid--split">
        <form onSubmit={(e) => void submit(e)} className="form" aria-busy={busy}>
          <ol className="steps">
            <li className={step === 1 ? "is-current" : ""}>
              <div>
                <p className="steps__title">Start from the SYNTHETIC example</p>
                <p className="steps__text">The quickest way to see the full pipeline. You can edit it before running.</p>
                <div className="form__row mt-3">
                  <button type="button" className="btn btn--primary" onClick={loadExample} disabled={busy}>
                    Load SYNTHETIC example
                  </button>
                  <label className={`btn btn--ghost file-btn${busy ? " is-disabled" : ""}`}>
                    Upload JSON
                    <input type="file" accept="application/json,.json" className="sr-only" onChange={onFile} disabled={busy} />
                  </label>
                </div>
              </div>
            </li>
            <li className={step === 2 ? "is-current" : ""}>
              <div className="field">
                <p className="steps__title">
                  <label htmlFor="assessment-json">AssessmentRequest JSON</label>
                </p>
                <p className="steps__text">Paste your own request, or review the example.</p>
                <textarea
                  id="assessment-json"
                  className="code-input"
                  spellCheck={false}
                  rows={14}
                  value={text}
                  readOnly={busy}
                  aria-describedby="editor-meta"
                  onChange={(e) => {
                    setText(e.target.value);
                    setSource("edited in the browser");
                  }}
                  placeholder='{"observations": [...], "resources": [...], "as_of": "..."}'
                />
                <div className="editor-meta" id="editor-meta">
                  <span>{source ? `Source: ${source}` : "No request loaded yet"}</span>
                  <span className="num">{hasText ? `${String(text.length)} characters` : ""}</span>
                </div>
              </div>
            </li>
            <li className={step === 3 ? "is-current" : ""}>
              <div>
                <p className="steps__title">Run it</p>
                <p className="steps__text">The result opens as soon as the API has stored it.</p>
                <div className="form__row mt-3">
                  <button type="submit" className={`btn btn--primary${busy ? " btn--busy" : ""}`} disabled={busy || !hasText}>
                    {busy ? "Assessing…" : "Run assessment"}
                  </button>
                  {hasText && !busy ? (
                    <button
                      type="button"
                      className="btn btn--ghost"
                      onClick={() => {
                        setText("");
                        setSource(null);
                        setError(null);
                      }}
                    >
                      Clear
                    </button>
                  ) : null}
                </div>
                {busy ? (
                  <p className="small muted mt-3" role="status">
                    Submitting — please wait. Further submissions are blocked until the API answers.
                  </p>
                ) : null}
              </div>
            </li>
          </ol>
          {error ? <ErrorView error={error} hint={hint ?? undefined} /> : null}
        </form>
        <FormatGuide />
      </div>
    </Panel>
  );
}

export function AssessmentsPage() {
  const api = useApi();
  const { state, reload } = useAsync(() => api.assessments(50), "static");
  return (
    <div className="page">
      <PageHero
        eyebrow="Assessments"
        title={
          <>
            Assess a <span className="accent">chain</span>
          </>
        }
        lead="Submit structured security observations. The API correlates them into attack chains, forecasts likely next techniques, derives a risk score and proposes defenses for a human analyst to review."
      />
      <SubmitForm />
      <Panel
        title="Stored assessments"
        subtitle="Immutable records returned by GET /api/v1/assessments (newest first)"
        testId="stored-assessments"
      >
        {state.status === "loading" ? <Loading /> : null}
        {state.status === "error" ? <ErrorView error={state.error} onRetry={reload} /> : null}
        {state.status === "ready" && state.data.length === 0 ? <Empty>No assessments stored yet.</Empty> : null}
        {state.status === "ready" && state.data.length > 0 ? (
          <TableWrap label="Stored assessments">
            <table className="table" data-testid="assessment-list">
              <thead>
                <tr>
                  <th scope="col">Assessment</th>
                  <th scope="col">Origin</th>
                  <th scope="col" className="td-num">
                    Incidents
                  </th>
                  <th scope="col">Max model-derived risk</th>
                  <th scope="col" className="td-num">
                    Recommendations
                  </th>
                </tr>
              </thead>
              <tbody>
                {state.data.map((s) => (
                  <tr key={s.assessment_id}>
                    <td>
                      <Link className="mono" to={`/assessments/${encodeURIComponent(s.assessment_id)}`}>
                        {s.assessment_id}
                      </Link>
                      <span className="cell-sub num">Created {when(s.created_at)}</span>
                    </td>
                    <td>
                      <OriginChip origin={s.data_origin} />
                    </td>
                    <td className="td-num">{s.incidents}</td>
                    <td>
                      <span className="bar-cell">
                        {s.max_risk_score === null ? null : <Meter value={s.max_risk_score / 100} tone="neutral" />}
                        <span className="num">{num(s.max_risk_score, 2)}</span>
                      </span>
                    </td>
                    <td className="td-num">{s.recommendations}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </TableWrap>
        ) : null}
      </Panel>
    </div>
  );
}
