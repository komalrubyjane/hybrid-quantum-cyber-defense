import { useState } from "react";

import { ApiError, messageOf } from "../api/client";
import { useApi } from "../api/useApi";
import type { Decision, DecisionRecord, RecommendationView } from "../api/types";
import { when } from "../lib/format";

/**
 * Records an analyst decision through the API. RECORDING ONLY: approving a recommendation
 * does not execute it, and nothing in the dashboard can execute anything. The two-step
 * acknowledgement for HIGH-disruption recommendations is enforced by the SERVER (409); the
 * dashboard only explains it and shows the server's answer.
 */
export function DecisionControls({
  assessmentId,
  view,
  onRecorded,
}: {
  assessmentId: string;
  view: RecommendationView;
  onRecorded: (record: DecisionRecord) => void;
}) {
  const api = useApi();
  const rec = view.recommendation;
  const [analyst, setAnalyst] = useState("");
  const [note, setNote] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<ApiError | null>(null);
  const [last, setLast] = useState<DecisionRecord | null>(null);
  const highDisruption = rec.disruption === "HIGH";
  const acknowledged = view.decisions.some((d) => d.decision === "ACKNOWLEDGED");

  async function record(decision: Decision) {
    setError(null);
    if (!analyst.trim()) {
      setError(new ApiError("validation", "Enter the analyst name before recording a decision."));
      return;
    }
    setBusy(true);
    try {
      const result = await api.recordDecision(assessmentId, rec.recommendation_id, decision, analyst.trim(), note.trim() || undefined);
      setLast(result);
      onRecorded(result);
    } catch (e) {
      setError(e instanceof ApiError ? e : new ApiError("http", messageOf(e)));
    } finally {
      setBusy(false);
    }
  }

  const idBase = `dc-${rec.recommendation_id}`;
  return (
    <div className="decision" data-testid="decision-controls">
      <p className="decision__title">
        Analyst decision <span className="muted">(recorded for audit — never executed)</span>
      </p>
      {highDisruption ? (
        <p className="notice notice--two-step small" data-testid="two-step-notice">
          HIGH-disruption proposal: an acknowledgement must be recorded before an approval (two-step
          workflow enforced by the server). {acknowledged ? "Acknowledgement on record." : "No acknowledgement yet."}
        </p>
      ) : null}
      <div className="decision__fields">
        <div className="field">
          <label htmlFor={`${idBase}-analyst`}>Analyst</label>
          <input
            id={`${idBase}-analyst`}
            value={analyst}
            maxLength={200}
            autoComplete="off"
            placeholder="Your name (not authenticated)"
            onChange={(e) => {
              setAnalyst(e.target.value);
            }}
          />
        </div>
        <div className="field">
          <label htmlFor={`${idBase}-note`}>Note (optional)</label>
          <input
            id={`${idBase}-note`}
            value={note}
            maxLength={2000}
            autoComplete="off"
            onChange={(e) => {
              setNote(e.target.value);
            }}
          />
        </div>
      </div>
      <div className="decision__buttons" role="group" aria-label="Record analyst decision">
        <button type="button" className="btn btn--record btn--ack" disabled={busy} onClick={() => void record("ACKNOWLEDGED")}>
          Record acknowledgement
        </button>
        <button type="button" className="btn btn--record btn--approve" disabled={busy} onClick={() => void record("APPROVED")}>
          Record approval (does not execute)
        </button>
        <button type="button" className="btn btn--record btn--reject" disabled={busy} onClick={() => void record("REJECTED")}>
          Record rejection
        </button>
      </div>
      <p className="micro muted">
        These buttons only add an entry to the audit log. Approval never executes the proposal; any action is taken by
        people outside this system.
      </p>
      {error ? (
        <p className={`decision__error decision__error--${error.kind}`} role="alert">
          {error.kind === "conflict" ? "Workflow conflict (409): " : ""}
          {error.message}
        </p>
      ) : null}
      {last ? (
        <p className="decision__ok" role="status">
          Recorded {last.decision} by {last.analyst} at {when(last.recorded_at)} — <code>executed: false</code>
        </p>
      ) : null}
    </div>
  );
}
