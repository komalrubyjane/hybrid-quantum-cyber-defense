import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import type { RecommendationView } from "../api/types";
import { clone, fx, mockFetch, renderWithApi } from "../test/harness";
import { AttackChainTimeline } from "./AttackChainTimeline";
import { PredictionPanel } from "./PredictionPanel";
import { QuantumPanel } from "./QuantumPanel";
import { RecommendationsPanel } from "./RecommendationsPanel";
import { RiskPanel } from "./RiskPanel";

const mainIncident = () => {
  const incident = fx.assessment.output.incidents[0];
  if (!incident) throw new Error("fixture missing");
  return incident;
};

describe("attack chain: observed vs predicted", () => {
  it("renders observed steps then visually distinct predicted steps", () => {
    const incident = mainIncident();
    renderWithApi(<AttackChainTimeline incident={incident} />);
    const observed = screen.getAllByTestId("step-observed");
    const predicted = screen.getAllByTestId("step-predicted");
    expect(observed).toHaveLength(incident.chain.chain.steps.length);
    expect(predicted).toHaveLength(incident.prediction.result.paths?.[0]?.technique_ids.length ?? 0);
    for (const node of observed) {
      expect(node).toHaveClass("timeline__node--observed");
      expect(node).not.toHaveTextContent("PREDICTED");
    }
    for (const node of predicted) {
      expect(node).toHaveClass("timeline__node--predicted");
      expect(node).toHaveTextContent("Not observed, not confirmed");
      expect(node).not.toHaveTextContent(/OBSERVED/);
    }
    // Observed details come from the API: technique, tactic, timestamp, confidence, source.
    const first = observed[0] as HTMLElement;
    expect(first).toHaveTextContent("T1190");
    expect(first).toHaveTextContent("TA0001");
    expect(first).toHaveTextContent("2026-01-15 09:00:00Z");
    expect(first).toHaveTextContent("90.0%");
    expect(first).toHaveTextContent("SYNTHETIC_SCENARIO:synthetic-multistage@1");
    // Order: every observed node precedes every predicted node.
    const all = screen.getAllByTestId(/step-(observed|predicted)/);
    expect(all.indexOf(predicted[0] as HTMLElement)).toBe(observed.length);
    expect(screen.getByTestId("path-score")).toHaveTextContent("not calibrated");
  });

  it("links IDs to the public ATT&CK site without fetching", () => {
    renderWithApi(<AttackChainTimeline incident={mainIncident()} />);
    const link = screen.getAllByRole("link", { name: "T1059.004" })[0];
    expect(link).toHaveAttribute("href", "https://attack.mitre.org/techniques/T1059/004/");
    expect(link).toHaveAttribute("rel", "noopener noreferrer");
  });

  it("handles a chain without predicted paths", () => {
    const incident = clone(mainIncident());
    incident.prediction.result.paths = [];
    renderWithApi(<AttackChainTimeline incident={incident} />);
    expect(screen.queryAllByTestId("step-predicted")).toHaveLength(0);
    expect(screen.getByText("No predicted path returned.")).toBeInTheDocument();
  });
});

describe("prediction panel", () => {
  it("shows next-step probabilities and path scores as returned", () => {
    const incident = mainIncident();
    renderWithApi(<PredictionPanel incident={incident} />);
    const panel = screen.getByTestId("prediction-panel");
    expect(panel).toHaveTextContent(incident.prediction.next_step_semantics);
    expect(panel).toHaveTextContent(incident.prediction.path_score_semantics);
    expect(panel).toHaveTextContent("HYBRID");
    const top = incident.prediction.result.next_step?.[0];
    expect(top && panel.textContent).toContain(`${((top?.probability ?? 0) * 100).toFixed(2)}%`);
  });
});

describe("risk panel", () => {
  it("displays the API's model-derived score and factors without recomputing", () => {
    const risk = mainIncident().risk;
    renderWithApi(<RiskPanel risk={risk} />);
    const panel = screen.getByTestId("risk-panel");
    expect(panel).toHaveTextContent("MODEL-DERIVED RISK SCORE");
    expect(panel).toHaveTextContent(risk.score.toFixed(2));
    expect(panel).toHaveTextContent("CRITICAL");
    expect(panel).toHaveTextContent("NEEDS ADDITIONAL EVIDENCE");
    expect(panel).toHaveTextContent("not a probability");
    const rows = within(screen.getByTestId("risk-components")).getAllByRole("row").slice(1);
    expect(rows).toHaveLength(risk.components.length);
    risk.components.forEach((c, i) => {
      expect(rows[i]).toHaveTextContent(c.name);
      expect(rows[i]).toHaveTextContent(c.contribution.toFixed(2));
    });
    const quantumRow = rows.find((r) => r.textContent.includes("quantum_second_opinion"));
    expect(quantumRow).toHaveTextContent("0.00");
  });

  it("handles missing optional fields", () => {
    const risk = clone(mainIncident().risk);
    risk.evidence_status = null;
    risk.affected_assets = [];
    risk.uncertainty = null;
    risk.quantum_disagreement = false;
    renderWithApi(<RiskPanel risk={risk} />);
    expect(screen.getByTestId("risk-panel")).toHaveTextContent("no detector evidence");
  });
});

describe("quantum second opinion", () => {
  it("shows agreement, disagreement and that the classical verdict is kept", () => {
    const detections = mainIncident().chain.detections ?? [];
    renderWithApi(<QuantumPanel detections={detections} />);
    const panel = screen.getByTestId("quantum-panel");
    expect(panel).toHaveTextContent("never overrides the classical verdict");
    expect(panel).toHaveTextContent("No quantum advantage is claimed");
    expect(panel).not.toHaveTextContent(/quantum advantage (?!is claimed)/i);
    expect(screen.getAllByTestId("detection-row")).toHaveLength(detections.length);
    expect(panel).toHaveTextContent("DISAGREES (classical verdict kept)");
    expect(panel).toHaveTextContent("CORROBORATED BY INDEPENDENT EVIDENCE");
    expect(panel).toHaveTextContent("NEEDS ADDITIONAL EVIDENCE");
    expect(panel).toHaveTextContent("not triggered");
    expect(panel).toHaveTextContent("synthetic fixture score");
  });

  it("shows latency when returned and an empty state", () => {
    const detections = clone(mainIncident().chain.detections ?? []);
    const withLatency = detections.find((d) => d.quantum?.gate_triggered);
    if (withLatency?.quantum) withLatency.quantum.latency_ms = 1.25;
    const { unmount } = renderWithApi(<QuantumPanel detections={detections} />);
    expect(screen.getByTestId("quantum-panel")).toHaveTextContent("1.25 ms");
    unmount();
    renderWithApi(<QuantumPanel detections={[]} />);
    expect(screen.getByText("No detector evidence for this chain.")).toBeInTheDocument();
  });
});

// Imperative action verbs that must never start a control label.
const FORBIDDEN_BUTTON = /^(execute|run|apply|isolate|block|disable|reset|kill|deploy|enforce)\b|firewall|shell|command/i;

function noQuantumViews(): RecommendationView[] {
  return clone(fx.recommendationsNoQuantum);
}

describe("adaptive defense panel", () => {
  it("presents proposals, never execution controls", () => {
    const views = noQuantumViews();
    renderWithApi(<RecommendationsPanel assessmentId="a" views={views} onRecorded={vi.fn()} />);
    expect(screen.getByTestId("recommendation-only-notice")).toHaveTextContent(
      "Recommendation only — no action has been executed.",
    );
    const cards = screen.getAllByTestId("recommendation");
    expect(cards).toHaveLength(views.length);
    for (const card of cards) {
      expect(card).toHaveTextContent("Human approval required: true");
      expect(card).toHaveTextContent("executed: false");
      expect(card).toHaveTextContent("PROPOSAL · PROPOSED");
      expect(card).toHaveTextContent("Recommendation only — no action has been executed.");
    }
    const buttons = screen.getAllByRole("button");
    expect(buttons.length).toBeGreaterThan(0);
    for (const b of buttons) {
      expect(b.textContent).toMatch(/^Record (acknowledgement|approval \(does not execute\)|rejection)$/);
      expect(b.textContent).not.toMatch(FORBIDDEN_BUTTON);
    }
    expect(screen.getAllByText("Consider isolating the affected host")).toHaveLength(1);
    expect(screen.getAllByText(/two-step workflow enforced by the server/).length).toBeGreaterThan(0);
  });

  it("shows decision history with executed: false and an empty state", () => {
    const views = noQuantumViews();
    const first = views[0];
    if (first) {
      first.decisions = [clone(fx.acknowledged), clone(fx.approved)];
      first.latest_decision = "APPROVED";
    }
    const { unmount } = renderWithApi(<RecommendationsPanel assessmentId="a" views={views} onRecorded={vi.fn()} />);
    const history = screen.getAllByTestId("decision-history")[0] as HTMLElement;
    expect(within(history).getAllByText("executed: false")).toHaveLength(2);
    unmount();
    renderWithApi(<RecommendationsPanel assessmentId="a" views={[]} onRecorded={vi.fn()} />);
    expect(screen.getByText("No recommendations for this incident.")).toBeInTheDocument();
  });
});

describe("analyst decision workflow", () => {
  function isolateView(): RecommendationView {
    const view = noQuantumViews().find((v) => v.recommendation.action === "isolate_affected_host");
    if (!view) throw new Error("fixture missing");
    return view;
  }

  it("requires an analyst name before calling the API", async () => {
    const calls = mockFetch({});
    renderWithApi(<RecommendationsPanel assessmentId="a" views={[isolateView()]} onRecorded={vi.fn()} />);
    await userEvent.click(screen.getByRole("button", { name: "Record acknowledgement" }));
    expect(screen.getByRole("alert")).toHaveTextContent("Enter the analyst name");
    expect(calls).toHaveLength(0);
  });

  it("surfaces the server's 409 two-step rule, then records acknowledge and approve", async () => {
    const view = isolateView();
    const path = `POST /api/v1/assessments/asm-1/recommendations/${encodeURIComponent(view.recommendation.recommendation_id)}/decisions`;
    let acknowledged = false;
    const calls = mockFetch({
      [path]: (_url, init) => {
        const body = JSON.parse(typeof init?.body === "string" ? init.body : "{}") as { decision: string };
        if (body.decision === "APPROVED" && !acknowledged) return fx.error409;
        if (body.decision === "ACKNOWLEDGED") acknowledged = true;
        return { status: 201, body: body.decision === "APPROVED" ? fx.approved : fx.acknowledged };
      },
    });
    const onRecorded = vi.fn();
    renderWithApi(<RecommendationsPanel assessmentId="asm-1" views={[view]} onRecorded={onRecorded} />);
    await userEvent.type(screen.getByLabelText("Analyst"), "analyst-1");
    await userEvent.click(screen.getByRole("button", { name: "Record approval (does not execute)" }));
    const conflict = await screen.findByRole("alert");
    expect(conflict).toHaveTextContent("Workflow conflict (409)");
    expect(conflict).toHaveTextContent("must be ACKNOWLEDGED before APPROVED");
    expect(onRecorded).not.toHaveBeenCalled();

    await userEvent.click(screen.getByRole("button", { name: "Record acknowledgement" }));
    await waitFor(() => {
      expect(screen.getByRole("status")).toHaveTextContent("Recorded ACKNOWLEDGED by analyst-1");
    });
    expect(screen.getByRole("status")).toHaveTextContent("executed: false");
    await userEvent.click(screen.getByRole("button", { name: "Record approval (does not execute)" }));
    await waitFor(() => {
      expect(screen.getByRole("status")).toHaveTextContent("Recorded APPROVED");
    });
    expect(onRecorded).toHaveBeenCalledTimes(2);
    expect(calls.map((c) => (c.body as { decision: string }).decision)).toEqual(["APPROVED", "ACKNOWLEDGED", "APPROVED"]);
    expect(calls.every((c) => c.url.endsWith("/decisions"))).toBe(true);
  });

  it("records a rejection with a note and shows other API errors", async () => {
    const view = isolateView();
    const path = `POST /api/v1/assessments/asm-1/recommendations/${encodeURIComponent(view.recommendation.recommendation_id)}/decisions`;
    let calls = mockFetch({ [path]: () => ({ status: 201, body: { ...fx.acknowledged, decision: "REJECTED" } }) });
    const { unmount } = renderWithApi(<RecommendationsPanel assessmentId="asm-1" views={[view]} onRecorded={vi.fn()} />);
    await userEvent.type(screen.getByLabelText("Analyst"), "a2");
    await userEvent.type(screen.getByLabelText("Note (optional)"), "false positive");
    await userEvent.click(screen.getByRole("button", { name: "Record rejection" }));
    await screen.findByText(/Recorded REJECTED/);
    expect(calls[0]?.body).toEqual({ decision: "REJECTED", analyst: "a2", note: "false positive" });
    unmount();
    calls = mockFetch({ [path]: () => ({ status: 503, body: { detail: "unavailable" } }) });
    renderWithApi(<RecommendationsPanel assessmentId="asm-1" views={[view]} onRecorded={vi.fn()} />);
    await userEvent.type(screen.getByLabelText("Analyst"), "a3");
    await userEvent.click(screen.getByRole("button", { name: "Record acknowledgement" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("unavailable");
    expect(calls).toHaveLength(1);
  });
});
