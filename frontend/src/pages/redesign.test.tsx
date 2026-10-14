/**
 * Tests for the redesigned dashboard: navigation, submission safety, error states, overview
 * headline, evaluation comparison and the visual distinction of decision controls. All data
 * comes from the real captured API fixtures; nothing here adds behaviour to the backend.
 */
import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import type { RecommendationView } from "../api/types";
import { RecommendationsPanel } from "../components/RecommendationsPanel";
import { headlineValue, isProportion, pivotMetrics } from "../lib/metrics";
import { clone, defaultRoutes, fx, mockFetch, ok, renderApp, renderWithApi, type Reply } from "../test/harness";

const A1 = fx.assessment.assessment_id;

describe("responsive navigation", () => {
  it("toggles the mobile menu and closes it after navigating", async () => {
    mockFetch(defaultRoutes());
    renderApp("/");
    const toggle = screen.getByRole("button", { name: "Menu" });
    expect(toggle).toHaveAttribute("aria-expanded", "false");
    expect(toggle).toHaveAttribute("aria-controls", "primary-nav");
    await userEvent.click(toggle);
    expect(screen.getByRole("button", { name: "Close menu" })).toHaveAttribute("aria-expanded", "true");
    expect(document.getElementById("primary-nav")).toHaveClass("is-open");
    const nav = screen.getByRole("navigation", { name: "Primary" });
    await userEvent.click(within(nav).getByRole("link", { name: "MITRE ATT&CK" }));
    expect(await screen.findByTestId("attack-version")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Menu" })).toHaveAttribute("aria-expanded", "false");
    expect(within(nav).getByRole("link", { name: "MITRE ATT&CK" })).toHaveAttribute("aria-current", "page");
  });

  it("offers a skip link and a single h1 per page", () => {
    mockFetch(defaultRoutes());
    renderApp("/");
    expect(screen.getByRole("link", { name: "Skip to content" })).toHaveAttribute("href", "#main");
    expect(screen.getAllByRole("heading", { level: 1 })).toHaveLength(1);
  });
});

describe("overview headline", () => {
  it("shows the highest API risk score with its MODEL-DERIVED label, without recomputing", async () => {
    mockFetch(defaultRoutes());
    renderApp("/");
    const headline = await screen.findByTestId("headline");
    const top = Math.max(
      ...[fx.assessment, fx.assessmentNoQuantum].flatMap((a) => a.output.incidents.map((i) => i.risk.score)),
    );
    expect(headline).toHaveTextContent(top.toFixed(2));
    expect(headline).toHaveTextContent("MODEL-DERIVED RISK SCORE");
    expect(headline).toHaveTextContent("not a probability");
    expect(screen.getByTestId("overview-stats")).toHaveTextContent("proposals only — none executed");
  });
});

describe("assessment submission safety", () => {
  it("disables the form while a request is in flight and sends exactly one POST", async () => {
    const routes = defaultRoutes();
    let release: (reply: Reply) => void = () => undefined;
    routes["POST /api/v1/assessments"] = () =>
      new Promise<Reply>((resolve) => {
        release = resolve;
      });
    const calls = mockFetch(routes);
    renderApp("/assessments");
    await userEvent.click(await screen.findByRole("button", { name: "Load SYNTHETIC example" }));
    await userEvent.click(screen.getByRole("button", { name: "Run assessment" }));
    const busyButton = await screen.findByRole("button", { name: "Assessing…" });
    expect(busyButton).toBeDisabled();
    expect(screen.getByRole("button", { name: "Load SYNTHETIC example" })).toBeDisabled();
    expect(screen.getByLabelText("AssessmentRequest JSON")).toHaveAttribute("readonly");
    expect(screen.getByText(/Further submissions are blocked/)).toBeInTheDocument();
    await userEvent.click(busyButton);
    expect(calls.filter((c) => c.method === "POST")).toHaveLength(1);
    release({ status: 201, body: fx.assessment });
    expect(await screen.findByTestId("assessment-header")).toHaveTextContent(A1);
  });

  it("explains the input format and that the example is not real traffic", async () => {
    mockFetch(defaultRoutes());
    renderApp("/assessments");
    const form = await screen.findByTestId("submit-assessment");
    expect(form).toHaveTextContent("not real network traffic");
    expect(form).toHaveTextContent("not accepted directly");
    expect(form).toHaveTextContent('"observations"');
    expect(screen.getByRole("button", { name: "Run assessment" })).toBeDisabled();
  });

  it("adds a parser hint to the local JSON error", async () => {
    mockFetch(defaultRoutes());
    renderApp("/assessments");
    await userEvent.type(await screen.findByLabelText("AssessmentRequest JSON"), "{{oops");
    await userEvent.click(screen.getByRole("button", { name: "Run assessment" }));
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("The request is not valid JSON.");
    expect(alert).toHaveTextContent("Check for a missing comma, quote or bracket.");
    expect(within(alert).queryByRole("button", { name: "Retry" })).toBeNull();
  });
});

describe("error states", () => {
  it("offers a way back instead of a pointless retry for an unknown assessment", async () => {
    mockFetch(defaultRoutes());
    renderApp("/assessments/asm-missing");
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("Not found (404)");
    expect(within(alert).queryByRole("button", { name: "Retry" })).toBeNull();
    expect(within(alert).getByRole("link", { name: "Back to assessments" })).toHaveAttribute("href", "/assessments");
  });

  it("explains how to recover when the API is unreachable", async () => {
    mockFetch({ ...defaultRoutes(), [`GET /api/v1/assessments/${A1}`]: () => "network-error" });
    renderApp(`/assessments/${A1}`);
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("API unavailable");
    expect(alert).toHaveTextContent("Start the API");
    expect(within(alert).getByRole("button", { name: "Retry" })).toBeInTheDocument();
  });

  it("shows a loading state before data arrives", async () => {
    mockFetch(defaultRoutes());
    renderApp(`/assessments/${A1}`);
    expect(screen.getAllByRole("status").some((s) => s.textContent.includes("Loading assessment"))).toBe(true);
    expect(await screen.findByTestId("assessment-header")).toBeInTheDocument();
  });
});

describe("assessment detail layout", () => {
  it("links to each incident and keeps observed and predicted steps distinct", async () => {
    mockFetch(defaultRoutes());
    renderApp(`/assessments/${A1}`);
    const jump = await screen.findByRole("navigation", { name: "Incidents in this assessment" });
    const links = within(jump).getAllByRole("link");
    const incidents = screen.getAllByTestId("incident");
    expect(links).toHaveLength(incidents.length);
    links.forEach((link, i) => {
      expect(link.getAttribute("href")).toBe(`#${incidents[i]?.id ?? ""}`);
    });
    const first = incidents[0] as HTMLElement;
    for (const node of within(first).getAllByTestId("step-predicted")) {
      expect(node).toHaveTextContent("Not observed, not confirmed");
      expect(node).not.toHaveClass("timeline__node--observed");
    }
    expect(within(first).getByTestId("quantum-panel")).toHaveTextContent("EXPERIMENTAL");
  });
});

describe("decision controls are records, never actions", () => {
  it("gives acknowledge, approve and reject distinct dashed record styles, none primary", () => {
    const views: RecommendationView[] = clone(fx.recommendationsNoQuantum).slice(0, 1);
    renderWithApi(<RecommendationsPanel assessmentId="a" views={views} onRecorded={vi.fn()} />);
    const ack = screen.getByRole("button", { name: "Record acknowledgement" });
    const approve = screen.getByRole("button", { name: "Record approval (does not execute)" });
    const reject = screen.getByRole("button", { name: "Record rejection" });
    expect(ack).toHaveClass("btn--record", "btn--ack");
    expect(approve).toHaveClass("btn--record", "btn--approve");
    expect(reject).toHaveClass("btn--record", "btn--reject");
    for (const b of [ack, approve, reject]) expect(b).not.toHaveClass("btn--primary");
    expect(screen.getByTestId("recommendation")).toHaveTextContent("Approval never executes the proposal");
  });
});

describe("evaluation comparison", () => {
  it("pivots stored metrics and shows CIs only where stored", async () => {
    mockFetch(defaultRoutes());
    renderApp("/evaluation");
    const table = await screen.findByTestId("runs-table");
    const run = fx.runs[0];
    if (!run) throw new Error("fixture missing");
    await userEvent.click(within(table).getAllByRole("button")[0] as HTMLElement);
    const metrics = await screen.findByTestId("run-metrics");
    expect(within(metrics).getByRole("region", { name: "Metric comparison" })).toBeInTheDocument();
    const hasCi = Object.keys(run.metrics).some((k) => k.endsWith(".ci_low"));
    expect(metrics.textContent.includes("CI [")).toBe(hasCi);
    expect(screen.getByRole("heading", { name: "Current serving versions" })).toBeInTheDocument();
  });
});

describe("metric pivot (display-only)", () => {
  it("groups keys into rows and metric columns and attaches stored statistics", () => {
    const pivot = pivotMetrics([
      ["document.B1.macro.top1", 0.4],
      ["document.B1.macro.top1.ci_low", 0.3],
      ["document.B1.macro.top1.ci_high", 0.5],
      ["document.B1.macro.log_loss", 3.2],
      ["e2.n100.d4.zz_qsvm.pr_auc.mean", 0.7],
      ["checks_passed", 9],
    ]);
    expect(pivot.rows).toEqual(["document.B1.macro", "e2.n100.d4.zz_qsvm", "(run)"]);
    expect(pivot.columns).toEqual(["top1", "log_loss", "pr_auc", "checks_passed"]);
    expect(pivot.cells.get("document.B1.macro")?.get("top1")).toEqual({ value: 0.4, ci_low: 0.3, ci_high: 0.5 });
    expect(headlineValue(pivot.cells.get("e2.n100.d4.zz_qsvm")?.get("pr_auc"))).toBe(0.7);
    expect(headlineValue(pivot.cells.get("(run)")?.get("checks_passed"))).toBe(9);
  });

  it("only treats bounded proportions as bars (never losses or paired differences)", () => {
    expect(isProportion("document.B1.macro", "top1", 0.4)).toBe(true);
    expect(isProportion("document.B1.macro", "log_loss", 0.4)).toBe(false);
    expect(isProportion("e2.paired:zz_qsvm-rbf_svm", "pr_auc", 0.1)).toBe(false);
    expect(isProportion("full.rf", "roc_auc", 1.2)).toBe(false);
  });
});

describe("overview empty headline", () => {
  it("points first-time users to the synthetic example", async () => {
    mockFetch({ ...defaultRoutes(), "GET /api/v1/assessments": ok([]) });
    renderApp("/");
    expect(await screen.findByText(/highest model-derived risk appears here/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Run the SYNTHETIC example →" })).toHaveAttribute("href", "/assessments");
    await waitFor(() => {
      expect(screen.queryByTestId("headline")).toBeNull();
    });
  });
});
