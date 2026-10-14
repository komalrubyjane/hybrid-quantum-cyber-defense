import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";

import { BASE, clone, defaultRoutes, fx, mockFetch, ok, renderApp } from "../test/harness";

const A1 = fx.assessment.assessment_id;
const A2 = fx.assessmentNoQuantum.assessment_id;

describe("overview", () => {
  it("shows health, versions, runs, assessments, risk distribution and decisions", async () => {
    const routes = defaultRoutes();
    const views = clone(fx.recommendationsNoQuantum);
    if (views[0]) views[0].decisions = [clone(fx.acknowledged)];
    routes[`GET /api/v1/assessments/${A2}/recommendations`] = ok(views);
    mockFetch(routes);
    renderApp("/");
    expect(screen.getAllByRole("status").length).toBeGreaterThan(0); // loading states
    expect(await screen.findByTestId("health")).toHaveTextContent("recommendation-only");
    const versions = await screen.findByTestId("versions");
    expect(versions).toHaveTextContent(fx.meta.attack_version);
    expect(versions).toHaveTextContent(fx.meta.vocabulary_version);
    expect(versions).toHaveTextContent("risk-policy-v1");
    expect(versions).toHaveTextContent("alpha=0.7");
    const distribution = await screen.findByTestId("risk-distribution");
    const rows = within(distribution).getAllByRole("listitem");
    expect(rows.map((r) => r.textContent)).toEqual(["LOW0", "MEDIUM2", "HIGH0", "CRITICAL2"]);
    expect(await screen.findByTestId("recent-decisions")).toHaveTextContent("ACKNOWLEDGED");
    expect(screen.getByTestId("recent-decisions")).toHaveTextContent("executed: false");
    expect(await screen.findByTestId("runs-overview")).toHaveTextContent(fx.runs[0]?.run_id ?? "");
    expect(screen.getByTestId("assessment-summaries")).toHaveTextContent(A1);
    expect(screen.getByText(/API: ok/)).toBeInTheDocument();
  });

  it("shows API-unavailable and empty states", async () => {
    mockFetch({
      "GET /health": () => "network-error",
      "GET /api/v1/meta": () => "network-error",
      "GET /api/v1/runs": ok([]),
      "GET /api/v1/assessments": ok([]),
    });
    renderApp("/");
    expect((await screen.findAllByText("API unavailable")).length).toBeGreaterThan(0);
    expect(await screen.findByText("No stored evaluation runs.")).toBeInTheDocument();
    expect(await screen.findByText(/No assessments yet/)).toBeInTheDocument();
    expect(screen.getByText("No incidents.")).toBeInTheDocument();
    expect(screen.getByText("No analyst decisions recorded.")).toBeInTheDocument();
    expect(screen.getByText(/API: unreachable/)).toBeInTheDocument();
  });

  it("shows the 503 missing-artifacts state and retries", async () => {
    const routes = defaultRoutes();
    routes["GET /api/v1/meta"] = () => ({ status: 503, body: { detail: "Intelligence services unavailable: the local ATT&CK knowledge base or stored prediction artifacts are missing or invalid (see docs/API.md)." } });
    const calls = mockFetch(routes);
    renderApp("/");
    expect(await screen.findByText("Intelligence services unavailable (503)")).toBeInTheDocument();
    const before = calls.filter((c) => c.url.endsWith("/api/v1/meta")).length;
    await userEvent.click(screen.getAllByRole("button", { name: "Retry" })[0] as HTMLElement);
    await waitFor(() => {
      expect(calls.filter((c) => c.url.endsWith("/api/v1/meta")).length).toBe(before + 1);
    });
  });
});

describe("assessment detail", () => {
  it("renders incidents with chain, prediction, risk, quantum and recommendations", async () => {
    mockFetch(defaultRoutes());
    renderApp(`/assessments/${A1}`);
    expect(await screen.findByTestId("assessment-header")).toHaveTextContent(A1);
    const incidents = screen.getAllByTestId("incident");
    expect(incidents).toHaveLength(2);
    const main = incidents[0] as HTMLElement;
    expect(main).toHaveTextContent("chain-syn-ms-e01");
    expect(main).toHaveTextContent("NEEDS ADDITIONAL EVIDENCE");
    expect(main).toHaveTextContent("SYNTHETIC");
    expect(within(main).getAllByTestId("step-observed")).toHaveLength(6);
    expect(within(main).getAllByTestId("step-predicted")).toHaveLength(3);
    expect(within(main).getByTestId("risk-panel")).toHaveTextContent("76.45");
    expect(within(main).getByTestId("quantum-panel")).toHaveTextContent("DISAGREES");
    // Disruptive proposals are withheld by the backend while evidence is needed.
    const recs = within(main).getAllByTestId("recommendation");
    expect(recs.map((r) => r.querySelector("code")?.textContent)).toEqual([
      "escalate_severity",
      "restrict_communication",
      "collect_additional_evidence",
      "increase_monitoring",
    ]);
    expect(screen.getAllByText("Recommendation only — no action has been executed.").length).toBeGreaterThan(1);
    expect(screen.getByTestId("assessment-header")).toHaveTextContent("syn-ms-e02");
  });

  it("refreshes the decision history from the API after recording", async () => {
    const routes = defaultRoutes();
    const views = clone(fx.recommendationsNoQuantum);
    const isolate = views.find((v) => v.recommendation.action === "isolate_affected_host");
    if (!isolate) throw new Error("fixture missing");
    const rid = encodeURIComponent(isolate.recommendation.recommendation_id);
    let recorded = false;
    routes[`GET /api/v1/assessments/${A2}/recommendations`] = () => ({
      status: 200,
      body: recorded
        ? views.map((v) => (v === isolate ? { ...v, decisions: [fx.acknowledged], latest_decision: "ACKNOWLEDGED" } : v))
        : views,
    });
    routes[`POST /api/v1/assessments/${A2}/recommendations/${rid}/decisions`] = () => {
      recorded = true;
      return { status: 201, body: fx.acknowledged };
    };
    mockFetch(routes);
    renderApp(`/assessments/${A2}`);
    const card = (await screen.findAllByTestId("recommendation")).find((c) => c.textContent.includes("isolate_affected_host"));
    if (!card) throw new Error("card missing");
    await userEvent.type(within(card).getByLabelText("Analyst"), "analyst-1");
    await userEvent.click(within(card).getByRole("button", { name: "Record acknowledgement" }));
    await waitFor(() => {
      expect(within(card).getByTestId("decision-history")).toHaveTextContent("ACKNOWLEDGED");
    });
    expect(within(card).getByTestId("decision-history")).toHaveTextContent("executed: false");
    expect(card).toHaveTextContent("Latest decisionACKNOWLEDGED");
  });

  it("shows 404 for an unknown assessment", async () => {
    mockFetch(defaultRoutes());
    renderApp("/assessments/asm-missing");
    expect(await screen.findByText("Not found (404)")).toBeInTheDocument();
  });
});

describe("assessment submission", () => {
  it("loads the synthetic example, submits it and navigates to the result", async () => {
    const routes = defaultRoutes();
    routes["POST /api/v1/assessments"] = () => ({ status: 201, body: fx.assessment });
    const calls = mockFetch(routes);
    renderApp("/assessments");
    expect(await screen.findByTestId("assessment-list")).toHaveTextContent(A1);
    await userEvent.click(screen.getByRole("button", { name: "Load SYNTHETIC example" }));
    const textarea = screen.getByLabelText("AssessmentRequest JSON");
    expect((textarea as HTMLTextAreaElement).value).toContain("syn-ms-e01");
    await userEvent.click(screen.getByRole("button", { name: "Run assessment" }));
    expect(await screen.findByTestId("assessment-header")).toHaveTextContent(A1);
    const post = calls.find((c) => c.method === "POST");
    expect((post?.body as { observations: unknown[] }).observations).toHaveLength(8);
  });

  it("rejects invalid JSON locally and shows the API's 422 cleanly", async () => {
    const routes = defaultRoutes();
    routes["POST /api/v1/assessments"] = () => fx.error422;
    const calls = mockFetch(routes);
    renderApp("/assessments");
    const textarea = await screen.findByLabelText("AssessmentRequest JSON");
    await userEvent.type(textarea, "not json");
    await userEvent.click(screen.getByRole("button", { name: "Run assessment" }));
    expect(await screen.findByText("The request is not valid JSON.")).toBeInTheDocument();
    expect(calls.some((c) => c.method === "POST")).toBe(false);
    await userEvent.clear(textarea);
    await userEvent.click(textarea);
    await userEvent.paste('{"observations": []}');
    await userEvent.click(screen.getByRole("button", { name: "Run assessment" }));
    const alert = await screen.findByText("Request rejected (422)");
    expect(alert.parentElement).toHaveTextContent("observations: List should have at least 1 item");
  });

  it("shows the empty state", async () => {
    mockFetch({ ...defaultRoutes(), "GET /api/v1/assessments": ok([]) });
    renderApp("/assessments");
    expect(await screen.findByText("No assessments stored yet.")).toBeInTheDocument();
  });
});

describe("MITRE and evaluation views", () => {
  it("lists techniques and tactics from API data only", async () => {
    const calls = mockFetch(defaultRoutes());
    renderApp("/mitre");
    expect(await screen.findByTestId("attack-version")).toHaveTextContent("19.2");
    const list = await screen.findByTestId("technique-list");
    for (const id of ["T1190", "T1059.004", "T1098.004", "T1003.008", "T1021.004", "T1041", "T1110.001"]) {
      expect(list).toHaveTextContent(id);
    }
    expect(screen.getByTestId("tactic-list")).toHaveTextContent("TA0010");
    expect(calls.every((c) => c.url.startsWith(`${BASE}/`))).toBe(true);
  });

  it("shows run summaries and metrics without internal paths", async () => {
    mockFetch(defaultRoutes());
    renderApp("/evaluation");
    const table = await screen.findByTestId("runs-table");
    expect(within(table).getAllByRole("row")).toHaveLength(fx.runs.length + 1);
    const run = fx.runs[0];
    if (!run) throw new Error("fixture missing");
    const button = within(table).getAllByRole("button")[0] as HTMLElement;
    await userEvent.click(button);
    const metrics = await screen.findByTestId("run-metrics");
    const first = Object.keys(run.metrics).sort()[0] ?? "";
    expect(metrics).toHaveTextContent(first);
    await userEvent.type(screen.getByLabelText(/Filter/), "zzz-no-match");
    expect(screen.getByText("No metrics match.")).toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(/\/Users\/|\/home\/|run_dir|model_configuration/);
  });

  it("renders a not-found page", () => {
    mockFetch(defaultRoutes());
    renderApp("/no-such-page");
    expect(screen.getByText("Page not found")).toBeInTheDocument();
  });
});
