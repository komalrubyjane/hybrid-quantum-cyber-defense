/**
 * OPT-IN live validation (Milestone 10): the dashboard's own API client, boundary validators and
 * pages against a RUNNING API. Skipped unless HQC_LIVE_API_URL is set, e.g.
 *   HQC_DB_PATH=/tmp/hqc-e2e.sqlite3 uvicorn hqc.api.server:create_api_app --factory --port 8000
 *   HQC_LIVE_API_URL=http://127.0.0.1:8000 npx vitest run src/test/live-api.test.tsx
 * Use a scratch HQC_DB_PATH: assessments and decisions are append-only.
 */
import { render, screen, within } from "@testing-library/react";
import { MemoryRouter } from "react-router";
import { describe, expect, it } from "vitest";

import { App } from "../App";
import { ApiClient } from "../api/client";
import { createApi } from "../api/endpoints";
import request from "../fixtures/synthetic-assessment-request.json";

const LIVE = process.env.HQC_LIVE_API_URL;

describe.skipIf(!LIVE)("live API end-to-end (opt-in)", () => {
  const api = createApi(new ApiClient(LIVE ?? ""));

  it("submits, renders, and records decisions without executing anything", async () => {
    expect((await api.meta()).defense_mode).toBe("recommendation-only");
    const record = await api.createAssessment(request);
    const main = record.output.incidents[0];
    expect(main?.chain.chain.steps.every((s) => s.provenance === "OBSERVED")).toBe(true);
    expect(main?.risk.label).toBe("MODEL-DERIVED RISK SCORE");

    render(
      <MemoryRouter initialEntries={[`/assessments/${record.assessment_id}`]}>
        <App api={api} />
      </MemoryRouter>,
    );
    const incidents = await screen.findAllByTestId("incident", {}, { timeout: 10000 });
    const first = incidents[0] as HTMLElement;
    expect(within(first).getAllByTestId("step-observed")).toHaveLength(6);
    for (const node of within(first).getAllByTestId("step-predicted")) {
      expect(node).toHaveTextContent("Not observed, not confirmed");
    }
    expect(within(first).getByTestId("risk-panel")).toHaveTextContent("MODEL-DERIVED RISK SCORE");
    expect(screen.getAllByText("Recommendation only — no action has been executed.").length).toBeGreaterThan(0);

    const views = await api.recommendations(record.assessment_id);
    const view = views[0];
    if (!view) throw new Error("no recommendation returned");
    expect(view.recommendation.status).toBe("PROPOSED");
    const ack = await api.recordDecision(record.assessment_id, view.recommendation.recommendation_id, "ACKNOWLEDGED", "live-validator");
    const rej = await api.recordDecision(record.assessment_id, view.recommendation.recommendation_id, "REJECTED", "live-validator");
    expect([ack.executed, rej.executed]).toEqual([false, false]);
    const after = await api.recommendations(record.assessment_id);
    expect(after.find((v) => v.recommendation.recommendation_id === view.recommendation.recommendation_id)?.recommendation.status).toBe("PROPOSED");
  }, 30000);
});
