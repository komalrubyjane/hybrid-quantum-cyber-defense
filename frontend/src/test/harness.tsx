/**
 * Test harness. Fixtures under ./fixtures are REAL responses of the Milestone 8 API captured by
 * `scripts/export_frontend_contract.py --responses` (in-memory API state), so tests exercise the
 * actual response schemas.
 */
import { render } from "@testing-library/react";
import type { ReactElement } from "react";
import { MemoryRouter } from "react-router";
import { vi } from "vitest";

import { App } from "../App";
import { ApiClient } from "../api/client";
import { ApiProvider } from "../api/context";
import { createApi, type Api } from "../api/endpoints";
import type {
  AssessmentRecord,
  AssessmentSummary,
  DecisionRecord,
  HealthResponse,
  MetaResponse,
  RecommendationView,
  RunSummary,
} from "../api/types";
import assessmentJson from "./fixtures/assessment.json";
import assessmentNoQuantumJson from "./fixtures/assessment-no-quantum.json";
import assessmentsJson from "./fixtures/assessments.json";
import ackJson from "./fixtures/decision-acknowledged.json";
import approvedJson from "./fixtures/decision-approved.json";
import error404Json from "./fixtures/error-404.json";
import error409Json from "./fixtures/error-409.json";
import error422Json from "./fixtures/error-422.json";
import healthJson from "./fixtures/health.json";
import metaJson from "./fixtures/meta.json";
import recommendationsJson from "./fixtures/recommendations.json";
import recommendationsNoQuantumJson from "./fixtures/recommendations-no-quantum.json";
import runsJson from "./fixtures/runs.json";

export const BASE = "http://api.test";

// JSON imports are widened by TypeScript; the casts below are checked by validate.test.ts.
export const fx = {
  health: healthJson as unknown as HealthResponse,
  meta: metaJson as unknown as MetaResponse,
  runs: runsJson as unknown as RunSummary[],
  assessment: assessmentJson as unknown as AssessmentRecord,
  assessmentNoQuantum: assessmentNoQuantumJson as unknown as AssessmentRecord,
  assessments: assessmentsJson as unknown as AssessmentSummary[],
  recommendations: recommendationsJson as unknown as RecommendationView[],
  recommendationsNoQuantum: recommendationsNoQuantumJson as unknown as RecommendationView[],
  acknowledged: ackJson as unknown as DecisionRecord,
  approved: approvedJson as unknown as DecisionRecord,
  error404: error404Json,
  error409: error409Json,
  error422: error422Json,
};

export function clone<T>(value: T): T {
  return structuredClone(value);
}

export interface Reply {
  status: number;
  body: unknown;
}
export type Handler = (url: URL, init: RequestInit | undefined) => Reply | Promise<Reply> | "network-error";

export interface MockCall {
  method: string;
  url: string;
  body: unknown;
}

/** Stub global fetch. Handlers are matched by "METHOD /path" (query ignored); unknown routes 404. */
export function mockFetch(routes: Record<string, Handler>): MockCall[] {
  const calls: MockCall[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: string | URL, init?: RequestInit) => {
      const url = new URL(String(input));
      const method = init?.method ?? "GET";
      const body: unknown = typeof init?.body === "string" ? JSON.parse(init.body) : null;
      calls.push({ method, url: url.toString(), body });
      const handler = routes[`${method} ${url.pathname}`];
      const reply = handler ? await handler(url, init) : { status: 404, body: { detail: "Not Found" } };
      if (reply === "network-error") throw new TypeError("Failed to fetch");
      return new Response(JSON.stringify(reply.body), {
        status: reply.status,
        headers: { "Content-Type": "application/json" },
      });
    }),
  );
  return calls;
}

export const ok = (body: unknown): Handler => () => ({ status: 200, body });

/** Routes for a healthy API with the captured fixtures. */
export function defaultRoutes(): Record<string, Handler> {
  const a1 = fx.assessment.assessment_id;
  const a2 = fx.assessmentNoQuantum.assessment_id;
  return {
    "GET /health": ok(fx.health),
    "GET /api/v1/meta": ok(fx.meta),
    "GET /api/v1/runs": ok(fx.runs),
    "GET /api/v1/assessments": ok(fx.assessments),
    [`GET /api/v1/assessments/${a1}`]: ok(fx.assessment),
    [`GET /api/v1/assessments/${a2}`]: ok(fx.assessmentNoQuantum),
    [`GET /api/v1/assessments/${a1}/recommendations`]: ok(fx.recommendations),
    [`GET /api/v1/assessments/${a2}/recommendations`]: ok(fx.recommendationsNoQuantum),
  };
}

export function testApi(): Api {
  return createApi(new ApiClient(BASE));
}

export function renderApp(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <App api={testApi()} />
    </MemoryRouter>,
  );
}

export function renderWithApi(ui: ReactElement) {
  return render(
    <MemoryRouter>
      <ApiProvider api={testApi()}>{ui}</ApiProvider>
    </MemoryRouter>,
  );
}
