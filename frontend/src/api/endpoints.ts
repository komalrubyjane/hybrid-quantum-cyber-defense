/**
 * Typed wrappers for the Milestone 8 endpoints consumed by the dashboard. Paths are fixed
 * templates; identifiers are URL-encoded. There is deliberately no function that executes a
 * recommendation: the API has no such endpoint and the dashboard adds none.
 */
import { ApiClient } from "./client";
import type {
  AssessmentRecord,
  AssessmentSummary,
  Decision,
  DecisionRecord,
  HealthResponse,
  MetaResponse,
  RecommendationView,
  RunSummary,
} from "./types";
import {
  validateAssessment,
  validateAssessmentSummaries,
  validateDecision,
  validateDecisions,
  validateHealth,
  validateMeta,
  validateRecommendationViews,
  validateRuns,
} from "./validate";

const id = encodeURIComponent;

export interface Api {
  health(): Promise<HealthResponse>;
  meta(): Promise<MetaResponse>;
  runs(limit?: number): Promise<RunSummary[]>;
  assessments(limit?: number): Promise<AssessmentSummary[]>;
  assessment(assessmentId: string): Promise<AssessmentRecord>;
  createAssessment(body: unknown): Promise<AssessmentRecord>;
  recommendations(assessmentId: string): Promise<RecommendationView[]>;
  decisions(assessmentId: string, recommendationId: string): Promise<DecisionRecord[]>;
  recordDecision(
    assessmentId: string,
    recommendationId: string,
    decision: Decision,
    analyst: string,
    note?: string,
  ): Promise<DecisionRecord>;
}

export function createApi(client: ApiClient): Api {
  return {
    health: () => client.request("/health", validateHealth),
    meta: () => client.request("/api/v1/meta", validateMeta),
    runs: (limit = 200) => client.request(`/api/v1/runs?limit=${String(limit)}`, validateRuns),
    assessments: (limit = 50) =>
      client.request(`/api/v1/assessments?limit=${String(limit)}`, validateAssessmentSummaries),
    assessment: (assessmentId) =>
      client.request(`/api/v1/assessments/${id(assessmentId)}`, validateAssessment),
    // The request body is validated by the API (422 on error); the browser re-implements no rule.
    createAssessment: (body) =>
      client.request("/api/v1/assessments", validateAssessment, { method: "POST", body }),
    recommendations: (assessmentId) =>
      client.request(
        `/api/v1/assessments/${id(assessmentId)}/recommendations`,
        validateRecommendationViews,
      ),
    decisions: (assessmentId, recommendationId) =>
      client.request(
        `/api/v1/assessments/${id(assessmentId)}/recommendations/${id(recommendationId)}/decisions`,
        validateDecisions,
      ),
    recordDecision: (assessmentId, recommendationId, decision, analyst, note) =>
      client.request(
        `/api/v1/assessments/${id(assessmentId)}/recommendations/${id(recommendationId)}/decisions`,
        validateDecision,
        {
          method: "POST",
          body: note ? { decision, analyst, note } : { decision, analyst },
        },
      ),
  };
}
