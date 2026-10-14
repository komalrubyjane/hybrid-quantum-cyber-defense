/**
 * Runtime checks at the API boundary. TypeScript types come from the OpenAPI document, but
 * responses are still checked at run time for the fields the UI relies on, and for the
 * SAFETY INVARIANTS the dashboard must never contradict:
 * - every recommendation requires human approval;
 * - recommendation views and decision records report `executed: false`;
 * - risk carries the MODEL-DERIVED RISK SCORE label;
 * - incident chains contain OBSERVED steps only; predictions are PREDICTED.
 * A violation raises, and the client reports a contract error instead of rendering.
 */
import type {
  AssessmentRecord,
  AssessmentSummary,
  DecisionRecord,
  HealthResponse,
  IncidentAssessment,
  MetaResponse,
  RecommendationView,
  RunSummary,
} from "./types";

type Obj = Record<string, unknown>;

function obj(value: unknown, what: string): Obj {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`${what} is not an object`);
  }
  return value as Obj;
}

function arr(value: unknown, what: string): unknown[] {
  if (!Array.isArray(value)) throw new Error(`${what} is not a list`);
  return value;
}

function str(value: unknown, what: string): string {
  if (typeof value !== "string") throw new Error(`${what} is not a string`);
  return value;
}

function num(value: unknown, what: string): number {
  if (typeof value !== "number" || !Number.isFinite(value)) throw new Error(`${what} is not a number`);
  return value;
}

function checkRecommendation(value: unknown): void {
  const rec = obj(value, "recommendation");
  str(rec.recommendation_id, "recommendation_id");
  str(rec.action, "action");
  if (rec.requires_human_approval !== true) {
    throw new Error("a recommendation does not require human approval");
  }
}

function checkIncident(value: unknown): void {
  const incident = obj(value, "incident");
  const chain = obj(obj(incident.chain, "chain").chain, "attack chain");
  for (const step of arr(chain.steps, "steps")) {
    const s = obj(step, "step");
    str(s.technique_id, "technique_id");
    if (s.provenance !== "OBSERVED") throw new Error("an incident chain step is not OBSERVED");
  }
  const prediction = obj(incident.prediction, "prediction");
  if (prediction.provenance !== "PREDICTED") throw new Error("prediction is not PREDICTED");
  const result = obj(prediction.result, "prediction result");
  if (result.provenance !== "PREDICTED") throw new Error("prediction result is not PREDICTED");
  arr(result.next_step, "next_step");
  const risk = obj(incident.risk, "risk");
  num(risk.score, "risk score");
  str(risk.level, "risk level");
  if (risk.label !== "MODEL-DERIVED RISK SCORE") throw new Error("risk is not labelled MODEL-DERIVED");
  arr(risk.components, "risk components");
  arr(incident.recommendations, "recommendations").forEach(checkRecommendation);
}

export function validateHealth(value: unknown): HealthResponse {
  const h = obj(value, "health");
  str(h.status, "status");
  return h as unknown as HealthResponse;
}

export function validateMeta(value: unknown): MetaResponse {
  const m = obj(value, "meta");
  if (m.defense_mode !== "recommendation-only") throw new Error("defense mode is not recommendation-only");
  str(m.attack_version, "attack_version");
  obj(m.model_versions, "model_versions");
  obj(m.policy_versions, "policy_versions");
  return m as unknown as MetaResponse;
}

export function validateRuns(value: unknown): RunSummary[] {
  for (const run of arr(value, "runs")) {
    const r = obj(run, "run");
    str(r.run_id, "run_id");
    obj(r.metrics, "metrics");
  }
  return value as RunSummary[];
}

export function validateAssessmentSummaries(value: unknown): AssessmentSummary[] {
  for (const item of arr(value, "assessments")) str(obj(item, "assessment").assessment_id, "assessment_id");
  return value as AssessmentSummary[];
}

export function validateAssessment(value: unknown): AssessmentRecord {
  const record = obj(value, "assessment");
  str(record.assessment_id, "assessment_id");
  const output = obj(record.output, "output");
  arr(output.incidents, "incidents").forEach(checkIncident);
  return record as unknown as AssessmentRecord;
}

export function validateIncident(value: unknown): IncidentAssessment {
  checkIncident(value);
  return value as IncidentAssessment;
}

function checkDecision(value: unknown): void {
  const d = obj(value, "decision");
  if (d.executed !== false) throw new Error("a decision record does not report executed: false");
  str(d.decision, "decision");
}

export function validateDecision(value: unknown): DecisionRecord {
  checkDecision(value);
  return value as DecisionRecord;
}

export function validateDecisions(value: unknown): DecisionRecord[] {
  arr(value, "decisions").forEach(checkDecision);
  return value as DecisionRecord[];
}

export function validateRecommendationViews(value: unknown): RecommendationView[] {
  for (const item of arr(value, "recommendations")) {
    const v = obj(item, "recommendation view");
    if (v.executed !== false) throw new Error("a recommendation view does not report executed: false");
    checkRecommendation(v.recommendation);
    arr(v.decisions, "decisions").forEach(checkDecision);
  }
  return value as RecommendationView[];
}
