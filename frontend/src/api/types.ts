/**
 * Central API types: aliases of the schemas GENERATED from the backend's OpenAPI document
 * (`npm run gen:api`). No field is invented here.
 */
import type { components } from "./schema";

type S = components["schemas"];

export type HealthResponse = S["HealthResponse"];
export type MetaResponse = S["MetaResponse"];
export type RunSummary = S["RunSummary"];
export type AssessmentSummary = S["AssessmentSummary"];
export type AssessmentRecord = S["AssessmentRecord"];
export type AssessmentRequest = S["AssessmentRequest"];
export type PipelineOutput = S["PipelineOutput"];
export type IncidentAssessment = S["IncidentAssessment"];
export type IncidentChain = S["IncidentChain"];
export type AttackStep = S["AttackStep"];
export type NextTechniquePrediction = S["NextTechniquePrediction"];
export type PredictedPath = S["PredictedPath"];
export type RiskAssessment = S["RiskAssessment"];
export type RiskComponent = S["RiskComponent"];
export type RiskLevel = S["RiskLevel"];
export type DetectionEvidence = S["DetectionEvidence"];
export type QuantumOpinion = S["QuantumOpinion"];
export type DefenseRecommendation = S["DefenseRecommendation"];
export type DefenseAction = S["DefenseAction"];
export type RecommendationView = S["RecommendationView"];
export type Decision = S["Decision"];
export type DecisionRecord = S["DecisionRecord"];
export type DecisionRequest = S["DecisionRequest"];
export type CorrelationDecision = S["CorrelationDecision"];

export const RISK_LEVELS: readonly RiskLevel[] = ["LOW", "MEDIUM", "HIGH", "CRITICAL"];
