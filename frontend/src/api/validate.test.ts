import { describe, expect, it } from "vitest";

import { clone, fx } from "../test/harness";
import {
  validateAssessment,
  validateAssessmentSummaries,
  validateDecision,
  validateDecisions,
  validateHealth,
  validateIncident,
  validateMeta,
  validateRecommendationViews,
  validateRuns,
} from "./validate";

type Json = Record<string, unknown>;

describe("real API responses satisfy the boundary checks", () => {
  it("accepts every captured fixture", () => {
    expect(validateHealth(fx.health).status).toBe("ok");
    expect(validateMeta(fx.meta).defense_mode).toBe("recommendation-only");
    expect(validateRuns(fx.runs).length).toBeGreaterThan(0);
    expect(validateAssessmentSummaries(fx.assessments)).toHaveLength(2);
    expect(validateAssessment(fx.assessment).output.incidents).toHaveLength(2);
    expect(validateAssessment(fx.assessmentNoQuantum).output.incidents).toHaveLength(2);
    expect(validateRecommendationViews(fx.recommendations).length).toBeGreaterThan(0);
    expect(validateRecommendationViews(fx.recommendationsNoQuantum).length).toBeGreaterThan(0);
    expect(validateDecision(fx.approved).executed).toBe(false);
    expect(validateDecisions([fx.acknowledged, fx.approved])).toHaveLength(2);
    const first = fx.assessment.output.incidents[0];
    expect(first && validateIncident(first).risk.label).toBe("MODEL-DERIVED RISK SCORE");
  });
});

describe("safety invariants are enforced at the boundary", () => {
  it("rejects a decision or view claiming execution", () => {
    expect(() => validateDecision({ ...clone(fx.approved), executed: true })).toThrow(/executed: false/);
    const views = clone(fx.recommendations) as unknown as Json[];
    (views[0] as Json).executed = true;
    expect(() => validateRecommendationViews(views)).toThrow(/executed: false/);
  });

  it("rejects recommendations without mandatory human approval", () => {
    const record = clone(fx.assessment) as unknown as { output: { incidents: { recommendations: Json[] }[] } };
    const rec = record.output.incidents[0]?.recommendations[0];
    if (rec) rec.requires_human_approval = false;
    expect(() => validateAssessment(record)).toThrow(/human approval/);
  });

  it("rejects non-model-derived risk and mixed provenance", () => {
    const relabelled = clone(fx.assessment) as unknown as { output: { incidents: { risk: Json }[] } };
    const risk = relabelled.output.incidents[0]?.risk;
    if (risk) risk.label = "PROBABILITY OF ATTACK";
    expect(() => validateAssessment(relabelled)).toThrow(/MODEL-DERIVED/);
    const mixed = clone(fx.assessment) as unknown as { output: { incidents: { chain: { chain: { steps: Json[] } } }[] } };
    const step = mixed.output.incidents[0]?.chain.chain.steps[0];
    if (step) step.provenance = "PREDICTED";
    expect(() => validateAssessment(mixed)).toThrow(/OBSERVED/);
    const notPredicted = clone(fx.assessment) as unknown as { output: { incidents: { prediction: Json }[] } };
    const prediction = notPredicted.output.incidents[0]?.prediction;
    if (prediction) prediction.provenance = "OBSERVED";
    expect(() => validateAssessment(notPredicted)).toThrow(/PREDICTED/);
  });

  it("rejects malformed shapes", () => {
    expect(() => validateMeta({ ...fx.meta, defense_mode: "auto" })).toThrow();
    expect(() => validateRuns({})).toThrow(/list/);
    expect(() => validateRuns([{ run_id: 1, metrics: {} }])).toThrow(/string/);
    expect(() => validateAssessment(null)).toThrow(/object/);
    expect(() => validateHealth([])).toThrow(/object/);
    const badScore = clone(fx.assessment) as unknown as { output: { incidents: { risk: Json }[] } };
    const r = badScore.output.incidents[0]?.risk;
    if (r) r.score = Number.NaN;
    expect(() => validateAssessment(badScore)).toThrow(/number/);
  });
});
