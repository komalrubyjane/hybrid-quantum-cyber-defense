import type { Api } from "../api/endpoints";
import type { AssessmentRecord, DecisionRecord, RecommendationView } from "../api/types";

export interface RecentAssessments {
  records: AssessmentRecord[];
  views: Map<string, RecommendationView[]>;
  decisions: DecisionRecord[];
}

/**
 * The API has no global decision list: recent decisions are gathered from the recommendation
 * views of the most recent assessments (read-only GETs).
 */
export async function loadRecent(api: Api, limit = 10): Promise<RecentAssessments> {
  const summaries = await api.assessments(limit);
  const records = await Promise.all(summaries.map((s) => api.assessment(s.assessment_id)));
  const viewLists = await Promise.all(records.map((r) => api.recommendations(r.assessment_id)));
  const views = new Map<string, RecommendationView[]>();
  records.forEach((r, i) => views.set(r.assessment_id, viewLists[i] ?? []));
  const decisions = viewLists
    .flat()
    .flatMap((v) => v.decisions)
    .sort((a, b) => b.recorded_at.localeCompare(a.recorded_at));
  return { records, views, decisions };
}
