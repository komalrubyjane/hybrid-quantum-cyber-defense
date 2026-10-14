/**
 * Display-only formatting. No backend rule (risk formula, thresholds, evidence status,
 * correlation, approval policy) is re-implemented here.
 */
import type { DefenseAction } from "../api/types";

const TECHNIQUE_ID = /^T(\d{4})(?:\.(\d{3}))?$/;
const TACTIC_ID = /^TA\d{4}$/;
const MITIGATION_ID = /^M\d{4}$/;

/** Outbound link to the public ATT&CK page (navigation only; nothing is fetched). */
export function techniqueUrl(techniqueId: string): string | null {
  const m = TECHNIQUE_ID.exec(techniqueId);
  if (!m) return null;
  const sub = m[2] ? `/${m[2]}` : "";
  return `https://attack.mitre.org/techniques/T${m[1] ?? ""}${sub}/`;
}

export function tacticUrl(tacticId: string): string | null {
  return TACTIC_ID.test(tacticId) ? `https://attack.mitre.org/tactics/${tacticId}/` : null;
}

export function mitigationUrl(mitigationId: string): string | null {
  return MITIGATION_ID.test(mitigationId) ? `https://attack.mitre.org/mitigations/${mitigationId}/` : null;
}

export function pct(value: number | null | undefined, digits = 1): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return "n/a";
  return `${(value * 100).toFixed(digits)}%`;
}

export function num(value: number | null | undefined, digits = 2): string {
  if (value === null || value === undefined || !Number.isFinite(value)) return "n/a";
  return value.toFixed(digits);
}

export function sci(value: number): string {
  return value === 0 ? "0" : value.toExponential(2);
}

export function when(value: string | null | undefined): string {
  if (!value) return "n/a";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toISOString().replace("T", " ").replace(/\.\d+Z$/, "Z");
}

/** Wording for the API's action values. Every label is a PROPOSAL, never an action taken. */
export const ACTION_LABELS: Record<DefenseAction, string> = {
  block_suspicious_access: "Consider blocking suspicious access",
  isolate_affected_host: "Consider isolating the affected host",
  restrict_communication: "Consider restricting suspicious communication",
  disable_compromised_credentials: "Consider resetting / disabling compromised credentials",
  increase_monitoring: "Increase monitoring",
  escalate_severity: "Escalate to a SOC analyst",
  collect_additional_evidence: "Collect additional evidence",
};

export function titleCase(value: string): string {
  return value
    .split("_")
    .map((w) => (w ? w.charAt(0).toUpperCase() + w.slice(1).toLowerCase() : w))
    .join(" ");
}
