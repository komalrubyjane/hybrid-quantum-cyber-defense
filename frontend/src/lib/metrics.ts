/**
 * Display-only reshaping of a run's stored metrics into a comparison table. Keys are split on
 * "." into a row (everything before the metric name) and a column (the metric name). A trailing
 * statistic suffix (ci_low / ci_high / mean / std) is attached to its metric instead of becoming
 * a column. No value is computed, re-weighted or invented: every number shown is a stored metric.
 */

const STAT_SUFFIXES = new Set(["ci_low", "ci_high", "mean", "std"]);

export interface MetricCell {
  value?: number;
  ci_low?: number;
  ci_high?: number;
  mean?: number;
  std?: number;
}

export interface MetricPivot {
  rows: string[];
  columns: string[];
  cells: Map<string, Map<string, MetricCell>>;
}

/** Names of metrics whose values are proportions in [0, 1] by definition (bar length only; no "better" direction). */
const PROPORTION = /^(top\d+|mrr|tactic_top1|accuracy|balanced_accuracy|f1|precision|recall|roc_auc|pr_auc|step\d+_acc|path_hit@\d+|malicious_detection_rate|benign_false_positive_rate)(_tie_aware)?$/;

/** Rows holding paired differences (e.g. "paired:zz_qsvm-rbf_svm") are not proportions. */
export function isProportion(row: string, metric: string, value: number): boolean {
  return !/paired|diff|delta/i.test(row) && PROPORTION.test(metric) && value >= 0 && value <= 1;
}

export function pivotMetrics(entries: [string, number][]): MetricPivot {
  const rows: string[] = [];
  const columns: string[] = [];
  const cells = new Map<string, Map<string, MetricCell>>();
  for (const [key, value] of entries) {
    const parts = key.split(".");
    let stat: keyof MetricCell = "value";
    const last = parts[parts.length - 1] ?? "";
    if (parts.length > 1 && STAT_SUFFIXES.has(last)) {
      stat = last as keyof MetricCell;
      parts.pop();
    }
    const metric = parts.pop() ?? key;
    const row = parts.join(".") || "(run)";
    if (!cells.has(row)) {
      cells.set(row, new Map());
      rows.push(row);
    }
    if (!columns.includes(metric)) columns.push(metric);
    const rowCells = cells.get(row);
    if (!rowCells) continue;
    const cell = rowCells.get(metric) ?? {};
    cell[stat] = value;
    rowCells.set(metric, cell);
  }
  return { rows, columns, cells };
}

/** The headline number of a cell: the plain value if stored, otherwise the stored mean. */
export function headlineValue(cell: MetricCell | undefined): number | undefined {
  return cell?.value ?? cell?.mean;
}
