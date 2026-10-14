import type { ReactNode } from "react";

import { ApiError } from "../api/client";
import type { RiskLevel } from "../api/types";
import { mitigationUrl, tacticUrl, techniqueUrl } from "../lib/format";

export function Panel({
  title,
  subtitle,
  actions,
  children,
  className = "",
  testId,
  id,
}: {
  title: ReactNode;
  subtitle?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  testId?: string;
  id?: string;
}) {
  return (
    <section className={`panel ${className}`} data-testid={testId} id={id}>
      <header className="panel__header">
        <div>
          <h2 className="panel__title">{title}</h2>
          {subtitle ? <p className="panel__subtitle">{subtitle}</p> : null}
        </div>
        {actions ? <div className="panel__actions">{actions}</div> : null}
      </header>
      <div className="panel__body">{children}</div>
    </section>
  );
}

/** Decorative geometric accent (thin concentric outlines). Purely presentational. */
export function Orbit() {
  return (
    <svg className="orbit" viewBox="0 0 168 168" fill="none" aria-hidden="true" focusable="false">
      <circle cx="84" cy="84" r="83" stroke="currentColor" />
      <circle cx="84" cy="84" r="60" stroke="currentColor" strokeDasharray="2 6" />
      <circle cx="84" cy="84" r="36" stroke="currentColor" />
      <circle cx="84" cy="84" r="3" fill="#a5ff78" />
      <g className="orbit__dot">
        <circle cx="84" cy="1" r="4.5" fill="#a5ff78" />
      </g>
    </svg>
  );
}

/** Oversized editorial page heading. */
export function PageHero({
  eyebrow,
  title,
  lead,
  aside,
  compact = false,
}: {
  eyebrow: ReactNode;
  title: ReactNode;
  lead?: ReactNode;
  aside?: ReactNode;
  compact?: boolean;
}) {
  return (
    <header className="hero">
      <div>
        <p className="hero__eyebrow">{eyebrow}</p>
        <h1 className={`hero__title${compact ? " hero__title--compact" : ""}`}>{title}</h1>
        {lead ? <p className="hero__lead">{lead}</p> : null}
      </div>
      <div className="hero__aside">{aside ?? <Orbit />}</div>
    </header>
  );
}

export function SectionHead({ title, sub, actions }: { title: ReactNode; sub?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="section__head">
      <div>
        <h2 className="section__title">{title}</h2>
        {sub ? <p className="section__sub">{sub}</p> : null}
      </div>
      {actions}
    </div>
  );
}

export function Stat({ label, value, note }: { label: ReactNode; value: ReactNode; note?: ReactNode }) {
  return (
    <div className="stat">
      <div className="stat__label">{label}</div>
      <strong className="stat__value">{value}</strong>
      {note ? <p className="stat__note">{note}</p> : null}
    </div>
  );
}

/** Thin horizontal bar for a value already in [0, 1] (display only). */
export function Meter({ value, tone = "lime", inline = false }: { value: number; tone?: string; inline?: boolean }) {
  const width = Math.max(0, Math.min(1, value)) * 100;
  return (
    <span className={`meter${inline ? " meter--inline" : ""}`} aria-hidden="true">
      <span className={`meter__fill meter__fill--${tone}`} style={{ width: `${String(width)}%` }} />
    </span>
  );
}

/** Circular ring drawn from the API's score (0–100). The frontend never computes a score. */
export function RiskGauge({ score, level, children }: { score: number; level: RiskLevel; children: ReactNode }) {
  const r = 88;
  const circumference = 2 * Math.PI * r;
  const fraction = Math.max(0, Math.min(100, score)) / 100;
  return (
    <div className="gauge">
      <svg viewBox="0 0 200 200" fill="none" aria-hidden="true" focusable="false">
        <circle className="gauge__ring" cx="100" cy="100" r="98" strokeWidth="1" />
        <circle className="gauge__track" cx="100" cy="100" r={r} strokeWidth="6" />
        <circle
          className={`gauge__value gauge__value--${level.toLowerCase()}`}
          cx="100"
          cy="100"
          r={r}
          strokeWidth="6"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={circumference * (1 - fraction)}
        />
      </svg>
      <div className="gauge__center">{children}</div>
    </div>
  );
}

export function Loading({ label = "Loading" }: { label?: string }) {
  return (
    <div className="state state--loading" role="status" aria-live="polite">
      <span className="spinner" aria-hidden="true" />
      {label}…
    </div>
  );
}

const ERROR_TITLES: Record<ApiError["kind"], string> = {
  unavailable: "API unavailable",
  service_unavailable: "Intelligence services unavailable (503)",
  validation: "Request rejected (422)",
  conflict: "Workflow conflict (409)",
  not_found: "Not found (404)",
  contract: "Unexpected API response",
  http: "API error",
};

const ERROR_HINTS: Partial<Record<ApiError["kind"], string>> = {
  unavailable: "Start the API (see docs/API.md) and retry.",
  service_unavailable: "The API is running but its local knowledge base or model artifacts are missing.",
  contract: "The response did not match the expected API contract, so it is not displayed.",
};

/** Retrying cannot change a 404 or a 422, so no Retry button is offered for them. */
const NO_RETRY: ReadonlySet<ApiError["kind"]> = new Set(["not_found", "validation"]);

export function ErrorView({
  error,
  onRetry,
  hint,
  action,
}: {
  error: ApiError;
  onRetry?: () => void;
  hint?: ReactNode;
  action?: ReactNode;
}) {
  const help = hint ?? ERROR_HINTS[error.kind];
  return (
    <div className={`state state--error state--${error.kind}`} role="alert">
      <strong>{ERROR_TITLES[error.kind]}</strong>
      <p>{error.message}</p>
      {help ? <p className="state__hint">{help}</p> : null}
      {(onRetry && !NO_RETRY.has(error.kind)) || action ? (
        <div className="row">
          {onRetry && !NO_RETRY.has(error.kind) ? (
            <button type="button" className="btn btn--ghost btn--small" onClick={onRetry}>
              Retry
            </button>
          ) : null}
          {action}
        </div>
      ) : null}
    </div>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="state state--empty">{children}</div>;
}

/** Score shown with two decimals everywhere, exactly as the API returned it (rounded for display). */
export function RiskBadge({ level, score }: { level: RiskLevel; score?: number }) {
  return (
    <span className={`risk-badge risk-badge--${level.toLowerCase()}`}>
      {level}
      {score === undefined ? null : <span className="risk-badge__score">{score.toFixed(2)}</span>}
    </span>
  );
}

export function Chip({ tone = "neutral", children }: { tone?: string; children: ReactNode }) {
  return <span className={`chip chip--${tone}`}>{children}</span>;
}

export function OriginChip({ origin }: { origin: string }) {
  return <Chip tone={origin === "SYNTHETIC" ? "warn" : "neutral"}>{origin}</Chip>;
}

function ExternalId({ id, href, title }: { id: string; href: string | null; title: string }) {
  if (href === null) return <code className="attack-id">{id}</code>;
  return (
    <a className="attack-id" href={href} target="_blank" rel="noopener noreferrer" title={title}>
      {id}
    </a>
  );
}

export function TechniqueId({ id }: { id: string }) {
  return <ExternalId id={id} href={techniqueUrl(id)} title="Open the public ATT&CK page (external)" />;
}

export function TacticId({ id }: { id: string | null | undefined }) {
  if (!id) return <span className="muted">tactic not attributed</span>;
  return <ExternalId id={id} href={tacticUrl(id)} title="Open the public ATT&CK tactic page (external)" />;
}

export function MitigationId({ id }: { id: string }) {
  return <ExternalId id={id} href={mitigationUrl(id)} title="Open the public ATT&CK mitigation page (external)" />;
}

/** A wrapping row of ATT&CK IDs (wraps on narrow screens). */
export function IdList({ children }: { children: ReactNode }) {
  return <span className="id-cloud">{children}</span>;
}

export function RecommendationOnlyNotice() {
  return (
    <p className="notice notice--safety" data-testid="recommendation-only-notice">
      <span className="notice__icon" aria-hidden="true" />
      <span>
        Recommendation only — no action has been executed. This system executes nothing; any action is taken by
        humans outside the system.
      </span>
    </p>
  );
}

export function ModelDerivedNotice() {
  return (
    <p className="notice notice--model small">
      MODEL-DERIVED RISK SCORE — an engineering score from a documented policy, not a probability, certainty or
      confirmed compromise.
    </p>
  );
}

/** Scrollable wrapper for wide tables: keyboard-focusable so it can be scrolled without a pointer. */
export function TableWrap({ label, children, tall = false }: { label: string; children: ReactNode; tall?: boolean }) {
  return (
    <div className={`table-wrap${tall ? " table-wrap--tall" : ""}`} tabIndex={0} role="region" aria-label={label}>
      {children}
    </div>
  );
}
