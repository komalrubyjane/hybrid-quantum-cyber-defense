/**
 * Central API client. The ONLY module that performs network requests.
 *
 * - The base URL comes from `VITE_API_BASE_URL` (http/https only) and is fixed at start-up;
 *   requests go only to fixed path templates built by `endpoints.ts` (no arbitrary URLs).
 * - Errors become `ApiError` with a category and a short, sanitised message: no stack traces,
 *   no filesystem paths, no echoed request bodies.
 */

export const DEFAULT_API_BASE_URL = "http://127.0.0.1:8000";

export type ApiErrorKind =
  | "unavailable" // network failure: API not reachable
  | "service_unavailable" // 503: local artifacts missing
  | "validation" // 422
  | "conflict" // 409: e.g. two-step approval workflow
  | "not_found" // 404
  | "contract" // response violated the expected contract
  | "http"; // any other non-2xx status

export class ApiError extends Error {
  readonly kind: ApiErrorKind;
  readonly status: number | null;

  constructor(kind: ApiErrorKind, message: string, status: number | null = null) {
    super(message);
    this.name = "ApiError";
    this.kind = kind;
    this.status = status;
  }
}

export function resolveBaseUrl(raw: string | undefined): string {
  const value = (raw ?? "").trim() || DEFAULT_API_BASE_URL;
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error("VITE_API_BASE_URL is not a valid URL");
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error("VITE_API_BASE_URL must use http or https");
  }
  if (url.username || url.password || url.search || url.hash) {
    throw new Error("VITE_API_BASE_URL must not contain credentials, a query or a fragment");
  }
  return url.toString().replace(/\/+$/, "");
}

const PATH_PATTERN = /(?:[A-Za-z]:\\|\/(?:Users|home|private|tmp|var|etc|opt|root)\/)[^\s"'`]*/g;
const MAX_MESSAGE = 300;

/** Remove anything resembling a filesystem path or traceback and cap the length. */
export function sanitize(message: string): string {
  const firstLine = message.split(/\r?\n/)[0] ?? "";
  const cleaned = firstLine.replace(PATH_PATTERN, "[path removed]").replace(/Traceback.*/i, "");
  return cleaned.length > MAX_MESSAGE ? `${cleaned.slice(0, MAX_MESSAGE)}…` : cleaned;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** Human-readable text from a FastAPI error body (string detail or 422 item list). */
export function describeDetail(body: unknown): string | null {
  if (!isRecord(body)) return null;
  const detail = body.detail;
  if (typeof detail === "string") return sanitize(detail);
  if (Array.isArray(detail)) {
    const items = detail.slice(0, 5).map((item) => {
      if (!isRecord(item)) return "invalid request";
      const loc = Array.isArray(item.loc) ? item.loc.filter((p) => p !== "body").join(".") : "";
      const msg = typeof item.msg === "string" ? item.msg : "invalid value";
      return sanitize(loc ? `${loc}: ${msg}` : msg);
    });
    const more = detail.length > 5 ? ` (+${String(detail.length - 5)} more)` : "";
    return items.join("; ") + more;
  }
  return null;
}

const FALLBACK: Record<ApiErrorKind, string> = {
  unavailable: "The API is not reachable. Check that the backend is running.",
  service_unavailable:
    "Intelligence services are unavailable: required local artifacts are missing on the server.",
  validation: "The request was rejected by the API's validation.",
  conflict: "The request conflicts with the analyst workflow.",
  not_found: "The requested resource was not found.",
  contract: "The API response did not match the expected contract.",
  http: "The API returned an error.",
};

function kindFor(status: number): ApiErrorKind {
  if (status === 503) return "service_unavailable";
  if (status === 422) return "validation";
  if (status === 409) return "conflict";
  if (status === 404) return "not_found";
  return "http";
}

export class ApiClient {
  readonly baseUrl: string;

  constructor(baseUrl: string) {
    this.baseUrl = resolveBaseUrl(baseUrl);
  }

  async request<T>(
    path: string,
    validate: (data: unknown) => T,
    init?: { method: "GET" | "POST"; body?: unknown },
  ): Promise<T> {
    if (!path.startsWith("/") || path.startsWith("//") || path.includes("..")) {
      throw new ApiError("contract", "Refusing to request a non-API path");
    }
    const method = init?.method ?? "GET";
    let response: Response;
    try {
      response = await fetch(`${this.baseUrl}${path}`, {
        method,
        headers: init?.body === undefined ? {} : { "Content-Type": "application/json" },
        body: init?.body === undefined ? null : JSON.stringify(init.body),
        credentials: "omit",
      });
    } catch {
      throw new ApiError("unavailable", FALLBACK.unavailable);
    }
    const body: unknown = await response.json().catch(() => null);
    if (!response.ok) {
      const kind = kindFor(response.status);
      throw new ApiError(kind, describeDetail(body) ?? FALLBACK[kind], response.status);
    }
    try {
      return validate(body);
    } catch (error) {
      const reason = error instanceof Error ? sanitize(error.message) : "unexpected response";
      throw new ApiError("contract", `${FALLBACK.contract} (${reason})`, response.status);
    }
  }
}

export function messageOf(error: unknown): string {
  if (error instanceof ApiError) return error.message;
  return "Unexpected error.";
}
