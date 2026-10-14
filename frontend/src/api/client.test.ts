import { describe, expect, it } from "vitest";

import { BASE, clone, fx, mockFetch, ok } from "../test/harness";
import { ApiClient, ApiError, DEFAULT_API_BASE_URL, describeDetail, messageOf, resolveBaseUrl, sanitize } from "./client";
import { createApi } from "./endpoints";
import { validateHealth } from "./validate";

describe("base URL", () => {
  it("defaults, trims and strips trailing slashes", () => {
    expect(resolveBaseUrl(undefined)).toBe(DEFAULT_API_BASE_URL);
    expect(resolveBaseUrl("  ")).toBe(DEFAULT_API_BASE_URL);
    expect(resolveBaseUrl("https://soc.example.test/api/")).toBe("https://soc.example.test/api");
  });
  it.each(["javascript:alert(1)", "ftp://x.test", "file:///etc/passwd", "not a url", "https://u:p@x.test", "https://x.test/?q=1", "https://x.test/#a"])(
    "rejects %s",
    (value) => {
      expect(() => resolveBaseUrl(value)).toThrow();
    },
  );
});

describe("error sanitising", () => {
  it("removes filesystem paths and tracebacks", () => {
    const s = sanitize("failed at /Users/alice/project/data/x.json and C:\\secret\\y");
    expect(s).not.toContain("/Users/alice");
    expect(s).not.toContain("C:\\secret");
    expect(s).toContain("[path removed]");
    expect(sanitize("boom\nTraceback (most recent call last):\n  File ...")).toBe("boom");
    expect(sanitize("x".repeat(400)).length).toBeLessThanOrEqual(301);
  });
  it("formats 422 bodies without echoing the submitted input", () => {
    const text = describeDetail(fx.error422.body) ?? "";
    expect(text).toContain("observations: List should have at least 1 item");
    expect(text).not.toContain("input");
    expect(describeDetail({ detail: "plain" })).toBe("plain");
    expect(describeDetail({ nope: 1 })).toBeNull();
    expect(describeDetail("x")).toBeNull();
    const many = { detail: Array.from({ length: 7 }, (_, i) => ({ loc: ["body", `f${String(i)}`], msg: "bad" })) };
    expect(describeDetail(many)).toContain("(+2 more)");
    expect(describeDetail({ detail: [42, { msg: 1 }] })).toBe("invalid request; invalid value");
  });
});

describe("ApiClient", () => {
  const api = () => createApi(new ApiClient(BASE));

  it("maps HTTP failures to categories with clean messages", async () => {
    mockFetch({
      "GET /api/v1/meta": () => ({ status: 503, body: { detail: "Intelligence services unavailable: missing artifacts" } }),
      "GET /api/v1/runs": () => ({ status: 500, body: null }),
      "GET /api/v1/assessments/asm-x": () => ({ status: 404, body: fx.error404.body }),
      "GET /health": () => "network-error",
    });
    await expect(api().meta()).rejects.toMatchObject({ kind: "service_unavailable", status: 503 });
    await expect(api().runs()).rejects.toMatchObject({ kind: "http", status: 500, message: "The API returned an error." });
    await expect(api().assessment("asm-x")).rejects.toMatchObject({ kind: "not_found", message: "Assessment not found" });
    await expect(api().health()).rejects.toMatchObject({ kind: "unavailable", status: null });
  });

  it("reports 409 workflow conflicts and 422 validation errors", async () => {
    mockFetch({
      "POST /api/v1/assessments/a/recommendations/r/decisions": () => fx.error409,
      "POST /api/v1/assessments": () => fx.error422,
    });
    await expect(api().recordDecision("a", "r", "APPROVED", "x")).rejects.toMatchObject({
      kind: "conflict",
      message: "HIGH-disruption recommendations must be ACKNOWLEDGED before APPROVED",
    });
    await expect(api().createAssessment({ observations: [] })).rejects.toMatchObject({ kind: "validation", status: 422 });
  });

  it("rejects responses that break the contract", async () => {
    const tampered = clone(fx.approved) as unknown as Record<string, unknown>;
    tampered.executed = true;
    mockFetch({
      "POST /api/v1/assessments/a/recommendations/r/decisions": () => ({ status: 201, body: tampered }),
      "GET /api/v1/meta": ok({ ...fx.meta, defense_mode: "automatic" }),
    });
    await expect(api().recordDecision("a", "r", "ACKNOWLEDGED", "x")).rejects.toMatchObject({ kind: "contract" });
    await expect(api().meta()).rejects.toMatchObject({ kind: "contract" });
  });

  it("sends JSON only to fixed API paths with encoded identifiers", async () => {
    const calls = mockFetch({
      "POST /api/v1/assessments/a%2Fb/recommendations/r%3F1/decisions": () => ({ status: 201, body: fx.acknowledged }),
      "GET /api/v1/runs": ok(fx.runs),
    });
    await api().recordDecision("a/b", "r?1", "ACKNOWLEDGED", "analyst-1", "note");
    await api().recordDecision("a/b", "r?1", "ACKNOWLEDGED", "analyst-1");
    await api().runs(5);
    expect(calls[0]).toMatchObject({ method: "POST", body: { decision: "ACKNOWLEDGED", analyst: "analyst-1", note: "note" } });
    expect(calls[1]?.body).toEqual({ decision: "ACKNOWLEDGED", analyst: "analyst-1" });
    expect(calls[2]?.url).toBe(`${BASE}/api/v1/runs?limit=5`);
    expect(calls.every((c) => c.url.startsWith(`${BASE}/`))).toBe(true);
    const fetchMock = globalThis.fetch as unknown as { mock: { calls: [string, RequestInit][] } };
    expect(fetchMock.mock.calls[0]?.[1].credentials).toBe("omit");
  });

  it("refuses non-API paths", async () => {
    const client = new ApiClient(BASE);
    for (const path of ["//evil.test/x", "https://evil.test", "/api/../x", "relative"]) {
      await expect(client.request(path, validateHealth)).rejects.toBeInstanceOf(ApiError);
    }
  });

  it("describes unknown errors generically", () => {
    expect(messageOf(new ApiError("http", "x"))).toBe("x");
    expect(messageOf(new Error("/Users/secret"))).toBe("Unexpected error.");
  });
});
