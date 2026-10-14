/**
 * Static security / safety scan of the dashboard source (complements ESLint rules).
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { describe, expect, it } from "vitest";

const SRC = join(__dirname, "..");

function sourceFiles(dir: string = SRC): string[] {
  return readdirSync(dir).flatMap((name) => {
    const path = join(dir, name);
    if (statSync(path).isDirectory()) return name === "test" || name === "fixtures" ? [] : sourceFiles(path);
    return /\.(ts|tsx)$/.test(name) && !/\.test\.tsx?$/.test(name) && !name.endsWith(".d.ts") ? [path] : [];
  });
}

const files = sourceFiles().map((path) => ({ path: relative(SRC, path), text: readFileSync(path, "utf8") }));

describe("dashboard source safety", () => {
  it("scans the application source", () => {
    expect(files.map((f) => f.path)).toEqual(expect.arrayContaining(["api/client.ts", "App.tsx", "components/DecisionControls.tsx"]));
  });

  it("uses no raw HTML injection or dynamic code", () => {
    for (const { path, text } of files) {
      expect(text, path).not.toMatch(/dangerouslySetInnerHTML|\.innerHTML\s*=|\beval\(|new Function\(|document\.write/);
    }
  });

  it("performs network requests only in the central API client", () => {
    for (const { path, text } of files) {
      if (path === "api/client.ts") continue;
      expect(text, path).not.toMatch(/\bfetch\(|XMLHttpRequest|WebSocket|EventSource|navigator\.sendBeacon/);
    }
  });

  it("contains no secrets or credentials", () => {
    for (const { path, text } of files) {
      // Credential-like assignments or auth headers (the base-URL check that REJECTS
      // credentials in URLs is allowed).
      expect(text, path).not.toMatch(/\b(api[_-]?key|secret|password|token)\s*[:=]\s*["'`](?!\$\{)[^"'`]{4,}["'`]/i);
      expect(text, path).not.toMatch(/bearer\s+[a-z0-9]|["']authorization["']\s*:/i);
    }
  });

  it("secret pattern catches real assignments", () => {
    const pattern = /\b(api[_-]?key|secret|password|token)\s*[:=]\s*["'`](?!\$\{)[^"'`]{4,}["'`]/i;
    expect('const apiKey = "sk-live-123456"').toMatch(pattern);
    expect("token: 'abcd1234'").toMatch(pattern);
    expect("const token = `${key}#1`").not.toMatch(pattern);
  });

  it("only references the configured API and public ATT&CK pages", () => {
    for (const { path, text } of files) {
      for (const url of text.match(/https?:\/\/[^\s"'`)]+/g) ?? []) {
        expect(url, path).toMatch(/^(http:\/\/127\.0\.0\.1:8000|https:\/\/attack\.mitre\.org\/)/);
      }
    }
  });

  it("exposes no endpoint or control that executes a recommendation", () => {
    for (const { path, text } of files) {
      expect(text, path).not.toMatch(/\/execute|\/apply|executeRecommendation|runAction|child_process/);
      for (const label of text.match(/<button[^>]*>([^<]*)</g) ?? []) {
        expect(label, path).not.toMatch(/>\s*(execute|run|apply|isolate|block|disable|reset|kill)\b/i);
      }
    }
  });
});
