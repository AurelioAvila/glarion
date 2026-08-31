// Tests for the design tokens shared by the four pages.
//
// Every page carries its own <style> block, so a token like --ink-3 is
// declared four times over. Nothing links those copies: a value corrected on
// the dashboard stays wrong on the marketing page, and the two only differ by
// a shade of grey, which is exactly the kind of difference nobody spots by
// looking. That had already happened — index.html sat on #63656f while the
// other three had moved to #7c7e88, and the darker one did not carry enough
// contrast to be read comfortably.
//
// The contrast check is here for the same reason: it is arithmetic, so a
// screenshot that "looks fine" is not evidence, and the failure lands on the
// people least able to work around it.
//
//   cd web && npm test

import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync, readdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const WEB = join(dirname(fileURLToPath(import.meta.url)), "..");

// WCAG 2.1 AA for body text. Large text is allowed 3:1, but these tokens are
// used for prose and table cells, so the stricter threshold is the honest one.
const AA_BODY_TEXT = 4.5;

/// Tokens that carry text, and therefore have to be legible on --bg.
const TEXT_TOKENS = ["ink", "ink-2", "ink-3"];

function pages(): string[] {
  return readdirSync(WEB).filter((f) => f.endsWith(".html"));
}

/// The :root custom properties declared inside a page's <style> blocks.
function tokensOf(page: string): Map<string, string> {
  const html = readFileSync(join(WEB, page), "utf8");
  const styles = [...html.matchAll(/<style[^>]*>([\s\S]*?)<\/style>/g)]
    .map((m) => m[1])
    .join("\n");
  const found = new Map<string, string>();
  for (const block of styles.matchAll(/:root\s*\{([\s\S]*?)\}/g)) {
    for (const [, name, value] of block[1].matchAll(/--([a-z0-9-]+)\s*:\s*([^;]+);/g)) {
      found.set(name, value.trim());
    }
  }
  return found;
}

function relativeLuminance(hex: string): number {
  const h = hex.replace("#", "");
  const full = h.length === 3 ? [...h].map((c) => c + c).join("") : h;
  const channels = [0, 2, 4].map((i) => {
    const c = parseInt(full.slice(i, i + 2), 16) / 255;
    return c <= 0.04045 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4);
  });
  return 0.2126 * channels[0] + 0.7152 * channels[1] + 0.0722 * channels[2];
}

function contrast(a: string, b: string): number {
  const [x, y] = [relativeLuminance(a), relativeLuminance(b)];
  const [light, dark] = x > y ? [x, y] : [y, x];
  return (light + 0.05) / (dark + 0.05);
}

test("a token declared on more than one page has one value", () => {
  const seen = new Map<string, Map<string, string>>();
  for (const page of pages()) {
    for (const [name, value] of tokensOf(page)) {
      if (!seen.has(name)) seen.set(name, new Map());
      seen.get(name)!.set(page, value);
    }
  }

  for (const [name, byPage] of seen) {
    const values = new Set(byPage.values());
    assert.equal(
      values.size,
      1,
      `--${name} differs between pages: ${[...byPage]
        .map(([page, value]) => `${page}=${value}`)
        .join(", ")}`,
    );
  }
});

test("text tokens are legible on the background they sit on", () => {
  for (const page of pages()) {
    const tokens = tokensOf(page);
    const background = tokens.get("bg");
    if (!background) continue;

    for (const name of TEXT_TOKENS) {
      const colour = tokens.get(name);
      if (!colour || !colour.startsWith("#")) continue;

      const ratio = contrast(colour, background);
      assert.ok(
        ratio >= AA_BODY_TEXT,
        `${page}: --${name} (${colour}) on --bg (${background}) is ` +
          `${ratio.toFixed(2)}:1, under ${AA_BODY_TEXT}:1`,
      );
    }
  }
});
