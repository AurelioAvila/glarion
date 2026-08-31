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
  return readdirSync(WEB).filter((name) => name.endsWith(".html"));
}

/// The :root custom properties declared inside a page's <style> blocks.
function tokensOf(page: string): Map<string, string> {
  const html = readFileSync(join(WEB, page), "utf8");
  const styles = [...html.matchAll(/<style[^>]*>([\s\S]*?)<\/style>/g)]
    .map((match) => match[1] ?? "")
    .join("\n");

  const found = new Map<string, string>();
  for (const block of styles.matchAll(/:root\s*\{([\s\S]*?)\}/g)) {
    const body = block[1] ?? "";
    for (const declaration of body.matchAll(/--([a-z0-9-]+)\s*:\s*([^;]+);/g)) {
      const name = declaration[1];
      const value = declaration[2];
      if (name && value) found.set(name, value.trim());
    }
  }
  return found;
}

function relativeLuminance(hex: string): number {
  const digits = hex.replace("#", "");
  const full = digits.length === 3 ? [...digits].map((c) => c + c).join("") : digits;

  // Written as a function of the offset rather than an array lookup: under
  // noUncheckedIndexedAccess every index is possibly undefined, and coercing
  // that away would hide a genuinely malformed colour instead of failing on it.
  const channel = (offset: number): number => {
    const value = parseInt(full.slice(offset, offset + 2), 16) / 255;
    return value <= 0.04045 ? value / 12.92 : Math.pow((value + 0.055) / 1.055, 2.4);
  };

  return 0.2126 * channel(0) + 0.7152 * channel(2) + 0.0722 * channel(4);
}

function contrast(a: string, b: string): number {
  const first = relativeLuminance(a);
  const second = relativeLuminance(b);
  const light = Math.max(first, second);
  const dark = Math.min(first, second);
  return (light + 0.05) / (dark + 0.05);
}

test("a token declared on more than one page has one value", () => {
  const seen = new Map<string, Map<string, string>>();
  for (const page of pages()) {
    for (const [name, value] of tokensOf(page)) {
      const byPage = seen.get(name) ?? new Map<string, string>();
      byPage.set(page, value);
      seen.set(name, byPage);
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
    if (background === undefined || !background.startsWith("#")) continue;

    for (const name of TEXT_TOKENS) {
      const colour = tokens.get(name);
      if (colour === undefined || !colour.startsWith("#")) continue;

      const ratio = contrast(colour, background);
      assert.ok(
        ratio >= AA_BODY_TEXT,
        `${page}: --${name} (${colour}) on --bg (${background}) is ` +
          `${ratio.toFixed(2)}:1, under ${AA_BODY_TEXT}:1`,
      );
    }
  }
});
