// Tests for the domain carried from the free check into signup.
//
// Two things here are worth pinning. The shape check is a guard, not a
// convenience: the value arrives in a URL anybody can write and is read back
// to the visitor on our own origin, so anything that is not a hostname has
// to be refused rather than tidied up. And the entry is consumed on read —
// without that, a signup abandoned in March puts somebody else's client
// domain in the box in April.
//
//   cd web && npm test

import assert from "node:assert/strict";
import test from "node:test";

import { cleanDomain, rememberDomain, takeRememberedDomain } from "./carry.js";

/// The browser API the module reaches for, small enough to keep honest.
function installStorage(): Map<string, string> {
  const cells = new Map<string, string>();
  (globalThis as { localStorage?: unknown }).localStorage = {
    getItem: (key: string) => cells.get(key) ?? null,
    setItem: (key: string, value: string) => void cells.set(key, value),
    removeItem: (key: string) => void cells.delete(key),
  };
  return cells;
}

test("a hostname survives, and everything else is refused", () => {
  assert.equal(cleanDomain("example.com"), "example.com");
  assert.equal(cleanDomain("  Client-Site.CO.UK  "), "client-site.co.uk");
  assert.equal(cleanDomain("example.com."), "example.com", "a root dot is not a rejection");

  for (const hostile of [
    null,
    "",
    "   ",
    "localhost",
    "not a domain",
    "example.com/../../etc",
    "javascript:alert(1)",
    "<img src=x onerror=alert(1)>",
    "https://example.com",
    "example.com?x=1",
    "-example.com",
    `${"a".repeat(250)}.example.com`,
  ]) {
    assert.equal(cleanDomain(hostile), null, `should have been refused: ${String(hostile)}`);
  }
});

test("the domain survives the round trip and is handed over once", () => {
  installStorage();

  rememberDomain("client-site.com");

  assert.equal(takeRememberedDomain(), "client-site.com");
  assert.equal(takeRememberedDomain(), null, "a second read must not repeat it");
});

test("a domain left over from a month ago is not offered", () => {
  const cells = installStorage();
  const lastMonth = Date.now() - 30 * 24 * 60 * 60 * 1000;

  cells.set("glarion.signup.domain", JSON.stringify({ domain: "old-client.com", at: lastMonth }));

  assert.equal(takeRememberedDomain(), null);
  assert.equal(cells.has("glarion.signup.domain"), false, "stale entries are cleared, not kept");
});

test("a value written by something else is ignored rather than thrown", () => {
  const cells = installStorage();

  for (const junk of ["", "not json", "{}", '{"domain":"javascript:alert(1)","at":' + Date.now() + "}"]) {
    cells.set("glarion.signup.domain", junk);
    assert.equal(takeRememberedDomain(), null, `should have been ignored: ${junk}`);
  }
});

test("storage that refuses to answer leaves the form alone", () => {
  (globalThis as { localStorage?: unknown }).localStorage = {
    getItem: () => {
      throw new Error("site data is blocked");
    },
    setItem: () => {
      throw new Error("site data is blocked");
    },
    removeItem: () => {
      throw new Error("site data is blocked");
    },
  };

  assert.doesNotThrow(() => rememberDomain("client-site.com"));
  assert.equal(takeRememberedDomain(), null);
});
