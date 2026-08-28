// Tests for the palette's matching.
//
// This is the part that decides whether the palette feels sharp or
// useless: a reader types three letters and either the site they wanted is
// first, or they go back to the mouse and never open it again. It is also
// pure, so it can be tested without a browser.
//
//   cd web && npm test

import assert from "node:assert/strict";
import test from "node:test";

import { rank, score, type Command } from "./palette.js";

function command(label: string, detail?: string): Command {
  return { group: "Sites", label, detail, run: () => {} };
}

/// Asserts a query matched, and hands back the score.
///
/// `score` returns null for "no match", and reading that as a number is
/// exactly the mistake these tests exist to catch — so it is unwrapped
/// once, here, rather than asserted around at every call site.
function matched(query: string, text: string): number {
  const result = score(query, text);
  assert.notEqual(result, null, `expected "${query}" to match "${text}"`);
  return result as number;
}

test("an exact prefix outranks a match further in", () => {
  const prefix = matched("acme", "acme-client.com");
  const later = matched("client", "acme-client.com");

  assert.ok(prefix > later, "a name starting with what was typed should win");
});

test("letters scattered through a name still match", () => {
  // How people type when they half-remember a domain.
  assert.notEqual(score("acl", "acme-client.com"), null);
  assert.notEqual(score("rvd", "riverside-dental.com"), null);
});

test("a tighter subsequence outranks a looser one", () => {
  const tight = matched("acm", "acme-client.com");
  const loose = matched("acm", "a-very-long-name-with-c-and-m-far-apart.com");

  assert.ok(tight > loose);
});

test("letters in the wrong order do not match", () => {
  assert.equal(score("mca", "acme.com"), null);
});

test("matching ignores case", () => {
  assert.notEqual(score("ACME", "acme-client.com"), null);
  assert.notEqual(score("acme", "ACME-CLIENT.COM"), null);
});

test("an empty query keeps everything, in the order given", () => {
  const commands = [command("acme.com"), command("riverside.com")];
  const ranked = rank(commands, "");

  assert.deepEqual(
    ranked.map((entry) => entry.label),
    ["acme.com", "riverside.com"],
  );
});

test("the client name is searchable, not just the domain", () => {
  // Somebody thinks in client names, not in domains they registered.
  const commands = [command("xk-9912.example", "Riverside Dental"), command("acme.com", "Acme")];
  const ranked = rank(commands, "riverside");

  assert.equal(ranked[0]?.label, "xk-9912.example");
});

test("what was typed lands first when several things match", () => {
  const commands = [command("northgate-legal.co.uk"), command("acme-client.com")];
  const ranked = rank(commands, "acme");

  assert.equal(ranked[0]?.label, "acme-client.com");
});

test("nothing matching yields nothing rather than everything", () => {
  // Showing the full list when a query matches none of it is how a palette
  // ends up opening the wrong thing on Enter.
  const commands = [command("acme.com"), command("riverside.com")];

  assert.deepEqual(rank(commands, "zzzzz"), []);
});

test("whitespace around a query is ignored", () => {
  assert.notEqual(score("  acme  ", "acme-client.com"), null);
});
