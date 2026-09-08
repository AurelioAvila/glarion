import assert from "node:assert/strict";
import test from "node:test";
import { classifySource, acquisitionHeaders } from "./acquisition.js";
test("channel classification strips private parameters and rejects lookalike hosts", () => {
  assert.equal(classifySource("?utm_source=youtube&email=private", ""), "youtube");
  assert.equal(classifySource("?utm_source=private@example.com", ""), "direct");
  assert.equal(classifySource("", "https://youtube.com.attacker.example/private"), "referral");
  assert.equal(classifySource("", "https://dev.to/glarion/example"), "dev");
  assert.deepEqual(acquisitionHeaders(), {});
});
test("privacy preferences and internal visits suppress attribution", () => {
  const saved = new Map(["window", "navigator", "document", "sessionStorage"].map(k => [k, Object.getOwnPropertyDescriptor(globalThis, k)]));
  const storage = new Map<string, string>();
  const location = {hostname: "glarion.app", search: "?utm_source=youtube"};
  const navigator = {doNotTrack: "0", globalPrivacyControl: false};
  try {
    for (const [key, value] of Object.entries({window: {location}, navigator, document: {referrer: ""}, sessionStorage: {
      getItem: (key: string) => storage.get(key) ?? null,
      setItem: (key: string, value: string) => storage.set(key, value),
    }})) Object.defineProperty(globalThis, key, {configurable: true, value});
    assert.deepEqual(acquisitionHeaders(), {"x-glarion-source": "youtube"});
    navigator.globalPrivacyControl = true;
    assert.deepEqual(acquisitionHeaders(), {});
    navigator.globalPrivacyControl = false;
    navigator.doNotTrack = "1";
    assert.deepEqual(acquisitionHeaders(), {});
    navigator.doNotTrack = "0";
    location.search = "?growth=off";
    assert.deepEqual(acquisitionHeaders(), {});
    location.search = "";
    assert.deepEqual(acquisitionHeaders(), {});
    storage.clear();
    location.hostname = "localhost";
    assert.deepEqual(acquisitionHeaders(), {});
  } finally {
    for (const [key, descriptor] of saved) {
      if (descriptor) Object.defineProperty(globalThis, key, descriptor);
      else Reflect.deleteProperty(globalThis, key);
    }
  }
});
