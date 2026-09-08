import assert from "node:assert/strict";
import test from "node:test";
import { apiBase } from "./api.js";

test("API requests remain on the serving origin unless explicitly configured", () => {
  const previous = Object.getOwnPropertyDescriptor(globalThis, "document");
  let content = "";
  Object.defineProperty(globalThis, "document", {
    configurable: true,
    value: { querySelector: () => ({ content }) },
  });
  try {
    // No window/location exists here: default resolution must not depend
    // on a guessed development port or another local service.
    assert.equal(apiBase(), "");
    content = "   ";
    assert.equal(apiBase(), "");
    content = " https://api.example.test/ ";
    assert.equal(apiBase(), "https://api.example.test");
  } finally {
    if (previous) Object.defineProperty(globalThis, "document", previous);
    else Reflect.deleteProperty(globalThis, "document");
  }
});
