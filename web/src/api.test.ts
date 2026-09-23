import assert from "node:assert/strict";
import test from "node:test";
import { api, apiBase, session } from "./api.js";

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

test("an expired session returns to sign-in without redirecting bad credentials", async () => {
  const keys = new Map<string, string>();
  const previous = ["document", "window", "localStorage", "fetch"].map((key) =>
    [key, Object.getOwnPropertyDescriptor(globalThis, key)] as const,
  );
  const location = { hostname: "example.test", hash: "#/targets" };
  Object.defineProperties(globalThis, {
    document: { configurable: true, value: { querySelector: () => null } },
    window: { configurable: true, value: { location } },
    localStorage: { configurable: true, value: {
      getItem: (key: string) => keys.get(key) ?? null,
      setItem: (key: string, value: string) => { keys.set(key, value); },
      removeItem: (key: string) => { keys.delete(key); },
    } },
    fetch: { configurable: true, value: async () => Response.json({ error: "unauthorized" }, { status: 401 }) },
  });
  try {
    session.set();
    await assert.rejects(api.profile());
    assert.equal(location.hash, "#/signin");
    assert.equal(session.isSignedIn, false);

    location.hash = "#/forgot";
    globalThis.fetch = async () => Response.json({ error: "invalid_credentials" }, { status: 401 });
    await assert.rejects(api.login("person@example.test", "wrong"));
    assert.equal(location.hash, "#/forgot");
  } finally {
    for (const [key, descriptor] of previous) {
      if (descriptor) Object.defineProperty(globalThis, key, descriptor);
      else Reflect.deleteProperty(globalThis, key);
    }
  }
});
