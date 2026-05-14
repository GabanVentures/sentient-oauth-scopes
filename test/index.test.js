import { describe, test } from "node:test";
import assert from "node:assert/strict";
import {
  REQUIRED_TRADING_SCOPES,
  decodeJwtPayload,
  extractGrantedScopes,
  normalizeScopes,
  verifyRequiredScopes,
} from "../src/index.js";

describe("normalizeScopes", () => {
  test("space-separated string", () => {
    assert.deepEqual(normalizeScopes("read trade"), ["read", "trade"]);
  });
  test("comma-separated string", () => {
    assert.deepEqual(normalizeScopes("read, trade"), ["read", "trade"]);
  });
  test("array of strings", () => {
    assert.deepEqual(normalizeScopes(["Read", "Trade"]), ["read", "trade"]);
  });
  test("lowercases entries", () => {
    assert.deepEqual(normalizeScopes("READ TRADE"), ["read", "trade"]);
  });
  test("array filters non-strings", () => {
    assert.deepEqual(normalizeScopes(["read", 42, null, "trade"]), ["read", "trade"]);
  });
  test("returns [] for unsupported types", () => {
    assert.deepEqual(normalizeScopes(null), []);
    assert.deepEqual(normalizeScopes(undefined), []);
    assert.deepEqual(normalizeScopes({}), []);
    assert.deepEqual(normalizeScopes(42), []);
  });
});

describe("decodeJwtPayload", () => {
  test("decodes a well-formed JWT payload", () => {
    // header.payload.sig — payload is `{"scope":"read trade"}`
    const token = "eyJhbGciOiJIUzI1NiJ9.eyJzY29wZSI6InJlYWQgdHJhZGUifQ.sig";
    const claim = decodeJwtPayload(token);
    assert.deepEqual(claim, { scope: "read trade" });
  });
  test("returns null for malformed tokens", () => {
    assert.equal(decodeJwtPayload("not.a.jwt"), null);
    assert.equal(decodeJwtPayload("only-one-part"), null);
    assert.equal(decodeJwtPayload(""), null);
  });
  test("returns null for non-string inputs", () => {
    // @ts-expect-error - testing runtime guard
    assert.equal(decodeJwtPayload(null), null);
    // @ts-expect-error - testing runtime guard
    assert.equal(decodeJwtPayload(42), null);
  });
});

describe("extractGrantedScopes — fallback chain", () => {
  // Helper: build a JWT with the given payload object.
  function buildJwt(payloadObj) {
    const base64Url = (str) =>
      Buffer.from(str).toString("base64").replace(/=+$/, "").replace(/\+/g, "-").replace(/\//g, "_");
    return `eyJhbGciOiJIUzI1NiJ9.${base64Url(JSON.stringify(payloadObj))}.sig`;
  }

  test("reads payload.scope (preferred)", () => {
    assert.deepEqual(
      extractGrantedScopes({ scope: "read trade" }, "irrelevant"),
      ["read", "trade"],
    );
  });

  test("falls back to payload.scp", () => {
    assert.deepEqual(
      extractGrantedScopes({ scp: ["read", "trade"] }, "irrelevant"),
      ["read", "trade"],
    );
  });

  test("falls back to payload.scopes", () => {
    assert.deepEqual(
      extractGrantedScopes({ scopes: "read,trade" }, "irrelevant"),
      ["read", "trade"],
    );
  });

  test("falls back to payload.data.scope", () => {
    assert.deepEqual(
      extractGrantedScopes({ data: { scope: "read trade" } }, "irrelevant"),
      ["read", "trade"],
    );
  });

  test("falls back to payload.data.scp", () => {
    assert.deepEqual(
      extractGrantedScopes({ data: { scp: ["read", "trade"] } }, "irrelevant"),
      ["read", "trade"],
    );
  });

  test("falls back to JWT claim.scope", () => {
    const token = buildJwt({ scope: "read trade" });
    assert.deepEqual(extractGrantedScopes({}, token), ["read", "trade"]);
  });

  test("falls back to JWT claim.scp", () => {
    const token = buildJwt({ scp: ["read", "trade"] });
    assert.deepEqual(extractGrantedScopes({}, token), ["read", "trade"]);
  });

  test("returns [] when nothing usable is found", () => {
    assert.deepEqual(extractGrantedScopes({}, "not.a.jwt"), []);
  });

  test("returns [] for an unrelated payload + invalid JWT", () => {
    assert.deepEqual(
      extractGrantedScopes({ unrelated_field: "value" }, ""),
      [],
    );
  });

  test("does not silently 'fall through' a present-but-empty source", () => {
    // payload.scope is empty string — extractor should treat it as "no
    // info here" and try the next candidate.
    assert.deepEqual(
      extractGrantedScopes({ scope: "", scp: "read trade" }, "irrelevant"),
      ["read", "trade"],
    );
  });
});

describe("verifyRequiredScopes", () => {
  test("ok when all required scopes are granted", () => {
    assert.deepEqual(
      verifyRequiredScopes(["read", "trade"]),
      { ok: true },
    );
  });

  test("ok when granted has more than required", () => {
    assert.deepEqual(
      verifyRequiredScopes(["read", "trade", "admin"]),
      { ok: true },
    );
  });

  test("reports missing scopes", () => {
    assert.deepEqual(
      verifyRequiredScopes(["read"]),
      { ok: false, missing: ["trade"] },
    );
  });

  test("reports all missing when nothing granted", () => {
    assert.deepEqual(
      verifyRequiredScopes([]),
      { ok: false, missing: ["read", "trade"] },
    );
  });

  test("case-insensitive comparison", () => {
    assert.deepEqual(
      verifyRequiredScopes(["READ", "TRADE"]),
      { ok: true },
    );
  });

  test("custom required scopes", () => {
    assert.deepEqual(
      verifyRequiredScopes(["read"], ["read", "admin"]),
      { ok: false, missing: ["admin"] },
    );
  });
});

describe("REQUIRED_TRADING_SCOPES", () => {
  test("is the canonical pair", () => {
    assert.deepEqual([...REQUIRED_TRADING_SCOPES], ["read", "trade"]);
  });
  test("is frozen", () => {
    assert.throws(() => {
      // @ts-expect-error - intentional runtime mutation attempt
      REQUIRED_TRADING_SCOPES.push("admin");
    });
  });
});
