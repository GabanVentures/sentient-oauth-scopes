// Shared TastyTrade OAuth scope normalization.
//
// Single source of truth for the platform (sentient-options-platform) and
// bot (agent-scripts). If you change semantics here, both consumers pick it
// up via npm. Drift was the failure mode that motivated this package — the
// dashboard's smoke test once requested only `read` while the bot demanded
// `trade`, so a valid-looking save could still crash production on the next
// order. Don't reintroduce that by branching the logic in either repo.

/**
 * Scopes the live trading daemon requires before it will place orders.
 * The bot verifies these explicitly after auth; the dashboard verifies them
 * at credential-save time so the failure surfaces to the user, not the bot.
 */
export const REQUIRED_TRADING_SCOPES = Object.freeze(["read", "trade"]);

/**
 * Normalize any of TastyTrade's scope encodings into a sorted, lowercased
 * string array. Accepts either a space/comma-separated string or an array.
 * Anything else becomes [].
 *
 * @param {unknown} input
 * @returns {string[]}
 */
export function normalizeScopes(input) {
  if (Array.isArray(input)) {
    // Trim + lowercase + drop empties so " READ " and "READ" hash to "read"
    // regardless of which encoding TastyTrade returned. The string branch
    // already does this; both branches must agree or verifyRequiredScopes
    // gets false negatives when scopes arrive with stray whitespace.
    return input
      .filter((s) => typeof s === "string")
      .map((s) => s.trim().toLowerCase())
      .filter((s) => s.length > 0);
  }
  if (typeof input === "string") {
    return input
      .split(/[\s,]+/)
      .map((s) => s.trim().toLowerCase())
      .filter((s) => s.length > 0);
  }
  return [];
}

/**
 * Decode a JWT payload without verifying its signature. Used only to read
 * the `scope` / `scp` / `scopes` claim when the OAuth response doesn't
 * include the granted scopes at the top level — TastyTrade is inconsistent
 * about where it puts them. We're not authenticating with this, just
 * inspecting the bearer's stated capabilities.
 *
 * @param {string} token
 * @returns {Record<string, unknown> | null}
 */
export function decodeJwtPayload(token) {
  if (typeof token !== "string") return null;
  const parts = token.split(".");
  if (parts.length < 2 || !parts[1]) return null;
  try {
    const padded = parts[1].replace(/-/g, "+").replace(/_/g, "/");
    const padding = padded.length % 4 === 0 ? "" : "=".repeat(4 - (padded.length % 4));
    const decoded = globalThis.Buffer
      ? globalThis.Buffer.from(padded + padding, "base64").toString("utf8")
      : new TextDecoder().decode(Uint8Array.from(atob(padded + padding), (c) => c.charCodeAt(0)));
    return JSON.parse(decoded);
  } catch {
    return null;
  }
}

/**
 * Pull the granted-scopes list out of a TastyTrade OAuth token response.
 * Fallback chain:
 *   1. `payload.scope`
 *   2. `payload.scp`
 *   3. `payload.scopes`
 *   4. Same three keys, but under `payload.data`.
 *   5. Decode the access-token JWT and try `scope` / `scp` / `scopes` there.
 *
 * Returns [] if nothing usable is found — caller should treat that as a
 * "didn't grant the trading scopes we need" failure rather than as
 * "any scope was granted."
 *
 * @param {Record<string, unknown>} payload
 * @param {string} accessToken
 * @returns {string[]}
 */
export function extractGrantedScopes(payload, accessToken) {
  const data = /** @type {Record<string, unknown> | undefined} */ (payload?.data);
  /** @type {unknown[]} */
  const candidates = [
    payload?.scope,
    payload?.scp,
    payload?.scopes,
    data?.scope,
    data?.scp,
    data?.scopes,
  ];
  for (const candidate of candidates) {
    const scopes = normalizeScopes(candidate);
    if (scopes.length > 0) return scopes;
  }
  const claim = decodeJwtPayload(accessToken);
  if (claim) {
    const fromClaim = normalizeScopes(claim.scope ?? claim.scp ?? claim.scopes);
    if (fromClaim.length > 0) return fromClaim;
  }
  return [];
}

/**
 * Convenience for credential-validation flows. Returns `{ ok: true }` if
 * every scope in `required` is present in `granted`, otherwise `{ ok: false,
 * missing: [...] }`. Case-insensitive — `granted` is expected to be the
 * output of normalizeScopes / extractGrantedScopes (already lowercased).
 *
 * @param {readonly string[]} granted
 * @param {readonly string[]} [required]
 * @returns {{ ok: true } | { ok: false; missing: string[] }}
 */
export function verifyRequiredScopes(granted, required = REQUIRED_TRADING_SCOPES) {
  const grantedSet = new Set(granted.map((s) => s.toLowerCase()));
  const missing = required
    .map((s) => s.toLowerCase())
    .filter((s) => !grantedSet.has(s));
  if (missing.length === 0) return { ok: true };
  return { ok: false, missing };
}
