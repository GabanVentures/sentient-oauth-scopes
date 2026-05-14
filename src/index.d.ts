/**
 * Scopes the live trading daemon requires before it will place orders.
 */
export const REQUIRED_TRADING_SCOPES: readonly ["read", "trade"];

/**
 * Normalize any of TastyTrade's scope encodings into a lowercased string
 * array. Accepts a space/comma-separated string or an array. Anything
 * else becomes [].
 */
export function normalizeScopes(input: unknown): string[];

/**
 * Decode a JWT payload WITHOUT verifying its signature. Used only to
 * inspect the bearer's stated `scope` / `scp` / `scopes` claim when the
 * OAuth response omits granted scopes at the top level.
 */
export function decodeJwtPayload(token: string): Record<string, unknown> | null;

/**
 * Pull the granted-scopes list out of a TastyTrade OAuth token response.
 * See implementation for the full fallback chain.
 *
 * Returns [] if nothing usable is found.
 */
export function extractGrantedScopes(
  payload: Record<string, unknown>,
  accessToken: string,
): string[];

/**
 * Returns `{ ok: true }` if every scope in `required` is present in
 * `granted`, otherwise `{ ok: false, missing: [...] }`. Case-insensitive.
 */
export function verifyRequiredScopes(
  granted: readonly string[],
  required?: readonly string[],
): { ok: true } | { ok: false; missing: string[] };
