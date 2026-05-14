# @sentient/oauth-scopes

Shared TastyTrade OAuth scope normalization for the [Sentient Trading bot](https://github.com/GabanVentures/agent-scripts) and [dashboard](https://github.com/GabanVentures/sentient-options-platform).

## Why this exists

The dashboard runs a credential-save smoke test that hits TastyTrade and verifies the granted scopes include `trade` before persisting the row. The bot runs the same verification at daemon startup before accepting the session for live order placement. If those two parsers drift, you get one of two failure modes:

- **Save-time false positive** — dashboard accepts a token the bot will later reject, causing a crash loop on the NYC server.
- **Save-time false negative** — dashboard rejects a token the bot would accept, blocking onboarding for no real reason.

This package is the single source of truth so both sides can't disagree.

## Install

In each repo's `package.json`:

```jsonc
"dependencies": {
  "@sentient/oauth-scopes": "github:GabanVentures/sentient-oauth-scopes#v0.1.0"
}
```

Pin to a tag (`#v0.1.0`) — never to `main` — so upgrades are deliberate and visible in PR diffs.

## Usage

```js
import {
  REQUIRED_TRADING_SCOPES,
  extractGrantedScopes,
  verifyRequiredScopes,
} from "@sentient/oauth-scopes";

const granted = extractGrantedScopes(oauthResponse, accessToken);
const check = verifyRequiredScopes(granted);
if (!check.ok) {
  throw new Error(`Missing scopes: ${check.missing.join(", ")}`);
}
```

## API

| Export | What |
|---|---|
| `REQUIRED_TRADING_SCOPES` | `["read", "trade"]` — the canonical pair the trading daemon needs |
| `normalizeScopes(input)` | String or array → lowercased string array |
| `decodeJwtPayload(token)` | Read a JWT's payload claim (no signature verification) |
| `extractGrantedScopes(payload, accessToken)` | Pull granted scopes from a TT OAuth response. Falls back through `scope`, `scp`, `scopes` at top-level, `data.*`, and JWT claim |
| `verifyRequiredScopes(granted, required?)` | `{ ok: true }` or `{ ok: false, missing: [...] }` |

## Run the tests

```bash
node --test test/index.test.js
```

27 tests covering every branch of the fallback chain. Add a test before every behaviour change — these guarantees are load-bearing for production trading.
