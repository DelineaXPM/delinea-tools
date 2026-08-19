# External API contracts

This is the complete set of Delinea REST/Identity behaviors the **engine**
hard-codes. Everything else is reached through `api.Do`, where the caller owns
the path and body, so it is not pinned here.

Two properties bound the risk:

- **Additive changes are free.** Decoding uses `encoding/json` with no
  `DisallowUnknownFields`, so fields or endpoints Delinea *adds* are ignored,
  not errors. Only a **removed/renamed field, a changed path, or a changed
  semantic** in the list below can break us.
- **The offline suite cannot detect a break here** — it pins these same shapes
  in fixtures. The live e2e suite (`.github/workflows/e2e.yml`, `make e2e`)
  against a real tenant is the detector. Run it on the schedule; a red run
  points at the contract below that moved.

When something breaks, the fix is almost always in the one file named against
each contract.

## Token grants — `api/auth.go`

| | |
|---|---|
| Secret Server | `POST {URL}/oauth2/token`, form `grant_type=password`, `username`, `password`, optional `domain` |
| Platform | `POST {URL}/identity/api/oauth2/token/xpmplatform`, form `grant_type=client_credentials`, `client_id`, `client_secret`, `scope=xpmheadless` |
| Response (both) | JSON `access_token` (required, at least four bytes), `token_type` (must be empty or `Bearer`), `expires_in` (seconds, `0 < n ≤ 365d`) |

A non-2xx with status 400/401/403 is classified `ErrAccessDenied`; retryable
408/429/500/502/503/504 responses are `ErrTransport`; redirects are `ErrConfig`;
other completed failures are `ErrAuth`.

Responses are limited to 1 MiB and a successful response over that limit is
rejected. Endpoint-controlled diagnostics redact the submitted password,
client secret, configured bearer token, and current granted token before they
are returned to the caller. Identity prompts and summaries also redact prior
MFA answers.

## Pre-obtained-token validation — `api/auth.go`

`Client.Authenticate` validates a configured bearer token with one read-only
request: `GET /api/v1/users/current` for Secret Server or
`GET /vaultbroker/api/vaults` for Platform. Because the endpoint depends on the
service, callers using a pre-obtained token with `Authenticate` must set
`Config.Target` explicitly.

## Authenticated request recovery — `api/client.go`

- A reused token rejected with 401 is evicted. GET and HEAD are granted a new
  token and replayed once; mutating methods are never replayed and never follow
  redirects, including same-origin 307/308 responses that preserve the body.
- Secret Server's documented token-expiration operation produces a distinct
  stale-authentication response: 403 with a bounded JSON object containing only
  `{"message":"Authentication failed or expired token."}`. A reused token
  receiving that exact response is also evicted; GET/HEAD are eligible for one
  replay and mutations are returned without replay after eviction. Because HTTP
  omits response bodies for HEAD, a 403 HEAD is confirmed with one read-only
  current-user GET using the same token before it is classified as stale. The
  streamed response classifier restores every byte it inspects before returning
  a nonmatching or mutating response to the caller.
- A token first granted during the current call is not replayed when rejected:
  it is already current, so another grant cannot repair the request.
- Every other 403 is resource authorization and is returned unchanged. It
  neither evicts the token nor replays the request. This follows OAuth bearer
  semantics: `invalid_token` uses 401, while `insufficient_scope` uses 403
  ([RFC 6750 section 3.1](https://www.rfc-editor.org/rfc/rfc6750#section-3.1)).

The strict live suite verifies that deliberately invalid bearer tokens receive
401 from both supported product paths and that a Secret Server token invalidated
through `POST /api/v1/oauth-expiration` is recovered through the exact 403 above.
The 2026-08-18 manual matrix also recorded 401 for both wrong-audience directions.
Platform natural expiration/revocation remains a manual QA case when it can be
induced without disrupting shared tenant credentials or sessions. Any additional
403 recovery must likewise key on an authoritative token-error signal rather than
treating every 403 as stale authentication.

## Timeouts and retries — `api/client.go`, `api/auth.go`

- `Config.Retries` is an attempt count: values below 1 select the default of
  three; 1 disables retries.
- API retries are limited to GET and HEAD. Transport errors, timeouts, and
  408/429/500/502/503/504 are retriable. Writes are never replayed.
- Token grants use the same attempt budget for transport failures and those
  transient statuses. A completed non-transient authentication answer is
  authoritative and is never retried.
- Exponential fallback backoff starts at 200 ms. Fallback and custom backoff are
  clamped to 30 seconds.
- `Retry-After` accepts delta-seconds or an HTTP date up to 30 seconds. A longer
  server-requested delay returns the current outcome immediately rather than
  sleeping, retrying, or substituting fallback backoff.
- `Config.Timeout` defaults to 30 seconds and independently bounds response
  headers, the start of body consumption, and each blocked body read. It is an
  idle/progress limit, not a total duration: a continuously flowing response may
  run longer.

## Vault broker (Platform) — `api/vault.go`

- `GET {URL}/vaultbroker/api/vaults`
- Response: `{"vaults":[{ "vaultId","name","type","isDefault","isGlobalDefault","isActive","connection":{"url"} }]}`
- We select the first vault with `isDefault && isActive` and route vault calls to `connection.url`.
- A selected route is memoized per vault ID for five minutes. After expiry the
  next caller synchronously refreshes it; concurrent callers for that ID share
  one lookup. Refresh failure is returned rather than using expired routing
  data. Different vault IDs refresh independently.
- **Trust policy** (the broker URL is untrusted input): must be https, no
  userinfo/query/fragment, host must be same-origin with the platform, on the
  cloud-domain allowlist, or explicitly allowed via `AllowedVaultHosts` /
  `--vault-allow`. Automatic cloud trust and a hostname-only explicit entry
  cover port 443 only; an alternate port requires the exact `host:port`.
- **Cloud-domain allowlist** (`delineaCloudVaultDomains`): `devsecretservercloud.com`,
  `secretservercloud.com`, `.eu`, `.com.au`, `.com.sg`, `.ca`, `.co.uk`, `.ae`.
  New Delinea cloud regions must be added here — but operators are never blocked
  meanwhile, because `--vault-allow` is the escape hatch.

## Identity login (Platform, native-account MFA) — `api/identity.go`

The most string-dependent contract, and the least e2e-covered (its out-of-band
path needs a human mailbox). Highest drift risk.

- Endpoints: `POST /identity/Security/StartAuthentication`, `POST /identity/Security/AdvanceAuthentication`
- Envelope: `{"success":bool,"Result":{...},"Message":string}`
- Start result: `SessionId`, `TenantId`, `Redirect` (a non-empty value is refused — federated redirects unsupported), `Challenges[].Mechanisms[]`
- Mechanism: `MechanismId`, `Name` (`UP` = password, auto-answered), `AnswerType` (containing `Oob` = out-of-band), `PromptSelectMech`, `PromptMechChosen`
- Advance result: `Summary`, `Challenges`, `OAuthTokens.access_token`
- `Summary` values we branch on: `LoginSuccess`, `StartNextChallenge`, `NewPackage`, `OobPending`
- Advance actions we send: `Answer`, `StartOOB`, `Poll`
- Non-2xx classification: 401/403 are `ErrAccessDenied`, retryable statuses are
  `ErrTransport`, redirects are `ErrConfig`, and other completed failures are
  `ErrAuth`.
- Responses use the same 1 MiB limit and diagnostic redaction as token grants;
  MFA answers are included in the redaction set.

## Secret read + field download — `secrets/fetcher.go`

- By id: `GET /api/v1/secrets/{id}`
- By path: `GET /api/v1/secrets/0?secretPath={escaped}`
- File field content: `GET /api/v1/secrets/{id}/fields/{slug}` (slug path-escaped;
  empty and dot-segment slugs are rejected before URL resolution)
- Secret JSON: `items[]`, each with `slug`, `itemValue`, `isFile`,
  `fileAttachmentId`, `filename`, `fieldName`. A field is resolved by `slug` or
  `fieldName`. File fields are downloaded and substituted; fan-out is capped
  (count and total bytes).

## Health probe — `api/probe.go`

- `GET {URL}/api/v1/healthcheck` (Secret Server), then `GET {URL}/health` (Platform)
- Only a 2xx response can be healthy. Its body must be valid JSON containing a
  `healthy` boolean whose value is true, or the exact trimmed legacy text
  `Healthy` compared case-insensitively. Other JSON, `Not Healthy`, HTML, and
  arbitrary text containing that word are not health verdicts. The probe sends
  no Delinea credential but does send configured same-origin gateway headers.
  It follows no redirects and redacts configured header values from transport
  diagnostics.

## Not pinned (caller-owned via `api.Do`)

Search (`/api/v1/secrets?filter.searchText=…`), create/update/delete, folders,
and any other endpoint not listed above are constructed by the caller, so an
upstream change to them requires no change to this module — only to the calling
code.
