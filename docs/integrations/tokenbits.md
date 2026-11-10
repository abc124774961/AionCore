# Optional TokenBits integration

AionUi retains its existing name, providers, and agent configurations. TokenBits is
an additional, optional source of OpenAI-chat model connections. External CLI
credential configuration is not changed by this integration.

The Core facade is `/api/integrations/tokenbits`. Its request/response DTOs live in
`crates/aionui-api-types/src/tokenbits.rs`. Responses use the ordinary Core
`ApiResponse`/`ErrorResponse` envelopes and Unix-second timestamps.

| Method | Suffix | Input / result |
| --- | --- | --- |
| GET | `/status` | Connection status, API issuer, browser origin, device ID, account identity, last synchronization, enabled provider count |
| POST | `/browser-authorizations` | `{client_id, device_name, redirect_uri?}`; returns flow ID, browser authorization URL, expiry and desktop/web mode |
| POST | `/browser-authorizations/complete` | Web-only `{flow_id, code, state}` with the original browser-binding cookie; returns authorized status |
| GET | `/browser-authorizations/{id}` | Pending, authorized or expired status; never exchanges credentials |
| DELETE | `/browser-authorizations/{id}` | Cancel flow and close its desktop callback listener |
| POST | `/device-authorizations` | `{client_id, device_name}`; returns flow ID, user code, verification URLs, interval and expiry |
| POST | `/device-authorizations/{id}/poll` | No secret input; returns pending, authorized, slow_down, denied or expired |
| DELETE | `/device-authorizations/{id}` | Cancel this Core user's outstanding flow |
| GET | `/account` | Wallet/subscription information from TokenBits, without credential material |
| GET | `/catalog` | Current allowed model groups and model metadata; no inference call |
| POST | `/sync` | `{group, models}`; explicit group, at most 20 exact model IDs; an empty models list selects that group's recommendation |
| DELETE | `/connection` | Revoke the remote device, then clear local secrets and disable its providers |

Every facade request requires `X-AionUi-Integration: tokenbits`. Web mode uses the
existing Core user session and CSRF middleware. Conversation-helper runtime tokens
do not authorize this domain. Local mode additionally requires
`X-AionUi-Local-Secret` matching a per-launch secret supplied by the desktop main
process via `AIONUI_TOKENBITS_LOCAL_SECRET`. The desktop should generate at least
32 random bytes and provide them only through its trusted preload bridge. The
secret is never sent to TokenBits. Local mode rejects missing startup secrets and
untrusted browser origins. All facade responses are `Cache-Control: no-store`.

The default issuer is `https://api.tokenbits.net`. Only the process startup setting
`AIONUI_TOKENBITS_ISSUER` can override it. HTTPS is required except for loopback HTTP
fixtures. The browser origin defaults to `https://ai.tokenbits.net` for that official
issuer so an existing site login can be reused. Custom issuers default to their own
origin; the startup-only `AIONUI_TOKENBITS_BROWSER_ORIGIN` can override it with an
HTTPS or loopback HTTP origin. Frontend requests cannot choose either origin. Legacy
verification URLs, top-up URLs and model API base URLs stay on the API issuer;
new browser authorization URLs use the separately configured browser origin.
HTTP redirects are disabled for API calls, which also have timeouts and bounded
response sizes.

Opening the connection flow uses a front-channel authorization code. An already
logged-in TokenBits browser automatically returns to AionUi without a second grant
button. An unauthenticated browser still signs in normally. Core owns a random
state, PKCE verifier, exact redirect URI and ten-minute flow lifetime. The gateway
limits the returned code to sixty seconds and binds its exchange to the proof key
and redirect. Legacy device-code links retain their original explicit confirmation;
they cannot exchange the new browser codes.

Desktop mode binds an ephemeral listener only on `127.0.0.1`, checks the exact Host,
path and random state, and closes it on completion, cancel or expiry. The listener
does not log request URLs. Web mode requires a redirect on the request's own origin,
with a fixed `/tokenbits/callback` path; HTTP is allowed only on loopback. The issuer
also requires an explicit allowlist for remote HTTPS Web origins. A random HttpOnly,
SameSite=Strict cookie binds the pending flow to the same browser, in addition to
Core authentication and CSRF. A different browser for the same account cannot
complete it. Web code/state arrive in a fragment that the UI clears before loading
the workbench; desktop receives only the short-lived code at its local callback.

After a successful Web complete the binding cookie is cleared. If response headers
arrive but the body is lost, retrying complete is deliberately rejected; the UI can
recover by querying the authenticated flow-status endpoint and accepting an already
authorized status. A retained-cookie retry uses the same exchange identity and is
idempotent. Pending flow state is memory-only, so a Core restart requires a new flow.
No connection or background status operation sends a model request. Explicit
disconnect cancels outstanding flows and does not start another one automatically.

Core owns PKCE verifier, device code, access/refresh tokens and dedicated model
keys. Pending authorization state expires in memory. Account state is encrypted
using Core's AES-256-GCM storage key; no TokenBits secrets enter API responses.
Refresh is serialized per Core user and keeps its exchange identity across failed
transport/storage attempts. Successful rotation persists both credentials together.

A single-model TokenBits connection maps to one ordinary provider row with an
explicit `credential_source=tokenbits`. Its name includes the billing group and
model. Its API key remains encrypted and is always empty in provider responses.
Generic provider edit/delete/fetch-model operations reject managed providers.
Synchronization adds or updates only explicitly selected models and preserves
previous selections. It stages remote results before a single local transaction.
Managed models use OpenAI chat completions without claiming other protocols or
undeclared model capabilities.

Managed provider state is checked at runtime creation and before every new Aionrs
turn, including cached runtimes. Disabling or disconnecting prevents new turns;
existing upstream streams are not forcibly terminated. Remote revocation can take
up to the gateway's documented cache propagation window. A model connection that
was separately disabled remotely returns `connection_inactive`; reconnect the
TokenBits device to establish a new connection.

Disconnect reports success only after remote revocation succeeds or a known device
is explicitly reported revoked. Expired/invalid credentials alone do not prove
revocation: `TOKENBITS_REVOCATION_UNCONFIRMED` preserves local state and directs the
user to revoke the device in TokenBits. A subsequent request can then confirm it
while the gateway retains the credential record.

The storage key may reside in the same database under Core's existing default
configuration. This is encryption at rest, not OS-keychain-backed protection.
Hosted deployments should set `AIONUI_ENCRYPTION_SECRET` outside the database and
protect the full data directory. Full untrusted multi-user execution isolation
requires separate Core/container/OS boundaries; user-scoped records alone do not
sandbox file access or agent execution.

## macOS arm64 desktop bundle

Build this source with the pinned Rust toolchain:

```sh
cargo build --release --target aarch64-apple-darwin -p aionui-app --bin aioncore
mkdir -p output/tokenbits-managed-bundle
cp target/aarch64-apple-darwin/release/aioncore output/tokenbits-managed-bundle/aioncore
AIONUI_BUNDLED_MANAGED_RESOURCES='' output/tokenbits-managed-bundle/aioncore \
  --data-dir output/tokenbits-managed-prepare-data \
  prepare-managed-resources \
  --bundle-out output/tokenbits-managed-bundle/managed-resources
```

Pass the absolute bundle directory to AionUi packaging as
`AIONUI_BACKEND_LOCAL_BUNDLE_DIR`, together with an explicit
`AIONUI_BACKEND_VERSION` (for example `v0.2.2-tokenbits`) rather than `latest`.
The complete local bundle is selected before the release download.
`AIONUI_BACKEND_LOCAL_BINARY` alone is a fallback after release download and does
not guarantee that this integration-enabled binary is packaged. Verify the copied
binary hash and the AionUi bundle manifest's `sourceType: local-bundle` after
packaging. Managed resources are exported by Core's
`prepare-managed-resources` command; AionUi's shared bundle verifier validates
its resource manifest before packaging.
