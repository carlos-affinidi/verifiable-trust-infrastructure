# WebVH hosting-type alignment and daemon REST auth follow-up

Status: implemented and validated on the current branch.

This note started as the hosting-type alignment plan. It now records the
completed daemon REST-auth follow-up that closes the registered
`webvh-daemon` blocker. The remaining WebVH auth-state leak remediation is now
tracked separately in `docs/05-design-notes/webvh_server_auth_state_leak_remediation_plan.md`.

Related:
- `vta-service/src/operations/did_webvh/servers.rs`
- `vta-service/src/operations/did_webvh/mod.rs`
- `vta-service/src/webvh_client.rs`
- `vta-sdk/src/webvh.rs`
- `affinidi-webvh-service/webvh-daemon/src/main.rs`
- `affinidi-webvh-service/webvh-control/src/routes/mod.rs`
- `affinidi-webvh-service/webvh-control/src/routes/auth.rs`

## Outcome

VTA now supports the full registered-server flow for a REST-only
`webvh-daemon`:

- `vta webvh add-server` accepts hosting DIDs that advertise `WebVHHosting`
- transport resolution falls back to REST when DIDComm is absent
- VTA authenticates to the daemon as its configured `vta_did`
- VTA persists WebVH token state on the registered server record, reuses fresh
  access tokens, attempts refresh when possible, and falls back to full
  re-authentication when needed
- TGW `create_if_missing = true` can publish through a registered
  `webvh-daemon` once the daemon ACL includes the VTA DID

## Hosting-type alignment

Accepted server service types:

- `DIDCommMessaging`
- `WebVHHosting`
- `WebVHHostingService`

Transport resolution rules:

1. prefer `DIDCommMessaging`
2. otherwise use REST for `WebVHHosting`
3. otherwise use REST for `WebVHHostingService`

`WebVHHostingService` remains a compatibility alias.

## Daemon REST-auth validation

### Daemon-side contract

Validated in the current `affinidi-webvh-service` code:

- in daemon mode, the control-plane router is merged at the daemon root, so the
  same origin exposes both `/api/auth/*` and `/api/dids*`
- `POST /api/auth/challenge` issues a nonce bound to the requested DID
- `POST /api/auth/` expects a signed DIDComm
  `https://affinidi.com/webvh/1.0/authenticate` message
- daemon auth checks the sender DID against the daemon ACL before issuing a
  bearer token
- the DID-management endpoints under `/api/dids*` require that bearer token

This matches the single-daemon local shape used by the TGW runbook.

### VTA-side implementation

Validated in the current `verifiable-trust-infrastructure` code:

- `WebvhClient::authenticate()` drives the daemon challenge-response flow over
  REST by calling `/api/auth/challenge`, signing the returned challenge as the
  VTA DID, and submitting the packed message to `/api/auth/`
- `resolve_server_transport()` prefers DIDComm when available and otherwise
  resolves `WebVHHosting` / `WebVHHostingService` endpoints to REST
- `build_authenticated_rest_client()`:
  - reuses a stored access token when it remains outside the 30-second refresh
    skew window
  - otherwise attempts `/api/auth/refresh` when a refresh token exists
  - falls back to full re-authentication as the configured `vta_did` when
    refresh is unavailable or rejected
  - persists the updated token state back into the registered server record
- REST publication then uses bearer auth for:
  - `POST /api/dids`
  - `POST /api/dids/check`
  - `PUT /api/dids/{mnemonic}`
  - `DELETE /api/dids/{mnemonic}`

### Operational requirement

The daemon ACL must contain the **VTA DID**, not the TGW credential DID.
For the single-daemon local PoC, `owner` remains sufficient.

## Validation performed

Code inspection confirmed:

- daemon root-path API shape and auth contract
- VTA REST-auth handshake compatibility with the daemon
- persistence and reuse of WebVH access-token state in the server record
- refresh-first / re-auth fallback behavior for stale token state

Targeted VTA tests passed:

```bash
cargo test -p vta-service supported_server_service
cargo test -p vta-service resolve_server_transport
cargo test -p vta-service access_token_is_fresh
cargo test -p vta-service apply_webvh_auth_state
```

These cover:

- server admission for `DIDCommMessaging`, `WebVHHosting`, and
  `WebVHHostingService`
- transport resolution for DIDComm-vs-REST selection
- access-token freshness checks and refresh skew handling
- auth-state persistence semantics when refresh does not issue a new refresh
  token

## Remaining follow-up

### Token-redaction gap

`WebvhServerRecord` now carries:

- `access_token`
- `access_expires_at`
- `refresh_token`

That same struct is currently used for:

- persistence in the `webvh` keyspace
- REST and DIDComm `list webvh servers` responses
- SDK result types
- backup payload serialization

`list_webvh_servers()` is callable by any authenticated VTA caller and currently
returns the full `WebvhServerRecord`. Once a server has been used, that means
non-super-admin callers can receive live WebVH bearer / refresh-token state.

The remediation plan for this leak now lives in:

- `docs/05-design-notes/webvh_server_auth_state_leak_remediation_plan.md`

## Current limitation

REST auth currently assumes the VTA signing key is seed-derived
(`KeyOrigin::Derived`). A deployment whose active VTA identity key is imported
will fail in `load_vta_signing_secret()` until that path learns how to load the
imported signing secret.

## Result

The original hosting-type mismatch remains resolved and the daemon REST-auth
blocker is closed for the registered `webvh-daemon` flow. The remaining planned
security follow-up is to separate WebVH server auth cache from the public server
record and backup surface so VTA APIs, SDK events, and backups no longer
serialize live daemon tokens.
