# WebVH server auth-state leak remediation plan

Status: planned. This note captures a design finding from the WebVH daemon REST-auth work; the remediation should ship together with that functionality.

Related:
- `docs/05-design-notes/webvh_hosting_type_alignment_plan.md`
- `vta-sdk/src/webvh.rs`
- `vta-sdk/src/protocols/did_management/servers.rs`
- `vta-sdk/src/provision_client/event.rs`
- `vta-service/src/webvh_store.rs`
- `vta-service/src/operations/did_webvh/servers.rs`
- `vta-service/src/operations/did_webvh/mod.rs`
- `vta-service/src/operations/backup.rs`

## Problem

The WebVH daemon REST-auth work exposed a design problem in the current server
record boundary: `WebvhServerRecord` mixes operator-visible server metadata with
daemon REST auth cache:

- `access_token`
- `access_expires_at`
- `refresh_token`

That same public SDK type is reused for:

- persistence in the `webvh` keyspace under `server:{id}`
- REST and DIDComm `list webvh servers` responses
- SDK preflight/event payloads such as `PreflightDone`
- backup payload serialization

Persisting daemon auth state in `WebvhServerRecord` would expose live WebVH
bearer state on every surface that serializes the record.

## Decisions

- Treat this as a type-boundary design fix that lands with the daemon REST-auth
  work, not as a follow-up response-redaction patch.
- Fix the issue at the type and storage boundary, not by redacting individual
  response handlers.
- Make the public `WebvhServerRecord` metadata-only.
- Introduce a service-private auth-state record for daemon REST auth cache.
- Persist metadata under `server:{id}` and auth cache under `server-auth:{id}`.
- Exclude WebVH auth cache from backup export/import.
- Take the public SDK/API change as a clean break in the next workspace
  release; bump workspace crate versions together and keep internal dependency
  versions aligned.
- Preserve read compatibility with legacy `server:{id}` values and legacy
  backups that still contain embedded auth fields.

## Plan

### Public type split

Update `vta-sdk/src/webvh.rs` so `WebvhServerRecord` contains only:

- `id`
- `did`
- `label`
- `created_at`
- `updated_at`

Keep `vta-sdk/src/protocols/did_management/servers.rs`,
`vta-sdk/src/provision_client/event.rs`, and CLI callers on that metadata-only
shape.

### Storage split

Add a service-private auth-state type in `vta-service` for:

- `access_token`
- `access_expires_at`
- `refresh_token`

Extend `vta-service/src/webvh_store.rs` with helpers to load, store, and delete
`server-auth:{id}` independently of `server:{id}`.

### Runtime auth refactor

Update `vta-service/src/operations/did_webvh/mod.rs` so
`build_authenticated_rest_client()`:

- loads auth cache from `server-auth:{id}`
- reuses a fresh access token when available
- attempts refresh when a refresh token exists
- falls back to full re-authentication when refresh is unavailable or rejected
- writes back only `server-auth:{id}` after refresh or re-auth

`add_webvh_server()`, `update_webvh_server()`, and `list_webvh_servers()` in
`vta-service/src/operations/did_webvh/servers.rs` remain metadata-only.

### Backup behavior

Keep `BackupPayload.webvh_servers` metadata-only.

Do not export or import `server-auth:{id}` records. Treat WebVH daemon auth
state as runtime cache that can be repopulated on the next REST-authenticated
publication attempt.

Update `vta-service/src/operations/backup.rs` so export only collects `server:`
entries and restore only writes metadata back under `server:{id}`.

### Compatibility

Older `server:{id}` values and old backups may still contain embedded
`access_token`, `access_expires_at`, and `refresh_token` fields.

The new metadata-only `WebvhServerRecord` must deserialize those payloads
without failing and ignore the embedded auth fields.

No token migration is required. On the first REST-authenticated daemon call
after upgrade or restore, the VTA re-authenticates and writes fresh
`server-auth:{id}` state.

### Validation

Add or update targeted tests for:

- REST `list webvh servers` responses not serializing auth fields
- DIDComm `list_webvh_servers` responses not serializing auth fields
- SDK preflight server catalog remaining metadata-only
- auth-state persistence across token reuse, refresh, and re-auth
- backup export excluding `server-auth:` records
- restore compatibility with legacy backups that still embed auth fields

## Out of scope

These defense-in-depth items are future improvements, not part of this follow-up:

- custom `Debug` redaction and broader log-hardening for the storage-only
  auth-state type
- additional authorization tightening for WebVH server metadata read paths
- proactive auth-state scrubbing or rotation beyond the storage split
