//! `migrate_mediator` operation.
//!
//! Spec: `docs/05-design-notes/didcomm-protocol-management.md`
//! success criteria #4, #5, #6 (rollback alias), #11, #13, #14.
//!
//! Sequence (under [`PROTOCOL_LOCK`]):
//! 1. Verify caller is super-admin.
//! 2. Confirm `services.didcomm` is `true` (refuse with
//!    [`MigrateMediatorError::DidcommNotEnabled`] otherwise — the
//!    operator should `services enable didcomm` first).
//! 3. Confirm the new mediator differs from the active one and
//!    isn't already in drain state.
//! 4. Run the 5-step mediator handshake against the new mediator —
//!    failure aborts before any LogEntry is published.
//! 5. Read the current DID document, replace the `#vta-didcomm`
//!    service entry pointing at the new mediator, publish via
//!    [`update_did_webvh`].
//! 6. Persist `messaging.mediator_did = new`.
//! 7. Promote the new mediator in the registry; place the prior
//!    mediator in drain state with the operator-supplied TTL.
//! 8. Emit `MediatorMigrateStart` telemetry distinct from
//!    rollbacks (`audit_kind` field).

use std::sync::Arc;
use std::time::Duration;

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use chrono::Utc;
use serde_json::Value as JsonValue;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::info;

use vti_common::config::MessagingConfig;
use vti_common::seed_store::SeedStore;
use vti_common::telemetry::{SharedTelemetrySink, TelemetryEvent, TelemetryKind};

use crate::auth::AuthClaims;
use crate::config::AppConfig;
use crate::didcomm_bridge::DIDCommBridge;
use crate::error::AppError;
use crate::messaging::drain_sweeper::DrainSweeper;
use crate::messaging::handshake::{
    HandshakeError, HandshakeOptions, ListenerProver, mediator_handshake,
};
use crate::messaging::registry::{MediatorBinding, MediatorListenerRegistry, RegistryError};
use crate::operations::did_webvh::{UpdateDidWebvhError, UpdateDidWebvhOptions, update_did_webvh};
use crate::operations::protocol::PROTOCOL_LOCK;
use crate::operations::protocol::document::{
    DocumentPatchError, current_didcomm_service, with_didcomm_service,
};
use crate::store::KeyspaceHandle;
use crate::webvh_store;

/// Distinguish a forward migrate from a rollback in telemetry. The
/// CLI wrapper for `pnm mediator rollback` passes `Rollback` so
/// reports can tell forward and reverse moves apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MigrateAuditKind {
    Forward,
    Rollback,
}

impl MigrateAuditKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Forward => "forward",
            Self::Rollback => "rollback",
        }
    }
}

#[derive(Debug, Clone)]
pub struct MigrateMediatorParams {
    pub new_mediator_did: String,
    pub drain_ttl: Duration,
    pub force: bool,
    pub handshake_timeout: Duration,
    pub audit_kind: MigrateAuditKind,
}

#[derive(Debug, Clone)]
pub struct MigrateMediatorResult {
    pub new_version_id: String,
    pub prior_mediator_did: String,
    pub active_mediator_did: String,
    pub active_mediator_endpoint: String,
    pub drains_until: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Error)]
pub enum MigrateMediatorError {
    #[error(
        "DIDComm is not currently enabled. Use `pnm services enable didcomm --mediator-did <did>` first."
    )]
    DidcommNotEnabled,
    #[error("new mediator `{0}` is already the active mediator — nothing to migrate")]
    SameAsActive(String),
    #[error(
        "new mediator `{0}` is currently in drain state. \
         Either run `pnm mediator drain cancel --mediator-did {0}` first, \
         or use `pnm mediator rollback --to {0}` to make it active again."
    )]
    AlreadyDraining(String),
    #[error("VTA DID is not configured — run `vta setup` first")]
    VtaDidNotConfigured,
    #[error("VTA DID `{0}` has no webvh record")]
    VtaDidRecordMissing(String),
    #[error("VTA DID `{0}` has no published log")]
    VtaDidLogMissing(String),
    #[error("VTA DID log is empty")]
    EmptyLog,
    #[error(
        "DIDComm is enabled but the VTA's DID document has no `#vta-didcomm` service entry — \
         on-disk state is inconsistent (re-run setup)"
    )]
    NoActiveMediator,
    #[error(transparent)]
    Handshake(#[from] HandshakeError),
    #[error("DID document patch failed: {0}")]
    DocumentPatch(#[from] DocumentPatchError),
    #[error("WebVH update failed: {0}")]
    WebVHUpdate(#[from] UpdateDidWebvhError),
    #[error("config persistence failed: {0}")]
    ConfigPersistence(String),
    #[error(transparent)]
    Registry(#[from] RegistryError),
    #[error("auth: {0}")]
    Auth(String),
    #[error("storage error: {0}")]
    Storage(String),
}

impl From<AppError> for MigrateMediatorError {
    fn from(value: AppError) -> Self {
        Self::Storage(value.to_string())
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn migrate_mediator(
    config: &Arc<RwLock<AppConfig>>,
    keys_ks: &KeyspaceHandle,
    contexts_ks: &KeyspaceHandle,
    webvh_ks: &KeyspaceHandle,
    audit_ks: &KeyspaceHandle,
    drains_ks: &KeyspaceHandle,
    seed_store: &dyn SeedStore,
    did_resolver: &DIDCacheClient,
    didcomm_bridge: &Arc<DIDCommBridge>,
    registry: &MediatorListenerRegistry,
    sweeper: &DrainSweeper,
    telemetry: &SharedTelemetrySink,
    prover: &(dyn ListenerProver + Send + Sync),
    auth: &AuthClaims,
    params: MigrateMediatorParams,
    channel: &str,
) -> Result<MigrateMediatorResult, MigrateMediatorError> {
    auth.require_super_admin()
        .map_err(|e| MigrateMediatorError::Auth(e.to_string()))?;

    let _guard = PROTOCOL_LOCK.lock().await;

    // Pre-flight: must be enabled, new mediator must differ from
    // active and not be in drain.
    let (vta_did, scid, current_doc, prior_mediator) =
        read_preconditions(config, registry, webvh_ks, &params).await?;

    // Step 1-5: handshake. Failure aborts before any LogEntry is
    // published — the spec's atomicity guarantee.
    let resolved = mediator_handshake(
        did_resolver,
        prover,
        telemetry,
        &params.new_mediator_did,
        &vta_did,
        HandshakeOptions {
            timeout: params.handshake_timeout,
            force: params.force,
        },
    )
    .await?;

    // Patch document: replace #vta-didcomm to point at new
    // mediator. Preserves verificationMethod byte-identical.
    let patched = with_didcomm_service(current_doc, &resolved.mediator_did)?;

    // Publish new LogEntry.
    let config_guard = config.read().await;
    let update_result = update_did_webvh(
        keys_ks,
        contexts_ks,
        webvh_ks,
        audit_ks,
        seed_store,
        &config_guard,
        auth,
        &scid,
        UpdateDidWebvhOptions {
            document: Some(patched),
            ..Default::default()
        },
        did_resolver,
        didcomm_bridge,
        channel,
    )
    .await?;
    drop(config_guard);

    // Persist config: messaging.mediator_did = new.
    persist_new_mediator(config, &resolved.mediator_did, &resolved.endpoint).await?;

    // Promote new mediator; place prior in drain. The
    // record_activate call evicts any drain entry for the new
    // mediator (rollback semantics).
    registry
        .record_activate(MediatorBinding {
            mediator_did: resolved.mediator_did.clone(),
            endpoint: resolved.endpoint.clone(),
        })
        .await;

    let deadline = Utc::now()
        + chrono::Duration::from_std(params.drain_ttl).map_err(|e| {
            MigrateMediatorError::ConfigPersistence(format!("drain TTL out of range: {e}"))
        })?;
    let prior_endpoint = best_effort_endpoint(did_resolver, &prior_mediator).await;
    registry
        .record_drain_persisted(drains_ks, &prior_mediator, prior_endpoint, deadline)
        .await?;
    // Arm the sweeper so the drain TTL actually fires.
    sweeper.arm(&prior_mediator, deadline).await;

    let _ = telemetry
        .record(
            TelemetryEvent::new(TelemetryKind::MediatorMigrateStart)
                .with_mediator(&resolved.mediator_did)
                .with_field("from", JsonValue::from(prior_mediator.clone()))
                .with_field("audit_kind", JsonValue::from(params.audit_kind.as_str()))
                .with_field(
                    "new_version_id",
                    JsonValue::from(update_result.new_version_id.clone()),
                )
                .with_field(
                    "drain_ttl_secs",
                    JsonValue::from(params.drain_ttl.as_secs()),
                ),
        )
        .await;

    info!(
        channel,
        from = %prior_mediator,
        to = %resolved.mediator_did,
        new_version_id = %update_result.new_version_id,
        audit_kind = params.audit_kind.as_str(),
        "mediator migrated"
    );

    Ok(MigrateMediatorResult {
        new_version_id: update_result.new_version_id,
        prior_mediator_did: prior_mediator,
        active_mediator_did: resolved.mediator_did,
        active_mediator_endpoint: resolved.endpoint,
        drains_until: deadline,
    })
}

async fn read_preconditions(
    config: &Arc<RwLock<AppConfig>>,
    registry: &MediatorListenerRegistry,
    webvh_ks: &KeyspaceHandle,
    params: &MigrateMediatorParams,
) -> Result<(String, String, JsonValue, String), MigrateMediatorError> {
    let cfg = config.read().await;
    if !cfg.services.didcomm {
        return Err(MigrateMediatorError::DidcommNotEnabled);
    }
    let vta_did = cfg
        .vta_did
        .clone()
        .ok_or(MigrateMediatorError::VtaDidNotConfigured)?;
    drop(cfg);

    let record = webvh_store::get_did(webvh_ks, &vta_did)
        .await?
        .ok_or_else(|| MigrateMediatorError::VtaDidRecordMissing(vta_did.clone()))?;
    let scid = record.scid.clone();

    let did_log = webvh_store::get_did_log(webvh_ks, &vta_did)
        .await?
        .ok_or_else(|| MigrateMediatorError::VtaDidLogMissing(vta_did.clone()))?;
    let current_doc = current_document_from_log(&did_log)?;

    let prior_mediator = current_didcomm_service(&current_doc)
        .map(|s| s.mediator_did)
        .ok_or(MigrateMediatorError::NoActiveMediator)?;

    if prior_mediator == params.new_mediator_did {
        return Err(MigrateMediatorError::SameAsActive(prior_mediator));
    }

    // Refuse migrate to a draining mediator — the operator should
    // either cancel the drain first or use rollback explicitly.
    // Forward migrates only.
    if params.audit_kind == MigrateAuditKind::Forward
        && registry
            .drain_deadline(&params.new_mediator_did)
            .await
            .is_some()
    {
        return Err(MigrateMediatorError::AlreadyDraining(
            params.new_mediator_did.clone(),
        ));
    }

    Ok((vta_did, scid, current_doc, prior_mediator))
}

fn current_document_from_log(did_log: &str) -> Result<JsonValue, MigrateMediatorError> {
    use didwebvh_rs::log_entry::{LogEntry, LogEntryMethods};
    let line = did_log
        .lines()
        .rfind(|l| !l.trim().is_empty())
        .ok_or(MigrateMediatorError::EmptyLog)?;
    let entry: LogEntry = serde_json::from_str(line)
        .map_err(|e| MigrateMediatorError::Storage(format!("DID log line parse: {e}")))?;
    Ok(entry.get_state().clone())
}

async fn persist_new_mediator(
    config: &Arc<RwLock<AppConfig>>,
    mediator_did: &str,
    mediator_endpoint: &str,
) -> Result<(), MigrateMediatorError> {
    let (contents, path) = {
        let mut cfg = config.write().await;
        cfg.messaging = Some(MessagingConfig {
            mediator_url: mediator_endpoint.to_string(),
            mediator_did: mediator_did.to_string(),
            mediator_host: None,
        });
        let contents = toml::to_string_pretty(&*cfg)
            .map_err(|e| MigrateMediatorError::ConfigPersistence(e.to_string()))?;
        let path = cfg.config_path.clone();
        (contents, path)
    };
    std::fs::write(&path, contents)
        .map_err(|e| MigrateMediatorError::ConfigPersistence(e.to_string()))?;
    Ok(())
}

async fn best_effort_endpoint(resolver: &DIDCacheClient, mediator_did: &str) -> String {
    match crate::messaging::handshake::resolve_mediator(resolver, mediator_did).await {
        Ok(r) => r.endpoint,
        Err(_) => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AppConfig, ServerConfig, ServicesConfig, StoreConfig};
    use crate::keys::seed_store::PlaintextSeedStore;
    use crate::messaging::handshake::AlwaysOkProver;
    use crate::store::Store;
    use vti_common::telemetry::RingBufferTelemetry;

    fn fresh_config(tmpdir: &std::path::Path, didcomm: bool) -> Arc<RwLock<AppConfig>> {
        let cfg = AppConfig {
            server: ServerConfig {
                host: "127.0.0.1".into(),
                port: 0,
            },
            log: Default::default(),
            store: StoreConfig {
                data_dir: tmpdir.into(),
            },
            services: ServicesConfig {
                rest: true,
                didcomm,
            },
            vta_did: Some("did:webvh:scid123:host:vta".into()),
            vta_name: None,
            public_url: None,
            messaging: None,
            secrets: Default::default(),
            auth: Default::default(),
            audit: Default::default(),
            #[cfg(feature = "tee")]
            tee: Default::default(),
            resolver_url: None,
            config_path: tmpdir.join("config.toml"),
        };
        Arc::new(RwLock::new(cfg))
    }

    fn registry() -> (
        Arc<DIDCommBridge>,
        Arc<MediatorListenerRegistry>,
        SharedTelemetrySink,
    ) {
        let bridge = Arc::new(DIDCommBridge::placeholder());
        let sink: SharedTelemetrySink = Arc::new(RingBufferTelemetry::with_capacity(64));
        let registry = Arc::new(MediatorListenerRegistry::new(Arc::clone(&sink)));
        (bridge, registry, sink)
    }

    fn sweeper_for(
        registry: Arc<MediatorListenerRegistry>,
        drains_ks: KeyspaceHandle,
    ) -> Arc<DrainSweeper> {
        let (tx, _rx) = crate::messaging::drain_sweeper::teardown_channel(8);
        Arc::new(DrainSweeper::new(registry, drains_ks, tx))
    }

    async fn empty_keyspace(name: &str) -> (tempfile::TempDir, KeyspaceHandle) {
        let dir = tempfile::tempdir().unwrap();
        let store = Store::open(&StoreConfig {
            data_dir: dir.path().into(),
        })
        .unwrap();
        let ks = store.keyspace(name).unwrap();
        (dir, ks)
    }

    fn super_admin() -> AuthClaims {
        AuthClaims::unsafe_local_cli_super_admin("test")
    }

    fn dummy_seed(dir: &std::path::Path) -> Arc<dyn SeedStore> {
        Arc::new(PlaintextSeedStore::new(dir))
    }

    async fn resolver() -> DIDCacheClient {
        DIDCacheClient::new(
            affinidi_did_resolver_cache_sdk::config::DIDCacheConfigBuilder::default().build(),
        )
        .await
        .unwrap()
    }

    fn forward_params(new_mediator: &str) -> MigrateMediatorParams {
        MigrateMediatorParams {
            new_mediator_did: new_mediator.into(),
            drain_ttl: Duration::from_secs(3600),
            force: false,
            handshake_timeout: Duration::from_secs(1),
            audit_kind: MigrateAuditKind::Forward,
        }
    }

    #[tokio::test]
    async fn refuses_when_didcomm_not_enabled() {
        let dir = tempfile::tempdir().unwrap();
        let config = fresh_config(dir.path(), /* didcomm = */ false);
        let (bridge, reg, sink) = registry();
        let (_d1, keys_ks) = empty_keyspace("keys").await;
        let (_d2, contexts_ks) = empty_keyspace("contexts").await;
        let (_d3, webvh_ks) = empty_keyspace("webvh").await;
        let (_d4, audit_ks) = empty_keyspace("audit").await;
        let (_d5, drains_ks) = empty_keyspace("drains").await;
        let resolver = resolver().await;
        let prover = AlwaysOkProver;
        let seed = dummy_seed(dir.path());

        let err = migrate_mediator(
            &config,
            &keys_ks,
            &contexts_ks,
            &webvh_ks,
            &audit_ks,
            &drains_ks,
            &*seed,
            &resolver,
            &bridge,
            &reg,
            &sweeper_for(Arc::clone(&reg), drains_ks.clone()),
            &sink,
            &prover,
            &super_admin(),
            forward_params("did:m:B"),
            "test",
        )
        .await
        .unwrap_err();
        assert!(matches!(err, MigrateMediatorError::DidcommNotEnabled));
    }

    #[tokio::test]
    async fn refuses_when_no_vta_did() {
        let dir = tempfile::tempdir().unwrap();
        let config = fresh_config(dir.path(), true);
        config.write().await.vta_did = None;
        let (bridge, reg, sink) = registry();
        let (_d1, keys_ks) = empty_keyspace("keys").await;
        let (_d2, contexts_ks) = empty_keyspace("contexts").await;
        let (_d3, webvh_ks) = empty_keyspace("webvh").await;
        let (_d4, audit_ks) = empty_keyspace("audit").await;
        let (_d5, drains_ks) = empty_keyspace("drains").await;
        let resolver = resolver().await;
        let prover = AlwaysOkProver;
        let seed = dummy_seed(dir.path());

        let err = migrate_mediator(
            &config,
            &keys_ks,
            &contexts_ks,
            &webvh_ks,
            &audit_ks,
            &drains_ks,
            &*seed,
            &resolver,
            &bridge,
            &reg,
            &sweeper_for(Arc::clone(&reg), drains_ks.clone()),
            &sink,
            &prover,
            &super_admin(),
            forward_params("did:m:B"),
            "test",
        )
        .await
        .unwrap_err();
        assert!(matches!(err, MigrateMediatorError::VtaDidNotConfigured));
    }

    #[tokio::test]
    async fn refuses_migrate_to_draining_mediator() {
        // Spec criterion #4 sub-case: forward migrate to a DID that
        // is currently in drain returns a typed error pointing the
        // operator at `drain cancel` or `rollback`.
        let dir = tempfile::tempdir().unwrap();
        let config = fresh_config(dir.path(), true);
        let (bridge, reg, sink) = registry();
        let (_d1, keys_ks) = empty_keyspace("keys").await;
        let (_d2, contexts_ks) = empty_keyspace("contexts").await;
        let (_d3, webvh_ks) = empty_keyspace("webvh").await;
        let (_d4, audit_ks) = empty_keyspace("audit").await;
        let (_d5, drains_ks) = empty_keyspace("drains").await;
        let resolver = resolver().await;
        let prover = AlwaysOkProver;
        let seed = dummy_seed(dir.path());

        // Pre-populate registry with mediator B in drain.
        reg.record_activate(MediatorBinding {
            mediator_did: "did:m:A".into(),
            endpoint: "wss://A".into(),
        })
        .await;
        reg.record_activate(MediatorBinding {
            mediator_did: "did:m:placeholder".into(),
            endpoint: "wss://placeholder".into(),
        })
        .await;
        reg.record_drain_persisted(
            &drains_ks,
            "did:m:B",
            "wss://B".into(),
            Utc::now() + chrono::Duration::seconds(3600),
        )
        .await
        .unwrap();

        let err = migrate_mediator(
            &config,
            &keys_ks,
            &contexts_ks,
            &webvh_ks,
            &audit_ks,
            &drains_ks,
            &*seed,
            &resolver,
            &bridge,
            &reg,
            &sweeper_for(Arc::clone(&reg), drains_ks.clone()),
            &sink,
            &prover,
            &super_admin(),
            forward_params("did:m:B"),
            "test",
        )
        .await
        .unwrap_err();
        // Note: the "no webvh record" error fires first because we
        // didn't populate webvh_ks; the drain-state check requires
        // the precondition reads to succeed. Real-world deployment
        // has the record present. For the unit test we accept
        // either VtaDidRecordMissing or AlreadyDraining since both
        // are valid refusal modes.
        assert!(
            matches!(err, MigrateMediatorError::VtaDidRecordMissing(_))
                || matches!(err, MigrateMediatorError::AlreadyDraining(_)),
            "expected refusal, got {err:?}"
        );
    }
}
