//! `disable_didcomm` operation.
//!
//! Spec: `docs/05-design-notes/didcomm-protocol-management.md`
//! success criteria #2, #3, #12.
//!
//! Sequence (under [`PROTOCOL_LOCK`]):
//! 1. Verify caller is super-admin.
//! 2. Confirm `services.didcomm` is currently `true` (refuse with
//!    [`DisableDidcommError::DidcommNotEnabled`] otherwise).
//! 3. Confirm `services.rest` is also currently `true` — otherwise
//!    disabling DIDComm leaves the VTA with no protocol surface.
//! 4. If transport is DIDComm, refuse `--drain-ttl 0s` (would drop
//!    the response on the inbound listener mid-flight). Spec
//!    minimum: 1h over DIDComm transport, any value over REST.
//! 5. Look up the VTA's webvh record + current document, patch out
//!    the `#vta-didcomm` service entry, publish via
//!    [`update_did_webvh`].
//! 6. Persist `services.didcomm = false` (the `messaging` block is
//!    LEFT IN PLACE so the drained listener can still reach the
//!    mediator until its TTL expires).
//! 7. If TTL > 0, register the prior mediator as draining via
//!    `record_drain_persisted`. If TTL == 0 (REST-only), tear down
//!    the listener immediately by deactivating the registry.
//! 8. Emit `ServicesDidcommDisable` telemetry.

use std::sync::Arc;
use std::time::Duration;

use affinidi_did_resolver_cache_sdk::DIDCacheClient;
use chrono::Utc;
use serde_json::Value as JsonValue;
use thiserror::Error;
use tokio::sync::RwLock;
use tracing::info;

use vti_common::seed_store::SeedStore;
use vti_common::telemetry::{SharedTelemetrySink, TelemetryEvent, TelemetryKind};

use crate::auth::AuthClaims;
use crate::config::AppConfig;
use crate::didcomm_bridge::DIDCommBridge;
use crate::error::AppError;
use crate::messaging::drain_sweeper::DrainSweeper;
use crate::messaging::registry::{MediatorListenerRegistry, RegistryError};
use crate::operations::did_webvh::{UpdateDidWebvhError, UpdateDidWebvhOptions, update_did_webvh};
use crate::operations::protocol::PROTOCOL_LOCK;
use crate::operations::protocol::document::{DocumentPatchError, without_didcomm_service};
use crate::store::KeyspaceHandle;
use crate::webvh_store;

/// Spec minimum drain TTL when called over DIDComm transport: 1
/// hour. Avoids the race where the inbound listener's response
/// drops while the listener is being torn down.
pub const MIN_DRAIN_TTL_OVER_DIDCOMM: Duration = Duration::from_secs(3600);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DisableTransport {
    Rest,
    Didcomm,
}

#[derive(Debug, Clone)]
pub struct DisableDidcommParams {
    /// How long to keep the listener on the prior mediator
    /// connected while in-flight messages drain. Zero means
    /// immediate teardown (REST transport only).
    pub drain_ttl: Duration,
    /// Transport over which the operator dispatched this request.
    /// Drives the 1h-min-TTL guard.
    pub transport: DisableTransport,
}

#[derive(Debug, Clone)]
pub struct DisableDidcommResult {
    pub new_version_id: String,
    pub prior_mediator_did: String,
    /// `Some(deadline)` if the prior listener entered drain state;
    /// `None` if the listener was torn down immediately (TTL = 0).
    pub drains_until: Option<chrono::DateTime<chrono::Utc>>,
}

#[derive(Debug, Error)]
pub enum DisableDidcommError {
    #[error(
        "DIDComm is not currently enabled. Use `pnm services enable didcomm --mediator-did <did>` first."
    )]
    DidcommNotEnabled,
    #[error(
        "cannot disable DIDComm — REST is also disabled. The VTA would have no protocol surface left. \
         Run `pnm services enable rest` first, or use `pnm services disable didcomm --drain-ttl 0s` \
         after enabling REST."
    )]
    NoProtocolRemaining,
    #[error(
        "drain-ttl 0s over DIDComm transport is not permitted (minimum 1h). \
         Either retry over REST transport (`--transport rest`) or use a TTL >= 1h."
    )]
    DrainTtlTooShortForDidcomm,
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

impl From<AppError> for DisableDidcommError {
    fn from(value: AppError) -> Self {
        Self::Storage(value.to_string())
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn disable_didcomm(
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
    auth: &AuthClaims,
    params: DisableDidcommParams,
    channel: &str,
) -> Result<DisableDidcommResult, DisableDidcommError> {
    auth.require_super_admin()
        .map_err(|e| DisableDidcommError::Auth(e.to_string()))?;

    let _guard = PROTOCOL_LOCK.lock().await;

    // Pre-flight checks (atomic; nothing mutated until past here).
    let (_vta_did, scid, current_doc, prior_mediator) =
        read_preconditions(config, webvh_ks, &params).await?;

    // Patch out the `#vta-didcomm` service entry.
    let patched = without_didcomm_service(current_doc);

    // Publish via update_did_webvh.
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

    // Persist config: services.didcomm = false. Leave `messaging`
    // intact so the drained listener can still reach the mediator
    // until its TTL expires (cleared by a future `drain cancel` or
    // expiry sweep).
    persist_didcomm_disabled(config).await?;

    // Schedule the drain or immediate teardown.
    let drains_until = if params.drain_ttl.is_zero() {
        // Immediate: deactivate the registry so the listener stops
        // receiving. The teardown channel consumer in server.rs
        // calls `DIDCommService::remove_listener` when the
        // sweeper fires; with TTL=0 we don't go through the
        // sweeper, so deactivate is the only signal — the
        // listener is removed on next service restart.
        registry.record_deactivate().await;
        None
    } else {
        // First, dethrone the active mediator in registry state so
        // the subsequent drain insert isn't refused with
        // `ActiveMediatorMustBeReplaced`.
        registry.record_deactivate().await;
        let deadline = Utc::now()
            + chrono::Duration::from_std(params.drain_ttl).map_err(|e| {
                DisableDidcommError::ConfigPersistence(format!("drain TTL out of range: {e}"))
            })?;
        // Resolve a best-effort endpoint string for the drain
        // entry. Re-resolving the prior mediator here is bounded
        // and avoids carrying the endpoint through several layers
        // of state.
        let endpoint = best_effort_endpoint(did_resolver, &prior_mediator).await;
        registry
            .record_drain_persisted(drains_ks, &prior_mediator, endpoint, deadline)
            .await?;
        // Arm the sweeper so the TTL actually fires. Without this
        // call the drain entry sits in fjall + registry forever
        // (it would be replayed on next boot but never expire).
        sweeper.arm(&prior_mediator, deadline).await;
        Some(deadline)
    };

    let _ = telemetry
        .record(
            TelemetryEvent::new(TelemetryKind::ServicesDidcommDisable)
                .with_mediator(&prior_mediator)
                .with_field(
                    "drain_ttl_secs",
                    JsonValue::from(params.drain_ttl.as_secs()),
                )
                .with_field(
                    "new_version_id",
                    JsonValue::from(update_result.new_version_id.clone()),
                )
                .with_field(
                    "transport",
                    JsonValue::from(match params.transport {
                        DisableTransport::Rest => "rest",
                        DisableTransport::Didcomm => "didcomm",
                    }),
                ),
        )
        .await;

    info!(
        channel,
        prior_mediator = %prior_mediator,
        new_version_id = %update_result.new_version_id,
        drain_ttl_secs = params.drain_ttl.as_secs(),
        "DIDComm disabled"
    );

    Ok(DisableDidcommResult {
        new_version_id: update_result.new_version_id,
        prior_mediator_did: prior_mediator,
        drains_until,
    })
}

async fn read_preconditions(
    config: &Arc<RwLock<AppConfig>>,
    webvh_ks: &KeyspaceHandle,
    params: &DisableDidcommParams,
) -> Result<(String, String, JsonValue, String), DisableDidcommError> {
    let cfg = config.read().await;
    if !cfg.services.didcomm {
        return Err(DisableDidcommError::DidcommNotEnabled);
    }
    if !cfg.services.rest {
        return Err(DisableDidcommError::NoProtocolRemaining);
    }
    if params.transport == DisableTransport::Didcomm
        && params.drain_ttl < MIN_DRAIN_TTL_OVER_DIDCOMM
    {
        return Err(DisableDidcommError::DrainTtlTooShortForDidcomm);
    }
    let vta_did = cfg
        .vta_did
        .clone()
        .ok_or(DisableDidcommError::VtaDidNotConfigured)?;
    drop(cfg);

    let record = webvh_store::get_did(webvh_ks, &vta_did)
        .await?
        .ok_or_else(|| DisableDidcommError::VtaDidRecordMissing(vta_did.clone()))?;
    let scid = record.scid.clone();

    let did_log = webvh_store::get_did_log(webvh_ks, &vta_did)
        .await?
        .ok_or_else(|| DisableDidcommError::VtaDidLogMissing(vta_did.clone()))?;
    let current_doc = current_document_from_log(&did_log)?;

    let prior_mediator =
        crate::operations::protocol::document::current_didcomm_service(&current_doc)
            .map(|s| s.mediator_did)
            .ok_or(DisableDidcommError::NoActiveMediator)?;

    Ok((vta_did, scid, current_doc, prior_mediator))
}

fn current_document_from_log(did_log: &str) -> Result<JsonValue, DisableDidcommError> {
    use didwebvh_rs::log_entry::{LogEntry, LogEntryMethods};
    let line = did_log
        .lines()
        .rfind(|l| !l.trim().is_empty())
        .ok_or(DisableDidcommError::EmptyLog)?;
    let entry: LogEntry = serde_json::from_str(line)
        .map_err(|e| DisableDidcommError::Storage(format!("DID log line parse: {e}")))?;
    Ok(entry.get_state().clone())
}

async fn persist_didcomm_disabled(
    config: &Arc<RwLock<AppConfig>>,
) -> Result<(), DisableDidcommError> {
    let (contents, path) = {
        let mut cfg = config.write().await;
        cfg.services.didcomm = false;
        // `messaging` deliberately preserved so the drained
        // listener can still resolve its mediator's endpoint.
        let contents = toml::to_string_pretty(&*cfg)
            .map_err(|e| DisableDidcommError::ConfigPersistence(e.to_string()))?;
        let path = cfg.config_path.clone();
        (contents, path)
    };
    std::fs::write(&path, contents)
        .map_err(|e| DisableDidcommError::ConfigPersistence(e.to_string()))?;
    Ok(())
}

async fn best_effort_endpoint(resolver: &DIDCacheClient, mediator_did: &str) -> String {
    match crate::messaging::handshake::resolve_mediator(resolver, mediator_did).await {
        Ok(r) => r.endpoint,
        // Endpoint string is operational metadata only — losing it
        // doesn't break drain. The mediator DID itself is the
        // identifier the listener uses.
        Err(_) => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{AppConfig, ServerConfig, ServicesConfig, StoreConfig};
    use crate::keys::seed_store::PlaintextSeedStore;
    use crate::store::Store;
    use vti_common::telemetry::RingBufferTelemetry;

    fn fresh_config(tmpdir: &std::path::Path, didcomm: bool, rest: bool) -> Arc<RwLock<AppConfig>> {
        let cfg = AppConfig {
            server: ServerConfig {
                host: "127.0.0.1".into(),
                port: 0,
            },
            log: Default::default(),
            store: StoreConfig {
                data_dir: tmpdir.into(),
            },
            services: ServicesConfig { rest, didcomm },
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

    fn rest_params(ttl: Duration) -> DisableDidcommParams {
        DisableDidcommParams {
            drain_ttl: ttl,
            transport: DisableTransport::Rest,
        }
    }

    fn didcomm_params(ttl: Duration) -> DisableDidcommParams {
        DisableDidcommParams {
            drain_ttl: ttl,
            transport: DisableTransport::Didcomm,
        }
    }

    #[tokio::test]
    async fn refuses_when_not_currently_enabled() {
        let dir = tempfile::tempdir().unwrap();
        let config = fresh_config(
            dir.path(),
            /* didcomm = */ false,
            /* rest = */ true,
        );
        let (bridge, reg, sink) = registry();
        let (_d1, keys_ks) = empty_keyspace("keys").await;
        let (_d2, contexts_ks) = empty_keyspace("contexts").await;
        let (_d3, webvh_ks) = empty_keyspace("webvh").await;
        let (_d4, audit_ks) = empty_keyspace("audit").await;
        let (_d5, drains_ks) = empty_keyspace("drains").await;
        let resolver = resolver().await;
        let seed = dummy_seed(dir.path());

        let err = disable_didcomm(
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
            &super_admin(),
            rest_params(Duration::from_secs(3600)),
            "test",
        )
        .await
        .unwrap_err();
        assert!(matches!(err, DisableDidcommError::DidcommNotEnabled));
    }

    #[tokio::test]
    async fn refuses_when_rest_also_disabled() {
        // Spec criterion #3: VTA must not end up with no protocol
        // surface.
        let dir = tempfile::tempdir().unwrap();
        let config = fresh_config(
            dir.path(),
            /* didcomm = */ true,
            /* rest = */ false,
        );
        let (bridge, reg, sink) = registry();
        let (_d1, keys_ks) = empty_keyspace("keys").await;
        let (_d2, contexts_ks) = empty_keyspace("contexts").await;
        let (_d3, webvh_ks) = empty_keyspace("webvh").await;
        let (_d4, audit_ks) = empty_keyspace("audit").await;
        let (_d5, drains_ks) = empty_keyspace("drains").await;
        let resolver = resolver().await;
        let seed = dummy_seed(dir.path());

        let err = disable_didcomm(
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
            &super_admin(),
            rest_params(Duration::from_secs(3600)),
            "test",
        )
        .await
        .unwrap_err();
        assert!(matches!(err, DisableDidcommError::NoProtocolRemaining));
    }

    #[tokio::test]
    async fn refuses_short_drain_over_didcomm() {
        // Spec criterion #12: 1h minimum drain when called over
        // DIDComm transport.
        let dir = tempfile::tempdir().unwrap();
        let config = fresh_config(dir.path(), true, true);
        let (bridge, reg, sink) = registry();
        let (_d1, keys_ks) = empty_keyspace("keys").await;
        let (_d2, contexts_ks) = empty_keyspace("contexts").await;
        let (_d3, webvh_ks) = empty_keyspace("webvh").await;
        let (_d4, audit_ks) = empty_keyspace("audit").await;
        let (_d5, drains_ks) = empty_keyspace("drains").await;
        let resolver = resolver().await;
        let seed = dummy_seed(dir.path());

        // 30 minutes < 1h minimum.
        let err = disable_didcomm(
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
            &super_admin(),
            didcomm_params(Duration::from_secs(1800)),
            "test",
        )
        .await
        .unwrap_err();
        assert!(matches!(
            err,
            DisableDidcommError::DrainTtlTooShortForDidcomm
        ));
    }

    #[tokio::test]
    async fn allows_zero_drain_over_rest() {
        // 0s is permitted over REST transport.
        let dir = tempfile::tempdir().unwrap();
        let config = fresh_config(dir.path(), true, true);
        let (bridge, reg, sink) = registry();
        let (_d1, keys_ks) = empty_keyspace("keys").await;
        let (_d2, contexts_ks) = empty_keyspace("contexts").await;
        let (_d3, webvh_ks) = empty_keyspace("webvh").await;
        let (_d4, audit_ks) = empty_keyspace("audit").await;
        let (_d5, drains_ks) = empty_keyspace("drains").await;
        let resolver = resolver().await;
        let seed = dummy_seed(dir.path());

        // 0s over REST passes the TTL guard; the next refusal
        // will be VtaDidRecordMissing (because no webvh setup in
        // the fixture). That confirms TTL=0 is not the blocker.
        let err = disable_didcomm(
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
            &super_admin(),
            rest_params(Duration::from_secs(0)),
            "test",
        )
        .await
        .unwrap_err();
        assert!(
            matches!(err, DisableDidcommError::VtaDidRecordMissing(_)),
            "TTL=0 over REST must pass the TTL guard; saw {err:?}"
        );
    }

    #[tokio::test]
    async fn allows_1h_drain_over_didcomm() {
        let dir = tempfile::tempdir().unwrap();
        let config = fresh_config(dir.path(), true, true);
        let (bridge, reg, sink) = registry();
        let (_d1, keys_ks) = empty_keyspace("keys").await;
        let (_d2, contexts_ks) = empty_keyspace("contexts").await;
        let (_d3, webvh_ks) = empty_keyspace("webvh").await;
        let (_d4, audit_ks) = empty_keyspace("audit").await;
        let (_d5, drains_ks) = empty_keyspace("drains").await;
        let resolver = resolver().await;
        let seed = dummy_seed(dir.path());

        let err = disable_didcomm(
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
            &super_admin(),
            didcomm_params(Duration::from_secs(3600)),
            "test",
        )
        .await
        .unwrap_err();
        // 1h passes the TTL guard; VtaDidRecordMissing is the next
        // refusal (no webvh setup in the fixture).
        assert!(matches!(err, DisableDidcommError::VtaDidRecordMissing(_)));
    }
}
