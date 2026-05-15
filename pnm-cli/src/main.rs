mod auth;
mod bootstrap;
mod config;
mod setup;

use clap::{Parser, Subcommand};
use vta_sdk::client::VtaClient;

use vta_cli_common::commands::{
    acl, audit, config as config_cmd, contexts, credentials, did_templates, keys, mediator,
    services, webvh,
};
use vta_cli_common::render::{CYAN, DIM, GREEN, RED, RESET};

#[derive(Parser)]
#[command(
    name = "pnm-cli",
    about = "CLI for managing a personal Verifiable Trust Agent"
)]
struct Cli {
    /// Base URL of the VTA service (overrides config)
    #[arg(long, env = "VTA_URL")]
    url: Option<String>,

    /// VTA slug to use (overrides default)
    #[arg(short, long, env = "PNM_VTA", global = true)]
    vta: Option<String>,

    /// Enable verbose debug output (can also set RUST_LOG=debug)
    #[arg(short = 'V', long, global = true)]
    verbose: bool,

    /// Show full identifiers (DIDs, key ids, template names, …) in
    /// list output instead of the compact table view that may truncate
    /// long values. Useful when you need to copy a complete ID.
    #[arg(long, global = true)]
    full_display: bool,

    /// Emit list output as JSON instead of a human-readable table.
    /// Use this for automation: `pnm acl list --json | jq …`.
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Configure VTA URL and credentials.
    ///
    /// Bare `pnm setup` runs the interactive wizard. Non-interactive
    /// phase-1 lives behind `--name`; phase-2 (supply a VTA DID for a
    /// pending slug) lives under the `continue` subcommand.
    ///
    ///   # Interactive:
    ///   pnm setup
    ///
    ///   # Non-interactive phase 1 (mint + park pending; JSON on stdout):
    ///   pnm setup --name "My VTA"
    ///   pnm setup --name "My VTA" --overwrite    # replace existing pending
    ///
    ///   # Phase 2 (interactive — prompts for VTA DID):
    ///   pnm setup continue my-vta
    ///
    ///   # Phase 2 (non-interactive — JSON on stdout):
    ///   pnm setup continue my-vta --vta-did did:webvh:...
    Setup {
        #[command(subcommand)]
        command: Option<SetupCommands>,

        /// Non-interactive phase 1: human-readable VTA name. Slugified
        /// the same way as the interactive wizard. Combining with the
        /// `continue` subcommand is an error, enforced at dispatch.
        #[arg(long)]
        name: Option<String>,

        /// Non-interactive phase 1: overwrite an existing *pending*
        /// setup for the same slug. Never overwrites a complete VTA —
        /// use `pnm vta remove <slug>` first.
        #[arg(long)]
        overwrite: bool,
    },

    /// Check service health
    Health,

    /// Authentication management
    Auth {
        #[command(subcommand)]
        command: AuthCommands,
    },

    /// Configuration management
    Config {
        #[command(subcommand)]
        command: ConfigCommands,
    },

    /// Manage which protocol surfaces (REST, DIDComm) the VTA exposes.
    ///
    /// Spec: docs/05-design-notes/didcomm-protocol-management.md
    Services {
        #[command(subcommand)]
        command: ServicesCommands,
    },

    /// Manage the active and draining DIDComm mediators.
    ///
    /// Spec: docs/05-design-notes/didcomm-protocol-management.md
    Mediator {
        #[command(subcommand)]
        command: MediatorCommands,
    },

    /// Key management
    Keys {
        #[command(subcommand)]
        command: KeyCommands,
    },

    /// Application context management
    Contexts {
        #[command(subcommand)]
        command: ContextCommands,
    },

    /// Access control list management
    Acl {
        #[command(subcommand)]
        command: AclCommands,
    },

    /// Generate auth credentials for applications and services
    AuthCredential {
        #[command(subcommand)]
        command: AuthCredentialCommands,
    },

    /// WebVH server management
    Webvh {
        #[command(subcommand)]
        command: WebvhCommands,
    },

    /// Audit log management
    Audit {
        #[command(subcommand)]
        command: AuditCommands,
    },

    /// Backup and restore VTA data
    Backup {
        #[command(subcommand)]
        command: BackupCommands,
    },

    /// VTA connection management
    Vta {
        #[command(subcommand)]
        command: VtaCommands,
    },

    /// Sealed-transfer bootstrap (consumer side).
    Bootstrap {
        #[command(subcommand)]
        command: BootstrapCommands,
    },

    /// DID document template management.
    ///
    /// Phase 1 surface is offline-only: validate a template file, or scaffold
    /// a starter by forking a built-in. Later phases will add list/create/
    /// update/delete commands that hit the VTA.
    #[command(name = "did-templates")]
    DidTemplates {
        #[command(subcommand)]
        command: DidTemplateCommands,
    },
}

#[derive(Subcommand)]
enum SetupCommands {
    /// Finish a pending VTA setup by supplying the VTA DID.
    ///
    /// Interactive when `--vta-did` is omitted; non-interactive with
    /// JSON stdout when supplied. The ephemeral `did:key` minted in
    /// phase 1 is preserved — this command only binds the VTA DID and
    /// flips the session to `PendingRotation`.
    Continue {
        /// Slug identifying the pending VTA (see `pnm vta list`).
        slug: String,

        /// VTA DID to bind (non-interactive). Must start with `did:`.
        #[arg(long)]
        vta_did: Option<String>,

        /// VTA REST URL (required for did:key DIDs that cannot advertise a service endpoint).
        #[arg(long)]
        vta_url: Option<String>,
    },
}

#[derive(Subcommand)]
enum BootstrapCommands {
    /// Generate an ephemeral keypair and emit a BootstrapRequest for the producer.
    ///
    /// The X25519 secret is stored on disk under
    /// `~/.config/pnm/bootstrap-secrets/<bundle_id>.key` (mode 0600). The
    /// emitted JSON file contains only the public key, a fresh nonce, and an
    /// optional label — no secrets cross the boundary.
    Request {
        /// Output path for the BootstrapRequest JSON.
        #[arg(long)]
        out: std::path::PathBuf,
        /// Optional human-readable label visible to the operator.
        #[arg(long)]
        label: Option<String>,
    },
    /// Open an armored sealed bundle returned by the producer.
    ///
    /// `--expect-digest <hex>` is required by default. Use `--no-verify-digest`
    /// to opt out (with a warning) — there is no silent TOFU.
    Open {
        /// Path to the armored bundle file.
        #[arg(long)]
        bundle: std::path::PathBuf,
        /// Expected SHA-256 digest, communicated out-of-band by the producer.
        #[arg(long)]
        expect_digest: Option<String>,
        /// Skip out-of-band digest verification (testing only — prints a warning).
        #[arg(long)]
        no_verify_digest: bool,
        /// Pin the VTA DID out-of-band. When supplied and the payload
        /// is `TemplateBootstrap`, the VC is verified end-to-end
        /// against this DID (pinned-DID check + issuer-pubkey
        /// extraction + Data Integrity verify + validity window).
        /// Without this flag, verification is digest-only.
        #[arg(long)]
        expect_vta_did: Option<String>,
    },

    /// One-command TEE first-boot bootstrap against a running VTA.
    ///
    /// Generates an ephemeral keypair, POSTs to `/bootstrap/request`,
    /// verifies the attestation quote, and installs the minted admin
    /// credential. Only works against a fresh TEE VTA that has not yet
    /// bootstrapped an admin — the carve-out closes permanently on first
    /// success.
    ///
    /// For non-TEE VTAs use `pnm setup` (temp did:key + ACL grant +
    /// auto-rotate on first connect).
    Connect {
        /// Base URL of the target VTA.
        #[arg(long)]
        vta_url: String,
        /// Out-of-band digest anchor. Compared against the server's
        /// reported digest and the locally computed one. Required unless
        /// `--no-verify-digest` is passed.
        #[arg(long)]
        expect_digest: Option<String>,
        /// Skip out-of-band digest verification (testing only — prints a warning).
        /// Required when `--expect-digest` is not provided; there is no silent TOFU.
        #[arg(long)]
        no_verify_digest: bool,
        /// Slug to register this VTA under in pnm config (default: tail of the
        /// VTA DID).
        #[arg(long)]
        slug: Option<String>,
    },

    /// Generate a VP-framed BootstrapRequest for the provision-integration
    /// flow (consumer side).
    ///
    /// Mints an ephemeral Ed25519 keypair, persists the seed under
    /// `~/.config/pnm/bootstrap-secrets/<bundle_id>.key`, and writes a
    /// signed VP naming the target DID template (e.g.
    /// `didcomm-mediator`, `webvh-control`, `webvh-daemon`, `webvh-server`) + variables. Hand the
    /// JSON to the VTA operator. Counterpart to `vta bootstrap
    /// provision-request` — same wire shape, same on-disk layout,
    /// different default seed directory.
    ///
    /// See `docs/03-integrating/provision-integration.md` for the flow.
    ProvisionRequest {
        /// DID template name the VTA should render (e.g.
        /// `didcomm-mediator`, `webvh-control`, `webvh-daemon`, `webvh-server`, or an
        /// operator-uploaded custom template).
        #[arg(long)]
        template: String,
        /// Template variable, repeat for each binding. Format `KEY=VALUE`.
        /// Values are parsed as JSON when possible; otherwise treated as
        /// a string.
        #[arg(long = "var", value_name = "KEY=VALUE")]
        vars: Vec<String>,
        /// Hint the target VTA context.
        #[arg(long)]
        context_hint: Option<String>,
        /// Opt into long-term admin-DID rollover (typically
        /// `--admin-template vta-admin`).
        #[arg(long)]
        admin_template: Option<String>,
        /// Freshness window in hours for the VP's `validUntil`. Default
        /// 168 (7 days).
        #[arg(long, value_name = "HOURS", default_value_t = 168.0)]
        validity_hours: f64,
        /// Free-form human label echoed back in audit logs.
        #[arg(long)]
        label: Option<String>,
        /// Output path for the signed BootstrapRequest JSON.
        #[arg(long)]
        out: std::path::PathBuf,
    },
    /// Bridge a VP-framed BootstrapRequest to `POST /bootstrap/provision-integration`
    /// on the configured VTA, writing the returned armored sealed bundle to disk.
    ///
    /// Mirrors the offline `vta bootstrap provision-integration` command;
    /// the difference is purely the transport — the VTA runs the same
    /// shared library function regardless of how the request arrived.
    ProvisionIntegration {
        /// Path to the VP-framed BootstrapRequest JSON (emitted by the
        /// integration's operator via `pnm bootstrap request`).
        #[arg(long)]
        request: std::path::PathBuf,
        /// VTA context to provision into. If the request carries a
        /// `contextHint`, this flag must either match it or be omitted.
        #[arg(long)]
        context: Option<String>,
        /// Producer assertion mode. `did-signed` (default) signs with
        /// the VTA's assertion key; `pinned-only` is a dev/test
        /// escape hatch.
        #[arg(long, default_value = "did-signed")]
        assertion: String,
        /// Override for the VC's `validUntil` window, in seconds.
        #[arg(long, value_name = "SECONDS")]
        vc_validity_seconds: Option<i64>,
        /// Output path for the armored bundle.
        #[arg(long)]
        out: std::path::PathBuf,
    },
}

#[derive(Subcommand)]
enum DidTemplateCommands {
    /// Validate a DID template file against the v1 schema.
    ///
    /// Runs offline — never talks to the VTA. Reports whether the file
    /// parses, its placeholders are all declared, and its reserved/required
    /// variables are well-formed.
    Validate {
        /// Path to a template JSON file to validate.
        file: std::path::PathBuf,
    },

    /// Scaffold a starter template by forking an embedded built-in.
    ///
    /// Emits JSON on stdout so it can be redirected to a file for editing.
    /// `kind` accepts either the full built-in name
    /// (`didcomm-mediator`, `webvh-control`, `webvh-daemon`, `webvh-server`) or a short alias
    /// (`mediator`, `control`, `webvh-hosting`, `hosting`, `daemon`, `witness`, `watcher`, `server`).
    Init {
        /// Built-in kind or alias to fork.
        kind: String,
    },

    /// List every built-in template shipped with this SDK.
    #[command(name = "list-builtins")]
    ListBuiltins,

    /// List DID templates stored on the VTA.
    ///
    /// Without `--context`, lists global-scope templates (visible across
    /// every context). With `--context X`, lists templates scoped to X.
    List {
        /// FILTER: scope the listing to one context. Omit for global scope.
        /// Does not merge in the other scope — use `list-builtins` for
        /// built-ins.
        #[arg(long)]
        context: Option<String>,
    },

    /// Show a stored template by name.
    ///
    /// Without `--rendered`, prints the raw record. With `--rendered`, the
    /// server renders the template using `--var KEY=VALUE` pairs.
    Show {
        /// Template name as stored on the VTA.
        name: String,
        /// LOOKUP SCOPE: which scope to search for the named template.
        /// Omit for global scope.
        #[arg(long)]
        context: Option<String>,
        /// Render the template rather than showing its raw record.
        #[arg(long)]
        rendered: bool,
        /// `KEY=VALUE` — supply a template variable. Repeatable.
        #[arg(long = "var", value_parser = parse_key_value)]
        vars: Vec<(String, String)>,
    },

    /// Upload a new template.
    ///
    /// Without `--context`: global scope (super admin only). With
    /// `--context X`: context scope (context admin or super admin).
    Create {
        /// Path to a template JSON file.
        #[arg(long)]
        file: std::path::PathBuf,
        /// TARGET SCOPE: create the template in this context's scope
        /// instead of global. Requires context-admin access to the context.
        #[arg(long)]
        context: Option<String>,
    },

    /// Replace a stored template.
    Update {
        /// Template name as stored on the VTA.
        name: String,
        /// Path to the replacement JSON file. Its `name` field must match.
        #[arg(long)]
        file: std::path::PathBuf,
        /// TARGET SCOPE: operate on this context's stored template instead
        /// of the global one.
        #[arg(long)]
        context: Option<String>,
    },

    /// Delete a stored template.
    Delete {
        /// Template name.
        name: String,
        /// TARGET SCOPE: operate on this context's stored template instead
        /// of the global one.
        #[arg(long)]
        context: Option<String>,
    },

    /// Export a stored template to stdout as a portable JSON file.
    ///
    /// Strips server provenance so the output can be edited and re-uploaded
    /// via `create --file`. Pipe into a file or `jq` for scripted workflows.
    Export {
        /// Template name.
        name: String,
        /// LOOKUP SCOPE: export from this context's scope instead of global.
        #[arg(long)]
        context: Option<String>,
    },

    /// Compare a local template file against the VTA-stored version.
    ///
    /// Shows every JSON path whose value differs, exits non-zero when the
    /// two diverge (so it plugs into drift-detection scripts).
    Diff {
        /// Template name.
        name: String,
        /// Path to the local template JSON file.
        #[arg(long)]
        file: std::path::PathBuf,
        /// LOOKUP SCOPE: fetch the stored template from this context's scope
        /// instead of global.
        #[arg(long)]
        context: Option<String>,
    },
}

fn parse_key_value(s: &str) -> Result<(String, String), String> {
    let (k, v) = s
        .split_once('=')
        .ok_or_else(|| format!("expected KEY=VALUE, got '{s}'"))?;
    Ok((k.to_string(), v.to_string()))
}

#[derive(Subcommand)]
enum BackupCommands {
    /// Export VTA state to an encrypted backup file
    Export {
        /// Include audit logs in the backup
        #[arg(long)]
        include_audit: bool,
        /// Output file path (default: `vta-backup-<timestamp>.vtabak`)
        #[arg(short, long)]
        output: Option<std::path::PathBuf>,
    },
    /// Import VTA state from an encrypted backup file
    Import {
        /// Path to the .vtabak backup file
        file: std::path::PathBuf,
        /// Preview only — show what would be imported without applying
        #[arg(long)]
        preview: bool,
    },
}

#[derive(Subcommand)]
enum VtaCommands {
    /// List configured VTAs
    List,
    /// Set the default VTA
    Use { slug: String },
    /// Remove a VTA connection
    Remove { slug: String },
    /// Show current VTA details
    Info,
    /// Restart the VTA service (soft restart — reloads config and reconnects)
    Restart,
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
enum WebvhCommands {
    /// Add a WebVH server
    AddServer {
        /// Server identifier
        #[arg(long)]
        id: String,
        /// Server DID (must resolve to a DID document with a DIDCommMessaging, WebVHHosting, or WebVHHostingService endpoint)
        #[arg(long)]
        did: String,
        /// Human-readable label
        #[arg(long)]
        label: Option<String>,
    },
    /// List configured WebVH servers
    ListServers,
    /// Update a WebVH server
    UpdateServer {
        /// Server identifier to update
        id: String,
        /// New label (empty string to clear)
        #[arg(long)]
        label: Option<String>,
    },
    /// Remove a WebVH server
    RemoveServer {
        /// Server identifier to remove
        id: String,
    },
    /// Create a WebVH DID
    CreateDid {
        /// Application context ID
        #[arg(long)]
        context: String,
        /// WebVH server ID (mutually exclusive with --did-url)
        #[arg(long)]
        server: Option<String>,
        /// DID URL for serverless creation (mutually exclusive with --server)
        #[arg(long)]
        did_url: Option<String>,
        /// Optional path on the WebVH server
        #[arg(long)]
        path: Option<String>,
        /// Human-readable label
        #[arg(long)]
        label: Option<String>,
        /// Make the DID portable (default: true)
        #[arg(long, default_value = "true")]
        portable: bool,
        /// Add a mediator service endpoint
        #[arg(long)]
        mediator_service: bool,
        /// Additional service endpoints (JSON array)
        #[arg(long)]
        services: Option<String>,
        /// Number of pre-rotation keys to generate
        #[arg(long, default_value = "0")]
        pre_rotation: u32,
        /// Path to a JSON file containing a DID Document template (template mode)
        #[arg(long)]
        did_document: Option<String>,
        /// Path to a did.jsonl file containing a pre-signed log entry (final mode)
        #[arg(long)]
        did_log: Option<String>,
        /// Do not set this DID as the primary DID for the context
        #[arg(long)]
        no_primary: bool,
        /// Use an existing key ID as the signing verification method
        #[arg(long)]
        signing_key: Option<String>,
        /// Use an existing key ID as the key-agreement verification method
        #[arg(long)]
        ka_key: Option<String>,
        /// Name of a stored DID template to render into the DID document.
        /// Mutually exclusive with `--did-document` and `--did-log`.
        #[arg(long)]
        template: Option<String>,
        /// Look up the template in this context's scope first. Defaults to
        /// the DID's own `--context` so context-local templates shadow
        /// global ones naturally.
        #[arg(long)]
        template_context: Option<String>,
        /// `KEY=VALUE` — supply a template variable. Repeatable.
        #[arg(long = "var", value_parser = parse_key_value)]
        vars: Vec<(String, String)>,
    },
    /// List WebVH DIDs
    ListDids {
        /// FILTER: only show DIDs belonging to this context.
        #[arg(long)]
        context: Option<String>,
        /// FILTER: only show DIDs hosted by this WebVH server.
        #[arg(long)]
        server: Option<String>,
    },
    /// Get details of a WebVH DID
    GetDid {
        /// The DID to look up
        did: String,
    },
    /// Delete a WebVH DID
    DeleteDid {
        /// The DID to delete
        did: String,
    },
    /// Print the raw `did.jsonl` log for a webvh DID the VTA knows.
    ///
    /// Snapshot from provisioning time — not a live resolver. Use for
    /// audit, debugging, or republication fallback.
    ///
    /// The VTA's endpoint is public (webvh logs are world-readable by
    /// design), so this runs without a session token.
    DidLog {
        /// The DID to retrieve the log for.
        did: String,
        /// Optional output file; stdout if omitted.
        #[arg(long)]
        out: Option<std::path::PathBuf>,
    },
}

#[derive(Subcommand)]
enum AuthCommands {
    /// Clear stored credentials and tokens
    Logout,
    /// Show current authentication status
    Status,
}

#[derive(Subcommand)]
enum ConfigCommands {
    /// Get current configuration
    Get,
    /// Update configuration
    Update {
        /// VTA DID
        #[arg(long)]
        community_vta_did: Option<String>,
        /// VTA name
        #[arg(long)]
        community_vta_name: Option<String>,
        /// Public URL for this VTA
        #[arg(long)]
        public_url: Option<String>,
    },
}

#[derive(Subcommand)]
enum ServicesCommands {
    /// Enable a protocol on this VTA (today: only `didcomm`).
    Enable {
        #[command(subcommand)]
        protocol: ServicesEnableProtocol,
    },
    /// Disable a protocol on this VTA (today: only `didcomm`).
    /// Refuses if REST is also disabled — the VTA must keep at
    /// least one protocol surface. Use `--drain-ttl 0s` to tear
    /// the listener down immediately.
    Disable {
        #[command(subcommand)]
        protocol: ServicesDisableProtocol,
    },
}

#[derive(Subcommand)]
enum ServicesEnableProtocol {
    /// Enable DIDComm. Requires a mediator DID and super-admin auth.
    /// The VTA must currently be REST-only.
    Didcomm {
        /// Mediator's DID (e.g. did:webvh:scid:host:path)
        #[arg(long)]
        mediator_did: String,
        /// Skip handshake steps 2-5 (DID resolution always runs).
        /// Use only when reachability has been validated out-of-band.
        #[arg(long)]
        force: bool,
        /// Trust-ping round-trip timeout in seconds (default 10).
        #[arg(long)]
        handshake_timeout: Option<u64>,
    },
}

#[derive(Subcommand)]
enum ServicesDisableProtocol {
    /// Disable DIDComm. The current mediator's listener stays up
    /// for `drain-ttl` seconds so in-flight messages can drain
    /// (default: 1 hour).
    Didcomm {
        /// Drain window in seconds. 0 = immediate teardown.
        /// Server enforces a 1h minimum when called over DIDComm
        /// transport; over REST any value is permitted.
        #[arg(long, default_value_t = 3600)]
        drain_ttl: u64,
    },
}

#[derive(Subcommand)]
enum MediatorCommands {
    /// Migrate to a new mediator. Runs the pre-promotion handshake;
    /// the prior mediator's listener stays up until `drain-ttl`
    /// expires so in-flight messages can still arrive.
    Migrate {
        /// New mediator's DID.
        #[arg(long = "to")]
        new_mediator_did: String,
        /// Drain window for the prior mediator (seconds).
        #[arg(long, default_value_t = 3600)]
        drain_ttl: u64,
        /// Skip handshake steps 2-5 (DID resolution always runs).
        #[arg(long)]
        force: bool,
        /// Trust-ping timeout (seconds, default 10).
        #[arg(long)]
        handshake_timeout: Option<u64>,
    },
    /// Rollback to a previously-active mediator. Mechanically the
    /// same as `migrate`, but tagged in telemetry as a rollback.
    Rollback {
        /// Target mediator's DID (typically a previously-active one
        /// that may still be in drain).
        #[arg(long = "to")]
        target_mediator_did: String,
        /// Drain window for the now-prior mediator (seconds).
        #[arg(long, default_value_t = 3600)]
        drain_ttl: u64,
        /// Skip handshake steps 2-5 (DID resolution always runs).
        #[arg(long)]
        force: bool,
        /// Trust-ping timeout (seconds, default 10).
        #[arg(long)]
        handshake_timeout: Option<u64>,
    },
    /// Drain-set management (cancel an in-flight drain).
    Drain {
        #[command(subcommand)]
        command: MediatorDrainCommands,
    },
    /// Show inbound-message attribution by mediator and sender.
    Report {
        /// Lower bound (RFC 3339, e.g. 2026-04-29T15:00:00Z).
        #[arg(long)]
        since: Option<String>,
        /// Upper bound (RFC 3339).
        #[arg(long)]
        until: Option<String>,
        /// Output format: `json` (default) or `table`.
        #[arg(long, default_value = "json")]
        format: String,
    },
}

#[derive(Subcommand)]
enum MediatorDrainCommands {
    /// Cancel a drain entry. Drops the listener for that mediator
    /// immediately. Refuses if the named DID is the active mediator
    /// (use `services disable didcomm` instead).
    Cancel {
        #[arg(long)]
        mediator_did: String,
    },
}

#[derive(Subcommand)]
enum ContextCommands {
    /// List all application contexts
    List,
    /// Get a context by ID
    Get {
        /// Context ID (e.g. "vta")
        id: String,
    },
    /// Create a new application context, optionally with an admin ACL entry.
    ///
    /// Without `--admin-did` the command just creates the context (historical
    /// behaviour). Supply `--admin-did` to atomically grant that DID admin
    /// access scoped to the new context.
    ///
    /// The admin ACL entry is **permanent** by default. Pass `--admin-expires`
    /// to make it a **setup ACL** that auto-expires if the admin never claims
    /// it — useful when the DID was minted on a fresh `pnm setup` and you
    /// want an automatic safety window.
    Create {
        /// Context slug (lowercase alphanumeric + hyphens)
        #[arg(long)]
        id: String,
        /// Human-readable name
        #[arg(long)]
        name: String,
        /// Optional description
        #[arg(long)]
        description: Option<String>,
        /// DID to grant admin access to (must start with `did:`). When set,
        /// creates an ACL entry with role=admin scoped to this context.
        #[arg(long)]
        admin_did: Option<String>,
        /// Human-readable label for the admin ACL entry.
        #[arg(long)]
        admin_label: Option<String>,
        /// Setup-ACL expiry — accepts `N[s|m|h|d|w]` (e.g. `24h`, `7d`).
        /// When set, the admin ACL entry auto-expires via the server's ACL
        /// sweeper; the expectation is that the admin authenticates and
        /// rotates to a fresh did:key before expiry. Without this flag the
        /// entry is permanent. Requires `--admin-did`.
        #[arg(long, requires = "admin_did")]
        admin_expires: Option<String>,
    },
    /// Update an existing context
    Update {
        /// Context ID
        id: String,
        /// New name
        #[arg(long)]
        name: Option<String>,
        /// Set the DID for this context
        #[arg(long)]
        did: Option<String>,
        /// New description
        #[arg(long)]
        description: Option<String>,
    },
    /// Update the DID for a context (context admin or super admin)
    UpdateDid {
        /// Context ID
        id: String,
        /// The new DID to assign
        did: String,
    },
    /// Delete an application context and all associated resources
    Delete {
        /// Context ID
        id: String,
        /// Skip confirmation and delete immediately
        #[arg(long, short)]
        force: bool,
    },
    /// Create a context and mint a sealed admin credential for its first admin.
    ///
    /// The admin did:key is generated locally by the CLI and registered via
    /// `POST /acl`; the VTA never sees the private key. The minted credential
    /// is sealed to the `--recipient` and printed as an armored bundle.
    Bootstrap {
        /// Context slug (lowercase alphanumeric + hyphens)
        #[arg(long)]
        id: String,
        /// Human-readable name
        #[arg(long)]
        name: String,
        /// Optional description
        #[arg(long)]
        description: Option<String>,
        /// Admin label
        #[arg(long)]
        admin_label: Option<String>,
        /// Path to a BootstrapRequest JSON file produced by `pnm bootstrap request`.
        #[arg(long, conflicts_with_all = ["recipient_did", "recipient_nonce"])]
        recipient: Option<std::path::PathBuf>,
        /// Recipient's `did:key` (Ed25519). The X25519 pubkey HPKE seals to
        /// is derived locally.
        #[arg(long, requires = "recipient_nonce", conflicts_with = "recipient")]
        recipient_did: Option<String>,
        /// Recipient's 16-byte nonce in hex.
        #[arg(long, requires = "recipient_did", conflicts_with = "recipient")]
        recipient_nonce: Option<String>,
    },
    /// Provision a new application context with a portable config bundle
    ///
    /// Creates a context, generates admin credentials, and optionally creates a
    /// WebVH DID. Emits an armored sealed bundle (`-----BEGIN VTA SEALED BUNDLE-----`)
    /// containing everything an application needs to connect, authenticate,
    /// and self-administer its context. Pass `--recipient <file>` with a
    /// `BootstrapRequest` JSON (produced by `pnm bootstrap request --out`) or
    /// `--recipient-pubkey` + `--recipient-nonce` inline.
    Provision {
        /// Context slug (lowercase alphanumeric + hyphens)
        #[arg(long)]
        id: String,
        /// Human-readable name
        #[arg(long)]
        name: String,
        /// Optional description
        #[arg(long)]
        description: Option<String>,
        /// Admin label
        #[arg(long)]
        admin_label: Option<String>,
        /// Create a DID using this WebVH server (mutually exclusive with --did-url)
        #[arg(long)]
        server: Option<String>,
        /// Create a DID at this URL for self-hosting (mutually exclusive with --server)
        #[arg(long)]
        did_url: Option<String>,
        /// Make the DID portable (default: true)
        #[arg(long, default_value = "true")]
        portable: bool,
        /// Add a mediator service endpoint to the DID
        #[arg(long)]
        mediator_service: bool,
        /// Number of pre-rotation keys to generate
        #[arg(long, default_value = "0")]
        pre_rotation: u32,
        /// Path to a BootstrapRequest JSON file produced by `pnm bootstrap request`.
        #[arg(long, conflicts_with_all = ["recipient_did", "recipient_nonce"])]
        recipient: Option<std::path::PathBuf>,
        /// Recipient's `did:key` (Ed25519). The X25519 pubkey HPKE seals to
        /// is derived locally.
        /// Requires --recipient-nonce. Mutually exclusive with --recipient.
        #[arg(long, requires = "recipient_nonce", conflicts_with = "recipient")]
        recipient_did: Option<String>,
        /// Recipient's 16-byte nonce in hex (32 chars).
        /// Requires --recipient-did. Mutually exclusive with --recipient.
        #[arg(long, requires = "recipient_did", conflicts_with = "recipient")]
        recipient_nonce: Option<String>,
    },
    /// Regenerate a provision bundle for an existing context.
    ///
    /// The DID's operational keys (signing, KA, any pre-rotation) are
    /// auto-included in the bundle. `--admin-key` separately picks which
    /// existing VTA-stored Ed25519 key's seed backs the admin credential
    /// — the `did:key` the mediator operator uses to authenticate back
    /// to the VTA for ACL-gated operations. Omit to interactively select
    /// from existing keys or create a new one.
    Reprovision {
        /// Context ID to reprovision
        #[arg(long)]
        id: String,
        /// Key ID of an existing VTA-stored Ed25519 key whose seed backs
        /// the exported admin credential. Kept as `--key` for backward
        /// compatibility.
        #[arg(long = "admin-key", alias = "key")]
        admin_key: Option<String>,
        /// Label for a newly created admin key (used when no
        /// `--admin-key` is provided and the interactive prompt selects
        /// "create new").
        #[arg(long)]
        admin_label: Option<String>,
        /// Path to a BootstrapRequest JSON file produced by `pnm bootstrap request`.
        #[arg(long, conflicts_with_all = ["recipient_did", "recipient_nonce"])]
        recipient: Option<std::path::PathBuf>,
        /// Recipient's `did:key` (Ed25519). The X25519 pubkey HPKE seals to
        /// is derived locally.
        #[arg(long, requires = "recipient_nonce", conflicts_with = "recipient")]
        recipient_did: Option<String>,
        /// Recipient's 16-byte nonce in hex.
        #[arg(long, requires = "recipient_did", conflicts_with = "recipient")]
        recipient_nonce: Option<String>,
    },
}

#[derive(Subcommand)]
enum AclCommands {
    /// List ACL entries
    List {
        /// FILTER: only show ACL entries whose `allowed_contexts` include
        /// this context. Omit to see every entry visible to you.
        #[arg(long)]
        context: Option<String>,
    },
    /// Get an ACL entry by DID
    Get {
        /// DID to look up
        did: String,
    },
    /// Create an ACL entry.
    ///
    /// Not idempotent — errors with 409 Conflict if an entry already exists
    /// for the given DID. To change a role or context list on an existing
    /// entry use `pnm acl update`. To revoke access use `pnm acl delete`.
    Create {
        /// DID to grant access to
        #[arg(long)]
        did: String,
        /// Role: admin, initiator, application, or reader
        #[arg(long)]
        role: String,
        /// Human-readable label
        #[arg(long)]
        label: Option<String>,
        /// Comma-separated context IDs (empty = unrestricted)
        #[arg(long, value_delimiter = ',')]
        contexts: Vec<String>,
        /// Optional expiry — accepts `N[s|m|h|d|w]` (e.g. `24h`, `7d`). When
        /// set, the server's ACL sweeper removes the entry after the deadline.
        /// Without this flag the entry is permanent.
        #[arg(long)]
        expires: Option<String>,
    },
    /// Update an ACL entry
    Update {
        /// DID of the entry to update
        did: String,
        /// New role
        #[arg(long)]
        role: Option<String>,
        /// New label
        #[arg(long)]
        label: Option<String>,
        /// New comma-separated context IDs
        #[arg(long, value_delimiter = ',')]
        contexts: Option<Vec<String>>,
    },
    /// Delete an ACL entry
    Delete {
        /// DID of the entry to delete
        did: String,
    },
}

#[derive(Subcommand)]
enum AuthCredentialCommands {
    /// Generate a new auth credential (did:key minted locally + ACL entry)
    /// and seal it to the given recipient.
    Create {
        /// Role: admin, initiator, application, or reader
        #[arg(long)]
        role: String,
        /// Human-readable label
        #[arg(long)]
        label: Option<String>,
        /// Comma-separated context IDs (empty = unrestricted)
        #[arg(long, value_delimiter = ',')]
        contexts: Vec<String>,
        /// Path to a BootstrapRequest JSON file produced by `pnm bootstrap request`.
        #[arg(long, conflicts_with_all = ["recipient_did", "recipient_nonce"])]
        recipient: Option<std::path::PathBuf>,
        /// Recipient's `did:key` (Ed25519). The X25519 pubkey HPKE seals to
        /// is derived locally.
        #[arg(long, requires = "recipient_nonce", conflicts_with = "recipient")]
        recipient_did: Option<String>,
        /// Recipient's 16-byte nonce in hex.
        #[arg(long, requires = "recipient_did", conflicts_with = "recipient")]
        recipient_nonce: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum AuditCommands {
    /// List audit log entries with optional filtering
    List {
        /// Start time (unix epoch seconds)
        #[arg(long)]
        from: Option<u64>,
        /// End time (unix epoch seconds)
        #[arg(long)]
        to: Option<u64>,
        /// Filter by action (e.g. "auth.challenge", "key.create")
        #[arg(long)]
        action: Option<String>,
        /// Filter by actor DID
        #[arg(long)]
        actor: Option<String>,
        /// Filter by outcome (e.g. "success", "denied")
        #[arg(long)]
        outcome: Option<String>,
        /// Filter by context ID
        #[arg(long)]
        context_id: Option<String>,
        /// Page number (default 1)
        #[arg(long, default_value_t = 1)]
        page: u64,
        /// Page size (default 50, max 500)
        #[arg(long, default_value_t = 50)]
        page_size: u64,
    },
    /// Manage audit log retention
    Retention {
        #[command(subcommand)]
        command: RetentionCommands,
    },
}

#[derive(Subcommand, Debug)]
enum RetentionCommands {
    /// Get the current retention period
    Get,
    /// Set the retention period (super-admin only)
    Set {
        /// Number of days to retain audit logs (1-365)
        #[arg(long)]
        days: u32,
    },
}

#[derive(Subcommand)]
enum KeyCommands {
    /// Create a new key.
    ///
    /// Not idempotent — every invocation mints a fresh key record (even with
    /// identical arguments). Use `pnm keys list` to discover existing keys
    /// in a context first if you're trying to avoid duplicates.
    Create {
        /// Key type: ed25519, x25519, or p256
        #[arg(long)]
        key_type: String,
        /// BIP-32 derivation path (auto-derived from context if omitted)
        #[arg(long)]
        derivation_path: Option<String>,
        /// BIP-39 mnemonic phrase
        #[arg(long)]
        mnemonic: Option<String>,
        /// Human-readable label
        #[arg(long)]
        label: Option<String>,
        /// TARGET SCOPE: store the new key under this context. Required
        /// unless you're a super admin creating a context-less key (rare).
        #[arg(long = "context", alias = "context-id", value_name = "ID")]
        context_id: Option<String>,
    },
    /// Import an externally-created private key
    Import {
        /// Key type: ed25519, x25519, or p256
        #[arg(long)]
        key_type: String,
        /// Multibase-encoded private key
        #[arg(long)]
        private_key: Option<String>,
        /// Path to private key file
        #[arg(long)]
        private_key_file: Option<std::path::PathBuf>,
        /// Human-readable label
        #[arg(long)]
        label: Option<String>,
        /// TARGET SCOPE: store the imported key under this context.
        #[arg(long = "context", alias = "context-id", value_name = "ID")]
        context_id: Option<String>,
    },
    /// Get a key by ID
    Get {
        /// Key ID
        key_id: String,
        /// Reveal private key material (multibase)
        #[arg(long)]
        secret: bool,
    },
    /// Revoke (invalidate) a key
    Revoke {
        /// Key ID
        key_id: String,
    },
    /// Rename a key
    Rename {
        /// Current key ID
        key_id: String,
        /// New key ID
        new_key_id: String,
    },
    /// List all keys
    List {
        /// Maximum number of keys to return
        #[arg(long, default_value = "50")]
        limit: u64,
        /// Number of keys to skip
        #[arg(long, default_value = "0")]
        offset: u64,
        /// FILTER: only keys with this status (`active` or `revoked`).
        #[arg(long)]
        status: Option<String>,
        /// FILTER: only keys belonging to this context.
        #[arg(long)]
        context: Option<String>,
    },
    /// Export secret key material for one or more keys
    Secrets {
        /// Key IDs to export (omit to export all active keys in --context)
        key_ids: Vec<String>,
        /// REFERENCE: export every active key in this context when no
        /// `key_ids` are supplied.
        #[arg(long)]
        context: Option<String>,
    },
    /// Export a portable DID secrets bundle for a context as an armored
    /// sealed bundle. The recipient runs `pnm bootstrap open` to decrypt.
    Bundle {
        /// Application context ID whose DID and keys to bundle
        context: String,
        /// Path to a BootstrapRequest JSON file produced by `pnm bootstrap request`.
        #[arg(long, conflicts_with_all = ["recipient_did", "recipient_nonce"])]
        recipient: Option<std::path::PathBuf>,
        /// Recipient's `did:key` (Ed25519). The X25519 pubkey HPKE seals to
        /// is derived locally.
        #[arg(long, requires = "recipient_nonce", conflicts_with = "recipient")]
        recipient_did: Option<String>,
        /// Recipient's 16-byte nonce in hex.
        #[arg(long, requires = "recipient_did", conflicts_with = "recipient")]
        recipient_nonce: Option<String>,
    },
    /// List seed generations
    Seeds,
    /// Rotate to a new seed generation
    RotateSeed {
        /// BIP-39 mnemonic phrase for the new seed (random if omitted)
        #[arg(long)]
        mnemonic: Option<String>,
    },
}

fn print_banner() {
    let cyan = "\x1b[36m";
    let magenta = "\x1b[35m";
    let yellow = "\x1b[33m";
    let dim = "\x1b[2m";
    let reset = "\x1b[0m";

    eprintln!(
        r#"
{cyan} ██████╗  {magenta}███╗   ██╗ {yellow}███╗   ███╗{reset}
{cyan} ██╔══██╗ {magenta}████╗  ██║ {yellow}████╗ ████║{reset}
{cyan} ██████╔╝ {magenta}██╔██╗ ██║ {yellow}██╔████╔██║{reset}
{cyan} ██╔═══╝  {magenta}██║╚██╗██║ {yellow}██║╚██╔╝██║{reset}
{cyan} ██║      {magenta}██║ ╚████║ {yellow}██║ ╚═╝ ██║{reset}
{cyan} ╚═╝      {magenta}╚═╝  ╚═══╝ {yellow}╚═╝     ╚═╝{reset}
{dim}  Personal Network Manager v{version}{reset}
"#,
        version = env!("CARGO_PKG_VERSION"),
    );
}

/// Returns true if this command requires authentication.
/// Implementation of `pnm auth login --credential-bundle <file>`.
///
/// Opens an armored sealed bundle (matching a secret persisted earlier by
/// Parse `pnm contexts create`'s `--admin-did` / `--admin-label` /
/// `--admin-expires` flags into [`contexts::AdminAclOptions`]. Resolves the
/// duration string to an absolute unix-epoch `expires_at` on the client
/// side so the server just stores the value verbatim.
fn resolve_admin_acl_options(
    admin_did: Option<String>,
    admin_label: Option<String>,
    admin_expires: Option<&str>,
) -> Result<contexts::AdminAclOptions, Box<dyn std::error::Error>> {
    let expires_at = match admin_expires {
        Some(s) => Some(
            vta_cli_common::duration::duration_to_expires_at(s)
                .map_err(|e| format!("--admin-expires: {e}"))?,
        ),
        None => None,
    };
    Ok(contexts::AdminAclOptions {
        did: admin_did,
        label: admin_label,
        expires_at,
        expires_duration: admin_expires.map(str::to_string),
    })
}

/// Resolve an optional `--expires` duration string (e.g. `24h`, `7d`) to an
/// absolute unix-epoch `expires_at`. Matches the error-prefix style used by
/// `resolve_admin_acl_options` so CLI messages read consistently.
fn resolve_expires_at(expires: Option<&str>) -> Result<Option<u64>, Box<dyn std::error::Error>> {
    match expires {
        Some(s) => Ok(Some(
            vta_cli_common::duration::duration_to_expires_at(s)
                .map_err(|e| format!("--expires: {e}"))?,
        )),
        None => Ok(None),
    }
}

use vta_cli_common::sealed_producer::resolve_recipient;

fn requires_auth(cmd: &Commands) -> bool {
    // VTA restart requires auth; other VTA subcommands don't
    if matches!(
        cmd,
        Commands::Vta {
            command: VtaCommands::Restart
        }
    ) {
        return true;
    }
    // did-templates has both offline (Validate/Init/ListBuiltins) and online
    // (List/Show/Create/Update/Delete) subcommands — the former run without
    // authentication, the latter need a VTA connection.
    if let Commands::DidTemplates { command } = cmd {
        return is_online_template_cmd(command);
    }
    // Bootstrap has mostly offline subcommands, but
    // ProvisionIntegration bridges to the authenticated endpoint.
    if let Commands::Bootstrap { command } = cmd {
        return matches!(command, BootstrapCommands::ProvisionIntegration { .. });
    }
    !matches!(
        cmd,
        Commands::Health
            | Commands::Auth { .. }
            | Commands::Setup { .. }
            | Commands::Vta { .. }
            | Commands::Bootstrap { .. }
    )
}

fn is_online_template_cmd(cmd: &DidTemplateCommands) -> bool {
    !matches!(
        cmd,
        DidTemplateCommands::Validate { .. }
            | DidTemplateCommands::Init { .. }
            | DidTemplateCommands::ListBuiltins
    )
}

/// Spawn a Ctrl-C / SIGTERM watcher that lets a second signal force the
/// process out. Operations like a stuck mediator handshake can hold the
/// async runtime for tens of seconds even though the runtime itself
/// observed the signal — without this, the operator has no escape.
fn install_force_exit_handler() {
    use std::sync::atomic::{AtomicBool, Ordering};
    static SHUTDOWN_REQUESTED: AtomicBool = AtomicBool::new(false);

    tokio::spawn(async {
        loop {
            if tokio::signal::ctrl_c().await.is_err() {
                return;
            }
            if SHUTDOWN_REQUESTED.swap(true, Ordering::SeqCst) {
                eprintln!("\nForcing exit.");
                std::process::exit(130);
            }
            eprintln!("\nShutting down — press Ctrl-C again to force exit.");
        }
    });
}

#[tokio::main]
async fn main() {
    install_force_exit_handler();

    let cli = Cli::parse();

    // Propagate --full-display to the shared render module so any list
    // command — including ones reached via the shared vta-cli-common
    // handlers — picks up the setting without threading a bool through
    // every signature.
    vta_cli_common::render::set_full_display(cli.full_display);
    if cli.json {
        vta_cli_common::render::set_output_format(vta_cli_common::render::OutputFormat::Json);
    }
    vta_cli_common::render::set_bin_name("pnm");

    // Initialize tracing: --verbose sets pnm_cli=debug, or respect RUST_LOG
    let filter = if cli.verbose {
        tracing_subscriber::EnvFilter::new("pnm_cli=debug")
    } else {
        tracing_subscriber::EnvFilter::from_default_env()
    };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .without_time()
        .with_writer(std::io::stderr)
        .init();

    #[cfg(feature = "keyring")]
    if let Err(e) = vta_sdk::keyring_init::install_default_store() {
        eprintln!("warning: OS keyring unavailable: {e}");
    }

    print_banner();

    // Load PNM config
    let mut pnm_config = match config::load_config() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Warning: could not load config: {e}");
            config::PnmConfig::default()
        }
    };

    // Save overrides before consuming
    let url_override = cli.url.clone();
    let vta_override = cli.vta.clone();

    // Handle commands that don't need VTA resolution
    match &cli.command {
        Commands::Setup {
            command,
            name,
            overwrite,
        } => {
            // Route based on (command, name) pair. Clap allows both to be
            // set (they're orthogonal to the parser); enforce the conflict
            // at dispatch so operators get a targeted error instead of
            // clap's generic one.
            let result: Result<(), Box<dyn std::error::Error>> = match (command, name) {
                (
                    Some(SetupCommands::Continue {
                        slug,
                        vta_did: None,
                        ..
                    }),
                    None,
                ) => setup::continue_non_tee_setup_interactive(&mut pnm_config, slug).await,
                (
                    Some(SetupCommands::Continue {
                        slug,
                        vta_did: Some(vta_did),
                        vta_url,
                    }),
                    None,
                ) => {
                    setup::continue_non_tee_setup_non_interactive(
                        &mut pnm_config,
                        slug,
                        vta_did,
                        vta_url.as_deref(),
                    )
                    .await
                }
                (None, Some(name)) => {
                    setup::start_non_tee_setup_non_interactive(&mut pnm_config, name, *overwrite)
                        .await
                }
                (None, None) => setup::run_setup(setup::SetupOptions {}, &mut pnm_config).await,
                (Some(_), Some(_)) => Err(
                    "conflicting options: `--name` is for phase 1, `continue` is for phase 2 — \
                     pass one or the other, not both."
                        .into(),
                ),
            };
            if let Err(e) = result {
                vta_cli_common::render::print_cli_error(e.as_ref());
                std::process::exit(1);
            }
            return;
        }
        Commands::Bootstrap { command } => {
            // Offline / no-auth subcommands handle themselves here and
            // return. `ProvisionIntegration` needs an authed VtaClient
            // so it falls through to the main dispatch below.
            let result = match command {
                BootstrapCommands::Request { out, label } => {
                    Some(bootstrap::run_request(out.clone(), label.clone()).await)
                }
                BootstrapCommands::Open {
                    bundle,
                    expect_digest,
                    no_verify_digest,
                    expect_vta_did,
                } => Some(
                    bootstrap::run_open(
                        bundle.clone(),
                        expect_digest.clone(),
                        *no_verify_digest,
                        expect_vta_did.clone(),
                    )
                    .await,
                ),
                BootstrapCommands::Connect {
                    vta_url,
                    expect_digest,
                    no_verify_digest,
                    slug,
                } => Some(
                    bootstrap::run_connect(
                        vta_url.clone(),
                        expect_digest.clone(),
                        *no_verify_digest,
                        slug.clone(),
                        &mut pnm_config,
                    )
                    .await,
                ),
                BootstrapCommands::ProvisionRequest {
                    template,
                    vars,
                    context_hint,
                    admin_template,
                    validity_hours,
                    label,
                    out,
                } => Some(
                    bootstrap::run_provision_request(
                        template.clone(),
                        vars.clone(),
                        context_hint.clone(),
                        admin_template.clone(),
                        *validity_hours,
                        label.clone(),
                        out.clone(),
                    )
                    .await,
                ),
                // Authed — handled in the main dispatch below.
                BootstrapCommands::ProvisionIntegration { .. } => None,
            };
            if let Some(r) = result {
                if let Err(e) = r {
                    vta_cli_common::render::print_cli_error(e.as_ref());
                    std::process::exit(1);
                }
                return;
            }
        }
        Commands::DidTemplates { command } if !is_online_template_cmd(command) => {
            let result = match command {
                DidTemplateCommands::Validate { file } => did_templates::cmd_validate(file.clone()),
                DidTemplateCommands::Init { kind } => did_templates::cmd_init(kind.clone()),
                DidTemplateCommands::ListBuiltins => did_templates::cmd_list_builtins(),
                // Online subcommands fall through to the authenticated dispatch
                // below; the `requires_auth` guard routes them there.
                _ => unreachable!("online did-templates run post-auth"),
            };
            if let Err(e) = result {
                vta_cli_common::render::print_cli_error(e.as_ref());
                std::process::exit(1);
            }
            return;
        }
        Commands::Vta { command } => {
            match command {
                VtaCommands::List => {
                    if pnm_config.vtas.is_empty() {
                        println!("No VTAs configured.");
                        println!("\nRun `pnm setup` to configure your first VTA.");
                    } else {
                        let default = pnm_config.default_vta.as_deref().unwrap_or("");
                        for (slug, vta) in &pnm_config.vtas {
                            let marker = if slug == default { " (default)" } else { "" };
                            println!("  {slug}{marker}");
                            println!("    Name: {}", vta.name);
                            if let Some(ref did) = vta.vta_did {
                                println!("    DID:  {did}");
                            }
                            println!();
                        }
                    }
                }
                VtaCommands::Use { slug } => {
                    if !pnm_config.vtas.contains_key(slug) {
                        eprintln!(
                            "Error: VTA '{slug}' not found.\n\nConfigured VTAs: {}",
                            pnm_config
                                .vtas
                                .keys()
                                .cloned()
                                .collect::<Vec<_>>()
                                .join(", ")
                        );
                        std::process::exit(1);
                    }
                    pnm_config.default_vta = Some(slug.clone());
                    if let Err(e) = config::save_config(&pnm_config) {
                        eprintln!("Error saving config: {e}");
                        std::process::exit(1);
                    }
                    println!("Default VTA set to '{slug}'.");
                }
                VtaCommands::Remove { slug } => {
                    if !pnm_config.vtas.contains_key(slug) {
                        eprintln!("Error: VTA '{slug}' not found.");
                        std::process::exit(1);
                    }
                    pnm_config.vtas.remove(slug);
                    // Clear default if it was the removed VTA
                    if pnm_config.default_vta.as_deref() == Some(slug.as_str()) {
                        pnm_config.default_vta = pnm_config.vtas.keys().next().cloned();
                    }
                    // Clear the keyring entry
                    let key = config::vta_keyring_key(slug);
                    auth::logout(&key);
                    if let Err(e) = config::save_config(&pnm_config) {
                        eprintln!("Error saving config: {e}");
                        std::process::exit(1);
                    }
                    println!("VTA '{slug}' removed.");
                }
                VtaCommands::Info => {
                    match config::resolve_vta(vta_override.as_deref(), &pnm_config) {
                        Ok((slug, vta)) => {
                            println!("Active VTA: {slug}");
                            println!("  Name: {}", vta.name);
                            if let Some(ref did) = vta.vta_did {
                                println!("  DID:  {did}");
                                // REST endpoint isn't stored in PNM config —
                                // it lives in the VTA's DID document. Try to
                                // resolve and surface it for the operator.
                                if let Ok(url) = vta_sdk::session::resolve_vta_url(did).await {
                                    println!("  URL:  {url} (from DID)");
                                }
                            }
                            let key = config::vta_keyring_key(&slug);
                            auth::status(&key);
                        }
                        Err(e) => {
                            eprintln!("Error: {e}");
                            std::process::exit(1);
                        }
                    }
                }
                VtaCommands::Restart => {
                    // Fall through to authenticated command handling below
                }
            }
            // Restart needs VTA connectivity — don't return early
            if !matches!(
                cli.command,
                Commands::Vta {
                    command: VtaCommands::Restart
                }
            ) {
                return;
            }
        }
        _ => {}
    }

    // Resolve active VTA
    let (slug, vta_config) = match config::resolve_vta(vta_override.as_deref(), &pnm_config) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error: {e}");
            std::process::exit(1);
        }
    };
    let keyring_key = config::vta_keyring_key(&slug);

    // Print VTA info banner
    eprintln!("  {DIM}VTA: {slug}{RESET}");
    if let Some(ref did) = vta_config.vta_did {
        eprintln!("  {DIM}DID: {did}{RESET}");
    }
    eprintln!();

    // Build client
    // For did:key VTAs, use the persisted URL as fallback (DID has no service endpoint).
    let effective_url_override = url_override.as_deref().or(vta_config.url.as_deref());

    let client = if requires_auth(&cli.command) {
        match auth::connect(effective_url_override, &keyring_key).await {
            Ok(c) => c,
            Err(e) => {
                vta_cli_common::render::print_cli_error(e.as_ref());
                std::process::exit(1);
            }
        }
    } else {
        // Non-auth commands (e.g. `pnm health`) build the client without
        // running the SessionStore::connect path. Honour an explicit
        // `--url` override only — never silently fall back to a URL
        // synthesized from the VTA DID. For DIDComm-only VTAs that
        // synthesized URL points at nothing, and downstream code (e.g.
        // `pnm health`) would then probe REST + try to authenticate
        // against an endpoint that does not exist. Commands that need
        // a URL and have none can decide for themselves how to react.
        let url = effective_url_override.unwrap_or_default().to_string();
        VtaClient::new(&url)
    };

    let result = match cli.command {
        Commands::Setup { .. } => unreachable!("Setup handled earlier"),
        Commands::Bootstrap { command } => match command {
            BootstrapCommands::ProvisionIntegration {
                request,
                context,
                assertion,
                vc_validity_seconds,
                out,
            } => {
                bootstrap::run_provision_integration(
                    &client,
                    request,
                    context,
                    assertion,
                    vc_validity_seconds,
                    out,
                )
                .await
            }
            // Request / Open / Connect are handled in the early dispatch
            // above (they don't need an authed VtaClient).
            BootstrapCommands::Request { .. }
            | BootstrapCommands::Open { .. }
            | BootstrapCommands::Connect { .. }
            | BootstrapCommands::ProvisionRequest { .. } => unreachable!(),
        },
        Commands::DidTemplates { command } => match command {
            DidTemplateCommands::Validate { .. }
            | DidTemplateCommands::Init { .. }
            | DidTemplateCommands::ListBuiltins => unreachable!("offline commands run pre-auth"),
            DidTemplateCommands::List { context } => {
                did_templates::cmd_list(&client, context.as_deref()).await
            }
            DidTemplateCommands::Show {
                name,
                context,
                rendered,
                vars,
            } => did_templates::cmd_show(&client, &name, context.as_deref(), rendered, vars).await,
            DidTemplateCommands::Create { file, context } => {
                did_templates::cmd_create(&client, context.as_deref(), file).await
            }
            DidTemplateCommands::Update {
                name,
                file,
                context,
            } => did_templates::cmd_update(&client, &name, context.as_deref(), file).await,
            DidTemplateCommands::Delete { name, context } => {
                did_templates::cmd_delete(&client, &name, context.as_deref()).await
            }
            DidTemplateCommands::Export { name, context } => {
                did_templates::cmd_export(&client, &name, context.as_deref()).await
            }
            DidTemplateCommands::Diff {
                name,
                file,
                context,
            } => did_templates::cmd_diff(&client, &name, context.as_deref(), file).await,
        },
        Commands::Vta {
            command: VtaCommands::Restart,
        } => cmd_restart(&client).await,
        Commands::Vta { .. } => unreachable!(),
        Commands::Health => cmd_health(effective_url_override, &keyring_key).await,
        Commands::Auth { command } => match command {
            AuthCommands::Logout => {
                auth::logout(&keyring_key);
                Ok(())
            }
            AuthCommands::Status => {
                auth::status(&keyring_key);
                Ok(())
            }
        },
        Commands::Config { command } => match command {
            ConfigCommands::Get => config_cmd::cmd_config_get(&client, "").await,
            ConfigCommands::Update {
                community_vta_did,
                community_vta_name,
                public_url,
            } => {
                config_cmd::cmd_config_update(
                    &client,
                    "",
                    community_vta_did,
                    community_vta_name,
                    public_url,
                )
                .await
            }
        },
        Commands::Services { command } => match command {
            ServicesCommands::Enable { protocol } => match protocol {
                ServicesEnableProtocol::Didcomm {
                    mediator_did,
                    force,
                    handshake_timeout,
                } => {
                    services::cmd_services_enable_didcomm(
                        &client,
                        mediator_did,
                        force,
                        handshake_timeout,
                    )
                    .await
                }
            },
            ServicesCommands::Disable { protocol } => match protocol {
                ServicesDisableProtocol::Didcomm { drain_ttl } => {
                    services::cmd_services_disable_didcomm(&client, drain_ttl).await
                }
            },
        },
        Commands::Mediator { command } => match command {
            MediatorCommands::Migrate {
                new_mediator_did,
                drain_ttl,
                force,
                handshake_timeout,
            } => {
                mediator::cmd_mediator_migrate(
                    &client,
                    new_mediator_did,
                    drain_ttl,
                    force,
                    handshake_timeout,
                )
                .await
            }
            MediatorCommands::Rollback {
                target_mediator_did,
                drain_ttl,
                force,
                handshake_timeout,
            } => {
                mediator::cmd_mediator_rollback(
                    &client,
                    target_mediator_did,
                    drain_ttl,
                    force,
                    handshake_timeout,
                )
                .await
            }
            MediatorCommands::Drain { command } => match command {
                MediatorDrainCommands::Cancel { mediator_did } => {
                    mediator::cmd_mediator_drain_cancel(&client, mediator_did).await
                }
            },
            MediatorCommands::Report {
                since,
                until,
                format,
            } => match format.parse::<mediator::ReportFormat>() {
                Ok(format) => mediator::cmd_mediator_report(&client, since, until, format).await,
                Err(msg) => Err(msg.into()),
            },
        },
        Commands::Contexts { command } => match command {
            ContextCommands::List => contexts::cmd_context_list(&client).await,
            ContextCommands::Get { id } => contexts::cmd_context_get(&client, &id).await,
            ContextCommands::Create {
                id,
                name,
                description,
                admin_did,
                admin_label,
                admin_expires,
            } => {
                match resolve_admin_acl_options(admin_did, admin_label, admin_expires.as_deref()) {
                    Ok(admin) => {
                        contexts::cmd_context_create(&client, &id, &name, description, admin).await
                    }
                    Err(e) => Err(e),
                }
            }
            ContextCommands::Update {
                id,
                name,
                did,
                description,
            } => contexts::cmd_context_update(&client, &id, name, did, description).await,
            ContextCommands::UpdateDid { id, did } => {
                contexts::cmd_context_update_did(&client, &id, &did).await
            }
            ContextCommands::Delete { id, force } => {
                contexts::cmd_context_delete(&client, &id, force).await
            }
            ContextCommands::Bootstrap {
                id,
                name,
                description,
                admin_label,
                recipient,
                recipient_did,
                recipient_nonce,
            } => match resolve_recipient(
                recipient.as_deref(),
                recipient_did.as_deref(),
                recipient_nonce.as_deref(),
            ) {
                Ok(recipient) => {
                    contexts::cmd_context_bootstrap(
                        &client,
                        &id,
                        &name,
                        description,
                        admin_label,
                        recipient,
                    )
                    .await
                }
                Err(e) => Err(e),
            },
            ContextCommands::Provision {
                id,
                name,
                description,
                admin_label,
                server,
                did_url,
                portable,
                mediator_service,
                pre_rotation,
                recipient,
                recipient_did,
                recipient_nonce,
            } => {
                if server.is_some() && did_url.is_some() {
                    Err("--server and --did-url are mutually exclusive".into())
                } else {
                    let recipient_spec = resolve_recipient(
                        recipient.as_deref(),
                        recipient_did.as_deref(),
                        recipient_nonce.as_deref(),
                    );
                    match recipient_spec {
                        Ok(recipient) => {
                            let did_opts = match (&server, &did_url) {
                                (None, None) => None,
                                _ => Some(contexts::ProvisionDidOptions {
                                    server_id: server,
                                    did_url,
                                    portable,
                                    add_mediator_service: mediator_service,
                                    pre_rotation_count: pre_rotation,
                                }),
                            };
                            contexts::cmd_context_provision(
                                &client,
                                &id,
                                &name,
                                description,
                                admin_label,
                                did_opts,
                                recipient,
                            )
                            .await
                        }
                        Err(e) => Err(e),
                    }
                }
            }
            ContextCommands::Reprovision {
                id,
                admin_key,
                admin_label,
                recipient,
                recipient_did,
                recipient_nonce,
            } => match resolve_recipient(
                recipient.as_deref(),
                recipient_did.as_deref(),
                recipient_nonce.as_deref(),
            ) {
                Ok(recipient) => {
                    contexts::cmd_context_reprovision(
                        &client,
                        &id,
                        admin_key,
                        admin_label,
                        recipient,
                    )
                    .await
                }
                Err(e) => Err(e),
            },
        },
        Commands::Acl { command } => match command {
            AclCommands::List { context } => acl::cmd_acl_list(&client, context.as_deref()).await,
            AclCommands::Get { did } => acl::cmd_acl_get(&client, &did).await,
            AclCommands::Create {
                did,
                role,
                label,
                contexts,
                expires,
            } => match resolve_expires_at(expires.as_deref()) {
                Ok(expires_at) => {
                    acl::cmd_acl_create(&client, did, role, label, contexts, expires_at).await
                }
                Err(e) => Err(e),
            },
            AclCommands::Update {
                did,
                role,
                label,
                contexts,
            } => acl::cmd_acl_update(&client, &did, role, label, contexts).await,
            AclCommands::Delete { did } => acl::cmd_acl_delete(&client, &did).await,
        },
        Commands::AuthCredential { command } => match command {
            AuthCredentialCommands::Create {
                role,
                label,
                contexts,
                recipient,
                recipient_did,
                recipient_nonce,
            } => match resolve_recipient(
                recipient.as_deref(),
                recipient_did.as_deref(),
                recipient_nonce.as_deref(),
            ) {
                Ok(recipient) => {
                    credentials::cmd_auth_credential_create(
                        &client, role, label, contexts, recipient,
                    )
                    .await
                }
                Err(e) => Err(e),
            },
        },
        Commands::Webvh { command } => match command {
            WebvhCommands::AddServer { id, did, label } => {
                webvh::cmd_webvh_server_add(&client, id, did, label).await
            }
            WebvhCommands::ListServers => webvh::cmd_webvh_server_list(&client).await,
            WebvhCommands::UpdateServer { id, label } => {
                webvh::cmd_webvh_server_update(&client, &id, label).await
            }
            WebvhCommands::RemoveServer { id } => {
                webvh::cmd_webvh_server_remove(&client, &id).await
            }
            WebvhCommands::CreateDid {
                context,
                server,
                did_url,
                path,
                label,
                portable,
                mediator_service,
                services,
                pre_rotation,
                did_document,
                did_log,
                no_primary,
                signing_key,
                ka_key,
                template,
                template_context,
                vars,
            } => {
                if server.is_none() && did_url.is_none() {
                    Err("either --server or --did-url is required".into())
                } else if server.is_some() && did_url.is_some() {
                    Err("--server and --did-url are mutually exclusive".into())
                } else {
                    // Default template lookup to the DID's own context so
                    // context-local overrides are found before the global
                    // fallback.
                    let template_context =
                        template_context.or_else(|| template.as_ref().map(|_| context.clone()));
                    webvh::cmd_webvh_did_create_with_files(
                        &client,
                        context,
                        server,
                        did_url,
                        path,
                        label,
                        portable,
                        mediator_service,
                        services,
                        pre_rotation,
                        did_document,
                        did_log,
                        no_primary,
                        signing_key,
                        ka_key,
                        template,
                        template_context,
                        vars,
                    )
                    .await
                }
            }
            WebvhCommands::ListDids { context, server } => {
                webvh::cmd_webvh_did_list(&client, context.as_deref(), server.as_deref()).await
            }
            WebvhCommands::GetDid { did } => webvh::cmd_webvh_did_get(&client, &did).await,
            WebvhCommands::DeleteDid { did } => webvh::cmd_webvh_did_delete(&client, &did).await,
            WebvhCommands::DidLog { did, out } => {
                webvh::cmd_webvh_did_log(client.base_url(), &did, out).await
            }
        },
        Commands::Audit { command } => match command {
            AuditCommands::List {
                from,
                to,
                action,
                actor,
                outcome,
                context_id,
                page,
                page_size,
            } => {
                let params = vta_sdk::protocols::audit_management::list::ListAuditLogsBody {
                    from,
                    to,
                    action,
                    actor,
                    outcome,
                    context_id,
                    page,
                    page_size,
                };
                audit::cmd_list_audit_logs(&client, &params).await
            }
            AuditCommands::Retention { command } => match command {
                RetentionCommands::Get => audit::cmd_get_retention(&client).await,
                RetentionCommands::Set { days } => audit::cmd_update_retention(&client, days).await,
            },
        },
        Commands::Backup { command } => match command {
            BackupCommands::Export {
                include_audit,
                output,
            } => cmd_backup_export(&client, include_audit, output).await,
            BackupCommands::Import { file, preview } => {
                cmd_backup_import(&client, file, preview).await
            }
        },
        Commands::Keys { command } => match command {
            KeyCommands::Create {
                key_type,
                derivation_path,
                mnemonic,
                label,
                context_id,
            } => {
                keys::cmd_key_create(
                    &client,
                    &key_type,
                    derivation_path,
                    mnemonic,
                    label,
                    context_id,
                )
                .await
            }
            KeyCommands::Import {
                key_type,
                private_key,
                private_key_file,
                label,
                context_id,
            } => {
                keys::cmd_key_import(
                    &client,
                    &key_type,
                    private_key,
                    private_key_file,
                    label,
                    context_id,
                )
                .await
            }
            KeyCommands::Get { key_id, secret } => {
                keys::cmd_key_get(&client, &key_id, secret).await
            }
            KeyCommands::Revoke { key_id } => keys::cmd_key_revoke(&client, &key_id).await,
            KeyCommands::Rename { key_id, new_key_id } => {
                keys::cmd_key_rename(&client, &key_id, &new_key_id).await
            }
            KeyCommands::List {
                limit,
                offset,
                status,
                context,
            } => keys::cmd_key_list(&client, offset, limit, status, context).await,
            KeyCommands::Secrets { key_ids, context } => {
                keys::cmd_key_secrets(&client, key_ids, context).await
            }
            KeyCommands::Bundle {
                context,
                recipient,
                recipient_did,
                recipient_nonce,
            } => match resolve_recipient(
                recipient.as_deref(),
                recipient_did.as_deref(),
                recipient_nonce.as_deref(),
            ) {
                Ok(recipient) => keys::cmd_key_bundle(&client, &context, recipient).await,
                Err(e) => Err(e),
            },
            KeyCommands::Seeds => keys::cmd_seeds_list(&client).await,
            KeyCommands::RotateSeed { mnemonic } => keys::cmd_seeds_rotate(&client, mnemonic).await,
        },
    };

    client.shutdown().await;

    if let Err(e) = result {
        vta_cli_common::render::print_cli_error(e.as_ref());
        std::process::exit(1);
    }
}

async fn cmd_restart(client: &VtaClient) -> Result<(), Box<dyn std::error::Error>> {
    println!("Requesting VTA restart...");
    client.restart().await?;
    println!("{GREEN}✓{RESET} Restart initiated");

    // Wait briefly, then check health
    println!("Waiting for VTA to come back...");
    tokio::time::sleep(std::time::Duration::from_secs(3)).await;

    for attempt in 1..=5 {
        match client.health().await {
            Ok(resp) => {
                let ver = resp.version.as_deref().unwrap_or("?");
                println!("{GREEN}✓{RESET} VTA is back (v{ver})");
                return Ok(());
            }
            Err(_) if attempt < 5 => {
                tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            }
            Err(e) => {
                println!("{RED}✗{RESET} VTA did not come back after restart: {e}");
                println!("  The VTA may still be restarting. Try `pnm health` in a few seconds.");
            }
        }
    }
    Ok(())
}

async fn cmd_backup_export(
    client: &VtaClient,
    include_audit: bool,
    output: Option<std::path::PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    // Prompt for password
    let password = dialoguer::Password::new()
        .with_prompt("Backup password (min 12 chars)")
        .with_confirmation("Confirm password", "Passwords do not match")
        .interact()?;
    if password.len() < 12 {
        return Err("password must be at least 12 characters".into());
    }

    println!("Exporting backup...");
    let envelope = client.backup_export(&password, include_audit).await?;

    // Determine output path
    let path = output.unwrap_or_else(|| {
        let ts = chrono::Utc::now().format("%Y%m%d-%H%M%S");
        let slug = envelope
            .source_did
            .as_deref()
            .and_then(|d| d.rsplit(':').next())
            .unwrap_or("vta");
        std::path::PathBuf::from(format!("vta-backup-{slug}-{ts}.vtabak"))
    });

    let json = serde_json::to_string_pretty(&envelope)?;
    std::fs::write(&path, &json)?;

    println!("{GREEN}✓{RESET} Backup saved to {}", path.display());
    println!(
        "  Source DID: {}",
        envelope.source_did.as_deref().unwrap_or("(none)")
    );
    println!("  Includes audit: {}", envelope.includes_audit);
    println!("  File size: {} bytes", json.len());
    Ok(())
}

async fn cmd_backup_import(
    client: &VtaClient,
    file: std::path::PathBuf,
    preview_only: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let json = std::fs::read_to_string(&file)?;
    let envelope: vta_sdk::protocols::backup_management::types::BackupEnvelope =
        serde_json::from_str(&json)?;

    println!("Backup file: {}", file.display());
    println!(
        "  Source DID:  {}",
        envelope.source_did.as_deref().unwrap_or("(none)")
    );
    println!("  Created:     {}", envelope.created_at);
    println!("  Version:     {}", envelope.source_version);
    println!("  Audit:       {}", envelope.includes_audit);

    let password = dialoguer::Password::new()
        .with_prompt("Backup password")
        .interact()?;

    // Preview first
    let preview = client.backup_import(&envelope, &password, false).await?;
    println!();
    println!("  Keys:        {}", preview.key_count);
    println!("  ACL entries: {}", preview.acl_count);
    println!("  Contexts:    {}", preview.context_count);
    println!("  Audit logs:  {}", preview.audit_count);

    if preview_only {
        println!("\n{DIM}Preview only — no changes applied.{RESET}");
        return Ok(());
    }

    // Confirm
    println!();
    println!("{RED}WARNING: This will REPLACE ALL DATA in the VTA.{RESET}");
    print!("Type 'yes' to confirm: ");
    std::io::Write::flush(&mut std::io::stdout())?;
    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    if input.trim() != "yes" {
        println!("Import cancelled.");
        return Ok(());
    }

    println!("Importing...");
    let result = client.backup_import(&envelope, &password, true).await?;
    println!(
        "{GREEN}✓{RESET} {}",
        result.message.as_deref().unwrap_or("Import complete")
    );

    if result.status == "imported" {
        println!("  VTA is restarting with the new identity.");
        println!("  You may need to re-authenticate if the VTA DID changed.");
    }
    Ok(())
}

use vta_cli_common::render::print_section;

// ── Command handlers ────────────────────────────────────────────────

async fn cmd_health(
    url_override: Option<&str>,
    keyring_key: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    use affinidi_did_resolver_cache_sdk::{DIDCacheClient, config::DIDCacheConfigBuilder};

    let session = auth::loaded_session(keyring_key);

    // Single shared DID resolver — cached across all resolutions
    let did_resolver = DIDCacheClient::new(DIDCacheConfigBuilder::default().build())
        .await
        .ok();

    // ── VTA ────────────────────────────────────────────────────────
    print_section("VTA");

    if let Some(ref info) = session {
        match info.vta_did.as_deref() {
            Some(vta_did) => {
                println!("  {CYAN}{:<13}{RESET} {vta_did}", "DID");
                if let Some(ref resolver) = did_resolver {
                    match resolver.resolve(vta_did).await {
                        Ok(_) => {
                            let method = vta_did
                                .strip_prefix("did:")
                                .and_then(|s| s.split(':').next())
                                .unwrap_or("?");
                            println!("                {GREEN}✓{RESET} resolves ({method})");
                        }
                        Err(e) => {
                            println!("                {RED}✗{RESET} resolution failed: {e}")
                        }
                    }
                }
            }
            None => {
                println!(
                    "  {CYAN}{:<13}{RESET} {DIM}(pending — run `pnm setup continue <slug>`){RESET}",
                    "DID"
                );
            }
        }
    }

    // What the VTA's DID document actually advertises. Source of truth
    // for the "Mode" label below — and for whether to show URL / probe
    // Service / attempt REST authentication. An explicit `--url`
    // override (or `[vta] url = "..."` in pnm config) is the only thing
    // that can light those up when the DID document doesn't advertise
    // REST itself; falling back to a URL synthesized from the DID
    // string would point at a non-existent endpoint for DIDComm-only
    // VTAs.
    let advertised = match session.as_ref().and_then(|s| s.vta_did.as_deref()) {
        Some(vta_did) => vta_sdk::session::resolve_vta_endpoint(vta_did).await.ok(),
        None => None,
    };

    let (mode_label, advertised_rest_url, advertises_didcomm) = match &advertised {
        Some(vta_sdk::session::VtaEndpoint::DIDComm {
            rest_url: Some(u), ..
        }) => ("DIDComm + REST", Some(u.clone()), true),
        Some(vta_sdk::session::VtaEndpoint::DIDComm { rest_url: None, .. }) => {
            ("DIDComm-only", None, true)
        }
        Some(vta_sdk::session::VtaEndpoint::Rest { url }) => {
            ("REST-only", Some(url.clone()), false)
        }
        None if session
            .as_ref()
            .and_then(|s| s.vta_did.as_deref())
            .is_some() =>
        {
            ("unknown (could not enumerate services)", None, false)
        }
        None => ("(pending DID setup)", None, false),
    };
    println!("  {CYAN}{:<13}{RESET} {mode_label}", "Mode");

    // Effective URL = explicit override (CLI / config) OR what the DID
    // doc advertised. When neither is present (DIDComm-only VTA, no
    // override), `effective_rest_url` stays None and the URL / Service
    // / Authentication rows below are suppressed entirely.
    let override_url = url_override
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    let url_overridden =
        override_url.is_some() && advertised_rest_url.as_deref() != override_url.as_deref();
    let effective_rest_url = override_url.clone().or_else(|| advertised_rest_url.clone());

    if let Some(ref url) = effective_rest_url {
        let suffix = if url_overridden {
            format!(" {DIM}(--url override){RESET}")
        } else {
            format!(" {DIM}(from DID){RESET}")
        };
        println!("  {CYAN}{:<13}{RESET} {url}{suffix}", "URL");

        let probe_client = VtaClient::new(url);
        match probe_client.health().await {
            Ok(resp) => {
                let ver = resp
                    .version
                    .as_deref()
                    .map(|v| format!(" (v{v})"))
                    .unwrap_or_default();
                println!("  {CYAN}{:<13}{RESET} {GREEN}✓{RESET} ok{ver}", "Service");
            }
            Err(e) => {
                println!(
                    "  {CYAN}{:<13}{RESET} {RED}✗{RESET} unreachable ({e})",
                    "Service"
                );
            }
        }
    }

    // ── Authentication ─────────────────────────────────────────────
    print_section("Authentication");

    if let Some(ref url) = effective_rest_url {
        if let Some(ref info) = session {
            println!("  {CYAN}{:<13}{RESET} {}", "Client DID", info.client_did);
            match auth::ensure_authenticated(url, keyring_key).await {
                Ok(_token) => {
                    if let Some(status) = auth::session_status(keyring_key) {
                        match status.token_status {
                            vta_sdk::session::TokenStatus::Valid { expires_in_secs } => {
                                println!(
                                    "  {CYAN}{:<13}{RESET} {GREEN}✓{RESET} valid (expires in {expires_in_secs}s)",
                                    "Token"
                                );
                            }
                            _ => {
                                println!("  {CYAN}{:<13}{RESET} {GREEN}✓{RESET} valid", "Token");
                            }
                        }
                    }
                }
                Err(e) => {
                    println!("  {CYAN}{:<13}{RESET} {RED}✗{RESET} {e}", "Token");
                }
            }
        } else {
            println!("  {DIM}Not authenticated{RESET}");
        }
    } else if advertises_didcomm {
        println!("  {DIM}DIDComm-only VTA — no REST auth{RESET}");
    } else {
        println!("  {DIM}No transport advertised{RESET}");
    }

    // ── Mediator + DIDComm pings ──────────────────────────────────
    print_section("Mediator");

    if let Some(ref info) = session
        && let Some(vta_did) = info.vta_did.as_deref()
    {
        // Resolve mediator DID using the shared resolver (avoids creating a second one)
        let mediator_result = if let Some(ref resolver) = did_resolver {
            vta_sdk::session::resolve_mediator_did_with_resolver(vta_did, resolver).await
        } else {
            vta_sdk::session::resolve_mediator_did(vta_did).await
        };

        match mediator_result {
            Ok(Some(mediator_did)) => {
                println!("  {CYAN}{:<13}{RESET} {mediator_did}", "DID");

                // Resolve mediator DID document (uses cached resolver)
                if let Some(ref resolver) = did_resolver {
                    match resolver.resolve(&mediator_did).await {
                        Ok(_) => {
                            let method = mediator_did
                                .strip_prefix("did:")
                                .and_then(|s| s.split(':').next())
                                .unwrap_or("?");
                            println!("                {GREEN}✓{RESET} resolves ({method})");
                        }
                        Err(e) => {
                            println!("                {RED}✗{RESET} resolution failed: {e}");
                        }
                    }
                }

                // Set up a single DIDComm session and reuse for both pings
                match tokio::time::timeout(
                    std::time::Duration::from_secs(15),
                    vta_sdk::session::TrustPingSession::new(
                        &info.client_did,
                        &info.private_key_multibase,
                        &mediator_did,
                    ),
                )
                .await
                {
                    Ok(Ok(session)) => {
                        // Ping mediator
                        match tokio::time::timeout(
                            std::time::Duration::from_secs(10),
                            session.ping(None),
                        )
                        .await
                        {
                            Ok(Ok(latency)) => {
                                println!("                {GREEN}✓{RESET} pong ({latency}ms)");
                            }
                            Ok(Err(e)) => {
                                println!("                {RED}✗{RESET} trust-ping failed: {e}");
                            }
                            Err(_) => {
                                println!("                {RED}✗{RESET} trust-ping timed out");
                            }
                        }

                        // Ping VTA through the same session
                        print_section("VTA DIDComm");

                        match tokio::time::timeout(
                            std::time::Duration::from_secs(15),
                            session.ping(Some(vta_did)),
                        )
                        .await
                        {
                            Ok(Ok(latency)) => {
                                println!(
                                    "  {CYAN}{:<13}{RESET} {GREEN}✓{RESET} pong ({latency}ms)",
                                    "Trust-ping"
                                );
                            }
                            Ok(Err(e)) => {
                                println!(
                                    "  {CYAN}{:<13}{RESET} {RED}✗{RESET} trust-ping failed: {e}",
                                    "Trust-ping"
                                );
                            }
                            Err(_) => {
                                println!(
                                    "  {CYAN}{:<13}{RESET} {RED}✗{RESET} trust-ping timed out",
                                    "Trust-ping"
                                );
                            }
                        }

                        session.shutdown().await;
                    }
                    Ok(Err(e)) => {
                        println!("                {RED}✗{RESET} DIDComm setup failed: {e}");
                    }
                    Err(_) => {
                        println!("                {RED}✗{RESET} DIDComm setup timed out");
                    }
                }
            }
            Ok(None) => {
                println!("  {DIM}(not configured){RESET}");
            }
            Err(e) => {
                println!(
                    "  {CYAN}{:<13}{RESET} {RED}✗{RESET} could not resolve VTA DID: {e}",
                    "DID"
                );
            }
        }
    } else {
        println!("  {DIM}(no session){RESET}");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── requires_auth ──────────────────────────────────────────────

    #[test]
    fn test_requires_auth_health_false() {
        assert!(!requires_auth(&Commands::Health));
    }

    #[test]
    fn test_requires_auth_auth_status_false() {
        let cmd = Commands::Auth {
            command: AuthCommands::Status,
        };
        assert!(!requires_auth(&cmd));
    }

    #[test]
    fn test_requires_auth_setup_false() {
        let cmd = Commands::Setup {
            command: None,
            name: None,
            overwrite: false,
        };
        assert!(!requires_auth(&cmd));
    }

    // ── Setup clap parse shapes ───────────────────────────────────
    //
    // The spec requires all of these to parse unambiguously. If clap
    // surfaces a regression here (e.g. `--name continue` being absorbed
    // as a value for the subcommand), these tests pin the contract.

    fn parse(args: &[&str]) -> Cli {
        Cli::try_parse_from(args).expect("should parse")
    }

    #[test]
    fn setup_bare_parses_all_none() {
        let cli = parse(&["pnm", "setup"]);
        match cli.command {
            Commands::Setup {
                command,
                name,
                overwrite,
            } => {
                assert!(command.is_none());
                assert!(name.is_none());
                assert!(!overwrite);
            }
            _ => panic!("expected Setup"),
        }
    }

    #[test]
    fn setup_with_name_parses_as_non_interactive_phase1() {
        let cli = parse(&["pnm", "setup", "--name", "My VTA"]);
        match cli.command {
            Commands::Setup {
                command,
                name,
                overwrite,
            } => {
                assert!(command.is_none());
                assert_eq!(name.as_deref(), Some("My VTA"));
                assert!(!overwrite);
            }
            _ => panic!("expected Setup"),
        }
    }

    #[test]
    fn setup_with_name_and_overwrite_parses() {
        let cli = parse(&["pnm", "setup", "--name", "foo", "--overwrite"]);
        match cli.command {
            Commands::Setup {
                name, overwrite, ..
            } => {
                assert_eq!(name.as_deref(), Some("foo"));
                assert!(overwrite);
            }
            _ => panic!("expected Setup"),
        }
    }

    #[test]
    fn setup_continue_parses_interactive() {
        let cli = parse(&["pnm", "setup", "continue", "my-vta"]);
        match cli.command {
            Commands::Setup {
                command,
                name,
                overwrite,
            } => {
                assert!(matches!(
                    command,
                    Some(SetupCommands::Continue { vta_did: None, .. })
                ));
                assert!(name.is_none());
                assert!(!overwrite);
                if let Some(SetupCommands::Continue { slug, .. }) = command {
                    assert_eq!(slug, "my-vta");
                }
            }
            _ => panic!("expected Setup"),
        }
    }

    #[test]
    fn setup_continue_parses_non_interactive() {
        let cli = parse(&[
            "pnm",
            "setup",
            "continue",
            "my-vta",
            "--vta-did",
            "did:webvh:abc:vta.example.com:primary",
        ]);
        match cli.command {
            Commands::Setup {
                command: Some(SetupCommands::Continue { slug, vta_did, .. }),
                ..
            } => {
                assert_eq!(slug, "my-vta");
                assert_eq!(
                    vta_did.as_deref(),
                    Some("did:webvh:abc:vta.example.com:primary")
                );
            }
            _ => panic!("expected Setup+Continue"),
        }
    }

    #[test]
    fn setup_name_with_continue_subcommand_parses() {
        // Clap treats subcommand and parent args as orthogonal, so
        // `pnm setup --name foo continue bar` parses. The runtime
        // dispatch rejects this combination — enforced in commit 3
        // (setup logic + pending detection), covered by the
        // integration suite in commit 4. This test pins the parse
        // contract so a future clap upgrade doesn't silently change
        // it.
        let cli = parse(&["pnm", "setup", "--name", "foo", "continue", "bar"]);
        match cli.command {
            Commands::Setup { command, name, .. } => {
                assert_eq!(name.as_deref(), Some("foo"));
                assert!(matches!(command, Some(SetupCommands::Continue { .. })));
            }
            _ => panic!("expected Setup"),
        }
    }

    #[test]
    fn test_requires_auth_keys_true() {
        let cmd = Commands::Keys {
            command: KeyCommands::List {
                limit: 50,
                offset: 0,
                status: None,
                context: None,
            },
        };
        assert!(requires_auth(&cmd));
    }

    #[test]
    fn test_requires_auth_config_true() {
        let cmd = Commands::Config {
            command: ConfigCommands::Get,
        };
        assert!(requires_auth(&cmd));
    }

    #[test]
    fn test_requires_auth_acl_true() {
        let cmd = Commands::Acl {
            command: AclCommands::List { context: None },
        };
        assert!(requires_auth(&cmd));
    }

    #[test]
    fn test_requires_auth_contexts_true() {
        let cmd = Commands::Contexts {
            command: ContextCommands::List,
        };
        assert!(requires_auth(&cmd));
    }

    #[test]
    fn test_requires_auth_vta_false() {
        let cmd = Commands::Vta {
            command: VtaCommands::List,
        };
        assert!(!requires_auth(&cmd));
    }
}
