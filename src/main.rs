use anyhow::Context;
use arc_swap::ArcSwap;
use axum::routing::{get, post};
use axum::{Extension, Router};
use clap::Parser;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::signal;
use tower_http::cors::CorsLayer;
use tower_http::trace::TraceLayer;
use tracing::{info, warn};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use steer_core::config::SteerConfig;
use steer_core::detectors::tool_governance::{ToolGovernanceConfig, ToolGovernanceDetector};
use steer_core::detectors::ContentDetector;
use steer_core::handover::HoldStore;
use steer_core::mcp_registry::{McpRegistryProvider, McpServerRegistry};
use steer_core::middleware::{InFlightLayer, MAX_IN_FLIGHT};
use steer_core::performance::{AnomalyProvider, NoopAnomaly, NoopPerformance, PerformanceProvider};
use steer_core::pii::RegexPiiEngine;
use steer_core::pipeline::PipelineState;
use steer_core::policy::cedar::CedarEngine;
use steer_core::policy::registry::{
    PolicyRegistryBackend, TenantPolicyConfig, TenantPolicyRegistry,
};
use steer_core::policy::watcher::PolicyWatcher;
use steer_core::routes::{chat, eval, health, holds};
use steer_core::tenants::{
    policy_config::ManagedPolicyVersion, SingleTenantAuth, SingleTenantSettings,
    TenantAuthProvider, TenantSettings, TenantSettingsProvider,
};
use steer_core::tokens::{BudgetCache, CostEstimator, ModelCost, NoopTokenProvider, TokenProvider};

#[derive(Parser, Debug)]
#[command(
    name = "steer",
    version,
    about = "EnforceGrid - Runtime AI enforcement engine"
)]
struct Cli {
    /// Path to steer.yaml.
    ///
    /// When omitted, the binary searches:
    ///   1. `./steer.yaml` in the current directory (devloop convention)
    ///   2. `$XDG_CONFIG_HOME/steer/steer.yaml` (or `~/.config/steer/steer.yaml`)
    ///
    /// An explicit `--config` or `$STEER_CONFIG` always wins and is loaded verbatim.
    #[arg(short, long, env = "STEER_CONFIG")]
    config: Option<String>,

    #[arg(long, env = "STEER_HOST")]
    host: Option<String>,

    #[arg(long, env = "STEER_PORT")]
    port: Option<u16>,

    #[arg(long, default_value = "false")]
    json_logs: bool,
}

/// Single-tenant policy registry backend.
///
/// Loads the managed baseline from every `*.cedar` file at the top level of
/// `policy_dir` (non-recursive). Tenant overrides live one level down at
/// `<policy_dir>/<tenant_id>/*.cedar` and are appended by the registry on
/// top of the baseline returned here.
///
/// Layering:
/// - Baseline (this function)      → ships with the binary
/// - Tenant overrides              → operator-authored, upgrade-safe
///
/// Note: Cedar requires unique `@id` per policy in the loaded set, so an
/// override file cannot redefine a baseline rule by reusing its ID. To
/// disable a baseline rule today, operators fork `default.cedar` into a
/// separate dir and point `policy_dir` there. A future disable-list
/// mechanism is tracked in `stage/doc_requirements.md §16.2`.
struct SingleTenantPolicyBackend {
    policy_dir: String,
}

impl PolicyRegistryBackend for SingleTenantPolicyBackend {
    fn get_tenant_config(&self, tenant_id: &str) -> anyhow::Result<TenantPolicyConfig> {
        Ok(TenantPolicyConfig::default_for(tenant_id))
    }

    fn get_managed_version(&self, _version: &str) -> anyhow::Result<Option<ManagedPolicyVersion>> {
        let dir = std::path::Path::new(&self.policy_dir);
        if !dir.is_dir() {
            return Ok(None);
        }

        let mut entries: Vec<_> = std::fs::read_dir(dir)?
            .filter_map(|e| e.ok())
            // Top-level .cedar files only. Subdirectories are tenant overrides.
            .filter(|e| {
                e.file_type().map(|t| t.is_file()).unwrap_or(false)
                    && e.path().extension().is_some_and(|x| x == "cedar")
            })
            .collect();
        entries.sort_by_key(|e| e.path());

        if entries.is_empty() {
            return Ok(None);
        }

        let mut content = String::new();
        for entry in entries {
            let body = std::fs::read_to_string(entry.path())?;
            content.push_str(&body);
            content.push('\n');
        }

        // hash for traceability; not security-critical (Cedar text is the
        // authoritative input — this is operator metadata only).
        use sha2::{Digest, Sha256};
        let content_hash = hex::encode(Sha256::digest(content.as_bytes()));

        Ok(Some(ManagedPolicyVersion {
            version: "oss-filesystem".to_string(),
            description: format!("Loaded from {} (top-level *.cedar files)", self.policy_dir),
            content,
            content_hash,
            published_at: chrono::Utc::now().to_rfc3339(),
            published_by: None,
        }))
    }

    fn tenants_with_auto_upgrade(&self) -> anyhow::Result<Vec<String>> {
        Ok(vec![])
    }
    fn upgrade_tenant_version(&self, _tenant_id: &str, _version: &str) -> anyhow::Result<()> {
        Ok(())
    }
    fn managed_policy_count_for_version(&self, _version: &str) -> usize {
        // Best-effort: count top-level .cedar files. Errors → 0.
        std::fs::read_dir(&self.policy_dir)
            .map(|rd| {
                rd.filter_map(|e| e.ok())
                    .filter(|e| {
                        e.file_type().map(|t| t.is_file()).unwrap_or(false)
                            && e.path().extension().is_some_and(|x| x == "cedar")
                    })
                    .count()
            })
            .unwrap_or(0)
    }
}

/// Resolve the path to `steer.yaml` according to XDG-aware fallthrough:
///
/// 1. If `explicit` is `Some` (from `--config` or `$STEER_CONFIG`), use it verbatim.
///    Errors propagate via the loader if the file doesn't exist — this is
///    the operator-pinned path.
/// 2. Else `./steer.yaml` in the current working directory (devloop convention).
/// 3. Else `$XDG_CONFIG_HOME/steer/steer.yaml` (defaults to
///    `~/.config/steer/steer.yaml`) — the location `install.sh` writes a
///    working config to on first install.
/// 4. Else error with a `where-I-looked` message that points at the
///    install-script-managed location.
fn resolve_config_path(explicit: Option<&str>) -> anyhow::Result<PathBuf> {
    if let Some(p) = explicit {
        return Ok(PathBuf::from(p));
    }

    let cwd = PathBuf::from("steer.yaml");
    if cwd.exists() {
        return Ok(cwd);
    }

    if let Some(xdg) = xdg_config_home() {
        let candidate = xdg.join("steer").join("steer.yaml");
        if candidate.exists() {
            return Ok(candidate);
        }
    }

    let xdg_hint = xdg_config_home()
        .map(|p| p.join("steer"))
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "~/.config/steer".to_string());

    anyhow::bail!(
        "no steer.yaml found. Searched:\n  - ./steer.yaml\n  - {xdg_hint}/steer.yaml\n\n\
         If you installed via install.sh, bootstrap a config with:\n\
           cp {xdg_hint}/steer.example.yaml {xdg_hint}/steer.yaml\n\n\
         Or pass --config explicitly."
    )
}

/// XDG-spec config-home resolution.
///
/// Honors `$XDG_CONFIG_HOME` when set and non-empty; otherwise falls back
/// to `$HOME/.config`. Returns `None` only when neither variable is set —
/// the binary then surfaces the explicit search-path error.
fn xdg_config_home() -> Option<PathBuf> {
    if let Ok(p) = std::env::var("XDG_CONFIG_HOME") {
        if !p.is_empty() {
            return Some(PathBuf::from(p));
        }
    }
    std::env::var("HOME")
        .ok()
        .map(|h| PathBuf::from(h).join(".config"))
}

fn build_detectors() -> Vec<Box<dyn ContentDetector>> {
    vec![
        Box::new(steer_core::detectors::identity::IdentityClaimDetector::new()),
        Box::new(steer_core::detectors::confidential::ConfidentialDetector::new()),
        Box::new(steer_core::detectors::injection::InjectionDetector::new()),
        Box::new(steer_core::detectors::jailbreak::JailbreakDetector::new()),
        Box::new(steer_core::detectors::exfiltration::ExfiltrationDetector::new()),
        Box::new(steer_core::detectors::threat::ThreatDetector::new()),
        Box::new(steer_core::detectors::bias::BiasDetector::new()),
    ]
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| "steer=info".into());
    if cli.json_logs {
        tracing_subscriber::registry()
            .with(fmt::layer().json())
            .with(env_filter)
            .init();
    } else {
        tracing_subscriber::registry()
            .with(fmt::layer())
            .with(env_filter)
            .init();
    }

    let cfg_path = resolve_config_path(cli.config.as_deref())?;
    let cfg_path_str = cfg_path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("config path is not valid UTF-8: {}", cfg_path.display()))?;
    info!(config = %cfg_path.display(), "loading config");
    let mut config: SteerConfig = steer_core::config::load(cfg_path_str)
        .with_context(|| format!("Failed to load config from {}", cfg_path.display()))?;

    if let Some(host) = cli.host {
        config.proxy.host = host;
    }
    if let Some(port) = cli.port {
        config.proxy.port = port;
    } else if let Ok(s) = std::env::var("PORT") {
        if let Ok(p) = s.parse::<u16>() {
            config.proxy.port = p;
        }
    }

    if std::env::var("STEER_API_KEY")
        .ok()
        .filter(|s| !s.is_empty())
        .is_none()
    {
        warn!("STEER_API_KEY is not set — all endpoints are unauthenticated. Do NOT run in production.");
    }
    if config.proxy.fail_open {
        warn!("fail_open is true — policy errors will allow requests through. Set fail_open: false for production.");
    }

    let fail_open = config.proxy.fail_open;
    let addr: SocketAddr = format!("{}:{}", config.proxy.host, config.proxy.port)
        .parse()
        .context("Invalid listen address")?;

    info!(
        version = env!("CARGO_PKG_VERSION"),
        addr = %addr,
        fail_open,
        "steer starting"
    );

    health::init();

    let config = Arc::new(config);

    let pii_engine = Arc::new(RegexPiiEngine::with_custom(
        &config.pii.patterns,
        &config.pii.custom_patterns,
    ));

    let initial_engine = Arc::new(CedarEngine::load_from_config(&config.policy)?);

    // Startup consistency check: every PII pattern name referenced inside a
    // Cedar `containsAny([...])` must be in the compiled PII engine's pattern
    // set. If a name is missing, the regex was never compiled and the Cedar
    // rule will silently never fire — the kind of policy-degradation defect
    // CISO/compliance review flagged for v0.1.0. We warn rather than fail so
    // operators can still boot in a degraded state knowingly; the warning
    // text gives a concrete fix hint.
    //
    // Tracked in stage/doc_requirements.md §16.7.
    {
        let cedar_text = initial_engine.policy_text();
        let names = pii_engine.pattern_names();
        let missing = steer_core::policy::consistency::find_missing_patterns(cedar_text, &names);
        for m in &missing {
            let policy_label = if m.policy_id.is_empty() {
                "<unnamed>".to_string()
            } else {
                m.policy_id.clone()
            };
            warn!(
                policy_id = %policy_label,
                pattern = %m.pattern_name,
                "Cedar policy references PII pattern '{}' that is not compiled — rule will never fire. \
                 Fix: add '{}' to pii.patterns in steer.yaml, or remove it from policy '{}'.",
                m.pattern_name,
                m.pattern_name,
                policy_label,
            );
        }
        if !missing.is_empty() {
            warn!(
                count = missing.len(),
                "policy/PII-pattern consistency check found {} degraded rule reference(s)",
                missing.len()
            );
        }
    }

    let policy_swap: Arc<ArcSwap<CedarEngine>> = Arc::new(ArcSwap::new(initial_engine));

    if config.policy.watch {
        let swap = Arc::clone(&policy_swap);
        let policy_cfg = config.policy.clone();
        tokio::spawn(async move {
            match PolicyWatcher::new(policy_cfg, swap) {
                Ok(mut w) => {
                    let _ = w.run().await;
                }
                Err(e) => warn!(error = %e, "policy watcher failed to start"),
            }
        });
    }

    let observation_mode = match config.policy.mode.as_str() {
        "observe" => true,
        "enforce" => false,
        other => {
            warn!(
                mode = other,
                "unknown policy.mode — expected 'enforce' or 'observe'. Defaulting to 'enforce'."
            );
            false
        }
    };

    let tenant_settings_provider: Arc<dyn TenantSettingsProvider> =
        Arc::new(SingleTenantSettings {
            settings: TenantSettings {
                observation_mode,
                consent_given: config.tenant.consent_given,
                data_processing_consent: config.tenant.consent_given,
                industry: Some(config.tenant.industry.clone()),
                timezone: Some(config.tenant.timezone.clone()),
                data_residency_region: if config.tenant.region.is_empty() {
                    None
                } else {
                    Some(config.tenant.region.clone())
                },
                business_hours_window: if config.tenant.business_hours_window.is_empty() {
                    None
                } else {
                    Some(config.tenant.business_hours_window.clone())
                },
            },
        });

    let policy_registry = Arc::new(
        TenantPolicyRegistry::new(
            Arc::new(SingleTenantPolicyBackend {
                policy_dir: config.policy.policy_dir.clone(),
            }),
            &config.policy.policy_dir,
        )
        .with_settings_provider(Arc::clone(&tenant_settings_provider)),
    );

    let http_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_millis(config.proxy.timeout_ms))
        .pool_max_idle_per_host(config.proxy.pool_max_idle_per_host)
        .tcp_keepalive(std::time::Duration::from_secs(
            config.proxy.tcp_keepalive_secs,
        ))
        .build()?;

    let cost_estimator = {
        let mut costs = HashMap::new();
        for (model, cfg) in &config.token_costs {
            costs.insert(
                model.clone(),
                ModelCost {
                    prompt_per_1k: cfg.prompt_per_1k,
                    completion_per_1k: cfg.completion_per_1k,
                },
            );
        }
        Arc::new(CostEstimator::new(costs))
    };

    let budget_cache = Arc::new(BudgetCache::new());
    if !config.budget.budgets.is_empty() {
        steer_core::tokens::yaml_source::populate_cache(&budget_cache, &config.budget.budgets);
        let cache_clone = budget_cache.clone();
        let budgets_clone = config.budget.budgets.clone();
        let interval = config.budget.check_interval_secs;
        tokio::spawn(steer_core::tokens::yaml_source::run_rollover_task(
            cache_clone,
            budgets_clone,
            interval,
        ));
        info!(
            count = config.budget.budgets.len(),
            check_interval_secs = interval,
            "budget tracking enabled (yaml-driven, in-memory)"
        );
    }
    let hold_store = HoldStore::new(config.handover.max_concurrent_holds);
    let mcp_registry: Arc<dyn McpRegistryProvider> = Arc::new(McpServerRegistry::new());

    let tool_governance = {
        use std::collections::HashSet;
        let tg = &config.detectors.tool_governance;
        ToolGovernanceDetector::new(ToolGovernanceConfig {
            allowed_tools: tg.allowed_tools.iter().cloned().collect::<HashSet<_>>(),
            block_in_allowlist_mode: tg.block_in_allowlist_mode,
        })
    };

    // WARN on suspicious api_key values (placeholders, whitespace, wrong vendor prefix).
    // v0.1.1: warn only; v0.2 will promote to refuse-to-start (see Item 2 of v0.1.1 spec).
    for w in steer_core::config::validate::validate(&config) {
        warn!(field = %w.field, message = %w.message, "config sanity check");
    }

    // Fail-loud: a misconfigured audit sink must abort startup. Silently
    // falling back to stdout would compromise the evidentiary guarantee that
    // Steer's value proposition rests on. See stage/doc_requirements.md §16.7.
    let audit_sink = steer_core::audit::build_sink(
        &config.audit.backend,
        &config.audit.log_path,
        &config.audit.format,
    )
    .with_context(|| {
        format!(
            "Failed to initialize audit sink (backend={}, log_path={})",
            config.audit.backend, config.audit.log_path
        )
    })?;

    info!(
        policy_mode = %config.policy.mode,
        policy_dir = %config.policy.policy_dir,
        audit_backend = %config.audit.backend,
        audit_format = %config.audit.format,
        "config wiring resolved"
    );

    let state = Arc::new(PipelineState {
        config: Arc::clone(&config),
        pii_engine,
        policy_engine: Arc::clone(&policy_swap),
        policy_registry: Arc::clone(&policy_registry),
        audit_sink,
        perf: Arc::new(NoopPerformance) as Arc<dyn PerformanceProvider>,
        http_client,
        token_provider: Arc::new(NoopTokenProvider) as Arc<dyn TokenProvider>,
        budget_cache: Arc::clone(&budget_cache),
        cost_estimator: Arc::clone(&cost_estimator),
        detectors: Arc::new(build_detectors()),
        tenant_auth: Arc::new(SingleTenantAuth) as Arc<dyn TenantAuthProvider>,
        tenant_id_cache: dashmap::DashMap::new(),
        sync_cache: Arc::new(dashmap::DashMap::new()),
        tenant_settings: Arc::clone(&tenant_settings_provider),
        anomaly: Arc::new(NoopAnomaly) as Arc<dyn AnomalyProvider>,
        kill_switch: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        mcp_registry: Arc::clone(&mcp_registry),
        tool_governance,
        hold_store: Arc::clone(&hold_store),
    });

    let semaphore = Arc::new(tokio::sync::Semaphore::new(MAX_IN_FLIGHT));

    let app = Router::new()
        .route("/health", get(health::health))
        .route("/v1/chat/completions", post(chat::chat_completions))
        .route("/v1/messages", post(chat::messages))
        .route("/v1/models", get(chat::passthrough))
        .route("/api/v1/holds", get(holds::list_holds))
        .route("/api/v1/holds/:id", get(holds::get_hold))
        .route("/api/v1/holds/:id/resolve", post(holds::resolve_hold))
        .route("/api/v1/policies/eval", post(eval::eval_policy))
        .route("/api/v1/detectors", get(eval::list_detectors))
        .layer(Extension(state))
        .layer(Extension(hold_store))
        .layer(Extension(Arc::clone(&budget_cache)))
        .layer(Extension(Arc::clone(&cost_estimator)))
        .layer(InFlightLayer::new(Arc::clone(&semaphore)))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http());

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .with_context(|| format!("Failed to bind to {addr}"))?;

    info!("listening on {addr}");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("server error")?;

    info!("draining in-flight requests");
    let _ = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        semaphore.acquire_many(MAX_IN_FLIGHT as u32),
    )
    .await;

    info!("steer stopped");
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    };
    #[cfg(unix)]
    let terminate = async {
        signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("failed to install SIGTERM handler")
            .recv()
            .await;
    };
    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c  => { info!("received Ctrl+C, initiating graceful shutdown"); },
        _ = terminate => { info!("received SIGTERM, initiating graceful shutdown"); },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use tempfile::TempDir;

    /// Process-wide mutex for tests that mutate global state (`CWD`, env vars).
    /// `cargo test` runs the bin's tests in parallel threads by default; without
    /// this lock the env/CWD races produce flaky failures. One lock guards the
    /// whole `main`-bin test module — every test takes it on entry.
    static GLOBAL_TEST_LOCK: Mutex<()> = Mutex::new(());

    /// Guard that mutates env vars (XDG_CONFIG_HOME / HOME) for a single test
    /// and restores prior state on drop.
    struct EnvGuard {
        keys: Vec<(String, Option<String>)>,
    }
    impl EnvGuard {
        fn new(pairs: &[(&str, Option<&str>)]) -> Self {
            let mut keys = Vec::with_capacity(pairs.len());
            for (k, v) in pairs {
                keys.push((k.to_string(), std::env::var(k).ok()));
                match v {
                    Some(val) => std::env::set_var(k, val),
                    None => std::env::remove_var(k),
                }
            }
            Self { keys }
        }
    }
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            for (k, v) in &self.keys {
                match v {
                    Some(val) => std::env::set_var(k, val),
                    None => std::env::remove_var(k),
                }
            }
        }
    }

    #[test]
    fn explicit_config_arg_is_used_verbatim() {
        let _lock = GLOBAL_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        // Pin won — XDG never consulted, file existence never checked.
        let resolved = resolve_config_path(Some("/nonexistent/explicit.yaml")).unwrap();
        assert_eq!(resolved, PathBuf::from("/nonexistent/explicit.yaml"));
    }

    #[test]
    fn cwd_steer_yaml_takes_precedence_when_present() {
        let _lock = GLOBAL_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        // Use a temp dir as CWD so the test doesn't depend on the repo state.
        let tmp = TempDir::new().unwrap();
        std::fs::write(tmp.path().join("steer.yaml"), "proxy: {}").unwrap();
        let cwd_save = std::env::current_dir().unwrap();
        std::env::set_current_dir(tmp.path()).unwrap();
        // Force XDG to point at a *different* dir that ALSO has a file, so we
        // can prove CWD wins.
        let xdg_tmp = TempDir::new().unwrap();
        std::fs::create_dir_all(xdg_tmp.path().join("steer")).unwrap();
        std::fs::write(xdg_tmp.path().join("steer/steer.yaml"), "proxy: {}").unwrap();
        let _g = EnvGuard::new(&[("XDG_CONFIG_HOME", Some(xdg_tmp.path().to_str().unwrap()))]);

        let resolved = resolve_config_path(None).unwrap();
        assert_eq!(resolved, PathBuf::from("steer.yaml"));

        std::env::set_current_dir(cwd_save).unwrap();
    }

    #[test]
    fn xdg_config_home_used_when_cwd_empty() {
        let _lock = GLOBAL_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let cwd_tmp = TempDir::new().unwrap();
        let cwd_save = std::env::current_dir().unwrap();
        std::env::set_current_dir(cwd_tmp.path()).unwrap();

        let xdg_tmp = TempDir::new().unwrap();
        std::fs::create_dir_all(xdg_tmp.path().join("steer")).unwrap();
        let xdg_yaml = xdg_tmp.path().join("steer/steer.yaml");
        std::fs::write(&xdg_yaml, "proxy: {}").unwrap();
        let _g = EnvGuard::new(&[("XDG_CONFIG_HOME", Some(xdg_tmp.path().to_str().unwrap()))]);

        let resolved = resolve_config_path(None).unwrap();
        // macOS TempDir paths under /var are symlinks to /private/var, so
        // resolved (built from env) and xdg_yaml (built from tempdir.path())
        // can render differently. Canonicalise both before comparing.
        assert_eq!(
            std::fs::canonicalize(&resolved).unwrap(),
            std::fs::canonicalize(&xdg_yaml).unwrap()
        );

        std::env::set_current_dir(cwd_save).unwrap();
    }

    #[test]
    fn home_dotconfig_used_when_xdg_unset() {
        let _lock = GLOBAL_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        // No XDG_CONFIG_HOME → fall back to $HOME/.config.
        let cwd_tmp = TempDir::new().unwrap();
        let cwd_save = std::env::current_dir().unwrap();
        std::env::set_current_dir(cwd_tmp.path()).unwrap();

        let home_tmp = TempDir::new().unwrap();
        let steer_dir = home_tmp.path().join(".config/steer");
        std::fs::create_dir_all(&steer_dir).unwrap();
        let yaml = steer_dir.join("steer.yaml");
        std::fs::write(&yaml, "proxy: {}").unwrap();
        let _g = EnvGuard::new(&[
            ("XDG_CONFIG_HOME", None),
            ("HOME", Some(home_tmp.path().to_str().unwrap())),
        ]);

        let resolved = resolve_config_path(None).unwrap();
        assert_eq!(
            std::fs::canonicalize(&resolved).unwrap(),
            std::fs::canonicalize(&yaml).unwrap()
        );

        std::env::set_current_dir(cwd_save).unwrap();
    }

    #[test]
    fn error_lists_searched_paths_when_nothing_found() {
        let _lock = GLOBAL_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let cwd_tmp = TempDir::new().unwrap();
        let cwd_save = std::env::current_dir().unwrap();
        std::env::set_current_dir(cwd_tmp.path()).unwrap();

        let xdg_tmp = TempDir::new().unwrap();
        // Note: we deliberately do NOT create the steer/ subdir or the file.
        let _g = EnvGuard::new(&[("XDG_CONFIG_HOME", Some(xdg_tmp.path().to_str().unwrap()))]);

        let err = resolve_config_path(None).unwrap_err().to_string();
        assert!(err.contains("./steer.yaml"), "error must cite CWD path");
        assert!(err.contains("steer.yaml"), "error must mention steer.yaml");
        assert!(
            err.contains("install.sh"),
            "error must hint at the install-sh workflow"
        );

        std::env::set_current_dir(cwd_save).unwrap();
    }

    #[test]
    fn empty_xdg_config_home_falls_through_to_home() {
        let _lock = GLOBAL_TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        // `XDG_CONFIG_HOME=""` (set-but-empty) is a real footgun — POSIX env
        // returns an empty string, which we must treat as unset per the XDG
        // spec to avoid resolving `/steer/steer.yaml` at the filesystem root.
        let _g = EnvGuard::new(&[
            ("XDG_CONFIG_HOME", Some("")),
            ("HOME", Some("/tmp/test-home-xdg-empty")),
        ]);
        let resolved = xdg_config_home().unwrap();
        assert_eq!(resolved, PathBuf::from("/tmp/test-home-xdg-empty/.config"));
    }
}
