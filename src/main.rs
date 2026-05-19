use anyhow::Context;
use arc_swap::ArcSwap;
use axum::routing::{get, post};
use axum::{Extension, Router};
use clap::Parser;
use std::collections::HashMap;
use std::net::SocketAddr;
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
#[command(name = "steer", about = "EnforceGrid - Runtime AI enforcement engine")]
struct Cli {
    #[arg(short, long, default_value = "steer.yaml", env = "STEER_CONFIG")]
    config: String,

    #[arg(long, env = "STEER_HOST")]
    host: Option<String>,

    #[arg(long, env = "STEER_PORT")]
    port: Option<u16>,

    #[arg(long, default_value = "false")]
    json_logs: bool,
}

/// Noop policy registry backend — all tenants get the global policy directory.
/// No managed-version DB, no per-tenant overrides.
struct SingleTenantPolicyBackend;

impl PolicyRegistryBackend for SingleTenantPolicyBackend {
    fn get_tenant_config(&self, tenant_id: &str) -> anyhow::Result<TenantPolicyConfig> {
        Ok(TenantPolicyConfig::default_for(tenant_id))
    }
    fn get_managed_version(&self, _version: &str) -> anyhow::Result<Option<ManagedPolicyVersion>> {
        Ok(None)
    }
    fn tenants_with_auto_upgrade(&self) -> anyhow::Result<Vec<String>> {
        Ok(vec![])
    }
    fn upgrade_tenant_version(&self, _tenant_id: &str, _version: &str) -> anyhow::Result<()> {
        Ok(())
    }
    fn managed_policy_count_for_version(&self, _version: &str) -> usize {
        0
    }
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

    let cfg_path = &cli.config;
    let mut config: SteerConfig = steer_core::config::load(cfg_path)
        .with_context(|| format!("Failed to load config from {cfg_path}"))?;

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

    let policy_registry = Arc::new(TenantPolicyRegistry::new(
        Arc::new(SingleTenantPolicyBackend),
        &config.policy.policy_dir,
    ));

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

    let state = Arc::new(PipelineState {
        config: Arc::clone(&config),
        pii_engine,
        policy_engine: Arc::clone(&policy_swap),
        policy_registry: Arc::clone(&policy_registry),
        audit_sink: Arc::new(steer_core::audit::StdoutAuditSink),
        perf: Arc::new(NoopPerformance) as Arc<dyn PerformanceProvider>,
        http_client,
        token_provider: Arc::new(NoopTokenProvider) as Arc<dyn TokenProvider>,
        budget_cache: Arc::clone(&budget_cache),
        cost_estimator: Arc::clone(&cost_estimator),
        detectors: Arc::new(build_detectors()),
        tenant_auth: Arc::new(SingleTenantAuth) as Arc<dyn TenantAuthProvider>,
        tenant_id_cache: dashmap::DashMap::new(),
        sync_cache: Arc::new(dashmap::DashMap::new()),
        tenant_settings: Arc::new(SingleTenantSettings {
            settings: TenantSettings::default(),
        }) as Arc<dyn TenantSettingsProvider>,
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
