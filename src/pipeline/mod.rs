use std::sync::Arc;
use std::time::Instant;

use arc_swap::ArcSwap;

use async_stream::stream;
use axum::body::Body;
use axum::http::{HeaderMap, Method, StatusCode, Uri};
use axum::response::IntoResponse;
use axum::response::Response;
use chrono::{Timelike, Utc};
use chrono_tz::Tz;
use futures::StreamExt;
use serde_json::{json, Value};
use tokio::sync::oneshot;
use tracing::warn;

use sha2::{Digest, Sha256};

use crate::audit::AuditSink;
use crate::auth::resolve_auth_for_provider;
use crate::config::SteerConfig;
use crate::detectors::tool_governance::ToolGovernanceDetector;
use crate::detectors::{ContentDetector, DetectionResult};
use crate::error::SteerError;
use crate::handover::{HoldStatus, HoldStore};
use crate::headers::{forward_headers, response_headers, EgHeaders};
use crate::performance::{
    models::{PerformanceSample, PhaseTiming},
    AnomalyProvider, PerformanceProvider,
};
use crate::pii::{PiiFinding, RegexPiiEngine};
use crate::policy::cedar::CedarEngine;
use crate::policy::registry::TenantPolicyRegistry;
use crate::policy::sync_promoter::SyncRequirements;
use crate::policy::{
    build_context, ContextParams, EnforcementAction, PolicyAction, PolicyDecision, PolicyEngine,
    PolicyInput,
};
use crate::routing::{build_upstream_url, resolve_route, rewrite_model_in_body};
use crate::streaming::buffer::WordBoundaryBuffer;
use crate::tenants::{TenantAuthProvider, TenantSettingsProvider};
use crate::tokens::{
    parse_usage, BudgetCache, CostEstimator, NewTokenUsage, RateLimitCheckResult, TokenProvider,
    TokenUsage,
};

/// Accumulated stats from the SSE enforced stream, sent back via oneshot for audit.
struct StreamStats {
    bytes_received: usize,
    bytes_emitted: usize,
    frames_received: usize,
    frames_emitted: usize,
    findings: Vec<PiiFinding>,
    first_byte_ms: Option<f64>,
    stream_duration_ms: f64,
    flush_on_boundary: usize,
    flush_on_size_cap: usize,
    flush_on_stream_end: usize,
    stream_verdict: String,
    /// Tool names the LLM invoked in this streaming response (from delta.tool_calls).
    /// Always recorded regardless of whether a policy fired on them.
    invoked_tools: Vec<String>,
    /// Total wall-clock time spent in the enforcement path (PII scan + policy eval),
    /// summed across all buffer flushes. Does not include upstream wait time.
    cadabra_ms: f64,
}

/// Cached sync requirements for a tenant's policy set.
/// Computed from `SyncRequirements::analyze()` and cached per tenant_id.
/// Evicted on policy reload so the next request picks up new requirements.
#[derive(Clone)]
pub struct SyncRequirementsCache {
    pub sync_detectors: std::collections::HashSet<String>,
    pub pii_sync: bool,
    pub has_response_enforcement: bool,
    pub all_async: bool,
}

impl SyncRequirementsCache {
    fn from_requirements(req: &SyncRequirements) -> Self {
        Self {
            sync_detectors: req.sync_detectors.clone(),
            pii_sync: req.pii_sync,
            has_response_enforcement: req.has_response_enforcement,
            all_async: req.all_async(),
        }
    }
}

pub struct PipelineState {
    pub config: Arc<SteerConfig>,
    pub pii_engine: Arc<RegexPiiEngine>,
    /// Global ArcSwap engine — used by admin routes (reload/validate/conflicts).
    /// Hot-path requests use `policy_registry.engine_for(tenant_id)` instead.
    pub policy_engine: Arc<ArcSwap<CedarEngine>>,
    /// Per-tenant Cedar engine registry. Lazily loads and caches one engine per
    /// tenant, each pinned to the tenant's configured managed policy version.
    pub policy_registry: Arc<TenantPolicyRegistry>,
    pub audit_sink: Arc<dyn AuditSink>,
    pub perf: Arc<dyn PerformanceProvider>,
    pub http_client: reqwest::Client,
    pub token_provider: Arc<dyn TokenProvider>,
    pub budget_cache: Arc<BudgetCache>,
    pub cost_estimator: Arc<CostEstimator>,
    pub detectors: Arc<Vec<Box<dyn ContentDetector>>>,
    /// Used in the hot path to resolve API key → tenant_id for per-tenant policy lookup.
    pub tenant_auth: Arc<dyn TenantAuthProvider>,
    /// Cache of raw_api_key → (tenant_id, bound_agent_id). API key ↔ tenant mapping
    /// is permanent (a key always belongs to the same tenant until revoked, and revoked
    /// keys fail the ApiKeyLayer check before reaching the pipeline). Safe to cache
    /// indefinitely.
    pub tenant_id_cache: dashmap::DashMap<String, (String, Option<String>)>,
    /// Cached sync requirements per tenant — determines which detectors run
    /// in the hot path vs. async enrichment. Evicted on policy reload.
    pub sync_cache: Arc<dashmap::DashMap<String, SyncRequirementsCache>>,
    /// Tenant settings — used to read per-tenant consent flags.
    pub tenant_settings: Arc<dyn TenantSettingsProvider>,
    /// Anomaly detection state — refreshed every 30s, checked per-request (AIUC-1 D005).
    pub anomaly: Arc<dyn AnomalyProvider>,
    /// Emergency kill switch — when true, ALL requests get 503 before any processing (AIUC-1 C008).
    pub kill_switch: Arc<std::sync::atomic::AtomicBool>,
    /// Dynamic MCP server registry — admin API-driven allowlist (OWASP ASI04).
    pub mcp_registry: Arc<dyn crate::mcp_registry::McpRegistryProvider>,
    /// Pre-built tool governance detector — avoids rebuilding the HashSet on every request.
    pub tool_governance: ToolGovernanceDetector,
    /// Human-in-the-loop hold store — parked requests awaiting reviewer approval.
    pub hold_store: Arc<HoldStore>,
}

impl PipelineState {
    /// Convenience: load the global engine snapshot (admin/backward-compat use only).
    #[inline]
    pub fn engine(&self) -> Arc<CedarEngine> {
        self.policy_engine.load_full()
    }

    /// Evict a tenant's cached sync requirements (call on policy reload).
    pub fn evict_sync_cache(&self, tenant_id: &str) {
        self.sync_cache.remove(tenant_id);
    }

    /// Resolve the tenant_id and optional bound_agent_id from a raw API key value.
    /// Returns ("default", None) when no tenant is found (single-tenant / env-var key mode).
    /// Results are cached permanently — API key → tenant mapping never changes.
    pub fn resolve_tenant(&self, raw_api_key: Option<&str>) -> (String, Option<String>) {
        let key = match raw_api_key {
            None => return ("default".to_string(), None),
            Some(k) => k,
        };
        // Fast path: cache hit
        if let Some(entry) = self.tenant_id_cache.get(key) {
            return entry.value().clone();
        }
        // Slow path: auth provider lookup
        let (tenant_id, bound_agent_id) = self
            .tenant_auth
            .resolve_key(key)
            .ok()
            .map(|rk| (rk.tenant_id, rk.agent_id))
            .unwrap_or_else(|| ("default".to_string(), None));
        self.tenant_id_cache
            .insert(key.to_string(), (tenant_id.clone(), bound_agent_id.clone()));
        (tenant_id, bound_agent_id)
    }
}

/// Execute the full enforcement pipeline.
///
/// `override_tenant` — when `Some(non-empty string)`, use it as the tenant_id instead of
/// resolving from the API key.  This lets the middleware-resolved `TenantContext` (which
/// handles `X-Steer-Tenant-Id` for service-key callers) propagate into the audit trail.
/// `bound_agent_id` is still resolved from the API key regardless of this override.
pub async fn run(
    state: &PipelineState,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body_bytes: bytes::Bytes,
    override_tenant: Option<String>,
) -> Response {
    // ── Kill switch (AIUC-1 C008) ─────────────────────────────────────────────
    // Pre-policy, pre-processing emergency stop. Zero overhead when inactive.
    if state.kill_switch.load(std::sync::atomic::Ordering::Relaxed) {
        return Response::builder()
            .status(503)
            .header("content-type", "application/json")
            .body(axum::body::Body::from(
                r#"{"error":"emergency_shutdown","message":"AI proxy traffic halted by administrator"}"#,
            ))
            .unwrap_or_else(|_| {
                Response::builder().status(503).body(axum::body::Body::empty()).unwrap()
            });
    }

    let start = Instant::now();
    let audit_id = crate::audit::generate_audit_id();
    let mut timing = PhaseTiming::default();

    // ── Phase 1: Auth + agent extraction ─────────────────────────────────────
    let t = Instant::now();
    let eg = EgHeaders::extract(&headers);
    let mut fwd_headers = forward_headers(&headers);
    // Auth header injection happens after Phase 2 routing so the correct
    // provider is known (Anthropic needs x-api-key; others need Authorization).

    // Resolve tenant_id and bound agent identity from the calling API key.
    // Falls back to ("default", None) for single-tenant / env-var key deployments.
    // When override_tenant is provided (e.g. from X-Steer-Tenant-Id via middleware), use it
    // as the tenant_id so service-key callers are stamped with the correct tenant in audit.
    let (resolved_tenant, bound_agent_id) = state.resolve_tenant(eg.api_key.as_deref());
    let tenant_id = override_tenant
        .filter(|t| !t.is_empty() && t != "default")
        .unwrap_or(resolved_tenant);

    // ── MCP supply chain check (OWASP ASI04) ──────────────────────────────
    let mcp_server_id_raw = eg.mcp_server_id.clone().unwrap_or_default();
    // Sanitize: malformed header values (control chars, >255 chars) treated as absent.
    let mcp_server_id_str = if !mcp_server_id_raw.is_empty()
        && mcp_server_id_raw.len() <= 255
        && mcp_server_id_raw
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_' || c == '.')
    {
        mcp_server_id_raw
    } else {
        String::new()
    };
    let mcp_server_approved = if !state.config.mcp_allowlist.enabled {
        // Feature disabled → permissive default, no registry lookup
        true
    } else if mcp_server_id_str.is_empty() {
        // No MCP server header (or malformed) → not an MCP request, treat as approved
        true
    } else {
        // Check the dynamic admin-managed registry
        state.mcp_registry.is_approved(&mcp_server_id_str)
    };

    // Resolve tenant settings (consent + data residency).
    let tenant_settings = state.tenant_settings.get_settings(&tenant_id);
    let consent_given = tenant_settings.data_processing_consent;

    timing.auth_ms = Some(t.elapsed().as_secs_f64() * 1000.0);
    timing.agent_extract_ms = Some(0.0);

    // ── Resolve principal identity ────────────────────────────────────────
    // Bound agent identity from the API key takes precedence over the header.
    // If the key has a bound_agent_id, it acts as a prefix constraint:
    //   - eg-agent-id starts with bound prefix → use header (preserves stage attribution)
    //   - eg-agent-id doesn't match → use bound_agent_id as-is
    // Reserved prefixes (abra:, steer:) are stripped from non-bound keys to prevent spoofing.
    let is_system_key = bound_agent_id.is_some()
        && bound_agent_id
            .as_deref()
            .is_some_and(|b| b.starts_with("abra:") || b.starts_with("steer:"));
    let agent_id_str = match &bound_agent_id {
        Some(bound) => {
            // Extract prefix (everything up to and including first ':')
            let prefix = bound.find(':').map(|i| &bound[..=i]);
            match (prefix, eg.agent_id.as_deref()) {
                // Header starts with bound prefix → use header (e.g., "abra:pipeline.parse")
                (Some(pfx), Some(header_id)) if header_id.starts_with(pfx) => header_id.to_string(),
                // Header doesn't match prefix → use bound identity
                _ => bound.clone(),
            }
        }
        None => {
            // No binding — use header, but strip reserved prefixes
            match eg.agent_id.as_deref() {
                Some(id) if id.starts_with("abra:") || id.starts_with("steer:") => String::new(),
                Some(id) => id.to_string(),
                None => String::new(),
            }
        }
    };

    // Governance context from config
    let risk_level = state.config.risk_level.as_str();

    // ── Phase 2: Model routing ───────────────────────────────────────────────
    let t = Instant::now();
    let body_str = std::str::from_utf8(&body_bytes).unwrap_or("{}");
    let body_json: Value = serde_json::from_str(body_str).unwrap_or(Value::Null);
    let model = body_json
        .get("model")
        .and_then(|m| m.as_str())
        .map(|s| s.to_string());
    let is_streaming = body_json
        .get("stream")
        .and_then(|s| s.as_bool())
        .unwrap_or(false);
    let route = resolve_route(model.as_deref(), &state.config);
    let model_approved = model
        .as_deref()
        .is_some_and(|m| state.config.models.contains_key(m));

    // ── Data residency compliance (AIUC-1 E004) ────────────────────────────
    let data_residency_compliant = match &tenant_settings.data_residency_region {
        None => true, // no requirement → compliant
        Some(tenant_region) => match &route.region {
            None => false, // tenant requires region but model has none → can't verify
            Some(model_region) if model_region.eq_ignore_ascii_case("global") => true,
            Some(model_region) => model_region.eq_ignore_ascii_case(tenant_region),
        },
    };

    // ── Org context fields ────────────────────────────────────────────────────
    let org_timezone_str = tenant_settings.timezone.as_deref().unwrap_or("UTC");
    let org_industry_str = tenant_settings.industry.as_deref().unwrap_or("other");
    let org_region_str = tenant_settings
        .data_residency_region
        .as_deref()
        .unwrap_or("");
    let org_business_hours_active = compute_business_hours_active(
        org_timezone_str,
        tenant_settings.business_hours_window.as_deref(),
    );

    // Inject auth headers now that we know the provider (Anthropic → x-api-key,
    // others → Authorization: Bearer).
    // When provider_name is not explicitly set in steer.yaml, infer Anthropic from
    // the upstream base URL or the request path (e.g. /v1/messages).  This mirrors
    // the same heuristic used in the fallback/retry loop below and fixes T-410:
    // Claude Code routes without an explicit `provider:` field were receiving
    // `Authorization: Bearer` instead of `x-api-key`.
    let effective_provider: Option<&str> = route.provider_name.as_deref().or_else(|| {
        if route.base_url.contains("anthropic.com") || uri.path().contains("/v1/messages") {
            Some("anthropic")
        } else {
            None
        }
    });
    if let Err(msg) =
        resolve_auth_for_provider(&mut fwd_headers, &route.api_key, effective_provider)
    {
        if !state.config.proxy.fail_open {
            return SteerError::NoApiKey.into_response();
        }
        warn!(audit_id = %audit_id, msg = %msg, "no api key — fail_open passthrough");
    }
    timing.model_routing_ms = Some(t.elapsed().as_secs_f64() * 1000.0);

    // ── Phase 2b: Rate limit enforcement ────────────────────────────────────
    // Checked before Cedar and PII scan — fast 429 path.
    {
        let now = Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let api_key_hash_rl = eg.api_key.as_deref().map(hash_api_key);

        if let Some(breach) = check_rate_limits(
            &*state.token_provider,
            &tenant_id,
            api_key_hash_rl.as_deref(),
            eg.agent_id.as_deref(),
            model.as_deref(),
            &now,
        ) {
            return breach;
        }
    }

    // ── Phase 2c: Sync requirements lookup (cached per tenant) ────────────
    let tenant_engine = state.policy_registry.engine_for(&tenant_id);
    let sync_reqs = state
        .sync_cache
        .entry(tenant_id.clone())
        .or_insert_with(|| {
            let policy_text = tenant_engine.policy_text();
            let reqs = SyncRequirements::analyze(policy_text);
            tracing::debug!(
                tenant_id = %tenant_id,
                sync_detectors = ?reqs.sync_detectors,
                pii_sync = reqs.pii_sync,
                has_response_enforcement = reqs.has_response_enforcement,
                all_async = reqs.all_async(),
                "computed sync requirements"
            );
            SyncRequirementsCache::from_requirements(&reqs)
        })
        .clone();

    // ── Phase 3: PII scan (request) ──────────────────────────────────────────
    // PII runs sync only if enforcement policies reference pii_detected.
    // Otherwise, observation-mode tenants skip PII in the hot path and get
    // PII findings via async enrichment.
    let t = Instant::now();
    let pii_result = if state.config.pii.enabled && !body_bytes.is_empty() && sync_reqs.pii_sync {
        state.pii_engine.scan_and_redact(body_str, "request")
    } else {
        crate::pii::PiiScanResult {
            redacted_text: body_str.to_string(),
            findings: vec![],
        }
    };
    let enforced_body = if !pii_result.findings.is_empty() {
        pii_result.redacted_text.as_bytes().to_vec()
    } else {
        body_bytes.to_vec()
    };
    timing.pii_request_ms = Some(t.elapsed().as_secs_f64() * 1000.0);

    // Prepare masked request payload for audit retention
    let retained_request_payload: Option<String> = match state.config.audit.retain_payloads.as_str()
    {
        "masked" => Some(truncate_payload(
            &pii_result.redacted_text,
            state.config.audit.max_payload_bytes,
        )),
        "raw" => Some(truncate_payload(
            body_str,
            state.config.audit.max_payload_bytes,
        )),
        _ => None, // "never"
    };

    // ── Phase 3b: Content detectors (request) ───────────────────────────────
    // Only run detectors needed for enforcement decisions (sync detectors).
    // Remaining detectors run post-upstream in the async enrichment task.
    const MIN_DETECTOR_TEXT_LEN: usize = 10;
    let t = Instant::now();
    let request_text = extract_user_text(&body_json);

    let (sync_detector_results, async_detector_indices): (Vec<DetectionResult>, Vec<usize>) =
        if request_text.len() >= MIN_DETECTOR_TEXT_LEN && !state.detectors.is_empty() {
            if sync_reqs.all_async {
                // Pure observation mode: skip ALL detectors in hot path
                (Vec::new(), (0..state.detectors.len()).collect())
            } else {
                let mut sync_results = Vec::new();
                let mut async_indices = Vec::new();
                for (i, d) in state.detectors.iter().enumerate() {
                    if sync_reqs.sync_detectors.contains(d.detector_type()) {
                        sync_results.push(d.scan(&request_text));
                    } else {
                        async_indices.push(i);
                    }
                }
                (sync_results, async_indices)
            }
        } else {
            (Vec::new(), Vec::new())
        };

    let detector_results: &[DetectionResult] = &sync_detector_results;
    let injection_result = detector_results
        .iter()
        .find(|r| r.detector_type == "injection");
    let jailbreak_result = detector_results
        .iter()
        .find(|r| r.detector_type == "jailbreak");
    let threat_result = detector_results
        .iter()
        .find(|r| r.detector_type == "threat");
    let identity_result = detector_results
        .iter()
        .find(|r| r.detector_type == "identity_claim");
    let confidential_result = detector_results
        .iter()
        .find(|r| r.detector_type == "confidential");
    let bias_result = detector_results.iter().find(|r| r.detector_type == "bias");

    let injection_detected = injection_result.is_some_and(|r| r.detected);
    let jailbreak_detected = jailbreak_result.is_some_and(|r| r.detected);
    let threat_detected = threat_result.is_some_and(|r| r.detected);
    let identity_claim_detected = identity_result.is_some_and(|r| r.detected);
    let confidential_detected = confidential_result.is_some_and(|r| r.detected);
    let bias_detected = bias_result.is_some_and(|r| r.detected);

    timing.detectors_request_ms = Some(t.elapsed().as_secs_f64() * 1000.0);

    // ── Budget lookup (for policy context + failover) ────────────────────────
    let api_key_hash = eg.api_key.as_deref().map(hash_api_key);
    let agent_scope_id = eg.agent_id.as_deref().unwrap_or("anonymous");

    // Heuristic pre-request cost estimate: 1000 prompt + 500 completion tokens
    let heuristic_usage = TokenUsage {
        prompt_tokens: 1000,
        completion_tokens: 500,
        total_tokens: 1500,
        model: model.as_deref().unwrap_or("").to_string(),
        provider: "openai".to_string(),
    };
    let _estimated_cost_usd = state
        .cost_estimator
        .estimate(model.as_deref().unwrap_or(""), &heuristic_usage);

    // Check budgets: prefer api_key scope, then tenant, then agent
    let budget_status = api_key_hash
        .as_deref()
        .and_then(|kh| state.budget_cache.check("api_key", kh))
        .or_else(|| {
            if tenant_id != "default" {
                state.budget_cache.check("tenant", &tenant_id)
            } else {
                None
            }
        })
        .or_else(|| state.budget_cache.check("agent", agent_scope_id));

    let budget_remaining_usd = budget_status.as_ref().map_or(0.0, |s| s.remaining_usd);
    let budget_utilization_pct = budget_status.as_ref().map_or(0.0, |s| s.utilization_pct);

    // ── T-902: Extract requested tools from inbound request ────────────────
    let (requested_tools, _requested_tool_count) = extract_requested_tools(&body_json);

    // ── Phase 3d: Tool governance (request) ────────────────────────────────
    // Zero-config allowlist/denylist enforcement on incoming tool requests.
    // Does not block here — signals are injected into Cedar context for policy eval.
    let tool_gov_result = if !requested_tools.is_empty() {
        state.tool_governance.scan_tools(&requested_tools)
    } else {
        crate::detectors::tool_governance::ToolGovernanceResult::default()
    };
    let tool_gov_categories_str = tool_gov_result.categories_csv();

    // ── Phase 3e: Exfiltration scan (request) ─────────────────────────────
    // Catches pre-staged exfiltration instructions embedded in request prompts.
    let req_exfil_result = detector_results
        .iter()
        .find(|r| r.detector_type == "exfiltration");
    let req_exfil_detected = req_exfil_result.is_some_and(|r| r.detected);
    let req_exfil_type_str = req_exfil_result
        .and_then(|r| r.findings.first())
        .map(|f| f.category.clone())
        .unwrap_or_default();

    // ── Phase 3f: Anomaly state (cached, no per-request SQL) ───────────────
    let anomaly_detected = state.anomaly.is_anomalous();
    let anomaly_type_str = state.anomaly.anomaly_type();

    // ── Phase 4: Policy evaluation (request) ────────────────────────────────
    let t = Instant::now();
    let request_action = PolicyAction::from_path(uri.path());
    let principal = if agent_id_str.is_empty() {
        "anonymous"
    } else {
        &agent_id_str
    };
    // Budget: -1 means "no budget configured" so Cedar policies can
    // distinguish "no budget" from "budget at zero".
    let has_budget = budget_status.is_some();
    let pii_finding_names: Vec<String> = pii_result
        .findings
        .iter()
        .map(|f| f.pattern.clone())
        .collect();
    let request_context_params = ContextParams {
        model: model.as_deref().unwrap_or(""),
        streaming: is_streaming,
        pii_detected: !pii_result.findings.is_empty(),
        pii_findings: &pii_finding_names,
        risk_level,
        requested_tools: &requested_tools,
        budget_remaining_cents: if has_budget {
            (budget_remaining_usd * 100.0) as i64
        } else {
            -1
        },
        budget_utilization_pct: if has_budget {
            budget_utilization_pct as i64
        } else {
            -1
        },
        injection_detected,
        jailbreak_detected,
        threat_detected,
        identity_claim_detected,
        confidential_detected,
        bias_detected,
        // Exfiltration (request-side)
        exfiltration_detected: req_exfil_detected,
        exfiltration_type: &req_exfil_type_str,
        // Tool governance
        unauthorized_tool_detected: tool_gov_result.detected,
        tool_categories: &tool_gov_categories_str,
        tool_highest_risk_category: &tool_gov_result.highest_risk_category,
        tool_allowlist_mode: tool_gov_result.allowlist_mode,
        fallback_available: !route.fallback.is_empty(),
        model_approved,
        consent_given,
        anomaly_detected,
        anomaly_type: &anomaly_type_str,
        data_residency_compliant,
        org_timezone: org_timezone_str,
        org_industry: org_industry_str,
        org_region: org_region_str,
        org_business_hours_active,
        mcp_server_approved,
        mcp_server_id: &mcp_server_id_str,
        ..Default::default()
    };
    let policy_context = build_cedar_context_compat(&request_context_params);
    let request_policy_input =
        PolicyInput::new(principal, request_action, "request", policy_context.clone());
    // System keys (abra:*, steer:*) bypass tenant Cedar evaluation entirely.
    // Cedar's forbid-wins-over-permit model means a tenant forbid(principal, action, resource)
    // would block system agents even with an explicit permit — so we skip Cedar for system calls.
    // System calls are still audited with enforcement.rule_id = "system-bypass".
    let request_decision = if is_system_key {
        PolicyDecision {
            action: EnforcementAction::Allow,
            rule_id: Some("system-bypass".to_string()),
            steer_message: None,
            transform_to: None,
            description: Some("System agent — tenant Cedar evaluation bypassed".to_string()),
            regulatory_mapping: vec![],
            matched_rules: vec![],
        }
    } else {
        tenant_engine.evaluate_request(
            principal,
            request_action.as_cedar_action(),
            &body_json,
            &policy_context,
        ).unwrap_or_else(|e| {
            warn!(error = %e, tenant_id = %tenant_id, "policy eval error — defaulting to allow");
            PolicyDecision::allow()
        })
    };
    timing.cedar_request_ms = Some(t.elapsed().as_secs_f64() * 1000.0);

    // ── ARG-173: Decision-based observation mode ────────────────────────────
    // If Cedar decided allow or flag (observation-only), revert to the original
    // request body — skip PII redaction so upstream prompt caching is preserved.
    // Detectors already ran and populated Cedar context; we just don't modify
    // the body when no enforcement action is needed.
    let enforced_body = if request_decision.action.requires_body_modification() {
        enforced_body
    } else {
        body_bytes.to_vec()
    };

    // ── T-005: propagate request_id upstream ─────────────────────────────────
    fwd_headers.insert("x-request-id".to_string(), eg.request_id.clone());

    // Handle block before upstream call
    if request_decision.action == EnforcementAction::Block {
        let overhead_ms = start.elapsed().as_secs_f64() * 1000.0;
        let req_payload_ref = if should_retain_payload(&state.config.audit, "block") {
            retained_request_payload.as_deref()
        } else {
            None
        };
        let entry = build_audit_entry(AuditParams {
            audit_id: &audit_id,
            request_id: &eg.request_id,
            method: &method,
            path: uri.path(),
            model: model.as_deref(),
            streaming: is_streaming,
            status: 0,
            overhead_ms,
            upstream_ms: 0.0,
            pii_findings: &pii_result.findings,
            action: "block",
            rule_id: request_decision.rule_id.as_deref(),
            description: request_decision.description.as_deref(),
            regulatory_mapping: &request_decision.regulatory_mapping,
            matched_rules: &request_decision.matched_rules,
            retries_made: 0,
            fallback_triggered: false,
            labels: &build_labels(
                detector_results,
                &pii_result.findings,
                "block",
                request_decision.rule_id.as_deref(),
            ),
            request_payload: req_payload_ref,
            response_payload: None, // no upstream call was made
            tenant_id: &tenant_id,
            agent_id: Some(principal),
            context_snapshot: Some(&policy_context),
            hold_id: None,
        });
        state.audit_sink.write(entry);
        record_perf(
            state,
            &eg,
            model.as_deref(),
            route.provider_name.as_deref(),
            is_streaming,
            0.0,
            &timing,
        );
        let mut resp = SteerError::PolicyBlock {
            rule: request_decision
                .rule_id
                .unwrap_or_else(|| "policy_block".to_string()),
        }
        .into_response();
        resp.headers_mut()
            .insert("eg-audit-id", audit_id.parse().unwrap());
        if let Ok(hv) = request_policy_input.to_header_value(4096).parse() {
            resp.headers_mut().insert("eg-policy-input", hv);
        }
        return resp;
    }

    // ── Human-in-the-loop hold (action = steer) ──────────────────────────────
    // When Cedar fires action=steer and handover is enabled, park the request in
    // the HoldStore and long-poll until a reviewer approves, rejects, or the
    // configured timeout elapses.
    if request_decision.action == EnforcementAction::Steer && state.config.handover.enabled {
        let request_hash = hex::encode(Sha256::digest(&body_bytes));
        let reason = request_decision
            .steer_message
            .as_deref()
            .or(request_decision.rule_id.as_deref())
            .unwrap_or("policy_hold");
        match state.hold_store.create(
            reason,
            Some(principal.to_string()),
            &request_hash,
            request_decision.rule_id.clone(),
            Some(tenant_id.clone()),
        ) {
            Ok(hold) => {
                let overhead_ms = start.elapsed().as_secs_f64() * 1000.0;
                let req_payload_ref = if should_retain_payload(&state.config.audit, "steer") {
                    retained_request_payload.as_deref()
                } else {
                    None
                };
                let entry = build_audit_entry(AuditParams {
                    audit_id: &audit_id,
                    request_id: &eg.request_id,
                    method: &method,
                    path: uri.path(),
                    model: model.as_deref(),
                    streaming: is_streaming,
                    status: 0,
                    overhead_ms,
                    upstream_ms: 0.0,
                    pii_findings: &pii_result.findings,
                    action: "steer",
                    rule_id: request_decision.rule_id.as_deref(),
                    description: request_decision.description.as_deref(),
                    regulatory_mapping: &request_decision.regulatory_mapping,
                    matched_rules: &request_decision.matched_rules,
                    retries_made: 0,
                    fallback_triggered: false,
                    labels: &build_labels(
                        detector_results,
                        &pii_result.findings,
                        "steer",
                        request_decision.rule_id.as_deref(),
                    ),
                    request_payload: req_payload_ref,
                    response_payload: None,
                    tenant_id: &tenant_id,
                    agent_id: Some(principal),
                    context_snapshot: Some(&policy_context),
                    hold_id: Some(&hold.hold_id),
                });
                state.audit_sink.write(entry);

                let poll_interval = tokio::time::Duration::from_millis(500);
                let deadline = tokio::time::Instant::now()
                    + tokio::time::Duration::from_secs(state.config.handover.timeout_secs);
                loop {
                    tokio::time::sleep(poll_interval).await;
                    match state.hold_store.get(&hold.hold_id) {
                        Some(h) if h.status == HoldStatus::Approved => break,
                        Some(h) if h.status == HoldStatus::Rejected => {
                            let mut resp = SteerError::PolicyBlock {
                                rule: hold
                                    .policy_id
                                    .clone()
                                    .unwrap_or_else(|| "hold_rejected".to_string()),
                            }
                            .into_response();
                            resp.headers_mut()
                                .insert("eg-audit-id", audit_id.parse().unwrap());
                            if let Ok(hv) = hold.hold_id.parse() {
                                resp.headers_mut().insert("eg-hold-id", hv);
                            }
                            return resp;
                        }
                        _ => {}
                    }
                    if tokio::time::Instant::now() >= deadline {
                        state
                            .hold_store
                            .update_status(&hold.hold_id, HoldStatus::Expired);
                        return Response::builder()
                            .status(503)
                            .header("content-type", "application/json")
                            .header("eg-audit-id", audit_id.as_str())
                            .header("eg-hold-id", hold.hold_id.as_str())
                            .body(axum::body::Body::from(format!(
                                r#"{{"error":"hold_timeout","hold_id":"{}","message":"No reviewer decision within {}s"}}"#,
                                hold.hold_id, state.config.handover.timeout_secs
                            )))
                            .unwrap_or_else(|_| {
                                Response::builder()
                                    .status(503)
                                    .body(axum::body::Body::empty())
                                    .unwrap()
                            });
                    }
                }
                // Approved — fall through to Phase 5.
            }
            Err(_) => {
                return Response::builder()
                    .status(503)
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(
                        r#"{"error":"holds_capacity","message":"Max concurrent holds exceeded"}"#,
                    ))
                    .unwrap_or_else(|_| {
                        Response::builder()
                            .status(503)
                            .body(axum::body::Body::empty())
                            .unwrap()
                    });
            }
        }
    }

    // ── Phase 5: Upstream call with retry + fallback chain ───────────────────
    let timeout = std::time::Duration::from_millis(state.config.proxy.timeout_ms);
    let max_retries = state.config.proxy.retry_attempts;
    let upstream_start = Instant::now();

    // Build the list of (base_url, api_key, model_override) attempts:
    // first the primary, then each fallback entry.
    let primary_model = route.actual_model.clone();
    // Each target: (base_url, api_key, model_override, provider_name)
    let mut attempt_targets: Vec<(String, String, Option<String>, Option<String>)> = vec![(
        route.base_url.clone(),
        route.api_key.clone(),
        primary_model.clone(),
        route.provider_name.clone(),
    )];
    for fb in &route.fallback {
        // T-302: skip conditional fallbacks whose condition is not met
        if let Some(ref condition) = fb.condition {
            if condition == "budget_exceeded" {
                // Only include this fallback if the budget is actually exceeded
                let budget_exceeded = budget_status
                    .as_ref()
                    .map(|s| s.remaining_usd <= 0.0)
                    .unwrap_or(false);
                if !budget_exceeded {
                    continue; // skip this fallback — budget not exceeded
                }
            }
        }
        if let Some(provider) = state.config.providers.get(&fb.provider) {
            let api_key = if provider.api_key.is_empty() {
                state.config.upstream.api_key.clone()
            } else {
                provider.api_key.clone()
            };
            attempt_targets.push((
                provider.base_url.clone(),
                api_key,
                Some(fb.model.clone()),
                Some(fb.provider.clone()),
            ));
        }
    }

    let mut last_response: Option<reqwest::Response> = None;
    let mut retries_made: u32 = 0;
    let mut fallback_triggered = false;
    let mut used_model = primary_model.clone();

    'outer: for (target_idx, (base_url, api_key, model_override, provider)) in
        attempt_targets.iter().enumerate()
    {
        // Rewrite model in body if the fallback uses a different model
        let current_body: Vec<u8> = if let Some(ref m) = model_override {
            if model_override != &primary_model {
                rewrite_model_in_body(&enforced_body, m)
            } else {
                enforced_body.clone()
            }
        } else {
            enforced_body.clone()
        };

        let upstream_url = build_upstream_url(base_url, uri.path(), uri.query());
        let mut req_headers_for_upstream = fwd_headers.clone();
        // Detect provider: explicit from route, or infer from base_url / request path
        let effective_provider = provider.as_deref().or_else(|| {
            if base_url.contains("anthropic.com") || uri.path().contains("/v1/messages") {
                Some("anthropic")
            } else {
                None
            }
        });
        if !api_key.is_empty() {
            let has_auth = req_headers_for_upstream.contains_key("authorization")
                || req_headers_for_upstream.contains_key("x-api-key");
            if !has_auth {
                let is_anthropic =
                    effective_provider.is_some_and(|p| p.eq_ignore_ascii_case("anthropic"));
                if is_anthropic {
                    req_headers_for_upstream.insert("x-api-key".to_string(), api_key.clone());
                } else {
                    req_headers_for_upstream
                        .insert("authorization".to_string(), format!("Bearer {}", api_key));
                }
            }
        }

        for attempt in 0..=max_retries {
            let result = state
                .http_client
                .request(method.clone(), &upstream_url)
                .timeout(timeout)
                .headers(map_to_header_map(&req_headers_for_upstream))
                .body(current_body.clone())
                .send()
                .await;

            match result {
                Ok(resp) if resp.status().is_server_error() => {
                    warn!(
                        audit_id = %audit_id,
                        request_id = %eg.request_id,
                        status = %resp.status(),
                        attempt = attempt,
                        target_idx = target_idx,
                        "upstream 5xx — will retry or fallback"
                    );
                    last_response = Some(resp);
                    retries_made += 1;
                    if attempt < max_retries {
                        let backoff_ms = 50u64 * (1u64 << attempt.min(3));
                        tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
                        continue; // retry same target
                    }
                    // exhausted retries on this target — try next fallback
                    if target_idx > 0 {
                        fallback_triggered = true;
                    }
                    continue 'outer;
                }
                Ok(resp) => {
                    // Success (2xx/3xx/4xx are terminal — don't retry client errors)
                    if target_idx > 0 {
                        fallback_triggered = true;
                    }
                    used_model = model_override.clone();
                    timing.upstream_ms = upstream_start.elapsed().as_secs_f64() * 1000.0;
                    last_response = Some(resp);
                    break 'outer;
                }
                Err(e) if e.is_timeout() => {
                    return SteerError::UpstreamTimeout {
                        ms: state.config.proxy.timeout_ms,
                    }
                    .into_response();
                }
                Err(e) => {
                    last_response = None;
                    warn!(audit_id = %audit_id, request_id = %eg.request_id, error = %e, "upstream error");
                    if attempt < max_retries {
                        let backoff_ms = 50u64 * (1u64 << attempt.min(3));
                        tokio::time::sleep(std::time::Duration::from_millis(backoff_ms)).await;
                        continue;
                    }
                    continue 'outer;
                }
            }
        }
    }

    timing.upstream_ms = upstream_start.elapsed().as_secs_f64() * 1000.0;

    let upstream_resp = match last_response {
        Some(r) => r,
        None => {
            return StatusCode::BAD_GATEWAY.into_response();
        }
    };

    let status = upstream_resp.status();
    let resp_hdr_map = upstream_resp.headers().clone();
    let resp_headers_map = response_headers(&resp_hdr_map);
    let content_type = resp_headers_map
        .get("content-type")
        .cloned()
        .unwrap_or_default();
    let is_sse = content_type.contains("text/event-stream")
        || content_type.contains("application/vnd.amazon.eventstream");

    let axum_status =
        StatusCode::from_u16(status.as_u16()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

    // ── Async enrichment (fire-and-forget) ──────────────────────────────────
    // Run remaining (non-sync) detectors and PII scan_only in a background
    // task. Results are logged / written to the enrichment audit entry.
    // This decouples observation-mode latency from the hot path.
    if !async_detector_indices.is_empty() || (state.config.pii.enabled && !sync_reqs.pii_sync) {
        let async_detectors_arc = Arc::clone(&state.detectors);
        let async_indices = async_detector_indices;
        let text_clone = request_text.clone();
        let pii_engine = Arc::clone(&state.pii_engine);
        let audit_writer_enrich: Arc<dyn AuditSink> = Arc::clone(&state.audit_sink);
        let audit_id_enrich = audit_id.clone();
        let pii_enabled = state.config.pii.enabled;
        let pii_sync = sync_reqs.pii_sync;

        tokio::spawn(async move {
            let enrich_start = Instant::now();

            // Run async detectors
            let async_results: Vec<DetectionResult> = async_indices
                .iter()
                .map(|&i| async_detectors_arc[i].scan(&text_clone))
                .collect();

            // PII scan_only if not run in sync path
            let pii_findings = if pii_enabled && !pii_sync && text_clone.len() >= 5 {
                pii_engine.scan_only(&text_clone, "request_async")
            } else {
                Vec::new()
            };

            let latency = enrich_start.elapsed().as_secs_f64() * 1000.0;

            let async_detected: Vec<&str> = async_results
                .iter()
                .filter(|r| r.detected)
                .map(|r| r.detector_type.as_str())
                .collect();

            tracing::debug!(
                audit_id = %audit_id_enrich,
                async_detectors = async_results.len(),
                async_detected = ?async_detected,
                pii_findings = pii_findings.len(),
                enrichment_latency_ms = latency,
                "async enrichment complete"
            );

            // Build detector snapshot from async results
            let detector_snapshot = serde_json::json!(async_results
                .iter()
                .map(|r| {
                    (
                        r.detector_type.clone(),
                        serde_json::json!({
                            "detected": r.detected,
                            "confidence": r.confidence,
                            "findings_count": r.findings.len(),
                        }),
                    )
                })
                .collect::<serde_json::Map<String, serde_json::Value>>());

            // Build evidence labels from detected signals
            let evidence_labels: Vec<String> = async_results
                .iter()
                .filter(|r| r.detected)
                .map(|r| r.detector_type.clone())
                .chain(if !pii_findings.is_empty() {
                    vec!["pii".to_string()]
                } else {
                    vec![]
                })
                .collect();

            // Only write enrichment entry if there's something to report
            if !evidence_labels.is_empty() || !pii_findings.is_empty() {
                let entry = crate::audit::build_enrichment_entry(
                    &audit_id_enrich,
                    None, // request payload already in parent entry
                    None, // response payload already in parent entry
                    Some(&detector_snapshot),
                    None, // control facts not re-evaluated async
                    &evidence_labels,
                    latency,
                );
                audit_writer_enrich.write(entry); // audit_writer_enrich is Arc<dyn AuditSink>
            }
        });
    }

    // ── Phase 6: SSE enforcement pipeline (or raw passthrough when disabled) ──
    if is_sse {
        let total_overhead = start.elapsed().as_secs_f64() * 1000.0 - timing.upstream_ms;

        // Clone what we need to move into the enforced stream and the audit task
        let pii_engine_sse = Arc::clone(&state.pii_engine);
        // T-006: snapshot the tenant-specific policy engine for this stream's lifetime.
        // Captured at request time — mid-stream version upgrades don't affect in-flight SSE.
        let policy_engine_sse: Arc<CedarEngine> = Arc::clone(&tenant_engine);
        let audit_writer_sse: Arc<dyn AuditSink> = Arc::clone(&state.audit_sink);
        let buffer_size = state.config.streaming.buffer_size_bytes;
        let streaming_enabled = state.config.streaming.enabled;
        let provider = crate::streaming::parsers::detect_provider(
            route.provider_name.as_deref(),
            uri.path(),
            None,
        );
        let provider_sse_post = provider.to_string();
        // T-006: snapshot principal for mid-stream policy evaluation
        let principal_sse = eg.agent_id.clone();
        let risk_level_sse = risk_level.to_string();
        let has_budget_sse = has_budget;
        let budget_remaining_sse = budget_remaining_usd;
        let budget_utilization_sse = budget_utilization_pct;
        let fallback_available_sse = !route.fallback.is_empty();

        // Snapshot scalar values for use in the spawned audit task
        let audit_id_sse = audit_id.clone();
        let request_id_sse = eg.request_id.clone();
        let method_str = method.to_string();
        let path_str = uri.path().to_string();
        let model_sse = used_model.clone().or_else(|| model.clone());
        // Separate clone for the audit task (the stream closure may consume model_sse)
        let model_sse_audit = model_sse.clone();
        let status_code = status.as_u16();
        let upstream_ms_sse = timing.upstream_ms;
        let req_findings = pii_result.findings.clone();
        let action_str = request_decision.action.to_string();
        let rule_id_str = request_decision.rule_id.clone();
        let matched_rules_sse = request_decision.matched_rules.clone();
        let retries_sse = retries_made;
        let fallback_sse = fallback_triggered;
        let agent_id_audit = agent_id_str.to_string();
        let policy_context_sse = policy_context.clone();
        let org_timezone_sse = org_timezone_str.to_string();
        let org_industry_sse = org_industry_str.to_string();
        let org_region_sse = org_region_str.to_string();
        let org_business_hours_active_sse = org_business_hours_active;
        let mcp_server_approved_sse = mcp_server_approved;
        let mcp_server_id_sse = mcp_server_id_str.clone();
        // Tool governance signals for streaming tool-call Cedar evaluations.
        // These mirror the pre-request context — if tools were unauthorized before
        // the stream, they remain unauthorized when the model calls them mid-stream.
        let unauthorized_tool_detected_sse = tool_gov_result.detected;
        let tool_allowlist_mode_sse = tool_gov_result.allowlist_mode;
        // Observe mode: Allow and Flag do not modify the response body.
        // In observe mode the SSE frames must pass through byte-faithful so
        // clients on the 7-day trial see zero wire-format mutation.
        let observe_mode = !request_decision.action.requires_body_modification();

        // Channel to receive stream stats after the stream completes
        let (tx, rx) = oneshot::channel::<StreamStats>();

        let enforced_stream = stream! {
            let mut buffer = WordBoundaryBuffer::new(buffer_size);
            let mut raw_stream = upstream_resp.bytes_stream();
            let stream_start = Instant::now();
            let mut first_byte_ms: Option<f64> = None;
            let mut bytes_received: usize = 0;
            let mut bytes_emitted: usize = 0;
            let mut frames_received: usize = 0;
            let mut frames_emitted: usize = 0;
            let mut findings: Vec<PiiFinding> = vec![];
            let mut stream_verdict = "allow".to_string();
            // Enforcement overhead: sum of PII scan + any policy eval time per flush.
            // Does not include upstream I/O time.
            let mut cadabra_ms: f64 = 0.0;
            let parser = crate::streaming::parsers::get_parser(provider);
            // T-903: Accumulate tool call names from streaming deltas
            let mut streaming_tool_names: Vec<String> = vec![];
            let mut tool_call_policy_checked = false;
            // Accumulate tool call argument deltas per index for PII scanning
            let mut streaming_tool_args: std::collections::HashMap<usize, String> = std::collections::HashMap::new();
            // SSE line-buffering: accumulate bytes across TCP chunks until
            // complete \n\n-terminated events are available. Prevents silent
            // data loss when a single SSE event is split across chunk boundaries
            // (the continuation chunk lacks the "data: " prefix and would be
            // dropped by parse_frame without reassembly).
            let mut sse_buf: Vec<u8> = Vec::new();

            while let Some(chunk_result) = raw_stream.next().await {
                match chunk_result {
                    Ok(chunk) => {
                        if first_byte_ms.is_none() {
                            first_byte_ms = Some(stream_start.elapsed().as_secs_f64() * 1000.0);
                        }
                        bytes_received += chunk.len();

                        if !streaming_enabled {
                            // Zero-buffer passthrough — no PII scanning
                            bytes_emitted += chunk.len();
                            frames_received += 1;
                            frames_emitted += 1;
                            yield Ok::<bytes::Bytes, std::io::Error>(chunk);
                            continue;
                        }

                        if observe_mode {
                            // Observe mode: scan for findings but never modify output.
                            // Emit original SSE frames byte-faithful so downstream clients
                            // see a valid wire format regardless of which policies fired.
                            sse_buf.extend_from_slice(&chunk);
                            let complete_events = if parser.is_binary() {
                                crate::streaming::parsers::extract_complete_bedrock_frames(&mut sse_buf)
                            } else {
                                crate::streaming::parsers::extract_complete_sse_events(&mut sse_buf)
                            };
                            if complete_events.is_empty() {
                                continue; // No complete event yet
                            }
                            let obs_frames: Vec<_> = complete_events.iter()
                                .flat_map(|ev| parser.parse_frame(ev))
                                .collect();
                            frames_received += obs_frames.len();
                            for frame in &obs_frames {
                                // Extract tool calls unconditionally — Gemini sends functionCall +
                                // finishReason:STOP in the same terminal frame (LiteLLM #12240/#21041).
                                if let Ok(v) = serde_json::from_str::<serde_json::Value>(&frame.data) {
                                    extract_streaming_tool_calls(&v, provider, &mut streaming_tool_names);
                                    extract_streaming_tool_args(&v, provider, &mut streaming_tool_args);
                                }
                                if !frame.is_done && !frame.is_error {
                                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&frame.data) {
                                        if let Some(text) = extract_delta_text(&v) {
                                            let enforce_t = Instant::now();
                                            let (_, new_findings) = pii_engine_sse.scan_bytes(text.as_bytes(), "streaming_response");
                                            cadabra_ms += enforce_t.elapsed().as_secs_f64() * 1000.0;
                                            if !new_findings.is_empty() {
                                                stream_verdict = "flag".to_string();
                                            }
                                            findings.extend(new_findings);
                                        }
                                    }
                                }
                                // On [DONE]: scan accumulated tool call arguments for PII.
                                if frame.is_done && !streaming_tool_args.is_empty() {
                                    let joined_args: String = streaming_tool_args.values().cloned().collect::<Vec<_>>().join(" ");
                                    if !joined_args.is_empty() {
                                        let enforce_t = Instant::now();
                                        let args_findings = pii_engine_sse.scan_only(&joined_args, "streaming_tool_args");
                                        cadabra_ms += enforce_t.elapsed().as_secs_f64() * 1000.0;
                                        if !args_findings.is_empty() {
                                            stream_verdict = "flag".to_string();
                                        }
                                        findings.extend(args_findings);
                                    }
                                }
                                // On [DONE]: run tool-call policy if names were accumulated.
                                // The non-observe path handles this after the observe_mode block,
                                // but the `continue` below bypasses it — so we must check here.
                                if frame.is_done && !streaming_tool_names.is_empty() && !tool_call_policy_checked {
                                    tool_call_policy_checked = true;
                                    let enforce_t = Instant::now();
                                    let streaming_pii_findings: Vec<String> = findings
                                        .iter()
                                        .map(|f| f.pattern.clone())
                                        .collect();
                                    let tool_ctx = build_cedar_context_compat(&ContextParams {
                                        model: model_sse.as_deref().unwrap_or(""),
                                        streaming: true,
                                        pii_detected: !findings.is_empty(),
                                        pii_findings: &streaming_pii_findings,
                                        risk_level: &risk_level_sse,
                                        tool_names: &streaming_tool_names,
                                        tool_count: streaming_tool_names.len() as i64,
                                        budget_remaining_cents: if has_budget_sse { (budget_remaining_sse * 100.0) as i64 } else { -1 },
                                        budget_utilization_pct: if has_budget_sse { budget_utilization_sse as i64 } else { -1 },
                                        fallback_available: fallback_available_sse,
                                        model_approved,
                                        consent_given,
                                        org_timezone: &org_timezone_sse,
                                        org_industry: &org_industry_sse,
                                        org_region: &org_region_sse,
                                        org_business_hours_active: org_business_hours_active_sse,
                                        mcp_server_approved: mcp_server_approved_sse,
                                        mcp_server_id: &mcp_server_id_sse,
                                        unauthorized_tool_detected: unauthorized_tool_detected_sse,
                                        tool_allowlist_mode: tool_allowlist_mode_sse,
                                        ..Default::default()
                                    });
                                    let tool_decision = policy_engine_sse.evaluate_response(
                                        principal_sse.as_deref().unwrap_or("anonymous"),
                                        PolicyAction::ToolCall.as_cedar_action(),
                                        &serde_json::Value::Null,
                                        &tool_ctx,
                                    ).unwrap_or_else(|e| {
                                        warn!(error = %e, "observe mode streaming tool policy eval error — defaulting to allow");
                                        PolicyDecision::allow()
                                    });
                                    cadabra_ms += enforce_t.elapsed().as_secs_f64() * 1000.0;
                                    if tool_decision.action == EnforcementAction::Flag {
                                        stream_verdict = "flag".to_string();
                                        let rule_id = tool_decision.rule_id.unwrap_or_else(|| "streaming_tool_policy".to_string());
                                        findings.push(PiiFinding {
                                            pattern: rule_id,
                                            redacted_to: String::new(),
                                            count: streaming_tool_names.len(),
                                            location: "streaming_response_tool_calls".to_string(),
                                            matched_text: Some(streaming_tool_names.join(",")),
                                        });
                                    } else if tool_decision.action == EnforcementAction::Block {
                                        stream_verdict = "block".to_string();
                                        let rule_id = tool_decision.rule_id.unwrap_or_else(|| "streaming_tool_policy".to_string());
                                        findings.push(PiiFinding {
                                            pattern: rule_id,
                                            redacted_to: String::new(),
                                            count: streaming_tool_names.len(),
                                            location: "streaming_response_tool_calls".to_string(),
                                            matched_text: Some(streaming_tool_names.join(",")),
                                        });
                                    }
                                }
                                // Re-emit byte-faithful SSE (restores data: ...\n\n)
                                let out = parser.encode_frame(frame);
                                bytes_emitted += out.len();
                                frames_emitted += 1;
                                yield Ok(out);
                            }
                            continue;
                        }

                        // Parse frames from this chunk and enforce.
                        // Bedrock uses binary frame splitting; other providers use SSE \n\n splitting.
                        sse_buf.extend_from_slice(&chunk);
                        let complete_events = if parser.is_binary() {
                            crate::streaming::parsers::extract_complete_bedrock_frames(&mut sse_buf)
                        } else {
                            crate::streaming::parsers::extract_complete_sse_events(&mut sse_buf)
                        };
                        if complete_events.is_empty() {
                            continue; // No complete event yet
                        }
                        let frames: Vec<_> = complete_events.iter()
                            .flat_map(|ev| parser.parse_frame(ev))
                            .collect();
                        frames_received += frames.len();

                        // Enforce-path frame dispatch:
                        //   1. is_done || is_error  → flush buffer, run tool policy, emit via encode_frame
                        //   2. has text delta        → buffer for PII scan, emit on word boundary
                        //   3. no text delta (else)  → emit via encode_frame (tool_calls, finish_reason, metadata)
                        //
                        // Audit note: ALL emission paths (observe + enforce) use encode_frame
                        // to produce properly \n\n-terminated SSE frames. parse_frame stores
                        // raw as the trimmed data: line (OpenAI/Anthropic) or full input bytes
                        // (Bedrock/Gemini passthrough). encode_frame normalizes this: it adds
                        // the SSE envelope (data: ...\n\n) for text parsers, and is a no-op
                        // clone for binary passthrough parsers.
                        for frame in frames {
                            // Extract tool calls unconditionally — Gemini sends functionCall +
                            // finishReason:STOP in the same terminal frame (LiteLLM #12240/#21041),
                            // so extraction must happen before the is_done gate.
                            if let Ok(v) = serde_json::from_str::<serde_json::Value>(&frame.data) {
                                extract_streaming_tool_calls(&v, provider, &mut streaming_tool_names);
                                extract_streaming_tool_args(&v, provider, &mut streaming_tool_args);
                            }

                            if frame.is_done || frame.is_error {
                                // Flush remaining buffered content before the control frame
                                if let Some(remaining) = buffer.flush_end() {
                                    let enforce_t = Instant::now();
                                    let (scanned, new_findings) = pii_engine_sse.scan_bytes(&remaining, "streaming_response");
                                    cadabra_ms += enforce_t.elapsed().as_secs_f64() * 1000.0;
                                    findings.extend(new_findings);
                                    let scanned_str = String::from_utf8_lossy(&scanned);
                                    let encoded = parser.encode_text_delta(&scanned_str);
                                    bytes_emitted += encoded.len();
                                    frames_emitted += 1;
                                    yield Ok(encoded);
                                }
                                // Scan accumulated tool call arguments for PII at stream end
                                if !streaming_tool_args.is_empty() {
                                    let joined_args: String = streaming_tool_args.values().cloned().collect::<Vec<_>>().join(" ");
                                    if !joined_args.is_empty() {
                                        let enforce_t = Instant::now();
                                        let (_, args_findings) = pii_engine_sse.scan_bytes(joined_args.as_bytes(), "streaming_tool_args");
                                        cadabra_ms += enforce_t.elapsed().as_secs_f64() * 1000.0;
                                        if !args_findings.is_empty() {
                                            stream_verdict = "flag".to_string();
                                        }
                                        findings.extend(args_findings);
                                    }
                                }
                                // T-903: Evaluate tool-call policy on stream end
                                if !streaming_tool_names.is_empty() && !tool_call_policy_checked {
                                    tool_call_policy_checked = true;
                                    let enforce_t = Instant::now();
                                    let streaming_pii_findings: Vec<String> = findings
                                        .iter()
                                        .map(|f| f.pattern.clone())
                                        .collect();
                                    let tool_ctx = build_cedar_context_compat(&ContextParams {
                                        model: model_sse.as_deref().unwrap_or(""),
                                        streaming: true,
                                        pii_detected: !findings.is_empty(),
                                        pii_findings: &streaming_pii_findings,
                                        risk_level: &risk_level_sse,
                                        tool_names: &streaming_tool_names,
                                        tool_count: streaming_tool_names.len() as i64,
                                        budget_remaining_cents: if has_budget_sse { (budget_remaining_sse * 100.0) as i64 } else { -1 },
                                        budget_utilization_pct: if has_budget_sse { budget_utilization_sse as i64 } else { -1 },
                                        fallback_available: fallback_available_sse,
                                        model_approved,
                                        consent_given,
                                        org_timezone: &org_timezone_sse,
                                        org_industry: &org_industry_sse,
                                        org_region: &org_region_sse,
                                        org_business_hours_active: org_business_hours_active_sse,
                                        mcp_server_approved: mcp_server_approved_sse,
                                        mcp_server_id: &mcp_server_id_sse,
                                        unauthorized_tool_detected: unauthorized_tool_detected_sse,
                                        tool_allowlist_mode: tool_allowlist_mode_sse,
                                        ..Default::default()
                                    });
                                    let tool_decision = policy_engine_sse.evaluate_response(
                                        principal_sse.as_deref().unwrap_or("anonymous"),
                                        PolicyAction::ToolCall.as_cedar_action(),
                                        &serde_json::Value::Null,
                                        &tool_ctx,
                                    ).unwrap_or_else(|e| {
                                        warn!(error = %e, "streaming tool policy eval error — defaulting to allow");
                                        PolicyDecision::allow()
                                    });
                                    cadabra_ms += enforce_t.elapsed().as_secs_f64() * 1000.0;
                                    if tool_decision.action == EnforcementAction::Flag {
                                        stream_verdict = "flag".to_string();
                                        let rule_id = tool_decision.rule_id.unwrap_or_else(|| "streaming_tool_policy".to_string());
                                        findings.push(PiiFinding {
                                            pattern: rule_id,
                                            redacted_to: String::new(),
                                            count: streaming_tool_names.len(),
                                            location: "streaming_response_tool_calls".to_string(),
                                            matched_text: Some(streaming_tool_names.join(",")),
                                        });
                                    } else if tool_decision.action == EnforcementAction::Block {
                                        stream_verdict = "block".to_string();
                                        // Can't fully block mid-stream, but record the violation
                                        let rule_id = tool_decision.rule_id.unwrap_or_else(|| "streaming_tool_policy".to_string());
                                        findings.push(PiiFinding {
                                            pattern: rule_id,
                                            redacted_to: String::new(),
                                            count: streaming_tool_names.len(),
                                            location: "streaming_response_tool_calls".to_string(),
                                            matched_text: Some(streaming_tool_names.join(",")),
                                        });
                                    }
                                }
                                // Emit control frame with proper SSE framing.
                                // Use encode_frame (not frame.raw) because OpenAI/Anthropic
                                // parse_frame stores raw as the trimmed data: line without
                                // the \n\n SSE terminator; encode_frame adds it back.
                                let encoded = parser.encode_frame(&frame);
                                bytes_emitted += encoded.len();
                                frames_emitted += 1;
                                yield Ok(encoded);
                            } else {
                                // Extract text delta and buffer it for PII scanning.
                                // Tool calls were already extracted unconditionally above.
                                let text_opt = if let Ok(v) = serde_json::from_str::<serde_json::Value>(&frame.data) {
                                    extract_delta_text(&v)
                                } else {
                                    None
                                };

                                if let Some(text) = text_opt {
                                    if let Some((flushed, _reason)) = buffer.push(text.as_bytes()) {
                                        let enforce_t = Instant::now();
                                        // PII scan on flushed content (always runs first)
                                        let (scanned, new_findings) = pii_engine_sse.scan_bytes(&flushed, "streaming_response");
                                        let pii_detected = !new_findings.is_empty();
                                        findings.extend(new_findings);

                                        // T-006: Policy evaluation on flushed content
                                        let policy_context_resp = build_cedar_context_compat(&ContextParams {
                                            model: model_sse.as_deref().unwrap_or(""),
                                            streaming: true,
                                            pii_detected,
                                            risk_level: &risk_level_sse,
                                            budget_remaining_cents: if has_budget_sse { (budget_remaining_sse * 100.0) as i64 } else { -1 },
                                            budget_utilization_pct: if has_budget_sse { budget_utilization_sse as i64 } else { -1 },
                                            fallback_available: fallback_available_sse,
                                            model_approved,
                                            consent_given,
                                            org_timezone: &org_timezone_sse,
                                            org_industry: &org_industry_sse,
                                            org_region: &org_region_sse,
                                            org_business_hours_active: org_business_hours_active_sse,
                                            mcp_server_approved: mcp_server_approved_sse,
                                            mcp_server_id: &mcp_server_id_sse,
                                            ..Default::default()
                                        });
                                        let resp_decision = policy_engine_sse.evaluate_response(
                                            principal_sse.as_deref().unwrap_or("anonymous"),
                                            PolicyAction::LlmResponse.as_cedar_action(),
                                            &serde_json::Value::Null,
                                            &policy_context_resp,
                                        ).unwrap_or_else(|e| {
                                            warn!(error = %e, "streaming policy eval error — defaulting to allow");
                                            PolicyDecision::allow()
                                        });

                                        cadabra_ms += enforce_t.elapsed().as_secs_f64() * 1000.0;

                                        // T-007: Apply 5-action verdict
                                        match resp_decision.action {
                                            EnforcementAction::Allow => {
                                                let scanned_str = String::from_utf8_lossy(&scanned);
                                                let encoded = parser.encode_text_delta(&scanned_str);
                                                bytes_emitted += encoded.len();
                                                frames_emitted += 1;
                                                yield Ok(encoded);
                                            }
                                            EnforcementAction::Flag => {
                                                // Emit content unchanged; add a policy-flag finding
                                                stream_verdict = "flag".to_string();
                                                let rule_id = resp_decision.rule_id.clone()
                                                    .unwrap_or_else(|| "streaming_policy".to_string());
                                                findings.push(PiiFinding {
                                                    pattern: rule_id,
                                                    redacted_to: String::new(),
                                                    count: 1,
                                                    location: "streaming_response_policy".to_string(),
                                                    matched_text: None,
                                                });
                                                let scanned_str = String::from_utf8_lossy(&scanned);
                                                let encoded = parser.encode_text_delta(&scanned_str);
                                                bytes_emitted += encoded.len();
                                                frames_emitted += 1;
                                                yield Ok(encoded);
                                            }
                                            EnforcementAction::Transform => {
                                                stream_verdict = "transform".to_string();
                                                let output_text = if let Some(ref transform_meta) = resp_decision.transform_to {
                                                    // transform_to format: "pattern\x1freplace"
                                                    let parts: Vec<&str> = transform_meta.splitn(2, '\x1f').collect();
                                                    if parts.len() == 2 {
                                                        let text_str = String::from_utf8_lossy(&scanned);
                                                        text_str.replace(parts[0], parts[1])
                                                    } else {
                                                        String::from_utf8_lossy(&scanned).into_owned()
                                                    }
                                                } else {
                                                    String::from_utf8_lossy(&scanned).into_owned()
                                                };
                                                let encoded = parser.encode_text_delta(&output_text);
                                                bytes_emitted += encoded.len();
                                                frames_emitted += 1;
                                                yield Ok(encoded);
                                            }
                                            EnforcementAction::Steer => {
                                                stream_verdict = "steer".to_string();
                                                // Drain remaining buffer without emitting
                                                let _ = buffer.flush_end();
                                                // Emit the steer message
                                                let msg = resp_decision.steer_message.as_deref()
                                                    .unwrap_or("I can't help with that.");
                                                let steer_bytes = parser.encode_steer(msg, "steer");
                                                bytes_emitted += steer_bytes.len();
                                                frames_emitted += 1;
                                                yield Ok(steer_bytes);
                                                // Drain remaining upstream without emitting
                                                while raw_stream.next().await.is_some() {}
                                                break;
                                            }
                                            EnforcementAction::Block => {
                                                stream_verdict = "block".to_string();
                                                // Drain remaining buffer without emitting
                                                let _ = buffer.flush_end();
                                                // Emit error frame
                                                let rule_id = resp_decision.rule_id.as_deref()
                                                    .unwrap_or("policy_block");
                                                let error_bytes = parser.encode_error(rule_id, "block");
                                                bytes_emitted += error_bytes.len();
                                                frames_emitted += 1;
                                                yield Ok(error_bytes);
                                                // Drain remaining upstream without emitting
                                                while raw_stream.next().await.is_some() {}
                                                break;
                                            }
                                        }
                                    }
                                } else {
                                    // Non-text frame: emit with proper SSE framing. Covers:
                                    //   - OpenAI: tool_call deltas (name, arguments), finish_reason
                                    //   - Anthropic: content_block_start/stop, input_json_delta,
                                    //     message_start/delta, ping
                                    //   - Bedrock/Gemini: all frames (passthrough parsers)
                                    // extract_delta_text returns None for all of these because
                                    // they lack choices[].delta.content (OpenAI) or delta.text
                                    // (Anthropic). Dropping them would lose finish_reason and
                                    // tool call streaming state — see enforcer.rs regression tests.
                                    // Use encode_frame (not frame.raw) because parse_frame stores
                                    // raw without the \n\n SSE terminator; encode_frame adds it.
                                    let encoded = parser.encode_frame(&frame);
                                    bytes_emitted += encoded.len();
                                    frames_emitted += 1;
                                    yield Ok(encoded);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        stream_verdict = "upstream_error".to_string();
                        yield Err(std::io::Error::other(e.to_string()));
                        break;
                    }
                }
            }

            // Drain any SSE events still in sse_buf when the stream closes.
            // This handles the case where the upstream closes the connection before
            // emitting a trailing \n\n — e.g. finish_reason: "tool_calls" arriving
            // in the last TCP segment without proper SSE termination.
            {
                // First pass: extract any complete frames (binary or SSE) from the residual buffer.
                let tail_events = if parser.is_binary() {
                    crate::streaming::parsers::extract_complete_bedrock_frames(&mut sse_buf)
                } else {
                    crate::streaming::parsers::extract_complete_sse_events(&mut sse_buf)
                };
                for ev in tail_events {
                    let tail_frames: Vec<_> = parser.parse_frame(&ev).into_iter().collect();
                    frames_received += tail_frames.len();
                    for frame in tail_frames {
                        if observe_mode {
                            let out = parser.encode_frame(&frame);
                            bytes_emitted += out.len();
                            frames_emitted += 1;
                            yield Ok(out);
                        } else {
                            // Enforce drain: emit ALL frames with proper SSE framing.
                            // Unlike the main loop (which buffers text deltas for PII
                            // scanning), the drain path must not selectively filter —
                            // doing so would drop finish_reason frames (e.g. "tool_calls",
                            // "length") that carry no text delta but are required by
                            // downstream clients for correct response handling.
                            // Use encode_frame (not frame.raw) for correct \n\n termination.
                            let encoded = parser.encode_frame(&frame);
                            bytes_emitted += encoded.len();
                            frames_emitted += 1;
                            yield Ok(encoded);
                        }
                    }
                }
                // Second pass: if content remains with no \n\n (truly unterminated),
                // try parsing it as-is — the data: line is complete even if \n\n is absent.
                if !sse_buf.is_empty() {
                    let tail_frames: Vec<_> = parser.parse_frame(&sse_buf).into_iter().collect();
                    frames_received += tail_frames.len();
                    for frame in tail_frames {
                        if observe_mode {
                            let out = parser.encode_frame(&frame);
                            bytes_emitted += out.len();
                            frames_emitted += 1;
                            yield Ok(out);
                        } else {
                            // Same rationale as first-pass drain above: use encode_frame
                            // for correct \n\n SSE termination.
                            let encoded = parser.encode_frame(&frame);
                            bytes_emitted += encoded.len();
                            frames_emitted += 1;
                            yield Ok(encoded);
                        }
                    }
                    sse_buf.clear();
                }
            }

            // Final flush for any content still in the buffer (stream ended without [DONE])
            if let Some(remaining) = buffer.flush_end() {
                let enforce_t = Instant::now();
                let (scanned, new_findings) = pii_engine_sse.scan_bytes(&remaining, "streaming_response");
                cadabra_ms += enforce_t.elapsed().as_secs_f64() * 1000.0;
                findings.extend(new_findings);
                let scanned_str = String::from_utf8_lossy(&scanned);
                let encoded = parser.encode_text_delta(&scanned_str);
                bytes_emitted += encoded.len();
                frames_emitted += 1;
                yield Ok(encoded);
            }

            // Send stats back for the audit entry
            let stats = StreamStats {
                bytes_received,
                bytes_emitted,
                frames_received,
                frames_emitted,
                findings,
                first_byte_ms,
                stream_duration_ms: stream_start.elapsed().as_secs_f64() * 1000.0,
                flush_on_boundary: buffer.flush_counts.on_boundary,
                flush_on_size_cap: buffer.flush_counts.on_size_cap,
                flush_on_stream_end: buffer.flush_counts.on_stream_end,
                stream_verdict,
                invoked_tools: streaming_tool_names,
                cadabra_ms,
            };
            let _ = tx.send(stats);
        };

        // Spawn a task to write the streaming audit entry once the stream closes
        tokio::spawn(async move {
            if let Ok(stats) = rx.await {
                let entry = build_streaming_audit_entry(
                    &audit_id_sse,
                    &request_id_sse,
                    &tenant_id,
                    &method_str,
                    &path_str,
                    model_sse_audit.as_deref(),
                    status_code,
                    total_overhead,
                    upstream_ms_sse,
                    &req_findings,
                    &action_str,
                    rule_id_str.as_deref(),
                    &matched_rules_sse,
                    retries_sse,
                    fallback_sse,
                    &stats,
                    streaming_enabled,
                    &provider_sse_post,
                    Some(agent_id_audit.as_str()),
                    Some(&policy_context_sse),
                );
                audit_writer_sse.write(entry);
            }
        });

        record_perf(
            state,
            &eg,
            model.as_deref(),
            route.provider_name.as_deref(),
            is_streaming,
            timing.upstream_ms,
            &timing,
        );
        let mut builder = axum::response::Response::builder().status(axum_status);
        for (k, v) in &resp_headers_map {
            builder = builder.header(k.as_str(), v.as_str());
        }
        builder = builder.header("x-request-id", eg.request_id.as_str());
        builder = builder.header("eg-audit-id", audit_id.as_str());
        if let Ok(hv) = request_policy_input
            .to_header_value(4096)
            .parse::<axum::http::HeaderValue>()
        {
            builder = builder.header("eg-policy-input", hv);
        }
        let body = Body::from_stream(enforced_stream);
        return builder
            .body(body)
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
    }

    // Non-SSE: read full body, scan only message content for PII.
    // When PII is disabled or no findings, we keep the raw `bytes::Bytes`
    // directly — Body::from(bytes::Bytes) is zero-copy in axum and avoids
    // the `.to_vec()` allocation that was previously always performed.
    let t = Instant::now();
    let raw = upstream_resp.bytes().await.unwrap_or_default();
    // Response-side PII scan only when response enforcement is active.
    // Observation-mode tenants skip this entirely (zero overhead on response path).
    let resp_body_bytes: bytes::Bytes =
        if sync_reqs.has_response_enforcement && state.config.pii.enabled && !raw.is_empty() {
            let text = std::str::from_utf8(&raw).unwrap_or("");
            let r = state.pii_engine.scan_and_redact_response(text, "response");
            if !r.findings.is_empty() {
                bytes::Bytes::from(r.redacted_text.into_bytes())
            } else {
                raw // zero-copy: reuse the Bytes buffer from reqwest
            }
        } else {
            raw // zero-copy: reuse the Bytes buffer from reqwest
        };
    timing.pii_response_ms = Some(t.elapsed().as_secs_f64() * 1000.0);

    // ── Phase 6b: Exfiltration scan (response) ──────────────────────────────
    // Only run if response enforcement is active.
    let (resp_exfil_detected, resp_exfil_type_str) = if sync_reqs.has_response_enforcement {
        let resp_text_for_exfil = std::str::from_utf8(&resp_body_bytes).unwrap_or("");
        let resp_exfil_result = {
            use crate::detectors::exfiltration::ExfiltrationDetector;
            let det = ExfiltrationDetector::new();
            det.scan(resp_text_for_exfil)
        };
        let detected = resp_exfil_result.detected;
        let type_str = resp_exfil_result
            .findings
            .first()
            .map(|f| f.category.clone())
            .unwrap_or_default();
        (detected, type_str)
    } else {
        (false, String::new())
    };

    // ── T-901: Response-side tool-call extraction + policy evaluation ────────
    let t = Instant::now();
    let (response_tool_names, response_tool_count) = if sync_reqs.has_response_enforcement {
        extract_response_tool_calls(&resp_body_bytes)
    } else {
        (vec![], 0)
    };
    let response_action = PolicyAction::from_response(response_tool_count > 0);
    // Response-side tool governance for tool calls in the LLM response
    let resp_tool_gov_result = if response_tool_count > 0 {
        state.tool_governance.scan_tools(&response_tool_names)
    } else {
        crate::detectors::tool_governance::ToolGovernanceResult::default()
    };
    let resp_tool_gov_categories_str = resp_tool_gov_result.categories_csv();

    let response_decision = if response_tool_count > 0 || resp_exfil_detected {
        let resp_context = build_cedar_context_compat(&ContextParams {
            model: used_model.as_deref().or(model.as_deref()).unwrap_or(""),
            streaming: false,
            pii_detected: !pii_result.findings.is_empty(),
            pii_findings: &pii_finding_names,
            risk_level,
            tool_names: &response_tool_names,
            tool_count: response_tool_count as i64,
            tool_name: response_tool_names
                .first()
                .map(|s| s.as_str())
                .unwrap_or(""),
            budget_remaining_cents: if has_budget {
                (budget_remaining_usd * 100.0) as i64
            } else {
                -1
            },
            budget_utilization_pct: if has_budget {
                budget_utilization_pct as i64
            } else {
                -1
            },
            // Exfiltration (response-side)
            exfiltration_detected: resp_exfil_detected,
            exfiltration_type: &resp_exfil_type_str,
            // Tool governance (response-side)
            unauthorized_tool_detected: resp_tool_gov_result.detected,
            tool_categories: &resp_tool_gov_categories_str,
            tool_highest_risk_category: &resp_tool_gov_result.highest_risk_category,
            tool_allowlist_mode: resp_tool_gov_result.allowlist_mode,
            fallback_available: !route.fallback.is_empty(),
            model_approved,
            consent_given,
            org_timezone: org_timezone_str,
            org_industry: org_industry_str,
            org_region: org_region_str,
            org_business_hours_active,
            mcp_server_approved,
            mcp_server_id: &mcp_server_id_str,
            ..Default::default()
        });
        let cedar_t = Instant::now();
        let decision = tenant_engine.evaluate_response(
            principal,
            response_action.as_cedar_action(),
            &Value::Null,
            &resp_context,
        ).unwrap_or_else(|e| {
            warn!(error = %e, tenant_id = %tenant_id, "response tool policy eval error — defaulting to allow");
            PolicyDecision::allow()
        });
        timing.cedar_response_ms = Some(cedar_t.elapsed().as_secs_f64() * 1000.0);
        decision
    } else {
        PolicyDecision::allow()
    };
    timing.tool_check_ms = Some(t.elapsed().as_secs_f64() * 1000.0);

    // Prepare masked response payload for audit retention
    let retained_response_payload: Option<String> =
        match state.config.audit.retain_payloads.as_str() {
            "masked" | "raw" => {
                // resp_body_bytes is already post-PII-scan for "masked"; for "raw" we'd need the original
                // but since the response PII scan is in-place, masked is all we have. This is fine —
                // "raw" for responses means "as received after PII scan" which is the safe default.
                let text = std::str::from_utf8(&resp_body_bytes).unwrap_or("");
                Some(truncate_payload(text, state.config.audit.max_payload_bytes))
            }
            _ => None,
        };

    // If response policy blocks, return 403 instead of the upstream response
    if response_decision.action == EnforcementAction::Block {
        let total_overhead = start.elapsed().as_secs_f64() * 1000.0 - timing.upstream_ms;
        let req_payload_ref = if should_retain_payload(&state.config.audit, "block") {
            retained_request_payload.as_deref()
        } else {
            None
        };
        let resp_payload_ref = if should_retain_payload(&state.config.audit, "block") {
            retained_response_payload.as_deref()
        } else {
            None
        };
        let entry = build_audit_entry(AuditParams {
            audit_id: &audit_id,
            request_id: &eg.request_id,
            method: &method,
            path: uri.path(),
            model: used_model.as_deref().or(model.as_deref()),
            streaming: is_streaming,
            status: status.as_u16(),
            overhead_ms: total_overhead,
            upstream_ms: timing.upstream_ms,
            pii_findings: &pii_result.findings,
            action: "block",
            rule_id: response_decision.rule_id.as_deref(),
            description: response_decision.description.as_deref(),
            regulatory_mapping: &response_decision.regulatory_mapping,
            matched_rules: &response_decision.matched_rules,
            retries_made,
            fallback_triggered,
            labels: &build_labels(
                detector_results,
                &pii_result.findings,
                "block",
                response_decision.rule_id.as_deref(),
            ),
            request_payload: req_payload_ref,
            response_payload: resp_payload_ref,
            tenant_id: &tenant_id,
            agent_id: Some(principal),
            context_snapshot: Some(&policy_context),
            hold_id: None,
        });
        state.audit_sink.write(entry);
        record_perf(
            state,
            &eg,
            model.as_deref(),
            route.provider_name.as_deref(),
            is_streaming,
            timing.upstream_ms,
            &timing,
        );
        let mut resp = SteerError::PolicyBlock {
            rule: response_decision
                .rule_id
                .unwrap_or_else(|| "response_tool_policy".to_string()),
        }
        .into_response();
        resp.headers_mut()
            .insert("eg-audit-id", audit_id.parse().unwrap());
        if let Ok(hv) = request_policy_input.to_header_value(4096).parse() {
            resp.headers_mut().insert("eg-policy-input", hv);
        }
        return resp;
    }

    // Use the most restrictive action between request and response policy
    let final_action = if response_decision.action > request_decision.action {
        &response_decision
    } else {
        &request_decision
    };

    // ── T-301: Token recording (fire-and-forget) ─────────────────────────────
    // Parse token usage from the response body and record asynchronously.
    {
        let body_for_tokens = resp_body_bytes.clone();
        let provider_str = crate::streaming::parsers::detect_provider(
            route.provider_name.as_deref(),
            uri.path(),
            None,
        )
        .to_string();
        let model_str = used_model
            .clone()
            .or_else(|| model.clone())
            .unwrap_or_default();
        let request_id_tok = eg.request_id.clone();
        let api_key_hash_tok = api_key_hash.clone();
        let agent_id_tok = eg.agent_id.clone();
        let tenant_id_tok = tenant_id.clone();
        let token_provider: Arc<dyn TokenProvider> = Arc::clone(&state.token_provider);
        let budget_cache = Arc::clone(&state.budget_cache);
        let cost_estimator = Arc::clone(&state.cost_estimator);
        let api_key_hash_budget = api_key_hash.clone();
        let agent_id_budget = if agent_id_str.is_empty() {
            None
        } else {
            Some(agent_id_str.to_string())
        };
        let tenant_id_budget = tenant_id.clone();

        tokio::spawn(async move {
            if let Ok(body_json) = serde_json::from_slice::<serde_json::Value>(&body_for_tokens) {
                if let Some(usage) = parse_usage(&body_json, &provider_str) {
                    let cost = cost_estimator.estimate(&model_str, &usage);
                    let record = NewTokenUsage {
                        request_id: request_id_tok,
                        api_key_hash: api_key_hash_tok.clone(),
                        agent_id: agent_id_tok,
                        tenant_id: Some(tenant_id_tok),
                        model: usage.model.clone(),
                        provider: usage.provider.clone(),
                        prompt_tokens: usage.prompt_tokens,
                        completion_tokens: usage.completion_tokens,
                        total_tokens: usage.total_tokens,
                        estimated_cost_usd: cost,
                    };
                    if let Err(e) = token_provider.record_usage(&record) {
                        tracing::warn!(error = %e, "token usage record failed");
                    }
                    // Update budget cache for api_key scope
                    if let Some(ref kh) = api_key_hash_budget {
                        budget_cache.record_spend("api_key", kh, cost);
                        if let Err(e) = token_provider.update_budget_spend("api_key", kh, cost) {
                            tracing::warn!(error = %e, "budget spend update (api_key) failed");
                        }
                    }
                    // Update budget cache for agent scope
                    let agent_id_str = agent_id_budget.as_deref().unwrap_or("anonymous");
                    budget_cache.record_spend("agent", agent_id_str, cost);
                    if let Err(e) = token_provider.update_budget_spend("agent", agent_id_str, cost)
                    {
                        tracing::warn!(error = %e, "budget spend update (agent) failed");
                    }
                    // Update budget cache for tenant scope
                    if tenant_id_budget != "default" {
                        budget_cache.record_spend("tenant", &tenant_id_budget, cost);
                        if let Err(e) =
                            token_provider.update_budget_spend("tenant", &tenant_id_budget, cost)
                        {
                            tracing::warn!(error = %e, "budget spend update (tenant) failed");
                        }
                    }
                }
            }
        });
    }

    let total_overhead = start.elapsed().as_secs_f64() * 1000.0 - timing.upstream_ms;

    // ── Audit + perf ──────────────────────────────────────────────────────────
    let final_action_str = final_action.action.to_string();
    let req_payload_ref = if should_retain_payload(&state.config.audit, &final_action_str) {
        retained_request_payload.as_deref()
    } else {
        None
    };
    let resp_payload_ref = if should_retain_payload(&state.config.audit, &final_action_str) {
        retained_response_payload.as_deref()
    } else {
        None
    };
    let entry = build_audit_entry(AuditParams {
        audit_id: &audit_id,
        request_id: &eg.request_id,
        method: &method,
        path: uri.path(),
        model: used_model.as_deref().or(model.as_deref()),
        streaming: is_streaming,
        status: status.as_u16(),
        overhead_ms: total_overhead,
        upstream_ms: timing.upstream_ms,
        pii_findings: &pii_result.findings,
        action: &final_action_str,
        rule_id: final_action.rule_id.as_deref(),
        description: final_action.description.as_deref(),
        regulatory_mapping: &final_action.regulatory_mapping,
        matched_rules: &final_action.matched_rules,
        retries_made,
        fallback_triggered,
        labels: &build_labels(
            detector_results,
            &pii_result.findings,
            &final_action_str,
            final_action.rule_id.as_deref(),
        ),
        request_payload: req_payload_ref,
        response_payload: resp_payload_ref,
        tenant_id: &tenant_id,
        agent_id: Some(principal),
        context_snapshot: Some(&policy_context),
        hold_id: None,
    });
    state.audit_sink.write(entry);
    record_perf(
        state,
        &eg,
        model.as_deref(),
        route.provider_name.as_deref(),
        is_streaming,
        timing.upstream_ms,
        &timing,
    );

    // ── Build response ────────────────────────────────────────────────────────
    let mut builder = axum::response::Response::builder().status(axum_status);
    for (k, v) in &resp_headers_map {
        builder = builder.header(k.as_str(), v.as_str());
    }
    builder = builder.header("x-request-id", eg.request_id.as_str());
    builder = builder.header("eg-audit-id", audit_id.as_str());
    if let Ok(hv) = request_policy_input
        .to_header_value(4096)
        .parse::<axum::http::HeaderValue>()
    {
        builder = builder.header("eg-policy-input", hv);
    }
    builder
        .body(Body::from(resp_body_bytes))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// Extract the text delta from a streaming frame, if present.
///
/// Returns `Some(text)` only for frames that carry a text content delta:
///   - OpenAI:    `choices[0].delta.content`
///   - Anthropic: `delta.text` (content_block_delta with type text_delta)
///
/// Returns `None` for all other frame shapes — including:
///   - Tool call deltas (`delta.tool_calls`, `delta.type: "input_json_delta"`)
///   - Finish-reason-only frames (`delta: {}`, `finish_reason: "tool_calls"`)
///   - Metadata frames (message_start, content_block_start/stop, ping)
///   - Deprecated `function_call` format
///   - Gemini candidates (handled: `candidates[0].content.parts[*].text`)
///   - Bedrock binary frames (handled: same delta.text path as Anthropic)
///
/// Frames returning `None` are emitted verbatim by the enforce path's else clause.
fn extract_delta_text(v: &serde_json::Value) -> Option<String> {
    // OpenAI/Azure: choices[0].delta.content
    if let Some(text) = v
        .get("choices")
        .and_then(|c| c.get(0))
        .and_then(|c| c.get("delta"))
        .and_then(|d| d.get("content"))
        .and_then(|c| c.as_str())
    {
        return Some(text.to_string());
    }
    // Anthropic/Bedrock: delta.type == "text_delta", delta.text
    if let Some(text) = v
        .get("delta")
        .and_then(|d| d.get("text"))
        .and_then(|t| t.as_str())
    {
        return Some(text.to_string());
    }
    // Anthropic/Bedrock extended thinking: delta.type == "thinking_delta", delta.thinking
    // Claude 3.7+ thinking blocks can contain PII (model reasons through tool args verbatim)
    if let Some(text) = v
        .get("delta")
        .and_then(|d| d.get("thinking"))
        .and_then(|t| t.as_str())
    {
        return Some(text.to_string());
    }
    // Gemini: candidates[0].content.parts[*].text (concatenate all text parts)
    if let Some(parts) = v
        .get("candidates")
        .and_then(|c| c.get(0))
        .and_then(|c| c.get("content"))
        .and_then(|c| c.get("parts"))
        .and_then(|p| p.as_array())
    {
        let text: String = parts
            .iter()
            .filter_map(|p| p.get("text").and_then(|t| t.as_str()))
            .collect();
        if !text.is_empty() {
            return Some(text);
        }
    }
    None
}

#[allow(clippy::too_many_arguments)]
fn build_streaming_audit_entry(
    audit_id: &str,
    request_id: &str,
    tenant_id: &str,
    method: &str,
    path: &str,
    model: Option<&str>,
    status: u16,
    overhead_ms: f64,
    upstream_ms: f64,
    pii_findings: &[PiiFinding],
    action: &str,
    rule_id: Option<&str>,
    matched_rules: &[crate::policy::MatchedRule],
    retries_made: u32,
    fallback_triggered: bool,
    stats: &StreamStats,
    streaming_scan_enabled: bool,
    provider: &str,
    agent_id: Option<&str>,
    context_snapshot: Option<&Value>,
) -> serde_json::Value {
    // Merge request-time PII findings with streaming PII findings (those that were
    // redacted during stream — tool-policy violations have empty redacted_to and are
    // intentionally excluded from pii_findings; they live only in streaming.findings).
    let streaming_pii: Vec<&PiiFinding> = stats
        .findings
        .iter()
        .filter(|f| !f.redacted_to.is_empty())
        .collect();
    let merged_pii: Vec<&PiiFinding> = pii_findings
        .iter()
        .chain(streaming_pii.iter().copied())
        .collect();
    let has_pii = !merged_pii.is_empty();

    let mut entry = json!({
        "audit_id": audit_id,
        "request_id": request_id,
        "tenant_id": tenant_id,
        "timestamp": Utc::now().to_rfc3339(),
        "agent_id": agent_id,
        "request": {
            "method": method,
            "path": path,
            "model": model,
            "streaming": true,
        },
        "response": { "status_code": status },
        "latency": {
            "upstream_ms": upstream_ms,
            "cadabra_ms": overhead_ms,
            "first_byte_ms": stats.first_byte_ms,
            "stream_duration_ms": stats.stream_duration_ms,
        },
        "pii_findings": merged_pii,
        "enforcement": {
            "action": action,
            "rule_id": rule_id,
            "matched_rules": matched_rules,
            "streaming_action": stats.stream_verdict,
            "observed": action == "flag",
        },
        "retries_made": retries_made,
        "fallback_triggered": fallback_triggered,
        "streaming": {
            "provider": provider,
            "action": stats.stream_verdict,
            "streaming_scan": if streaming_scan_enabled { "enabled" } else { "disabled" },
            "findings": stats.findings,
            "invoked_tools": stats.invoked_tools,
            "bytes_received": stats.bytes_received,
            "bytes_emitted": stats.bytes_emitted,
            "frames_received": stats.frames_received,
            "frames_emitted": stats.frames_emitted,
            "buffer_flushes": {
                "on_boundary": stats.flush_on_boundary,
                "on_size_cap": stats.flush_on_size_cap,
                "on_stream_end": stats.flush_on_stream_end,
            },
            "latency": {
                "first_byte_ms": stats.first_byte_ms.unwrap_or(0.0),
                "stream_duration_ms": stats.stream_duration_ms,
                // cadabra_ms is the sum of PII scan + policy eval time across all flushes;
                // it excludes upstream I/O time (which is in the outer latency.upstream_ms).
                "cadabra_ms": stats.cadabra_ms,
            },
        }
    });
    if let Some(snapshot) = context_snapshot {
        let mut snap = snapshot.clone();
        if has_pii {
            snap["pii_detected"] = json!(true);
            // Also keep data_protection sub-object consistent
            if let Some(dp) = snap["data_protection"].as_object_mut() {
                dp.insert("pii_present".to_string(), json!(true));
            }
        }
        entry["context_snapshot"] = snap;
    }
    entry
}

struct AuditParams<'a> {
    audit_id: &'a str,
    request_id: &'a str,
    method: &'a Method,
    path: &'a str,
    model: Option<&'a str>,
    streaming: bool,
    status: u16,
    overhead_ms: f64,
    upstream_ms: f64,
    pii_findings: &'a [crate::pii::PiiFinding],
    action: &'a str,
    rule_id: Option<&'a str>,
    description: Option<&'a str>,
    regulatory_mapping: &'a [String],
    matched_rules: &'a [crate::policy::MatchedRule],
    retries_made: u32,
    fallback_triggered: bool,
    labels: &'a [crate::policy::DetectionLabel],
    request_payload: Option<&'a str>,
    response_payload: Option<&'a str>,
    tenant_id: &'a str,
    agent_id: Option<&'a str>,
    /// Non-default Cedar context fields for field-in-traffic queries.
    context_snapshot: Option<&'a Value>,
    /// Hold ID when action is "steer" (human-in-the-loop).
    hold_id: Option<&'a str>,
}

/// Truncate a payload string to max_bytes, appending "[…truncated]" if cut.
fn truncate_payload(s: &str, max_bytes: usize) -> String {
    if s.len() <= max_bytes {
        s.to_string()
    } else {
        // Find a valid UTF-8 boundary at or before max_bytes
        let mut end = max_bytes.saturating_sub(14).min(s.len());
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        let truncated = &s[..end];
        format!("{truncated}[…truncated]")
    }
}

/// Determine whether payloads should be retained for this audit entry.
fn should_retain_payload(config: &crate::config::AuditConfig, action: &str) -> bool {
    if config.retain_payloads == "never" {
        return false;
    }
    match config.retain_on.as_str() {
        "always" => true,
        "on_enforcement" => action != "allow",
        _ => false, // "never" or unknown
    }
}

fn build_audit_entry(p: AuditParams<'_>) -> serde_json::Value {
    let mut entry = json!({
        "audit_id": p.audit_id,
        "request_id": p.request_id,
        "timestamp": Utc::now().to_rfc3339(),
        "request": {
            "method": p.method.as_str(),
            "path": p.path,
            "model": p.model,
            "streaming": p.streaming,
        },
        "response": { "status_code": p.status },
        "latency": { "upstream_ms": p.upstream_ms, "cadabra_ms": p.overhead_ms },
        "pii_findings": p.pii_findings,
        "enforcement": {
            "action": p.action,
            "rule_id": p.rule_id,
            "description": p.description,
            "regulatory_mapping": p.regulatory_mapping,
            "matched_rules": p.matched_rules,
            "observed": p.action == "flag",
        },
        "retries_made": p.retries_made,
        "fallback_triggered": p.fallback_triggered,
        "tenant_id": p.tenant_id,
        "agent_id": p.agent_id,
    });
    if let Some(hid) = p.hold_id {
        entry["enforcement"]["hold_id"] = json!(hid);
    }
    if !p.labels.is_empty() {
        entry["labels"] = json!(p.labels);
    }
    if let Some(snapshot) = p.context_snapshot {
        entry["context_snapshot"] = snapshot.clone();
    }
    if let Some(payload) = p.request_payload {
        entry["request_payload"] = json!(payload);
    }
    if let Some(payload) = p.response_payload {
        entry["response_payload"] = json!(payload);
    }
    entry
}

fn record_perf(
    state: &PipelineState,
    eg: &EgHeaders,
    model: Option<&str>,
    provider: Option<&str>,
    streaming: bool,
    upstream_ms: f64,
    timing: &PhaseTiming,
) {
    if !state.config.performance.enabled {
        return;
    }
    let sample = PerformanceSample {
        timestamp: Utc::now().to_rfc3339(),
        agent_id: eg.agent_id.clone(),
        model: model.map(|s| s.to_string()),
        provider: provider.map(|s| s.to_string()),
        streaming,
        total_ms: timing.total_overhead_ms(),
        upstream_ms,
        auth_ms: timing.auth_ms,
        agent_extract_ms: timing.agent_extract_ms,
        model_routing_ms: timing.model_routing_ms,
        pii_request_ms: timing.pii_request_ms,
        detectors_request_ms: timing.detectors_request_ms,
        cedar_request_ms: timing.cedar_request_ms,
        custom_policy_ms: timing.custom_policy_ms,
        pii_response_ms: timing.pii_response_ms,
        tool_check_ms: timing.tool_check_ms,
        cedar_response_ms: timing.cedar_response_ms,
        handover_ms: timing.handover_ms,
        audit_write_ms: timing.audit_write_ms,
        event_store_ms: timing.event_store_ms,
        sandbox_enrich_ms: timing.sandbox_enrich_ms,
    };
    state.perf.record(sample);
    crate::routes::health::record_request();
}

/// Convert detector results + PII findings into DetectionLabels for audit.
fn build_labels(
    detector_results: &[DetectionResult],
    pii_findings: &[PiiFinding],
    policy_action: &str,
    rule_id: Option<&str>,
) -> Vec<crate::policy::DetectionLabel> {
    use std::collections::HashMap;
    let mut labels = Vec::new();

    // Labels from content detectors
    for result in detector_results {
        if result.detected {
            for finding in &result.findings {
                let mut metadata = HashMap::new();
                metadata.insert("pattern".to_string(), finding.pattern_name.clone());
                metadata.insert("category".to_string(), finding.category.clone());
                if !finding.matched_text.is_empty() {
                    metadata.insert("matched_text".to_string(), finding.matched_text.clone());
                }
                labels.push(crate::policy::DetectionLabel {
                    label_type: result.detector_type.clone(),
                    detector: format!("regex_{}", result.detector_type),
                    confidence: finding.confidence,
                    location: "request".to_string(),
                    metadata,
                });
            }
        }
    }

    // Labels from PII findings
    for finding in pii_findings {
        let mut metadata = HashMap::new();
        metadata.insert("redacted_to".to_string(), finding.redacted_to.clone());
        metadata.insert("count".to_string(), finding.count.to_string());
        labels.push(crate::policy::DetectionLabel {
            label_type: "pii".to_string(),
            detector: "regex_pii".to_string(),
            confidence: 1.0,
            location: finding.location.clone(),
            metadata,
        });
    }

    // Label from policy decision
    if policy_action != "allow" {
        let mut metadata = HashMap::new();
        if let Some(rid) = rule_id {
            metadata.insert("rule_id".to_string(), rid.to_string());
        }
        labels.push(crate::policy::DetectionLabel {
            label_type: "policy".to_string(),
            detector: "cedar".to_string(),
            confidence: 1.0,
            location: "request".to_string(),
            metadata,
        });
    }

    labels
}

/// Check all relevant rate limits for the current request.
///
/// Checks in order: global → tenant → api_key → agent → model.
/// Each check increments the counter by 1 (request count).
/// Returns a 429 response body if any limit is breached, or `None` if allowed.
fn check_rate_limits(
    token_provider: &dyn TokenProvider,
    tenant_id: &str,
    api_key_hash: Option<&str>,
    agent_id: Option<&str>,
    model: Option<&str>,
    now: &str,
) -> Option<axum::response::Response> {
    // Build list of (scope, scope_id) pairs to check
    let mut checks: Vec<(&str, String)> = Vec::new();
    checks.push(("global", "*".to_string()));
    if tenant_id != "default" {
        checks.push(("tenant", tenant_id.to_string()));
    }
    if let Some(kh) = api_key_hash {
        checks.push(("api_key", kh.to_string()));
    }
    if let Some(aid) = agent_id {
        checks.push(("agent", aid.to_string()));
    }
    if let Some(m) = model {
        checks.push(("model", m.to_string()));
    }

    for (scope, scope_id) in checks {
        match token_provider.check_and_increment(scope, &scope_id, "request", 1.0, now) {
            Ok(RateLimitCheckResult::Exceeded {
                limit_type,
                window,
                limit_value,
                current,
                ..
            }) => {
                let body = serde_json::json!({
                    "error": "rate_limit_exceeded",
                    "scope": scope,
                    "window": window,
                    "limit": limit_value,
                    "current": current,
                });
                let resp =
                    (axum::http::StatusCode::TOO_MANY_REQUESTS, axum::Json(body)).into_response();
                tracing::warn!(
                    scope = scope,
                    scope_id = %scope_id,
                    limit_type = %limit_type,
                    window = %window,
                    limit = limit_value,
                    current = current,
                    "rate limit exceeded"
                );
                return Some(resp);
            }
            Ok(RateLimitCheckResult::Allowed) => {}
            Err(e) => {
                // Fail-open: log and continue
                tracing::warn!(error = %e, scope = scope, "rate limit check error — fail-open");
            }
        }
    }

    None
}

/// SHA-256-hash an API key for use as a stable, non-reversible identifier.
pub fn hash_api_key(key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    format!("{:x}", hasher.finalize())
}

pub fn map_to_header_map(
    map: &std::collections::HashMap<String, String>,
) -> reqwest::header::HeaderMap {
    let mut hm = reqwest::header::HeaderMap::new();
    for (k, v) in map {
        if let (Ok(name), Ok(val)) = (
            reqwest::header::HeaderName::from_bytes(k.as_bytes()),
            reqwest::header::HeaderValue::from_str(v),
        ) {
            hm.insert(name, val);
        }
    }
    hm
}

/// T-903: Extract tool call names from a streaming delta chunk for any provider.
///
/// - OpenAI/Azure: `choices[0].delta.tool_calls[*].function.name`
/// - Anthropic/Bedrock: `content_block_start` event with `content_block.type == "tool_use"`
/// - Gemini: `candidates[0].content.parts[*].functionCall.name`
///   (do NOT rely on `finishReason == "tool_calls"` — Gemini reports "STOP" even for tool calls)
fn extract_streaming_tool_calls(v: &Value, provider: &str, accumulated: &mut Vec<String>) {
    match provider {
        "anthropic" | "bedrock" => {
            // Anthropic streaming: content_block_start event carries the tool name
            if v.get("type").and_then(|t| t.as_str()) == Some("content_block_start") {
                if let Some(name) = v
                    .get("content_block")
                    .filter(|cb| cb.get("type").and_then(|t| t.as_str()) == Some("tool_use"))
                    .and_then(|cb| cb.get("name"))
                    .and_then(|n| n.as_str())
                {
                    if !name.is_empty() && !accumulated.contains(&name.to_string()) {
                        accumulated.push(name.to_string());
                    }
                }
            }
        }
        "gemini" => {
            // Gemini: functionCall parts — finishReason is "STOP" even for tool calls, do not use it
            if let Some(parts) = v
                .get("candidates")
                .and_then(|c| c.get(0))
                .and_then(|c| c.get("content"))
                .and_then(|c| c.get("parts"))
                .and_then(|p| p.as_array())
            {
                for part in parts {
                    if let Some(name) = part
                        .get("functionCall")
                        .and_then(|fc| fc.get("name"))
                        .and_then(|n| n.as_str())
                    {
                        if !name.is_empty() && !accumulated.contains(&name.to_string()) {
                            accumulated.push(name.to_string());
                        }
                    }
                }
            }
        }
        _ => {
            // OpenAI/Azure: name only appears in the first delta per tool call index
            let tool_calls = match v
                .get("choices")
                .and_then(|c| c.get(0))
                .and_then(|c| c.get("delta"))
                .and_then(|d| d.get("tool_calls"))
                .and_then(|tc| tc.as_array())
            {
                Some(arr) => arr,
                None => return,
            };
            for tc in tool_calls {
                if let Some(name) = tc
                    .get("function")
                    .and_then(|f| f.get("name"))
                    .and_then(|n| n.as_str())
                {
                    if !name.is_empty() && !accumulated.contains(&name.to_string()) {
                        accumulated.push(name.to_string());
                    }
                }
            }
        }
    }
}

/// Extract tool call argument deltas from a streaming chunk and accumulate
/// per tool-call index. OpenAI streams arguments as JSON fragments across
/// multiple SSE events: `choices[0].delta.tool_calls[{index, function: {arguments: "..."}}]`.
/// Each delta's `arguments` field is appended to the existing entry for that index.
fn extract_streaming_tool_args(
    v: &Value,
    provider: &str,
    accumulated_args: &mut std::collections::HashMap<usize, String>,
) {
    // Anthropic/Bedrock: arguments arrive as input_json_delta events
    if matches!(provider, "anthropic" | "bedrock") {
        if v.get("type").and_then(|t| t.as_str()) == Some("content_block_delta") {
            if let Some(partial) = v
                .get("delta")
                .filter(|d| d.get("type").and_then(|t| t.as_str()) == Some("input_json_delta"))
                .and_then(|d| d.get("partial_json"))
                .and_then(|j| j.as_str())
            {
                let index = v.get("index").and_then(|i| i.as_u64()).unwrap_or(0) as usize;
                accumulated_args.entry(index).or_default().push_str(partial);
            }
        }
        return;
    }
    // Gemini: args are delivered in one shot in the functionCall object — no streaming fragments
    if provider == "gemini" {
        return;
    }
    // OpenAI/Azure
    let tool_calls = match v
        .get("choices")
        .and_then(|c| c.get(0))
        .and_then(|c| c.get("delta"))
        .and_then(|d| d.get("tool_calls"))
        .and_then(|tc| tc.as_array())
    {
        Some(arr) => arr,
        None => return,
    };
    for tc in tool_calls {
        let index = tc.get("index").and_then(|i| i.as_u64()).unwrap_or(0) as usize;
        if let Some(args_fragment) = tc
            .get("function")
            .and_then(|f| f.get("arguments"))
            .and_then(|a| a.as_str())
        {
            accumulated_args
                .entry(index)
                .or_default()
                .push_str(args_fragment);
        }
    }
}

/// T-902: Extract tool/function names from the request `tools` array.
/// Returns (Vec<tool_name_strings>, count). Works for OpenAI format:
/// `tools: [{ "type": "function", "function": { "name": "..." } }, ...]`
fn extract_requested_tools(body: &Value) -> (Vec<String>, usize) {
    let tools = match body.get("tools").and_then(|t| t.as_array()) {
        Some(arr) => arr,
        None => return (vec![], 0),
    };
    let names: Vec<String> = tools
        .iter()
        .filter_map(|t| {
            t.get("function")
                .and_then(|f| f.get("name"))
                .and_then(|n| n.as_str())
                .map(|s| s.to_string())
        })
        .collect();
    let count = names.len();
    (names, count)
}

/// Compute whether the current time falls within the tenant's business hours window.
/// Returns false if timezone is invalid or window is not configured/malformed.
fn compute_business_hours_active(timezone_str: &str, window: Option<&str>) -> bool {
    let window = match window {
        Some(w) => w,
        None => return false,
    };
    let tz: Tz = match timezone_str.parse() {
        Ok(tz) => tz,
        Err(_) => return false,
    };
    // Parse "HH:MM-HH:MM"
    let parts: Vec<&str> = window.split('-').collect();
    if parts.len() != 2 {
        return false;
    }
    let parse_hhmm = |s: &str| -> Option<(u32, u32)> {
        let hm: Vec<&str> = s.split(':').collect();
        if hm.len() != 2 {
            return None;
        }
        Some((hm[0].parse().ok()?, hm[1].parse().ok()?))
    };
    let (start_h, start_m) = match parse_hhmm(parts[0]) {
        Some(v) => v,
        None => return false,
    };
    let (end_h, end_m) = match parse_hhmm(parts[1]) {
        Some(v) => v,
        None => return false,
    };
    let now = Utc::now().with_timezone(&tz);
    let now_minutes = now.hour() * 60 + now.minute();
    let start_minutes = start_h * 60 + start_m;
    let end_minutes = end_h * 60 + end_m;
    if start_minutes <= end_minutes {
        now_minutes >= start_minutes && now_minutes < end_minutes
    } else {
        // Overnight window (e.g. "22:00-06:00")
        now_minutes >= start_minutes || now_minutes < end_minutes
    }
}

/// Build Cedar context with backward-compatible flat fields AND namespaced
/// fields for the new observation-mode architecture.
/// Both flat (`injection_detected`) and nested (`agent_integrity.injection_detected`)
/// forms are emitted so existing and new policies both evaluate correctly.
fn build_cedar_context_compat(params: &ContextParams) -> Value {
    let mut ctx = build_context(params);

    if let Some(obj) = ctx.as_object_mut() {
        obj.insert(
            "agent_integrity".to_string(),
            json!({
                "injection_detected": params.injection_detected,
                "jailbreak_detected": params.jailbreak_detected,
            }),
        );
        obj.insert(
            "data_protection".to_string(),
            json!({
                "pii_present": params.pii_detected,
                "confidential_detected": params.confidential_detected,
                "exfiltration_detected": params.exfiltration_detected,
            }),
        );
        obj.insert(
            "content_safety".to_string(),
            json!({
                "threat_detected": params.threat_detected,
                "bias_detected": params.bias_detected,
            }),
        );
        obj.insert(
            "identity_safety".to_string(),
            json!({
                "disclosure_detected": params.identity_claim_detected,
            }),
        );
        obj.insert(
            "tool_governance".to_string(),
            json!({
                "unauthorized_detected": params.unauthorized_tool_detected,
            }),
        );
        obj.insert(
            "supply_chain".to_string(),
            json!({
                "mcp_server_approved": params.mcp_server_approved,
                "mcp_server_id": params.mcp_server_id,
            }),
        );
    }
    ctx
}

/// Extract user message text from the request body for content detection.
/// Handles OpenAI format: `messages[].content` where `role == "user"`.
fn extract_user_text(body: &Value) -> String {
    let mut text = String::new();
    if let Some(messages) = body.get("messages").and_then(|m| m.as_array()) {
        for msg in messages {
            if msg.get("role").and_then(|r| r.as_str()) == Some("user") {
                if let Some(content) = msg.get("content").and_then(|c| c.as_str()) {
                    if !text.is_empty() {
                        text.push(' ');
                    }
                    text.push_str(content);
                }
            }
        }
    }
    // Fallback: if no messages array, check for a top-level "input" or "prompt" field
    if text.is_empty() {
        if let Some(input) = body.get("input").and_then(|i| i.as_str()) {
            text.push_str(input);
        } else if let Some(prompt) = body.get("prompt").and_then(|p| p.as_str()) {
            text.push_str(prompt);
        }
    }
    text
}

/// T-901: Extract tool call names from a non-streaming response — any provider.
///
/// - Anthropic/Bedrock: `content[*].type == "tool_use"` → `content[*].name`
/// - Gemini: `candidates[0].content.parts[*].functionCall.name`
/// - OpenAI/Azure: `choices[0].message.tool_calls[*].function.name`
///
/// Auto-detects format from response schema; no explicit provider param needed.
fn extract_response_tool_calls(body_bytes: &[u8]) -> (Vec<String>, usize) {
    let body: Value = match serde_json::from_slice(body_bytes) {
        Ok(v) => v,
        Err(_) => return (vec![], 0),
    };

    // Anthropic/Bedrock: content[] array with type == "tool_use"
    if let Some(content) = body.get("content").and_then(|c| c.as_array()) {
        let names: Vec<String> = content
            .iter()
            .filter_map(|item| {
                if item.get("type").and_then(|t| t.as_str()) == Some("tool_use") {
                    item.get("name")
                        .and_then(|n| n.as_str())
                        .map(|s| s.to_string())
                } else {
                    None
                }
            })
            .collect();
        if !names.is_empty() {
            let count = names.len();
            return (names, count);
        }
    }

    // Gemini: candidates[0].content.parts[*].functionCall
    if let Some(parts) = body
        .get("candidates")
        .and_then(|c| c.get(0))
        .and_then(|c| c.get("content"))
        .and_then(|c| c.get("parts"))
        .and_then(|p| p.as_array())
    {
        let names: Vec<String> = parts
            .iter()
            .filter_map(|part| {
                part.get("functionCall")
                    .and_then(|fc| fc.get("name"))
                    .and_then(|n| n.as_str())
                    .map(|s| s.to_string())
            })
            .collect();
        if !names.is_empty() {
            let count = names.len();
            return (names, count);
        }
    }

    // OpenAI/Azure: choices[0].message.tool_calls[*].function.name
    let tool_calls = match body
        .get("choices")
        .and_then(|c| c.get(0))
        .and_then(|c| c.get("message"))
        .and_then(|m| m.get("tool_calls"))
        .and_then(|tc| tc.as_array())
    {
        Some(arr) => arr,
        None => return (vec![], 0),
    };
    let names: Vec<String> = tool_calls
        .iter()
        .filter_map(|tc| {
            tc.get("function")
                .and_then(|f| f.get("name"))
                .and_then(|n| n.as_str())
                .map(|s| s.to_string())
        })
        .collect();
    let count = names.len();
    (names, count)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    #[allow(clippy::too_many_arguments)]
    fn make_stats(
        bytes_received: usize,
        bytes_emitted: usize,
        frames_received: usize,
        frames_emitted: usize,
        flush_on_boundary: usize,
        flush_on_size_cap: usize,
        flush_on_stream_end: usize,
        first_byte_ms: Option<f64>,
        stream_duration_ms: f64,
        cadabra_ms: f64,
        verdict: &str,
    ) -> StreamStats {
        StreamStats {
            bytes_received,
            bytes_emitted,
            frames_received,
            frames_emitted,
            findings: vec![],
            first_byte_ms,
            stream_duration_ms,
            flush_on_boundary,
            flush_on_size_cap,
            flush_on_stream_end,
            stream_verdict: verdict.to_string(),
            invoked_tools: vec![],
            cadabra_ms,
        }
    }

    fn call_build(stats: &StreamStats, streaming_enabled: bool, provider: &str) -> Value {
        build_streaming_audit_entry(
            "audit-1",
            "req-1",
            "test-tenant",
            "POST",
            "/v1/chat/completions",
            Some("gpt-4o"),
            200,
            5.0,
            120.0,
            &[],
            "allow",
            None,
            &[],
            0,
            false,
            stats,
            streaming_enabled,
            provider,
            None,
            None,
        )
    }

    #[test]
    fn streaming_audit_has_all_required_top_level_fields() {
        let stats = make_stats(1000, 900, 10, 10, 3, 0, 1, Some(45.2), 500.0, 12.3, "allow");
        let entry = call_build(&stats, true, "openai");
        let streaming = &entry["streaming"];

        // Required by streaming-decision.v1.json
        assert!(
            !streaming["provider"].is_null(),
            "missing streaming.provider"
        );
        assert!(!streaming["action"].is_null(), "missing streaming.action");
        assert!(
            !streaming["bytes_received"].is_null(),
            "missing streaming.bytes_received"
        );
        assert!(
            !streaming["bytes_emitted"].is_null(),
            "missing streaming.bytes_emitted"
        );
        assert!(
            !streaming["findings"].is_null(),
            "missing streaming.findings"
        );
        assert!(
            !streaming["invoked_tools"].is_null(),
            "missing streaming.invoked_tools"
        );
        assert!(!streaming["latency"].is_null(), "missing streaming.latency");
        assert!(
            !streaming["buffer_flushes"].is_null(),
            "missing streaming.buffer_flushes"
        );
        assert!(
            !streaming["frames_received"].is_null(),
            "missing streaming.frames_received"
        );
        assert!(
            !streaming["frames_emitted"].is_null(),
            "missing streaming.frames_emitted"
        );
        assert!(
            !streaming["streaming_scan"].is_null(),
            "missing streaming.streaming_scan"
        );
    }

    #[test]
    fn streaming_audit_buffer_flushes_match_stats() {
        let stats = make_stats(500, 490, 5, 5, 7, 2, 1, Some(30.0), 200.0, 8.0, "allow");
        let entry = call_build(&stats, true, "openai");
        let flushes = &entry["streaming"]["buffer_flushes"];

        assert_eq!(flushes["on_boundary"], 7);
        assert_eq!(flushes["on_size_cap"], 2);
        assert_eq!(flushes["on_stream_end"], 1);
    }

    #[test]
    fn streaming_scan_disabled_when_streaming_not_enabled() {
        let stats = make_stats(200, 200, 2, 2, 0, 0, 0, Some(10.0), 100.0, 0.0, "allow");
        let entry = call_build(&stats, false, "openai");
        assert_eq!(entry["streaming"]["streaming_scan"], "disabled");
    }

    #[test]
    fn streaming_scan_enabled_when_streaming_enabled() {
        let stats = make_stats(200, 200, 2, 2, 1, 0, 1, Some(10.0), 100.0, 2.5, "allow");
        let entry = call_build(&stats, true, "openai");
        assert_eq!(entry["streaming"]["streaming_scan"], "enabled");
    }

    #[test]
    fn streaming_latency_first_byte_ms_non_negative() {
        let stats = make_stats(100, 100, 1, 1, 0, 0, 1, Some(45.2), 300.0, 3.0, "allow");
        let entry = call_build(&stats, true, "openai");
        let first_byte = entry["streaming"]["latency"]["first_byte_ms"]
            .as_f64()
            .expect("first_byte_ms should be a number");
        assert!(
            first_byte >= 0.0,
            "first_byte_ms must be non-negative, got {first_byte}"
        );
    }

    #[test]
    fn streaming_latency_cadabra_ms_is_enforcement_overhead() {
        let stats = make_stats(400, 380, 4, 4, 2, 0, 1, Some(20.0), 250.0, 11.5, "allow");
        let entry = call_build(&stats, true, "openai");
        let cadabra = entry["streaming"]["latency"]["cadabra_ms"]
            .as_f64()
            .expect("cadabra_ms should be a number");
        // Must equal stats.cadabra_ms (enforcement overhead), not the overhead_ms arg (5.0)
        assert_eq!(
            cadabra, 11.5,
            "cadabra_ms should be enforcement overhead sum, not total overhead"
        );
    }

    #[test]
    fn streaming_provider_set_correctly() {
        let stats = make_stats(300, 290, 3, 3, 1, 0, 1, Some(25.0), 150.0, 5.0, "allow");

        let entry_openai = call_build(&stats, true, "openai");
        assert_eq!(entry_openai["streaming"]["provider"], "openai");

        let entry_anthropic = call_build(&stats, true, "anthropic");
        assert_eq!(entry_anthropic["streaming"]["provider"], "anthropic");
    }

    #[test]
    fn streaming_action_reflects_stream_verdict() {
        let stats_block = make_stats(100, 20, 1, 1, 0, 0, 0, Some(5.0), 50.0, 1.0, "block");
        let entry = call_build(&stats_block, true, "openai");
        assert_eq!(entry["streaming"]["action"], "block");
    }

    // ── T-902: Request tool extraction tests ────────────────────────────────

    #[test]
    fn extract_requested_tools_openai_format() {
        let body = json!({
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "hello"}],
            "tools": [
                {"type": "function", "function": {"name": "get_weather", "parameters": {}}},
                {"type": "function", "function": {"name": "send_email", "parameters": {}}},
            ]
        });
        let (names, count) = extract_requested_tools(&body);
        assert_eq!(count, 2);
        assert_eq!(names, vec!["get_weather", "send_email"]);
    }

    #[test]
    fn extract_requested_tools_no_tools() {
        let body = json!({"model": "gpt-4o", "messages": []});
        let (names, count) = extract_requested_tools(&body);
        assert_eq!(count, 0);
        assert!(names.is_empty());
    }

    #[test]
    fn extract_requested_tools_empty_array() {
        let body = json!({"model": "gpt-4o", "tools": []});
        let (names, count) = extract_requested_tools(&body);
        assert_eq!(count, 0);
        assert!(names.is_empty());
    }

    // ── T-901: Response tool-call extraction tests ──────────────────────────

    #[test]
    fn extract_response_tool_calls_single() {
        let body = json!({
            "choices": [{
                "message": {
                    "role": "assistant",
                    "tool_calls": [{
                        "id": "call_1",
                        "type": "function",
                        "function": {"name": "get_weather", "arguments": "{\"city\":\"SF\"}"}
                    }]
                }
            }]
        });
        let bytes = serde_json::to_vec(&body).unwrap();
        let (names, count) = extract_response_tool_calls(&bytes);
        assert_eq!(count, 1);
        assert_eq!(names, vec!["get_weather"]);
    }

    #[test]
    fn extract_response_tool_calls_multiple() {
        let body = json!({
            "choices": [{
                "message": {
                    "role": "assistant",
                    "tool_calls": [
                        {"id": "call_1", "type": "function", "function": {"name": "get_weather", "arguments": "{}"}},
                        {"id": "call_2", "type": "function", "function": {"name": "send_email", "arguments": "{}"}},
                        {"id": "call_3", "type": "function", "function": {"name": "delete_file", "arguments": "{}"}},
                    ]
                }
            }]
        });
        let bytes = serde_json::to_vec(&body).unwrap();
        let (names, count) = extract_response_tool_calls(&bytes);
        assert_eq!(count, 3);
        assert_eq!(names, vec!["get_weather", "send_email", "delete_file"]);
    }

    #[test]
    fn extract_response_tool_calls_no_tool_calls() {
        let body = json!({
            "choices": [{
                "message": {
                    "role": "assistant",
                    "content": "Hello!"
                }
            }]
        });
        let bytes = serde_json::to_vec(&body).unwrap();
        let (names, count) = extract_response_tool_calls(&bytes);
        assert_eq!(count, 0);
        assert!(names.is_empty());
    }

    #[test]
    fn extract_response_tool_calls_invalid_json() {
        let (names, count) = extract_response_tool_calls(b"not json");
        assert_eq!(count, 0);
        assert!(names.is_empty());
    }

    // ── T-903: Streaming tool-call extraction tests ─────────────────────────

    #[test]
    fn extract_streaming_tool_calls_first_delta() {
        let delta = json!({
            "choices": [{
                "delta": {
                    "tool_calls": [{
                        "index": 0,
                        "function": {"name": "get_weather", "arguments": ""}
                    }]
                }
            }]
        });
        let mut names = vec![];
        extract_streaming_tool_calls(&delta, "openai", &mut names);
        assert_eq!(names, vec!["get_weather"]);
    }

    #[test]
    fn extract_streaming_tool_calls_argument_delta_no_duplicate() {
        // First delta has the name
        let delta1 = json!({
            "choices": [{"delta": {"tool_calls": [{"index": 0, "function": {"name": "get_weather", "arguments": ""}}]}}]
        });
        // Subsequent deltas have only arguments
        let delta2 = json!({
            "choices": [{"delta": {"tool_calls": [{"index": 0, "function": {"arguments": "{\"city\":"}}]}}]
        });
        let mut names = vec![];
        extract_streaming_tool_calls(&delta1, "openai", &mut names);
        extract_streaming_tool_calls(&delta2, "openai", &mut names);
        assert_eq!(names, vec!["get_weather"]); // no duplicate
    }

    #[test]
    fn extract_streaming_tool_calls_multiple_tools() {
        let delta1 = json!({
            "choices": [{"delta": {"tool_calls": [{"index": 0, "function": {"name": "get_weather"}}]}}]
        });
        let delta2 = json!({
            "choices": [{"delta": {"tool_calls": [{"index": 1, "function": {"name": "send_email"}}]}}]
        });
        let mut names = vec![];
        extract_streaming_tool_calls(&delta1, "openai", &mut names);
        extract_streaming_tool_calls(&delta2, "openai", &mut names);
        assert_eq!(names, vec!["get_weather", "send_email"]);
    }

    #[test]
    fn extract_streaming_tool_calls_no_tool_calls_in_delta() {
        let delta = json!({"choices": [{"delta": {"content": "Hello"}}]});
        let mut names = vec![];
        extract_streaming_tool_calls(&delta, "openai", &mut names);
        assert!(names.is_empty());
    }

    #[test]
    fn extract_delta_text_bedrock_thinking_delta() {
        let v = serde_json::json!({
            "type": "content_block_delta",
            "index": 0,
            "delta": {"type": "thinking_delta", "thinking": "The user's SSN is 123-45-6789"}
        });
        assert_eq!(
            extract_delta_text(&v),
            Some("The user's SSN is 123-45-6789".to_string()),
            "thinking_delta text must be extracted for PII scanning"
        );
    }

    #[test]
    fn extract_delta_text_text_delta_still_extracted() {
        let v = serde_json::json!({
            "type": "content_block_delta",
            "index": 0,
            "delta": {"type": "text_delta", "text": "hello"}
        });
        assert_eq!(extract_delta_text(&v), Some("hello".to_string()));
    }

    #[test]
    fn extract_delta_text_signature_delta_returns_none() {
        let v = serde_json::json!({
            "type": "content_block_delta",
            "index": 0,
            "delta": {"type": "signature_delta", "signature": "base64encodedXYZ=="}
        });
        assert_eq!(
            extract_delta_text(&v),
            None,
            "signature_delta must not be extracted"
        );
    }

    #[test]
    fn extract_streaming_tool_calls_anthropic_content_block_start() {
        let delta = json!({
            "type": "content_block_start",
            "index": 1,
            "content_block": { "type": "tool_use", "id": "toolu_ABC", "name": "my_tool", "input": {} }
        });
        let mut names = vec![];
        extract_streaming_tool_calls(&delta, "anthropic", &mut names);
        assert_eq!(names, vec!["my_tool"]);
    }

    #[test]
    fn extract_streaming_tool_calls_bedrock_tool_use() {
        let delta = json!({
            "type": "content_block_start",
            "index": 0,
            "content_block": { "type": "tool_use", "id": "toolu_XYZ", "name": "list_s3_buckets", "input": {} }
        });
        let mut names = vec![];
        extract_streaming_tool_calls(&delta, "bedrock", &mut names);
        assert_eq!(names, vec!["list_s3_buckets"]);
    }

    #[test]
    fn extract_streaming_tool_calls_gemini_function_call() {
        let delta = json!({
            "candidates": [{
                "content": {
                    "parts": [{
                        "functionCall": { "name": "get_weather", "args": { "location": "Paris" } }
                    }]
                }
            }]
        });
        let mut names = vec![];
        extract_streaming_tool_calls(&delta, "gemini", &mut names);
        assert_eq!(names, vec!["get_weather"]);
    }

    #[test]
    fn extract_response_tool_calls_anthropic_content_array() {
        let body = json!({
            "id": "msg_abc",
            "type": "message",
            "content": [
                { "type": "text", "text": "I'll call the tool." },
                { "type": "tool_use", "id": "toolu_1", "name": "get_weather", "input": { "city": "SF" } }
            ]
        });
        let bytes = serde_json::to_vec(&body).unwrap();
        let (names, count) = extract_response_tool_calls(&bytes);
        assert_eq!(count, 1);
        assert_eq!(names, vec!["get_weather"]);
    }

    #[test]
    fn extract_response_tool_calls_gemini_function_call() {
        let body = json!({
            "candidates": [{
                "content": {
                    "parts": [{
                        "functionCall": { "name": "get_weather", "args": { "location": "Paris" } }
                    }]
                }
            }]
        });
        let bytes = serde_json::to_vec(&body).unwrap();
        let (names, count) = extract_response_tool_calls(&bytes);
        assert_eq!(count, 1);
        assert_eq!(names, vec!["get_weather"]);
    }

    // ── invoked_tools audit coverage ──────────────────────────────────────

    #[test]
    fn invoked_tools_appear_in_audit_json_when_populated() {
        let mut stats = make_stats(500, 490, 6, 6, 2, 0, 1, Some(15.0), 300.0, 4.0, "allow");
        stats.invoked_tools = vec!["list_tickets".to_string(), "get_customer".to_string()];
        let entry = call_build(&stats, true, "openai");
        let tools = entry["streaming"]["invoked_tools"]
            .as_array()
            .expect("streaming.invoked_tools must be a JSON array");
        assert_eq!(tools.len(), 2);
        assert_eq!(tools[0], "list_tickets");
        assert_eq!(tools[1], "get_customer");
    }

    #[test]
    fn invoked_tools_is_empty_array_not_null_when_no_tools_called() {
        let stats = make_stats(200, 200, 3, 3, 1, 0, 1, Some(10.0), 150.0, 2.0, "allow");
        let entry = call_build(&stats, true, "openai");
        let tools = &entry["streaming"]["invoked_tools"];
        assert!(
            !tools.is_null(),
            "streaming.invoked_tools must be present even when empty"
        );
        assert_eq!(
            tools.as_array().unwrap().len(),
            0,
            "streaming.invoked_tools must be an empty array when no tools were invoked"
        );
    }

    #[test]
    fn invoked_tools_populated_from_accumulation_across_frames() {
        // Simulate what the streaming loop does: accumulate names from deltas,
        // then move them into StreamStats.invoked_tools for the audit entry.
        let frame1 = json!({
            "choices": [{"delta": {"tool_calls": [{"index": 0, "function": {"name": "issue_refund_simulated", "arguments": ""}}]}}]
        });
        let frame2 = json!({
            "choices": [{"delta": {"tool_calls": [{"index": 1, "function": {"name": "delete_record_simulated", "arguments": ""}}]}}]
        });
        let mut accumulated = vec![];
        extract_streaming_tool_calls(&frame1, "openai", &mut accumulated);
        extract_streaming_tool_calls(&frame2, "openai", &mut accumulated);
        assert_eq!(accumulated.len(), 2);

        let mut stats = make_stats(300, 295, 4, 4, 1, 0, 1, Some(8.0), 200.0, 3.0, "flag");
        stats.invoked_tools = accumulated;
        let entry = call_build(&stats, true, "openai");
        let tools = entry["streaming"]["invoked_tools"].as_array().unwrap();
        assert_eq!(tools.len(), 2);
        assert!(tools.contains(&json!("issue_refund_simulated")));
        assert!(tools.contains(&json!("delete_record_simulated")));
    }

    #[test]
    fn tool_policy_finding_has_correct_location_and_matched_text() {
        // Simulates the pipeline writing a finding when Cedar flags a streaming tool call.
        // invoked_tools and streaming.findings are both populated; both appear in audit JSON.
        let tool_names = vec![
            "delete_record_simulated".to_string(),
            "issue_refund_simulated".to_string(),
        ];
        let mut stats = make_stats(400, 400, 5, 5, 1, 0, 1, Some(12.0), 250.0, 8.0, "flag");
        stats.invoked_tools = tool_names.clone();
        stats.findings.push(PiiFinding {
            pattern: "default-tool-governance".to_string(),
            redacted_to: String::new(),
            count: tool_names.len(),
            location: "streaming_response_tool_calls".to_string(),
            matched_text: Some(tool_names.join(",")),
        });

        let entry = call_build(&stats, true, "openai");
        let findings = entry["streaming"]["findings"]
            .as_array()
            .expect("findings must be array");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0]["location"], "streaming_response_tool_calls");
        assert_eq!(
            findings[0]["matched_text"],
            "delete_record_simulated,issue_refund_simulated"
        );
        // invoked_tools also recorded unconditionally alongside the finding
        let tools = entry["streaming"]["invoked_tools"].as_array().unwrap();
        assert_eq!(tools.len(), 2);

        // Tool-policy findings (empty redacted_to) must NOT bleed into top-level pii_findings
        assert!(
            entry["pii_findings"].as_array().unwrap().is_empty(),
            "tool-policy findings with empty redacted_to must not appear in top-level pii_findings"
        );
        // No context_snapshot was passed, so it stays null; pii_detected must not be set to true
        assert!(
            !entry["context_snapshot"]["pii_detected"].as_bool().unwrap_or(false),
            "context_snapshot.pii_detected must not be true when only tool-policy finding is present"
        );
    }

    #[test]
    fn streaming_pii_in_tool_args_surfaces_in_top_level_pii_findings() {
        // Regression: email found in streaming_tool_args must appear in pii_findings and
        // set context_snapshot.pii_detected = true. Previously these lived only in
        // streaming.findings while pii_findings stayed empty and pii_detected stayed false.
        let mut stats = make_stats(500, 490, 6, 6, 1, 0, 1, Some(5.0), 335.0, 5.9, "flag");
        stats.findings.push(PiiFinding {
            pattern: "email".to_string(),
            redacted_to: "[REDACTED_EMAIL]".to_string(),
            count: 1,
            location: "streaming_tool_args".to_string(),
            matched_text: None,
        });

        // Pass a context_snapshot with pii_detected=false (as Cedar sets at request time)
        let snapshot = json!({
            "pii_detected": false,
            "data_protection": {
                "pii_present": false,
                "confidential_detected": false,
                "exfiltration_detected": false
            },
            "model": "gpt-5.4-nano"
        });

        let entry = build_streaming_audit_entry(
            "audit-pii-1",
            "req-pii-1",
            "test-tenant",
            "POST",
            "/v1/chat/completions",
            Some("gpt-5.4-nano"),
            200,
            5.0,
            335.0,
            &[],
            "flag",
            None,
            &[],
            0,
            false,
            &stats,
            true,
            "openai",
            Some("force:support.voice"),
            Some(&snapshot),
        );

        // Top-level pii_findings must contain the streaming finding
        let pii_findings = entry["pii_findings"]
            .as_array()
            .expect("pii_findings must be array");
        assert_eq!(
            pii_findings.len(),
            1,
            "email finding from streaming_tool_args must appear in pii_findings"
        );
        assert_eq!(pii_findings[0]["location"], "streaming_tool_args");
        assert_eq!(pii_findings[0]["pattern"], "email");

        // context_snapshot.pii_detected must be patched to true
        assert_eq!(
            entry["context_snapshot"]["pii_detected"],
            json!(true),
            "context_snapshot.pii_detected must be true when streaming PII found"
        );
        // data_protection.pii_present must also be updated
        assert_eq!(
            entry["context_snapshot"]["data_protection"]["pii_present"],
            json!(true),
            "data_protection.pii_present must be true when streaming PII found"
        );

        // streaming.findings still contains the original finding too
        let streaming_findings = entry["streaming"]["findings"].as_array().unwrap();
        assert_eq!(streaming_findings.len(), 1);
        assert_eq!(streaming_findings[0]["location"], "streaming_tool_args");
    }

    // ── Observation-mode pipeline tests ───────────────────────────────────

    #[test]
    fn sync_requirements_cache_from_default_policies() {
        use crate::policy::sync_promoter::SyncRequirements;
        let cedar = include_str!("../../dsl/policies/default.cedar");
        let reqs = SyncRequirements::analyze(cedar);
        let cache = SyncRequirementsCache::from_requirements(&reqs);

        // v2 observation mode: only exfiltration is enforced (block)
        assert!(
            cache.sync_detectors.contains("exfiltration"),
            "exfiltration should be sync"
        );
        assert!(
            !cache.sync_detectors.contains("injection"),
            "injection should be async (flag only)"
        );
        assert!(
            !cache.sync_detectors.contains("jailbreak"),
            "jailbreak should be async (flag only)"
        );
        // PII is now sync in the shipped defaults because `default-secrets-block`
        // is a block-action policy referencing `context.pii_findings`. The
        // alternative (async-only) would forward auth secrets upstream
        // unredacted, defeating the purpose of the rule.
        assert!(
            cache.pii_sync,
            "PII must be sync — default-secrets-block needs hot-path findings"
        );
        assert!(
            cache.has_response_enforcement,
            "response enforcement should be detected"
        );
        assert!(
            !cache.all_async,
            "not all async — exfiltration still enforced"
        );
    }

    #[test]
    fn sync_requirements_cache_all_flag_is_all_async() {
        use crate::policy::sync_promoter::SyncRequirements;
        let cedar = r#"
            @enforcement("flag")
            forbid(principal, action, resource)
            when { context.injection_detected == true };

            @enforcement("flag")
            forbid(principal, action, resource)
            when { context.pii_detected == true };

            @enforcement("flag")
            forbid(principal, action, resource)
            when { context.jailbreak_detected == true };
        "#;
        let reqs = SyncRequirements::analyze(cedar);
        let cache = SyncRequirementsCache::from_requirements(&reqs);

        assert!(cache.all_async, "all-flag policies should be fully async");
        assert!(cache.sync_detectors.is_empty());
        assert!(!cache.pii_sync);
    }

    #[test]
    fn sync_cache_eviction_clears_tenant_entry() {
        let cache: dashmap::DashMap<String, SyncRequirementsCache> = dashmap::DashMap::new();
        cache.insert(
            "tenant-1".to_string(),
            SyncRequirementsCache {
                sync_detectors: std::collections::HashSet::new(),
                pii_sync: false,
                has_response_enforcement: false,
                all_async: true,
            },
        );
        assert!(cache.contains_key("tenant-1"));

        cache.remove("tenant-1");
        assert!(
            !cache.contains_key("tenant-1"),
            "eviction should clear the entry"
        );
    }

    #[test]
    fn sync_cache_repopulates_after_eviction() {
        use crate::policy::sync_promoter::SyncRequirements;
        let cache: dashmap::DashMap<String, SyncRequirementsCache> = dashmap::DashMap::new();

        // First insert: all-flag
        let flag_policy = r#"
            @enforcement("flag")
            forbid(principal, action, resource)
            when { context.injection_detected == true };
        "#;
        let reqs1 = SyncRequirements::analyze(flag_policy);
        cache.insert(
            "t1".to_string(),
            SyncRequirementsCache::from_requirements(&reqs1),
        );
        assert!(cache.get("t1").unwrap().all_async);

        // Evict (simulates policy reload)
        cache.remove("t1");

        // Re-populate with block policy
        let block_policy = r#"
            @enforcement("block")
            forbid(principal, action, resource)
            when { context.injection_detected == true };
        "#;
        let reqs2 = SyncRequirements::analyze(block_policy);
        cache.insert(
            "t1".to_string(),
            SyncRequirementsCache::from_requirements(&reqs2),
        );
        let entry = cache.get("t1").unwrap();
        assert!(
            !entry.all_async,
            "after reload with block policy, should not be all_async"
        );
        assert!(entry.sync_detectors.contains("injection"));
    }

    // ── ARG-173: Decision-based observation mode ─────────────────────────

    #[test]
    fn decision_based_observation_skips_body_modification() {
        // Simulate: PII scan found something and produced a redacted body,
        // but Cedar decided "flag" (observation only).
        // The pipeline should revert to the original body.
        let original_body = b"my SSN is 123-45-6789".to_vec();
        let redacted_body = b"my SSN is [REDACTED]".to_vec();

        // Flag decision → no body modification needed
        let flag_decision = PolicyDecision {
            action: EnforcementAction::Flag,
            rule_id: Some("pii_flag".to_string()),
            steer_message: None,
            transform_to: None,
            description: None,
            regulatory_mapping: vec![],
            matched_rules: vec![],
        };
        let enforced_body = if flag_decision.action.requires_body_modification() {
            redacted_body.clone()
        } else {
            original_body.clone()
        };
        assert_eq!(
            enforced_body, original_body,
            "flag decision should preserve original body for prompt caching"
        );

        // Allow decision → same behavior
        let allow_decision = PolicyDecision::allow();
        let enforced_body = if allow_decision.action.requires_body_modification() {
            redacted_body.clone()
        } else {
            original_body.clone()
        };
        assert_eq!(
            enforced_body, original_body,
            "allow decision should preserve original body"
        );

        // Transform decision → body modification required
        let transform_decision = PolicyDecision {
            action: EnforcementAction::Transform,
            rule_id: Some("pii_redact".to_string()),
            steer_message: None,
            transform_to: None,
            description: None,
            regulatory_mapping: vec![],
            matched_rules: vec![],
        };
        let enforced_body = if transform_decision.action.requires_body_modification() {
            redacted_body.clone()
        } else {
            original_body.clone()
        };
        assert_eq!(
            enforced_body, redacted_body,
            "transform decision should apply PII redaction"
        );

        // Block decision → body modification required (though request won't proceed)
        let block_decision = PolicyDecision {
            action: EnforcementAction::Block,
            rule_id: Some("pii_block".to_string()),
            steer_message: None,
            transform_to: None,
            description: None,
            regulatory_mapping: vec![],
            matched_rules: vec![],
        };
        assert!(
            block_decision.action.requires_body_modification(),
            "block decision should require body modification"
        );
    }

    #[test]
    fn requires_body_modification_matches_observation_actions() {
        assert!(!EnforcementAction::Allow.requires_body_modification());
        assert!(!EnforcementAction::Flag.requires_body_modification());
        assert!(EnforcementAction::Transform.requires_body_modification());
        assert!(EnforcementAction::Steer.requires_body_modification());
        assert!(EnforcementAction::Block.requires_body_modification());
    }

    fn test_context_params(
        overrides: impl FnOnce(&mut ContextParams<'_>),
    ) -> ContextParams<'static> {
        let mut params = ContextParams {
            model: "test-model",
            risk_level: "low",
            budget_remaining_cents: -1,
            ..Default::default()
        };
        overrides(&mut params);
        params
    }

    #[test]
    fn build_cedar_context_compat_emits_flat_and_namespaced() {
        let params = test_context_params(|p| {
            p.injection_detected = true;
            p.pii_detected = true;
        });
        let ctx = build_cedar_context_compat(&params);

        // Flat fields (backward compat — build_context)
        assert_eq!(ctx["injection_detected"], true);
        assert_eq!(ctx["pii_detected"], true);
        assert_eq!(ctx["jailbreak_detected"], false);

        // Namespaced fields
        assert_eq!(ctx["agent_integrity"]["injection_detected"], true);
        assert_eq!(ctx["agent_integrity"]["jailbreak_detected"], false);
        assert_eq!(ctx["data_protection"]["pii_present"], true);
        assert_eq!(ctx["data_protection"]["confidential_detected"], false);
        assert_eq!(ctx["data_protection"]["exfiltration_detected"], false);
        assert_eq!(ctx["content_safety"]["threat_detected"], false);
        assert_eq!(ctx["identity_safety"]["disclosure_detected"], false);
        assert_eq!(ctx["tool_governance"]["unauthorized_detected"], false);
    }

    #[test]
    fn build_cedar_context_compat_risk_level_propagated() {
        let tools = vec!["get_weather".to_string()];
        let params = ContextParams {
            model: "test-model",
            risk_level: "high",
            requested_tools: &tools,
            budget_remaining_cents: 500,
            ..Default::default()
        };
        let ctx = build_cedar_context_compat(&params);

        // risk_level and budget come from build_context (flat)
        assert_eq!(ctx["risk_level"], "high");
        assert_eq!(ctx["budget_remaining_cents"], 500);
        assert_eq!(ctx["requested_tools"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn build_cedar_context_compat_mcp_server_approved_true() {
        let params = ContextParams {
            mcp_server_approved: true,
            mcp_server_id: "github-mcp",
            ..Default::default()
        };
        let ctx = build_cedar_context_compat(&params);

        // Flat fields
        assert_eq!(ctx["mcp_server_approved"], true);
        assert_eq!(ctx["mcp_server_id"], "github-mcp");
        // Namespaced supply_chain fields
        assert_eq!(ctx["supply_chain"]["mcp_server_approved"], true);
        assert_eq!(ctx["supply_chain"]["mcp_server_id"], "github-mcp");
    }

    #[test]
    fn build_cedar_context_compat_mcp_server_unapproved() {
        let params = ContextParams {
            mcp_server_approved: false,
            mcp_server_id: "malicious-mcp",
            ..Default::default()
        };
        let ctx = build_cedar_context_compat(&params);

        assert_eq!(ctx["mcp_server_approved"], false);
        assert_eq!(ctx["mcp_server_id"], "malicious-mcp");
        assert_eq!(ctx["supply_chain"]["mcp_server_approved"], false);
    }

    #[test]
    fn build_cedar_context_compat_mcp_no_header_defaults_approved() {
        // When no MCP header is present, mcp_server_id is "" and approved defaults true
        let params = ContextParams {
            mcp_server_approved: true,
            mcp_server_id: "",
            ..Default::default()
        };
        let ctx = build_cedar_context_compat(&params);

        assert_eq!(ctx["mcp_server_approved"], true);
        assert_eq!(ctx["mcp_server_id"], "");
    }

    // ── Agent-B: Streaming tool-call argument PII scanning tests ────────

    #[test]
    fn extract_streaming_tool_args_accumulates_deltas_b() {
        // Verify that argument deltas for the same tool call index are
        // concatenated correctly across multiple streaming chunks.
        let mut args: std::collections::HashMap<usize, String> = std::collections::HashMap::new();

        let delta1 = json!({
            "choices": [{
                "delta": {
                    "tool_calls": [{
                        "index": 0,
                        "function": { "name": "get_weather", "arguments": "{\"city\":" }
                    }]
                }
            }]
        });
        let delta2 = json!({
            "choices": [{
                "delta": {
                    "tool_calls": [{
                        "index": 0,
                        "function": { "arguments": " \"New York\"}" }
                    }]
                }
            }]
        });

        extract_streaming_tool_args(&delta1, "openai", &mut args);
        extract_streaming_tool_args(&delta2, "openai", &mut args);

        assert_eq!(args.len(), 1, "should have exactly one tool call index");
        assert_eq!(
            args.get(&0).unwrap(),
            "{\"city\": \"New York\"}",
            "argument fragments should be concatenated in order"
        );
    }

    #[test]
    fn extract_streaming_tool_args_concurrent_indices_b() {
        // Two concurrent tool calls (index 0 and index 1) must accumulate
        // their argument deltas independently.
        let mut args: std::collections::HashMap<usize, String> = std::collections::HashMap::new();

        // Index 0 starts
        let d1 = json!({
            "choices": [{"delta": {"tool_calls": [
                {"index": 0, "function": {"name": "get_weather", "arguments": "{\"city\":"}}
            ]}}]
        });
        // Index 1 starts
        let d2 = json!({
            "choices": [{"delta": {"tool_calls": [
                {"index": 1, "function": {"name": "send_email", "arguments": "{\"to\":"}}
            ]}}]
        });
        // Index 0 continues
        let d3 = json!({
            "choices": [{"delta": {"tool_calls": [
                {"index": 0, "function": {"arguments": " \"SF\"}"}}
            ]}}]
        });
        // Index 1 continues
        let d4 = json!({
            "choices": [{"delta": {"tool_calls": [
                {"index": 1, "function": {"arguments": " \"bob@example.com\"}"}}
            ]}}]
        });

        extract_streaming_tool_args(&d1, "openai", &mut args);
        extract_streaming_tool_args(&d2, "openai", &mut args);
        extract_streaming_tool_args(&d3, "openai", &mut args);
        extract_streaming_tool_args(&d4, "openai", &mut args);

        assert_eq!(
            args.len(),
            2,
            "should have two independent tool call indices"
        );
        assert_eq!(args.get(&0).unwrap(), "{\"city\": \"SF\"}");
        assert_eq!(args.get(&1).unwrap(), "{\"to\": \"bob@example.com\"}");
    }

    #[test]
    fn pii_scanner_finds_email_in_tool_args_b() {
        // PII scanner (RegexPiiEngine with default patterns) must detect an
        // email address inside concatenated tool call arguments JSON.
        let engine = crate::pii::RegexPiiEngine::new(&[]);
        let tool_args = "{\"recipient\": \"alice@secretcorp.com\", \"subject\": \"meeting\"}";
        let result = engine.scan_and_redact(tool_args, "streaming_tool_args");
        assert!(
            !result.findings.is_empty(),
            "PII engine should detect email in tool call arguments; got no findings"
        );
        assert!(
            result.findings.iter().any(|f| f.pattern.contains("email")),
            "at least one finding should be an email pattern; findings: {:?}",
            result
                .findings
                .iter()
                .map(|f| &f.pattern)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn request_body_scan_catches_pii_in_tool_role_message_b() {
        // The pre-stream scan at line 348 runs scan_and_redact on the full
        // raw request JSON body (body_str). This test proves that PII inside
        // a role:tool message content field IS scanned and redacted, because
        // scan_and_redact operates on the entire string — it doesn't parse JSON.
        let engine = crate::pii::RegexPiiEngine::new(&[]);
        let request_body = serde_json::to_string(&json!({
            "model": "gpt-4o",
            "messages": [
                {"role": "user", "content": "Look up this customer"},
                {"role": "assistant", "content": null, "tool_calls": [
                    {"id": "call_1", "type": "function", "function": {"name": "get_customer", "arguments": "{}"}}
                ]},
                {"role": "tool", "tool_call_id": "call_1", "content": "Customer email: user@example.com, SSN: 123-45-6789"}
            ]
        })).unwrap();

        let result = engine.scan_and_redact(&request_body, "request");
        assert!(
            !result.findings.is_empty(),
            "scan_and_redact on full request body should catch PII in role:tool content"
        );
        // Verify at least the email was caught
        let has_email = result.findings.iter().any(|f| f.pattern.contains("email"));
        assert!(
            has_email,
            "email in tool message content should be detected"
        );
        // The SSN should also be caught
        let has_ssn = result.findings.iter().any(|f| {
            f.pattern.contains("ssn") || f.pattern.contains("SSN") || f.pattern.contains("social")
        });
        assert!(
            has_ssn,
            "SSN in tool message content should be detected; patterns: {:?}",
            result
                .findings
                .iter()
                .map(|f| &f.pattern)
                .collect::<Vec<_>>()
        );
    }
}
