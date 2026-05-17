// EnforceGrid Steer — Managed Default Policies
// Analogous to Cloudflare's OWASP Core Rule Set for AI governance.
// Auto-updated on deploy as _managed.cedar. Modify or replace as needed.
//
// Enforcement annotations:
//   @enforcement("allow"|"transform"|"flag"|"steer"|"block")
//   Defaults: forbid → block, permit → allow (when annotation absent)

// ── Baseline: permit all traffic not intercepted by a forbid rule ───────
permit(principal, action, resource);

// ═══════════════════════════════════════════════════════════════════════════
// FLAG policies — log for review, don't block
// ═══════════════════════════════════════════════════════════════════════════

// F1: Flag PII detected in prompts (log mode — upgrade to block when ready)
// AIUC1_E006: PII detection audit events generate the evidence record that
//             supports data subject right of access and erasure queries.
@id("default-pii-flag")
@category("data_protection")
@regulatory_mapping("AIUC1_E001, AIUC1_B005, AIUC1_E006, GDPR_ART_5, GDPR_ART_25, EU_AI_ACT_ART_12, EU_AI_ACT_ART_26, CO_SB205_S6, CCPA_1798.100, NIST_AI_600_1, PCI_DSS_REQ3")
@enforcement("flag")
@description("PII detected in prompt — flagged for review")
forbid(principal, action == EnforceGrid::Action::"llm.request", resource)
when { context.pii_detected == true };

// F2: Flag threatening content for human review
@id("default-threat-flag")
@category("content_safety")
@regulatory_mapping("AIUC1_C007, AIUC1_C002, AIUC1_C001, AIUC1_C003, EU_AI_ACT_ART_9, EU_AI_ACT_ART_12, EU_AI_ACT_ART_14, NIST_AI_RMF_MG, NIST_AI_600_1")
@enforcement("flag")
@description("Threatening content detected — flagged for human review")
forbid(principal, action == EnforceGrid::Action::"llm.request", resource)
when { context.threat_detected == true };

// F3: Flag AI identity claims — EU AI Act Art. 50 transparency
@id("default-identity-flag")
@category("content_safety")
@regulatory_mapping("AIUC1_F001, EU_AI_ACT_ART_50, CO_SB205_S4, NIST_AI_600_1, CN_GENAI_ART12")
@enforcement("flag")
@description("AI identity claim in response — transparency flag")
forbid(principal, action == EnforceGrid::Action::"llm.response", resource)
when { context.identity_claim_detected == true };

// F4: Flag excessive tool calls (possible injection-driven tool abuse)
@id("default-tool-count-flag")
@category("tool_governance")
@regulatory_mapping("AIUC1_A003, OWASP_AGENTIC_ASI01, OWASP_AGENTIC_ASI02, OWASP_AGENTIC_ASI06, NIST_AI_RMF_MS")
@enforcement("flag")
@description("Excessive tool calls detected — possible injection-driven abuse")
forbid(principal, action == EnforceGrid::Action::"tool.call", resource)
when { context.tool_count > 5 };

// ═══════════════════════════════════════════════════════════════════════════
// OBSERVATION policies — flag by default, upgrade to block when ready
// ═══════════════════════════════════════════════════════════════════════════

// B1: Flag prompt injection attempts (observation mode default — upgrade to block when ready)
@id("default-injection-flag")
@category("injection")
@regulatory_mapping("AIUC1_C005, OWASP_AGENTIC_ASI01, EU_AI_ACT_ART_9, EU_AI_ACT_ART_12, EU_AI_ACT_ART_15, EU_AI_ACT_ART_26, MITRE_ATLAS_M0015, NIST_AI_RMF_MS")
@enforcement("flag")
@description("Prompt injection attempt detected — flagged for review")
forbid(principal, action == EnforceGrid::Action::"llm.request", resource)
when { context.injection_detected == true };

// B2: Flag jailbreak attempts (observation mode default — upgrade to block when ready)
@id("default-jailbreak-flag")
@category("injection")
@regulatory_mapping("AIUC1_C002, OWASP_AGENTIC_ASI01, EU_AI_ACT_ART_9, EU_AI_ACT_ART_12, EU_AI_ACT_ART_15, EU_AI_ACT_ART_26, MITRE_ATLAS_M0015, NIST_AI_RMF_MS")
@enforcement("flag")
@description("Jailbreak attempt detected — flagged for review")
forbid(principal, action == EnforceGrid::Action::"llm.request", resource)
when { context.jailbreak_detected == true };

// B3: Flag confidential content leakage in responses (observation mode default)
@id("default-confidential-flag")
@category("data_protection")
@regulatory_mapping("AIUC1_E003, AIUC1_B009, OWASP_AGENTIC_ASI04, OWASP_AGENTIC_ASI07, ISO42001_A8, ISO27001_A8.11, NIST_AI_600_1")
@enforcement("flag")
@description("Confidential content detected in response — flagged for review")
forbid(principal, action == EnforceGrid::Action::"llm.response", resource)
when { context.confidential_detected == true };

// B4: Block when budget is exhausted
@id("default-budget-block")
@category("operational")
@regulatory_mapping("AIUC1_B004, OWASP_AGENTIC_ASI06, OWASP_AGENTIC_ASI08, MITRE_ATLAS_M0004, NIST_AI_RMF_MG")
@enforcement("block")
@description("Token budget exhausted — request blocked")
forbid(principal, action, resource)
when { context.budget_remaining_cents == 0 };

// B5: Block prohibited AI risk level (when configured)
// AIUC1_A002: enforcing operator-assigned risk levels provides runtime evidence
// that a risk assessment methodology is in execution.
@id("default-prohibited-block")
@category("operational")
@regulatory_mapping("AIUC1_A002, EU_AI_ACT_ART_5, NIST_AI_RMF_MG")
@enforcement("block")
@description("Prohibited AI risk level — request blocked")
forbid(principal, action, resource)
when { context.risk_level == "prohibited" };

// B6: Block exfiltration patterns in requests
//   Catches request-side staging: prompts that tell the agent to exfiltrate
//   data (webhook instructions, markdown image injection in prompts, etc.)
@id("default-exfiltration-request-block")
@category("exfiltration")
@regulatory_mapping("AIUC1_E003, OWASP_AGENTIC_ASI07, GDPR_ART_5, EU_AI_ACT_ART_9, MITRE_ATLAS_M0015, ISO27001_A8.16, NIST_AI_RMF_MG")
@enforcement("block")
@description("Exfiltration instruction detected in request — pre-staged data routing attempt blocked")
forbid(principal, action == EnforceGrid::Action::"llm.request", resource)
when { context.exfiltration_detected == true };

// B7: Block exfiltration patterns in LLM responses
//   (data embedded in URLs, webhook instructions, C2 channel patterns)
@id("default-exfiltration-block")
@category("exfiltration")
@regulatory_mapping("AIUC1_E003, AIUC1_C006, OWASP_AGENTIC_ASI04, OWASP_AGENTIC_ASI07, GDPR_ART_5, EU_AI_ACT_ART_9, EU_AI_ACT_ART_12, MITRE_ATLAS_M0015, ISO27001_A8.16, NIST_AI_RMF_MG")
@enforcement("block")
@description("Exfiltration pattern detected in response — data routing attempt blocked")
forbid(principal, action == EnforceGrid::Action::"llm.response", resource)
when { context.exfiltration_detected == true };

// B8: Block exfiltration patterns in tool call responses
@id("default-exfiltration-tool-block")
@category("exfiltration")
@regulatory_mapping("AIUC1_E003, OWASP_AGENTIC_ASI04, OWASP_AGENTIC_ASI07, GDPR_ART_5, MITRE_ATLAS_M0015, NIST_AI_RMF_MG")
@enforcement("block")
@description("Exfiltration pattern in tool call response — blocked")
forbid(principal, action == EnforceGrid::Action::"tool.call", resource)
when { context.exfiltration_detected == true };

// F5: Flag unauthorized tool use (denylist heuristic mode — default)
//   Operators who want hard enforcement should set default_action: block in
//   steer.yaml or write a Cedar block policy on unauthorized_tool_detected.
@id("default-unauthorized-tool-flag")
@category("tool_governance")
@regulatory_mapping("AIUC1_A003, OWASP_AGENTIC_ASI01, OWASP_AGENTIC_ASI02, OWASP_AGENTIC_ASI06, EU_AI_ACT_ART_9, NIST_AI_RMF_MS")
@enforcement("flag")
@description("Tool call matches dangerous-name heuristic — flagged for review")
forbid(principal, action == EnforceGrid::Action::"tool.call", resource)
when { context.unauthorized_tool_detected == true && context.tool_allowlist_mode == false };

// B10: Flag requests to models with no fallback configured (degradation risk)
@id("default-no-fallback-flag")
@category("operational")
@regulatory_mapping("AIUC1_B002, OWASP_AGENTIC_ASI09")
@enforcement("flag")
@description("Request routed to model with no fallback configured — degradation risk")
forbid(principal, action == EnforceGrid::Action::"llm.request", resource)
when { context.fallback_available == false };

// B9: Flag unapproved model usage (model not in steer.yaml model_routes registry)
// AIUC1_B007: model registry enforces version-controlled approved model list.
// AIUC1_D004: unapproved-model check provides a supply chain signal — only
//             whitelisted model providers/versions may be called.
@id("default-unapproved-model-flag")
@category("operational")
@regulatory_mapping("AIUC1_A005, AIUC1_B007, AIUC1_D004, OWASP_AGENTIC_ASI09")
@enforcement("flag")
@description("Request uses a model not in the approved registry — flagged for review")
forbid(principal, action == EnforceGrid::Action::"llm.request", resource)
when { context.model_approved == false };

// B11: Flag potential bias detected in AI responses
@id("default-bias-flag")
@category("content_safety")
@regulatory_mapping("AIUC1_C004, AIUC1_F004, EU_AI_ACT_ART_9, EU_AI_ACT_ART_26, CO_SB205_S3")
@enforcement("flag")
@description("Potential bias detected in response — flagged for fairness review")
forbid(principal, action == EnforceGrid::Action::"llm.response", resource)
when { context.bias_detected == true };

// B13: Flag when data processing consent not recorded (AIUC-1 E005)
@id("default-no-consent-flag")
@category("data_protection")
@regulatory_mapping("AIUC1_E005, GDPR_ART_6")
@enforcement("flag")
@description("Data processing consent not recorded for tenant — flagged")
forbid(principal, action == EnforceGrid::Action::"llm.request", resource)
when { context.consent_given == false };

// B12: Flag anomalous traffic patterns (AIUC-1 D005)
// AIUC1_A008: anomaly detection feeds continuous improvement workflow.
// AIUC1_C003: anomaly events provide safety incident evidence trail.
// AIUC1_D002: anomaly detection is the first step in incident response.
// EU_AI_ACT_ART_72: post-market monitoring system — continuous operational monitoring.
@id("default-anomaly-flag")
@category("operational")
@regulatory_mapping("AIUC1_D005, AIUC1_A008, AIUC1_C003, AIUC1_D002, OWASP_AGENTIC_ASI10, EU_AI_ACT_ART_9, EU_AI_ACT_ART_12, EU_AI_ACT_ART_26, EU_AI_ACT_ART_72")
@enforcement("flag")
@description("Anomalous traffic pattern detected — flagged for investigation")
forbid(principal, action == EnforceGrid::Action::"llm.request", resource)
when { context.anomaly_detected == true };

// B14: Flag cross-border data residency violations (AIUC-1 E004)
@id("default-data-residency-flag")
@category("data_protection")
@regulatory_mapping("AIUC1_E004, GDPR_ART_5, EU_AI_ACT_ART_26")
@enforcement("flag")
@description("Request routed to model outside tenant's required data residency region — flagged")
forbid(principal, action == EnforceGrid::Action::"llm.request", resource)
when { context.data_residency_compliant == false };

// O1: Flag tool calls with code execution risk (OWASP ASI05)
@id("default-code-execution-risk-flag")
@category("tool_governance")
@regulatory_mapping("OWASP_AGENTIC_ASI05")
@enforcement("flag")
@description("Tool call detected with code execution risk — flagged for sandboxing review")
forbid(principal, action == EnforceGrid::Action::"tool.call", resource)
when { context.tool_highest_risk_category == "code_execution" };

// O2: Block privilege escalation tool calls (OWASP ASI03)
@id("default-privilege-escalation-block")
@category("tool_governance")
@regulatory_mapping("OWASP_AGENTIC_ASI03, NIST_AI_RMF_MG")
@enforcement("block")
@description("Privilege escalation tool detected — blocked")
forbid(principal, action == EnforceGrid::Action::"tool.call", resource)
when { context.tool_highest_risk_category == "privilege_escalation" };

// O3: Block credential access tool calls (OWASP ASI03)
@id("default-credential-access-block")
@category("tool_governance")
@regulatory_mapping("OWASP_AGENTIC_ASI03, NIST_AI_RMF_MG")
@enforcement("block")
@description("Credential access tool detected — blocked")
forbid(principal, action == EnforceGrid::Action::"tool.call", resource)
when { context.tool_highest_risk_category == "credential_access" };

// ═══════════════════════════════════════════════════════════════════════════
// TRANSFORM policies — modify content, allow through
// ═══════════════════════════════════════════════════════════════════════════

// T1: Redact "CONFIDENTIAL" markers in responses that pass through
// (This catches explicit labels even when confidential_detected doesn't fire)
@id("default-confidential-redact")
@category("data_protection")
@regulatory_mapping("AIUC1_E003, OWASP_AGENTIC_ASI04, ISO27001_A8.11, ISO42001_A8, NIST_AI_600_1")
@enforcement("transform")
@description("Classification markers redacted from response")
@transform_pattern("\\b(CONFIDENTIAL|TOP SECRET|RESTRICTED)\\b")
@transform_replace("[CLASSIFICATION REDACTED]")
permit(principal, action == EnforceGrid::Action::"llm.response", resource);
