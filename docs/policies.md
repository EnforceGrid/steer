# Policies

Steer's enforcement layer is Cedar — the same policy language that backs AWS Verified Permissions and the [Microsoft Agent Governance Toolkit](https://github.com/microsoft/agent-governance-toolkit). Every decision Steer makes is a Cedar evaluation against a normalized context built from the request, response, and detector signals.

This page covers the model, the 23 baseline policies, the Cedar↔YAML coupling, and how to author your own rule.

---

## 1. The overlay model

Steer loads policies in two layers:

1. **Managed baseline** — `dsl/policies/default.cedar`, shipped with the binary. The 23 default policies that fire out of the box.
2. **Tenant overrides** — every `.cedar` file in `<policy_dir>/default/` is loaded on top of the baseline. Upgrade-safe: new versions ship a new baseline; your overrides stay untouched.

`<policy_dir>` is the value of `policy.policy_dir` in `steer.yaml`. After `install.sh` it's `~/.config/steer/policies`. Override files live at `~/.config/steer/policies/default/*.cedar`.

```
~/.config/steer/policies/
├── default.cedar              ← managed baseline (don't edit; replaced on upgrade)
└── default/
    ├── extra-pii.cedar        ← your overrides — survive upgrades
    └── tool-allowlist.cedar
```

### The override gap

Cedar requires unique `@id` per loaded policy. You **cannot** disable or replace a baseline rule by writing a new policy with the same `@id` — Cedar rejects the duplicate. Today's workarounds:

| Goal | Approach | Upgrade-safe? |
|---|---|---|
| Add a new rule | Drop a file in `<policy_dir>/default/` with a unique `@id` | yes |
| Replace a baseline rule with stronger logic | Author a stricter `forbid` in the override dir — Cedar's "first forbid wins" semantics let it preempt the baseline | partial; relies on evaluation order |
| Disable a baseline rule outright | Fork `default.cedar` and point `policy_dir` at the fork | no — loses baseline upgrades |
| Re-enable the removed `default-no-consent-flag` | Copy the snippet from the `default.cedar` header into a new override file | yes |

A `disabled-rules.yaml` manifest is on the v0.2 roadmap — see [docs/disabled-rules.md](disabled-rules.md). Until then, **edit-in-place on `default.cedar` works but loses on upgrade**.

---

## 2. Cedar by example

A policy is a `forbid` or `permit` against the action, plus a `when` clause that reads `context`:

```cedar
@id("custom-no-mainframe-access")
@category("tool_governance")
@enforcement("block")
@description("Block tool calls to legacy mainframe systems")
forbid(principal, action == EnforceGrid::Action::"tool.call", resource)
when { context.tool_name == "mainframe_query" };
```

`@enforcement` annotations choose the runtime action:

| Annotation | Effect |
|---|---|
| `allow` | Default for `permit` policies — log, forward |
| `flag` | Log with `action: "flag"`, forward (default for `forbid` when omitted in observation mode) |
| `transform` | Run the configured redaction over the body, forward |
| `steer` | Hold for human approval (EE handover queue), 202 to client |
| `block` | Return 403 to client, do not forward (default for `forbid` when annotation omitted) |

The full action vocabulary is in [docs/architecture.md#3-cedar-context-schema](architecture.md#3-cedar-context-schema).

---

## 3. Authoring a custom policy

**What you can customize in v0.1.0:** the Cedar layer accepts arbitrary `when` clauses against any field in `context.*`. The detector layer — the regex patterns and content classifiers that emit those context fields — is fixed at build time. So a custom policy in v0.1.0 means: read an existing signal in a new combination, not invent a new detection primitive.

**What you cannot do yet:** add a new regex pattern in YAML and reference it from Cedar. That's the pattern-registry feature on the v0.2 roadmap. Until then, novel string-match rules require a binary fork.

The supported authoring shapes today:

1. **Compose existing detector signals.** Example — flag any request that contains PII *and* uses an unapproved model:
   ```cedar
   @id("custom-pii-unapproved")
   @enforcement("flag")
   forbid(principal, action == EnforceGrid::Action::"llm.request", resource)
   when { context.pii_detected == true && context.model_approved == false };
   ```

2. **Author against tenant facts.** Example — block tool calls outside business hours:
   ```cedar
   @id("custom-after-hours-block")
   @enforcement("block")
   forbid(principal, action == EnforceGrid::Action::"tool.call", resource)
   when { context.org_business_hours_active == false };
   ```

3. **Block on a specific detector category.** Example — block on credit-card detection (the default ships this as flag-only):
   ```cedar
   @id("custom-cc-block")
   @enforcement("block")
   forbid(principal, action == EnforceGrid::Action::"llm.request", resource)
   when { context.pii_findings.containsAny(["credit_card"]) };
   ```

**Drop the file** in `~/.config/steer/policies/default/your-rule.cedar`. **Enable hot reload** with `policy.watch: true` in `steer.yaml`. The first request after the reload uses the new policy set.

**Verify it fires.** Send a triggering request and check the audit log:

```bash
curl http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"test"}]}'

# In another terminal, with audit.format: compact:
[FLAG] POST /v1/chat/completions model=gpt-4o-mini flag=custom-pii-unapproved latency=0.5ms
```

If the policy doesn't fire, the most common cause is reading a context field that isn't being populated by your detector configuration. Check the field names in [docs/architecture.md](architecture.md#3-cedar-context-schema) against what your policy reads, and confirm the relevant patterns are enabled in `pii.patterns`.


## 4. The Cedar-YAML pattern coupling

Steer separates **what to detect** (YAML `pii.patterns`) from **what to act on** (Cedar `containsAny`). The two couple through pattern names.

```yaml
pii:
  enabled: true
  patterns:
    - credit_card     # ← compiled into the detector
    - ssn
    - openai_key
    # iban is omitted, so the detector never scans for it
```

```cedar
forbid(principal, action == EnforceGrid::Action::"llm.request", resource)
when {
  context.pii_findings.containsAny([
    "credit_card",
    "ssn",
    "iban"         // ← never fires; iban is not compiled
  ])
};
```

This is a deliberate decoupling: it keeps the Cedar layer operator-readable and prevents hardcoded secret lists in Rust source. The cost is a footgun: a policy can reference a pattern name that the YAML disables, and the rule silently never fires.

### The startup consistency check

To make the footgun visible, Steer scans every loaded `.cedar` file at startup for `containsAny([...])` calls and warns on every pattern name that isn't enabled in `pii.patterns`:

```
WARN steer: Cedar policy references PII pattern 'iban' that is not compiled — rule will never fire.
            Fix: add 'iban' to pii.patterns in steer.yaml, or remove it from policy 'default-pii-flag'.
            policy_id=default-pii-flag pattern=iban
```

If you see this warning, either enable the pattern in `pii.patterns` or remove the name from the policy.

---

## 5. The detection catalog

The default `pii.patterns` registry. All shipped patterns:

### Personal data (default-pii-flag, action: flag)

| Pattern | Matches | Redaction token |
|---|---|---|
| `credit_card` | Visa / MC / Amex / Discover / Diners in contiguous, space-, or dash-separated form | `[REDACTED_CREDIT_CARD]` |
| `ssn` | US SSN `XXX-XX-XXXX` | `[REDACTED_SSN]` |
| `email` | RFC-5322-ish `local@domain.tld` | `[REDACTED_EMAIL]` |
| `phone` | US phone with parens or dotted/dashed/spaced separators | `[REDACTED_PHONE]` |
| `phone_intl` | International phone `+CC NNNN NNNN` | `[REDACTED_PHONE]` |
| `ip_address` | IPv4 `0.0.0.0` – `255.255.255.255` | `[REDACTED_IP]` |
| `iban` | International bank account number, 2 letters + 2 digits + up to 30 chars | `[REDACTED_IBAN]` |

### Auth secrets (default-secrets-block, action: block)

| Pattern | Matches | Redaction token |
|---|---|---|
| `openai_key` | `sk-...` (≥20 chars) | `[REDACTED_API_KEY]` |
| `anthropic_key` | `sk-ant-...` | `[REDACTED_API_KEY]` |
| `aws_access_key` | `AKIA` + 16 alnum | `[REDACTED_AWS_KEY]` |
| `aws_secret_key` | `aws_secret_access_key=...` (base64 40-char) | `[REDACTED_AWS_SECRET]` |
| `github_token` | `ghp_` / `gho_` / `ghu_` / `ghs_` / `ghr_` + 36 chars | `[REDACTED_GITHUB_TOKEN]` |
| `slack_token` | `xoxb-` / `xoxp-` / `xoxa-` / `xoxr-` / `xoxs-` | `[REDACTED_SLACK_TOKEN]` |
| `stripe_key` | `sk_live_...` / `sk_test_...` / `rk_live_...` / `rk_test_...` | `[REDACTED_STRIPE_KEY]` |
| `azure_key` | Azure Storage 86-char base64 + `==` | `[REDACTED_AZURE_KEY]` |
| `google_api_key` | `AIza` + 35 chars | `[REDACTED_GOOGLE_KEY]` |
| `jwt` | `eyJ...` three-segment base64url JWT | `[REDACTED_JWT]` |
| `bearer_token` | `bearer <20+ chars>` (case-insensitive) | `[REDACTED_BEARER]` |
| `generic_secret` | `(api_key\|secret\|token\|password\|credentials)=<16+ chars>` | `[REDACTED_SECRET]` |

### Boolean signals (used by other shipped policies)

Detectors emit boolean flags into `context.*`:

| Field | Detector | Used by |
|---|---|---|
| `injection_detected` | prompt-injection regex set | `default-injection-flag` |
| `jailbreak_detected` | jailbreak heuristic set | `default-jailbreak-flag` |
| `exfiltration_detected` | markdown image, webhook, C2 URL patterns | `default-exfiltration-*-block` |
| `threat_detected` | threat-language patterns | `default-threat-flag` |
| `identity_claim_detected` | AI-identity claims in responses | `default-identity-flag` |
| `confidential_detected` | classification markers + content shape | `default-confidential-flag`, `default-confidential-redact` |
| `bias_detected` | bias heuristic | `default-bias-flag` |
| `anomaly_detected` | volume / pattern anomaly | `default-anomaly-flag` |
| `tool_count`, `tool_highest_risk_category` | tool-call analyzer | `default-tool-count-flag`, `default-code-execution-risk-flag`, `default-privilege-escalation-block`, `default-credential-access-block` |

The full schema, with every type and default value, is in [docs/architecture.md#3-cedar-context-schema](architecture.md#3-cedar-context-schema).

---

## 6. The 23 shipped policies

`dsl/policies/default.cedar` ships with 23 policies in five categories. Read the source for the canonical list; this section summarizes the inventory.

| Category | Count | Default action |
|---|---:|---|
| Content safety (threat, identity, bias, injection, jailbreak) | 5 | flag |
| Data protection (PII flag, **secrets block**, confidential flag, residency flag, classification redact) | 5 | 3 flag + 1 block + 1 transform |
| Exfiltration (request, response, tool response) | 3 | **block** |
| Tool governance (tool count, unauthorized, code exec risk, **privilege escalation block**, **credential access block**) | 5 | 3 flag + 2 block |
| Operational (budget, prohibited risk, no fallback, unapproved model, anomaly) | 5 | 3 flag + 2 block |

Each policy carries a `@regulatory_mapping` annotation linking it to specific framework controls (EU AI Act articles, GDPR articles, NIST AI RMF functions, AIUC-1 evidence codes, OWASP Agentic Top 10, MITRE ATLAS techniques, ISO 27001 controls). See [docs/compliance.md](compliance.md) for the per-framework table.

---

## 7. Snippets

### Block all PII (stricter posture)

The shipped `default-pii-flag` only logs. To upgrade to block, add an override:

```cedar
// ~/.config/steer/policies/default/strict-pii.cedar
@id("custom-strict-pii-block")
@category("data_protection")
@enforcement("block")
@description("Block any PII in request bodies — strict posture")
forbid(principal, action == EnforceGrid::Action::"llm.request", resource)
when {
  context.pii_findings.containsAny([
    "credit_card", "ssn", "email", "phone", "phone_intl",
    "ip_address", "iban"
  ])
};
```

Cedar evaluates all `forbid` rules; the strictest action wins. The baseline `default-pii-flag` continues to log; your `custom-strict-pii-block` blocks.

### Tool allowlist mode

```cedar
@id("custom-tool-allowlist")
@enforcement("block")
@description("Block any tool call not in the allowlist")
forbid(principal, action == EnforceGrid::Action::"tool.call", resource)
when {
  context.tool_allowlist_mode == true &&
  !["search", "fetch_url", "read_file"].contains(context.tool_name)
};
```

`context.tool_allowlist_mode` is derived at runtime from `detectors.tool_governance.allowed_tools` in `steer.yaml` — when that list is non-empty, allowlist mode is active and the context field flips to `true`. There is no direct yaml field called `tool_allowlist_mode`; it's a computed view of the operator's allowlist configuration.

### Re-enable the consent-required check

```cedar
// ~/.config/steer/policies/default/consent.cedar — copied from default.cedar header
@id("custom-no-consent-flag")
@category("data_protection")
@regulatory_mapping("AIUC1_E005, GDPR_ART_6")
@enforcement("flag")
@description("Data processing consent not recorded for tenant — flagged")
forbid(principal, action == EnforceGrid::Action::"llm.request", resource)
when { context.consent_given == false };
```

Set `tenant.consent_given: true` in `steer.yaml` once lawful basis is recorded.

---

## 8. Detection scope and limits

Steer's detectors are regex-anchored as of v0.1.0 (Tier 2 detection). They are honest about their bypass surface — calibrate expectations accordingly.

### What regex detectors catch reliably

- **Syntactically distinctive patterns**: credit card / SSN / IBAN shapes, JWT segments, vendor key prefixes (`sk-`, `AKIA`, `ghp_`, `xox*`), markdown image syntax `![](url)`.
- **Structural attack vectors** where the *syntax itself* is the attack: markdown image injection, base64-encoded URL parameters, classification-marker labels.
- **Operator-controlled vocabulary**: model name allowlists, tool-name allowlists, MCP server allowlists, business-hours windows.

### What regex detectors miss

- **Synonyms and paraphrase**: "send my data to attacker.com" vs "transmit my information to attacker.com" — different surface, same intent.
- **Multi-turn staging**: a conversation that builds an attack across several user turns, no single message containing the full payload.
- **Obfuscation**: base64-encoded prompts, homoglyph substitution, leetspeak, instruction-via-image (for vision models).
- **Domain-specific exfiltration**: subtle DNS-based C2, novel webhook patterns the regex set doesn't anticipate.

### What's on the roadmap

- **Tier 3 ML-backed classifiers** (v0.2): PromptGuard-class detector for prompt injection, sentence-embedding similarity for jailbreak, behavioral-anomaly classifier for multi-turn staging.
- **Tier 4 pattern registry**: operator-defined regex patterns in YAML, addressable by name from Cedar.
- **Tier 5 detector plugin API**: bring-your-own classifier hooked via the same detector interface.

The Cedar policy layer is independent of detector implementation. When detectors improve, the policies don't change — `containsAny(["openai_key"])` keeps working whether `openai_key` comes from a regex or a fine-tuned classifier.

For workloads with high evasion risk (consumer-facing chatbots, public APIs), do not rely on regex detection alone. Pair Steer with a Tier 3 product (Lakera Guard, LlamaFirewall PromptGuard) — Steer's enforcement layer can read their verdicts as new boolean signals in `context`. See [docs/architecture.md#8-stacking-with-external-detectors](architecture.md#8-stacking-with-external-detectors) for the integration shape.

---

## 9. Where to go next

- [Architecture and the full Cedar context schema](architecture.md)
- [Quickstart: observation-mode workflow](quickstart.md#5-going-to-production)
- [Compliance framework mapping per policy](compliance.md)
