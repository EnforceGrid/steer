# Compliance

## Read this first

**Steer produces evidence that supports specific obligations under the frameworks listed below. Steer is a control component, not a compliance solution.** Whether the evidence is sufficient for any particular audit depends on:

- **Operational practices** — who reviews the audit log, how often, on what cadence, with what response SLA.
- **Audit-sink integrity** — whether an operator can rewrite history.
- **Scope of coverage** — Steer governs the LLM API boundary; it does not govern your data warehouse, your CRM, your model training pipeline, or your employee endpoints.
- **Policy customization** — the 23 shipped policies are a sensible default; your auditor may require additional rules specific to your environment.

OSS Steer ships with an append-only file audit sink and no integrity chain. **An operator with shell access to the host can rewrite `audit.jsonl`.** EnforceGrid Enterprise adds hash chaining, signed audit trails, tenant isolation, and time-source attestation — that's the difference between *evidence-of* (OSS) and *assurance-of* (EE) audit. See [docs/enterprise.md](enterprise.md).

The rest of this page maps Steer's policies to specific framework controls and walks through what an auditor sees.

---

## 1. Framework coverage at a glance

| Framework | Mappings present in shipped policies | OSS evidence | EE assurance |
|---|---|---|---|
| **EU AI Act** | Art. 5, 9, 12, 14, 15, 26, 50, 72 | decision log (contributes evidence) | + cryptographically chained audit |
| **GDPR** | Art. 5, 6, 25, 32 | decision log with PII pattern findings | + signed integrity + DSAR workflow |
| **NIST AI RMF** | Map / Measure / Manage / Govern; NIST AI 600-1 | per-decision control-execution record | + chain-of-custody |
| **ISO 42001** | A.8 (Operations) | runtime control evidence | + cryptographic verification |
| **ISO 27001** | A.8.11, A.8.16 | classification + monitoring events | + ISO 27037-aligned |
| **MITRE ATLAS** | M0004, M0015 | mitigation execution log | + DFIR-ready chain |
| **AIUC-1** | A001–A008, B002–B009, C001–C007, D002/D004/D005, E001–E006, F001/F004 | evidence-coded decision stream | + auditor portal |
| **OWASP LLM Top 10 / Agentic Top 10** | LLM06, ASI01–ASI10 | per-rule mapping with policy IDs | + verifiable signed chain |
| **Colorado SB-205** | S3, S4, S6 | algorithmic decision log | + retention enforcement |
| **CCPA** | §1798.100 | consumer-data detection events | + DSAR workflow |
| **PCI-DSS** | Req 3 (data protection) — partial; see [§5](#5-pci-dss-hipaa-nydfs-500-soc-2) | card-data **detection** events (flag-only by default; redaction requires policy override) | + segmented audit |
| **China Generative AI Measures** | Art. 12 (anti-impersonation) | AI-identity-claim detection events | + region-pinned audit |

This is the union of `@regulatory_mapping` annotations across the 23 shipped policies. Per-policy detail in [§6](#6-per-policy-regulatory-mapping).

**The cells indicate the artifact Steer contributes — not framework certification.** A check mark in this table means "one or more shipped policies emit signal tagged to that framework." It does not mean Steer alone satisfies the framework. See [§5](#5-pci-dss-hipaa-nydfs-500-soc-2) and [§7](#7-demonstrating-steer-to-a-regulator) for the demonstration walkthrough.

---

## 2. EU AI Act mapping

The shipped policies provide evidence supporting these articles:

| Article | Topic | Steer evidence |
|---|---|---|
| **Art. 5** — Prohibited practices | Risk-level enforcement (`default-prohibited-block`) blocks requests whose configured risk classification is `prohibited` |
| **Art. 9** — Risk management | Injection, jailbreak, threat, exfiltration, residency, anomaly, bias detection events — collectively a runtime risk-management evidence stream |
| **Art. 12** — Record-keeping | Every decision is logged with timestamp, request, policy ID, action, regulatory mapping. The audit log is a **structured input** to the Art. 12 record. Full Art. 12 compliance for high-risk systems also requires reviewer identity (EE handover supplies this), retention enforcement, and linkage to input data — Steer contributes the per-decision evidence stream component. |
| **Art. 14** — Human oversight | Threat-flag and steer (hold-for-approval) policies route to a human review queue. EE handover system is the operationalization. |
| **Art. 15** — Accuracy & robustness | Injection/jailbreak flag events surface attempts to subvert the model's intended behaviour. |
| **Art. 26** — Provider obligations | The decision log establishes deployer-side controls. PII detection, residency check, anomaly detection. |
| **Art. 50** — Transparency | `default-identity-flag` detects model identity claims in responses, which supports an anti-impersonation control adjacent to (not equivalent to) the Art. 50 user-facing disclosure obligation. The Art. 50 obligation that natural persons are informed they interact with AI is a deployer-side product/UX concern Steer doesn't address. |
| **Art. 72** — Post-market monitoring | `default-anomaly-flag` provides the operational-monitoring signal Art. 72 requires of high-risk systems. |

What Steer does **not** cover under the AI Act:
- Conformity assessment, CE marking, technical documentation
- Training-data governance (Art. 10) — Steer doesn't see training data
- Quality management system requirements
- Article 47 declarations

---

## 3. GDPR mapping

| Article | Topic | Steer evidence |
|---|---|---|
| **Art. 5** | Principles — lawfulness, minimisation, integrity | The default PII policy *flags*; the secrets-block policy *blocks*. Together they produce evidence that PII flowed through the boundary. Active data minimisation requires enabling `default-confidential-redact` or the strict-PII override. |
| **Art. 6** | Lawfulness of processing | `default-no-consent-flag` is **not** in the shipped baseline (it generated noise without a yaml control). The body is included as a commented snippet in `default.cedar` — operators copy it into an override file at `<policy_dir>/default/consent.cedar` to enforce, and set `tenant.consent_given: true` once lawful basis is recorded. |
| **Art. 25** | Data protection by design | The proxy is positioned as a design-time boundary control. The shipped default PII policy *flags*; redaction requires enabling `default-confidential-redact` or the strict-PII override. By-design status depends on which policies you enable. |
| **Art. 32** | Security of processing | `default-secrets-block` prevents credential leakage to upstream third parties — the strongest GDPR mapping in the shipped set. |

What Steer does **not** cover under GDPR:
- Data subject access requests (the audit log is one input among many; you still need DSAR workflow)
- Right to erasure across your full data estate
- DPIA documentation
- International transfer mechanism (Standard Contractual Clauses, etc.)

---

## 4. NIST AI RMF and AIUC-1

The NIST AI Risk Management Framework defines four core functions:

| Function | Steer contribution |
|---|---|
| **Govern** | Policy authoring + enforcement record |
| **Map** | Detector signals categorize each request by risk class (PII, injection, exfiltration, etc.) |
| **Measure** | Audit log captures rate, severity, and trend of policy violations |
| **Manage** | Hold-for-approval (`steer` action) and block (`block` action) are the manage primitive |

**AIUC-1** (the AI Underwriting Compliance framework — emerging insurance standard) is mapped at evidence-code granularity. The shipped policies cover **A001–A008** (governance), **B002–B009** (capability bounds), **C001–C007** (content safety), **D002/D004/D005** (detection), **E001–E006** (data protection), and **F001/F004** (output transparency).

For the complete per-evidence-code mapping, see [§6](#6-per-policy-regulatory-mapping). The AIUC-1 framework reference is `aiuc.org` (their TLS certificate was expired at the time of writing — search "AIUC-1 framework" for an archived mirror until they renew).

---

## 5. PCI-DSS, HIPAA, NYDFS 500, SOC 2

**These are out of scope for OSS Steer as compliance certifications.** OSS Steer *can produce evidence* that supports controls under each, but does not certify them.

- **PCI-DSS Requirement 3** (protect stored cardholder data) — `default-pii-flag` with the `credit_card` pattern produces detection events when card data crosses the LLM boundary. The shipped policy *flags*; for blocking, use the [strict-PII override](policies.md#7-snippets). A PCI assessor will require the strict-PII override or `default-confidential-redact` to be active, plus evidence of that activation in your config-management trail. PCI compliance also requires a network-segmented environment, key management, vulnerability scanning, and an annual assessment — Steer contributes one input among many.
- **HIPAA** — OSS Steer is **not HIPAA-compliant** out of the box. No BAA. No PHI-specific detectors shipped. EnforceGrid Enterprise offers a BAA-signable deployment.
- **NYDFS 500** (New York DFS cybersecurity regulation) — Steer's audit log supports §500.06 (audit trail) and §500.14 (training/monitoring) for AI-mediated workflows. Full §500 compliance requires programmatic controls Steer doesn't claim.
- **SOC 2** — Steer is a control component that produces evidence for SOC 2 audits (CC7.2 — system monitoring, CC6.7 — data protection). EnforceGrid Enterprise carries a SOC 2 Type II attestation; OSS does not.

If your auditor asks "does this satisfy HIPAA / PCI / SOC 2," answer: *"Steer is a runtime control that produces evidence under those frameworks; the framework controls have additional requirements Steer alone does not satisfy."*

For frameworks where certification or BAA matters, see [docs/enterprise.md](enterprise.md).

---

## 6. Per-policy regulatory mapping

The source of truth is the `@regulatory_mapping` annotation on each policy in `dsl/policies/default.cedar`. Summary below:

| Policy `@id` | Action | Frameworks |
|---|---|---|
| `default-pii-flag` | flag | AIUC1 E001/B005/E006, GDPR Art 5/25, EU AI Act Art 12/26, CO SB-205 S6, CCPA §1798.100, NIST AI 600-1, PCI-DSS Req 3 |
| `default-secrets-block` | **block** | OWASP LLM06, OWASP ASI04, AIUC1 E001/E003, NIST AI RMF MS, GDPR Art 32 |
| `default-threat-flag` | flag | AIUC1 C001/C002/C003/C007, EU AI Act Art 9/12/14, NIST AI RMF MG, NIST AI 600-1 |
| `default-identity-flag` | flag | AIUC1 F001, EU AI Act Art 50, CO SB-205 S4, NIST AI 600-1, CN GenAI Art 12 |
| `default-tool-count-flag` | flag | AIUC1 A003, OWASP ASI01/02/06, NIST AI RMF MS |
| `default-injection-flag` | flag | AIUC1 C005, OWASP ASI01, EU AI Act Art 9/12/15/26, MITRE ATLAS M0015, NIST AI RMF MS |
| `default-jailbreak-flag` | flag | AIUC1 C002, OWASP ASI01, EU AI Act Art 9/12/15/26, MITRE ATLAS M0015, NIST AI RMF MS |
| `default-confidential-flag` | flag | AIUC1 E003/B009, OWASP ASI04/07, ISO 42001 A.8, ISO 27001 A.8.11, NIST AI 600-1 |
| `default-budget-block` | **block** | AIUC1 B004, OWASP ASI06/08, MITRE ATLAS M0004, NIST AI RMF MG |
| `default-prohibited-block` | **block** | AIUC1 A002, EU AI Act Art 5, NIST AI RMF MG |
| `default-exfiltration-request-block` | **block** | AIUC1 E003, OWASP ASI07, GDPR Art 5, EU AI Act Art 9, MITRE ATLAS M0015, ISO 27001 A.8.16, NIST AI RMF MG |
| `default-exfiltration-block` | **block** | AIUC1 E003/C006, OWASP ASI04/07, GDPR Art 5, EU AI Act Art 9/12, MITRE ATLAS M0015, ISO 27001 A.8.16, NIST AI RMF MG |
| `default-exfiltration-tool-block` | **block** | AIUC1 E003, OWASP ASI04/07, GDPR Art 5, MITRE ATLAS M0015, NIST AI RMF MG |
| `default-unauthorized-tool-flag` | flag | AIUC1 A003, OWASP ASI01/02/06, EU AI Act Art 9, NIST AI RMF MS |
| `default-no-fallback-flag` | flag | AIUC1 B002, OWASP ASI09 |
| `default-unapproved-model-flag` | flag | AIUC1 A005/B007/D004, OWASP ASI09 |
| `default-bias-flag` | flag | AIUC1 C004/F004, EU AI Act Art 9/26, CO SB-205 S3 |
| `default-anomaly-flag` | flag | AIUC1 D005/A008/C003/D002, OWASP ASI10, EU AI Act Art 9/12/26/72 |
| `default-data-residency-flag` | flag | AIUC1 E004, GDPR Art 5, EU AI Act Art 26 |
| `default-code-execution-risk-flag` | flag | OWASP ASI05 |
| `default-privilege-escalation-block` | **block** | OWASP ASI03, NIST AI RMF MG |
| `default-credential-access-block` | **block** | OWASP ASI03, NIST AI RMF MG |
| `default-confidential-redact` | transform | AIUC1 E003, OWASP ASI04, ISO 27001 A.8.11, ISO 42001 A.8, NIST AI 600-1 |

The annotation strings are forwarded into the audit record's `enforcement.regulatory_mapping` field, so a SIEM query like *"every event under EU AI Act Art 9"* is a single `jq` filter:

```bash
jq 'select(.enforcement.regulatory_mapping[]? == "EU_AI_ACT_ART_9")' audit.jsonl
```

---

## 7. Demonstrating Steer to a regulator

A typical walkthrough an auditor or regulator will run:

**1. "Show me your AI risk controls."**
Open `dsl/policies/default.cedar`. Each policy carries `@id`, `@enforcement` action, `@description`, and `@regulatory_mapping`. The annotation strings are plain text; the Cedar `forbid`/`when` body is short enough that a technical reviewer can audit the logic alongside.

**2. "Show me they actually fire."**
Tail the audit log:

```bash
jq '.enforcement | {rule_id, action, regulatory_mapping}' audit.jsonl | head -20
```

Each line is a control-execution record with timestamp, request context, decision, and regulatory framework attribution.

**3. "Show me the evidence chain is unbroken."**
This is where the OSS/EE gap matters. OSS audit is append-only file — *evidence of decisions taken*, no cryptographic chain. EE adds `prev_hash` chaining, signed entries, and trusted time source — *assurance that the evidence has not been tampered with*. If your auditor requires the latter, you need EE.

**4. "Show me a specific framework control."**
Filter by mapping:

```bash
# Every GDPR Art 32 (security of processing) event in the last 30 days:
jq 'select(.enforcement.regulatory_mapping[]? == "GDPR_ART_32" and .timestamp >= (now - 86400*30 | todate))' audit.jsonl

# Every blocked secret leak:
jq 'select(.enforcement.rule_id == "default-secrets-block")' audit.jsonl

# Every observation-mode would-have-blocked event:
jq 'select(.enforcement.observed == true)' audit.jsonl
```

**5. "What happens when a policy errors?"**
With `proxy.fail_open: false` (default), the request is blocked and a 503 returned. The audit log records the failure. For production, `fail_open: false` is non-negotiable from a control-integrity standpoint.

---

## 8. Known limitations (be transparent with your auditor)

### Silent-degradation footgun (mitigated)

Cedar policies can reference PII pattern names via `containsAny([...])`. If an operator removes a pattern from `pii.patterns` in `steer.yaml`, the corresponding regex is not compiled, and the Cedar rule silently never fires.

**Mitigation shipped in v0.1.0:** Steer runs a startup-time consistency check that scans every loaded `.cedar` file and warns on every referenced pattern that is not in `pii.patterns`:

```
WARN Cedar policy references PII pattern 'iban' that is not compiled — rule will never fire.
     Fix: add 'iban' to pii.patterns, or remove it from policy 'default-pii-flag'.
```

An auditor checking control integrity should grep the startup log for this warning class. Zero warnings = no silently-disabled rules. See [docs/policies.md#the-startup-consistency-check](policies.md#the-startup-consistency-check).

### Audit log integrity (OSS)

OSS file audit is append-only at the application layer, but the filesystem permits an operator with shell access to truncate, edit, or delete the file. **Steer's OSS audit is evidence-of, not assurance-of.** For tamper-evident audit, EE adds hash chaining and external attestation.

### Detection scope (Tier 2 regex)

The shipped detectors are regex-anchored. They catch syntactically distinctive patterns reliably but miss synonyms, multi-turn staging, and obfuscation. See [docs/policies.md#8-detection-scope-and-limits](policies.md#8-detection-scope-and-limits). For workloads with high evasion risk, pair Steer with a Tier 3 ML classifier.

### Coverage boundary

Steer governs the **LLM API boundary**. It does not see:
- Inter-agent messaging that bypasses the LLM proxy
- Direct database queries an agent issues outside the LLM call
- Model fine-tuning, training-data ingestion, or post-training behaviour
- Endpoint security, employee credentials, or the data warehouse

A complete compliance posture combines Steer with framework-appropriate controls in each of those other domains.

---

## 9. Where to go next

- [Enterprise features — BAA, SOC 2, tamper-evident audit](enterprise.md)
- [Policy authoring — extending the baseline for your framework](policies.md)
- [Architecture — audit record schema, fail modes](architecture.md)
