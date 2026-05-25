# Enterprise

OSS Steer is the runtime — the proxy, the policy engine, the detector pipeline, the audit emitter. EnforceGrid Enterprise (EE) adds the components that organizations with auditors, multiple teams, and long retention horizons typically require: cryptographically chained audit, multi-tenancy, SSO, a control plane, BAA, support.

This page describes the line between OSS and EE so you can decide which fits.

---

## 1. The OSS/EE feature matrix

| Capability | OSS | EnforceGrid Enterprise |
|---|---|---|
| **Drop-in OpenAI-compatible proxy** | ✓ | ✓ |
| **23 baseline Cedar policies** | ✓ | ✓ (+ extended policy library) |
| **Cedar policy authoring + hot reload** | ✓ | ✓ |
| **All shipped detectors** (PII, injection, jailbreak, threat, identity-claim, exfiltration, confidential, bias, anomaly, tool-governance) | ✓ | ✓ |
| **Observation mode** (`policy.mode: observe`) | ✓ | ✓ |
| **Audit log — append-only file** | ✓ (evidence-of) | ✓ + hash chain (assurance-of) |
| **Tamper-evident audit** (cryptographic chain, signed entries, trusted time source) | — | ✓ |
| **Multi-tenancy** | single tenant | per-tenant isolation, per-tenant policy overlays, per-tenant audit |
| **SSO** (SAML, OIDC) | — | ✓ |
| **RBAC** for control-plane access | — | ✓ |
| **Hold-for-approval queue** (`steer` action — human-in-the-loop) | hook only | full handover system with operator inbox |
| **Auditor portal** (read-only, framework-filtered audit views for external reviewers) | — | ✓ |
| **DSAR / right-of-erasure workflow** | self-managed jq queries | structured workflow with attestation |
| **Detector plugin API** (bring-your-own classifier) | — | v0.2 roadmap (both) |
| **Tier 3 ML-backed detectors** (PromptGuard-class) | — | partner integrations + native (roadmap) |
| **SIEM connectors** (Splunk, Datadog, OpenSearch, Sumo) | DIY via stdout pipe | turnkey connectors |
| **Retention policy enforcement** | self-managed `purge_jsonl_file` cron | configurable per-tenant retention with enforcement evidence |
| **HA / clustered audit** | self-managed L4 LB | clustered control plane, leader election |
| **BAA-signable deployment** | — | ✓ |
| **SOC 2 Type II attestation** | — | ✓ (annual) |
| **Procurement contracts, MSA, DPA** | — | ✓ |
| **24×7 support with SLA** | best-effort GitHub | tiered with response SLA |

If your decision question is "*do I need EE?*," the discriminating items are usually one of:

- **An auditor asks for tamper-evident audit chains** → EE
- **HIPAA or BAA required** → EE
- **More than one tenant** → EE
- **SOC 2 evidence in your procurement package** → EE
- **External reviewers need scoped audit access** → EE auditor portal

If none of those apply, OSS is sufficient.

---

## 2. Tamper-evident audit

The core difference between OSS and EE audit is cryptographic integrity.

**OSS** — Each audit entry has an `audit_id` and a timestamp. The `prev_hash` field is present in the schema but always empty. An operator with shell access can edit `audit.jsonl` with no detection.

**EE** — Each entry's `prev_hash` is the SHA-256 of the previous entry's canonical serialization. The chain is signed by a key that lives outside the host (HSM, KMS, or external signing service). Tampering with any entry invalidates the chain from that point forward; verification is a single pass over the file.

The schema is **forward-compatible**: an OSS deployment can later be migrated to EE without changing the audit consumer's parsing — `prev_hash` is just present and non-empty. Audit logs from before the migration are not retroactively chained.

For the cryptographic details of the chain (canonicalization, signature scheme, key rotation), contact EnforceGrid.

---

## 3. Multi-tenancy

OSS Steer is single-tenant: one `tenant.*` block in `steer.yaml`, one policy overlay directory, one audit stream. Adequate for a single team or a single product.

EE multi-tenancy provides:

- **Per-tenant policy overlay directories** — `<policy_dir>/<tenant_id>/*.cedar`
- **Per-tenant audit streams** — segregated for retention, access control, and DSAR scope
- **Per-tenant detector configuration** — different PII pattern sets per tenant
- **Per-tenant rate limits and budgets**
- **Tenant routing** — `EG-Tenant-Id` header or principal-derived tenant resolution
- **Per-tenant compliance posture** — one tenant in `enforce`, another in `observe`, simultaneously

Use cases: SaaS platform with customers each requiring isolated governance; multi-team enterprise with different compliance bars per team; AI vendor governance where each third-party AI has its own audit and policy scope.

---

## 4. SSO and RBAC

EE adds SAML 2.0 and OIDC SSO for the control-plane web UI. Role mapping is set in the IdP; supported roles:

| Role | Capabilities |
|---|---|
| `viewer` | Read-only audit, read-only policy |
| `operator` | Edit policy, change runtime config, ack holds in the handover queue |
| `admin` | Operator + manage users, manage tenants, rotate audit signing keys |
| `auditor` | Read-only audit with framework-filtered views; cannot see request bodies in plaintext |

OSS Steer has no web UI; configuration is YAML files on disk.

---

## 5. Hold-for-approval (the `steer` action)

The Cedar `@enforcement("steer")` action puts a request into a hold queue and returns HTTP 202 + a `hold_id` to the client. A human operator reviews the held request in a UI and approves or denies; the client polls for the resolution.

In OSS, this is a hook — Steer emits the audit entry with `enforcement.hold_id`, but there's no shipped UI or queue. You can build one against the audit stream.

In EE, the handover system is a full operator inbox: web UI, role-based access, decision SLA tracking, escalation routing, and audit attribution for the approver. Per-tenant queues with per-tenant approval workflows.

---

## 6. Compliance posture

| Framework | OSS | EE |
|---|---|---|
| GDPR (controller / processor) | Evidence under Art 5, 25, 32 | + Art 17, 20 DSAR workflow + DPA |
| EU AI Act | Evidence under Art 5, 9, 12, 14, 26, 50, 72 | + conformity-assessment package |
| HIPAA | **Not compliant**, no BAA | BAA-signable deployment with PHI-aware detectors |
| PCI-DSS | Detection events for card data | + segmented audit + key management |
| SOC 2 | Evidence component | Type II attestation (annual) |
| ISO 27001 / 42001 | Control execution evidence | + cryptographic chain |
| NYDFS 500 | Audit-trail support | + retention enforcement + segregation |

See [docs/compliance.md](compliance.md) for the framing of evidence-of vs assurance-of audit and the per-policy regulatory mapping. **OSS Steer is a runtime control, not a compliance certification.** Where certification matters, EE provides the additional controls and assertions that auditors require.

---

## 7. Support

| Tier | OSS | EE |
|---|---|---|
| Documentation | This repo | + private knowledge base |
| Community | [GitHub Issues](https://github.com/EnforceGrid/steer/issues) | + dedicated Slack/Teams channel |
| Issue response | Best-effort | Tiered SLA (severity 1: 1h, severity 2: 4h, severity 3: next business day) |
| Security advisories | [SECURITY.md](../SECURITY.md) | + private pre-disclosure, customer-specific advisories |
| Onboarding | Self-serve | Implementation support, policy authoring workshops |
| Roadmap input | Public Discussions | Direct product-management access |

---

## 8. Procurement

EE is commercial-licensed. Typical procurement path:

1. **Initial conversation** — what frameworks you operate under, your traffic profile, your audit cadence. Helps us scope the right deployment shape (self-hosted vs managed, single-region vs global, BAA requirements, etc.).
2. **MSA + DPA + DPIA** as needed. Standard SaaS contracting; we sign customer paper or provide ours.
3. **Pilot** — typically 60 days against your real traffic. Observation mode for the first 1–2 weeks (same as OSS), then enforce against your tuned policy set.
4. **Production rollout** — coordinated with your release schedule. We provide the migration playbook for moving from OSS to EE without audit-log discontinuity.

Contact: **[enforcegrid.com](https://enforcegrid.com)** or open an issue at [github.com/EnforceGrid/steer](https://github.com/EnforceGrid/steer/issues) and mention you'd like an enterprise call (or use the email on enforcegrid.com if your inquiry contains sensitive context).

Pricing: per-tenant + per-request, with annual commitment discounts. No public price list — pricing depends on deployment shape (region count, audit retention, SSO requirements, SLA tier) and is set in the MSA.

---

## 9. The line between the two

OSS Steer is feature-complete for single-tenant deployments: the runtime, policies, detectors, and audit emit are the same code path that ships in EE. EE adds capabilities; it does not unlock disabled OSS features. If you want a single-tenant LLM proxy with Cedar enforcement and a SIEM-compatible audit log, OSS is sufficient.

EE adds cryptographic audit integrity, multi-tenancy, SSO, an auditor portal, a BAA, and a 24×7 SLA — the items external auditors typically require before relying on a control component on its own.

If you're not sure which fits: start with OSS in observation mode against real traffic. Decide based on what your auditor or procurement function asks for. Migration from OSS to EE is incremental.

---

## 10. Where to go next

- [Compliance — evidence vs assurance framing](compliance.md)
- [Architecture — what OSS and EE share](architecture.md)
- [Quickstart — start with OSS](quickstart.md)
- [enforcegrid.com](https://enforcegrid.com) — EE product page
