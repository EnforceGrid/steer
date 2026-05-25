# Multi-tenant agent governance

*Stub — full operator playbook is on the v0.2 roadmap.*

OSS Steer is single-tenant. The runtime primitives that support multi-tenant agent governance are present in v0.1.0 but the operator playbook for composing them — particularly for governing third-party AI vendors you don't own — is deferred.

## What exists in v0.1.0

- **Tenant-overlay policy directories.** Drop `.cedar` files under `<policy_dir>/<tenant_id>/` and they load on top of the baseline. (EE adds tenant resolution and per-tenant isolation; OSS treats the single tenant as `default`.)
- **`pii_findings: Set<String>`** in the Cedar context — per-tenant pattern lists can drive per-tenant block scope.
- **Observation mode** (`policy.mode: observe`) — flip per-deployment to roll out a vendor onto your governance plane without blocking their agent first.
- **`@regulatory_mapping`** annotations propagate into audit so per-vendor compliance attribution is possible at the SIEM layer.

## What's deferred to v0.2

- **Per-vendor tenant isolation in OSS.** Today, OSS is single-tenant; EE has multi-tenant. The OSS path to per-vendor governance is *N* parallel Steer instances behind a router, one per vendor.
- **Per-vendor audit correlation.** A pattern for joining audit streams across vendors with a common correlation key (e.g., per-customer per-task) — useful for cross-vendor incident response.
- **Vendor-revocation pattern.** A documented operator workflow for cutting off a specific third-party AI agent without restarting the proxy.
- **Vendor identity attestation.** Cryptographic identity for the calling vendor agent (sender-pays-attestation pattern) so the audit log is tamper-resistant against client-side spoofing.

## Until v0.2 ships

If you need per-vendor governance today:

1. **Run one Steer instance per vendor** behind a routing layer (NGINX, HAProxy, or a custom reverse proxy that inspects the `EG-Vendor-Id` header). Each instance gets its own `steer.yaml` with its own `policy_dir` and audit sink.
2. **Tag audit entries** with the vendor identity via a custom `EG-Agent-Id` header your router sets; the audit emitter writes it into `agent_id`.
3. **Use observation mode** for new vendor onboarding. Watch their would-have-blocked events for 1–2 weeks before flipping to enforce.
4. **EE if you need this at scale.** Multi-tenancy with per-tenant isolation, per-tenant policy, per-tenant audit is in EnforceGrid Enterprise — see [docs/enterprise.md](enterprise.md).

If you have a specific multi-vendor scenario you'd like guidance on, open an [issue](https://github.com/EnforceGrid/steer/issues). We want the v0.2 playbook grounded in real operator scenarios.

---

## Related

- [docs/policies.md](policies.md) — tenant-overlay model
- [docs/enterprise.md](enterprise.md) — EE multi-tenancy
- [docs/architecture.md](architecture.md) — audit fields useful for correlation
