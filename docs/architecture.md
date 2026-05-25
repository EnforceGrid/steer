# Architecture

How Steer processes a request, what it emits, and how it fails.

---

## 1. Request lifecycle

```
┌──────────┐         ┌──────────────────────────────────────────────────────────┐         ┌──────────┐
│  Client  │ ───────▶│  Steer                                                   │ ───────▶│ Upstream │
│ (SDK,    │  HTTP   │  ┌────────────────────────────────────────────────────┐  │  HTTPS  │   LLM    │
│  agent,  │         │  │ 1. Route resolution (path → action, model → upstream│ │         │ provider │
│  curl)   │         │  │ 2. Request-side detectors (sync where blocking)    │  │         │          │
│          │         │  │ 3. Cedar evaluation (request action)               │  │         │          │
│          │         │  │ 4. Forward (or 403 with audit entry)               │  │         │          │
│          │         │  │ 5. Response stream — buffered detector pass         │  │         │          │
│          │         │  │ 6. Cedar evaluation (response / tool action)        │  │         │          │
│          │         │  │ 7. Audit emit (hot path) + async enrichment        │  │         │          │
│          │         │  └────────────────────────────────────────────────────┘  │         │          │
└──────────┘         └──────────────────────────────────────────────────────────┘         └──────────┘
                              │
                              ▼
                       ┌──────────────┐
                       │ Audit sink   │
                       │ stdout │ file│
                       └──────────────┘
```

Cedar evaluation is sub-millisecond. Detectors run async on the hot path **except** where a `block` decision requires a sync verdict (e.g., `default-secrets-block` must scan the request body before forwarding, or the credential reaches the upstream). The hot/async split is the reason for the two-stage audit model in [§4](#4-two-stage-audit).

---

## 2. Audit record schema

Every proxied request emits one JSON line to the configured audit sink. The schema is stable across v0.1.x — adding fields is a minor version, removing or renaming is a major version.

### Top-level fields

| Field | Type | Required | Notes |
|---|---|---|---|
| `audit_id` | `string` (16-char hex) | yes | Per-request UUID truncated to 16 chars |
| `timestamp` | `string` (RFC 3339) | yes | UTC, microsecond precision |
| `prev_hash` | `string` | omitted in OSS | Populated only by EE for hash-chain verification |
| `request` | `object` | yes | See [request fields](#request-fields) |
| `response` | `object` | yes | See [response fields](#response-fields) |
| `latency` | `object` | yes | `upstream_ms`, `cadabra_ms` |
| `pii_findings` | `array` | omitted when empty | One entry per detector match |
| `enforcement` | `object` | yes | The decision — see [enforcement fields](#enforcement-fields) |
| `streaming` | `object` | omitted when not streaming | Buffer flush counts, stream latency |
| `tenant_id` | `string` | omitted in single-tenant OSS | EE multi-tenancy |
| `agent_id` | `string` | optional | When client supplies `EG-Agent-Id` header |
| `provider` | `string` | optional | Resolved upstream identifier (`openai`, `anthropic`, etc.) |
| `labels` | `array` | omitted when empty | Typed detector labels for offline analysis |
| `detector_snapshot` | `object` | optional | Per-detector flag/score/version |
| `control_facts` | `object` | optional | Namespaced facts (`agent_integrity.injection_detected`, etc.) |
| `evidence_labels` | `array` | omitted when empty | Coarse-grained labels for compliance queries |
| `payload_redaction` | `string` | optional | `"inline"`, `"deferred"`, or `"none"` |

### Request fields

```json
{
  "method": "POST",
  "path": "/v1/chat/completions",
  "model": "gpt-4o-mini",
  "streaming": false
}
```

### Response fields

```json
{ "status_code": 403 }
```

Status code reflects what the client received. `403` on a Steer block; the upstream response status when forwarded.

### Latency fields

```json
{ "upstream_ms": 124.7, "cadabra_ms": 0.7 }
```

`cadabra_ms` is the total time spent in the Steer pipeline (detector + Cedar + audit serialization), in milliseconds.

> **Field rename in v0.2.** `cadabra_ms` will be renamed to `steer_ms`. A back-compat alias will emit both fields for one minor cycle so existing log pipelines have time to migrate.

### Enforcement fields

```json
{
  "action": "block",
  "rule_id": "default-exfiltration-request-block",
  "description": "Exfiltration instruction detected in request — pre-staged data routing attempt blocked",
  "regulatory_mapping": ["AIUC1_E003", "OWASP_AGENTIC_ASI07", "GDPR_ART_5", "MITRE_ATLAS_M0015"],
  "observed": false,
  "matched_rules": [
    {"rule_id": "default-exfiltration-request-block", "action": "block"},
    {"rule_id": "default-pii-flag", "action": "flag"}
  ]
}
```

- `action` — deciding action: `allow`, `flag`, `transform`, `steer`, `block`
- `rule_id` — the deciding policy `@id`
- `description` — populated from the policy's `@description` annotation
- `regulatory_mapping` — populated from the policy's `@regulatory_mapping` annotation
- `observed: true` — would-have-blocked event in observation mode (see [§5](#5-observation-mode))
- `matched_rules` — every policy that contributed to the decision, not just the winner
- `hold_id` — set when `action == "steer"` (EE handover queue link)
- `steer_message` — operator-facing reason text for held requests

### PII findings

```json
[
  {"pattern": "openai_key", "count": 1, "redaction_token": "[REDACTED_API_KEY]"}
]
```

Pattern name matches the YAML `pii.patterns` registry. Used to drive `context.pii_findings: Set<String>` for Cedar `containsAny`.

### Retention

OSS file sink is append-only with no built-in rotation. The shipped `purge_jsonl_file()` helper removes entries older than `retention_days` via temp-file + atomic rename; wire it to a cron task. Production deployments should pipe to a SIEM (Splunk, Datadog, OpenSearch) for long-term retention.

EE adds hash chaining via `prev_hash`, signed audit entries, and retention enforcement.

---

## 3. Cedar context schema

The `context` object Cedar policies read. Every field is always present; no `context has X` guards needed.

### Request facts

| Field | Type | Default | Description |
|---|---|---|---|
| `model` | `String` | `""` | Resolved model name from the request body |
| `streaming` | `bool` | `false` | True for SSE/streaming responses |
| `pii_detected` | `bool` | `false` | Any PII pattern matched (legacy convenience flag) |
| `pii_findings` | `Set<String>` | `[]` | Names of every matched pattern (`["openai_key", "ssn"]`) |
| `risk_level` | `String` | `""` | Tenant-configured risk classification |
| `consent_given` | `bool` | `false` | From `tenant.consent_given` in yaml |

### Detector signals

| Field | Type | Used by |
|---|---|---|
| `injection_detected` | `bool` | `default-injection-flag` |
| `jailbreak_detected` | `bool` | `default-jailbreak-flag` |
| `threat_detected` | `bool` | `default-threat-flag` |
| `identity_claim_detected` | `bool` | `default-identity-flag` |
| `confidential_detected` | `bool` | `default-confidential-flag` |
| `bias_detected` | `bool` | `default-bias-flag` |
| `anomaly_detected` | `bool` | `default-anomaly-flag` |
| `anomaly_type` | `String` | for downstream classification |
| `exfiltration_detected` | `bool` | `default-exfiltration-*-block` |
| `exfiltration_type` | `String` | first matched category |

### Tool governance

| Field | Type | Description |
|---|---|---|
| `tool_name` | `String` | Single tool call name |
| `tool_names` | `Set<String>` | All tool names in this response |
| `tool_count` | `Long` | Number of tool calls |
| `requested_tools` | `Set<String>` | Tools the request authorized |
| `tool_allowlist_mode` | `bool` | `false` = denylist heuristic, `true` = strict allowlist |
| `unauthorized_tool_detected` | `bool` | Tool name matches dangerous-name list |
| `tool_categories` | `String` | CSV of matched risk categories |
| `tool_highest_risk_category` | `String` | Highest-severity: `"code_execution"`, `"privilege_escalation"`, `"credential_access"`, ... |

### Operational

| Field | Type | Default | Description |
|---|---|---|---|
| `budget_remaining_cents` | `Long` | `-1` | `-1` = no budget configured |
| `budget_utilization_pct` | `Long` | `-1` | Percentage of budget consumed |
| `fallback_available` | `bool` | `false` | Current model route has fallback entries |
| `model_approved` | `bool` | `false` | Model is in the approved registry (`models:` block) |
| `data_residency_compliant` | `bool` | `false` | Model region matches `tenant.region` |

### Tenant facts

| Field | Type | Source |
|---|---|---|
| `org_timezone` | `String` | `tenant.timezone` (default `"UTC"`) |
| `org_industry` | `String` | `tenant.industry` (default `"other"`) |
| `org_region` | `String` | `tenant.region` |
| `org_business_hours_active` | `bool` | Derived from `tenant.business_hours_window` and current time |

### Supply chain

| Field | Type | Description |
|---|---|---|
| `mcp_server_approved` | `bool` | MCP server ID is in approved registry. **Defaults `false`** (restrictive). |
| `mcp_server_id` | `String` | From the `X-MCP-Server-ID` request header (case-insensitive) |

The Rust source of truth is `src/policy/input.rs::ContextParams`. Every field listed here corresponds 1:1 to a field there.

---

## 4. Two-stage audit

A blocking decision must be deterministic and fast. A complete evidence record can be richer than the hot path can afford. Steer splits these:

**Stage 1 — hot path (sync).** Detectors needed for blocking decisions run inline. Cedar evaluates. The base `AuditEntry` is serialized and emitted to the sink. The HTTP response goes back to the client. This is the path measured by `latency.cadabra_ms`.

**Stage 2 — enrichment (async).** Heavier detectors (cross-corpus similarity, embedding lookups, expensive ML classifiers) run after the response is on the wire. The enrichment writes a separate audit entry with `type: "enrichment"` and `parent_audit_id` pointing at the stage-1 record.

In the compact audit format, enrichment entries show as a dim line:

```
[ENRICH] parent=ab12cd34ef56...
```

Both entries land in the same audit log file or stdout stream; downstream consumers join on `audit_id` ↔ `parent_audit_id`.

---

## 5. Observation mode

`policy.mode: observe` in `steer.yaml` rewrites every `@enforcement("block"|"steer")` annotation to `@enforcement("flag")` **at policy load time** via `rewrite_enforcement_annotations()`. The rewrite is global — no per-policy edits required.

In observation mode:
- Every decision is logged.
- Would-have-blocked events carry `enforcement.observed: true` for filtering.
- No request is ever blocked.
- The startup log announces `loading policies in observation mode` once.

Switching modes is a config edit + restart. Flip back to `mode: enforce` after the would-have-blocked stream is quiet against your traffic. The audit log preserves the full history across both postures.

---

## 6. Fail modes

Steer sits on the request path. The failure semantics for each class:

| Class | Behaviour | Recovery |
|---|---|---|
| **Cedar evaluation error** | The shipped `steer.example.yaml` sets `proxy.fail_open: false`, which blocks any request whose Cedar evaluation errors and emits an audit entry. If `fail_open: true`, the request is forwarded with `action: "allow"` and a warning is logged. The Rust struct default is `true`, so any deployment that does not supply a yaml override must set `fail_open: false` explicitly for production. | Fix the offending policy; hot-reload picks it up |
| **Upstream timeout** | Steer returns the upstream's error response verbatim. No automatic retry. | Compose Steer behind LiteLLM / Portkey if you need retries |
| **Audit sink failure (file)** | `FileAuditSink::open` is fail-loud — Steer refuses to start with an actionable error. Per-write failures are logged to stderr but never panic the request path. | Fix permissions or path; restart |
| **Policy load failure at startup** | Steer logs the parse error with file path and refuses to start | Fix the `.cedar` syntax |
| **Policy load failure on hot-reload** | The new file is rejected; the previous policy set continues to evaluate. Error logged with file path. | Fix the file; the watcher picks it up |
| **Panic in worker** | tokio worker panic surfaces as HTTP 503 to the client. No silent corruption of the audit stream. | Investigate the stack trace; file a bug |
| **OOM** | Process exits. Health check sees the failure; the load balancer drains. | Restart; investigate the request that triggered it |

`proxy.fail_open: false` is the value the shipped `steer.example.yaml` sets, and it is the only safe value for production. `fail_open: true` may be useful during initial integration when a misconfigured policy could take down traffic — never run with it in production.

---

## 7. HA topology

Steer is stateless apart from the audit sink. Failover is a TCP-level concern.

```
                   ┌──────────────┐
                   │   Layer-4    │
                   │ Load Balancer│
                   └──────┬───────┘
            ┌─────────────┴─────────────┐
       ┌────▼────┐                ┌─────▼────┐
       │ Steer A │                │  Steer B │
       └────┬────┘                └─────┬────┘
            └─────────────┬─────────────┘
                          ▼
                  ┌──────────────┐
                  │   Upstream   │
                  │  (LiteLLM /  │
                  │  provider)   │
                  └──────────────┘
```

### Topology choices

| Pattern | When |
|---|---|
| **Single instance** | Local dev, small team, single host. No HA. |
| **Two behind LB** | Production baseline. Two Steer instances behind L4 LB, each writing to its own audit sink. Aggregate via SIEM. |
| **Sidecar** | One Steer per agent host (loopback). Lowest latency. Per-host audit volume. |
| **Gateway** | Single Steer pool fronting a fleet of agents. Centralized audit. Add capacity proportional to RPS. |

For full HA semantics (clustered audit, leader election, signed audit chains), see [docs/enterprise.md](enterprise.md).

---

## 8. Stacking with external detectors

The Cedar policy layer reads from `context.*`. Anything you put into context can be a policy input — that includes the verdict of a third-party detector you call before evaluation.

**Today's integration shape (v0.1.0):** an external classifier sits in front of Steer. The classifier inspects the request and sets a verdict header (e.g. `EG-Lakera-Verdict: clean|injection|jailbreak`). A custom Cedar policy reads the header — Steer exposes inbound headers to the policy context — and acts on it. This is operator-built glue, not a turnkey integration.

**Order:** `client → external classifier → Steer → upstream`. The classifier blocks on its own surface; Steer's audit captures the classifier's verdict alongside the Cedar decision, giving one log line per request with both signals.

**v0.2 roadmap:** a detector-plugin trait you implement in-process, with the verdict surfaced as a new typed field in `context.*`. The Cedar policy layer does not change.

---

## 9. Streaming

`/v1/chat/completions` and `/v1/messages` with `stream: true` produce a server-sent-events response. Steer buffers small windows (`streaming.buffer_size_bytes`, default 512; `streaming.buffer_timeout_ms`, default 200ms) so detectors can pattern-match across token boundaries before flushing.

The streaming audit entry carries:

```json
{
  "streaming": {
    "provider": "openai",
    "action": "allow",
    "bytes_received": 1480,
    "bytes_emitted": 1480,
    "buffer_flushes": {"on_boundary": 12, "on_size_cap": 3, "on_stream_end": 1},
    "latency": {"first_byte_ms": 318.4, "stream_duration_ms": 2840.1, "cadabra_ms": 2.1}
  }
}
```

If a response-side block fires mid-stream, Steer terminates the SSE connection with a `data: {"error":"blocked","rule_id":"..."}` frame followed by `[DONE]`. Already-emitted bytes cannot be retracted — the client has seen them.

---

## 10. Where to go next

- [Policies — Cedar authoring, the 23 baseline rules](policies.md)
- [Providers — base URL config, stacking with routers](providers.md)
- [Performance — benchmarks, methodology](performance.md)
- [Compliance — framework mapping, evidence framing](compliance.md)
