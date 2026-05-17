# Steer

Runtime enforcement engine for AI agents. One URL change.

```
Your app  ──►  Steer (:8080)  ──►  OpenAI / Anthropic / Google / Bedrock / any LLM
                    │
                    ├─ 1. Scan request        PII · injection · jailbreak · exfiltration
                    ├─ 2. Evaluate policy     allow / flag / block / transform
                    ├─ 3. Forward to LLM      (only if not blocked)
                    ├─ 4. Scan response       confidential · exfiltration · bias
                    └─ 5. Evaluate policy     allow / flag / block / transform
```

---

## What Steer covers

**LLM providers** — point `base_url` at any of these and Steer routes through:

| Provider | How |
|---|---|
| OpenAI (GPT-4o, GPT-4o-mini, o1, o3…) | Native `/v1/chat/completions` |
| Anthropic (Claude 3.x, Claude 4.x) | Native `/v1/messages` |
| Google Gemini | Dedicated streaming parser |
| AWS Bedrock | Dedicated streaming parser |
| Azure OpenAI | OpenAI-compatible, set `base_url` to your Azure endpoint |
| Mistral | OpenAI-compatible |
| Cohere | OpenAI-compatible |
| Meta Llama (Ollama, Together, Groq…) | OpenAI-compatible |
| Any OpenAI-compatible endpoint | Falls through to `upstream` config |

**Agent frameworks** — any framework that lets you configure `base_url` works out of the box:

LangChain · LangGraph · CrewAI · AutoGen · Semantic Kernel · Mastra · any framework using the OpenAI or Anthropic SDK

**Compliance frameworks covered** — 23 Cedar policies + config-driven rate limiting map across: OWASP Agentic AI Top 10 (all 10), EU AI Act (Art. 5/9/12/14/15/26/50/72), GDPR (Art. 5/6), NIST AI RMF, ISO 42001, Colorado SB205, MITRE ATLAS.

EU AI Act article coverage: Art. 5 (prohibited practices), Art. 9/12/14/15 (risk management, logging, human oversight, robustness), Art. 26 (deployer obligations), Art. 50 (AI identity transparency), Art. 72 (post-market monitoring). These map directly to Cedar policy categories — see `@regulatory_mapping` annotations in `dsl/policies/default.cedar`.

---

## Prerequisites

- **Rust** — install via [rustup](https://rustup.rs) (1.75 or later)
- **An API key** for your LLM provider

---

## Quick start

```bash
make setup          # copy steer.example.yaml → steer.yaml; install clippy + rustfmt
$EDITOR steer.yaml  # set your upstream API key
make dev            # build and start the proxy on :8080
```

To add Anthropic alongside OpenAI:

```yaml
providers:
  anthropic:
    base_url: "https://api.anthropic.com"
    api_key: "${ANTHROPIC_API_KEY}"

models:
  claude-sonnet-4-6:
    provider: anthropic
    model: claude-sonnet-4-6
```

Requests for a mapped model name route to that provider. Everything else falls through to `upstream`.

---

## Enforcement in action

The three examples below cover the three enforcement points. They use `/api/v1/policies/eval` — the same enforcement engine as the live proxy, against a context you supply. **No LLM key needed.**

### 1. Blocking a request before it reaches the LLM

A prompt injection attempt is detected. The policy blocks it — the LLM is never called.

```bash
curl -s http://localhost:8080/api/v1/policies/eval \
  -H "Content-Type: application/json" \
  -d '{
    "cedar_text": "permit(principal,action,resource); @id(\"block-injection\") @enforcement(\"block\") @description(\"Prompt injection attempt blocked\") forbid(principal,action,resource) when { context.injection_detected == true };",
    "action": "llm.request",
    "context": { "injection_detected": true, "model": "gpt-4o" }
  }'
```

```json
{ "decision": "block", "rule_id": "block-injection", "description": "Prompt injection attempt blocked" }
```

### 2. Blocking a response before it reaches the client

The LLM responded with content containing confidential data. Steer intercepts it before the client sees it.

```bash
curl -s http://localhost:8080/api/v1/policies/eval \
  -H "Content-Type: application/json" \
  -d '{
    "cedar_text": "permit(principal,action,resource); @id(\"block-confidential\") @enforcement(\"block\") @description(\"Confidential data in LLM response blocked\") forbid(principal,action,resource) when { context.confidential_detected == true };",
    "action": "llm.response",
    "resource": "response",
    "context": { "confidential_detected": true }
  }'
```

```json
{ "decision": "block", "rule_id": "block-confidential", "description": "Confidential data in LLM response blocked" }
```

### 3. Blocking a tool call

An agentic response requests a tool with a `privilege_escalation` risk category. Steer blocks it before execution.

```bash
curl -s http://localhost:8080/api/v1/policies/eval \
  -H "Content-Type: application/json" \
  -d '{
    "cedar_text": "permit(principal,action,resource); @id(\"block-privesc\") @enforcement(\"block\") @description(\"Privilege escalation tool call blocked\") forbid(principal,action,resource) when { context.tool_highest_risk_category == \"privilege_escalation\" };",
    "action": "tool.call",
    "resource": "response",
    "context": { "tool_name": "sudo_exec", "tool_highest_risk_category": "privilege_escalation" }
  }'
```

```json
{ "decision": "block", "rule_id": "block-privesc", "description": "Privilege escalation tool call blocked" }
```

---

## Sending real requests

Point your SDK's `base_url` at `http://localhost:8080`. No other changes needed.

```bash
curl http://localhost:8080/health
# → {"status":"ok"}

curl http://localhost:8080/v1/chat/completions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"What is the capital of France?"}]}'
```

Every proxied request produces an audit entry on stdout:

```json
{"action":"llm.request","decision":"allow","tenant_id":"default","model":"gpt-4o-mini","pii_detected":false}
```

---

## Observation mode

The safest first deployment: all policies in `flag` mode, no blocking. Steer logs every signal without ever rejecting a request.

In observation mode the hot path is near-zero overhead — detectors run asynchronously after the response is sent, so they add nothing to latency. The audit log fills up with real signal from your actual traffic. When you're confident in a detector, flip the policy to `block`.

**To deploy in observation mode:** the default policy set ships entirely in `flag` mode (except exfiltration and privilege escalation, which block). No config change needed — this is the default.

**To promote a specific policy to enforce:**

```
# In dsl/policies/default.cedar — change one annotation:
@enforcement("flag")   →   @enforcement("block")
```

Set `policy.watch: true` in `steer.yaml` to hot-reload without restart.

---

## Policies

23 policies ship in `dsl/policies/default.cedar`. Add your own `.policy` files alongside them — they load automatically.

**Content safety**

| Policy | Enforcement | Trigger |
|---|---|---|
| `default-injection-flag` | flag | Prompt injection pattern |
| `default-jailbreak-flag` | flag | Jailbreak attempt |
| `default-threat-flag` | flag | Threatening content |
| `default-identity-flag` | flag | AI identity claim in response |
| `default-bias-flag` | flag | Potential bias in response |

**Data protection**

| Policy | Enforcement | Trigger |
|---|---|---|
| `default-pii-flag` | flag | PII in request |
| `default-confidential-flag` | flag | Confidential data in response |
| `default-confidential-redact` | **transform** | Classification markers → `[CLASSIFICATION REDACTED]` |
| `default-no-consent-flag` | flag | Data processing consent not recorded |
| `default-data-residency-flag` | flag | Model outside tenant's required data region |

**Exfiltration**

| Policy | Enforcement | Trigger |
|---|---|---|
| `default-exfiltration-request-block` | **block** | Exfiltration instruction in request |
| `default-exfiltration-block` | **block** | Exfiltration pattern in LLM response |
| `default-exfiltration-tool-block` | **block** | Exfiltration pattern in tool response |

**Tool governance**

| Policy | Enforcement | Trigger |
|---|---|---|
| `default-tool-count-flag` | flag | Excessive tool calls (> 5) |
| `default-unauthorized-tool-flag` | flag | Tool matches dangerous-name heuristic |
| `default-code-execution-risk-flag` | flag | Tool with code execution risk |
| `default-privilege-escalation-block` | **block** | Privilege escalation tool |
| `default-credential-access-block` | **block** | Credential access tool |

**Operational**

| Policy | Enforcement | Trigger |
|---|---|---|
| `default-budget-block` | **block** | Token budget exhausted |
| `default-prohibited-block` | **block** | Risk level set to `prohibited` |
| `default-no-fallback-flag` | flag | Model has no fallback configured |
| `default-unapproved-model-flag` | flag | Model not in approved registry |
| `default-anomaly-flag` | flag | Anomalous traffic pattern |

---

## Configuration

`make setup` creates `steer.yaml` from `steer.example.yaml`. Key sections:

```yaml
upstream:
  base_url: "https://api.openai.com"
  api_key: "${OPENAI_API_KEY}"      # env-var substitution supported

policy:
  policy_dir: "./dsl/policies"
  watch: false                       # set true for hot-reload on file change

audit:
  backend: stdout                    # stdout | file
  retain_payloads: masked            # never | masked | raw
```

Full reference: `steer.example.yaml`.
### Fail-open behaviour

`proxy.fail_open` controls what happens if Steer encounters a runtime fault during policy evaluation — not a normal block decision, but an internal error.

| Setting | Behaviour |
|---|---|
| `fail_open: false` *(default)* | Policy errors are treated as blocks. The agent receives an error response. Correct default for regulated environments. |
| `fail_open: true` | Policy errors let the request through to the LLM. The agent continues; the fault is logged. Useful during initial rollout to avoid disruption while validating your policy set. |

Note: fail_open is not the same as a proxy outage. If Steer is unreachable, agents call the LLM directly — that is inherent to the proxy topology and is not controlled by this setting. Fail-open only governs policy evaluation faults within a running Steer process.


---

## Benchmarks

CPU enforcement overhead measured with Criterion.rs on Apple M-series (arm64, release build). Benchmarks isolate enforcement cost — no upstream network, no disk I/O.

**Enforcement pipeline (median)**

Benchmarks are organised into tiers so the cost of each layer is measurable:

| Tier | What runs | 100c | 500c | 2000c |
|---|---|---|---|---|
| Tier 0 — Cedar eval, sparse context | Raw Cedar overhead | 37 µs | 37 µs | 37 µs |
| Tier 1 — Cedar eval, full context | Cedar at production context size | 53 µs | 53 µs | 53 µs |
| Tier 2 — Cedar + 5 detectors | Detection pipeline, no PII | 56 µs | 63 µs | 98 µs |
| **Tier 3 — Full pipeline** | **Cedar + PII + 5 detectors** | **59 µs** | **67 µs** | **102 µs** |

All targets met: Tier 0 p99 < 500 µs ✓ · Tier 3 p99 (500c) < 2 ms ✓ · Tier 3 p99 (2000c) < 8 ms ✓

Phase isolation at 500 chars (median):

| Phase | Time |
|---|---|
| PII scan | 1.3 µs |
| 5× content detectors | 7.5 µs |
| Streaming buffer (100 frames) | 4.6 µs |
| Cedar eval (full context) | 53 µs |

**Throughput ceiling (k6, mock upstream)**

Load-tested with k6 against a 60ms mock upstream on the same Apple M-series hardware. Full enforcement pipeline active (Cedar + 5 detectors + PII). All three processes — k6, Steer, mock — sharing one laptop.

| Max VUs | Peak RPS | Error rate | p50 | p95 |
|---|---|---|---|---|
| **750** | **1,374 req/s** | **0.00%** | 351 ms | 725 ms |
| 1,500 | 1,401 req/s | 10.8% | 716 ms | 1,555 ms |

At 750 VUs errors are zero — that is the clean operating range on shared hardware. Errors appear at 1,500 VUs when the laptop CPU saturates across all three processes, not a Steer-specific bottleneck. On a dedicated server with k6 running externally, throughput scales substantially higher. Upstream LLM rate limits (typically 500–10,000 RPM) are the practical binding constraint before Steer saturates.

**End-to-end latency overhead (k6, live endpoint)**

20 VUs · 5 min · 26,917 requests · Railway production (Singapore) · client in India (~60ms RTT) · OpenAI `gpt-4o-mini`:

| Path | p50 | p95 | p99 |
|---|---|---|---|
| Through Steer | 334 ms | 509 ms | 698 ms |
| Direct to OpenAI | 278 ms | 374 ms | 688 ms |
| **Overhead** | **+56 ms** | **+134 ms** | **+10 ms** |

The +56ms p50 overhead is the extra network hop (client → Singapore proxy → OpenAI), not enforcement. Enforcement CPU cost is ~0.1ms — noise at this scale. At p99, upstream LLM variance dominates; Steer adds ~10ms. Co-located deployments (client and proxy in the same region) see overhead close to the Criterion numbers.

Run `make bench` for Criterion results (HTML report: `target/criterion/index.html`). Run `make load` for the k6 throughput ceiling test (requires node + k6).

---

## Development

```
make help      # list all targets
make check     # fmt check + linter + cargo check
make test      # run library tests
make ci        # full CI gate: check + test
make bench     # Criterion microbenchmarks
make load      # k6 throughput test against mock upstream (requires node + k6)
make env       # show environment variable status
```

---

## License

Apache 2.0 — see [LICENSE](LICENSE).

Enterprise features (SSO/OIDC, RBAC, compliance reporting, multi-tenancy, hash-chained audit) are available under a commercial license at [enforcegrid.com](https://enforcegrid.com).
