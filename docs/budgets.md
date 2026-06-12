# Budgets

In-memory USD caps per scope, with period rollover. The pipeline checks remaining budget before evaluating policy and records spend after upstream responds. The shipped `default-budget-block` Cedar rule blocks any request when the consulted scope is exhausted.

OSS persists nothing across restarts. EE persists spent state via SQLite.

---

## 1. Quick start

Minimal config that lets you observe the full lifecycle during an evaluation:

```yaml
budget:
  budgets:
    - scope: "agent"
      scope_id: "anonymous"  # default agent_scope_id when no eg-agent-id header is sent
      amount_usd: 1.00       # low cap so you can trip the block during a session
      period: "daily"        # resets at UTC midnight
  check_interval_secs: 30    # how often the rollover task polls; default 30s
```

Fire requests against Steer without any `eg-agent-id` header — they all bucket into the `"anonymous"` agent budget. Watch `budget_remaining_cents` and `budget_utilization_pct` in audit `context_snapshot` entries. After about $1 of upstream cost, the next request returns HTTP 400 with `rule_id: "default-budget-block"`.

> **Why agent / anonymous and not tenant / default?** OSS skips the `tenant` scope check entirely when `tenant_id == "default"` (`pipeline/mod.rs:536-540`). The agent scope works out of the box; tenant doesn't.

---

## 2. Patterns

Four common shapes. Pick the one that matches your intent; you can stack them.

### Pattern A — eval sandbox cap

What you saw in §1. Use it to trial Steer end-to-end on a single dev machine.

```yaml
budget:
  budgets:
    - scope: "agent"
      scope_id: "anonymous"
      amount_usd: 1.00
      period: "daily"
```

**When to use:** first-time setup, demos, single-developer sandbox. Any request that doesn't carry an `eg-agent-id` header lands in the `anonymous` bucket and decrements this cap.

### Pattern B — per-API-key cap

Each developer or client gets their own Steer-issued key with their own cap. The gating scope is `api_key`, and `scope_id` is the **sha256 of the value clients send in the `eg-api-key` header** (`headers.rs:105`, `pipeline/mod.rs:516`, `hash_api_key` at `pipeline/mod.rs:2768-2773`).

> **Important:** Steer's `eg-api-key` is its own identification header, distinct from the upstream provider's auth (`x-api-key` for Anthropic, `Authorization: Bearer` for OpenAI). Clients send both: `eg-api-key` for Steer identity, and the upstream auth header for the LLM provider. If `eg-api-key` is absent, `eg.api_key` is `None` and api_key budget tracking is silently a no-op for that request.

```yaml
budget:
  budgets:
    # alice: sha256 of "alice-team-key-value"
    - scope: "api_key"
      scope_id: "a1b2c3d4e5f6...."   # see hash command below
      amount_usd: 5.00
      period: "daily"
    # bob: sha256 of "bob-team-key-value"
    - scope: "api_key"
      scope_id: "9f8e7d6c5b4a...."
      amount_usd: 10.00
      period: "daily"
```

Compute the hash with:

```bash
echo -n "alice-team-key-value" | shasum -a 256 | cut -d ' ' -f 1
```

Clients send the eg-api-key header alongside the upstream auth header:

```bash
curl -X POST http://localhost:8080/v1/messages \
  -H "eg-api-key: alice-team-key-value" \
  -H "x-api-key: $ANTHROPIC_API_KEY" \
  -H "anthropic-version: 2023-06-01" \
  -H "Content-Type: application/json" \
  -d '{"model":"claude-sonnet-4-6","max_tokens":50,"messages":[{"role":"user","content":"hi"}]}'
```

Steer hashes the inbound `eg-api-key` value, matches against `scope_id`, decrements the matched budget.

**When to use:** charging different teams or clients against separate caps from a shared Steer deployment. **Gotcha:** no wildcard support — every distinct `eg-api-key` value needs its own sha256 entry.

### Pattern C — per-agent cap

Each agent identity gets its own cap. The client sends `eg-agent-id: <name>` and Steer keys the budget off the literal header value (`headers.rs:102`).

```yaml
budget:
  budgets:
    - scope: "agent"
      scope_id: "support-bot"
      amount_usd: 2.00
      period: "daily"
    - scope: "agent"
      scope_id: "research-bot"
      amount_usd: 20.00
      period: "daily"
```

Client sends:

```bash
curl -X POST http://localhost:8080/v1/messages \
  -H "eg-agent-id: support-bot" \
  -H "x-api-key: $ANTHROPIC_API_KEY" \
  -H "anthropic-version: 2023-06-01" \
  -H "Content-Type: application/json" \
  -d '{"model":"claude-sonnet-4-6","max_tokens":50,"messages":[{"role":"user","content":"hi"}]}'
```

**When to use:** running multiple agent personas behind a single LLM provider key, want spend isolated per persona. **Gotcha:** clients without `eg-agent-id` fall back to the literal string `"anonymous"` (`pipeline/mod.rs:517`) — set an explicit budget for `"anonymous"` or those requests share a single bucket.

### Pattern D — soft warning + hard block (custom Cedar)

Default policy only ships a hard block at zero. Stack a flag-level warning at high utilization by dropping a custom rule into `./dsl/policies/`. Useful for ops alerting before the block actually fires.

`./dsl/policies/budget-warning.cedar`:

```cedar
@id("custom-budget-warning-80")
@category("operational")
@enforcement("flag")
@description("Budget utilization above 80% — flag for review")
forbid(principal, action, resource)
when { context.budget_utilization_pct >= 80 };
```

`policy.watch: true` in `steer.yaml` hot-reloads this without a restart. Audit entries at 80–99% utilization show `custom-budget-warning-80` in `matched_rules` without `default-budget-block`. At 100% (`budget_remaining_cents == 0`) both rules match — your alerting pipeline pages on the first, blocking takes over at the second.

**When to use:** production, where surprise blocks are bad. Pair with a Slack/PagerDuty webhook off the audit stream.

### Stacking and the asymmetry to know

You can configure entries from multiple patterns simultaneously. The check picks one scope per request (api_key → tenant → agent precedence, first match); spend records against **all** configured scopes the request maps to. See [§5](#5-check-vs-spend-recording) for details.

A typical OSS shape uses one budget per traffic class. The precedence is what segments the classes:

```yaml
budget:
  budgets:
    # Authenticated team traffic — gated by api_key
    - scope: "api_key"
      scope_id: "<sha256 of team-alpha eg-api-key value>"
      amount_usd: 50.00
      period: "daily"
    # Unauthenticated traffic (no eg-api-key header) — gated by agent/anonymous
    - scope: "agent"
      scope_id: "anonymous"
      amount_usd: 1.00
      period: "daily"
```

A request carrying the team's `eg-api-key` hits the api_key bucket and only the api_key bucket gates. A request without `eg-api-key` falls through (no match on api_key → tenant skipped in OSS → matches `agent`/`anonymous`) and the agent bucket gates instead.

> **What spend recording does NOT do.** Even though spend is recorded against every configured scope the request maps to (api_key, agent, and tenant — see [§5](#5-check-vs-spend-recording)), the *check* only consults the first-matched scope. A non-matched bucket exhausting silently in the background does not block — Cedar never sees its `remaining_cents`. If you want a backstop that actually gates, your traffic shape has to be such that the backstop becomes the matched scope (e.g. by dropping the `eg-api-key` header).
>
> **No global tenant ceiling in OSS.** The `tenant` scope check is hard-skipped when `tenant_id == "default"`. Use stacked `api_key` entries if you want hard-team segmentation across multiple teams.

---

## 3. Verify it's working

Quick recipes to confirm what you've configured is actually doing what you think.

### A. Watch budget state live during traffic

If you set `audit.backend: file` and `audit.log_path: ./audit.jsonl`:

```bash
tail -f ./audit.jsonl | jq -c 'select(.context_snapshot.budget_remaining_cents != -1) | {
  t: .timestamp,
  scope_id: .agent_id,
  remaining_cents: .context_snapshot.budget_remaining_cents,
  util_pct: .context_snapshot.budget_utilization_pct,
  action: .enforcement.action,
  rule: .enforcement.rule_id
}'
```

You should see `remaining_cents` decrement after each completed request. If `remaining_cents` stays at `-1` → no budget matched your request's scope (check the precedence in [§5](#5-check-vs-spend-recording) and the `scope_id` derivation in [§4](#scope_id-derivation)).

### B. Force a block

Lower the cap to a few cents, then loop a cheap request until the block hits. The loop below exercises the **Pattern A (agent / anonymous)** setup — no `eg-agent-id` header, so every request lands in the `anonymous` bucket:

```bash
# Set amount_usd: 0.05 for the "anonymous" agent entry in steer.yaml, restart, then:
for i in $(seq 1 20); do
  curl -sS -X POST http://localhost:8080/v1/messages \
    -H "x-api-key: $ANTHROPIC_API_KEY" \
    -H "anthropic-version: 2023-06-01" \
    -H "Content-Type: application/json" \
    -d '{"model":"claude-sonnet-4-6","max_tokens":50,"messages":[{"role":"user","content":"hi"}]}' \
    -o /dev/null -w "%{http_code}\n"
done
```

When the budget exhausts you'll see the response code flip from `200` to `400`. The corresponding audit entry has `enforcement.rule_id: "default-budget-block"`.

For Pattern B or C, add `-H "eg-api-key: <value>"` or `-H "eg-agent-id: <name>"` so the request matches the intended scope.

### C. Confirm rollover is registered

Search stderr/stdout for the rollover event:

```bash
grep "budget period reset" steer.log
```

If you never see this, either the rollover task isn't running (check `check_interval_secs`) or no period boundary has passed since startup. For a `daily` budget, force-test the rollover by setting your machine clock back 23h before starting, then advance — or just wait for UTC midnight.

### D. Confirm your model is priced

If `remaining_cents` doesn't decrement at all after a successful upstream call, the model probably isn't in the pricing table at `src/config/mod.rs:589-668`. Check by grepping:

```bash
grep -i "your-model-name" src/config/mod.rs
```

No match → cost is computed as `0.0` (`tokens/costs.rs:42`), and budget tracking is a silent no-op for that traffic. Add a custom pricing entry to your `steer.yaml` if your model isn't shipped (see provider docs for the override schema).

### E. Common "why isn't this working?" checklist

| Symptom | Likely cause |
|---|---|
| `budget_remaining_cents: -1` on every request | No `BudgetEntry` matched. Check scope precedence (api_key → tenant → agent) and that your `scope_id` exactly matches the derivation rule. |
| `remaining_cents` stays at cap after upstream calls | Model isn't in the pricing table → cost = 0. See recipe D. |
| Budget seems to "refund" mysteriously | OSS process restarted (spent is in-memory only). See [§11](#11-persistence). |
| Per-API-key budget never matches | Client isn't sending the `eg-api-key` header (different from upstream auth), or `scope_id` isn't the sha256 of the header value. See Pattern B. |
| Per-agent budget never matches | Client isn't sending `eg-agent-id` header, or the header value doesn't exactly match `scope_id`. Missing header buckets to `"anonymous"`. |
| Tenant budget never matches in OSS | OSS skips tenant scope when `tenant_id == "default"` (`pipeline/mod.rs:536`). Use `api_key` or `agent` scope in OSS. |

---

## 4. Config reference

`audit.backend = stdout` and `audit.format = json` recommended during budget evaluation — `budget_remaining_cents` is in `context_snapshot`, which the `compact` format does not emit.

### `BudgetConfig`

Defined at `src/config/mod.rs:94-102`.

| Field | Type | Default | Notes |
|---|---|---|---|
| `budgets` | `Vec<BudgetEntry>` | `[]` | Empty list disables budget tracking entirely. |
| `check_interval_secs` | `u64` | `30` | How often the async rollover task checks for period boundaries. |

### `BudgetEntry`

Defined at `src/config/mod.rs:104-114`.

| Field | Type | Accepted values | Notes |
|---|---|---|---|
| `scope` | `String` | `"api_key"`, `"agent"`, `"tenant"` | Unknown strings load without error and never match at runtime. |
| `scope_id` | `String` | Exact-match identifier | Wildcard match is called out as future work at `config/mod.rs:93`. |
| `amount_usd` | `f64` | Positive USD cap | No internal validation; nonsense values load. |
| `period` | `String` | `"daily"`, `"weekly"`, `"monthly"` | Unknown periods default to a 1-day rollover at `tokens/yaml_source.rs:22`. |

### `scope_id` derivation

How the runtime resolves `scope_id` for an inbound request:

| `scope` | `scope_id` source |
|---|---|
| `api_key` | `sha256` of the **`eg-api-key` request header value** (trimmed, UTF-8 bytes), via `hash_api_key()` at `pipeline/mod.rs:2768-2773`. Hash call site: `pipeline/mod.rs:516`. The upstream provider's auth header (`Authorization`, `x-api-key`) is not used. |
| `agent` | `EG-Agent-Id` header (`headers.rs:102`); falls back to the literal string `"anonymous"` when absent. |
| `tenant` | Resolved from the API-key→tenant mapping; in single-tenant OSS the value is the literal string `"default"`. |

If the request can't supply the required identifier (e.g. `scope: "api_key"` with no auth header), the budget check returns `None` for that scope and the next scope in precedence is consulted.

---

## 5. Check vs. spend recording

Two distinct passes per request, with **asymmetric** scope handling. This is the single most important behavior to internalize.

### Check (pre-upstream): first match wins

`pipeline/mod.rs:531-542` consults scopes in fixed precedence and short-circuits on the first match:

```
api_key → tenant (unless tenant_id == "default") → agent
```

Only the matched scope's `budget_remaining_cents` is surfaced into the Cedar context. `default-budget-block` fires when this value is `0`.

### Spend recording (post-upstream): all configured scopes

`pipeline/mod.rs:2167-2189` records cost against **every** scope that the request maps to, regardless of which one gated the check:

- `api_key` — recorded if the auth header was present (line 2168)
- `agent` — recorded always except when `agent_id` is empty (line 2176)
- `tenant` — recorded when `tenant_id != "default"` (line 2182)

**Concrete implication.** If you configure both an `api_key` budget and an `agent` budget for the same traffic and the request carries an `eg-api-key` header, the check uses **only** the `api_key` bucket. Cedar's `default-budget-block` evaluates `context.budget_remaining_cents`, which contains the api_key bucket's remaining — never the agent bucket's. The agent bucket still decrements (visible in audit if you query that scope separately), but its exhaustion is invisible to Cedar and **does not block**. Only the matched scope can gate. If you want a backstop that actually gates, you have to make sure your traffic falls through to it — e.g. by omitting the higher-precedence scope's identifier (no `eg-api-key` header → agent becomes the matched scope).

### Blocked requests do not record spend

`pipeline/mod.rs:681` returns to the client before the upstream call and before the spend spawn at line 2148 fires. A request blocked by `default-budget-block` is free.

---

## 6. Cost estimation

Cost is computed twice per request:

1. **Pre-request heuristic** at `pipeline/mod.rs:519` — fixed estimate of 1000 prompt + 500 completion tokens against the request model. Result is computed but not currently used for the budget check (the check uses cached `spent_usd`, not a pre-request projection). Held for future failover logic.

2. **Post-response actual** at `pipeline/mod.rs:2151` — costed from the upstream's reported `usage` block via `CostEstimator::estimate()` (`tokens/costs.rs:34-44`).

Pricing table lives at `src/config/mod.rs:589-668` and ships with ~10 models including the Claude and GPT families. **Models not in the pricing table cost `0.0`** (`tokens/costs.rs:42`). If you proxy traffic for a model Steer doesn't price, budget tracking is silently a no-op for those calls. Add the model to the YAML pricing table to fix it.

---

## 7. Period rollover

Logic at `src/tokens/yaml_source.rs:17-24,75-118`.

| Period | Reset boundary |
|---|---|
| `daily` | Next UTC midnight |
| `weekly` | Next Monday 00:00 UTC |
| `monthly` | Next 1st of month, 00:00 UTC |

A background tokio task polls every `check_interval_secs`. When `reset_at <= now`, it atomically replaces the cache entry — `spent_usd` resets to `0`. There is no per-request rollover check; the granularity of rollover detection is bounded by `check_interval_secs`.

**Mid-rollover request behavior is unverified from code.** A request in flight at the exact boundary will use whichever balance was loaded into its `request_context_params` at line 591-607 — typically the pre-rollover value.

---

## 8. Cedar integration

### Fields surfaced into context

| Field | Type | Sentinel | Notes |
|---|---|---|---|
| `budget_remaining_cents` | `i64` | `-1` = no budget configured for any consulted scope | USD × 100, truncated to integer. |
| `budget_utilization_pct` | `i64` | `-1` = no budget configured | Whole-percent, 0–100. |

Both fields are always present in the context, so Cedar rules don't need `has` guards (`policy/input.rs:194-240`).

### Shipped rule

The default policy includes one rule that consumes budget signals (`dsl/policies/default.cedar:132-139`):

```cedar
@id("default-budget-block")
@category("operational")
@enforcement("block")
@description("Token budget exhausted — request blocked")
forbid(principal, action, resource)
when { context.budget_remaining_cents == 0 };
```

The rule applies to every action (`llm.request`, `llm.response`, `tool.call`), but since the check happens at request evaluation, it effectively blocks at the request boundary. Custom warning rules can be written against `budget_utilization_pct` — e.g. a flag at 90% utilization:

```cedar
@id("custom-budget-warning")
@enforcement("flag")
forbid(principal, action, resource)
when { context.budget_utilization_pct >= 90 };
```

---

## 9. Audit fields

Per-request budget signals land in `context_snapshot` of the audit entry. Visible only in `audit.format: json` or `pretty` — the compact one-line format (`audit/mod.rs:105-244`) does not include them.

```json
{
  "context_snapshot": {
    "budget_remaining_cents": 0,
    "budget_utilization_pct": 100,
    "...": "..."
  },
  "enforcement": {
    "action": "block",
    "rule_id": "default-budget-block",
    "matched_rules": [
      {"rule_id": "default-budget-block", "action": "block", "category": "operational"}
    ]
  }
}
```

### Block response

`default-budget-block` returns `HTTP 400` with the standard policy-block payload from `src/error.rs:51-73`:

```json
{
  "error": {
    "type": "policy_block",
    "code": "policy_block",
    "message": "Request blocked by policy: default-budget-block"
  }
}
```

The `eg-audit-id` response header (`pipeline/mod.rs:2104-2105`) links the client back to the audit entry. There is **no budget-specific status code or header** distinguishing budget blocks from content blocks — clients have to read the `rule_id` from either the body or the audit entry.

---

## 10. Observability

Tracing events operators can grep:

| Event | Level | Source |
|---|---|---|
| `"budget period reset"` with `scope`, `scope_id`, `period` fields | `info` | `tokens/yaml_source.rs:108-113` |
| `"budget spend update (api_key) failed"` (or `agent`/`tenant`) | `warn` | `pipeline/mod.rs:2170, 2177, 2185` |
| `"BudgetCache refresh failed"` | `warn` | `tokens/cache.rs:190` (EE only) |

No dedicated event for "request blocked by budget" — the standard Cedar block path emits the audit entry with `rule_id: "default-budget-block"`. Grep audits for `enforcement.action == "block"` combined with `context_snapshot.budget_remaining_cents == 0` to isolate.

### No inspection endpoint

There is **no HTTP endpoint** to query current `spent_usd` or remaining balance. Inspection options are:

- Tail the most recent audit entry for the scope of interest and read `budget_remaining_cents` from `context_snapshot`.
- Watch stderr/stdout for `"budget period reset"` events to see when rollovers occurred.

This is a known gap. EE adds a query API via the SQLite-backed source.

---

## 11. Persistence

| Edition | Cache backing | Restart behavior |
|---|---|---|
| **OSS** | In-memory `HashMap` behind `parking_lot::RwLock` (`tokens/cache.rs:73`), seeded from YAML at startup. | Spent resets to 0 on every binary restart. Next request sees the full cap available. |
| **EE** | SQLite via `BudgetSource` trait swap (`tokens/cache.rs:23,179-194`). | Survives restarts; cache refreshes from DB every `check_interval_secs`. |

OSS deployments should treat budgets as **soft rate-limits on a single process**, not as accounting truth. Anything requiring durable spend tracking needs the EE source or external reconciliation against your provider's billing API.

---

## 12. Limitations and gotchas

- **Exact-match `scope_id` only.** Wildcard support is future work (`config/mod.rs:93`). To budget "any of these N API keys," you need N entries — one per sha256 hash.
- **Unknown models cost zero.** If your traffic uses a model not in the pricing table at `config/mod.rs:589-668`, budget tracking silently no-ops for those requests. Audit `budget_remaining_cents` will not decrement.
- **Tenant scope skipped in single-tenant OSS.** The check at `pipeline/mod.rs:536` explicitly skips `tenant` scope when `tenant_id == "default"`, but recording at line 2182 does the same skip. Net effect: tenant-scope budgets are dormant in OSS unless you've manually overridden the tenant resolution.
- **No YAML-level reload.** Changing `budget.budgets` requires a binary restart. Hot-reload via `policy.watch` covers Cedar files only, not the `budget` config section.
- **Heuristic estimate isn't budget-aware yet.** The pre-request estimate at line 519 is computed but unused for the budget check. The block decision uses the cached `spent_usd` from prior completed requests — a single in-flight expensive request can still complete after the pre-block check passes, even if it pushes `spent` past the cap. This makes budgets eventually-consistent under concurrent load.
- **`fail_open: true`** (the OSS default) means budget check failures fall through and allow the request. Flip to `fail_open: false` if you want budget exhaustion to never silently leak through under cache contention.

---

## 13. Where to go next

- [Architecture — audit entry shape, enforcement actions](architecture.md)
- [Policies — Cedar authoring, default rule reference](policies.md)
- [Multi-tenant — EE persistence and per-tenant budget isolation](multi-tenant.md)
