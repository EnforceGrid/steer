# Budgets User Guide

## Table of Contents

- [1. Overview](#1-overview)
- [2. Quickstart](#2-quickstart)
- [3. Budget Scopes](#3-budget-scopes)
  - [3.1 Sandbox cap](#31-sandbox-cap)
  - [3.2 Per client cap](#32-per-client-cap)
  - [3.3 Per-agent cap](#33-per-agent-cap)
  - [3.4 Stacking scopes](#34-stacking-scopes)
- [4. Policy](#4-policy)
  - [4.1 Utilization warning](#41-utilization-warning)
  - [4.2 Budget exhausted](#42-budget-exhausted)
- [5. Cost Estimation & Budget Check](#5-cost-estimation--budget-check)
  - [5.1 Cost Estimation](#51-cost-estimation)
  - [5.2 Budget Check & Spend Tracking](#52-budget-check--spend-tracking)
- [6. Audit Log](#6-audit-log)
- [7. Verify it's Working](#7-verify-its-working)
- [8. Why isn't it working? - Common Scenarios](#8-why-it-isnt-working--common-causes)
- [9. Observability](#9-observability)
- [10. Persistence](#10-persistence)
- [11. OSS (Open Source) & EE (Enterprise Ed)](#11-oss-open-source--ee-enterprise-ed)
- [12. Limitations](#12-limitations)
- [Appendix](#appendix)
  - [A.1 Custom Model Pricing](#a1-custom-model-pricing)

---

## 1. Overview

Steer's budget system lets you set USD spend caps on LLM traffic, with automatic period rollover. When a budget threshold is reached, the Cedar policy engine evaluates the request **before** it is sent to the upstream provider. Depending on your policy configuration, Steer can:

- **Block** — reject the request immediately, returning HTTP 400 to the client
- **Flag** — allow the request but mark it in the audit log for review
- **Steer** — route the request to a human or system review queue before proceeding

### Scopes

Budgets are defined per scope — the identity dimension Steer uses to group and track spend:

| Scope | What it tracks | Identified by |
|---|---|---|
| `agent` | Spend per named agent | `eg-agent-id` request header; falls back to `"anonymous"` when absent |
| `api_key` | Spend per Steer client key | SHA256 of the `eg-api-key` request header |
| `tenant` | Spend per tenant | Tenant resolved from the API key; only available in EE |

You can configure multiple budget entries across different scopes simultaneously. For each request, Steer checks scopes in precedence order (`api_key` → `tenant` → `agent`) and gates on the first match.

### Periods

Each budget entry resets on a `daily`, `weekly`, or `monthly` boundary. See [§5.2 Periodic Reset](#periodic-reset) for reset timing details.

### How budgets connect to policy

Steer surfaces two fields into the Cedar policy context for every request:

- `budget_remaining_cents` — remaining balance in cents (`-1` if no budget matched)
- `budget_utilization_pct` — whole-percent utilization, 0–100 (`-1` if no budget matched)

The default policy ships with one budget rule:

```cedar
@id("default-budget-block")
@category("operational")
@enforcement("block")
@description("Token budget exhausted — request blocked")
forbid(principal, action, resource)
when { context.budget_remaining_cents == 0 };
```

This fires when the matched scope's balance reaches zero and returns HTTP 400 to the client. You can write additional Cedar rules against `budget_utilization_pct` to flag or steer requests before the hard block fires — see [§4 Policy](#4-policy).

---

## 2. Quickstart

Minimal config to observe the full budget lifecycle. Add the following to your `steer.yaml`:

```yaml
budget:
  budgets:
    - scope: "agent"
      scope_id: "anonymous"  # default when no eg-agent-id header is sent
      amount_usd: 1.00       # low cap so you can trip the block during a session
      period: "daily"        # resets at UTC midnight
  check_interval_secs: 30    # how often the rollover task polls; default 30s
```

Fire requests against Steer without any `eg-agent-id` header — they all bucket into the `"anonymous"` agent budget. Watch `budget_remaining_cents` and `budget_utilization_pct` in audit `context_snapshot` entries. After about $1 of upstream cost, the next request returns HTTP 400 with `rule_id: "default-budget-block"`.

---

## 3. Budget Scopes

There are 3 different scopes for budget — each targeting a different identity dimension. You can also stack (combine) multiple scopes simultaneously, covered in §3.4.

### 3.1 Sandbox cap

Use this to trial Steer end-to-end on a single dev machine.

```yaml
budget:
  budgets:
    - scope: "agent"
      scope_id: "anonymous"
      amount_usd: 1.00
      period: "daily"
```

**When to use:** first-time setup, demos, single-developer sandbox. Any request that doesn't carry an `eg-agent-id` header lands in the `anonymous` bucket and decrements this cap.

### 3.2 Per client cap

Each client gets their own Steer-issued key with their own cap. A client can be a developer, a team, or a project — whatever unit of allocation fits your organization. The `scope_id` is the **SHA256 of the value clients send in the `eg-api-key` header**.

> **Important:** Steer's `eg-api-key` is its own identification header, distinct from the upstream provider's auth (`x-api-key` for Anthropic, `Authorization: Bearer` for OpenAI). Clients send both: `eg-api-key` for Steer identity, and the upstream auth header for the LLM provider. If `eg-api-key` is absent, api_key budget tracking is silently a no-op for that request.

```yaml
budget:
  budgets:
    # alice: sha256 of "alice-team-key-value"
    - scope: "api_key"
      scope_id: "a1b2c3d4e5f6...."
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

Clients send the `eg-api-key` header alongside the upstream auth header:

```bash
curl -X POST http://localhost:8080/v1/messages \
  -H "eg-api-key: alice-team-key-value" \
  -H "x-api-key: $ANTHROPIC_API_KEY" \
  -H "anthropic-version: 2023-06-01" \
  -H "Content-Type: application/json" \
  -d '{"model":"claude-sonnet-4-6","max_tokens":50,"messages":[{"role":"user","content":"hi"}]}'
```

Steer hashes the inbound `eg-api-key` value, matches against `scope_id`, and decrements the matched budget.

**When to use:** enforcing separate caps per developer, team, or project from a shared Steer deployment. **Gotcha:** no wildcard support — every distinct `eg-api-key` value needs its own SHA256 entry.

### 3.3 Per-agent cap

Each agent identity gets its own cap. The client sends `eg-agent-id: <name>` and Steer keys the budget off the literal header value.

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

**When to use:** running multiple agent personas behind a single LLM provider key, want spend isolated per persona. **Gotcha:** clients without `eg-agent-id` fall back to the literal string `"anonymous"` — set an explicit budget for `"anonymous"` or those requests share a single bucket.

### 3.4 Stacking scopes

You can configure entries from multiple scopes simultaneously. The check picks the first matching scope per request (`api_key` → `tenant` → `agent`); spend is recorded against **all** configured scopes the request maps to.

A typical OSS shape uses one budget per traffic class:

```yaml
budget:
  budgets:
    # Authenticated client traffic — gated by api_key
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

A request carrying the client's `eg-api-key` hits the `api_key` bucket and only the `api_key` bucket gates. A request without `eg-api-key` falls through to the `agent` / `anonymous` bucket instead.

> **What spend recording does NOT do.** Even though spend is recorded against every configured scope a request maps to, the *check* only consults the first-matched scope. A non-matched bucket exhausting in the background does not block — Cedar only sees the matched scope's `remaining_cents`. If you want a backstop that actually gates, your traffic shape has to be such that the backstop becomes the matched scope (e.g. by omitting the higher-precedence identifier).

---

## 4. Policy

Budget state is surfaced into Cedar as `budget_remaining_cents` and `budget_utilization_pct`. You can write rules against either field to control what happens at different points in the budget lifecycle. Drop custom rules into `./dsl/policies/` — with `policy.watch: true` in `steer.yaml` they hot-reload without a restart.

### 4.1 Utilization warning

Trigger policy actions before the budget is fully exhausted. This gives your team visibility — or a chance to intervene — before the hard block fires.

**Flag at high utilization** (request proceeds; audit entry records the rule match):

`./dsl/policies/budget-warning.cedar`:

```cedar
@id("custom-budget-warning-80")
@category("operational")
@enforcement("flag")
@description("Budget utilization above 80% — flag for review")
forbid(principal, action, resource)
when { context.budget_utilization_pct >= 80 };
```

**Steer to human review** (request is held for approval before proceeding):

```cedar
@id("custom-budget-steer-90")
@category("operational")
@enforcement("steer")
@description("Budget utilization above 90% — route to human review")
forbid(principal, action, resource)
when { context.budget_utilization_pct >= 90 };
```

Pair utilization rules with a Slack or PagerDuty webhook off the audit stream for proactive alerting before exhaustion.

### 4.2 Budget exhausted

When `budget_remaining_cents == 0`, the default shipped rule hard-blocks the request. You can replace or supplement it with a different enforcement action depending on how strictly you want to enforce the cap.

**Block** (default — reject immediately, HTTP 400):

```cedar
@id("default-budget-block")
@category("operational")
@enforcement("block")
@description("Token budget exhausted — request blocked")
forbid(principal, action, resource)
when { context.budget_remaining_cents == 0 };
```

**Flag** (allow but mark in the audit log for review):

```cedar
@id("custom-budget-exhausted-flag")
@category("operational")
@enforcement("flag")
@description("Token budget exhausted — flag and allow")
forbid(principal, action, resource)
when { context.budget_remaining_cents == 0 };
```

**Steer to human** (route to HITL queue instead of blocking outright):

```cedar
@id("custom-budget-exhausted-steer")
@category("operational")
@enforcement("steer")
@description("Token budget exhausted — route to human review")
forbid(principal, action, resource)
when { context.budget_remaining_cents == 0 };
```

**When to use:** use `block` for strict hard limits. Use `flag` when you want observability without disrupting the client. Use `steer` when exhausted requests should go to a human or approval system before being allowed or rejected.

---

## 5. Cost Estimation & Budget Check

### 5.1 Cost Estimation

Cost is estimated twice per request:

1. **Pre-request heuristic** — a fixed estimate based on a typical prompt and completion length. This is computed at request time but is not currently used for the budget check itself; it is held for future failover logic.

2. **Post-response actual** — the real cost, derived from the token usage reported in the upstream provider's response. This is the value that decrements the budget.

Steer ships a built-in pricing table (`src/config/mod.rs`) for the following models:

| Provider | Model |
|---|---|
| OpenAI | `gpt-4o` |
| OpenAI | `gpt-4o-mini` |
| OpenAI | `gpt-4.1` |
| OpenAI | `gpt-4.1-mini` |
| OpenAI | `gpt-4.1-nano` |
| OpenAI | `o3-mini` |
| Anthropic | `claude-opus-4-6` |
| Anthropic | `claude-sonnet-4-6` |
| Anthropic | `claude-haiku-4-5-20251001` |
| Google | `gemini-2.5-pro` |

**Models not in this table are costed at $0.00**, which means budget tracking is silently a no-op for those requests — `budget_remaining_cents` will not decrement. If your traffic uses a model that isn't listed, add a custom pricing entry to `steer.yaml` — see [Appendix A.1](#a1-custom-model-pricing).

### 5.2 Budget Check & Spend Tracking

#### Budget Scoping

Before checking the budget, Steer resolves which scope and scope ID apply to the request:

| Scope | How `scope_id` is resolved |
|---|---|
| `api_key` | SHA256 of the `eg-api-key` request header value |
| `agent` | Value of the `eg-agent-id` header; falls back to `"anonymous"` when absent |
| `tenant` | Resolved from the API-key→tenant mapping; EE only |

If the request cannot supply the required identifier for a scope (e.g. `scope: api_key` but no `eg-api-key` header), that scope is skipped and the next in precedence is consulted.

#### Check (pre-upstream): first match wins

Steer consults scopes in fixed precedence order and stops at the first match:

```
api_key → tenant (EE only) → agent
```

Only the matched scope's `budget_remaining_cents` is surfaced into the Cedar policy context. The built-in `default-budget-block` rule fires when this value is `0`, blocking the request before it reaches the upstream provider.

#### Spend recording (post-upstream): all configured scopes

After the upstream responds, cost is recorded against **every** configured scope the request maps to — not just the one that gated the check:

- `api_key` — recorded if the `eg-api-key` header was present
- `agent` — recorded for all requests
- `tenant` — recorded when a tenant is resolved (EE only)

**Key asymmetry.** Only the first-matched scope's balance is visible to Cedar. A non-matched scope can exhaust in the background without triggering a block, because Cedar never sees its remaining balance. If you want a non-primary scope to act as a hard backstop, traffic must fall through to it as the matched scope — for example, by omitting the higher-precedence identifier.

#### Blocked requests do not record spend

A request blocked by `default-budget-block` is rejected before the upstream call, so no spend is recorded and no upstream cost is incurred.

#### Periodic Reset

Spend recorded against each budget entry resets to zero at the end of its configured period — it is the *spent amount* that resets, not the budget cap itself.

| Period | Resets at |
|---|---|
| `daily` | Next UTC midnight |
| `weekly` | Next Monday 00:00 UTC |
| `monthly` | Next 1st of month, 00:00 UTC |

Reset is detected by a background task that polls every few seconds — there is no per-request reset check. A budget technically resets at midnight but won't be seen as reset until the next poll fires.

**Mid-period request behavior.** A request in flight at the exact period boundary will use the balance that was loaded at the start of that request — typically the pre-reset value. This edge case is expected to be rare in practice.

---

## 6. Audit Log

The audit log provides three key capabilities for budget monitoring: inspecting real-time budget state per request, capturing block events with HTTP response details, and surfacing log events for rollover and spend errors.

Per-request budget state is included in the `context_snapshot` field of every audit entry. This is only visible when `audit.format` is set to `json` or `pretty` — the compact single-line format does not include `context_snapshot`.

```json
{
  "context_snapshot": {
    "budget_remaining_cents": 0,
    "budget_utilization_pct": 100
  },
  "enforcement": {
    "action": "block",
    "rule_id": "default-budget-block",
    "matched_rules": [
      { "rule_id": "default-budget-block", "action": "block", "category": "operational" }
    ]
  }
}
```

When a request is blocked by `default-budget-block`, the client receives HTTP 400:

```json
{
  "error": {
    "type": "policy_block",
    "code": "policy_block",
    "message": "Request blocked by policy: default-budget-block"
  }
}
```

The `eg-audit-id` response header in the block response links the client back to the corresponding audit entry. There is no budget-specific status code or header that distinguishes a budget block from a content policy block — clients need to read the `rule_id` from the response body or the audit entry.

### Log events

| Event | Level |
|---|---|
| `"budget period reset"` (with `scope`, `scope_id`, `period` fields) | `info` |
| `"budget spend update (api_key) failed"` (or `agent` / `tenant`) | `warn` |
| `"BudgetCache refresh failed"` (EE only) | `warn` |

There is no dedicated log event for "request blocked by budget". To isolate budget blocks in the audit stream, filter for `enforcement.action == "block"` combined with `context_snapshot.budget_remaining_cents == 0`.

### Inspect Budget State

To inspect current budget state, tail the audit log and read `budget_remaining_cents` and `budget_utilization_pct` from `context_snapshot` for the scope of interest. Every request entry includes these fields when `audit.format` is `json` or `pretty`.

---

## 7. Verify it's Working

### A. Watch budget state live

**Step 1.** Configure the audit log to write to a file in `steer.yaml`:

```yaml
audit:
  backend: file
  log_path: ./audit.jsonl
  format: json
```

**Step 2.** Tail the log and filter for budget fields:

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

You should see `remaining_cents` decrement after each completed request. If `remaining_cents` stays at `-1` on every request, no budget matched — check scope precedence and that your `scope_id` matches the derivation rules in [§5.2](#52-budget-check--spend-tracking).

### B. Force a block

Set `amount_usd: 0.05` for the target budget entry in `steer.yaml` and restart Steer, then loop a cheap request until the block fires. The example below uses the sandbox setup (no `eg-agent-id` header, so all requests land in the `anonymous` bucket):

```bash
for i in $(seq 1 20); do
  curl -sS -X POST http://localhost:8080/v1/messages \
    -H "x-api-key: $ANTHROPIC_API_KEY" \
    -H "anthropic-version: 2023-06-01" \
    -H "Content-Type: application/json" \
    -d '{"model":"claude-sonnet-4-6","max_tokens":50,"messages":[{"role":"user","content":"hi"}]}' \
    -o /dev/null -w "%{http_code}\n"
done
```

When the budget exhausts you'll see the response code flip from `200` to `400`. For client cap or per-agent cap, add `-H "eg-api-key: <value>"` or `-H "eg-agent-id: <name>"` so the request matches the intended scope.

### C. Confirm rollover

The rollover event is emitted to Steer's process stdout log (not the audit file). Search whichever file you redirect Steer's stdout to — for example:

```bash
grep "budget period reset" steer.log
```

If this never appears, either no period boundary has passed since startup, or `check_interval_secs` is set too high. For a `daily` budget, the event appears at the next UTC midnight.

### D. Confirm your model is priced

If `remaining_cents` does not decrement after successful upstream calls, the model may not be in the pricing table. Check your `steer.yaml` pricing configuration, or add a custom pricing entry for the model. If no custom entry exists and the model is not in the default table, cost is computed as `$0.00` and budget tracking is a silent no-op for that traffic.

---

## 8. Why isn't it working? - Common Scenarios

| Symptom | Likely cause |
|---|---|
| `budget_remaining_cents: -1` on every request | No budget entry matched. Check scope precedence (`api_key` → `tenant` → `agent`) and that your `scope_id` matches the derivation rule for that scope. |
| `remaining_cents` stays at the cap after upstream calls | Model not in the pricing table — cost is computed as $0.00. Add a custom pricing entry in `steer.yaml`. |
| Budget appears to "refund" between sessions | OSS spend is in-memory only and resets on process restart. |
| Client cap never matches | Client is not sending the `eg-api-key` header, or `scope_id` is not the SHA256 of the header value. |
| Per-agent cap never matches | Client is not sending the `eg-agent-id` header, or the header value doesn't exactly match `scope_id`. Requests without the header fall back to `"anonymous"`. |
| Tenant budget never matches in OSS | `tenant` scope is not active in OSS. Use `api_key` or `agent` scope instead. |
| Budget block fires unexpectedly on first request | `fail_open: false` is set and the budget cache had an error at startup — requests fail closed. Check logs for `"BudgetCache refresh failed"`. |

---

## 9. Observability

Observability into budget state is primarily through the Audit Log — see [§6 Audit Log](#6-audit-log) for the full details on audit entry format, log events, and how to stream budget state in real time.

### No inspection endpoint

There is no HTTP endpoint to query current spend or remaining balance directly. EE adds a query API backed by SQLite, which allows programmatic inspection of current spend and remaining balance per scope. In OSS, the audit log is the only live view.

---

## 10. Persistence

| Edition | Spend state | Restart behavior |
|---|---|---|
| OSS | In-memory; seeded from `steer.yaml` at startup | Resets to zero on every process restart — the next request sees the full cap |
| EE | SQLite-backed | Survives restarts; refreshes from the database periodically |

OSS deployments should treat budgets as soft rate-limits on a single running process, not as accounting truth. Anything requiring durable spend tracking across restarts needs EE, or external reconciliation against your provider's billing API.

---

## 11. OSS (Open Source) & EE (Enterprise Ed)

| | OSS (Open Source) | EE (Enterprise Ed) |
|---|---|---|
| Spend state | In-memory; resets on process restart | SQLite-backed; survives restarts |
| Persistence across restarts | No | Yes |
| `tenant` scope | Not supported | Supported |
| Budget inspection API | No | Yes |

In OSS, budgets act as soft rate-limits on a single running process. Spend is not persisted — a restart resets all counters to zero. Anything requiring durable spend tracking across restarts requires EE or external reconciliation against your provider's billing API.

The `tenant` scope check is skipped entirely in OSS. Use `api_key` or `agent` scope for all budget enforcement in OSS deployments.

---

## 12. Limitations

- **Exact-match `scope_id` only.** Wildcard support is not yet available. To budget across N API keys, you need N entries — one per SHA256 hash.
- **Unknown models cost zero.** If your traffic uses a model not in the pricing table, budget tracking silently no-ops for those requests — `budget_remaining_cents` will not decrement. See [§5.1](#51-cost-estimation) and [Appendix A.1](#a1-custom-model-pricing).
- **Tenant scope skipped in OSS.** `tenant`-scope budgets are dormant in OSS. Use `api_key` or `agent` scope instead.
- **No YAML-level reload.** Changing `budget.budgets` requires a process restart. Hot-reload via `policy.watch` covers Cedar files only, not the `budget` config section.
- **Budgets are eventually consistent under concurrent load.** The block decision uses the last recorded spend from prior completed requests. A single in-flight expensive request can still complete after the pre-block check passes, even if it pushes spend past the cap.
- **`fail_open: true`** (the OSS default) means budget check failures fall through and allow the request. Set `fail_open: false` if you want budget exhaustion to never silently leak through under cache contention.

---

## Appendix

### A.1 Custom Model Pricing

If your traffic uses a model not covered by Steer's built-in pricing table, add a custom entry under `token_costs` in `steer.yaml`:

```yaml
token_costs:
  your-model-name:
    prompt_per_1k: 0.005
    completion_per_1k: 0.015
```

Replace `your-model-name` with the exact model identifier as it appears in the upstream provider's response (e.g. `claude-opus-4-8`, `gpt-4o`). Use your provider's published token pricing for the cost values — these are USD per 1,000 tokens.

> If the model identifier doesn't match exactly, cost will be computed as $0.00 and budget tracking will be a silent no-op for those requests.
