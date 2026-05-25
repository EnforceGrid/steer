# Providers

Steer is an OpenAI-compatible HTTP proxy. Any client that lets you set `base_url` works — coding agents, language SDKs, agent frameworks. This page covers the configuration end-to-end: per-tool setup, auth passthrough, named providers, and stacking with router/gateway tools.

---

## 1. The base URL swap

For every supported client, the setup pattern is identical: replace the upstream's host with Steer's host. Everything else — model name, headers, request body, API key — stays the same.

| Upstream | Original | Through Steer |
|---|---|---|
| OpenAI | `https://api.openai.com/v1` | `http://localhost:8080/v1` |
| Anthropic | `https://api.anthropic.com` | `http://localhost:8080` |

The `/v1` vs root distinction matches each provider's own path convention. Steer dispatches to the right upstream based on the request path (`/v1/chat/completions` → OpenAI, `/v1/messages` → Anthropic, etc.) and the model name.

---

## 2. Coding agents

### Cursor

Settings → **Models** → toggle "Override OpenAI Base URL" → enter `http://localhost:8080/v1`. Cursor's own model menu continues to work; the requests flow through Steer.

### Claude Code

```bash
export ANTHROPIC_BASE_URL=http://localhost:8080
claude --model claude-sonnet-4-6
```

**Subscription-alias gotcha:** Claude Pro / Max / Team accounts have CLI aliases (`opus`, `sonnet`) that resolve to subscription endpoints, not the standard Anthropic API. Pass `--model claude-sonnet-4-6` (or another exact API model ID) so the request resolves to a `/v1/messages` call Steer can intercept. The `ANTHROPIC_BASE_URL` env var is honored only for API-path calls.

### Cline (VS Code)

In the Cline panel: Provider → **OpenAI Compatible** → Base URL: `http://localhost:8080/v1`. Use your real API key in the API Key field — Cline sends it in the `Authorization` header, which passes through Steer unchanged (see [auth passthrough](#3-auth-passthrough)).

### Aider

```bash
aider --openai-api-base http://localhost:8080/v1
```

Or in `.aider.conf.yml`:

```yaml
openai-api-base: http://localhost:8080/v1
```

### Continue.dev

`~/.continue/config.json`:

```json
{
  "models": [
    {
      "title": "GPT-4o via Steer",
      "provider": "openai",
      "model": "gpt-4o-mini",
      "apiBase": "http://localhost:8080/v1",
      "apiKey": "${OPENAI_API_KEY}"
    }
  ]
}
```

### Zed, Windsurf, Cody, GitHub Copilot

Any IDE-integrated assistant that exposes a base URL override works the same way. For tools that don't expose the setting in the UI, check the underlying SDK config file (often `~/.config/<tool>/`).

---

## 3. Auth passthrough

Default behaviour: the inbound `Authorization` header is forwarded to the upstream LLM **unchanged**. Steer never reads or stores the bearer token. The policy pipeline scans the request *body* but treats headers as opaque.

You can verify with a stripped Steer config (no `providers.*.api_key` set):

```bash
curl http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer $OPENAI_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hello"}]}'
```

### Overriding the inbound key

For centralized key rotation, set `providers.<name>.api_key` in `steer.yaml`. Steer replaces the inbound header with the configured value before forwarding:

```yaml
providers:
  anthropic:
    base_url: "https://api.anthropic.com"
    api_key: "${ANTHROPIC_API_KEY}"   # injected — inbound Authorization is dropped
```

When `api_key` is empty or unset, passthrough resumes for that provider.

### Anthropic vs OpenAI header conventions

| Provider | Auth header | Steer behaviour |
|---|---|---|
| OpenAI | `Authorization: Bearer <key>` | Passthrough or override per `providers.<name>.api_key` |
| Anthropic | `x-api-key: <key>` plus `anthropic-version: 2023-06-01` | Passthrough; `anthropic-version` preserved verbatim |
| Azure OpenAI | `api-key: <key>` (and `api-version` query param) | Passthrough |
| AWS Bedrock | SigV4 signed request | Use a Bedrock-compatible client; Steer forwards signed headers |

If your client sends a different auth header shape, Steer forwards it as-is. The override-via-config path only activates for the standard `Authorization: Bearer` and `x-api-key` patterns.

---

## 4. Named providers and model routing

`steer.yaml` lets you define multiple upstreams and route by model name:

```yaml
upstream:
  base_url: "https://api.openai.com"
  api_key: "${OPENAI_API_KEY}"

providers:
  anthropic:
    base_url: "https://api.anthropic.com"
    api_key: "${ANTHROPIC_API_KEY}"
  groq:
    base_url: "https://api.groq.com/openai"
    api_key: "${GROQ_API_KEY}"

models:
  claude-sonnet-4-6:
    provider: anthropic
    model: claude-sonnet-4-6
  llama-3.3-70b:
    provider: groq
    model: llama-3.3-70b-versatile
```

Requests whose `model` field matches a key under `models:` route to the named provider. Unmapped models fall through to `upstream`.

Steer is OpenAI-compatible at the wire format. When you route an OpenAI-shaped request to a non-OpenAI provider, Steer does **not** translate the wire format — the upstream must accept the OpenAI schema. For native Anthropic `/v1/messages` requests, your client must issue them directly against `http://localhost:8080/v1/messages`.

---

## 5. Supported upstream providers

| Provider | Notes |
|---|---|
| **OpenAI** | `/v1/chat/completions`, `/v1/embeddings`, `/v1/images/generations` |
| **Anthropic** | `/v1/messages`; preserve `anthropic-version` header |
| **Google Gemini** | OpenAI-compatible mode at `https://generativelanguage.googleapis.com/v1beta/openai/` |
| **AWS Bedrock** | Via SigV4-signing client; works with the Bedrock OpenAI-compatibility shim |
| **Azure OpenAI** | Use the Azure-style URL with deployment name as the model; preserve `api-version` query param |
| **Mistral** | OpenAI-compatible at `https://api.mistral.ai/v1` |
| **Cohere** | OpenAI-compatible at `https://api.cohere.ai/compatibility/v1` |
| **Groq** | `https://api.groq.com/openai/v1` — fast Llama/Mixtral inference |
| **Together AI** | `https://api.together.xyz/v1` |
| **Ollama** | `http://localhost:11434/v1` — local model serving |
| **vLLM, TGI, LM Studio** | Any OpenAI-compatible server endpoint |

Anything that speaks OpenAI's wire format works without source changes. Native-format providers (Anthropic `/v1/messages`, Bedrock Converse, etc.) are forwarded transparently by path.

---

## 6. Agent frameworks

Set the framework's underlying LLM client to point at Steer. The same `base_url` swap pattern applies — Steer doesn't know or care what's calling it.

### LangChain (Python)

```python
from langchain_openai import ChatOpenAI

llm = ChatOpenAI(
    base_url="http://localhost:8080/v1",
    api_key="${OPENAI_API_KEY}",
    model="gpt-4o-mini",
)
```

### LangGraph

Inherits the LangChain client — set `base_url` on the underlying `ChatOpenAI` / `ChatAnthropic` instance. Every node in the graph that hits the LLM goes through Steer.

### CrewAI

```python
from crewai import LLM
llm = LLM(model="openai/gpt-4o-mini", base_url="http://localhost:8080/v1")
```

### AutoGen

```python
config_list = [{
    "model": "gpt-4o-mini",
    "base_url": "http://localhost:8080/v1",
    "api_key": "${OPENAI_API_KEY}",
}]
```

### Semantic Kernel (.NET / Python)

Use the `OpenAIChatCompletion` connector with `Endpoint = "http://localhost:8080"` (or its SDK-specific equivalent).

### Mastra (TypeScript)

```ts
import { openai } from "@ai-sdk/openai";
const model = openai("gpt-4o-mini", { baseURL: "http://localhost:8080/v1" });
```

### OpenAI / Anthropic SDKs

```python
from openai import OpenAI
client = OpenAI(base_url="http://localhost:8080/v1", api_key="...")

from anthropic import Anthropic
client = Anthropic(base_url="http://localhost:8080", api_key="...")
```

---

## 7. Stacking with routers and gateways

Steer enforces policy on the LLM request path. It does **not** do multi-provider routing, retries, fallbacks, or cost-aware load balancing. Those are different concerns, owned by different tools. Most production stacks run both.

### In front of LiteLLM (recommended)

```
client → Steer → LiteLLM → {OpenAI, Anthropic, Bedrock, ...}
```

Steer enforces policy on the inbound request and the response stream. LiteLLM handles provider routing, fallback, key rotation, and cost tracking on the upstream side. Set your client's `base_url` to Steer; set Steer's `upstream.base_url` to LiteLLM's listener.

```yaml
# steer.yaml
upstream:
  base_url: "http://litellm:4000"
  api_key: ""   # let LiteLLM's master key handle upstream auth
```

### In front of Portkey

Same pattern as LiteLLM. Portkey's strength is observability + guardrails-as-plugin; Steer's is policy enforcement with a Cedar audit trail. Run both, route client → Steer → Portkey.

### Behind Bifrost

Bifrost handles edge caching and provider load balancing. Place it upstream of Steer if you want the cache to short-circuit before policy evaluation — but be aware that cache hits skip your audit trail. The recommended order for evidence integrity is: Steer first, then Bifrost.

### Position decision

| Need | Order |
|---|---|
| Policy on every request, including cached | client → **Steer** → router → cache → upstream |
| Cache hits skip policy (latency-critical, lower governance bar) | client → router → cache → **Steer** → upstream |
| Multi-tenant per-vendor governance | client → **Steer** (tenant overlay) → router |

---

## 8. Streaming

Steer supports streaming responses. The pipeline buffers small windows (default 512 bytes, 200ms timeout) so detectors can pattern-match across token boundaries before flushing to the client. For full mechanics see [docs/architecture.md#9-streaming](architecture.md#9-streaming).

Streaming-aware coding agents (Cursor, Claude Code, Cline, all the SDKs) work without changes. The first byte to the client is delayed by the configured buffer window.

---

## 9. Where to go next

- [Authoring custom Cedar policies](policies.md) — make a rule fire on your traffic
- [Architecture](architecture.md) — how requests flow, fail modes
- [Compliance coverage](compliance.md) — what evidence each policy produces
