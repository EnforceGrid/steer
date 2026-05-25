.DEFAULT_GOAL := help

# ── Colours ───────────────────────────────────────────────────────────────────
BOLD  := \033[1m
RESET := \033[0m
GREEN := \033[0;32m
CYAN  := \033[0;36m
YELLOW := \033[0;33m

.PHONY: help setup env tools check test dev ci bench load

# ── Help ──────────────────────────────────────────────────────────────────────

help: ## Show this help
	@printf '$(BOLD)EnforceGrid Steer$(RESET) — Runtime AI enforcement engine\n\n'
	@printf '$(BOLD)Usage:$(RESET)\n  make <target>\n\n'
	@printf '$(BOLD)Targets:$(RESET)\n'
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  $(CYAN)%-8s$(RESET) %s\n", $$1, $$2}'

# ── Setup ─────────────────────────────────────────────────────────────────────

setup: tools ## First-time setup: config file + toolchain components
	@if [ ! -f steer.yaml ]; then \
		cp steer.example.yaml steer.yaml; \
		printf '$(GREEN)✓$(RESET) Created steer.yaml from steer.example.yaml\n'; \
		printf '$(YELLOW)→$(RESET) Edit steer.yaml and set your API keys, then run: make dev\n'; \
	else \
		printf '$(GREEN)✓$(RESET) steer.yaml already exists\n'; \
	fi

# ── Environment diagnostic ────────────────────────────────────────────────────

env: ## Show environment variable status (informational, never fails)
	@printf '$(BOLD)Environment$(RESET)\n'
	@printf '  OPENAI_API_KEY    %s\n'    "$$([ -n "$$OPENAI_API_KEY" ]    && echo '$(GREEN)set$(RESET)' || echo 'not set')"
	@printf '  ANTHROPIC_API_KEY %s\n'    "$$([ -n "$$ANTHROPIC_API_KEY" ] && echo '$(GREEN)set$(RESET)' || echo 'not set')"
	@printf '  STEER_API_KEY     %s\n'    "$$([ -n "$$STEER_API_KEY" ]     && echo '$(GREEN)set$(RESET)' || echo 'not set (unauthenticated dev mode)')"
	@printf '  STEER_PORT        %s\n'    "$$([ -n "$$STEER_PORT" ]        && echo "$$STEER_PORT"        || echo '8080 (default)')"
	@printf '  steer.yaml        %s\n'    "$$([ -f steer.yaml ]            && echo '$(GREEN)present$(RESET)' || echo '$(YELLOW)missing — run: make setup$(RESET)')"

# ── Toolchain ─────────────────────────────────────────────────────────────────

tools: ## Install required rustup components (idempotent)
	@rustup component add clippy rustfmt 2>/dev/null; \
		printf '$(GREEN)✓$(RESET) clippy and rustfmt ready\n'

# ── Code quality ──────────────────────────────────────────────────────────────

check: ## Run fmt check, clippy, and cargo check
	cargo fmt --check
	cargo clippy -- -D warnings
	cargo check

# ── Tests ─────────────────────────────────────────────────────────────────────

test: ## Run all library tests
	cargo test --lib

# ── Local dev server ──────────────────────────────────────────────────────────

dev: ## Start the local dev server (requires steer.yaml)
	@if [ ! -f steer.yaml ]; then \
		printf '$(YELLOW)steer.yaml not found$(RESET) — run: make setup\n'; exit 1; \
	fi
	cargo run -- --config steer.yaml

# ── Microbenchmarks (Criterion) ───────────────────────────────────────────────

bench: ## Run Criterion microbenchmarks; HTML report in target/criterion/
	cargo bench --bench proxy_overhead
	@printf '$(GREEN)✓$(RESET) Report: target/criterion/index.html\n'

# ── Load test (k6 throughput, mock upstream) ──────────────────────────────────

load: ## Run k6 throughput benchmark against mock upstream (requires node + k6)
	@command -v node >/dev/null 2>&1 || { printf '$(YELLOW)node not found$(RESET) — install Node.js to run the mock upstream\n'; exit 1; }
	@command -v k6   >/dev/null 2>&1 || { printf '$(YELLOW)k6 not found$(RESET)   — brew install k6\n'; exit 1; }
	@cargo build --release --bin steer 2>/dev/null
	@printf '$(CYAN)→$(RESET) Starting mock upstream on :9999…\n'
	@node k6/mock-upstream.js &
	@MOCK_PID=$$!; \
	sleep 1; \
	printf '$(CYAN)→$(RESET) Starting steer on :8080…\n'; \
	STEER_PORT=8080 ./target/release/steer --config k6/steer-bench.yaml &; \
	STEER_PID=$$!; \
	sleep 1; \
	printf '$(CYAN)→$(RESET) Running k6 throughput ceiling…\n'; \
	k6 run k6/throughput-ceiling.js; \
	kill $$STEER_PID $$MOCK_PID 2>/dev/null; \
	printf '$(GREEN)✓$(RESET) Load test complete\n'

# ── CI gate ───────────────────────────────────────────────────────────────────

ci: check test ## Full CI gate: check + test
