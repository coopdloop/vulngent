# vulngent dev orchestration.
#
# `make dev` (default) starts a local Arize Phoenix in the background, then runs the
# chat UI in the foreground with PHOENIX_TRACING_ENABLED=true — so every LLM call the
# app makes (web, CLI, run-cycle) is traced and the usage dashboard runs in "observed"
# mode. Ctrl-C stops the app and the trap kills the backgrounded Phoenix too.
# `make dev-nophoenix` runs the app alone, in "partial" fallback mode.

APP_PORT ?= 7899
# Phoenix reads its port from env, not a flag.
PHOENIX_PORT ?= 6006
PHOENIX_PROJECT ?= vulngent
DEV_ENV = PHOENIX_ENDPOINT=http://localhost:$(PHOENIX_PORT) \
          PHOENIX_PROJECT_NAME=$(PHOENIX_PROJECT) \
          PHOENIX_TRACING_ENABLED=true

.PHONY: dev dev-nophoenix phoenix app setup test help

dev: setup
	@PHOENIX_PORT=$(PHOENIX_PORT) uv run --with arize-phoenix phoenix serve & \
	trap 'kill %1 2>/dev/null; wait' INT TERM EXIT; \
	echo "Phoenix on :$(PHOENIX_PORT) (project $(PHOENIX_PROJECT))"; \
	$(DEV_ENV) uv run vulngent chat --no-open --port $(APP_PORT)

# App only, no tracing: usage dashboard shows the partial (web-chat-only) fallback.
dev-nophoenix:
	uv run vulngent chat --no-open --port $(APP_PORT)

# Phoenix in the foreground (own terminal) instead of dev's backgrounded one.
phoenix:
	uv run --with arize-phoenix phoenix serve

# Chat UI with tracing pointed at whatever PHOENIX_ENDPOINT says.
app:
	$(DEV_ENV) uv run vulngent chat --no-open --port $(APP_PORT)

# Install the optional trace-export deps so PHOENIX_TRACING_ENABLED actually works.
setup:
	uv sync --extra phoenix

test:
	uv run pytest -q

help:
	@echo "make dev            - background Phoenix (tracing on) + chat UI  [default]"
	@echo "make dev-nophoenix  - chat UI only (partial usage mode)"
	@echo "make phoenix        - Phoenix server in the foreground"
	@echo "make app            - chat UI with tracing enabled"
	@echo "make setup          - uv sync --extra phoenix"
	@echo "make test           - pytest"
