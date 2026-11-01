# re-lab: isolated local model + headless Ghidra MCP for reverse-engineering research.
# Works on macOS (Apple Silicon, Metal) and Linux (NVIDIA CUDA, or CPU).
# Run `make help` for the list of targets.

SHELL := /bin/bash
.DEFAULT_GOAL := help
PY := agent/.venv/bin/python

.PHONY: help setup llama model ghidra all model-up model-fg model-down agent projects delete-project package security hooks status smoke model-info profile template clean-run

help: ## show this help
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  \033[1m%-11s\033[0m %s\n", $$1, $$2}'

setup: ## check prerequisites, create folders, build the agent's Python env
	@scripts/setup.sh

llama: ## build llama-server (native Metal on macOS, CUDA/CPU container on Linux)
	@scripts/build-llama.sh

model: ## download the pinned GGUF and verify its SHA-256
	@scripts/get-model.sh

ghidra: ## build the Ghidra + pyghidra-mcp image (network only during the build)
	@scripts/build-ghidra.sh

all: setup llama model ghidra ## everything above, in order

model-up: ## start the sandboxed model server in the background
	@scripts/start-model.sh --background

model-fg: ## start the sandboxed model server in this terminal
	@scripts/start-model.sh

model-down: ## stop the model server
	@scripts/stop-model.sh

agent: ## start the interactive agent (ARGS="--allow-edits" etc.)
	@test -x $(PY) || { echo "run 'make setup' first"; exit 1; }
	@$(PY) agent/agent.py $(ARGS)

projects: ## list Ghidra projects and the samples each one imported
	@scripts/list-projects.sh

delete-project: ## delete a Ghidra project: make delete-project NAME=lab (asks first)
	@test -n "$(NAME)" || { echo "usage: make delete-project NAME=<project>   (make projects lists them)"; exit 1; }
	@scripts/delete-project.sh "$(NAME)"

package: ## pack only the files needed to run the lab into dist/re-lab-<date>.tar.gz
	@scripts/package.sh

security: ## run the security gate (supply-chain + fuzz); same checks as the pre-commit hook
	@scripts/security-check.sh

hooks: ## install the git pre-commit hook so the security gate runs on every commit
	@git config core.hooksPath .githooks && echo "pre-commit hook enabled (.githooks/pre-commit)"

status: ## show what is running
	@source scripts/lib.sh; echo "backend: $$(backend)"; \
	  if llama_curl /health >/dev/null 2>&1; then echo "model:   up"; else echo "model:   down"; fi; \
	  docker ps --filter name=re-lab- --format 'container: {{.Names}}  {{.Status}}' 2>/dev/null || true

smoke: ## send one short request to the model; shows its reply, how it ended and its speed
	@source scripts/lib.sh; llama_curl /v1/chat/completions -m 120 \
	  -H "Authorization: Bearer $$(cat .run/llama.key)" -H 'Content-Type: application/json' \
	  -d '{"messages":[{"role":"user","content":"Reply with exactly five words."}],"max_tokens":64}' \
	  | tee logs/smoke.json | python3 -c 'import json,sys; r=json.load(sys.stdin); c=r["choices"][0]; t=r.get("timings",{}); \
	  print("reply:   ", c["message"]["content"].strip()); \
	  print("finished:", {"stop": "on its own (good)", "length": "hit the token limit (wrong chat template?)"}.get(c.get("finish_reason"), c.get("finish_reason"))); \
	  print("speed:    %.1f tokens/s generating, %.1f tokens/s reading the prompt" % (t.get("predicted_per_second",0), t.get("prompt_per_second",0)))'

model-info: ## show the model file's special tokens and whether it embeds a chat template
	@python3 scripts/gguf-info.py

profile: ## print the resolved macOS sandbox profile
	@scripts/start-model.sh --print-profile

template: ## print the chat template embedded in the model (server must be up)
	@source scripts/lib.sh; llama_curl /props -H "Authorization: Bearer $$(cat .run/llama.key)" \
	  | python3 -c 'import json,sys; print(json.load(sys.stdin).get("chat_template","(none reported)"))'

clean-run: ## remove runtime state (.run/), keeping models, projects and logs
	@scripts/stop-model.sh; rm -rf .run
