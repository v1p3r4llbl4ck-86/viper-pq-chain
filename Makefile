# Viper PQ Chain — project Makefile
#
# All `ansible-*` targets cd into deploy/ansible/ first so that
# ansible.cfg (with roles_path and inventory relative paths) is picked up
# automatically — no need to specify -i or --roles-path manually.
#
# Usage from project root:
#   make deploy             # full provision (first time or after infra changes)
#   make deploy-binary      # rebuild binary on nodes + restart (code changes only)
#   make deploy-config      # push config + restart, no rebuild
#   make deploy-frontend    # update explorer/notary static files only
#   make reset-chain        # wipe block data, restart from genesis
#   make health             # non-destructive cluster health check
#   make teardown           # DANGER: remove everything from all nodes
#   make build              # local cargo build (debug)
#   make build-release      # local cargo build --release
#   make test               # run workspace tests
#   make fmt                # cargo fmt
#   make lint               # cargo clippy
#   make ci                 # every gate the CI runs: fmt, clippy, deny, tests, licences, links

ANSIBLE_DIR := deploy/ansible
PLAYBOOKS   := $(ANSIBLE_DIR)/playbooks

# ── Ansible helpers ───────────────────────────────────────────────────────────

# Run a playbook via the deploy/ansible directory so ansible.cfg is found.
define ansible
	cd $(ANSIBLE_DIR) && ansible-playbook playbooks/$(1) $(ANSIBLE_ARGS)
endef

# ── Deployment targets ────────────────────────────────────────────────────────

## Full provisioning — common, rust, build, configure, firewall, deploy, web
.PHONY: deploy
deploy:
	$(call ansible,site.yml)

## Push locally-built release binary to all nodes and restart
.PHONY: deploy-binary
deploy-binary: build-release
	cd $(ANSIBLE_DIR) && ansible-playbook playbooks/pipeline-deploy.yml \
		-e "binary_src=$(CURDIR)/target/release/pqcd" $(ANSIBLE_ARGS)

## Push updated config (node.json, systemd unit) and restart — no rebuild
.PHONY: deploy-config
deploy-config:
	$(call ansible,deploy-only.yml)

## Update explorer and notary static files only — no binary restart
.PHONY: deploy-frontend
deploy-frontend:
	$(call ansible,deploy-frontend.yml)

## Wipe on-disk chain data on all nodes and restart from genesis
.PHONY: reset-chain
reset-chain:
	$(call ansible,reset-chain.yml)

## Non-destructive health check across all nodes
.PHONY: health
health:
	$(call ansible,check-health.yml)

## DANGER: remove pqcd binary, config, data, and systemd unit from all nodes
.PHONY: teardown
teardown:
	@echo "WARNING: this will destroy ALL chain data and remove the service."
	@echo "Press Ctrl-C to abort, or wait 5 seconds to continue."
	@sleep 5
	$(call ansible,teardown.yml)

## Limit any target to a single host: make deploy ANSIBLE_ARGS="--limit validator-1"
## Or a specific tag:               make deploy ANSIBLE_ARGS="--tags configure"

# ── Local Rust targets ────────────────────────────────────────────────────────

.PHONY: build
build:
	cargo build

.PHONY: build-release
build-release:
	cargo build --release

.PHONY: test
test:
	cargo test --workspace

.PHONY: fmt
fmt:
	cargo fmt --all

.PHONY: lint
lint:
	cargo clippy --workspace -- -D warnings

## End-to-end smoke test for the Issue #1 deploy-unblock pipeline:
## generates a synthetic V3 envelope, runs the migration script, and
## verifies the output via `pqcd keystore verify`. Operator pre-flight.
.PHONY: keystore-smoke
keystore-smoke: build
	a one-off migration script (private)

.PHONY: help
help:
	@grep -E '^##' Makefile | sed 's/^## /  /'

## Every gate the CI runs, in order. Heavy: the test step builds the whole
## workspace with all features (add -j3 on small machines).
.PHONY: ci
ci:
	cargo fmt --all -- --check
	cargo clippy --workspace --all-targets --all-features -- -D warnings
	cargo deny check
	cargo test --workspace --all-features --no-fail-fast
	scripts/check-licenses.sh
	scripts/check-links.sh
