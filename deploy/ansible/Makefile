.PHONY: deploy deploy-only deploy-frontend health teardown reset-chain check-inventory ssh-validator notary-restart ui-stop ui-start cutover-libp2p rollback-libp2p launch-viper-pq-1 p2p-health p2p-soak

# Full provisioning: install Rust, build from source, configure, deploy.
# Safe to re-run (idempotent for config changes; skips recompile if no code change).
deploy:
	cd $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST)))) && \
	ansible-playbook playbooks/site.yml

# Config + restart only — no recompile. Run after deploy has succeeded at least once.
deploy-only:
	cd $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST)))) && \
	ansible-playbook playbooks/deploy-only.yml

# Deploy static frontend files only (explorer JSX + docs site).
# No recompile, no node restart. Use after frontend-only changes.
deploy-frontend:
	cd $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST)))) && \
	ansible-playbook playbooks/deploy-frontend.yml

# Non-destructive health probe. Reports node height, chain ID, metrics status.
health:
	cd $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST)))) && \
	ansible-playbook playbooks/check-health.yml

# Full teardown and data wipe. WARNING: deletes all chain data.
teardown:
	cd $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST)))) && \
	ansible-playbook playbooks/teardown.yml

# Wipe on-disk chain data only (keeps binary + config) and restart from genesis.
# Use after deploying a binary whose checkpoint format differs from the stored one.
reset-chain:
	cd $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST)))) && \
	ansible-playbook playbooks/reset-chain.yml

# Validate inventory syntax without connecting to hosts.
check-inventory:
	cd $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST)))) && \
	ansible-inventory --list | jq 'keys'

# Restart only the notary service on the validator (no rebuild, no node restart).
notary-restart:
	cd $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST)))) && \
	ansible -i inventory/hosts.yml validators -m systemd \
	  -a "name=viper-notary state=restarted" --become

# Stop the public UI (nginx) on the validator. Chain keeps running.
ui-stop:
	cd $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST)))) && \
	ansible -i inventory/hosts.yml validators -m systemd \
	  -a "name=nginx state=stopped" --become

# Start the public UI (nginx) on the validator.
ui-start:
	cd $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST)))) && \
	ansible -i inventory/hosts.yml validators -m systemd \
	  -a "name=nginx state=started" --become

# Phase 8 M1 — libp2p/QUIC cutover (TASK-141). Maintenance window required.
# Preconditions: viper_libp2p.enable=true in group_vars, bootstrap_peers set,
# UFW pre-opened (TASK-140), rollback tag `phase-8-m1-pre` exists.
cutover-libp2p:
	cd $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST)))) && \
	ansible-playbook playbooks/cutover-libp2p.yml

# Phase 8 M1 — revert to Phase 6 transport (TASK-142). Edit group_vars to set
# viper_libp2p.enable=false BEFORE running.
rollback-libp2p:
	cd $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST)))) && \
	ansible-playbook playbooks/rollback-libp2p.yml

# viper-pq-1 LAUNCH ceremony (TASK-205, ADR-053). Live since 2026-04-25
# 16:09 UTC+2 on the 3 dev hosts; the chain was archived on 2026-05-12 at
# height 33,976. Re-running this playbook against
# already-launched hosts is gated by the playbook's own pre-flight checks
# (chain_id mismatch refusal, binary-SHA pin guard); it is NOT a routine
# operation. The legacy cutover-devnet-3 / rollback-devnet-3 targets and
# playbooks were removed (2026-08-24); the incident record lives in
# KNOWN-ISSUES R-09 and the private repository history.
launch-viper-pq-1:
	cd $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST)))) && \
	ansible-playbook playbooks/launch-viper-pq-1.yml

# Quick libp2p peer-count probe across all hosts (TASK-143).
p2p-health:
	$(shell dirname $(dir $(realpath $(firstword $(MAKEFILE_LIST)))))/../scripts/p2p-health.sh

# 1h libp2p convergence soak (TASK-144). Non-blocking; emits report to reports/soak/.
p2p-soak:
	$(shell dirname $(dir $(realpath $(firstword $(MAKEFILE_LIST)))))/../scripts/libp2p-soak.sh

# SSH into the validator node (reads ansible_host from inventory).
ssh-validator:
	@VALIDATOR_IP=$$(cd $(shell dirname $(realpath $(firstword $(MAKEFILE_LIST)))) && \
	  ansible-inventory --host producer-1 2>/dev/null | jq -r '.ansible_host'); \
	echo "Connecting to validator at $$VALIDATOR_IP..."; \
	ssh root@$$VALIDATOR_IP
