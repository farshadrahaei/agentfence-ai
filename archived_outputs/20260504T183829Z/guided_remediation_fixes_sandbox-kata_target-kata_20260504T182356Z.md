# Sandbox Audit Report

- Generated: 2026-05-04T18:23:56.191000+00:00
- Namespace: sandbox-kata
- Workload: deployment/target-kata
- Risk score: 0 (low)

## Findings
- **NO_ACTIONABLE_FAILURES** [info] No failed checks were mapped to a built-in remediation rule

## Dependencies
- services: target-kata
- ingresses: none
- network_policies: allow-attacker-to-target, allow-dns-egress, allow-llm-gateway-egress, default-deny-all
- hpas: none
- pdbs: none
- configmaps: none
- secrets: none
- runtime_class: kata-qemu
- node_selector: {'sandbox': 'kata'}
- volumes: {"emptyDir": {}, "name": "workspace"}, {"emptyDir": {}, "name": "artifacts"}

## Fix result
- Status: applied
- SERVICE_ACCOUNT_TOKEN: resolved_by_applied_patch
- ROOTFS_RW: resolved_by_applied_patch
- Post-remediation risk score: 0 (low) (partially verified)
