# Sandbox Audit Report

- Generated: 2026-05-04T18:26:56.880506+00:00
- Namespace: sandbox-kata
- Workload: deployment/target-kata
- Risk score: 0 (low)

## Findings
- **NO_ACTIONABLE_FAILURES** [info] No failed checks were mapped to a built-in remediation rule

## Dependencies
- services: none
- ingresses: none
- network_policies: allow-dns-egress, allow-llm-gateway-egress, default-deny-all
- hpas: none
- pdbs: none
- configmaps: none
- secrets: none
- runtime_class: None
- node_selector: {}
- volumes: none

## Fix result
- Status: applied
- SERVICE_ACCOUNT_TOKEN: resolved_by_applied_patch
- ROOTFS_RW: resolved_by_applied_patch
- Post-remediation risk score: 0 (low) (partially verified)
