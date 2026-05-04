# Sandbox Audit Report

- Generated: 2026-05-04T18:52:29.491817+00:00
- Namespace: sandbox-kata
- Workload: deployment/target-kata
- Risk score: 2 (low)

## Findings
- **SETID_BINARIES_PRESENT** [medium] Remove setuid/setgid binaries from the image

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
- Post-remediation risk score: 2 (low) (partially verified)
