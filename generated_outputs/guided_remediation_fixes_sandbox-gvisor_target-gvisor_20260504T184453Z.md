# Sandbox Audit Report

- Generated: 2026-05-04T18:52:35.684126+00:00
- Namespace: sandbox-gvisor
- Workload: deployment/target-gvisor
- Risk score: 2 (low)

## Findings
- **SETID_BINARIES_PRESENT** [medium] Remove setuid/setgid binaries from the image

## Dependencies
- services: target-gvisor
- ingresses: none
- network_policies: allow-attacker-to-target, allow-dns-egress, allow-llm-gateway-egress, default-deny-all
- hpas: none
- pdbs: none
- configmaps: none
- secrets: none
- runtime_class: gvisor
- node_selector: {'sandbox': 'gvisor'}
- volumes: {"emptyDir": {}, "name": "workspace"}, {"emptyDir": {}, "name": "artifacts"}

## Fix result
- Status: applied
- SERVICE_ACCOUNT_TOKEN: resolved_by_applied_patch
- ROOTFS_RW: resolved_by_applied_patch
- Post-remediation risk score: 2 (low)
