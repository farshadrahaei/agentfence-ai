# Sandbox Audit Report

- Generated: 2026-05-05T15:55:20.139741+00:00
- Namespace: sandbox-gvisor
- Workload: deployment/target-gvisor
- Risk score: 14 (high)

## Findings
- **SERVICE_ACCOUNT_TOKEN** [high] Reduce service account token exposure
- **ROOTFS_RW** [high] Mount the root filesystem read-only
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
