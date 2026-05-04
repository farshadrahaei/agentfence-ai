# Sandbox Audit Report

- Generated: 2026-05-03T23:11:35.805925+00:00
- Namespace: sandbox-gvisor
- Workload: deployment/target-gvisor
- Risk score: 12 (high)

## Findings
- **SERVICE_ACCOUNT_TOKEN** [high] Reduce service account token exposure
- **ROOTFS_RW** [high] Mount the root filesystem read-only

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
