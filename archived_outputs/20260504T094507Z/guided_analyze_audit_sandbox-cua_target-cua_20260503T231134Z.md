# Sandbox Audit Report

- Generated: 2026-05-03T23:11:34.430153+00:00
- Namespace: sandbox-cua
- Workload: deployment/target-cua
- Risk score: 6 (medium)

## Findings
- **ROOTFS_RW** [high] Mount the root filesystem read-only

## Dependencies
- services: target-cua
- ingresses: none
- network_policies: allow-attacker-to-target, allow-dns-egress, allow-llm-gateway-egress, default-deny-all
- hpas: none
- pdbs: none
- configmaps: none
- secrets: none
- runtime_class: None
- node_selector: {'sandbox': 'cua'}
- volumes: {"emptyDir": {}, "name": "workspace"}, {"emptyDir": {}, "name": "artifacts"}
