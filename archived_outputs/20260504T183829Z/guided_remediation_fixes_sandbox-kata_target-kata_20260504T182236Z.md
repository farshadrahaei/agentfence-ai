# Sandbox Audit Report

- Generated: 2026-05-04T18:22:36.157122+00:00
- Namespace: sandbox-kata
- Workload: deployment/target-kata
- Risk score: 12 (high)

## Findings
- **ROOTFS_RW** [high] Mount the root filesystem read-only
- **SERVICE_ACCOUNT_TOKEN** [high] Reduce service account token exposure

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
- SERVICE_ACCOUNT_TOKEN: manual_only
- ROOTFS_RW: manual_only
- Post-remediation risk score: 12 (high) (partially verified)
