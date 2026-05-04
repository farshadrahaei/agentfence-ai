# Sandbox Audit Report

- Generated: 2026-05-04T17:07:57.066168+00:00
- Namespace: sandbox-kata
- Workload: deployment/target-kata
- Risk score: 12 (high)

## Findings
- **SERVICE_ACCOUNT_TOKEN** [high] Reduce service account token exposure
- **ROOTFS_RW** [high] Mount the root filesystem read-only

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

## AI Advisor
- Guided message: Review each recommendation, confirm workload API needs and writable paths, then apply changes in a test environment and run functional tests before rolling to production.
- Executive summary: Two high-severity issues: a mounted service account token and a writable root filesystem. Both increase attack surface; fixes are manual-approval recommended because they may break the workload.
- Remediation overview: 1) Disable automounting of the service account token for the pod if it does not need Kubernetes API access. 2) Make the container filesystem read-only and relocate writable paths to explicit volumes (emptyDir) before enabling. Both changes should be validated against runtime behavior and require operator confirmation.

### Prioritized roadmap
- Identity and credentials [high]: Service account tokens allow broad in-cluster access; removing reduces lateral movement risk.
  Issues: SERVICE_ACCOUNT_TOKEN
- Filesystem immutability [high]: Read-only root limits persistence and tampering; enable after ensuring writable paths are explicit.
  Issues: ROOTFS_RW

### Item guidance
- SERVICE_ACCOUNT_TOKEN: The pod currently has an automounted service account token, exposing credentials inside the container.
- ROOTFS_RW: Container root filesystem is writable; an attacker could modify binaries or persist artifacts.
- Warning: Do not disable automount if the pod needs Kubernetes API access — it will break functionality.
- Warning: Enabling readOnlyRootFilesystem can break apps that write to root-owned paths; move writes to volumes first.
- Warning: Automatic fixes were withheld due to compatibility uncertainty; operator approval required.
