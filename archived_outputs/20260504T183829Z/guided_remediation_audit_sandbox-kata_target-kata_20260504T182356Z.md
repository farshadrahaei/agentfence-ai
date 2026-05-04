# Sandbox Audit Report

- Generated: 2026-05-04T18:23:56.193845+00:00
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
- Guided message: Review whether this deployment needs the service account token and which paths must be writable; stage changes to disable automount and enable read-only root after moving writes to volumes.
- Executive summary: Two high-severity issues increase attack surface: a mounted service account token and a writable root filesystem. Both fixes are not auto-applied due to compatibility risk; operator review required.
- Remediation overview: Assess whether the pod requires in-cluster API access and which filesystem paths must remain writable. If safe, disable automountServiceAccountToken and set readOnlyRootFilesystem after placing writable paths on explicit volumes (emptyDir shown). Validate each change in staging.

### Prioritized roadmap
- Service account token exposure [P1]: Token access enables privilege escalation and lateral movement; likely high impact (blast radius 6). Confirm workload API needs before changing.
  Issues: SERVICE_ACCOUNT_TOKEN
- Writable root filesystem [P1]: Read-write root increases persistence and tampering risk. Requires ensuring application writable paths are moved to volumes first.
  Issues: ROOTFS_RW

### Item guidance
- SERVICE_ACCOUNT_TOKEN: Pod currently receives a service account token; this exposes cluster credentials to in-pod adversaries.
- ROOTFS_RW: Container root filesystem is writable, allowing modification of binaries, configs, or persistence of artifacts by an attacker.
- Warning: Do not flip automountServiceAccountToken without confirming in-pod Kubernetes API usage.
- Warning: Enabling readOnlyRootFilesystem can break the app if writable paths are not relocated.
- Warning: Auto-fixes were withheld due to workload compatibility uncertainty.
