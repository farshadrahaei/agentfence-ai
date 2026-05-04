# Sandbox Audit Report

- Generated: 2026-05-04T18:06:29.370666+00:00
- Namespace: sandbox-kata
- Workload: deployment/target-kata
- Risk score: 14 (high)

## Findings
- **SERVICE_ACCOUNT_TOKEN** [high] Reduce service account token exposure
- **ROOTFS_RW** [high] Mount the root filesystem read-only
- **SETID_BINARIES_PRESENT** [medium] Remove setuid/setgid binaries from the image

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
- Guided message: Review and validate each remediation in staging: disable automount only if no in-pod API usage; move writable paths to volumes before enabling read-only root; rebuild images to remove setuid tools.
- Executive summary: Three issues found for Deployment sandbox-kata/target-kata: service account token automounting, writable root filesystem, and setuid/setgid binaries in the image. Risk band: high (total 14).
- Remediation overview: All fixes require operator review. SERVICE_ACCOUNT_TOKEN and ROOTFS_RW can be auto-generated but may break the workload; SETID_BINARIES_PRESENT requires image rebuild. Validate compatibility before applying changes.

### Prioritized roadmap
- Prevent credential exposure [high]: Service account tokens in pods increase risk of cluster compromise; high severity and blast radius.
  Issues: SERVICE_ACCOUNT_TOKEN
- Harden filesystem [high]: Writable root increases attack surface and persistence opportunities; requires verifying writable paths.
  Issues: ROOTFS_RW
- Reduce privileged tooling in image [medium]: Setuid/setgid binaries can be abused for privilege escalation; removal needs image rebuild and testing.
  Issues: SETID_BINARIES_PRESENT

### Item guidance
- SERVICE_ACCOUNT_TOKEN: Pod has an automounted service account token available inside the container.
- ROOTFS_RW: Container root filesystem is writable, allowing modification of binaries/config and persistence of changes.
- SETID_BINARIES_PRESENT: Image contains setuid/setgid binaries that can be used for privilege escalation.
- Warning: Do not disable automountServiceAccountToken without confirming in-pod API usage.
- Warning: Enabling readOnlyRootFilesystem can break the workload if writable paths remain.
- Warning: Removing setuid/setgid binaries requires image rebuild and validation; do not remove blindly.
