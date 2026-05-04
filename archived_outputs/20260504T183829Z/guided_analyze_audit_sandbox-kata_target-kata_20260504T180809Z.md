# Sandbox Audit Report

- Generated: 2026-05-04T18:08:09.391234+00:00
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
- Guided message: Review and validate each remediation in a test environment before applying to production; start by confirming API usage and writable paths.
- Executive summary: Three issues found on deployment sandbox-kata/target-kata: service account token automount, writable root filesystem, and setuid/setgid binaries in the image. Risk band: high; recommended manual validation before changes.
- Remediation overview: All fixes require operator review or image rebuild. Do not apply automatic patches without validating workload behavior (Kubernetes API usage, writable paths, and required setuid helpers).

### Prioritized roadmap
- Protect credentials and API access [P1]: Service account tokens exposed to pod present high privilege risk and high blast radius.
  Issues: SERVICE_ACCOUNT_TOKEN
- Harden filesystem immutability [P1]: Writable root increases attack surface; enabling read-only root must be validated to avoid breakage.
  Issues: ROOTFS_RW
- Reduce privileged binaries in image [P2]: Setuid/setgid binaries increase privilege escalation risk but require image rebuild to remediate.
  Issues: SETID_BINARIES_PRESENT

### Item guidance
- SERVICE_ACCOUNT_TOKEN: Pod mounts a service account token enabling in-cluster API access; this increases credential exposure.
- ROOTFS_RW: Container filesystem is writable at root; attackers who gain code execution can modify binaries/config or persist changes.
- SETID_BINARIES_PRESENT: Image contains setuid/setgid binaries which can be leveraged for privilege escalation.
- Warning: Do not disable service account token automount without confirming in-pod API usage.
- Warning: Enabling readOnlyRootFilesystem can break the application if writable paths are not relocated.
- Warning: Removing setuid/setgid binaries requires an image rebuild and functional validation.
