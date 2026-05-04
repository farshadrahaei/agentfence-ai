# Sandbox Audit Report

- Generated: 2026-05-04T18:45:07.818533+00:00
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
- Guided message: Review API usage and writable paths first; test changes in staging replicas before applying to production.
- Executive summary: Three issues found for Deployment sandbox-kata/target-kata: service account token automount, writable root filesystem, and setuid/setgid binaries. Risk band: high (score 14). Changes may break the workload; operator review required.
- Remediation overview: Manual remediation recommended. Confirm service account API needs before disabling automount; identify and relocate writable paths before enforcing readOnlyRootFilesystem; rebuild images to remove setuid/setgid binaries. Do not apply automated fixes without validation.

### Prioritized roadmap
- Prevent credential exposure [high]: Service account tokens enable cluster access and contribute high blast radius; immediate verification required before disabling automount.
  Issues: SERVICE_ACCOUNT_TOKEN
- Harden filesystem immutability [high]: Read-only root reduces attack surface but likely breaks writes—needs workload-specific path adjustments first.
  Issues: ROOTFS_RW
- Reduce privileged binaries [medium]: Setuid/setgid binaries increase risk; removal requires image rebuild and validation.
  Issues: SETID_BINARIES_PRESENT

### Item guidance
- SERVICE_ACCOUNT_TOKEN: Pod currently exposes a service account token via automount. This grants in-cluster API access if used by attackers or processes.
- ROOTFS_RW: Containers run with writable root filesystem allowing runtime modification of system files and binaries.
- SETID_BINARIES_PRESENT: Image contains setuid/setgid binaries which can be abused for privilege escalation inside the pod.
- Warning: Do not disable automount if workload requires Kubernetes API access without testing.
- Warning: Enabling readOnlyRootFilesystem can cause immediate application failures if writable paths are not relocated.
- Warning: Removing setuid/setgid binaries requires image rebuild and may remove expected tooling.
