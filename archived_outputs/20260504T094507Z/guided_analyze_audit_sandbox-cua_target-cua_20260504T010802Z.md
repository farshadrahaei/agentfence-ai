# Sandbox Audit Report

- Generated: 2026-05-04T01:08:02.474381+00:00
- Namespace: sandbox-cua
- Workload: deployment/target-cua
- Risk score: 14 (high)

## Findings
- **SERVICE_ACCOUNT_TOKEN** [high] Reduce service account token exposure
- **ROOTFS_RW** [high] Mount the root filesystem read-only
- **SETID_BINARIES_PRESENT** [medium] Remove setuid/setgid binaries from the image

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

## AI Advisor
- Guided message: Validate app behavior and writable paths before applying patches; do not auto-apply fixes without testing.
- Executive summary: Three issues raise a high-risk score: service account token exposure, writable root filesystem, and setuid/setgid binaries. Two high-severity items require operator validation before applying fixes; one medium requires image rebuild.
- Remediation overview: Do not auto-apply. Validate workload behavior and dependencies before changing automountServiceAccountToken or enabling readOnlyRootFilesystem. Rebuild images to remove setuid/setgid binaries if feasible.

### Prioritized roadmap
- Prevent credential exposure [high]: Token exposure enables cluster API abuse; high blast radius and severity.
  Issues: SERVICE_ACCOUNT_TOKEN
- Harden filesystem immutability [high]: Writable root increases tampering persistence and attack surface; may break workloads if applied blindly.
  Issues: ROOTFS_RW
- Minimize privileged binaries in image [medium]: Setuid/setgid binaries increase privilege escalation risk; remediation requires image changes.
  Issues: SETID_BINARIES_PRESENT

### Item guidance
- SERVICE_ACCOUNT_TOKEN: Pod currently exposes a service account token via automount; this allows in-cluster API access if exploited.
- ROOTFS_RW: Container root filesystem is writable, permitting adversaries to modify binaries or persist artifacts.
- SETID_BINARIES_PRESENT: Image contains setuid/setgid binaries which can be abused for privilege escalation.
- Warning: Disabling automountServiceAccountToken may break in-cluster API calls.
- Warning: Enabling readOnlyRootFilesystem can break apps that write to standard paths.
- Warning: Removing setuid/setgid binaries requires image rebuild and may remove expected admin tools.
