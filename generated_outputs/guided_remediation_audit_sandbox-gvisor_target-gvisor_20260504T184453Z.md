# Sandbox Audit Report

- Generated: 2026-05-04T18:44:53.216928+00:00
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

## AI Advisor
- Guided message: Review API access needs, identify writable paths to convert to volumes, and schedule an image rebuild for setuid removal; test changes in staging before production rollout.
- Executive summary: Three issues found for Deployment sandbox-gvisor/target-gvisor: exposed service account token, writable root filesystem, and setuid/setgid binaries in image. Risk band: high (total 14).
- Remediation overview: All fixes require operator involvement. Two high-risk runtime changes (disable automount, enable readOnlyRootFilesystem) may break the workload; validate mounts and API needs before applying. Removing setuid/setgid binaries requires image rebuild.

### Prioritized roadmap
- Identity and credentials [high]: Service account tokens present increase lateral movement and API access risk; high severity and blast radius.
  Issues: SERVICE_ACCOUNT_TOKEN
- Filesystem immutability [high]: Writable root increases persistence and tampering risk; enabling readOnlyRootFilesystem is impactful and must be validated.
  Issues: ROOTFS_RW
- Image hardening [medium]: Setuid/setgid binaries expand privilege escalation risk but require image rebuild to remediate.
  Issues: SETID_BINARIES_PRESENT

### Item guidance
- SERVICE_ACCOUNT_TOKEN: Pod currently exposes a mounted service account token which allows in-cluster API access if compromised.
- ROOTFS_RW: Root filesystem is writable; adversaries can modify binaries/config or persist files under standard paths.
- SETID_BINARIES_PRESENT: Image contains setuid/setgid binaries which can be abused for privilege escalation inside the container.
- Warning: Disabling automount may break in-pod API clients and dependent resources.
- Warning: Enabling readOnlyRootFilesystem will break workloads that write to non-volume paths.
- Warning: Removing setuid/setgid binaries requires image rebuild and may remove expected admin tools.
