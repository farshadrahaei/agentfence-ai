# Sandbox Audit Report

- Generated: 2026-05-04T01:12:21.845845+00:00
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
- Guided message: Review and approve fixes in staging: disable token automount if unused, relocate writable paths then enable read-only rootfs, and rebuild images to remove setuid/setgid binaries.
- Executive summary: High-risk workload (sandbox-cua/target-cua) has 3 issues: service account token exposure, writable root filesystem, and setuid/setgid binaries. Fixes require operator validation or image changes to avoid breaking functionality.
- Remediation overview: Prioritize disabling automount of service account tokens and making root filesystem read-only after validating runtime needs and writable paths. Remove setuid/setgid binaries via image rebuild. Do not auto-apply without testing; use workload-specific validation steps described below.

### Prioritized roadmap
- Prevent credential exposure [high]: Service account tokens can be used for lateral privilege escalation; high severity and blast radius.
  Issues: SERVICE_ACCOUNT_TOKEN
- Harden filesystem integrity [high]: Writable root filesystem increases attack surface and persistence opportunities.
  Issues: ROOTFS_RW
- Reduce privilege escalation vectors in image [medium]: Setuid/setgid binaries enable local privilege escalation; requires image rebuild.
  Issues: SETID_BINARIES_PRESENT

### Item guidance
- SERVICE_ACCOUNT_TOKEN: Pod automounts a service account token, exposing credentials inside the container.
- ROOTFS_RW: Container root filesystem is writable, allowing modification of binaries/config and persistence.
- SETID_BINARIES_PRESENT: Image contains setuid/setgid binaries which can be abused for privilege escalation.
- Warning: Do not auto-apply patches; changes can break workload functionality.
- Warning: Disabling automount will break any in-pod Kubernetes API callers.
- Warning: Enabling read-only rootfs requires explicit writable volumes for app data.
