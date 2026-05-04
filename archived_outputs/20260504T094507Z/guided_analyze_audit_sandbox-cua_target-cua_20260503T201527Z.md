# Sandbox Audit Report

- Generated: 2026-05-03T20:15:27.500367+00:00
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
- Guided message: Review API usage and writable paths; stage changes (staging namespace) and validate before applying to production.
- Executive summary: High-risk workload: 3 findings (2 high, 1 medium). Key risks are exposed service account token and writable root filesystem; both can break workload if changed without validation. Image contains setuid/setgid binaries requiring rebuild to remove.
- Remediation overview: Apply manual, staged mitigations: confirm API needs before disabling automount; identify and relocate writable paths before enforcing readOnlyRootFilesystem; rebuild images to remove setuid/setgid helpers. Tests and operator approval required before changes.

### Prioritized roadmap
- Prevent credential exposure [high]: Service account token exposure enables cluster access; immediate operator review required before disabling automount.
  Issues: SERVICE_ACCOUNT_TOKEN
- Enforce immutable root filesystem [high]: Writable root increases attack surface and persistence; requires filesystem changes and app validation.
  Issues: ROOTFS_RW
- Harden container image [medium]: Setuid/setgid binaries increase privilege escalation risk; removal needs image rebuild and functional testing.
  Issues: SETID_BINARIES_PRESENT

### Item guidance
- SERVICE_ACCOUNT_TOKEN: Pod currently mounts a service account token, exposing credentials to processes inside the container.
- ROOTFS_RW: Root filesystem is writable, allowing modification or persistence by an attacker.
- SETID_BINARIES_PRESENT: Image contains setuid/setgid binaries that may be abused for privilege escalation.
- Warning: Do not disable automount without confirming in-pod Kubernetes API usage.
- Warning: Enabling readOnlyRootFilesystem will break workloads that write to root paths if writes are not moved to volumes.
- Warning: Removing setuid/setgid requires image rebuild and can remove expected tooling.
