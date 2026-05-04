# Sandbox Audit Report

- Generated: 2026-05-04T01:47:07.733373+00:00
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
- Guided message: Review each remediation carefully in staging: confirm no in-pod API usage, relocate writable paths, and plan image rebuilds before applying changes.
- Executive summary: Three issues found on Deployment sandbox-cua/target-cua: service account token automount enabled (high), writable root filesystem (high), and setuid/setgid binaries in image (medium). Changes are not auto-applied due to compatibility risk; operator review required.
- Remediation overview: For each issue, validate workload needs and dependencies before applying fixes. Service account token automount can be disabled if no in-pod Kubernetes API access is required. Make root filesystem read-only after relocating writable paths to explicit volumes. Remove setuid/setgid binaries by rebuilding images.

### Prioritized roadmap
- Identity and API access [P0]: High severity and broad blast radius; token exposure enables API access from pod.
  Issues: SERVICE_ACCOUNT_TOKEN
- Filesystem immutability [P0]: High severity; writable root increases attack surface and persistence options.
  Issues: ROOTFS_RW
- Image hardening [P1]: Medium severity; requires image rebuild and validation.
  Issues: SETID_BINARIES_PRESENT

### Item guidance
- SERVICE_ACCOUNT_TOKEN: Pod currently can mount a service account token, allowing in-cluster API access if code uses it.
- ROOTFS_RW: Container root filesystem is writable, enabling modification of binaries/config at runtime.
- SETID_BINARIES_PRESENT: Image contains setuid/setgid binaries which can be abused for privilege escalation.
- Warning: Do not disable service account tokens if workload uses Kubernetes API—this will break functionality.
- Warning: Enabling readOnlyRootFilesystem without moving writable paths will cause runtime failures.
- Warning: Removing setuid/setgid binaries may remove expected admin tooling; validate before deployment.
