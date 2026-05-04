# Sandbox Audit Report

- Generated: 2026-05-04T01:02:41.339775+00:00
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
- Guided message: Review workload API usage and writable paths; validate fixes in staging before applying to production.
- Executive summary: Three security issues found for Deployment target-cua in namespace sandbox-cua: service-account token exposure, writable root filesystem, and setuid/setgid binaries. Risks are high; fixes require operator validation or image rebuilds.
- Remediation overview: All fixes are manual or operator-approved. Recommend confirming Kubernetes API needs before disabling automount, identifying writable paths before enabling readOnlyRootFilesystem, and rebuilding images to remove setuid/setgid binaries.

### Prioritized roadmap
- Prevent credential exposure [high]: Service account token presence increases cluster access risk (high severity, large blast radius). Verify workload API usage before change.
  Issues: SERVICE_ACCOUNT_TOKEN
- Harden filesystem immutability [high]: Writable root increases escalate-and-persist risk; enabling readOnlyRootFilesystem mitigates but may break app.
  Issues: ROOTFS_RW
- Reduce privileged binaries in image [medium]: Setuid/setgid binaries enable privilege escalation; removal requires image rebuild and testing.
  Issues: SETID_BINARIES_PRESENT

### Item guidance
- SERVICE_ACCOUNT_TOKEN: Pod mounts a service account token, exposing cluster credentials to container processes.
- ROOTFS_RW: Container root filesystem is writable, allowing modification of binaries/config at runtime.
- SETID_BINARIES_PRESENT: Image contains setuid/setgid binaries that can be abused for privilege escalation.
- Warning: Do not disable automount if workload needs Kubernetes API access.
- Warning: Enabling readOnlyRootFilesystem can break applications that write to system paths.
- Warning: Removing setuid/setgid binaries requires image rebuild and may remove expected tooling.
