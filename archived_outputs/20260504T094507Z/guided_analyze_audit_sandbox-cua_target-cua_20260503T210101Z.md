# Sandbox Audit Report

- Generated: 2026-05-03T21:01:01.783896+00:00
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
- Guided message: Review API usage and writable paths before applying fixes; schedule image rebuild for setuid binaries and validate changes in staging.
- Executive summary: Three security issues found for Deployment target-cua in namespace sandbox-cua: service account token automount enabled (high), root filesystem writable (high), and setuid/setgid binaries present in image (medium). Remediations require operator validation and some need image/workload changes.
- Remediation overview: Prioritize disabling service account token automount and making root filesystem read-only after confirming workload compatibility. Remove setuid/setgid binaries via image rebuild. Do not auto-apply; validate application behavior and dependencies first.

### Prioritized roadmap
- Credentials exposure and API access [high]: Service account token availability increases lateral movement and cluster access risk; breaking changes possible so confirm dependency on Kubernetes API.
  Issues: SERVICE_ACCOUNT_TOKEN
- Filesystem immutability [high]: Writable root increases attack surface; enabling readOnlyRootFilesystem can break apps that write to root—verify writable paths first.
  Issues: ROOTFS_RW
- Image hardening [medium]: Setuid/setgid binaries elevate local privilege; removal requires image rebuild and functional validation.
  Issues: SETID_BINARIES_PRESENT

### Item guidance
- SERVICE_ACCOUNT_TOKEN: Pod automounts a service account token, exposing credentials inside the container.
- ROOTFS_RW: Container root filesystem is writable, allowing modification of binaries/config and increasing attack surface.
- SETID_BINARIES_PRESENT: Image contains setuid/setgid binaries which can be abused to escalate privileges inside the container.
- Warning: Do not disable automount if pod needs Kubernetes API access—this will break functionality.
- Warning: Enabling readOnlyRootFilesystem can break apps that write to root-owned paths.
- Warning: Removing setuid/setgid binaries requires image rebuild and may affect admin tooling.
