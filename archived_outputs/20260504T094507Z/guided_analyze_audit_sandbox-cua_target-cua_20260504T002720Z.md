# Sandbox Audit Report

- Generated: 2026-05-04T00:27:20.659057+00:00
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
- Guided message: Review API usage and writable paths, test fixes in staging, then apply changes in controlled rollout.
- Executive summary: Three issues found (2 high, 1 medium) increasing risk for the deployment target-cua in namespace sandbox-cua. Changes require operator validation before applying due to potential workload breakage.
- Remediation overview: Provide operator-reviewed changes: disable automounting service account token if API access is unnecessary, make root filesystem read-only after relocating writable paths to volumes, and rebuild images to remove setuid/setgid binaries. All fixes are manual approval or image/build changes.

### Prioritized roadmap
- Service account token exposure [high]: Present token increases cluster access risk; quick mitigation but may break in-pod API usage.
  Issues: SERVICE_ACCOUNT_TOKEN
- Writable root filesystem [high]: Read-only root reduces attack surface for tampering; requires relocating writable paths first.
  Issues: ROOTFS_RW
- Setuid/setgid binaries in image [medium]: Privileged binaries increase lateral movement risk; fix needs image rebuild and testing.
  Issues: SETID_BINARIES_PRESENT

### Item guidance
- SERVICE_ACCOUNT_TOKEN: Pod currently has a mounted service account token, allowing in-cluster API access if exploited.
- ROOTFS_RW: Container root filesystem is writable, enabling modification of binaries/config at runtime.
- SETID_BINARIES_PRESENT: Image contains setuid/setgid binaries that can escalate privileges if abused.
- Warning: Do not disable automount if the application uses the Kubernetes API.
- Warning: Enabling readOnlyRootFilesystem can break workloads that write to root-owned paths.
- Warning: Removing setuid/setgid binaries requires image rebuild and may remove required tooling.
