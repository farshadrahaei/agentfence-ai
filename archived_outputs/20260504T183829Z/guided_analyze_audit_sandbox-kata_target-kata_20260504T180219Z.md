# Sandbox Audit Report

- Generated: 2026-05-04T18:02:19.559807+00:00
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
- Guided message: Review and validate each remediation in staging: disable automount only if pod doesn't need API access, convert writable paths to volumes before readOnlyRootFilesystem, and rebuild images to remove setuid/setgid binaries.
- Executive summary: Three security issues found for Deployment sandbox-kata/target-kata: service account token automount enabled, writable root filesystem, and setuid/setgid binaries in the image. These increase attack surface and persistence risk; fixes require operator validation before applying.
- Remediation overview: Prioritize disabling service account token automount and making root filesystem read-only after verifying workload needs and writable paths. Remove setuid/setgid binaries via image rebuild. All fixes are manual-review or operator-approved due to compatibility risk.

### Prioritized roadmap
- Credentials exposure (highest) [P0]: Service account tokens in-pod enable lateral movement and API access; high severity and blast radius.
  Issues: SERVICE_ACCOUNT_TOKEN
- Immutable filesystem (high) [P0]: Writable root increases attack persistence and tampering; enabling readOnlyRootFilesystem mitigates but may break app.
  Issues: ROOTFS_RW
- Image hardening (medium) [P1]: Setuid/setgid binaries enable privilege escalation; requires image rebuild and validation.
  Issues: SETID_BINARIES_PRESENT

### Item guidance
- SERVICE_ACCOUNT_TOKEN: Pod mounts a service account token, allowing in-pod access to Kubernetes API and cluster credentials exposure.
- ROOTFS_RW: Container root filesystem is writable, permitting persistence and tampering of binaries/config in runtime.
- SETID_BINARIES_PRESENT: Image contains setuid/setgid binaries which can be abused for privilege escalation inside the container.
- Warning: Do not disable automount without confirming Kubernetes API usage by the workload.
- Warning: Making root filesystem read-only will break apps that write to OS paths unless writable volumes are provided.
- Warning: Removing setuid/setgid binaries requires image rebuild and may alter expected tooling behavior.
