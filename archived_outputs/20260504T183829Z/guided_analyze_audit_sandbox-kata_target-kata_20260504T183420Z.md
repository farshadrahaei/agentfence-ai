# Sandbox Audit Report

- Generated: 2026-05-04T18:34:20.585999+00:00
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
- Guided message: Review service-account and filesystem changes in staging first; only apply image rebuilds after validating functionality.
- Executive summary: Three security issues found for Deployment target-kata (namespace sandbox-kata): exposed service account token, writable root filesystem, and setuid/setgid binaries in the image. Risk band: high (total 14).
- Remediation overview: All fixes require operator review. Two fixes (serviceAccount automount and readOnlyRootFilesystem) can be patched but may break the workload; image rebuild needed to remove setuid/setgid binaries. Validate compatibility before applying.

### Prioritized roadmap
- Service account token exposure [P0]: High severity and high blast radius; tokens enable Kubernetes API access from the pod.
  Issues: SERVICE_ACCOUNT_TOKEN
- Writable root filesystem [P0]: High severity: writable root increases attack surface; enabling readOnlyRootFilesystem hardens container but can break writes.
  Issues: ROOTFS_RW
- Setuid/setgid binaries in image [P1]: Medium severity; requires image rebuild and validation of admin tooling.
  Issues: SETID_BINARIES_PRESENT

### Item guidance
- SERVICE_ACCOUNT_TOKEN: Pod automounts a service account token, allowing in-cluster API access which increases credential exposure.
- ROOTFS_RW: Container root filesystem is writable, enabling attackers to modify binaries or persistence on compromise.
- SETID_BINARIES_PRESENT: Image contains setuid/setgid binaries which can be used for privilege escalation if exploited.
- Warning: Do not disable automount if the pod legitimately uses the Kubernetes API.
- Warning: Enabling readOnlyRootFilesystem can cause application failures if writable paths aren’t remapped.
- Warning: Removing setuid/setgid binaries may remove required admin tooling—validate in CI/staging.
