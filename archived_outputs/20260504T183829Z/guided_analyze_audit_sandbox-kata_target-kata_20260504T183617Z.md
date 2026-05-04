# Sandbox Audit Report

- Generated: 2026-05-04T18:36:17.738417+00:00
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
- Guided message: Coordinate with app owners: verify API usage and writable paths before applying hardening; plan an image rebuild for setuid binaries.
- Executive summary: Deployment sandbox-kata/target-kata has 3 findings: two high-risk (service account token exposure, writable rootfs) and one medium-risk (setuid/setgid binaries). Risk band: high. Changes are not auto-applied due to compatibility concerns.
- Remediation overview: Review each finding with workload owners. For SERVICE_ACCOUNT_TOKEN and ROOTFS_RW, verify in-pod Kubernetes API usage and writable paths respectively before enabling protections. For SETID_BINARIES_PRESENT, plan an image rebuild to remove unnecessary setuid/setgid helpers.

### Prioritized roadmap
- Prevent credential exposure [P0]: High severity and blast radius; tokens in pods enable cluster API access.
  Issues: SERVICE_ACCOUNT_TOKEN
- Harden filesystem immutability [P0]: High severity; readOnlyRootFilesystem prevents many escalation vectors but may break writable apps.
  Issues: ROOTFS_RW
- Reduce privileged binaries in image [P1]: Medium severity; requires image rebuild and validation.
  Issues: SETID_BINARIES_PRESENT

### Item guidance
- SERVICE_ACCOUNT_TOKEN: Pod currently mounts a ServiceAccount token exposing cluster credentials to the workload.
- ROOTFS_RW: Container filesystem is writable; enabling readOnlyRootFilesystem may mitigate persistence and tampering risks.
- SETID_BINARIES_PRESENT: Image contains setuid/setgid binaries which can be abused for privilege escalation.
- Warning: Do not disable automount without confirming no in-cluster API usage.
- Warning: Enabling readOnlyRootFilesystem can break the workload if writable paths aren’t relocated.
- Warning: Removing setuid binaries requires image rebuild and testing.
