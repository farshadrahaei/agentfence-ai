# Sandbox Audit Report

- Generated: 2026-05-03T23:03:23.444452+00:00
- Namespace: sandbox-kata
- Workload: deployment/target-kata
- Risk score: 12 (high)

## Findings
- **SERVICE_ACCOUNT_TOKEN** [high] Reduce service account token exposure
- **ROOTFS_RW** [high] Mount the root filesystem read-only

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
- Guided message: Review API usage and writable paths in this deployment; test fixes in staging before rolling to production.
- Executive summary: Two high-severity issues: a mounted service account token and a writable root filesystem. Both increase risk if an attacker compromises the pod. Automated fixes were withheld due to potential breakage; operator review required.
- Remediation overview: Confirm application needs before changing. For the service account token, disable automount if the pod does not call the Kubernetes API. For rootfs, identify writable paths and move them to explicit writable volumes (emptyDir) then enable readOnlyRootFilesystem.

### Prioritized roadmap
- Credentials and API access [P0]: Service account token exposure allows lateral movement and cluster API misuse; high blast radius and immediate impact.
  Issues: SERVICE_ACCOUNT_TOKEN
- Filesystem immutability [P1]: Writable root filesystem enables persistence for an attacker and tampering with code/config; requires compatibility checks before enforcing.
  Issues: ROOTFS_RW

### Item guidance
- SERVICE_ACCOUNT_TOKEN: Pod currently mounts a service account token, exposing credentials to processes in the container.
- ROOTFS_RW: Root filesystem is writable, allowing attackers to modify binaries, config, or persist artifacts.
- Warning: Do not enable fixes in-place without compatibility testing; both fixes can break the workload.
- Warning: Services selecting this workload (target-kata) may be blocked by default-deny network policy changes.
