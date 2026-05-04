# Sandbox Audit Report

- Generated: 2026-05-04T17:28:20.906534+00:00
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
- Guided message: Review whether the pod needs Kubernetes API access and which paths must remain writable; then apply the recommended patches in a staging environment and run full functionality tests before rollout.
- Executive summary: Two high-severity issues found for Deployment sandbox-kata/target-kata: a mounted service account token and a writable root filesystem. Both increase privilege exposure and post-exploit persistence risk. Fixes require operator verification to avoid breaking the workload.
- Remediation overview: Recommend (1) disable automounting of the service account token for the pod unless Kubernetes API access is required, and (2) enable readOnlyRootFilesystem after relocating any required writable paths to dedicated writable volumes (emptyDir or specific mounts). Both changes are not auto-applied due to compatibility risk—validate functionality after changes.

### Prioritized roadmap
- Credentials exposure [high]: Service account tokens in the pod broaden attacker access to cluster API; high blast radius and probability.
  Issues: SERVICE_ACCOUNT_TOKEN
- Filesystem integrity / persistence [high]: Writable root filesystem allows easier persistence and file tampering; moving writable paths first reduces breakage risk.
  Issues: ROOTFS_RW

### Item guidance
- SERVICE_ACCOUNT_TOKEN: Pod currently has an automounted service account token exposing cluster credentials to processes inside the container.
- ROOTFS_RW: Container root filesystem is writable which enables modification of system and application files by a compromised process.
- Warning: Disabling service account automount will break any in-pod Kubernetes API usage.
- Warning: Making the root filesystem read-only can break apps that write to /tmp, /var, /etc or to the workspace mount.
- Warning: Changes were not auto-applied due to compatibility uncertainty; operator approval required.
