# Sandbox Audit Report

- Generated: 2026-05-04T18:09:39.357436+00:00
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
- Guided message: Review API usage and writable paths; stage changes in a test replica: disable automount if not needed and make root read-only only after moving writable data to volumes.
- Executive summary: Two high-severity issues: a mounted service account token (SERVICE_ACCOUNT_TOKEN) and a writable root filesystem (ROOTFS_RW). Both have high blast radius and can break the workload if changed without validation.
- Remediation overview: Review and stage changes: 1) Determine if pod needs in-cluster API access; if not, disable automountServiceAccountToken. 2) Make writable paths explicit (emptyDir or dedicated volumes), then enable readOnlyRootFilesystem. Do not apply automatically without testing.

### Prioritized roadmap
- Identity and Credentials [P0]: Exposed tokens enable cluster privilege escalation; high severity and common attack vector.
  Issues: SERVICE_ACCOUNT_TOKEN
- Filesystem Hardening [P1]: Read-only root reduces persistence and tampering, but requires verifying writable paths to avoid breakage.
  Issues: ROOTFS_RW

### Item guidance
- SERVICE_ACCOUNT_TOKEN: The pod currently has an automounted service account token which can be used to call the Kubernetes API from inside the container.
- ROOTFS_RW: The container root filesystem is writable, allowing in-container modification of binaries/config and persistence of artifacts.
- Warning: Do not auto-apply fixes: both remediations may break the workload.
- Warning: Disabling automount will stop any in-pod Kubernetes API interactions.
- Warning: Enabling readOnlyRootFilesystem will break writes to unspecified paths.
