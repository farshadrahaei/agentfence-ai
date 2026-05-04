# Sandbox Audit Report

- Generated: 2026-05-04T18:26:56.879179+00:00
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
- Guided message: Review whether the pod needs Kubernetes API access and which paths must be writable; then stage changes (disable automount and enable readOnlyRootFilesystem) in a non-production environment and monitor behavior.
- Executive summary: Two high-severity findings for Deployment sandbox-kata/target-kata: (1) Service account token is mounted in the pod, increasing credential exposure. (2) Root filesystem is writable, increasing attack surface. Both fixes were NOT auto-applied due to compatibility risks.
- Remediation overview: Validate workload needs before changing: disable automountServiceAccountToken if the pod does not call the Kubernetes API; enable readOnlyRootFilesystem after moving writable paths (e.g., /tmp, /var/tmp, workspace) to explicit writable volumes (emptyDir).

### Prioritized roadmap
- Service account token exposure [high]: Token exposure can allow in-cluster privilege abuse; fix may break API-using pods so operator verification required.
  Issues: SERVICE_ACCOUNT_TOKEN
- Writable root filesystem [high]: Writable root increases persistence/escape risk; enabling readOnlyRootFilesystem can break apps that write to root-owned paths.
  Issues: ROOTFS_RW

### Item guidance
- SERVICE_ACCOUNT_TOKEN: The pod has a projected/service account token mounted, allowing in-cluster API access if misused.
- ROOTFS_RW: Containers run with a writable root filesystem, enabling attackers to modify system files or persist tools.
- Warning: Do not disable automountServiceAccountToken if the workload needs in-cluster API access.
- Warning: Enabling readOnlyRootFilesystem without relocating writable paths will likely break the pod.
- Warning: Fixes were not auto-applied due to potential compatibility impacts.
