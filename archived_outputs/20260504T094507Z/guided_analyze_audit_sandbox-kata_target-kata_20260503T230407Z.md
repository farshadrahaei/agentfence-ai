# Sandbox Audit Report

- Generated: 2026-05-03T23:04:07.777090+00:00
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
- Guided message: Review whether this workload needs in-cluster API access and which paths must remain writable. Approve fixes only after staging tests.
- Executive summary: Two high-severity findings: service account token is automounted into the pod and the container root filesystem is writable. Both fixes are not auto-applied due to potential workload breakage; operator review required.
- Remediation overview: For SERVICE_ACCOUNT_TOKEN: verify whether in-pod Kubernetes API access is required; if not, disable automountServiceAccountToken for the pod/workload or use a minimal dedicated ServiceAccount. For ROOTFS_RW: identify writable paths, move them to explicit volumes (emptyDir or PVC), then enable readOnlyRootFilesystem on containers.

### Prioritized roadmap
- Service account token exposure [high]: Token exposure enables lateral privilege escalation and API abuse; remove if not required.
  Issues: SERVICE_ACCOUNT_TOKEN
- Writable root filesystem [high]: Writable root increases persistence and tampering risk; prefer explicit writable volumes and read-only root.
  Issues: ROOTFS_RW

### Item guidance
- SERVICE_ACCOUNT_TOKEN: The pod currently receives a service account token. If the workload does not need Kubernetes API access, automounting the token increases attack surface.
- ROOTFS_RW: Containers run with a writable root filesystem. This allows attackers to modify binaries/config and maintain persistence if compromised.
- Warning: Disabling automountServiceAccountToken will break workloads using in-cluster Kubernetes clients.
- Warning: Enabling readOnlyRootFilesystem will break applications that write to root-owned paths unless writes are moved to volumes.
- Warning: Auto-generated fixes were withheld due to compatibility uncertainty; manual verification required.
