# Sandbox Audit Report

- Generated: 2026-05-04T16:53:21.840015+00:00
- Namespace: sandbox-gvisor
- Workload: deployment/target-gvisor
- Risk score: 12 (high)

## Findings
- **SERVICE_ACCOUNT_TOKEN** [high] Reduce service account token exposure
- **ROOTFS_RW** [high] Mount the root filesystem read-only

## Dependencies
- services: target-gvisor
- ingresses: none
- network_policies: allow-attacker-to-target, allow-dns-egress, allow-llm-gateway-egress, default-deny-all
- hpas: none
- pdbs: none
- configmaps: none
- secrets: none
- runtime_class: gvisor
- node_selector: {'sandbox': 'gvisor'}
- volumes: {"emptyDir": {}, "name": "workspace"}, {"emptyDir": {}, "name": "artifacts"}

## AI Advisor
- Guided message: Confirm whether this workload needs Kubernetes API access and identify writable paths; then apply token automount disabling and readOnlyRootFilesystem in a tested Deployment copy before rolling to production.
- Executive summary: Two high-severity issues detected for Deployment sandbox-gvisor/target-gvisor: a service account token is automounted into pods (SERVICE_ACCOUNT_TOKEN) and the container root filesystem is writable (ROOTFS_RW). Both increase risk if the pod is compromised. fixes are not auto-applied due to potential workload breakage.
- Remediation overview: Validate whether the workload needs in-cluster API access and which paths must remain writable. Then either disable automounting of the service account token and/or set readOnlyRootFilesystem after moving writable paths to explicit volumes (emptyDir) or other writable mounts. Apply changes with operator approval and test.

### Prioritized roadmap
- Credentials exposure [P0]: Automounted tokens allow privilege escalation and lateral movement; high severity and broad blast radius.
  Issues: SERVICE_ACCOUNT_TOKEN
- Filesystem integrity [P1]: Writable root filesystem enables persistence and tampering if container is compromised; requires compatibility checks.
  Issues: ROOTFS_RW

### Item guidance
- SERVICE_ACCOUNT_TOKEN: Pods currently have the service account token automounted, exposing cluster credentials to any process in the container.
- ROOTFS_RW: Containers run with a writable root filesystem, allowing an attacker to modify binaries/config or persist files.
- Warning: Do not disable automountServiceAccountToken if the pod or sidecars call the Kubernetes API.
- Warning: Do not enable readOnlyRootFilesystem until all required writable paths are mounted explicitly.
- Warning: Workload runs on runtimeClass gvisor; validate compatibility after changes.
