# Sandbox Audit Report

- Generated: 2026-05-04T01:12:23.200072+00:00
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
- Guided message: Review service account usage and writable paths; validate fixes in staging before applying to production.
- Executive summary: Three issues found for Deployment target-cua in namespace sandbox-cua: two high-risk (service account token exposure, writable root filesystem) and one medium-risk (setuid/setgid binaries). Automatic fixes were not applied due to compatibility risk; operator validation required.
- Remediation overview: Prioritize disabling service account token automount and enabling read-only root filesystem after verifying workload needs and writable paths. Remove setuid/setgid binaries via image rebuild. Do not auto-apply without operator review.

### Prioritized roadmap
- Identity and credentials [high]: Service account tokens enable Kubernetes API access and present high blast radius if abused.
  Issues: SERVICE_ACCOUNT_TOKEN
- Filesystem hardening [high]: Writable root filesystem increases persistence and tampering risk; enabling read-only rootfs mitigates this.
  Issues: ROOTFS_RW
- Image hygiene [medium]: Setuid/setgid binaries in image increase privilege escalation risk and require image changes to fix.
  Issues: SETID_BINARIES_PRESENT

### Item guidance
- SERVICE_ACCOUNT_TOKEN: Pod automounts service account token; this exposes cluster credentials to processes in the container.
- ROOTFS_RW: Container root filesystem is writable, allowing attackers to modify binaries or persist files.
- SETID_BINARIES_PRESENT: Image contains setuid/setgid binaries that can be abused for privilege escalation.
- Warning: Do not disable automount if workload requires Kubernetes API access.
- Warning: Enabling readOnlyRootFilesystem without moving writable paths will break the application.
- Warning: Removing setuid/setgid binaries requires image rebuild and testing.
