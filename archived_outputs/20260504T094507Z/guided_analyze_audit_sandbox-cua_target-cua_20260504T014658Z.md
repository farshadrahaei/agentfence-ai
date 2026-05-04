# Sandbox Audit Report

- Generated: 2026-05-04T01:46:58.558173+00:00
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
- Guided message: Review and validate each recommended change in staging before applying to production; prioritize service account and rootfs items.
- Executive summary: High-risk workload with 3 findings: service account token exposure, writable root filesystem, and setuid/setgid binaries. Changes may break functionality; operator validation required before fixes.
- Remediation overview: Recommend operator review each finding, validate workload behavior/dependencies, then apply fixes in order: reduce token exposure, make root filesystem read-only by relocating writable paths, rebuild images to remove setuid/setgid binaries.

### Prioritized roadmap
- Immediate operator review [high]: High-severity issues with potential to increase compromise impact or break workloads if changed without validation.
  Issues: SERVICE_ACCOUNT_TOKEN, ROOTFS_RW
- Image hardening [medium]: Requires image rebuild and functional validation; lower immediate blast potential but important to reduce privilege escalation risk.
  Issues: SETID_BINARIES_PRESENT

### Item guidance
- SERVICE_ACCOUNT_TOKEN: Pod automounts a service account token, exposing cluster credentials to containerized code.
- ROOTFS_RW: Container root filesystem is writable, allowing modification of binaries/configs at runtime.
- SETID_BINARIES_PRESENT: Image contains setuid/setgid binaries that enable privilege escalation within container.
- Warning: Disabling token automount will break in-pod Kubernetes API usage.
- Warning: Making root filesystem read-only may break apps that write to standard paths.
- Warning: Removing setuid/setgid binaries requires image rebuild and may remove expected utilities.
