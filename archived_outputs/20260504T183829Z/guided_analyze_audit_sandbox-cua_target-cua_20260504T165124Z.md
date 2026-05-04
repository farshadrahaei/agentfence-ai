# Sandbox Audit Report

- Generated: 2026-05-04T16:51:24.512472+00:00
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
- Guided message: Review and approve fixes in a staging environment: disable token automount and enable readOnlyRootFilesystem only after verifying writable paths; schedule image rebuild to remove setuid/setgid binaries.
- Executive summary: Three security issues found for Deployment target-cua in namespace sandbox-cua: service account token automount, root filesystem writable, and setuid/setgid binaries in the image. Risk band: high. Changes require operator review before applying.
- Remediation overview: All fixes are manual-review required. Prioritize disabling token automount and enabling readOnlyRootFilesystem after validating workload behavior; rebuild images to remove setuid/setgid binaries as longer-term work.

### Prioritized roadmap
- High priority — immediate audit and mitigations [high]: Both are high-severity with large blast radius and can enable privilege escalation or tampering; require verification before automated patching.
  Issues: SERVICE_ACCOUNT_TOKEN, ROOTFS_RW
- Medium priority — image rebuild [medium]: Requires image changes and validation; lower immediate exploitability but should be remediated in CI/CD.
  Issues: SETID_BINARIES_PRESENT

### Item guidance
- SERVICE_ACCOUNT_TOKEN: Pod automounts a ServiceAccount token which increases cluster API exposure if container is compromised.
- ROOTFS_RW: Root filesystem is writable allowing in-container modification of binaries/config which aids persistence and tampering.
- SETID_BINARIES_PRESENT: Image contains setuid/setgid binaries enabling privilege escalation inside the container if exploited.
- Warning: Do not auto-apply changes in production without testing — they can break workloads.
- Warning: Disabling automount will break in-pod Kubernetes API usage.
- Warning: Enabling readOnlyRootFilesystem will break apps that write to root paths unless those are remounted writable.
