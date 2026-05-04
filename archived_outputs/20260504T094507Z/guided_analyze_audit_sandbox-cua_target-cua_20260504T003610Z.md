# Sandbox Audit Report

- Generated: 2026-05-04T00:36:10.373916+00:00
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
- Guided message: Review API usage and writable paths for target-cua before applying fixes; approve service account and rootfs changes, and plan an image rebuild for setuid artifacts.
- Executive summary: Three security issues found for Deployment target-cua in namespace sandbox-cua: two high-risk items (service account token exposure and writable root filesystem) and one medium-risk item (setuid/setgid binaries). Automatic fixes were withheld due to compatibility and functional risk; operator validation is required before remediation.
- Remediation overview: Prioritize disabling service account token automount and making root filesystem read-only after validating workload API usage and writable paths. Rebuild images to remove setuid/setgid binaries as a lower-priority, manual task.

### Prioritized roadmap
- Identity and credentials [high]: Exposed service account tokens enable cluster API access; immediate review needed to limit blast radius.
  Issues: SERVICE_ACCOUNT_TOKEN
- Filesystem immutability [high]: Writable root filesystem increases attack surface and persistence options; requires path validation before enforcing read-only.
  Issues: ROOTFS_RW
- Image hardening [medium]: Setuid/setgid binaries in images can be abused; removal requires image rebuild and functional testing.
  Issues: SETID_BINARIES_PRESENT

### Item guidance
- SERVICE_ACCOUNT_TOKEN: Pod currently has a mounted service account token which can be used to access the Kubernetes API.
- ROOTFS_RW: Container root filesystem is writable, allowing persistent or in-place tampering by attackers.
- SETID_BINARIES_PRESENT: Image contains setuid/setgid binaries which can be used to escalate privileges inside the container.
- Warning: Do not disable automount if pod uses Kubernetes API tokens; verify first.
- Warning: Enabling readOnlyRootFilesystem can break the workload if writable paths are not relocated.
- Warning: Removing setuid/setgid binaries requires image rebuild and validation; may remove expected tooling.
