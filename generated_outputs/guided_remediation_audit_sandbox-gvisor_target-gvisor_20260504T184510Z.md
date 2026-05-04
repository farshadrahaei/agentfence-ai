# Sandbox Audit Report

- Generated: 2026-05-04T18:45:10.401167+00:00
- Namespace: sandbox-gvisor
- Workload: deployment/target-gvisor
- Risk score: 14 (high)

## Findings
- **SERVICE_ACCOUNT_TOKEN** [high] Reduce service account token exposure
- **ROOTFS_RW** [high] Mount the root filesystem read-only
- **SETID_BINARIES_PRESENT** [medium] Remove setuid/setgid binaries from the image

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
- Guided message: Validate API dependency and writable paths; test fixes in staging under the gVisor runtime before applying to production.
- Executive summary: Three security issues found for Deployment sandbox-gvisor/target-gvisor: two high-risk (service account token exposure; writable root filesystem) and one medium (setuid/setgid binaries). Fixes require operator review and possible image/workload changes.
- Remediation overview: Prioritize reducing token exposure and enabling read-only root filesystem after validating workload dependencies and writable paths. Rebuild images to remove setuid/setgid helpers. Do not auto-apply; validate compatibility with gVisor runtime and services that select this workload.

### Prioritized roadmap
- Immediate (high priority) [high]: High severity and largest contribution to overall risk; both can enable privilege escalation or persistent compromise.
  Issues: SERVICE_ACCOUNT_TOKEN, ROOTFS_RW
- Needed (medium priority) [medium]: Medium severity; requires image rebuild and validation but lower blast radius.
  Issues: SETID_BINARIES_PRESENT

### Item guidance
- SERVICE_ACCOUNT_TOKEN: Pod currently mounts a service account token increasing API access exposure.
- ROOTFS_RW: Container root filesystem is writable, allowing modification of binaries/config and persistence of compromise.
- SETID_BINARIES_PRESENT: Image contains setuid/setgid binaries that can be abused for privilege escalation inside the container.
- Warning: Do not disable automount or enable read-only rootfs without confirming workload compatibility.
- Warning: gVisor runtime may affect compatibility—test changes on nodes labeled sandbox=gvisor.
- Warning: Image rebuilds are required to remove setuid/setgid binaries; patching runtime alone is insufficient.
