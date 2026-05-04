# Sandbox Audit Report

- Generated: 2026-05-03T23:14:23.030520+00:00
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
- Guided message: Prioritize removing token exposure and making rootfs read-only; perform changes in staging and validate app behavior before production.
- Executive summary: High-risk findings for Deployment target-cua: service account token exposed, writable root filesystem, and setuid/setgid binaries present. Remediations require application/image changes and careful validation; not safe to auto-apply.
- Remediation overview: Address highest-impact items first: restrict or remove service account token usage, make root filesystem read-only where feasible, and rebuild images to remove setuid/setgid binaries. Validate functionality in staging before rollout.

### Prioritized roadmap
- Credentials and API access [high]: Exposed tokens enable Kubernetes API access and have highest blast radius.
  Issues: SERVICE_ACCOUNT_TOKEN
- Filesystem protections [high]: Writable root enables persistence and privilege escalation; requires app validation.
  Issues: ROOTFS_RW
- Image hardening [medium]: Setuid/setgid binaries increase local privilege escalation risk; fix via image rebuild.
  Issues: SETID_BINARIES_PRESENT

### Item guidance
- SERVICE_ACCOUNT_TOKEN: Pod has an accessible service account token that may allow access to the Kubernetes API.
- ROOTFS_RW: Container root filesystem is writable, allowing modification of binaries and system files.
- SETID_BINARIES_PRESENT: Image contains setuid/setgid binaries that can be abused for privilege escalation.
- Warning: Do not auto-apply fixes; workload redesign or image rebuilds are required.
- Warning: Default-deny network policy may block services that select this workload; verify service connectivity after changes.
- Warning: Changing rootfs or service account behavior can break runtime functionality—test thoroughly.
