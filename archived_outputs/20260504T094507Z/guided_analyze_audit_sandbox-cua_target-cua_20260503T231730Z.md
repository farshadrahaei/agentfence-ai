# Sandbox Audit Report

- Generated: 2026-05-03T23:17:30.114247+00:00
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
- Guided message: Prioritize removing service-account token exposure and enabling read-only rootfs in staging; rebuild images to remove setuid/setgid binaries. Validate each change before rolling to production.
- Executive summary: Three issues raise a high-risk posture: service account token exposure and writable rootfs (both high), plus setuid/setgid binaries (medium). Remediations require workload or image changes and cannot be auto-applied safely.
- Remediation overview: Perform manual changes to the workload and container image: remove or restrict service account token usage, enable read-only root filesystem after ensuring writable paths are handled, and rebuild images without setuid/setgid binaries. Validate each change in a staging environment before production rollout.

### Prioritized roadmap
- Privilege and credential exposure [P1]: Service account tokens grant API access; highest impact and probability.
  Issues: SERVICE_ACCOUNT_TOKEN
- Filesystem integrity [P1]: Writable root increases persistence and tampering risk; requires app validation.
  Issues: ROOTFS_RW
- Image hardening [P2]: Setuid/setgid binaries enable privilege escalation; lower blast radius but should be removed in image rebuild.
  Issues: SETID_BINARIES_PRESENT

### Item guidance
- SERVICE_ACCOUNT_TOKEN: Pod has a projected or mounted service account token that could allow cluster API access if compromised.
- ROOTFS_RW: Container root filesystem is writable, enabling file tampering or persistence after compromise.
- SETID_BINARIES_PRESENT: Image contains setuid/setgid binaries which can be abused for privilege escalation.
- Warning: Changes require application or image modifications—do not patch pods in place.
- Warning: Enabling read-only root may break apps that write to root paths; verify writable mounts first.
- Warning: Removing service account tokens can disrupt legitimate API calls if not accounted for.
