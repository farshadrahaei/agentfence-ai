# Sandbox Audit Report

- Generated: 2026-05-03T23:15:23.137519+00:00
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
- Guided message: Address service account token exposure and read-only rootfs first in staging; then rebuild images to remove setuid/setgid binaries. Validate each step before production.
- Executive summary: Three issues raise a high-risk score for the Deployment target-cua: exposed service account tokens, writable root filesystem, and setuid/setgid binaries in the image. All fixes require manual design or image changes and cannot be auto-applied.
- Remediation overview: Prioritize eliminating credentials exposure and minimizing runtime privileges. Implement workload and image changes: remove or limit service account token mounts, enforce read-only rootfs with explicit writable volumes, and rebuild images without setuid/setgid binaries. Validate each change in a staging environment before production roll-out.

### Prioritized roadmap
- Credentials & API access [P0]: Service account tokens enable cluster API access and have highest blast/probability contribution.
  Issues: SERVICE_ACCOUNT_TOKEN
- Runtime filesystem immutability [P0]: Writable root increases persistence and lateral movement risk; mitigations require app validation.
  Issues: ROOTFS_RW
- Image hardening [P1]: Setuid/setgid binaries increase privilege escalation risk; fix via image rebuild.
  Issues: SETID_BINARIES_PRESENT

### Item guidance
- SERVICE_ACCOUNT_TOKEN: Pod has access to a mounted service account token, allowing in-cluster API access if not needed.
- ROOTFS_RW: Container root filesystem is writable, enabling runtime tampering and persistence.
- SETID_BINARIES_PRESENT: Image contains setuid/setgid binaries which attackers can abuse for privilege escalation.
- Warning: Do not apply changes directly in production without staging validation.
- Warning: Removing tokens or enabling read-only root may break legitimate application behavior.
- Warning: Image changes may require CI/CD and dependency updates.
