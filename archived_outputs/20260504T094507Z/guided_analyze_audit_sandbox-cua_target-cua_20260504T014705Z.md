# Sandbox Audit Report

- Generated: 2026-05-04T01:47:05.317402+00:00
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
- Guided message: Review and approve fixes in staging: disable token automount if API access not needed, convert writable paths to volumes then enable readOnlyRootFilesystem, and rebuild images to remove setuid/setgid binaries.
- Executive summary: Three findings for Deployment sandbox-cua/target-cua: service account token automount exposed (high), root filesystem writable (high), and setuid/setgid binaries in image (medium). Fixes require operator review; automatic patches were not applied due to compatibility risk.
- Remediation overview: Prioritize disabling automount and making rootfs read-only after verifying workload needs and writable paths. Remove setuid/setgid binaries by rebuilding images. Apply changes with validation in staging before production.

### Prioritized roadmap
- Identity and credentials [high]: Service account tokens enable cluster access; reducing exposure reduces blast radius.
  Issues: SERVICE_ACCOUNT_TOKEN
- Filesystem immutability [high]: Making root filesystem read-only prevents many post-exploit persistence and tampering vectors.
  Issues: ROOTFS_RW
- Image hardening [medium]: Removing setuid/setgid helpers reduces privilege escalation risk inside the container.
  Issues: SETID_BINARIES_PRESENT

### Item guidance
- SERVICE_ACCOUNT_TOKEN: Pod currently allows automounting of the ServiceAccount token, exposing credentials to containerized processes.
- ROOTFS_RW: Container image or pod spec allows a writable root filesystem, increasing risk of tampering and persistence.
- SETID_BINARIES_PRESENT: Image contains setuid/setgid binaries that can be abused for privilege escalation inside the container.
- Warning: Do not disable automount if the workload requires Kubernetes API access without verifying.
- Warning: Enabling readOnlyRootFilesystem will break writes to non-volume paths unless moved first.
- Warning: Removing setuid/setgid binaries may remove expected admin utilities; validate tooling needs.
