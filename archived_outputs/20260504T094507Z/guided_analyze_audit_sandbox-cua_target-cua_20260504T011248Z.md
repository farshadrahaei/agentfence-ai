# Sandbox Audit Report

- Generated: 2026-05-04T01:12:48.736982+00:00
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
- Guided message: Review and approve the recommended changes in staging: disable automount if no API use, move writable paths to volumes and enable read-only rootfs, and rebuild images to remove setuid/setgid binaries.
- Executive summary: Three security issues found for Deployment target-cua in sandbox-cua: service-account token automount exposed, root filesystem writable, and setuid/setgid binaries present. Risk band: high (total 14).
- Remediation overview: All fixes require operator review or image/workload changes. Do not apply automatically. Confirm Kubernetes API needs before disabling automount, identify writable paths and move them to volumes before enabling read-only rootfs, and rebuild images to remove setuid/setgid binaries.

### Prioritized roadmap
- Service account token exposure [P0]: High severity and high blast radius; tokens permit cluster API access and should be limited first.
  Issues: SERVICE_ACCOUNT_TOKEN
- Writable root filesystem [P0]: High severity; making rootfs read-only reduces runtime attack surface but can break workloads, so validate before change.
  Issues: ROOTFS_RW
- Setuid/Setgid binaries in image [P1]: Medium severity; requires image rebuild and testing, lower immediate blast than token/rootfs issues.
  Issues: SETID_BINARIES_PRESENT

### Item guidance
- SERVICE_ACCOUNT_TOKEN: Pod currently exposes a service account token (automount). This grants in-cluster API access if exploited.
- ROOTFS_RW: Containers mount a writable root filesystem allowing runtime modification of binaries/config, increasing persistence risk.
- SETID_BINARIES_PRESENT: Image contains setuid/setgid binaries which can be abused for privilege escalation inside the container.
- Warning: Do not disable token automount without confirming in-pod Kubernetes API usage; it will break API clients.
- Warning: Enabling readOnlyRootFilesystem will break writes to /tmp, /var, and specified mounts unless moved to volumes.
- Warning: Removing setuid/setgid binaries requires image rebuild and may remove expected admin functionality.
