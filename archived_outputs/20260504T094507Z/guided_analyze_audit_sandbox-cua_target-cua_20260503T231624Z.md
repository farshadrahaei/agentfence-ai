# Sandbox Audit Report

- Generated: 2026-05-03T23:16:24.398112+00:00
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
- Guided message: Review API token necessity first, then make root fs read-only in staging and rebuild images to remove setuid/setgid binaries before promoting to production.
- Executive summary: Three security issues detected on Deployment target-cua in namespace sandbox-cua: exposed service account token, writable root filesystem, and setuid/setgid binaries in the image. Two are high severity and increase risk of container escape or lateral movement.
- Remediation overview: All fixes require manual changes to workload design or images. Prioritize removing unnecessary API access, making filesystem read-only where compatible, and rebuilding images to remove setuid/setgid binaries. Validate changes in staging before rollout.

### Prioritized roadmap
- Reduce runtime-capability and token exposure [high]: Service account tokens enable Kubernetes API access and lateral movement; high blast radius and severity.
  Issues: SERVICE_ACCOUNT_TOKEN
- Harden filesystem immutability [high]: Writable rootfs increases persistence and tampering risk; mitigations may require app changes.
  Issues: ROOTFS_RW
- Remove privileged binaries from image [medium]: Setuid/setgid binaries enable privilege escalation inside container; fix via image rebuild.
  Issues: SETID_BINARIES_PRESENT

### Item guidance
- SERVICE_ACCOUNT_TOKEN: Pod has an accessible service account token which may allow in-cluster API access if not required.
- ROOTFS_RW: Container root filesystem is writable, allowing persistence or modification of binaries/config at runtime.
- SETID_BINARIES_PRESENT: Image contains setuid/setgid binaries that can be abused for privilege escalation inside the container.
- Warning: Do not auto-apply fixes; changes require workload or image redesign and testing.
- Warning: Default-deny network policy may block traffic to this workload after changes; validate service dependencies.
- Warning: Enabling readOnlyRootFilesystem can break apps that write to root paths.
