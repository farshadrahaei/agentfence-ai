# Sandbox Audit Report

- Generated: 2026-05-04T18:21:55.873279+00:00
- Namespace: sandbox-kata
- Workload: deployment/target-kata
- Risk score: 14 (high)

## Findings
- **SERVICE_ACCOUNT_TOKEN** [high] Reduce service account token exposure
- **ROOTFS_RW** [high] Mount the root filesystem read-only
- **SETID_BINARIES_PRESENT** [medium] Remove setuid/setgid binaries from the image

## Dependencies
- services: target-kata
- ingresses: none
- network_policies: allow-attacker-to-target, allow-dns-egress, allow-llm-gateway-egress, default-deny-all
- hpas: none
- pdbs: none
- configmaps: none
- secrets: none
- runtime_class: kata-qemu
- node_selector: {'sandbox': 'kata'}
- volumes: {"emptyDir": {}, "name": "workspace"}, {"emptyDir": {}, "name": "artifacts"}

## AI Advisor
- Guided message: Review API usage and writable paths before applying changes; test in staging on kata runtime and coordinate image rebuilds with owners.
- Executive summary: Deployment 'target-kata' in namespace 'sandbox-kata' has three issues: exposed service account token, writable root filesystem, and setuid/setgid binaries. These increase risk (high band, total score 14) and may allow privilege escalation or lateral movement. Fixes require operator validation; automatic patching was withheld due to compatibility concerns.
- Remediation overview: Prioritize disabling service account token automount and enforcing read-only root filesystem after validating workload behavior. Rebuild images to remove setuid/setgid binaries as a lower-priority, manual change. Coordinate changes with owners and test in staging on kata runtime.

### Prioritized roadmap
- High priority — API token exposure [high]: Service account tokens enable Kubernetes API access and high-impact lateral movement; disabling automount reduces attack surface but may break legitimate API calls.
  Issues: SERVICE_ACCOUNT_TOKEN
- High priority — Filesystem immutability [high]: Writable root increases modification and persistence risk; making root read-only prevents many attacks but requires handling writable paths.
  Issues: ROOTFS_RW
- Medium priority — In-image setuid/setgid [medium]: Setuid/setgid binaries can be abused for privilege escalation; removal requires image rebuild and validation.
  Issues: SETID_BINARIES_PRESENT

### Item guidance
- SERVICE_ACCOUNT_TOKEN: Pod currently has an automounted service account token, exposing cluster credentials to processes in the pod.
- ROOTFS_RW: Root filesystem is writable, allowing file tampering and persistence of malicious artifacts.
- SETID_BINARIES_PRESENT: Image contains setuid/setgid binaries that can permit privilege escalation from within the container.
- Warning: Disabling automount will break pods that use in-cluster API credentials.
- Warning: Enabling readOnlyRootFilesystem can cause application failures if writable paths are not relocated.
- Warning: Removing setuid/setgid binaries may break admin tooling and requires image rebuild.
