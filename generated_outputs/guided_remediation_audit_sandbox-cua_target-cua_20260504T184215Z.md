# Sandbox Audit Report

- Generated: 2026-05-04T18:42:15.386290+00:00
- Namespace: sandbox-cua
- Workload: deployment/target-cua
- Risk score: 8 (medium)

## Findings
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
- Guided message: Start by identifying writable paths and moving them to explicit volumes; then enable readOnlyRootFilesystem for the pod and validate. Plan an image rebuild to remove setuid/setgid binaries and test in staging before rollout.
- Executive summary: Two security issues found for Deployment target-cua in namespace sandbox-cua: a high-severity writable root filesystem (ROOTFS_RW) and a medium-severity presence of setuid/setgid binaries in the image (SETID_BINARIES_PRESENT). Both require manual intervention and validation before changes.
- Remediation overview: Prioritize making the root filesystem read-only by first locating and remediating writable paths (move to volumes/emptyDir). Then plan an image rebuild to remove setuid/setgid binaries. Do not auto-apply changes; validate functionality after each step.

### Prioritized roadmap
- Prevent host/privilege escalation via filesystem protections [high]: Writable root filesystem gives attackers higher persistence and modification capability; fixing reduces blast radius significantly.
  Issues: ROOTFS_RW
- Harden container image privileges [medium]: Setuid/setgid binaries increase privilege escalation risk; removal requires image rebuild and behavior validation.
  Issues: SETID_BINARIES_PRESENT

### Item guidance
- ROOTFS_RW: Container root filesystem is writable. Making it readOnlyRootFilesystem reduces modification and persistence risk but can break workloads that write to paths like /tmp, /var, or app-specific directories.
- SETID_BINARIES_PRESENT: Image contains setuid/setgid binaries which can be abused for privilege escalation.
- Warning: Enabling readOnlyRootFilesystem without relocating writable paths can break the workload.
- Warning: Removing setuid/setgid binaries may remove expected admin utilities and require image redesign.
- Warning: Network default-deny policy may block service traffic after changes; verify service selectors and policies.
