# Sandbox Audit Report

- Generated: 2026-05-04T01:05:20.879541+00:00
- Namespace: sandbox-cua
- Workload: deployment/target-cua
- Risk score: 6 (medium)

## Findings
- **ROOTFS_RW** [high] Mount the root filesystem read-only

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
- Guided message: Identify and relocate writable paths to explicit volumes, test in a staging pod with readOnlyRootFilesystem, then enable the setting when validated.
- Executive summary: One high-severity finding: the workload root filesystem is writable. Recommend mounting root FS read-only after ensuring the app has no required writes to root-owned paths.
- Remediation overview: Prepare writable paths as explicit volumes (emptyDir or persistent volumes) for /tmp, /var/tmp, application-specific dirs and any other write targets. After validating, enable readOnlyRootFilesystem in the pod securityContext. Do not auto-apply without testing.

### Prioritized roadmap
- Prevent tampering and limit attack surface [high]: Read-only root reduces persistence and modification by attackers; high severity and medium risk score contribution.
  Issues: ROOTFS_RW

### Item guidance
- ROOTFS_RW: Pod's root filesystem is writable. This allows an attacker or compromised process to modify system files, persist malware, or tamper with binaries and configs.
- Warning: Do not enable readOnlyRootFilesystem before verifying all required writable paths are mounted.
- Warning: Changing filesystem mode can cause runtime failures and loss of functionality if writes are blocked.
