# Sandbox Audit Report

- Generated: 2026-05-03T23:20:59.625077+00:00
- Namespace: sandbox-gvisor
- Workload: deployment/target-gvisor
- Risk score: 20 (critical)

## Findings
- **SECCOMP_DISABLED** [high] Enable seccomp filtering
- **SERVICE_ACCOUNT_TOKEN** [high] Reduce service account token exposure
- **ROOTFS_RW** [high] Mount the root filesystem read-only
- **SETID_BINARIES_PRESENT** [medium] Remove setuid/setgid binaries from the image
- **NO_NEW_PRIVS_DISABLED** [medium] Disallow privilege escalation

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
- Guided message: Start by validating writable paths and whether the SA token is needed; then stage seccomp and readOnlyRootFilesystem changes in a non-production rollout before full deployment.
- Executive summary: Five security findings for Deployment target-gvisor in namespace sandbox-gvisor: three high (seccomp disabled, service account token exposed, rootfs writable) and two medium (setuid/setgid binaries present, allow privilege escalation). Remediations require manual changes to images, pod spec, or workload design and cannot be auto-applied.
- Remediation overview: Prioritize protections that reduce attack surface first: enable seccomp, remove service-account token mounting or limit its permissions, and make root filesystem read-only after validating writable paths. Then remediate image-level issues (remove setuid/setgid) and disallow privilege escalation via pod spec.

### Prioritized roadmap
- Platform hardening (highest) [P0]: These issues have highest severity and blast radius; fixing them greatly reduces exploitability.
  Issues: SECCOMP_DISABLED, SERVICE_ACCOUNT_TOKEN, ROOTFS_RW
- Image and runtime hygiene [P1]: Lower severity but important to prevent privilege escalation; image rebuilds and pod spec flags required.
  Issues: SETID_BINARIES_PRESENT, NO_NEW_PRIVS_DISABLED

### Item guidance
- SECCOMP_DISABLED: Pod lacks seccomp profile; syscalls are not filtered which increases kernel attack surface.
- SERVICE_ACCOUNT_TOKEN: Service account token is exposed to the pod, enabling potential Kubernetes API access if compromised.
- ROOTFS_RW: Root filesystem is writable, allowing persistent or unexpected modifications inside container.
- SETID_BINARIES_PRESENT: Image contains setuid/setgid binaries that can allow privilege escalation if abused.
- NO_NEW_PRIVS_DISABLED: no_new_privs is not set; processes could gain additional privileges via execve tricks.
- Warning: Automatic fixes were not applied because changes require image rebuilds or workload-specific validation.
- Warning: Default-deny network policy may block expected traffic; confirm service dependencies after changes.
- Warning: gVisor runtime may change syscall compatibility—test seccomp and fs changes thoroughly.
