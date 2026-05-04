# Sandbox Audit Report

- Generated: 2026-05-03T23:22:06.052876+00:00
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
- Guided message: Prioritize enabling seccomp and reducing token exposure, then enforce read-only rootfs after validating writable paths; plan image rebuilds and staged testing.
- Executive summary: Deployment sandbox-gvisor/target-gvisor has 5 security issues (3 high, 2 medium) increasing risk (critical band, blast radius 10). Issues require manual redesigns or image/environment validation and cannot be auto-fixed.
- Remediation overview: Address high-severity items first: enable seccomp, reduce service account token exposure, and make root filesystem read-only after validating writable paths. Then remove setuid/setgid binaries and disable privilege escalation. Changes may require image rebuilds, pod spec updates, and functional testing.

### Prioritized roadmap
- Immediate - container runtime and credentials [high]: These issues most increase attack surface and contribute highest to risk score; they affect sandboxing, API access, and filesystem integrity.
  Issues: SECCOMP_DISABLED, SERVICE_ACCOUNT_TOKEN, ROOTFS_RW
- Follow-up - image hardening and process restrictions [medium]: Hardening image and preventing privilege escalation reduce lateral escalation risk but typically require image rebuilds and validation.
  Issues: SETID_BINARIES_PRESENT, NO_NEW_PRIVS_DISABLED

### Item guidance
- SECCOMP_DISABLED: Enable a seccomp profile (runtime/default or a tailored profile) in the pod securityContext to restrict syscalls.
- SERVICE_ACCOUNT_TOKEN: Avoid mounting service account tokens when not needed: set automountServiceAccountToken: false or use minimal RBAC if API access required.
- ROOTFS_RW: Set securityContext.readOnlyRootFilesystem: true and relocate any required writable paths to explicit writable volumes (ensure /tmp, workspace mounts are writable if needed).
- SETID_BINARIES_PRESENT: Remove or replace setuid/setgid binaries in the container image; run minimal base images and drop unnecessary tools.
- NO_NEW_PRIVS_DISABLED: Enable securityContext.allowPrivilegeEscalation: false and set securityContext.runAsNonRoot where applicable to prevent processes gaining elevated privileges.
- Warning: Changes require workload redesign, image changes, and environment-specific validation.
- Warning: Do not apply fixes in production without testing; some settings can break the app (writes, API access).
- Warning: Default-deny network policy may block expected traffic from services selecting this workload.
