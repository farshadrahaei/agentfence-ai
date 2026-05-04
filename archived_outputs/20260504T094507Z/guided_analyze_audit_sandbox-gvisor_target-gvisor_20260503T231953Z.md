# Sandbox Audit Report

- Generated: 2026-05-03T23:19:53.580108+00:00
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
- Guided message: Start remediation in a test environment: enable seccomp, remove or limit SA token exposure, and convert writable root paths to volumes before enabling read-only rootfs. Rebuild images for setuid removals and disable privilege escalation once validated.
- Executive summary: Deployment target-gvisor in namespace sandbox-gvisor has five security issues (3 high, 2 medium) raising a critical risk score. Issues require manual changes to images, pod spec, or workload design and cannot be auto-fixed safely.
- Remediation overview: Address high-severity issues first: enable seccomp, remove service-account token exposure, and make root filesystem read-only after validating writable paths. Then remove setuid/setgid binaries and disable privilege escalation. Changes may require image rebuilds, manifest updates, and functional testing.

### Prioritized roadmap
- High priority — reduce attack surface [P0]: These issues have highest severity and largest contribution to the critical risk score and blast radius.
  Issues: SECCOMP_DISABLED, SERVICE_ACCOUNT_TOKEN, ROOTFS_RW
- Medium priority — harden runtime [P1]: Lower severity but meaningful mitigation by removing setuid/setgid binaries and disabling privilege escalation.
  Issues: SETID_BINARIES_PRESENT, NO_NEW_PRIVS_DISABLED

### Item guidance
- SECCOMP_DISABLED: Pod is not using seccomp filtering; processes lack syscall-level restrictions.
- SERVICE_ACCOUNT_TOKEN: ServiceAccount token is projected into the pod or automount is enabled, exposing credentials.
- ROOTFS_RW: Root filesystem is writable, allowing runtime modification of binaries and config.
- SETID_BINARIES_PRESENT: Image contains setuid/setgid binaries increasing privilege escalation risk.
- NO_NEW_PRIVS_DISABLED: noNewPrivileges is not set, allowing execve-based privilege gains in some scenarios.
- Warning: Remediations require workload redesigns, image rebuilds, and functional testing—do not apply directly to production.
- Warning: Dependency graph indicates other resources may rely on this workload; changes can cause outages if not validated.
- Warning: Default-deny network policy may block expected traffic when adjusting network-related behavior.
