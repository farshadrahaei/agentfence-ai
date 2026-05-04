# Sandbox Audit Report

- Generated: 2026-05-03T23:23:09.680135+00:00
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
- Guided message: Prioritize enabling seccomp, removing service account token exposure, and making the root filesystem read-only—test each change in staging under gVisor before production rollout.
- Executive summary: The target deployment (sandbox-gvisor/target-gvisor) has 5 security issues: three high (disabled seccomp, service account token exposure, writable rootfs) and two medium (setuid/setgid binaries present, NO_NEW_PRIVS disabled). Risk band: critical with high blast radius. Remediations require manual workload/image changes and validation; none are auto-applicable.
- Remediation overview: Address high-severity items first: enable seccomp, remove service account token exposure, and make root filesystem read-only after validating writable paths. Then remove setuid/setgid binaries and disable privilege escalation. Changes likely require image rebuilds, PodSpec updates, and functional testing.

### Prioritized roadmap
- Enable kernel-level sandboxing and token minimization [P1]: These high-severity findings drive the critical risk band and have largest blast-radius and probability—mitigating them reduces attack surface most.
  Issues: SECCOMP_DISABLED, SERVICE_ACCOUNT_TOKEN, ROOTFS_RW
- Harden container image and runtime flags [P2]: Medium-severity issues that require image changes and runtime flag adjustments; lower immediate impact but important for defense-in-depth.
  Issues: SETID_BINARIES_PRESENT, NO_NEW_PRIVS_DISABLED

### Item guidance
- SECCOMP_DISABLED: Pod has no seccomp profile; processes can invoke risky syscalls.
- SERVICE_ACCOUNT_TOKEN: ServiceAccount token appears mounted, exposing Kubernetes API credentials to the container.
- ROOTFS_RW: Root filesystem is writable, increasing persistence/manipulation risk.
- SETID_BINARIES_PRESENT: Image contains setuid/setgid binaries that can escalate privileges.
- NO_NEW_PRIVS_DISABLED: NoNewPrivileges not enforced; processes may gain privileges via execve.
- Warning: None of these fixes are safe to auto-apply; manual validation is required.
- Warning: Default-deny network policy may block expected service traffic; check service selectors.
- Warning: Changes may require image rebuilds and application redesign to avoid outages.
