# Sandbox Audit Report

- Generated: 2026-05-04T16:54:33.741460+00:00
- Namespace: sandbox-kata
- Workload: deployment/target-kata
- Risk score: 20 (critical)

## Findings
- **SECCOMP_DISABLED** [high] Enable seccomp filtering
- **SERVICE_ACCOUNT_TOKEN** [high] Reduce service account token exposure
- **ROOTFS_RW** [high] Mount the root filesystem read-only
- **NO_NEW_PRIVS_DISABLED** [medium] Disallow privilege escalation
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
- Guided message: Start by testing NO_NEW_PRIVS and RuntimeDefault seccomp on a staging replica; validate automount and read-only root changes before applying to production; plan image rebuilds for setuid removal.
- Executive summary: Cluster analysis for Deployment sandbox-kata/target-kata found 5 security issues (3 high, 2 medium). Key risks: missing seccomp, service account token automount, writable rootfs, privilege escalation allowed, and setuid/setgid binaries in image. Overall risk band: critical with high blast radius (10).
- Remediation overview: Apply low-risk automatic patches first (enable no-new-privs, enable seccomp RuntimeDefault after validation). For changes with workload compatibility risk (disable automount, readOnlyRootFilesystem, remove setuid/setgid) perform operator validation, image rebuilds, or redesign before applying.

### Prioritized roadmap
- Automatic / Low-impact fixes [high]: These patches are low blast radius and can be applied safely after basic validation; they reduce attack surface quickly.
  Issues: NO_NEW_PRIVS_DISABLED, SECCOMP_DISABLED
- Workload-compatibility sensitive [high]: Require operator verification because changes can break runtime behavior (Kubernetes API access, writable paths).
  Issues: SERVICE_ACCOUNT_TOKEN, ROOTFS_RW
- Image rebuild required [medium]: Removal requires image changes and validation of admin tooling; not safe to auto-apply.
  Issues: SETID_BINARIES_PRESENT

### Item guidance
- SECCOMP_DISABLED: Pod has no seccomp profile; enabling RuntimeDefault restricts syscalls and reduces kernel attack surface.
- SERVICE_ACCOUNT_TOKEN: Service account token is automounted into the pod, exposing Kubernetes API credentials to processes inside the container.
- ROOTFS_RW: Container root filesystem is writable; attackers could persist modifications. readOnlyRootFilesystem mitigates this.
- NO_NEW_PRIVS_DISABLED: NO_NEW_PRIVS not set, allowing processes to gain privileges via setuid binaries or execve tricks.
- SETID_BINARIES_PRESENT: Image contains setuid/setgid binaries which can be abused to escalate privileges inside the container.
- Warning: Services select this workload; default-deny network policy may block expected traffic after changes.
- Warning: Disabling token automount will break workloads that call the Kubernetes API from inside the pod.
- Warning: Enabling readOnlyRootFilesystem can break workloads that write under /tmp, /var, /etc, or application paths.
