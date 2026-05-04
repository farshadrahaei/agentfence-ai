# Sandbox Audit Report

- Generated: 2026-05-04T17:54:02.372260+00:00
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
- Guided message: Apply the two safe patches (no-new-privs and seccomp) in a staging rollout first; validate API usage and writable paths before changing tokens or rootfs, and plan an image rebuild for setuid binaries.
- Executive summary: Deployment target-kata in namespace sandbox-kata has 5 security issues (3 high, 2 medium). Highest-risk items: seccomp disabled, service account token automount, and writable root filesystem. Apply low-risk automatic patches first, then validate and approve higher-impact changes.
- Remediation overview: Apply auto-applicable patches (enable no-new-privs, enable seccomp RuntimeDefault) after validating seccomp compatibility. For non-auto fixes, validate workload behavior (API access, writable paths, setuid/setgid usage) and schedule image or manifest changes with operator approval.

### Prioritized roadmap
- Immediate auto-applicable fixes [high]: Low blast radius patches available; reduces attack surface quickly.
  Issues: NO_NEW_PRIVS_DISABLED, SECCOMP_DISABLED
- Validate workload behaviors before patching [high]: Changes can break functionality (API access, writable paths); require operator validation.
  Issues: SERVICE_ACCOUNT_TOKEN, ROOTFS_RW
- Image rebuild and hardening [medium]: Requires image changes and testing; lower immediate priority but reduces privilege abuse risk.
  Issues: SETID_BINARIES_PRESENT

### Item guidance
- SECCOMP_DISABLED: Seccomp not enforced; pod can make unsafe syscalls.
- SERVICE_ACCOUNT_TOKEN: ServiceAccount token automount enabled exposing kube API credentials to the pod.
- ROOTFS_RW: Root filesystem is writable allowing post-deploy modification of filesystem contents.
- NO_NEW_PRIVS_DISABLED: noNewPrivs not set; processes could gain privileges via setuid helpers.
- SETID_BINARIES_PRESENT: Image contains setuid/setgid binaries increasing privilege escalation risk.
- Warning: Do not disable automountServiceAccountToken without confirming no in-pod Kubernetes API usage.
- Warning: Enabling readOnlyRootFilesystem can break apps that expect writeable root paths.
- Warning: RuntimeDefault seccomp may block less-common syscalls—test before enforcing in production.
