# Sandbox Audit Report

- Generated: 2026-05-04T16:54:27.997807+00:00
- Namespace: sandbox-gvisor
- Workload: deployment/target-gvisor
- Risk score: 8 (medium)

## Findings
- **SECCOMP_DISABLED** [high] Enable seccomp filtering
- **NO_NEW_PRIVS_DISABLED** [medium] Disallow privilege escalation
- **SETID_BINARIES_PRESENT** [medium] Remove setuid/setgid binaries from the image

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
- Guided message: First test RuntimeDefault seccomp and allowPrivilegeEscalation=false on a staging replica of target-gvisor; if behavior is acceptable, promote to production and schedule an image rebuild to remove setuid/setgid binaries.
- Executive summary: Three findings for Deployment sandbox-gvisor/target-gvisor: enable seccomp (high), disallow privilege escalation (medium), and remove setuid/setgid binaries from the image (medium). Risk band: medium, blast radius moderate.
- Remediation overview: Apply two safe workload patches to the Deployment (enable RuntimeDefault seccomp and set allowPrivilegeEscalation=false) after validating behavior; rebuild images to remove setuid/setgid helpers as a manual change.

### Prioritized roadmap
- Immediate workload hardening [high]: Both are low-blast-radius pod spec changes that reduce exploitability and can be tested in-place.
  Issues: SECCOMP_DISABLED, NO_NEW_PRIVS_DISABLED
- Image remediation [medium]: Requires image rebuild and functional validation; prevents privilege-escalation helpers from being abused.
  Issues: SETID_BINARIES_PRESENT

### Item guidance
- SECCOMP_DISABLED: Pod has no seccomp profile; enabling RuntimeDefault limits syscalls available to processes.
- NO_NEW_PRIVS_DISABLED: allowPrivilegeEscalation not enforced; processes may gain privileges via helpers.
- SETID_BINARIES_PRESENT: Image contains setuid/setgid binaries which can be abused for privilege escalation.
- Warning: Enabling RuntimeDefault seccomp can block uncommon syscalls used by debuggers or special runtimes.
- Warning: Disallowing privilege escalation may break images that rely on setuid/setgid helpers until images are rebuilt.
- Warning: Default-deny network policy may block expected traffic for services selecting this workload.
