# Sandbox Audit Report

- Generated: 2026-05-04T17:48:03.553985+00:00
- Namespace: sandbox-kata
- Workload: deployment/target-kata
- Risk score: 8 (medium)

## Findings
- **SECCOMP_DISABLED** [high] Enable seccomp filtering
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
- Guided message: Start by testing RuntimeDefault seccomp and disabling privilege escalation in staging; plan an image rebuild to remove setuid/setgid binaries.
- Executive summary: Three findings for Deployment target-kata in namespace sandbox-kata: missing Seccomp, noNewPrivs disabled, and setuid/setgid binaries present. Overall risk band: medium (total 8).
- Remediation overview: Apply workload-scoped patches for seccomp and no_new_privs; rebuild images to remove setuid/setgid helpers. Validate in a non-production environment (RuntimeDefault testing) before enforcing in production.

### Prioritized roadmap
- Enable runtime security hardening [high]: Both are low-blast-radius workload patches that reduce attack surface quickly; Seccomp rated high severity increases priority.
  Issues: SECCOMP_DISABLED, NO_NEW_PRIVS_DISABLED
- Image hygiene and build changes [medium]: Requires image rebuild and functional validation; moderate impact on exploitation risk.
  Issues: SETID_BINARIES_PRESENT

### Item guidance
- SECCOMP_DISABLED: Pod lacks Seccomp profile; set profile to RuntimeDefault to block uncommon syscalls.
- NO_NEW_PRIVS_DISABLED: allowPrivilegeEscalation unset/true; set to false to prevent privilege escalation.
- SETID_BINARIES_PRESENT: Image contains setuid/setgid binaries that can be abused for privilege escalation.
- Warning: Enforcing RuntimeDefault may break apps that use uncommon syscalls—test first.
- Warning: Removing setuid/setgid binaries can require application redesign and validation.
- Warning: Do not apply production enforcement without staging validation.
