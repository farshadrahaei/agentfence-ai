# Sandbox Audit Report

- Generated: 2026-05-04T17:46:56.004545+00:00
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
