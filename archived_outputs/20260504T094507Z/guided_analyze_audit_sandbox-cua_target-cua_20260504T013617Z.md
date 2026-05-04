# Sandbox Audit Report

- Generated: 2026-05-04T01:36:17.996815+00:00
- Namespace: sandbox-cua
- Workload: deployment/target-cua
- Risk score: 2 (low)

## Findings
- **SETID_BINARIES_PRESENT** [medium] Remove setuid/setgid binaries from the image

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
- Guided message: Rebuild the workload image removing unnecessary setuid/setgid binaries, validate tooling, and redeploy via normal CI/CD.
- Executive summary: One medium-severity issue found: setuid/setgid binaries present in the workload image. Remediation requires rebuilding the image and cannot be auto-applied.
- Remediation overview: Remove or replace setuid/setgid binaries by rebuilding the container image from a minimal base and validating required admin tooling. This is a manual change; do not modify running pods directly.

### Prioritized roadmap
- Image hardening (manual) [high]: Setuid/setgid binaries increase privilege escalation risk; fixing requires image rebuild and validation.
  Issues: SETID_BINARIES_PRESENT

### Item guidance
- SETID_BINARIES_PRESENT: The container image contains setuid/setgid helper binaries which can be abused for privilege escalation or lateral movement.
- Warning: Do not attempt to remove setuid/setgid bits from running pods as a long-term fix.
- Warning: Removing these binaries may break administrative or maintenance functionality unless replaced appropriately.
