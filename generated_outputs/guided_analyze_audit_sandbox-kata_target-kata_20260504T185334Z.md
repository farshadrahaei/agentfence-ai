# Sandbox Audit Report

- Generated: 2026-05-04T18:53:34.784803+00:00
- Namespace: sandbox-kata
- Workload: deployment/target-kata
- Risk score: 2 (low)

## Findings
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
- Guided message: Plan an image rebuild to remove setuid/setgid binaries; validate in staging and update deployment with the new image once tested.
- Executive summary: One medium-severity issue: setuid/setgid binaries are present in the workload image. Fix requires image rebuild and validation; risk band is low with limited blast radius.
- Remediation overview: Rebuild the container image from a minimal base, remove or replace unnecessary setuid/setgid helpers, and validate functionality in a staging environment before deployment. This is a manual change; do not attempt in-cluster automatic removal.

### Prioritized roadmap
- Manual image hardening [high]: Setuid/setgid binaries increase privilege escalation risk and require image rebuilds and functional validation; address first to reduce attack surface.
  Issues: SETID_BINARIES_PRESENT

### Item guidance
- SETID_BINARIES_PRESENT: The container image contains setuid/setgid binaries which can be abused for privilege escalation inside the pod or by a compromised container.
- Warning: Do not attempt to remove setuid/setgid files from running pods—changes require image rebuild.
- Warning: Services selecting this workload (target-kata) and default-deny network policies may affect testing; validate connectivity.
