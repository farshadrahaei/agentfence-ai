# Sandbox Audit Report

- Generated: 2026-05-04T18:42:44.743197+00:00
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
- Guided message: Plan an image rebuild to remove setuid/setgid helpers, test in staging, then deploy the updated image.
- Executive summary: One medium-severity issue: the container image contains setuid/setgid binaries which increase privilege escalation risk. Fix requires image rebuild and validation; not safe to auto-apply.
- Remediation overview: Rebuild the image from a minimal base, remove or replace unnecessary setuid/setgid helpers, and validate functionality of any admin tooling that relied on them. Deploy the rebuilt image after testing.

### Prioritized roadmap
- Manual image hardening [high]: Setuid/setgid binaries present in the image create a local privilege escalation vector; remediation requires image changes and manual validation.
  Issues: SETID_BINARIES_PRESENT

### Item guidance
- SETID_BINARIES_PRESENT: The container image contains setuid/setgid binaries which can be abused for privilege escalation inside the pod.
- Warning: Do not attempt automated in-cluster removal of setuid/setgid files; changes require image rebuild and application-level validation.
- Warning: Removing binaries may break admin or debugging tools if not validated.
