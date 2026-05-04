# Sandbox Audit Report

- Generated: 2026-05-04T18:44:51.835685+00:00
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
- Guided message: Rebuild the workload image without setuid/setgid helpers, validate in sandbox, then redeploy; do not attempt in-cluster binary removal.
- Executive summary: One medium-severity issue: container image contains setuid/setgid binaries which increase privilege escalation risk. Fix requires image rebuild and validation; not safe to auto-patch in-cluster.
- Remediation overview: Rebuild the affected image from a minimal base, remove or replace unnecessary setuid/setgid helpers, and validate functionality. Update CI/build pipeline to prevent reintroduction and redeploy the workload once validated.

### Prioritized roadmap
- Manual image hardening [high]: Removing setuid/setgid binaries reduces attack surface but requires image changes and workload validation; address first to eliminate privilege escalation vector.
  Issues: SETID_BINARIES_PRESENT

### Item guidance
- SETID_BINARIES_PRESENT: Image contains setuid/setgid binaries which can be used for privilege escalation if exploited.
- Warning: In-cluster removal of setuid/setgid files is unsafe and temporary—do not rely on it.
- Warning: Removing binaries may break admin or tooling workflows; test thoroughly before production rollout.
- Warning: Default-deny network policy may block expected traffic after redeploy; verify connectivity.
