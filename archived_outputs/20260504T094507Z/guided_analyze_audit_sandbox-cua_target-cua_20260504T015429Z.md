# Sandbox Audit Report

- Generated: 2026-05-04T01:54:29.935456+00:00
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
- Guided message: Plan an image rebuild to remove setuid/setgid binaries; validate in staging and coordinate rollout.
- Executive summary: One medium-severity finding: setuid/setgid binaries present in the workload image (target-cua). Remediation requires image rebuild and validation; not auto-applicable.
- Remediation overview: Remove unnecessary setuid/setgid binaries by rebuilding the container image from a minimal base, removing or replacing helper tools that require elevated bits, and validating admin workflows. Test in staging before deploy.

### Prioritized roadmap
- Manual image hardening [high]: Setuid/setgid binaries increase privilege escalation risk and require image rebuild and functional validation; fix cannot be applied safely in-cluster.
  Issues: SETID_BINARIES_PRESENT

### Item guidance
- SETID_BINARIES_PRESENT: Container image contains setuid/setgid helper binaries which allow privilege escalation if exploited.
- Warning: Do not attempt in-cluster binary removal; changes must be made in the image build process.
- Warning: Removing setuid/setgid binaries may disrupt admin or tooling workflows—validate before production rollout.
