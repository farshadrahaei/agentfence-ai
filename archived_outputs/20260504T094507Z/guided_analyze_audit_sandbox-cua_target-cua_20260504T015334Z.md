# Sandbox Audit Report

- Generated: 2026-05-04T01:53:34.395371+00:00
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
- Guided message: Plan an image rebuild to remove setuid/setgid binaries; test thoroughly in staging before rollout.
- Executive summary: One medium-risk issue: the workload image contains setuid/setgid binaries which increase privilege risk. Fix requires rebuilding the image and validating tooling; not safe to auto-remediate.
- Remediation overview: Rebuild the container image on a minimal base and remove or replace unnecessary setuid/setgid helpers. Validate functionality of admin tooling and workflows after changes. Do not modify running pods directly.

### Prioritized roadmap
- Manual image hardening [high]: Contains binaries that elevate privileges; remediation requires image rebuild and functional validation to avoid breaking workload administration.
  Issues: SETID_BINARIES_PRESENT

### Item guidance
- SETID_BINARIES_PRESENT: The container image includes setuid/setgid binaries which can be used to escalate privileges if exploited.
- Warning: Do not attempt in-cluster binary removal on running pods — changes will be lost on restart.
- Warning: Removing setuid helpers can break administrative scripts or tooling if not validated.
