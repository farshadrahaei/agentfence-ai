# Sandbox Audit Report

- Generated: 2026-05-04T01:53:11.409577+00:00
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
- Guided message: Plan an image rebuild: identify which setuid/setgid binaries are required, remove unnecessary ones, test the new image in staging, then deploy.
- Executive summary: One medium-risk finding: setuid/setgid binaries present in the workload image. Fix requires rebuilding the image and validating admin tooling; not safe to auto-fix.
- Remediation overview: Rebuild the container image from a minimal base and remove unnecessary setuid/setgid helpers. Validate any admin or tooling that relied on those binaries. Deploy rebuilt images after testing in a non-production environment.

### Prioritized roadmap
- Image hardening [high]: Setuid/setgid binaries increase local privilege escalation risk inside the pod; remediation requires image changes and validation.
  Issues: SETID_BINARIES_PRESENT

### Item guidance
- SETID_BINARIES_PRESENT: The container image contains setuid/setgid binaries which can allow privilege escalation within the pod if exploited.
- Warning: Do not attempt in-place pod binary removal in production; results may be transient and incomplete.
- Warning: Removing setuid/setgid helpers can break admin tooling; validate before rollout.
