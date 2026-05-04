# Sandbox Audit Report

- Generated: 2026-05-04T01:39:22.760988+00:00
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
- Guided message: Rebuild the target-cua image without setuid/setgid helpers, test in staging, then update the Deployment and CI pipeline.
- Executive summary: One medium-severity issue: image contains setuid/setgid binaries which increase privilege escalation risk. Fix requires rebuilding the image and validating dependent tooling; not safe to auto-fix.
- Remediation overview: Remove or replace unnecessary setuid/setgid utilities from the container image by rebuilding on a minimal base, validate functionality of admin tools, and redeploy the workload. Update CI/image build to prevent recurrence.

### Prioritized roadmap
- Image hardening (manual) [high]: Setuid/setgid binaries in images can enable privilege escalation even with low blast radius; remediation requires image rebuild and validation.
  Issues: SETID_BINARIES_PRESENT

### Item guidance
- SETID_BINARIES_PRESENT: The container image contains setuid/setgid binaries which can allow local privilege escalation inside the pod.
- Warning: Do not attempt in-place binary removal on running pods—changes won't survive pod restart and may break dependencies.
- Warning: Removing setuid/setgid helpers can break admin or debug tooling; validate thoroughly before production rollout.
