# Sandbox Audit Report

- Generated: 2026-05-04T18:35:40.451906+00:00
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
- Guided message: Plan an image rebuild to remove setuid/setgid binaries, test in staging, then roll out replacement to the target-kata Deployment.
- Executive summary: One medium-severity issue: image contains setuid/setgid binaries. Fix requires image rebuild and validation; cannot be auto-fixed safely.
- Remediation overview: Rebuild the container image from a minimal base, remove unnecessary setuid/setgid helpers, and validate that administrative tooling and workflows still function. Deploy rebuilt image to the kata-targeted Deployment and verify functionality and network policies.

### Prioritized roadmap
- Manual image hardening [high]: Setuid/setgid binaries elevate risk inside the pod; remediation requires image changes and functional validation before rollout.
  Issues: SETID_BINARIES_PRESENT

### Item guidance
- SETID_BINARIES_PRESENT: Container image contains setuid/setgid binaries that can be abused for local privilege escalation inside the pod.
- Warning: Do not attempt in-place file removal on running pods—image rebuild is required.
- Warning: Removing setuid/setgid helpers may break administrative scripts; validate thoroughly.
- Warning: Services selecting this workload (target-kata) may be impacted by network policy default-deny.
