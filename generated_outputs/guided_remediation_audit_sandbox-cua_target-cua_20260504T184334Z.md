# Sandbox Audit Report

- Generated: 2026-05-04T18:43:34.999413+00:00
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
- Guided message: Rebuild the target-cua image from a minimal base, remove unnecessary setuid/setgid binaries, run tests, then deploy updated image.
- Executive summary: One medium-security issue: image contains setuid/setgid binaries. This increases privilege escalation risk and requires image rebuilds to remediate.
- Remediation overview: Remove unnecessary setuid/setgid binaries from the container image by rebuilding from a minimal base and validating functionality. This is a manual change; do not attempt in-place pod edits.

### Prioritized roadmap
- Manual image hardening [high]: Requires image rebuild and validation; direct fix affects CI/image pipeline and runtime behavior.
  Issues: SETID_BINARIES_PRESENT

### Item guidance
- SETID_BINARIES_PRESENT: The image contains setuid/setgid helper binaries which can be abused for local privilege escalation inside the pod.
- Warning: Do not attempt to remove setuid/setgid files from running pods—changes will be lost on restart.
- Warning: Removing binaries may break expected admin workflows; validate in staging.
- Warning: Automatic in-cluster fixes are not safe for this issue.
