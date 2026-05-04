# Sandbox Audit Report

- Generated: 2026-05-04T01:41:51.300355+00:00
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
- Guided message: Rebuild the image to remove setuid/setgid binaries, validate functionality in staging, then update the Deployment image.
- Executive summary: One medium-severity issue: the workload image contains setuid/setgid binaries which increase risk if exploited. Fix requires image rebuild and validation; not safe to auto-remediate in-cluster.
- Remediation overview: Rebuild the container image from a minimal base, remove or replace unnecessary setuid/setgid binaries, and validate required admin tooling and runtime behavior before redeploying.

### Prioritized roadmap
- Image hardening (manual) [high]: Setuid/setgid binaries in the image present privilege-escalation risk and require image changes and validation; address first to reduce attack surface.
  Issues: SETID_BINARIES_PRESENT

### Item guidance
- SETID_BINARIES_PRESENT: The container image includes setuid/setgid binaries which can allow privilege escalation if exploited.
- Warning: Do not attempt in-cluster binary removal; changes must be done in the image build process.
- Warning: Removing setuid/setgid files may break expected admin tooling—test thoroughly.
