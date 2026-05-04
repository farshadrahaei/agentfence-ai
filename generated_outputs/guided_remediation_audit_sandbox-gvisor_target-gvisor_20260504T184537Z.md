# Sandbox Audit Report

- Generated: 2026-05-04T18:45:37.948242+00:00
- Namespace: sandbox-gvisor
- Workload: deployment/target-gvisor
- Risk score: 2 (low)

## Findings
- **SETID_BINARIES_PRESENT** [medium] Remove setuid/setgid binaries from the image

## Dependencies
- services: target-gvisor
- ingresses: none
- network_policies: allow-attacker-to-target, allow-dns-egress, allow-llm-gateway-egress, default-deny-all
- hpas: none
- pdbs: none
- configmaps: none
- secrets: none
- runtime_class: gvisor
- node_selector: {'sandbox': 'gvisor'}
- volumes: {"emptyDir": {}, "name": "workspace"}, {"emptyDir": {}, "name": "artifacts"}

## AI Advisor
- Guided message: Rebuild the target-gvisor image removing unnecessary setuid/setgid binaries, validate in staging (gvisor runtime), then roll out the new image.
- Executive summary: One medium-severity issue: image contains setuid/setgid binaries. Remediation requires image rebuild and validation; not safe to auto-fix.
- Remediation overview: Rebuild the container image from a minimal base, remove unnecessary setuid/setgid helpers, and validate workload functionality and admin tooling in a test environment before redeploying.

### Prioritized roadmap
- Image hardening (required) [high]: Setuid/setgid binaries increase privilege escalation risk; fix requires image rebuild and testing.
  Issues: SETID_BINARIES_PRESENT

### Item guidance
- SETID_BINARIES_PRESENT: Container image contains files with setuid/setgid bits enabling privilege elevation inside the container.
- Warning: Do not attempt in-cluster binary removal; changes must be made in the image build process.
- Warning: Removing setuid/setgid helpers may break administration scripts or tooling—test thoroughly.
