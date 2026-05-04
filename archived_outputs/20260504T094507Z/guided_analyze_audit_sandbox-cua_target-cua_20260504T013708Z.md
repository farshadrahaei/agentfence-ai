# Sandbox Audit Report

- Generated: 2026-05-04T01:37:08.180203+00:00
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
- Guided message: Rebuild the target-cua image to remove setuid/setgid binaries, test in staging, then roll out the updated image to sandbox-cua.
- Executive summary: One medium-severity finding: setuid/setgid binaries are present in the target image (target-cua). This increases privilege escalation risk and requires image rebuild to remediate.
- Remediation overview: Do not auto-patch. Rebuild the container image from a minimal base, remove or replace unneeded setuid/setgid helpers, and validate any administrative workflows that relied on them. Deploy the rebuilt image after testing in a staging environment.

### Prioritized roadmap
- Image hardening (highest) [high]: Setuid/setgid binaries in the image enable local privilege escalation; remediation requires image changes and validation.
  Issues: SETID_BINARIES_PRESENT

### Item guidance
- SETID_BINARIES_PRESENT: The container image contains setuid/setgid binaries which can allow privilege escalation if an attacker gains code execution in the container.
- Warning: Do not attempt in-cluster binary removal — changes must be made in the image build.
- Warning: Removing setuid/setgid helpers may break expected admin workflows; validate before production rollout.
