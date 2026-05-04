# Sandbox Audit Report

- Generated: 2026-05-04T18:53:07.436023+00:00
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
- Guided message: Rebuild the workload image removing unnecessary setuid/setgid binaries, test thoroughly in staging, then deploy the updated image.
- Executive summary: One medium-severity issue found: the container image contains setuid/setgid binaries which increase privilege risk. Remediation requires image rebuild and validation; not safe to auto-fix.
- Remediation overview: Rebuild the image on a minimal base and remove unnecessary setuid/setgid helpers. Validate admin tooling and functionality after changes. Do not modify running pods automatically.

### Prioritized roadmap
- Manual image hardening [high]: Setuid/setgid binaries in the image present a medium risk and require source/image changes and functional validation.
  Issues: SETID_BINARIES_PRESENT

### Item guidance
- SETID_BINARIES_PRESENT: Image contains setuid/setgid binaries that can be abused to escalate privileges inside the container or be leveraged in escapes.
- Warning: Automatic in-cluster fixes are unsafe for this issue.
- Warning: Removing setuid/setgid binaries can break admin tooling if not validated.
