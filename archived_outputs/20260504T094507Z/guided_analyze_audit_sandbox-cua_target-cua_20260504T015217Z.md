# Sandbox Audit Report

- Generated: 2026-05-04T01:52:17.427777+00:00
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
- Guided message: Plan an image rebuild to remove setuid/setgid binaries, test thoroughly in staging, then roll out the updated image.
- Executive summary: One medium-severity issue: setuid/setgid binaries are present in the workload image, increasing privilege escalation risk. Fix requires image rebuild and validation; not auto-applicable.
- Remediation overview: Rebuild the container image from a minimal base, remove unnecessary setuid/setgid helpers, and validate functionality of admin tooling. Deploy rebuilt image after testing in a staging environment.

### Prioritized roadmap
- Manual image hardening [P1]: Setuid/setgid binaries enable privilege escalation and require image rebuild and functional testing; address first to reduce attack surface.
  Issues: SETID_BINARIES_PRESENT

### Item guidance
- SETID_BINARIES_PRESENT: Image contains setuid/setgid binaries that can be abused to escalate privileges inside the container.
- Warning: Do not attempt in-cluster binary removal; changes must be made in the image build process.
- Warning: Removing setuid/setgid helpers can break admin tooling—validate workflows before production rollout.
