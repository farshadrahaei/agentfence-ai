# Sandbox Audit Report

- Generated: 2026-05-04T01:38:30.430954+00:00
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
- Guided message: Rebuild the workload image to remove setuid/setgid binaries, validate functionality, then roll out the new image via your pipeline.
- Executive summary: One medium-risk finding: setuid/setgid binaries are present in the workload image (target-cua). Fix requires an image rebuild and validation; not safe to auto-remediate in-cluster.
- Remediation overview: Rebuild the container image from a minimal base and remove unnecessary setuid/setgid helpers. Validate functionality of any admin tooling that relied on those binaries before redeploying. Apply updated image via normal CI/CD pipeline.

### Prioritized roadmap
- Image hardening (required) [high]: Presence of setuid/setgid binaries increases risk; mitigation requires image rebuild and testing, so address first.
  Issues: SETID_BINARIES_PRESENT

### Item guidance
- SETID_BINARIES_PRESENT: Image contains setuid/setgid helper binaries that can be abused for privilege escalation inside the container.
- Warning: Do not attempt automated in-cluster removal of binaries—this may break the workload.
- Warning: Removing setuid/setgid helpers can disrupt admin tools; validate thoroughly in staging first.
