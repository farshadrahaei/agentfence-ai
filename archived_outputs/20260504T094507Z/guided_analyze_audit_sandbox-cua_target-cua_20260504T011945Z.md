# Sandbox Audit Report

- Generated: 2026-05-04T01:19:45.628538+00:00
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
- Guided message: Plan an image rebuild: identify and remove unnecessary setuid/setgid binaries, validate in staging, then deploy the updated image to sandbox-cua.
- Executive summary: One medium-severity finding: setuid/setgid binaries are present in the workload image (target-cua). This increases privilege-elevation risk and requires image rebuild to remediate safely.
- Remediation overview: Do not auto-patch. Rebuild the container image from a minimal base, remove unnecessary setuid/setgid helpers, validate admin tooling and functionality, then redeploy the updated image.

### Prioritized roadmap
- Image hardening (highest priority) [high]: Setuid/setgid binaries allow local privilege escalation; fixing reduces attack surface and blast radius (affects single deployment).
  Issues: SETID_BINARIES_PRESENT

### Item guidance
- SETID_BINARIES_PRESENT: The container image contains setuid/setgid binaries that can be abused for privilege escalation inside the pod.
- Warning: Automatic in-cluster fixes are unsafe for this issue; do not attempt binary removal on running pods.
- Warning: Removing utilities may disrupt admin or operational scripts — validate thoroughly.
