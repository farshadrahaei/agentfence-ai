# Sandbox Audit Report

- Generated: 2026-05-04T01:18:51.779169+00:00
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
- Guided message: Rebuild the target-cua image to remove setuid/setgid binaries, test in staging, then deploy the patched image.
- Executive summary: One medium-severity finding: setuid/setgid binaries are present in the workload image, increasing privilege escalation risk. Remediation requires image rebuild and validation; not safe to auto-fix in-cluster.
- Remediation overview: Remove unnecessary setuid/setgid binaries by rebuilding the container image from a minimal base, auditing required admin tooling, and validating functionality in a test environment before deployment.

### Prioritized roadmap
- Image hardening (manual) [high]: Setuid/setgid binaries elevate risk inside the pod; addressing them reduces privilege escalation potential and requires image changes and validation.
  Issues: SETID_BINARIES_PRESENT

### Item guidance
- SETID_BINARIES_PRESENT: The container image contains setuid/setgid binaries which can be abused for privilege escalation if an attacker gains code execution inside the pod.
- Warning: Do not attempt in-cluster binary removal; rebuild the image instead.
- Warning: Removing setuid/setgid helpers may break admin workflows—validate thoroughly.
- Warning: Default-deny network policy may block service traffic when testing; account for it.
