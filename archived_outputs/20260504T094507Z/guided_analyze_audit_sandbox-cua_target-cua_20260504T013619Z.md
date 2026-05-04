# Sandbox Audit Report

- Generated: 2026-05-04T01:36:19.662547+00:00
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
- Guided message: Plan an image rebuild: remove unnecessary setuid/setgid helpers, run validation in staging, then roll out the updated Deployment.
- Executive summary: One medium-risk issue: setuid/setgid binaries present in the workload image (target-cua). This increases privilege escalation risk and requires an image rebuild to remediate safely.
- Remediation overview: Do not modify running pods automatically. Rebuild the container image using a minimal base, remove unnecessary setuid/setgid helpers, and validate admin tooling and functionality before redeploying.

### Prioritized roadmap
- Image hardening (highest impact) [high]: Removing setuid/setgid binaries reduces privilege escalation risk but requires image rebuild and functional validation.
  Issues: SETID_BINARIES_PRESENT

### Item guidance
- SETID_BINARIES_PRESENT: The container image contains setuid/setgid binaries which can be abused for privilege escalation inside the pod.
- Warning: Automatic in-cluster patching is not recommended; changes require image rebuild and testing.
- Warning: Removing setuid/setgid binaries may break expected admin tooling or scripts.
