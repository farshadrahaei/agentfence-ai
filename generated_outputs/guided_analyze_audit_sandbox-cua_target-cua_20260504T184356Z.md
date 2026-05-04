# Sandbox Audit Report

- Generated: 2026-05-04T18:43:56.577521+00:00
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
- Guided message: Rebuild and replace the image without setuid/setgid helpers; test thoroughly before redeploying.
- Executive summary: One medium-severity finding: setuid/setgid binaries present in the container image for Deployment target-cua. Fix requires image rebuild and validation; not safe to auto-fix in-cluster.
- Remediation overview: Rebuild the container image from a minimal base, remove unnecessary setuid/setgid helpers, and re-deploy after testing. Validate any administrative tooling that relied on those binaries.

### Prioritized roadmap
- Image hardening (manual) [high]: Setuid/setgid binaries increase privilege risk and require image rebuilds and functional validation; address before wider deployment.
  Issues: SETID_BINARIES_PRESENT

### Item guidance
- SETID_BINARIES_PRESENT: The container image contains setuid/setgid binaries which can be abused to escalate privileges inside the pod.
- Warning: Do not attempt in-cluster removal of binaries — changes require image rebuild.
- Warning: Removing binaries may break admin tooling; validate functionality after change.
