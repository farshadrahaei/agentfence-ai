# Sandbox Audit Report

- Generated: 2026-05-03T21:36:10.717021+00:00
- Namespace: sandbox-cua
- Workload: deployment/target-cua
- Risk score: 0 (low)

## Findings
- **NO_ACTIONABLE_FAILURES** [info] No failed checks were mapped to a built-in remediation rule

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
- Guided message: No automatic fixes available — review workload design, container images, and network policies, then apply and validate manual changes.
- Executive summary: No actionable security failures mapped to automated remediations for deployment target-cua in namespace sandbox-cua. Findings require manual design/image or environment-specific validation.
- Remediation overview: No automatic fixes available. Review workload design, container images, environment dependencies, and relevant network policies and services before making changes. Plan manual remediation and testing.

### Prioritized roadmap
- Manual review required [low]: No failed checks mapped to built-in remediations; changes require redesign, image updates, or environment-specific validation.
  Issues: NO_ACTIONABLE_FAILURES

### Item guidance
- NO_ACTIONABLE_FAILURES: Scanner found no failures that can be safely auto-fixed. Remediation requires workload redesign, image changes, or validation in your environment.
- Warning: Do not perform blind automated patches; redesign or image changes need testing.
- Warning: Default-deny network policy may block expected traffic to this workload.
