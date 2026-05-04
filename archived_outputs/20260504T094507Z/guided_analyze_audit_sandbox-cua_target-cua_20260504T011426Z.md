# Sandbox Audit Report

- Generated: 2026-05-04T01:14:26.679751+00:00
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
- Guided message: No automatic fixes available. Manually review the findings, assess workload design and dependent resources, and test changes in a safe environment.
- Executive summary: Analysis found no actionable security failures mapped to automated remediations. The report recommends manual review of findings and consideration of workload design and dependent resources (services, network policies) before any changes.
- Remediation overview: No auto-applicable fixes. Issues require manual review or workload redesign; follow provided manual recommendation and validate in environment-specific context.

### Prioritized roadmap
- Manual review required [low]: No built-in remediation rule applies; changes may affect dependent resources and need human validation.
  Issues: NO_ACTIONABLE_FAILURES

### Item guidance
- NO_ACTIONABLE_FAILURES: No failed checks were matched to an automated remediation; resolving would require redesign, image changes, or environment-specific validation.
- Warning: Do not apply blind automated patches; workload redesign or image changes may be required.
- Warning: Default-deny network policy may block expected traffic if workload networking is changed.
