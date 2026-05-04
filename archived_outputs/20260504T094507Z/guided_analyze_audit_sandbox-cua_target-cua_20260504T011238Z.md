# Sandbox Audit Report

- Generated: 2026-05-04T01:12:38.405788+00:00
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
- Guided message: No auto-remediation available. Manually review findings and validate any design or image changes in a test environment before applying.
- Executive summary: Analysis found no actionable or auto-remediable security failures for deployment target-cua in namespace sandbox-cua. Manual review recommended for contextual findings.
- Remediation overview: All detected findings are informational and require manual review or workload redesign. No automatic fixes are safe to apply.

### Prioritized roadmap
- Informational findings (manual review) [low]: No built-in remediation rules matched; fixes require design, image, or environment changes and validation.
  Issues: NO_ACTIONABLE_FAILURES

### Item guidance
- NO_ACTIONABLE_FAILURES: No failed checks mapped to an automated remediation. Issues—if any—need contextual investigation and potential workload redesign or image updates.
- Warning: Services select this workload; default-deny network policy may block expected traffic.
- Warning: Automatic fixes were not applied to avoid unsafe changes to workload-scoped resources.
