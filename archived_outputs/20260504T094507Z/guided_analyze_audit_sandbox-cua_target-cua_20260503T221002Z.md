# Sandbox Audit Report

- Generated: 2026-05-03T22:10:02.134829+00:00
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
- Guided message: No automatic remediations available. Review workload design, images, and network policies; validate changes in staging before applying to sandbox-cua.
- Executive summary: Analysis found no actionable security failures mapped to built-in remediation rules for deployment target-cua in namespace sandbox-cua. No automatic fixes applied; some fixes would require redesign or environment-specific validation.
- Remediation overview: No auto-applicable remediations. Remaining items require manual design changes (e.g., image updates, workload redesign) or validation against service dependencies and network policies before any change.

### Prioritized roadmap
- Informational — No actionable findings [low]: Scanner did not map any failed checks to built-in remediation rules; risk score is low.
  Issues: NO_ACTIONABLE_FAILURES

### Item guidance
- NO_ACTIONABLE_FAILURES: No failed checks matched automatic remediation rules. Potential fixes require workload redesign, image changes, or environment-specific validation.
- Warning: Services select this workload (target-cua); default-deny network policy may block expected traffic after changes.
- Warning: Remediations would require manual redesign or image updates—do not modify in production without testing.
