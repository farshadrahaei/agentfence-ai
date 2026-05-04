# Sandbox Audit Report

- Generated: 2026-05-03T22:20:19.877625+00:00
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
- Guided message: No auto-remediation available. Coordinate with app owners to review design, images, and network policies before making manual changes.
- Executive summary: Analysis found no actionable security failures mapped to automatic remediations for the target deployment (target-cua in sandbox-cua). No high/medium/low/critical issues detected.
- Remediation overview: No automatic fixes recommended. Remaining items require workload redesign, image changes, or environment-specific validation and should be handled manually by the application owners.

### Prioritized roadmap
- Informational — No actionable failures [low]: Findings are informational; fixes require manual intervention or redesign and cannot be safely auto-applied.
  Issues: NO_ACTIONABLE_FAILURES

### Item guidance
- NO_ACTIONABLE_FAILURES: Scanner did not map any failed checks to built-in remediation rules. Remaining concerns (if any) involve workload design, container images, or environment-specific behaviors.
- Warning: Default-deny network policy may block expected traffic to this workload; verify service selectors and policy rules.
- Warning: No automatic fixes applied — manual validation required for any design or image changes.
