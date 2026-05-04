# Sandbox Audit Report

- Generated: 2026-05-03T21:30:36.973751+00:00
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
- Guided message: No automatic fixes available. Manually review workload design, images, and cluster network policies (default-deny may affect service traffic).
- Executive summary: Analysis found no actionable security failures mapped to built-in remediation rules for deployment target-cua in namespace sandbox-cua. No automatic fixes are recommended; changes would require workload redesign, image updates, or environment-specific validation.
- Remediation overview: No auto-applicable remediation items. Manual review only: consider workload design, image hardening, and validating network policy/service interactions (default-deny may block service traffic).

### Prioritized roadmap
- Informational — review and validate [low]: No detected security failures require immediate remediation, but design and environment assumptions should be validated manually.
  Issues: NO_ACTIONABLE_FAILURES

### Item guidance
- NO_ACTIONABLE_FAILURES: Scanner did not map any failed checks to safe built-in remediation rules. Fixes would need code/image changes, workload redesign, or environment-specific validation.
- Warning: Default-deny network policy may block expected service traffic to this workload.
- Warning: No automatic remediation performed; manual validation required before making changes.
