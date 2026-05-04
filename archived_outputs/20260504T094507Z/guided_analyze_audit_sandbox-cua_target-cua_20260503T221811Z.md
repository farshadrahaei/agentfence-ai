# Sandbox Audit Report

- Generated: 2026-05-03T22:18:11.129444+00:00
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
- Guided message: No automatic fixes available. Manually review workload design, container images, and network policy interactions before making changes.
- Executive summary: Analysis of Deployment target-cua in namespace sandbox-cua found no actionable security findings mapped to built-in remediation rules. No automatic fixes recommended; remediation requires workload redesign, image changes, or environment-specific validation.
- Remediation overview: All checks returned informational results. The single remediation item indicates no mapped automated fixes. Review workload design, image hardening, and network policy interactions (services select this workload; default-deny may block traffic) before applying changes.

### Prioritized roadmap
- Informational — Review Required [low]: No security failures detected that can be safely auto-fixed. Manual review recommended for design or image-level improvements and network policy compatibility.
  Issues: NO_ACTIONABLE_FAILURES

### Item guidance
- NO_ACTIONABLE_FAILURES: No checks produced failures that match built-in remediation rules. Fixes would require workload redesign, image modifications, or environment-specific validation beyond safe automated changes.
- Warning: Do not apply blind automated patches; fixes require context and validation.
- Warning: Modifying workload selectors or network policies may disrupt service traffic.
