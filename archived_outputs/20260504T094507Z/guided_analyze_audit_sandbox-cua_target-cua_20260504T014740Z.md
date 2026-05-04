# Sandbox Audit Report

- Generated: 2026-05-04T01:47:40.938905+00:00
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
- Guided message: No automatic fixes available—please manually review the findings, dependency graph, and workload design before making changes.
- Executive summary: Analysis found no actionable security failures mapped to automatic remediation rules. Remaining items require manual review or workload redesign.
- Remediation overview: No auto-applicable fixes. One informational item advises manual review of raw findings and consideration of workload/image/environment changes before implementing fixes.

### Prioritized roadmap
- Manual review required [low]: Findings are informational and need human assessment; fixes involve design or image changes.
  Issues: NO_ACTIONABLE_FAILURES

### Item guidance
- NO_ACTIONABLE_FAILURES: No specific failed checks map to built-in remediation; resolving would require redesign, image updates, or environment-specific validation.
- Warning: Do not apply blind automated changes; fixes may require image or design updates.
- Warning: Default-deny network policy may block expected traffic—verify service connectivity if you change policies.
