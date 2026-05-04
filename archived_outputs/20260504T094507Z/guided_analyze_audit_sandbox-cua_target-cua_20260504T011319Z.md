# Sandbox Audit Report

- Generated: 2026-05-04T01:13:19.328008+00:00
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
- Guided message: No automatic fixes available. Manually review findings, validate network-policy/service interactions, and plan any redesigns in a test environment.
- Executive summary: Analysis found no actionable security failures mapped to automatic remediation. Review findings manually and consider workload-design or image changes if concerns remain.
- Remediation overview: All detected issues are informational and require manual review; no safe automated fixes available. Follow manual_recommendation and validate any redesigns in staging before production.

### Prioritized roadmap
- Manual review required [low]: No built-in remediation rules apply; fixes need workload redesign, image updates, or environment-specific validation.
  Issues: NO_ACTIONABLE_FAILURES

### Item guidance
- NO_ACTIONABLE_FAILURES: No failed checks mapped to an automatic remediation rule. The scan flagged informational items only.
- Warning: Default-deny network policy may block expected traffic to this workload.
- Warning: Remediation requires manual changes; avoid live production edits without testing.
