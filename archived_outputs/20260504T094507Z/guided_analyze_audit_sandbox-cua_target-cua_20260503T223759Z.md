# Sandbox Audit Report

- Generated: 2026-05-03T22:37:59.352240+00:00
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
- Guided message: No automatic fixes available. If you plan changes, design and validate them manually and re-run the analyzer.
- Executive summary: Analysis found no actionable security failures mapped to built-in remediation rules for the Deployment target-cua in namespace sandbox-cua. Risk is low; no automatic fixes recommended.
- Remediation overview: No remediation items applicable. The single informational finding indicates fixes would require workload redesign, image updates, or environment-specific validation and cannot be safely auto-applied.

### Prioritized roadmap
- Informational—no automatic remediations [low]: No failed checks map to built-in remediation rules; changes would need manual design and validation.
  Issues: NO_ACTIONABLE_FAILURES

### Item guidance
- NO_ACTIONABLE_FAILURES: No detected failures that match automated remediation rules. Addressing potential improvements requires manual workload redesign, image changes, or environment-specific validation.
- Warning: Default-deny network policy may block expected traffic to services selecting this workload.
- Warning: No auto-remediation—manual changes could impact availability if not validated.
