# Sandbox Audit Report

- Generated: 2026-05-04T01:48:50.924709+00:00
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
- Guided message: No automatic fixes available. Manually review the raw findings and validate any design or image changes in staging before applying to sandbox-cua.
- Executive summary: Analysis found no actionable security failures mapped to automated remediation rules. The scan identified informational findings only; manual review is recommended for design or image-level issues.
- Remediation overview: No automatic fixes available. Follow the single manual remediation item: review raw findings and assess workload design, images, and environment-specific constraints before making changes.

### Prioritized roadmap
- Manual review required [low]: No actionable automated remediations; changes require manual design or image updates and validation.
  Issues: NO_ACTIONABLE_FAILURES

### Item guidance
- NO_ACTIONABLE_FAILURES: Scanner found no checks that map to built-in remediation rules. Remaining concerns (if any) need manual investigation of images, workload design, and environment interactions.
- Warning: Default-deny network policy may block expected traffic; verify service selectors and policies before changing network rules.
- Warning: Manual changes (images, workload design, network policies) can affect availability—test in staging.
