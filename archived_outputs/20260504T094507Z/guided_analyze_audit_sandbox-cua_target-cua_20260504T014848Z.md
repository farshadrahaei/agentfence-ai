# Sandbox Audit Report

- Generated: 2026-05-04T01:48:48.130400+00:00
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
- Guided message: No automatic fixes available. Manually review the workload and images, then re-run analysis after changes.
- Executive summary: Analysis found no actionable security failures mapped to built-in remediation rules for the workload target-cua in namespace sandbox-cua. Manual review is recommended for any design or environment-specific issues.
- Remediation overview: No automatic fixes applicable. The single remediation item indicates manual review only—changes would require workload redesign, image updates, or environment-specific validation.

### Prioritized roadmap
- Manual review required [low]: No auto-remediation rules matched; fixes involve design or image changes and have low blast radius.
  Issues: NO_ACTIONABLE_FAILURES

### Item guidance
- NO_ACTIONABLE_FAILURES: Scanner did not map any failed checks to safe built-in remediation rules. Remaining concerns (if any) need manual investigation of workload design, images, and environment dependencies.
- Warning: Default-deny network policy may block expected traffic to this workload.
- Warning: Remediation requires manual design or image changes; do not apply untested changes in production.
