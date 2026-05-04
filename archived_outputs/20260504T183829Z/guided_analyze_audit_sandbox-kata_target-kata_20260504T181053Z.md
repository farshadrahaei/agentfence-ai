# Sandbox Audit Report

- Generated: 2026-05-04T18:10:53.893065+00:00
- Namespace: sandbox-kata
- Workload: deployment/target-kata
- Risk score: 0 (low)

## Findings
- **NO_ACTIONABLE_FAILURES** [info] No failed checks were mapped to a built-in remediation rule

## Dependencies
- services: target-kata
- ingresses: none
- network_policies: allow-attacker-to-target, allow-dns-egress, allow-llm-gateway-egress, default-deny-all
- hpas: none
- pdbs: none
- configmaps: none
- secrets: none
- runtime_class: kata-qemu
- node_selector: {'sandbox': 'kata'}
- volumes: {"emptyDir": {}, "name": "workspace"}, {"emptyDir": {}, "name": "artifacts"}

## AI Advisor
- Guided message: Review the raw findings and plan manual remediation steps; validate changes in a safe test environment before applying to production.
- Executive summary: Analysis found no actionable security failures mapped to automated remediations for the target deployment (target-kata in namespace sandbox-kata). Remaining items require manual review or workload redesign.
- Remediation overview: No automatic fixes available. One info-level finding advises manual review of raw findings and dependency-aware changes. Follow manual recommendations before altering workload or network policy.

### Prioritized roadmap
- Manual review required [low]: No security failures mapped to built-in remediation; changes may impact dependent resources and require environment-specific validation.
  Issues: NO_ACTIONABLE_FAILURES

### Item guidance
- NO_ACTIONABLE_FAILURES: Scanner did not map any failed checks to automated remediations. The deployment or its environment may need redesign, image changes, or manual validation.
- Warning: Services select this workload (target-kata); modifications may disrupt traffic.
- Warning: Default-deny network policy may block expected communication after changes.
- Warning: Remediations require workload redesign or image changes and cannot be auto-applied.
