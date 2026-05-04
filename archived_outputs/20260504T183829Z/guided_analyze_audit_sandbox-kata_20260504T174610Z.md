# Sandbox Audit Report

- Generated: 2026-05-04T17:46:10.843896+00:00
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
- Guided message: There are no auto-fixable issues. Manually review the scan output and dependency graph before planning changes; validate in staging.
- Executive summary: Analysis found no actionable failures mapped to built-in remediation rules. Low risk score and no detected security issues. Manual review advised for context-specific concerns.
- Remediation overview: No automatic fixes applied. One informational remediation item requires manual review of raw findings and potential workload redesign or image/environment changes before any changes.

### Prioritized roadmap
- Manual review required [low]: No auto-applicable fixes; findings require manual interpretation and potential redesign.
  Issues: NO_ACTIONABLE_FAILURES
- Network and selector dependencies [medium]: Workload uses nodeSelector kata, runtimeClass kata-qemu, and network policies including default-deny; changes could impact connectivity.
  Issues: NO_ACTIONABLE_FAILURES

### Item guidance
- NO_ACTIONABLE_FAILURES: No failed checks matched automated remediation rules. The finding is informational and may require workload redesign, image updates, or environment-specific validation.
- Warning: Do not modify runtimeClass/nodeSelector or network policies in production without testing.
- Warning: Services select this workload; default-deny network policy may block expected traffic if altered.
