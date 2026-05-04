# Sandbox Audit Report

- Generated: 2026-05-03T22:45:35.338659+00:00
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
- Guided message: No automated remediations available. Manually review design, network policies, and service dependencies before making changes.
- Executive summary: Analysis found no actionable security failures mapped to built-in remediation rules for Deployment target-kata in namespace sandbox-kata. Risk band is low with zero probability and zero blast radius.
- Remediation overview: No automatic fixes recommended. Remaining items require manual review or workload redesign; verify network policies and service dependencies before making changes.

### Prioritized roadmap
- Informational — No actionable findings [low]: Scanner mapped no remediable failures; environment-specific or design changes needed for any improvements.
  Issues: NO_ACTIONABLE_FAILURES
- Network and service dependencies to review [medium]: Services select this workload and network policies (including default-deny) could block expected traffic; validate intent.
  Issues: NO_ACTIONABLE_FAILURES

### Item guidance
- NO_ACTIONABLE_FAILURES: No failed checks correspond to built-in remediation rules. Fixes would require redesign, image changes, or environment-specific validation.
- Warning: Do not apply broad network policy changes without testing — may break service traffic.
- Warning: Workload redesign or image changes require deployment validation to avoid downtime.
