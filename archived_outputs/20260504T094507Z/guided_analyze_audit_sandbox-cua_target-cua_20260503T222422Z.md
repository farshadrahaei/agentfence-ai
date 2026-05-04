# Sandbox Audit Report

- Generated: 2026-05-03T22:24:22.407744+00:00
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
- Guided message: No automatic remediations available. Review the Deployment and dependent resources manually; apply workload redesign or image fixes where necessary and validate in staging.
- Executive summary: Analysis found no actionable security failures mapped to built-in remediation rules for the Deployment target-cua in namespace sandbox-cua. No automatic fixes are recommended; manual design or image changes may be required for any issues not captured here.
- Remediation overview: No remediation items applicable. The single informational item indicates no detected checks mapped to automatic remediation. Any required fixes will need manual work such as workload redesign, image updates, or environment-specific validation.

### Prioritized roadmap
- Informational — No auto-remediations [low]: No failed checks mapped to built-in remediation rules; changes would be workload-specific and require manual validation.
  Issues: NO_ACTIONABLE_FAILURES

### Item guidance
- NO_ACTIONABLE_FAILURES: Scanner did not map any failed checks to safe automated remediations for this workload. Fixes may involve architecture or image changes that cannot be applied automatically.
- Warning: Services select this workload (target-cua); default-deny network policy may block expected traffic.
- Warning: No automatic fixes were applied—manual validation required for any changes.
