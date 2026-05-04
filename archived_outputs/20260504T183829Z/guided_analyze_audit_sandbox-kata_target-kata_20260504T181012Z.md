# Sandbox Audit Report

- Generated: 2026-05-04T18:10:12.228600+00:00
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
- Guided message: No automated fixes available. Manually review scan output and plan any redesigns or image changes in a test environment before applying to production.
- Executive summary: No actionable security failures were found for the selected Deployment (target-kata). The scanner mapped no checks to built-in remediation rules; remaining items require manual review or design changes.
- Remediation overview: There are no automated fixes. A single informational item advises manual review of findings and consideration of workload redesign, image changes, or environment-specific validations before applying changes.

### Prioritized roadmap
- Manual review required [low]: No failed checks map to automated remediations; any fixes require manual assessment and potential workload or image changes.
  Issues: NO_ACTIONABLE_FAILURES

### Item guidance
- NO_ACTIONABLE_FAILURES: Scanner found no failures that match built-in remediation rules. Remaining concerns (if any) need manual investigation, redesign, or image/environment updates.
- Warning: Services select this workload (target-kata); default-deny policies may block expected traffic.
- Warning: Remediation requires manual changes—avoid making ad hoc edits in production without testing.
