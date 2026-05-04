# Sandbox Audit Report

- Generated: 2026-05-03T22:47:50.463879+00:00
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
- Guided message: No automated fixes recommended. If you plan changes, test them in staging and review workload design, images, and network policies before applying to production.
- Executive summary: Analysis found no actionable security failures for the selected Deployment (target-kata). Risk score is low and no remediations were auto-applied because fixes would require workload redesign or environment-specific validation.
- Remediation overview: No built-in remediation rules matched. Any changes would be manual, potentially involving image updates, workload redesign, or network policy adjustments. Proceed with caution and validate in a safe environment.

### Prioritized roadmap
- Informational — no immediate issues [low]: No failed checks mapped to automated remediations; only informational findings present.
  Issues: NO_ACTIONABLE_FAILURES

### Item guidance
- NO_ACTIONABLE_FAILURES: Scanner did not find failures that map to safe, automated remediation rules. Fixes would require manual changes such as redesigning the workload, updating container images, or validating environment-specific network policies.
- Warning: Services select this workload (target-kata); default-deny network policies may block expected traffic after changes.
- Warning: Remediations were not auto-applied because fixes require manual design and validation.
