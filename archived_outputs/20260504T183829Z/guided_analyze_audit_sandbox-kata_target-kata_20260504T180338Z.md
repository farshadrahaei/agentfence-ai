# Sandbox Audit Report

- Generated: 2026-05-04T18:03:38.302783+00:00
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
- Guided message: No auto-remediations available—please review findings and dependencies manually, test in staging, then apply controlled changes.
- Executive summary: Analysis found no actionable security failures mapped to built-in remediation rules for the target Deployment (target-kata in namespace sandbox-kata). Remaining findings require manual review or workload redesign.
- Remediation overview: No automatic fixes available. Manual review recommended: inspect design, images, and environment-specific dependencies (network policies, node selector, runtime class, volumes, and services) before implementing changes.

### Prioritized roadmap
- Manual review required [low]: No mapped remediation rules; fixes require workload redesign, image changes, or environment-specific validation.
  Issues: NO_ACTIONABLE_FAILURES

### Item guidance
- NO_ACTIONABLE_FAILURES: Scanner did not map any failed checks to safe automated remediations. Dependencies (services, network policies, runtime class, node selector, volumes) mean changes could break the workload or cluster behavior.
- Warning: Do not apply blind automated fixes; workload-scoped dependencies exist.
- Warning: Default-deny network policy may block expected traffic if altered incorrectly.
- Warning: Changes to node selector or runtime class can prevent scheduling.
