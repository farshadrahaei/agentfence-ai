# Sandbox Audit Report

- Generated: 2026-05-03T22:47:10.463855+00:00
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
- Guided message: No automatic fixes available. Review workload design, images, and environment constraints; test manual changes in staging before applying to production.
- Executive summary: Analysis of Deployment sandbox-kata/target-kata found no actionable security findings mapped to built-in remediation rules. No fixes were applied because identified items require workload redesign, image changes, or environment-specific validation.
- Remediation overview: No automatic remediations available. Any changes will be manual and may involve redesigning the workload, updating container images, or validating environment-specific network and runtime constraints (e.g., runtimeClass kata-qemu, nodeSelector sandbox=kata).

### Prioritized roadmap
- Informational - No actionable failures [low]: Scanner did not map any failed checks to safe automated remediations; changes require manual design or validation.
  Issues: NO_ACTIONABLE_FAILURES

### Item guidance
- NO_ACTIONABLE_FAILURES: No failed checks were mappable to a built-in remediation rule. Fixes would need workload redesign, image updates, or environment-specific checks.
- Warning: Services select this workload (target-kata); default-deny network policy may block expected traffic if modified.
- Warning: RuntimeClass kata-qemu and nodeSelector sandbox=kata imply environment-specific constraints—validate changes there.
