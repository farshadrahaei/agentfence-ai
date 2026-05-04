# Sandbox Audit Report

- Generated: 2026-05-03T22:55:56.727842+00:00
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
- Guided message: No urgent security fixes found. Review connectivity and runtime assumptions and perform manual validation before changing the workload.
- Executive summary: No actionable security failures detected for the target-kata Deployment in namespace sandbox-kata. Existing network policies and runtime settings are noted; recommended actions are operational and design-oriented rather than urgent fixes.
- Remediation overview: No automatic fixes available. Review workload design, network policy interactions (services selecting this workload), and runtime expectations (kata runtime) before making changes. Any changes require manual validation in your environment.

### Prioritized roadmap
- Design and validation tasks [medium]: Findings require workload redesign, image or environment-specific validation rather than automated remediations.
  Issues: NO_ACTIONABLE_FAILURES
- Network policy and service alignment [low]: Services select this workload; default-deny policy may block expected traffic—verify intended connectivity.
  Issues: NO_ACTIONABLE_FAILURES
- Runtime and node selection review [low]: Workload uses kata-qemu runtime_class and node selector sandbox=kata — confirm compatibility and performance expectations.
  Issues: NO_ACTIONABLE_FAILURES

### Item guidance
- NO_ACTIONABLE_FAILURES: Scans found no mapped remediation rules. Fixes would need workload redesign, image updates, or environment-specific validation beyond safe automatic changes.
- Warning: Do not apply automated patches—fixes require manual redesign or validation.
- Warning: Services selecting this workload may be blocked by default-deny network policy if not accounted for.
