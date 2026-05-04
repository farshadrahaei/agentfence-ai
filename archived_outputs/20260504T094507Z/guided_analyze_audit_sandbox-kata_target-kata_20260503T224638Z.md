# Sandbox Audit Report

- Generated: 2026-05-03T22:46:38.099288+00:00
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
- Guided message: No automated fixes available. Manually review workload design, node/runtime settings, and network policies before any changes.
- Executive summary: Scan found no actionable security failures for the selected Deployment (sandbox-kata/target-kata). Risk is low and no automatic remediations are available.
- Remediation overview: No built-in remediation rules apply. Any changes would require manual workload redesign, image updates, or environment-specific validation. Review dependencies and network policies before making changes.

### Prioritized roadmap
- Information — review only [low]: No failed checks mapped to remediation rules; verify design and dependencies (network policies, runtime_class, node selector) manually.
  Issues: NO_ACTIONABLE_FAILURES

### Item guidance
- NO_ACTIONABLE_FAILURES: Scanner did not map any failed checks to an automated remediation. The workload uses kata runtime, node selector, and several network policies that may require manual adjustments.
- Warning: Services select this workload; default-deny network policy may block expected traffic if adjusted.
- Warning: Runtime class kata-qemu and nodeSelector sandbox=kata imply environment-specific constraints.
