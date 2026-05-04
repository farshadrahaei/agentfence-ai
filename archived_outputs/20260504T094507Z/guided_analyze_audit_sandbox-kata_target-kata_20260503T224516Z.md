# Sandbox Audit Report

- Generated: 2026-05-03T22:45:16.009134+00:00
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
- Guided message: No automatic fixes available. Manually review architecture and dependent resources before making changes.
- Executive summary: No actionable security issues were detected for the target-kata Deployment in sandbox-kata. Findings indicate informational status only; no automatic remediations apply.
- Remediation overview: No built-in remediation rules apply. Remaining recommendations are manual and may require workload redesign, image updates, or environment-specific validation before changes are made.

### Prioritized roadmap
- Informational — Review only [low]: No failed checks mapped to remediation rules; verify design and dependencies manually.
  Issues: NO_ACTIONABLE_FAILURES

### Item guidance
- NO_ACTIONABLE_FAILURES: Scanner found no fixable security failures. Some concerns (network policy selection, runtime class, node selector) are noted as dependencies but are informational.
- Warning: Default-deny network policy may block service traffic — confirm services select this workload.
- Warning: Runtime class kata-qemu and node selector sandbox=kata are environment-specific; validate compatibility when changing images or configs.
