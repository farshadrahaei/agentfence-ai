# Sandbox Audit Report

- Generated: 2026-05-04T17:45:06.315188+00:00
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
- Guided message: No auto-fixes available. Manually review the findings and dependency graph; plan redesign or image/environment changes and validate in staging before applying to sandbox-kata/target-kata.
- Executive summary: Analysis found no actionable security failures that map to built-in remediation rules. Remaining items require manual review or workload redesign.
- Remediation overview: No automatic fixes recommended. A single informational finding advises manual review of raw findings and consideration of workload-specific redesign, image updates, or environment validation before changes.

### Prioritized roadmap
- Manual review required [low]: No auto-applicable remediations; fixes need human-driven design, image, or environment changes.
  Issues: NO_ACTIONABLE_FAILURES

### Item guidance
- NO_ACTIONABLE_FAILURES: No failed checks matched a built-in remediation rule. The report requires manual interpretation and potential redesign or image/environment changes.
- Warning: Services select this workload (target-kata); default-deny network policy may block expected traffic if network rules change.
- Warning: No automatic remediation applied—manual changes may impact dependent services.
