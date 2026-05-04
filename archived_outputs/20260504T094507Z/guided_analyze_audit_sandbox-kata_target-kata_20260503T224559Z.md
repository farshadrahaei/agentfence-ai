# Sandbox Audit Report

- Generated: 2026-05-03T22:45:59.403966+00:00
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
- Guided message: No automatic remediations available. If you plan changes, perform manual design and staged validation, paying attention to networking and runtime_class.
- Executive summary: Scan found no actionable security failures for workload target-kata in namespace sandbox-kata. Risk score is low and all checks mapped to remediation rules returned informational results only.
- Remediation overview: No automated fixes recommended. If changes are desired, they require manual design, image updates, or environment-specific validation. Review network policy and workload design dependencies before modifying.

### Prioritized roadmap
- Informational findings [low]: Only informational checks were returned; no high/medium/critical issues to remediate automatically.
  Issues: NO_ACTIONABLE_FAILURES

### Item guidance
- NO_ACTIONABLE_FAILURES: No failed checks mapped to built-in remediation rules. Fixes would require workload redesign, image changes, or environment-specific validation.
- Warning: Services select this workload (target-kata); altering labels or selectors may disrupt traffic.
- Warning: default-deny network policy may block expected egress/ingress after changes.
- Warning: Runtime class kata-qemu and node selector sandbox=kata constrain scheduling; test compatibility before changes.
