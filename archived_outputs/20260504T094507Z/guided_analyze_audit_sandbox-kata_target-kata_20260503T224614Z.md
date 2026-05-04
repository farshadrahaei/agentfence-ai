# Sandbox Audit Report

- Generated: 2026-05-03T22:46:14.247270+00:00
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
- Guided message: No urgent remediations. Confirm design choices and validate network-policy connectivity for services using this Deployment.
- Executive summary: Analysis found no actionable security failures mapped to built-in remediations for the Deployment target-kata in namespace sandbox-kata. Risk is low and no automatic fixes are proposed.
- Remediation overview: No remediation rules apply. Remaining items require workload redesign, image changes, or environment-specific validation and must be handled manually if desired.

### Prioritized roadmap
- Informational findings [low]: Only informational item present; no security issues detected that map to automated fixes.
  Issues: NO_ACTIONABLE_FAILURES

### Item guidance
- NO_ACTIONABLE_FAILURES: Scanner did not map any failing checks to built-in remediation rules. Fixes would require design, image, or environment changes beyond safe automated patches.
- Warning: Services select this workload: target-kata — default-deny network policy may block expected traffic.
- Warning: No automated fixes available; manual changes may require testing and rollout planning.
