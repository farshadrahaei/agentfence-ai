# Sandbox Audit Report

- Generated: 2026-05-03T22:55:14.617533+00:00
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
- Guided message: No urgent fixes detected. Review network policies and any planned design/image changes; proceed with manual testing before applying.
- Executive summary: No actionable security failures were identified for the target-kata Deployment. Risk band is low and no automatic remediations apply.
- Remediation overview: No built-in remediation rules mapped to findings. Any fixes would require workload redesign, image changes, or environment-specific validation and must be applied manually with testing.

### Prioritized roadmap
- Informational — review only [low]: Only informational findings present; no security issues requiring immediate action.
  Issues: NO_ACTIONABLE_FAILURES
- Network policy awareness [medium]: Services select this workload and default-deny network policy may affect traffic; validate intended connectivity.
  Issues: NO_ACTIONABLE_FAILURES

### Item guidance
- NO_ACTIONABLE_FAILURES: Scanner found no remediable security checks for this workload; remaining considerations require design or environment changes.
- Warning: No automated fixes available — manual changes may be required for design or image issues.
- Warning: Services select this workload; default-deny policies can block expected traffic.
