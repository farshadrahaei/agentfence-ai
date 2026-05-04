# Sandbox Audit Report

- Generated: 2026-05-03T22:28:59.322303+00:00
- Namespace: sandbox-cua
- Workload: deployment/target-cua
- Risk score: 0 (low)

## Findings
- **NO_ACTIONABLE_FAILURES** [info] No failed checks were mapped to a built-in remediation rule

## Dependencies
- services: target-cua
- ingresses: none
- network_policies: allow-attacker-to-target, allow-dns-egress, allow-llm-gateway-egress, default-deny-all
- hpas: none
- pdbs: none
- configmaps: none
- secrets: none
- runtime_class: None
- node_selector: {'sandbox': 'cua'}
- volumes: {"emptyDir": {}, "name": "workspace"}, {"emptyDir": {}, "name": "artifacts"}

## AI Advisor
- Guided message: No automatic fixes available. If you plan changes, perform them in a test namespace, validate service and network-policy behavior, and roll out gradually.
- Executive summary: No actionable security failures were identified for the deployment target-cua. Scanning mapped no built-in remediation rules; fixes require design or image changes and environment validation.
- Remediation overview: No automatic remediations available. Any changes will be manual and may involve workload redesign, container image updates, or environment-specific testing. Review network policies and service dependencies before modifying the workload.

### Prioritized roadmap
- Informational — no fixes [low]: Scanner found no matching remediation rules; remaining items require manual design or image-level changes.
  Issues: NO_ACTIONABLE_FAILURES

### Item guidance
- NO_ACTIONABLE_FAILURES: No failed checks mapped to built-in remediation rules. Addressing potential concerns requires workload redesign, image modifications, or environment-specific validation beyond safe automatic changes.
- Warning: Services select this workload; default-deny network policy may block expected traffic after changes.
- Warning: Remediations require workload or image changes—do not modify in production without testing.
