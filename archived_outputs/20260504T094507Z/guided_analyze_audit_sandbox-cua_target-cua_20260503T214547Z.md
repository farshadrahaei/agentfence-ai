# Sandbox Audit Report

- Generated: 2026-05-03T21:45:47.324371+00:00
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
- Guided message: No immediate fixes required; review workload design and dependencies (services, network policies) if you plan changes.
- Executive summary: No actionable security findings were identified for the deployment target-cua in namespace sandbox-cua. The scanner mapped no failed checks to built-in remediation rules; fixes would require workload redesign or environment-specific validation.
- Remediation overview: No automatic remediations are recommended. Any changes would be manual and potentially involve redesigning images, workload configuration, or validating environment dependencies like services and network policies.

### Prioritized roadmap
- Information — No actionable failures [low]: Scanner found no remediable security issues; remaining items require manual, context-specific redesign or validation.
  Issues: NO_ACTIONABLE_FAILURES

### Item guidance
- NO_ACTIONABLE_FAILURES: No failed checks mapped to a built-in remediation rule. Potential fixes need workload redesign, image changes, or environment-specific validation.
- Warning: Default-deny network policy may block expected traffic to this workload—validate service/network policy alignment.
- Warning: Remediation requires manual redesign or image changes; do not apply automated patches.
