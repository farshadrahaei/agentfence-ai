# Sandbox Audit Report

- Generated: 2026-05-03T21:27:09.231042+00:00
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
- Guided message: No automatic fixes available—review workload design and network policy interactions, then plan manual remediation and testing.
- Executive summary: Analysis of Deployment sandbox-cua/target-cua found no actionable security failures mapped to built-in remediation rules. Risk band: low. Some network policies exist; services select this workload which may interact with default-deny rules.
- Remediation overview: No automatic fixes available. Remaining items require manual review or workload redesign. Validate service-network policy interactions and any environment-specific needs before making changes.

### Prioritized roadmap
- Informational: no mapped failures [low]: Scanner did not identify remediation rules that can be safely auto-applied; manual assessment may still be useful.
  Issues: NO_ACTIONABLE_FAILURES
- Networking compatibility check [medium]: Services select this workload; default-deny network policy may block expected traffic—validate connectivity.

### Item guidance
- NO_ACTIONABLE_FAILURES: No failed checks were mapped to an automated remediation. Fixes require workload redesign, image changes, or environment-specific validation.
- Warning: Do not auto-patch the pod in isolation; dependencies may be affected.
- Warning: Default-deny network policy may prevent expected service traffic.
