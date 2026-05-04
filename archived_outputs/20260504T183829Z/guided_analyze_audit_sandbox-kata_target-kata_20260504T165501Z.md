# Sandbox Audit Report

- Generated: 2026-05-04T16:55:01.324191+00:00
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
- Guided message: No auto-fixes available. Manually review findings, validate network policies and workload design, and test changes in staging before applying to production.
- Executive summary: No actionable security failures were detected for deployment target-kata in namespace sandbox-kata. Findings require manual review rather than automated fixes.
- Remediation overview: No automatic remediations available. Review the raw findings and evaluate design, images, and environment-specific validations before applying manual changes. Consider network policy interactions and workload dependencies.

### Prioritized roadmap
- Manual review required [low]: No mapped remediation rules; fixes require redesign, image changes, or environment validation.
  Issues: NO_ACTIONABLE_FAILURES
- Network policy awareness [medium]: Services select this workload and default-deny policy may block expected traffic; confirm policy intent.
  Issues: NO_ACTIONABLE_FAILURES

### Item guidance
- NO_ACTIONABLE_FAILURES: No failed checks mapped to built-in remediation. Issues (if any) need contextual/manual remediation such as changing images, code, or workload design.
- Warning: Do not apply cluster-wide changes without testing — redesigns may cause downtime.
- Warning: Default-deny network policy may block legitimate traffic if not adjusted.
