# Sandbox Audit Report

- Generated: 2026-05-04T18:07:48.569081+00:00
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
- Guided message: No automated fixes available — manually review the raw findings and assess whether workload or environment changes are needed.
- Executive summary: No actionable security failures were detected for the selected Deployment (target-kata). Findings require manual review; no automated remediations are recommended.
- Remediation overview: All detected issues are informational and flagged as non-actionable by automated rules. Address any design, image, or environment-specific concerns via manual changes to workload design, images, or dependent resources.

### Prioritized roadmap
- Manual review required [low]: No built-in remediation rule applies; fixes need workload redesign, image changes, or environment validation.
  Issues: NO_ACTIONABLE_FAILURES

### Item guidance
- NO_ACTIONABLE_FAILURES: Scanner found no failed checks that map to automated remediations. Remaining observations require human judgement and possibly architecture or image changes.
- Warning: Services selecting this workload (target-kata) may be affected if you change policies or selectors.
- Warning: Default-deny network policy may block expected traffic; verify network policy intent before changes.
