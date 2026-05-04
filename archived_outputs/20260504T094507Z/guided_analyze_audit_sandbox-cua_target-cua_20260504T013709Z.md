# Sandbox Audit Report

- Generated: 2026-05-04T01:37:09.447576+00:00
- Namespace: sandbox-cua
- Workload: deployment/target-cua
- Risk score: 2 (low)

## Findings
- **SETID_BINARIES_PRESENT** [medium] Remove setuid/setgid binaries from the image

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
- Guided message: Plan an image rebuild: remove setuid/setgid helpers, test in staging, then redeploy the updated image.
- Executive summary: One medium-severity issue: setuid/setgid binaries are present in the workload image. Fix requires rebuilding the image and validating tooling; not safe to auto-apply.
- Remediation overview: Rebuild the container image from a minimal base and remove any unnecessary setuid/setgid helper binaries. Validate admin workflows that depended on those binaries and redeploy the updated image.

### Prioritized roadmap
- Image hardening (highest priority) [high]: Setuid/setgid binaries increase privilege escalation risk inside the container; remediation reduces attack surface.
  Issues: SETID_BINARIES_PRESENT

### Item guidance
- SETID_BINARIES_PRESENT: The container image contains setuid/setgid binaries which can be abused for privilege escalation if an attacker gains code execution in the pod.
- Warning: Do not attempt in-cluster binary removal—changes must be made in the image build process.
- Warning: Removing these binaries may break expected admin tooling; validate before production rollout.
