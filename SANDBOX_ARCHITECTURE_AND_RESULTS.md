# Sandbox Architecture And Results

This document explains the Kubernetes sandbox architectures used for `CUA`, `gVisor`, and `Kata`, and how `AgentFence AI` produces the result artifacts stored in [generated_outputs/](generated_outputs/).

## Purpose

`AgentFence AI` evaluates and hardens sandboxed agentic AI workloads that run in Kubernetes. The current evaluation uses three sandbox tracks:

- `sandbox-cua` / `sandbox-cua-fresh`
- `sandbox-gvisor` / `sandbox-gvisor-fresh`
- `sandbox-kata` / `sandbox-kata-fresh`

Each sandbox represents a different runtime or isolation profile, but the analysis workflow is intentionally consistent:

1. discover the target workload
2. analyze workload and sandbox posture
3. score security findings using disjoint TBE/ELE scoring
4. create a rollback checkpoint before mutation
5. remediate supported issues
6. revalidate the workload after remediation
7. preserve fixed findings and manual recommendations in generated reports

## Shared Kubernetes Model

All three sandboxes follow the same broad model:

- one namespace per sandbox track
- one target workload deployment
- one adjacent measurement/attacker workload used for controlled probing
- supporting service and network policy resources
- egress path to the LLM gateway where the workload requires it

The app excludes attacker resources from primary target selection and focuses remediation on the selected target workload.

## Sandbox-Specific Notes

### CUA

`CUA` is the compatibility-sensitive baseline track. It can represent an interactive or multi-container agentic workload that may need writable workspace volumes and service exposure. It is useful for showing where automatic hardening must be careful: some controls can be applied and verified, while others remain manual because forcing them could break the workload.

### gVisor

`gVisor` uses a sandboxed runtime class intended to reduce kernel attack surface. It demonstrates that runtime isolation can reduce some host-adjacent risk while Kubernetes workload controls such as seccomp, capabilities, service-account exposure, and no-new-privileges still matter.

### Kata

`Kata` uses VM-like container isolation through a dedicated runtime class. It provides a stronger runtime boundary than a standard OCI runtime, but workload configuration, runtime settings, image behavior, and side-channel surfaces still affect the final risk profile.

## How AgentFence AI Produces Results

The result files in `generated_outputs/` are created by the live workflow used in both `default` mode and `ai` mode.

At a high level, the app does the following:

1. identify the cluster, namespace, target pod, and workload context
2. collect remote, Kubernetes, and in-workload evidence
3. run the unified probe catalog
4. mark reachable service exposure as review-only communication evidence
5. compute raw, TBE, ELE, and headline scores
6. generate remediation items for all probes
7. create a rollback checkpoint before mutation
8. apply guarded auto-fixes and gated node/runtime hardening only when applicable
9. revalidate workload health and rerun probes
10. write JSON, Markdown, evaluation-factor, and rollback metadata artifacts

## Current Artifact Types

Current artifact names use the `agentfence_*` prefix. Older `guided_*` artifacts in this repository are legacy examples from earlier application versions.

### Main report

Files named like:

```text
agentfence_<action>_<namespace>_<timestamp>.json
agentfence_<action>_<namespace>_<timestamp>.md
```

These capture:

- discovered workload metadata
- all probe results
- scored unsafe findings
- review-only communication exposure
- skipped findings
- TBE/ELE/headline scores
- remediation plan and outcomes
- before/after comparisons for remediation workflows
- fixed probes and remaining manual recommendations

### Evaluation-factor report

Files named like:

```text
agentfence_f1_f5_<action>_<namespace>_<timestamp>.json
agentfence_f1_f5_<action>_<namespace>_<timestamp>.md
```

These capture:

- F1: workload and context capture
- F2: analyze probe summary
- F3: remediation effectiveness
- F4: artifact consistency
- F5: recoverability and rollback readiness

These factors are review evidence, not a second scoring system.

### Rollback bundle

Directories named like:

```text
rollback_bundle_<namespace>_<target>_<timestamp>/
```

These can contain:

- `backup_manifest.json`
- namespace snapshots
- affected resource snapshots
- cluster dependency metadata
- checksums
- validation metadata

Raw rollback bundles are not included in the public repository because they can contain environment-specific and sensitive material, including image pull secrets, registry credentials, service-account metadata, internal node names, pod IPs, network CIDRs, absolute local paths, Kubernetes events, and cluster dependency snapshots.

Operators should generate rollback bundles in their own environment immediately before remediation. A rollback bundle from one cluster should not be treated as portable recovery material for another cluster.

## Current Fresh-Sandbox Results

The latest reported fresh-sandbox analyze-remediation runs are:

| Track | Main report | Evaluation-factor report | Analyze result | Analyze to remediation | Headline score |
| --- | --- | --- | --- | --- | --- |
| CUA | `agentfence_analyze-remediation_sandbox-cua-fresh_20260516T144201Z.*` | `agentfence_f1_f5_analyze-remediation_sandbox-cua-fresh_20260516T144201Z.*` | 12 scored unsafe, 27 safe, 0 skipped | 12 issues, raw 16.5 -> 10 issues, raw 14.5 | 4.1748 -> 4.0554 |
| gVisor | `agentfence_analyze-remediation_sandbox-gvisor-fresh_20260516T154032Z.*` | `agentfence_f1_f5_analyze-remediation_sandbox-gvisor-fresh_20260516T154032Z.*` | 10 scored unsafe, 29 safe, 0 skipped | 10 issues, raw 15.0 -> 8 issues, raw 13.0 | 1.6930 -> 1.5736 |
| Kata | `agentfence_analyze-remediation_sandbox-kata-fresh_20260516T161818Z.*` | `agentfence_f1_f5_analyze-remediation_sandbox-kata-fresh_20260516T161818Z.*` | 11 scored unsafe, 28 safe, 0 skipped | 11 issues, raw 15.5 -> 6 issues, raw 4.5 | 0.9254 -> 0.2687 |

Verified fixed probes in the latest runs:

- CUA: seccomp filtering; no-new-privileges enforcement.
- gVisor: seccomp filtering; Linux capability bounding.
- Kata: seccomp filtering; kernel log restriction; BPF program-load restriction; performance-event restriction; capability bounding.

## Interpreting Results

The intended interpretation model is:

- analyze shows what unsafe conditions were observed
- review-only communication exposure remains visible but unscored
- remediation fixes supported and verified issues
- unsafe changes are rolled back or left as manual recommendations
- image-level, runtime-level, workload-design, and side-channel findings may remain after remediation
- the final risk should decrease, but not incorrectly drop to zero if residual findings remain

The score is decision support, not a proof of complete security. Read it together with fixed probes, rolled-back attempts, review-only findings, and manual recommendations.

## Why Results May Differ Across Sandboxes

Even with the same app logic, differences can come from:

- runtime class differences
- kernel and runtime behavior
- tool availability inside the target pod
- workload compatibility with non-root, read-only root filesystem, or no-new-privileges settings
- whether node/runtime hardening is applicable and not already enabled
- whether a remaining issue requires image rebuild, workload redesign, or operator communication-intent review

This is why `AgentFence AI` combines:

- runtime evidence when available
- Kubernetes spec reconciliation
- workload revalidation
- rollback-aware remediation
- explicit carry-forward of unresolved manual findings

## Recommended Reading Order

If you are reviewing a current run, read:

1. main Markdown report
2. main JSON report
3. evaluation-factor Markdown report
4. evaluation-factor JSON report
5. rollback bundle summary or local backup manifest, if available in your own environment

This gives the clearest picture of:

- what was found
- what was scored
- what was fixed
- what was left for manual review
- how restore readiness was established before mutation
