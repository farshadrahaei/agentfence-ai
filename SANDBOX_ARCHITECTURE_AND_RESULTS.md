# Sandbox Architecture And Results

This document explains the sandbox architectures used for `CUA`, `gVisor`, and `Kata`, and how `AgentFence AI` produces the result artifacts stored in [generated_outputs/](generated_outputs/).

## Purpose

`AgentFence AI` is designed to evaluate and harden sandboxed agentic AI workloads that run in Kubernetes. In this project, the key sandbox targets are:

- `sandbox-cua`
- `sandbox-gvisor`
- `sandbox-kata`

Each sandbox represents a different runtime or isolation profile, but the analysis workflow is intentionally consistent:

1. discover the target workload
2. analyze the workload posture
3. score the security findings
4. remediate supported issues
5. revalidate the workload after remediation
6. preserve rollback and source-of-truth artifacts

## Shared Kubernetes Model

All three sandboxes follow the same broad model:

- one namespace per sandbox
- one target workload deployment
- one attacker workload used for controlled remote probing
- supporting network policies and service resources

The target workloads discovered by the app are:

- `sandbox-cua` -> `deployment/target-cua`
- `sandbox-gvisor` -> `deployment/target-gvisor`
- `sandbox-kata` -> `deployment/target-kata`

The app excludes attacker resources from the primary target selection flow and focuses on the target deployment.

## Sandbox-Specific Notes

### CUA

`CUA` is used as the baseline agentic workload sandbox. It reflects a desktop-style or interactive AI workload that may need writable workspace volumes and service exposure. This makes it useful for showing:

- risky writable-root posture
- service account token exposure
- image-level issues such as setuid/setgid binaries

### gVisor

`gVisor` uses a sandboxed runtime class intended to reduce kernel attack surface. In the source configuration and live manifests, this usually appears through a sandbox-specific runtime setup and associated namespace isolation controls.

This environment is useful for demonstrating:

- how runtime isolation helps but does not eliminate workload-level issues
- how Kubernetes spec issues can still be remediated even when a sandboxed runtime is used

### Kata

`Kata` uses VM-like container isolation through a dedicated runtime class. It provides a stronger isolation boundary than a standard OCI container runtime, but the workload spec and image still matter.

This environment is useful for demonstrating:

- separation between runtime isolation and workload hardening
- cases where some issues are fixable in-cluster
- cases where image-level issues remain after remediation

## How AgentFence AI Produces Results

The result files in `generated_outputs/` are created by the live workflow used in `default` mode and `ai` mode.

At a high level, the app does the following:

1. identify the cluster, namespace, and workload
2. collect remote and Kubernetes evidence
3. try internal validation from the target pod when possible
4. fall back to spec-based validation when runtime validation is incomplete
5. generate remediation items and risk scores
6. optionally execute supported remediations
7. generate post-fix validation results
8. write artifacts to `generated_outputs/`

## Main Artifact Types

### Analyze audit

Files named like:

```text
guided_analyze_audit_<namespace>_<workload>_<timestamp>.json
guided_analyze_audit_<namespace>_<workload>_<timestamp>.md
```

These capture:

- discovered workload metadata
- findings
- risk score
- AI advisor guidance
- remediation candidates

### Remediation audit

Files named like:

```text
guided_remediation_audit_<namespace>_<workload>_<timestamp>.json
guided_remediation_audit_<namespace>_<workload>_<timestamp>.md
```

These represent the audit state that directly feeds the remediation decision for that run.

This is especially important because the remediation step should use the same effective findings that justify the fix execution.

### Remediation fixes

Files named like:

```text
guided_remediation_fixes_<namespace>_<workload>_<timestamp>.json
guided_remediation_fixes_<namespace>_<workload>_<timestamp>.md
```

These record:

- selected issues
- issue-by-issue fix status
- executed change steps
- post-fix validation
- recalculated risk after remediation

### Source-of-truth manifest

Files named like:

```text
source_of_truth_manifest_<namespace>_<workload>_<timestamp>.yaml
```

These are the recommended manifest changes to make the fix permanent in source automation such as Git.

## Output Folder

The generated result set referenced throughout this document is stored in the repository under [generated_outputs/](generated_outputs/).

### Rollback bundle

Directories named like:

```text
rollback_bundle_<namespace>_<workload>_<timestamp>/
```

These contain:

- resource snapshots
- a backup manifest
- data needed to restore the workload to its earlier state

## Interpreting Results

The intended interpretation model is:

- analyze shows what is currently wrong
- remediation fixes supported Kubernetes-spec issues
- unresolved image-level issues remain visible after remediation
- the final risk should decrease, but not incorrectly drop to zero if unresolved findings remain

For example, a common pattern in these sandboxes is:

- before remediation:
  - `SERVICE_ACCOUNT_TOKEN`
  - `ROOTFS_RW`
  - `SETID_BINARIES_PRESENT`
- after remediation:
  - `SERVICE_ACCOUNT_TOKEN` fixed
  - `ROOTFS_RW` fixed
  - `SETID_BINARIES_PRESENT` remains

That means the post-remediation score should go down, but still remain nonzero.

## Why Results May Differ Across Sandboxes

Even with the same app logic, some differences can come from:

- runtime class differences
- tool availability inside the target pod
- whether internal validation can run directly
- whether fallback validation must be used
- whether the remaining issue is image-level versus spec-level

This is why `AgentFence AI` now combines:

- runtime evidence when available
- Kubernetes spec reconciliation
- carry-forward of unresolved non-spec issues such as `SETID_BINARIES_PRESENT`

That combination helps keep the output consistent across CUA, gVisor, and Kata.

## Recommended Reading Order

If you are reviewing a run, the best order is:

1. analyze JSON
2. remediation fixes JSON
3. manifest YAML
4. rollback bundle manifest

This gives the clearest picture of:

- what was found
- what was fixed
- what remains
- how to make the fix permanent
