#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AgentFence — single-file audit: 39 unified probes, one catalog, one scorer.

Semantics: status "pass" = UNSAFE (attack/threat succeeded). "fail" = safe. "skip" = no score.

Scoring (disjoint layers — each scored probe in exactly one group, catalog v1.3.0):
  - TBE (Trust-boundary exposure): host-adjacent subset → tbe_* metrics.
  - ELE (Execution-local exposure): all remaining scored probes → ele_* metrics.
  - Review-only findings remain reported but do not affect issue_count, raw score, or headline.
  - Totals: issue_count / score_raw = scored passes (equals tbe_score_raw + ele_score_raw).
  - Headline: score_normalized = α·tbe_norm + (1−α)·ele_norm (default α=0.6).

All modes use: results = run_all_probes(ctx); metrics = summarize_results(results, α).
"""
from __future__ import annotations

import argparse
import datetime
import hashlib
import ipaddress
import json
import math
import os
import pathlib
import platform
import re
import shlex
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Literal, Optional, Tuple

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

CATALOG_VERSION = "1.3.0"
DEFAULT_HEADLINE_ALPHA = 0.6
ACTIVE_KUBE_CONTEXT: Optional[str] = None
AI_KEYCHAIN_SERVICE = os.environ.get("AGENTFENCE_OPENAI_KEYCHAIN_SERVICE", "AgentFence OpenAI API Key").strip() or "AgentFence OpenAI API Key"
AI_KEYCHAIN_ACCOUNT = os.environ.get("AGENTFENCE_OPENAI_KEYCHAIN_ACCOUNT", "default").strip() or "default"

SEVERITY_WEIGHTS = {"critical": 5.0, "high": 3.0, "medium": 1.0, "low": 0.5}

Status = Literal["pass", "fail", "skip"]
Severity = Literal["critical", "high", "medium", "low"]
RemediationAction = Literal["auto_fix", "hybrid", "manual_recommendation"]


@dataclass
class ProbeSpec:
    id: str
    severity: Severity
    origin_note: str = ""  # documentation only (classic vs new)


@dataclass
class TestResult:
    id: str
    severity: Severity
    status: Status
    evidence: str = ""
    matched_clause: str = ""
    duration_ms: int = 0


@dataclass
class ScoreBundle:
    """Disjoint TBE + ELE; totals match full catalog (no double counting)."""
    issue_count: int  # scored unsafe probes only; review-only findings are reported separately
    score_raw: float  # sum scored weights (= tbe_score_raw + ele_score_raw)
    # TBE — Trust-boundary exposure (layer 1)
    tbe_issue_count: int = 0
    tbe_score_raw: float = 0.0
    tbe_score_normalized: float = 0.0
    catalog_max_tbe: float = 0.0
    # ELE — Execution-local exposure (layer 2)
    ele_issue_count: int = 0
    ele_score_raw: float = 0.0
    ele_score_normalized: float = 0.0
    catalog_max_ele: float = 0.0
    # Headline: blend of disjoint normalized layers
    score_normalized: float = 0.0
    headline_alpha: float = DEFAULT_HEADLINE_ALPHA
    catalog_version: str = CATALOG_VERSION
    by_severity: Dict[str, int] = field(default_factory=dict)
    skipped: List[str] = field(default_factory=list)


@dataclass
class RunContext:
    namespace: str
    kubeconfig: str
    target_pod: str
    target_container: str
    attacker_pod: str
    attacker_container: str
    target_ip: str
    dry_run: bool = False
    probe_timeout: int = 25
    allow_node_runtime_remediation: bool = False


@dataclass(frozen=True)
class RemediationRecipe:
    probe_id: str
    issue_id: str
    title: str
    risk: str
    action_type: RemediationAction
    recommendation: str
    validation: str
    operator_steps: Tuple[str, ...]
    dry_run_artifact: str = ""


# Single unified catalog (39 probes). No separate manifest/battery execution paths.
CATALOG: List[ProbeSpec] = [
    ProbeSpec("AgentFence.ID.RUN_AS_UID_ZERO", "high", "classic: RUN_AS_ROOT"),
    ProbeSpec("AgentFence.ID.ROOTFS_WRITE_OK", "high", "classic: ROOTFS_RW"),
    ProbeSpec("AgentFence.ID.SA_TOKEN_READABLE", "high", "classic: SERVICE_ACCOUNT_TOKEN"),
    ProbeSpec("AgentFence.REMOTE.UNAUTH_SERVICE_REACHABLE", "high", "classic: REMOTE_REACHABILITY"),
    ProbeSpec("AgentFence.HOSTPATH.SENSITIVE_WRITE_OK", "high", "classic: SENSITIVE_PATHS_WRITABLE"),
    ProbeSpec("AgentFence.KERNEL.KEXEC_REACHABLE", "high", "battery"),
    ProbeSpec("AgentFence.KERNEL.INIT_MODULE_REACHABLE", "high", "battery"),
    ProbeSpec("AgentFence.KERNEL.BPF_PROG_LOAD_REACHABLE", "high", "battery"),
    ProbeSpec("AgentFence.KERNEL.USERFAULTFD_REACHABLE", "high", "battery"),
    ProbeSpec("AgentFence.KERNEL.PERF_EVENT_OPEN_REACHABLE", "high", "battery"),
    ProbeSpec("AgentFence.KERNEL.KALLSYMS_VISIBLE", "high", "battery"),
    ProbeSpec("AgentFence.KERNEL.DMESG_VISIBLE", "high", "battery"),
    ProbeSpec("AgentFence.FS.HOST_PROC_VISIBLE", "medium", "battery"),
    ProbeSpec("AgentFence.FS.HOST_SYS_VISIBLE", "medium", "battery"),
    ProbeSpec("AgentFence.FS.KCORE_READABLE", "medium", "battery"),
    ProbeSpec("AgentFence.FS.HOST_DEVICES_VISIBLE", "medium", "battery"),
    ProbeSpec("AgentFence.FS.ROOTFS_HOST_SHARED", "medium", "battery"),
    ProbeSpec("AgentFence.FS.HOST_FS_REACHABLE_VIA_PROC", "medium", "battery"),
    ProbeSpec("AgentFence.DEVICE.KVM_PRESENT", "high", "battery"),
    ProbeSpec("AgentFence.DEVICE.TUN_TAP_PRESENT", "high", "battery"),
    ProbeSpec("AgentFence.DEVICE.USB_PRESENT", "high", "battery"),
    ProbeSpec("AgentFence.DEVICE.RAW_SOCKET_USABLE", "high", "battery"),
    ProbeSpec("AgentFence.NS.PID_NS_SHARES_HOST", "medium", "battery"),
    ProbeSpec("AgentFence.NS.USER_NS_ROOT_MAPS_HOST_ROOT", "medium", "battery"),
    ProbeSpec("AgentFence.NS.IPC_NS_SHARES_HOST", "medium", "battery"),
    ProbeSpec("AgentFence.NS.NET_NS_SHARES_HOST", "medium", "battery"),
    ProbeSpec("AgentFence.NS.UTS_NS_SHARES_HOST", "medium", "battery"),
    ProbeSpec("AgentFence.NET.HOST_NETWORK_REACHABLE", "high", "battery"),
    ProbeSpec("AgentFence.NET.IMDS_REACHABLE", "high", "battery"),
    ProbeSpec("AgentFence.NET.KUBELET_API_REACHABLE", "high", "battery"),
    ProbeSpec("AgentFence.NET.APISERVER_DIRECT_REACHABLE", "high", "battery"),
    ProbeSpec("AgentFence.IDENTITY.SECCOMP_BYPASS_OK", "medium", "battery"),
    ProbeSpec("AgentFence.IDENTITY.NO_NEW_PRIVS_BYPASS_OK", "medium", "battery"),
    ProbeSpec("AgentFence.IDENTITY.CAP_BOUNDING_PERMISSIVE", "medium", "battery"),
    ProbeSpec("AgentFence.IDENTITY.PROCFS_HIDEPID_LAX", "medium", "battery"),
    ProbeSpec("AgentFence.SIDE.HOST_CPUINFO_LEAKED", "low", "battery"),
    ProbeSpec("AgentFence.SIDE.HOST_DMI_LEAKED", "low", "battery"),
    ProbeSpec("AgentFence.SIDE.HIGH_RES_TIMER_AVAILABLE", "low", "battery"),
    ProbeSpec("AgentFence.SIDE.HOST_CACHE_TOPOLOGY_LEAKED", "low", "battery"),
]

LEGACY_PROBE_PREFIX = "AF" + "PLUS."
PROBE_ID_ALIASES: Dict[str, str] = {
    p.id.replace("AgentFence.", LEGACY_PROBE_PREFIX): p.id for p in CATALOG
}


def canonical_probe_id(probe_id: Any) -> str:
    pid = str(probe_id or "")
    return PROBE_ID_ALIASES.get(pid, pid)


def canonical_test_result(result: TestResult) -> TestResult:
    pid = canonical_probe_id(result.id)
    if pid == result.id:
        return result
    return TestResult(
        id=pid,
        severity=result.severity,
        status=result.status,
        evidence=result.evidence,
        matched_clause=result.matched_clause,
        duration_ms=result.duration_ms,
    )


REVIEW_ONLY_PROBE_IDS: frozenset[str] = frozenset(
    {"AgentFence.REMOTE.UNAUTH_SERVICE_REACHABLE"}
)


def is_review_only_probe(probe_id: Any) -> bool:
    return canonical_probe_id(probe_id) in REVIEW_ONLY_PROBE_IDS


def is_scored_probe(probe_id: Any) -> bool:
    return not is_review_only_probe(probe_id)


# TBE — Trust-boundary exposure (disjoint layer 1). ELE is all other scored catalog probes.
TBE_PROBE_IDS: frozenset[str] = frozenset(
    {
        "AgentFence.DEVICE.RAW_SOCKET_USABLE",
        "AgentFence.HOSTPATH.SENSITIVE_WRITE_OK",
        "AgentFence.FS.HOST_SYS_VISIBLE",
    }
)


def _rr(
    probe_id: str,
    issue_id: str,
    title: str,
    risk: str,
    action_type: RemediationAction,
    recommendation: str,
    validation: str,
    operator_steps: Tuple[str, ...],
    dry_run_artifact: str = "",
) -> RemediationRecipe:
    return RemediationRecipe(
        probe_id=probe_id,
        issue_id=issue_id,
        title=title,
        risk=risk,
        action_type=action_type,
        recommendation=recommendation,
        validation=validation,
        operator_steps=operator_steps,
        dry_run_artifact=dry_run_artifact,
    )


REMEDIATION_RECIPES: Dict[str, RemediationRecipe] = {
    "AgentFence.ID.RUN_AS_UID_ZERO": _rr(
        "AgentFence.ID.RUN_AS_UID_ZERO",
        "RUN_AS_ROOT",
        "Run workload as non-root",
        "Root execution increases post-compromise impact.",
        "auto_fix",
        "Generate a pod/container securityContext with runAsNonRoot and an explicit non-zero UID/GID.",
        "Re-run AgentFence.ID.RUN_AS_UID_ZERO and confirm uid != 0.",
        ("Review image file ownership.", "Set runAsNonRoot: true.", "Set runAsUser/runAsGroup to a workload-owned ID."),
        "pod_security_context_patch",
    ),
    "AgentFence.ID.ROOTFS_WRITE_OK": _rr(
        "AgentFence.ID.ROOTFS_WRITE_OK",
        "ROOTFS_RW",
        "Mount root filesystem read-only",
        "Writable root filesystems make tampering and persistence easier.",
        "hybrid",
        "Generate readOnlyRootFilesystem plus manual writable-path migration guidance.",
        "Re-run AgentFence.ID.ROOTFS_WRITE_OK and confirm writes under / fail.",
        ("Inventory writes to /tmp, caches, logs, and workspace paths.", "Move mutable paths to explicit volumes.", "Enable readOnlyRootFilesystem."),
        "readonly_rootfs_patch",
    ),
    "AgentFence.ID.SA_TOKEN_READABLE": _rr(
        "AgentFence.ID.SA_TOKEN_READABLE",
        "SERVICE_ACCOUNT_TOKEN",
        "Reduce service account token exposure",
        "Readable tokens expand Kubernetes API blast radius.",
        "auto_fix",
        "Generate automountServiceAccountToken: false or least-privilege ServiceAccount guidance.",
        "Re-run AgentFence.ID.SA_TOKEN_READABLE and confirm token bytes are zero or absent.",
        ("Confirm whether the workload needs Kubernetes API access.", "Disable automount when not needed.", "Use dedicated least-privilege RBAC when needed."),
        "service_account_patch",
    ),
    "AgentFence.REMOTE.UNAUTH_SERVICE_REACHABLE": _rr(
        "AgentFence.REMOTE.UNAUTH_SERVICE_REACHABLE",
        "REMOTE_REACHABILITY",
        "Review service reachability from sibling pods",
        "Reachability from a sibling pod may be legitimate workload communication or unintended lateral exposure; AgentFence needs operator intent before scoring or mutating this path.",
        "manual_recommendation",
        "Inventory required callers, ports, and authentication expectations before applying least-privilege NetworkPolicy changes.",
        "Re-run remote reachability after defining allowed callers and confirm only approved paths respond.",
        ("Inventory required listeners and peer workloads.", "Document allowed ingress sources, ports, and authentication gates.", "Apply an allowlist NetworkPolicy only after confirming workload intent."),
    ),
    "AgentFence.HOSTPATH.SENSITIVE_WRITE_OK": _rr(
        "AgentFence.HOSTPATH.SENSITIVE_WRITE_OK",
        "HOSTPATH_SENSITIVE_WRITE",
        "Remove writable sensitive hostPath access",
        "Writable hostPath mounts can collapse the container/host boundary.",
        "hybrid",
        "Generate hostPath removal/read-only guidance and a replacement plan for required host access.",
        "Re-run hostPath write probe and confirm writes fail or hostPath is absent.",
        ("Identify the mounted host path and business need.", "Remove the hostPath or mount it read-only.", "Replace broad host access with a narrow API or sidecar."),
        "hostpath_review_patch",
    ),
    "AgentFence.KERNEL.KEXEC_REACHABLE": _rr(
        "AgentFence.KERNEL.KEXEC_REACHABLE",
        "KEXEC_REACHABLE",
        "Block kexec kernel-loading surface",
        "Reachable kexec paths expose high-impact kernel attack surface.",
        "hybrid",
        "Generate seccomp/capability hardening and manual runtime/node policy validation.",
        "Re-run AgentFence.KERNEL.KEXEC_REACHABLE and confirm EPERM or ENOSYS.",
        ("Drop privileged mode and dangerous capabilities.", "Enable seccomp RuntimeDefault.", "Review node runtime policy for kexec restrictions."),
        "kernel_surface_hardening_patch",
    ),
    "AgentFence.KERNEL.INIT_MODULE_REACHABLE": _rr(
        "AgentFence.KERNEL.INIT_MODULE_REACHABLE",
        "INIT_MODULE_REACHABLE",
        "Block module loading surface",
        "Kernel module loading can lead to host-level compromise.",
        "hybrid",
        "Generate capability/seccomp hardening and manual module-loading policy guidance.",
        "Re-run AgentFence.KERNEL.INIT_MODULE_REACHABLE and confirm blocked syscall behavior.",
        ("Drop SYS_MODULE and privileged mode.", "Enable RuntimeDefault seccomp.", "Validate node policy prevents module loading from workloads."),
        "kernel_surface_hardening_patch",
    ),
    "AgentFence.KERNEL.BPF_PROG_LOAD_REACHABLE": _rr(
        "AgentFence.KERNEL.BPF_PROG_LOAD_REACHABLE",
        "BPF_PROG_LOAD_REACHABLE",
        "Constrain eBPF program loading",
        "eBPF loading expands kernel-facing attack surface.",
        "hybrid",
        "Generate seccomp/capability restrictions and manual kernel lockdown guidance.",
        "Re-run AgentFence.KERNEL.BPF_PROG_LOAD_REACHABLE and confirm EPERM or ENOSYS.",
        ("Drop BPF, SYS_ADMIN, and privileged mode where present.", "Use seccomp RuntimeDefault or stricter profiles.", "Review node eBPF policy."),
        "kernel_surface_hardening_patch",
    ),
    "AgentFence.KERNEL.USERFAULTFD_REACHABLE": _rr(
        "AgentFence.KERNEL.USERFAULTFD_REACHABLE",
        "USERFAULTFD_REACHABLE",
        "Restrict userfaultfd exposure",
        "userfaultfd can strengthen kernel exploitation primitives.",
        "manual_recommendation",
        "Generate runtime/seccomp/kernel sysctl guidance because mitigation is node/runtime specific.",
        "Re-run AgentFence.KERNEL.USERFAULTFD_REACHABLE and confirm blocked access.",
        ("Review runtime seccomp profile.", "Set node/userfaultfd restrictions where supported.", "Prefer sandbox/VM runtimes for untrusted workloads."),
    ),
    "AgentFence.KERNEL.PERF_EVENT_OPEN_REACHABLE": _rr(
        "AgentFence.KERNEL.PERF_EVENT_OPEN_REACHABLE",
        "PERF_EVENT_OPEN_REACHABLE",
        "Restrict perf event access",
        "perf_event_open can expose side-channel and kernel attack surface.",
        "manual_recommendation",
        "Generate node sysctl/runtime guidance for perf restrictions.",
        "Re-run AgentFence.KERNEL.PERF_EVENT_OPEN_REACHABLE and confirm EPERM, EACCES, or ENOSYS.",
        ("Review kernel.perf_event_paranoid on nodes.", "Use runtime policies that block perf_event_open.", "Validate observability tools still work."),
    ),
    "AgentFence.KERNEL.KALLSYMS_VISIBLE": _rr(
        "AgentFence.KERNEL.KALLSYMS_VISIBLE",
        "KALLSYMS_VISIBLE",
        "Hide kernel symbols",
        "Visible kernel addresses weaken exploit resistance.",
        "manual_recommendation",
        "Generate host kernel pointer/kallsyms restriction guidance and capability review.",
        "Re-run AgentFence.KERNEL.KALLSYMS_VISIBLE and confirm zeroed or unavailable addresses.",
        ("Review kptr_restrict and kernel symbol exposure.", "Drop capabilities that expose kernel internals.", "Prefer stronger runtime isolation for untrusted workloads."),
    ),
    "AgentFence.KERNEL.DMESG_VISIBLE": _rr(
        "AgentFence.KERNEL.DMESG_VISIBLE",
        "DMESG_VISIBLE",
        "Restrict kernel log visibility",
        "Kernel logs can leak host and exploit-relevant details.",
        "hybrid",
        "Generate capability/seccomp hardening and manual node dmesg_restrict guidance.",
        "Re-run AgentFence.KERNEL.DMESG_VISIBLE and confirm permission denial or empty output.",
        ("Drop SYSLOG/SYS_ADMIN-like access.", "Enable RuntimeDefault seccomp.", "Set node kernel.dmesg_restrict where appropriate."),
        "kernel_surface_hardening_patch",
    ),
    "AgentFence.FS.HOST_PROC_VISIBLE": _rr(
        "AgentFence.FS.HOST_PROC_VISIBLE",
        "HOST_PROC_VISIBLE",
        "Prevent host /proc visibility",
        "Host process visibility enables host reconnaissance and escape planning.",
        "hybrid",
        "Generate hostPID false and mount isolation guidance.",
        "Re-run AgentFence.FS.HOST_PROC_VISIBLE and confirm host init/kubelet is not visible.",
        ("Set hostPID: false.", "Remove broad /proc host mounts.", "Validate application process discovery still works."),
        "namespace_isolation_patch",
    ),
    "AgentFence.FS.HOST_SYS_VISIBLE": _rr(
        "AgentFence.FS.HOST_SYS_VISIBLE",
        "HOST_SYS_VISIBLE",
        "Prevent host /sys visibility",
        "Host sysfs visibility leaks hardware and node state.",
        "hybrid",
        "Generate hostPath/sysfs removal or read-only restriction guidance.",
        "Re-run AgentFence.FS.HOST_SYS_VISIBLE and confirm sensitive sysfs paths are hidden.",
        ("Remove /sys hostPath mounts.", "Use read-only narrow mounts only when required.", "Review device plugin needs."),
        "hostpath_review_patch",
    ),
    "AgentFence.FS.KCORE_READABLE": _rr(
        "AgentFence.FS.KCORE_READABLE",
        "KCORE_READABLE",
        "Block /proc/kcore reads",
        "Readable kernel memory interfaces can expose severe host data.",
        "hybrid",
        "Generate privileged/capability removal guidance and manual node/runtime policy validation.",
        "Re-run AgentFence.FS.KCORE_READABLE and confirm permission denial.",
        ("Remove privileged mode.", "Drop dangerous capabilities.", "Validate runtime blocks kernel memory interfaces."),
        "kernel_surface_hardening_patch",
    ),
    "AgentFence.FS.HOST_DEVICES_VISIBLE": _rr(
        "AgentFence.FS.HOST_DEVICES_VISIBLE",
        "HOST_DEVICES_VISIBLE",
        "Remove visible host block devices",
        "Host device visibility increases data exposure and escape risk.",
        "hybrid",
        "Generate device mount removal guidance and manual replacement plan for required devices.",
        "Re-run AgentFence.FS.HOST_DEVICES_VISIBLE and confirm host block devices are absent.",
        ("Remove broad device mounts.", "Use device plugins with narrow allocation.", "Document any required hardware access."),
        "device_access_review_patch",
    ),
    "AgentFence.FS.ROOTFS_HOST_SHARED": _rr(
        "AgentFence.FS.ROOTFS_HOST_SHARED",
        "ROOTFS_HOST_SHARED",
        "Separate container rootfs from host rootfs",
        "Shared rootfs semantics indicate weak filesystem isolation.",
        "manual_recommendation",
        "Generate runtime/storage isolation guidance because rootfs sharing is environment specific.",
        "Re-run AgentFence.FS.ROOTFS_HOST_SHARED and confirm the container root is not host-shared.",
        ("Review container runtime storage configuration.", "Remove host root bind mounts.", "Prefer sandbox/VM runtime isolation for untrusted workloads."),
    ),
    "AgentFence.FS.HOST_FS_REACHABLE_VIA_PROC": _rr(
        "AgentFence.FS.HOST_FS_REACHABLE_VIA_PROC",
        "HOST_FS_REACHABLE_VIA_PROC",
        "Block host filesystem traversal through /proc",
        "Host filesystem reachability through /proc can expose sensitive host files.",
        "hybrid",
        "Generate hostPID false, hostPath removal, and containment validation steps.",
        "Re-run AgentFence.FS.HOST_FS_REACHABLE_VIA_PROC and confirm host files are not reachable.",
        ("Set hostPID: false.", "Remove broad hostPath mounts.", "Validate /proc/1/root does not expose host paths."),
        "namespace_isolation_patch",
    ),
    "AgentFence.DEVICE.KVM_PRESENT": _rr(
        "AgentFence.DEVICE.KVM_PRESENT",
        "KVM_DEVICE_PRESENT",
        "Review /dev/kvm exposure",
        "/dev/kvm exposes virtualization controls and must be tightly scoped.",
        "hybrid",
        "Generate /dev/kvm device removal guidance and manual VM/sandbox requirement review.",
        "Re-run AgentFence.DEVICE.KVM_PRESENT and confirm /dev/kvm is absent unless explicitly required.",
        ("Confirm whether nested virtualization is required.", "Remove /dev/kvm from general workloads.", "Constrain to dedicated sandbox nodes when required."),
        "device_access_review_patch",
    ),
    "AgentFence.DEVICE.TUN_TAP_PRESENT": _rr(
        "AgentFence.DEVICE.TUN_TAP_PRESENT",
        "TUN_TAP_PRESENT",
        "Review TUN/TAP device exposure",
        "TUN/TAP access can bypass expected network controls.",
        "hybrid",
        "Generate /dev/net/tun and NET_ADMIN removal guidance with networking compatibility checks.",
        "Re-run AgentFence.DEVICE.TUN_TAP_PRESENT and confirm the device is absent when not required.",
        ("Remove /dev/net/tun unless required.", "Drop NET_ADMIN.", "Validate VPN/proxy use cases separately."),
        "device_access_review_patch",
    ),
    "AgentFence.DEVICE.USB_PRESENT": _rr(
        "AgentFence.DEVICE.USB_PRESENT",
        "USB_DEVICE_PRESENT",
        "Remove USB device exposure",
        "USB device exposure expands host hardware attack surface.",
        "hybrid",
        "Generate USB device mount removal guidance and manual hardware access replacement plan.",
        "Re-run AgentFence.DEVICE.USB_PRESENT and confirm USB paths are absent.",
        ("Remove USB bus mounts.", "Use narrow device plugins where hardware is required.", "Document operational exceptions."),
        "device_access_review_patch",
    ),
    "AgentFence.DEVICE.RAW_SOCKET_USABLE": _rr(
        "AgentFence.DEVICE.RAW_SOCKET_USABLE",
        "RAW_SOCKET_USABLE",
        "Drop raw socket capability",
        "Raw sockets enable packet crafting and stronger lateral probes.",
        "auto_fix",
        "Generate capability drop for NET_RAW.",
        "Re-run AgentFence.DEVICE.RAW_SOCKET_USABLE and confirm raw socket creation is denied.",
        ("Drop NET_RAW or ALL capabilities.", "Re-add only documented required capabilities.", "Validate network diagnostics alternatives."),
        "capabilities_drop_patch",
    ),
    "AgentFence.NS.PID_NS_SHARES_HOST": _rr(
        "AgentFence.NS.PID_NS_SHARES_HOST",
        "HOST_PID_ENABLED",
        "Disable host PID namespace",
        "Host PID namespace sharing exposes host processes.",
        "auto_fix",
        "Generate hostPID: false patch.",
        "Re-run AgentFence.NS.PID_NS_SHARES_HOST and confirm hostPID=false.",
        ("Set hostPID: false.", "Validate process monitoring alternatives.", "Redeploy and re-run namespace probes."),
        "namespace_isolation_patch",
    ),
    "AgentFence.NS.USER_NS_ROOT_MAPS_HOST_ROOT": _rr(
        "AgentFence.NS.USER_NS_ROOT_MAPS_HOST_ROOT",
        "USER_NS_ROOT_MAPS_HOST_ROOT",
        "Review user namespace root mapping",
        "Root-to-root user namespace mapping weakens UID isolation.",
        "manual_recommendation",
        "Generate runtime/user namespace remapping guidance and validation commands.",
        "Re-run AgentFence.NS.USER_NS_ROOT_MAPS_HOST_ROOT and confirm root is not mapped to host root.",
        ("Enable user namespace remapping where supported.", "Review runtime configuration.", "Prefer non-root workload identity even with remapping."),
    ),
    "AgentFence.NS.IPC_NS_SHARES_HOST": _rr(
        "AgentFence.NS.IPC_NS_SHARES_HOST",
        "HOST_IPC_ENABLED",
        "Disable host IPC namespace",
        "Host IPC sharing exposes host IPC primitives.",
        "auto_fix",
        "Generate hostIPC: false patch.",
        "Re-run AgentFence.NS.IPC_NS_SHARES_HOST and confirm hostIPC=false.",
        ("Set hostIPC: false.", "Validate shared-memory use cases.", "Redeploy and re-run namespace probes."),
        "namespace_isolation_patch",
    ),
    "AgentFence.NS.NET_NS_SHARES_HOST": _rr(
        "AgentFence.NS.NET_NS_SHARES_HOST",
        "HOST_NETWORK_ENABLED",
        "Disable host network namespace",
        "Host networking bypasses pod network isolation.",
        "auto_fix",
        "Generate hostNetwork: false patch plus Service/NetworkPolicy replacement guidance.",
        "Re-run AgentFence.NS.NET_NS_SHARES_HOST and confirm hostNetwork=false.",
        ("Set hostNetwork: false.", "Expose required ports through Services.", "Apply least-privilege NetworkPolicy."),
        "namespace_isolation_patch",
    ),
    "AgentFence.NS.UTS_NS_SHARES_HOST": _rr(
        "AgentFence.NS.UTS_NS_SHARES_HOST",
        "HOST_UTS_RISK",
        "Isolate hostname/UTS context",
        "Host-like UTS exposure can reveal or couple node identity.",
        "hybrid",
        "Generate hostNetwork false or hostname isolation guidance and manual compatibility review.",
        "Re-run AgentFence.NS.UTS_NS_SHARES_HOST and confirm isolated UTS behavior.",
        ("Remove hostNetwork when possible.", "Avoid host aliases that reveal node identity.", "Validate service discovery behavior."),
        "namespace_isolation_patch",
    ),
    "AgentFence.NET.HOST_NETWORK_REACHABLE": _rr(
        "AgentFence.NET.HOST_NETWORK_REACHABLE",
        "HOST_NETWORK_REACHABLE",
        "Restrict node network reachability",
        "Reachable node services increase lateral and node-adjacent risk.",
        "hybrid",
        "Generate egress NetworkPolicy restrictions and manual node-admin surface review.",
        "Re-run AgentFence.NET.HOST_NETWORK_REACHABLE and confirm node admin ports are blocked.",
        ("Inventory required node egress.", "Block node-admin ports by policy/firewall.", "Validate operational monitoring paths."),
        "egress_network_policy_manifest",
    ),
    "AgentFence.NET.IMDS_REACHABLE": _rr(
        "AgentFence.NET.IMDS_REACHABLE",
        "IMDS_REACHABLE",
        "Block cloud metadata access",
        "Metadata access can expose node or cloud credentials.",
        "auto_fix",
        "Generate target-scoped metadata-service egress deny policy with post-apply validation.",
        "Re-run AgentFence.NET.IMDS_REACHABLE and confirm metadata endpoint is blocked.",
        ("Block 169.254.169.254 and provider equivalents.", "Use workload identity.", "Validate applications do not depend on node metadata."),
        "metadata_egress_policy_manifest",
    ),
    "AgentFence.NET.KUBELET_API_REACHABLE": _rr(
        "AgentFence.NET.KUBELET_API_REACHABLE",
        "KUBELET_API_REACHABLE",
        "Block kubelet API reachability",
        "Kubelet API reachability exposes node administrative surface.",
        "hybrid",
        "Generate egress NetworkPolicy for kubelet/node ports and manual node firewall/RBAC guidance.",
        "Re-run AgentFence.NET.KUBELET_API_REACHABLE and confirm kubelet API is unreachable.",
        ("Block kubelet ports from workloads.", "Review node firewall rules.", "Validate metrics collection through approved paths."),
        "egress_network_policy_manifest",
    ),
    "AgentFence.NET.APISERVER_DIRECT_REACHABLE": _rr(
        "AgentFence.NET.APISERVER_DIRECT_REACHABLE",
        "APISERVER_DIRECT_REACHABLE",
        "Review Kubernetes API reachability",
        "Direct API reachability plus credentials can expand blast radius.",
        "hybrid",
        "Generate ServiceAccount/RBAC and egress policy guidance; manual review if API access is legitimate.",
        "Re-run AgentFence.NET.APISERVER_DIRECT_REACHABLE and confirm only approved API access remains.",
        ("Disable unnecessary ServiceAccount tokens.", "Apply least-privilege RBAC.", "Restrict API egress where policy allows."),
        "service_account_and_egress_patch",
    ),
    "AgentFence.IDENTITY.SECCOMP_BYPASS_OK": _rr(
        "AgentFence.IDENTITY.SECCOMP_BYPASS_OK",
        "SECCOMP_BYPASS_OK",
        "Enable seccomp filtering",
        "Missing or weak seccomp leaves privileged syscall surface exposed.",
        "auto_fix",
        "Generate seccompProfile.type: RuntimeDefault or stricter profile recommendation.",
        "Re-run AgentFence.IDENTITY.SECCOMP_BYPASS_OK and confirm blocked syscall behavior or runtime-specific mediation evidence.",
        ("Set seccompProfile.type: RuntimeDefault.", "Use Localhost profiles for stricter workloads after validation.", "Redeploy and re-run identity probes."),
        "pod_security_context_patch",
    ),
    "AgentFence.IDENTITY.NO_NEW_PRIVS_BYPASS_OK": _rr(
        "AgentFence.IDENTITY.NO_NEW_PRIVS_BYPASS_OK",
        "NO_NEW_PRIVS_DISABLED",
        "Disallow privilege escalation",
        "NoNewPrivs disabled allows privilege-gaining execution paths.",
        "auto_fix",
        "Generate allowPrivilegeEscalation: false patch.",
        "Re-run AgentFence.IDENTITY.NO_NEW_PRIVS_BYPASS_OK and confirm NoNewPrivs is enabled.",
        ("Set allowPrivilegeEscalation: false.", "Remove setuid helpers where possible.", "Validate startup behavior."),
        "pod_security_context_patch",
    ),
    "AgentFence.IDENTITY.CAP_BOUNDING_PERMISSIVE": _rr(
        "AgentFence.IDENTITY.CAP_BOUNDING_PERMISSIVE",
        "CAP_BOUNDING_PERMISSIVE",
        "Minimize Linux capability bounding set",
        "Dangerous capabilities increase kernel and network attack surface.",
        "auto_fix",
        "Generate capabilities.drop: [ALL] with explicit allowlist guidance.",
        "Re-run AgentFence.IDENTITY.CAP_BOUNDING_PERMISSIVE and confirm dangerous caps are absent.",
        ("Drop ALL capabilities.", "Re-add only documented capabilities.", "Validate workload diagnostics and networking."),
        "capabilities_drop_patch",
    ),
    "AgentFence.IDENTITY.PROCFS_HIDEPID_LAX": _rr(
        "AgentFence.IDENTITY.PROCFS_HIDEPID_LAX",
        "PROCFS_HIDEPID_LAX",
        "Reduce process visibility",
        "Broad procfs process visibility aids reconnaissance.",
        "manual_recommendation",
        "Generate runtime/node procfs isolation guidance and validation commands.",
        "Re-run AgentFence.IDENTITY.PROCFS_HIDEPID_LAX and confirm only expected processes are visible.",
        ("Review runtime procfs masking.", "Avoid hostPID.", "Use sandbox/VM runtimes for untrusted workloads."),
    ),
    "AgentFence.SIDE.HOST_CPUINFO_LEAKED": _rr(
        "AgentFence.SIDE.HOST_CPUINFO_LEAKED",
        "HOST_CPUINFO_LEAKED",
        "Reduce CPU information leakage",
        "CPU details can support fingerprinting and side-channel planning.",
        "manual_recommendation",
        "Generate runtime isolation guidance and note that full mitigation may require sandbox/VM runtime selection.",
        "Re-run AgentFence.SIDE.HOST_CPUINFO_LEAKED and compare exposed CPU details.",
        ("Prefer sandbox/VM runtime for untrusted workloads.", "Review CPU masking support.", "Document residual side-channel risk."),
    ),
    "AgentFence.SIDE.HOST_DMI_LEAKED": _rr(
        "AgentFence.SIDE.HOST_DMI_LEAKED",
        "HOST_DMI_LEAKED",
        "Mask host DMI information",
        "DMI data reveals host and platform details.",
        "manual_recommendation",
        "Generate sysfs/DMI masking or runtime isolation guidance.",
        "Re-run AgentFence.SIDE.HOST_DMI_LEAKED and confirm DMI paths are absent or masked.",
        ("Remove DMI sysfs mounts.", "Review runtime masking options.", "Prefer sandbox/VM runtime isolation."),
    ),
    "AgentFence.SIDE.HIGH_RES_TIMER_AVAILABLE": _rr(
        "AgentFence.SIDE.HIGH_RES_TIMER_AVAILABLE",
        "HIGH_RES_TIMER_AVAILABLE",
        "Assess high-resolution timer exposure",
        "High-resolution timers can strengthen timing side channels.",
        "manual_recommendation",
        "Generate side-channel mitigation guidance, runtime selection notes, and workload-specific tradeoffs.",
        "Re-run AgentFence.SIDE.HIGH_RES_TIMER_AVAILABLE and record timer resolution.",
        ("Assess threat model for timing channels.", "Prefer stronger runtime isolation for hostile code.", "Consider scheduling and noise controls where practical."),
    ),
    "AgentFence.SIDE.HOST_CACHE_TOPOLOGY_LEAKED": _rr(
        "AgentFence.SIDE.HOST_CACHE_TOPOLOGY_LEAKED",
        "HOST_CACHE_TOPOLOGY_LEAKED",
        "Reduce cache topology leakage",
        "Cache topology details can assist side-channel analysis.",
        "manual_recommendation",
        "Generate runtime isolation and scheduling guidance; include residual-risk explanation.",
        "Re-run AgentFence.SIDE.HOST_CACHE_TOPOLOGY_LEAKED and confirm reduced topology exposure where possible.",
        ("Prefer sandbox/VM runtime isolation.", "Use dedicated nodes for hostile workloads.", "Document residual cache side-channel risk."),
    ),
}


def catalog_max() -> float:
    return sum(SEVERITY_WEIGHTS[p.severity] for p in CATALOG if is_scored_probe(p.id))


def catalog_max_tbe() -> float:
    return sum(SEVERITY_WEIGHTS[p.severity] for p in CATALOG if p.id in TBE_PROBE_IDS and is_scored_probe(p.id))


def catalog_max_ele() -> float:
    return sum(SEVERITY_WEIGHTS[p.severity] for p in CATALOG if p.id not in TBE_PROBE_IDS and is_scored_probe(p.id))


def summarize_results(
    results: List[TestResult], headline_alpha: float = DEFAULT_HEADLINE_ALPHA
) -> ScoreBundle:
    """TBE and ELE are disjoint; each probe counted in at most one layer raw sum."""
    normalized_results = [canonical_test_result(r) for r in results]
    passed = [
        r
        for r in normalized_results
        if r.status == "pass" and is_scored_probe(r.id)
    ]
    passed_tbe = [r for r in passed if r.id in TBE_PROBE_IDS]
    passed_ele = [r for r in passed if r.id not in TBE_PROBE_IDS]
    skipped = [r.id for r in normalized_results if r.status == "skip"]
    raw_total = sum(SEVERITY_WEIGHTS[r.severity] for r in passed)
    raw_tbe = sum(SEVERITY_WEIGHTS[r.severity] for r in passed_tbe)
    raw_ele = sum(SEVERITY_WEIGHTS[r.severity] for r in passed_ele)
    if not math.isclose(raw_total, raw_tbe + raw_ele, rel_tol=0, abs_tol=1e-4):
        raise RuntimeError(f"TBE/ELE partition mismatch {raw_total=} {raw_tbe=} {raw_ele=}")
    mx_t = catalog_max_tbe()
    mx_e = catalog_max_ele()
    tbe_norm = (raw_tbe / mx_t * 10.0) if mx_t > 0 else 0.0
    ele_norm = (raw_ele / mx_e * 10.0) if mx_e > 0 else 0.0
    a = max(0.0, min(1.0, float(headline_alpha)))
    headline = a * tbe_norm + (1.0 - a) * ele_norm
    by_sev: Dict[str, int] = {}
    for r in passed:
        by_sev[r.severity] = by_sev.get(r.severity, 0) + 1
    return ScoreBundle(
        issue_count=len(passed),
        score_raw=round(raw_total, 4),
        tbe_issue_count=len(passed_tbe),
        tbe_score_raw=round(raw_tbe, 4),
        tbe_score_normalized=round(tbe_norm, 4),
        catalog_max_tbe=round(mx_t, 4),
        ele_issue_count=len(passed_ele),
        ele_score_raw=round(raw_ele, 4),
        ele_score_normalized=round(ele_norm, 4),
        catalog_max_ele=round(mx_e, 4),
        score_normalized=round(headline, 4),
        headline_alpha=a,
        catalog_version=CATALOG_VERSION,
        by_severity=by_sev,
        skipped=skipped,
    )


def score_bundle_from_dict(mb: Dict[str, Any]) -> ScoreBundle:
    """Deserialize metrics dict (v1.2.0+; partial legacy support)."""
    a = float(mb.get("headline_alpha", DEFAULT_HEADLINE_ALPHA))
    if "tbe_score_raw" in mb:
        tbe_n = float(mb.get("tbe_score_normalized", 0))
        ele_n = float(mb.get("ele_score_normalized", 0))
        head = float(mb.get("score_normalized", a * tbe_n + (1.0 - a) * ele_n))
        return ScoreBundle(
            issue_count=int(mb.get("issue_count", 0)),
            score_raw=float(mb.get("score_raw", 0)),
            tbe_issue_count=int(mb.get("tbe_issue_count", 0)),
            tbe_score_raw=float(mb.get("tbe_score_raw", 0)),
            tbe_score_normalized=float(mb.get("tbe_score_normalized", 0)),
            catalog_max_tbe=float(mb.get("catalog_max_tbe", catalog_max_tbe())),
            ele_issue_count=int(mb.get("ele_issue_count", 0)),
            ele_score_raw=float(mb.get("ele_score_raw", 0)),
            ele_score_normalized=float(mb.get("ele_score_normalized", 0)),
            catalog_max_ele=float(mb.get("catalog_max_ele", catalog_max_ele())),
            score_normalized=head,
            headline_alpha=a,
            catalog_version=str(mb.get("catalog_version", CATALOG_VERSION)),
            by_severity=dict(mb.get("by_severity") or {}),
            skipped=list(mb.get("skipped") or []),
        )
    # legacy v1.1
    mx = float(mb.get("catalog_max", 77))
    raw = float(mb.get("score_raw", 0))
    exp_n = float(mb.get("exposure_score_normalized", (raw / mx * 10.0) if mx else 0))
    mx_h = float(mb.get("catalog_max_isolation", 31))
    raw_i = float(mb.get("isolation_score_raw", 0))
    iso_n = float(
        mb.get("isolation_score_normalized", (raw_i / mx_h * 10.0) if mx_h else 0)
    )
    head = float(mb.get("score_normalized", a * iso_n + (1.0 - a) * exp_n))
    iso_issues = int(mb.get("isolation_issue_count", 0))
    total_issues = int(mb.get("issue_count", 0))
    ele_issues = max(0, total_issues - iso_issues)
    return ScoreBundle(
        issue_count=total_issues,
        score_raw=raw,
        tbe_issue_count=iso_issues,
        tbe_score_raw=raw_i,
        tbe_score_normalized=iso_n,
        catalog_max_tbe=mx_h,
        ele_issue_count=ele_issues,
        ele_score_raw=max(0.0, raw - raw_i),
        ele_score_normalized=exp_n,
        catalog_max_ele=mx,
        score_normalized=head,
        headline_alpha=a,
        catalog_version=str(mb.get("catalog_version", CATALOG_VERSION)),
        by_severity=dict(mb.get("by_severity") or {}),
        skipped=list(mb.get("skipped") or []),
    )


def recipe_to_dict(recipe: RemediationRecipe) -> Dict[str, Any]:
    return {
        "probe_id": recipe.probe_id,
        "issue_id": recipe.issue_id,
        "title": recipe.title,
        "risk": recipe.risk,
        "action_type": recipe.action_type,
        "recommendation": recipe.recommendation,
        "validation": recipe.validation,
        "operator_steps": list(recipe.operator_steps),
        "dry_run_artifact": recipe.dry_run_artifact,
    }


def dry_run_artifact_for_recipe(
    recipe: RemediationRecipe, context: Optional[Dict[str, Any]] = None
) -> Optional[Dict[str, Any]]:
    if recipe.action_type == "manual_recommendation":
        return None
    context = context or {}
    target = context.get("target_pod") or context.get("workload") or "<workload>"
    namespace = context.get("namespace") or "default"
    artifact_kind = recipe.dry_run_artifact or "manual_patch"
    return {
        "artifact_kind": artifact_kind,
        "namespace": namespace,
        "target": target,
        "mode": "dry_run",
        "description": recipe.recommendation,
        "apply_gate": "requires explicit execution approval before mutation",
    }


def remediation_item_from_result(
    result: TestResult, context: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    result = canonical_test_result(result)
    recipe = REMEDIATION_RECIPES[result.id]
    review_only = is_review_only_probe(result.id)
    if result.status == "pass" and review_only:
        disposition = "needs_review"
    elif result.status == "pass":
        disposition = "needs_action"
    elif result.status == "fail":
        disposition = "not_needed"
    else:
        disposition = "not_assessed"
    item = {
        "probe_id": result.id,
        "issue_id": recipe.issue_id,
        "severity": result.severity,
        "status": disposition,
        "action_type": recipe.action_type,
        "title": recipe.title,
        "risk": recipe.risk,
        "matched_clause": result.matched_clause,
        "evidence": result.evidence,
        "recommendation": recipe.recommendation,
        "validation": recipe.validation,
        "operator_steps": list(recipe.operator_steps),
        "review_only": review_only,
        "score_contributes": not review_only,
        "auto_applicable": (not review_only) and recipe.action_type in ("auto_fix", "hybrid"),
        "manual_recommendation": recipe.action_type in ("manual_recommendation", "hybrid"),
    }
    artifact = dry_run_artifact_for_recipe(recipe, context)
    if artifact:
        item["dry_run_artifact"] = artifact
    if result.status == "skip":
        item["note"] = "Probe was not assessed; this recipe applies if the probe later confirms unsafe behavior."
    elif result.status == "fail":
        item["note"] = "Probe is currently safe; remediation is not needed for this finding."
    elif review_only:
        item["note"] = "Review-only communication exposure observed; no score or automatic remediation is applied until workload intent is declared."
    else:
        item["note"] = "Unsafe behavior confirmed; apply the recommended remediation path."
    return item


def build_remediation_plan(
    results: List[TestResult], context: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    items = [remediation_item_from_result(r, context) for r in results]
    actionable = [i for i in items if i["status"] in ("needs_action", "needs_review")]
    return {
        "schema": "agentfence-remediation-plan-v2",
        "coverage": {
            "catalog_count": len(CATALOG),
            "recipe_count": len(REMEDIATION_RECIPES),
            "complete": set(REMEDIATION_RECIPES) == {p.id for p in CATALOG},
        },
        "count": len(items),
        "actionable_count": len(actionable),
        "items": items,
        "actionable_items": actionable,
        "note": "Every AgentFence probe has either auto_fix, hybrid, or manual_recommendation coverage; review-only communication exposure is reported but unscored.",
    }


def checkpoint_allows_mutation(checkpoint: Optional[Dict[str, Any]], dry_run: bool) -> bool:
    if dry_run:
        return True
    return (checkpoint or {}).get("status") in ("verified", "verified_with_warnings")


def target_match_labels(ctx: RunContext) -> Dict[str, str]:
    pod = load_target_pod_json(ctx)
    labels = ((pod or {}).get("metadata") or {}).get("labels") or {}
    stable = {
        k: str(v)
        for k, v in labels.items()
        if k
        not in (
            "pod-template-hash",
            "controller-revision-hash",
            "statefulset.kubernetes.io/pod-name",
            "batch.kubernetes.io/controller-uid",
            "controller-uid",
        )
    }
    if stable:
        return stable
    return {str(k): str(v) for k, v in labels.items()}


def workload_template_patch(resource: str, pod_spec_patch: Dict[str, Any]) -> Dict[str, Any]:
    if resource == "cronjob":
        return {
            "spec": {
                "jobTemplate": {
                    "spec": {
                        "template": {
                            "spec": pod_spec_patch,
                        }
                    }
                }
            }
        }
    return {"spec": {"template": {"spec": pod_spec_patch}}}


def merge_capabilities_drop_all(sc: Dict[str, Any]) -> None:
    caps = dict(sc.get("capabilities") or {})
    existing = caps.get("drop") or []
    merged = sorted(set([str(x) for x in existing] + ["ALL"]))
    caps["drop"] = merged
    sc["capabilities"] = caps


def workload_allows_auto_security_context(pod_spec: Dict[str, Any]) -> Tuple[bool, str]:
    containers = pod_spec.get("containers") or []
    init_containers = pod_spec.get("initContainers") or []
    if len(containers) != 1 or init_containers:
        return False, "multi-container or init-container workloads need per-container compatibility review"
    return True, "single-container workload with no init containers"


def _container_declares_kube_api_dependency(container: Dict[str, Any]) -> Optional[str]:
    for env in container.get("env") or []:
        name = str(env.get("name") or "")
        value = str(env.get("value") or "")
        if name.startswith("KUBE") or "kubernetes.default.svc" in value:
            return f"container env {name!r} suggests Kubernetes API use"
    for mount in container.get("volumeMounts") or []:
        path = str(mount.get("mountPath") or "")
        if path.startswith("/var/run/secrets/kubernetes.io/serviceaccount"):
            return "container explicitly mounts the service-account token path"
    return None


def _service_account_subject_matches(
    subject: Dict[str, Any], namespace: str, service_account: str
) -> bool:
    if subject.get("kind") != "ServiceAccount":
        return False
    if subject.get("name") != service_account:
        return False
    subject_ns = subject.get("namespace")
    return subject_ns in (None, "", namespace)


def service_account_has_rbac_binding(ctx: RunContext, service_account: str) -> Tuple[bool, str]:
    role_bindings = kubectl_get_json(
        ctx.kubeconfig,
        ["get", "rolebindings.rbac.authorization.k8s.io", "-n", ctx.namespace],
    )
    if role_bindings is None:
        return True, "unable to inspect namespaced RoleBindings"
    for rb in role_bindings.get("items") or []:
        for subject in rb.get("subjects") or []:
            if _service_account_subject_matches(subject, ctx.namespace, service_account):
                name = ((rb.get("metadata") or {}).get("name")) or "<unnamed>"
                return True, f"service account is referenced by RoleBinding {name}"

    cluster_role_bindings = kubectl_get_json(
        ctx.kubeconfig,
        ["get", "clusterrolebindings.rbac.authorization.k8s.io"],
    )
    if cluster_role_bindings is None:
        return True, "unable to inspect ClusterRoleBindings"
    for crb in cluster_role_bindings.get("items") or []:
        for subject in crb.get("subjects") or []:
            if _service_account_subject_matches(subject, ctx.namespace, service_account):
                name = ((crb.get("metadata") or {}).get("name")) or "<unnamed>"
                return True, f"service account is referenced by ClusterRoleBinding {name}"
    return False, "no RoleBinding or ClusterRoleBinding references the service account"


def workload_allows_auto_service_account_token(
    ctx: RunContext, pod_spec: Dict[str, Any]
) -> Tuple[bool, str]:
    automount = pod_spec.get("automountServiceAccountToken")
    if automount is False:
        return False, "service-account token automount is already disabled"
    if automount is True:
        return False, "service-account token automount is explicitly enabled in the workload"

    service_account = str(pod_spec.get("serviceAccountName") or "default")
    if service_account != "default":
        return False, f"dedicated service account {service_account!r} needs API-use review"

    for volume in pod_spec.get("volumes") or []:
        projected_sources = ((volume.get("projected") or {}).get("sources")) or []
        if any("serviceAccountToken" in source for source in projected_sources):
            return False, "workload declares an explicit projected service-account token"

    for container in (pod_spec.get("containers") or []) + (pod_spec.get("initContainers") or []):
        reason = _container_declares_kube_api_dependency(container)
        if reason:
            return False, reason

    has_binding, reason = service_account_has_rbac_binding(ctx, service_account)
    if has_binding:
        return False, reason
    return True, "default service account has no explicit API dependency or RBAC binding"


def selector_matches_labels(selector: Dict[str, Any], labels: Dict[str, str]) -> bool:
    if not selector:
        return True
    for key, value in (selector.get("matchLabels") or {}).items():
        if str(labels.get(key)) != str(value):
            return False
    for expr in selector.get("matchExpressions") or []:
        key = str(expr.get("key") or "")
        op = str(expr.get("operator") or "")
        values = {str(v) for v in expr.get("values") or []}
        present = key in labels
        current = str(labels.get(key) or "")
        if op == "In" and current not in values:
            return False
        if op == "NotIn" and current in values:
            return False
        if op == "Exists" and not present:
            return False
        if op == "DoesNotExist" and present:
            return False
    return True


def selector_to_label_arg(selector: Dict[str, Any]) -> str:
    parts = []
    for key, value in (selector.get("matchLabels") or {}).items():
        parts.append(f"{key}={value}")
    return ",".join(parts)


def _tcp_ip_from_cidr(cidr: str) -> Optional[str]:
    try:
        net = ipaddress.ip_network(str(cidr), strict=False)
    except ValueError:
        return None
    if net.version == 4 and net.prefixlen == 32:
        return str(net.network_address)
    if net.version == 6 and net.prefixlen == 128:
        return str(net.network_address)
    return None


def capture_connectivity_expectations(
    ctx: RunContext, pod_labels: Dict[str, str]
) -> List[Dict[str, Any]]:
    """Capture concrete TCP egress endpoints from NetworkPolicies that select the pod."""
    policies = kubectl_get_json(ctx.kubeconfig, ["get", "networkpolicies.networking.k8s.io", "-n", ctx.namespace])
    expectations: List[Dict[str, Any]] = []
    seen = set()
    for policy in (policies or {}).get("items") or []:
        spec = policy.get("spec") or {}
        if not selector_matches_labels(spec.get("podSelector") or {}, pod_labels):
            continue
        if "Egress" not in (spec.get("policyTypes") or []):
            continue
        policy_name = ((policy.get("metadata") or {}).get("name")) or ""
        for rule in spec.get("egress") or []:
            tcp_ports = []
            for port in rule.get("ports") or []:
                if str(port.get("protocol") or "TCP").upper() != "TCP":
                    continue
                raw_port = port.get("port")
                if isinstance(raw_port, int):
                    tcp_ports.append(raw_port)
                elif isinstance(raw_port, str) and raw_port.isdigit():
                    tcp_ports.append(int(raw_port))
            if not tcp_ports:
                continue
            for to in rule.get("to") or []:
                ip_block = to.get("ipBlock") or {}
                host = _tcp_ip_from_cidr(str(ip_block.get("cidr") or ""))
                if not host:
                    continue
                for port in tcp_ports:
                    key = (policy_name, host, port)
                    if key in seen:
                        continue
                    seen.add(key)
                    expectations.append(
                        {
                            "source_policy": policy_name,
                            "host": host,
                            "port": port,
                            "protocol": "TCP",
                            "reason": "captured from concrete NetworkPolicy egress ipBlock before remediation",
                        }
                    )
    return expectations[:12]


def workload_pods_for_snapshot(ctx: RunContext, snapshot: Dict[str, Any]) -> List[Dict[str, Any]]:
    selector = ((snapshot.get("selector") or {}).get("matchLabels")) or {}
    if selector:
        label_arg = ",".join(f"{k}={v}" for k, v in selector.items())
        data = kubectl_get_json(ctx.kubeconfig, ["get", "pods", "-n", ctx.namespace, "-l", label_arg])
        return (data or {}).get("items") or []
    pod = load_target_pod_json(ctx)
    return [pod] if pod else []


def capture_workload_config_before_patch(
    ctx: RunContext,
    workload_ref: Dict[str, Any],
    workload_json: Dict[str, Any],
    pod_spec: Dict[str, Any],
) -> Dict[str, Any]:
    pod = load_target_pod_json(ctx) or {}
    pod_labels = ((pod.get("metadata") or {}).get("labels")) or {}
    metadata = workload_json.get("metadata") or {}
    spec = workload_json.get("spec") or {}
    selector = spec.get("selector") or {}
    template = spec.get("template") or {}
    template_spec = template.get("spec") or pod_spec
    pods_before = []
    for item in workload_pods_for_snapshot(
        ctx,
        {
            "selector": selector,
        },
    ):
        pod_meta = item.get("metadata") or {}
        pods_before.append(
            {
                "name": pod_meta.get("name"),
                "uid": pod_meta.get("uid"),
                "phase": ((item.get("status") or {}).get("phase")),
            }
        )
    return {
        "schema": "agentfence-workload-config-before-autofix-v1",
        "captured_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "namespace": ctx.namespace,
        "target_pod": ctx.target_pod,
        "target_container": ctx.target_container,
        "workload_reference": workload_ref,
        "workload_api_version": workload_json.get("apiVersion"),
        "workload_kind": workload_json.get("kind"),
        "workload_name": metadata.get("name"),
        "replicas": spec.get("replicas"),
        "selector": selector,
        "template_labels": ((template.get("metadata") or {}).get("labels")) or {},
        "service_account": template_spec.get("serviceAccountName") or "default",
        "runtime_class": template_spec.get("runtimeClassName"),
        "node_selector": template_spec.get("nodeSelector") or {},
        "pod_security_context": template_spec.get("securityContext") or {},
        "automount_service_account_token": template_spec.get("automountServiceAccountToken"),
        "containers": [
            {
                "name": c.get("name"),
                "image": c.get("image"),
                "ports": c.get("ports") or [],
                "security_context": c.get("securityContext"),
                "readiness_probe": c.get("readinessProbe"),
                "liveness_probe": c.get("livenessProbe"),
            }
            for c in template_spec.get("containers") or []
        ],
        "init_containers": [
            {
                "name": c.get("name"),
                "image": c.get("image"),
                "security_context": c.get("securityContext"),
            }
            for c in template_spec.get("initContainers") or []
        ],
        "pods_before": pods_before,
        "connectivity_expectations": capture_connectivity_expectations(ctx, pod_labels),
    }


def tcp_connectivity_command(host: str, port: int) -> str:
    return (
        f"HOST={shlex.quote(host)} PORT={int(port)}; export HOST PORT; "
        "if command -v python3 >/dev/null 2>&1; then PY=python3; "
        "elif command -v python >/dev/null 2>&1; then PY=python; else PY=''; fi; "
        "if [ -n \"$PY\" ]; then \"$PY\" - <<'PY'\n"
        "import os, socket, sys\n"
        "host=os.environ['HOST']; port=int(os.environ['PORT'])\n"
        "try:\n"
        "    s=socket.create_connection((host, port), 5)\n"
        "    s.close()\n"
        "    print('OK')\n"
        "except Exception as e:\n"
        "    print(type(e).__name__ + ': ' + str(e))\n"
        "    sys.exit(1)\n"
        "PY\n"
        "elif command -v nc >/dev/null 2>&1; then nc -z -w 5 \"$HOST\" \"$PORT\" && echo OK; "
        "elif command -v timeout >/dev/null 2>&1; then timeout 5 sh -c '</dev/tcp/'\"$HOST\"'/'\"$PORT\" && echo OK; "
        "else echo NO_TCP_CHECK_TOOL; exit 2; fi"
    )


def verify_workload_online_after_patch(
    ctx: RunContext,
    patch_info: Dict[str, Any],
    patch_result: Dict[str, Any],
) -> Dict[str, Any]:
    snapshot = patch_info.get("workload_config_before") or {}
    if ctx.dry_run:
        return {"status": "dry_run_not_executed", "healthy": True}
    resource = str(patch_info.get("resource") or "")
    name = str(patch_info.get("name") or "")
    health: Dict[str, Any] = {
        "schema": "agentfence-workload-revalidation-v1",
        "status": "unknown",
        "healthy": False,
        "resource": resource,
        "name": name,
        "expected_containers": [c.get("name") for c in snapshot.get("containers") or [] if c.get("name")],
        "requires_pod_recreation": bool(patch_result.get("changed")) and resource in ("deployment", "statefulset", "daemonset"),
    }
    if resource in ("deployment", "statefulset", "daemonset") and name:
        rc, out, err = run_kubectl(
            ctx.kubeconfig,
            ["rollout", "status", f"{resource}/{name}", "-n", ctx.namespace, "--timeout=180s"],
            timeout=210,
        )
        health["rollout_status"] = "complete" if rc == 0 else "failed"
        health["rollout_message"] = (out or err or f"exit {rc}")[:2000]
        if rc != 0:
            health["status"] = "unhealthy"
            health["reason"] = "rollout did not complete"
            return health

    refresh = refresh_run_context_target(ctx)
    health["target_refresh"] = refresh
    pods = workload_pods_for_snapshot(ctx, snapshot)
    running = [p for p in pods if ((p.get("status") or {}).get("phase") == "Running")]
    health["pod_count"] = len(pods)
    health["running_pod_count"] = len(running)
    old_uids = {p.get("uid") for p in snapshot.get("pods_before") or [] if p.get("uid")}
    new_uids = {((p.get("metadata") or {}).get("uid")) for p in running if ((p.get("metadata") or {}).get("uid"))}
    health["pod_recreated"] = bool(new_uids - old_uids) if old_uids else None
    if health["requires_pod_recreation"] and health["pod_recreated"] is False:
        health["status"] = "unhealthy"
        health["reason"] = "pod template changed but no replacement pod was observed"
        return health
    if not running:
        health["status"] = "unhealthy"
        health["reason"] = "no running pods matched the captured workload selector"
        return health

    expected = set(health["expected_containers"])
    container_checks = []
    for pod in running:
        pod_name = ((pod.get("metadata") or {}).get("name")) or ""
        statuses = {
            s.get("name"): bool(s.get("ready"))
            for s in ((pod.get("status") or {}).get("containerStatuses") or [])
        }
        present = set(statuses)
        missing = sorted(expected - present)
        not_ready = sorted(name for name in expected & present if not statuses.get(name))
        container_checks.append(
            {
                "pod": pod_name,
                "missing_containers": missing,
                "not_ready_containers": not_ready,
                "all_expected_ready": not missing and not not_ready,
            }
        )
    health["container_readiness"] = container_checks
    if not all(c["all_expected_ready"] for c in container_checks):
        health["status"] = "unhealthy"
        health["reason"] = "one or more expected containers were missing or not ready"
        return health

    connectivity_results = []
    expectations = snapshot.get("connectivity_expectations") or []
    if expectations:
        pod_name = ((running[0].get("metadata") or {}).get("name")) or ctx.target_pod
        for container in sorted(expected):
            for target in expectations[:6]:
                if str(target.get("protocol") or "TCP").upper() != "TCP":
                    continue
                host = str(target.get("host") or "")
                port = int(target.get("port") or 0)
                if not host or not port:
                    continue
                rc, out = kubectl_exec(
                    ctx.kubeconfig,
                    ctx.namespace,
                    pod_name,
                    container,
                    tcp_connectivity_command(host, port),
                    15,
                )
                status = "reachable" if rc == 0 and "OK" in out else "failed"
                if "NO_TCP_CHECK_TOOL" in out:
                    status = "not_assessed"
                connectivity_results.append(
                    {
                        "pod": pod_name,
                        "container": container,
                        "host": host,
                        "port": port,
                        "source_policy": target.get("source_policy"),
                        "status": status,
                        "output": out[:500],
                    }
                )
    health["connectivity_checks"] = connectivity_results
    if connectivity_results and any(r.get("status") == "failed" for r in connectivity_results):
        health["status"] = "unhealthy"
        health["reason"] = "one or more captured TCP egress expectations failed"
        return health
    health["status"] = "healthy"
    health["healthy"] = True
    return health


def runtime_class_handler(ctx: RunContext, runtime_class_name: Optional[str]) -> Dict[str, Any]:
    if not runtime_class_name:
        return {"runtime_class": None, "handler": "default", "family": "runc"}
    obj = kubectl_get_json(ctx.kubeconfig, ["get", "runtimeclass", str(runtime_class_name)])
    handler = str(((obj or {}).get("handler")) or "")
    name = str(runtime_class_name)
    folded = f"{name} {handler}".lower()
    if "kata" in folded:
        family = "kata"
    elif "gvisor" in folded or "runsc" in folded:
        family = "gvisor"
    else:
        family = "other"
    return {"runtime_class": name, "handler": handler or None, "family": family}


def current_workload_template_spec(ctx: RunContext, patch_info: Dict[str, Any]) -> Dict[str, Any]:
    resource = str(patch_info.get("resource") or "")
    name = str(patch_info.get("name") or "")
    if not resource or not name:
        return {}
    obj = kubectl_get_json(ctx.kubeconfig, ["get", resource, name, "-n", ctx.namespace]) or {}
    if resource == "cronjob":
        return (
            ((obj.get("spec") or {}).get("jobTemplate") or {})
            .get("spec", {})
            .get("template", {})
            .get("spec", {})
        ) or {}
    return ((obj.get("spec") or {}).get("template") or {}).get("spec") or {}


def seccomp_profile_type(value: Optional[Dict[str, Any]]) -> Optional[str]:
    profile = (value or {}).get("seccompProfile") or {}
    return profile.get("type")


def workload_template_spec_for_context(ctx: RunContext) -> Dict[str, Any]:
    workload = discover_workload_reference(ctx)
    wl = workload.get("workload") or {}
    resource = str(wl.get("resource") or "")
    name = str(wl.get("name") or "")
    spec: Dict[str, Any] = {}
    if resource and name:
        spec = current_workload_template_spec(ctx, {"resource": resource, "name": name})
    if not spec:
        pod = load_target_pod_json(ctx) or {}
        spec = (pod.get("spec") or {}) if isinstance(pod, dict) else {}
    return {"workload_reference": workload, "spec": spec}


def seccomp_state_for_context(ctx: RunContext) -> Dict[str, Any]:
    info = workload_template_spec_for_context(ctx)
    spec = info.get("spec") or {}
    workload = info.get("workload_reference") or {}
    runtime = runtime_class_handler(ctx, spec.get("runtimeClassName") or workload.get("runtime_class"))
    pod_profile = seccomp_profile_type(spec.get("securityContext"))
    container_profiles = {}
    for c in (spec.get("containers") or []) + (spec.get("initContainers") or []):
        name = c.get("name")
        if name:
            container_profiles[name] = seccomp_profile_type(c.get("securityContext"))
    target_profile = container_profiles.get(ctx.target_container) or pod_profile
    return {
        "runtime": runtime,
        "pod_seccomp_profile": pod_profile,
        "container_seccomp_profiles": container_profiles,
        "target_container": ctx.target_container,
        "target_effective_seccomp_profile": target_profile,
        "workload": (workload.get("workload") or {}),
    }


def gvisor_runtime_seccomp_verified(state: Dict[str, Any]) -> bool:
    runtime = state.get("runtime") or {}
    return (
        runtime.get("family") == "gvisor"
        and state.get("target_effective_seccomp_profile") == "RuntimeDefault"
    )


def format_seccomp_state_evidence(state: Dict[str, Any]) -> str:
    runtime = state.get("runtime") or {}
    workload = state.get("workload") or {}
    return (
        f"runtime_family={runtime.get('family')} "
        f"runtime_class={runtime.get('runtime_class')} "
        f"handler={runtime.get('handler')} "
        f"workload={workload.get('kind')}/{workload.get('name')} "
        f"target_container={state.get('target_container')} "
        f"target_effective_seccomp={state.get('target_effective_seccomp_profile')} "
        f"pod_seccomp={state.get('pod_seccomp_profile')} "
        f"container_seccomp_profiles={state.get('container_seccomp_profiles')}"
    )


def inspect_container_seccomp_status(ctx: RunContext, snapshot: Dict[str, Any]) -> List[Dict[str, Any]]:
    pods = workload_pods_for_snapshot(ctx, snapshot)
    running = [p for p in pods if ((p.get("status") or {}).get("phase") == "Running")]
    if not running:
        return []
    pod_name = ((running[0].get("metadata") or {}).get("name")) or ctx.target_pod
    containers = [c.get("name") for c in snapshot.get("containers") or [] if c.get("name")]
    rows = []
    for container in containers:
        rc, out = kubectl_exec(
            ctx.kubeconfig,
            ctx.namespace,
            pod_name,
            str(container),
            "grep -E '^(NoNewPrivs|Seccomp|CapBnd):' /proc/self/status 2>/dev/null || true",
            15,
        )
        seccomp_mode = None
        m = re.search(r"^Seccomp:\s*(\d+)", out or "", re.M)
        if m:
            seccomp_mode = int(m.group(1))
        rows.append(
            {
                "pod": pod_name,
                "container": container,
                "status": "captured" if rc == 0 else "failed",
                "seccomp_mode": seccomp_mode,
                "output": out[:1000],
            }
        )
    return rows


def build_runtime_seccomp_diagnostic(
    ctx: RunContext,
    patch_info: Dict[str, Any],
    verification: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    probe_ids = set(patch_info.get("probe_ids") or [])
    if "AgentFence.IDENTITY.SECCOMP_BYPASS_OK" not in probe_ids:
        return {}
    snapshot = patch_info.get("workload_config_before") or {}
    spec = current_workload_template_spec(ctx, patch_info)
    runtime = runtime_class_handler(ctx, spec.get("runtimeClassName") or snapshot.get("runtime_class"))
    expected_containers = [c.get("name") for c in snapshot.get("containers") or [] if c.get("name")]
    container_profiles = {}
    for c in spec.get("containers") or []:
        name = c.get("name")
        if name:
            container_profiles[name] = seccomp_profile_type(c.get("securityContext"))
    process_status = inspect_container_seccomp_status(ctx, snapshot)
    all_expected_configured = bool(expected_containers) and all(
        container_profiles.get(name) == "RuntimeDefault" for name in expected_containers
    )
    process_modes = [row.get("seccomp_mode") for row in process_status if row.get("seccomp_mode") is not None]
    process_active = bool(process_modes) and all(mode == 2 for mode in process_modes)
    unresolved = set((verification or {}).get("still_unsafe_probe_ids") or [])
    gvisor_runtime_verified = runtime.get("family") == "gvisor" and all_expected_configured
    runtime_config_required = (
        "AgentFence.IDENTITY.SECCOMP_BYPASS_OK" in unresolved
        or (
            runtime.get("family") in ("gvisor", "kata")
            and all_expected_configured
            and not process_active
            and not gvisor_runtime_verified
        )
    )
    recommendation = ""
    if runtime.get("family") == "kata":
        recommendation = (
            "Kata accepted the workload seccomp profile but did not expose active process seccomp. "
            "Enable guest seccomp for the Kata runtime, for example set disable_guest_seccomp = false "
            "in the active Kata configuration for this handler, restart the runtime/containerd path, "
            "then recreate the workload pods and rerun AgentFence."
        )
    elif runtime.get("family") == "gvisor":
        recommendation = (
            "gVisor accepted the workload seccomp profile. AgentFence treats the runsc RuntimeClass plus "
            "workload RuntimeDefault profile as the runtime-specific seccomp success condition because "
            "gVisor syscall mediation does not require the sandboxed process to show Linux Seccomp:2."
        )
    elif runtime_config_required:
        recommendation = (
            "The workload seccomp profile is configured but the post-remediation probe did not verify it. "
            "Review runtime support or use a Localhost seccomp profile."
        )
    return {
        "schema": "agentfence-runtime-seccomp-diagnostic-v1",
        "runtime": runtime,
        "pod_seccomp_profile": seccomp_profile_type(spec.get("securityContext")),
        "container_seccomp_profiles": container_profiles,
        "expected_containers": expected_containers,
        "all_expected_containers_configured": all_expected_configured,
        "process_seccomp_status": process_status,
        "process_seccomp_active": process_active,
        "gvisor_runtime_verified": gvisor_runtime_verified,
        "runtime_config_required": runtime_config_required,
        "node_config_changed": False,
        "recommendation": recommendation,
    }


def apply_kata_node_seccomp_runtime_remediation(
    ctx: RunContext,
    patch_info: Dict[str, Any],
    runtime_diag: Dict[str, Any],
) -> Tuple[Dict[str, Any], Optional[List[TestResult]]]:
    record: Dict[str, Any] = {
        "kind": "node_runtime_seccomp",
        "status": "not_applicable",
        "probe_ids": ["AgentFence.IDENTITY.SECCOMP_BYPASS_OK"],
        "runtime": runtime_diag.get("runtime") or {},
        "workload": patch_info.get("workload_reference"),
        "workload_config_before": patch_info.get("workload_config_before"),
        "node_config_changed": False,
        "operator_gate": "requires --allow-node-runtime-remediation",
    }
    if not runtime_diag.get("runtime_config_required"):
        record["reason"] = "runtime seccomp already verified or not required"
        return record, None
    runtime = runtime_diag.get("runtime") or {}
    if runtime.get("family") != "kata":
        record["reason"] = "node runtime remediation is only implemented for Kata guest seccomp"
        return record, None
    if ctx.dry_run:
        record["status"] = "dry_run_planned"
        record["reason"] = "would enable Kata guest seccomp on the target node and recreate the workload"
        return record, None
    if not ctx.allow_node_runtime_remediation:
        record["status"] = "manual_recommendation"
        record["reason"] = (
            "Kata guest seccomp requires node/runtime configuration. Re-run with "
            "--allow-node-runtime-remediation only after confirming other Kata workloads "
            "on the same node can tolerate guest seccomp."
        )
        return record, None

    pod = load_target_pod_json(ctx) or {}
    node = ((pod.get("spec") or {}).get("nodeName")) or ""
    if not node:
        record["status"] = "failed"
        record["reason"] = "unable to determine target node for Kata runtime remediation"
        return record, None
    record["node"] = node

    script = r"""
set -eu
configs="/etc/kata-containers/configuration-qemu.toml /etc/kata-containers/configuration.toml /usr/share/defaults/kata-containers/configuration-qemu.toml /usr/share/defaults/kata-containers/configuration.toml /opt/kata/share/defaults/kata-containers/runtimes/qemu/configuration-qemu.toml /opt/kata/share/defaults/kata-containers/configuration-qemu.toml /opt/kata/share/defaults/kata-containers/configuration.toml"
chosen=""
for f in $configs; do
  if [ -f "$f" ]; then chosen="$f"; break; fi
done
if [ -z "$chosen" ]; then
  echo "NO_KATA_CONFIG_FOUND" >&2
  exit 3
fi
cp "$chosen" "$chosen.agentfence.bak.$(date +%Y%m%d%H%M%S)"
if grep -q '^[[:space:]]*disable_guest_seccomp[[:space:]]*=' "$chosen"; then
  sed -i 's/^[[:space:]]*disable_guest_seccomp[[:space:]]*=.*/disable_guest_seccomp = false/' "$chosen"
else
  printf '\n# Added by AgentFence after operator-approved remediation\ndisable_guest_seccomp = false\n' >> "$chosen"
fi
if command -v systemctl >/dev/null 2>&1; then
  systemctl restart containerd
else
  service containerd restart
fi
echo "KATA_SECCOMP_CONFIGURED $chosen"
"""
    debug_custom = {
        "resources": {
            "requests": {"cpu": "25m", "memory": "64Mi"},
            "limits": {"cpu": "100m", "memory": "128Mi"},
        }
    }
    custom_path = ""
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json", delete=False) as f:
            json.dump(debug_custom, f)
            custom_path = f.name
        rc, out, err = run_kubectl(
            ctx.kubeconfig,
            [
                "debug",
                f"node/{node}",
                "-n",
                ctx.namespace,
                "--image=busybox:1.36",
                "--profile=sysadmin",
                f"--custom={custom_path}",
                "--",
                "chroot",
                "/host",
                "sh",
                "-c",
                script,
            ],
            timeout=300,
        )
    finally:
        if custom_path:
            try:
                os.unlink(custom_path)
            except OSError:
                pass
    debug_pod = ""
    m = re.search(r"Creating debugging pod\s+([^\s]+)", out or "")
    if m:
        debug_pod = m.group(1)
    debug_phase = ""
    debug_logs = ""
    if debug_pod:
        deadline = time.time() + 180
        while time.time() < deadline:
            prc, pout, _ = run_kubectl(
                ctx.kubeconfig,
                ["get", "pod", debug_pod, "-n", ctx.namespace, "-o", "jsonpath={.status.phase}"],
                timeout=15,
            )
            debug_phase = (pout or "").strip() if prc == 0 else debug_phase
            if debug_phase in ("Succeeded", "Failed"):
                break
            time.sleep(3)
        _, debug_logs, _ = run_kubectl(
            ctx.kubeconfig,
            ["logs", debug_pod, "-n", ctx.namespace, "--tail=200"],
            timeout=30,
        )
        run_kubectl(
            ctx.kubeconfig,
            ["delete", "pod", debug_pod, "-n", ctx.namespace, "--ignore-not-found"],
            timeout=30,
        )
    marker_seen = "KATA_SECCOMP_CONFIGURED" in (debug_logs or out or "")
    record["node_runtime_command"] = {
        "status": "complete" if rc == 0 and marker_seen else "failed",
        "exit_code": rc,
        "debug_pod": debug_pod,
        "debug_pod_phase": debug_phase,
        "stdout": (out or "")[-3000:],
        "stderr": (err or "")[-3000:],
        "logs": (debug_logs or "")[-3000:],
    }
    if rc != 0 or not marker_seen:
        record["status"] = "failed"
        record["reason"] = (
            "failed to enable Kata guest seccomp through kubectl node debug"
            if rc != 0
            else "node debug pod completed without the Kata seccomp success marker"
        )
        return record, None
    record["node_config_changed"] = True

    resource = str(patch_info.get("resource") or "")
    name = str(patch_info.get("name") or "")
    if resource in ("deployment", "statefulset", "daemonset") and name:
        rc2, out2, err2 = run_kubectl(
            ctx.kubeconfig,
            ["rollout", "restart", f"{resource}/{name}", "-n", ctx.namespace],
            timeout=90,
        )
        record["workload_recreate_command"] = {
            "status": "started" if rc2 == 0 else "failed",
            "exit_code": rc2,
            "output": (out2 or err2 or "")[:2000],
        }
        if rc2 != 0:
            record["status"] = "failed"
            record["reason"] = "node config changed, but workload recreation failed to start"
            return record, None
    else:
        record["status"] = "manual_recommendation"
        record["reason"] = "node config changed, but workload controller type requires manual pod recreation"
        return record, None

    health = verify_workload_online_after_patch(
        ctx,
        patch_info,
        {"status": "applied", "changed": True},
    )
    record["workload_revalidation"] = health
    if not health.get("healthy"):
        record["status"] = "failed"
        record["reason"] = health.get("reason") or "workload did not become healthy after runtime remediation"
        return record, run_all_probes(ctx)

    after_results = run_all_probes(ctx)
    after_unsafe = unsafe_probe_ids(after_results)
    runtime_after = build_runtime_seccomp_diagnostic(
        ctx,
        patch_info,
        {"still_unsafe_probe_ids": sorted(after_unsafe & {"AgentFence.IDENTITY.SECCOMP_BYPASS_OK"})},
    )
    record["runtime_seccomp_diagnostic_after"] = runtime_after
    if (
        "AgentFence.IDENTITY.SECCOMP_BYPASS_OK" not in after_unsafe
        or runtime_after.get("process_seccomp_active")
    ):
        record["status"] = "applied"
        record["resolved_probe_ids"] = ["AgentFence.IDENTITY.SECCOMP_BYPASS_OK"]
    else:
        record["status"] = "applied_with_verification_warning"
        record["resolved_probe_ids"] = []
        record["verification_warnings"] = [
            "Kata runtime config was changed and workload was recreated, but process-level seccomp still did not verify."
        ]
    return record, after_results


NODE_SYSCTL_HARDENING: Dict[str, Dict[str, str]] = {
    "AgentFence.KERNEL.DMESG_VISIBLE": {
        "sysctl": "kernel.dmesg_restrict",
        "value": "1",
        "title": "Restrict kernel dmesg",
    },
    "AgentFence.KERNEL.PERF_EVENT_OPEN_REACHABLE": {
        "sysctl": "kernel.perf_event_paranoid",
        "value": "4",
        "title": "Restrict perf_event_open",
    },
    "AgentFence.KERNEL.BPF_PROG_LOAD_REACHABLE": {
        "sysctl": "kernel.unprivileged_bpf_disabled",
        "value": "2",
        "title": "Disable unprivileged BPF",
    },
    "AgentFence.KERNEL.USERFAULTFD_REACHABLE": {
        "sysctl": "vm.unprivileged_userfaultfd",
        "value": "0",
        "title": "Restrict unprivileged userfaultfd",
    },
}


def audit_node_runtime_hardening(ctx: RunContext) -> Dict[str, Any]:
    """Read target-node hardening state without changing node or runtime config."""
    audit: Dict[str, Any] = {
        "kind": "node_runtime_hardening_preflight",
        "status": "unknown",
        "node": "",
        "runtime": {},
        "sysctls": NODE_SYSCTL_HARDENING,
        "sysctl_states": {},
        "desired_values_met": {},
        "kata_guest_seccomp": {},
        "changes_needed": True,
        "change_reasons": [],
    }
    try:
        pod = load_target_pod_json(ctx) or {}
    except Exception as e:
        audit["reason"] = f"unable to load target pod: {type(e).__name__}: {e}"
        return audit
    spec = (pod.get("spec") or {})
    node = str(spec.get("nodeName") or "")
    audit["node"] = node
    runtime = runtime_class_handler(ctx, spec.get("runtimeClassName"))
    audit["runtime"] = runtime
    if not node:
        audit["reason"] = "unable to determine target node"
        return audit

    sysctl_commands = []
    for cfg in NODE_SYSCTL_HARDENING.values():
        key = cfg["sysctl"]
        sysctl_commands.append(
            f"echo AGENTFENCE_AUDIT_SYSCTL {shlex.quote(key)} value=$(sysctl -n {shlex.quote(key)} 2>/dev/null || true)"
        )
    kata_commands = r"""
configs="/etc/kata-containers/configuration-qemu.toml /etc/kata-containers/configuration.toml /usr/share/defaults/kata-containers/configuration-qemu.toml /usr/share/defaults/kata-containers/configuration.toml /opt/kata/share/defaults/kata-containers/runtimes/qemu/configuration-qemu.toml /opt/kata/share/defaults/kata-containers/configuration-qemu.toml /opt/kata/share/defaults/kata-containers/configuration.toml"
chosen=""
for f in $configs; do
  if [ -f "$f" ]; then chosen="$f"; break; fi
done
if [ -n "$chosen" ]; then
  value="$(sed -n 's/^[[:space:]]*disable_guest_seccomp[[:space:]]*=[[:space:]]*//p' "$chosen" | tail -1 | tr -d ' "')" || value=""
  echo "AGENTFENCE_AUDIT_KATA_CONFIG path=$chosen disable_guest_seccomp=${value:-unset}"
else
  echo "AGENTFENCE_AUDIT_KATA_CONFIG path= disable_guest_seccomp=missing"
fi
"""
    script = "set -eu\n" + "\n".join(sysctl_commands) + "\n" + kata_commands + "\necho AGENTFENCE_AUDIT_COMPLETE\n"
    debug_custom = {
        "resources": {
            "requests": {"cpu": "25m", "memory": "64Mi"},
            "limits": {"cpu": "100m", "memory": "128Mi"},
        }
    }
    custom_path = ""
    rc = 1
    out = ""
    err = ""
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json", delete=False) as f:
            json.dump(debug_custom, f)
            custom_path = f.name
        rc, out, err = run_kubectl(
            ctx.kubeconfig,
            [
                "debug",
                f"node/{node}",
                "-n",
                ctx.namespace,
                "--image=busybox:1.36",
                "--profile=sysadmin",
                f"--custom={custom_path}",
                "--",
                "chroot",
                "/host",
                "sh",
                "-c",
                script,
            ],
            timeout=120,
        )
    finally:
        if custom_path:
            try:
                os.unlink(custom_path)
            except OSError:
                pass

    debug_pod = ""
    m = re.search(r"Creating debugging pod\s+([^\s]+)", out or "")
    if m:
        debug_pod = m.group(1)
    debug_phase = ""
    debug_logs = ""
    if debug_pod:
        deadline = time.time() + 90
        while time.time() < deadline:
            prc, pout, _ = run_kubectl(
                ctx.kubeconfig,
                ["get", "pod", debug_pod, "-n", ctx.namespace, "-o", "jsonpath={.status.phase}"],
                timeout=15,
            )
            debug_phase = (pout or "").strip() if prc == 0 else debug_phase
            if debug_phase in ("Succeeded", "Failed"):
                break
            time.sleep(2)
        _, debug_logs, _ = run_kubectl(
            ctx.kubeconfig,
            ["logs", debug_pod, "-n", ctx.namespace, "--tail=200"],
            timeout=30,
        )
        run_kubectl(
            ctx.kubeconfig,
            ["delete", "pod", debug_pod, "-n", ctx.namespace, "--ignore-not-found"],
            timeout=30,
        )
    combined = debug_logs or out or ""
    audit["node_runtime_command"] = {
        "status": "complete" if rc == 0 and "AGENTFENCE_AUDIT_COMPLETE" in combined else "failed",
        "exit_code": rc,
        "debug_pod": debug_pod,
        "debug_pod_phase": debug_phase,
        "stdout": (out or "")[-2000:],
        "stderr": (err or "")[-2000:],
        "logs": (debug_logs or "")[-2000:],
    }
    if rc != 0 or "AGENTFENCE_AUDIT_COMPLETE" not in combined:
        audit["reason"] = "unable to complete node hardening preflight audit"
        return audit

    sysctl_states: Dict[str, Dict[str, str]] = {}
    for line in combined.splitlines():
        m_state = re.match(r"AGENTFENCE_AUDIT_SYSCTL\s+(\S+)\s+value=(\S*)", line.strip())
        if m_state:
            sysctl_states[m_state.group(1)] = {"current": m_state.group(2)}
            continue
        m_kata = re.match(r"AGENTFENCE_AUDIT_KATA_CONFIG\s+path=(\S*)\s+disable_guest_seccomp=(\S*)", line.strip())
        if m_kata:
            audit["kata_guest_seccomp"] = {
                "path": m_kata.group(1),
                "disable_guest_seccomp": m_kata.group(2),
            }
    desired_met = {
        pid: sysctl_states.get(cfg["sysctl"], {}).get("current") == cfg["value"]
        for pid, cfg in NODE_SYSCTL_HARDENING.items()
    }
    reasons = [
        f"{cfg['sysctl']} should be {cfg['value']} but is {sysctl_states.get(cfg['sysctl'], {}).get('current', 'unreadable')}"
        for pid, cfg in NODE_SYSCTL_HARDENING.items()
        if not desired_met.get(pid)
    ]
    if runtime.get("family") == "kata":
        kata_value = str((audit.get("kata_guest_seccomp") or {}).get("disable_guest_seccomp") or "")
        if kata_value.lower() != "false":
            reasons.append("Kata guest seccomp is not enabled in the active runtime configuration")
    audit["sysctl_states"] = sysctl_states
    audit["desired_values_met"] = desired_met
    audit["change_reasons"] = reasons
    audit["changes_needed"] = bool(reasons)
    audit["status"] = "changes_needed" if reasons else "already_hardened"
    return audit


def apply_node_sysctl_hardening(
    ctx: RunContext,
    baseline_results: Optional[List[TestResult]],
) -> Tuple[List[Dict[str, Any]], Optional[List[TestResult]]]:
    if not ctx.allow_node_runtime_remediation or ctx.dry_run or not baseline_results:
        return [], None
    unsafe = unsafe_probe_ids(baseline_results)
    targets = dict(NODE_SYSCTL_HARDENING)
    unsafe_targets = {pid: cfg for pid, cfg in targets.items() if pid in unsafe}
    preflight = audit_node_runtime_hardening(ctx)
    sysctl_changes_needed = any(
        not bool((preflight.get("desired_values_met") or {}).get(pid))
        for pid in targets
    )
    if preflight.get("status") == "already_hardened" and not preflight.get("changes_needed"):
        return [
            {
                "kind": "node_sysctl_hardening",
                "status": "not_applicable",
                "reason": "node hardening preflight found all desired sysctl values already enabled; no node changes applied",
                "node": preflight.get("node"),
                "probe_ids": sorted(targets),
                "unsafe_probe_ids": sorted(unsafe_targets),
                "sysctls": targets,
                "sysctl_states": preflight.get("sysctl_states") or {},
                "desired_values_met": preflight.get("desired_values_met") or {},
                "node_config_changed": False,
                "node_config_already_hardened": True,
                "preflight": preflight,
            }
        ], None
    if not sysctl_changes_needed:
        return [
            {
                "kind": "node_sysctl_hardening",
                "status": "not_applicable",
                "reason": "node hardening preflight found no sysctl changes to apply",
                "node": preflight.get("node"),
                "probe_ids": sorted(targets),
                "unsafe_probe_ids": sorted(unsafe_targets),
                "sysctls": targets,
                "sysctl_states": preflight.get("sysctl_states") or {},
                "desired_values_met": preflight.get("desired_values_met") or {},
                "node_config_changed": False,
                "node_config_already_hardened": True,
                "preflight": preflight,
            }
        ], None
    if preflight.get("status") not in ("changes_needed", "unknown"):
        return [
            {
                "kind": "node_sysctl_hardening",
                "status": "manual_recommendation",
                "reason": "node hardening preflight did not identify an applicable automatic sysctl change",
                "node": preflight.get("node"),
                "probe_ids": sorted(targets),
                "unsafe_probe_ids": sorted(unsafe_targets),
                "node_config_changed": False,
                "preflight": preflight,
            }
        ], None
    pod = load_target_pod_json(ctx) or {}
    node = ((pod.get("spec") or {}).get("nodeName")) or ""
    if not node:
        return [
            {
                "kind": "node_sysctl_hardening",
                "status": "failed",
                "reason": "unable to determine target node",
                "probe_ids": sorted(targets),
                "unsafe_probe_ids": sorted(unsafe_targets),
            }
        ], None

    commands = []
    for cfg in targets.values():
        key = cfg["sysctl"]
        value = cfg["value"]
        safe_name = key.replace(".", "_")
        commands.append(f"before_{safe_name}=$(sysctl -n {shlex.quote(key)} 2>/dev/null || true)")
        commands.append(f"sysctl -w {shlex.quote(key)}={shlex.quote(value)}")
        commands.append(f"after_{safe_name}=$(sysctl -n {shlex.quote(key)} 2>/dev/null || true)")
        commands.append(f"echo AGENTFENCE_SYSCTL {shlex.quote(key)} before=${{before_{safe_name}}} after=${{after_{safe_name}}}")
    script = "set -eu\n" + "\n".join(commands) + "\necho AGENTFENCE_SYSCTL_CONFIGURED\n"

    debug_custom = {
        "resources": {
            "requests": {"cpu": "25m", "memory": "64Mi"},
            "limits": {"cpu": "100m", "memory": "128Mi"},
        }
    }
    custom_path = ""
    rc = 1
    out = ""
    err = ""
    try:
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json", delete=False) as f:
            json.dump(debug_custom, f)
            custom_path = f.name
        rc, out, err = run_kubectl(
            ctx.kubeconfig,
            [
                "debug",
                f"node/{node}",
                "-n",
                ctx.namespace,
                "--image=busybox:1.36",
                "--profile=sysadmin",
                f"--custom={custom_path}",
                "--",
                "chroot",
                "/host",
                "sh",
                "-c",
                script,
            ],
            timeout=180,
        )
    finally:
        if custom_path:
            try:
                os.unlink(custom_path)
            except OSError:
                pass

    debug_pod = ""
    m = re.search(r"Creating debugging pod\s+([^\s]+)", out or "")
    if m:
        debug_pod = m.group(1)
    debug_phase = ""
    debug_logs = ""
    if debug_pod:
        deadline = time.time() + 120
        while time.time() < deadline:
            prc, pout, _ = run_kubectl(
                ctx.kubeconfig,
                ["get", "pod", debug_pod, "-n", ctx.namespace, "-o", "jsonpath={.status.phase}"],
                timeout=15,
            )
            debug_phase = (pout or "").strip() if prc == 0 else debug_phase
            if debug_phase in ("Succeeded", "Failed"):
                break
            time.sleep(3)
        _, debug_logs, _ = run_kubectl(
            ctx.kubeconfig,
            ["logs", debug_pod, "-n", ctx.namespace, "--tail=200"],
            timeout=30,
        )
        run_kubectl(
            ctx.kubeconfig,
            ["delete", "pod", debug_pod, "-n", ctx.namespace, "--ignore-not-found"],
            timeout=30,
        )
    marker_seen = "AGENTFENCE_SYSCTL_CONFIGURED" in (debug_logs or out or "")
    sysctl_states: Dict[str, Dict[str, str]] = {}
    for line in (debug_logs or out or "").splitlines():
        m_state = re.match(r"AGENTFENCE_SYSCTL\s+(\S+)\s+before=(\S*)\s+after=(\S*)", line.strip())
        if not m_state:
            continue
        sysctl_states[m_state.group(1)] = {
            "before": m_state.group(2),
            "after": m_state.group(3),
        }
    desired_met = {
        pid: sysctl_states.get(cfg["sysctl"], {}).get("after") == cfg["value"]
        for pid, cfg in targets.items()
    }
    all_desired = bool(desired_met) and all(desired_met.values())
    changed_values = [
        cfg["sysctl"]
        for cfg in targets.values()
        if sysctl_states.get(cfg["sysctl"], {}).get("before")
        != sysctl_states.get(cfg["sysctl"], {}).get("after")
    ]
    record: Dict[str, Any] = {
        "kind": "node_sysctl_hardening",
        "node": node,
        "probe_ids": sorted(targets),
        "unsafe_probe_ids": sorted(unsafe_targets),
        "sysctls": targets,
        "sysctl_states": sysctl_states,
        "desired_values_met": desired_met,
        "status": "applied" if rc == 0 and marker_seen and all_desired else "failed",
        "node_config_changed": bool(changed_values),
        "node_config_already_hardened": bool(rc == 0 and marker_seen and all_desired and not changed_values),
        "node_runtime_command": {
            "status": "complete" if rc == 0 and marker_seen and all_desired else "failed",
            "exit_code": rc,
            "debug_pod": debug_pod,
            "debug_pod_phase": debug_phase,
            "stdout": (out or "")[-3000:],
            "stderr": (err or "")[-3000:],
            "logs": (debug_logs or "")[-3000:],
        },
    }
    if record["status"] != "applied":
        record["reason"] = "node sysctl hardening did not complete"
        return [record], None
    after_results = run_all_probes(ctx)
    before_unsafe = unsafe
    after_unsafe = unsafe_probe_ids(after_results)
    record["resolved_probe_ids"] = sorted((before_unsafe & set(unsafe_targets)) - after_unsafe)
    record["still_unsafe_probe_ids"] = sorted((before_unsafe & set(unsafe_targets)) & after_unsafe)
    if record["still_unsafe_probe_ids"]:
        record["verification_warnings"] = [
            "Node sysctl hardening is at the desired value, but one or more related probes remain unsafe; "
            "the remaining evidence is likely runtime-specific or requires a non-sysctl control."
        ]
    return [record], after_results


def build_workload_hardening_patch(
    ctx: RunContext,
    remediation_plan: Dict[str, Any],
) -> Tuple[Optional[Dict[str, Any]], Dict[str, Any]]:
    patches, info = build_workload_hardening_patches(ctx, remediation_plan)
    if not patches:
        return None, info
    first = dict(patches[0])
    return first.pop("patch"), first


def build_workload_hardening_patches(
    ctx: RunContext,
    remediation_plan: Dict[str, Any],
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    actionable = remediation_plan.get("actionable_items") or []
    workload = discover_workload_reference(ctx)
    wl = workload.get("workload") or {}
    resource = wl.get("resource")
    name = wl.get("name")
    if not resource or not name:
        return [], {"reason": "no supported controller workload discovered", "workload_reference": workload}
    workload_json = kubectl_get_json(ctx.kubeconfig, ["get", str(resource), str(name), "-n", ctx.namespace])
    if not workload_json:
        return [], {"reason": "unable to load controller workload", "workload_reference": workload}

    if resource == "cronjob":
        pod_spec = (
            ((workload_json.get("spec") or {}).get("jobTemplate") or {})
            .get("spec", {})
            .get("template", {})
            .get("spec", {})
        )
    else:
        pod_spec = ((workload_json.get("spec") or {}).get("template") or {}).get("spec") or {}
    container_names = [c.get("name") for c in (pod_spec.get("containers") or []) if c.get("name")]
    init_container_names = [c.get("name") for c in (pod_spec.get("initContainers") or []) if c.get("name")]
    if not container_names and not init_container_names:
        return [], {"reason": "workload has no named containers", "workload_reference": workload}

    workload_snapshot = capture_workload_config_before_patch(ctx, workload, workload_json, pod_spec)
    allows_security_context, compatibility_reason = workload_allows_auto_security_context(pod_spec)
    allows_sa_token, sa_token_reason = workload_allows_auto_service_account_token(ctx, pod_spec)
    # Some recipes are mechanically patchable but not universally safe. The app
    # uses workload shape and Kubernetes rollout validation, not sandbox/runtime
    # names, to decide what can be attempted automatically.
    unsafe_blind_auto = {"AgentFence.ID.RUN_AS_UID_ZERO"}
    guarded_hybrid_artifacts = {
        "kernel_surface_hardening_patch",
        "namespace_isolation_patch",
        "readonly_rootfs_patch",
        "device_access_review_patch",
    }
    conservative_multi_container_probe_ids = {
        "AgentFence.IDENTITY.SECCOMP_BYPASS_OK",
        "AgentFence.IDENTITY.NO_NEW_PRIVS_BYPASS_OK",
        "AgentFence.IDENTITY.CAP_BOUNDING_PERMISSIVE",
        "AgentFence.DEVICE.RAW_SOCKET_USABLE",
    }
    auto_items = [
        i
        for i in actionable
        if (
            i.get("probe_id") not in unsafe_blind_auto
            and (
                allows_security_context
                or i.get("probe_id") in conservative_multi_container_probe_ids
            )
            and (
                i.get("action_type") == "auto_fix"
                or (
                    i.get("action_type") == "hybrid"
                    and ((i.get("dry_run_artifact") or {}).get("artifact_kind") in guarded_hybrid_artifacts)
                )
            )
        )
    ]
    probe_ids = {str(i.get("probe_id")) for i in auto_items}
    artifacts = {
        ((i.get("dry_run_artifact") or {}).get("artifact_kind") or "")
        for i in auto_items
    }

    base_info: Dict[str, Any] = {
        "workload_reference": workload,
        "resource": str(resource),
        "name": str(name),
        "workload_config_before": workload_snapshot,
        "compatibility": {
            "auto_security_context": allows_security_context,
            "reason": compatibility_reason,
            "auto_service_account_token": allows_sa_token,
            "service_account_reason": sa_token_reason,
        },
    }
    stages: List[Dict[str, Any]] = []

    def selected_container_names() -> List[str]:
        if allows_security_context:
            return list(container_names)
        if ctx.target_container in container_names:
            return [ctx.target_container]
        return list(container_names[:1])

    def container_patch(sc: Dict[str, Any], names: List[str]) -> Dict[str, Any]:
        pod_patch: Dict[str, Any] = {}
        if names:
            pod_patch["containers"] = [
                {"name": cname, "securityContext": dict(sc)}
                for cname in names
            ]
        if allows_security_context and init_container_names:
            pod_patch["initContainers"] = [
                {"name": cname, "securityContext": dict(sc)}
                for cname in init_container_names
            ]
        return pod_patch

    def add_stage(
        stage_name: str,
        pod_spec_patch: Dict[str, Any],
        changed_for: Iterable[str],
        artifact_kinds: Iterable[str],
        risk_level: str = "guarded",
    ) -> None:
        probe_list = sorted({str(x) for x in changed_for if x})
        if not pod_spec_patch or not probe_list:
            return
        info = {
            **base_info,
            "stage": stage_name,
            "risk_level": risk_level,
            "probe_ids": probe_list,
            "artifact_kinds": sorted({str(a) for a in artifact_kinds if a}),
            "patch": workload_template_patch(str(resource), pod_spec_patch),
        }
        stages.append(info)

    seccomp_probe_ids = probe_ids & {"AgentFence.IDENTITY.SECCOMP_BYPASS_OK"}
    kernel_surface_probe_ids = probe_ids & {
        "AgentFence.KERNEL.KEXEC_REACHABLE",
        "AgentFence.KERNEL.INIT_MODULE_REACHABLE",
        "AgentFence.KERNEL.BPF_PROG_LOAD_REACHABLE",
        "AgentFence.KERNEL.DMESG_VISIBLE",
        "AgentFence.FS.KCORE_READABLE",
    }
    if seccomp_probe_ids:
        seccomp_container_sc = {"seccompProfile": {"type": "RuntimeDefault"}}
        seccomp_patch = {
            "securityContext": {"seccompProfile": {"type": "RuntimeDefault"}},
            **container_patch(seccomp_container_sc, list(container_names)),
        }
        add_stage(
            "seccomp_runtime_default",
            seccomp_patch,
            seccomp_probe_ids,
            {"pod_security_context_patch"},
            "low",
        )

    nnp_probe_ids = probe_ids & {"AgentFence.IDENTITY.NO_NEW_PRIVS_BYPASS_OK"}
    if nnp_probe_ids:
        add_stage(
            "no_new_privileges",
            container_patch(
                {"allowPrivilegeEscalation": False},
                selected_container_names(),
            ),
            nnp_probe_ids,
            {"pod_security_context_patch"},
            "guarded",
        )

    capability_probe_ids = probe_ids & {
        "AgentFence.DEVICE.RAW_SOCKET_USABLE",
        "AgentFence.IDENTITY.CAP_BOUNDING_PERMISSIVE",
        "AgentFence.DEVICE.TUN_TAP_PRESENT",
        "AgentFence.DEVICE.KVM_PRESENT",
        "AgentFence.DEVICE.USB_PRESENT",
        "AgentFence.FS.HOST_DEVICES_VISIBLE",
    }
    if capability_probe_ids:
        cap_sc: Dict[str, Any] = {"privileged": False}
        merge_capabilities_drop_all(cap_sc)
        add_stage(
            "capability_minimization",
            container_patch(cap_sc, selected_container_names()),
            capability_probe_ids,
            {"capabilities_drop_patch", "device_access_review_patch"},
            "guarded",
        )
    if kernel_surface_probe_ids and allows_security_context:
        kernel_sc: Dict[str, Any] = {
            "seccompProfile": {"type": "RuntimeDefault"},
            "privileged": False,
        }
        merge_capabilities_drop_all(kernel_sc)
        add_stage(
            "kernel_surface_hardening",
            {
                "securityContext": {"seccompProfile": {"type": "RuntimeDefault"}},
                **container_patch(kernel_sc, list(container_names)),
            },
            kernel_surface_probe_ids,
            {"kernel_surface_hardening_patch"},
            "guarded",
        )

    readonly_probe_ids = probe_ids & {"AgentFence.ID.ROOTFS_WRITE_OK"}
    if readonly_probe_ids and allows_security_context:
        add_stage(
            "readonly_root_filesystem",
            container_patch(
                {"readOnlyRootFilesystem": True},
                list(container_names),
            ),
            readonly_probe_ids,
            {"readonly_rootfs_patch"},
            "high_compatibility_risk",
        )

    if (
        ("service_account_patch" in artifacts or "service_account_and_egress_patch" in artifacts)
        and allows_sa_token
    ):
        sa_probe_ids = probe_ids & {
            "AgentFence.ID.SA_TOKEN_READABLE",
            "AgentFence.NET.APISERVER_DIRECT_REACHABLE",
        }
        add_stage(
            "disable_service_account_token_automount",
            {"automountServiceAccountToken": False},
            sa_probe_ids,
            {"service_account_patch", "service_account_and_egress_patch"},
            "guarded",
        )

    if "namespace_isolation_patch" in artifacts:
        ns_probe_ids = probe_ids & {
            "AgentFence.NS.PID_NS_SHARES_HOST",
            "AgentFence.NS.IPC_NS_SHARES_HOST",
            "AgentFence.NS.NET_NS_SHARES_HOST",
            "AgentFence.NS.UTS_NS_SHARES_HOST",
            "AgentFence.FS.HOST_PROC_VISIBLE",
            "AgentFence.FS.HOST_FS_REACHABLE_VIA_PROC",
        }
        if ns_probe_ids and allows_security_context:
            add_stage(
                "namespace_isolation",
                {"hostPID": False, "hostIPC": False, "hostNetwork": False},
                ns_probe_ids,
                {"namespace_isolation_patch"},
                "guarded",
            )

    if not stages:
        return [], {
            "reason": "no supported workload patch for current findings",
            **base_info,
        }

    return stages, {**base_info, "stage_count": len(stages)}


def kubectl_patch_workload(
    ctx: RunContext,
    resource: str,
    name: str,
    patch: Dict[str, Any],
    dry_run: bool,
) -> Dict[str, Any]:
    patch_json = json.dumps(patch, separators=(",", ":"))
    base = [
        "patch",
        resource,
        name,
        "-n",
        ctx.namespace,
        "--type=strategic",
        "-p",
        patch_json,
    ]
    rc, out, err = run_kubectl(ctx.kubeconfig, base + ["--dry-run=server"], timeout=90)
    if rc != 0:
        return {"status": "failed", "phase": "dry_run_server", "error": (err or out or f"exit {rc}")[:2000]}
    if dry_run:
        return {"status": "dry_run_planned", "server_dry_run": (out or "").strip()[:1000]}
    rc, out, err = run_kubectl(ctx.kubeconfig, base, timeout=120)
    if rc != 0:
        return {"status": "failed", "phase": "apply", "error": (err or out or f"exit {rc}")[:2000]}
    apply_output = (out or "").strip()[:1000]
    changed = "(no change)" not in apply_output and " unchanged" not in apply_output
    rollout_status = "not_applicable"
    rollout_message = ""
    if resource in ("deployment", "statefulset", "daemonset"):
        rc2, out2, err2 = run_kubectl(
            ctx.kubeconfig,
            ["rollout", "status", f"{resource}/{name}", "-n", ctx.namespace, "--timeout=120s"],
            timeout=150,
        )
        rollout_status = "complete" if rc2 == 0 else "warning"
        rollout_message = (out2 or err2 or f"exit {rc2}")[:2000]
        if rc2 != 0:
            undo_rc, undo_out, undo_err = run_kubectl(
                ctx.kubeconfig,
                ["rollout", "undo", f"{resource}/{name}", "-n", ctx.namespace],
                timeout=60,
            )
            return {
                "status": "failed",
                "phase": "rollout",
                "kubectl": (out or "").strip()[:1000],
                "rollout_status": rollout_status,
                "rollout_message": rollout_message,
                "rollback_attempted": True,
                "rollback_status": "started" if undo_rc == 0 else "failed",
                "rollback_message": (undo_out or undo_err or f"exit {undo_rc}")[:2000],
            }
    return {
        "status": "applied",
        "kubectl": apply_output,
        "changed": changed,
        "rollout_status": rollout_status,
        "rollout_message": rollout_message,
    }


def node_internal_ip(ctx: RunContext, node_name: Optional[str]) -> Optional[str]:
    if not node_name:
        return None
    node = kubectl_get_json(ctx.kubeconfig, ["get", "node", node_name])
    for addr in ((node or {}).get("status") or {}).get("addresses") or []:
        if addr.get("type") == "InternalIP" and addr.get("address"):
            return str(addr["address"])
    return None


def kubernetes_service_ip(ctx: RunContext) -> Optional[str]:
    svc = kubectl_get_json(ctx.kubeconfig, ["get", "service", "kubernetes", "-n", "default"])
    ip = ((svc or {}).get("spec") or {}).get("clusterIP")
    return str(ip) if ip and ip != "None" else None


def reapplyable_manifest(obj: Dict[str, Any]) -> Dict[str, Any]:
    data = json.loads(json.dumps(obj))
    _strip_managed_fields(data)
    metadata = data.get("metadata") or {}
    for key in (
        "creationTimestamp",
        "deletionGracePeriodSeconds",
        "deletionTimestamp",
        "finalizers",
        "generation",
        "resourceVersion",
        "selfLink",
        "uid",
    ):
        metadata.pop(key, None)
    annotations = metadata.get("annotations") or {}
    annotations.pop("kubectl.kubernetes.io/last-applied-configuration", None)
    if annotations:
        metadata["annotations"] = annotations
    else:
        metadata.pop("annotations", None)
    data.pop("status", None)
    return data


def manifest_resource_ref(manifest: Dict[str, Any]) -> Tuple[str, str, str]:
    metadata = manifest.get("metadata") or {}
    return (
        str(manifest.get("kind") or ""),
        str(metadata.get("name") or ""),
        str(metadata.get("namespace") or ""),
    )


def apply_json_manifest(ctx: RunContext, manifest: Dict[str, Any], dry_run: bool) -> Dict[str, Any]:
    kind, name, namespace = manifest_resource_ref(manifest)
    previous_manifest = None
    if kind and name:
        get_args = ["get", kind, name]
        if namespace:
            get_args += ["-n", namespace]
        previous = kubectl_get_json(ctx.kubeconfig, get_args)
        if isinstance(previous, dict) and previous.get("kind"):
            previous_manifest = reapplyable_manifest(previous)

    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json", delete=False) as tmp:
        json.dump(manifest, tmp, indent=2)
        tmp_path = tmp.name
    try:
        rc, out, err = run_kubectl(ctx.kubeconfig, ["apply", "--dry-run=server", "-f", tmp_path], timeout=90)
        if rc != 0:
            return {"status": "failed", "phase": "dry_run_server", "error": (err or out or f"exit {rc}")[:2000]}
        if dry_run:
            return {"status": "dry_run_planned", "server_dry_run": (out or "").strip()[:1000]}
        rc, out, err = run_kubectl(ctx.kubeconfig, ["apply", "-f", tmp_path], timeout=120)
        if rc != 0:
            return {"status": "failed", "phase": "apply", "error": (err or out or f"exit {rc}")[:2000]}
        apply_output = (out or "").strip()[:1000]
        operation = "unknown"
        if " created" in apply_output:
            operation = "created"
        elif " configured" in apply_output:
            operation = "configured"
        elif " unchanged" in apply_output:
            operation = "unchanged"
        result = {
            "status": "applied",
            "kubectl": apply_output,
            "apply_operation": operation,
            "changed": operation != "unchanged",
        }
        if previous_manifest:
            result["previous_manifest"] = previous_manifest
        return result
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def pod_selector_matches_labels(selector: Dict[str, Any], labels: Dict[str, str]) -> bool:
    match_labels = selector.get("matchLabels") or {}
    if not all(labels.get(str(k)) == str(v) for k, v in match_labels.items()):
        return False
    expressions = selector.get("matchExpressions") or []
    for expr in expressions:
        key = str(expr.get("key") or "")
        operator = str(expr.get("operator") or "")
        values = [str(v) for v in expr.get("values") or []]
        actual = labels.get(key)
        if operator == "In" and actual not in values:
            return False
        if operator == "NotIn" and actual in values:
            return False
        if operator == "Exists" and key not in labels:
            return False
        if operator == "DoesNotExist" and key in labels:
            return False
    return True


def target_has_existing_egress_policy(ctx: RunContext, labels: Dict[str, str]) -> Tuple[bool, str]:
    policies = kubectl_get_json(
        ctx.kubeconfig,
        ["get", "networkpolicies.networking.k8s.io", "-n", ctx.namespace],
    )
    if policies is None:
        return True, "unable to inspect existing NetworkPolicies"
    for policy in policies.get("items") or []:
        metadata = policy.get("metadata") or {}
        name = str(metadata.get("name") or "")
        if name == "agentfence-egress-restrict-target":
            continue
        spec = policy.get("spec") or {}
        policy_types = set(spec.get("policyTypes") or [])
        has_egress = "Egress" in policy_types or bool(spec.get("egress"))
        if not has_egress:
            continue
        if pod_selector_matches_labels(spec.get("podSelector") or {}, labels):
            return True, f"existing egress NetworkPolicy {name!r} selects the target"
    return False, "no existing egress NetworkPolicy selects the target"


def target_exclusion_selector(labels: Dict[str, str]) -> Optional[Dict[str, Any]]:
    for key in ("role", "app", "app.kubernetes.io/name"):
        value = labels.get(key)
        if value:
            return {"matchExpressions": [{"key": key, "operator": "NotIn", "values": [value]}]}
    return None


def manifest_agentfence_annotations(manifest: Dict[str, Any], probe_ids: List[str]) -> None:
    metadata = manifest.setdefault("metadata", {})
    annotations = metadata.setdefault("annotations", {})
    annotations["agentfence.dev/probe-ids"] = ",".join(sorted(set(probe_ids)))


def ingress_policy_selects_target(policy: Dict[str, Any], labels: Dict[str, str]) -> bool:
    spec = policy.get("spec") or {}
    if not pod_selector_matches_labels(spec.get("podSelector") or {}, labels):
        return False
    policy_types = set(spec.get("policyTypes") or [])
    return "Ingress" in policy_types or bool(spec.get("ingress"))


def build_target_ingress_isolation_manifests(
    ctx: RunContext, labels: Dict[str, str]
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    manifests: List[Dict[str, Any]] = []
    notes: List[Dict[str, Any]] = []
    deny_target = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {
            "name": "agentfence-deny-ingress-target",
            "namespace": ctx.namespace,
            "labels": {"app.kubernetes.io/managed-by": "agentfence"},
        },
        "spec": {
            "podSelector": {"matchLabels": labels},
            "policyTypes": ["Ingress"],
            "ingress": [],
        },
    }
    manifest_agentfence_annotations(deny_target, ["AgentFence.REMOTE.UNAUTH_SERVICE_REACHABLE"])
    manifests.append(deny_target)

    exclusion_selector = target_exclusion_selector(labels)
    if not exclusion_selector:
        notes.append(
            {
                "probe_id": "AgentFence.REMOTE.UNAUTH_SERVICE_REACHABLE",
                "status": "manual_recommendation",
                "reason": "cannot safely narrow broad ingress policies because target lacks a stable role/app label",
            }
        )
        return manifests, notes

    policies = kubectl_get_json(
        ctx.kubeconfig,
        ["get", "networkpolicies.networking.k8s.io", "-n", ctx.namespace],
    )
    if policies is None:
        notes.append(
            {
                "probe_id": "AgentFence.REMOTE.UNAUTH_SERVICE_REACHABLE",
                "status": "manual_recommendation",
                "reason": "unable to inspect existing NetworkPolicies for safe ingress narrowing",
            }
        )
        return manifests, notes

    for policy in policies.get("items") or []:
        metadata = policy.get("metadata") or {}
        name = str(metadata.get("name") or "")
        if name.startswith("agentfence-"):
            continue
        spec = policy.get("spec") or {}
        ingress = spec.get("ingress")
        if not ingress_policy_selects_target(policy, labels) or not ingress:
            continue

        narrowed = reapplyable_manifest(policy)
        narrowed_spec = narrowed.setdefault("spec", {})
        narrowed_spec["podSelector"] = exclusion_selector
        narrowed.setdefault("metadata", {}).setdefault("labels", {})[
            "app.kubernetes.io/managed-by"
        ] = "agentfence"
        manifest_agentfence_annotations(narrowed, ["AgentFence.REMOTE.UNAUTH_SERVICE_REACHABLE"])
        manifests.append(narrowed)

    return manifests, notes


def network_policy_manifests(
    ctx: RunContext,
    remediation_plan: Dict[str, Any],
    workload_info: Dict[str, Any],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    actionable = remediation_plan.get("actionable_items") or []
    auto_items = [
        i
        for i in actionable
        if i.get("action_type") == "auto_fix" and is_scored_probe(i.get("probe_id"))
    ]
    probe_ids = {canonical_probe_id(i.get("probe_id")) for i in auto_items}
    labels = target_match_labels(ctx)
    if not labels:
        return [], [{"status": "manual_recommendation", "reason": "target pod has no labels for NetworkPolicy podSelector"}]

    manifests: List[Dict[str, Any]] = []
    notes: List[Dict[str, Any]] = []
    forbidden: List[str] = []
    if "AgentFence.NET.IMDS_REACHABLE" in probe_ids:
        has_existing_egress, egress_reason = target_has_existing_egress_policy(ctx, labels)
        if has_existing_egress:
            notes.append(
                {
                    "probe_id": "AgentFence.NET.IMDS_REACHABLE",
                    "status": "manual_recommendation",
                    "reason": (
                        "metadata egress blocking requires editing existing egress policy; "
                        f"blind add-on policy could broaden access ({egress_reason})"
                    ),
                }
            )
        else:
            forbidden.append("169.254.169.254/32")
    wl = workload_info.get("workload_reference") or {}
    node_ip = node_internal_ip(ctx)
    if "AgentFence.NET.KUBELET_API_REACHABLE" in probe_ids and node_ip:
        forbidden.append(f"{node_ip}/32")
    api_ip = kubernetes_service_ip(ctx)
    if "AgentFence.NET.APISERVER_DIRECT_REACHABLE" in probe_ids and api_ip:
        forbidden.append(f"{api_ip}/32")
    forbidden = sorted(set(forbidden))
    if forbidden:
        manifests.append(
            {
                "apiVersion": "networking.k8s.io/v1",
                "kind": "NetworkPolicy",
                "metadata": {
                    "name": "agentfence-egress-restrict-target",
                    "namespace": ctx.namespace,
                    "labels": {"app.kubernetes.io/managed-by": "agentfence"},
                },
                "spec": {
                    "podSelector": {"matchLabels": labels},
                    "policyTypes": ["Egress"],
                    "egress": [
                        {
                            "to": [
                                {
                                    "ipBlock": {
                                        "cidr": "0.0.0.0/0",
                                        "except": forbidden,
                                    }
                                }
                            ]
                        }
                    ],
                },
            }
        )
    if "AgentFence.NET.HOST_NETWORK_REACHABLE" in probe_ids:
        notes.append(
            {
                "probe_id": "AgentFence.NET.HOST_NETWORK_REACHABLE",
                "status": "manual_recommendation",
                "reason": "host/private network egress needs environment-specific allowlisting; app avoids broad blind network outage",
            }
        )
    return manifests, notes


def unsafe_probe_ids(results: List[TestResult]) -> set:
    return {r.id for r in results if r.status == "pass"}


def network_policy_probe_ids(manifest: Dict[str, Any]) -> List[str]:
    annotations = ((manifest.get("metadata") or {}).get("annotations")) or {}
    annotated = annotations.get("agentfence.dev/probe-ids")
    if annotated:
        return sorted({x.strip() for x in str(annotated).split(",") if x.strip()})
    name = ((manifest.get("metadata") or {}).get("name")) or ""
    if name == "agentfence-deny-ingress-target":
        return ["AgentFence.REMOTE.UNAUTH_SERVICE_REACHABLE"]
    if name != "agentfence-egress-restrict-target":
        return []
    probe_ids: List[str] = []
    for egress in ((manifest.get("spec") or {}).get("egress")) or []:
        for to in egress.get("to") or []:
            ip_block = to.get("ipBlock") or {}
            exceptions = set(ip_block.get("except") or [])
            if "169.254.169.254/32" in exceptions:
                probe_ids.append("AgentFence.NET.IMDS_REACHABLE")
    return sorted(set(probe_ids))


def rollback_workload_record(ctx: RunContext, record: Dict[str, Any]) -> Dict[str, Any]:
    resource = str(record.get("resource") or "")
    name = str(record.get("name") or "")
    if not resource or not name:
        return {"status": "failed", "reason": "missing workload resource/name for rollback"}
    if resource not in ("deployment", "statefulset", "daemonset"):
        return {
            "status": "manual_required",
            "reason": f"automatic rollback for {resource} requires restore checkpoint",
        }
    rc, out, err = run_kubectl(
        ctx.kubeconfig,
        ["rollout", "undo", f"{resource}/{name}", "-n", ctx.namespace],
        timeout=90,
    )
    if rc != 0:
        return {"status": "failed", "phase": "undo", "error": (err or out or f"exit {rc}")[:2000]}
    rc2, out2, err2 = run_kubectl(
        ctx.kubeconfig,
        ["rollout", "status", f"{resource}/{name}", "-n", ctx.namespace, "--timeout=120s"],
        timeout=150,
    )
    return {
        "status": "complete" if rc2 == 0 else "warning",
        "undo": (out or "").strip()[:1000],
        "rollout": (out2 or err2 or f"exit {rc2}")[:2000],
    }


def rollback_network_policy_record(ctx: RunContext, record: Dict[str, Any]) -> Dict[str, Any]:
    name = str(record.get("name") or "")
    if not name:
        return {"status": "failed", "reason": "missing NetworkPolicy name for rollback"}
    operation = record.get("apply_operation")
    previous = record.get("previous_manifest")
    if operation == "created" and not previous:
        rc, out, err = run_kubectl(
            ctx.kubeconfig,
            ["delete", "networkpolicy", name, "-n", ctx.namespace, "--ignore-not-found"],
            timeout=90,
        )
        if rc != 0:
            return {"status": "failed", "phase": "delete", "error": (err or out or f"exit {rc}")[:2000]}
        return {"status": "complete", "delete": (out or "").strip()[:1000]}
    if isinstance(previous, dict):
        restored = apply_json_manifest(ctx, previous, False)
        return {
            "status": "complete" if restored.get("status") == "applied" else "failed",
            "restore": restored,
        }
    return {
        "status": "manual_required",
        "reason": "NetworkPolicy existed before this run; use restore checkpoint if rollback is needed",
    }


def rollback_auto_record(ctx: RunContext, record: Dict[str, Any]) -> Dict[str, Any]:
    if record.get("kind") == "workload_hardening_patch":
        return rollback_workload_record(ctx, record)
    if record.get("kind") == "network_policy":
        return rollback_network_policy_record(ctx, record)
    return {"status": "manual_required", "reason": f"no rollback handler for {record.get('kind')}"}


def verify_auto_record(
    ctx: RunContext,
    record: Dict[str, Any],
    baseline_results: Optional[List[TestResult]],
) -> Tuple[Dict[str, Any], Optional[List[TestResult]]]:
    if ctx.dry_run:
        return {"status": "dry_run_not_executed"}, None
    if record.get("status") != "applied":
        return {"status": "not_applicable", "reason": f"record status is {record.get('status')}"}, None
    if not baseline_results:
        return {"status": "not_run", "reason": "no baseline results supplied"}, None

    probe_ids = set(str(x) for x in (record.get("probe_ids") or []) if x)
    if not probe_ids:
        return {"status": "not_run", "reason": "record has no related probe ids"}, None

    after_results = run_all_probes(ctx)
    before_unsafe = unsafe_probe_ids(baseline_results)
    after_unsafe = unsafe_probe_ids(after_results)
    before_metrics = summarize_results(baseline_results)
    after_metrics = summarize_results(after_results)
    targeted_before = before_unsafe & probe_ids
    resolved = sorted(targeted_before - after_unsafe)
    still_unsafe = sorted(targeted_before & after_unsafe)
    new_unsafe = sorted(after_unsafe - before_unsafe)
    score_worsened = after_metrics.score_raw > before_metrics.score_raw
    no_target_improvement = bool(targeted_before) and not resolved

    verification = {
        "status": "verified",
        "probe_ids": sorted(probe_ids),
        "resolved_probe_ids": resolved,
        "still_unsafe_probe_ids": still_unsafe,
        "new_unsafe_probe_ids": new_unsafe,
        "score_raw_before": before_metrics.score_raw,
        "score_raw_after": after_metrics.score_raw,
        "changed": record.get("changed"),
    }
    if record.get("changed") is False:
        verification["status"] = "no_change" if resolved else "no_change_unresolved"
        return verification, after_results

    rollback_reasons = []
    if score_worsened:
        rollback_reasons.append("raw score worsened")
    if new_unsafe:
        rollback_reasons.append("new unsafe probes appeared")
    if no_target_improvement:
        rollback_reasons.append("related probes did not improve")
    runtime_diag = record.get("runtime_seccomp_diagnostic") or {}
    seccomp_runtime_config_required = (
        record.get("kind") == "workload_hardening_patch"
        and "AgentFence.IDENTITY.SECCOMP_BYPASS_OK" in probe_ids
        and "AgentFence.IDENTITY.SECCOMP_BYPASS_OK" in still_unsafe
        and (runtime_diag.get("runtime") or {}).get("family") in ("gvisor", "kata")
        and runtime_diag.get("all_expected_containers_configured") is True
        and not score_worsened
    )
    if seccomp_runtime_config_required:
        rollback_reasons = [
            reason
            for reason in rollback_reasons
            if reason != "related probes did not improve"
        ]
        if not rollback_reasons:
            verification["status"] = "runtime_config_required"
            verification["verification_warnings"] = [
                runtime_diag.get("recommendation")
                or "Runtime-specific seccomp enablement is still required."
            ]
            return verification, after_results
    warning_only = (
        record.get("kind") == "workload_hardening_patch"
        and bool(resolved)
        and new_unsafe
        and after_metrics.score_raw < before_metrics.score_raw
        and not score_worsened
    )
    if warning_only:
        verification["status"] = "verified_with_warnings"
        verification["verification_warnings"] = [
            "new unsafe probes appeared during workload-hardening verification, "
            "but related probes improved and the raw score decreased"
        ]
        return verification, after_results
    if rollback_reasons:
        rollback = rollback_auto_record(ctx, record)
        verification["status"] = (
            "rolled_back" if rollback.get("status") in ("complete", "warning") else "rollback_failed"
        )
        verification["rollback_reasons"] = rollback_reasons
        verification["rollback"] = rollback
        return verification, run_all_probes(ctx)
    return verification, after_results


def reconcile_seccomp_verification_with_runtime(
    verification: Dict[str, Any],
    runtime_seccomp: Dict[str, Any],
) -> Dict[str, Any]:
    if not runtime_seccomp.get("runtime_config_required"):
        return verification
    pid = "AgentFence.IDENTITY.SECCOMP_BYPASS_OK"
    resolved = set(verification.get("resolved_probe_ids") or [])
    still_unsafe = set(verification.get("still_unsafe_probe_ids") or [])
    if pid not in resolved and pid in still_unsafe:
        return verification
    if pid in resolved:
        resolved.remove(pid)
        still_unsafe.add(pid)
        verification["resolved_probe_ids"] = sorted(resolved)
        verification["still_unsafe_probe_ids"] = sorted(still_unsafe)
    warning = (
        runtime_seccomp.get("recommendation")
        or "Runtime-specific seccomp enablement is still required."
    )
    verification["verification_warnings"] = sorted(
        set((verification.get("verification_warnings") or []) + [warning])
    )
    verification["status"] = (
        "runtime_config_required"
        if not verification.get("resolved_probe_ids")
        else "verified_with_warnings"
    )
    return verification


def apply_remediation_actions(
    ctx: RunContext,
    remediation_plan: Dict[str, Any],
    backup_checkpoint: Optional[Dict[str, Any]],
    baseline_results: Optional[List[TestResult]] = None,
) -> Dict[str, Any]:
    actionable = remediation_plan.get("actionable_items") or []
    if not actionable:
        return {
            "schema": "agentfence-remediation-apply-v1",
            "status": "nothing_to_apply",
            "dry_run": ctx.dry_run,
            "applied_count": 0,
            "failed_count": 0,
            "manual_count": 0,
            "records": [],
        }
    if not checkpoint_allows_mutation(backup_checkpoint, ctx.dry_run):
        return {
            "schema": "agentfence-remediation-apply-v1",
            "status": "blocked",
            "dry_run": ctx.dry_run,
            "reason": "restore checkpoint is not verified; refusing to mutate",
            "backup_status": (backup_checkpoint or {}).get("status"),
            "applied_count": 0,
            "failed_count": 0,
            "manual_count": len(actionable),
            "records": [],
        }

    records: List[Dict[str, Any]] = []
    current_results = baseline_results
    workload_patch_infos, patch_info = build_workload_hardening_patches(ctx, remediation_plan)

    refresh_record = refresh_run_context_target(ctx)
    if refresh_record.get("status") != "unchanged":
        records.append(refresh_record)

    manifests, manual_net_notes = network_policy_manifests(ctx, remediation_plan, patch_info)
    for manifest in manifests:
        result = apply_json_manifest(ctx, manifest, ctx.dry_run)
        record = {
            "kind": "network_policy",
            "name": (manifest.get("metadata") or {}).get("name"),
            "probe_ids": network_policy_probe_ids(manifest),
            "manifest": manifest,
            **result,
        }
        verification, verified_results = verify_auto_record(ctx, record, current_results)
        record["verification"] = verification
        record["resolved_probe_ids"] = verification.get("resolved_probe_ids") or []
        if verification.get("status") in ("rolled_back", "rollback_failed"):
            record["status"] = verification["status"]
        if verified_results is not None:
            current_results = verified_results
        records.append(record)
    records.extend(manual_net_notes)

    sysctl_records, sysctl_results = apply_node_sysctl_hardening(ctx, current_results)
    if sysctl_records:
        records.extend(sysctl_records)
    if sysctl_results is not None:
        current_results = sysctl_results

    for stage_info in workload_patch_infos:
        patch = stage_info.get("patch")
        if not patch:
            continue
        result = kubectl_patch_workload(
            ctx,
            str(stage_info["resource"]),
            str(stage_info["name"]),
            patch,
            ctx.dry_run,
        )
        record = {
            "kind": "workload_hardening_patch",
            "stage": stage_info.get("stage"),
            "risk_level": stage_info.get("risk_level"),
            "resource": stage_info.get("resource"),
            "name": stage_info.get("name"),
            "probe_ids": stage_info.get("probe_ids") or [],
            "artifact_kinds": stage_info.get("artifact_kinds") or [],
            "workload": stage_info.get("workload_reference"),
            "workload_config_before": stage_info.get("workload_config_before"),
            "patch": patch,
            **result,
        }
        workload_health = verify_workload_online_after_patch(ctx, stage_info, result)
        record["workload_revalidation"] = workload_health
        if result.get("status") == "applied" and not workload_health.get("healthy"):
            rollback = rollback_auto_record(ctx, record)
            record["status"] = "rolled_back" if rollback.get("status") in ("complete", "warning") else "rollback_failed"
            record["verification"] = {
                "status": record["status"],
                "probe_ids": record.get("probe_ids") or [],
                "resolved_probe_ids": [],
                "still_unsafe_probe_ids": record.get("probe_ids") or [],
                "rollback_reasons": [workload_health.get("reason") or "workload revalidation failed"],
                "rollback": rollback,
            }
            refresh_after_rollback = refresh_run_context_target(ctx)
            if refresh_after_rollback.get("status") != "unchanged":
                record["target_refresh_after_rollback"] = refresh_after_rollback
            current_results = run_all_probes(ctx) if not ctx.dry_run else current_results
        else:
            runtime_seccomp = build_runtime_seccomp_diagnostic(ctx, stage_info, None)
            if runtime_seccomp:
                record["runtime_seccomp_diagnostic"] = runtime_seccomp
            verification, verified_results = verify_auto_record(ctx, record, current_results)
            runtime_seccomp = build_runtime_seccomp_diagnostic(ctx, stage_info, verification)
            if runtime_seccomp:
                record["runtime_seccomp_diagnostic"] = runtime_seccomp
                verification = reconcile_seccomp_verification_with_runtime(
                    verification, runtime_seccomp
                )
            record["verification"] = verification
            record["resolved_probe_ids"] = verification.get("resolved_probe_ids") or []
            if verification.get("status") == "runtime_config_required":
                record["status"] = "applied_with_verification_warning"
                record["verification_warnings"] = verification.get("verification_warnings") or []
                refresh_after_rollout = refresh_run_context_target(ctx)
                if refresh_after_rollout.get("status") != "unchanged":
                    record["target_refresh_after_rollout"] = refresh_after_rollout
                runtime_record, runtime_results = apply_kata_node_seccomp_runtime_remediation(
                    ctx,
                    stage_info,
                    runtime_seccomp,
                )
                if runtime_record.get("status") != "not_applicable":
                    records.append(runtime_record)
                if runtime_results is not None:
                    current_results = runtime_results
            elif verification.get("status") in ("rolled_back", "rollback_failed"):
                record["status"] = verification["status"]
                refresh_after_rollback = refresh_run_context_target(ctx)
                if refresh_after_rollback.get("status") != "unchanged":
                    record["target_refresh_after_rollback"] = refresh_after_rollback
            elif verification.get("status") == "verified_with_warnings":
                record["status"] = "applied_with_verification_warning"
                record["verification_warnings"] = verification.get("verification_warnings") or []
                refresh_after_rollout = refresh_run_context_target(ctx)
                if refresh_after_rollout.get("status") != "unchanged":
                    record["target_refresh_after_rollout"] = refresh_after_rollout
            elif record.get("changed"):
                refresh_after_rollout = refresh_run_context_target(ctx)
                if refresh_after_rollout.get("status") != "unchanged":
                    record["target_refresh_after_rollout"] = refresh_after_rollout
            if verified_results is not None and verification.get("status") != "runtime_config_required":
                current_results = verified_results
        records.append(record)
    if not workload_patch_infos:
        records.append({"kind": "workload_hardening_patch", "status": "not_applicable", **patch_info})

    auto_probe_ids = set()
    attempted_auto_probe_ids = set()
    for record in records:
        if record.get("status") in ("applied", "applied_with_verification_warning", "dry_run_planned"):
            attempted_auto_probe_ids.update(record.get("probe_ids") or [])
            if ctx.dry_run:
                auto_probe_ids.update(record.get("probe_ids") or [])
            else:
                auto_probe_ids.update(record.get("resolved_probe_ids") or [])

    compatibility = (patch_info.get("compatibility") or {}) if isinstance(patch_info, dict) else {}
    guarded_auto = {"AgentFence.ID.RUN_AS_UID_ZERO"}
    if compatibility.get("auto_security_context") is False:
        guarded_auto.update(
            {
                "AgentFence.DEVICE.RAW_SOCKET_USABLE",
                "AgentFence.IDENTITY.NO_NEW_PRIVS_BYPASS_OK",
                "AgentFence.IDENTITY.CAP_BOUNDING_PERMISSIVE",
            }
        )
    if compatibility.get("auto_service_account_token") is False:
        guarded_auto.add("AgentFence.ID.SA_TOKEN_READABLE")
    manual_records_by_probe = {
        r.get("probe_id"): r
        for r in records
        if r.get("status") == "manual_recommendation" and r.get("probe_id")
    }
    runtime_seccomp_by_probe = {}
    for record in records:
        diagnostic = record.get("runtime_seccomp_diagnostic")
        if not diagnostic:
            continue
        for probe_id in record.get("probe_ids") or []:
            runtime_seccomp_by_probe[probe_id] = diagnostic
    for item in actionable:
        pid = item.get("probe_id")
        if pid in auto_probe_ids:
            continue
        if pid in manual_records_by_probe:
            manual_records_by_probe[pid].setdefault("title", item.get("title"))
            manual_records_by_probe[pid].setdefault("action_type", item.get("action_type"))
            manual_records_by_probe[pid].setdefault("recommendation", item.get("recommendation"))
            continue
        if item.get("action_type") in ("manual_recommendation", "hybrid"):
            records.append(
                {
                    "kind": "manual_recommendation",
                    "status": "manual_recommendation",
                    "probe_id": pid,
                    "title": item.get("title"),
                    "action_type": item.get("action_type"),
                    "recommendation": item.get("recommendation"),
                }
            )
        elif pid in guarded_auto:
            reason = "mechanically patchable but unsafe to apply blindly; some images must start as root and drop privileges internally"
            if pid == "AgentFence.ID.SA_TOKEN_READABLE":
                reason = compatibility.get("service_account_reason") or "service-account token use needs workload/RBAC review"
            records.append(
                {
                    "kind": "compatibility_guard",
                    "status": "manual_recommendation",
                    "probe_id": pid,
                    "title": item.get("title"),
                    "action_type": item.get("action_type"),
                    "recommendation": item.get("recommendation"),
                    "reason": reason,
                }
            )
        elif item.get("action_type") == "auto_fix":
            runtime_seccomp = runtime_seccomp_by_probe.get(pid) or {}
            if runtime_seccomp.get("runtime_config_required"):
                reason = (
                    "workload-level RuntimeDefault seccomp was applied and the workload was revalidated, "
                    "but the runtime did not verify process-level seccomp; runtime configuration is required"
                )
            else:
                reason = (
                    "automatic remediation was attempted but did not verify"
                    if pid in attempted_auto_probe_ids
                    else "automatic remediation is available but was not safe to apply automatically"
                )
            records.append(
                {
                    "kind": "manual_recommendation",
                    "status": "manual_recommendation",
                    "probe_id": pid,
                    "title": item.get("title"),
                    "action_type": item.get("action_type"),
                    "recommendation": item.get("recommendation"),
                    "reason": reason,
                    "runtime_seccomp_diagnostic": runtime_seccomp or None,
                }
            )

    applied_count = sum(1 for r in records if r.get("status") in ("applied", "applied_with_verification_warning", "dry_run_planned"))
    failed_count = sum(1 for r in records if r.get("status") in ("failed", "rolled_back", "rollback_failed"))
    manual_count = sum(1 for r in records if r.get("status") == "manual_recommendation")
    if ctx.dry_run:
        status = "dry_run_planned"
    elif failed_count and applied_count:
        status = "partial"
    elif failed_count:
        status = "failed"
    elif applied_count:
        status = "applied"
    else:
        status = "manual_only"
    return {
        "schema": "agentfence-remediation-apply-v1",
        "status": status,
        "dry_run": ctx.dry_run,
        "applied_count": applied_count,
        "failed_count": failed_count,
        "manual_count": manual_count,
        "records": records,
        "note": "Automatic remediation applies bounded workload securityContext, seccomp RuntimeDefault, service-account, namespace-isolation, and NetworkPolicy changes; workload-level patches capture pre-fix config, require rollout/workload revalidation, then post-remediation analysis runs again.",
    }


def now_stamp() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def kubectl_base(kubeconfig: str) -> List[str]:
    cmd = ["kubectl"]
    if kubeconfig:
        expanded = os.path.expanduser(kubeconfig)
        if os.path.exists(expanded):
            cmd += ["--kubeconfig", expanded]
    return cmd


def run_kubectl(
    kubeconfig: str, args: List[str], timeout: int = 60
) -> Tuple[int, str, str]:
    cmd = kubectl_base(kubeconfig)
    if ACTIVE_KUBE_CONTEXT:
        cmd += ["--context", ACTIVE_KUBE_CONTEXT]
    cmd += args
    try:
        p = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return p.returncode, p.stdout or "", p.stderr or ""
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except Exception as e:
        return 1, "", f"{type(e).__name__}: {e}"


def kubectl_get_json(kubeconfig: str, args: List[str]) -> Optional[Any]:
    rc, out, err = run_kubectl(kubeconfig, args + ["-o", "json"], timeout=45)
    if rc != 0:
        return None
    try:
        return json.loads(out)
    except json.JSONDecodeError:
        return None


def kubectl_exec(
    kubeconfig: str,
    namespace: str,
    pod: str,
    container: str,
    shell_cmd: str,
    timeout: int,
) -> Tuple[int, str]:
    args = ["exec", "-n", namespace, pod]
    if container:
        args += ["-c", container]
    args += ["--", "sh", "-c", shell_cmd]
    rc, out, err = run_kubectl(kubeconfig, args, timeout=timeout)
    return rc, (out + err).strip()


def first_container(pod: Dict[str, Any]) -> str:
    cts = (pod.get("spec") or {}).get("containers") or []
    if not cts:
        return ""
    return cts[0].get("name") or ""


def pod_is_ready(pod: Dict[str, Any]) -> bool:
    if (pod.get("status") or {}).get("phase") != "Running":
        return False
    if (pod.get("metadata") or {}).get("deletionTimestamp"):
        return False
    statuses = (pod.get("status") or {}).get("containerStatuses") or []
    return bool(statuses) and all(bool(s.get("ready")) for s in statuses)


def sorted_ready_pods(pods: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    ready = [p for p in pods if pod_is_ready(p)]
    return sorted(
        ready,
        key=lambda p: str((p.get("metadata") or {}).get("creationTimestamp") or ""),
        reverse=True,
    )


def auto_select_target(
    kubeconfig: str, namespace: str, override: Optional[str]
) -> Tuple[str, str]:
    if override:
        pod = kubectl_get_json(
            kubeconfig, ["get", "pod", override, "-n", namespace]
        )
        if not pod:
            raise RuntimeError(f"override pod {override} not found")
        return override, first_container(pod)

    rc, out, _ = run_kubectl(
        kubeconfig,
        ["get", "pods", "-n", namespace, "-l", "role=target", "-o", "json"],
        timeout=30,
    )
    pods = []
    if rc == 0 and out:
        try:
            pods = json.loads(out).get("items") or []
        except json.JSONDecodeError:
            pods = []
    ready_pods = sorted_ready_pods(pods)
    if ready_pods:
        p = ready_pods[0]
        name = p["metadata"]["name"]
        return name, first_container(p)

    rc, out, _ = run_kubectl(
        kubeconfig,
        ["get", "pods", "-n", namespace, "-o", "json"],
        timeout=30,
    )
    if rc != 0 or not out:
        raise RuntimeError(f"cannot list pods in {namespace}: {out}")
    data = json.loads(out)
    cands = []
    for p in data.get("items") or []:
        name = p.get("metadata", {}).get("name") or ""
        if name.startswith("target-"):
            cands.append((name, p))
    if len(cands) == 1:
        n, p = cands[0]
        return n, first_container(p)
    if len(cands) > 1:
        names = [x[0] for x in cands]
        raise RuntimeError(
            f"multiple target-* pods: {names}; use --target-pod NAME"
        )
    raise RuntimeError(
        "no target pod: add label role=target or name prefix target-; "
        "or pass --target-pod"
    )


def auto_select_attacker(kubeconfig: str, namespace: str) -> Tuple[str, str]:
    for label in ("role=attacker", "app=attacker"):
        rc, out, _ = run_kubectl(
            kubeconfig,
            ["get", "pods", "-n", namespace, "-l", label, "-o", "json"],
            timeout=30,
        )
        if rc != 0 or not out:
            continue
        try:
            items = json.loads(out).get("items") or []
        except json.JSONDecodeError:
            continue
        running = [
            p
            for p in items
            if (p.get("status") or {}).get("phase") == "Running"
        ]
        if running:
            p = running[0]
            return p["metadata"]["name"], first_container(p)
    raise RuntimeError(
        "no attacker pod (label role=attacker or app=attacker, Running)"
    )


def pod_ip(kubeconfig: str, namespace: str, pod_name: str) -> str:
    rc, out, _ = run_kubectl(
        kubeconfig,
        [
            "get",
            "pod",
            pod_name,
            "-n",
            namespace,
            "-o",
            "jsonpath={.status.podIP}",
        ],
        timeout=20,
    )
    ip = (out or "").strip()
    if not ip:
        raise RuntimeError(f"no podIP for {pod_name}")
    return ip


def refresh_run_context_target(ctx: RunContext) -> Dict[str, Any]:
    if ctx.dry_run:
        return {"kind": "target_refresh", "status": "dry_run_not_executed"}
    before = {
        "target_pod": ctx.target_pod,
        "target_container": ctx.target_container,
        "target_ip": ctx.target_ip,
    }
    try:
        current = load_target_pod_json(ctx)
        if (
            isinstance(current, dict)
            and ((current.get("metadata") or {}).get("name") == ctx.target_pod)
            and pod_is_ready(current)
        ):
            target_pod = ctx.target_pod
            target_container = first_container(current) or ctx.target_container
            target_ip = str(((current.get("status") or {}).get("podIP")) or ctx.target_ip)
        else:
            target_pod, target_container = auto_select_target(ctx.kubeconfig, ctx.namespace, None)
            target_ip = pod_ip(ctx.kubeconfig, ctx.namespace, target_pod)
    except Exception as e:
        return {
            "kind": "target_refresh",
            "status": "failed",
            "before": before,
            "error": f"{type(e).__name__}: {e}",
        }

    ctx.target_pod = target_pod
    ctx.target_container = target_container
    ctx.target_ip = target_ip
    after = {
        "target_pod": ctx.target_pod,
        "target_container": ctx.target_container,
        "target_ip": ctx.target_ip,
    }
    return {
        "kind": "target_refresh",
        "status": "updated" if after != before else "unchanged",
        "before": before,
        "after": after,
    }


def load_target_pod_json(ctx: RunContext) -> Optional[Dict[str, Any]]:
    return kubectl_get_json(
        ctx.kubeconfig,
        ["get", "pod", ctx.target_pod, "-n", ctx.namespace],
    )


def tr(
    pid: str,
    sev: Severity,
    status: Status,
    evidence: str = "",
    clause: str = "",
    ms: int = 0,
) -> TestResult:
    return TestResult(
        id=pid,
        severity=sev,
        status=status,
        evidence=evidence[:4000],
        matched_clause=clause,
        duration_ms=ms,
    )


# ---------------------------------------------------------------------------
# Probe implementations (39) — each returns TestResult for its catalog id
# ---------------------------------------------------------------------------


def probe_run_as_uid_zero(ctx: RunContext) -> TestResult:
    t0 = time.time()
    if ctx.dry_run:
        return tr("AgentFence.ID.RUN_AS_UID_ZERO", "high", "skip", "dry-run")
    rc, out = kubectl_exec(
        ctx.kubeconfig,
        ctx.namespace,
        ctx.target_pod,
        ctx.target_container,
        "id -u 2>/dev/null || true",
        ctx.probe_timeout,
    )
    ms = int((time.time() - t0) * 1000)
    u = (out or "").strip().splitlines()[-1] if out else ""
    try:
        uid = int(u)
    except ValueError:
        return tr("AgentFence.ID.RUN_AS_UID_ZERO", "high", "skip", out, "non-numeric id", ms)
    if uid == 0:
        return tr("AgentFence.ID.RUN_AS_UID_ZERO", "high", "pass", out, "uid==0", ms)
    return tr("AgentFence.ID.RUN_AS_UID_ZERO", "high", "fail", out, "uid!=0", ms)


def probe_rootfs_write(ctx: RunContext) -> TestResult:
    t0 = time.time()
    if ctx.dry_run:
        return tr("AgentFence.ID.ROOTFS_WRITE_OK", "high", "skip", "dry-run")
    script = (
        "f=/.afp_w_$$; rm -f \"$f\" 2>/dev/null; "
        "if touch \"$f\" 2>/dev/null; then rm -f \"$f\"; echo OK; else echo FAIL; fi"
    )
    rc, out = kubectl_exec(
        ctx.kubeconfig,
        ctx.namespace,
        ctx.target_pod,
        ctx.target_container,
        script,
        ctx.probe_timeout,
    )
    ms = int((time.time() - t0) * 1000)
    if "OK" in (out or ""):
        return tr("AgentFence.ID.ROOTFS_WRITE_OK", "high", "pass", out, "touch / succeeded", ms)
    return tr("AgentFence.ID.ROOTFS_WRITE_OK", "high", "fail", out, "rootfs not writable at /", ms)


def probe_sa_token(ctx: RunContext) -> TestResult:
    t0 = time.time()
    if ctx.dry_run:
        return tr("AgentFence.ID.SA_TOKEN_READABLE", "high", "skip", "dry-run")
    script = (
        "p=/var/run/secrets/kubernetes.io/serviceaccount/token; "
        "if test -r \"$p\"; then wc -c < \"$p\"; else echo 0; fi"
    )
    rc, out = kubectl_exec(
        ctx.kubeconfig,
        ctx.namespace,
        ctx.target_pod,
        ctx.target_container,
        script,
        ctx.probe_timeout,
    )
    ms = int((time.time() - t0) * 1000)
    try:
        n = int((out or "").strip().splitlines()[-1])
    except ValueError:
        return tr("AgentFence.ID.SA_TOKEN_READABLE", "high", "skip", out, ms=ms)
    if n > 0:
        return tr("AgentFence.ID.SA_TOKEN_READABLE", "high", "pass", f"bytes={n}", "token readable", ms)
    return tr("AgentFence.ID.SA_TOKEN_READABLE", "high", "fail", out, "no token", ms)


def probe_remote_unauth(ctx: RunContext) -> TestResult:
    t0 = time.time()
    if ctx.dry_run:
        return tr("AgentFence.REMOTE.UNAUTH_SERVICE_REACHABLE", "high", "skip", "dry-run")
    tip = ctx.target_ip
    ports = []
    pj = load_target_pod_json(ctx)
    if pj:
        for c in (pj.get("spec") or {}).get("containers") or []:
            for p in c.get("ports") or []:
                cp = p.get("containerPort")
                if isinstance(cp, int):
                    ports.append(cp)
    ports = sorted(set(ports)) or [80, 443, 8000, 8080, 5901, 6901]
    script_parts = []
    for port in ports[:12]:
        script_parts.append(
            f"echo PORT:{port}; "
            f"(nc -z -w2 {shlex.quote(tip)} {port} 2>/dev/null && echo OPEN:{port}) || true"
        )
    script = "; ".join(script_parts)
    rc, out = kubectl_exec(
        ctx.kubeconfig,
        ctx.namespace,
        ctx.attacker_pod,
        ctx.attacker_container,
        script,
        ctx.probe_timeout,
    )
    ms = int((time.time() - t0) * 1000)
    open_ports = []
    for m in re.finditer(r"OPEN:(\d+)", out or ""):
        open_ports.append(int(m.group(1)))
    if not open_ports:
        return tr(
            "AgentFence.REMOTE.UNAUTH_SERVICE_REACHABLE",
            "high",
            "fail",
            out or "",
            "no tcp open from attacker",
            ms,
        )
    # Try HTTP or RFB on first few open ports
    for p in open_ports[:6]:
        curl_script = (
            f"code=$(wget -qO- --timeout=2 http://{shlex.quote(tip)}:{p}/ 2>/dev/null | head -c 20 | wc -c); "
            f"echo HTTPBYTES:{p}:$code"
        )
        _, o2 = kubectl_exec(
            ctx.kubeconfig,
            ctx.namespace,
            ctx.attacker_pod,
            ctx.attacker_container,
            curl_script,
            ctx.probe_timeout,
        )
        if o2 and "HTTPBYTES" in o2:
            for line in (o2 or "").splitlines():
                if "HTTPBYTES:" in line and ":0" not in line.split(":")[-1]:
                    return tr(
                        "AgentFence.REMOTE.UNAUTH_SERVICE_REACHABLE",
                        "high",
                        "pass",
                        f"open={open_ports} detail={line}",
                        "service responded without auth gate",
                        ms,
                    )
        if p in (5901, 6901):
            rfb = (
                f"python3 - <<'PY'\n"
                f"import socket\n"
                f"s=socket.create_connection(({repr(tip)}, {p}), 2)\n"
                f"d=s.recv(12)\n"
                f"print('RFB' if d.startswith(b'RFB') else d[:20])\n"
                f"PY"
            )
            _, o3 = kubectl_exec(
                ctx.kubeconfig,
                ctx.namespace,
                ctx.attacker_pod,
                ctx.attacker_container,
                rfb,
                ctx.probe_timeout,
            )
            if o3 and "RFB" in o3:
                return tr(
                    "AgentFence.REMOTE.UNAUTH_SERVICE_REACHABLE",
                    "high",
                    "pass",
                    f"open={open_ports} rfb={p}",
                    "RFB banner",
                    ms,
                )
    return tr(
        "AgentFence.REMOTE.UNAUTH_SERVICE_REACHABLE",
        "high",
        "fail",
        f"open={open_ports}",
        "ports open but no unauth HTTP/RFB signal",
        ms,
    )


def probe_hostpath_write(ctx: RunContext) -> TestResult:
    t0 = time.time()
    if ctx.dry_run:
        return tr("AgentFence.HOSTPATH.SENSITIVE_WRITE_OK", "high", "skip", "dry-run")
    pj = load_target_pod_json(ctx)
    if not pj:
        return tr("AgentFence.HOSTPATH.SENSITIVE_WRITE_OK", "high", "skip", "no pod json")
    mounts = []
    for vol in (pj.get("spec") or {}).get("volumes") or []:
        hp = vol.get("hostPath")
        if not hp:
            continue
        path = hp.get("path") or ""
        for c in (pj.get("spec") or {}).get("containers") or []:
            for vm in c.get("volumeMounts") or []:
                if vm.get("name") == vol.get("name"):
                    mp = vm.get("mountPath")
                    if mp:
                        mounts.append(mp)
    if not mounts:
        return tr(
            "AgentFence.HOSTPATH.SENSITIVE_WRITE_OK",
            "high",
            "fail",
            "",
            "no hostPath mounts",
            int((time.time() - t0) * 1000),
        )
    for mp in mounts[:5]:
        script = (
            f"test -d {shlex.quote(mp)} || exit 2; "
            f"f={shlex.quote(mp)}/.afp_hp_$$; rm -f \"$f\" 2>/dev/null; "
            f"if touch \"$f\" 2>/dev/null; then rm -f \"$f\"; echo OK:{shlex.quote(mp)}; "
            f"else echo NO:{shlex.quote(mp)}; fi"
        )
        rc, out = kubectl_exec(
            ctx.kubeconfig,
            ctx.namespace,
            ctx.target_pod,
            ctx.target_container,
            script,
            ctx.probe_timeout,
        )
        if "OK:" in (out or ""):
            return tr(
                "AgentFence.HOSTPATH.SENSITIVE_WRITE_OK",
                "high",
                "pass",
                out,
                "hostPath writable",
                int((time.time() - t0) * 1000),
            )
    return tr(
        "AgentFence.HOSTPATH.SENSITIVE_WRITE_OK",
        "high",
        "fail",
        "mounts=" + ",".join(mounts),
        "no writable hostPath",
        int((time.time() - t0) * 1000),
    )


def _py_syscall_probe(ctx: RunContext, script: str, probe_id: str, sev: Severity) -> TestResult:
    t0 = time.time()
    if ctx.dry_run:
        return tr(probe_id, sev, "skip", "dry-run")
    rc, out = kubectl_exec(
        ctx.kubeconfig,
        ctx.namespace,
        ctx.target_pod,
        ctx.target_container,
        script,
        ctx.probe_timeout,
    )
    ms = int((time.time() - t0) * 1000)
    if "UNSAFE" in (out or ""):
        return tr(probe_id, sev, "pass", out, "unsafe syscall outcome", ms)
    if "SAFE" in (out or ""):
        return tr(probe_id, sev, "fail", out, "blocked", ms)
    return tr(probe_id, sev, "skip", out or "", "ambiguous", ms)


def probe_kexec(ctx: RunContext) -> TestResult:
    script = r"""python3 - <<'PY'
import ctypes, errno, os
libc = ctypes.CDLL(None, use_errno=True)
SYS_kexec_load = getattr(os, 'SYS_kexec_load', 246)
libc.syscall.restype = ctypes.c_long
ret = libc.syscall(SYS_kexec_load, 0, 0, 0, 0)
err = ctypes.get_errno()
if ret == -1 and err in (errno.EPERM, errno.ENOSYS):
    print('SAFE', 'errno', err)
elif ret == -1 and err == errno.EINVAL:
    print('SAFE', 'EINVAL')
else:
    print('UNSAFE', 'ret', ret, 'errno', err)
PY"""
    return _py_syscall_probe(ctx, script, "AgentFence.KERNEL.KEXEC_REACHABLE", "high")


def probe_init_module(ctx: RunContext) -> TestResult:
    script = r"""python3 - <<'PY'
import ctypes, errno, os
libc = ctypes.CDLL(None, use_errno=True)
SYS_init_module = getattr(os, 'SYS_init_module', 175)
libc.syscall.restype = ctypes.c_long
ret = libc.syscall(SYS_init_module, 0, 0, 0)
err = ctypes.get_errno()
if ret == -1 and err in (errno.EPERM, errno.ENOSYS, errno.EFAULT, errno.EINVAL):
    print('SAFE', 'errno', err)
else:
    print('UNSAFE', 'ret', ret, 'errno', err)
PY"""
    return _py_syscall_probe(ctx, script, "AgentFence.KERNEL.INIT_MODULE_REACHABLE", "high")


def probe_bpf(ctx: RunContext) -> TestResult:
    script = r"""python3 - <<'PY'
import ctypes, errno, os
libc = ctypes.CDLL(None, use_errno=True)
SYS_bpf = getattr(os, 'SYS_bpf', 321)
BPF_PROG_LOAD = 5
libc.syscall.restype = ctypes.c_long
ret = libc.syscall(SYS_bpf, BPF_PROG_LOAD, 0, 0)
err = ctypes.get_errno()
if ret == -1 and err in (errno.EPERM, errno.ENOSYS):
    print('SAFE', 'errno', err)
elif ret == -1 and err in (errno.EINVAL, errno.E2BIG, errno.ENOMEM):
    print('UNSAFE', 'reached kernel err', err)
else:
    print('UNSAFE', 'ret', ret, 'errno', err)
PY"""
    return _py_syscall_probe(ctx, script, "AgentFence.KERNEL.BPF_PROG_LOAD_REACHABLE", "high")


def probe_userfaultfd(ctx: RunContext) -> TestResult:
    script = r"""python3 - <<'PY'
import ctypes, errno, os
libc = ctypes.CDLL(None, use_errno=True)
SYS_userfaultfd = getattr(os, 'SYS_userfaultfd', 323)
libc.syscall.restype = ctypes.c_long
fd = libc.syscall(SYS_userfaultfd, 0)
err = ctypes.get_errno()
if fd >= 0:
    print('UNSAFE', 'fd', fd)
elif err in (errno.EPERM, errno.ENOSYS):
    print('SAFE', 'errno', err)
else:
    print('UNSAFE', 'errno', err)
PY"""
    t0 = time.time()
    if ctx.dry_run:
        return tr("AgentFence.KERNEL.USERFAULTFD_REACHABLE", "high", "skip", "dry-run")
    rc, out = kubectl_exec(
        ctx.kubeconfig,
        ctx.namespace,
        ctx.target_pod,
        ctx.target_container,
        script,
        ctx.probe_timeout,
    )
    ms = int((time.time() - t0) * 1000)
    if "UNSAFE" in (out or ""):
        return tr("AgentFence.KERNEL.USERFAULTFD_REACHABLE", "high", "pass", out, "userfaultfd", ms)
    return tr("AgentFence.KERNEL.USERFAULTFD_REACHABLE", "high", "fail", out, "blocked", ms)


def probe_perf_event(ctx: RunContext) -> TestResult:
    script = r"""python3 - <<'PY'
import ctypes, errno, os
libc = ctypes.CDLL(None, use_errno=True)
SYS_perf_event_open = getattr(os, 'SYS_perf_event_open', 298)
libc.syscall.restype = ctypes.c_long
ret = libc.syscall(SYS_perf_event_open, 0, 0, -1, 0, 0)
err = ctypes.get_errno()
if ret >= 0:
    print('UNSAFE', 'fd', ret)
elif err in (errno.EPERM, errno.EACCES, errno.ENOSYS):
    print('SAFE', 'errno', err)
else:
    print('UNSAFE', 'errno', err)
PY"""
    return _py_syscall_probe(ctx, script, "AgentFence.KERNEL.PERF_EVENT_OPEN_REACHABLE", "high")


def probe_kallsyms(ctx: RunContext) -> TestResult:
    t0 = time.time()
    if ctx.dry_run:
        return tr("AgentFence.KERNEL.KALLSYMS_VISIBLE", "high", "skip", "dry-run")
    rc, out = kubectl_exec(
        ctx.kubeconfig,
        ctx.namespace,
        ctx.target_pod,
        ctx.target_container,
        "head -n 3 /proc/kallsyms 2>/dev/null || true",
        ctx.probe_timeout,
    )
    ms = int((time.time() - t0) * 1000)
    for line in (out or "").splitlines():
        parts = line.split()
        if len(parts) >= 2 and re.match(r"^[0-9a-fA-F]+$", parts[0]):
            if parts[0].strip("0") or parts[0] == "0":
                if parts[0] != "0000000000000000":
                    return tr("AgentFence.KERNEL.KALLSYMS_VISIBLE", "high", "pass", line, "non-zero symbol addr", ms)
    return tr("AgentFence.KERNEL.KALLSYMS_VISIBLE", "high", "fail", out, "hidden or empty", ms)


def probe_dmesg(ctx: RunContext) -> TestResult:
    t0 = time.time()
    if ctx.dry_run:
        return tr("AgentFence.KERNEL.DMESG_VISIBLE", "high", "skip", "dry-run")
    rc, out = kubectl_exec(
        ctx.kubeconfig,
        ctx.namespace,
        ctx.target_pod,
        ctx.target_container,
        "dmesg 2>&1 | head -n 2",
        ctx.probe_timeout,
    )
    ms = int((time.time() - t0) * 1000)
    o = (out or "").lower()
    if "operation not permitted" in o or "klogctl" in o and "permission" in o:
        return tr("AgentFence.KERNEL.DMESG_VISIBLE", "high", "fail", out, "dmesg denied", ms)
    if (out or "").strip():
        return tr("AgentFence.KERNEL.DMESG_VISIBLE", "high", "pass", out, "dmesg output", ms)
    return tr("AgentFence.KERNEL.DMESG_VISIBLE", "high", "fail", out, "empty", ms)


def probe_shell_pattern(ctx: RunContext, pid: str, sev: Severity, script: str, unsafe_if: Callable[[str], bool]) -> TestResult:
    t0 = time.time()
    if ctx.dry_run:
        return tr(pid, sev, "skip", "dry-run")
    rc, out = kubectl_exec(
        ctx.kubeconfig,
        ctx.namespace,
        ctx.target_pod,
        ctx.target_container,
        script,
        ctx.probe_timeout,
    )
    ms = int((time.time() - t0) * 1000)
    if unsafe_if(out or ""):
        return tr(pid, sev, "pass", out, "unsafe condition", ms)
    return tr(pid, sev, "fail", out, "safe", ms)


def probe_host_proc(ctx: RunContext) -> TestResult:
    script = "tr '\\0' ' ' < /proc/1/cmdline 2>/dev/null; echo"
    def unsafe(o: str) -> bool:
        s = o.lower()
        return "kubelet" in s or "/usr/lib/systemd/systemd" in s or s.strip().startswith("/sbin/init ")

    return probe_shell_pattern(ctx, "AgentFence.FS.HOST_PROC_VISIBLE", "medium", script, unsafe)


def probe_host_sys(ctx: RunContext) -> TestResult:
    script = "ls /sys/class/dmi/id 2>/dev/null | head"
    def unsafe(o: str) -> bool:
        return bool(o.strip())

    return probe_shell_pattern(ctx, "AgentFence.FS.HOST_SYS_VISIBLE", "medium", script, unsafe)


def probe_kcore(ctx: RunContext) -> TestResult:
    script = "dd if=/proc/kcore of=/dev/null bs=1 count=1 2>&1; echo EXIT:$?"
    def unsafe(o: str) -> bool:
        return "EXIT:0" in o and "Permission denied" not in o

    return probe_shell_pattern(ctx, "AgentFence.FS.KCORE_READABLE", "medium", script, unsafe)


def probe_host_devices(ctx: RunContext) -> TestResult:
    script = "ls /dev/sda /dev/nvme0n1 /dev/vda 2>/dev/null | head -n 1"
    def unsafe(o: str) -> bool:
        return bool((o or "").strip())

    return probe_shell_pattern(ctx, "AgentFence.FS.HOST_DEVICES_VISIBLE", "medium", script, unsafe)


def probe_rootfs_host_shared(ctx: RunContext) -> TestResult:
    script = "awk '$2==\"/\" {print $3,$4}' /proc/self/mountinfo 2>/dev/null | head -n 1"
    def unsafe(o: str) -> bool:
        # host bind mounts often show as bind vs overlay for container root
        return "bind" in (o or "") and "overlay" not in (o or "").lower()

    return probe_shell_pattern(ctx, "AgentFence.FS.ROOTFS_HOST_SHARED", "medium", script, unsafe)


def probe_host_fs_via_proc(ctx: RunContext) -> TestResult:
    script = "ls /proc/1/root/etc/hostname 2>&1 | head -n 1"
    def unsafe(o: str) -> bool:
        return "hostname" in o and "Permission denied" not in o and "No such file" not in o

    return probe_shell_pattern(ctx, "AgentFence.FS.HOST_FS_REACHABLE_VIA_PROC", "medium", script, unsafe)


def probe_file_exists(ctx: RunContext, pid: str, sev: Severity, path: str) -> TestResult:
    t0 = time.time()
    if ctx.dry_run:
        return tr(pid, sev, "skip", "dry-run")
    script = f"test -e {shlex.quote(path)} && echo YES || echo NO"
    rc, out = kubectl_exec(
        ctx.kubeconfig,
        ctx.namespace,
        ctx.target_pod,
        ctx.target_container,
        script,
        ctx.probe_timeout,
    )
    ms = int((time.time() - t0) * 1000)
    if "YES" in (out or ""):
        return tr(pid, sev, "pass", out, "exists", ms)
    return tr(pid, sev, "fail", out, "absent", ms)


def probe_kvm(ctx: RunContext) -> TestResult:
    return probe_file_exists(ctx, "AgentFence.DEVICE.KVM_PRESENT", "high", "/dev/kvm")


def probe_tun(ctx: RunContext) -> TestResult:
    return probe_file_exists(ctx, "AgentFence.DEVICE.TUN_TAP_PRESENT", "high", "/dev/net/tun")


def probe_usb(ctx: RunContext) -> TestResult:
    t0 = time.time()
    if ctx.dry_run:
        return tr("AgentFence.DEVICE.USB_PRESENT", "high", "skip", "dry-run")
    rc, out = kubectl_exec(
        ctx.kubeconfig,
        ctx.namespace,
        ctx.target_pod,
        ctx.target_container,
        "ls /dev/bus/usb 2>/dev/null | head -n 1",
        ctx.probe_timeout,
    )
    ms = int((time.time() - t0) * 1000)
    if (out or "").strip():
        return tr("AgentFence.DEVICE.USB_PRESENT", "high", "pass", out, "usb devfs", ms)
    return tr("AgentFence.DEVICE.USB_PRESENT", "high", "fail", out, "no usb", ms)


def probe_raw_socket(ctx: RunContext) -> TestResult:
    script = r"""python3 - <<'PY'
import socket
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    s.close()
    print('UNSAFE')
except PermissionError:
    print('SAFE')
except OSError as e:
    print('SAFE', e)
PY"""
    t0 = time.time()
    if ctx.dry_run:
        return tr("AgentFence.DEVICE.RAW_SOCKET_USABLE", "high", "skip", "dry-run")
    rc, out = kubectl_exec(
        ctx.kubeconfig,
        ctx.namespace,
        ctx.target_pod,
        ctx.target_container,
        script,
        ctx.probe_timeout,
    )
    ms = int((time.time() - t0) * 1000)
    if "UNSAFE" in (out or ""):
        return tr("AgentFence.DEVICE.RAW_SOCKET_USABLE", "high", "pass", out, "raw icmp", ms)
    return tr("AgentFence.DEVICE.RAW_SOCKET_USABLE", "high", "fail", out, "blocked", ms)


def _pod_spec_flags(ctx: RunContext) -> Tuple[bool, bool, bool]:
    pj = load_target_pod_json(ctx) or {}
    spec = pj.get("spec") or {}
    return (
        bool(spec.get("hostNetwork")),
        bool(spec.get("hostPID")),
        bool(spec.get("hostIPC")),
    )


def probe_pid_ns_host(ctx: RunContext) -> TestResult:
    t0 = time.time()
    hn, hp, hi = _pod_spec_flags(ctx)
    ms = int((time.time() - t0) * 1000)
    if hp:
        return tr("AgentFence.NS.PID_NS_SHARES_HOST", "medium", "pass", "hostPID=true", "spec", ms)
    return tr("AgentFence.NS.PID_NS_SHARES_HOST", "medium", "fail", "hostPID=false", "spec", ms)


def probe_user_ns_map(ctx: RunContext) -> TestResult:
    t0 = time.time()
    if ctx.dry_run:
        return tr("AgentFence.NS.USER_NS_ROOT_MAPS_HOST_ROOT", "medium", "skip", "dry-run")
    rc, out = kubectl_exec(
        ctx.kubeconfig,
        ctx.namespace,
        ctx.target_pod,
        ctx.target_container,
        "cat /proc/self/uid_map 2>/dev/null || true",
        ctx.probe_timeout,
    )
    ms = int((time.time() - t0) * 1000)
    for line in (out or "").splitlines():
        p = line.split()
        if len(p) >= 3 and p[0] == "0" and p[1] == "0":
            return tr("AgentFence.NS.USER_NS_ROOT_MAPS_HOST_ROOT", "medium", "pass", line, "0 0 map", ms)
    return tr("AgentFence.NS.USER_NS_ROOT_MAPS_HOST_ROOT", "medium", "fail", out, "no 0 0 map", ms)


def probe_ipc_ns(ctx: RunContext) -> TestResult:
    t0 = time.time()
    _, _, hi = _pod_spec_flags(ctx)
    ms = int((time.time() - t0) * 1000)
    if hi:
        return tr("AgentFence.NS.IPC_NS_SHARES_HOST", "medium", "pass", "hostIPC=true", ms=ms)
    return tr("AgentFence.NS.IPC_NS_SHARES_HOST", "medium", "fail", "hostIPC=false", ms=ms)


def probe_net_ns(ctx: RunContext) -> TestResult:
    t0 = time.time()
    hn, _, _ = _pod_spec_flags(ctx)
    ms = int((time.time() - t0) * 1000)
    if hn:
        return tr("AgentFence.NS.NET_NS_SHARES_HOST", "medium", "pass", "hostNetwork=true", ms=ms)
    return tr("AgentFence.NS.NET_NS_SHARES_HOST", "medium", "fail", "hostNetwork=false", ms=ms)


def probe_uts_ns(ctx: RunContext) -> TestResult:
    t0 = time.time()
    hn, _, _ = _pod_spec_flags(ctx)
    ms = int((time.time() - t0) * 1000)
    if hn:
        return tr("AgentFence.NS.UTS_NS_SHARES_HOST", "medium", "pass", "hostNetwork implies host UTS risk", ms=ms)
    return tr("AgentFence.NS.UTS_NS_SHARES_HOST", "medium", "fail", "isolated UTS likely", ms=ms)


def node_internal_ip(ctx: RunContext) -> Optional[str]:
    pj = load_target_pod_json(ctx) or {}
    node = (pj.get("spec") or {}).get("nodeName")
    if not node:
        return None
    n = kubectl_get_json(ctx.kubeconfig, ["get", "node", node, "-o", "json"])
    if not n:
        return None
    for addr in (n.get("status") or {}).get("addresses") or []:
        if addr.get("type") == "InternalIP":
            return addr.get("address")
    return None


def probe_host_net_reach(ctx: RunContext) -> TestResult:
    t0 = time.time()
    if ctx.dry_run:
        return tr("AgentFence.NET.HOST_NETWORK_REACHABLE", "high", "skip", "dry-run")
    ip = node_internal_ip(ctx)
    if not ip:
        return tr("AgentFence.NET.HOST_NETWORK_REACHABLE", "high", "skip", "no node IP")
    script = f"nc -z -w2 {shlex.quote(ip)} 22 2>/dev/null && echo OPEN || echo CLOSED"
    rc, out = kubectl_exec(
        ctx.kubeconfig,
        ctx.namespace,
        ctx.target_pod,
        ctx.target_container,
        script,
        ctx.probe_timeout,
    )
    ms = int((time.time() - t0) * 1000)
    if "OPEN" in (out or ""):
        return tr("AgentFence.NET.HOST_NETWORK_REACHABLE", "high", "pass", out, f"ssh port on {ip}", ms)
    return tr("AgentFence.NET.HOST_NETWORK_REACHABLE", "high", "fail", out, "node ssh not reachable", ms)


def probe_imds(ctx: RunContext) -> TestResult:
    t0 = time.time()
    if ctx.dry_run:
        return tr("AgentFence.NET.IMDS_REACHABLE", "high", "skip", "dry-run")
    script = r"""if command -v python3 >/dev/null 2>&1; then
python3 - <<'PY'
import socket
sock = None
try:
    sock = socket.create_connection(("169.254.169.254", 80), 2.0)
    sock.settimeout(2.0)
    sock.sendall(b"GET /latest/meta-data/ HTTP/1.0\r\nHost: 169.254.169.254\r\n\r\n")
    data = sock.recv(256)
    print("HTTP_BYTES", len(data))
    print(data[:200].decode("latin1", "replace"))
except Exception as exc:
    print("CONNECT_FAILED", type(exc).__name__, str(exc)[:120])
finally:
    if sock:
        sock.close()
PY
elif command -v wget >/dev/null 2>&1; then
  wget -qO- --timeout=2 http://169.254.169.254/latest/meta-data/ 2>&1 | head -c 240
elif command -v curl >/dev/null 2>&1; then
  curl -fsS --max-time 2 http://169.254.169.254/latest/meta-data/ 2>&1 | head -c 240
else
  echo NO_HTTP_CLIENT
fi"""
    rc, out = kubectl_exec(
        ctx.kubeconfig,
        ctx.namespace,
        ctx.target_pod,
        ctx.target_container,
        script,
        ctx.probe_timeout,
    )
    ms = int((time.time() - t0) * 1000)
    o = out or ""
    low = o.lower()
    if "NO_HTTP_CLIENT" in o:
        return tr("AgentFence.NET.IMDS_REACHABLE", "high", "skip", o[:500], "no HTTP client available", ms)
    if "CONNECT_FAILED" in o:
        return tr("AgentFence.NET.IMDS_REACHABLE", "high", "fail", o[:500], "metadata TCP connect failed", ms)
    if "not found" in low and ("wget" in low or "curl" in low or "python3" in low):
        return tr("AgentFence.NET.IMDS_REACHABLE", "high", "skip", o[:500], "metadata probe client unavailable", ms)
    m = re.search(r"HTTP_BYTES\s+(\d+)", o)
    if m and int(m.group(1)) > 0:
        return tr("AgentFence.NET.IMDS_REACHABLE", "high", "pass", o[:500], "metadata HTTP response", ms)
    if "ami-" in low or "instance-id" in low or "metadata-flavor" in low or "http/" in low:
        return tr("AgentFence.NET.IMDS_REACHABLE", "high", "pass", o[:500], "metadata-like HTTP response", ms)
    if "connection refused" in low or "timed out" in low or "network is unreachable" in low:
        return tr("AgentFence.NET.IMDS_REACHABLE", "high", "fail", o[:500], "no IMDS", ms)
    return tr("AgentFence.NET.IMDS_REACHABLE", "high", "fail", o[:500], "no IMDS", ms)


def probe_kubelet(ctx: RunContext) -> TestResult:
    t0 = time.time()
    if ctx.dry_run:
        return tr("AgentFence.NET.KUBELET_API_REACHABLE", "high", "skip", "dry-run")
    ip = node_internal_ip(ctx)
    if not ip:
        return tr("AgentFence.NET.KUBELET_API_REACHABLE", "high", "skip", "no node IP")
    script = (
        f"wget -qO- --timeout=2 --no-check-certificate "
        f"https://{shlex.quote(ip)}:10250/pods 2>&1 | head -c 120"
    )
    rc, out = kubectl_exec(
        ctx.kubeconfig,
        ctx.namespace,
        ctx.target_pod,
        ctx.target_container,
        script,
        ctx.probe_timeout,
    )
    ms = int((time.time() - t0) * 1000)
    o = out or ""
    if "Unauthorized" in o or '"kind"' in o or "pods" in o.lower():
        return tr("AgentFence.NET.KUBELET_API_REACHABLE", "high", "pass", o, "kubelet responded", ms)
    return tr("AgentFence.NET.KUBELET_API_REACHABLE", "high", "fail", o, "no kubelet API", ms)


def probe_apiserver_direct(ctx: RunContext) -> TestResult:
    t0 = time.time()
    if ctx.dry_run:
        return tr("AgentFence.NET.APISERVER_DIRECT_REACHABLE", "high", "skip", "dry-run")
    script = (
        "wget -qO- --timeout=3 --no-check-certificate "
        "https://kubernetes.default.svc/version 2>&1 | head -c 200"
    )
    rc, out = kubectl_exec(
        ctx.kubeconfig,
        ctx.namespace,
        ctx.target_pod,
        ctx.target_container,
        script,
        ctx.probe_timeout,
    )
    ms = int((time.time() - t0) * 1000)
    o = out or ""
    if "gitVersion" in o or '"major"' in o:
        return tr("AgentFence.NET.APISERVER_DIRECT_REACHABLE", "high", "pass", o[:500], "apiserver json", ms)
    return tr("AgentFence.NET.APISERVER_DIRECT_REACHABLE", "high", "fail", o[:500], "no version", ms)


def probe_seccomp_bypass(ctx: RunContext) -> TestResult:
    script = r"""python3 - <<'PY'
import ctypes, errno, os
libc = ctypes.CDLL(None, use_errno=True)
SYS_add_key = 248
libc.syscall.restype = ctypes.c_long
ret = libc.syscall(SYS_add_key, 0, 0, 0, 0)
err = ctypes.get_errno()
if ret == -1 and err == errno.EPERM:
    print('SAFE', 'EPERM')
else:
    print('UNSAFE', 'ret', ret, 'errno', err)
PY"""
    t0 = time.time()
    if ctx.dry_run:
        return tr("AgentFence.IDENTITY.SECCOMP_BYPASS_OK", "medium", "skip", "dry-run")
    rc, out = kubectl_exec(
        ctx.kubeconfig,
        ctx.namespace,
        ctx.target_pod,
        ctx.target_container,
        script,
        ctx.probe_timeout,
    )
    ms = int((time.time() - t0) * 1000)
    o = out or ""
    if rc != 0:
        return tr("AgentFence.IDENTITY.SECCOMP_BYPASS_OK", "medium", "skip", o, "exec failed", ms)
    if "UNSAFE" in o:
        state = seccomp_state_for_context(ctx)
        if gvisor_runtime_seccomp_verified(state):
            evidence = (
                f"{o}\n"
                f"GVISOR_RUNTIME_SECCOMP_VERIFIED {format_seccomp_state_evidence(state)}"
            )
            return tr(
                "AgentFence.IDENTITY.SECCOMP_BYPASS_OK",
                "medium",
                "fail",
                evidence,
                "gvisor RuntimeDefault mediation",
                ms,
            )
        return tr("AgentFence.IDENTITY.SECCOMP_BYPASS_OK", "medium", "pass", out, "syscall not EPERM", ms)
    if "SAFE" in o and "EPERM" in o:
        return tr("AgentFence.IDENTITY.SECCOMP_BYPASS_OK", "medium", "fail", out, "EPERM", ms)
    return tr("AgentFence.IDENTITY.SECCOMP_BYPASS_OK", "medium", "skip", o, "unexpected probe output", ms)


def probe_no_new_privs_bypass(ctx: RunContext) -> TestResult:
    # Heuristic: try to read nnp from status
    t0 = time.time()
    if ctx.dry_run:
        return tr("AgentFence.IDENTITY.NO_NEW_PRIVS_BYPASS_OK", "medium", "skip", "dry-run")
    rc, out = kubectl_exec(
        ctx.kubeconfig,
        ctx.namespace,
        ctx.target_pod,
        ctx.target_container,
        "grep -E '^NoNewPrivs:' /proc/self/status 2>/dev/null || true",
        ctx.probe_timeout,
    )
    ms = int((time.time() - t0) * 1000)
    if "NoNewPrivs:\t0" in (out or "") or "NoNewPrivs: 0" in (out or ""):
        return tr("AgentFence.IDENTITY.NO_NEW_PRIVS_BYPASS_OK", "medium", "pass", out, "nnp off", ms)
    return tr("AgentFence.IDENTITY.NO_NEW_PRIVS_BYPASS_OK", "medium", "fail", out, "nnp on or unknown", ms)


def probe_cap_bounding(ctx: RunContext) -> TestResult:
    t0 = time.time()
    if ctx.dry_run:
        return tr("AgentFence.IDENTITY.CAP_BOUNDING_PERMISSIVE", "medium", "skip", "dry-run")
    rc, out = kubectl_exec(
        ctx.kubeconfig,
        ctx.namespace,
        ctx.target_pod,
        ctx.target_container,
        "grep ^CapBnd: /proc/self/status 2>/dev/null",
        ctx.probe_timeout,
    )
    ms = int((time.time() - t0) * 1000)
    m = re.search(r"CapBnd:\s*([0-9a-fA-F]+)", out or "")
    if not m:
        return tr("AgentFence.IDENTITY.CAP_BOUNDING_PERMISSIVE", "medium", "skip", out, ms=ms)
    mask = int(m.group(1), 16)
    bad = (1 << 21) | (1 << 12) | (1 << 1)  # SYS_ADMIN, NET_ADMIN, DAC_OVERRIDE
    if mask & bad:
        return tr("AgentFence.IDENTITY.CAP_BOUNDING_PERMISSIVE", "medium", "pass", out, "dangerous cap in bounding set", ms)
    return tr("AgentFence.IDENTITY.CAP_BOUNDING_PERMISSIVE", "medium", "fail", out, "tight caps", ms)


def probe_procfs_hidepid(ctx: RunContext) -> TestResult:
    t0 = time.time()
    if ctx.dry_run:
        return tr("AgentFence.IDENTITY.PROCFS_HIDEPID_LAX", "medium", "skip", "dry-run")
    rc, out = kubectl_exec(
        ctx.kubeconfig,
        ctx.namespace,
        ctx.target_pod,
        ctx.target_container,
        "ls /proc 2>/dev/null | grep -E '^[0-9]+$' | wc -l",
        ctx.probe_timeout,
    )
    ms = int((time.time() - t0) * 1000)
    try:
        n = int((out or "").strip())
    except ValueError:
        return tr("AgentFence.IDENTITY.PROCFS_HIDEPID_LAX", "medium", "skip", out, ms=ms)
    if n > 80:
        return tr("AgentFence.IDENTITY.PROCFS_HIDEPID_LAX", "medium", "pass", out, "many pids visible", ms)
    return tr("AgentFence.IDENTITY.PROCFS_HIDEPID_LAX", "medium", "fail", out, "few pids", ms)


def probe_cpuinfo_leak(ctx: RunContext) -> TestResult:
    t0 = time.time()
    if ctx.dry_run:
        return tr("AgentFence.SIDE.HOST_CPUINFO_LEAKED", "low", "skip", "dry-run")
    rc, out = kubectl_exec(
        ctx.kubeconfig,
        ctx.namespace,
        ctx.target_pod,
        ctx.target_container,
        "grep -i hypervisor /proc/cpuinfo 2>/dev/null | head -n1",
        ctx.probe_timeout,
    )
    ms = int((time.time() - t0) * 1000)
    o = (out or "").lower()
    if "hypervisor" in o:
        return tr("AgentFence.SIDE.HOST_CPUINFO_LEAKED", "low", "fail", out, "guest cpuinfo", ms)
    return tr("AgentFence.SIDE.HOST_CPUINFO_LEAKED", "low", "pass", out, "no hypervisor flag (possible host leak)", ms)


def probe_dmi_leak(ctx: RunContext) -> TestResult:
    t0 = time.time()
    if ctx.dry_run:
        return tr("AgentFence.SIDE.HOST_DMI_LEAKED", "low", "skip", "dry-run")
    rc, out = kubectl_exec(
        ctx.kubeconfig,
        ctx.namespace,
        ctx.target_pod,
        ctx.target_container,
        "cat /sys/class/dmi/id/sys_vendor 2>/dev/null; cat /sys/class/dmi/id/product_name 2>/dev/null",
        ctx.probe_timeout,
    )
    ms = int((time.time() - t0) * 1000)
    if (out or "").strip():
        return tr("AgentFence.SIDE.HOST_DMI_LEAKED", "low", "pass", out, "DMI visible", ms)
    return tr("AgentFence.SIDE.HOST_DMI_LEAKED", "low", "fail", out, "no DMI", ms)


def probe_high_res_timer(ctx: RunContext) -> TestResult:
    script = r"""python3 - <<'PY'
import ctypes, os
class timespec(ctypes.Structure):
    _fields_ = [('tv_sec', ctypes.c_long), ('tv_nsec', ctypes.c_long)]
CLOCK_MONOTONIC_RAW = 4
try:
    libc = ctypes.CDLL(None)
    ts = timespec()
    if hasattr(libc, 'clock_getres'):
        libc.clock_getres(CLOCK_MONOTONIC_RAW, ctypes.byref(ts))
        ns = ts.tv_nsec + ts.tv_sec * 1_000_000_000
        print('RES', ns)
    else:
        print('SKIP')
except Exception as e:
    print('SKIP', e)
PY"""
    t0 = time.time()
    if ctx.dry_run:
        return tr("AgentFence.SIDE.HIGH_RES_TIMER_AVAILABLE", "low", "skip", "dry-run")
    rc, out = kubectl_exec(
        ctx.kubeconfig,
        ctx.namespace,
        ctx.target_pod,
        ctx.target_container,
        script,
        ctx.probe_timeout,
    )
    ms = int((time.time() - t0) * 1000)
    m = re.search(r"RES\s+(\d+)", out or "")
    if m and int(m.group(1)) < 1000:
        return tr("AgentFence.SIDE.HIGH_RES_TIMER_AVAILABLE", "low", "pass", out, "sub-microsecond", ms)
    if "SKIP" in (out or ""):
        return tr("AgentFence.SIDE.HIGH_RES_TIMER_AVAILABLE", "low", "skip", out, ms=ms)
    return tr("AgentFence.SIDE.HIGH_RES_TIMER_AVAILABLE", "low", "fail", out, "coarse timer", ms)


def probe_cache_topology(ctx: RunContext) -> TestResult:
    t0 = time.time()
    if ctx.dry_run:
        return tr("AgentFence.SIDE.HOST_CACHE_TOPOLOGY_LEAKED", "low", "skip", "dry-run")
    rc, out = kubectl_exec(
        ctx.kubeconfig,
        ctx.namespace,
        ctx.target_pod,
        ctx.target_container,
        "cat /sys/devices/system/cpu/cpu0/cache/index0/size 2>/dev/null || true",
        ctx.probe_timeout,
    )
    ms = int((time.time() - t0) * 1000)
    if re.search(r"\d+K", out or ""):
        return tr("AgentFence.SIDE.HOST_CACHE_TOPOLOGY_LEAKED", "low", "pass", out, "cache size visible", ms)
    return tr("AgentFence.SIDE.HOST_CACHE_TOPOLOGY_LEAKED", "low", "fail", out, "no cache info", ms)


PROBE_RUNNERS: Dict[str, Callable[[RunContext], TestResult]] = {
    "AgentFence.ID.RUN_AS_UID_ZERO": probe_run_as_uid_zero,
    "AgentFence.ID.ROOTFS_WRITE_OK": probe_rootfs_write,
    "AgentFence.ID.SA_TOKEN_READABLE": probe_sa_token,
    "AgentFence.REMOTE.UNAUTH_SERVICE_REACHABLE": probe_remote_unauth,
    "AgentFence.HOSTPATH.SENSITIVE_WRITE_OK": probe_hostpath_write,
    "AgentFence.KERNEL.KEXEC_REACHABLE": probe_kexec,
    "AgentFence.KERNEL.INIT_MODULE_REACHABLE": probe_init_module,
    "AgentFence.KERNEL.BPF_PROG_LOAD_REACHABLE": probe_bpf,
    "AgentFence.KERNEL.USERFAULTFD_REACHABLE": probe_userfaultfd,
    "AgentFence.KERNEL.PERF_EVENT_OPEN_REACHABLE": probe_perf_event,
    "AgentFence.KERNEL.KALLSYMS_VISIBLE": probe_kallsyms,
    "AgentFence.KERNEL.DMESG_VISIBLE": probe_dmesg,
    "AgentFence.FS.HOST_PROC_VISIBLE": probe_host_proc,
    "AgentFence.FS.HOST_SYS_VISIBLE": probe_host_sys,
    "AgentFence.FS.KCORE_READABLE": probe_kcore,
    "AgentFence.FS.HOST_DEVICES_VISIBLE": probe_host_devices,
    "AgentFence.FS.ROOTFS_HOST_SHARED": probe_rootfs_host_shared,
    "AgentFence.FS.HOST_FS_REACHABLE_VIA_PROC": probe_host_fs_via_proc,
    "AgentFence.DEVICE.KVM_PRESENT": probe_kvm,
    "AgentFence.DEVICE.TUN_TAP_PRESENT": probe_tun,
    "AgentFence.DEVICE.USB_PRESENT": probe_usb,
    "AgentFence.DEVICE.RAW_SOCKET_USABLE": probe_raw_socket,
    "AgentFence.NS.PID_NS_SHARES_HOST": probe_pid_ns_host,
    "AgentFence.NS.USER_NS_ROOT_MAPS_HOST_ROOT": probe_user_ns_map,
    "AgentFence.NS.IPC_NS_SHARES_HOST": probe_ipc_ns,
    "AgentFence.NS.NET_NS_SHARES_HOST": probe_net_ns,
    "AgentFence.NS.UTS_NS_SHARES_HOST": probe_uts_ns,
    "AgentFence.NET.HOST_NETWORK_REACHABLE": probe_host_net_reach,
    "AgentFence.NET.IMDS_REACHABLE": probe_imds,
    "AgentFence.NET.KUBELET_API_REACHABLE": probe_kubelet,
    "AgentFence.NET.APISERVER_DIRECT_REACHABLE": probe_apiserver_direct,
    "AgentFence.IDENTITY.SECCOMP_BYPASS_OK": probe_seccomp_bypass,
    "AgentFence.IDENTITY.NO_NEW_PRIVS_BYPASS_OK": probe_no_new_privs_bypass,
    "AgentFence.IDENTITY.CAP_BOUNDING_PERMISSIVE": probe_cap_bounding,
    "AgentFence.IDENTITY.PROCFS_HIDEPID_LAX": probe_procfs_hidepid,
    "AgentFence.SIDE.HOST_CPUINFO_LEAKED": probe_cpuinfo_leak,
    "AgentFence.SIDE.HOST_DMI_LEAKED": probe_dmi_leak,
    "AgentFence.SIDE.HIGH_RES_TIMER_AVAILABLE": probe_high_res_timer,
    "AgentFence.SIDE.HOST_CACHE_TOPOLOGY_LEAKED": probe_cache_topology,
}


def run_all_probes(ctx: RunContext) -> List[TestResult]:
    """Single loop over unified CATALOG — no separate pools."""
    out: List[TestResult] = []
    for spec in CATALOG:
        fn = PROBE_RUNNERS.get(spec.id)
        if not fn:
            out.append(
                tr(spec.id, spec.severity, "skip", "", "no runner registered")
            )
            continue
        try:
            out.append(fn(ctx))
        except Exception as e:
            out.append(
                tr(
                    spec.id,
                    spec.severity,
                    "skip",
                    str(e),
                    "runner exception",
                )
            )
    return out


def build_context(
    namespace: str,
    kubeconfig: str,
    target_override: Optional[str],
    dry_run: bool,
    timeout: int,
    allow_node_runtime_remediation: bool = False,
) -> RunContext:
    if dry_run:
        target = target_override or "dry-run-target"
        return RunContext(
            namespace=namespace,
            kubeconfig=kubeconfig,
            target_pod=target,
            target_container="dry-run-container",
            attacker_pod="dry-run-attacker",
            attacker_container="dry-run-container",
            target_ip="0.0.0.0",
            dry_run=True,
            probe_timeout=timeout,
            allow_node_runtime_remediation=allow_node_runtime_remediation,
        )
    tp, tc = auto_select_target(kubeconfig, namespace, target_override)
    ap, ac = auto_select_attacker(kubeconfig, namespace)
    tip = pod_ip(kubeconfig, namespace, tp)
    return RunContext(
        namespace=namespace,
        kubeconfig=kubeconfig,
        target_pod=tp,
        target_container=tc,
        attacker_pod=ap,
        attacker_container=ac,
        target_ip=tip,
        dry_run=dry_run,
        probe_timeout=timeout,
        allow_node_runtime_remediation=allow_node_runtime_remediation,
    )


def write_json(path: str, payload: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, ensure_ascii=False)


def write_text_file(path: str, text: str, executable: bool = False) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    if executable:
        os.chmod(path, 0o755)


PROBE_REPORT_OVERRIDES: Dict[str, Dict[str, str]] = {
    "AgentFence.REMOTE.UNAUTH_SERVICE_REACHABLE": {
        "title": "Review sibling-pod service reachability",
        "explanation": "A sibling pod can reach target listeners. This is review-only because the port may be required application ingress; AgentFence needs declared communication intent before scoring it as a policy violation.",
        "manual_fix": "Inventory required callers, ports, and authentication gates. If sibling pods are not approved callers, replace broad same-namespace allow rules with target-specific allowlists.",
    },
    "AgentFence.KERNEL.PERF_EVENT_OPEN_REACHABLE": {
        "title": "Tighten perf_event_open exposure",
        "explanation": "The workload can reach performance-monitoring syscall surface. That can leak host information and side-channel signals, and on weak kernels it may assist exploitation.",
        "manual_fix": "Restrict perf_event_open with node/runtime policy, review kernel.perf_event_paranoid, and keep explicit observability exceptions only for workloads that require them.",
    },
    "AgentFence.KERNEL.DMESG_VISIBLE": {
        "title": "Restrict kernel log visibility",
        "explanation": "Kernel log output can reveal runtime, host, driver, and exploit-relevant details to the workload.",
        "manual_fix": "Enable node dmesg restrictions, remove unnecessary privileged/capability grants, and prefer a runtime profile that blocks kernel log access for untrusted workloads.",
    },
    "AgentFence.FS.HOST_SYS_VISIBLE": {
        "title": "Limit sysfs exposure from the container",
        "explanation": "Visible host sysfs paths expose hardware, platform, and kernel interface details that help fingerprint the node.",
        "manual_fix": "Remove broad sysfs/hostPath mounts, avoid privileged mode, and use stronger sandbox or VM isolation where sysfs masking is required.",
    },
    "AgentFence.FS.HOST_FS_REACHABLE_VIA_PROC": {
        "title": "Block proc-based host filesystem reachability",
        "explanation": "The workload can traverse host-like filesystem paths through proc. That weakens filesystem isolation and may expose sensitive node files.",
        "manual_fix": "Remove dangerous host mounts, avoid shared process namespaces, tighten runtime procfs masking, and re-run the probe after runtimeClass or mount changes.",
    },
    "AgentFence.DEVICE.TUN_TAP_PRESENT": {
        "title": "Review TUN/TAP device exposure",
        "explanation": "TUN/TAP devices can enable packet tunneling and bypass expected pod network controls when exposed unnecessarily.",
        "manual_fix": "Remove /dev/net/tun unless the workload explicitly needs VPN or tunneling behavior; otherwise isolate it with a dedicated profile and network policy.",
    },
    "AgentFence.NS.USER_NS_ROOT_MAPS_HOST_ROOT": {
        "title": "Review user namespace / UID mapping configuration",
        "explanation": "A root-to-root user namespace mapping weakens UID isolation and can make container-root semantics more sensitive.",
        "manual_fix": "Enable user namespace remapping where supported, align image USER with pod runAsUser/runAsGroup, and document residual mapping risk where remapping is unavailable.",
    },
    "AgentFence.NET.IMDS_REACHABLE": {
        "title": "Block cloud metadata egress",
        "explanation": "Metadata service reachability can expose instance identity, bootstrap data, or cloud credentials depending on provider configuration.",
        "manual_fix": "Deny 169.254.169.254/32 and provider equivalents using CNI/VPC controls or tightly scoped NetworkPolicy after validating workload identity behavior.",
    },
    "AgentFence.IDENTITY.SECCOMP_BYPASS_OK": {
        "title": "Enforce a restrictive seccomp profile",
        "explanation": "A weak or ineffective seccomp profile leaves risky syscall surface available to the workload.",
        "manual_fix": "Start with RuntimeDefault, then validate whether the runtime actually blocks the probe. Use a Localhost profile or runtime-specific policy when RuntimeDefault is insufficient.",
    },
    "AgentFence.IDENTITY.NO_NEW_PRIVS_BYPASS_OK": {
        "title": "Enable no-new-privileges",
        "explanation": "NoNewPrivs disabled can permit privilege-gaining execution paths such as setuid helpers.",
        "manual_fix": "Set allowPrivilegeEscalation: false when compatible, remove setuid helpers where possible, and validate process startup and helper behavior.",
    },
    "AgentFence.IDENTITY.CAP_BOUNDING_PERMISSIVE": {
        "title": "Minimize Linux capability bounding set",
        "explanation": "Dangerous capabilities increase kernel, filesystem, and network attack surface after compromise.",
        "manual_fix": "Drop ALL capabilities by default, re-add only documented required capabilities, and validate network diagnostics or observability workflows separately.",
    },
    "AgentFence.SIDE.HOST_DMI_LEAKED": {
        "title": "Mask host DMI information",
        "explanation": "DMI/SMBIOS values reveal platform details and can help fingerprint the host environment.",
        "manual_fix": "Remove DMI sysfs exposure, review runtime masking options, and document residual hardware fingerprinting risk where full masking is not feasible.",
    },
    "AgentFence.SIDE.HIGH_RES_TIMER_AVAILABLE": {
        "title": "Assess high-resolution timer exposure",
        "explanation": "High-resolution timers can improve timing side-channel experiments against shared resources.",
        "manual_fix": "Treat this as residual risk on shared kernels, use stronger isolation or dedicated nodes for hostile workloads, and document timer resolution in the threat model.",
    },
    "AgentFence.SIDE.HOST_CACHE_TOPOLOGY_LEAKED": {
        "title": "Reduce cache topology leakage",
        "explanation": "Cache topology details can support side-channel planning and host fingerprinting.",
        "manual_fix": "Prefer VM/sandbox isolation or dedicated nodes for hostile workloads, and document residual cache topology exposure when it cannot be masked.",
    },
}


def probe_title(probe_id: str) -> str:
    override = PROBE_REPORT_OVERRIDES.get(probe_id) or {}
    if override.get("title"):
        return override["title"]
    recipe = REMEDIATION_RECIPES.get(probe_id)
    return recipe.title if recipe else probe_id


def report_fix_class(item: Optional[Dict[str, Any]], recipe: Optional[RemediationRecipe]) -> str:
    if item and item.get("action_type") == "auto_fix" and item.get("auto_applicable"):
        return "auto_fix"
    if recipe and recipe.action_type == "auto_fix":
        return "guarded_auto"
    if recipe and recipe.action_type == "hybrid":
        return "hybrid_manual"
    return "manual"


def result_dict_map(results: Optional[List[Any]]) -> Dict[str, Dict[str, Any]]:
    return {r.get("id"): r for r in result_dicts(results) if r.get("id")}


def result_from_dict(d: Dict[str, Any]) -> TestResult:
    return TestResult(
        id=canonical_probe_id(d.get("id")),
        severity=d.get("severity") or "low",
        status=d.get("status") or "skip",
        evidence=str(d.get("evidence") or ""),
        matched_clause=str(d.get("matched_clause") or ""),
        duration_ms=int(d.get("duration_ms") or 0),
    )


def remediation_item_map(remediation_plan: Optional[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    out: Dict[str, Dict[str, Any]] = {}
    for item in (remediation_plan or {}).get("items", []):
        if not item.get("probe_id"):
            continue
        normalized = dict(item)
        normalized["probe_id"] = canonical_probe_id(item.get("probe_id"))
        out[normalized["probe_id"]] = normalized
    return out


def fixed_probe_ids_from_apply(remediation_apply: Optional[Dict[str, Any]]) -> set:
    fixed = set()
    for record in (remediation_apply or {}).get("records") or []:
        fixed.update(
            canonical_probe_id(x)
            for x in record.get("resolved_probe_ids") or []
            if x and is_scored_probe(x)
        )
    return fixed


def records_by_probe(remediation_apply: Optional[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    out: Dict[str, List[Dict[str, Any]]] = {}
    for record in (remediation_apply or {}).get("records") or []:
        probe_ids = list(record.get("probe_ids") or [])
        if record.get("probe_id"):
            probe_ids.append(record["probe_id"])
        for pid in probe_ids:
            out.setdefault(canonical_probe_id(pid), []).append(record)
    return out


def enriched_probe_entry(
    probe: ProbeSpec,
    result: Optional[Dict[str, Any]],
    item: Optional[Dict[str, Any]],
    remediation_apply: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    recipe = REMEDIATION_RECIPES.get(probe.id)
    override = PROBE_REPORT_OVERRIDES.get(probe.id) or {}
    status = (result or {}).get("status") or "not_observed"
    review_only = is_review_only_probe(probe.id)
    fix_class = "manual_review" if review_only else report_fix_class(item, recipe)
    fix_group = (recipe.dry_run_artifact if recipe else "") or "manual"
    related_records = records_by_probe(remediation_apply).get(probe.id, [])
    fixed = probe.id in fixed_probe_ids_from_apply(remediation_apply)
    attempted = any(r.get("kind") != "manual_recommendation" for r in related_records)
    layer = "Review" if review_only else ("TBE" if probe.id in TBE_PROBE_IDS else "ELE")
    status_meaning = {
        "pass": "unsafe condition observed",
        "fail": "safe for this probe",
        "skip": "not assessed",
        "not_observed": "not present in this report",
    }.get(status, status)
    if review_only and status == "pass":
        status_meaning = "review-only communication exposure observed; score unaffected"
    return {
        "id": probe.id,
        "title": probe_title(probe.id),
        "layer": layer,
        "severity": (result or {}).get("severity") or probe.severity,
        "status": status,
        "status_meaning": status_meaning,
        "evidence": (result or {}).get("evidence") or "",
        "matched_clause": (result or {}).get("matched_clause") or "",
        "issue_explanation": override.get("explanation") or (recipe.risk if recipe else "No issue explanation available."),
        "security_impact": recipe.risk if recipe else "",
        "fix_class": fix_class,
        "fix_group": fix_group,
        "review_only": review_only,
        "score_contributes": not review_only,
        "score_weight": 0.0 if review_only else SEVERITY_WEIGHTS.get((result or {}).get("severity") or probe.severity, 0.0),
        "auto_fix_available": False if review_only else fix_class in ("auto_fix", "guarded_auto"),
        "auto_fix_description": "" if review_only else (recipe.recommendation if recipe else ""),
        "manual_fix": override.get("manual_fix") or (recipe.recommendation if recipe else ""),
        "operator_steps": list(recipe.operator_steps) if recipe else [],
        "validation": recipe.validation if recipe else "",
        "fixed_by_remediation": False if review_only else fixed,
        "auto_attempted": False if review_only else attempted,
        "remediation_records": [
            {
                "kind": r.get("kind"),
                "status": r.get("status"),
                "name": r.get("name"),
                "resolved_probe_ids": r.get("resolved_probe_ids") or [],
                "verification": r.get("verification"),
                "reason": r.get("reason"),
            }
            for r in related_records
        ],
    }


def build_enriched_report(
    action: str,
    context: Dict[str, Any],
    metrics_before: Any,
    results_before: Optional[List[Any]],
    remediation_plan: Optional[Dict[str, Any]] = None,
    remediation_apply: Optional[Dict[str, Any]] = None,
    metrics_after: Optional[Any] = None,
    results_after: Optional[List[Any]] = None,
    evaluation: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    before_map = result_dict_map(results_before)
    after_map = result_dict_map(results_after)
    current_map = after_map or before_map
    item_map = remediation_item_map(remediation_plan)
    coverage = [
        enriched_probe_entry(probe, current_map.get(probe.id), item_map.get(probe.id), remediation_apply)
        for probe in CATALOG
    ]
    unsafe = [e for e in coverage if e["status"] == "pass" and e["score_contributes"]]
    review_only = [e for e in coverage if e["status"] == "pass" and e["review_only"]]
    skipped = [e for e in coverage if e["status"] == "skip"]
    fixed = sorted(pid for pid in (set(before_map) - set(after_map) if after_map else set()) if is_scored_probe(pid))
    if after_map:
        fixed = sorted(
            pid
            for pid, r in before_map.items()
            if is_scored_probe(pid)
            and r.get("status") == "pass"
            and (after_map.get(pid) or {}).get("status") != "pass"
        )
    fixed_from_apply = sorted(fixed_probe_ids_from_apply(remediation_apply))
    before_metrics = metrics_to_dict(metrics_before)
    after_metrics = metrics_to_dict(metrics_after)
    comparison = None
    if after_metrics:
        comparison = {
            "issue_count_before": before_metrics.get("issue_count"),
            "issue_count_after": after_metrics.get("issue_count"),
            "issue_delta": (after_metrics.get("issue_count") or 0) - (before_metrics.get("issue_count") or 0),
            "score_raw_before": before_metrics.get("score_raw"),
            "score_raw_after": after_metrics.get("score_raw"),
            "score_raw_delta": round((after_metrics.get("score_raw") or 0) - (before_metrics.get("score_raw") or 0), 4),
            "headline_before": before_metrics.get("score_normalized"),
            "headline_after": after_metrics.get("score_normalized"),
            "headline_delta": round((after_metrics.get("score_normalized") or 0) - (before_metrics.get("score_normalized") or 0), 4),
            "fixed_probe_ids": fixed,
            "verified_fixed_probe_ids": fixed_from_apply,
            "new_unsafe_probe_ids": sorted(
                pid
                for pid, r in after_map.items()
                if is_scored_probe(pid)
                and r.get("status") == "pass"
                and (before_map.get(pid) or {}).get("status") != "pass"
            ),
            "score_basis": "review-only communication reachability findings are excluded from issue counts and scores",
        }
    return {
        "schema": "agentfence-enriched-report-v1",
        "action": action,
        "context": context,
        "probe_coverage_count": len(coverage),
        "probe_coverage": coverage,
        "unsafe_findings": unsafe,
        "review_only_findings": review_only,
        "skipped_findings": skipped,
        "auto_fixable_probe_ids": [e["id"] for e in unsafe if e["auto_fix_available"]],
        "manual_probe_ids": [e["id"] for e in unsafe if not e["auto_fix_available"]],
        "review_only_probe_ids": [e["id"] for e in review_only],
        "fixed_probe_ids": comparison.get("fixed_probe_ids") if comparison else [],
        "verified_fixed_probe_ids": fixed_from_apply,
        "workload_revalidations": [
            r.get("workload_revalidation")
            for r in (remediation_apply or {}).get("records") or []
            if r.get("workload_revalidation")
        ],
        "workload_config_snapshots_before_autofix": [
            r.get("workload_config_before")
            for r in (remediation_apply or {}).get("records") or []
            if r.get("workload_config_before")
        ],
        "runtime_seccomp_diagnostics": [
            r.get("runtime_seccomp_diagnostic")
            for r in (remediation_apply or {}).get("records") or []
            if r.get("runtime_seccomp_diagnostic")
        ],
        "remaining_manual_findings": [e for e in unsafe + review_only if not e["fixed_by_remediation"]],
        "score_comparison": comparison,
        "f1_f5_summary": {
            k: (evaluation or {}).get(k)
            for k in (
                "F1_runtime_placement",
                "F2_attack_path_containment",
                "F3_remediation_effectiveness",
                "F4_artifact_consistency",
                "F5_recoverability",
            )
        }
        if evaluation
        else None,
    }


def md_escape(value: Any, limit: int = 160) -> str:
    text = str(value or "").replace("\n", " ").replace("|", "\\|")
    return text[:limit]


def write_md(
    path: str,
    title: str,
    results: List[TestResult],
    metrics: ScoreBundle,
    remediation_plan: Optional[Dict[str, Any]] = None,
    remediation_apply: Optional[Dict[str, Any]] = None,
    evaluation: Optional[Dict[str, Any]] = None,
    action: str = "analyze",
    context: Optional[Dict[str, Any]] = None,
    results_after: Optional[List[TestResult]] = None,
    metrics_after: Optional[ScoreBundle] = None,
) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    enriched = build_enriched_report(
        action=action,
        context=context or {},
        metrics_before=metrics,
        results_before=results,
        remediation_plan=remediation_plan,
        remediation_apply=remediation_apply,
        metrics_after=metrics_after,
        results_after=results_after,
        evaluation=evaluation,
    )
    display_results = results_after or results
    display_metrics = metrics_after or metrics
    unsafe = enriched["unsafe_findings"]
    review_only = enriched["review_only_findings"]
    auto_fixable = [e for e in unsafe if e["auto_fix_available"]]
    manual = [e for e in unsafe if not e["auto_fix_available"]]
    comparison = enriched.get("score_comparison")
    lines = [
        f"# {title}",
        "",
        "## Context",
        "",
        f"- namespace: `{(context or {}).get('namespace', '')}`",
        f"- target_pod: `{(context or {}).get('target_pod', '')}`",
        f"- target_container: `{(context or {}).get('target_container', '')}`",
        f"- attacker_pod: `{(context or {}).get('attacker_pod', '')}`",
        "",
        "## Executive Summary",
        "",
        f"- catalog_version: {display_metrics.catalog_version}",
        f"- probes covered: **{enriched['probe_coverage_count']} / {len(CATALOG)}**",
        f"- scored unsafe findings shown here: **{len(unsafe)}**",
        f"- review-only communication findings: **{len(review_only)}**",
        f"- auto-fixable or guarded-auto unsafe findings: **{len(auto_fixable)}**",
        f"- manual/remains-manual unsafe findings: **{len(manual)}**",
        f"- headline_alpha: **{display_metrics.headline_alpha}**",
        f"- **TBE**: issues={display_metrics.tbe_issue_count}, raw={display_metrics.tbe_score_raw}, norm/10={display_metrics.tbe_score_normalized}",
        f"- **ELE**: issues={display_metrics.ele_issue_count}, raw={display_metrics.ele_score_raw}, norm/10={display_metrics.ele_score_normalized}",
        f"- **Total unsafe**: issues={display_metrics.issue_count}, raw={display_metrics.score_raw}",
        f"- **Headline** (/10): **{display_metrics.score_normalized}**",
        f"- skipped probes: {len(display_metrics.skipped)}",
    ]
    if comparison:
        lines.extend(
            [
                "",
                "## Before/After Comparison",
                "",
                f"- issues: {comparison.get('issue_count_before')} -> {comparison.get('issue_count_after')} ({comparison.get('issue_delta')})",
                f"- raw score: {comparison.get('score_raw_before')} -> {comparison.get('score_raw_after')} ({comparison.get('score_raw_delta')})",
                f"- headline: {comparison.get('headline_before')} -> {comparison.get('headline_after')} ({comparison.get('headline_delta')})",
                f"- score basis: {comparison.get('score_basis')}",
                f"- fixed probes: {', '.join(comparison.get('fixed_probe_ids') or []) or 'none'}",
                f"- verified fixed probes: {', '.join(comparison.get('verified_fixed_probe_ids') or []) or 'none'}",
                f"- new unsafe probes: {', '.join(comparison.get('new_unsafe_probe_ids') or []) or 'none'}",
            ]
        )
    if evaluation:
        lines.extend(["", "## F1-F5 Summary", ""])
        for key in (
            "F1_runtime_placement",
            "F2_attack_path_containment",
            "F3_remediation_effectiveness",
            "F4_artifact_consistency",
            "F5_recoverability",
        ):
            factor = evaluation.get(key) or {}
            detail = ""
            if key == "F3_remediation_effectiveness":
                detail = f" headline {factor.get('headline_before')} -> {factor.get('headline_after')}"
            elif key == "F5_recoverability":
                detail = f" restore_ready={factor.get('restore_ready')}"
            lines.append(f"- **{key}**: {factor.get('status', 'unknown')}{detail}")

    fixed_entries = [e for e in enriched["probe_coverage"] if e["fixed_by_remediation"]]
    if remediation_apply:
        lines.extend(
            [
                "",
                "## Remediation Results",
                "",
                f"- status: {remediation_apply.get('status')}",
                f"- applied records: {remediation_apply.get('applied_count', 0)}",
                f"- failed/rolled-back records: {remediation_apply.get('failed_count', 0)}",
                f"- manual recommendations: {remediation_apply.get('manual_count', 0)}",
            ]
        )
        for record in (remediation_apply.get("records") or []):
            label = record.get("name") or record.get("probe_id") or record.get("kind")
            resolved = ", ".join(record.get("resolved_probe_ids") or [])
            verification = (record.get("verification") or {}).get("status")
            lines.append(f"- `{record.get('kind')}` {label}: {record.get('status')} verification={verification or 'n/a'} resolved={resolved or 'none'}")
            workload_health = record.get("workload_revalidation") or {}
            if workload_health:
                lines.append(
                    f"  - workload revalidation: {workload_health.get('status')} "
                    f"pod_recreated={workload_health.get('pod_recreated')} "
                    f"running_pods={workload_health.get('running_pod_count')}"
                )
                conn = workload_health.get("connectivity_checks") or []
                if conn:
                    ok = sum(1 for c in conn if c.get("status") == "reachable")
                    lines.append(f"  - captured TCP egress checks: {ok}/{len(conn)} reachable")
            snapshot = record.get("workload_config_before") or {}
            if snapshot:
                containers = ", ".join(c.get("name") or "" for c in snapshot.get("containers") or [])
                lines.append(
                    f"  - pre-auto-fix workload snapshot: `{snapshot.get('workload_kind')}/{snapshot.get('workload_name')}` "
                    f"containers={containers or 'none'} runtime={snapshot.get('runtime_class') or 'default'}"
                )
            runtime_diag = record.get("runtime_seccomp_diagnostic") or {}
            if runtime_diag:
                runtime = runtime_diag.get("runtime") or {}
                lines.append(
                    f"  - runtime seccomp: family={runtime.get('family')} handler={runtime.get('handler') or 'default'} "
                    f"pod_profile={runtime_diag.get('pod_seccomp_profile')} "
                    f"process_active={runtime_diag.get('process_seccomp_active')} "
                    f"runtime_config_required={runtime_diag.get('runtime_config_required')}"
                )
                if runtime_diag.get("recommendation"):
                    lines.append(f"  - runtime recommendation: {runtime_diag.get('recommendation')}")

    if review_only:
        lines.extend(["", "## Review-Only Communication Exposure", ""])
        for e in review_only:
            lines.extend(
                [
                    f"### `{e['id']}` — {e['title']}",
                    "",
                    f"- layer: {e['layer']} | severity: {e['severity']} | status: {e['status']} ({e['status_meaning']})",
                    f"- score impact: none | automatic remediation: none",
                    f"- issue: {e['issue_explanation']}",
                    f"- evidence: `{md_escape(e['evidence'], 220)}`",
                    f"- manual fix: {e['manual_fix'] or 'manual review required'}",
                    f"- validation: {e['validation'] or 're-run the probe after defining communication intent'}",
                ]
            )
            if e["operator_steps"]:
                lines.append("- operator steps:")
                for step in e["operator_steps"]:
                    lines.append(f"  - {step}")
            lines.append("")
    if fixed_entries:
        lines.extend(["", "## Auto-Fixed Issues", ""])
        for e in fixed_entries:
            lines.extend(
                [
                    f"### `{e['id']}` — {e['title']}",
                    "",
                    f"- layer: {e['layer']} | severity: {e['severity']} | fix_class: {e['fix_class']} | fix_group: {e['fix_group']}",
                    f"- issue: {e['issue_explanation']}",
                    f"- auto fix applied/verified: {e['fixed_by_remediation']}",
                    f"- validation: {e['validation']}",
                    "",
                ]
            )

    if unsafe:
        lines.extend(["", "## Unsafe Findings Requiring Attention", ""])
        for e in unsafe:
            lines.extend(
                [
                    f"### `{e['id']}` — {e['title']}",
                    "",
                    f"- layer: {e['layer']} | severity: {e['severity']} | status: {e['status']} ({e['status_meaning']})",
                    f"- fix_class: {e['fix_class']} | fix_group: {e['fix_group']} | auto_fix_available: {e['auto_fix_available']}",
                    f"- issue: {e['issue_explanation']}",
                    f"- evidence: `{md_escape(e['evidence'], 220)}`",
                    f"- automatic remediation path: {e['auto_fix_description'] or 'none'}",
                    f"- manual fix: {e['manual_fix'] or 'manual review required'}",
                    f"- validation: {e['validation'] or 're-run the probe after remediation'}",
                ]
            )
            if e["operator_steps"]:
                lines.append("- operator steps:")
                for step in e["operator_steps"]:
                    lines.append(f"  - {step}")
            lines.append("")

    lines.extend(
        [
            "",
            "## Probe Coverage: All 39",
            "",
            "| layer | id | title | severity | status | fix_class | evidence (trunc) |",
            "|---|---|---|---|---|---|---|",
        ]
    )
    for e in enriched["probe_coverage"]:
        lines.append(
            f"| {e['layer']} | {e['id']} | {md_escape(e['title'], 80)} | {e['severity']} | {e['status']} | {e['fix_class']} | {md_escape(e['evidence'], 120)} |"
        )

    lines.extend(
        [
            "",
            "## Raw Results",
        "",
        "| layer | id | severity | status | matched | evidence (trunc) |",
        "|---|---|---|---|---|---|",
    ]
    )
    for r in display_results:
        cid = canonical_probe_id(r.id)
        layer = "Review" if is_review_only_probe(cid) else ("TBE" if cid in TBE_PROBE_IDS else "ELE")
        ev = md_escape(r.evidence, 120)
        lines.append(
            f"| {layer} | {cid} | {r.severity} | {r.status} | {r.matched_clause} | {ev} |"
        )
    if remediation_plan:
        lines.extend(
            [
                "",
                "## Remediation Coverage Summary",
                "",
                f"- recipes: {remediation_plan.get('coverage', {}).get('recipe_count')} / {remediation_plan.get('coverage', {}).get('catalog_count')}",
                f"- actionable findings: {remediation_plan.get('actionable_count', 0)}",
            ]
        )
        for item in (remediation_plan.get("actionable_items") or []):
            lines.append(
                f"- `{item.get('probe_id')}` -> `{item.get('action_type')}`: {item.get('title')}"
            )
    lines.append("")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def context_from_ctx(ctx: RunContext) -> Dict[str, Any]:
    return {
        "namespace": ctx.namespace,
        "target_pod": ctx.target_pod,
        "target_container": ctx.target_container,
        "attacker_pod": ctx.attacker_pod,
        "attacker_container": ctx.attacker_container,
        "target_ip": ctx.target_ip,
        "dry_run": ctx.dry_run,
    }


# Namespaced API objects to snapshot into a rollback-oriented bundle (order = preferred apply order).
BACKUP_NAMESPACE_KINDS: Tuple[str, ...] = (
    "serviceaccounts",
    "roles",
    "rolebindings",
    "configmaps",
    "networkpolicies",
    "services",
    "ingresses",
    "persistentvolumeclaims",
    "deployments",
    "statefulsets",
    "daemonsets",
    "replicasets",
    "horizontalpodautoscalers",
    "poddisruptionbudgets",
    "limitranges",
    "resourcequotas",
)

_BACKUP_KIND_ORDER: Dict[str, int] = {k: i for i, k in enumerate(BACKUP_NAMESPACE_KINDS)}

COMPREHENSIVE_BACKUP_SCHEMA = "agentfence-restore-checkpoint-v2"

BASE_NAMESPACE_RESOURCES: Tuple[str, ...] = (
    "serviceaccounts",
    "roles.rbac.authorization.k8s.io",
    "rolebindings.rbac.authorization.k8s.io",
    "configmaps",
    "secrets",
    "services",
    "endpoints",
    "networkpolicies.networking.k8s.io",
    "persistentvolumeclaims",
    "pods",
    "replicasets.apps",
    "deployments.apps",
    "statefulsets.apps",
    "daemonsets.apps",
    "jobs.batch",
    "cronjobs.batch",
    "horizontalpodautoscalers.autoscaling",
    "poddisruptionbudgets.policy",
    "limitranges",
    "resourcequotas",
    "ingresses.networking.k8s.io",
    "gateways.gateway.networking.k8s.io",
    "httproutes.gateway.networking.k8s.io",
    "referencegrants.gateway.networking.k8s.io",
)

CLUSTER_DEPENDENCY_RESOURCES: Tuple[str, ...] = (
    "runtimeclasses.node.k8s.io",
    "storageclasses.storage.k8s.io",
    "volumesnapshotclasses.snapshot.storage.k8s.io",
    "priorityclasses.scheduling.k8s.io",
)


def _strip_managed_fields(obj: Any) -> Any:
    if isinstance(obj, dict):
        obj.pop("managedFields", None)
        for v in obj.values():
            _strip_managed_fields(v)
    elif isinstance(obj, list):
        for x in obj:
            _strip_managed_fields(x)
    return obj


def _safe_backup_filename(s: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "_", s)[:200] or "unnamed"


def _write_bundle_checksums(bundle_dir: str) -> str:
    checksum_path = os.path.join(bundle_dir, "checksums.sha256")
    lines: List[str] = []
    for root, _, files in os.walk(bundle_dir):
        for fn in sorted(files):
            if fn == "checksums.sha256":
                continue
            fp = os.path.join(root, fn)
            rel = os.path.relpath(fp, bundle_dir)
            h = hashlib.sha256()
            with open(fp, "rb") as bf:
                for chunk in iter(lambda: bf.read(65536), b""):
                    h.update(chunk)
            lines.append(f"{h.hexdigest()}  {rel}\n")
    with open(checksum_path, "w", encoding="utf-8") as cf:
        cf.writelines(lines)
    return checksum_path


def create_namespace_backup_bundle(
    kubeconfig: str,
    namespace: str,
    parent_dir: str,
    *,
    include_secrets: bool = False,
    run_velero: bool = False,
) -> Dict[str, Any]:
    """Dump namespaced objects to JSON plus manifest, restore script, and checksums."""
    stamp = now_stamp()
    bundle_name = f"rollback_bundle_{_safe_backup_filename(namespace)}_{stamp}"
    bundle_dir = os.path.join(parent_dir, bundle_name)
    objects_dir = os.path.join(bundle_dir, "objects")
    os.makedirs(objects_dir, exist_ok=True)

    kinds = list(BACKUP_NAMESPACE_KINDS)
    if include_secrets:
        kinds.append("secrets")

    captured: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []

    for kind in kinds:
        data = kubectl_get_json(kubeconfig, ["get", kind, "-n", namespace])
        if data is None:
            errors.append({"kind": kind, "error": "kubectl get failed or invalid JSON"})
            continue
        items = data.get("items") or []
        for item in items:
            meta = item.get("metadata") or {}
            name = meta.get("name") or "unknown"
            api = item.get("apiVersion") or ""
            okind = item.get("kind") or kind
            item_copy = json.loads(json.dumps(item))
            _strip_managed_fields(item_copy)
            fn = f"{kind}__{_safe_backup_filename(name)}.json"
            obj_path = os.path.join(objects_dir, fn)
            with open(obj_path, "w", encoding="utf-8") as wf:
                json.dump(item_copy, wf, indent=2, sort_keys=True)
            captured.append(
                {
                    "kind": kind,
                    "apiVersion": api,
                    "objectKind": okind,
                    "name": name,
                    "file": fn,
                }
            )

    manifest: Dict[str, Any] = {
        "schema": "agentfence-backup-bundle-v1",
        "created_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "namespace": namespace,
        "kubeconfig_basename": os.path.basename(kubeconfig) if kubeconfig else "",
        "catalog_version": CATALOG_VERSION,
        "include_secrets": include_secrets,
        "objects": sorted(
            captured,
            key=lambda o: (_BACKUP_KIND_ORDER.get(str(o.get("kind")), 999), str(o.get("name"))),
        ),
        "errors": errors,
        "velero_backup_name": None,
        "velero_message": None,
    }

    if run_velero:
        vb = f"af-pre-{_safe_backup_filename(namespace)}-{stamp}"
        if shutil.which("velero"):
            try:
                pr = subprocess.run(
                    [
                        "velero",
                        "backup",
                        "create",
                        vb,
                        "--include-namespaces",
                        namespace,
                        "--wait",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=600,
                    check=False,
                )
                if pr.returncode == 0:
                    manifest["velero_backup_name"] = vb
                    manifest["velero_message"] = (pr.stdout or "").strip()[:2000]
                else:
                    manifest["velero_message"] = ((pr.stderr or "") + (pr.stdout or "")).strip()[:2000]
            except Exception as e:
                manifest["velero_message"] = f"{type(e).__name__}: {e}"
        else:
            manifest["velero_message"] = "velero CLI not found in PATH; skipped"

    manifest_path = os.path.join(bundle_dir, "backup_manifest.json")
    with open(manifest_path, "w", encoding="utf-8") as mf:
        json.dump(manifest, mf, indent=2, sort_keys=True)

    restore_path = os.path.join(bundle_dir, "restore_commands.sh")
    lines = [
        "#!/usr/bin/env bash",
        "set -euo pipefail",
        'ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"',
        'if test -z "${KUBECONFIG:-}"; then echo "Set KUBECONFIG to the target cluster kubeconfig." >&2; exit 1; fi',
        f'NS="{namespace}"',
        'echo "Applying objects in bundle order (namespace must exist)."',
    ]
    for obj in manifest["objects"]:
        fn = obj.get("file")
        if not fn:
            continue
        lines.append(f'echo "kubectl apply -f objects/{fn}"')
        lines.append(f'kubectl apply -f "$ROOT/objects/{fn}"')
    with open(restore_path, "w", encoding="utf-8") as rf:
        rf.write("\n".join(lines) + "\n")
    os.chmod(restore_path, 0o755)

    checksum_path = _write_bundle_checksums(bundle_dir)

    status = "complete"
    if errors and not captured:
        status = "failed"
    elif errors:
        status = "partial"

    return {
        "status": status,
        "bundle_dir": bundle_dir,
        "manifest_path": manifest_path,
        "restore_script": restore_path,
        "checksums_path": checksum_path,
        "object_count": len(captured),
        "error_count": len(errors),
        "manifest": manifest,
    }


def _restore_error_is_empty_apply(message: str) -> bool:
    msg = (message or "").lower()
    return "no objects passed to apply" in msg or "no objects passed to create" in msg


def _object_list_from_kubectl_json(data: Dict[str, Any]) -> List[Dict[str, Any]]:
    if data.get("kind") == "List":
        return [x for x in (data.get("items") or []) if isinstance(x, dict) and x.get("kind")]
    if data.get("kind"):
        return [data]
    return []


def _restore_file_objects(kubeconfig: str, path: str) -> Tuple[List[Dict[str, Any]], str]:
    """Load backup objects without requiring PyYAML; kubectl parses YAML bundles for us."""
    if path.endswith(".json"):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return _object_list_from_kubectl_json(data), ""
        except Exception as e:
            return [], f"{type(e).__name__}: {e}"

    rc, out, err = run_kubectl(
        kubeconfig,
        ["apply", "--dry-run=client", "-f", path, "-o", "json"],
        timeout=120,
    )
    if rc != 0:
        msg = err or out or f"exit {rc}"
        if _restore_error_is_empty_apply(msg):
            return [], ""
        return [], msg[:2000]
    try:
        return _object_list_from_kubectl_json(json.loads(out)), ""
    except Exception as e:
        return [], f"{type(e).__name__}: {e}"


def _write_temp_restore_manifest(objects: List[Dict[str, Any]]) -> str:
    payload: Dict[str, Any]
    if len(objects) == 1:
        payload = objects[0]
    else:
        payload = {"apiVersion": "v1", "kind": "List", "items": objects}
    tmp = tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".json", delete=False)
    with tmp:
        json.dump(payload, tmp, indent=2, sort_keys=True)
    return tmp.name


def _apply_restore_objects(
    kubeconfig: str,
    objects: List[Dict[str, Any]],
    *,
    server_side_force: bool = False,
) -> Tuple[int, str, str]:
    tmp_path = _write_temp_restore_manifest(objects)
    try:
        args = ["apply", "-f", tmp_path]
        if server_side_force:
            args = ["apply", "--server-side", "--force-conflicts", "-f", tmp_path]
        return run_kubectl(kubeconfig, args, timeout=180)
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


def _restore_apply_file_resilient(
    kubeconfig: str,
    path: str,
    rel: str,
) -> Dict[str, Any]:
    rc, out, err = run_kubectl(kubeconfig, ["apply", "-f", path], timeout=120)
    if rc == 0:
        objects, _ = _restore_file_objects(kubeconfig, path)
        return {
            "status": "applied",
            "file": rel,
            "method": "plain_apply",
            "message": (out or "").strip()[:1200],
            "objects": [reapplyable_manifest(x) for x in objects],
        }

    first_error = (err or out or f"exit {rc}")[:4000]
    if _restore_error_is_empty_apply(first_error):
        return {
            "status": "skipped_empty",
            "file": rel,
            "method": "plain_apply",
            "message": first_error,
            "objects": [],
        }

    objects, load_error = _restore_file_objects(kubeconfig, path)
    if load_error:
        return {
            "status": "failed",
            "file": rel,
            "method": "load_for_sanitized_apply",
            "error": load_error,
            "initial_error": first_error,
            "objects": [],
        }
    if not objects:
        return {
            "status": "skipped_empty",
            "file": rel,
            "method": "load_for_sanitized_apply",
            "message": "restore file contained no applyable objects",
            "initial_error": first_error,
            "objects": [],
        }

    clean_objects = [reapplyable_manifest(obj) for obj in objects]
    rc2, out2, err2 = _apply_restore_objects(kubeconfig, clean_objects)
    if rc2 == 0:
        return {
            "status": "applied",
            "file": rel,
            "method": "sanitized_apply",
            "message": (out2 or "").strip()[:1200],
            "initial_error": first_error,
            "objects": clean_objects,
        }

    second_error = (err2 or out2 or f"exit {rc2}")[:4000]
    rc3, out3, err3 = _apply_restore_objects(kubeconfig, clean_objects, server_side_force=True)
    if rc3 == 0:
        return {
            "status": "applied",
            "file": rel,
            "method": "sanitized_server_side_force_conflicts",
            "message": (out3 or "").strip()[:1200],
            "initial_error": first_error,
            "sanitized_error": second_error,
            "objects": clean_objects,
        }

    return {
        "status": "failed",
        "file": rel,
        "method": "sanitized_server_side_force_conflicts",
        "error": (err3 or out3 or f"exit {rc3}")[:4000],
        "initial_error": first_error,
        "sanitized_error": second_error,
        "objects": clean_objects,
    }


def _public_restore_result(result: Dict[str, Any]) -> Dict[str, Any]:
    public = {k: v for k, v in result.items() if k != "objects"}
    rel = str(public.get("file") or "").lower()
    if "secret" in rel:
        for key in ("message", "initial_error", "sanitized_error", "error"):
            if public.get(key):
                public[key] = "[redacted: Secret restore details are not printed]"
    return public


def _json_pointer_escape(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def _value_at_path(obj: Dict[str, Any], path: List[Any]) -> Tuple[bool, Any]:
    cur: Any = obj
    for part in path:
        if isinstance(part, int):
            if not isinstance(cur, list) or part < 0 or part >= len(cur):
                return False, None
            cur = cur[part]
        else:
            if not isinstance(cur, dict) or part not in cur:
                return False, None
            cur = cur[part]
    return True, cur


def _json_patch_remove(path: List[Any]) -> Dict[str, str]:
    pointer = "".join(
        "/" + (str(part) if isinstance(part, int) else _json_pointer_escape(str(part)))
        for part in path
    )
    return {"op": "remove", "path": pointer}


def _pod_spec_path_for_restore(kind: str) -> Optional[List[Any]]:
    if kind in {"Deployment", "DaemonSet", "ReplicaSet", "StatefulSet", "Job"}:
        return ["spec", "template", "spec"]
    if kind == "CronJob":
        return ["spec", "jobTemplate", "spec", "template", "spec"]
    if kind == "Pod":
        return ["spec"]
    return None


def _restore_absent_security_json_patches(
    expected: Dict[str, Any],
    live: Dict[str, Any],
) -> List[Dict[str, str]]:
    kind = str(expected.get("kind") or "")
    pod_path = _pod_spec_path_for_restore(kind)
    if not pod_path:
        return []
    exp_ok, exp_pod_spec = _value_at_path(expected, pod_path)
    live_ok, live_pod_spec = _value_at_path(live, pod_path)
    if not exp_ok or not live_ok or not isinstance(exp_pod_spec, dict) or not isinstance(live_pod_spec, dict):
        return []

    patches: List[Dict[str, str]] = []
    exp_pod_sc = exp_pod_spec.get("securityContext")
    live_pod_sc = live_pod_spec.get("securityContext")
    if isinstance(live_pod_sc, dict):
        if not isinstance(exp_pod_sc, dict):
            patches.append(_json_patch_remove(pod_path + ["securityContext"]))
        else:
            for key in sorted(live_pod_sc):
                if key not in exp_pod_sc:
                    patches.append(_json_patch_remove(pod_path + ["securityContext", key]))

    exp_containers = {
        str(c.get("name") or ""): c
        for c in (exp_pod_spec.get("containers") or [])
        if isinstance(c, dict) and c.get("name")
    }
    for idx, live_container in enumerate(live_pod_spec.get("containers") or []):
        if not isinstance(live_container, dict):
            continue
        cname = str(live_container.get("name") or "")
        exp_container = exp_containers.get(cname)
        if not exp_container:
            continue
        live_sc = live_container.get("securityContext")
        exp_sc = exp_container.get("securityContext")
        if not isinstance(live_sc, dict):
            continue
        if not isinstance(exp_sc, dict):
            patches.append(_json_patch_remove(pod_path + ["containers", idx, "securityContext"]))
        else:
            for key in sorted(live_sc):
                if key not in exp_sc:
                    patches.append(_json_patch_remove(pod_path + ["containers", idx, "securityContext", key]))
    return patches


def _restore_resource_args(kind: str, name: str, namespace: str) -> List[str]:
    args = ["get", kind, name]
    if namespace:
        args += ["-n", namespace]
    return args


def _patch_restore_json(kubeconfig: str, kind: str, name: str, namespace: str, patch: List[Dict[str, str]]) -> Dict[str, Any]:
    args = ["patch", kind, name, "--type=json", "-p", json.dumps(patch)]
    if namespace:
        args += ["-n", namespace]
    rc, out, err = run_kubectl(kubeconfig, args, timeout=90)
    return {
        "status": "patched" if rc == 0 else "failed",
        "kind": kind,
        "name": name,
        "namespace": namespace,
        "method": "json_patch",
        "message": (out if rc == 0 else err or out or f"exit {rc}")[:2000],
        "patch_count": len(patch),
    }


def _patch_restore_merge(kubeconfig: str, kind: str, name: str, namespace: str, patch: Dict[str, Any]) -> Dict[str, Any]:
    args = ["patch", kind, name, "--type=merge", "-p", json.dumps(patch)]
    if namespace:
        args += ["-n", namespace]
    rc, out, err = run_kubectl(kubeconfig, args, timeout=90)
    return {
        "status": "patched" if rc == 0 else "failed",
        "kind": kind,
        "name": name,
        "namespace": namespace,
        "method": "merge_patch",
        "message": (out if rc == 0 else err or out or f"exit {rc}")[:2000],
    }


def _restore_cleanup_agentfence_markers(
    kubeconfig: str,
    expected: Dict[str, Any],
    live: Dict[str, Any],
) -> List[Dict[str, Any]]:
    kind, name, namespace = manifest_resource_ref(expected)
    if not kind or not name:
        return []
    live_meta = live.get("metadata") or {}
    live_labels = live_meta.get("labels") or {}
    live_annotations = live_meta.get("annotations") or {}
    results: List[Dict[str, Any]] = []

    for key, value in sorted(live_labels.items()):
        if key == "app.kubernetes.io/managed-by" and value == "agentfence":
            args = ["label", kind, name, f"{key}-"]
            if namespace:
                args += ["-n", namespace]
            rc, out, err = run_kubectl(kubeconfig, args, timeout=60)
            results.append(
                {
                    "status": "patched" if rc == 0 else "failed",
                    "kind": kind,
                    "name": name,
                    "namespace": namespace,
                    "method": "remove_agentfence_label",
                    "key": key,
                    "message": (out if rc == 0 else err or out or f"exit {rc}")[:1200],
                }
            )

    for key, value in sorted(live_annotations.items()):
        if key.startswith("agentfence.dev/"):
            args = ["annotate", kind, name, f"{key}-"]
            if namespace:
                args += ["-n", namespace]
            rc, out, err = run_kubectl(kubeconfig, args, timeout=60)
            results.append(
                {
                    "status": "patched" if rc == 0 else "failed",
                    "kind": kind,
                    "name": name,
                    "namespace": namespace,
                    "method": "remove_agentfence_annotation",
                    "key": key,
                    "message": (out if rc == 0 else err or out or f"exit {rc}")[:1200],
                }
            )
    return results


def _reconcile_restored_object(kubeconfig: str, expected: Dict[str, Any]) -> List[Dict[str, Any]]:
    kind, name, namespace = manifest_resource_ref(expected)
    if not kind or not name:
        return []
    live = kubectl_get_json(kubeconfig, _restore_resource_args(kind, name, namespace))
    if not isinstance(live, dict) or not live.get("kind"):
        return [
            {
                "status": "failed",
                "kind": kind,
                "name": name,
                "namespace": namespace,
                "method": "live_lookup",
                "message": "resource not found after restore apply",
            }
        ]

    results: List[Dict[str, Any]] = []
    exp_spec = expected.get("spec")
    live_spec = live.get("spec")
    if kind == "NetworkPolicy" and isinstance(exp_spec, dict) and isinstance(live_spec, dict):
        exp_selector = exp_spec.get("podSelector") or {}
        if live_spec.get("podSelector") != exp_selector:
            results.append(
                _patch_restore_merge(
                    kubeconfig,
                    kind,
                    name,
                    namespace,
                    {"spec": {"podSelector": exp_selector}},
                )
            )
            live = kubectl_get_json(kubeconfig, _restore_resource_args(kind, name, namespace)) or live

    security_patches = _restore_absent_security_json_patches(expected, live)
    if security_patches:
        results.append(_patch_restore_json(kubeconfig, kind, name, namespace, security_patches))
        live = kubectl_get_json(kubeconfig, _restore_resource_args(kind, name, namespace)) or live

    results.extend(_restore_cleanup_agentfence_markers(kubeconfig, expected, live))
    return results


def _reconcile_restored_objects(kubeconfig: str, objects: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    reconciled: List[Dict[str, Any]] = []
    by_ref: Dict[Tuple[str, str, str], Dict[str, Any]] = {}
    for obj in objects:
        expected = reapplyable_manifest(obj)
        ref = manifest_resource_ref(expected)
        if not ref[0] or not ref[1]:
            continue
        by_ref[ref] = expected
    for expected in by_ref.values():
        reconciled.extend(_reconcile_restored_object(kubeconfig, expected))
    return reconciled


def restore_namespace_bundle(
    kubeconfig: str,
    bundle_dir: str,
    *,
    dry_run: bool = False,
) -> Dict[str, Any]:
    """Restore namespace bundles with sanitized retry and universal drift reconciliation."""
    manifest_path = os.path.join(bundle_dir, "backup_manifest.json")
    if not os.path.isfile(manifest_path):
        return {"status": "error", "message": f"missing {manifest_path}"}
    with open(manifest_path, "r", encoding="utf-8") as mf:
        manifest = json.load(mf)
    if manifest.get("schema") == COMPREHENSIVE_BACKUP_SCHEMA:
        restore_items = list(manifest.get("restore_order") or [])
        applied: List[str] = []
        skipped: List[str] = []
        fallback_applied: List[Dict[str, Any]] = []
        failures: List[Dict[str, Any]] = []
        expected_objects: List[Dict[str, Any]] = []
        for item in restore_items:
            rel = item.get("file")
            if not rel:
                continue
            fp = os.path.join(bundle_dir, rel)
            if not os.path.isfile(fp):
                failures.append({"file": rel, "error": "missing file"})
                continue
            if dry_run:
                applied.append(rel)
                objs, _ = _restore_file_objects(kubeconfig, fp)
                expected_objects.extend([reapplyable_manifest(x) for x in objs])
                continue
            res = _restore_apply_file_resilient(kubeconfig, fp, rel)
            expected_objects.extend([reapplyable_manifest(x) for x in (res.get("objects") or [])])
            if res.get("status") == "applied":
                applied.append(rel)
                if res.get("method") != "plain_apply":
                    fallback_applied.append(_public_restore_result(res))
            elif res.get("status") == "skipped_empty":
                skipped.append(rel)
            else:
                public_res = _public_restore_result(res)
                failures.append(
                    {
                        "file": rel,
                        "error": public_res.get("error") or public_res.get("message") or "restore apply failed",
                        "method": public_res.get("method"),
                        "initial_error": public_res.get("initial_error"),
                        "sanitized_error": public_res.get("sanitized_error"),
                    }
                )
        reconciled = [] if dry_run else _reconcile_restored_objects(kubeconfig, expected_objects)
        reconcile_failures = [r for r in reconciled if r.get("status") == "failed"]
        failures.extend(reconcile_failures)
        st = "complete" if not failures else ("partial" if applied else "failed")
        return {
            "status": st,
            "applied": applied,
            "skipped_empty": skipped,
            "fallback_applied": fallback_applied,
            "reconciled": reconciled,
            "failures": failures,
            "dry_run": dry_run,
        }
    if manifest.get("schema") != "agentfence-backup-bundle-v1":
        return {"status": "error", "message": "invalid backup_manifest schema"}
    objects = list(manifest.get("objects") or [])
    objects.sort(
        key=lambda o: (_BACKUP_KIND_ORDER.get(str(o.get("kind")), 999), str(o.get("name")))
    )
    applied: List[str] = []
    skipped: List[str] = []
    fallback_applied: List[Dict[str, Any]] = []
    failures: List[Dict[str, Any]] = []
    expected_objects: List[Dict[str, Any]] = []
    for obj in objects:
        fn = obj.get("file")
        if not fn:
            continue
        fp = os.path.join(bundle_dir, "objects", fn)
        if not os.path.isfile(fp):
            failures.append({"file": fn, "error": "missing file"})
            continue
        if dry_run:
            applied.append(fn)
            objs, _ = _restore_file_objects(kubeconfig, fp)
            expected_objects.extend([reapplyable_manifest(x) for x in objs])
            continue
        res = _restore_apply_file_resilient(kubeconfig, fp, fn)
        expected_objects.extend([reapplyable_manifest(x) for x in (res.get("objects") or [])])
        if res.get("status") == "applied":
            applied.append(fn)
            if res.get("method") != "plain_apply":
                fallback_applied.append(_public_restore_result(res))
        elif res.get("status") == "skipped_empty":
            skipped.append(fn)
        else:
            public_res = _public_restore_result(res)
            failures.append(
                {
                    "file": fn,
                    "error": public_res.get("error") or public_res.get("message") or "restore apply failed",
                    "method": public_res.get("method"),
                    "initial_error": public_res.get("initial_error"),
                    "sanitized_error": public_res.get("sanitized_error"),
                }
            )
    reconciled = [] if dry_run else _reconcile_restored_objects(kubeconfig, expected_objects)
    reconcile_failures = [r for r in reconciled if r.get("status") == "failed"]
    failures.extend(reconcile_failures)
    st = "complete" if not failures else ("partial" if applied else "failed")
    return {
        "status": st,
        "applied": applied,
        "skipped_empty": skipped,
        "fallback_applied": fallback_applied,
        "reconciled": reconciled,
        "failures": failures,
        "dry_run": dry_run,
    }


def _dedupe_ordered(values: List[str]) -> List[str]:
    seen = set()
    out: List[str] = []
    for value in values:
        v = (value or "").strip()
        if not v or v in seen:
            continue
        seen.add(v)
        out.append(v)
    return out


def _resource_file_name(resource: str) -> str:
    return _safe_backup_filename(resource.replace("/", "_")) + ".yaml"


def kubectl_yaml(kubeconfig: str, args: List[str], timeout: int = 45) -> Tuple[int, str, str]:
    return run_kubectl(kubeconfig, args + ["-o", "yaml"], timeout=timeout)


def _record_capture(
    captures: List[Dict[str, Any]],
    *,
    category: str,
    rel_path: str,
    command: List[str],
    status: str,
    required: bool = False,
    message: str = "",
    resource: str = "",
    scope: str = "namespace",
) -> None:
    captures.append(
        {
            "category": category,
            "file": rel_path,
            "command": "kubectl " + " ".join(shlex.quote(x) for x in command),
            "status": status,
            "required": required,
            "message": message[:1200],
            "resource": resource,
            "scope": scope,
        }
    )


def capture_yaml(
    kubeconfig: str,
    bundle_dir: str,
    captures: List[Dict[str, Any]],
    rel_path: str,
    args: List[str],
    *,
    category: str,
    resource: str = "",
    scope: str = "namespace",
    required: bool = False,
    timeout: int = 45,
) -> bool:
    rc, out, err = kubectl_yaml(kubeconfig, args, timeout=timeout)
    if rc == 0 and out.strip():
        write_text_file(os.path.join(bundle_dir, rel_path), out)
        _record_capture(
            captures,
            category=category,
            rel_path=rel_path,
            command=args + ["-o", "yaml"],
            status="captured",
            required=required,
            resource=resource,
            scope=scope,
        )
        return True
    _record_capture(
        captures,
        category=category,
        rel_path=rel_path,
        command=args + ["-o", "yaml"],
        status="failed" if required else "skipped",
        required=required,
        message=(err or out or f"exit {rc}").strip(),
        resource=resource,
        scope=scope,
    )
    return False


def discover_namespaced_resources(kubeconfig: str, include_secrets: bool = True) -> Dict[str, Any]:
    rc, out, err = run_kubectl(
        kubeconfig,
        ["api-resources", "--namespaced=true", "--verbs=list", "-o", "name"],
        timeout=45,
    )
    discovered = [line.strip() for line in out.splitlines() if line.strip()] if rc == 0 else []
    resources = _dedupe_ordered(list(BASE_NAMESPACE_RESOURCES) + discovered)
    if not include_secrets:
        resources = [r for r in resources if r != "secrets"]
    return {
        "status": "captured" if rc == 0 else "fallback",
        "resources": resources,
        "error": "" if rc == 0 else (err or out or f"exit {rc}")[:1200],
    }


def discover_workload_reference(ctx: RunContext) -> Dict[str, Any]:
    info: Dict[str, Any] = {
        "target_pod": ctx.target_pod,
        "target_container": ctx.target_container,
        "service_account": None,
        "node": None,
        "runtime_class": None,
        "node_selector": None,
        "workload": None,
        "owner_chain": [],
        "warnings": [],
    }
    if ctx.dry_run or not ctx.target_pod:
        info["warnings"].append("target pod discovery skipped")
        return info
    pod = load_target_pod_json(ctx)
    if not pod:
        info["warnings"].append("target pod JSON unavailable")
        return info
    spec = pod.get("spec") or {}
    info["service_account"] = spec.get("serviceAccountName") or "default"
    info["node"] = spec.get("nodeName")
    info["runtime_class"] = spec.get("runtimeClassName")
    info["node_selector"] = spec.get("nodeSelector") or {}
    owners = (pod.get("metadata") or {}).get("ownerReferences") or []
    if not owners:
        info["warnings"].append("target pod has no ownerReferences")
        return info

    owner = owners[0]
    owner_kind = owner.get("kind")
    owner_name = owner.get("name")
    if owner_kind and owner_name:
        info["owner_chain"].append({"kind": owner_kind, "name": owner_name})

    kind_to_resource = {
        "Deployment": "deployment",
        "StatefulSet": "statefulset",
        "DaemonSet": "daemonset",
        "ReplicaSet": "replicaset",
        "Job": "job",
        "CronJob": "cronjob",
    }

    if owner_kind == "ReplicaSet" and owner_name:
        rs = kubectl_get_json(ctx.kubeconfig, ["get", "replicaset", owner_name, "-n", ctx.namespace])
        rs_owners = ((rs or {}).get("metadata") or {}).get("ownerReferences") or []
        if rs_owners:
            top = rs_owners[0]
            top_kind = top.get("kind")
            top_name = top.get("name")
            if top_kind and top_name:
                info["owner_chain"].append({"kind": top_kind, "name": top_name})
                owner_kind, owner_name = top_kind, top_name

    if owner_kind == "Job" and owner_name:
        job = kubectl_get_json(ctx.kubeconfig, ["get", "job", owner_name, "-n", ctx.namespace])
        job_owners = ((job or {}).get("metadata") or {}).get("ownerReferences") or []
        if job_owners:
            top = job_owners[0]
            top_kind = top.get("kind")
            top_name = top.get("name")
            if top_kind and top_name:
                info["owner_chain"].append({"kind": top_kind, "name": top_name})
                owner_kind, owner_name = top_kind, top_name

    resource = kind_to_resource.get(str(owner_kind or ""))
    if resource and owner_name:
        info["workload"] = {"kind": owner_kind, "resource": resource, "name": owner_name}
    elif owner_kind or owner_name:
        info["warnings"].append(f"unhandled owner kind/name: {owner_kind}/{owner_name}")
    return info


def discover_rbac_dependencies(ctx: RunContext, bundle_dir: str, captures: List[Dict[str, Any]]) -> Dict[str, Any]:
    clusterroles = set()
    captured_crbs: List[str] = []

    rolebindings = kubectl_get_json(
        ctx.kubeconfig,
        ["get", "rolebindings.rbac.authorization.k8s.io", "-n", ctx.namespace],
    )
    for rb in (rolebindings or {}).get("items") or []:
        ref = rb.get("roleRef") or {}
        if ref.get("kind") == "ClusterRole" and ref.get("name"):
            clusterroles.add(ref["name"])

    crbs = kubectl_get_json(ctx.kubeconfig, ["get", "clusterrolebindings.rbac.authorization.k8s.io"])
    for crb in (crbs or {}).get("items") or []:
        subjects = crb.get("subjects") or []
        namespaced_subject = any(
            s.get("kind") == "ServiceAccount" and s.get("namespace") == ctx.namespace
            for s in subjects
        )
        if not namespaced_subject:
            continue
        name = (crb.get("metadata") or {}).get("name")
        if not name:
            continue
        captured_crbs.append(name)
        ref = crb.get("roleRef") or {}
        if ref.get("kind") == "ClusterRole" and ref.get("name"):
            clusterroles.add(ref["name"])
        capture_yaml(
            ctx.kubeconfig,
            bundle_dir,
            captures,
            f"cluster_dependencies/clusterrolebinding_{_safe_backup_filename(name)}.yaml",
            ["get", "clusterrolebinding", name],
            category="cluster_dependency",
            resource="clusterrolebindings.rbac.authorization.k8s.io",
            scope="cluster",
        )

    for name in sorted(clusterroles):
        capture_yaml(
            ctx.kubeconfig,
            bundle_dir,
            captures,
            f"cluster_dependencies/clusterrole_{_safe_backup_filename(name)}.yaml",
            ["get", "clusterrole", name],
            category="cluster_dependency",
            resource="clusterroles.rbac.authorization.k8s.io",
            scope="cluster",
        )

    return {"clusterroles": sorted(clusterroles), "clusterrolebindings": sorted(captured_crbs)}


def detect_pvc_data_status(ctx: RunContext, bundle_dir: str) -> Dict[str, Any]:
    pvcs = kubectl_get_json(ctx.kubeconfig, ["get", "persistentvolumeclaims", "-n", ctx.namespace])
    items = (pvcs or {}).get("items") or []
    pvc_names = [(p.get("metadata") or {}).get("name") for p in items]
    pvc_names = [p for p in pvc_names if p]
    status = {
        "pvc_count": len(pvc_names),
        "pvc_names": pvc_names,
        "data_status": "not_applicable" if not pvc_names else "metadata_only",
        "snapshot_api_available": False,
        "warning": "",
    }
    if not pvc_names:
        write_json(os.path.join(bundle_dir, "pvc_data", "pvc_data_status.json"), status)
        return status

    rc, out, _ = run_kubectl(ctx.kubeconfig, ["api-resources", "-o", "name"], timeout=45)
    api_names = set(line.strip() for line in out.splitlines() if line.strip()) if rc == 0 else set()
    snapshot_available = "volumesnapshots.snapshot.storage.k8s.io" in api_names
    status["snapshot_api_available"] = snapshot_available
    status["data_status"] = "snapshot_plan_available_not_created" if snapshot_available else "metadata_only"
    status["warning"] = (
        "PVC object metadata is captured. Persistent volume bytes require CSI VolumeSnapshot, Velero/restic, "
        "or storage-provider backup before destructive remediation."
    )
    plan_lines = [
        "# AgentFence PVC data backup plan",
        "# This file is a generated operator checklist; AgentFence does not snapshot volume bytes automatically.",
        f"# Namespace: {ctx.namespace}",
        "",
    ]
    for pvc_name in pvc_names:
        plan_lines.extend(
            [
                "---",
                "apiVersion: snapshot.storage.k8s.io/v1",
                "kind: VolumeSnapshot",
                "metadata:",
                f"  name: af-pre-{_safe_backup_filename(pvc_name)}",
                f"  namespace: {ctx.namespace}",
                "spec:",
                "  source:",
                f"    persistentVolumeClaimName: {pvc_name}",
                "",
            ]
        )
    write_text_file(os.path.join(bundle_dir, "pvc_data", "volume_snapshot_plan.yaml"), "\n".join(plan_lines))
    write_json(os.path.join(bundle_dir, "pvc_data", "pvc_data_status.json"), status)
    return status


def _restore_priority(resource: str) -> int:
    ordered = (
        "namespaces",
        "serviceaccounts",
        "roles.rbac.authorization.k8s.io",
        "rolebindings.rbac.authorization.k8s.io",
        "configmaps",
        "secrets",
        "persistentvolumeclaims",
        "services",
        "deployments.apps",
        "statefulsets.apps",
        "daemonsets.apps",
        "jobs.batch",
        "cronjobs.batch",
        "horizontalpodautoscalers.autoscaling",
        "poddisruptionbudgets.policy",
        "networkpolicies.networking.k8s.io",
        "ingresses.networking.k8s.io",
        "gateways.gateway.networking.k8s.io",
        "httproutes.gateway.networking.k8s.io",
        "referencegrants.gateway.networking.k8s.io",
    )
    try:
        return ordered.index(resource)
    except ValueError:
        return 999


def build_restore_order(captures: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    excluded = {
        "pods",
        "replicasets.apps",
        "endpoints",
        "events",
        "events.events.k8s.io",
        "nodes",
        "runtimeclasses.node.k8s.io",
        "storageclasses.storage.k8s.io",
        "volumesnapshotclasses.snapshot.storage.k8s.io",
        "priorityclasses.scheduling.k8s.io",
        "clusterroles.rbac.authorization.k8s.io",
        "clusterrolebindings.rbac.authorization.k8s.io",
    }
    restore: List[Dict[str, Any]] = []
    seen = set()
    for capture in captures:
        if capture.get("status") != "captured":
            continue
        if capture.get("category") == "generated_remediation":
            continue
        rel = capture.get("file")
        resource = capture.get("resource") or ""
        if not rel or not rel.endswith((".yaml", ".yml")) or resource in excluded:
            continue
        if rel in seen:
            continue
        seen.add(rel)
        restore.append(
            {
                "file": rel,
                "resource": resource,
                "scope": capture.get("scope") or "namespace",
                "priority": _restore_priority(resource),
            }
        )
    restore.sort(key=lambda i: (int(i.get("priority") or 999), str(i.get("file"))))
    return restore


def restore_script_text(namespace: str, restore_order: List[Dict[str, Any]]) -> str:
    lines = [
        "#!/usr/bin/env bash",
        "set -euo pipefail",
        'ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"',
        'if test -z "${KUBECONFIG:-}"; then echo "Set KUBECONFIG to the target cluster kubeconfig." >&2; exit 1; fi',
        f'NS="{namespace}"',
        'echo "Restoring AgentFence checkpoint for namespace ${NS}"',
        'echo "Server-side dry run first:"',
    ]
    for item in restore_order:
        rel = item.get("file")
        if rel:
            lines.append(f'kubectl apply --dry-run=server -f "$ROOT/{rel}" >/dev/null')
    lines.append('echo "Dry run passed; applying captured namespace resources."')
    for item in restore_order:
        rel = item.get("file")
        if rel:
            lines.append(f'kubectl apply -f "$ROOT/{rel}"')
    lines.append('echo "Restore apply complete. Re-run AgentFence analyze to validate the restored state."')
    return "\n".join(lines) + "\n"


def validate_checkpoint_files(
    kubeconfig: str,
    bundle_dir: str,
    restore_order: List[Dict[str, Any]],
    captures: List[Dict[str, Any]],
) -> Dict[str, Any]:
    missing: List[str] = []
    json_errors: List[Dict[str, str]] = []
    dry_run_warnings: List[Dict[str, str]] = []

    for capture in captures:
        if capture.get("status") != "captured":
            continue
        rel = capture.get("file")
        if not rel:
            continue
        path = os.path.join(bundle_dir, rel)
        if not os.path.isfile(path) or os.path.getsize(path) == 0:
            missing.append(rel)
            continue
        if rel.endswith(".json"):
            try:
                with open(path, "r", encoding="utf-8") as f:
                    json.load(f)
            except Exception as e:
                json_errors.append({"file": rel, "error": f"{type(e).__name__}: {e}"})

    for item in restore_order:
        rel = item.get("file")
        if not rel:
            continue
        path = os.path.join(bundle_dir, rel)
        if not os.path.isfile(path):
            missing.append(rel)
            continue
        rc, out, err = run_kubectl(kubeconfig, ["apply", "--dry-run=server", "-f", path], timeout=90)
        if rc != 0:
            dry_run_warnings.append({"file": rel, "error": (err or out or f"exit {rc}")[:1200]})

    failed_required = [
        c for c in captures if c.get("required") and c.get("status") != "captured"
    ]
    status = "verified"
    if missing or json_errors or failed_required:
        status = "failed"
    elif dry_run_warnings or any(c.get("status") != "captured" for c in captures):
        status = "verified_with_warnings"
    return {
        "status": status,
        "missing_files": missing,
        "json_errors": json_errors,
        "dry_run_warnings": dry_run_warnings,
        "failed_required_captures": failed_required,
    }


def build_generated_remediation_manifest(remediation_plan: Optional[Dict[str, Any]]) -> str:
    lines = [
        "# AgentFence generated remediation source-of-truth",
        "# Review before applying. This is intentionally generated as a checklist/patch catalog.",
        "",
    ]
    for item in (remediation_plan or {}).get("actionable_items") or []:
        lines.extend(
            [
                "---",
                f"# probe_id: {item.get('probe_id')}",
                f"# action_type: {item.get('action_type')}",
                f"# title: {item.get('title')}",
                f"# recommendation: {item.get('recommendation')}",
            ]
        )
        artifact = item.get("dry_run_artifact")
        if artifact:
            lines.append(str(artifact))
        else:
            lines.append("# Manual recommendation only; no generated Kubernetes patch.")
        lines.append("")
    if len(lines) <= 3:
        lines.append("# No actionable remediation items were detected.")
    return "\n".join(lines) + "\n"


def attach_remediation_plan_to_checkpoint(
    checkpoint: Optional[Dict[str, Any]],
    remediation_plan: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    if not checkpoint or not checkpoint.get("bundle_dir"):
        return checkpoint
    bundle_dir = str(checkpoint["bundle_dir"])
    if not os.path.isdir(bundle_dir):
        return checkpoint
    remediation_dir = os.path.join(bundle_dir, "generated_remediation")
    os.makedirs(remediation_dir, exist_ok=True)
    write_json(os.path.join(remediation_dir, "remediation_plan.json"), remediation_plan)
    write_text_file(
        os.path.join(remediation_dir, "source_of_truth_manifest.yaml"),
        build_generated_remediation_manifest(remediation_plan),
    )
    manifest_path = os.path.join(bundle_dir, "backup_manifest.json")
    if os.path.isfile(manifest_path):
        try:
            with open(manifest_path, "r", encoding="utf-8") as f:
                manifest = json.load(f)
        except Exception:
            manifest = {}
        if isinstance(manifest, dict):
            manifest["post_run_remediation_plan_attached"] = True
            manifest["post_run_remediation_plan_attached_at_utc"] = datetime.datetime.now(
                datetime.timezone.utc
            ).isoformat()
            write_json(manifest_path, manifest)
            checksum_path = _write_bundle_checksums(bundle_dir)
            manifest["checksums_path"] = checksum_path
            write_json(manifest_path, manifest)
            _write_bundle_checksums(bundle_dir)
    checkpoint["post_run_remediation_plan_attached"] = True
    return checkpoint


def build_restore_checkpoint(
    ctx: RunContext,
    action: str,
    remediation_plan: Optional[Dict[str, Any]] = None,
    *,
    base_dir: Optional[str] = None,
    include_secrets: bool = True,
    run_velero: bool = False,
) -> Dict[str, Any]:
    parent_dir = base_dir or os.path.join(os.path.dirname(os.path.abspath(__file__)), "generated_outputs")
    if ctx.dry_run:
        return {
            "schema": COMPREHENSIVE_BACKUP_SCHEMA,
            "status": "dry_run_not_created",
            "action": action,
            "namespace": ctx.namespace,
            "bundle_dir": None,
            "mutation_gate": {
                "status": "open",
                "reason": "dry-run mode does not mutate cluster resources",
            },
        }

    stamp = now_stamp()
    bundle_name = (
        f"rollback_bundle_{_safe_backup_filename(ctx.namespace)}_"
        f"{_safe_backup_filename(ctx.target_pod or 'namespace')}_{stamp}"
    )
    bundle_dir = os.path.join(parent_dir, bundle_name)
    for sub in (
        "affected_resources",
        "namespace_snapshot",
        "cluster_dependencies",
        "generated_remediation",
        "pvc_data",
    ):
        os.makedirs(os.path.join(bundle_dir, sub), exist_ok=True)

    captures: List[Dict[str, Any]] = []
    workload = discover_workload_reference(ctx)

    capture_yaml(
        ctx.kubeconfig,
        bundle_dir,
        captures,
        "cluster_dependencies/namespace.yaml",
        ["get", "namespace", ctx.namespace],
        category="cluster_dependency",
        resource="namespaces",
        scope="cluster",
        required=True,
    )
    if ctx.target_pod:
        capture_yaml(
            ctx.kubeconfig,
            bundle_dir,
            captures,
            f"affected_resources/pod_{_safe_backup_filename(ctx.target_pod)}.yaml",
            ["get", "pod", ctx.target_pod, "-n", ctx.namespace],
            category="affected_resource",
            resource="pods",
            required=True,
        )
    if workload.get("service_account"):
        capture_yaml(
            ctx.kubeconfig,
            bundle_dir,
            captures,
            f"affected_resources/serviceaccount_{_safe_backup_filename(str(workload['service_account']))}.yaml",
            ["get", "serviceaccount", str(workload["service_account"]), "-n", ctx.namespace],
            category="affected_resource",
            resource="serviceaccounts",
            required=False,
        )
    wl = workload.get("workload") or {}
    if wl.get("resource") and wl.get("name"):
        capture_yaml(
            ctx.kubeconfig,
            bundle_dir,
            captures,
            f"affected_resources/workload_{_safe_backup_filename(str(wl['resource']))}_{_safe_backup_filename(str(wl['name']))}.yaml",
            ["get", str(wl["resource"]), str(wl["name"]), "-n", ctx.namespace],
            category="affected_resource",
            resource=f"{wl['resource']}s",
            required=False,
        )
    for resource in ("services", "networkpolicies.networking.k8s.io", "configmaps", "secrets"):
        if resource == "secrets" and not include_secrets:
            continue
        capture_yaml(
            ctx.kubeconfig,
            bundle_dir,
            captures,
            f"affected_resources/{_resource_file_name(resource)}",
            ["get", resource, "-n", ctx.namespace],
            category="affected_resource",
            resource=resource,
            required=False,
        )

    discovery = discover_namespaced_resources(ctx.kubeconfig, include_secrets=include_secrets)
    write_json(os.path.join(bundle_dir, "namespace_snapshot", "api-resources.json"), discovery)
    _record_capture(
        captures,
        category="namespace_snapshot",
        rel_path="namespace_snapshot/api-resources.json",
        command=["api-resources", "--namespaced=true", "--verbs=list", "-o", "name"],
        status="captured",
        resource="api-resources",
    )
    for resource in discovery["resources"]:
        capture_yaml(
            ctx.kubeconfig,
            bundle_dir,
            captures,
            f"namespace_snapshot/{_resource_file_name(resource)}",
            ["get", resource, "-n", ctx.namespace],
            category="namespace_snapshot",
            resource=resource,
            required=False,
            timeout=60,
        )

    node_name = workload.get("node")
    if node_name:
        capture_yaml(
            ctx.kubeconfig,
            bundle_dir,
            captures,
            f"cluster_dependencies/node_{_safe_backup_filename(str(node_name))}.yaml",
            ["get", "node", str(node_name)],
            category="cluster_dependency",
            resource="nodes",
            scope="cluster",
        )
    for resource in CLUSTER_DEPENDENCY_RESOURCES:
        capture_yaml(
            ctx.kubeconfig,
            bundle_dir,
            captures,
            f"cluster_dependencies/{_resource_file_name(resource)}",
            ["get", resource],
            category="cluster_dependency",
            resource=resource,
            scope="cluster",
            timeout=60,
        )
    rbac_dependencies = discover_rbac_dependencies(ctx, bundle_dir, captures)
    pvc_data = detect_pvc_data_status(ctx, bundle_dir)

    remediation_json = os.path.join(bundle_dir, "generated_remediation", "remediation_plan.json")
    write_json(remediation_json, remediation_plan or {})
    _record_capture(
        captures,
        category="generated_remediation",
        rel_path="generated_remediation/remediation_plan.json",
        command=["agentfence", "build-remediation-plan"],
        status="captured",
        resource="remediation-plan",
    )
    source_rel = "generated_remediation/source_of_truth_manifest.yaml"
    write_text_file(
        os.path.join(bundle_dir, source_rel),
        build_generated_remediation_manifest(remediation_plan),
    )
    _record_capture(
        captures,
        category="generated_remediation",
        rel_path=source_rel,
        command=["agentfence", "generate-source-of-truth"],
        status="captured",
        resource="remediation-source-of-truth",
    )

    if run_velero:
        velero_info: Dict[str, Any] = {"requested": True, "status": "not_run", "message": ""}
        vb = f"af-pre-{_safe_backup_filename(ctx.namespace)}-{stamp}"
        if shutil.which("velero"):
            try:
                pr = subprocess.run(
                    [
                        "velero",
                        "backup",
                        "create",
                        vb,
                        "--include-namespaces",
                        ctx.namespace,
                        "--wait",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=600,
                    check=False,
                )
                velero_info.update(
                    {
                        "status": "captured" if pr.returncode == 0 else "failed",
                        "backup_name": vb,
                        "message": ((pr.stdout or "") + (pr.stderr or "")).strip()[:2000],
                    }
                )
            except Exception as e:
                velero_info.update({"status": "failed", "message": f"{type(e).__name__}: {e}"})
        else:
            velero_info.update({"status": "skipped", "message": "velero CLI not found in PATH"})
    else:
        velero_info = {"requested": False, "status": "skipped"}

    restore_order = build_restore_order(captures)
    write_json(os.path.join(bundle_dir, "restore_order.json"), {"items": restore_order})
    write_text_file(
        os.path.join(bundle_dir, "restore.sh"),
        restore_script_text(ctx.namespace, restore_order),
        executable=True,
    )
    validation = validate_checkpoint_files(ctx.kubeconfig, bundle_dir, restore_order, captures)
    write_json(os.path.join(bundle_dir, "validation_report.json"), validation)

    required_failures = [
        c for c in captures if c.get("required") and c.get("status") != "captured"
    ]
    noncritical_warnings = [c for c in captures if c.get("status") != "captured"]
    status = validation["status"]
    if required_failures:
        status = "failed"
    elif status == "verified" and noncritical_warnings:
        status = "verified_with_warnings"
    mutation_gate = {
        "status": "open" if status in ("verified", "verified_with_warnings") else "blocked",
        "reason": "restore checkpoint verified before remediation guidance was emitted"
        if status in ("verified", "verified_with_warnings")
        else "required backup capture or validation failed",
    }

    manifest: Dict[str, Any] = {
        "schema": COMPREHENSIVE_BACKUP_SCHEMA,
        "status": status,
        "created_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "action": action,
        "namespace": ctx.namespace,
        "target_pod": ctx.target_pod,
        "target_container": ctx.target_container,
        "catalog_version": CATALOG_VERSION,
        "bundle_dir": bundle_dir,
        "include_secrets": include_secrets,
        "contains_secret_objects": include_secrets,
        "workload_reference": workload,
        "rbac_dependencies": rbac_dependencies,
        "pvc_data": pvc_data,
        "velero": velero_info,
        "captures": captures,
        "restore_order": restore_order,
        "validation_report": os.path.join(bundle_dir, "validation_report.json"),
        "restore_script": os.path.join(bundle_dir, "restore.sh"),
        "mutation_gate": mutation_gate,
    }
    manifest_path = os.path.join(bundle_dir, "backup_manifest.json")
    write_json(manifest_path, manifest)
    checksum_path = _write_bundle_checksums(bundle_dir)
    manifest["manifest_path"] = manifest_path
    manifest["checksums_path"] = checksum_path
    write_json(manifest_path, manifest)
    return manifest


def create_comprehensive_namespace_backup_bundle(
    kubeconfig: str,
    namespace: str,
    parent_dir: str,
    *,
    include_secrets: bool = True,
    run_velero: bool = False,
    target_pod: str = "",
) -> Dict[str, Any]:
    ctx = RunContext(
        namespace=namespace,
        kubeconfig=kubeconfig,
        target_pod=target_pod,
        target_container="",
        attacker_pod="",
        attacker_container="",
        target_ip="",
        dry_run=False,
    )
    return build_restore_checkpoint(
        ctx,
        "backup-namespace",
        remediation_plan=None,
        base_dir=parent_dir,
        include_secrets=include_secrets,
        run_velero=run_velero,
    )


def reconcile_evaluation_artifact_paths(evaluation: Dict[str, Any]) -> None:
    """Refresh F4 exists_at_generation after output files have been written to disk."""
    f4 = evaluation.get("F4_artifact_consistency")
    if not isinstance(f4, dict):
        return
    arts = f4.get("artifacts")
    if not isinstance(arts, list):
        return
    for entry in arts:
        if not isinstance(entry, dict):
            continue
        p = entry.get("path")
        if isinstance(p, str) and p:
            entry["exists_at_generation"] = os.path.exists(p)


def metrics_to_dict(metrics: Optional[Any]) -> Dict[str, Any]:
    if metrics is None:
        return {}
    if isinstance(metrics, ScoreBundle):
        return dict(metrics.__dict__)
    return dict(metrics)


def result_dicts(results: Optional[List[Any]]) -> List[Dict[str, Any]]:
    out = []
    for r in results or []:
        if isinstance(r, TestResult):
            data = dict(canonical_test_result(r).__dict__)
        else:
            data = dict(r)
            data["id"] = canonical_probe_id(data.get("id"))
        out.append(data)
    return out


def result_status_counts(results: Optional[List[Any]]) -> Dict[str, int]:
    counts = {"pass": 0, "fail": 0, "skip": 0}
    for r in result_dicts(results):
        status = str(r.get("status") or "skip")
        counts[status] = counts.get(status, 0) + 1
    return counts


def build_f1_f5_evaluation(
    action: str,
    namespace: str,
    context: Dict[str, Any],
    artifacts: Dict[str, str],
    metrics: Optional[Any] = None,
    results: Optional[List[Any]] = None,
    metrics_before: Optional[Any] = None,
    results_before: Optional[List[Any]] = None,
    metrics_after: Optional[Any] = None,
    results_after: Optional[List[Any]] = None,
    remediation_plan: Optional[Dict[str, Any]] = None,
    backup_checkpoint: Optional[Dict[str, Any]] = None,
    health: Optional[Dict[str, Any]] = None,
    error: Optional[str] = None,
) -> Dict[str, Any]:
    base_metrics = metrics_to_dict(metrics or metrics_before)
    after_metrics = metrics_to_dict(metrics_after)
    base_results = results if results is not None else results_before
    post_results = results_after or results or results_before
    base_counts = result_status_counts(base_results)
    post_counts = result_status_counts(post_results)
    f3_status = "baseline_only" if action == "analyze" else "not_improved"
    if after_metrics:
        before_score = float(base_metrics.get("score_normalized", 0))
        after_score = float(after_metrics.get("score_normalized", before_score))
        before_issues = int(base_metrics.get("issue_count", 0))
        after_issues = int(after_metrics.get("issue_count", before_issues))
        f3_status = "improved" if after_score < before_score or after_issues < before_issues else "unchanged"
    elif action != "analyze":
        f3_status = "post_revalidation_unavailable"

    artifact_entries = []
    for label, path in artifacts.items():
        if not path:
            continue
        artifact_entries.append(
            {
                "label": label,
                "path": path,
                "exists_at_generation": os.path.exists(path),
            }
        )

    checkpoint_status = (backup_checkpoint or {}).get("status")
    restore_ready = checkpoint_status in ("verified", "verified_with_warnings")
    f5_status = (health or {}).get("status") or ("not_applicable" if action == "analyze" else "not_assessed")
    if action != "analyze" and checkpoint_status:
        if restore_ready:
            f5_status = "restore_checkpoint_ready"
        elif checkpoint_status == "dry_run_not_created":
            f5_status = "dry_run_not_applicable"
        else:
            f5_status = "restore_checkpoint_blocked"

    status = "partial" if error else "complete"
    return {
        "schema": "agentfence-f1-f5-v2",
        "status": status,
        "generated_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "action": action,
        "namespace": namespace,
        "error": error,
        "F1_runtime_placement": {
            "status": "captured" if context.get("target_pod") else "insufficient_evidence",
            "target_pod": context.get("target_pod"),
            "target_container": context.get("target_container"),
            "node": context.get("node"),
            "runtime_class": context.get("runtime_class"),
            "node_selector": context.get("node_selector"),
            "attacker_pod": context.get("attacker_pod"),
        },
        "F2_attack_path_containment": {
            "status": "captured" if post_results else "insufficient_evidence",
            "source": "post_remediation" if results_after else "current_state",
            "counts": post_counts,
            "unsafe_probe_ids": [
                r["id"]
                for r in result_dicts(post_results)
                if r.get("status") == "pass" and is_scored_probe(r.get("id"))
            ],
            "review_only_probe_ids": [
                r["id"]
                for r in result_dicts(post_results)
                if r.get("status") == "pass" and is_review_only_probe(r.get("id"))
            ],
            "skipped_probe_ids": [r["id"] for r in result_dicts(post_results) if r.get("status") == "skip"],
        },
        "F3_remediation_effectiveness": {
            "status": f3_status,
            "metrics_before": base_metrics,
            "metrics_after": after_metrics or None,
            "issue_count_before": base_metrics.get("issue_count"),
            "issue_count_after": after_metrics.get("issue_count") if after_metrics else None,
            "headline_before": base_metrics.get("score_normalized"),
            "headline_after": after_metrics.get("score_normalized") if after_metrics else None,
            "remediation_actionable_count": (remediation_plan or {}).get("actionable_count"),
        },
        "F4_artifact_consistency": {
            "status": "captured" if artifact_entries or backup_checkpoint else "insufficient_evidence",
            "artifacts": artifact_entries,
            "backup_checkpoint": {
                "status": checkpoint_status,
                "bundle_dir": (backup_checkpoint or {}).get("bundle_dir"),
                "manifest_path": (backup_checkpoint or {}).get("manifest_path"),
                "validation_report": (backup_checkpoint or {}).get("validation_report"),
                "restore_script": (backup_checkpoint or {}).get("restore_script"),
            }
            if backup_checkpoint
            else None,
        },
        "F5_recoverability": {
            "status": f5_status,
            "health": health or {},
            "workload_revalidations": [
                r.get("workload_revalidation")
                for r in (health or {}).get("records", [])
                if r.get("workload_revalidation")
            ],
            "runtime_seccomp_diagnostics": [
                r.get("runtime_seccomp_diagnostic")
                for r in (health or {}).get("records", [])
                if r.get("runtime_seccomp_diagnostic")
            ],
            "rollback_bundle_recorded": bool(artifacts.get("rollback_bundle") or (backup_checkpoint or {}).get("bundle_dir")),
            "rollback_bundle_path": artifacts.get("rollback_bundle") or (backup_checkpoint or {}).get("bundle_dir") or None,
            "backup_status": checkpoint_status,
            "restore_ready": restore_ready,
            "pvc_data": (backup_checkpoint or {}).get("pvc_data"),
            "mutation_gate": (backup_checkpoint or {}).get("mutation_gate"),
            "notes": "Analyze-only runs do not mutate the workload." if action == "analyze" else "",
        },
        "base_result_counts": base_counts,
    }


def write_f1_f5_md(path: str, evaluation: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    lines = [
        f"# AgentFence F1-F5 Evaluation ({evaluation.get('action')})",
        "",
        f"- schema: {evaluation.get('schema')}",
        f"- status: {evaluation.get('status')}",
        f"- namespace: {evaluation.get('namespace')}",
        "",
        "| factor | status | key evidence |",
        "|---|---|---|",
    ]
    f1 = evaluation.get("F1_runtime_placement") or {}
    f2 = evaluation.get("F2_attack_path_containment") or {}
    f3 = evaluation.get("F3_remediation_effectiveness") or {}
    f4 = evaluation.get("F4_artifact_consistency") or {}
    f5 = evaluation.get("F5_recoverability") or {}
    lines.append(f"| F1 runtime placement | {f1.get('status')} | target={f1.get('target_pod')} runtime={f1.get('runtime_class')} |")
    lines.append(f"| F2 attack-path containment | {f2.get('status')} | scored={len(f2.get('unsafe_probe_ids') or [])} review_only={len(f2.get('review_only_probe_ids') or [])} counts={f2.get('counts')} |")
    lines.append(f"| F3 remediation effectiveness | {f3.get('status')} | headline {f3.get('headline_before')} -> {f3.get('headline_after')} |")
    lines.append(f"| F4 artifact consistency | {f4.get('status')} | artifacts={len(f4.get('artifacts') or [])} |")
    rb = f5.get("rollback_bundle_path") or ""
    lines.append(
        f"| F5 recoverability | {f5.get('status')} | rollback={f5.get('rollback_bundle_recorded')} path={rb!r} |"
    )
    lines.append("")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def analyze_pipeline(
    namespace: str,
    kubeconfig: str,
    target_override: Optional[str],
    dry_run: bool,
    timeout: int,
    headline_alpha: float = DEFAULT_HEADLINE_ALPHA,
    prebuilt_ctx: Optional[RunContext] = None,
    allow_node_runtime_remediation: bool = False,
) -> Tuple[List[TestResult], ScoreBundle, RunContext]:
    ctx = prebuilt_ctx or build_context(
        namespace,
        kubeconfig,
        target_override,
        dry_run,
        timeout,
        allow_node_runtime_remediation=allow_node_runtime_remediation,
    )
    if dry_run:
        results = [
            tr(p.id, p.severity, "skip", f"dry-run target={ctx.target_pod}", "dry-run")
            for p in CATALOG
        ]
    else:
        results = run_all_probes(ctx)
    metrics = summarize_results(results, headline_alpha=headline_alpha)
    return results, metrics, ctx


def remediation_pipeline(
    namespace: str,
    kubeconfig: str,
    target_override: Optional[str],
    dry_run: bool,
    timeout: int,
    headline_alpha: float = DEFAULT_HEADLINE_ALPHA,
    backup_parent_dir: Optional[str] = None,
    include_secrets_backup: bool = True,
    velero_backup: bool = False,
    create_backup: bool = True,
    pre_run_backup_checkpoint: Optional[Dict[str, Any]] = None,
    prebuilt_ctx: Optional[RunContext] = None,
    allow_node_runtime_remediation: bool = False,
) -> Dict[str, Any]:
    """Same scoring as analyze; emits hints. v1 does not mutate the cluster."""
    r_before, m_before, ctx = analyze_pipeline(
        namespace,
        kubeconfig,
        target_override,
        dry_run,
        timeout,
        headline_alpha,
        prebuilt_ctx=prebuilt_ctx,
        allow_node_runtime_remediation=allow_node_runtime_remediation,
    )
    context = context_from_ctx(ctx)
    remediation_plan = build_remediation_plan(r_before, context)
    if pre_run_backup_checkpoint:
        backup_checkpoint = attach_remediation_plan_to_checkpoint(
            pre_run_backup_checkpoint,
            remediation_plan,
        ) or pre_run_backup_checkpoint
    elif create_backup:
        backup_checkpoint = build_restore_checkpoint(
            ctx,
            "remediation",
            remediation_plan,
            base_dir=backup_parent_dir,
            include_secrets=include_secrets_backup,
            run_velero=velero_backup,
        )
    else:
        backup_checkpoint = {
            "schema": COMPREHENSIVE_BACKUP_SCHEMA,
            "status": "disabled_by_user",
            "action": "remediation",
            "namespace": namespace,
            "bundle_dir": None,
            "mutation_gate": {
                "status": "blocked",
                "reason": "pre-remediation backup was disabled",
            },
        }
    hints = [
        {
            "probe": item["probe_id"],
            "issue_id": item["issue_id"],
            "action_type": item["action_type"],
            "hint": item["recommendation"],
        }
        for item in remediation_plan.get("actionable_items", [])
    ]
    remediation_apply = apply_remediation_actions(ctx, remediation_plan, backup_checkpoint, r_before)
    r_after, m_after, _ = analyze_pipeline(
        namespace,
        kubeconfig,
        target_override,
        dry_run,
        timeout,
        headline_alpha,
        prebuilt_ctx=ctx if dry_run else None,
    )
    return {
        "context": context,
        "metrics_before": m_before.__dict__,
        "metrics_after": m_after.__dict__,
        "results_before": [r.__dict__ for r in r_before],
        "results_after": [r.__dict__ for r in r_after],
        "remediation": remediation_plan,
        "remediation_apply": remediation_apply,
        "backup_checkpoint": backup_checkpoint,
        "remediation_hints": hints,
        "note": "Remediation modes enforce a restore checkpoint, apply supported Kubernetes fixes, then re-run the 39-probe analysis. Manual recommendations remain for node/runtime-specific issues.",
    }


def analyze_remediation_pipeline(
    namespace: str,
    kubeconfig: str,
    target_override: Optional[str],
    dry_run: bool,
    timeout: int,
    headline_alpha: float = DEFAULT_HEADLINE_ALPHA,
    backup_parent_dir: Optional[str] = None,
    include_secrets_backup: bool = True,
    velero_backup: bool = False,
    create_backup: bool = True,
    pre_run_backup_checkpoint: Optional[Dict[str, Any]] = None,
    prebuilt_ctx: Optional[RunContext] = None,
    allow_node_runtime_remediation: bool = False,
) -> Dict[str, Any]:
    """Chained analyze + remediation report; both phases use summarize_results only."""
    rem = remediation_pipeline(
        namespace,
        kubeconfig,
        target_override,
        dry_run,
        timeout,
        headline_alpha,
        backup_parent_dir,
        include_secrets_backup,
        velero_backup,
        create_backup,
        pre_run_backup_checkpoint,
        prebuilt_ctx,
        allow_node_runtime_remediation,
    )
    return {"phase": "analyze-remediation", **rem}


def maybe_ai_narrate(
    metrics: ScoreBundle,
    results: List[TestResult],
    guided: str,
    *,
    backup_bundle_path: Optional[str] = None,
    backup_status: Optional[str] = None,
    action: str = "analyze",
) -> str:
    if guided != "ai":
        return ""
    lines = [
        "AgentFence (AI summary — numbers are fixed from summarize_results):",
        f"- TBE (Trust-boundary): issues={metrics.tbe_issue_count} raw={metrics.tbe_score_raw} norm={metrics.tbe_score_normalized}",
        f"- ELE (Execution-local): issues={metrics.ele_issue_count} raw={metrics.ele_score_raw} norm={metrics.ele_score_normalized}",
        f"- Total unsafe: issues={metrics.issue_count} raw={metrics.score_raw}",
        f"- Headline score_normalized={metrics.score_normalized} (alpha={metrics.headline_alpha})",
        f"- review-only communication findings={sum(1 for r in results if r.status == 'pass' and is_review_only_probe(r.id))}",
        f"- skipped={len(metrics.skipped)}",
    ]
    if backup_bundle_path:
        lines.append(
            f"- Rollback: a namespace backup bundle was written (kubectl apply restore + manifest): {backup_bundle_path}"
        )
    elif action in ("remediation", "analyze-remediation") and backup_status == "dry_run_not_created":
        lines.append(
            "- Rollback: dry-run mode recorded the enforced pre-run checkpoint gate; no cluster bundle was created."
        )
    elif action in ("remediation", "analyze-remediation"):
        lines.append(
            f"- Rollback: enforced pre-run checkpoint status={backup_status or 'unknown'}; no bundle path was recorded."
        )
    else:
        lines.append(
            "- Rollback: no namespace backup bundle for this analyze run (use --create-backup on analyze; remediation / analyze-remediation require an enforced restore checkpoint before probes)."
        )
    top = [r for r in results if r.status == "pass" and is_scored_probe(r.id)][:8]
    if top:
        lines.append("Top scored unsafe probes:")
        for r in top:
            lines.append(f"  - {r.id}: {r.matched_clause or r.evidence[:80]}")
    review_only = [r for r in results if r.status == "pass" and is_review_only_probe(r.id)]
    if review_only:
        lines.append("Review-only communication findings:")
        for r in review_only:
            lines.append(f"  - {canonical_probe_id(r.id)}: {r.matched_clause or r.evidence[:80]}")
    return "\n".join(lines)


def redact_for_ai(value: Any) -> Any:
    sensitive_tokens = ("secret", "token", "password", "credential", "apikey", "api_key", "authorization")
    if isinstance(value, dict):
        clean: Dict[str, Any] = {}
        for key, item in value.items():
            key_s = str(key)
            if any(token in key_s.lower() for token in sensitive_tokens):
                clean[key_s] = "<redacted>"
            else:
                clean[key_s] = redact_for_ai(item)
        return clean
    if isinstance(value, list):
        return [redact_for_ai(item) for item in value[:200]]
    if isinstance(value, str):
        if len(value) > 4000:
            return value[:4000] + "...<truncated>"
        return value
    return value


def compact_ai_context(payload: Dict[str, Any]) -> Dict[str, Any]:
    return redact_for_ai(
        {
            "catalog_version": payload.get("catalog_version"),
            "phase": payload.get("phase"),
            "context": payload.get("context"),
            "metrics_before": payload.get("metrics_before") or payload.get("metrics"),
            "metrics_after": payload.get("metrics_after"),
            "enriched_report": payload.get("enriched_report"),
            "evaluation": payload.get("evaluation"),
            "remediation": payload.get("remediation"),
            "remediation_apply": payload.get("remediation_apply"),
            "backup_checkpoint": payload.get("backup_checkpoint"),
        }
    )


def load_json_file(path: str) -> Optional[Dict[str, Any]]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def latest_agentfence_artifact(namespace: str = "", action: str = "") -> Optional[str]:
    root = pathlib.Path(os.path.dirname(os.path.abspath(__file__))) / "generated_outputs"
    if not root.exists():
        return None
    patterns: List[str] = []
    if action and namespace:
        patterns.append(f"agentfence_{action}_{namespace}_*.json")
    if namespace:
        patterns.append(f"agentfence_*_{namespace}_*.json")
    patterns.append("agentfence_*.json")
    seen: Dict[str, pathlib.Path] = {}
    for pattern in patterns:
        for path in root.glob(pattern):
            if "_f1_f5_" in path.name:
                continue
            seen[str(path)] = path
    if not seen:
        return None
    return str(sorted(seen.values(), key=lambda p: p.stat().st_mtime, reverse=True)[0])


def read_openai_api_key_from_keychain(
    service: str = AI_KEYCHAIN_SERVICE,
    account: str = AI_KEYCHAIN_ACCOUNT,
) -> Optional[str]:
    if platform.system() != "Darwin":
        return None
    if not shutil.which("security"):
        return None
    try:
        proc = subprocess.run(
            ["security", "find-generic-password", "-w", "-s", service, "-a", account],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5,
        )
        if proc.returncode != 0:
            return None
        value = (proc.stdout or "").strip()
        return value or None
    except Exception:
        return None


def read_openai_api_key_from_keyring(
    service: str = AI_KEYCHAIN_SERVICE,
    account: str = AI_KEYCHAIN_ACCOUNT,
) -> Optional[str]:
    try:
        import keyring  # type: ignore
    except Exception:
        return None
    try:
        value = keyring.get_password(service, account)
        value = (value or "").strip()
        return value or None
    except Exception:
        return None


def resolve_openai_api_key() -> Tuple[str, str]:
    env_value = (os.environ.get("OPENAI_API_KEY") or os.environ.get("AGENTFENCE_OPENAI_API_KEY") or "").strip()
    if env_value:
        return env_value, "environment"
    keychain_value = read_openai_api_key_from_keychain()
    if keychain_value:
        return keychain_value, "macos_keychain"
    keyring_value = read_openai_api_key_from_keyring()
    if keyring_value:
        return keyring_value, "keyring"
    return "", ""


def ask_ai_backend(question: str, report_payload: Dict[str, Any], history: List[Dict[str, str]]) -> str:
    api_key, _ = resolve_openai_api_key()
    if not api_key:
        return (
            "AI backend is not configured. AgentFence looked in environment variables, macOS Keychain, "
            "and Python keyring. The latest AgentFence artifact is loaded and ready for AI analysis."
        )
    model = os.environ.get("AGENTFENCE_AI_MODEL") or os.environ.get("AGENTFENCE_OPENAI_MODEL") or "gpt-4.1-mini"
    context = json.dumps(compact_ai_context(report_payload), indent=2, sort_keys=True)
    if len(context) > 120000:
        context = context[:120000] + "\n...<context truncated>"
    prior = "\n".join(
        f"{item.get('role', 'user')}: {item.get('content', '')[:1200]}"
        for item in history[-6:]
    )
    prompt_text = (
        "You are the AgentFence AI analysis backend. Answer the operator's question using only the "
        "AgentFence report context below. Be concrete about scored findings, review-only findings, "
        "remediation results, backup/restore state, and evaluation factors when relevant. If the "
        "report context does not support a claim, say so.\n\n"
        f"Recent conversation:\n{prior or '<none>'}\n\n"
        f"AgentFence report context:\n{context}\n\n"
        f"Operator question: {question}"
    )
    body = json.dumps(
        {
            "model": model,
            "input": [
                {
                    "role": "user",
                    "content": [{"type": "input_text", "text": prompt_text}],
                }
            ],
        }
    ).encode("utf-8")
    request = urllib.request.Request(
        os.environ.get("AGENTFENCE_OPENAI_BASE_URL", "https://api.openai.com/v1/responses"),
        data=body,
        headers={
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=60) as response:
            data = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="replace")[:1000]
        return f"AI backend request failed: HTTP {e.code}: {detail}"
    except Exception as e:
        return f"AI backend request failed: {type(e).__name__}: {e}"
    output_text = data.get("output_text")
    if isinstance(output_text, str) and output_text.strip():
        return output_text.strip()
    parts: List[str] = []
    for item in data.get("output") or []:
        for content in item.get("content") or []:
            text = content.get("text")
            if isinstance(text, str):
                parts.append(text)
    return "\n".join(parts).strip() or "AI backend returned no text."


def prompt(text: str, default: Optional[str] = None) -> str:
    suffix = f" [{default}]" if default not in (None, "") else ""
    value = input(f"{text}{suffix}: ").strip()
    return value or (default or "")


class AiPromptExit(SystemExit):
    pass


def is_cancel_command(value: str) -> bool:
    return value.strip().lower() in ("cancel", "back", "main")


def is_exit_command(value: str) -> bool:
    return value.strip().lower() in ("exit", "quit", "q")


def prompt_interactive(text: str, default: Optional[str] = None, allow_cancel: bool = True) -> Optional[str]:
    value = prompt(text, default)
    if is_exit_command(value):
        raise AiPromptExit(0)
    if allow_cancel and is_cancel_command(value):
        return None
    return value


def prompt_yes_no(text: str, default: bool = False, allow_cancel: bool = True) -> Optional[bool]:
    default_text = "yes" if default else "no"
    while True:
        value = prompt_interactive(text, default_text, allow_cancel=allow_cancel)
        if value is None:
            return None
        folded = value.strip().lower()
        if folded in ("y", "yes"):
            return True
        if folded in ("n", "no"):
            return False
        print("Please answer yes or no, or type cancel / exit.")


def print_node_runtime_preflight(audit: Dict[str, Any]) -> None:
    status = str(audit.get("status") or "unknown")
    node = str(audit.get("node") or "unknown")
    runtime = audit.get("runtime") or {}
    runtime_label = runtime.get("runtime_class") or runtime.get("handler") or runtime.get("family") or "default"
    if status == "already_hardened":
        print(f"\nNode runtime hardening preflight: {node} already satisfies the AgentFence baseline for runtime {runtime_label}.")
        print("No node-level hardening prompt is needed for this run.")
        return
    print(f"\nNode runtime hardening preflight: changes may be needed on {node} for runtime {runtime_label}.")
    reasons = audit.get("change_reasons") or []
    for reason in reasons[:8]:
        print(f"- {reason}")
    if not reasons:
        print("- AgentFence could not fully verify node hardening state, so operator confirmation is required before node changes.")


def prompt_ai_node_runtime_hardening(audit: Optional[Dict[str, Any]] = None) -> bool:
    if audit:
        print_node_runtime_preflight(audit)
        if audit.get("status") == "already_hardened" and not audit.get("changes_needed"):
            return False
    print("\nNode runtime hardening options:")
    print("1. Enable guest seccomp")
    print("2. Restrict kernel dmesg")
    print("3. Restrict perf_event_open")
    print("4. Disable unprivileged BPF")
    print("5. Restrict unprivileged userfaultfd")
    print("all. Apply all node runtime hardening")
    print("0. Skip node runtime hardening")
    print("")
    print("These options may change node/runtime settings on the target node. Guest seccomp can restart containerd and recreate the workload pod; sysctl options apply node-wide immediately.")
    print("This can affect other workloads using the same node/runtime handler.")
    while True:
        selected = prompt_interactive("Node runtime hardening option", "0", allow_cancel=True)
        if selected is None:
            print("Node runtime hardening cancelled for this run.")
            return False
        value = selected.strip().lower()
        if value in ("0", "skip", "no", "none"):
            return False
        if value in ("1", "2", "3", "4", "5", "all", "a", "yes", "y", "enable guest seccomp", "guest seccomp", "seccomp"):
            confirmed = prompt_yes_no("Apply selected node runtime hardening?", default=False, allow_cancel=True)
            return bool(confirmed)
        print("Please choose 1-5, all, 0 to skip, or type cancel / exit.")


def prompt_choice(text: str, choices: List[str], default: Optional[str] = None) -> str:
    folded = {c.lower(): c for c in choices}
    aliases = {
        "fix": "remediation",
        "remediate": "remediation",
        "analyze and remediate": "analyze-remediation",
        "analyze-remediate": "analyze-remediation",
        "analyze remediation": "analyze-remediation",
        "ar": "analyze-remediation",
        "backup": "backup-namespace",
        "restore": "restore-namespace",
    }
    while True:
        raw = prompt(f"{text} ({' | '.join(choices)})", default)
        key = aliases.get(raw.lower(), raw.lower())
        if key in folded:
            return folded[key]
        print(f"Please choose one of: {', '.join(choices)}")


def list_namespaces(kubeconfig: str) -> List[str]:
    data = kubectl_get_json(kubeconfig, ["get", "namespaces"])
    names = [
        str(((item.get("metadata") or {}).get("name")) or "")
        for item in (data or {}).get("items", [])
    ]
    return sorted(n for n in names if n)


def resolve_namespace(selection: str, namespaces: List[str]) -> Optional[str]:
    value = selection.strip()
    if not value:
        return None
    if value.isdigit():
        idx = int(value)
        if 1 <= idx <= len(namespaces):
            return namespaces[idx - 1]
    for namespace in namespaces:
        if namespace == value:
            return namespace
    matches = [namespace for namespace in namespaces if value.lower() in namespace.lower()]
    if len(matches) == 1:
        return matches[0]
    return None


def print_namespaces(kubeconfig: str) -> List[str]:
    names = list_namespaces(kubeconfig)
    print("\nAvailable namespaces:")
    if not names:
        print("  <none found>")
        return []
    for idx, name in enumerate(names, start=1):
        print(f"{idx}. {name}")
    return names


def prompt_namespace_choice(kubeconfig: str, default: str = "", allow_cancel: bool = True) -> Optional[str]:
    names = print_namespaces(kubeconfig)
    if not names:
        return prompt_interactive("Namespace", default, allow_cancel=allow_cancel)
    while True:
        selected = prompt_interactive("Namespace name or number", default, allow_cancel=allow_cancel)
        if selected is None:
            return None
        resolved = resolve_namespace(selected, names)
        if resolved:
            return resolved
        print("Please choose a namespace by number or name, or type cancel / exit.")


AI_ACTION_CHOICES = [
    "Analyze",
    "Remediation",
    "Analyze&Remediation",
    "Backup",
    "Restore",
]


def resolve_ai_action(selection: str) -> Optional[str]:
    raw = selection.strip()
    numeric_map = {
        "1": "analyze",
        "2": "remediation",
        "3": "analyze-remediation",
        "4": "backup-namespace",
        "5": "restore-namespace",
    }
    if raw in numeric_map:
        return numeric_map[raw]
    norm = re.sub(r"[^a-z]+", "", selection.lower())
    action_map = {
        "analyze": "analyze",
        "analysis": "analyze",
        "remediation": "remediation",
        "remediate": "remediation",
        "fix": "remediation",
        "analyzeremediation": "analyze-remediation",
        "analyzeremediate": "analyze-remediation",
        "analyzeandremediation": "analyze-remediation",
        "analyzeandremediate": "analyze-remediation",
        "ar": "analyze-remediation",
        "backup": "backup-namespace",
        "backupnamespace": "backup-namespace",
        "restore": "restore-namespace",
        "restorenamespace": "restore-namespace",
    }
    return action_map.get(norm)


def print_ai_action_choices() -> None:
    print("\nWhat would you like AgentFence to run?")
    for idx, label in enumerate(AI_ACTION_CHOICES, start=1):
        print(f"{idx}. {label}")


def prompt_ai_action_choice(allow_cancel: bool = True) -> Optional[str]:
    while True:
        print_ai_action_choices()
        selected = prompt_interactive("Action name or number", allow_cancel=allow_cancel)
        if selected is None:
            return None
        action = resolve_ai_action(selected)
        if action:
            return action
        print("Please choose Analyze, Remediation, Analyze&Remediation, Backup, or Restore; or type cancel / exit.")


def run_kubectl_config(kubeconfig: str, args: List[str], timeout: int = 15) -> Tuple[int, str, str]:
    """Read kubectl-visible context metadata without changing current-context or saved state.

    Discovery intentionally ignores --kubeconfig so every AI-mode session sees
    the operator's current kubectl environment fresh at runtime.
    """
    del kubeconfig
    cmd = kubectl_base("") + ["config"] + args
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        return p.returncode, p.stdout or "", p.stderr or ""
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except Exception as e:
        return 1, "", f"{type(e).__name__}: {e}"


def list_kube_contexts(kubeconfig: str) -> List[str]:
    rc, out, _ = run_kubectl_config(kubeconfig, ["get-contexts", "-o", "name"], timeout=15)
    if rc != 0:
        return []
    return [line.strip() for line in out.splitlines() if line.strip()]


def saved_current_context(kubeconfig: str) -> str:
    rc, out, _ = run_kubectl_config(kubeconfig, ["current-context"], timeout=15)
    return (out or "").strip() if rc == 0 else ""


def kubectl_cluster_reachable(kubeconfig: str) -> Tuple[bool, str]:
    rc, out, err = run_kubectl(kubeconfig, ["cluster-info"], timeout=20)
    detail = (out or err or f"kubectl exited {rc}").strip()
    return rc == 0, detail


def kubeconfig_status(kubeconfig: str) -> str:
    if not kubeconfig:
        return "discovery is using kubectl default runtime configuration"
    expanded = os.path.expanduser(kubeconfig)
    if os.path.exists(expanded):
        return f"run kubeconfig supplied: {expanded}; discovery still uses kubectl default runtime configuration"
    return f"run kubeconfig file not found: {expanded}; discovery still uses kubectl default runtime configuration"


def resolve_kube_context(selection: str, contexts: List[str]) -> Optional[str]:
    value = selection.strip()
    if not value:
        return None
    if value.isdigit():
        idx = int(value)
        if 1 <= idx <= len(contexts):
            return contexts[idx - 1]
    for ctx in contexts:
        if ctx == value:
            return ctx
    matches = [ctx for ctx in contexts if value.lower() in ctx.lower()]
    if len(matches) == 1:
        return matches[0]
    return None


def print_kube_contexts(kubeconfig: str) -> List[str]:
    contexts = list_kube_contexts(kubeconfig)
    current = saved_current_context(kubeconfig)
    print("\nAvailable Kubernetes clusters/contexts:")
    print(f"  {kubeconfig_status(kubeconfig)}")
    if not contexts:
        reachable, detail = kubectl_cluster_reachable(kubeconfig)
        print("  <no named contexts found>")
        if reachable:
            print("  kubectl can still reach a cluster without a named context.")
        else:
            print("  kubectl could not reach a cluster yet.")
            if shutil.which("kubectl"):
                print(f"  diagnostic: {detail[:500]}")
            else:
                print("  diagnostic: kubectl is not on PATH")
        return []
    for idx, ctx in enumerate(contexts, start=1):
        marker = " (saved current)" if ctx == current else ""
        print(f"{idx}. {ctx}{marker}")
    return contexts


def current_namespace(kubeconfig: str) -> str:
    rc, out, _ = run_kubectl(
        kubeconfig,
        ["config", "view", "--minify", "-o", "jsonpath={..namespace}"],
        timeout=15,
    )
    return (out or "").strip() if rc == 0 else ""


def latest_restore_bundle_for_namespace(base_dir: str, namespace: str) -> Optional[str]:
    root = pathlib.Path(base_dir)
    bundles = [
        p
        for p in root.glob(f"rollback_bundle_{_safe_backup_filename(namespace)}_*")
        if p.is_dir() and (p / "backup_manifest.json").exists()
    ]
    if not bundles:
        return None
    return str(sorted(bundles, key=lambda p: p.stat().st_mtime, reverse=True)[0])


def restore_bundles_for_namespace(base_dir: str, namespace: str) -> List[pathlib.Path]:
    root = pathlib.Path(base_dir)
    if not root.exists():
        return []
    bundles = [
        p
        for p in root.glob(f"rollback_bundle_{_safe_backup_filename(namespace)}_*")
        if p.is_dir() and (p / "backup_manifest.json").exists()
    ]
    return sorted(bundles, key=lambda p: p.stat().st_mtime, reverse=True)


def restore_bundle_summary(bundle: pathlib.Path) -> Dict[str, Any]:
    manifest = load_json_file(str(bundle / "backup_manifest.json")) or {}
    stat = bundle.stat()
    created = str(manifest.get("created_at_utc") or "")
    action = str(manifest.get("action") or "")
    status = str(manifest.get("status") or "")
    target = str(manifest.get("target_pod") or "")
    if not target:
        target = "namespace"
    return {
        "path": str(bundle),
        "name": bundle.name,
        "created_at_utc": created,
        "action": action,
        "status": status,
        "target": target,
        "mtime": stat.st_mtime,
    }


def print_restore_bundles(base_dir: str, namespace: str) -> List[pathlib.Path]:
    bundles = restore_bundles_for_namespace(base_dir, namespace)
    print(f"\nAvailable restore backups for namespace {namespace}:")
    if not bundles:
        print("  <none found>")
        return []
    for idx, bundle in enumerate(bundles, start=1):
        summary = restore_bundle_summary(bundle)
        created = summary.get("created_at_utc") or datetime.datetime.fromtimestamp(
            float(summary.get("mtime") or 0), datetime.timezone.utc
        ).isoformat()
        print(
            f"{idx}. {summary.get('name')} | target={summary.get('target')} "
            f"| action={summary.get('action') or 'unknown'} | status={summary.get('status') or 'unknown'} "
            f"| created={created}"
        )
    return bundles


def prompt_restore_bundle_choice(base_dir: str, namespace: str) -> Optional[str]:
    bundles = print_restore_bundles(base_dir, namespace)
    if not bundles:
        return None
    while True:
        selected = prompt_interactive("Restore backup name or number", "1", allow_cancel=True)
        if selected is None:
            return None
        value = selected.strip()
        if value.isdigit():
            idx = int(value)
            if 1 <= idx <= len(bundles):
                return str(bundles[idx - 1])
        for bundle in bundles:
            if bundle.name == value or str(bundle) == value:
                return str(bundle)
        matches = [bundle for bundle in bundles if value.lower() in bundle.name.lower()]
        if len(matches) == 1:
            return str(matches[0])
        print("Please choose a restore backup by number or name, or type cancel / exit.")


def parse_first_json_object(text: str) -> Optional[Dict[str, Any]]:
    decoder = json.JSONDecoder()
    for idx, char in enumerate(text or ""):
        if char != "{":
            continue
        try:
            obj, _ = decoder.raw_decode(text[idx:])
        except Exception:
            continue
        if isinstance(obj, dict):
            return obj
    return None


def print_restore_result_summary(status: int, stdout: str, stderr: str, bundle_dir: Optional[str]) -> None:
    result = parse_first_json_object(stdout) or {}
    restore_status = str(result.get("status") or ("failed" if status else "complete"))
    applied = result.get("applied") or []
    skipped = result.get("skipped_empty") or []
    fallback = result.get("fallback_applied") or []
    failures = result.get("failures") or []
    reconciled = result.get("reconciled") or []
    print("\nRestore summary:")
    print(f"- status: {restore_status}")
    print(f"- exit_code: {status}")
    if bundle_dir:
        print(f"- backup: {os.path.basename(bundle_dir)}")
    print(f"- applied_resources: {len(applied)}")
    print(f"- fallback_applied: {len(fallback)}")
    print(f"- reconciled_items: {len(reconciled)}")
    print(f"- skipped_empty: {len(skipped)}")
    print(f"- failures: {len(failures)}")
    if failures:
        print("- failed_items:")
        for item in failures[:5]:
            if isinstance(item, dict):
                label = item.get("file") or item.get("resource") or item.get("kind") or "unknown"
                message = item.get("message") or item.get("error") or item.get("reason") or ""
                print(f"  - {label}: {str(message)[:240]}")
            else:
                print(f"  - {str(item)[:240]}")
    elif status == 0 and restore_status == "complete":
        print("- result: restore completed successfully")
    if status != 0 and stderr:
        print(f"- error: {stderr.strip()[:500]}")


def print_ai_interactive_intro(kubeconfig: str) -> None:
    print("\n=== AgentFence AI interactive CLI ===")
    print("I can help you restore, analyze, remediate, or analyze-remediate a Kubernetes sandbox.")
    print("First I will look for Kubernetes clusters/contexts through kubectl runtime discovery.")
    print("Commands: list clusters, use cluster <name-or-number>, list namespaces, use namespace <name>, analyze, remediate, analyze-remediation, backup, restore, status, help, exit")
    print_kube_contexts(kubeconfig)


def run_agentfence_child(
    *,
    app_mode: str,
    namespace: str,
    action: str,
    kubeconfig: str,
    cluster: Optional[str],
    timeout: int,
    headline_alpha: float,
    backup_parent: str,
    include_secrets_backup: bool,
    velero_backup: bool,
    bundle_dir: Optional[str] = None,
    allow_node_runtime_remediation: bool = False,
) -> Tuple[int, Optional[str]]:
    script = os.path.abspath(__file__)
    mapped_action = action
    cmd = [
        sys.executable,
        script,
        "--app-mode",
        app_mode,
        "--namespace",
        namespace,
        "--action",
        mapped_action,
        "--timeout",
        str(timeout),
        "--headline-alpha",
        str(headline_alpha),
        "--backup-parent-dir",
        backup_parent,
    ]
    if kubeconfig:
        cmd.extend(["--kubeconfig", kubeconfig])
    if cluster:
        cmd.extend(["--cluster", cluster])
    if not include_secrets_backup:
        cmd.append("--omit-secrets-backup")
    if velero_backup:
        cmd.append("--velero-backup")
    if bundle_dir:
        cmd.extend(["--bundle-dir", bundle_dir])
    if allow_node_runtime_remediation:
        cmd.append("--allow-node-runtime-remediation")
    proc = subprocess.run(cmd, text=True, capture_output=True)
    if action == "restore-namespace":
        print_restore_result_summary(proc.returncode, proc.stdout or "", proc.stderr or "", bundle_dir)
    else:
        if proc.stdout:
            print(proc.stdout, end="")
        if proc.stderr:
            print(proc.stderr, end="", file=sys.stderr)
    artifact_path = None
    try:
        match = re.search(r'\{\s*"out"\s*:\s*"([^"]+)"', proc.stdout or "", re.S)
        if match:
            artifact_path = match.group(1)
    except Exception:
        artifact_path = None
    return proc.returncode, artifact_path


def run_ai_selected_action(
    *,
    action: str,
    namespace: str,
    cluster: Optional[str],
    kubeconfig: str,
    args: argparse.Namespace,
    backup_parent: str,
    include_secrets_backup: bool,
) -> Tuple[int, Optional[str]]:
    bundle_dir = None
    allow_node_runtime_remediation = bool(args.allow_node_runtime_remediation)
    if action == "restore-namespace":
        bundle_dir = args.bundle_dir or prompt_restore_bundle_choice(backup_parent, namespace)
        if not bundle_dir:
            print(f"No rollback bundle found for {namespace} under {backup_parent}.")
            return 2, None
    elif action in ("remediation", "analyze-remediation") and not allow_node_runtime_remediation:
        preflight: Optional[Dict[str, Any]] = None
        try:
            preflight_ctx = build_context(
                namespace,
                kubeconfig,
                args.target_pod,
                False,
                args.timeout,
                allow_node_runtime_remediation=False,
            )
            preflight = audit_node_runtime_hardening(preflight_ctx)
        except Exception as e:
            preflight = {
                "kind": "node_runtime_hardening_preflight",
                "status": "unknown",
                "changes_needed": True,
                "change_reasons": [f"preflight audit failed: {type(e).__name__}: {e}"],
            }
        allow_node_runtime_remediation = prompt_ai_node_runtime_hardening(preflight)
        if not allow_node_runtime_remediation:
            if preflight and preflight.get("status") == "already_hardened":
                print("Node/runtime remediation not enabled because the preflight found no node-level changes to apply.")
            else:
                print("Node/runtime remediation disabled for this run; AgentFence will report runtime changes as manual if needed.")
    print(f"\nRunning AgentFence {action} on {namespace}...")
    status, artifact_path = run_agentfence_child(
        app_mode="ai",
        namespace=namespace,
        action=action,
        kubeconfig=kubeconfig,
        cluster=cluster,
        timeout=args.timeout,
        headline_alpha=args.headline_alpha,
        backup_parent=backup_parent,
        include_secrets_backup=include_secrets_backup,
        velero_backup=args.velero_backup,
        bundle_dir=bundle_dir,
        allow_node_runtime_remediation=allow_node_runtime_remediation,
    )
    print(f"\nAgentFence command finished with exit code {status}.")
    return status, artifact_path


def run_ai_interactive_cli(args: argparse.Namespace, kubeconfig: str, backup_parent: str, include_secrets_backup: bool) -> int:
    global ACTIVE_KUBE_CONTEXT
    discovery_kubeconfig = ""
    cluster = args.cluster or None
    ACTIVE_KUBE_CONTEXT = cluster
    cluster_ready = bool(cluster)
    namespace = args.namespace or ""
    print_ai_interactive_intro(discovery_kubeconfig)
    if cluster:
        print(f"\nUsing Kubernetes context for this run only: {cluster}")
        if not args.namespace:
            namespace = prompt_namespace_choice(discovery_kubeconfig, current_namespace(discovery_kubeconfig)) or ""
    else:
        contexts = list_kube_contexts(discovery_kubeconfig)
        if contexts:
            selected = prompt_interactive("Cluster/context name or number", allow_cancel=True)
            if selected is None:
                selected = ""
            resolved = resolve_kube_context(selected, contexts)
            if resolved:
                cluster = resolved
                cluster_ready = True
                ACTIVE_KUBE_CONTEXT = cluster
                print(f"\nUsing Kubernetes context for this run only: {cluster}")
                namespace = args.namespace or (prompt_namespace_choice(discovery_kubeconfig, current_namespace(discovery_kubeconfig)) or "")
            else:
                print("No cluster context selected yet. Use `list clusters` and `use cluster <name-or-number>` before running an action.")
        else:
            reachable, _ = kubectl_cluster_reachable(discovery_kubeconfig)
            cluster_ready = reachable
            if reachable:
                print("\nNo named context was found, but kubectl can reach a cluster. AgentFence will use that live kubectl access for this run only.")
                namespace = args.namespace or (prompt_namespace_choice(discovery_kubeconfig, current_namespace(discovery_kubeconfig)) or "")
            else:
                print("\nNo kubeconfig context or live kubectl cluster access was found yet.")
                print("AgentFence will keep retrying discovery when you use `list clusters`; it will not create or save cluster configuration.")
    if namespace:
        print(f"\nUsing namespace: {namespace}")
    last_status = 0
    last_artifact_path: Optional[str] = None
    last_report_payload: Optional[Dict[str, Any]] = None
    ai_history: List[Dict[str, str]] = []
    pending_choice: Optional[Dict[str, Any]] = None

    def remember_run(status_and_artifact: Tuple[int, Optional[str]], action_name: str) -> None:
        nonlocal last_status, last_artifact_path, last_report_payload
        last_status, artifact_path = status_and_artifact
        if not artifact_path:
            artifact_path = latest_agentfence_artifact(namespace, action_name)
        if artifact_path:
            loaded = load_json_file(artifact_path)
            if loaded:
                last_artifact_path = artifact_path
                last_report_payload = loaded
                print(f"AI context loaded from: {artifact_path}")

    def select_namespace_and_run(requested: str) -> None:
        nonlocal namespace, pending_choice
        names = pending_choice.get("items") if pending_choice and pending_choice.get("type") == "namespace" else list_namespaces(discovery_kubeconfig)
        namespace = resolve_namespace(requested, names or []) or requested
        pending_choice = None
        print(f"\nUsing namespace: {namespace}")
        action = prompt_ai_action_choice()
        if action is None:
            print("Cancelled. Returning to main prompt.")
            return
        remember_run(
            run_ai_selected_action(
                action=action,
                namespace=namespace,
                cluster=cluster,
                kubeconfig=discovery_kubeconfig,
                args=args,
                backup_parent=backup_parent,
                include_secrets_backup=include_secrets_backup,
            ),
            action,
        )

    def select_cluster_then_namespace(requested: str) -> None:
        global ACTIVE_KUBE_CONTEXT
        nonlocal cluster, cluster_ready, namespace, pending_choice
        contexts = pending_choice.get("items") if pending_choice and pending_choice.get("type") == "cluster" else list_kube_contexts(discovery_kubeconfig)
        resolved = resolve_kube_context(requested, contexts or [])
        if not resolved:
            print(f"Could not resolve cluster/context {requested!r}. Use `list clusters` to see available contexts.")
            return
        cluster = resolved
        cluster_ready = True
        ACTIVE_KUBE_CONTEXT = cluster
        pending_choice = None
        print(f"\nUsing Kubernetes context for this run only: {cluster}")
        selected_namespace = prompt_namespace_choice(discovery_kubeconfig, current_namespace(discovery_kubeconfig))
        if selected_namespace is None:
            print("Cancelled. Returning to main prompt.")
            return
        select_namespace_and_run(selected_namespace)

    if cluster_ready and namespace:
        action = prompt_ai_action_choice()
        if action is None:
            print("Cancelled. Returning to main prompt.")
        else:
            remember_run(
                run_ai_selected_action(
                    action=action,
                    namespace=namespace,
                    cluster=cluster,
                    kubeconfig=discovery_kubeconfig,
                    args=args,
                    backup_parent=backup_parent,
                    include_secrets_backup=include_secrets_backup,
                ),
                action,
            )
    while True:
        try:
            raw = input("agentfence-ai> ").strip()
        except EOFError:
            print("\nExiting AgentFence AI interactive CLI.")
            return last_status
        if not raw:
            print("Type `help` for commands, or `exit` to leave.")
            continue
        command = raw.lower()
        if command in ("exit", "quit", "q"):
            print("Exiting AgentFence AI interactive CLI.")
            return last_status
        if pending_choice and is_cancel_command(raw):
            pending_choice = None
            print("Cancelled. Returning to main prompt.")
            continue
        if pending_choice and pending_choice.get("type") == "namespace":
            select_namespace_and_run(raw)
            continue
        if pending_choice and pending_choice.get("type") == "cluster":
            select_cluster_then_namespace(raw)
            continue
        if command == "help":
            print("Commands: list clusters, use cluster <name-or-number>, list namespaces, use namespace <name>, analyze, remediate, analyze-remediation, backup, restore, status, help, exit")
            print("The run commands use the same AgentFence app and write normal generated_outputs artifacts.")
            print("After a run, type a normal question and AgentFence will forward it to the AI backend with the latest report context.")
            print_ai_action_choices()
            continue
        if command in ("status", "show status"):
            print(f"cluster_context={cluster or ('<kubectl-default>' if cluster_ready else '<unset>')} namespace={namespace or '<unset>'} timeout={args.timeout} alpha={args.headline_alpha}")
            continue
        if command in ("list clusters", "list contexts", "clusters", "contexts"):
            contexts = print_kube_contexts(discovery_kubeconfig)
            if contexts:
                pending_choice = {"type": "cluster", "items": contexts}
                print("Cluster/context name or number:")
            if not cluster:
                reachable, _ = kubectl_cluster_reachable(discovery_kubeconfig)
                cluster_ready = reachable
            continue
        if command.startswith("use cluster ") or command.startswith("use context "):
            prefix = "use cluster " if command.startswith("use cluster ") else "use context "
            requested = raw[len(prefix):].strip()
            contexts = list_kube_contexts(discovery_kubeconfig)
            resolved = resolve_kube_context(requested, contexts)
            if not resolved:
                print(f"Could not resolve cluster/context {requested!r}. Use `list clusters` to see available contexts.")
                continue
            cluster = resolved
            cluster_ready = True
            ACTIVE_KUBE_CONTEXT = cluster
            print(f"\nUsing Kubernetes context for this run only: {cluster}")
            namespace = args.namespace or prompt_namespace_choice(discovery_kubeconfig, current_namespace(discovery_kubeconfig))
            if namespace is None:
                print("Cancelled. Returning to main prompt.")
                continue
            if namespace:
                print(f"\nUsing namespace: {namespace}")
                action = prompt_ai_action_choice()
                if action is None:
                    print("Cancelled. Returning to main prompt.")
                    continue
                remember_run(
                    run_ai_selected_action(
                        action=action,
                        namespace=namespace,
                        cluster=cluster,
                        kubeconfig=discovery_kubeconfig,
                        args=args,
                        backup_parent=backup_parent,
                        include_secrets_backup=include_secrets_backup,
                    ),
                    action,
                )
            continue
        namespace_command = re.sub(r"[^a-z]+", "", command)
        if command in ("list namespaces", "list namespace", "namespaces") or namespace_command in (
            "listnamespaces",
            "listnamespace",
            "listnamaspces",
            "listnamesapces",
            "listnamespces",
        ):
            if not cluster_ready:
                print("Select a cluster/context first with `use cluster <name-or-number>`, or provide kubectl access and run `list clusters` again.")
                continue
            names = print_namespaces(discovery_kubeconfig)
            if names:
                pending_choice = {"type": "namespace", "items": names}
                print("Namespace name or number:")
            continue
        if command.startswith("use namespace "):
            requested = raw[len("use namespace "):].strip()
            names = list_namespaces(discovery_kubeconfig)
            namespace = resolve_namespace(requested, names) or requested
            print(f"\nUsing namespace: {namespace}")
            action = prompt_ai_action_choice()
            if action is None:
                print("Cancelled. Returning to main prompt.")
                continue
            remember_run(
                run_ai_selected_action(
                    action=action,
                    namespace=namespace,
                    cluster=cluster,
                    kubeconfig=discovery_kubeconfig,
                    args=args,
                    backup_parent=backup_parent,
                    include_secrets_backup=include_secrets_backup,
                ),
                action,
            )
            continue
        if command.startswith("namespace "):
            requested = raw[len("namespace "):].strip()
            names = list_namespaces(discovery_kubeconfig)
            namespace = resolve_namespace(requested, names) or requested
            print(f"\nUsing namespace: {namespace}")
            action = prompt_ai_action_choice()
            if action is None:
                print("Cancelled. Returning to main prompt.")
                continue
            remember_run(
                run_ai_selected_action(
                    action=action,
                    namespace=namespace,
                    cluster=cluster,
                    kubeconfig=discovery_kubeconfig,
                    args=args,
                    backup_parent=backup_parent,
                    include_secrets_backup=include_secrets_backup,
                ),
                action,
            )
            continue

        action = resolve_ai_action(raw)
        if not action:
            if not last_report_payload:
                artifact_path = latest_agentfence_artifact(namespace)
                if artifact_path:
                    last_report_payload = load_json_file(artifact_path)
                    last_artifact_path = artifact_path if last_report_payload else last_artifact_path
            if last_report_payload:
                print("\nAgentFence AI is analyzing the latest report...")
                answer = ask_ai_backend(raw, last_report_payload, ai_history)
                print(answer)
                ai_history.append({"role": "user", "content": raw})
                ai_history.append({"role": "assistant", "content": answer})
            else:
                print("Run Analyze, Remediation, Analyze&Remediation, Backup, or Restore first; then ask a question about the results.")
            continue
        if not cluster_ready:
            print("Cluster access is required before running an action. Use `list clusters` to retry discovery or `use cluster <name-or-number>` if contexts appear.")
            continue
        if not namespace:
            namespace = prompt_namespace_choice(discovery_kubeconfig)
            if not namespace:
                print("Cancelled. Returning to main prompt.")
                continue
        remember_run(
            run_ai_selected_action(
                action=action,
                namespace=namespace,
                cluster=cluster,
                kubeconfig=discovery_kubeconfig,
                args=args,
                backup_parent=backup_parent,
                include_secrets_backup=include_secrets_backup,
            ),
            action,
        )


def self_test_sample_results(unsafe: int = 2) -> List[TestResult]:
    rows = []
    for idx, probe in enumerate(CATALOG):
        status: Status = "pass" if idx < unsafe else "fail"
        rows.append(TestResult(id=probe.id, severity=probe.severity, status=status))
    return rows


def run_self_test() -> int:
    checks: List[str] = []

    ids = [p.id for p in CATALOG]
    assert len(ids) == 39
    assert len(set(ids)) == 39
    assert set(ids) == set(PROBE_RUNNERS.keys())
    assert set(REMEDIATION_RECIPES.keys()) == set(ids)
    checks.append("catalog, runner, and remediation coverage")

    mixed = [
        TestResult(id="AgentFence.REMOTE.UNAUTH_SERVICE_REACHABLE", severity="high", status="pass"),
        TestResult(id="AgentFence.ID.RUN_AS_UID_ZERO", severity="high", status="pass"),
    ]
    metrics = summarize_results(mixed)
    assert metrics.issue_count == 1
    assert metrics.score_raw == 3.0
    assert math.isclose(metrics.score_raw, metrics.tbe_score_raw + metrics.ele_score_raw)
    assert math.isclose(catalog_max_tbe() + catalog_max_ele(), catalog_max())
    legacy_metrics = summarize_results(
        [
            TestResult(id=LEGACY_PROBE_PREFIX + "REMOTE.UNAUTH_SERVICE_REACHABLE", severity="high", status="pass"),
            TestResult(id=LEGACY_PROBE_PREFIX + "ID.RUN_AS_UID_ZERO", severity="high", status="pass"),
        ]
    )
    assert legacy_metrics.issue_count == metrics.issue_count
    assert legacy_metrics.score_raw == metrics.score_raw
    checks.append("disjoint TBE/ELE scoring and review-only alias handling")

    results = self_test_sample_results(unsafe=3)
    plan = build_remediation_plan(results, {"namespace": "ns", "target_pod": "pod"})
    assert plan["coverage"]["complete"] is True
    assert plan["actionable_count"] == 3
    assert all(i.get("recommendation") for i in plan["items"])
    checks.append("39-probe remediation plan coverage")

    evaluation = build_f1_f5_evaluation(
        action="remediation",
        namespace="ns",
        context={"namespace": "ns", "target_pod": "pod", "target_container": "c"},
        artifacts={"main_json": "/tmp/agentfence-self-test.json"},
        metrics_before=summarize_results(self_test_sample_results(unsafe=3)),
        results_before=self_test_sample_results(unsafe=3),
        metrics_after=summarize_results(self_test_sample_results(unsafe=1)),
        results_after=self_test_sample_results(unsafe=1),
        remediation_plan=plan,
        health={"status": "healthy"},
    )
    assert evaluation["schema"] == "agentfence-f1-f5-v2"
    assert evaluation["F3_remediation_effectiveness"]["status"] == "improved"
    checks.append("F1-F5 evaluation")

    dry_ctx = RunContext(
        namespace="dryrun",
        kubeconfig="",
        target_pod="dry-run-target",
        target_container="dry-run-container",
        attacker_pod="dry-run-attacker",
        attacker_container="dry-run-container",
        target_ip="0.0.0.0",
        dry_run=True,
    )
    dry_checkpoint = build_restore_checkpoint(dry_ctx, "remediation", plan)
    assert dry_checkpoint["status"] == "dry_run_not_created"
    assert dry_checkpoint["mutation_gate"]["status"] == "open"
    checks.append("dry-run enforced backup gate")

    original_run = run_kubectl
    original_get_json = kubectl_get_json

    pod_json = {
        "metadata": {
            "name": "target-pod",
            "uid": "pod-uid-1",
            "labels": {"app": "target", "role": "target"},
            "ownerReferences": [{"kind": "Deployment", "name": "target"}],
        },
        "spec": {
            "serviceAccountName": "default",
            "nodeName": "node-a",
            "runtimeClassName": "gvisor",
            "nodeSelector": {"runtime": "gvisor"},
            "containers": [{"name": "app"}],
        },
        "status": {
            "phase": "Running",
            "podIP": "10.0.0.5",
            "containerStatuses": [{"name": "app", "ready": True}],
        },
    }
    deployment_json = {
        "metadata": {"name": "target"},
        "spec": {
            "selector": {"matchLabels": {"app": "target", "role": "target"}},
            "template": {
                "metadata": {"labels": {"app": "target", "role": "target"}},
                "spec": {
                    "containers": [{"name": "app"}],
                }
            }
        },
    }

    def fake_run_kubectl(kubeconfig: str, args: List[str], timeout: int = 60) -> Tuple[int, str, str]:
        if args[:1] == ["api-resources"] and "--namespaced=true" in args:
            return 0, "deployments.apps\nservices\nconfigmaps\nsecrets\npersistentvolumeclaims\n", ""
        if args[:1] == ["api-resources"]:
            return 0, "volumesnapshots.snapshot.storage.k8s.io\n", ""
        if args[:3] == ["apply", "--dry-run=server", "-f"]:
            return 0, "ok", ""
        if args[:1] == ["patch"]:
            return 0, "deployment.apps/target unchanged", ""
        if args[:2] == ["get", "namespace"]:
            return 0, "apiVersion: v1\nkind: Namespace\nmetadata:\n  name: ns\n", ""
        if args[:2] == ["get", "pod"]:
            return 0, "apiVersion: v1\nkind: Pod\nmetadata:\n  name: target-pod\n", ""
        if args[:2] == ["get", "deployment"]:
            return 0, "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: target\n", ""
        return 0, "apiVersion: v1\nkind: List\nitems: []\n", ""

    def fake_get_json(kubeconfig: str, args: List[str]) -> Optional[Any]:
        if args[:2] == ["get", "pod"]:
            return pod_json
        if args[:2] == ["get", "deployment"]:
            return deployment_json
        if args[:2] == ["get", "pods"]:
            return {"items": [pod_json]}
        if "persistentvolumeclaims" in args:
            return {"items": []}
        if "rolebindings.rbac.authorization.k8s.io" in args:
            return {"items": []}
        if "clusterrolebindings.rbac.authorization.k8s.io" in args:
            return {"items": []}
        return {"items": []}

    globals()["run_kubectl"] = fake_run_kubectl
    globals()["kubectl_get_json"] = fake_get_json
    try:
        with tempfile.TemporaryDirectory() as td:
            ctx = RunContext(
                namespace="ns",
                kubeconfig="",
                target_pod="target-pod",
                target_container="app",
                attacker_pod="attacker",
                attacker_container="app",
                target_ip="10.0.0.5",
            )
            checkpoint = build_restore_checkpoint(ctx, "remediation", plan, base_dir=td)
            assert checkpoint["schema"] == COMPREHENSIVE_BACKUP_SCHEMA
            assert checkpoint["status"] == "verified"
            assert checkpoint["mutation_gate"]["status"] == "open"
            assert checkpoint["restore_order"]
            assert os.path.exists(checkpoint["restore_script"])
            apply_summary = apply_remediation_actions(ctx, plan, checkpoint)
            assert apply_summary["status"] == "applied"
            assert apply_summary["applied_count"] >= 1
        checks.append("comprehensive checkpoint capture")
        checks.append("automatic remediation apply path")
    finally:
        globals()["run_kubectl"] = original_run
        globals()["kubectl_get_json"] = original_get_json

    print(json.dumps({"status": "passed", "checks": checks}, indent=2))
    return 0


def main() -> int:
    global ACTIVE_KUBE_CONTEXT
    default_gen = os.path.join(os.path.dirname(os.path.abspath(__file__)), "generated_outputs")
    ap = argparse.ArgumentParser(description="AgentFence — 39 unified probes, one scorer")
    ap.add_argument("--app-mode", choices=["default", "ai"], default="default")
    ap.add_argument("--cluster", help="Kubernetes context to use for this run only; AgentFence never saves it to kubeconfig")
    ap.add_argument("--namespace", "-n", required=False)
    ap.add_argument(
        "--kubeconfig",
        default=os.environ.get("KUBECONFIG", "").split(os.pathsep)[0] if os.environ.get("KUBECONFIG") else "",
        help="kubeconfig path (or set KUBECONFIG)",
    )
    ap.add_argument(
        "--action",
        choices=[
            "analyze",
            "remediation",
            "analyze-remediation",
            "backup-namespace",
            "restore-namespace",
            "self-test",
        ],
        default=None,
    )
    ap.add_argument("--target-pod", help="Override auto-selected target pod")
    ap.add_argument("--timeout", type=int, default=25, help="per-probe kubectl exec timeout")
    ap.add_argument("--out", help="JSON output path")
    ap.add_argument("--md-out", help="Markdown output path")
    ap.add_argument("--dry-run", action="store_true", help="Skip probes; validate catalog and target selection")
    ap.add_argument(
        "--headline-alpha",
        type=float,
        default=DEFAULT_HEADLINE_ALPHA,
        help=f"Headline = α·TBE_norm + (1−α)·ELE_norm (default {DEFAULT_HEADLINE_ALPHA}); layers are disjoint",
    )
    ap.add_argument(
        "--bundle-dir",
        help="Rollback bundle directory (contains backup_manifest.json); used with restore-namespace",
    )
    ap.add_argument(
        "--backup-parent-dir",
        default=None,
        help="Directory under which rollback_bundle_* folders are created (default: generated_outputs beside this script)",
    )
    ap.add_argument(
        "--create-backup",
        action="store_true",
        help="Snapshot namespace into a rollback bundle before reports (on by default for remediation and analyze-remediation; use with analyze to opt in)",
    )
    ap.add_argument(
        "--no-backup",
        action="store_true",
        help="Analyze-only compatibility flag; rejected for remediation and analyze-remediation",
    )
    ap.add_argument(
        "--include-secrets-backup",
        action="store_true",
        help="Compatibility flag; comprehensive checkpoints include Secret objects unless --omit-secrets-backup is used",
    )
    ap.add_argument(
        "--omit-secrets-backup",
        action="store_true",
        help="Omit Secret objects from the restore checkpoint (less comprehensive, less sensitive)",
    )
    ap.add_argument(
        "--velero-backup",
        action="store_true",
        help="If velero is on PATH, also run velero backup create for the namespace",
    )
    ap.add_argument(
        "--allow-node-runtime-remediation",
        action="store_true",
        help=(
            "Allow operator-approved node/runtime changes when required for verification, "
            "currently Kata guest seccomp on the target node. This can affect other Kata "
            "workloads on that node/runtime handler."
        ),
    )
    args = ap.parse_args()

    kc = args.kubeconfig or os.path.expanduser("~/.kube/config")
    ACTIVE_KUBE_CONTEXT = args.cluster or None
    backup_parent = args.backup_parent_dir or default_gen
    include_secrets_backup = not args.omit_secrets_backup

    if args.app_mode == "ai" and sys.stdin.isatty() and args.action is None:
        return run_ai_interactive_cli(args, kc, backup_parent, include_secrets_backup)

    if args.action is None:
        args.action = "analyze"

    if args.action == "self-test":
        return run_self_test()

    if args.action == "backup-namespace":
        if not args.namespace:
            print("Error: --namespace is required for backup-namespace", file=sys.stderr)
            return 2
        os.makedirs(backup_parent, exist_ok=True)
        info = create_comprehensive_namespace_backup_bundle(
            kc,
            args.namespace,
            backup_parent,
            include_secrets=include_secrets_backup,
            run_velero=args.velero_backup,
        )
        print(json.dumps(info, indent=2))
        return 2 if info.get("status") == "failed" else 0

    if args.action == "restore-namespace":
        if not args.bundle_dir:
            print("Error: --bundle-dir is required for restore-namespace", file=sys.stderr)
            return 2
        bd = os.path.abspath(args.bundle_dir)
        res = restore_namespace_bundle(kc, bd, dry_run=args.dry_run)
        print(json.dumps(res, indent=2))
        if res.get("status") == "failed":
            return 2
        if res.get("status") == "partial":
            print("Warning: restore completed with some failures", file=sys.stderr)
            return 1
        return 0

    if not args.namespace:
        if args.app_mode == "ai" and sys.stdin.isatty():
            args.namespace = input("Namespace: ").strip()
        if not args.namespace:
            print("Error: --namespace is required (or provide when prompted in ai mode)", file=sys.stderr)
            return 2

    if args.app_mode == "ai" and sys.stdin.isatty() and "--action" not in sys.argv:
        raw_action = input(
            "Action [analyze | remediation | analyze-remediation] (default: analyze): "
        ).strip()
        norm = re.sub(r"[^a-z]+", "", raw_action.lower())
        if norm in ("analyzeremediation", "analyzeandremediation", "ar"):
            args.action = "analyze-remediation"
        elif norm in ("remediation", "r"):
            args.action = "remediation"
        elif raw_action and norm not in ("analyze", "a", ""):
            print(f"Warning: unrecognized action {raw_action!r}; using analyze", file=sys.stderr)

    enforced_pre_run_actions = frozenset({"remediation", "analyze-remediation"})
    pre_run_ctx: Optional[RunContext] = None
    pre_run_backup_checkpoint: Optional[Dict[str, Any]] = None
    if args.no_backup and args.action in enforced_pre_run_actions:
        print(
            "Error: --no-backup is not allowed for remediation or analyze-remediation. "
            "A restore checkpoint must be created before those actions run.",
            file=sys.stderr,
        )
        return 2

    if args.action in enforced_pre_run_actions:
        try:
            pre_run_ctx = build_context(
                args.namespace,
                kc,
                args.target_pod,
                args.dry_run,
                args.timeout,
                allow_node_runtime_remediation=args.allow_node_runtime_remediation,
            )
        except RuntimeError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 2
        pre_run_backup_checkpoint = build_restore_checkpoint(
            pre_run_ctx,
            args.action,
            remediation_plan=None,
            base_dir=backup_parent,
            include_secrets=include_secrets_backup,
            run_velero=args.velero_backup,
        )
        backup_status = pre_run_backup_checkpoint.get("status")
        allowed = {"verified", "verified_with_warnings", "dry_run_not_created"}
        if backup_status not in allowed:
            print(
                "Error: enforced pre-run restore checkpoint failed. "
                f"status={backup_status!r} bundle={pre_run_backup_checkpoint.get('bundle_dir')!r}. "
                "Remediation and analyze-remediation will not run until the checkpoint is restorable.",
                file=sys.stderr,
            )
            return 2
        print(
            f"Selected target: {pre_run_ctx.target_pod} (container={pre_run_ctx.target_container!r}) "
            f"attacker={pre_run_ctx.attacker_pod} target_ip={pre_run_ctx.target_ip}",
            file=sys.stderr,
        )

    if args.action == "analyze":
        try:
            results, metrics, ctx = analyze_pipeline(
                args.namespace,
                kc,
                args.target_pod,
                args.dry_run,
            args.timeout,
            args.headline_alpha,
            allow_node_runtime_remediation=args.allow_node_runtime_remediation,
        )
        except RuntimeError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 2
        print(
            f"Selected target: {ctx.target_pod} (container={ctx.target_container!r}) "
            f"attacker={ctx.attacker_pod} target_ip={ctx.target_ip}",
            file=sys.stderr,
        )
        print(
            f"Scores: headline={metrics.score_normalized} "
            f"(TBE_norm={metrics.tbe_score_normalized}, "
            f"ELE_norm={metrics.ele_score_normalized}, α={metrics.headline_alpha})",
            file=sys.stderr,
        )
        context = context_from_ctx(ctx)
        remediation_plan = build_remediation_plan(results, context)
        payload = {
            "agentfence": True,
            "catalog_version": CATALOG_VERSION,
            "action": "analyze",
            "namespace": args.namespace,
            "target_pod": ctx.target_pod,
            "context": context,
            "metrics": metrics.__dict__,
            "results": [r.__dict__ for r in results],
            "remediation": remediation_plan,
        }
        narr_m, narr_r = metrics, results
        report_results = results
        report_metrics = metrics
        report_remediation = remediation_plan
        report_remediation_apply = None
        report_results_after = None
        report_metrics_after = None
        eval_kwargs = {
            "metrics": metrics,
            "results": results,
            "remediation_plan": remediation_plan,
        }
    elif args.action == "remediation":
        payload = remediation_pipeline(
            args.namespace,
            kc,
            args.target_pod,
            args.dry_run,
            args.timeout,
            args.headline_alpha,
            backup_parent,
            include_secrets_backup,
            args.velero_backup,
            False,
            pre_run_backup_checkpoint,
            pre_run_ctx,
            args.allow_node_runtime_remediation,
        )
        payload["agentfence"] = True
        payload["catalog_version"] = CATALOG_VERSION
        mb = payload["metrics_before"]
        m_narr = score_bundle_from_dict(mb)
        r_narr = [result_from_dict(d) for d in payload.get("results_before", [])]
        narr_m, narr_r = m_narr, r_narr
        context = payload.get("context") or (
            context_from_ctx(pre_run_ctx) if pre_run_ctx else {}
        )
        report_results = r_narr
        report_metrics = m_narr
        report_remediation = payload.get("remediation")
        report_remediation_apply = payload.get("remediation_apply")
        report_results_after = [result_from_dict(d) for d in payload.get("results_after", [])]
        report_metrics_after = score_bundle_from_dict(payload.get("metrics_after", {})) if payload.get("metrics_after") else None
        eval_kwargs = {
            "metrics_before": payload.get("metrics_before"),
            "results_before": payload.get("results_before"),
            "metrics_after": payload.get("metrics_after"),
            "results_after": payload.get("results_after"),
            "remediation_plan": report_remediation,
            "backup_checkpoint": payload.get("backup_checkpoint"),
            "health": payload.get("remediation_apply") or {},
        }
    else:
        payload = analyze_remediation_pipeline(
            args.namespace,
            kc,
            args.target_pod,
            args.dry_run,
            args.timeout,
            args.headline_alpha,
            backup_parent,
            include_secrets_backup,
            args.velero_backup,
            False,
            pre_run_backup_checkpoint,
            pre_run_ctx,
            args.allow_node_runtime_remediation,
        )
        payload["agentfence"] = True
        payload["catalog_version"] = CATALOG_VERSION
        mb = payload["metrics_before"]
        m_narr = score_bundle_from_dict(mb)
        r_narr = [result_from_dict(d) for d in payload.get("results_before", [])]
        narr_m, narr_r = m_narr, r_narr
        context = payload.get("context") or (
            context_from_ctx(pre_run_ctx) if pre_run_ctx else {}
        )
        report_results = r_narr
        report_metrics = m_narr
        report_remediation = payload.get("remediation")
        report_remediation_apply = payload.get("remediation_apply")
        report_results_after = [result_from_dict(d) for d in payload.get("results_after", [])]
        report_metrics_after = score_bundle_from_dict(payload.get("metrics_after", {})) if payload.get("metrics_after") else None
        eval_kwargs = {
            "metrics_before": payload.get("metrics_before"),
            "results_before": payload.get("results_before"),
            "metrics_after": payload.get("metrics_after"),
            "results_after": payload.get("results_after"),
            "remediation_plan": report_remediation,
            "backup_checkpoint": payload.get("backup_checkpoint"),
            "health": payload.get("remediation_apply") or {},
        }

    ts = now_stamp()
    out_path = args.out or os.path.join(
        os.path.dirname(__file__),
        "generated_outputs",
        f"agentfence_{args.action}_{args.namespace}_{ts}.json",
    )
    md_path = args.md_out or os.path.join(
        os.path.dirname(__file__),
        "generated_outputs",
        f"agentfence_{args.action}_{args.namespace}_{ts}.md",
    )
    if args.out:
        eval_json_path = os.path.splitext(out_path)[0] + "_f1_f5.json"
    else:
        eval_json_path = os.path.join(
            os.path.dirname(__file__),
            "generated_outputs",
            f"agentfence_f1_f5_{args.action}_{args.namespace}_{ts}.json",
        )
    if args.md_out:
        eval_md_path = os.path.splitext(md_path)[0] + "_f1_f5.md"
    else:
        eval_md_path = os.path.join(
            os.path.dirname(__file__),
            "generated_outputs",
            f"agentfence_f1_f5_{args.action}_{args.namespace}_{ts}.md",
        )

    artifacts = {
        "main_json": out_path,
        "main_markdown": md_path,
        "f1_f5_json": eval_json_path,
        "f1_f5_markdown": eval_md_path,
    }
    backup_checkpoint = eval_kwargs.get("backup_checkpoint")
    if isinstance(backup_checkpoint, dict) and backup_checkpoint.get("bundle_dir"):
        artifacts["rollback_bundle"] = backup_checkpoint["bundle_dir"]

    if args.action == "analyze" and args.create_backup and not args.no_backup:
        os.makedirs(backup_parent, exist_ok=True)
        backup_checkpoint = build_restore_checkpoint(
            ctx,
            args.action,
            report_remediation,
            base_dir=backup_parent,
            include_secrets=include_secrets_backup,
            run_velero=args.velero_backup,
        )
        eval_kwargs["backup_checkpoint"] = backup_checkpoint
        payload["backup_checkpoint"] = backup_checkpoint
        if backup_checkpoint.get("bundle_dir"):
            artifacts["rollback_bundle"] = backup_checkpoint["bundle_dir"]

    if artifacts.get("rollback_bundle"):
        gate = (
            " (enforced pre-run checkpoint, before probes)"
            if pre_run_backup_checkpoint
            and artifacts["rollback_bundle"] == pre_run_backup_checkpoint.get("bundle_dir")
            else ""
        )
        print(f"Rollback bundle{gate}: {artifacts['rollback_bundle']}", file=sys.stderr)

    narr = maybe_ai_narrate(
        narr_m,
        narr_r,
        args.app_mode,
        backup_bundle_path=artifacts.get("rollback_bundle"),
        backup_status=(backup_checkpoint or {}).get("status")
        if isinstance(backup_checkpoint, dict)
        else None,
        action=args.action,
    )
    if narr:
        print(narr)

    evaluation = build_f1_f5_evaluation(
        action=args.action,
        namespace=args.namespace,
        context=context,
        artifacts=artifacts,
        **eval_kwargs,
    )
    payload["evaluation"] = evaluation
    payload["enriched_report"] = build_enriched_report(
        action=args.action,
        context=context,
        metrics_before=report_metrics,
        results_before=report_results,
        remediation_plan=report_remediation,
        remediation_apply=report_remediation_apply,
        metrics_after=report_metrics_after,
        results_after=report_results_after,
        evaluation=evaluation,
    )
    write_json(out_path, payload)
    write_json(eval_json_path, evaluation)
    write_f1_f5_md(eval_md_path, evaluation)
    write_md(
        md_path,
        f"AgentFence {args.action} {args.namespace}",
        report_results,
        report_metrics,
        remediation_plan=report_remediation,
        remediation_apply=report_remediation_apply,
        evaluation=evaluation,
        action=args.action,
        context=context,
        results_after=report_results_after,
        metrics_after=report_metrics_after,
    )

    reconcile_evaluation_artifact_paths(evaluation)
    payload["evaluation"] = evaluation
    payload["enriched_report"] = build_enriched_report(
        action=args.action,
        context=context,
        metrics_before=report_metrics,
        results_before=report_results,
        remediation_plan=report_remediation,
        remediation_apply=report_remediation_apply,
        metrics_after=report_metrics_after,
        results_after=report_results_after,
        evaluation=evaluation,
    )
    write_json(out_path, payload)
    write_json(eval_json_path, evaluation)
    write_f1_f5_md(eval_md_path, evaluation)
    write_md(
        md_path,
        f"AgentFence {args.action} {args.namespace}",
        report_results,
        report_metrics,
        remediation_plan=report_remediation,
        remediation_apply=report_remediation_apply,
        evaluation=evaluation,
        action=args.action,
        context=context,
        results_after=report_results_after,
        metrics_after=report_metrics_after,
    )

    print(json.dumps({"out": out_path, "md": md_path, "f1_f5_json": eval_json_path, "f1_f5_md": eval_md_path}, indent=2))
    return 0


# Boot-time catalog integrity
_ids = [p.id for p in CATALOG]
assert len(_ids) == 39, len(_ids)
assert len(set(_ids)) == 39, "duplicate probe id"
assert set(_ids) == set(PROBE_RUNNERS.keys()), set(_ids) ^ set(PROBE_RUNNERS.keys())
assert abs(catalog_max() - 74.0) < 0.001, catalog_max()
assert TBE_PROBE_IDS <= frozenset(p.id for p in CATALOG)
assert len(TBE_PROBE_IDS) == 3
assert abs(catalog_max_tbe() - 7.0) < 0.001, catalog_max_tbe()
assert abs(catalog_max_ele() - 67.0) < 0.001, catalog_max_ele()
assert math.isclose(catalog_max_tbe() + catalog_max_ele(), catalog_max())
assert set(REMEDIATION_RECIPES.keys()) == set(_ids), set(_ids) ^ set(REMEDIATION_RECIPES.keys())
assert all(r.action_type in ("auto_fix", "hybrid", "manual_recommendation") for r in REMEDIATION_RECIPES.values())
assert all(r.title and r.risk and r.recommendation and r.validation for r in REMEDIATION_RECIPES.values())
assert all(r.operator_steps for r in REMEDIATION_RECIPES.values())
assert all(r.dry_run_artifact for r in REMEDIATION_RECIPES.values() if r.action_type in ("auto_fix", "hybrid"))

if __name__ == "__main__":
    raise SystemExit(main())
