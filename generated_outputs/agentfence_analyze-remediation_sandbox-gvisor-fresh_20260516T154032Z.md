# AgentFence analyze-remediation sandbox-gvisor-fresh

## Context

- namespace: `sandbox-gvisor-fresh`
- target_pod: `target-gvisor-8d9db5f9-qd68b`
- target_container: `app`
- attacker_pod: `attacker-gvisor-6f4564bf9b-64nb4`

## Executive Summary

- catalog_version: 1.3.0
- probes covered: **39 / 39**
- scored unsafe findings shown here: **8**
- review-only communication findings: **1**
- auto-fixable or guarded-auto unsafe findings: **0**
- manual/remains-manual unsafe findings: **8**
- headline_alpha: **0.6**
- **TBE**: issues=1, raw=1.0, norm/10=1.4286
- **ELE**: issues=7, raw=12.0, norm/10=1.791
- **Total unsafe**: issues=8, raw=13.0
- **Headline** (/10): **1.5736**
- skipped probes: 0

## Before/After Comparison

- issues: 10 -> 8 (-2)
- raw score: 15.0 -> 13.0 (-2.0)
- headline: 1.693 -> 1.5736 (-0.1194)
- score basis: review-only communication reachability findings are excluded from issue counts and scores
- fixed probes: AgentFence.IDENTITY.CAP_BOUNDING_PERMISSIVE, AgentFence.IDENTITY.SECCOMP_BYPASS_OK
- verified fixed probes: AgentFence.IDENTITY.CAP_BOUNDING_PERMISSIVE, AgentFence.IDENTITY.SECCOMP_BYPASS_OK
- new unsafe probes: none

## F1-F5 Summary

- **F1_runtime_placement**: captured
- **F2_attack_path_containment**: captured
- **F3_remediation_effectiveness**: improved headline 1.693 -> 1.5736
- **F4_artifact_consistency**: captured
- **F5_recoverability**: restore_checkpoint_ready restore_ready=True

## Remediation Results

- status: applied
- applied records: 4
- failed/rolled-back records: 0
- manual recommendations: 9
- `node_sysctl_hardening` node_sysctl_hardening: not_applicable verification=n/a resolved=none
- `workload_hardening_patch` target-gvisor: applied verification=verified resolved=AgentFence.IDENTITY.SECCOMP_BYPASS_OK
  - workload revalidation: healthy pod_recreated=True running_pods=1
  - captured TCP egress checks: 1/1 reachable
  - pre-auto-fix workload snapshot: `Deployment/target-gvisor` containers=app runtime=gvisor
  - runtime seccomp: family=gvisor handler=runsc pod_profile=RuntimeDefault process_active=False runtime_config_required=False
  - runtime recommendation: gVisor accepted the workload seccomp profile. AgentFence treats the runsc RuntimeClass plus workload RuntimeDefault profile as the runtime-specific seccomp success condition because gVisor syscall mediation does not require the sandboxed process to show Linux Seccomp:2.
- `workload_hardening_patch` target-gvisor: applied verification=verified resolved=AgentFence.IDENTITY.CAP_BOUNDING_PERMISSIVE
  - workload revalidation: healthy pod_recreated=True running_pods=1
  - captured TCP egress checks: 1/1 reachable
  - pre-auto-fix workload snapshot: `Deployment/target-gvisor` containers=app runtime=gvisor
- `workload_hardening_patch` target-gvisor: applied verification=no_change_unresolved resolved=none
  - workload revalidation: healthy pod_recreated=True running_pods=1
  - captured TCP egress checks: 1/1 reachable
  - pre-auto-fix workload snapshot: `Deployment/target-gvisor` containers=app runtime=gvisor
- `workload_hardening_patch` target-gvisor: applied verification=no_change_unresolved resolved=none
  - workload revalidation: healthy pod_recreated=True running_pods=1
  - captured TCP egress checks: 1/1 reachable
  - pre-auto-fix workload snapshot: `Deployment/target-gvisor` containers=app runtime=gvisor
- `manual_recommendation` AgentFence.REMOTE.UNAUTH_SERVICE_REACHABLE: manual_recommendation verification=n/a resolved=none
- `manual_recommendation` AgentFence.KERNEL.PERF_EVENT_OPEN_REACHABLE: manual_recommendation verification=n/a resolved=none
- `manual_recommendation` AgentFence.KERNEL.DMESG_VISIBLE: manual_recommendation verification=n/a resolved=none
- `manual_recommendation` AgentFence.FS.HOST_SYS_VISIBLE: manual_recommendation verification=n/a resolved=none
- `manual_recommendation` AgentFence.FS.HOST_FS_REACHABLE_VIA_PROC: manual_recommendation verification=n/a resolved=none
- `manual_recommendation` AgentFence.DEVICE.TUN_TAP_PRESENT: manual_recommendation verification=n/a resolved=none
- `manual_recommendation` AgentFence.NS.USER_NS_ROOT_MAPS_HOST_ROOT: manual_recommendation verification=n/a resolved=none
- `manual_recommendation` AgentFence.SIDE.HOST_DMI_LEAKED: manual_recommendation verification=n/a resolved=none
- `manual_recommendation` AgentFence.SIDE.HIGH_RES_TIMER_AVAILABLE: manual_recommendation verification=n/a resolved=none

## Review-Only Communication Exposure

### `AgentFence.REMOTE.UNAUTH_SERVICE_REACHABLE` — Review sibling-pod service reachability

- layer: Review | severity: high | status: pass (review-only communication exposure observed; score unaffected)
- score impact: none | automatic remediation: none
- issue: A sibling pod can reach target listeners. This is review-only because the port may be required application ingress; AgentFence needs declared communication intent before scoring it as a policy violation.
- evidence: `open=[8000] detail=HTTPBYTES:8000:0`
- manual fix: Inventory required callers, ports, and authentication gates. If sibling pods are not approved callers, replace broad same-namespace allow rules with target-specific allowlists.
- validation: Re-run remote reachability after defining allowed callers and confirm only approved paths respond.
- operator steps:
  - Inventory required listeners and peer workloads.
  - Document allowed ingress sources, ports, and authentication gates.
  - Apply an allowlist NetworkPolicy only after confirming workload intent.


## Auto-Fixed Issues

### `AgentFence.IDENTITY.SECCOMP_BYPASS_OK` — Enforce a restrictive seccomp profile

- layer: ELE | severity: medium | fix_class: auto_fix | fix_group: pod_security_context_patch
- issue: A weak or ineffective seccomp profile leaves risky syscall surface available to the workload.
- auto fix applied/verified: True
- validation: Re-run AgentFence.IDENTITY.SECCOMP_BYPASS_OK and confirm blocked syscall behavior or runtime-specific mediation evidence.

### `AgentFence.IDENTITY.CAP_BOUNDING_PERMISSIVE` — Minimize Linux capability bounding set

- layer: ELE | severity: medium | fix_class: auto_fix | fix_group: capabilities_drop_patch
- issue: Dangerous capabilities increase kernel, filesystem, and network attack surface after compromise.
- auto fix applied/verified: True
- validation: Re-run AgentFence.IDENTITY.CAP_BOUNDING_PERMISSIVE and confirm dangerous caps are absent.


## Unsafe Findings Requiring Attention

### `AgentFence.KERNEL.PERF_EVENT_OPEN_REACHABLE` — Tighten perf_event_open exposure

- layer: ELE | severity: high | status: pass (unsafe condition observed)
- fix_class: manual | fix_group: manual | auto_fix_available: False
- issue: The workload can reach performance-monitoring syscall surface. That can leak host information and side-channel signals, and on weak kernels it may assist exploitation.
- evidence: `UNSAFE errno 19`
- automatic remediation path: Generate node sysctl/runtime guidance for perf restrictions.
- manual fix: Restrict perf_event_open with node/runtime policy, review kernel.perf_event_paranoid, and keep explicit observability exceptions only for workloads that require them.
- validation: Re-run AgentFence.KERNEL.PERF_EVENT_OPEN_REACHABLE and confirm EPERM, EACCES, or ENOSYS.
- operator steps:
  - Review kernel.perf_event_paranoid on nodes.
  - Use runtime policies that block perf_event_open.
  - Validate observability tools still work.

### `AgentFence.KERNEL.DMESG_VISIBLE` — Restrict kernel log visibility

- layer: ELE | severity: high | status: pass (unsafe condition observed)
- fix_class: hybrid_manual | fix_group: kernel_surface_hardening_patch | auto_fix_available: False
- issue: Kernel log output can reveal runtime, host, driver, and exploit-relevant details to the workload.
- evidence: `[    0.000000] Starting gVisor... [    0.148797] Asking an AI agent to fix the bugs...`
- automatic remediation path: Generate capability/seccomp hardening and manual node dmesg_restrict guidance.
- manual fix: Enable node dmesg restrictions, remove unnecessary privileged/capability grants, and prefer a runtime profile that blocks kernel log access for untrusted workloads.
- validation: Re-run AgentFence.KERNEL.DMESG_VISIBLE and confirm permission denial or empty output.
- operator steps:
  - Drop SYSLOG/SYS_ADMIN-like access.
  - Enable RuntimeDefault seccomp.
  - Set node kernel.dmesg_restrict where appropriate.

### `AgentFence.FS.HOST_SYS_VISIBLE` — Limit sysfs exposure from the container

- layer: TBE | severity: medium | status: pass (unsafe condition observed)
- fix_class: hybrid_manual | fix_group: hostpath_review_patch | auto_fix_available: False
- issue: Visible host sysfs paths expose hardware, platform, and kernel interface details that help fingerprint the node.
- evidence: `product_name`
- automatic remediation path: Generate hostPath/sysfs removal or read-only restriction guidance.
- manual fix: Remove broad sysfs/hostPath mounts, avoid privileged mode, and use stronger sandbox or VM isolation where sysfs masking is required.
- validation: Re-run AgentFence.FS.HOST_SYS_VISIBLE and confirm sensitive sysfs paths are hidden.
- operator steps:
  - Remove /sys hostPath mounts.
  - Use read-only narrow mounts only when required.
  - Review device plugin needs.

### `AgentFence.FS.HOST_FS_REACHABLE_VIA_PROC` — Block proc-based host filesystem reachability

- layer: ELE | severity: medium | status: pass (unsafe condition observed)
- fix_class: hybrid_manual | fix_group: namespace_isolation_patch | auto_fix_available: False
- issue: The workload can traverse host-like filesystem paths through proc. That weakens filesystem isolation and may expose sensitive node files.
- evidence: `/proc/1/root/etc/hostname`
- automatic remediation path: Generate hostPID false, hostPath removal, and containment validation steps.
- manual fix: Remove dangerous host mounts, avoid shared process namespaces, tighten runtime procfs masking, and re-run the probe after runtimeClass or mount changes.
- validation: Re-run AgentFence.FS.HOST_FS_REACHABLE_VIA_PROC and confirm host files are not reachable.
- operator steps:
  - Set hostPID: false.
  - Remove broad hostPath mounts.
  - Validate /proc/1/root does not expose host paths.

### `AgentFence.DEVICE.TUN_TAP_PRESENT` — Review TUN/TAP device exposure

- layer: ELE | severity: high | status: pass (unsafe condition observed)
- fix_class: hybrid_manual | fix_group: device_access_review_patch | auto_fix_available: False
- issue: TUN/TAP devices can enable packet tunneling and bypass expected pod network controls when exposed unnecessarily.
- evidence: `YES`
- automatic remediation path: Generate /dev/net/tun and NET_ADMIN removal guidance with networking compatibility checks.
- manual fix: Remove /dev/net/tun unless the workload explicitly needs VPN or tunneling behavior; otherwise isolate it with a dedicated profile and network policy.
- validation: Re-run AgentFence.DEVICE.TUN_TAP_PRESENT and confirm the device is absent when not required.
- operator steps:
  - Remove /dev/net/tun unless required.
  - Drop NET_ADMIN.
  - Validate VPN/proxy use cases separately.

### `AgentFence.NS.USER_NS_ROOT_MAPS_HOST_ROOT` — Review user namespace / UID mapping configuration

- layer: ELE | severity: medium | status: pass (unsafe condition observed)
- fix_class: manual | fix_group: manual | auto_fix_available: False
- issue: A root-to-root user namespace mapping weakens UID isolation and can make container-root semantics more sensitive.
- evidence: `0          0 4294967295`
- automatic remediation path: Generate runtime/user namespace remapping guidance and validation commands.
- manual fix: Enable user namespace remapping where supported, align image USER with pod runAsUser/runAsGroup, and document residual mapping risk where remapping is unavailable.
- validation: Re-run AgentFence.NS.USER_NS_ROOT_MAPS_HOST_ROOT and confirm root is not mapped to host root.
- operator steps:
  - Enable user namespace remapping where supported.
  - Review runtime configuration.
  - Prefer non-root workload identity even with remapping.

### `AgentFence.SIDE.HOST_DMI_LEAKED` — Mask host DMI information

- layer: ELE | severity: low | status: pass (unsafe condition observed)
- fix_class: manual | fix_group: manual | auto_fix_available: False
- issue: DMI/SMBIOS values reveal platform details and can help fingerprint the host environment.
- evidence: `Google Compute Engine`
- automatic remediation path: Generate sysfs/DMI masking or runtime isolation guidance.
- manual fix: Remove DMI sysfs exposure, review runtime masking options, and document residual hardware fingerprinting risk where full masking is not feasible.
- validation: Re-run AgentFence.SIDE.HOST_DMI_LEAKED and confirm DMI paths are absent or masked.
- operator steps:
  - Remove DMI sysfs mounts.
  - Review runtime masking options.
  - Prefer sandbox/VM runtime isolation.

### `AgentFence.SIDE.HIGH_RES_TIMER_AVAILABLE` — Assess high-resolution timer exposure

- layer: ELE | severity: low | status: pass (unsafe condition observed)
- fix_class: manual | fix_group: manual | auto_fix_available: False
- issue: High-resolution timers can improve timing side-channel experiments against shared resources.
- evidence: `RES 1`
- automatic remediation path: Generate side-channel mitigation guidance, runtime selection notes, and workload-specific tradeoffs.
- manual fix: Treat this as residual risk on shared kernels, use stronger isolation or dedicated nodes for hostile workloads, and document timer resolution in the threat model.
- validation: Re-run AgentFence.SIDE.HIGH_RES_TIMER_AVAILABLE and record timer resolution.
- operator steps:
  - Assess threat model for timing channels.
  - Prefer stronger runtime isolation for hostile code.
  - Consider scheduling and noise controls where practical.


## Probe Coverage: All 39

| layer | id | title | severity | status | fix_class | evidence (trunc) |
|---|---|---|---|---|---|---|
| ELE | AgentFence.ID.RUN_AS_UID_ZERO | Run workload as non-root | high | fail | auto_fix | 10001 |
| ELE | AgentFence.ID.ROOTFS_WRITE_OK | Mount root filesystem read-only | high | fail | hybrid_manual | FAIL |
| ELE | AgentFence.ID.SA_TOKEN_READABLE | Reduce service account token exposure | high | fail | auto_fix | 0 |
| Review | AgentFence.REMOTE.UNAUTH_SERVICE_REACHABLE | Review sibling-pod service reachability | high | pass | manual_review | open=[8000] detail=HTTPBYTES:8000:0 |
| TBE | AgentFence.HOSTPATH.SENSITIVE_WRITE_OK | Remove writable sensitive hostPath access | high | fail | hybrid_manual |  |
| ELE | AgentFence.KERNEL.KEXEC_REACHABLE | Block kexec kernel-loading surface | high | fail | hybrid_manual | SAFE errno 1 |
| ELE | AgentFence.KERNEL.INIT_MODULE_REACHABLE | Block module loading surface | high | fail | hybrid_manual | SAFE errno 1 |
| ELE | AgentFence.KERNEL.BPF_PROG_LOAD_REACHABLE | Constrain eBPF program loading | high | fail | hybrid_manual | SAFE errno 1 |
| ELE | AgentFence.KERNEL.USERFAULTFD_REACHABLE | Restrict userfaultfd exposure | high | fail | manual | SAFE errno 38 |
| ELE | AgentFence.KERNEL.PERF_EVENT_OPEN_REACHABLE | Tighten perf_event_open exposure | high | pass | manual | UNSAFE errno 19 |
| ELE | AgentFence.KERNEL.KALLSYMS_VISIBLE | Hide kernel symbols | high | fail | manual |  |
| ELE | AgentFence.KERNEL.DMESG_VISIBLE | Restrict kernel log visibility | high | pass | hybrid_manual | [    0.000000] Starting gVisor... [    0.148797] Asking an AI agent to fix the bugs... |
| ELE | AgentFence.FS.HOST_PROC_VISIBLE | Prevent host /proc visibility | medium | fail | hybrid_manual | /usr/local/bin/python3.11 /usr/local/bin/uvicorn src.app:app --host 0.0.0.0 --port 8000 |
| TBE | AgentFence.FS.HOST_SYS_VISIBLE | Limit sysfs exposure from the container | medium | pass | hybrid_manual | product_name |
| ELE | AgentFence.FS.KCORE_READABLE | Block /proc/kcore reads | medium | fail | hybrid_manual | dd: failed to open '/proc/kcore': No such file or directory EXIT:1 |
| ELE | AgentFence.FS.HOST_DEVICES_VISIBLE | Remove visible host block devices | medium | fail | hybrid_manual |  |
| ELE | AgentFence.FS.ROOTFS_HOST_SHARED | Separate container rootfs from host rootfs | medium | fail | manual |  |
| ELE | AgentFence.FS.HOST_FS_REACHABLE_VIA_PROC | Block proc-based host filesystem reachability | medium | pass | hybrid_manual | /proc/1/root/etc/hostname |
| ELE | AgentFence.DEVICE.KVM_PRESENT | Review /dev/kvm exposure | high | fail | hybrid_manual | NO |
| ELE | AgentFence.DEVICE.TUN_TAP_PRESENT | Review TUN/TAP device exposure | high | pass | hybrid_manual | YES |
| ELE | AgentFence.DEVICE.USB_PRESENT | Remove USB device exposure | high | fail | hybrid_manual |  |
| TBE | AgentFence.DEVICE.RAW_SOCKET_USABLE | Drop raw socket capability | high | fail | auto_fix | SAFE |
| ELE | AgentFence.NS.PID_NS_SHARES_HOST | Disable host PID namespace | medium | fail | auto_fix | hostPID=false |
| ELE | AgentFence.NS.USER_NS_ROOT_MAPS_HOST_ROOT | Review user namespace / UID mapping configuration | medium | pass | manual | 0          0 4294967295 |
| ELE | AgentFence.NS.IPC_NS_SHARES_HOST | Disable host IPC namespace | medium | fail | auto_fix | hostIPC=false |
| ELE | AgentFence.NS.NET_NS_SHARES_HOST | Disable host network namespace | medium | fail | auto_fix | hostNetwork=false |
| ELE | AgentFence.NS.UTS_NS_SHARES_HOST | Isolate hostname/UTS context | medium | fail | hybrid_manual | isolated UTS likely |
| ELE | AgentFence.NET.HOST_NETWORK_REACHABLE | Restrict node network reachability | high | fail | hybrid_manual | CLOSED |
| ELE | AgentFence.NET.IMDS_REACHABLE | Block cloud metadata egress | high | fail | auto_fix | CONNECT_FAILED TimeoutError timed out |
| ELE | AgentFence.NET.KUBELET_API_REACHABLE | Block kubelet API reachability | high | fail | hybrid_manual | sh: 1: wget: not found |
| ELE | AgentFence.NET.APISERVER_DIRECT_REACHABLE | Review Kubernetes API reachability | high | fail | hybrid_manual | sh: 1: wget: not found |
| ELE | AgentFence.IDENTITY.SECCOMP_BYPASS_OK | Enforce a restrictive seccomp profile | medium | fail | auto_fix | UNSAFE ret -1 errno 13 GVISOR_RUNTIME_SECCOMP_VERIFIED runtime_family=gvisor runtime_class=gvisor handler=runsc workload |
| ELE | AgentFence.IDENTITY.NO_NEW_PRIVS_BYPASS_OK | Enable no-new-privileges | medium | fail | auto_fix |  |
| ELE | AgentFence.IDENTITY.CAP_BOUNDING_PERMISSIVE | Minimize Linux capability bounding set | medium | fail | auto_fix | CapBnd:	0000000000000000 |
| ELE | AgentFence.IDENTITY.PROCFS_HIDEPID_LAX | Reduce process visibility | medium | fail | manual | 5 |
| ELE | AgentFence.SIDE.HOST_CPUINFO_LEAKED | Reduce CPU information leakage | low | fail | manual | flags		: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx |
| ELE | AgentFence.SIDE.HOST_DMI_LEAKED | Mask host DMI information | low | pass | manual | Google Compute Engine |
| ELE | AgentFence.SIDE.HIGH_RES_TIMER_AVAILABLE | Assess high-resolution timer exposure | low | pass | manual | RES 1 |
| ELE | AgentFence.SIDE.HOST_CACHE_TOPOLOGY_LEAKED | Reduce cache topology leakage | low | fail | manual |  |

## Raw Results

| layer | id | severity | status | matched | evidence (trunc) |
|---|---|---|---|---|---|
| ELE | AgentFence.ID.RUN_AS_UID_ZERO | high | fail | uid!=0 | 10001 |
| ELE | AgentFence.ID.ROOTFS_WRITE_OK | high | fail | rootfs not writable at / | FAIL |
| ELE | AgentFence.ID.SA_TOKEN_READABLE | high | fail | no token | 0 |
| Review | AgentFence.REMOTE.UNAUTH_SERVICE_REACHABLE | high | pass | service responded without auth gate | open=[8000] detail=HTTPBYTES:8000:0 |
| TBE | AgentFence.HOSTPATH.SENSITIVE_WRITE_OK | high | fail | no hostPath mounts |  |
| ELE | AgentFence.KERNEL.KEXEC_REACHABLE | high | fail | blocked | SAFE errno 1 |
| ELE | AgentFence.KERNEL.INIT_MODULE_REACHABLE | high | fail | blocked | SAFE errno 1 |
| ELE | AgentFence.KERNEL.BPF_PROG_LOAD_REACHABLE | high | fail | blocked | SAFE errno 1 |
| ELE | AgentFence.KERNEL.USERFAULTFD_REACHABLE | high | fail | blocked | SAFE errno 38 |
| ELE | AgentFence.KERNEL.PERF_EVENT_OPEN_REACHABLE | high | pass | unsafe syscall outcome | UNSAFE errno 19 |
| ELE | AgentFence.KERNEL.KALLSYMS_VISIBLE | high | fail | hidden or empty |  |
| ELE | AgentFence.KERNEL.DMESG_VISIBLE | high | pass | dmesg output | [    0.000000] Starting gVisor... [    0.148797] Asking an AI agent to fix the bugs... |
| ELE | AgentFence.FS.HOST_PROC_VISIBLE | medium | fail | safe | /usr/local/bin/python3.11 /usr/local/bin/uvicorn src.app:app --host 0.0.0.0 --port 8000 |
| TBE | AgentFence.FS.HOST_SYS_VISIBLE | medium | pass | unsafe condition | product_name |
| ELE | AgentFence.FS.KCORE_READABLE | medium | fail | safe | dd: failed to open '/proc/kcore': No such file or directory EXIT:1 |
| ELE | AgentFence.FS.HOST_DEVICES_VISIBLE | medium | fail | safe |  |
| ELE | AgentFence.FS.ROOTFS_HOST_SHARED | medium | fail | safe |  |
| ELE | AgentFence.FS.HOST_FS_REACHABLE_VIA_PROC | medium | pass | unsafe condition | /proc/1/root/etc/hostname |
| ELE | AgentFence.DEVICE.KVM_PRESENT | high | fail | absent | NO |
| ELE | AgentFence.DEVICE.TUN_TAP_PRESENT | high | pass | exists | YES |
| ELE | AgentFence.DEVICE.USB_PRESENT | high | fail | no usb |  |
| TBE | AgentFence.DEVICE.RAW_SOCKET_USABLE | high | fail | blocked | SAFE |
| ELE | AgentFence.NS.PID_NS_SHARES_HOST | medium | fail | spec | hostPID=false |
| ELE | AgentFence.NS.USER_NS_ROOT_MAPS_HOST_ROOT | medium | pass | 0 0 map | 0          0 4294967295 |
| ELE | AgentFence.NS.IPC_NS_SHARES_HOST | medium | fail |  | hostIPC=false |
| ELE | AgentFence.NS.NET_NS_SHARES_HOST | medium | fail |  | hostNetwork=false |
| ELE | AgentFence.NS.UTS_NS_SHARES_HOST | medium | fail |  | isolated UTS likely |
| ELE | AgentFence.NET.HOST_NETWORK_REACHABLE | high | fail | node ssh not reachable | CLOSED |
| ELE | AgentFence.NET.IMDS_REACHABLE | high | fail | metadata TCP connect failed | CONNECT_FAILED TimeoutError timed out |
| ELE | AgentFence.NET.KUBELET_API_REACHABLE | high | fail | no kubelet API | sh: 1: wget: not found |
| ELE | AgentFence.NET.APISERVER_DIRECT_REACHABLE | high | fail | no version | sh: 1: wget: not found |
| ELE | AgentFence.IDENTITY.SECCOMP_BYPASS_OK | medium | fail | gvisor RuntimeDefault mediation | UNSAFE ret -1 errno 13 GVISOR_RUNTIME_SECCOMP_VERIFIED runtime_family=gvisor runtime_class=gvisor handler=runsc workload |
| ELE | AgentFence.IDENTITY.NO_NEW_PRIVS_BYPASS_OK | medium | fail | nnp on or unknown |  |
| ELE | AgentFence.IDENTITY.CAP_BOUNDING_PERMISSIVE | medium | fail | tight caps | CapBnd:	0000000000000000 |
| ELE | AgentFence.IDENTITY.PROCFS_HIDEPID_LAX | medium | fail | few pids | 5 |
| ELE | AgentFence.SIDE.HOST_CPUINFO_LEAKED | low | fail | guest cpuinfo | flags		: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ht syscall nx |
| ELE | AgentFence.SIDE.HOST_DMI_LEAKED | low | pass | DMI visible | Google Compute Engine |
| ELE | AgentFence.SIDE.HIGH_RES_TIMER_AVAILABLE | low | pass | sub-microsecond | RES 1 |
| ELE | AgentFence.SIDE.HOST_CACHE_TOPOLOGY_LEAKED | low | fail | no cache info |  |

## Remediation Coverage Summary

- recipes: 39 / 39
- actionable findings: 11
- `AgentFence.REMOTE.UNAUTH_SERVICE_REACHABLE` -> `manual_recommendation`: Review service reachability from sibling pods
- `AgentFence.KERNEL.PERF_EVENT_OPEN_REACHABLE` -> `manual_recommendation`: Restrict perf event access
- `AgentFence.KERNEL.DMESG_VISIBLE` -> `hybrid`: Restrict kernel log visibility
- `AgentFence.FS.HOST_SYS_VISIBLE` -> `hybrid`: Prevent host /sys visibility
- `AgentFence.FS.HOST_FS_REACHABLE_VIA_PROC` -> `hybrid`: Block host filesystem traversal through /proc
- `AgentFence.DEVICE.TUN_TAP_PRESENT` -> `hybrid`: Review TUN/TAP device exposure
- `AgentFence.NS.USER_NS_ROOT_MAPS_HOST_ROOT` -> `manual_recommendation`: Review user namespace root mapping
- `AgentFence.IDENTITY.SECCOMP_BYPASS_OK` -> `auto_fix`: Enable seccomp filtering
- `AgentFence.IDENTITY.CAP_BOUNDING_PERMISSIVE` -> `auto_fix`: Minimize Linux capability bounding set
- `AgentFence.SIDE.HOST_DMI_LEAKED` -> `manual_recommendation`: Mask host DMI information
- `AgentFence.SIDE.HIGH_RES_TIMER_AVAILABLE` -> `manual_recommendation`: Assess high-resolution timer exposure
