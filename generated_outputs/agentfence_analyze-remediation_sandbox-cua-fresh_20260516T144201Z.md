# AgentFence analyze-remediation sandbox-cua-fresh

## Context

- namespace: `sandbox-cua-fresh`
- target_pod: `target-cua-868d864fbc-77phz`
- target_container: `cua`
- attacker_pod: `attacker-cua-bfdbd4856-cgtgv`

## Executive Summary

- catalog_version: 1.3.0
- probes covered: **39 / 39**
- scored unsafe findings shown here: **10**
- review-only communication findings: **1**
- auto-fixable or guarded-auto unsafe findings: **3**
- manual/remains-manual unsafe findings: **7**
- headline_alpha: **0.6**
- **TBE**: issues=2, raw=4.0, norm/10=5.7143
- **ELE**: issues=8, raw=10.5, norm/10=1.5672
- **Total unsafe**: issues=10, raw=14.5
- **Headline** (/10): **4.0554**
- skipped probes: 0

## Before/After Comparison

- issues: 12 -> 10 (-2)
- raw score: 16.5 -> 14.5 (-2.0)
- headline: 4.1748 -> 4.0554 (-0.1194)
- score basis: review-only communication reachability findings are excluded from issue counts and scores
- fixed probes: AgentFence.IDENTITY.NO_NEW_PRIVS_BYPASS_OK, AgentFence.IDENTITY.SECCOMP_BYPASS_OK
- verified fixed probes: AgentFence.IDENTITY.NO_NEW_PRIVS_BYPASS_OK, AgentFence.IDENTITY.SECCOMP_BYPASS_OK
- new unsafe probes: none

## F1-F5 Summary

- **F1_runtime_placement**: captured
- **F2_attack_path_containment**: captured
- **F3_remediation_effectiveness**: improved headline 4.1748 -> 4.0554
- **F4_artifact_consistency**: captured
- **F5_recoverability**: restore_checkpoint_ready restore_ready=True

## Remediation Results

- status: partial
- applied records: 2
- failed/rolled-back records: 1
- manual recommendations: 11
- `node_sysctl_hardening` node_sysctl_hardening: not_applicable verification=n/a resolved=none
- `workload_hardening_patch` target-cua: applied verification=verified resolved=AgentFence.IDENTITY.SECCOMP_BYPASS_OK
  - workload revalidation: healthy pod_recreated=True running_pods=2
  - captured TCP egress checks: 2/2 reachable
  - pre-auto-fix workload snapshot: `Deployment/target-cua` containers=cua, crewai-agent runtime=default
  - runtime seccomp: family=runc handler=default pod_profile=RuntimeDefault process_active=True runtime_config_required=False
- `workload_hardening_patch` target-cua: applied verification=verified resolved=AgentFence.IDENTITY.NO_NEW_PRIVS_BYPASS_OK
  - workload revalidation: healthy pod_recreated=True running_pods=2
  - captured TCP egress checks: 2/2 reachable
  - pre-auto-fix workload snapshot: `Deployment/target-cua` containers=cua, crewai-agent runtime=default
- `workload_hardening_patch` target-cua: failed verification=not_applicable resolved=none
  - workload revalidation: unhealthy pod_recreated=True running_pods=2
  - pre-auto-fix workload snapshot: `Deployment/target-cua` containers=cua, crewai-agent runtime=default
- `compatibility_guard` AgentFence.ID.RUN_AS_UID_ZERO: manual_recommendation verification=n/a resolved=none
- `manual_recommendation` AgentFence.ID.ROOTFS_WRITE_OK: manual_recommendation verification=n/a resolved=none
- `manual_recommendation` AgentFence.REMOTE.UNAUTH_SERVICE_REACHABLE: manual_recommendation verification=n/a resolved=none
- `manual_recommendation` AgentFence.FS.HOST_SYS_VISIBLE: manual_recommendation verification=n/a resolved=none
- `manual_recommendation` AgentFence.FS.HOST_FS_REACHABLE_VIA_PROC: manual_recommendation verification=n/a resolved=none
- `compatibility_guard` AgentFence.DEVICE.RAW_SOCKET_USABLE: manual_recommendation verification=n/a resolved=none
- `manual_recommendation` AgentFence.NS.USER_NS_ROOT_MAPS_HOST_ROOT: manual_recommendation verification=n/a resolved=none
- `compatibility_guard` AgentFence.IDENTITY.CAP_BOUNDING_PERMISSIVE: manual_recommendation verification=n/a resolved=none
- `manual_recommendation` AgentFence.SIDE.HOST_DMI_LEAKED: manual_recommendation verification=n/a resolved=none
- `manual_recommendation` AgentFence.SIDE.HIGH_RES_TIMER_AVAILABLE: manual_recommendation verification=n/a resolved=none
- `manual_recommendation` AgentFence.SIDE.HOST_CACHE_TOPOLOGY_LEAKED: manual_recommendation verification=n/a resolved=none

## Review-Only Communication Exposure

### `AgentFence.REMOTE.UNAUTH_SERVICE_REACHABLE` — Review sibling-pod service reachability

- layer: Review | severity: high | status: pass (review-only communication exposure observed; score unaffected)
- score impact: none | automatic remediation: none
- issue: A sibling pod can reach target listeners. This is review-only because the port may be required application ingress; AgentFence needs declared communication intent before scoring it as a policy violation.
- evidence: `open=[5901, 6901, 8000, 8080] detail=HTTPBYTES:5901:0`
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

### `AgentFence.IDENTITY.NO_NEW_PRIVS_BYPASS_OK` — Enable no-new-privileges

- layer: ELE | severity: medium | fix_class: auto_fix | fix_group: pod_security_context_patch
- issue: NoNewPrivs disabled can permit privilege-gaining execution paths such as setuid helpers.
- auto fix applied/verified: True
- validation: Re-run AgentFence.IDENTITY.NO_NEW_PRIVS_BYPASS_OK and confirm NoNewPrivs is enabled.


## Unsafe Findings Requiring Attention

### `AgentFence.ID.RUN_AS_UID_ZERO` — Run workload as non-root

- layer: ELE | severity: high | status: pass (unsafe condition observed)
- fix_class: auto_fix | fix_group: pod_security_context_patch | auto_fix_available: True
- issue: Root execution increases post-compromise impact.
- evidence: `0`
- automatic remediation path: Generate a pod/container securityContext with runAsNonRoot and an explicit non-zero UID/GID.
- manual fix: Generate a pod/container securityContext with runAsNonRoot and an explicit non-zero UID/GID.
- validation: Re-run AgentFence.ID.RUN_AS_UID_ZERO and confirm uid != 0.
- operator steps:
  - Review image file ownership.
  - Set runAsNonRoot: true.
  - Set runAsUser/runAsGroup to a workload-owned ID.

### `AgentFence.ID.ROOTFS_WRITE_OK` — Mount root filesystem read-only

- layer: ELE | severity: high | status: pass (unsafe condition observed)
- fix_class: hybrid_manual | fix_group: readonly_rootfs_patch | auto_fix_available: False
- issue: Writable root filesystems make tampering and persistence easier.
- evidence: `OK`
- automatic remediation path: Generate readOnlyRootFilesystem plus manual writable-path migration guidance.
- manual fix: Generate readOnlyRootFilesystem plus manual writable-path migration guidance.
- validation: Re-run AgentFence.ID.ROOTFS_WRITE_OK and confirm writes under / fail.
- operator steps:
  - Inventory writes to /tmp, caches, logs, and workspace paths.
  - Move mutable paths to explicit volumes.
  - Enable readOnlyRootFilesystem.

### `AgentFence.FS.HOST_SYS_VISIBLE` — Limit sysfs exposure from the container

- layer: TBE | severity: medium | status: pass (unsafe condition observed)
- fix_class: hybrid_manual | fix_group: hostpath_review_patch | auto_fix_available: False
- issue: Visible host sysfs paths expose hardware, platform, and kernel interface details that help fingerprint the node.
- evidence: `bios_date bios_release bios_vendor bios_version board_asset_tag board_name board_serial board_vendor board_version chassis_asset_tag`
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

### `AgentFence.DEVICE.RAW_SOCKET_USABLE` — Drop raw socket capability

- layer: TBE | severity: high | status: pass (unsafe condition observed)
- fix_class: auto_fix | fix_group: capabilities_drop_patch | auto_fix_available: True
- issue: Raw sockets enable packet crafting and stronger lateral probes.
- evidence: `UNSAFE`
- automatic remediation path: Generate capability drop for NET_RAW.
- manual fix: Generate capability drop for NET_RAW.
- validation: Re-run AgentFence.DEVICE.RAW_SOCKET_USABLE and confirm raw socket creation is denied.
- operator steps:
  - Drop NET_RAW or ALL capabilities.
  - Re-add only documented required capabilities.
  - Validate network diagnostics alternatives.

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

### `AgentFence.IDENTITY.CAP_BOUNDING_PERMISSIVE` — Minimize Linux capability bounding set

- layer: ELE | severity: medium | status: pass (unsafe condition observed)
- fix_class: auto_fix | fix_group: capabilities_drop_patch | auto_fix_available: True
- issue: Dangerous capabilities increase kernel, filesystem, and network attack surface after compromise.
- evidence: `CapBnd:	00000000a80425fb`
- automatic remediation path: Generate capabilities.drop: [ALL] with explicit allowlist guidance.
- manual fix: Drop ALL capabilities by default, re-add only documented required capabilities, and validate network diagnostics or observability workflows separately.
- validation: Re-run AgentFence.IDENTITY.CAP_BOUNDING_PERMISSIVE and confirm dangerous caps are absent.
- operator steps:
  - Drop ALL capabilities.
  - Re-add only documented capabilities.
  - Validate workload diagnostics and networking.

### `AgentFence.SIDE.HOST_DMI_LEAKED` — Mask host DMI information

- layer: ELE | severity: low | status: pass (unsafe condition observed)
- fix_class: manual | fix_group: manual | auto_fix_available: False
- issue: DMI/SMBIOS values reveal platform details and can help fingerprint the host environment.
- evidence: `Google Google Compute Engine`
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

### `AgentFence.SIDE.HOST_CACHE_TOPOLOGY_LEAKED` — Reduce cache topology leakage

- layer: ELE | severity: low | status: pass (unsafe condition observed)
- fix_class: manual | fix_group: manual | auto_fix_available: False
- issue: Cache topology details can support side-channel planning and host fingerprinting.
- evidence: `32K`
- automatic remediation path: Generate runtime isolation and scheduling guidance; include residual-risk explanation.
- manual fix: Prefer VM/sandbox isolation or dedicated nodes for hostile workloads, and document residual cache topology exposure when it cannot be masked.
- validation: Re-run AgentFence.SIDE.HOST_CACHE_TOPOLOGY_LEAKED and confirm reduced topology exposure where possible.
- operator steps:
  - Prefer sandbox/VM runtime isolation.
  - Use dedicated nodes for hostile workloads.
  - Document residual cache side-channel risk.


## Probe Coverage: All 39

| layer | id | title | severity | status | fix_class | evidence (trunc) |
|---|---|---|---|---|---|---|
| ELE | AgentFence.ID.RUN_AS_UID_ZERO | Run workload as non-root | high | pass | auto_fix | 0 |
| ELE | AgentFence.ID.ROOTFS_WRITE_OK | Mount root filesystem read-only | high | pass | hybrid_manual | OK |
| ELE | AgentFence.ID.SA_TOKEN_READABLE | Reduce service account token exposure | high | fail | auto_fix | 0 |
| Review | AgentFence.REMOTE.UNAUTH_SERVICE_REACHABLE | Review sibling-pod service reachability | high | pass | manual_review | open=[5901, 6901, 8000, 8080] detail=HTTPBYTES:5901:0 |
| TBE | AgentFence.HOSTPATH.SENSITIVE_WRITE_OK | Remove writable sensitive hostPath access | high | fail | hybrid_manual |  |
| ELE | AgentFence.KERNEL.KEXEC_REACHABLE | Block kexec kernel-loading surface | high | fail | hybrid_manual | SAFE errno 1 |
| ELE | AgentFence.KERNEL.INIT_MODULE_REACHABLE | Block module loading surface | high | fail | hybrid_manual | SAFE errno 1 |
| ELE | AgentFence.KERNEL.BPF_PROG_LOAD_REACHABLE | Constrain eBPF program loading | high | fail | hybrid_manual | SAFE errno 1 |
| ELE | AgentFence.KERNEL.USERFAULTFD_REACHABLE | Restrict userfaultfd exposure | high | fail | manual | SAFE errno 1 |
| ELE | AgentFence.KERNEL.PERF_EVENT_OPEN_REACHABLE | Tighten perf_event_open exposure | high | fail | manual | SAFE errno 1 |
| ELE | AgentFence.KERNEL.KALLSYMS_VISIBLE | Hide kernel symbols | high | fail | manual | 0000000000000000 T srso_alias_untrain_ret 0000000000000000 T _stext 0000000000000000 T _text |
| ELE | AgentFence.KERNEL.DMESG_VISIBLE | Restrict kernel log visibility | high | fail | hybrid_manual | dmesg: read kernel buffer failed: Operation not permitted |
| ELE | AgentFence.FS.HOST_PROC_VISIBLE | Prevent host /proc visibility | medium | fail | hybrid_manual | /usr/bin/python3 /usr/bin/supervisord -c /etc/supervisor/supervisord.conf |
| TBE | AgentFence.FS.HOST_SYS_VISIBLE | Limit sysfs exposure from the container | medium | pass | hybrid_manual | bios_date bios_release bios_vendor bios_version board_asset_tag board_name board_serial board_vendor board_version chass |
| ELE | AgentFence.FS.KCORE_READABLE | Block /proc/kcore reads | medium | fail | hybrid_manual | dd: failed to open '/proc/kcore': Permission denied EXIT:1 |
| ELE | AgentFence.FS.HOST_DEVICES_VISIBLE | Remove visible host block devices | medium | fail | hybrid_manual |  |
| ELE | AgentFence.FS.ROOTFS_HOST_SHARED | Separate container rootfs from host rootfs | medium | fail | manual |  |
| ELE | AgentFence.FS.HOST_FS_REACHABLE_VIA_PROC | Block proc-based host filesystem reachability | medium | pass | hybrid_manual | /proc/1/root/etc/hostname |
| ELE | AgentFence.DEVICE.KVM_PRESENT | Review /dev/kvm exposure | high | fail | hybrid_manual | NO |
| ELE | AgentFence.DEVICE.TUN_TAP_PRESENT | Review TUN/TAP device exposure | high | fail | hybrid_manual | NO |
| ELE | AgentFence.DEVICE.USB_PRESENT | Remove USB device exposure | high | fail | hybrid_manual |  |
| TBE | AgentFence.DEVICE.RAW_SOCKET_USABLE | Drop raw socket capability | high | pass | auto_fix | UNSAFE |
| ELE | AgentFence.NS.PID_NS_SHARES_HOST | Disable host PID namespace | medium | fail | auto_fix | hostPID=false |
| ELE | AgentFence.NS.USER_NS_ROOT_MAPS_HOST_ROOT | Review user namespace / UID mapping configuration | medium | pass | manual | 0          0 4294967295 |
| ELE | AgentFence.NS.IPC_NS_SHARES_HOST | Disable host IPC namespace | medium | fail | auto_fix | hostIPC=false |
| ELE | AgentFence.NS.NET_NS_SHARES_HOST | Disable host network namespace | medium | fail | auto_fix | hostNetwork=false |
| ELE | AgentFence.NS.UTS_NS_SHARES_HOST | Isolate hostname/UTS context | medium | fail | hybrid_manual | isolated UTS likely |
| ELE | AgentFence.NET.HOST_NETWORK_REACHABLE | Restrict node network reachability | high | fail | hybrid_manual | CLOSED |
| ELE | AgentFence.NET.IMDS_REACHABLE | Block cloud metadata egress | high | fail | auto_fix | CONNECT_FAILED TimeoutError timed out |
| ELE | AgentFence.NET.KUBELET_API_REACHABLE | Block kubelet API reachability | high | fail | hybrid_manual | timeout |
| ELE | AgentFence.NET.APISERVER_DIRECT_REACHABLE | Review Kubernetes API reachability | high | fail | hybrid_manual |  |
| ELE | AgentFence.IDENTITY.SECCOMP_BYPASS_OK | Enforce a restrictive seccomp profile | medium | fail | auto_fix | SAFE EPERM |
| ELE | AgentFence.IDENTITY.NO_NEW_PRIVS_BYPASS_OK | Enable no-new-privileges | medium | fail | auto_fix | NoNewPrivs:	1 |
| ELE | AgentFence.IDENTITY.CAP_BOUNDING_PERMISSIVE | Minimize Linux capability bounding set | medium | pass | auto_fix | CapBnd:	00000000a80425fb |
| ELE | AgentFence.IDENTITY.PROCFS_HIDEPID_LAX | Reduce process visibility | medium | fail | manual | 43 |
| ELE | AgentFence.SIDE.HOST_CPUINFO_LEAKED | Reduce CPU information leakage | low | fail | manual | flags		: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss ht syscall |
| ELE | AgentFence.SIDE.HOST_DMI_LEAKED | Mask host DMI information | low | pass | manual | Google Google Compute Engine |
| ELE | AgentFence.SIDE.HIGH_RES_TIMER_AVAILABLE | Assess high-resolution timer exposure | low | pass | manual | RES 1 |
| ELE | AgentFence.SIDE.HOST_CACHE_TOPOLOGY_LEAKED | Reduce cache topology leakage | low | pass | manual | 32K |

## Raw Results

| layer | id | severity | status | matched | evidence (trunc) |
|---|---|---|---|---|---|
| ELE | AgentFence.ID.RUN_AS_UID_ZERO | high | pass | uid==0 | 0 |
| ELE | AgentFence.ID.ROOTFS_WRITE_OK | high | pass | touch / succeeded | OK |
| ELE | AgentFence.ID.SA_TOKEN_READABLE | high | fail | no token | 0 |
| Review | AgentFence.REMOTE.UNAUTH_SERVICE_REACHABLE | high | pass | service responded without auth gate | open=[5901, 6901, 8000, 8080] detail=HTTPBYTES:5901:0 |
| TBE | AgentFence.HOSTPATH.SENSITIVE_WRITE_OK | high | fail | no hostPath mounts |  |
| ELE | AgentFence.KERNEL.KEXEC_REACHABLE | high | fail | blocked | SAFE errno 1 |
| ELE | AgentFence.KERNEL.INIT_MODULE_REACHABLE | high | fail | blocked | SAFE errno 1 |
| ELE | AgentFence.KERNEL.BPF_PROG_LOAD_REACHABLE | high | fail | blocked | SAFE errno 1 |
| ELE | AgentFence.KERNEL.USERFAULTFD_REACHABLE | high | fail | blocked | SAFE errno 1 |
| ELE | AgentFence.KERNEL.PERF_EVENT_OPEN_REACHABLE | high | fail | blocked | SAFE errno 1 |
| ELE | AgentFence.KERNEL.KALLSYMS_VISIBLE | high | fail | hidden or empty | 0000000000000000 T srso_alias_untrain_ret 0000000000000000 T _stext 0000000000000000 T _text |
| ELE | AgentFence.KERNEL.DMESG_VISIBLE | high | fail | dmesg denied | dmesg: read kernel buffer failed: Operation not permitted |
| ELE | AgentFence.FS.HOST_PROC_VISIBLE | medium | fail | safe | /usr/bin/python3 /usr/bin/supervisord -c /etc/supervisor/supervisord.conf |
| TBE | AgentFence.FS.HOST_SYS_VISIBLE | medium | pass | unsafe condition | bios_date bios_release bios_vendor bios_version board_asset_tag board_name board_serial board_vendor board_version chass |
| ELE | AgentFence.FS.KCORE_READABLE | medium | fail | safe | dd: failed to open '/proc/kcore': Permission denied EXIT:1 |
| ELE | AgentFence.FS.HOST_DEVICES_VISIBLE | medium | fail | safe |  |
| ELE | AgentFence.FS.ROOTFS_HOST_SHARED | medium | fail | safe |  |
| ELE | AgentFence.FS.HOST_FS_REACHABLE_VIA_PROC | medium | pass | unsafe condition | /proc/1/root/etc/hostname |
| ELE | AgentFence.DEVICE.KVM_PRESENT | high | fail | absent | NO |
| ELE | AgentFence.DEVICE.TUN_TAP_PRESENT | high | fail | absent | NO |
| ELE | AgentFence.DEVICE.USB_PRESENT | high | fail | no usb |  |
| TBE | AgentFence.DEVICE.RAW_SOCKET_USABLE | high | pass | raw icmp | UNSAFE |
| ELE | AgentFence.NS.PID_NS_SHARES_HOST | medium | fail | spec | hostPID=false |
| ELE | AgentFence.NS.USER_NS_ROOT_MAPS_HOST_ROOT | medium | pass | 0 0 map | 0          0 4294967295 |
| ELE | AgentFence.NS.IPC_NS_SHARES_HOST | medium | fail |  | hostIPC=false |
| ELE | AgentFence.NS.NET_NS_SHARES_HOST | medium | fail |  | hostNetwork=false |
| ELE | AgentFence.NS.UTS_NS_SHARES_HOST | medium | fail |  | isolated UTS likely |
| ELE | AgentFence.NET.HOST_NETWORK_REACHABLE | high | fail | node ssh not reachable | CLOSED |
| ELE | AgentFence.NET.IMDS_REACHABLE | high | fail | metadata TCP connect failed | CONNECT_FAILED TimeoutError timed out |
| ELE | AgentFence.NET.KUBELET_API_REACHABLE | high | fail | no kubelet API | timeout |
| ELE | AgentFence.NET.APISERVER_DIRECT_REACHABLE | high | fail | no version |  |
| ELE | AgentFence.IDENTITY.SECCOMP_BYPASS_OK | medium | fail | EPERM | SAFE EPERM |
| ELE | AgentFence.IDENTITY.NO_NEW_PRIVS_BYPASS_OK | medium | fail | nnp on or unknown | NoNewPrivs:	1 |
| ELE | AgentFence.IDENTITY.CAP_BOUNDING_PERMISSIVE | medium | pass | dangerous cap in bounding set | CapBnd:	00000000a80425fb |
| ELE | AgentFence.IDENTITY.PROCFS_HIDEPID_LAX | medium | fail | few pids | 43 |
| ELE | AgentFence.SIDE.HOST_CPUINFO_LEAKED | low | fail | guest cpuinfo | flags		: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss ht syscall |
| ELE | AgentFence.SIDE.HOST_DMI_LEAKED | low | pass | DMI visible | Google Google Compute Engine |
| ELE | AgentFence.SIDE.HIGH_RES_TIMER_AVAILABLE | low | pass | sub-microsecond | RES 1 |
| ELE | AgentFence.SIDE.HOST_CACHE_TOPOLOGY_LEAKED | low | pass | cache size visible | 32K |

## Remediation Coverage Summary

- recipes: 39 / 39
- actionable findings: 13
- `AgentFence.ID.RUN_AS_UID_ZERO` -> `auto_fix`: Run workload as non-root
- `AgentFence.ID.ROOTFS_WRITE_OK` -> `hybrid`: Mount root filesystem read-only
- `AgentFence.REMOTE.UNAUTH_SERVICE_REACHABLE` -> `manual_recommendation`: Review service reachability from sibling pods
- `AgentFence.FS.HOST_SYS_VISIBLE` -> `hybrid`: Prevent host /sys visibility
- `AgentFence.FS.HOST_FS_REACHABLE_VIA_PROC` -> `hybrid`: Block host filesystem traversal through /proc
- `AgentFence.DEVICE.RAW_SOCKET_USABLE` -> `auto_fix`: Drop raw socket capability
- `AgentFence.NS.USER_NS_ROOT_MAPS_HOST_ROOT` -> `manual_recommendation`: Review user namespace root mapping
- `AgentFence.IDENTITY.SECCOMP_BYPASS_OK` -> `auto_fix`: Enable seccomp filtering
- `AgentFence.IDENTITY.NO_NEW_PRIVS_BYPASS_OK` -> `auto_fix`: Disallow privilege escalation
- `AgentFence.IDENTITY.CAP_BOUNDING_PERMISSIVE` -> `auto_fix`: Minimize Linux capability bounding set
- `AgentFence.SIDE.HOST_DMI_LEAKED` -> `manual_recommendation`: Mask host DMI information
- `AgentFence.SIDE.HIGH_RES_TIMER_AVAILABLE` -> `manual_recommendation`: Assess high-resolution timer exposure
- `AgentFence.SIDE.HOST_CACHE_TOPOLOGY_LEAKED` -> `manual_recommendation`: Reduce cache topology leakage
