#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Combined sandbox audit.

Supports three modes in one file:
  1) internal  : run inside the target pod/workload
  2) remote    : run from a workstation or control host with kubectl access
  3) both      : run remote checks and then invoke this same file inside the
                 target pod to collect the internal audit as well

Design goals:
- Keep the internal audit pure stdlib.
- Preserve the remote kubectl-driven reachability audit.
- Normalize output into one JSON schema.

Examples:
  # inside target pod
  python3 combined_audit.py internal --out internal.json

  # from workstation with kubectl
  python3 combined_audit.py remote -n cua --target-selector app=cua --out remote.json

  # from workstation, collect both remote + internal in one run
  python3 combined_audit.py both -n cua --target-selector app=cua --out combined.json

  # generate remediation guidance from an existing audit JSON
  python3 combined_audit.py remediate --input combined.json --out remediation.json
"""

import argparse
import copy
import datetime
import json
import os
import platform
import re
import shlex
import socket
import ssl
import stat
import subprocess
import shutil
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

# --------------------------- shared helpers ---------------------------------

def now_utc_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def shell(cmd, timeout=10, check=False):
    try:
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=timeout)
        return out.decode("utf-8", "replace")
    except subprocess.CalledProcessError as e:
        if check:
            raise
        return e.output.decode("utf-8", "replace")
    except Exception as e:
        if check:
            raise
        return f"__ERR__ {type(e).__name__}: {e}"


def read_text(path, max_bytes=1_000_000):
    try:
        with open(path, "rb") as f:
            return f.read(max_bytes).decode("utf-8", "replace")
    except Exception as e:
        return f"__ERR__ {e}"


def file_exists(path):
    try:
        return os.path.exists(path)
    except Exception:
        return False


def bool_field(ok, evidence=""):
    return {"ok": bool(ok), "evidence": evidence or ""}


def tcp_connect(host, port, timeout=2.0):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, "tcp_connect_ok"
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"


def http_head_local(host="127.0.0.1", port=6901, path="/", timeout=2.0):
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            req = f"HEAD {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
            s.sendall(req.encode("utf-8"))
            data = s.recv(2048).decode("utf-8", "replace")
        m = re.search(r"HTTP/1\.[01]\s+(\d+)", data)
        code = int(m.group(1)) if m else None
        return code == 200, f"HTTP {code}"
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"


def websocket_upgrade_local(host="127.0.0.1", port=6901, path="/websockify", timeout=2.0):
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            req = (
                f"GET {path} HTTP/1.1\r\n"
                f"Host: {host}:{port}\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                "Sec-WebSocket-Key: x\r\n"
                "Sec-WebSocket-Version: 13\r\n\r\n"
            )
            s.sendall(req.encode("utf-8"))
            data = s.recv(2048).decode("utf-8", "replace")
        first = data.splitlines()[0] if data else ""
        m = re.search(r"HTTP/1\.[01]\s+(\d+)", data)
        code = int(m.group(1)) if m else None
        return code == 101, f"{first or 'no_reply'}"
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"


def rfb_greeting_local(host="127.0.0.1", port=5901, timeout=2.0, nbytes=12):
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(timeout)
            data = s.recv(nbytes)
        ok = data.startswith(b"RFB")
        try:
            preview = data.decode("ascii", "replace")
        except Exception:
            preview = data.hex()
        return ok, f"banner={preview}"
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"


def find_mount_opts(path):
    try:
        best = ("", "")
        with open("/proc/mounts", "r") as f:
            for line in f:
                parts = line.split()
                if len(parts) < 4:
                    continue
                mp, opts = parts[1], parts[3]
                if path.startswith(mp.rstrip("/")) and len(mp) > len(best[0]):
                    best = (mp, opts)
        return best[1]
    except Exception as e:
        return f"__ERR__ {e}"


def cap_eff_mask():
    try:
        st = read_text("/proc/self/status")
        m = re.search(r"^CapEff:\s*([0-9a-fA-F]+)", st, re.M)
        if not m:
            return 0, "missing CapEff"
        return int(m.group(1), 16), ""
    except Exception as e:
        return 0, f"__ERR__ {e}"


CAP_NAMES = [
    "CAP_CHOWN","CAP_DAC_OVERRIDE","CAP_DAC_READ_SEARCH","CAP_FOWNER","CAP_FSETID",
    "CAP_KILL","CAP_SETGID","CAP_SETUID","CAP_SETPCAP","CAP_LINUX_IMMUTABLE",
    "CAP_NET_BIND_SERVICE","CAP_NET_BROADCAST","CAP_NET_ADMIN","CAP_NET_RAW",
    "CAP_IPC_LOCK","CAP_IPC_OWNER","CAP_SYS_MODULE","CAP_SYS_RAWIO","CAP_SYS_CHROOT",
    "CAP_SYS_PTRACE","CAP_SYS_PACCT","CAP_SYS_ADMIN","CAP_SYS_BOOT","CAP_SYS_NICE",
    "CAP_SYS_RESOURCE","CAP_SYS_TIME","CAP_SYS_TTY_CONFIG","CAP_MKNOD",
    "CAP_LEASE","CAP_AUDIT_WRITE","CAP_AUDIT_CONTROL","CAP_SETFCAP",
    "CAP_MAC_OVERRIDE","CAP_MAC_ADMIN","CAP_SYSLOG","CAP_WAKE_ALARM",
    "CAP_BLOCK_SUSPEND","CAP_AUDIT_READ","CAP_PERFMON","CAP_BPF","CAP_CHECKPOINT_RESTORE"
] + [f"CAP_{i}" for i in range(41, 64)]


def caps_set(mask):
    out = []
    for i, name in enumerate(CAP_NAMES):
        if mask & (1 << i):
            out.append(name)
    return out


def count_ok(d):
    return sum(1 for v in d.values() if isinstance(v, dict) and v.get("ok") is True)


def count_total(d):
    return sum(1 for v in d.values() if isinstance(v, dict) and "ok" in v)




def shell_rc(cmd, timeout=10):
    try:
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=timeout)
        return 0, out.decode("utf-8", "replace")
    except subprocess.CalledProcessError as e:
        return e.returncode, e.output.decode("utf-8", "replace")
    except Exception as e:
        return 999, f"__ERR__ {type(e).__name__}: {e}"


def parse_json_from_mixed_output(text):
    try:
        return json.loads(text)
    except Exception:
        pass
    lines = [line for line in (text or "").splitlines() if line.strip()]
    for line in reversed(lines):
        try:
            return json.loads(line)
        except Exception:
            continue
    return None


def is_inside_kubernetes():
    return bool(os.environ.get("KUBERNETES_SERVICE_HOST")) or os.path.exists("/var/run/secrets/kubernetes.io/serviceaccount/token")


def has_kubectl():
    return shutil.which("kubectl") is not None


def kubectl_get_json(ns, resource, name=None, extra_args="", timeout=30):
    target = f"{resource} {shlex.quote(name)}" if name else resource
    cmd = f"kubectl -n {shlex.quote(ns)} get {target} -o json {extra_args}".strip()
    rc, out = shell_rc(cmd, timeout=timeout)
    if rc != 0:
        raise RuntimeError(out.strip() or f"kubectl get failed: {cmd}")
    return json.loads(out)


def kubectl_api_json(cmd, timeout=30):
    rc, out = shell_rc(cmd, timeout=timeout)
    if rc != 0:
        raise RuntimeError(out.strip() or cmd)
    return json.loads(out)


def parse_bool_ok(v):
    return isinstance(v, dict) and v.get("ok") is True


def writable_paths(paths):
    writable = []
    for path in paths:
        try:
            if os.path.exists(path) and os.access(path, os.W_OK):
                writable.append(path)
        except Exception:
            continue
    return writable


def find_setid_binaries(search_roots, max_hits=25):
    hits = []
    for root in search_roots:
        if not os.path.isdir(root):
            continue
        for cur_root, _, files in os.walk(root):
            for name in files:
                full = os.path.join(cur_root, name)
                try:
                    mode = os.stat(full).st_mode
                except Exception:
                    continue
                if mode & stat.S_ISUID or mode & stat.S_ISGID:
                    hits.append(full)
                    if len(hits) >= max_hits:
                        return hits
    return hits


def risky_device_nodes():
    nodes = []
    for path in ("/dev/kmsg", "/dev/mem", "/dev/kmem"):
        try:
            if os.path.exists(path) and os.access(path, os.R_OK | os.W_OK):
                nodes.append(path)
        except Exception:
            continue
    return nodes

# --------------------------- internal audit ---------------------------------

def sandbox_checks(timeout):
    res = {}
    env = os.environ
    has_pw = any(k in env for k in ("VNC_PW", "VNC_PASSWORD"))
    res["no_vnc_password_in_env"] = bool_field(not has_pw, f"vars={'present' if has_pw else 'absent'}")

    uid = os.geteuid() if hasattr(os, "geteuid") else 0
    res["running_as_non_root"] = bool_field(uid != 0, f"euid={uid}")

    root_opts = find_mount_opts("/")
    res["rootfs_readonly"] = bool_field(isinstance(root_opts, str) and "ro" in root_opts, f"root_mount_opts={root_opts}")
    writable = writable_paths(("/etc", "/bin", "/sbin", "/usr", "/root"))
    res["sensitive_paths_readonly"] = bool_field(len(writable) == 0, f"writable={','.join(writable) or 'none'}")

    setid_hits = find_setid_binaries(("/bin", "/sbin", "/usr/bin", "/usr/sbin"))
    res["setid_binaries_absent"] = bool_field(len(setid_hits) == 0, f"found={','.join(setid_hits[:10]) or 'none'}")

    mounts_txt = read_text("/proc/mounts", 2_000_000)
    bad_mounts = []
    for needle in ("/var/run/docker.sock", "/run/containerd/containerd.sock"):
        if needle in mounts_txt:
            bad_mounts.append(needle)
    res["host_engine_sockets_absent"] = bool_field(len(bad_mounts) == 0, f"found={','.join(bad_mounts) or 'none'}")

    blocked_all = True
    evs = []
    for host, port in (("169.254.169.254", 80), ("169.254.170.2", 80)):
        okc, _ = tcp_connect(host, port, timeout=min(timeout, 1.0))
        if okc:
            blocked_all = False
        evs.append(f"{host}:{port} reach={okc}")
    res["cloud_imds_blocked"] = bool_field(blocked_all, "; ".join(evs))
    risky_nodes = risky_device_nodes()
    res["risky_device_nodes_absent"] = bool_field(len(risky_nodes) == 0, f"found={','.join(risky_nodes) or 'none'}")

    return res


def https_get(host, port=443, path="/version", cafile=None, timeout=3.0):
    try:
        ctx = ssl.create_default_context(cafile=cafile) if cafile and os.path.exists(cafile) else ssl.create_default_context()
        ctx.check_hostname = False
        with socket.create_connection((host, port), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                req = f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
                ss.sendall(req.encode("utf-8"))
                data = ss.recv(4096).decode("utf-8", "replace")
                m = re.search(r"HTTP/1\.[01]\s+(\d+)", data)
                code = int(m.group(1)) if m else None
                first = data.splitlines()[0] if data else ""
                return True, f"HTTP {code} {first}"
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"


def kubernetes_checks(timeout):
    res = {}
    svc_host = os.environ.get("KUBERNETES_SERVICE_HOST", "kubernetes.default.svc")
    svc_port = int(os.environ.get("KUBERNETES_SERVICE_PORT", "443"))
    sa_dir = "/var/run/secrets/kubernetes.io/serviceaccount"
    sa_token = os.path.join(sa_dir, "token")
    sa_ca = os.path.join(sa_dir, "ca.crt")
    ns_file = os.path.join(sa_dir, "namespace")

    res["sa_token_present"] = bool_field(not file_exists(sa_token), f"exists={file_exists(sa_token)}")
    res["sa_ca_present"] = bool_field(not file_exists(sa_ca), f"exists={file_exists(sa_ca)}")
    res["sa_namespace_present"] = bool_field(not file_exists(ns_file), f"exists={file_exists(ns_file)}")
    ro_opts = find_mount_opts(sa_dir)
    res["sa_mount_readonly"] = bool_field(("ro" in ro_opts) if isinstance(ro_opts, str) else False, f"mount_opts={ro_opts}")

    status = read_text("/proc/self/status")
    m = re.search(r"^Seccomp:\s*(\d+)", status, re.M)
    seccomp_mode = int(m.group(1)) if m else None
    res["seccomp_enforced"] = bool_field(seccomp_mode == 2, f"Seccomp={seccomp_mode}")

    m = re.search(r"^NoNewPrivs:\s*(\d+)", status, re.M)
    nnp = int(m.group(1)) if m else 0
    res["no_new_privs"] = bool_field(nnp == 1, f"NoNewPrivs={nnp}")

    apparmor = read_text("/proc/self/attr/current").strip()
    res["apparmor_profile"] = bool_field(apparmor not in ("", "unconfined"), f"profile='{apparmor}'")

    mask, cap_err = cap_eff_mask()
    caps = caps_set(mask)
    dangerous = {"CAP_SYS_ADMIN", "CAP_SYS_PTRACE", "CAP_NET_ADMIN", "CAP_BPF", "CAP_SYS_MODULE", "CAP_SYS_TIME", "CAP_SYS_BOOT", "CAP_SYS_RAWIO"}
    present = sorted(list(set(caps) & dangerous))
    res["dangerous_caps_absent"] = bool_field(len(present) == 0, f"present={','.join(present) or 'none'};mask=0x{mask:x} {cap_err}".strip())

    root_opts = find_mount_opts("/")
    res["rootfs_readonly"] = bool_field(isinstance(root_opts, str) and "ro" in root_opts, f"root_mount_opts={root_opts}")

    mounts_txt = read_text("/proc/mounts", 2_000_000)
    suspicious = []
    for needle in ("/var/run/docker.sock", "/run/containerd/containerd.sock", "/lib/modules", "/var/lib/kubelet", "/etc/kubernetes"):
        if needle in mounts_txt:
            suspicious.append(needle)
    res["host_mounts_absent"] = bool_field(len(suspicious) == 0, f"found={','.join(suspicious) or 'none'}")

    ok, ev = tcp_connect(svc_host, svc_port, timeout=timeout)
    res["egress_api_tcp_443"] = bool_field(not ok, f"reachable={ok}; {ev}")
    ok, ev = https_get(svc_host, svc_port, "/version", cafile=sa_ca if file_exists(sa_ca) else None, timeout=max(timeout, 3.0))
    res["egress_api_https_version"] = bool_field(not ok, f"reachable={ok}; {ev}")

    blocked_all = True
    evs = []
    for host, port in (("169.254.169.254", 80), ("169.254.170.2", 80)):
        okc, _ = tcp_connect(host, port, timeout=min(timeout, 1.0))
        if okc:
            blocked_all = False
        evs.append(f"{host}:{port} reach={okc}")
    res["imds_blocked"] = bool_field(blocked_all, "; ".join(evs))

    res["net_raw_absent"] = bool_field("CAP_NET_RAW" not in caps, f"CAP_NET_RAW={'CAP_NET_RAW' in caps}")
    return res


def collect_internal(timeout=2.0):
    meta = {
        "ts_utc": now_utc_iso(),
        "python_version": sys.version.split()[0],
        "platform": platform.platform(),
        "hostname": platform.node(),
        "cwd": os.getcwd(),
        "uid": os.geteuid() if hasattr(os, "geteuid") else None,
        "env_hints": {
            "KUBERNETES_SERVICE_HOST": os.environ.get("KUBERNETES_SERVICE_HOST"),
            "HOSTNAME": os.environ.get("HOSTNAME"),
        },
    }

    results = {}
    kuberes = {}
    try:
        results.update(sandbox_checks(timeout=timeout))
    except Exception as e:
        results["collector_error"] = bool_field(False, f"{type(e).__name__}: {e}")

    try:
        kuberes.update(kubernetes_checks(timeout=timeout))
    except Exception as e:
        kuberes["collector_error"] = bool_field(False, f"{type(e).__name__}: {e}")

    total_checks = count_total(results) + count_total(kuberes)
    passed = count_ok(results) + count_ok(kuberes)

    obj = {
        "meta": meta,
        "results": results,
        "kubernetes": kuberes,
        "summary": {"passed": passed, "total": total_checks},
    }
    obj["remediation"] = remediation_from_audit(obj)
    return obj


# --------------------------- remote audit -----------------------------------

DEFAULT_PORTS = [22, 80, 443, 5901, 6080, 6901, 8000, 8080, 8443, 10250, 10255]


def kubectl_jsonpath(ns, pod, jp, timeout=20):
    cmd = f"kubectl -n {shlex.quote(ns)} get pod {shlex.quote(pod)} -o jsonpath={shlex.quote(jp)}"
    return shell(cmd, timeout=timeout, check=False).strip()


def first_running_pod_by_selector(ns, selector, timeout=20):
    cmd = (
        f"kubectl -n {shlex.quote(ns)} get pods -l {shlex.quote(selector)} "
        f"--field-selector=status.phase=Running -o jsonpath={{.items[0].metadata.name}}"
    )
    out = shell(cmd, timeout=timeout, check=False).strip()
    return out or None


def pod_exists(ns, pod, timeout=20):
    out = shell(f"kubectl -n {shlex.quote(ns)} get pod {shlex.quote(pod)} -o name", timeout=timeout, check=False)
    return f"pod/{pod}" in out


def ensure_attacker_pod(ns, prefer_name="attacker", create_if_missing=True):
    if pod_exists(ns, prefer_name):
        return prefer_name, False
    existing = first_running_pod_by_selector(ns, "role=attacker")
    if existing:
        return existing, False
    existing = first_running_pod_by_selector(ns, "app=attacker")
    if existing:
        return existing, False
    if not create_if_missing:
        raise RuntimeError(f"attacker pod '{prefer_name}' not found")
    tmp_name = "atk-tmp-" + str(int(time.time()))
    shell(
        f"kubectl -n {shlex.quote(ns)} run {shlex.quote(tmp_name)} "
        f"--image=nicolaka/netshoot --restart=Never --labels=app=attacker,role=attacker "
        f"--requests=cpu=100m,memory=128Mi --limits=cpu=250m,memory=256Mi -- tail -f /dev/null",
        check=True,
        timeout=120,
    )
    shell(f"kubectl -n {shlex.quote(ns)} wait --for=condition=Ready pod/{shlex.quote(tmp_name)} --timeout=120s", check=True, timeout=130)
    return tmp_name, True


def degraded_remote_result(reason, detail=""):
    return {"ok": False, "skipped": True, "reason": reason, "detail": detail or ""}


def attacker_exec(ns, atk_pod, cmd, timeout=60):
    return shell(f"kubectl -n {shlex.quote(ns)} exec {shlex.quote(atk_pod)} -- sh -lc {shlex.quote(cmd)}", timeout=timeout, check=False)


def probe_http_head(ns, atk_pod, ip, port, path="/"):
    out = attacker_exec(ns, atk_pod, f"curl -sI --max-time 3 http://{ip}:{port}{path} | head -n 1")
    return {"ok": bool(out.strip()), "status_line": out.strip()}


def probe_ws_upgrade(ns, atk_pod, ip, port, path="/websockify"):
    req = (
        f"printf 'GET {path} HTTP/1.1\\r\\nHost: {ip}:{port}\\r\\nUpgrade: websocket\\r\\n"
        f"Connection: Upgrade\\r\\nSec-WebSocket-Key: x\\r\\nSec-WebSocket-Version: 13\\r\\n\\r\\n' "
        f"| nc -v -w 2 {ip} {port} | head -n 2"
    )
    out = attacker_exec(ns, atk_pod, req)
    return {"raw": out, "switching_protocols_101": ("101" in out and "Switching Protocols" in out)}


def probe_nc(ns, atk_pod, ip, port):
    out = attacker_exec(ns, atk_pod, f"nc -vz -w 1 {ip} {port} 2>&1 || true")
    reachable = any(s in out.lower() for s in ["succeeded", "open"])
    return {"port": port, "reachable": reachable, "nc_output": out.strip()}


def ensure_python_in_attacker(ns, atk_pod):
    attacker_exec(ns, atk_pod, "command -v python3 >/dev/null 2>&1 || apk add --no-cache python3 >/dev/null 2>&1 || true")


def rfb_probe(ns, atk_pod, ip, port=5901, timeout=2, proofsafe=True):
    ensure_python_in_attacker(ns, atk_pod)
    py = """\
import socket, sys, json, struct
ip=sys.argv[1]; port=int(sys.argv[2]); to=float(sys.argv[3]); proof = (sys.argv[4]=='1')
out = {}
try:
    s=socket.create_connection((ip,port), to); s.settimeout(to)
    banner = s.recv(12)
    if len(banner) < 12:
        out['error']='short_banner'; print(json.dumps(out)); sys.exit(0)
    out['banner']=banner.decode(errors='ignore').strip()
    ver = banner.strip().split(b' ')[-1]
    s.sendall(b'RFB ' + ver + b'\\n')
    n = s.recv(1)
    if not n:
        out['error']='no_security_types'; print(json.dumps(out)); sys.exit(0)
    n = n[0]
    types = list(s.recv(n))
    out['types']=types
    none_available = 1 in types
    out['none_available'] = none_available
    if none_available and proof:
        s.sendall(bytes([1]))
        s.settimeout(to)
        secres = s.recv(4)
        if len(secres)==4:
            (code,) = struct.unpack('!I', secres)
            if code != 0:
                out['error']=f'security_result_nonzero_{code}'
                out['classification']='unauthenticated_vnc'
                print(json.dumps(out)); sys.exit(0)
        s.sendall(b'\\x01')
        hdr = s.recv(24)
        if len(hdr) < 24:
            out['error']='short_serverinit_header'
            out['classification']='unauthenticated_vnc'
            print(json.dumps(out)); sys.exit(0)
        w,h = struct.unpack('!HH', hdr[:4])
        nameLen = struct.unpack('!I', s.recv(4))[0]
        name = s.recv(nameLen).decode(errors='ignore')
        out['proofsafe_serverinit'] = {'width': int(w), 'height': int(h), 'name': name}
        out['classification'] = 'proofsafe_serverinit_ok'
    else:
        out['classification'] = 'unauthenticated_vnc' if none_available else 'password_required'
except Exception as e:
    out['error']=str(e)
    out['classification']='error'
print(json.dumps(out))
"""
    proof_flag = "1" if proofsafe else "0"
    cmd = (
        f"kubectl -n {shlex.quote(ns)} exec {shlex.quote(atk_pod)} -- "
        f"python3 -c {shlex.quote(py)} {shlex.quote(ip)} {int(port)} {float(timeout)} {proof_flag}"
    )
    out = shell(cmd, check=False, timeout=90)
    try:
        return json.loads(out)
    except Exception:
        return {"classification": "error", "error": "json_parse", "raw": out}


def optional_internal_introspection(ns, pod):
    data = {"ok": False}
    ps = shell(
        f"kubectl -n {shlex.quote(ns)} exec {shlex.quote(pod)} -- sh -lc "
        + shlex.quote('ps aux | egrep -i "novnc|websock|tigervnc|vncserver|computer_server" | grep -v egrep || true'),
        check=False,
        timeout=60,
    )
    ls = shell(
        f"kubectl -n {shlex.quote(ns)} exec {shlex.quote(pod)} -- sh -lc "
        + shlex.quote('ss -lntp || netstat -tlnp || true'),
        check=False,
        timeout=60,
    )
    env = shell(
        f"kubectl -n {shlex.quote(ns)} exec {shlex.quote(pod)} -- sh -lc "
        + shlex.quote('env | egrep -i "VNC|NOVNC|COMPUTER" || true'),
        check=False,
        timeout=60,
    )
    data["processes"] = ps.strip()
    data["listening"] = ls.strip()
    data["env"] = env.strip()
    data["ok"] = True
    return data


def internal_python_stdin_launcher(timeout):
    argv = json.dumps(["combined_audit_with_remediation.py", "internal", "--timeout", str(float(timeout)), "--stdout-json"])
    return (
        "python3 -c "
        + shlex.quote(
            "import sys; "
            f"sys.argv={argv}; "
            "src=sys.stdin.read(); "
            "ns={'__name__':'__main__','__file__':'combined_audit_with_remediation.py'}; "
            "exec(compile(src, 'combined_audit_with_remediation.py', 'exec'), ns, ns)"
        )
    )


def run_internal_via_kubectl(ns, pod, timeout=2.0):
    script_text = read_text(os.path.abspath(__file__), max_bytes=5_000_000)
    remote_cmd = internal_python_stdin_launcher(timeout)
    try:
        proc = subprocess.run(
            ["kubectl", "-n", ns, "exec", "-i", pod, "--", "sh", "-lc", remote_cmd],
            input=script_text.encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=300,
            check=False,
        )
        out = proc.stdout.decode("utf-8", "replace")
        parsed = parse_json_from_mixed_output(out)
        if parsed is not None:
            return parsed
        return {"error": "internal_exec_parse_failed", "raw": out}
    except Exception as e:
        return {"error": f"internal_exec_failed: {type(e).__name__}: {e}"}


def collect_remote(ns, selector, timeout=2.0, include_introspection=True, include_internal_audit=False):
    ts = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    meta = {
        "ts_utc": ts,
        "namespace": ns,
        "target_selector": selector,
        "tool": "combined_sandbox_audit",
        "host": os.uname().sysname + " " + os.uname().release,
    }

    target_pod = first_running_pod_by_selector(ns, selector)
    if not target_pod:
        raise RuntimeError(f"No running target pod found with selector: {selector}")

    target_ip = kubectl_jsonpath(ns, target_pod, "{.status.podIP}") or ""
    img = kubectl_jsonpath(ns, target_pod, "{.spec.containers[0].image}") or ""
    image_id = kubectl_jsonpath(ns, target_pod, "{.status.containerStatuses[0].imageID}") or ""
    node = kubectl_jsonpath(ns, target_pod, "{.spec.nodeName}") or ""

    meta.update({
        "target_pod": target_pod,
        "target_ip": target_ip,
        "node": node,
        "image": img,
        "imageID": image_id,
    })
    try:
        discovered = discover_workload_from_pod(ns, target_pod)
        meta.update({
            "workload_name": discovered.get("workload_name"),
            "workload_kind": (discovered.get("workload_kind") or "").lower(),
            "container_names": discovered.get("container_names", []),
            "service_account_name": discovered.get("service_account_name"),
            "selector_labels": discovered.get("selector_labels", {}),
        })
        if discovered.get("selector"):
            meta["target_selector"] = discovered.get("selector")
    except Exception as e:
        meta["discovery_error"] = str(e)

    attacker_name = None
    created_tmp = False
    attacker_error = None
    try:
        attacker_name, created_tmp = ensure_attacker_pod(ns, prefer_name="attacker", create_if_missing=True)
        meta["attacker_pod"] = attacker_name
        meta["attacker_created_tmp"] = created_tmp
    except Exception as e:
        attacker_error = f"{type(e).__name__}: {e}"
        meta["attacker_pod"] = None
        meta["attacker_created_tmp"] = False
        meta["attacker_setup_error"] = attacker_error

    results = {
        "scanned_ports": [],
        "novnc_http_6901": {},
        "novnc_ws_6901": {},
        "vnc_rfb_5901": {},
        "internal_introspection": {},
        "internal_audit": {},
        "classification": "unknown",
    }

    if attacker_name:
        for p in DEFAULT_PORTS:
            if not target_ip:
                results["scanned_ports"].append({"port": p, "reachable": False, "nc_output": "no target_ip"})
                continue
            results["scanned_ports"].append(probe_nc(ns, attacker_name, target_ip, p))

        if target_ip:
            results["novnc_http_6901"] = probe_http_head(ns, attacker_name, target_ip, 6901, path="/")
            results["novnc_ws_6901"] = probe_ws_upgrade(ns, attacker_name, target_ip, 6901, path="/websockify")
            results["vnc_rfb_5901"] = rfb_probe(ns, attacker_name, target_ip, port=5901, timeout=timeout, proofsafe=True)
    else:
        for p in DEFAULT_PORTS:
            results["scanned_ports"].append({"port": p, "reachable": False, "nc_output": f"skipped: {attacker_error or 'no attacker pod available'}"})
        results["novnc_http_6901"] = degraded_remote_result("attacker_unavailable", attacker_error)
        results["novnc_ws_6901"] = degraded_remote_result("attacker_unavailable", attacker_error)
        results["vnc_rfb_5901"] = {"classification": "skipped_attacker_unavailable", "error": attacker_error or "no attacker pod available"}

    if include_introspection:
        try:
            results["internal_introspection"] = optional_internal_introspection(ns, target_pod)
        except Exception as e:
            results["internal_introspection"] = {"ok": False, "error": str(e)}

    if include_internal_audit:
        try:
            results["internal_audit"] = run_internal_via_kubectl(ns, target_pod, timeout=timeout)
        except Exception as e:
            results["internal_audit"] = {"error": str(e)}

    rfb_class = (results.get("vnc_rfb_5901") or {}).get("classification", "")
    reachable_6901 = bool(results.get("novnc_http_6901", {}).get("ok")) and "200" in (results.get("novnc_http_6901", {}).get("status_line", ""))
    ws_ok = bool(results.get("novnc_ws_6901", {}).get("switching_protocols_101"))
    vnc5901_open = any(x for x in results["scanned_ports"] if x["port"] == 5901 and x["reachable"])

    if not attacker_name:
        results["classification"] = "remote_probe_skipped_attacker_unavailable"
    elif rfb_class in ("proofsafe_serverinit_ok", "unauthenticated_vnc"):
        results["classification"] = "remotely_reachable_from_pod_and_unauthenticated_vnc"
    elif rfb_class == "password_required":
        results["classification"] = "remotely_reachable_from_pod_but_password_required"
    elif reachable_6901 and ws_ok and vnc5901_open:
        results["classification"] = "remotely_reachable_from_pod_partial_signals"
    else:
        results["classification"] = "not_reachable_or_insufficient_signals"

    if created_tmp:
        try:
            shell(f"kubectl -n {shlex.quote(ns)} delete pod {shlex.quote(attacker_name)} --grace-period=0 --force", check=False, timeout=60)
        except Exception:
            pass

    obj = {"meta": meta, "results": results}
    obj["remediation"] = remediation_from_audit(obj)
    return obj






def autodetect_namespace(default="default"):
    ns_file = "/var/run/secrets/kubernetes.io/serviceaccount/namespace"
    if os.path.exists(ns_file):
        val = read_text(ns_file, 4096).strip()
        if val and not val.startswith("__ERR__"):
            return val
    ctx_ns = shell("kubectl config view --minify --output 'jsonpath={..namespace}'", timeout=10).strip() if has_kubectl() else ""
    return ctx_ns or default


def list_running_pods(ns, timeout=30):
    obj = kubectl_get_json(ns, 'pods', extra_args='--field-selector=status.phase=Running', timeout=timeout)
    return obj.get('items', [])


def pod_matches_selector(pod, selector):
    labels = ((pod or {}).get('metadata') or {}).get('labels') or {}
    for part in (selector or '').split(','):
        part = part.strip()
        if not part:
            continue
        if '=' not in part:
            return False
        k, v = part.split('=', 1)
        if labels.get(k.strip()) != v.strip():
            return False
    return True


def labels_to_selector(labels):
    if not labels:
        return ''
    ordered = sorted(labels.items())
    return ','.join(f"{k}={v}" for k, v in ordered)


def discover_workload_from_pod(ns, pod_name, timeout=30):
    pod = kubectl_get_json(ns, 'pod', pod_name, timeout=timeout)
    md = pod.get('metadata', {})
    spec = pod.get('spec', {})
    status = pod.get('status', {})
    out = {
        'namespace': ns,
        'pod_name': pod_name,
        'pod_ip': status.get('podIP', ''),
        'node_name': spec.get('nodeName', ''),
        'service_account_name': spec.get('serviceAccountName') or 'default',
        'container_names': [c.get('name') for c in spec.get('containers', []) if c.get('name')],
        'pod_labels': md.get('labels', {}) or {},
        'workload_kind': None,
        'workload_name': None,
        'selector_labels': {},
    }
    owners = md.get('ownerReferences') or []
    if not owners:
        out['workload_kind'] = 'Pod'
        out['workload_name'] = pod_name
        out['selector_labels'] = {k:v for k,v in out['pod_labels'].items() if k not in ('pod-template-hash','controller-revision-hash')}
        return out
    owner = owners[0]
    kind = owner.get('kind')
    name = owner.get('name')
    if kind == 'ReplicaSet' and name:
        rs = kubectl_get_json(ns, 'replicaset', name, timeout=timeout)
        rs_owners = (rs.get('metadata', {}).get('ownerReferences') or [])
        if rs_owners and rs_owners[0].get('kind') == 'Deployment':
            kind = 'Deployment'
            name = rs_owners[0].get('name')
            dep = kubectl_get_json(ns, 'deployment', name, timeout=timeout)
            out['selector_labels'] = (((dep.get('spec', {}) or {}).get('selector', {}) or {}).get('matchLabels') or {})
        else:
            out['selector_labels'] = (((rs.get('spec', {}) or {}).get('selector', {}) or {}).get('matchLabels') or {})
    elif kind == 'StatefulSet' and name:
        ss = kubectl_get_json(ns, 'statefulset', name, timeout=timeout)
        out['selector_labels'] = (((ss.get('spec', {}) or {}).get('selector', {}) or {}).get('matchLabels') or {})
    elif kind == 'DaemonSet' and name:
        ds = kubectl_get_json(ns, 'daemonset', name, timeout=timeout)
        out['selector_labels'] = (((ds.get('spec', {}) or {}).get('selector', {}) or {}).get('matchLabels') or {})
    else:
        out['selector_labels'] = {k:v for k,v in out['pod_labels'].items() if k not in ('pod-template-hash','controller-revision-hash')}
    out['workload_kind'] = kind or 'Pod'
    out['workload_name'] = name or pod_name
    if not out['selector_labels']:
        out['selector_labels'] = {k:v for k,v in out['pod_labels'].items() if k not in ('pod-template-hash','controller-revision-hash')}
    return out


def autodiscover_remote_target(ns=None, selector=None, timeout=30):
    ns = ns or autodetect_namespace('default')
    pods = list_running_pods(ns, timeout=timeout)
    if selector:
        pods = [p for p in pods if pod_matches_selector(p, selector)]
    scored = []
    for p in pods:
        md = p.get('metadata', {})
        name = md.get('name', '')
        labels = md.get('labels', {}) or {}
        score = 0
        for key in ('app','sandbox','runtime','component'):
            val = labels.get(key, '').lower()
            if any(tok in val for tok in ('cua','gvisor','kata','wasm','spin','sandbox','agent')):
                score += 3
        if 'attacker' in name:
            score -= 10
        if 'agent' in name:
            score -= 2
        if md.get('ownerReferences'):
            score += 1
        scored.append((score, name, p))
    if not scored:
        raise RuntimeError(f'No running pods found in namespace {ns}')
    scored.sort(key=lambda x: (x[0], x[1]), reverse=True)
    pod = scored[0][2]
    discovered = discover_workload_from_pod(ns, pod.get('metadata', {}).get('name'), timeout=timeout)
    discovered['selector'] = selector or labels_to_selector(discovered.get('selector_labels') or {})
    if not discovered['selector']:
        discovered['selector'] = labels_to_selector({k:v for k,v in discovered.get('pod_labels', {}).items() if k not in ('pod-template-hash','controller-revision-hash')})
    return discovered


def autodetect_mode():
    inside = is_inside_kubernetes()
    if inside and not has_kubectl():
        return 'internal'
    if has_kubectl():
        return 'both'
    return 'internal'


def list_candidate_resources(ns, timeout=30):
    pods = list_running_pods(ns, timeout=timeout)
    resources = []
    seen = set()
    for pod in pods:
        name = ((pod.get('metadata') or {}).get('name') or '')
        if not name:
            continue
        try:
            info = discover_workload_from_pod(ns, name, timeout=timeout)
        except Exception:
            continue
        key = (info.get('workload_kind') or 'Pod', info.get('workload_name') or name, info.get('selector') or labels_to_selector(info.get('selector_labels') or {}))
        if key in seen:
            continue
        seen.add(key)
        info['selector'] = info.get('selector') or labels_to_selector(info.get('selector_labels') or {})
        resources.append(info)
    resources.sort(key=lambda x: ((x.get('workload_kind') or ''), (x.get('workload_name') or ''), (x.get('pod_name') or '')))
    return resources


def print_resource_list(resources, title='Discovered resources'):
    print(f"\n=== {title} ===")
    if not resources:
        print('No resources discovered.')
        return
    for idx, r in enumerate(resources, start=1):
        selector = r.get('selector') or labels_to_selector(r.get('selector_labels') or {}) or '-'
        print(f"{idx}. {r.get('workload_kind','Pod')}/{r.get('workload_name')}")
        print(f"   pod={r.get('pod_name','-')}  ns={r.get('namespace','-')}  sa={r.get('service_account_name','-')}")
        print(f"   containers={','.join(r.get('container_names') or []) or '-'}")
        print(f"   selector={selector}")


def prompt_resource_selection(resources):
    if not resources:
        raise RuntimeError('No resources available for selection')
    while True:
        raw = prompt('Select resource number', '1')
        if raw.isdigit():
            idx = int(raw)
            if 1 <= idx <= len(resources):
                return resources[idx - 1]
        print(f'Enter a number from 1 to {len(resources)}')

# --------------------------- remediation module ----------------------------

def make_remediation_item(issue_id, severity, title, rationale, actions, snippet=None, refs=None):
    return {
        "issue_id": issue_id,
        "severity": severity,
        "title": title,
        "rationale": rationale,
        "actions": actions,
        "snippet": snippet or "",
        "refs": refs or [],
    }


def yaml_block_pod_hardening(selector="app=cua"):
    key, value = selector.split("=", 1) if "=" in selector else ("app", "REPLACE_ME")
    return f'''apiVersion: apps/v1
kind: Deployment
metadata:
  name: REPLACE_ME
spec:
  template:
    metadata:
      labels:
        {key}: {value}
    spec:
      automountServiceAccountToken: false
      containers:
      - name: REPLACE_ME
        securityContext:
          runAsNonRoot: true
          runAsUser: 10001
          runAsGroup: 10001
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop: ["ALL"]
          seccompProfile:
            type: RuntimeDefault'''


def yaml_block_networkpolicy(namespace="default", selector="app=cua"):
    key, value = selector.split("=", 1) if "=" in selector else ("app", "cua")
    return f'''apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: sandbox-default-deny
  namespace: {namespace}
spec:
  podSelector:
    matchLabels:
      {key}: {value}
  policyTypes:
  - Ingress
  - Egress
  ingress: []
  egress:
  - to:
    - namespaceSelector: {{}}
      podSelector:
        matchLabels:
          k8s-app: kube-dns
    ports:
    - protocol: UDP
      port: 53
    - protocol: TCP
      port: 53'''


def yaml_block_service_account(namespace="default"):
    return f'''apiVersion: v1
kind: ServiceAccount
metadata:
  name: sandbox-sa
  namespace: {namespace}
automountServiceAccountToken: false'''


def yaml_block_novnc_service_note():
    return (
        "Remove or disable noVNC/VNC listeners unless they are strictly required. If required, place them behind authenticated ingress, "
        "disable anonymous access, and restrict source access with NetworkPolicy or firewall rules."
    )


def remediation_from_audit(obj):
    meta = obj.get("meta", {})
    results = obj.get("results", {}) or {}
    k8s = obj.get("kubernetes", {}) or {}
    rem = []
    ns = meta.get("namespace", "default")
    selector = meta.get("target_selector", "app=cua")

    def failed(section, key):
        val = section.get(key)
        return isinstance(val, dict) and val.get("ok") is False

    def passed(section, key):
        val = section.get(key)
        return isinstance(val, dict) and val.get("ok") is True

    def listener_open(section, key):
        val = section.get(key)
        if not isinstance(val, dict):
            return False
        evidence = str(val.get("evidence", ""))
        return "listener_open=True" in evidence

    if failed(results, "running_as_non_root"):
        rem.append(make_remediation_item(
            "RUN_AS_ROOT",
            "high",
            "Run workload as non-root",
            "Root execution increases post-compromise impact and expands the effect of container escape or filesystem abuse.",
            [
                "Set runAsNonRoot: true and a fixed non-zero runAsUser/runAsGroup.",
                "Ensure the image filesystem permissions support the non-root UID.",
                "Avoid sudo inside the image and remove unnecessary setuid binaries."
            ],
            yaml_block_pod_hardening(selector),
            ["Kubernetes securityContext", "Pod Security Standards"]
        ))

    if failed(results, "rootfs_readonly") or failed(k8s, "rootfs_readonly"):
        rem.append(make_remediation_item(
            "ROOTFS_RW",
            "high",
            "Mount the root filesystem read-only",
            "Writable root filesystems make persistence and tampering easier after compromise.",
            [
                "Set readOnlyRootFilesystem: true.",
                "Move writable paths to explicit emptyDir or persistent volumes.",
                "Validate startup scripts and temp directories still work after the change."
            ],
            yaml_block_pod_hardening(selector),
            ["Kubernetes securityContext"]
        ))

    if failed(results, "sensitive_paths_readonly"):
        rem.append(make_remediation_item(
            "SENSITIVE_PATHS_WRITABLE",
            "high",
            "Make sensitive filesystem paths read-only",
            "Writable system paths such as /etc or /usr make tampering and persistence easier after compromise.",
            [
                "Keep system directories on a read-only layer.",
                "Redirect legitimate writes into explicit writable volumes only.",
                "Validate package managers, startup scripts, and app temp paths after tightening mounts."
            ],
            yaml_block_pod_hardening(selector),
            ["Filesystem hardening", "Immutable infrastructure"]
        ))

    if failed(results, "setid_binaries_absent"):
        rem.append(make_remediation_item(
            "SETID_BINARIES_PRESENT",
            "medium",
            "Remove setuid/setgid binaries from the image",
            "Setuid and setgid binaries create extra privilege-escalation paths even when the container is otherwise hardened.",
            [
                "Remove unnecessary setuid/setgid binaries from the image.",
                "Prefer distroless or minimal base images where possible.",
                "Verify no operational tooling depends on privilege-granting helpers."
            ],
            "Rebuild the image without unnecessary setuid/setgid helpers.",
            ["Image hardening", "Least privilege"]
        ))

    if failed(k8s, "dangerous_caps_absent") or failed(k8s, "net_raw_absent"):
        rem.append(make_remediation_item(
            "LINUX_CAPS",
            "high",
            "Drop Linux capabilities to the minimum required set",
            "Capabilities such as CAP_NET_RAW or CAP_SYS_ADMIN increase kernel-facing attack surface and enable stronger in-cluster pivoting primitives.",
            [
                "Drop ALL capabilities by default.",
                "Re-add only narrowly required capabilities after validation.",
                "Prefer application changes over retaining CAP_NET_RAW or CAP_SYS_ADMIN."
            ],
            yaml_block_pod_hardening(selector),
            ["Linux capabilities", "Kubernetes securityContext"]
        ))

    if failed(k8s, "seccomp_enforced"):
        rem.append(make_remediation_item(
            "SECCOMP_DISABLED",
            "high",
            "Enable seccomp filtering",
            "Seccomp reduces syscall surface and limits the effect of application-level compromise on the host kernel boundary.",
            [
                "Set seccompProfile.type to RuntimeDefault at minimum.",
                "Use Localhost profiles for stricter workloads if validated.",
                "Test the runtime profile against the sandbox process tree before production rollout."
            ],
            yaml_block_pod_hardening(selector),
            ["seccomp", "Kubernetes RuntimeDefault"]
        ))

    if failed(k8s, "no_new_privs"):
        rem.append(make_remediation_item(
            "NO_NEW_PRIVS_DISABLED",
            "medium",
            "Disallow privilege escalation",
            "allowPrivilegeEscalation=false prevents gaining more privilege through setuid binaries or similar execution paths.",
            [
                "Set allowPrivilegeEscalation: false.",
                "Remove setuid/setgid binaries not required by the workload.",
                "Rebuild the image if privilege-granting tools are bundled by default."
            ],
            yaml_block_pod_hardening(selector),
            ["allowPrivilegeEscalation"]
        ))

    if failed(k8s, "sa_token_present") or failed(k8s, "sa_ca_present") or failed(k8s, "sa_namespace_present") or failed(k8s, "sa_mount_readonly"):
        rem.append(make_remediation_item(
            "SERVICE_ACCOUNT_TOKEN",
            "high",
            "Reduce service account token exposure",
            "Mounted service account tokens expand blast radius when a pod is compromised and should be disabled unless the workload truly needs Kubernetes API access.",
            [
                "Set automountServiceAccountToken: false for workloads that do not need the API.",
                "Use a dedicated least-privilege service account when API access is required.",
                "Keep token mounts read-only and review RBAC bindings."
            ],
            yaml_block_service_account(ns),
            ["ServiceAccount", "RBAC"]
        ))

    if failed(k8s, "imds_blocked") or failed(results, "cloud_imds_blocked"):
        rem.append(make_remediation_item(
            "IMDS_REACHABLE",
            "high",
            "Block cloud metadata access from the workload",
            "Instance metadata access can expose node or cloud credentials and materially increase post-compromise blast radius.",
            [
                "Block 169.254.169.254 and equivalent metadata endpoints with NetworkPolicy, node firewalling, or cloud-native metadata protections.",
                "Prefer workload identity over node-scoped credentials.",
                "Retest from the pod after controls are applied."
            ],
            yaml_block_networkpolicy(ns, selector),
            ["Cloud metadata service", "Workload identity"]
        ))

    if failed(k8s, "host_mounts_absent") or failed(results, "host_engine_sockets_absent"):
        rem.append(make_remediation_item(
            "HOST_EXPOSURE",
            "critical",
            "Remove hostPath mounts and engine sockets",
            "Host paths and container engine sockets can collapse isolation boundaries and often enable host-level compromise.",
            [
                "Remove docker.sock, containerd sockets, kubelet paths, and other hostPath mounts unless absolutely necessary.",
                "Replace direct host access with a narrowly scoped sidecar or API broker if operationally needed.",
                "Re-run the audit after removing privileged mounts."
            ],
            "Remove hostPath and engine socket mounts from the Pod spec; do not expose /var/run/docker.sock or /run/containerd/containerd.sock to the workload.",
            ["hostPath", "container runtime socket exposure"]
        ))

    if failed(results, "risky_device_nodes_absent"):
        rem.append(make_remediation_item(
            "RISKY_DEVICE_NODES",
            "critical",
            "Remove risky writable device node access",
            "Writable access to device nodes like /dev/kmsg or /dev/mem can collapse isolation and expose the host kernel boundary.",
            [
                "Do not mount or expose host device nodes into the workload.",
                "Use a stricter runtime/device policy and remove privileged device access.",
                "Re-run the audit to confirm the nodes are no longer accessible."
            ],
            "Remove risky device mounts and privileged device access from the workload spec.",
            ["Device isolation", "Privileged container hardening"]
        ))

    if listener_open(results, "novnc_http_local_6901"):
        rem.append(make_remediation_item(
            "NOVNC_LISTENER",
            "medium",
            "Review local noVNC exposure",
            "A local noVNC listener may be intentional, but it should be authenticated and not reachable from sibling pods unless explicitly required.",
            [
                "Disable the listener when desktop access is not needed.",
                "Require authentication and put it behind a controlled access path.",
                "Restrict access with NetworkPolicy or firewall rules."
            ],
            yaml_block_novnc_service_note(),
            ["noVNC", "VNC hardening"]
        ))

    classification = results.get("classification", "")
    if classification in ("remotely_reachable_from_pod_and_unauthenticated_vnc", "remotely_reachable_from_pod_but_password_required", "remotely_reachable_from_pod_partial_signals"):
        severity = "critical" if "unauthenticated" in classification else "high"
        rem.append(make_remediation_item(
            "REMOTE_REACHABILITY",
            severity,
            "Restrict pod-to-pod reachability to exposed sandbox services",
            "A service reachable from a sibling pod expands lateral movement opportunities and weakens containment.",
            [
                "Apply default-deny ingress and egress NetworkPolicy for the sandbox pod.",
                "Remove unnecessary Service objects and listeners.",
                "Place required UI/API endpoints behind authenticated gateways instead of direct pod exposure."
            ],
            yaml_block_networkpolicy(ns, selector),
            ["NetworkPolicy", "least privilege networking"]
        ))

    if not rem:
        rem.append(make_remediation_item(
            "NO_ACTIONABLE_FAILURES",
            "info",
            "No failed checks were mapped to a built-in remediation rule",
            "The remediation engine did not find a failed check it recognizes in this audit result.",
            [
                "Review raw evidence manually.",
                "Extend remediation_from_audit() with environment-specific rules.",
                "Keep the audit JSON for traceability."
            ],
            "",
            []
        ))

    severity_rank = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
    rem.sort(key=lambda x: severity_rank.get(x["severity"], 0), reverse=True)
    return {
        "count": len(rem),
        "items": rem,
        "templates": {
            "pod_hardening": yaml_block_pod_hardening(selector),
            "network_policy": yaml_block_networkpolicy(ns, selector),
            "service_account": yaml_block_service_account(ns),
        }
    }




# --------------------------- apply fixes ------------------------------------

def slugify_name(s):
    s = (s or "resource").lower()
    s = re.sub(r"[^a-z0-9.-]+", "-", s)
    s = re.sub(r"-{2,}", "-", s).strip("-.")
    return s or "resource"


def selector_to_matchlabels(selector):
    labels = {}
    for part in (selector or "").split(","):
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            k, v = part.split("=", 1)
            labels[k.strip()] = v.strip()
    if not labels:
        labels = {"app": "REPLACE_ME"}
    return labels


def get_service_ports_for_labels(ns, labels, timeout=30):
    ports = []
    if not has_kubectl() or not ns or not labels:
        return ports
    try:
        obj = kubectl_get_json(ns, 'services', extra_args='--ignore-not-found', timeout=timeout)
        for item in obj.get('items', []):
            selector = ((item.get('spec') or {}).get('selector') or {})
            if selector and all(labels.get(k) == v for k, v in selector.items()):
                svc_name = item.get('metadata', {}).get('name')
                for p in ((item.get('spec') or {}).get('ports') or []):
                    port = p.get('targetPort', p.get('port'))
                    if isinstance(port, int):
                        ports.append({'service': svc_name, 'port': port, 'protocol': (p.get('protocol') or 'TCP').upper()})
                    elif isinstance(p.get('port'), int):
                        ports.append({'service': svc_name, 'port': p.get('port'), 'protocol': (p.get('protocol') or 'TCP').upper()})
    except Exception:
        pass
    dedup = []
    seen = set()
    for entry in ports:
        key = (entry['service'], entry['port'], entry['protocol'])
        if key not in seen:
            seen.add(key)
            dedup.append(entry)
    return dedup


def get_kubernetes_api_cluster_ip(timeout=20):
    if not has_kubectl():
        return None
    try:
        obj = kubectl_get_json('default', 'service', 'kubernetes', timeout=timeout)
        return ((obj.get('spec') or {}).get('clusterIP') or None)
    except Exception:
        return None


def extract_listener_ports(audit_obj):
    listeners = []
    results = (audit_obj.get('results') or {})
    remote = (audit_obj.get('remote') or {})
    if results.get('novnc_http_local_6901', {}).get('ok'):
        listeners.append({'port': 6901, 'protocol': 'TCP', 'reason': 'noVNC local listener'})
    if results.get('vnc_rfb_greeting_5901', {}).get('ok'):
        listeners.append({'port': 5901, 'protocol': 'TCP', 'reason': 'VNC local listener'})
    scanned = results.get('scanned_ports') or remote.get('scanned_ports') or []
    for item in scanned:
        port = item.get('port')
        if item.get('reachable') and isinstance(port, int):
            listeners.append({'port': port, 'protocol': (item.get('protocol') or 'TCP').upper(), 'reason': 'remote probe reachable'})
    dedup = []
    seen = set()
    for entry in listeners:
        key = (entry['port'], entry['protocol'])
        if key not in seen:
            seen.add(key)
            dedup.append(entry)
    return dedup


def build_workload_aware_networkpolicy(ns, workload_name, labels, audit_obj, dependencies=None, timeout=30):
    dependencies = dependencies or {}
    policy_name = f"{workload_name}-least-privilege"
    service_ports = get_service_ports_for_labels(ns, labels, timeout=timeout)
    listener_ports = extract_listener_ports(audit_obj)
    ingress_ports = service_ports[:] if service_ports else []
    if not ingress_ports and (dependencies.get('services') or []):
        for lp in listener_ports:
            ingress_ports.append({'service': 'inferred', 'port': lp['port'], 'protocol': lp.get('protocol', 'TCP')})

    ingress_rules = []
    strategy_notes = []
    if ingress_ports:
        ingress_rules.append({
            'from': [{'namespaceSelector': {'matchLabels': {'kubernetes.io/metadata.name': ns}}}],
            'ports': [{'protocol': p.get('protocol', 'TCP'), 'port': p['port']} for p in ingress_ports if isinstance(p.get('port'), int)]
        })
        strategy_notes.append(
            'Ingress allowlist preserved namespace-local access only for ports selected by current Services or inferred reachable listeners.'
        )
    else:
        strategy_notes.append('Ingress remains default-deny because no Service-selected ports were discovered for this workload.')

    egress_rules = [
        {
            'to': [
                {
                    'namespaceSelector': {},
                    'podSelector': {'matchLabels': {'k8s-app': 'kube-dns'}},
                }
            ],
            'ports': [
                {'protocol': 'UDP', 'port': 53},
                {'protocol': 'TCP', 'port': 53},
            ],
        }
    ]
    strategy_notes.append('DNS egress is preserved for kube-dns.')

    api_ip = get_kubernetes_api_cluster_ip(timeout=timeout)
    kubernetes_ok = (((audit_obj.get('kubernetes') or {}).get('egress_api_tcp_443') or {}).get('ok') is True)
    if api_ip and kubernetes_ok:
        egress_rules.append({
            'to': [{'ipBlock': {'cidr': f'{api_ip}/32'}}],
            'ports': [{'protocol': 'TCP', 'port': 443}],
        })
        strategy_notes.append(f'Kubernetes API egress preserved to clusterIP {api_ip}/32 on TCP 443 because the workload currently reaches the API.')

    if (((audit_obj.get('kubernetes') or {}).get('imds_blocked') or {}).get('ok') is False) or (((audit_obj.get('results') or {}).get('cloud_imds_blocked') or {}).get('ok') is False):
        strategy_notes.append('No metadata egress allow rule was generated, so the resulting policy blocks IMDS by default.')

    np_obj = {
        'apiVersion': 'networking.k8s.io/v1',
        'kind': 'NetworkPolicy',
        'metadata': {'name': policy_name, 'namespace': ns},
        'spec': {
            'podSelector': {'matchLabels': labels},
            'policyTypes': ['Ingress', 'Egress'],
            'ingress': ingress_rules,
            'egress': egress_rules,
        },
    }
    return {
        'object': np_obj,
        'service_ports': service_ports,
        'listener_ports': listener_ports,
        'strategy_notes': strategy_notes,
    }


def infer_target_workload_name(meta):
    for key in ("workload_name", "target_pod", "name"):
        val = meta.get(key)
        if val:
            return slugify_name(val)
    selector = meta.get("target_selector", "")
    ml = selector_to_matchlabels(selector)
    if "app" in ml:
        return slugify_name(ml["app"])
    return "sandbox-target"


def dict_to_yaml(obj, indent=0):
    sp = " " * indent
    if isinstance(obj, dict):
        lines = []
        for k, v in obj.items():
            if isinstance(v, (dict, list)):
                lines.append(f"{sp}{k}:")
                lines.append(dict_to_yaml(v, indent + 2))
            else:
                if isinstance(v, bool):
                    sval = "true" if v else "false"
                elif v is None:
                    sval = "null"
                elif isinstance(v, (int, float)):
                    sval = str(v)
                else:
                    sval = json.dumps(str(v))
                lines.append(f"{sp}{k}: {sval}")
        return "\n".join(lines)
    if isinstance(obj, list):
        lines = []
        for item in obj:
            if isinstance(item, (dict, list)):
                lines.append(f"{sp}-")
                lines.append(dict_to_yaml(item, indent + 2))
            else:
                if isinstance(item, bool):
                    sval = "true" if item else "false"
                elif item is None:
                    sval = "null"
                elif isinstance(item, (int, float)):
                    sval = str(item)
                else:
                    sval = json.dumps(str(item))
                lines.append(f"{sp}- {sval}")
        return "\n".join(lines)
    return f"{sp}{json.dumps(obj)}"


def build_apply_fix_artifacts(audit_obj):
    meta = audit_obj.get("meta", {}) or {}
    remediation = audit_obj.get("remediation") or remediation_from_audit(audit_obj)
    ns = meta.get("namespace") or autodetect_namespace('default')
    selector = meta.get("target_selector", "")
    labels = (meta.get("selector_labels") or selector_to_matchlabels(selector) or {})
    workload_name = infer_target_workload_name(meta)
    workload_kind = (meta.get("workload_kind") or "deployment").lower()
    if workload_kind == 'replicaset':
        workload_kind = 'deployment'
    if workload_kind not in {'deployment','statefulset','daemonset'}:
        workload_kind = 'deployment'
    service_account_name = meta.get("service_account_name") or 'default'
    container_names = list(meta.get("container_names") or [])
    if not container_names and meta.get("target_pod") and has_kubectl():
        try:
            discovered = discover_workload_from_pod(ns, meta.get("target_pod"))
            container_names = discovered.get('container_names', [])
            if discovered.get('service_account_name'):
                service_account_name = discovered['service_account_name']
            if discovered.get('selector_labels'):
                labels = discovered['selector_labels']
        except Exception:
            pass
    if not labels:
        labels = {"app": workload_name}
    if not selector:
        selector = labels_to_selector(labels)

    containers_patch = []
    for cname in container_names or [workload_name]:
        containers_patch.append({
            "name": cname,
            "securityContext": {
                "runAsNonRoot": True,
                "runAsUser": 10001,
                "runAsGroup": 10001,
                "allowPrivilegeEscalation": False,
                "readOnlyRootFilesystem": True,
                "capabilities": {"drop": ["ALL"]},
                "seccompProfile": {"type": "RuntimeDefault"},
            },
        })

    patch_obj = {
        "spec": {
            "template": {
                "spec": {
                    "automountServiceAccountToken": False,
                    "containers": containers_patch,
                }
            }
        }
    }

    dependencies = meta.get('dependencies') or summarize_dependencies(ns, workload_name=workload_name, pod_name=meta.get('target_pod'), labels=labels)
    np_plan = build_workload_aware_networkpolicy(ns, workload_name, labels, audit_obj, dependencies=dependencies)
    np_obj = np_plan['object']

    sa_patch_obj = {"automountServiceAccountToken": False}

    deployment_patch_json = json.dumps(patch_obj, indent=2)
    serviceaccount_patch_json = json.dumps(sa_patch_obj, indent=2)
    networkpolicy_yaml = dict_to_yaml(np_obj)
    patch_min = json.dumps(patch_obj, separators=(",", ":"))
    sa_min = json.dumps(sa_patch_obj, separators=(",", ":"))

    commands = {
        "patch_workload": f"kubectl -n {shlex.quote(ns)} patch {shlex.quote(workload_kind)} {shlex.quote(workload_name)} --type strategic -p {shlex.quote(patch_min)}",
        "apply_networkpolicy": f"kubectl apply -f NETWORKPOLICY_FILE.yaml",
        "patch_serviceaccount": f"kubectl -n {shlex.quote(ns)} patch serviceaccount {shlex.quote(service_account_name)} --type merge -p {shlex.quote(sa_min)}",
    }

    return {
        "meta": {
            "namespace": ns,
            "selector": selector,
            "workload_name": workload_name,
            "workload_kind": workload_kind,
            "service_account_name": service_account_name,
            "container_names": container_names,
            "labels": labels,
            "dependencies": dependencies,
            "network_policy_strategy": {
                "service_ports": np_plan.get('service_ports', []),
                "listener_ports": np_plan.get('listener_ports', []),
                "notes": np_plan.get('strategy_notes', []),
            },
        },
        "artifacts": {
            "workload_patch_json": deployment_patch_json,
            "serviceaccount_patch_json": serviceaccount_patch_json,
            "networkpolicy_yaml": networkpolicy_yaml,
        },
        "commands": commands,
        "remediation_count": remediation.get("count", 0),
    }


def apply_fixes(audit_obj, namespace=None, workload=None, kind=None, apply_network_policy=False, patch_service_account=False, dry_run=True):
    artifacts = build_apply_fix_artifacts(audit_obj)
    ns = namespace or artifacts["meta"]["namespace"]
    workload_name = workload or artifacts["meta"]["workload_name"]
    kind = (kind or artifacts["meta"]["workload_kind"] or "deployment").lower()
    service_account_name = artifacts["meta"].get("service_account_name") or 'default'

    patch_min = json.dumps(json.loads(artifacts["artifacts"]["workload_patch_json"]), separators=(",", ":"))
    executed = []
    if kind not in {"deployment", "statefulset", "daemonset"}:
        raise ValueError("kind must be deployment, statefulset, or daemonset")

    patch_cmd = f"kubectl -n {shlex.quote(ns)} patch {shlex.quote(kind)} {shlex.quote(workload_name)} --type strategic -p {shlex.quote(patch_min)}"
    executed.append({"step": f"patch_{kind}", "command": patch_cmd, "applied": not dry_run})
    if not dry_run:
        rc, out = shell_rc(patch_cmd, timeout=120)
        executed[-1]["rc"] = rc
        executed[-1]["output"] = out.strip()

    if apply_network_policy:
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".yaml") as tf:
            tf.write(artifacts["artifacts"]["networkpolicy_yaml"])
            np_path = tf.name
        np_cmd = f"kubectl apply -f {shlex.quote(np_path)}"
        executed.append({"step": "apply_networkpolicy", "command": np_cmd, "applied": not dry_run, "file": np_path})
        if not dry_run:
            rc, out = shell_rc(np_cmd, timeout=120)
            executed[-1]["rc"] = rc
            executed[-1]["output"] = out.strip()

    if patch_service_account:
        sa_patch_min = json.dumps(json.loads(artifacts["artifacts"]["serviceaccount_patch_json"]), separators=(",", ":"))
        sa_cmd = f"kubectl -n {shlex.quote(ns)} patch serviceaccount {shlex.quote(service_account_name)} --type merge -p {shlex.quote(sa_patch_min)}"
        executed.append({"step": "patch_serviceaccount", "command": sa_cmd, "applied": not dry_run})
        if not dry_run:
            rc, out = shell_rc(sa_cmd, timeout=120)
            executed[-1]["rc"] = rc
            executed[-1]["output"] = out.strip()

    return {
        "meta": artifacts["meta"],
        "dry_run": dry_run,
        "executed": executed,
        "artifacts": artifacts["artifacts"],
    }



# --------------------------- interactive workflow ---------------------------

RISK_PROFILES = {
    "RUN_AS_ROOT": {
        "risk_level": "high",
        "auto_applicable": True,
        "group": "workload_patch",
        "risk_note": "Changing to non-root can break startup if the image expects root-owned paths or privileged binds.",
        "manual_recommendation": "Validate file ownership, writable paths, and startup scripts before rollout.",
    },
    "ROOTFS_RW": {
        "risk_level": "high",
        "auto_applicable": True,
        "group": "workload_patch",
        "risk_note": "Enabling readOnlyRootFilesystem can break workloads that write under /tmp, /var, /etc, or application paths.",
        "manual_recommendation": "Identify writable paths and move them to explicit volumes or emptyDir mounts first.",
    },
    "SENSITIVE_PATHS_WRITABLE": {
        "risk_level": "high",
        "auto_applicable": False,
        "group": "manual_only",
        "risk_note": "Writable system paths often imply image or mount layout changes that should be validated carefully.",
        "manual_recommendation": "Lock down writes to /etc, /usr, /bin, /sbin, and /root by moving legitimate writes into explicit writable mounts.",
    },
    "SETID_BINARIES_PRESENT": {
        "risk_level": "medium",
        "auto_applicable": False,
        "group": "manual_only",
        "risk_note": "Removing setuid/setgid binaries usually requires an image rebuild and validation of admin tooling expectations.",
        "manual_recommendation": "Rebuild the image on a minimal base and remove unnecessary setuid/setgid helpers.",
    },
    "LINUX_CAPS": {
        "risk_level": "medium",
        "auto_applicable": True,
        "group": "workload_patch",
        "risk_note": "Dropping all capabilities can break workloads that implicitly rely on raw sockets or privileged network operations.",
        "manual_recommendation": "Test with ALL dropped, then add back only the single capability proven to be required.",
    },
    "SECCOMP_DISABLED": {
        "risk_level": "medium",
        "auto_applicable": True,
        "group": "workload_patch",
        "risk_note": "RuntimeDefault seccomp can block uncommon syscalls used by desktop stacks, debuggers, or special runtimes.",
        "manual_recommendation": "Validate the workload under RuntimeDefault before enforcing in production.",
    },
    "NO_NEW_PRIVS_DISABLED": {
        "risk_level": "low",
        "auto_applicable": True,
        "group": "workload_patch",
        "risk_note": "Usually low risk, but it can affect images that still depend on setuid/setgid helpers.",
        "manual_recommendation": "Check whether the image depends on privilege-granting helpers and remove them where possible.",
    },
    "SERVICE_ACCOUNT_TOKEN": {
        "risk_level": "high",
        "auto_applicable": True,
        "group": "service_account",
        "risk_note": "Disabling token automount will break workloads that call the Kubernetes API from inside the pod.",
        "manual_recommendation": "Confirm whether the workload needs Kubernetes API access before disabling automount.",
    },
    "IMDS_REACHABLE": {
        "risk_level": "high",
        "auto_applicable": True,
        "group": "network_policy",
        "risk_note": "Blocking metadata endpoints can affect software that still relies on node credentials or metadata-based discovery.",
        "manual_recommendation": "Prefer workload identity and verify cloud SDK behavior after blocking metadata access.",
    },
    "REMOTE_REACHABILITY": {
        "risk_level": "high",
        "auto_applicable": True,
        "group": "network_policy",
        "risk_note": "Default-deny NetworkPolicy can block legitimate east-west traffic and required egress beyond DNS.",
        "manual_recommendation": "Inventory required ingress and egress first, then expand the policy gradually.",
    },
    "HOST_EXPOSURE": {
        "risk_level": "critical",
        "auto_applicable": False,
        "group": "manual_only",
        "risk_note": "Removing hostPath mounts or engine sockets can break architecture assumptions and operational tooling.",
        "manual_recommendation": "Refactor the design to avoid hostPath and runtime sockets. Do not auto-remove without workload review.",
    },
    "RISKY_DEVICE_NODES": {
        "risk_level": "critical",
        "auto_applicable": False,
        "group": "manual_only",
        "risk_note": "Writable access to host-like device nodes is a severe isolation issue and usually requires workload redesign.",
        "manual_recommendation": "Remove privileged device access and any mounts exposing host-sensitive device nodes.",
    },
    "NOVNC_LISTENER": {
        "risk_level": "medium",
        "auto_applicable": False,
        "group": "manual_only",
        "risk_note": "Disabling noVNC/VNC can remove a required management or UI function.",
        "manual_recommendation": "If desktop access is required, keep it but put it behind authentication and narrow network controls.",
    },
    "NO_ACTIONABLE_FAILURES": {
        "risk_level": "info",
        "auto_applicable": False,
        "group": "manual_only",
        "risk_note": "",
        "manual_recommendation": "Review the raw findings manually.",
    },
}

def enrich_remediation(remediation):
    items = []
    for item in remediation.get("items", []):
        prof = RISK_PROFILES.get(item.get("issue_id", ""), {})
        merged = dict(item)
        merged["risk_level"] = prof.get("risk_level", item.get("severity", "medium"))
        merged["auto_applicable"] = prof.get("auto_applicable", False)
        merged["fix_group"] = prof.get("group", "manual_only")
        merged["risk_note"] = prof.get("risk_note", "")
        merged["manual_recommendation"] = prof.get("manual_recommendation", "")
        items.append(merged)
    return {"count": len(items), "items": items, "templates": remediation.get("templates", {})}

def default_json_path(prefix):
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return output_path(f"{prefix}_{stamp}.json")


def safe_slug(value, default="resource"):
    text = re.sub(r"[^a-zA-Z0-9._-]+", "-", str(value or "").strip()).strip("-").lower()
    return text or default


OUTPUT_ROOT = os.environ.get("COMBINED_AUDIT_OUTPUT_DIR", "generated_outputs")


def ensure_output_root():
    path = Path(OUTPUT_ROOT)
    path.mkdir(parents=True, exist_ok=True)
    return path


def output_path(filename):
    return str(ensure_output_root() / filename)


def resource_json_path(prefix, namespace=None, workload_name=None):
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    parts = [prefix]
    if namespace:
        parts.append(safe_slug(namespace, "namespace"))
    if workload_name:
        parts.append(safe_slug(workload_name, "workload"))
    parts.append(stamp)
    return output_path("_".join(parts) + ".json")


def security_issue_summary(obj):
    remediation = obj.get('remediation') or {}
    items = actionable_remediation_items(remediation)
    severity_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
    for item in items:
        sev = (item.get('severity') or 'info').lower()
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
    return {
        'count': len(items),
        'severity_counts': severity_counts,
        'issue_ids': [item.get('issue_id') for item in items],
    }

def prompt(text, default=None):
    suffix = f" [{default}]" if default is not None else ""
    val = input(f"{text}{suffix}: ").strip()
    return val if val else (default if default is not None else "")

def prompt_choice(text, choices, default=None):
    choices_txt = "/".join(choices)
    while True:
        val = prompt(f"{text} ({choices_txt})", default=default)
        if val in choices:
            return val
        print(f"Enter one of: {choices_txt}")

def prompt_yes_no(text, default="y"):
    return prompt_choice(text, ["y", "n"], default=default) == "y"

def print_audit_summary(obj):
    print("\n=== Audit summary ===")
    sec = security_issue_summary(obj)
    print(f"Security issues: {sec.get('count', 0)}")
    assessment_status = get_nested(obj, 'meta', 'assessment_status')
    assessment_reason = get_nested(obj, 'meta', 'assessment_reason')
    if assessment_status:
        rendered = assessment_status.replace('_', ' ')
        if assessment_reason:
            print(f"Assessment status: {rendered} ({assessment_reason})")
        else:
            print(f"Assessment status: {rendered}")
    sev = sec.get('severity_counts') or {}
    sev_parts = [f"{name}={sev.get(name, 0)}" for name in ('critical', 'high', 'medium', 'low') if sev.get(name, 0)]
    if sev_parts:
        print(f"Severity mix: {', '.join(sev_parts)}")
    if "summary" in obj:
        s = obj["summary"]
        print(f"Validation checks: {s.get('passed', 0)}/{s.get('total', 0)} passed")
    internal = ((obj.get("results") or {}).get("internal_audit") or {})
    if isinstance(internal, dict) and internal.get("summary"):
        s = internal["summary"]
        print(f"Internal validation: {s.get('passed', 0)}/{s.get('total', 0)} passed")
    cls = (((obj.get("results") or {}).get("classification")) or "")
    if cls:
        print(f"Remote classification: {cls}")
    meta = obj.get("meta", {})
    for k in ("namespace", "target_selector", "target_pod", "target_ip"):
        if meta.get(k):
            print(f"{k}: {meta.get(k)}")

def print_remediation_summary(remediation):
    print("\n=== Proposed fixes ===")
    for idx, item in enumerate(remediation.get("items", []), start=1):
        auto = "auto" if item.get("auto_applicable") else "manual"
        print(f"{idx}. [{item.get('severity','').upper()}] {item.get('title')} ({auto}, risk={item.get('risk_level','')})")
        if item.get("rationale"):
            print(f"   Why: {item['rationale']}")
        if item.get("risk_note"):
            print(f"   Risk: {item['risk_note']}")
        if item.get("manual_recommendation"):
            print(f"   Manual note: {item['manual_recommendation']}")

def write_json_file(path_out, obj, label):
    with open(path_out, "w") as f:
        json.dump(obj, f, indent=2)
    print(f"{label}: {path_out}")

def run_selected_fix_groups(audit_obj, selected_items, namespace=None, workload=None, kind="deployment", execute=False):
    selected = [x for x in selected_items if x.get("auto_applicable") or x.get("base_auto_applicable")]
    groups = {x.get("fix_group") for x in selected}
    result = {
        "meta": {
            "namespace": namespace or audit_obj.get("meta", {}).get("namespace"),
            "workload": workload or infer_target_workload_name(audit_obj.get("meta", {})),
            "kind": kind,
            "executed_at": now_utc_iso(),
        },
        "selected_issue_ids": [x.get("issue_id") for x in selected_items],
        "per_issue": [],
        "apply_result": None,
    }
    if not selected:
        result["status"] = "no_change"
        for item in selected_items:
            result["per_issue"].append({
                "issue_id": item.get("issue_id"),
                "title": item.get("title"),
                "status": "manual_only" if not item.get("auto_applicable") else "skipped",
                "risk_level": item.get("risk_level"),
                "note": item.get("manual_recommendation") or item.get("risk_note") or "No change requested.",
            })
        return result

    apply_network_policy = "network_policy" in groups
    patch_service_account = "service_account" in groups
    patch_workload = "workload_patch" in groups

    if patch_workload or apply_network_policy or patch_service_account:
        apply_result = apply_fixes(
            audit_obj,
            namespace=namespace,
            workload=workload,
            kind=kind,
            apply_network_policy=apply_network_policy,
            patch_service_account=patch_service_account,
            dry_run=(not execute),
        )
        result["apply_result"] = apply_result

    result["status"] = "applied" if execute else "planned"
    for item in selected_items:
        if not item.get("auto_applicable"):
            status = "manual_only"
            note = item.get("manual_recommendation") or item.get("risk_note")
        elif item.get("fix_group") in groups:
            status = "applied" if execute else "planned"
            note = item.get("risk_note") or ""
        else:
            status = "skipped"
            note = "No change requested."
        result["per_issue"].append({
            "issue_id": item.get("issue_id"),
            "title": item.get("title"),
            "status": status,
            "risk_level": item.get("risk_level"),
            "note": note,
        })
    return result

def print_fix_result(result):
    print("\n=== Fix results ===")
    print(f"Overall status: {result.get('status')}")
    for item in result.get("per_issue", []):
        print(f"- {item.get('issue_id')}: {item.get('status')} ({item.get('risk_level')})")
        if item.get("note"):
            print(f"  {item.get('note')}")
    apply_result = result.get("apply_result")
    if apply_result:
        print("\nCommands / execution:")
        for step in apply_result.get("executed", []):
            print(f"* {step.get('step')}: {'executed' if step.get('applied') else 'planned'}")
            print(f"  {step.get('command')}")
            if step.get("output"):
                print(f"  output: {step.get('output')}")
        if apply_result.get('source_of_truth_manifest'):
            print(f"Source-of-truth manifest: {apply_result.get('source_of_truth_manifest')}")
        if apply_result.get('backup_bundle'):
            print(f"Backup bundle: {apply_result['backup_bundle'].get('directory')}")
            print(f"Backup manifest: {apply_result['backup_bundle'].get('manifest')}")
        if apply_result.get('rollback'):
            print("Rollback artifacts available for patched resources.")
        if apply_result.get('post_fix_revalidation') and not apply_result['post_fix_revalidation'].get('error'):
            score = apply_result['post_fix_revalidation'].get('risk_score') or compute_risk_score(apply_result['post_fix_revalidation'])
            if apply_result['post_fix_revalidation'].get('risk_score_unverified'):
                print(f"Post-fix risk score: {score.get('total')} ({score.get('band')}, unverified)")
            else:
                print(f"Post-fix risk score: {score.get('total')} ({score.get('band')})")

def interactive_wizard():
    print("Interactive combined sandbox audit")
    mode = prompt_choice("Where should the audit run", ["internal", "remote", "both"], default="both")
    action = prompt_choice("What do you want to do for the selected resource", ["analyze", "fix", "analyze+fix"], default="analyze+fix")
    timeout = float(prompt("Socket / probe timeout seconds", "2.0") or "2.0")
    audit_out = prompt("Audit output JSON file", default_json_path("audit"))
    fix_out = prompt("Fix output JSON file", default_json_path("fixes")) if action in ("fix", "analyze+fix") else None
    namespace = None
    selector = None
    selected_resource = None

    if mode in ("remote", "both"):
        namespace = prompt("Namespace", autodetect_namespace('default'))
        resources = list_candidate_resources(namespace, timeout=30)
        print_resource_list(resources)
        selected_resource = prompt_resource_selection(resources)
        selector = selected_resource.get('selector') or labels_to_selector(selected_resource.get('selector_labels') or {})
        print(f"\nSelected: {selected_resource.get('workload_kind')}/{selected_resource.get('workload_name')} (selector={selector})")
    else:
        selected_resource = {
            'namespace': autodetect_namespace('default'),
            'workload_kind': 'CurrentPod',
            'workload_name': platform.node() or 'current',
            'pod_name': platform.node() or 'current',
            'service_account_name': os.environ.get('SERVICE_ACCOUNT', 'unknown'),
            'container_names': [],
            'selector': 'n/a',
        }
        print_resource_list([selected_resource], title='Current execution resource')
        _ = prompt_resource_selection([selected_resource])

    if mode == "internal":
        audit_obj = collect_internal(timeout=timeout)
    elif mode == "remote":
        audit_obj = collect_remote(namespace, selector, timeout=timeout, include_introspection=True, include_internal_audit=False)
    else:
        audit_obj = collect_remote(namespace, selector, timeout=timeout, include_introspection=True, include_internal_audit=True)

    audit_obj["remediation"] = enrich_remediation(audit_obj.get("remediation") or remediation_from_audit(audit_obj))
    if selected_resource and mode in ("remote", "both"):
        audit_obj.setdefault('meta', {})['selected_resource'] = selected_resource
    print_audit_summary(audit_obj)
    print_remediation_summary(audit_obj["remediation"])
    write_json_file(audit_out, audit_obj, "Audit JSON written")

    if action == 'analyze':
        return

    items = audit_obj.get('remediation', {}).get('items', [])
    if not items:
        fix_result = {
            'status': 'no_change',
            'reason': 'no_fixable_findings',
            'executed_at': now_utc_iso(),
            'per_issue': [],
        }
        print_fix_result(fix_result)
        write_json_file(fix_out, fix_result, 'Fix JSON written')
        return

    if mode == 'internal':
        fix_result = {
            'status': 'no_change',
            'reason': 'internal_mode_manual_recommendation_only',
            'executed_at': now_utc_iso(),
            'per_issue': [
                {
                    'issue_id': item.get('issue_id'),
                    'title': item.get('title'),
                    'status': 'manual_only',
                    'risk_level': item.get('risk_level'),
                    'note': item.get('manual_recommendation') or item.get('risk_note'),
                } for item in items
            ],
        }
        print_fix_result(fix_result)
        write_json_file(fix_out, fix_result, 'Fix JSON written')
        return

    fix_mode = prompt_choice('Apply fixes all at once or separately or none', ['all', 'separate', 'none'], default='separate')
    execute = prompt_yes_no('Execute the selected auto-applicable fixes now', default='n')
    selected_items = []

    if fix_mode == 'none':
        selected_items = []
    elif fix_mode == 'all':
        selected_items = items
    else:
        print("\nSelect which fixes to implement one by one:")
        for idx, item in enumerate(items, start=1):
            auto = 'auto' if item.get('auto_applicable') else 'manual'
            risk = item.get('risk_level', '')
            ans = prompt_yes_no(f"Apply {idx}. {item.get('title')} [{auto}, risk={risk}]", default='n' if risk in ('high','critical') else 'y')
            if ans:
                selected_items.append(item)

    fix_result = run_selected_fix_groups(
        audit_obj,
        selected_items,
        namespace=namespace,
        workload=(selected_resource or {}).get('workload_name'),
        kind=((selected_resource or {}).get('workload_kind') or 'Deployment').lower(),
        execute=execute,
    )
    print_fix_result(fix_result)
    write_json_file(fix_out, fix_result, 'Fix JSON written')


def auto_run(timeout=2.0, apply_safe_fixes=True, execute=False, aggressive_execute=False, audit_out=None, fix_out=None):
    mode = autodetect_mode()
    audit_out = audit_out or default_json_path('audit')
    fix_out = fix_out or default_json_path('fixes')
    namespace = None
    selector = None
    discovered = None
    if mode in ('remote', 'both'):
        namespace = autodetect_namespace('default')
        discovered = autodiscover_remote_target(namespace)
        selector = discovered.get('selector') or labels_to_selector(discovered.get('selector_labels') or {})
        if not selector:
            raise RuntimeError('Auto-discovery could not determine target selector')
    if mode == 'internal':
        audit_obj = collect_internal(timeout=timeout)
    elif mode == 'remote':
        audit_obj = collect_remote(namespace, selector, timeout=timeout, include_introspection=True, include_internal_audit=False)
    else:
        audit_obj = collect_remote(namespace, selector, timeout=timeout, include_introspection=True, include_internal_audit=True)
    audit_obj['remediation'] = enrich_remediation(audit_obj.get('remediation') or remediation_from_audit(audit_obj))
    print_audit_summary(audit_obj)
    print_remediation_summary(audit_obj['remediation'])
    write_json_file(audit_out, audit_obj, 'Audit JSON written')

    items = audit_obj['remediation'].get('items', [])
    if mode == 'internal':
        fix_result = {
            'status': 'no_change',
            'reason': 'internal_mode_manual_recommendation_only',
            'executed_at': now_utc_iso(),
            'per_issue': [
                {
                    'issue_id': item.get('issue_id'),
                    'title': item.get('title'),
                    'status': 'manual_only',
                    'risk_level': item.get('risk_level'),
                    'note': item.get('manual_recommendation') or item.get('risk_note'),
                } for item in items
            ],
        }
    else:
        selected_items = []
        for item in items:
            if not item.get('auto_applicable'):
                selected_items.append(item)
                continue
            if item.get('risk_level') in ('critical', 'high'):
                selected_items.append(dict(item, auto_applicable=False, fix_group='manual_only'))
            elif apply_safe_fixes:
                selected_items.append(item)
        fix_result = run_selected_fix_groups(
            audit_obj,
            selected_items,
            namespace=namespace,
            workload=(audit_obj.get('meta', {}) or {}).get('workload_name'),
            kind=(audit_obj.get('meta', {}) or {}).get('workload_kind') or 'deployment',
            execute=execute,
        )
        fix_result['automation_mode'] = {
            'apply_safe_fixes': apply_safe_fixes,
            'execute': execute,
            'risky_fixes_left_manual': True,
        }
    print_fix_result(fix_result)
    write_json_file(fix_out, fix_result, 'Fix JSON written')
    return {'audit': audit_obj, 'fix': fix_result}

# --------------------------- cli --------------------------------------------

def write_or_print(obj, out_path=None, stdout_json=False):
    if out_path:
        with open(out_path, "w") as f:
            json.dump(obj, f, indent=2)
        print(f"Wrote {out_path}")
    if stdout_json or not out_path:
        print(json.dumps(obj, indent=2))


def main():
    if len(sys.argv) == 1:
        interactive_wizard()
        return

    ap = argparse.ArgumentParser(description="Combined internal + remote sandbox audit")
    sub = ap.add_subparsers(dest="mode", required=True)

    ap_internal = sub.add_parser("internal", help="Run inside the target pod")
    ap_internal.add_argument("--out", help="Output JSON file")
    ap_internal.add_argument("--timeout", type=float, default=2.0)
    ap_internal.add_argument("--stdout-json", action="store_true", help="Print JSON to stdout")

    ap_remote = sub.add_parser("remote", help="Run remote audit from kubectl host")
    ap_remote.add_argument("-n", "--namespace", default="cua")
    ap_remote.add_argument("--target-selector", default="app=cua")
    ap_remote.add_argument("--out", help="Output JSON file")
    ap_remote.add_argument("--timeout", type=float, default=2.0)
    ap_remote.add_argument("--no-introspection", action="store_true")
    ap_remote.add_argument("--stdout-json", action="store_true", help="Print JSON to stdout")

    ap_both = sub.add_parser("both", help="Run remote audit and invoke internal audit in the target pod")
    ap_both.add_argument("-n", "--namespace", default="cua")
    ap_both.add_argument("--target-selector", default="app=cua")
    ap_both.add_argument("--out", help="Output JSON file")
    ap_both.add_argument("--timeout", type=float, default=2.0)
    ap_both.add_argument("--no-introspection", action="store_true")
    ap_both.add_argument("--stdout-json", action="store_true", help="Print JSON to stdout")

    ap_remediate = sub.add_parser("remediate", help="Generate remediation guidance from an existing audit JSON")
    ap_remediate.add_argument("--input", required=True, help="Path to existing audit JSON")
    ap_remediate.add_argument("--out", help="Output JSON file")
    ap_remediate.add_argument("--stdout-json", action="store_true", help="Print JSON to stdout")

    ap_rollback = sub.add_parser("rollback-bundle", help="Strictly restore resources from a saved rollback bundle and verify normalized equality")
    ap_rollback.add_argument("--bundle-dir", required=True, help="Rollback bundle directory containing backup_manifest.json")
    ap_rollback.add_argument("--out", help="Output JSON file")
    ap_rollback.add_argument("--stdout-json", action="store_true", help="Print JSON to stdout")

    ap_auto = sub.add_parser("auto", help="Fully automatic audit and safe-fix planning or execution")
    ap_auto.add_argument("--timeout", type=float, default=2.0)
    ap_auto.add_argument("--audit-out", help="Audit JSON file")
    ap_auto.add_argument("--fix-out", help="Fix-result JSON file")
    ap_auto.add_argument("--no-apply-safe-fixes", action="store_true", help="Do not auto-select safe low/medium fixes")
    ap_auto.add_argument("--execute", action="store_true", help="Actually execute safe fixes instead of planning them")
    ap_auto.add_argument("--aggressive-execute", action="store_true", help="Apply all patchable fixes, including conditional-approval items, with mandatory backup and rollback artifacts")

    ap_apply = sub.add_parser("apply-fix", help="Generate or apply kubectl patches from audit findings")
    ap_apply.add_argument("--input", required=True, help="Path to existing audit JSON")
    ap_apply.add_argument("--out", help="Output JSON file")
    ap_apply.add_argument("--stdout-json", action="store_true", help="Print JSON to stdout")
    ap_apply.add_argument("-n", "--namespace", help="Override namespace")
    ap_apply.add_argument("--workload", help="Deployment/StatefulSet/DaemonSet name to patch")
    ap_apply.add_argument("--kind", default="deployment", choices=["deployment", "statefulset", "daemonset"])
    ap_apply.add_argument("--apply-network-policy", action="store_true", help="Include kubectl apply for generated NetworkPolicy")
    ap_apply.add_argument("--patch-service-account", action="store_true", help="Patch sandbox-sa to disable automount token")
    ap_apply.add_argument("--execute", action="store_true", help="Actually run kubectl patch/apply commands instead of dry-run output")

    args = ap.parse_args()

    if args.mode == "internal":
        obj = collect_internal(timeout=args.timeout)
        obj["remediation"] = enrich_remediation(obj.get("remediation") or remediation_from_audit(obj))
        write_or_print(obj, out_path=args.out, stdout_json=args.stdout_json)
        return

    if args.mode == "remote":
        obj = collect_remote(
            ns=args.namespace,
            selector=args.target_selector,
            timeout=args.timeout,
            include_introspection=(not args.no_introspection),
            include_internal_audit=False,
        )
        obj["remediation"] = enrich_remediation(obj.get("remediation") or remediation_from_audit(obj))
        write_or_print(obj, out_path=args.out, stdout_json=args.stdout_json)
        return

    if args.mode == "both":
        obj = collect_remote(
            ns=args.namespace,
            selector=args.target_selector,
            timeout=args.timeout,
            include_introspection=(not args.no_introspection),
            include_internal_audit=True,
        )
        obj["remediation"] = enrich_remediation(obj.get("remediation") or remediation_from_audit(obj))
        write_or_print(obj, out_path=args.out, stdout_json=args.stdout_json)
        return

    if args.mode == "remediate":
        with open(args.input, "r") as f:
            obj = json.load(f)
        out = {
            "meta": obj.get("meta", {}),
            "remediation": enrich_remediation(obj.get("remediation") or remediation_from_audit(obj)),
        }
        write_or_print(out, out_path=args.out, stdout_json=args.stdout_json)
        return

    if args.mode == "rollback-bundle":
        out = strict_rollback_bundle(args.bundle_dir)
        write_or_print(out, out_path=args.out, stdout_json=args.stdout_json)
        return

    if args.mode == "auto":
        auto_run(
            timeout=args.timeout,
            apply_safe_fixes=(not args.no_apply_safe_fixes),
            execute=args.execute,
            aggressive_execute=args.aggressive_execute,
            audit_out=args.audit_out,
            fix_out=args.fix_out,
        )
        return

    if args.mode == "apply-fix":
        with open(args.input, "r") as f:
            obj = json.load(f)
        out = apply_fixes(
            obj,
            namespace=args.namespace,
            workload=args.workload,
            kind=args.kind,
            apply_network_policy=args.apply_network_policy,
            patch_service_account=args.patch_service_account,
            dry_run=(not args.execute),
        )
        write_or_print(out, out_path=args.out, stdout_json=args.stdout_json)
        return


# ---------------- enhanced recommendations layer ----------------
SEVERITY_TO_NUM = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def collect_evidence(section_name, section):
    out = []
    for k, v in (section or {}).items():
        if isinstance(v, dict) and 'ok' in v:
            out.append({
                'section': section_name,
                'check_id': k,
                'ok': v.get('ok'),
                'evidence': v.get('evidence', ''),
                'timestamp_utc': now_utc_iso(),
            })
    return out


def merge_remediation_items(primary_items, secondary_items):
    merged = []
    seen = set()
    for item in (primary_items or []) + (secondary_items or []):
        if not isinstance(item, dict):
            continue
        key = (item.get('issue_id'), item.get('title'))
        if key in seen:
            continue
        seen.add(key)
        merged.append(item)
    return merged


def actionable_remediation_items(remediation):
    items = ((remediation or {}).get('items') or [])
    return [item for item in items if item.get('issue_id') != 'NO_ACTIONABLE_FAILURES']


def promote_internal_audit_findings(audit_obj):
    audit_obj = dict(audit_obj or {})
    internal_audit = ((audit_obj.get('results') or {}).get('internal_audit') or {})
    if not isinstance(internal_audit, dict):
        return audit_obj
    top_items = actionable_remediation_items(audit_obj.get('remediation'))
    internal_items = actionable_remediation_items(internal_audit.get('remediation'))
    if internal_items:
        merged_items = merge_remediation_items(top_items, internal_items)
        templates = {}
        templates.update((audit_obj.get('remediation') or {}).get('templates', {}) or {})
        templates.update((internal_audit.get('remediation') or {}).get('templates', {}) or {})
        audit_obj['remediation'] = {'count': len(merged_items), 'items': merged_items, 'templates': templates}
        audit_obj['risk_score'] = compute_risk_score(audit_obj)
        if internal_audit.get('risk_score', {}).get('total', 0) > audit_obj['risk_score'].get('total', 0):
            audit_obj['risk_score'] = internal_audit['risk_score']
    evidence = list(audit_obj.get('evidence') or [])
    evidence.extend(internal_audit.get('evidence', []))
    if evidence:
        audit_obj['evidence'] = evidence
    return audit_obj


def apply_spec_fallback_if_needed(audit_obj):
    audit_obj = copy.deepcopy(audit_obj or {})
    internal_audit = ((audit_obj.get('results') or {}).get('internal_audit') or {})
    internal_error = internal_audit.get('error') if isinstance(internal_audit, dict) else None
    if not internal_error:
        return audit_obj
    fallback_errors = {
        'internal_exec_parse_failed',
        'no_python_in_target_pod',
        'no_shell_in_target_pod',
        'internal_exec_failed',
    }
    if internal_error not in fallback_errors and 'internal_exec' not in str(internal_error):
        return audit_obj
    fallback = build_spec_fallback_revalidation(audit_obj, audit_obj)
    fallback.setdefault('meta', {})['assessment_status'] = 'partially_verified'
    fallback['meta']['assessment_reason'] = internal_error
    return fallback


def reconcile_spec_backed_findings(audit_obj):
    audit_obj = copy.deepcopy(audit_obj or {})
    internal_audit = ((audit_obj.get('results') or {}).get('internal_audit') or {})
    if not isinstance(internal_audit, dict) or internal_audit.get('error'):
        return audit_obj
    try:
        fallback = build_spec_fallback_revalidation(audit_obj, audit_obj)
    except Exception:
        return audit_obj
    current_items = actionable_remediation_items(audit_obj.get('remediation'))
    fallback_items = actionable_remediation_items(fallback.get('remediation'))
    meta = audit_obj.get('meta') or {}
    recent_unverifiable = recent_unverifiable_issue_items(meta.get('namespace'), meta.get('workload_name'))
    if not current_items and not fallback_items and not recent_unverifiable:
        return audit_obj

    spec_backed_issue_ids = {
        'SERVICE_ACCOUNT_TOKEN',
        'ROOTFS_RW',
        'SECCOMP_DISABLED',
        'NO_NEW_PRIVS_DISABLED',
        'RUN_AS_ROOT',
        'LINUX_CAPS',
    }
    fallback_map = {item.get('issue_id'): copy.deepcopy(item) for item in fallback_items if item.get('issue_id')}
    merged = []
    seen = set()
    for item in current_items:
        issue_id = item.get('issue_id')
        if not issue_id or issue_id in seen:
            continue
        seen.add(issue_id)
        if issue_id in spec_backed_issue_ids:
            if issue_id in fallback_map:
                merged.append(copy.deepcopy(fallback_map[issue_id]))
            continue
        merged.append(copy.deepcopy(item))
    for issue_id, item in fallback_map.items():
        if issue_id in spec_backed_issue_ids and issue_id not in seen:
            merged.append(copy.deepcopy(item))
    for item in recent_unverifiable:
        issue_id = item.get('issue_id')
        if issue_id and issue_id not in seen:
            seen.add(issue_id)
            merged.append(copy.deepcopy(item))

    if any((item.get('issue_id') or '') != 'NO_ACTIONABLE_FAILURES' for item in merged):
        merged = [item for item in merged if (item.get('issue_id') or '') != 'NO_ACTIONABLE_FAILURES']

    templates = {}
    templates.update((audit_obj.get('remediation') or {}).get('templates', {}) or {})
    templates.update((fallback.get('remediation') or {}).get('templates', {}) or {})
    audit_obj['remediation'] = {'count': len(merged), 'items': merged, 'templates': templates}
    audit_obj['risk_score'] = compute_risk_score(audit_obj)
    audit_obj.setdefault('controller', {})['spec_reconciliation'] = {
        'status': 'applied',
        'reason': 'spec_backed_checks_reconciled',
    }
    return audit_obj


def recent_unverifiable_issue_items(namespace, workload_name, limit=20):
    if not namespace or not workload_name:
        return []
    patterns = [
        f"guided_analyze_audit_{safe_slug(namespace, 'namespace')}_{safe_slug(workload_name, 'workload')}_*.json",
        f"guided_remediation_audit_{safe_slug(namespace, 'namespace')}_{safe_slug(workload_name, 'workload')}_*.json",
    ]
    files = []
    root = ensure_output_root()
    for pattern in patterns:
        files.extend(sorted(root.glob(pattern), reverse=True))
    seen = set()
    carry_ids = {'SETID_BINARIES_PRESENT', 'SENSITIVE_PATHS_WRITABLE', 'RISKY_DEVICE_NODES'}
    carried = []
    for path in files[:limit]:
        try:
            obj = json.loads(Path(path).read_text())
        except Exception:
            continue
        for item in (((obj.get('remediation') or {}).get('items') or [])):
            issue_id = item.get('issue_id')
            if issue_id in carry_ids and issue_id not in seen:
                seen.add(issue_id)
                carried.append(copy.deepcopy(item))
    return carried


def get_nested(obj, *path):
    cur = obj
    for part in path:
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def summarize_dependencies(ns, workload_name=None, pod_name=None, labels=None, timeout=30):
    deps = {
        'services': [], 'ingresses': [], 'network_policies': [], 'hpas': [], 'pdbs': [],
        'configmaps': [], 'secrets': [], 'runtime_class': None, 'node_selector': {}, 'volumes': []
    }
    if not has_kubectl() or not ns:
        return deps
    labels = labels or {}
    if workload_name:
        for kind in ('deployment', 'statefulset', 'daemonset'):
            rc, out = shell_rc(f"kubectl -n {shlex.quote(ns)} get {kind} {shlex.quote(workload_name)} -o json", timeout=timeout)
            if rc == 0:
                try:
                    obj = json.loads(out)
                    spec = (((obj.get('spec') or {}).get('template') or {}).get('spec') or {})
                    deps['runtime_class'] = spec.get('runtimeClassName')
                    deps['node_selector'] = spec.get('nodeSelector') or {}
                    deps['volumes'] = spec.get('volumes') or []
                    for vol in deps['volumes']:
                        if vol.get('configMap'):
                            deps['configmaps'].append(vol['configMap'].get('name'))
                        if vol.get('secret'):
                            deps['secrets'].append(vol['secret'].get('secretName'))
                except Exception:
                    pass
                break
    for resource, key in [('services', 'services'), ('networkpolicy', 'network_policies'), ('ingress', 'ingresses'), ('hpa', 'hpas'), ('pdb', 'pdbs')]:
        try:
            obj = kubectl_get_json(ns, resource, extra_args='--ignore-not-found', timeout=timeout)
            for item in obj.get('items', []):
                name = item.get('metadata', {}).get('name')
                if resource == 'services':
                    selector = ((item.get('spec') or {}).get('selector') or {})
                    if selector and all(labels.get(k) == v for k, v in selector.items()):
                        deps[key].append(name)
                elif resource == 'networkpolicy':
                    ml = (((item.get('spec') or {}).get('podSelector') or {}).get('matchLabels') or {})
                    if (not ml) or all(labels.get(k) == v for k, v in ml.items()):
                        deps[key].append(name)
                else:
                    deps[key].append(name)
        except Exception:
            pass
    deps['configmaps'] = sorted(set([x for x in deps['configmaps'] if x]))
    deps['secrets'] = sorted(set([x for x in deps['secrets'] if x]))
    return deps


def compute_risk_score(audit_obj):
    rem = ((audit_obj.get('remediation') or {}).get('items') or [])
    weights = {
        'RUN_AS_ROOT': (2,2), 'ROOTFS_RW': (2,2), 'LINUX_CAPS': (2,2), 'SECCOMP_DISABLED': (1,1),
        'NO_NEW_PRIVS_DISABLED': (1,1), 'SERVICE_ACCOUNT_TOKEN': (2,2), 'IMDS_REACHABLE': (2,3),
        'HOST_EXPOSURE': (3,3), 'NOVNC_LISTENER': (1,1), 'REMOTE_REACHABILITY': (3,3),
        'SENSITIVE_PATHS_WRITABLE': (2,2), 'SETID_BINARIES_PRESENT': (1,1), 'RISKY_DEVICE_NODES': (3,3),
    }
    p = b = 0
    contributions = []
    for item in rem:
        sev = SEVERITY_TO_NUM.get(item.get('severity', 'low'), 1)
        wp, wb = weights.get(item.get('issue_id'), (0, 0))
        cp = min(5, wp + max(0, sev - 1) // 2)
        cb = min(5, wb + max(0, sev - 1) // 2)
        p += cp
        b += cb
        contributions.append({'issue_id': item.get('issue_id'), 'severity': item.get('severity'), 'P': cp, 'B': cb, 'title': item.get('title')})
    total = p + b
    band = 'low'
    if total >= 18:
        band = 'critical'
    elif total >= 12:
        band = 'high'
    elif total >= 6:
        band = 'medium'
    return {'probability': p, 'blast_radius': b, 'total': total, 'band': band, 'contributions': contributions}


def compatibility_assessment(audit_obj):
    res = audit_obj.get('results', {}) or {}
    meta = audit_obj.get('meta', {}) or {}
    notes = []
    if res.get('running_as_non_root', {}).get('ok') is False:
        notes.append({'issue_id': 'RUN_AS_ROOT', 'risk': 'high', 'message': 'Container runs as root; forcing non-root may fail if file ownership and entrypoint assumptions are not updated.'})
    if res.get('rootfs_readonly', {}).get('ok') is False or ((audit_obj.get('kubernetes') or {}).get('rootfs_readonly', {}) or {}).get('ok') is False:
        notes.append({'issue_id': 'ROOTFS_RW', 'risk': 'high', 'message': 'Writable root filesystem detected; validate /tmp, /var/tmp, and application workspace writes before enabling read-only rootfs.'})
    if 'listener_open=True' in str((res.get('novnc_http_local_6901') or {}).get('evidence', '')) or any(x.get('port') == 6901 and x.get('reachable') for x in res.get('scanned_ports', [])):
        notes.append({'issue_id': 'NOVNC_LISTENER', 'risk': 'medium', 'message': 'Port 6901 appears active; removing exposure may impact a required desktop/UI path.'})
    if 'listener_open=True' in str((res.get('vnc_rfb_greeting_5901') or {}).get('evidence', '')) or any(x.get('port') == 5901 and x.get('reachable') for x in res.get('scanned_ports', [])):
        notes.append({'issue_id': 'NOVNC_LISTENER', 'risk': 'medium', 'message': 'Port 5901 appears active; hardening may be safer than removal if desktop access is intentional.'})
    if (meta.get('dependencies') or {}).get('services'):
        notes.append({'issue_id': 'REMOTE_REACHABILITY', 'risk': 'high', 'message': f"Services select this workload: {', '.join(meta['dependencies']['services'])}. Default-deny policy may block expected traffic."})
    return notes


def markdown_report(audit_obj, fix_result=None):
    audit_obj = audit_obj or {}
    fix_result = fix_result or None
    meta = (audit_obj.get('meta', {}) or {}).copy()
    if fix_result and not meta:
        apply_meta = ((fix_result.get('apply_result') or {}).get('meta') or {})
        fix_meta = (fix_result.get('meta') or {})
        meta = {
            'namespace': apply_meta.get('namespace') or fix_meta.get('namespace'),
            'workload_kind': apply_meta.get('workload_kind') or fix_meta.get('kind'),
            'workload_name': apply_meta.get('workload_name') or fix_meta.get('workload'),
            'dependencies': apply_meta.get('dependencies') or {},
        }
    score = audit_obj.get('risk_score') or compute_risk_score(audit_obj)
    if fix_result:
        post_revalidated = ((fix_result.get('apply_result') or {}).get('post_fix_revalidation') or {})
        post_score = post_revalidated.get('risk_score')
        if post_score:
            score = post_score
    lines = [
        '# Sandbox Audit Report', '',
        f"- Generated: {now_utc_iso()}",
        f"- Namespace: {meta.get('namespace', 'n/a')}",
        f"- Workload: {meta.get('workload_kind', '')}/{meta.get('workload_name', '')}",
        f"- Risk score: {score.get('total')} ({score.get('band')})", ''
    ]
    lines.append('## Findings')
    for item in ((audit_obj.get('remediation') or {}).get('items') or []):
        lines.append(f"- **{item.get('issue_id')}** [{item.get('severity')}] {item.get('title')}")
    lines.append('')
    lines.append('## Dependencies')
    for k, v in (meta.get('dependencies') or {}).items():
        if isinstance(v, list):
            rendered = ', '.join(x if isinstance(x, str) else json.dumps(x, sort_keys=True) for x in v) if v else 'none'
            lines.append(f"- {k}: {rendered}")
        else:
            lines.append(f"- {k}: {v}")
    if fix_result:
        lines.extend(['', '## Fix result', f"- Status: {fix_result.get('status')}"])
        for item in fix_result.get('per_issue', []):
            lines.append(f"- {item.get('issue_id')}: {item.get('status')}")
        post_revalidated = ((fix_result.get('apply_result') or {}).get('post_fix_revalidation') or {})
        post_score = post_revalidated.get('risk_score')
        if post_score:
            suffix = ' (partially verified)' if post_revalidated.get('risk_score_unverified') else ''
            lines.append(f"- Post-remediation risk score: {post_score.get('total')} ({post_score.get('band')}){suffix}")
    advisor = audit_obj.get('ai_advisor') or {}
    if advisor.get('status') == 'ok':
        lines.extend(['', '## AI Advisor'])
        if advisor.get('guided_operator_message'):
            lines.append(f"- Guided message: {advisor.get('guided_operator_message')}")
        if advisor.get('executive_summary'):
            lines.append(f"- Executive summary: {advisor.get('executive_summary')}")
        if advisor.get('remediation_overview'):
            lines.append(f"- Remediation overview: {advisor.get('remediation_overview')}")
        groups = advisor.get('prioritized_groups') or []
        if groups:
            lines.extend(['', '### Prioritized roadmap'])
            for group in groups:
                lines.append(f"- {group.get('title')} [{group.get('priority')}]: {group.get('rationale')}")
                if group.get('issue_ids'):
                    lines.append(f"  Issues: {', '.join(group.get('issue_ids') or [])}")
        item_advice = advisor.get('item_advice') or []
        if item_advice:
            lines.extend(['', '### Item guidance'])
            for item in item_advice[:8]:
                lines.append(f"- {item.get('issue_id')}: {item.get('explanation')}")
        for warning in (advisor.get('warnings') or [])[:5]:
            lines.append(f"- Warning: {warning}")
    return '\n'.join(lines) + '\n'


def generate_admission_policies(labels):
    kyverno = """apiVersion: kyverno.io/v1
kind: ClusterPolicy
metadata:
  name: sandbox-restricted
spec:
  validationFailureAction: Audit
  rules:
  - name: require-restricted-security-context
    match:
      resources:
        kinds:
        - Pod
    validate:
      message: Enforce restricted securityContext for sandbox workloads.
      pattern:
        spec:
          containers:
          - securityContext:
              allowPrivilegeEscalation: false
              readOnlyRootFilesystem: true
              seccompProfile:
                type: RuntimeDefault
"""
    gatekeeper = """apiVersion: templates.gatekeeper.sh/v1beta1
kind: ConstraintTemplate
metadata:
  name: k8srequiredsandboxsecurity
spec:
  crd:
    spec:
      names:
        kind: K8sRequiredSandboxSecurity
  targets:
  - target: admission.k8s.gatekeeper.sh
    rego: |
      package k8srequiredsandboxsecurity
      violation[{\"msg\": msg}] {
        input.review.kind.kind == \"Pod\"
        not input.review.object.spec.containers[_].securityContext.readOnlyRootFilesystem
        msg := \"Sandbox pods must set readOnlyRootFilesystem=true\"
      }
"""
    psa = {'pod_security_admission': 'Use namespace labels: pod-security.kubernetes.io/enforce=restricted'}
    return {'kyverno_policy': kyverno, 'gatekeeper_template': gatekeeper, 'pod_security_admission': psa}


def capture_resource_snapshot(ns, kind, name, timeout=30):
    if not has_kubectl() or not ns or not kind or not name:
        return {'kind': kind, 'name': name, 'captured': False, 'reason': 'kubectl unavailable or incomplete target'}
    rc, out = shell_rc(f"kubectl -n {shlex.quote(ns)} get {shlex.quote(kind)} {shlex.quote(name)} -o json", timeout=timeout)
    if rc != 0:
        return {'kind': kind, 'name': name, 'captured': False, 'error': out.strip()}
    try:
        obj = json.loads(out)
    except Exception:
        obj = {'raw': out}
    return {'kind': kind, 'name': name, 'captured': True, 'resource_version': get_nested(obj, 'metadata', 'resourceVersion'), 'uid': get_nested(obj, 'metadata', 'uid'), 'object': obj}


def normalize_resource_object(obj):
    norm = copy.deepcopy(obj)
    if not isinstance(norm, dict):
        return norm
    norm.pop('status', None)
    md = norm.get('metadata', {})
    if isinstance(md, dict):
        for key in ['resourceVersion', 'uid', 'managedFields', 'creationTimestamp', 'generation', 'selfLink']:
            md.pop(key, None)
        annotations = md.get('annotations')
        if isinstance(annotations, dict):
            annotations.pop('deployment.kubernetes.io/revision', None)
            annotations.pop('kubectl.kubernetes.io/last-applied-configuration', None)
            if not annotations:
                md.pop('annotations', None)
    return norm


def prepare_replace_object(snapshot_obj, live_obj):
    prepared = copy.deepcopy(snapshot_obj)
    prepared.pop('status', None)
    prepared.setdefault('metadata', {})
    live_md = (live_obj or {}).get('metadata', {}) or {}
    prepared['metadata']['resourceVersion'] = live_md.get('resourceVersion')
    for key in ['uid', 'managedFields', 'creationTimestamp', 'generation', 'selfLink']:
        prepared['metadata'].pop(key, None)
    return prepared


def strict_restore_snapshot_file(snapshot_file, timeout=60):
    with open(snapshot_file, 'r') as f:
        snapshot_obj = json.load(f)
    kind = ((snapshot_obj.get('kind') or '')).lower()
    name = get_nested(snapshot_obj, 'metadata', 'name')
    ns = get_nested(snapshot_obj, 'metadata', 'namespace') or 'default'
    if not kind or not name:
        raise RuntimeError(f'invalid snapshot file: {snapshot_file}')
    live = kubectl_get_json(ns, kind, name=name, timeout=timeout)
    prepared = prepare_replace_object(snapshot_obj, live)
    tmp = tempfile.NamedTemporaryFile('w', delete=False, suffix='.json')
    try:
        json.dump(prepared, tmp, indent=2)
        tmp.close()
        rc, out = shell_rc(f"kubectl -n {shlex.quote(ns)} replace -f {shlex.quote(tmp.name)}", timeout=timeout)
        if rc != 0:
            raise RuntimeError(out.strip() or f'kubectl replace failed for {kind}/{name}')
        restored = kubectl_get_json(ns, kind, name=name, timeout=timeout)
        equal = normalize_resource_object(restored) == normalize_resource_object(snapshot_obj)
        diff = ''
        if not equal:
            import difflib
            a = json.dumps(normalize_resource_object(snapshot_obj), indent=2, sort_keys=True).splitlines()
            b = json.dumps(normalize_resource_object(restored), indent=2, sort_keys=True).splitlines()
            diff = '\n'.join(difflib.unified_diff(a, b, fromfile='snapshot', tofile='restored', n=2))
        return {
            'kind': kind,
            'name': name,
            'namespace': ns,
            'snapshot_file': snapshot_file,
            'restore_rc': rc,
            'restore_output': out.strip(),
            'normalized_equal': equal,
            'normalized_diff': diff,
        }
    finally:
        try:
            os.unlink(tmp.name)
        except Exception:
            pass


def strict_rollback_bundle(bundle_dir):
    manifest_path = os.path.join(bundle_dir, 'backup_manifest.json')
    with open(manifest_path, 'r') as f:
        manifest = json.load(f)
    results = []
    for key, snap in (manifest.get('snapshots') or {}).items():
        path = snap.get('file')
        if not path:
            results.append({'resource': key, 'skipped': True, 'reason': 'no snapshot file recorded'})
            continue
        results.append(strict_restore_snapshot_file(path))
    ok = all(r.get('normalized_equal') is True or r.get('skipped') for r in results)
    return {'bundle_dir': bundle_dir, 'manifest': manifest_path, 'results': results, 'status': 'restored' if ok else 'drift_remaining'}


def build_rollback_from_snapshot(snapshot):
    if not snapshot.get('captured'):
        return {'available': False, 'reason': snapshot.get('reason') or snapshot.get('error') or 'snapshot unavailable'}
    kind = (snapshot.get('kind') or '').lower()
    name = snapshot.get('name')
    ns = get_nested(snapshot.get('object', {}), 'metadata', 'namespace')
    return {
        'available': True,
        'kind': kind,
        'name': name,
        'namespace': ns,
        'restore_object_json': json.dumps(snapshot['object'], indent=2),
        'restore_command': f"kubectl -n {shlex.quote(ns or 'default')} replace -f SNAPSHOT_{slugify_name(kind)}_{slugify_name(name)}.json"
    }

def build_fix_backup_bundle(audit_obj, namespace=None, workload=None, kind=None, include_serviceaccount=False, include_networkpolicy=False):
    artifacts = _original_build_apply_fix_artifacts(audit_obj)
    meta = artifacts.get('meta', {})
    ns = namespace or meta.get('namespace')
    workload_name = workload or meta.get('workload_name')
    workload_kind = (kind or meta.get('workload_kind') or 'deployment').lower()
    service_account_name = meta.get('service_account_name')
    snapshots = {
        'workload': capture_resource_snapshot(ns, workload_kind, workload_name),
    }
    if include_serviceaccount:
        snapshots['serviceaccount'] = capture_resource_snapshot(ns, 'serviceaccount', service_account_name) if service_account_name else {'captured': False, 'reason': 'missing service account name'}
    if include_networkpolicy:
        try:
            np_obj = yaml_or_json_load(artifacts['artifacts']['networkpolicy_yaml'])
            np_name = get_nested(np_obj, 'metadata', 'name')
            snapshots['networkpolicy'] = capture_resource_snapshot(ns, 'networkpolicy', np_name) if np_name else {'captured': False, 'reason': 'missing network policy name'}
        except Exception as e:
            snapshots['networkpolicy'] = {'captured': False, 'error': f'network policy parse failed: {e}'}
    rollback = {k: build_rollback_from_snapshot(v) for k, v in snapshots.items()}
    return {'artifacts': artifacts, 'snapshots': snapshots, 'rollback': rollback}


def yaml_or_json_load(text):
    try:
        return json.loads(text)
    except Exception:
        pass
    lines = []
    stack = [({}, -1)]
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith('#'):
            continue
        indent = len(raw) - len(raw.lstrip(' '))
        line = raw.strip()
        while len(stack) > 1 and indent <= stack[-1][1]:
            stack.pop()
        parent = stack[-1][0]
        if line.endswith(':'):
            key = line[:-1]
            parent[key] = {}
            stack.append((parent[key], indent))
        else:
            key, value = line.split(':', 1)
            value = value.strip().strip('"')
            if value == 'true':
                value = True
            elif value == 'false':
                value = False
            elif value == 'null':
                value = None
            else:
                try:
                    value = int(value)
                except Exception:
                    pass
            parent[key] = value
    return stack[0][0]


def backup_bundle_dir(prefix, namespace=None, workload_name=None):
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    parts = [prefix, safe_slug(namespace, 'namespace'), safe_slug(workload_name, 'workload'), stamp]
    return str(ensure_output_root() / "_".join(parts))


def build_source_of_truth_manifest_text(artifacts, include_serviceaccount=False, include_networkpolicy=False):
    meta = artifacts.get('meta', {}) or {}
    ns = meta.get('namespace')
    workload_name = meta.get('workload_name')
    workload_kind = (meta.get('workload_kind') or 'deployment').lower()
    service_account_name = meta.get('service_account_name') or 'default'
    workload_patch = json.loads((artifacts.get('artifacts') or {}).get('workload_patch_json') or '{}')
    container_patches = get_nested(workload_patch, 'spec', 'template', 'spec', 'containers') or []
    pod_spec_patch = get_nested(workload_patch, 'spec', 'template', 'spec') or {}
    docs = []
    if include_serviceaccount:
        sa_obj = {
            'apiVersion': 'v1',
            'kind': 'ServiceAccount',
            'metadata': {'name': service_account_name, 'namespace': ns},
            'automountServiceAccountToken': False,
        }
        docs.append(dict_to_yaml(sa_obj))
    wl_obj = {
        'apiVersion': 'apps/v1',
        'kind': workload_kind.capitalize() if workload_kind != 'daemonset' else 'DaemonSet',
        'metadata': {'name': workload_name, 'namespace': ns},
        'spec': {
            'template': {
                'spec': {
                    'automountServiceAccountToken': pod_spec_patch.get('automountServiceAccountToken'),
                    'containers': container_patches,
                }
            }
        }
    }
    docs.append(dict_to_yaml(wl_obj))
    if include_networkpolicy:
        docs.append((artifacts.get('artifacts') or {}).get('networkpolicy_yaml', '').strip())
    return "\n---\n".join([d for d in docs if d]) + "\n"


def persist_source_of_truth_manifest(artifacts, include_serviceaccount=False, include_networkpolicy=False, out_dir=None):
    meta = artifacts.get('meta', {}) or {}
    filename = backup_bundle_dir('source_of_truth_manifest', namespace=meta.get('namespace'), workload_name=meta.get('workload_name')) + '.yaml'
    path = os.path.join(out_dir, os.path.basename(filename)) if out_dir else filename
    text = build_source_of_truth_manifest_text(
        artifacts,
        include_serviceaccount=include_serviceaccount,
        include_networkpolicy=include_networkpolicy,
    )
    with open(path, 'w') as f:
        f.write(text)
    return path


def persist_backup_bundle(bundle, prefix='rollback_bundle'):
    meta = ((bundle.get('artifacts') or {}).get('meta') or {})
    out_dir = backup_bundle_dir(prefix, namespace=meta.get('namespace'), workload_name=meta.get('workload_name'))
    os.makedirs(out_dir, exist_ok=True)
    manifest = {
        'meta': meta,
        'snapshots': {},
        'rollback': bundle.get('rollback', {}),
    }
    for key, snap in (bundle.get('snapshots') or {}).items():
        manifest['snapshots'][key] = {k: v for k, v in snap.items() if k != 'object'}
        if snap.get('captured') and snap.get('object') is not None:
            path = os.path.join(out_dir, f"snapshot_{safe_slug(snap.get('kind'), key)}_{safe_slug(snap.get('name'), key)}.json")
            with open(path, 'w') as f:
                json.dump(snap['object'], f, indent=2)
            manifest['snapshots'][key]['file'] = path
            if bundle.get('rollback', {}).get(key, {}).get('available'):
                bundle['rollback'][key]['restore_command'] = bundle['rollback'][key]['restore_command'].replace(
                    f"SNAPSHOT_{slugify_name((snap.get('kind') or '').lower())}_{slugify_name(snap.get('name'))}.json",
                    path
                )
    manifest['rollback'] = bundle.get('rollback', {})
    manifest_path = os.path.join(out_dir, 'backup_manifest.json')
    with open(manifest_path, 'w') as f:
        json.dump(manifest, f, indent=2)
    return {'directory': out_dir, 'manifest': manifest_path}


def ensure_mandatory_backup_bundle(audit_obj, namespace=None, workload=None, kind=None, include_serviceaccount=False, include_networkpolicy=False):
    bundle = build_fix_backup_bundle(
        audit_obj,
        namespace=namespace,
        workload=workload,
        kind=kind,
        include_serviceaccount=include_serviceaccount,
        include_networkpolicy=include_networkpolicy,
    )
    required = ['workload']
    if include_serviceaccount:
        required.append('serviceaccount')
    missing = [name for name in required if not get_nested(bundle, 'snapshots', name, 'captured')]
    if missing:
        reasons = []
        for name in missing:
            snap = get_nested(bundle, 'snapshots', name) or {}
            reasons.append(f"{name}: {snap.get('reason') or snap.get('error') or 'snapshot unavailable'}")
        raise RuntimeError("mandatory backup failed: " + "; ".join(reasons))
    persisted = persist_backup_bundle(bundle)
    bundle['persisted'] = persisted
    return bundle


def post_fix_revalidate(audit_obj, timeout=2.0):
    meta = audit_obj.get('meta', {}) or {}
    try:
        if meta.get('namespace') and meta.get('target_selector'):
            revalidated = collect_remote_with_attacker_policy(
                meta['namespace'],
                meta['target_selector'],
                timeout=timeout,
                include_introspection=True,
                include_internal_audit=False,
                create_if_missing=False,
                cleanup_temporary_attacker=False,
            )
            revalidated.setdefault('meta', {})
            for key in ('namespace', 'target_selector', 'workload_name', 'workload_kind', 'service_account_name', 'selector_labels'):
                if meta.get(key) and not revalidated['meta'].get(key):
                    revalidated['meta'][key] = copy.deepcopy(meta.get(key))
            if (audit_obj.get('results') or {}).get('internal_audit'):
                target_pod = get_nested(revalidated, 'meta', 'target_pod')
                if target_pod:
                    containers = get_pod_containers(meta['namespace'], target_pod)
                    container = containers[0] if containers else None
                    internal_audit, internal_state = run_internal_audit_for_target(meta['namespace'], target_pod, container=container, timeout=timeout)
                    revalidated.setdefault('results', {})['internal_audit'] = internal_audit
                    revalidated.setdefault('controller', {})['internal_execution'] = internal_state
                    revalidated = promote_internal_audit_findings(revalidated)
                    if internal_state.get('status') != 'collected_from_laptop':
                        revalidated = build_spec_fallback_revalidation(audit_obj, revalidated)
                else:
                    revalidated = build_spec_fallback_revalidation(audit_obj, revalidated)
            revalidated = reconcile_spec_backed_findings(revalidated)
            return revalidated
        return collect_internal(timeout=timeout)
    except Exception as e:
        return {'error': 'revalidate_failed', 'detail': str(e)}


def _all_containers(workload_obj):
    return get_nested(workload_obj, 'spec', 'template', 'spec', 'containers') or []


def _all_true(values):
    return bool(values) and all(bool(v) for v in values)


def _all_false(values):
    return bool(values) and all((v is False) for v in values)


def build_spec_fallback_revalidation(original_audit_obj, remote_obj):
    meta = (remote_obj.get('meta') or {}).copy()
    namespace = meta.get('namespace') or get_nested(original_audit_obj, 'meta', 'namespace')
    workload_name = meta.get('workload_name') or get_nested(original_audit_obj, 'meta', 'workload_name')
    workload_kind = (meta.get('workload_kind') or get_nested(original_audit_obj, 'meta', 'workload_kind') or 'deployment').lower()
    service_account_name = meta.get('service_account_name') or get_nested(original_audit_obj, 'meta', 'service_account_name') or 'default'
    workload_obj = kubectl_get_json(namespace, workload_kind, name=workload_name, timeout=30)
    sa_obj = kubectl_get_json(namespace, 'serviceaccount', name=service_account_name, timeout=30)
    pod_spec = get_nested(workload_obj, 'spec', 'template', 'spec') or {}
    containers = _all_containers(workload_obj)

    seccomp_vals = []
    for c in containers:
        csec = get_nested(c, 'securityContext', 'seccompProfile', 'type')
        psec = get_nested(pod_spec, 'securityContext', 'seccompProfile', 'type')
        seccomp_vals.append((csec or psec) in ('RuntimeDefault', 'Localhost'))

    rootfs_vals = [get_nested(c, 'securityContext', 'readOnlyRootFilesystem') is True for c in containers]
    ape_vals = [get_nested(c, 'securityContext', 'allowPrivilegeEscalation') is False for c in containers]
    nonroot_vals = []
    for c in containers:
        sc = get_nested(c, 'securityContext') or {}
        pod_sc = get_nested(pod_spec, 'securityContext') or {}
        run_as_non_root = sc.get('runAsNonRoot')
        run_as_user = sc.get('runAsUser')
        if run_as_non_root is None:
            run_as_non_root = pod_sc.get('runAsNonRoot')
        if run_as_user is None:
            run_as_user = pod_sc.get('runAsUser')
        nonroot_vals.append(run_as_non_root is True or (isinstance(run_as_user, int) and run_as_user != 0))

    caps_vals = []
    for c in containers:
        drops = get_nested(c, 'securityContext', 'capabilities', 'drop') or []
        adds = get_nested(c, 'securityContext', 'capabilities', 'add') or []
        drops_norm = {str(x).upper() for x in drops}
        adds_norm = {str(x).upper() for x in adds}
        dangerous = {'NET_RAW', 'SYS_ADMIN'}
        caps_vals.append(('ALL' in drops_norm) and not (dangerous & adds_norm))

    automount_pod = pod_spec.get('automountServiceAccountToken')
    automount_sa = sa_obj.get('automountServiceAccountToken')
    sa_disabled = (automount_pod is False) or (automount_pod is None and automount_sa is False)

    spec_results = {
        'running_as_non_root': bool_field(_all_true(nonroot_vals), f"spec_nonroot={nonroot_vals}"),
        'rootfs_readonly': bool_field(_all_true(rootfs_vals), f"spec_readonly_rootfs={rootfs_vals}"),
    }
    spec_k8s = {
        'seccomp_enforced': bool_field(_all_true(seccomp_vals), f"spec_seccomp={seccomp_vals}"),
        'no_new_privs': bool_field(_all_true(ape_vals), f"spec_allowPrivilegeEscalation_false={ape_vals}"),
        'rootfs_readonly': bool_field(_all_true(rootfs_vals), f"spec_readonly_rootfs={rootfs_vals}"),
        'dangerous_caps_absent': bool_field(_all_true(caps_vals), f"spec_caps_drop_all={caps_vals}"),
        'sa_token_present': bool_field(sa_disabled, f"automount_disabled={sa_disabled} pod={automount_pod} sa={automount_sa}"),
        'sa_ca_present': bool_field(sa_disabled, f"automount_disabled={sa_disabled} pod={automount_pod} sa={automount_sa}"),
        'sa_namespace_present': bool_field(sa_disabled, f"automount_disabled={sa_disabled} pod={automount_pod} sa={automount_sa}"),
        'sa_mount_readonly': bool_field(sa_disabled, f"automount_disabled={sa_disabled} pod={automount_pod} sa={automount_sa}"),
    }

    fallback = copy.deepcopy(remote_obj)
    fallback.setdefault('results', {}).update(spec_results)
    fallback['kubernetes'] = spec_k8s
    fallback.setdefault('results', {})['internal_audit'] = {
        'summary': {'passed': count_ok(spec_results) + count_ok(spec_k8s), 'total': count_total(spec_results) + count_total(spec_k8s)},
        'results': spec_results,
        'kubernetes': spec_k8s,
        'error': None,
        'verification_mode': 'spec_fallback',
    }
    fallback.setdefault('controller', {})['internal_execution'] = {
        'status': 'spec_fallback',
        'reason': get_nested(remote_obj, 'controller', 'internal_execution', 'reason') or 'runtime_internal_audit_unavailable',
    }
    fallback.setdefault('meta', {})['verification_status'] = 'partially_verified'
    fallback['remediation'] = remediation_from_audit(fallback)
    fallback = promote_internal_audit_findings(fallback)

    promoted_original = promote_internal_audit_findings(copy.deepcopy(original_audit_obj))
    original_remediation = promoted_original.get('remediation') or remediation_from_audit(promoted_original)
    original_items = ((original_remediation or {}).get('items') or [])
    current_items = ((fallback.get('remediation') or {}).get('items') or [])
    current_ids = {item.get('issue_id') for item in current_items}
    carry_forward_ids = {'SETID_BINARIES_PRESENT', 'SENSITIVE_PATHS_WRITABLE', 'RISKY_DEVICE_NODES'}
    for item in original_items:
        issue_id = item.get('issue_id')
        if issue_id in carry_forward_ids and issue_id not in current_ids:
            current_items.append(copy.deepcopy(item))
    if any((item.get('issue_id') or '') != 'NO_ACTIONABLE_FAILURES' for item in current_items):
        current_items = [item for item in current_items if (item.get('issue_id') or '') != 'NO_ACTIONABLE_FAILURES']
    fallback['remediation'] = enrich_remediation({'count': len(current_items), 'items': current_items, 'templates': (fallback.get('remediation') or {}).get('templates', {})})
    fallback['risk_score'] = compute_risk_score(fallback)
    fallback['risk_score_unverified'] = True
    return fallback


def wait_for_workload_rollout(namespace, workload, kind, timeout=60):
    if not has_kubectl() or not namespace or not workload or not kind:
        return {'ok': False, 'reason': 'missing_rollout_target'}
    rc, out = shell_rc(
        f"kubectl -n {shlex.quote(namespace)} rollout status {shlex.quote(kind)}/{shlex.quote(workload)} --timeout={int(timeout)}s",
        timeout=timeout + 10,
    )
    return {'ok': rc == 0, 'output': (out or '').strip(), 'rc': rc}


_original_collect_internal = collect_internal

def collect_internal(timeout=2.0):
    obj = _original_collect_internal(timeout=timeout)
    obj['evidence'] = collect_evidence('results', obj.get('results', {})) + collect_evidence('kubernetes', obj.get('kubernetes', {}))
    obj['risk_score'] = compute_risk_score(obj)
    obj.setdefault('meta', {})['compatibility_notes'] = compatibility_assessment(obj)
    obj['reports'] = {'markdown': markdown_report(obj)}
    return obj


_original_collect_remote = collect_remote

def collect_remote(ns, selector, timeout=2.0, include_introspection=True, include_internal_audit=False):
    obj = _original_collect_remote(ns, selector, timeout=timeout, include_introspection=include_introspection, include_internal_audit=include_internal_audit)
    obj.setdefault('meta', {})['dependencies'] = summarize_dependencies(ns, obj.get('meta', {}).get('workload_name'), obj.get('meta', {}).get('target_pod'), obj.get('meta', {}).get('selector_labels') or {})
    obj['evidence'] = collect_evidence('results', obj.get('results', {}))
    obj['risk_score'] = compute_risk_score(obj)
    obj = promote_internal_audit_findings(obj)
    obj.setdefault('meta', {})['compatibility_notes'] = compatibility_assessment(obj)
    obj['reports'] = {'markdown': markdown_report(obj)}
    return obj


_original_remediation_from_audit = remediation_from_audit

def remediation_from_audit(obj):
    rem = _original_remediation_from_audit(obj)
    rem.setdefault('templates', {}).update(generate_admission_policies(selector_to_matchlabels((obj.get('meta') or {}).get('target_selector', 'app=cua'))))
    return rem


_original_build_apply_fix_artifacts = build_apply_fix_artifacts

def build_apply_fix_artifacts(audit_obj):
    artifacts = _original_build_apply_fix_artifacts(audit_obj)
    meta = artifacts.get('meta', {})
    workload_snapshot = capture_resource_snapshot(meta.get('namespace'), meta.get('workload_kind'), meta.get('workload_name'))
    sa_snapshot = capture_resource_snapshot(meta.get('namespace'), 'serviceaccount', meta.get('service_account_name')) if meta.get('service_account_name') else {'captured': False}
    artifacts['snapshots'] = {'workload': workload_snapshot, 'serviceaccount': sa_snapshot}
    artifacts['rollback'] = {'workload': build_rollback_from_snapshot(workload_snapshot), 'serviceaccount': build_rollback_from_snapshot(sa_snapshot)}
    return artifacts


_original_apply_fixes = apply_fixes

def apply_fixes(audit_obj, namespace=None, workload=None, kind=None, apply_network_policy=False, patch_service_account=False, dry_run=True):
    backup_bundle = None
    if not dry_run:
        backup_bundle = ensure_mandatory_backup_bundle(
            audit_obj,
            namespace=namespace,
            workload=workload,
            kind=kind,
            include_serviceaccount=patch_service_account,
            include_networkpolicy=apply_network_policy,
        )
    out = _original_apply_fixes(audit_obj, namespace=namespace, workload=workload, kind=kind, apply_network_policy=apply_network_policy, patch_service_account=patch_service_account, dry_run=dry_run)
    if dry_run:
        artifacts = build_apply_fix_artifacts(audit_obj)
        out['snapshots'] = artifacts.get('snapshots', {})
        out['rollback'] = artifacts.get('rollback', {})
        out['source_of_truth_manifest'] = persist_source_of_truth_manifest(
            artifacts,
            include_serviceaccount=patch_service_account,
            include_networkpolicy=apply_network_policy,
        )
    else:
        out['snapshots'] = backup_bundle.get('snapshots', {})
        out['rollback'] = backup_bundle.get('rollback', {})
        out['backup_bundle'] = backup_bundle.get('persisted', {})
        out['source_of_truth_manifest'] = persist_source_of_truth_manifest(
            backup_bundle.get('artifacts', {}),
            include_serviceaccount=patch_service_account,
            include_networkpolicy=apply_network_policy,
            out_dir=backup_bundle.get('persisted', {}).get('directory'),
        )
    if not dry_run:
        rollout = wait_for_workload_rollout(namespace or out['meta'].get('namespace'), workload or out['meta'].get('workload_name'), kind or out['meta'].get('workload_kind') or 'deployment', timeout=90)
        out['rollout_status'] = rollout
        revalidated = post_fix_revalidate(audit_obj)
        if isinstance(revalidated, dict) and not revalidated.get('error'):
            revalidated['remediation'] = remediation_from_audit(revalidated)
            revalidated = promote_internal_audit_findings(revalidated)
            revalidated = reconcile_spec_backed_findings(revalidated)
            revalidated['remediation'] = enrich_remediation(revalidated.get('remediation') or {})
            revalidated['risk_score'] = compute_risk_score(revalidated)
            if ((revalidated.get('controller') or {}).get('internal_execution') or {}).get('status') != 'collected_from_laptop':
                revalidated['risk_score_unverified'] = True
        out['post_fix_revalidation'] = revalidated
    return out


def infer_fix_profile(selected_items):
    ids = {x.get('issue_id') for x in (selected_items or [])}
    if {'REMOTE_REACHABILITY', 'IMDS_REACHABLE', 'SERVICE_ACCOUNT_TOKEN'} & ids:
        return 'sandbox-strict'
    if {'NOVNC_LISTENER'} & ids:
        return 'agentic-desktop-compatible'
    if {'RUN_AS_ROOT', 'ROOTFS_RW', 'LINUX_CAPS', 'SECCOMP_DISABLED'} <= ids:
        return 'restricted-pod'
    return 'baseline-safe'


_original_enrich_remediation = enrich_remediation

def enrich_remediation(remediation):
    out = _original_enrich_remediation(remediation)
    for item in out.get('items', []):
        item['simulation_hint'] = item.get('risk_note') or item.get('manual_recommendation') or ''
    return out


def write_json_file(path_out, obj, label):
    with open(path_out, 'w') as f:
        json.dump(obj, f, indent=2)
    if label:
        print(f"{label}: {path_out}")
    try:
        md = None
        if isinstance(obj, dict) and obj.get('reports', {}).get('markdown'):
            md = obj['reports']['markdown']
        elif isinstance(obj, dict) and obj.get('audit'):
            md = markdown_report(obj.get('audit', {}), obj.get('fix'))
        if md:
            md_path = str(Path(path_out).with_suffix('.md'))
            Path(md_path).write_text(md)
            if label:
                print(f"Markdown report written: {md_path}")
    except Exception:
        pass


_base_write_json_file = write_json_file


def print_audit_summary(obj):
    print("\n=== Audit summary ===")
    sec = security_issue_summary(obj)
    print(f"Security issues: {sec.get('count', 0)}")
    sev = sec.get('severity_counts') or {}
    sev_parts = [f"{name}={sev.get(name, 0)}" for name in ('critical', 'high', 'medium', 'low') if sev.get(name, 0)]
    if sev_parts:
        print(f"Severity mix: {', '.join(sev_parts)}")
    if 'summary' in obj:
        s = obj['summary']
        print(f"Validation checks: {s.get('passed', 0)}/{s.get('total', 0)} passed")
    internal = ((obj.get("results") or {}).get("internal_audit") or {})
    if isinstance(internal, dict) and internal.get("summary"):
        s = internal["summary"]
        print(f"Internal validation: {s.get('passed', 0)}/{s.get('total', 0)} passed")
    cls = (((obj.get('results') or {}).get('classification')) or '')
    if cls:
        print(f"Remote classification: {cls}")
    score = obj.get('risk_score') or compute_risk_score(obj)
    print(f"Risk score: {score.get('total')} (P={score.get('probability')}, B={score.get('blast_radius')}) -> {score.get('band')}")
    meta = obj.get('meta', {})
    for k in ('namespace', 'target_selector', 'target_pod', 'target_ip', 'workload_kind', 'workload_name'):
        if meta.get(k):
            print(f"{k}: {meta.get(k)}")
    deps = meta.get('dependencies') or {}
    if deps:
        print('Dependencies / surrounding resources:')
        for k, v in deps.items():
            if isinstance(v, list):
                rendered = ', '.join(x if isinstance(x, str) else json.dumps(x, sort_keys=True) for x in v) if v else 'none'
                print(f"- {k}: {rendered}")
            elif v:
                print(f"- {k}: {v}")
    for note in meta.get('compatibility_notes', [])[:5]:
        print(f"Compatibility note: {note.get('message')}")


def print_fix_result(result):
    print("\n=== Fix results ===")
    print(f"Overall status: {result.get('status')}")
    if result.get('fix_profile'):
        print(f"Fix profile: {result.get('fix_profile')}")
    for item in result.get('per_issue', []):
        print(f"- {item.get('issue_id')}: {item.get('status')} ({item.get('risk_level')})")
        if item.get('note'):
            print(f"  {item.get('note')}")
    apply_result = result.get('apply_result')
    if apply_result:
        print("\nCommands / execution:")
        for step in apply_result.get('executed', []):
            print(f"* {step.get('step')}: {'executed' if step.get('applied') else 'planned'}")
            print(f"  {step.get('command')}")
            if step.get('output'):
                print(f"  output: {step.get('output')}")
        if apply_result.get('rollback'):
            print('Rollback artifacts available for patched resources.')
        if apply_result.get('post_fix_revalidation') and not apply_result['post_fix_revalidation'].get('error'):
            score = apply_result['post_fix_revalidation'].get('risk_score') or compute_risk_score(apply_result['post_fix_revalidation'])
            print(f"Post-fix risk score: {score.get('total')} ({score.get('band')})")


_original_run_selected_fix_groups = run_selected_fix_groups

def run_selected_fix_groups(audit_obj, selected_items, namespace=None, workload=None, kind='deployment', execute=False):
    result = _original_run_selected_fix_groups(audit_obj, selected_items, namespace=namespace, workload=workload, kind=kind, execute=execute)
    apply_result = result.get('apply_result') or {}
    revalidated = apply_result.get('post_fix_revalidation') or {}
    if execute and revalidated and not revalidated.get('error'):
        revalidated = reconcile_spec_backed_findings(revalidated)
        current_items = ((revalidated.get('remediation') or {}).get('items') or [])
        current_ids = {item.get('issue_id') for item in current_items}
        carry_ids = {'SETID_BINARIES_PRESENT', 'SENSITIVE_PATHS_WRITABLE', 'RISKY_DEVICE_NODES'}
        for item in (((audit_obj.get('remediation') or {}).get('items') or [])):
            issue_id = item.get('issue_id')
            if issue_id in carry_ids and issue_id not in current_ids:
                current_items.append(copy.deepcopy(item))
        if any((item.get('issue_id') or '') != 'NO_ACTIONABLE_FAILURES' for item in current_items):
            current_items = [item for item in current_items if (item.get('issue_id') or '') != 'NO_ACTIONABLE_FAILURES']
        revalidated['remediation'] = enrich_remediation({
            'count': len(current_items),
            'items': current_items,
            'templates': (revalidated.get('remediation') or {}).get('templates', {}),
        })
        revalidated['risk_score'] = compute_risk_score(revalidated)
        apply_result['post_fix_revalidation'] = revalidated
        result['apply_result'] = apply_result
    if execute and revalidated and revalidated.get('risk_score_unverified'):
        current_items = ((revalidated.get('remediation') or {}).get('items') or [])
        current_ids = {item.get('issue_id') for item in current_items}
        unverifiable_issue_ids = {'SETID_BINARIES_PRESENT', 'SENSITIVE_PATHS_WRITABLE', 'RISKY_DEVICE_NODES'}
        for item in selected_items:
            issue_id = item.get('issue_id')
            if not issue_id or issue_id in current_ids:
                continue
            if issue_id in unverifiable_issue_ids:
                current_items.append(copy.deepcopy(item))
        if any((item.get('issue_id') or '') != 'NO_ACTIONABLE_FAILURES' for item in current_items):
            current_items = [item for item in current_items if (item.get('issue_id') or '') != 'NO_ACTIONABLE_FAILURES']
        revalidated['remediation'] = enrich_remediation({
            'count': len(current_items),
            'items': current_items,
            'templates': (revalidated.get('remediation') or {}).get('templates', {}),
        })
        revalidated['risk_score'] = compute_risk_score(revalidated)
        apply_result['post_fix_revalidation'] = revalidated
        result['apply_result'] = apply_result
    if execute and revalidated and not revalidated.get('error'):
        remaining_issue_ids = {
            item.get('issue_id')
            for item in (((revalidated.get('remediation') or {}).get('items') or []))
            if item.get('issue_id') and item.get('issue_id') != 'NO_ACTIONABLE_FAILURES'
        }
        for item in result.get('per_issue', []):
            issue_id = item.get('issue_id')
            if not issue_id:
                continue
            if item.get('status') == 'manual_only' and issue_id not in remaining_issue_ids:
                item['status'] = 'resolved_by_applied_patch'
                note = item.get('note') or ''
                suffix = 'Cleared from post-remediation revalidation.'
                item['note'] = f"{note} {suffix}".strip()
    result['fix_profile'] = infer_fix_profile(selected_items)
    return result


_original_auto_run = auto_run

def auto_run(timeout=2.0, apply_safe_fixes=True, execute=False, audit_out=None, fix_out=None):
    bundle = _original_auto_run(timeout=timeout, apply_safe_fixes=apply_safe_fixes, execute=execute, audit_out=audit_out, fix_out=fix_out)
    if isinstance(bundle, dict):
        bundle['reports'] = {'markdown': markdown_report(bundle.get('audit', {}), bundle.get('fix'))}
    return bundle




# ---------------- smart recommendation and learning layer ----------------
SMART_HISTORY_PATH = os.environ.get('COMBINED_AUDIT_HISTORY', os.path.expanduser('~/.combined_audit_history.json'))
APP_MODE_DEFAULT = os.environ.get('AGENTFENCE_APP_MODE', 'default').strip().lower() or 'default'
AI_MODEL_DEFAULT = os.environ.get('AGENTFENCE_OPENAI_MODEL', 'gpt-5-mini').strip() or 'gpt-5-mini'
AI_API_BASE_DEFAULT = os.environ.get('AGENTFENCE_OPENAI_BASE_URL', 'https://api.openai.com/v1').rstrip('/')
AI_KEYCHAIN_SERVICE = os.environ.get('AGENTFENCE_OPENAI_KEYCHAIN_SERVICE', 'AgentFence OpenAI API Key').strip() or 'AgentFence OpenAI API Key'
AI_KEYCHAIN_ACCOUNT = os.environ.get('AGENTFENCE_OPENAI_KEYCHAIN_ACCOUNT', 'default').strip() or 'default'

RUNTIME_INTELLIGENCE = {
    'cua': {
        'expected_services': [6901, 5901, 8000],
        'summary': 'Hardened OCI baseline with higher chance of app-level exposure by default.',
        'recommended_profiles': ['agentic-desktop-compatible', 'baseline-safe'],
    },
    'gvisor': {
        'expected_services': [],
        'summary': 'User-space kernel isolation; unexpected listeners should generally be treated as posture regressions.',
        'recommended_profiles': ['restricted-pod', 'sandbox-strict'],
    },
    'kata': {
        'expected_services': [],
        'summary': 'MicroVM isolation; focus on workload posture and service exposure, not just runtime boundary.',
        'recommended_profiles': ['restricted-pod', 'sandbox-strict'],
    },
    'wasm': {
        'expected_services': [],
        'summary': 'Capability-oriented runtime; broad filesystem, root, or metadata exposure is especially suspicious.',
        'recommended_profiles': ['sandbox-strict', 'restricted-pod'],
    },
}


def normalize_app_mode(app_mode):
    mode = str(app_mode or APP_MODE_DEFAULT or 'default').strip().lower()
    return mode if mode in ('default', 'ai') else 'default'


def ai_mode_enabled(app_mode):
    return normalize_app_mode(app_mode) == 'ai'


def ai_config_from_env(app_mode=None):
    mode = normalize_app_mode(app_mode)
    api_key, key_source = resolve_openai_api_key()
    return {
        'app_mode': mode,
        'enabled': mode == 'ai',
        'provider': 'openai',
        'model': AI_MODEL_DEFAULT,
        'api_key_present': bool(api_key),
        'api_key_source': key_source,
        'api_base': AI_API_BASE_DEFAULT,
        'timeout_seconds': float(os.environ.get('AGENTFENCE_OPENAI_TIMEOUT', '60') or '60'),
    }


def read_openai_api_key_from_keychain(service=AI_KEYCHAIN_SERVICE, account=AI_KEYCHAIN_ACCOUNT):
    if platform.system() != 'Darwin':
        return None
    if not shutil.which('security'):
        return None
    try:
        proc = subprocess.run(
            ['security', 'find-generic-password', '-w', '-s', service, '-a', account],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=5,
        )
        if proc.returncode != 0:
            return None
        value = (proc.stdout or '').strip()
        return value or None
    except Exception:
        return None


def read_openai_api_key_from_keyring(service=AI_KEYCHAIN_SERVICE, account=AI_KEYCHAIN_ACCOUNT):
    try:
        import keyring
    except Exception:
        return None
    try:
        value = keyring.get_password(service, account)
        value = (value or '').strip()
        return value or None
    except Exception:
        return None


def resolve_openai_api_key():
    env_value = (os.environ.get('OPENAI_API_KEY') or '').strip()
    if env_value:
        return env_value, 'environment'
    if platform.system() == 'Darwin':
        keychain_value = read_openai_api_key_from_keychain()
        if keychain_value:
            return keychain_value, 'macos_keychain'
    keyring_value = read_openai_api_key_from_keyring()
    if keyring_value:
        return keyring_value, 'keyring'
    return None, None


def ai_issue_brief(item):
    if not isinstance(item, dict):
        return {}
    return {
        'issue_id': item.get('issue_id'),
        'title': item.get('title'),
        'severity': item.get('severity'),
        'risk_level': item.get('risk_level'),
        'auto_applicable': item.get('auto_applicable'),
        'fix_group': item.get('fix_group'),
        'manual_recommendation': item.get('manual_recommendation'),
        'risk_note': item.get('risk_note'),
        'policy_reasoning': item.get('policy_reasoning'),
        'decision_reasoning': item.get('decision_reasoning'),
        'why_not_auto_fixed': item.get('why_not_auto_fixed'),
        'simulation_hint': item.get('simulation_hint'),
    }


def build_ai_advisor_payload(audit_obj, selected=None, workflow_mode=None):
    meta = audit_obj.get('meta', {}) or {}
    score = audit_obj.get('risk_score') or compute_risk_score(audit_obj)
    remediation = (audit_obj.get('remediation') or {}).get('items') or []
    deps = meta.get('dependencies') or audit_obj.get('dependencies') or {}
    compatibility = meta.get('compatibility_notes') or []
    return {
        'workflow_mode': workflow_mode or 'guided',
        'target': {
            'namespace': meta.get('namespace'),
            'workload_kind': meta.get('workload_kind'),
            'workload_name': meta.get('workload_name'),
            'target_selector': meta.get('target_selector'),
            'target_pod': meta.get('target_pod'),
        },
        'selected_resource': {
            'workload_kind': (selected or {}).get('workload_kind'),
            'workload_name': (selected or {}).get('workload_name'),
            'selector': (selected or {}).get('selector'),
        },
        'risk_score': score,
        'security_summary': security_issue_summary(audit_obj),
        'compatibility_notes': [note.get('message') if isinstance(note, dict) else str(note) for note in compatibility[:6]],
        'dependencies': deps,
        'remediation_items': [ai_issue_brief(item) for item in remediation[:12]],
    }


def extract_text_from_response_api(data):
    if isinstance(data, dict):
        output_text = data.get('output_text')
        if isinstance(output_text, str) and output_text.strip():
            return output_text.strip()
        output = data.get('output') or []
        texts = []
        for item in output:
            if not isinstance(item, dict):
                continue
            content = item.get('content') or []
            for part in content:
                if not isinstance(part, dict):
                    continue
                if part.get('type') in ('output_text', 'text') and part.get('text'):
                    texts.append(part.get('text'))
        if texts:
            return "\n".join(texts).strip()
    return ""


def coerce_advisor_json(text):
    if not text:
        return None
    try:
        return json.loads(text)
    except Exception:
        pass
    match = re.search(r'(\{.*\})', text, re.S)
    if match:
        try:
            return json.loads(match.group(1))
        except Exception:
            return None
    return None


def advisor_response_format():
    return {
        'type': 'json_schema',
        'name': 'agentfence_ai_advisor',
        'schema': {
            'type': 'object',
            'additionalProperties': False,
            'properties': {
                'executive_summary': {'type': 'string'},
                'remediation_overview': {'type': 'string'},
                'prioritized_groups': {
                    'type': 'array',
                    'items': {
                        'type': 'object',
                        'additionalProperties': False,
                        'properties': {
                            'title': {'type': 'string'},
                            'priority': {'type': 'string'},
                            'issue_ids': {'type': 'array', 'items': {'type': 'string'}},
                            'rationale': {'type': 'string'},
                        },
                        'required': ['title', 'priority', 'issue_ids', 'rationale'],
                    },
                },
                'item_advice': {
                    'type': 'array',
                    'items': {
                        'type': 'object',
                        'additionalProperties': False,
                        'properties': {
                            'issue_id': {'type': 'string'},
                            'explanation': {'type': 'string'},
                            'operator_impact': {'type': 'string'},
                            'validation_advice': {'type': 'string'},
                            'ordering_reason': {'type': 'string'},
                        },
                        'required': ['issue_id', 'explanation', 'operator_impact', 'validation_advice', 'ordering_reason'],
                    },
                },
                'guided_operator_message': {'type': 'string'},
                'warnings': {'type': 'array', 'items': {'type': 'string'}},
                'next_steps': {'type': 'array', 'items': {'type': 'string'}},
            },
            'required': [
                'executive_summary',
                'remediation_overview',
                'prioritized_groups',
                'item_advice',
                'guided_operator_message',
                'warnings',
                'next_steps',
            ],
        },
    }


def openai_responses_create(instructions, payload, model, timeout=25.0, api_base=None):
    api_key, key_source = resolve_openai_api_key()
    if not api_key:
        raise RuntimeError('OpenAI API key is not configured in environment or macOS Keychain')
    body = {
        'model': model,
        'instructions': instructions,
        'input': [
            {
                'role': 'user',
                'content': [
                    {
                        'type': 'input_text',
                        'text': json.dumps(payload, indent=2, sort_keys=True),
                    }
                ],
            }
        ],
        'text': {'format': advisor_response_format(), 'verbosity': 'low'},
        'reasoning': {'effort': 'minimal'},
        'max_output_tokens': 4000,
    }
    req = urllib.request.Request(
        f"{(api_base or AI_API_BASE_DEFAULT).rstrip('/')}/responses",
        data=json.dumps(body).encode('utf-8'),
        headers={
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json',
        },
        method='POST',
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode('utf-8'))


def ai_advisor_instructions():
    return (
        "You are AgentFence AI, a Kubernetes sandbox security advisor. "
        "You are advisory only. Do not invent findings. Base everything on the provided JSON. "
        "Be concise and keep all fields short and practical. "
        "Return valid JSON only with these keys: "
        "executive_summary, remediation_overview, prioritized_groups, item_advice, guided_operator_message, warnings, next_steps. "
        "executive_summary and remediation_overview must be strings. "
        "prioritized_groups must be a list of objects with keys title, priority, issue_ids, rationale. "
        "item_advice must be a list of objects with keys issue_id, explanation, operator_impact, validation_advice, ordering_reason. "
        "guided_operator_message must be a short string written to an operator. "
        "warnings and next_steps must be lists of short strings. "
        "Never recommend automatic action beyond the remediation items already provided. "
        "Keep the tone concise, practical, and safety-aware."
    )


def run_ai_advisor(audit_obj, selected=None, workflow_mode=None, app_mode=None):
    config = ai_config_from_env(app_mode)
    base = {
        'status': 'disabled',
        'enabled': config['enabled'],
        'provider': config['provider'],
        'model': config['model'],
    }
    if not config['enabled']:
        return base
    if not config['api_key_present']:
        base.update({'status': 'unavailable', 'reason': 'missing_openai_api_key'})
        return base
    payload = build_ai_advisor_payload(audit_obj, selected=selected, workflow_mode=workflow_mode)
    attempts = 2
    for attempt in range(1, attempts + 1):
        try:
            response = openai_responses_create(
                instructions=ai_advisor_instructions(),
                payload=payload,
                model=config['model'],
                timeout=config['timeout_seconds'],
                api_base=config['api_base'],
            )
            text = extract_text_from_response_api(response)
            parsed = coerce_advisor_json(text)
            if not isinstance(parsed, dict):
                raise RuntimeError('ai_response_not_json')
            base.update(parsed)
            base['status'] = 'ok'
            if attempt > 1:
                base['retry_count'] = attempt - 1
            return base
        except urllib.error.HTTPError as e:
            detail = e.read().decode('utf-8', 'replace') if hasattr(e, 'read') else str(e)
            base.update({'status': 'failed', 'reason': f'http_{e.code}', 'detail': detail[:800]})
            if attempt > 1:
                base['retry_count'] = attempt - 1
            return base
        except TimeoutError as e:
            if attempt < attempts:
                time.sleep(1.5)
                continue
            base.update({'status': 'failed', 'reason': type(e).__name__, 'detail': str(e)[:800], 'retry_count': attempt - 1})
            return base
        except urllib.error.URLError as e:
            if 'timed out' in str(e).lower() and attempt < attempts:
                time.sleep(1.5)
                continue
            base.update({'status': 'failed', 'reason': type(e).__name__, 'detail': str(e)[:800]})
            if attempt > 1:
                base['retry_count'] = attempt - 1
            return base
        except Exception as e:
            base.update({'status': 'failed', 'reason': type(e).__name__, 'detail': str(e)[:800]})
            if attempt > 1:
                base['retry_count'] = attempt - 1
            return base
    return base


def attach_ai_advisor(audit_obj, selected=None, workflow_mode=None, app_mode=None):
    if not isinstance(audit_obj, dict):
        return audit_obj
    advisor = run_ai_advisor(audit_obj, selected=selected, workflow_mode=workflow_mode, app_mode=app_mode)
    audit_obj['app_mode'] = normalize_app_mode(app_mode)
    audit_obj['ai_advisor'] = advisor
    audit_obj.setdefault('meta', {})['app_mode'] = audit_obj['app_mode']
    return audit_obj


def print_ai_advisor_summary(audit_obj):
    advisor = (audit_obj or {}).get('ai_advisor') or {}
    if not advisor:
        return
    status = advisor.get('status')
    if status == 'disabled':
        return
    print("\n=== AI advisor ===")
    if status != 'ok':
        reason = advisor.get('reason') or 'unavailable'
        print(f"AI advisor status: {status} ({reason})")
        return
    if advisor.get('guided_operator_message'):
        print(advisor.get('guided_operator_message'))
    if advisor.get('executive_summary'):
        print(f"Summary: {advisor.get('executive_summary')}")
    groups = advisor.get('prioritized_groups') or []
    if groups:
        print('Recommended order:')
        for idx, group in enumerate(groups[:3], start=1):
            issue_ids = ', '.join(group.get('issue_ids') or [])
            print(f"{idx}. {group.get('title')} [{group.get('priority')}]")
            if issue_ids:
                print(f"   Issues: {issue_ids}")
            if group.get('rationale'):
                print(f"   Why now: {group.get('rationale')}")
    for warning in (advisor.get('warnings') or [])[:3]:
        print(f"Warning: {warning}")


def ai_chat_instructions():
    return (
        "You are AgentFence AI in an interactive terminal session. "
        "Answer as a practical Kubernetes security assistant using only the provided audit context and the user's follow-up question. "
        "If live cluster, namespace, or workload inventory is present in the provided context, use it directly in your answer. "
        "Be concise, direct, and actionable. "
        "Do not invent findings or claim actions were taken when they were not. "
        "If the user asks whether to apply a fix, explain risks, validation steps, and likely impact."
    )


def openai_text_response(instructions, payload, user_message, model, timeout=60.0, api_base=None):
    api_key, _ = resolve_openai_api_key()
    if not api_key:
        raise RuntimeError('OpenAI API key is not configured in environment, macOS Keychain, or keyring')
    body = {
        'model': model,
        'instructions': instructions,
        'input': [
            {
                'role': 'user',
                'content': [
                    {
                        'type': 'input_text',
                        'text': json.dumps({'context': payload, 'question': user_message}, indent=2, sort_keys=True),
                    }
                ],
            }
        ],
        'text': {'format': {'type': 'text'}, 'verbosity': 'low'},
        'reasoning': {'effort': 'minimal'},
        'max_output_tokens': 1200,
    }
    req = urllib.request.Request(
        f"{(api_base or AI_API_BASE_DEFAULT).rstrip('/')}/responses",
        data=json.dumps(body).encode('utf-8'),
        headers={
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json',
        },
        method='POST',
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode('utf-8'))


def build_ai_chat_payload(audit_obj, selected=None, workflow_mode='guided', session=None):
    config = ai_config_from_env('ai')
    payload = build_ai_advisor_payload(audit_obj, selected=selected, workflow_mode=workflow_mode)
    advisor = audit_obj.get('ai_advisor') or {}
    if advisor.get('status') == 'ok':
        payload['advisor_summary'] = {
            'executive_summary': advisor.get('executive_summary'),
            'remediation_overview': advisor.get('remediation_overview'),
            'prioritized_groups': advisor.get('prioritized_groups'),
            'warnings': advisor.get('warnings'),
            'next_steps': advisor.get('next_steps'),
        }
    session = session or {}
    payload['session_state'] = {
        'phase': session.get('phase'),
        'cluster': session.get('cluster'),
        'namespace': session.get('namespace'),
        'current_action': session.get('action'),
        'selected_workload': {
            'workload_kind': (session.get('selected') or {}).get('workload_kind'),
            'workload_name': (session.get('selected') or {}).get('workload_name'),
        },
    }
    payload['available_app_actions'] = [
        'list_clusters',
        'use_cluster',
        'list_namespaces',
        'use_namespace',
        'show_workloads',
        'select_workload',
        'analyze',
        'backup',
        'restore',
        'fix',
        'fix_execute',
        'show_manifest',
        'status',
    ]
    payload['discovered_inventory'] = {
        'clusters': session.get('available_clusters') or [],
        'namespaces': session.get('available_namespaces') or [],
        'workloads': [
            {
                'index': idx,
                'workload_kind': item.get('workload_kind'),
                'workload_name': item.get('workload_name'),
                'pod_name': item.get('pod_name'),
                'selector': item.get('selector') or labels_to_selector(item.get('selector_labels') or {}),
            }
            for idx, item in enumerate((session.get('resources') or []), start=1)
        ],
    }
    return config, payload


def run_ai_chat_turn(audit_obj, user_message, selected=None, workflow_mode='guided', session=None):
    config, payload = build_ai_chat_payload(audit_obj, selected=selected, workflow_mode=workflow_mode, session=session)
    response = openai_text_response(
        instructions=ai_chat_instructions(),
        payload=payload,
        user_message=user_message,
        model=config['model'],
        timeout=config['timeout_seconds'],
        api_base=config['api_base'],
    )
    text = extract_text_from_response_api(response).strip()
    if text:
        return text
    raise RuntimeError('ai_chat_empty_response')


def print_ai_chat_help():
    print("\nAvailable commands:")
    print("- help")
    print("- list clusters")
    print("- use cluster <name>")
    print("- list namespaces")
    print("- use namespace <name>")
    print("- action analyze")
    print("- action backup-restore")
    print("- action remediate")
    print("- action analyze-remediate")
    print("- select <number>")
    print("- status")
    print("- analyze")
    print("- show manifest")
    print("- backup")
    print("- fix")
    print("- fix --execute")
    print("- restore")
    print("- exit")


def print_ai_session_status(session):
    print("\n=== AgentFence AI status ===")
    print(f"cluster: {session.get('cluster')}")
    print(f"namespace: {session.get('namespace')}")
    print(f"phase: {session.get('phase')}")
    print(f"action: {session.get('action')}")
    selected = session.get('selected') or {}
    if selected:
        print(f"target: {selected.get('workload_kind')}/{selected.get('workload_name')}")
    if session.get('analyze_result') or session.get('audit_data_collected'):
        print("analysis: complete")
    if session.get('backup_result'):
        print(f"backup: {session['backup_result'].get('status')}")
    if session.get('fix_result'):
        print(f"fix: {session['fix_result'].get('status')}")
    if session.get('manifest_result'):
        print("manifest: available")


def terminal_hyperlink(label, path):
    try:
        abs_path = os.path.abspath(os.path.expanduser(str(path)))
        url = Path(abs_path).as_uri()
        return f"\033]8;;{url}\033\\{label}\033]8;;\033\\ ({abs_path})"
    except Exception:
        return f"{label}: {path}"


def manifest_path_from_result(manifest_result):
    source_manifest = (manifest_result or {}).get('source_of_truth_manifest')
    if isinstance(source_manifest, dict):
        return source_manifest.get('path')
    if isinstance(source_manifest, str):
        return source_manifest
    apply_result = (manifest_result or {}).get('apply_result') or {}
    source_manifest = apply_result.get('source_of_truth_manifest')
    if isinstance(source_manifest, dict):
        return source_manifest.get('path')
    if isinstance(source_manifest, str):
        return source_manifest
    return None


def print_manifest_summary(manifest_result):
    print("\n=== Manifest recommendation ===")
    if not manifest_result:
        print("No manifest recommendation is available yet. Run `analyze` first.")
        return
    path = manifest_path_from_result(manifest_result)
    if path:
        print(f"Source-of-truth manifest: {terminal_hyperlink('Open manifest', path)}")
    apply_result = manifest_result.get('apply_result') or manifest_result
    for step in (apply_result.get('executed') or [])[:5]:
        print(f"- {step.get('step')}: {step.get('command')}")


def print_permanent_fix_explanation(audit_obj, manifest_result):
    print("\nWhat this permanent fix does:")
    remediation = ((audit_obj or {}).get('remediation') or {}).get('items') or []
    issue_ids = [item.get('issue_id') for item in remediation]
    if not issue_ids:
        print("- No concrete remediation items were generated for this workload.")
        return
    if 'SERVICE_ACCOUNT_TOKEN' in issue_ids:
        print("- Disables automatic service-account token mounting unless the workload explicitly needs Kubernetes API access.")
    if 'ROOTFS_RW' in issue_ids:
        print("- Moves the workload toward a read-only root filesystem, which may require writable paths to be relocated to volumes.")
    if 'SECCOMP_DISABLED' in issue_ids:
        print("- Enforces RuntimeDefault seccomp to reduce syscall exposure.")
    if 'NO_NEW_PRIVS_DISABLED' in issue_ids:
        print("- Disables privilege escalation in the container security context.")
    if 'SETID_BINARIES_PRESENT' in issue_ids:
        print("- Flags that the image should be rebuilt without unnecessary setuid/setgid binaries.")
    print("- Review the generated manifest in staging, validate app behavior, then promote the same manifest change through your normal deployment workflow.")


def print_artifact_summary(analyze_result=None, fix_result=None, manifest_result=None):
    print("\n=== Downloadable artifacts ===")
    if analyze_result:
        outputs = analyze_result.get('outputs') or {}
        audit_path = outputs.get('audit')
        if audit_path:
            print(f"Analyze JSON: {terminal_hyperlink('Open analyze JSON', audit_path)}")
            print(f"Analyze Markdown: {terminal_hyperlink('Open analyze Markdown', Path(audit_path).with_suffix('.md'))}")
    if fix_result:
        fix_outputs = fix_result.get('outputs') or {}
        fix_path = fix_outputs.get('fix')
        if fix_path:
            print(f"Remediation JSON: {terminal_hyperlink('Open remediation JSON', fix_path)}")
            print(f"Remediation Markdown: {terminal_hyperlink('Open remediation Markdown', Path(fix_path).with_suffix('.md'))}")
        apply_result = (fix_result.get('fix') or {}).get('apply_result') or fix_result.get('apply_result') or {}
        backup_bundle = apply_result.get('backup_bundle') or {}
        backup_manifest = backup_bundle.get('manifest')
        backup_dir = backup_bundle.get('directory')
        if backup_manifest:
            print(f"Rollback bundle manifest: {terminal_hyperlink('Open rollback bundle manifest', backup_manifest)}")
        if backup_dir:
            print(f"Rollback bundle directory: {terminal_hyperlink('Open rollback bundle directory', backup_dir)}")
    if manifest_result:
        manifest_path = manifest_path_from_result(manifest_result)
        if manifest_path:
            print(f"Manifest recommendation: {terminal_hyperlink('Open manifest recommendation', manifest_path)}")


def print_ai_analyze_completion_summary(audit_obj):
    print("\n=== Summary ===")
    meta = (audit_obj or {}).get('meta') or {}
    remediation = ((audit_obj or {}).get('remediation') or {}).get('items') or []
    issue_ids = [item.get('issue_id') for item in remediation if item.get('issue_id')]
    risk = (audit_obj or {}).get('risk_score') or {}
    print(f"Analyzed {meta.get('workload_kind') or 'workload'}/{meta.get('workload_name') or 'unknown'} in namespace {meta.get('namespace') or 'unknown'}.")
    print(f"Found {len(remediation)} security issue(s); risk score is {risk.get('total', 0)} ({risk.get('band', 'unknown')}).")
    if issue_ids:
        print(f"Important findings: {', '.join(issue_ids)}")


def print_ai_remediation_completion_summary(audit_obj, fix_result, analyze_ran=False):
    print("\n=== Summary ===")
    meta = (audit_obj or {}).get('meta') or {}
    status = (fix_result or {}).get('status') or 'unknown'
    apply_result = ((fix_result or {}).get('apply_result') or {})
    executed = (apply_result.get('executed') or [])
    health = ((fix_result or {}).get('post_fix_health') or {}).get('status')
    revalidated = apply_result.get('post_fix_revalidation') or {}
    post_risk = revalidated.get('risk_score') or (compute_risk_score(revalidated) if revalidated and not revalidated.get('error') else None)
    post_risk_suffix = " (partially verified)" if revalidated.get('risk_score_unverified') else ""
    if not post_risk:
        post_risk = (audit_obj or {}).get('risk_score') or compute_risk_score(audit_obj or {})
    action_text = "Analyzed and remediated" if analyze_ran else "Remediated"
    print(f"{action_text} {meta.get('workload_kind') or 'workload'}/{meta.get('workload_name') or 'unknown'} in namespace {meta.get('namespace') or 'unknown'}.")
    print(f"Remediation status: {status}.")
    if executed:
        print(f"Applied {len(executed)} change step(s).")
    else:
        print("No in-cluster changes were applied.")
    print(f"Recalculated risk score after remediation: {post_risk.get('total', 0)} ({post_risk.get('band', 'unknown')}){post_risk_suffix}.")
    if health:
        print(f"Post-fix health: {health}.")


def print_ai_intake_intro(session):
    print("\n=== AgentFence AI chat ===")
    print("I can help you analyze and remediate a workload.")
    print("We'll first set the cluster, namespace, and target workload from inside this chat.")
    detected_cluster = session.get('detected_cluster')
    detected_namespace = session.get('detected_namespace')
    if detected_cluster:
        print(f"Detected current cluster: {detected_cluster}")
    if detected_namespace:
        print(f"Detected current namespace: {detected_namespace}")
    print("Try `list clusters` or `use cluster <name>`, or `help`.")


def print_workload_selection_prompt(session):
    resources = session.get('resources') or []
    print_resource_list(resources, title='Available workloads')
    if resources:
        print("Select a workload with `select 1` or another number from the list above.")
    else:
        print("No workloads were discovered. Check the cluster and namespace selection, then try again.")


def print_namespaces_prompt(session):
    namespaces = session.get('available_namespaces') or []
    print("\nAvailable namespaces:")
    if namespaces:
        for idx, name in enumerate(namespaces, start=1):
            print(f"{idx}. {name}")
    else:
        print("No namespaces could be listed automatically. Use `use namespace <name>`.")


def print_action_prompt(session):
    current_action = session.get('action')
    if current_action:
        print(f"\nSelected action: {current_action}")
    else:
        print("\nAvailable actions:")
        print("- Analyze")
        print("- Backup & Restore")
        print("- Remediate")
        print("- Analyze & Remediate")
        return
    print("Available actions:")
    print("- Analyze")
    print("- Backup & Restore")
    print("- Remediate")
    print("- Analyze & Remediate")


def print_action_and_workloads(session):
    print_action_prompt(session)
    resources = discover_ai_workloads(session)
    if session.get('selected'):
        return
    print_workload_selection_prompt(session)


def execute_ai_selected_action(session):
    action = session.get('action') or 'analyze'
    cluster = session.get('cluster')
    namespace = session.get('namespace')
    selected = session.get('selected') or {}
    timeout = session.get('timeout', 2.0)
    if action == 'analyze':
        result = guided_analyze_mode(cluster, namespace, selected, timeout=timeout, allow_prompt_for_attacker=True, app_mode='ai', start_chat=False)
        session['analyze_result'] = result
        session['audit'] = result.get('audit')
        session['audit_data_collected'] = True
        session['manifest_result'] = result.get('manifest_result')
        session['phase'] = 'post_analysis'
        print("\nRecommended next step:")
        print("Enter `remediate` to fix issues in the cluster. It automatically creates a backup before applying changes.")
        print("")
        print("This is a useful way to verify that your agentic AI workload continues to run correctly after remediation.")
        print("")
        print("Later, you can use the manifest YAML file to make the changes permanent in your source automation, such as Git.")
        return True
    if action == 'backup-restore':
        result = guided_backup_restore_mode(cluster, namespace, selected, action='backup', bundle_dir=session.get('restore_bundle_dir'))
        session['backup_result'] = result
        persisted = (result.get('backup_bundle') or {}).get('directory')
        if persisted:
            session['restore_bundle_dir'] = persisted
        session['phase'] = 'post_backup'
        print("\nRecommended next step: run `restore` if you need to roll back later, or switch action to `analyze` / `remediate` and continue.")
        return True
    if action == 'remediation':
        result = guided_remediation_mode(cluster, namespace, selected, timeout=timeout, analyze_first=True, app_mode='ai', start_chat=False)
        session['fix_result'] = result.get('fix')
        session['audit'] = result.get('audit')
        session['audit_data_collected'] = True
        session['phase'] = 'post_remediation'
        print("\nRecommended next step: review post-fix health above. If the workload regressed, run `restore`.")
        return True
    if action == 'analyze-remediation':
        analyze_result = guided_analyze_mode(cluster, namespace, selected, timeout=timeout, allow_prompt_for_attacker=True, app_mode='ai', start_chat=False)
        remediation_result = guided_remediation_mode(cluster, namespace, selected, timeout=timeout, analyze_first=False, app_mode='ai', start_chat=False, analyze_bundle_override=analyze_result)
        session['analyze_result'] = analyze_result
        session['fix_result'] = remediation_result.get('fix')
        session['audit'] = remediation_result.get('audit') or analyze_result.get('audit')
        session['audit_data_collected'] = True
        session['manifest_result'] = analyze_result.get('manifest_result')
        session['phase'] = 'post_remediation'
        print("\nRecommended next step: review post-fix health above. If the workload regressed, run `restore`.")
        return True
    print(f"Unsupported action: {action}")
    return True


def discover_ai_workloads(session):
    resources = [r for r in list_candidate_resources(session['namespace']) if not is_attacker_resource(r)]
    session['resources'] = resources
    if len(resources) == 1:
        session['selected'] = resources[0]
        session['phase'] = 'ready_for_analysis'
    else:
        session['selected'] = None
        session['phase'] = 'awaiting_workload_selection'
    return resources


def list_clusters():
    current = current_cluster_name()
    if has_kubectl():
        rc, out = shell_rc("kubectl config view -o json", timeout=15)
        if rc == 0:
            try:
                obj = json.loads(out)
                names = []
                seen = set()
                for ctx in (obj.get('contexts') or []):
                    cluster_name = get_nested(ctx, 'context', 'cluster')
                    if cluster_name and cluster_name not in seen:
                        seen.add(cluster_name)
                        names.append(cluster_name)
                if names:
                    if current and current in names:
                        names = [current] + [name for name in names if name != current]
                    return names
            except Exception:
                pass
    if current:
        return [current]
    return []


def resolve_cluster_input(value, session=None):
    raw = (value or '').strip()
    if not raw:
        return None
    clusters = list((session or {}).get('available_clusters') or [])
    if not clusters:
        clusters = list_clusters()
        if session is not None:
            session['available_clusters'] = clusters
    if raw.isdigit():
        idx = int(raw)
        if 1 <= idx <= len(clusters):
            return clusters[idx - 1]
    raw_lower = raw.lower()
    exact_matches = []
    for name in clusters:
        lowered = (name or '').lower()
        if lowered == raw_lower:
            exact_matches.append(name)
    if exact_matches:
        return exact_matches[0]
    partial_matches = [name for name in clusters if raw_lower in (name or '').lower()]
    if len(partial_matches) == 1:
        return partial_matches[0]
    return raw


def safe_resolve_cluster_or_current(value, session=None):
    resolved = resolve_cluster_input(value, session=session)
    try:
        return ensure_cluster_matches(resolved)
    except RuntimeError:
        current = current_cluster_name()
        if current:
            lowered = (str(value or '').strip().lower())
            if lowered and lowered in current.lower():
                return current
        raise


def resolve_namespace_input(value, session=None):
    raw = (value or '').strip()
    if not raw:
        return None
    namespaces = list((session or {}).get('available_namespaces') or [])
    if not namespaces and (session or {}).get('cluster'):
        namespaces = list_namespaces()
        if session is not None:
            session['available_namespaces'] = namespaces
    if raw.isdigit():
        idx = int(raw)
        if 1 <= idx <= len(namespaces):
            return namespaces[idx - 1]
    raw_lower = raw.lower()
    exact_matches = []
    for name in namespaces:
        lowered = (name or '').lower()
        if lowered == raw_lower:
            exact_matches.append(name)
    if exact_matches:
        return exact_matches[0]
    partial_matches = [name for name in namespaces if raw_lower in (name or '').lower()]
    if len(partial_matches) == 1:
        return partial_matches[0]
    return raw


def resolve_workload_input(value, session=None):
    raw = (value or '').strip()
    if not raw:
        return None
    resources = list((session or {}).get('resources') or [])
    if raw.isdigit():
        idx = int(raw)
        if 1 <= idx <= len(resources):
            return resources[idx - 1]
    raw_lower = raw.lower()
    exact_matches = []
    for item in resources:
        workload_name = (item.get('workload_name') or '').lower()
        pod_name = (item.get('pod_name') or '').lower()
        if raw_lower in (workload_name, pod_name):
            exact_matches.append(item)
    if exact_matches:
        return exact_matches[0]
    partial_matches = []
    for item in resources:
        workload_name = (item.get('workload_name') or '').lower()
        pod_name = (item.get('pod_name') or '').lower()
        if raw_lower and (raw_lower in workload_name or raw_lower in pod_name):
            partial_matches.append(item)
    if len(partial_matches) == 1:
        return partial_matches[0]
    return None


def resolve_namespace_from_free_text(value, session=None):
    raw = (value or '').strip().lower()
    if not raw:
        return None
    namespaces = list((session or {}).get('available_namespaces') or [])
    if not namespaces and (session or {}).get('cluster'):
        namespaces = list_namespaces()
        if session is not None:
            session['available_namespaces'] = namespaces
    tokens = [tok for tok in re.split(r'[^a-z0-9-]+', raw) if tok]
    matches = []
    for name in namespaces:
        lowered = (name or '').lower()
        if raw in lowered:
            matches.append(name)
            continue
        if any(tok and tok in lowered for tok in tokens):
            matches.append(name)
    matches = list(dict.fromkeys(matches))
    if len(matches) == 1:
        return matches[0]
    return None


def resolve_workload_from_free_text(value, session=None):
    raw = (value or '').strip().lower()
    if not raw:
        return None
    resources = list((session or {}).get('resources') or [])
    tokens = [tok for tok in re.split(r'[^a-z0-9-]+', raw) if tok]
    matches = []
    for item in resources:
        workload_name = (item.get('workload_name') or '').lower()
        pod_name = (item.get('pod_name') or '').lower()
        joined = f"{workload_name} {pod_name}"
        if raw in joined or any(tok and tok in joined for tok in tokens):
            matches.append(item)
    deduped = []
    seen = set()
    for item in matches:
        key = (item.get('workload_name'), item.get('pod_name'))
        if key in seen:
            continue
        seen.add(key)
        deduped.append(item)
    matches = deduped
    if len(matches) == 1:
        return matches[0]
    return None


def ai_command_interpreter_instructions():
    return (
        "Map the user's terminal message into an AgentFence command intent. "
        "Use the provided session inventory and phase. "
        "Return JSON only. "
        "Prefer mapping the message to one of the app's available actions whenever reasonably possible. "
        "If the user is asking to move the workflow forward, choose the most appropriate app action instead of returning chat. "
        "If the message is a normal security question rather than a workflow command or workflow choice, return intent=chat. "
        "Prefer deterministic actions when the user appears to be choosing a listed cluster, namespace, or workload by number or by exact name. "
        "Allowed intents: help, list_clusters, use_cluster, list_namespaces, use_namespace, show_workloads, select_workload, status, analyze, show_manifest, backup, fix, fix_execute, restore, exit, chat."
    )


def ai_command_response_format():
    return {
        'type': 'json_schema',
        'name': 'agentfence_ai_command',
        'schema': {
            'type': 'object',
            'additionalProperties': False,
            'properties': {
                'intent': {'type': 'string'},
                'target_type': {'type': 'string'},
                'target_value': {'type': 'string'},
            },
            'required': ['intent', 'target_type', 'target_value'],
        },
    }


def interpret_ai_command_with_llm(session, user_message):
    config, payload = build_ai_chat_payload((session.get('audit') or {}), selected=session.get('selected'), workflow_mode='guided', session=session)
    payload['command_request'] = user_message
    body = {
        'model': config['model'],
        'instructions': ai_command_interpreter_instructions(),
        'input': [
            {
                'role': 'user',
                'content': [{'type': 'input_text', 'text': json.dumps(payload, indent=2, sort_keys=True)}],
            }
        ],
        'text': {'format': ai_command_response_format(), 'verbosity': 'low'},
        'reasoning': {'effort': 'minimal'},
        'max_output_tokens': 300,
    }
    api_key, _ = resolve_openai_api_key()
    req = urllib.request.Request(
        f"{AI_API_BASE_DEFAULT.rstrip('/')}/responses",
        data=json.dumps(body).encode('utf-8'),
        headers={'Authorization': f'Bearer {api_key}', 'Content-Type': 'application/json'},
        method='POST',
    )
    with urllib.request.urlopen(req, timeout=config['timeout_seconds']) as resp:
        data = json.loads(resp.read().decode('utf-8'))
    text = extract_text_from_response_api(data).strip()
    if not text:
        return None
    try:
        return json.loads(text)
    except Exception:
        return None


def run_ai_session_command(session, user_message):
    command = user_message.strip()
    command_lower = command.lower()
    selected = session.get('selected') or {}
    cluster = session.get('cluster')
    namespace = session.get('namespace')
    timeout = session.get('timeout', 2.0)
    bundle_dir = session.get('restore_bundle_dir')
    if (
        session.get('namespace')
        and not session.get('selected')
        and session.get('resources')
        and len(session.get('resources') or []) == 1
        and any(token in command_lower for token in ('inspect', 'analy', 'analyze', 'review the target', 'inspect the target', 'go ahead'))
    ):
        session['selected'] = (session.get('resources') or [None])[0]
        session['phase'] = 'ready_for_analysis'
        session['action'] = 'analyze'
        selected_obj = session['selected']
        print(f"\nSelected workload: {selected_obj.get('workload_kind')}/{selected_obj.get('workload_name')}")
        return execute_ai_selected_action(session)
    if command.isdigit():
        return run_ai_session_command(session, f'choose {command}')
    if command == 'help':
        print_ai_chat_help()
        return True
    if command_lower in ('list clusters', 'list cluster', 'show clusters', 'show cluster'):
        clusters = list_clusters()
        session['available_clusters'] = clusters
        print("\nAvailable clusters:")
        if clusters:
            for idx, name in enumerate(clusters, start=1):
                print(f"{idx}. {name}")
        else:
            print("No clusters could be discovered automatically. Use `use cluster <name>`.")
        return True
    if command_lower.startswith('use cluster ') or command_lower.startswith('select cluster ') or command_lower.startswith('choose cluster '):
        if command_lower.startswith('use cluster '):
            value = command[len('use cluster '):].strip()
        elif command_lower.startswith('select cluster '):
            value = command[len('select cluster '):].strip()
        else:
            value = command[len('choose cluster '):].strip()
        if not value:
            print("Provide a cluster name, for example `use cluster kubernetes`.")
            return True
        try:
            resolved = safe_resolve_cluster_or_current(value, session=session)
        except RuntimeError as e:
            print(f"{e}")
            print("Try `list clusters` and choose one of the discovered options.")
            return True
        session['cluster'] = resolved
        if session.get('phase') == 'awaiting_cluster':
            session['phase'] = 'awaiting_namespace'
        print(f"\nUsing cluster: {resolved}")
        session['available_namespaces'] = list_namespaces()
        print_namespaces_prompt(session)
        return True
    if command_lower.startswith('choose '):
        choice = command[len('choose '):].strip()
        if not session.get('cluster'):
            if choice:
                try:
                    resolved = safe_resolve_cluster_or_current(choice, session=session)
                except RuntimeError as e:
                    print(f"{e}")
                    print("Try `list clusters` and choose one of the discovered options.")
                    return True
                session['cluster'] = resolved
                session['phase'] = 'awaiting_namespace'
                print(f"\nUsing cluster: {resolved}")
                session['available_namespaces'] = list_namespaces()
                print_namespaces_prompt(session)
                return True
        namespaces = session.get('available_namespaces') or []
        if namespaces and session.get('cluster') and (not session.get('namespace') or not (session.get('resources') or [])):
            selected_namespace = resolve_namespace_input(choice, session=session)
            if selected_namespace:
                session['namespace'] = selected_namespace
                session['phase'] = 'awaiting_action'
                session['action'] = None
                print(f"\nUsing namespace: {selected_namespace}")
                print_action_and_workloads(session)
                return True
        resources = session.get('resources') or []
        if resources:
            resolved_workload = resolve_workload_input(choice, session=session)
            if resolved_workload:
                session['selected'] = resolved_workload
                session['phase'] = 'ready_for_analysis'
                selected_obj = session['selected']
                print(f"\nSelected workload: {selected_obj.get('workload_kind')}/{selected_obj.get('workload_name')}")
                if session.get('action'):
                    return execute_ai_selected_action(session)
                print_action_prompt(session)
                return True
        # Let the GPT-backed command interpreter try to map this ambiguous choice
        # against the currently available clusters, namespaces, or workloads.
    if session.get('cluster') and not session.get('namespace'):
        selected_namespace = resolve_namespace_from_free_text(command, session=session)
        if selected_namespace:
            session['namespace'] = selected_namespace
            session['phase'] = 'awaiting_action'
            session['action'] = None
            print(f"\nUsing namespace: {selected_namespace}")
            print_action_and_workloads(session)
            return True
    if session.get('namespace') and not session.get('selected') and (session.get('resources') or []):
        resolved_workload = resolve_workload_from_free_text(command, session=session)
        if resolved_workload:
            session['selected'] = resolved_workload
            session['phase'] = 'ready_for_analysis'
            selected_obj = session['selected']
            print(f"\nSelected workload: {selected_obj.get('workload_kind')}/{selected_obj.get('workload_name')}")
            if session.get('action'):
                return execute_ai_selected_action(session)
            print_action_prompt(session)
            return True
    if command_lower in ('list namespaces', 'list namespace', 'show namespaces', 'show namespace'):
        if not session.get('cluster'):
            print("Set a cluster first with `use cluster <name>` or `choose <number>` from `list clusters`.")
            return True
        namespaces = list_namespaces()
        session['available_namespaces'] = namespaces
        print("\nAvailable namespaces:")
        if namespaces:
            for idx, name in enumerate(namespaces, start=1):
                print(f"{idx}. {name}")
        else:
            print("No namespaces could be listed automatically. Use `use namespace <name>`.")
        return True
    if command_lower.startswith('list namespace for ') or command_lower.startswith('list namespaces for '):
        if command_lower.startswith('list namespace for '):
            value = command[len('list namespace for '):].strip()
        else:
            value = command[len('list namespaces for '):].strip()
        try:
            resolved = safe_resolve_cluster_or_current(value, session=session)
        except RuntimeError as e:
            print(f"{e}")
            print("Try `list clusters` and choose one of the discovered options.")
            return True
        session['cluster'] = resolved
        session['phase'] = 'awaiting_namespace'
        session['available_namespaces'] = list_namespaces()
        print(f"\nUsing cluster: {resolved}")
        print_namespaces_prompt(session)
        return True
    if command.startswith('use namespace '):
        value = command[len('use namespace '):].strip()
        if not value:
            print("Provide a namespace name, for example `use namespace sandbox-cua`.")
            return True
        if not session.get('cluster'):
            print("Set a cluster first with `use cluster <name>`.")
            return True
        session['namespace'] = value
        if session.get('phase') in ('awaiting_cluster', 'awaiting_namespace'):
            session['phase'] = 'awaiting_action'
        session['action'] = None
        print(f"\nUsing namespace: {value}")
        print_action_and_workloads(session)
        return True
    if command_lower in ('backup & restore', 'backup and restore', 'backup-restore', 'remediate', 'analyze and remediate', 'analyze-remediate', 'analyze-remediation'):
        if command_lower in ('backup & restore', 'backup and restore', 'backup-restore'):
            session['action'] = 'backup-restore'
        elif command_lower == 'remediate':
            session['action'] = 'remediation'
        else:
            session['action'] = 'analyze-remediation'
        if session.get('selected'):
            return execute_ai_selected_action(session)
        if session.get('namespace'):
            print_action_and_workloads(session)
        else:
            print_action_prompt(session)
        return True
    if command_lower.startswith('action '):
        value = command[len('action '):].strip().lower()
        if value in ('analyze', 'analysis'):
            session['action'] = 'analyze'
        elif value in ('backup-restore', 'backup & restore', 'backup and restore', 'backup', 'backuprestore'):
            session['action'] = 'backup-restore'
        elif value in ('remediate', 'remediation'):
            session['action'] = 'remediation'
        elif value in ('analyze-remediate', 'analyze and remediate', 'analyze-remediation'):
            session['action'] = 'analyze-remediation'
        else:
            print("Use `action analyze`, `action backup-restore`, `action remediate`, or `action analyze-remediate`.")
            return True
        if session.get('selected'):
            return execute_ai_selected_action(session)
        if session.get('namespace'):
            print_action_and_workloads(session)
        else:
            print_action_prompt(session)
        return True
    if command == 'show workloads':
        print_workload_selection_prompt(session)
        return True
    if command.startswith('select '):
        raw_idx = command[len('select '):].strip()
        resources = session.get('resources') or []
        if resources:
            resolved_workload = resolve_workload_input(raw_idx, session=session)
            if resolved_workload:
                session['selected'] = resolved_workload
                session['phase'] = 'ready_for_analysis'
                selected_obj = session['selected']
                print(f"\nSelected workload: {selected_obj.get('workload_kind')}/{selected_obj.get('workload_name')}")
                if session.get('action'):
                    return execute_ai_selected_action(session)
                print_action_prompt(session)
                return True
        namespaces = session.get('available_namespaces') or []
        if namespaces and session.get('cluster') and (not session.get('namespace') or not resources):
            selected_namespace = resolve_namespace_input(raw_idx, session=session)
            if selected_namespace:
                session['namespace'] = selected_namespace
                session['phase'] = 'awaiting_action'
                session['action'] = None
                print(f"\nUsing namespace: {selected_namespace}")
                print_action_and_workloads(session)
                return True
        if not resources:
            print("No workloads are loaded yet. Pick a namespace first, or try the selection again.")
            return True
        # Fall through so GPT can try to map partial or fuzzy workload choices.
    if command == 'status':
        print_ai_session_status(session)
        return True
    if command == 'analyze':
        if not cluster or not namespace:
            print("Set cluster and namespace first.")
            return True
        if not selected:
            resources = session.get('resources') or discover_ai_workloads(session)
            if len(resources) == 1:
                session['selected'] = resources[0]
                session['phase'] = 'ready_for_analysis'
                selected = session['selected']
                print(f"\nSelected workload: {selected.get('workload_kind')}/{selected.get('workload_name')}")
            else:
                print_workload_selection_prompt(session)
                return True
        session['action'] = 'analyze'
        return execute_ai_selected_action(session)
    if command == 'show manifest':
        print_manifest_summary(session.get('manifest_result'))
        return True
    if command == 'backup':
        result = guided_backup_restore_mode(cluster, namespace, selected, action='backup', bundle_dir=None)
        session['backup_result'] = result
        persisted = (result.get('backup_bundle') or {}).get('directory')
        if persisted:
            session['restore_bundle_dir'] = persisted
        print("\nRecommended next step: run `fix --execute` to apply supported fixes with rollback artifacts and post-fix validation.")
        return True
    if command == 'fix':
        print("\nUse `fix --execute` to apply supported fixes. Review the manifest recommendation first with `show manifest` and create a backup with `backup`.")
        return True
    if command == 'fix --execute':
        result = guided_remediation_mode(cluster, namespace, selected, timeout=timeout, analyze_first=False, app_mode='ai', start_chat=False, analyze_bundle_override=session.get('analyze_result'))
        session['fix_result'] = result.get('fix')
        if result.get('audit'):
            session['audit'] = result.get('audit')
        print("\nRecommended next step: review post-fix health above. If the workload regressed, run `restore`.")
        return True
    if command == 'restore':
        try:
            result = guided_backup_restore_mode(cluster, namespace, selected, action='restore', bundle_dir=bundle_dir)
            session['restore_result'] = result
        except RuntimeError as e:
            print(f"\nRestore is not available yet: {e}")
            print("Create a backup first with `backup`, or run the `Backup & Restore` action before trying `restore`.")
        return True
    interpreted = interpret_ai_command_with_llm(session, user_message)
    if interpreted:
        intent = (interpreted.get('intent') or '').strip().lower()
        target_value = (interpreted.get('target_value') or '').strip()
        target_type = (interpreted.get('target_type') or '').strip().lower()
        if intent in ('exit', 'chat'):
            return False
        if intent == 'list_clusters':
            return run_ai_session_command(session, 'list clusters')
        if intent == 'use_cluster':
            value = target_value or ('1' if target_type == 'number' else '')
            if value:
                return run_ai_session_command(session, f'use cluster {value}')
        if intent == 'list_namespaces':
            if target_value:
                return run_ai_session_command(session, f'list namespaces for {target_value}')
            return run_ai_session_command(session, 'list namespaces')
        if intent == 'use_namespace' and target_value:
            return run_ai_session_command(session, f'use namespace {target_value}')
        if intent == 'show_workloads':
            return run_ai_session_command(session, 'show workloads')
        if intent == 'select_workload' and target_value:
            return run_ai_session_command(session, f'select {target_value}')
        if intent == 'status':
            return run_ai_session_command(session, 'status')
        if intent == 'analyze':
            return run_ai_session_command(session, 'analyze')
        if intent == 'show_manifest':
            return run_ai_session_command(session, 'show manifest')
        if intent == 'backup':
            return run_ai_session_command(session, 'backup')
        if intent == 'fix':
            return run_ai_session_command(session, 'fix')
        if intent == 'fix_execute':
            return run_ai_session_command(session, 'fix --execute')
        if intent == 'restore':
            return run_ai_session_command(session, 'restore')
        if intent == 'help':
            return run_ai_session_command(session, 'help')
    return False


def start_ai_chat_session(audit_obj, selected=None, workflow_mode='guided', session=None):
    active_mode = normalize_app_mode(((audit_obj or {}).get('app_mode')) or (session or {}).get('app_mode'))
    if active_mode != 'ai':
        return
    print_ai_intake_intro(session or {})
    print("Type `exit`, `quit`, or `q` to leave the chat.")
    print("Type `help` to see available workflow commands.")
    while True:
        try:
            raw = input("agentfence-ai> ")
        except EOFError:
            print("\nExiting AgentFence AI chat.")
            return
        user_message = (raw or '').strip()
        if not user_message:
            print("Type a question, or `exit` to leave the chat.")
            continue
        if user_message.lower() in ('exit', 'quit', 'q'):
            print("Exiting AgentFence AI chat.")
            return
        current_audit = (session or {}).get('audit') or audit_obj
        current_selected = (session or {}).get('selected') or selected
        if session and run_ai_session_command(session, user_message):
            if session.get('audit'):
                audit_obj = session['audit']
            if session.get('selected'):
                selected = session['selected']
            continue
        try:
            print("\n" + "=" * 72)
            print("User")
            print("-" * 72)
            print(user_message)
            answer = run_ai_chat_turn(current_audit, user_message, selected=current_selected, workflow_mode=workflow_mode, session=session)
            print("\n" + "-" * 72)
            print("AgentFence AI")
            print("-" * 72)
            print(answer)
            print("=" * 72)
        except Exception as e:
            print("\n" + "-" * 72)
            print("AgentFence AI")
            print("-" * 72)
            print(f"{type(e).__name__}: {e}")
            print("=" * 72)


def load_history(path=SMART_HISTORY_PATH):
    try:
        if os.path.exists(path):
            with open(path, 'r') as f:
                obj = json.load(f)
                if isinstance(obj, dict):
                    obj.setdefault('runs', [])
                    return obj
    except Exception:
        pass
    return {'runs': []}


def save_history(history, path=SMART_HISTORY_PATH):
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
    except Exception:
        pass
    try:
        with open(path, 'w') as f:
            json.dump(history, f, indent=2)
    except Exception:
        pass


def infer_workload_intent(audit_obj):
    res = (audit_obj.get('results') or {})
    deps = (audit_obj.get('dependencies') or {})
    meta = (audit_obj.get('meta') or {})
    listener_entries = extract_listener_ports(audit_obj)
    listener_ports = sorted({entry.get('port') for entry in listener_entries if isinstance(entry, dict) and isinstance(entry.get('port'), int)})
    services = deps.get('services') or []
    intent = []
    explanation = []
    if any(p in listener_ports for p in [5901, 6901]):
        intent.append('desktop-sandbox')
        explanation.append('Detected VNC/noVNC listener patterns associated with GUI sandbox workloads.')
    if 8000 in listener_ports or services:
        intent.append('service-endpoint')
        explanation.append('Detected service-like port exposure or Kubernetes Service objects selecting the workload.')
    if meta.get('workload_kind') in ('Job', 'CronJob'):
        intent.append('batch-job')
        explanation.append('Owner kind indicates a batch-oriented workload.')
    if not intent:
        intent.append('generic-sandbox')
        explanation.append('No strong service or desktop indicators were detected; treating as generic sandbox workload.')
    if deps.get('runtime_class'):
        explanation.append(f"RuntimeClass {deps.get('runtime_class')} contributes to runtime-specific remediation choices.")
    needs = {
        'network_egress': bool((audit_obj.get('remote') or {}).get('kubernetes_api_https') or deps.get('services')),
        'service_account': bool(get_nested(audit_obj, 'kubernetes', 'service_account_token_mounted', 'ok') is False or get_nested(audit_obj, 'results', 'service_account_token_present', 'ok') is False),
        'writable_workspace': bool(get_nested(audit_obj, 'results', 'rootfs_readonly', 'ok') is False or get_nested(audit_obj, 'kubernetes', 'rootfs_readonly', 'ok') is False),
    }
    return {
        'intent': sorted(set(intent)),
        'listener_ports': listener_ports,
        'services': services,
        'needs': needs,
        'explanation': explanation,
    }


def detect_environment_profile(audit_obj):
    meta = audit_obj.get('meta', {}) or {}
    ns = (meta.get('namespace') or '').lower()
    if ns in ('prod', 'production'):
        return 'production'
    if ns in ('stage', 'staging', 'preprod'):
        return 'staging'
    if ns in ('dev', 'development'):
        return 'dev'
    if 'desktop' in json.dumps(infer_workload_intent(audit_obj)).lower():
        return 'sandbox-desktop'
    return 'lab'


def build_dependency_graph(audit_obj):
    meta = audit_obj.get('meta', {}) or {}
    deps = audit_obj.get('dependencies', {}) or {}
    pod = meta.get('target_pod') or meta.get('pod_name') or 'unknown-pod'
    workload = meta.get('workload_name') or 'unknown-workload'
    graph = {
        'nodes': [
            {'id': pod, 'type': 'Pod'},
            {'id': workload, 'type': meta.get('workload_kind') or 'Workload'},
        ],
        'edges': [
            {'from': pod, 'to': workload, 'relationship': 'owned_by'},
        ],
    }
    for key, typ in [('services', 'Service'), ('ingresses', 'Ingress'), ('network_policies', 'NetworkPolicy'), ('hpas', 'HPA'), ('pdbs', 'PDB'), ('configmaps', 'ConfigMap'), ('secrets', 'Secret')]:
        for item in deps.get(key, []) or []:
            graph['nodes'].append({'id': item, 'type': typ})
            rel = 'selects' if typ in ('Service', 'NetworkPolicy') else 'depends_on'
            graph['edges'].append({'from': workload, 'to': item, 'relationship': rel})
    return graph


def confidence_from_item(item, audit_obj):
    base = 0.55
    reasons = []
    evidence = (item.get('evidence') or '') + ' ' + (item.get('summary') or '')
    if evidence.strip():
        base += 0.15
        reasons.append('Finding has direct evidence from audit probes.')
    if item.get('issue_id') in ('NOVNC_LISTENER', 'REMOTE_REACHABILITY', 'IMDS_REACHABLE'):
        base += 0.10
        reasons.append('Finding is backed by active network reachability evidence.')
    if item.get('risk_level') in ('high', 'critical'):
        base += 0.05
        reasons.append('Higher-severity items are prioritized with additional confidence weighting.')
    if item.get('issue_id') in ('RUN_AS_ROOT', 'ROOTFS_RW'):
        base -= 0.10
        reasons.append('Remediation safety depends heavily on workload behavior and image design.')
    fconf = min(0.98, max(0.20, base))
    sconf = min(0.98, max(0.10, fconf - (0.18 if item.get('risk_level') in ('high', 'critical') else 0.05)))
    return {
        'finding_confidence': round(fconf, 2),
        'fix_confidence': round(min(0.98, fconf - 0.03), 2),
        'safety_confidence': round(sconf, 2),
        'reasons': reasons,
    }


def pre_fix_validation_model(audit_obj, item):
    issue = item.get('issue_id')
    intent = infer_workload_intent(audit_obj)
    deps = audit_obj.get('dependencies', {}) or {}
    risks = []
    safe = True
    if issue == 'ROOTFS_RW':
        risks.append('Application may write under root-owned paths; verify /tmp, /var/tmp, and workspace mounts before enabling read-only root filesystem.')
        safe = False
    elif issue == 'RUN_AS_ROOT':
        risks.append('Non-root enforcement may fail if entrypoint scripts, permissions, or package-manager expectations require UID 0.')
        safe = False
    elif issue == 'REMOTE_REACHABILITY':
        if deps.get('services') or 'service-endpoint' in intent.get('intent', []):
            risks.append('NetworkPolicy tightening may interrupt legitimate east-west traffic that currently reaches this workload.')
            safe = False
    elif issue == 'SERVICE_ACCOUNT_TOKEN':
        if intent.get('needs', {}).get('service_account'):
            risks.append('ServiceAccount token appears present and may be used for Kubernetes API access; confirm before disabling automount.')
            safe = False
    elif issue == 'NOVNC_LISTENER':
        if 'desktop-sandbox' in intent.get('intent', []):
            risks.append('Desktop sandbox mode inferred; removing or isolating noVNC/VNC endpoints may be preferable to outright disablement.')
            safe = False
    elif issue == 'LINUX_CAPS':
        risks.append('Capability minimization is generally safe, but verify whether raw sockets are intentionally needed for diagnostics.')
    return {
        'safe_to_autofix': safe and item.get('risk_level') not in ('high', 'critical'),
        'predicted_risks': risks,
        'predicted_breakage': bool(risks and not safe),
    }


def explain_fix_decision(item, audit_obj):
    model = pre_fix_validation_model(audit_obj, item)
    reason = []
    if item.get('auto_applicable') and model.get('safe_to_autofix'):
        decision = 'auto-apply-safe'
        reason.append('Fix is represented as a bounded Kubernetes patch or policy artifact with low predicted blast radius.')
    elif item.get('auto_applicable'):
        decision = 'conditional-approval'
        reason.append('Fix can be generated automatically, but workload compatibility is uncertain and operator approval is recommended.')
    else:
        decision = 'manual-only'
        reason.append('Fix requires workload redesign, image changes, or environment-specific validation beyond safe automatic patching.')
    if model.get('predicted_risks'):
        reason.extend(model.get('predicted_risks'))
    return {'decision': decision, 'reasoning': reason}


def knowledge_base_patterns(audit_obj):
    patterns = []
    res = audit_obj.get('results', {}) or {}
    k8s = audit_obj.get('kubernetes', {}) or {}
    rem = ((audit_obj.get('remediation') or {}).get('items') or [])
    ids = {x.get('issue_id') for x in rem}
    if 'RUN_AS_ROOT' in ids and 'ROOTFS_RW' in ids and 'SECCOMP_DISABLED' in ids:
        patterns.append({
            'pattern': 'container-hardening-bundle',
            'recommendation': 'Apply a bundled pod securityContext hardening set: non-root, RuntimeDefault seccomp, no privilege escalation, drop capabilities, and evaluate read-only rootfs with writable scratch volumes.',
        })
    if 'NOVNC_LISTENER' in ids and 'REMOTE_REACHABILITY' in ids:
        patterns.append({
            'pattern': 'desktop-exposure-containment',
            'recommendation': 'Retain GUI endpoints only if required, then contain them with NetworkPolicy, auth, and exposure scoping rather than unrestricted pod-to-pod reachability.',
        })
    if 'SERVICE_ACCOUNT_TOKEN' in ids and not k8s.get('kubernetes_api_https', {}).get('ok'):
        patterns.append({
            'pattern': 'service-account-token-minimization',
            'recommendation': 'Disable automountServiceAccountToken when token presence is not matched by observed Kubernetes API usage.',
        })
    return patterns


def comparative_runtime_intelligence(audit_obj):
    meta = audit_obj.get('meta', {}) or {}
    text = json.dumps(meta).lower() + ' ' + json.dumps(audit_obj.get('dependencies', {})).lower()
    runtime_key = None
    for k in RUNTIME_INTELLIGENCE:
        if k in text:
            runtime_key = k
            break
    if not runtime_key:
        return {'runtime': 'unknown', 'notes': []}
    info = RUNTIME_INTELLIGENCE[runtime_key]
    notes = [info['summary']]
    listener_ports = infer_workload_intent(audit_obj).get('listener_ports', [])
    unexpected = [p for p in listener_ports if p not in info['expected_services']]
    if unexpected:
        notes.append(f'Ports {unexpected} are not typical for the inferred {runtime_key} profile and should be reviewed as possible posture deviations.')
    else:
        notes.append(f'Observed listener profile is consistent with the inferred {runtime_key} runtime expectations.')
    notes.append(f"Recommended fix profiles: {', '.join(info.get('recommended_profiles', []))}.")
    return {'runtime': runtime_key, 'notes': notes}


def history_insights(audit_obj, history):
    runs = history.get('runs', [])[-25:]
    current_ids = [x.get('issue_id') for x in ((audit_obj.get('remediation') or {}).get('items') or [])]
    repeats = {}
    learned = []
    for run in runs:
        for iid in run.get('issue_ids', []):
            repeats[iid] = repeats.get(iid, 0) + 1
    for iid in current_ids:
        if repeats.get(iid, 0) >= 2:
            learned.append(f'{iid} has appeared in {repeats[iid]} recent runs; consider promoting this into a default policy or baseline control.')
    recent_failures = [r for r in runs if r.get('fix_status') == 'partial_failure']
    if recent_failures:
        learned.append('Recent runs include partial fix failures; review manual approval thresholds before aggressive automatic remediation.')
    return {'repeated_findings': repeats, 'notes': learned}


def manual_runbook_for_item(item, audit_obj):
    ns = ((audit_obj.get('meta') or {}).get('namespace')) or 'default'
    wl = ((audit_obj.get('meta') or {}).get('workload_name')) or '<workload>'
    iid = item.get('issue_id')
    steps = []
    rollback = []
    if iid == 'RUN_AS_ROOT':
        steps = [
            'Inspect the image entrypoint and file ownership requirements.',
            'Add a dedicated non-root UID/GID and update writable paths.',
            'Set runAsNonRoot: true and explicit runAsUser/runAsGroup in the pod securityContext.',
            'Redeploy and verify readiness and core application workflows.',
        ]
        rollback = ['Revert the workload manifest or apply the rollback patch snapshot generated by the tool if the container fails to start.']
    elif iid == 'ROOTFS_RW':
        steps = [
            'Identify write paths from logs, entrypoint scripts, and runtime behavior.',
            'Move mutable paths to emptyDir or persistent volumes.',
            'Enable readOnlyRootFilesystem and redeploy.',
            'Validate application startup, temp-file creation, and user workflow paths.',
        ]
        rollback = ['Restore the previous writable filesystem setting and mounted scratch volumes if the application becomes unstable.']
    elif iid == 'REMOTE_REACHABILITY':
        steps = [
            'Review Services, Ingresses, and expected peer workloads that communicate with the target.',
            'Generate or refine a least-privilege NetworkPolicy that preserves only required ports and peers.',
            'Apply the policy in a dry-run or staging environment first.',
            'Re-run the remote audit to confirm intended paths still work and unintended paths are blocked.',
        ]
        rollback = ['Delete or roll back the generated NetworkPolicy if legitimate traffic is interrupted.']
    else:
        steps = ['Review the generated remediation recommendation and compatibility notes.', 'Apply the fix in a staging-safe manner and re-run the audit.']
        rollback = ['Use the generated rollback artifacts or restore the prior manifest revision.']
    commands = [f'kubectl -n {ns} get all', f'kubectl -n {ns} describe deploy/{wl}']
    return {'issue_id': iid, 'title': item.get('title'), 'steps': steps, 'rollback': rollback, 'validation_commands': commands}


def policy_reasoning(audit_obj, item):
    dep = audit_obj.get('dependency_graph') or {}
    service_count = len((audit_obj.get('dependencies') or {}).get('services') or [])
    reasons = []
    if item.get('issue_id') == 'REMOTE_REACHABILITY':
        reasons.append(f'NetworkPolicy generation preserved known Service-linked or inferred listener ports and blocks unmodeled paths by omission.')
        if service_count:
            reasons.append(f'{service_count} Service object(s) were discovered, so ingress policy should preserve only those expected service ports.')
    elif item.get('issue_id') == 'SERVICE_ACCOUNT_TOKEN':
        reasons.append('ServiceAccount remediation is governed by observed token presence plus whether Kubernetes API access appears necessary.')
    elif item.get('issue_id') == 'NOVNC_LISTENER':
        reasons.append('Desktop-oriented listener exposure is treated differently when workload intent suggests a GUI sandbox use case.')
    if dep.get('edges'):
        reasons.append('Dependency graph was used to avoid patching the pod in isolation when workload-scoped resources depend on it.')
    return reasons


def apply_smart_enrichment(audit_obj, history=None):
    audit_obj = dict(audit_obj)
    audit_obj.setdefault('meta', {})
    audit_obj['intent_inference'] = infer_workload_intent(audit_obj)
    audit_obj['environment_profile'] = detect_environment_profile(audit_obj)
    audit_obj['dependency_graph'] = build_dependency_graph(audit_obj)
    audit_obj['runtime_intelligence'] = comparative_runtime_intelligence(audit_obj)
    audit_obj['remediation'] = enrich_remediation(audit_obj.get('remediation') or remediation_from_audit(audit_obj))
    items = []
    for item in (audit_obj.get('remediation', {}).get('items') or []):
        item = dict(item)
        item['base_auto_applicable'] = item.get('auto_applicable', False)
        item['confidence'] = confidence_from_item(item, audit_obj)
        item['pre_fix_model'] = pre_fix_validation_model(audit_obj, item)
        decision = explain_fix_decision(item, audit_obj)
        item['automation_decision'] = decision['decision']
        item['decision_reasoning'] = decision['reasoning']
        item['priority_score'] = round((SEVERITY_TO_NUM.get(item.get('severity', 'low'), 1) * 10) + (item['confidence']['finding_confidence'] * 5) + (5 if item['automation_decision']=='auto-apply-safe' else 0), 2)
        item['policy_reasoning'] = policy_reasoning(audit_obj, item)
        item['why_not_auto_fixed'] = []
        if item['automation_decision'] != 'auto-apply-safe':
            item['why_not_auto_fixed'].extend(item['decision_reasoning'])
        item['manual_runbook'] = manual_runbook_for_item(item, audit_obj)
        item['auto_applicable'] = item.get('auto_applicable', False) and item['automation_decision'] == 'auto-apply-safe'
        items.append(item)
    items.sort(key=lambda x: x.get('priority_score', 0), reverse=True)
    audit_obj['remediation']['items'] = items
    audit_obj['knowledge_base_patterns'] = knowledge_base_patterns(audit_obj)
    audit_obj['history_insights'] = history_insights(audit_obj, history or load_history())
    audit_obj['risk_score'] = compute_risk_score(audit_obj)
    audit_obj['explainable_prioritization'] = [
        {
            'issue_id': i.get('issue_id'),
            'title': i.get('title'),
            'priority_score': i.get('priority_score'),
            'why_ranked_here': [
                f"Severity={i.get('severity')}, risk={i.get('risk_level')}",
                f"Finding confidence={i.get('confidence', {}).get('finding_confidence')}",
                f"Decision={i.get('automation_decision')}",
            ] + i.get('policy_reasoning', []),
        }
        for i in items
    ]
    return audit_obj


def record_run_history(audit_obj, fix_result=None, path=SMART_HISTORY_PATH):
    history = load_history(path)
    run = {
        'timestamp_utc': now_utc_iso(),
        'namespace': get_nested(audit_obj, 'meta', 'namespace'),
        'workload_name': get_nested(audit_obj, 'meta', 'workload_name'),
        'environment_profile': audit_obj.get('environment_profile'),
        'issue_ids': [x.get('issue_id') for x in ((audit_obj.get('remediation') or {}).get('items') or [])],
        'risk_score': (audit_obj.get('risk_score') or {}).get('total'),
        'fix_status': (fix_result or {}).get('status'),
    }
    history.setdefault('runs', []).append(run)
    history['runs'] = history['runs'][-100:]
    save_history(history, path)
    return history


def post_fix_health_validation(audit_obj, fix_result):
    health = {'checks': [], 'status': 'unknown'}
    apply_result = (fix_result or {}).get('apply_result') or {}
    if not apply_result or not apply_result.get('executed'):
        health['status'] = 'not_run'
        return health
    ns = get_nested(audit_obj, 'meta', 'namespace') or 'default'
    wl = get_nested(audit_obj, 'meta', 'workload_name')
    if has_kubectl() and wl:
        for kind in ['deployment', 'statefulset', 'daemonset']:
            rc, out = shell_rc(f"kubectl -n {shlex.quote(ns)} rollout status {kind}/{shlex.quote(wl)} --timeout=30s", timeout=40)
            if rc == 0:
                health['checks'].append({'name': f'rollout_status_{kind}', 'ok': True, 'output': out.strip()})
                health['status'] = 'healthy'
                break
        if not health['checks']:
            health['checks'].append({'name': 'rollout_status', 'ok': False, 'output': 'Unable to confirm rollout status for supported workload kinds.'})
            health['status'] = 'degraded'
    return health


def safe_autonomous_selection(items, aggressive=False):
    selected = []
    manual = []
    approval = []
    for item in items:
        decision = item.get('automation_decision')
        if aggressive and item.get('base_auto_applicable'):
            selected.append(item)
        elif decision == 'auto-apply-safe':
            selected.append(item)
        elif decision == 'conditional-approval':
            approval.append(item)
        else:
            manual.append(item)
    return {'selected': selected, 'approval_required': approval, 'manual_only': manual}


def print_smart_summary(audit_obj):
    print('\nSmart analysis:')
    print(f"Environment profile: {audit_obj.get('environment_profile')}")
    print(f"Intent: {', '.join((audit_obj.get('intent_inference') or {}).get('intent', []))}")
    rt = audit_obj.get('runtime_intelligence') or {}
    if rt.get('notes'):
        print('Runtime intelligence:')
        for n in rt.get('notes', []):
            print(f'  - {n}')
    hist = audit_obj.get('history_insights') or {}
    if hist.get('notes'):
        print('Learning from previous runs:')
        for n in hist.get('notes', []):
            print(f'  - {n}')
    kb = audit_obj.get('knowledge_base_patterns') or []
    if kb:
        print('Recognized fix patterns:')
        for p in kb:
            print(f"  - {p.get('pattern')}: {p.get('recommendation')}")


def smart_write_json_file(path, obj, msg=None, announce=True):
    _base_write_json_file(path, obj, msg if announce else None)
    try:
        md_path = os.path.splitext(path)[0] + '.md'
        report_audit = obj
        report_fix = obj if obj.get('per_issue') else None
        if not obj.get('results'):
            report_audit = (
                ((obj.get('apply_result') or {}).get('post_fix_revalidation'))
                or obj.get('audit')
                or {'meta': obj.get('meta', {}), 'remediation': obj.get('remediation', {}), 'risk_score': obj.get('risk_score', {})}
            )
        with open(md_path, 'w') as f:
            f.write(markdown_report(report_audit, report_fix))
        if announce:
            print(f'Markdown report written: {md_path}')
    except Exception:
        pass


_original_interactive_wizard = interactive_wizard

def interactive_wizard():
    mode = prompt_choice('Run inside pod, from adjacent pod, or both', ['inside', 'adjacent', 'both'], default='both')
    action = prompt_choice('Do you want to analyze, fix, or analyze+fix', ['analyze', 'fix', 'analyze+fix'], default='analyze+fix')
    ns = autodetect_namespace('default') if has_kubectl() else None
    resources = list_candidate_resources(ns) if ns else []
    print_resource_list(resources)
    selected = prompt_resource_selection(resources) if resources else None
    timeout = 2.0
    audit_out = default_json_path('audit')
    fix_out = default_json_path('fixes')
    selector = None
    if selected:
        selector = selected.get('selector') or labels_to_selector(selected.get('labels') or selected.get('selector_labels') or {})
    if mode == 'inside' and is_inside_kubernetes():
        audit_obj = collect_internal(timeout=timeout)
    elif mode == 'adjacent':
        audit_obj = collect_remote(ns, selector, timeout=timeout, include_introspection=True, include_internal_audit=False)
    else:
        audit_obj = collect_remote(ns, selector, timeout=timeout, include_introspection=True, include_internal_audit=True)
    audit_obj['dependencies'] = summarize_dependencies(ns, workload_name=get_nested(audit_obj, 'meta', 'workload_name'), pod_name=get_nested(audit_obj, 'meta', 'target_pod'), labels=(selected or {}).get('labels') or (selected or {}).get('selector_labels') or {}) if ns else {}
    audit_obj = apply_smart_enrichment(audit_obj, load_history())
    print_audit_summary(audit_obj)
    print_smart_summary(audit_obj)
    print_remediation_summary(audit_obj.get('remediation', {}))
    smart_write_json_file(audit_out, audit_obj, 'Audit JSON written')
    if action == 'analyze':
        record_run_history(audit_obj, {'status': 'analysis_only'})
        return
    groups = safe_autonomous_selection((audit_obj.get('remediation') or {}).get('items') or [])
    if action == 'fix':
        print('\nConditional approval items:')
        for item in groups['approval_required']:
            print(f"- {item.get('issue_id')}: {item.get('title')}")
            for line in item.get('why_not_auto_fixed', []):
                print(f'  {line}')
        selection_mode = prompt_choice('Apply fixes all at once, separately, or none', ['all', 'separate', 'none'], default='separate')
        execute = prompt_yes_no('Execute selected fixes now', default='n')
        chosen = []
        candidate_items = groups['selected'] + groups['approval_required']
        if selection_mode == 'all':
            chosen = candidate_items
        elif selection_mode == 'separate':
            for item in candidate_items:
                default = 'y' if item in groups['selected'] else 'n'
                if prompt_yes_no(f"Apply {item.get('issue_id')} - {item.get('title')}?", default=default):
                    chosen.append(item)
        fix_result = run_selected_fix_groups(audit_obj, chosen, namespace=ns, workload=(selected or {}).get('workload_name') or get_nested(audit_obj, 'meta', 'workload_name'), kind=((selected or {}).get('workload_kind') or get_nested(audit_obj, 'meta', 'workload_kind') or 'deployment').lower(), execute=execute)
        fix_result['approval_required'] = groups['approval_required']
        fix_result['manual_only'] = groups['manual_only']
        fix_result['post_fix_health'] = post_fix_health_validation(audit_obj, fix_result)
        print_fix_result(fix_result)
        smart_write_json_file(fix_out, fix_result, 'Fix JSON written')
        record_run_history(audit_obj, fix_result)


_original_auto_run = auto_run

def auto_run(timeout=2.0, apply_safe_fixes=True, execute=False, audit_out=None, fix_out=None):
    mode = autodetect_mode()
    audit_out = audit_out or default_json_path('audit')
    fix_out = fix_out or default_json_path('fixes')
    namespace = autodetect_namespace('default') if has_kubectl() else None
    selected = None
    if namespace:
        resources = list_candidate_resources(namespace)
        print_resource_list(resources)
        selected = prompt_resource_selection(resources) if resources else None
    selector = None
    if selected:
        selector = selected.get('selector') or labels_to_selector(selected.get('labels') or selected.get('selector_labels') or {})
    elif namespace and mode in ('remote', 'both'):
        discovered = autodiscover_remote_target(namespace)
        selector = discovered.get('selector') or labels_to_selector(discovered.get('selector_labels') or {})
    if mode == 'internal':
        audit_obj = collect_internal(timeout=timeout)
    elif mode == 'remote':
        audit_obj = collect_remote(namespace, selector, timeout=timeout, include_introspection=True, include_internal_audit=False)
    else:
        audit_obj = collect_remote(namespace, selector, timeout=timeout, include_introspection=True, include_internal_audit=True)
    audit_obj['dependencies'] = summarize_dependencies(namespace, workload_name=(selected or {}).get('workload_name') or get_nested(audit_obj, 'meta', 'workload_name'), pod_name=(selected or {}).get('pod_name') or get_nested(audit_obj, 'meta', 'target_pod'), labels=(selected or {}).get('labels') or (selected or {}).get('selector_labels') or {}) if namespace else {}
    audit_obj = apply_smart_enrichment(audit_obj, load_history())
    print_audit_summary(audit_obj)
    print_smart_summary(audit_obj)
    print_remediation_summary(audit_obj.get('remediation', {}))
    smart_write_json_file(audit_out, audit_obj, 'Audit JSON written')
    items = (audit_obj.get('remediation') or {}).get('items') or []
    grouping = safe_autonomous_selection(items, aggressive=aggressive_execute)
    chosen = grouping['selected'] if apply_safe_fixes else []
    fix_result = {
        'status': 'no_change',
        'per_issue': [],
        'approval_required': grouping['approval_required'],
        'manual_only': grouping['manual_only'],
    }
    if mode != 'internal' and chosen:
        fix_result = run_selected_fix_groups(audit_obj, chosen, namespace=namespace, workload=(selected or {}).get('workload_name') or get_nested(audit_obj, 'meta', 'workload_name'), kind=((selected or {}).get('workload_kind') or get_nested(audit_obj, 'meta', 'workload_kind') or 'deployment').lower(), execute=execute)
        fix_result['approval_required'] = grouping['approval_required']
        fix_result['manual_only'] = grouping['manual_only']
        if aggressive_execute:
            fix_result['aggressive_execute'] = True
    elif mode == 'internal':
        fix_result = {
            'status': 'no_change',
            'reason': 'internal_mode_manual_recommendation_only',
            'per_issue': [{'issue_id': i.get('issue_id'), 'status': 'manual_only', 'risk_level': i.get('risk_level'), 'note': '; '.join(i.get('why_not_auto_fixed', [])[:2])} for i in items],
            'approval_required': grouping['approval_required'],
            'manual_only': grouping['manual_only'],
        }
    fix_result['post_fix_health'] = post_fix_health_validation(audit_obj, fix_result)
    print_fix_result(fix_result)
    smart_write_json_file(fix_out, fix_result, 'Fix JSON written')
    record_run_history(audit_obj, fix_result)
    return {'audit': audit_obj, 'fix': fix_result, 'reports': {'markdown': markdown_report(audit_obj, fix_result)}}


_original_write_json_file = write_json_file

# ---------------- laptop-first controller mode ----------------

def kubectl_auth_can(verb, resource, namespace=None):
    if not has_kubectl():
        return False, 'kubectl_not_found'
    ns = f" -n {shlex.quote(namespace)}" if namespace else ""
    rc, out = shell_rc(f"kubectl auth can-i {shlex.quote(verb)} {shlex.quote(resource)}{ns}", timeout=20)
    txt = (out or '').strip().lower()
    return (rc == 0 and txt.startswith('yes')), txt or f'rc={rc}'


def detect_laptop_cluster_capabilities(namespace=None):
    caps = {
        'has_kubectl': has_kubectl(),
        'namespace': namespace,
        'operations': {},
        'level': 'manual_in_cluster_required',
    }
    if not caps['has_kubectl']:
        return caps
    checks = [
        ('get_pods', 'get', 'pods'), ('list_pods', 'list', 'pods'), ('exec_pods', 'create', 'pods/exec'),
        ('get_services', 'get', 'services'), ('get_ingresses', 'get', 'ingresses'),
        ('get_networkpolicies', 'get', 'networkpolicies'), ('get_serviceaccounts', 'get', 'serviceaccounts'),
        ('patch_deployments', 'patch', 'deployments'), ('patch_statefulsets', 'patch', 'statefulsets'),
        ('patch_daemonsets', 'patch', 'daemonsets'), ('apply_networkpolicies', 'create', 'networkpolicies'),
        ('create_pods', 'create', 'pods')
    ]
    for key, verb, res in checks:
        ok, detail = kubectl_auth_can(verb, res, namespace=namespace)
        caps['operations'][key] = {'allowed': ok, 'detail': detail}
    ops = caps['operations']
    if ops.get('get_pods', {}).get('allowed') and ops.get('list_pods', {}).get('allowed') and ops.get('exec_pods', {}).get('allowed'):
        caps['level'] = 'full_control'
    elif ops.get('get_pods', {}).get('allowed') and ops.get('list_pods', {}).get('allowed'):
        caps['level'] = 'audit_only'
    elif ops.get('get_pods', {}).get('allowed'):
        caps['level'] = 'remote_only'
    return caps


def print_capabilities_summary(caps):
    print('\nDetected cluster management capabilities')
    print('=' * 72)
    print(f"Level: {caps.get('level')}")
    for key, v in (caps.get('operations') or {}).items():
        print(f"- {key}: {'allowed' if v.get('allowed') else 'blocked'} ({v.get('detail')})")


def detect_pod_exec_runtime(namespace, pod, container=None):
    candidates = [
        ('python3', 'python3 --version'), ('python', 'python --version'), ('sh', 'sh -lc "echo ok"'), ('bash', 'bash -lc "echo ok"')
    ]
    out = {'pod': pod, 'container': container, 'python': None, 'shell': None, 'writable_tmp': None}
    cflag = f" -c {shlex.quote(container)}" if container else ""
    for name, probe in candidates:
        rc, txt = shell_rc(f"kubectl -n {shlex.quote(namespace)} exec {shlex.quote(pod)}{cflag} -- {probe}", timeout=25)
        if rc == 0:
            if name.startswith('python') and not out['python']:
                out['python'] = name
            if name in ('sh', 'bash') and not out['shell']:
                out['shell'] = name
    if out['shell']:
        rc, txt = shell_rc(f"kubectl -n {shlex.quote(namespace)} exec {shlex.quote(pod)}{cflag} -- {out['shell']} -lc 'test -w /tmp && echo yes || echo no'", timeout=20)
        out['writable_tmp'] = 'yes' in (txt or '').lower()
    return out


def get_pod_containers(namespace, pod):
    try:
        obj = kubectl_get_json(namespace, 'pod', name=pod)
        return [c.get('name') for c in (((obj.get('spec') or {}).get('containers') or [])) if c.get('name')]
    except Exception:
        return []


def stream_internal_audit_from_laptop(namespace, pod, container=None, timeout=2.0):
    script_text = read_text(os.path.abspath(__file__), max_bytes=6_000_000)
    runtime = detect_pod_exec_runtime(namespace, pod, container=container)
    py = runtime.get('python')
    sh_name = runtime.get('shell') or 'sh'
    if not py:
        return {'ok': False, 'method': 'exec_stream', 'error': 'no_python_in_target_pod', 'runtime': runtime}
    argv = json.dumps(["combined_audit_with_remediation.py", "internal", "--timeout", str(float(timeout)), "--stdout-json"])
    remote_cmd = (
        f"{py} -c "
        + shlex.quote(
            "import sys; "
            f"sys.argv={argv}; "
            "src=sys.stdin.read(); "
            "ns={'__name__':'__main__','__file__':'combined_audit_with_remediation.py'}; "
            "exec(compile(src, 'combined_audit_with_remediation.py', 'exec'), ns, ns)"
        )
    )
    cmd = ["kubectl", "-n", namespace, "exec", "-i", pod]
    if container:
        cmd.extend(["-c", container])
    cmd.extend(["--", sh_name, "-lc", remote_cmd])
    try:
        proc = subprocess.run(
            cmd,
            input=script_text.encode("utf-8"),
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=600,
            check=False,
        )
        out = proc.stdout.decode("utf-8", "replace")
        parsed = parse_json_from_mixed_output(out)
        if parsed is not None:
            return {'ok': proc.returncode == 0, 'method': 'exec_stream', 'runtime': runtime, 'result': parsed}
        return {'ok': False, 'method': 'exec_stream', 'runtime': runtime, 'error': 'internal_exec_parse_failed', 'raw': out}
    except Exception as e:
        return {'ok': False, 'method': 'exec_stream', 'runtime': runtime, 'error': f'exec_stream_failed: {type(e).__name__}: {e}'}
def manual_in_cluster_commands(namespace, pod, container=None, timeout=2.0):
    cflag = f" -c {container}" if container else ""
    return {
        'copy_and_run': [
            f"kubectl cp combined_audit_with_remediation.py {namespace}/{pod}:/tmp/combined_audit.py",
            f"kubectl exec -n {namespace} {pod}{cflag} -- python3 /tmp/combined_audit.py internal --timeout {timeout} --out /tmp/audit.json",
            f"kubectl cp {namespace}/{pod}:/tmp/audit.json ./audit.json",
        ],
        'stream_and_run': [
            f"cat combined_audit_with_remediation.py | kubectl exec -i -n {namespace} {pod}{cflag} -- sh -lc {shlex.quote(internal_python_stdin_launcher(timeout).replace('--stdout-json', '--out /dev/stdout'))}",
        ]
    }


def controller_run(timeout=2.0, execute=False, aggressive_execute=False, audit_out=None, fix_out=None, app_mode='default'):
    namespace = autodetect_namespace('default') if has_kubectl() else None
    caps = detect_laptop_cluster_capabilities(namespace)
    print_capabilities_summary(caps)
    if not caps.get('has_kubectl'):
        print("\nThis laptop does not have kubectl available. Run the script inside the cluster or install kubectl and kubeconfig access.")
        return {'status': 'manual_in_cluster_required', 'capabilities': caps}

    resources = list_candidate_resources(namespace) if namespace else []
    print_resource_list(resources)
    selected = prompt_resource_selection(resources) if resources else None
    if not selected:
        print('No resource selected. Nothing was analyzed.')
        return {'status': 'no_change', 'capabilities': caps}

    selector = selected.get('selector') or labels_to_selector(selected.get('labels') or selected.get('selector_labels') or {})
    pod = selected.get('pod_name') or selected.get('name')
    containers = get_pod_containers(namespace, pod)
    container = containers[0] if containers else None
    selected_kind = selected.get('kind') or selected.get('workload_kind') or 'Pod'
    selected_name = selected.get('name') or selected.get('workload_name') or pod
    print(f"\nSelected resource: {selected_kind} {selected_name} in namespace {namespace}")
    if containers:
        print(f"Containers: {', '.join(containers)}")

    remote_obj = collect_remote(namespace, selector, timeout=timeout, include_introspection=True, include_internal_audit=False)
    if not isinstance(remote_obj, dict):
        remote_obj = {'meta': {'namespace': namespace, 'target_pod': pod}, 'results': {}, 'remediation': {'items': []}}

    if caps.get('operations', {}).get('exec_pods', {}).get('allowed'):
        internal_exec = stream_internal_audit_from_laptop(namespace, pod, container=container, timeout=timeout)
        if internal_exec.get('ok') and internal_exec.get('result'):
            remote_obj.setdefault('results', {})['internal_audit'] = internal_exec['result']
            internal_state = {'status': 'collected_from_laptop', 'method': internal_exec.get('method'), 'runtime': internal_exec.get('runtime')}
        else:
            internal_state = {
                'status': 'manual_in_cluster_required',
                'reason': internal_exec.get('error') or 'exec_failed',
                'runtime': internal_exec.get('runtime'),
                'manual_commands': manual_in_cluster_commands(namespace, pod, container=container, timeout=timeout),
            }
    else:
        internal_state = {
            'status': 'manual_in_cluster_required',
            'reason': 'pods_exec_not_allowed',
            'manual_commands': manual_in_cluster_commands(namespace, pod, container=container, timeout=timeout),
        }

    remote_obj['controller'] = {'capabilities': caps, 'selected_resource': selected, 'internal_execution': internal_state}
    remote_obj['dependencies'] = summarize_dependencies(
        namespace,
        workload_name=selected.get('workload_name') or get_nested(remote_obj, 'meta', 'workload_name'),
        pod_name=pod,
        labels=selected.get('labels') or selected.get('selector_labels') or {},
    )
    remote_obj = promote_internal_audit_findings(remote_obj)
    remote_obj = apply_smart_enrichment(remote_obj, load_history())
    remote_obj = attach_ai_advisor(remote_obj, selected=selected, workflow_mode='controller', app_mode=app_mode)
    print_audit_summary(remote_obj)
    print_smart_summary(remote_obj)
    print_ai_advisor_summary(remote_obj)
    print_remediation_summary(remote_obj.get('remediation', {}))

    audit_out = audit_out or resource_json_path('controller_audit', namespace=namespace, workload_name=selected_name)
    fix_out = fix_out or resource_json_path('controller_fixes', namespace=namespace, workload_name=selected_name)
    smart_write_json_file(audit_out, remote_obj, 'Audit JSON written')

    items = (remote_obj.get('remediation') or {}).get('items') or []
    grouping = safe_autonomous_selection(items, aggressive=aggressive_execute)
    if execute and caps.get('level') == 'full_control':
        fix_result = run_selected_fix_groups(
            remote_obj,
            grouping['selected'],
            namespace=namespace,
            workload=selected.get('workload_name') or get_nested(remote_obj, 'meta', 'workload_name'),
            kind=((selected.get('workload_kind') or get_nested(remote_obj, 'meta', 'workload_kind') or 'deployment')).lower(),
            execute=True,
        )
        fix_result['approval_required'] = grouping['approval_required']
        fix_result['manual_only'] = grouping['manual_only']
        if aggressive_execute:
            fix_result['aggressive_execute'] = True
    else:
        fix_result = {
            'status': 'planned' if grouping['selected'] else 'no_change',
            'reason': 'execute_not_requested' if not execute else 'insufficient_apply_permissions',
            'per_issue': [{'issue_id': i.get('issue_id'), 'status': 'planned'} for i in grouping['selected']],
            'approval_required': grouping['approval_required'],
            'manual_only': grouping['manual_only'],
        }
        if aggressive_execute:
            fix_result['aggressive_execute'] = True

    fix_result['post_fix_health'] = post_fix_health_validation(remote_obj, fix_result)
    print_fix_result(fix_result)
    smart_write_json_file(fix_out, fix_result, 'Fix JSON written')

    if internal_state.get('status') == 'manual_in_cluster_required':
        print("\nInternal audit could not be executed automatically from this laptop.")
        print('Run one of the following inside the cluster management context:')
        for block, cmds in (internal_state.get('manual_commands') or {}).items():
            print(f"\n{block}:")
            for cmd in cmds:
                print(cmd)

    if normalize_app_mode(app_mode) == 'ai':
        start_ai_chat_session(remote_obj, selected=selected, workflow_mode='controller')

    record_run_history(remote_obj, fix_result)
    return {'audit': remote_obj, 'fix': fix_result}


def current_cluster_name():
    if not has_kubectl():
        return None
    return shell("kubectl config view --minify -o jsonpath='{.contexts[0].context.cluster}'", timeout=10).strip() or None


def is_attacker_resource(resource):
    labels = resource.get('labels') or resource.get('selector_labels') or {}
    workload_name = (resource.get('workload_name') or '').lower()
    selector = (resource.get('selector') or '').lower()
    return (
        labels.get('role') == 'attacker'
        or labels.get('app') == 'attacker'
        or 'role=attacker' in selector
        or 'app=attacker' in selector
        or 'attacker' in workload_name
    )


def discover_primary_target_resource(namespace, resources=None):
    resources = resources if resources is not None else list_candidate_resources(namespace)
    if not resources:
        return None, resources
    candidates = [r for r in resources if not is_attacker_resource(r)]
    if len(candidates) == 1:
        return candidates[0], resources
    if len(candidates) > 1:
        return prompt_resource_selection(candidates), resources
    return prompt_resource_selection(resources), resources


def ensure_cluster_matches(cluster_name):
    current = current_cluster_name()
    if cluster_name and current and cluster_name != current:
        raise RuntimeError(f"requested cluster '{cluster_name}' does not match current kubectl cluster '{current}'")
    return current or cluster_name


def guided_output_paths(prefix, namespace, workload_name):
    return {
        'audit': resource_json_path(f'{prefix}_audit', namespace=namespace, workload_name=workload_name),
        'fix': resource_json_path(f'{prefix}_fixes', namespace=namespace, workload_name=workload_name),
    }


def persist_attacker_lifecycle_backup(namespace, workload_name, target_selector, attacker_name=None, existed_before=False):
    path = output_path(
        f"attacker_lifecycle_{safe_slug(namespace, 'namespace')}_{safe_slug(workload_name, 'workload')}_"
        f"{datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json"
    )
    payload = {
        'created_at': now_utc_iso(),
        'namespace': namespace,
        'workload_name': workload_name,
        'target_selector': target_selector,
        'attacker_pod': attacker_name,
        'attacker_existed_before': existed_before,
    }
    _base_write_json_file(path, payload)
    return path


def verify_attacker_cleanup(namespace, attacker_name, existed_before=False):
    if not attacker_name or existed_before:
        return {'ok': True, 'reason': 'preexisting_or_not_created'}
    exists = pod_exists(namespace, attacker_name)
    return {'ok': not exists, 'reason': 'deleted' if not exists else 'attacker_pod_still_exists', 'attacker_pod': attacker_name}


def collect_remote_with_attacker_policy(ns, selector, timeout=2.0, include_introspection=True, include_internal_audit=False, create_if_missing=False, cleanup_temporary_attacker=False):
    ts = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    meta = {
        "ts_utc": ts,
        "namespace": ns,
        "target_selector": selector,
        "tool": "combined_sandbox_audit",
        "host": os.uname().sysname + " " + os.uname().release,
    }

    target_pod = first_running_pod_by_selector(ns, selector)
    if not target_pod:
        raise RuntimeError(f"No running target pod found with selector: {selector}")

    target_ip = kubectl_jsonpath(ns, target_pod, "{.status.podIP}") or ""
    img = kubectl_jsonpath(ns, target_pod, "{.spec.containers[0].image}") or ""
    image_id = kubectl_jsonpath(ns, target_pod, "{.status.containerStatuses[0].imageID}") or ""
    node = kubectl_jsonpath(ns, target_pod, "{.spec.nodeName}") or ""
    meta.update({
        "target_pod": target_pod,
        "target_ip": target_ip,
        "node": node,
        "image": img,
        "imageID": image_id,
    })
    try:
        discovered = discover_workload_from_pod(ns, target_pod)
        meta.update({
            "workload_name": discovered.get("workload_name"),
            "workload_kind": (discovered.get("workload_kind") or "").lower(),
            "container_names": discovered.get("container_names", []),
            "service_account_name": discovered.get("service_account_name"),
            "selector_labels": discovered.get("selector_labels", {}),
        })
        if discovered.get("selector"):
            meta["target_selector"] = discovered.get("selector")
    except Exception as e:
        meta["discovery_error"] = str(e)

    attacker_name = None
    created_tmp = False
    attacker_error = None
    try:
        attacker_name, created_tmp = ensure_attacker_pod(ns, prefer_name="attacker", create_if_missing=create_if_missing)
        meta["attacker_pod"] = attacker_name
        meta["attacker_created_tmp"] = created_tmp
    except Exception as e:
        attacker_error = f"{type(e).__name__}: {e}"
        meta["attacker_pod"] = None
        meta["attacker_created_tmp"] = False
        meta["attacker_setup_error"] = attacker_error

    results = {
        "scanned_ports": [],
        "novnc_http_6901": {},
        "novnc_ws_6901": {},
        "vnc_rfb_5901": {},
        "internal_introspection": {},
        "internal_audit": {},
        "classification": "unknown",
    }

    if attacker_name:
        for p in DEFAULT_PORTS:
            if not target_ip:
                results["scanned_ports"].append({"port": p, "reachable": False, "nc_output": "no target_ip"})
                continue
            results["scanned_ports"].append(probe_nc(ns, attacker_name, target_ip, p))
        if target_ip:
            results["novnc_http_6901"] = probe_http_head(ns, attacker_name, target_ip, 6901, path="/")
            results["novnc_ws_6901"] = probe_ws_upgrade(ns, attacker_name, target_ip, 6901, path="/websockify")
            results["vnc_rfb_5901"] = rfb_probe(ns, attacker_name, target_ip, port=5901, timeout=timeout, proofsafe=True)
    else:
        for p in DEFAULT_PORTS:
            results["scanned_ports"].append({"port": p, "reachable": False, "nc_output": f"skipped: {attacker_error or 'no attacker pod available'}"})
        results["novnc_http_6901"] = degraded_remote_result("attacker_unavailable", attacker_error)
        results["novnc_ws_6901"] = degraded_remote_result("attacker_unavailable", attacker_error)
        results["vnc_rfb_5901"] = {"classification": "skipped_attacker_unavailable", "error": attacker_error or "no attacker pod available"}

    if include_introspection:
        try:
            results["internal_introspection"] = optional_internal_introspection(ns, target_pod)
        except Exception as e:
            results["internal_introspection"] = {"ok": False, "error": str(e)}

    if include_internal_audit:
        try:
            results["internal_audit"] = run_internal_via_kubectl(ns, target_pod, timeout=timeout)
        except Exception as e:
            results["internal_audit"] = {"error": str(e)}

    rfb_class = (results.get("vnc_rfb_5901") or {}).get("classification", "")
    reachable_6901 = bool(results.get("novnc_http_6901", {}).get("ok")) and "200" in (results.get("novnc_http_6901", {}).get("status_line", ""))
    ws_ok = bool(results.get("novnc_ws_6901", {}).get("switching_protocols_101"))
    vnc5901_open = any(x for x in results["scanned_ports"] if x["port"] == 5901 and x["reachable"])
    if not attacker_name:
        results["classification"] = "remote_probe_skipped_attacker_unavailable"
    elif rfb_class in ("proofsafe_serverinit_ok", "unauthenticated_vnc"):
        results["classification"] = "remotely_reachable_from_pod_and_unauthenticated_vnc"
    elif rfb_class == "password_required":
        results["classification"] = "remotely_reachable_from_pod_but_password_required"
    elif reachable_6901 and ws_ok and vnc5901_open:
        results["classification"] = "remotely_reachable_from_pod_partial_signals"
    else:
        results["classification"] = "not_reachable_or_insufficient_signals"

    cleanup = {'ok': True, 'reason': 'not_requested'}
    if created_tmp and cleanup_temporary_attacker:
        try:
            shell(f"kubectl -n {shlex.quote(ns)} delete pod {shlex.quote(attacker_name)} --grace-period=0 --force", check=False, timeout=60)
        finally:
            cleanup = verify_attacker_cleanup(ns, attacker_name, existed_before=False)

    obj = {"meta": meta, "results": results}
    obj["remediation"] = remediation_from_audit(obj)
    obj.setdefault('meta', {})['dependencies'] = summarize_dependencies(ns, obj.get('meta', {}).get('workload_name'), obj.get('meta', {}).get('target_pod'), obj.get('meta', {}).get('selector_labels') or {})
    obj['evidence'] = collect_evidence('results', obj.get('results', {}))
    obj = promote_internal_audit_findings(obj)
    obj['risk_score'] = compute_risk_score(obj)
    obj.setdefault('meta', {})['compatibility_notes'] = compatibility_assessment(obj)
    obj['reports'] = {'markdown': markdown_report(obj)}
    obj['attacker_cleanup'] = cleanup
    return obj


def run_internal_audit_for_target(namespace, pod, container=None, timeout=2.0):
    internal_exec = stream_internal_audit_from_laptop(namespace, pod, container=container, timeout=timeout)
    if internal_exec.get('ok') and internal_exec.get('result'):
        return internal_exec['result'], {'status': 'collected_from_laptop', 'method': internal_exec.get('method'), 'runtime': internal_exec.get('runtime')}
    return (
        {'error': internal_exec.get('error') or 'internal_exec_failed', 'runtime': internal_exec.get('runtime')},
        {
            'status': 'manual_in_cluster_required',
            'reason': internal_exec.get('error') or 'exec_failed',
            'runtime': internal_exec.get('runtime'),
            'manual_commands': manual_in_cluster_commands(namespace, pod, container=container, timeout=timeout),
        },
    )


def build_base_analysis(namespace, selected, timeout=2.0, app_mode='default'):
    selector = selected.get('selector') or labels_to_selector(selected.get('labels') or selected.get('selector_labels') or {})
    pod = selected.get('pod_name') or selected.get('name')
    containers = get_pod_containers(namespace, pod)
    container = containers[0] if containers else None
    remote_obj = collect_remote_with_attacker_policy(namespace, selector, timeout=timeout, include_introspection=True, include_internal_audit=False, create_if_missing=False, cleanup_temporary_attacker=False)
    internal_audit, internal_state = run_internal_audit_for_target(namespace, pod, container=container, timeout=timeout)
    remote_obj.setdefault('results', {})['internal_audit'] = internal_audit
    remote_obj.setdefault('controller', {})['internal_execution'] = internal_state
    remote_obj.setdefault('controller', {})['selected_resource'] = selected
    remote_obj['dependencies'] = summarize_dependencies(
        namespace,
        workload_name=selected.get('workload_name') or get_nested(remote_obj, 'meta', 'workload_name'),
        pod_name=pod,
        labels=selected.get('labels') or selected.get('selector_labels') or {},
    )
    remote_obj = promote_internal_audit_findings(remote_obj)
    remote_obj = apply_spec_fallback_if_needed(remote_obj)
    remote_obj = reconcile_spec_backed_findings(remote_obj)
    remote_obj = apply_smart_enrichment(remote_obj, load_history())
    remote_obj = attach_ai_advisor(remote_obj, selected=selected, workflow_mode='analyze', app_mode=app_mode)
    return remote_obj, selector, pod, container


def run_remote_probe_phase(namespace, selector, timeout=2.0, create_if_missing=False, cleanup_temporary_attacker=False):
    remote_obj = collect_remote_with_attacker_policy(
        namespace,
        selector,
        timeout=timeout,
        include_introspection=True,
        include_internal_audit=False,
        create_if_missing=create_if_missing,
        cleanup_temporary_attacker=cleanup_temporary_attacker,
    )
    return apply_smart_enrichment(remote_obj, load_history())


def check_agentic_workload_health_guided(audit_obj, fix_result, timeout=2.0):
    health = post_fix_health_validation(audit_obj, fix_result)
    apply_result = (fix_result or {}).get('apply_result') or {}
    if not apply_result or not apply_result.get('executed'):
        return health
    revalidated = apply_result.get('post_fix_revalidation') or {}
    target_pod = get_nested(revalidated, 'meta', 'target_pod')
    namespace = get_nested(revalidated, 'meta', 'namespace')
    if namespace and target_pod:
        containers = get_pod_containers(namespace, target_pod)
        container = containers[0] if containers else None
        internal_audit, internal_state = run_internal_audit_for_target(namespace, target_pod, container=container, timeout=timeout)
        health['agentic_validation'] = {
            'internal_state': internal_state,
            'internal_summary': (internal_audit.get('summary') if isinstance(internal_audit, dict) else None),
            'internal_error': (internal_audit.get('error') if isinstance(internal_audit, dict) else 'unknown'),
        }
        if internal_state.get('status') == 'collected_from_laptop' and not internal_audit.get('error'):
            if health.get('status') in ('unknown', 'healthy'):
                health['status'] = 'healthy'
        else:
            if health.get('status') == 'healthy':
                health['status'] = 'validation_incomplete'
            else:
                health['status'] = 'degraded'
    return health


def print_guided_context(cluster, namespace, selected):
    print("\nGuided execution context")
    print("=" * 72)
    print(f"cluster: {cluster}")
    print(f"namespace: {namespace}")
    print(f"target: {selected.get('workload_kind')}/{selected.get('workload_name')}")
    print(f"selector: {selected.get('selector') or labels_to_selector(selected.get('selector_labels') or {})}")


def find_latest_rollback_bundle(namespace, workload_name, base_dir=None):
    root = base_dir or ensure_output_root()
    prefix = f"rollback_bundle_{slugify_name(namespace)}_{slugify_name(workload_name)}_"
    try:
        entries = []
        for name in os.listdir(root):
            full = os.path.join(root, name)
            if name.startswith(prefix) and os.path.isdir(full):
                manifest = os.path.join(full, 'backup_manifest.json')
                if os.path.exists(manifest):
                    entries.append(full)
        if not entries:
            return None
        return sorted(entries)[-1]
    except Exception:
        return None


def find_preferred_rollback_bundle(namespace, workload_name, base_dir=None):
    root = base_dir or ensure_output_root()
    backup_prefix = f"guided_backup_restore_{safe_slug(namespace, 'namespace')}_{safe_slug(workload_name, 'workload')}_"
    remediation_prefix = f"guided_remediation_fixes_{safe_slug(namespace, 'namespace')}_{safe_slug(workload_name, 'workload')}_"
    backup_candidates = []
    remediation_candidates = []
    try:
        for name in os.listdir(root):
            full = os.path.join(root, name)
            if not os.path.isfile(full) or not name.endswith('.json'):
                continue
            try:
                with open(full, 'r') as fh:
                    obj = json.load(fh)
            except Exception:
                continue
            if name.startswith(backup_prefix) and obj.get('status') == 'backup_created':
                bundle_dir = get_nested(obj, 'backup_bundle', 'directory')
                if bundle_dir and os.path.isdir(bundle_dir) and os.path.exists(os.path.join(bundle_dir, 'backup_manifest.json')):
                    backup_candidates.append(bundle_dir)
            elif name.startswith(remediation_prefix) and obj.get('status') == 'applied':
                bundle_dir = get_nested(obj, 'apply_result', 'backup_bundle', 'directory')
                if bundle_dir and os.path.isdir(bundle_dir) and os.path.exists(os.path.join(bundle_dir, 'backup_manifest.json')):
                    remediation_candidates.append(bundle_dir)
    except Exception:
        pass
    if backup_candidates:
        return sorted(backup_candidates)[-1], 'latest explicit backup'
    if remediation_candidates:
        return sorted(remediation_candidates)[-1], 'latest remediation backup'
    latest = find_latest_rollback_bundle(namespace, workload_name, base_dir=root)
    if latest:
        return latest, 'latest matching rollback bundle'
    return None, None


def list_rollback_bundle_options(namespace, workload_name, base_dir=None):
    root = base_dir or ensure_output_root()
    options = []
    seen = set()
    backup_prefix = f"guided_backup_restore_{safe_slug(namespace, 'namespace')}_{safe_slug(workload_name, 'workload')}_"
    remediation_prefix = f"guided_remediation_fixes_{safe_slug(namespace, 'namespace')}_{safe_slug(workload_name, 'workload')}_"
    try:
        for name in sorted(os.listdir(root)):
            full = os.path.join(root, name)
            if not os.path.isfile(full) or not name.endswith('.json'):
                continue
            try:
                with open(full, 'r') as fh:
                    obj = json.load(fh)
            except Exception:
                continue
            bundle_dir = None
            label = None
            if name.startswith(backup_prefix) and obj.get('status') == 'backup_created':
                bundle_dir = get_nested(obj, 'backup_bundle', 'directory')
                label = 'backup before remediation'
            elif name.startswith(remediation_prefix) and obj.get('status') == 'applied':
                bundle_dir = get_nested(obj, 'apply_result', 'backup_bundle', 'directory')
                label = 'backup created by remediation'
            if not bundle_dir or bundle_dir in seen:
                continue
            manifest = os.path.join(bundle_dir, 'backup_manifest.json')
            if not (os.path.isdir(bundle_dir) and os.path.exists(manifest)):
                continue
            seen.add(bundle_dir)
            options.append({
                'bundle_dir': bundle_dir,
                'label': label,
                'source_file': name,
                'basename': os.path.basename(bundle_dir),
            })
    except Exception:
        pass
    options.sort(key=lambda x: x['bundle_dir'], reverse=True)
    return options


def resolve_rollback_bundle_dir(bundle_dir, namespace, workload_name):
    if bundle_dir:
        candidate = os.path.expanduser(bundle_dir)
        if os.path.isdir(candidate):
            return candidate, 'user supplied'
        output_candidate = os.path.join(ensure_output_root(), os.path.basename(candidate))
        if os.path.isdir(output_candidate):
            return output_candidate, 'user supplied'
        raise RuntimeError(f"Rollback bundle not found: {bundle_dir}")
    latest, reason = find_preferred_rollback_bundle(namespace, workload_name)
    if latest:
        return latest, reason
    raise RuntimeError(f"No rollback bundle found for {namespace}/{workload_name} in {ensure_output_root()}")


def choose_rollback_bundle(namespace, workload_name, bundle_dir=None):
    if bundle_dir:
        resolved, reason = resolve_rollback_bundle_dir(bundle_dir, namespace, workload_name)
        return resolved, reason
    options = list_rollback_bundle_options(namespace, workload_name)
    preferred, preferred_reason = find_preferred_rollback_bundle(namespace, workload_name)
    if not options:
        return resolve_rollback_bundle_dir(None, namespace, workload_name)
    if len(options) == 1:
        return options[0]['bundle_dir'], preferred_reason or options[0]['label']
    default_idx = 1
    for idx, opt in enumerate(options, start=1):
        if opt['bundle_dir'] == preferred:
            default_idx = idx
            break
    print("\nAvailable rollback bundles")
    print("-" * 72)
    for idx, opt in enumerate(options, start=1):
        default_note = " [default]" if idx == default_idx else ""
        print(f"{idx}. {opt['basename']} - {opt['label']}{default_note}")
    raw = prompt('Select rollback bundle number', str(default_idx))
    try:
        choice = int((raw or str(default_idx)).strip())
    except Exception:
        choice = default_idx
    if choice < 1 or choice > len(options):
        choice = default_idx
    selected = options[choice - 1]
    return selected['bundle_dir'], selected['label']


def print_backup_restore_summary(result):
    print("\n=== Backup / Restore ===")
    status = (result or {}).get('status') or 'unknown'
    if status == 'backup_created':
        bundle_dir = get_nested(result, 'backup_bundle', 'directory')
        print(f"Status: backup created")
        if bundle_dir:
            print(f"Bundle: {bundle_dir}")
        return
    if status in ('restored', 'drift_remaining'):
        print(f"Status: {status}")
        print(f"Bundle: {result.get('bundle_dir')}")
        if result.get('bundle_selection_reason'):
            print(f"Bundle selection: {result.get('bundle_selection_reason')}")
        for item in (result.get('results') or []):
            label = f"{item.get('kind')}/{item.get('name')}"
            if item.get('skipped'):
                print(f"- {label}: skipped ({item.get('reason')})")
            elif item.get('normalized_equal'):
                print(f"- {label}: restored cleanly")
            else:
                print(f"- {label}: restored with drift remaining")
        return
    print(f"Status: {status}")


def guided_backup_restore_mode(cluster, namespace, selected, action='backup', bundle_dir=None):
    selector = selected.get('selector') or labels_to_selector(selected.get('selector_labels') or {})
    workload_name = selected.get('workload_name')
    kind = (selected.get('workload_kind') or 'deployment').lower()
    if action == 'backup':
        base_obj = {'meta': {'namespace': namespace, 'workload_name': workload_name, 'workload_kind': kind, 'target_selector': selector}}
        bundle = ensure_mandatory_backup_bundle(base_obj, namespace=namespace, workload=workload_name, kind=kind, include_serviceaccount=True)
        result = {'status': 'backup_created', 'cluster': cluster, 'namespace': namespace, 'workload_name': workload_name, 'backup_bundle': bundle.get('persisted', {}), 'rollback': bundle.get('rollback', {})}
        out_path = resource_json_path('guided_backup_restore', namespace=namespace, workload_name=workload_name)
        smart_write_json_file(out_path, result, 'Backup/restore JSON written')
        print_backup_restore_summary(result)
        return result
    bundle_dir, selection_reason = choose_rollback_bundle(namespace, workload_name, bundle_dir=bundle_dir)
    result = strict_rollback_bundle(bundle_dir)
    result['cluster'] = cluster
    result['bundle_selection_reason'] = selection_reason
    out_path = resource_json_path('guided_backup_restore', namespace=namespace, workload_name=workload_name)
    smart_write_json_file(out_path, result, 'Backup/restore JSON written')
    print_backup_restore_summary(result)
    return result


def guided_analyze_mode(cluster, namespace, selected, timeout=2.0, allow_prompt_for_attacker=True, app_mode='default', start_chat=True, display_output=True):
    audit_obj, selector, pod, container = build_base_analysis(namespace, selected, timeout=timeout, app_mode=app_mode)
    prompt_answer = 'n'
    attacker_bundle = None
    remote_probe = None
    attacker_present = not bool(get_nested(audit_obj, 'meta', 'attacker_setup_error'))
    if not attacker_present and allow_prompt_for_attacker:
        print("\nInternal audit completed without an attacker pod.")
        prompt_answer = 'y' if prompt_yes_no('Create a temporary attacker pod backup record and run remote probes now', default='y') else 'n'
        if prompt_answer == 'y':
            attacker_bundle = persist_attacker_lifecycle_backup(namespace, selected.get('workload_name'), selector, attacker_name=None, existed_before=False)
            remote_probe = run_remote_probe_phase(namespace, selector, timeout=timeout, create_if_missing=True, cleanup_temporary_attacker=True)
            audit_obj['results']['remote_probe_after_internal'] = remote_probe.get('results', {})
            audit_obj['meta']['attacker_backup_record'] = attacker_bundle
            audit_obj['meta']['attacker_cleanup'] = remote_probe.get('attacker_cleanup', {})
            audit_obj = promote_internal_audit_findings(audit_obj)
            audit_obj = apply_spec_fallback_if_needed(audit_obj)
            audit_obj = apply_smart_enrichment(audit_obj, load_history())
            audit_obj = attach_ai_advisor(audit_obj, selected=selected, workflow_mode='analyze', app_mode=app_mode)
    outputs = guided_output_paths('guided_analyze', namespace, selected.get('workload_name'))
    ai_mode = normalize_app_mode(app_mode) == 'ai'
    smart_write_json_file(outputs['audit'], audit_obj, 'Audit JSON written', announce=not ai_mode)
    manifest_result = apply_fixes(
        audit_obj,
        namespace=namespace,
        workload=selected.get('workload_name'),
        kind=(selected.get('workload_kind') or 'deployment').lower(),
        patch_service_account=True,
        dry_run=True,
    )
    result = {
        'status': 'analyzed',
        'cluster': cluster,
        'namespace': namespace,
        'audit': audit_obj,
        'selector': selector,
        'pod': pod,
        'container': container,
        'prompted_for_attacker': allow_prompt_for_attacker and not attacker_present,
        'attacker_prompt_answer': prompt_answer,
        'attacker_backup_record': attacker_bundle,
        'remote_probe': remote_probe,
        'manifest_result': manifest_result,
        'outputs': outputs,
    }
    if display_output:
        if ai_mode:
            print_ai_analyze_completion_summary(audit_obj)
            print_artifact_summary(analyze_result=result, manifest_result=manifest_result)
        else:
            print_audit_summary(audit_obj)
            print_smart_summary(audit_obj)
            print_ai_advisor_summary(audit_obj)
            print_remediation_summary(audit_obj.get('remediation', {}))
            print_fix_result({'status': 'planned', 'apply_result': manifest_result, 'per_issue': []})
            print_artifact_summary(analyze_result=result, manifest_result=manifest_result)
            print_permanent_fix_explanation(audit_obj, manifest_result)
    if normalize_app_mode(app_mode) == 'ai' and start_chat:
        start_ai_chat_session(audit_obj, selected=selected, workflow_mode='guided-analyze')
    return result


def guided_remediation_mode(cluster, namespace, selected, timeout=2.0, analyze_first=True, app_mode='default', start_chat=True, analyze_bundle_override=None):
    analyze_bundle = analyze_bundle_override or (guided_analyze_mode(cluster, namespace, selected, timeout=timeout, allow_prompt_for_attacker=False, app_mode=app_mode, start_chat=False, display_output=False) if analyze_first else None)
    audit_obj = (analyze_bundle or {}).get('audit')
    if not audit_obj:
        audit_obj, _, _, _ = build_base_analysis(namespace, selected, timeout=timeout, app_mode=app_mode)
    outputs = guided_output_paths('guided_remediation', namespace, selected.get('workload_name'))
    ai_mode = normalize_app_mode(app_mode) == 'ai'
    smart_write_json_file(outputs['audit'], audit_obj, 'Audit JSON written', announce=not ai_mode)
    items = (audit_obj.get('remediation') or {}).get('items') or []
    actionable_items = [item for item in items if (item.get('issue_id') or '') != 'NO_ACTIONABLE_FAILURES']
    if not actionable_items:
        fix_result = {
            'status': 'no_change',
            'meta': {
                'namespace': namespace,
                'workload': selected.get('workload_name'),
                'kind': (selected.get('workload_kind') or 'deployment').lower(),
                'executed_at': now_utc_iso(),
            },
            'selected_issue_ids': [item.get('issue_id') for item in items],
            'per_issue': [{
                'issue_id': item.get('issue_id'),
                'title': item.get('title'),
                'status': 'manual_only',
                'risk_level': item.get('risk_level'),
                'note': item.get('manual_recommendation') or item.get('risk_note') or 'No actionable remediation rule was confirmed for this audit.',
            } for item in items],
            'apply_result': None,
            'approval_required': [],
            'manual_only': items,
            'aggressive_execute': True,
            'post_fix_health': {'status': 'not_run', 'checks': [], 'reason': 'no_actionable_remediation_items'},
        }
        smart_write_json_file(outputs['fix'], fix_result, 'Fix JSON written', announce=not ai_mode)
        remediation_bundle = {'outputs': outputs, 'fix': fix_result}
        if ai_mode:
            print_ai_remediation_completion_summary(audit_obj, fix_result, analyze_ran=bool(analyze_bundle))
            print_artifact_summary(analyze_result=analyze_bundle, fix_result=remediation_bundle, manifest_result=(analyze_bundle or {}).get('manifest_result'))
        else:
            print_fix_result(fix_result)
            print_artifact_summary(analyze_result=analyze_bundle, fix_result=remediation_bundle, manifest_result=(analyze_bundle or {}).get('manifest_result'))
        if normalize_app_mode(app_mode) == 'ai' and start_chat:
            start_ai_chat_session(audit_obj, selected=selected, workflow_mode='guided-remediation')
        return {'status': 'remediated', 'cluster': cluster, 'namespace': namespace, 'audit': audit_obj, 'fix': fix_result, 'outputs': outputs, 'analyze_bundle': analyze_bundle}
    grouping = safe_autonomous_selection(items, aggressive=True)
    fix_result = run_selected_fix_groups(
        audit_obj,
        grouping['selected'] + grouping['approval_required'],
        namespace=namespace,
        workload=selected.get('workload_name'),
        kind=(selected.get('workload_kind') or 'deployment').lower(),
        execute=True,
    )
    fix_result['approval_required'] = grouping['approval_required']
    fix_result['manual_only'] = grouping['manual_only']
    fix_result['aggressive_execute'] = True
    fix_result['post_fix_health'] = check_agentic_workload_health_guided(audit_obj, fix_result, timeout=timeout)
    smart_write_json_file(outputs['fix'], fix_result, 'Fix JSON written', announce=not ai_mode)
    remediation_bundle = {'outputs': outputs, 'fix': fix_result}
    if ai_mode:
        print_ai_remediation_completion_summary(audit_obj, fix_result, analyze_ran=bool(analyze_bundle))
        print_artifact_summary(analyze_result=analyze_bundle, fix_result=remediation_bundle, manifest_result=(analyze_bundle or {}).get('manifest_result'))
    else:
        print_ai_advisor_summary(audit_obj)
        print_fix_result(fix_result)
        print_artifact_summary(analyze_result=analyze_bundle, fix_result=remediation_bundle, manifest_result=(analyze_bundle or {}).get('manifest_result'))
        if analyze_bundle and analyze_bundle.get('manifest_result'):
            print_permanent_fix_explanation(audit_obj, analyze_bundle.get('manifest_result'))
    if normalize_app_mode(app_mode) == 'ai' and start_chat:
        start_ai_chat_session(audit_obj, selected=selected, workflow_mode='guided-remediation')
    return {'status': 'remediated', 'cluster': cluster, 'namespace': namespace, 'audit': audit_obj, 'fix': fix_result, 'outputs': outputs, 'analyze_bundle': analyze_bundle}


def guided_mode_run(cluster=None, namespace=None, mode=None, timeout=2.0, restore_bundle_dir=None, app_mode='default'):
    resolved_cluster = ensure_cluster_matches(cluster)
    namespace = namespace or autodetect_namespace('default')
    app_mode = normalize_app_mode(app_mode)
    mode = mode or prompt_choice('Mode', ['backup-restore', 'analyze', 'remediation', 'analyze-remediation'], default='analyze')
    resources = list_candidate_resources(namespace) if namespace else []
    selected, resources = discover_primary_target_resource(namespace, resources=resources)
    if not selected:
        raise RuntimeError(f'No target workload discovered in namespace {namespace}')
    print_guided_context(resolved_cluster, namespace, selected)
    print(f"app_mode: {app_mode}")
    if mode == 'backup-restore':
        action = prompt_choice('Backup or restore', ['backup', 'restore'], default='backup')
        bundle_dir = restore_bundle_dir
        result = guided_backup_restore_mode(resolved_cluster, namespace, selected, action=action, bundle_dir=bundle_dir)
    elif mode == 'analyze':
        result = guided_analyze_mode(resolved_cluster, namespace, selected, timeout=timeout, allow_prompt_for_attacker=True, app_mode=app_mode)
    elif mode == 'remediation':
        result = guided_remediation_mode(resolved_cluster, namespace, selected, timeout=timeout, analyze_first=True, app_mode=app_mode)
    elif mode == 'analyze-remediation':
        analyze_result = guided_analyze_mode(resolved_cluster, namespace, selected, timeout=timeout, allow_prompt_for_attacker=True, app_mode=app_mode)
        remediation_result = guided_remediation_mode(resolved_cluster, namespace, selected, timeout=timeout, analyze_first=False, app_mode=app_mode)
        result = {'status': 'analyze_and_remediate_complete', 'cluster': resolved_cluster, 'namespace': namespace, 'analyze': analyze_result, 'remediation': remediation_result}
    else:
        raise RuntimeError(f'unsupported guided mode: {mode}')
    record_run_history((result.get('audit') if isinstance(result, dict) else {}) or {}, (result.get('fix') if isinstance(result, dict) else None) or {'status': result.get('status') if isinstance(result, dict) else 'unknown'})
    return result


def list_namespaces(timeout=30):
    if not has_kubectl():
        return []
    try:
        obj = kubectl_get_json('', 'namespaces', timeout=timeout)
        names = [get_nested(item, 'metadata', 'name') for item in (obj.get('items') or [])]
        return [name for name in names if name]
    except Exception:
        return []


def prompt_for_cluster(initial=None):
    detected = initial or current_cluster_name() or ''
    while True:
        value = prompt('Cluster to analyze', detected or None).strip()
        if value:
            return value
        if detected:
            return detected
        print('Enter a cluster name.')


def prompt_for_namespace(initial=None):
    detected = initial or autodetect_namespace('default')
    while True:
        value = prompt('Namespace to analyze (or type `list`)', detected or None).strip()
        if value.lower() == 'list':
            namespaces = list_namespaces()
            print('\nAvailable namespaces:')
            if namespaces:
                for idx, ns in enumerate(namespaces, start=1):
                    print(f"{idx}. {ns}")
            else:
                print('No namespaces could be listed.')
            continue
        if value:
            return value
        if detected:
            return detected
        print('Enter a namespace.')


def select_resource_for_default(namespace, workload_name=None):
    resources = list_candidate_resources(namespace)
    candidates = [r for r in resources if not is_attacker_resource(r)]
    if workload_name:
        matches = [r for r in candidates if (r.get('workload_name') or '').lower() == workload_name.lower()]
        if not matches:
            raise RuntimeError(f"No workload named '{workload_name}' discovered in namespace {namespace}")
        return matches[0]
    if len(candidates) == 1:
        return candidates[0]
    if not candidates:
        raise RuntimeError(f'No target workload discovered in namespace {namespace}')
    print_resource_list(candidates, title='Discovered target resources')
    names = ', '.join(sorted({r.get('workload_name') for r in candidates if r.get('workload_name')}))
    raise RuntimeError(f"Multiple workloads discovered in namespace {namespace}; rerun with --workload-name. Available: {names}")


def run_default_app_mode(cluster=None, namespace=None, action=None, timeout=2.0, restore_bundle_dir=None, workload_name=None):
    if not cluster or not namespace or not action:
        raise RuntimeError('default mode requires --cluster, --namespace, and --action')
    resolved_cluster = ensure_cluster_matches(cluster)
    selected = select_resource_for_default(namespace, workload_name=workload_name)
    print_guided_context(resolved_cluster, namespace, selected)
    print("app_mode: default")
    if action == 'backup-restore':
        result = guided_backup_restore_mode(resolved_cluster, namespace, selected, action='backup', bundle_dir=restore_bundle_dir)
    elif action == 'analyze':
        result = guided_analyze_mode(resolved_cluster, namespace, selected, timeout=timeout, allow_prompt_for_attacker=True, app_mode='default', start_chat=False)
    elif action == 'remediation':
        result = guided_remediation_mode(resolved_cluster, namespace, selected, timeout=timeout, analyze_first=True, app_mode='default', start_chat=False)
    elif action == 'analyze-remediation':
        analyze_result = guided_analyze_mode(resolved_cluster, namespace, selected, timeout=timeout, allow_prompt_for_attacker=True, app_mode='default', start_chat=False)
        remediation_result = guided_remediation_mode(resolved_cluster, namespace, selected, timeout=timeout, analyze_first=False, app_mode='default', start_chat=False)
        result = {'status': 'analyze_and_remediate_complete', 'cluster': resolved_cluster, 'namespace': namespace, 'analyze': analyze_result, 'remediation': remediation_result}
    else:
        raise RuntimeError(f'unsupported action: {action}')
    return result


def run_ai_app_mode(cluster=None, namespace=None, timeout=2.0, restore_bundle_dir=None):
    session = {
        'app_mode': 'ai',
        'cluster': None,
        'namespace': None,
        'selected': None,
        'resources': [],
        'timeout': timeout,
        'restore_bundle_dir': restore_bundle_dir,
        'analyze_result': None,
        'audit': {'app_mode': 'ai'},
        'audit_data_collected': False,
        'manifest_result': None,
        'detected_cluster': current_cluster_name() if has_kubectl() else None,
        'detected_namespace': autodetect_namespace('default') if has_kubectl() else None,
        'phase': 'awaiting_cluster',
    }
    if cluster:
        resolved_cluster = ensure_cluster_matches(cluster)
        session['cluster'] = resolved_cluster
        session['phase'] = 'awaiting_namespace'
    if namespace:
        session['namespace'] = namespace
        if session.get('cluster'):
            session['phase'] = 'awaiting_workload_discovery'
    start_ai_chat_session(session.get('audit') or {}, selected=session.get('selected'), workflow_mode='guided-ai', session=session)
    return session.get('analyze_result') or {'status': 'ai_session_closed', 'cluster': session.get('cluster'), 'namespace': session.get('namespace')}


def run_hidden_internal_cli(argv):
    ap = argparse.ArgumentParser(description='AgentFence internal compatibility mode')
    ap.add_argument('--timeout', type=float, default=2.0)
    ap.add_argument('--stdout-json', action='store_true')
    ap.add_argument('--out')
    args = ap.parse_args(argv)
    obj = collect_internal(timeout=args.timeout)
    if args.out:
        with open(args.out, 'w') as fh:
            json.dump(obj, fh, indent=2)
    if args.stdout_json or not args.out:
        print(json.dumps(obj, indent=2))
    return obj


_original_main = main

def main():
    if len(sys.argv) > 1 and sys.argv[1] == 'internal':
        try:
            return run_hidden_internal_cli(sys.argv[2:])
        except RuntimeError as e:
            print(f"Error: {e}", file=sys.stderr)
            return 2
    ap = argparse.ArgumentParser(description='AgentFence AI')
    ap.add_argument('--app-mode', choices=['default', 'ai'], default=APP_MODE_DEFAULT)
    ap.add_argument('--cluster')
    ap.add_argument('--namespace')
    ap.add_argument('--action', choices=['backup-restore', 'analyze', 'remediation', 'analyze-remediation'])
    ap.add_argument('--workload-name')
    ap.add_argument('--timeout', type=float, default=2.0)
    ap.add_argument('--restore-bundle-dir')
    args = ap.parse_args()
    try:
        if args.app_mode == 'ai':
            return run_ai_app_mode(cluster=args.cluster, namespace=args.namespace, timeout=args.timeout, restore_bundle_dir=args.restore_bundle_dir)
        return run_default_app_mode(
            cluster=args.cluster,
            namespace=args.namespace,
            action=args.action,
            timeout=args.timeout,
            restore_bundle_dir=args.restore_bundle_dir,
            workload_name=args.workload_name,
        )
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(2)

if __name__ == "__main__":
    main()
