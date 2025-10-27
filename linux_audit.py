#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Linux Hardening Audit Tool

Checks (subset mapped to common CIS Linux Server benchmarks):
- Firewall configured and active (UFW/Firewalld/Iptables)
- Unused/risky services disabled
- SSH hardening settings in /etc/ssh/sshd_config
- Permissions on key system files (/etc/passwd, /etc/shadow, /etc/group, /etc/gshadow, /etc/ssh/sshd_config)
- Simple rootkit/stealth indicators (ld.so.preload, extra UID 0 accounts, PATH hygiene)

Outputs:
- Human-readable console report with compliance score
- Optional JSON report via --json-out <path>

Note:
- Run with sudo for most accurate results (some files readable without root, but service/firewall states may differ).
- This is a simplified auditor; for full CIS compliance use official benchmarks and tooling.
"""

import argparse
import json
import os
import platform
import re
import shlex
import shutil
import socket
import stat
import subprocess
import sys
from datetime import datetime
from typing import Dict, Any, List, Tuple


def run_cmd(cmd: str, timeout: int = 10) -> Tuple[int, str, str]:
    try:
        proc = subprocess.run(
            shlex.split(cmd),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            text=True,
            check=False,
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except FileNotFoundError:
        return 127, "", f"command not found: {cmd}"
    except subprocess.TimeoutExpired:
        return 124, "", f"timeout after {timeout}s: {cmd}"


def is_root() -> bool:
    try:
        return os.geteuid() == 0  # type: ignore[attr-defined]
    except AttributeError:
        # Non-POSIX (e.g., Windows). On Linux this exists.
        return False


def read_file(path: str) -> Tuple[bool, str]:
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return True, f.read()
    except Exception as e:
        return False, str(e)


def file_mode_owner(path: str) -> Tuple[bool, Dict[str, Any]]:
    try:
        st = os.stat(path)
        mode = stat.S_IMODE(st.st_mode)
        return True, {"mode": mode, "uid": st.st_uid, "gid": st.st_gid}
    except Exception as e:
        return False, {"error": str(e)}


def detect_distro() -> Dict[str, Any]:
    info = {"platform": platform.platform(), "system": platform.system(), "release": platform.release()}
    # Try to parse /etc/os-release
    ok, content = read_file("/etc/os-release")
    if ok:
        for line in content.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                v = v.strip().strip('"')
                info[k] = v
    return info


def which(binary: str) -> bool:
    return shutil.which(binary) is not None


# ----------------------------- Checks ---------------------------------


def check_firewall() -> Dict[str, Any]:
    result = {
        "id": "FW-1",
        "title": "Firewall configured and active",
        "pass": False,
        "evidence": [],
        "remediation": [
            "Install and enable a host-based firewall (UFW or firewalld).",
            "Default-deny inbound; allow only required ports.",
            "UFW example: apt/yum install ufw; ufw default deny incoming; ufw allow ssh; ufw enable",
            "firewalld example: dnf/yum install firewalld; systemctl enable --now firewalld; firewall-cmd --permanent --set-default-zone=drop; firewall-cmd --permanent --add-service=ssh; firewall-cmd --reload",
        ],
        "points": 8,
    }

    active = False
    default_deny = False

    # UFW
    if which("ufw"):
        rc, out, err = run_cmd("ufw status verbose")
        result["evidence"].append(f"ufw rc={rc} out={out or err}")
        if rc == 0:
            if re.search(r"Status:\s+active", out, re.IGNORECASE):
                active = True
            if re.search(r"Default: .*incoming: deny", out, re.IGNORECASE):
                default_deny = True

    # firewalld
    if which("firewall-cmd"):
        rc, out, err = run_cmd("firewall-cmd --state")
        result["evidence"].append(f"firewalld rc={rc} out={out or err}")
        if rc == 0 and out.strip() == "running":
            active = True
            # Check default zone policy if possible
            rc2, out2, err2 = run_cmd("firewall-cmd --get-default-zone")
            if rc2 == 0:
                result["evidence"].append(f"firewalld default zone={out2}")

    # iptables/nftables rudimentary check
    if which("iptables"):
        rc, out, err = run_cmd("iptables -S")
        rules = len([l for l in out.splitlines() if l.strip().startswith("-")]) if rc == 0 else 0
        result["evidence"].append(f"iptables rc={rc} rules={rules}")
        # Assume active if there are rules (approximation)
        if rules > 0:
            active = True
    if which("nft"):
        rc, out, err = run_cmd("nft list ruleset")
        if rc == 0 and out:
            result["evidence"].append("nftables ruleset present")
            active = True

    # Final decision
    result["pass"] = active and (default_deny or which("firewall-cmd"))
    return result


def parse_systemctl_enabled_services() -> List[str]:
    if not which("systemctl"):
        return []
    rc, out, err = run_cmd("systemctl list-unit-files --type=service --state=enabled")
    if rc != 0:
        return []
    services = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[0].endswith(".service") and parts[1] == "enabled":
            services.append(parts[0])
    return services


def check_services() -> Dict[str, Any]:
    risky = [
        "telnet.service",
        "rsh.socket",
        "rlogin.socket",
        "rexec.socket",
        "vsftpd.service",
        "tftp.service",
        "nfs-server.service",
        "rpcbind.service",
        "cups.service",
        "avahi-daemon.service",
        "smb.service",
        "snmpd.service",
    ]
    enabled = parse_systemctl_enabled_services()

    present = [s for s in enabled if s in risky]

    # Check listening sockets breadth
    listening_any = []
    if which("ss"):
        rc, out, err = run_cmd("ss -tuln")
        if rc == 0:
            for line in out.splitlines():
                if "LISTEN" in line and ("0.0.0.0:" in line or ":[::]:" in line):
                    listening_any.append(line.strip())

    passed = (len(present) == 0)
    evidence = {
        "enabled_services_count": len(enabled),
        "risky_enabled": present,
        "listening_any": listening_any[:20],
    }

    remediation = [
        "Disable unused network services (systemctl disable --now <svc>).",
        "Avoid legacy/unsafe services: telnet, rsh, rexec, vsftpd, tftp.",
        "Restrict listeners to specific interfaces where possible.",
    ]

    return {
        "id": "SRV-1",
        "title": "Unused/risky services disabled and listeners restricted",
        "pass": passed,
        "evidence": evidence,
        "remediation": remediation,
        "points": 6,
    }


def parse_sshd_config() -> Dict[str, Any]:
    path = "/etc/ssh/sshd_config"
    ok, content = read_file(path)
    values: Dict[str, str] = {}
    if not ok:
        return {"error": content}
    for raw in content.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # Split key value (support inline comments)
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = re.split(r"\s+", line, maxsplit=1)
        if len(parts) == 2:
            key, val = parts[0].strip(), parts[1].strip()
            values[key.lower()] = val
        elif len(parts) == 1:
            values[parts[0].lower()] = "yes"
    return values


def check_ssh() -> Dict[str, Any]:
    values = parse_sshd_config()
    evidence = {"config": values}
    if "error" in values:
        return {
            "id": "SSH-1",
            "title": "SSH hardening",
            "pass": False,
            "evidence": values,
            "remediation": ["Ensure /etc/ssh/sshd_config exists and is readable."],
            "points": 8,
        }

    def is_no(v: str) -> bool:
        return v.lower() in {"no", "prohibit-password", "forced-commands-only"}

    controls = {
        "permitrootlogin": lambda v: is_no(v),
        "passwordauthentication": lambda v: v.lower() == "no",
        "protocol": lambda v: v.strip() == "2",
        "x11forwarding": lambda v: v.lower() == "no",
        "maxauthtries": lambda v: int(re.findall(r"\d+", v)[0]) <= 4 if re.findall(r"\d+", v) else False,
    }

    failed = []
    for k, fn in controls.items():
        v = values.get(k, "")
        try:
            if not v or not fn(v):
                failed.append(k)
        except Exception:
            failed.append(k)

    remediation = [
        "In /etc/ssh/sshd_config set: PermitRootLogin no",
        "Set: PasswordAuthentication no (use key-based auth)",
        "Ensure: Protocol 2",
        "Set: X11Forwarding no unless required",
        "Set: MaxAuthTries 4",
        "Then: systemctl reload sshd",
    ]

    return {
        "id": "SSH-1",
        "title": "SSH hardening",
        "pass": len(failed) == 0,
        "evidence": {"failed": failed, **evidence},
        "remediation": remediation,
        "points": 10,
    }


def check_file_perms() -> Dict[str, Any]:
    targets = [
        {"path": "/etc/passwd", "mode_max": 0o644, "uid": 0, "gid_any": True},
        {"path": "/etc/group", "mode_max": 0o644, "uid": 0, "gid_any": True},
        {"path": "/etc/shadow", "mode_max": 0o640, "uid": 0, "gid": 42},  # gid shadow often 42 (Debian/Ubuntu) or 0 on some
        {"path": "/etc/gshadow", "mode_max": 0o640, "uid": 0, "gid": 42},
        {"path": "/etc/ssh/sshd_config", "mode_max": 0o644, "uid": 0, "gid_any": True},
    ]

    issues = []
    details = []
    for t in targets:
        ok, meta = file_mode_owner(t["path"])
        if not ok:
            issues.append(f"unreadable:{t['path']}")
            details.append({"path": t["path"], "error": meta.get("error")})
            continue
        mode = meta["mode"]
        uid = meta["uid"]
        gid = meta["gid"]
        mode_ok = mode <= t["mode_max"]
        uid_ok = uid == t.get("uid", 0)
        gid_req = t.get("gid")
        gid_ok = True if t.get("gid_any") else (gid_req is not None and gid == gid_req)
        if not (mode_ok and uid_ok and gid_ok):
            issues.append(t["path"])
        details.append({
            "path": t["path"],
            "mode": oct(mode),
            "uid": uid,
            "gid": gid,
            "mode_max_allowed": oct(t["mode_max"]),
            "uid_required": t.get("uid", 0),
            "gid_required": t.get("gid", "any" if t.get("gid_any") else None),
        })

    remediation = [
        "Set secure ownership and permissions:",
        "chown root:root /etc/passwd /etc/group; chmod 644 /etc/passwd /etc/group",
        "chown root:shadow /etc/shadow /etc/gshadow; chmod 640 /etc/shadow /etc/gshadow",
        "chown root:root /etc/ssh/sshd_config; chmod 644 /etc/ssh/sshd_config",
    ]

    return {
        "id": "PERM-1",
        "title": "Permissions on critical system files",
        "pass": len(issues) == 0,
        "evidence": {"issues": issues, "details": details},
        "remediation": remediation,
        "points": 10,
    }


def check_rootkit_indicators() -> Dict[str, Any]:
    indicators = []

    # 1) ld.so.preload unusual entries
    ok, content = read_file("/etc/ld.so.preload")
    if ok and content.strip():
        lines = [l.strip() for l in content.splitlines() if l.strip() and not l.strip().startswith("#")]
        indicators.append({"ld.so.preload": lines})

    # 2) Additional UID 0 accounts
    okp, passwd = read_file("/etc/passwd")
    if okp:
        uid0 = []
        for line in passwd.splitlines():
            if not line or line.startswith("#"):
                continue
            parts = line.split(":")
            if len(parts) >= 3:
                try:
                    if int(parts[2]) == 0 and parts[0] != "root":
                        uid0.append(parts[0])
                except ValueError:
                    pass
        if uid0:
            indicators.append({"uid0_accounts": uid0})

    # 3) PATH hygiene (dot or empty)
    path = os.environ.get("PATH", "")
    if ":.:" in f":{path}:" or path.startswith(":" ) or path.endswith(":"):
        indicators.append({"path_hygiene": path})

    # 4) Suspicious kernel modules names (heuristic)
    if which("lsmod"):
        rc, out, err = run_cmd("lsmod")
        if rc == 0:
            sus_names = {"hide", "rk", "rootkit", "diamorphine", "suterusu"}
            found = []
            for line in out.splitlines()[1:]:
                name = line.split()[0]
                for s in sus_names:
                    if s in name.lower():
                        found.append(name)
                        break
            if found:
                indicators.append({"sus_modules": found})

    passed = len(indicators) == 0
    remediation = [
        "Investigate and remove unexpected entries in /etc/ld.so.preload.",
        "Ensure only 'root' has UID 0.",
        "Sanitize PATH to exclude '.' and empty segments.",
        "Investigate suspicious kernel modules (lsmod, dmesg); reboot into known-good kernel if needed.",
    ]

    return {
        "id": "RK-1",
        "title": "Rootkit/stealth indicators",
        "pass": passed,
        "evidence": indicators,
        "remediation": remediation,
        "points": 8,
    }


# ------------------------- Scoring and Report --------------------------


def compute_score(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    total = sum(r.get("points", 0) for r in results)
    earned = sum(r.get("points", 0) for r in results if r.get("pass"))
    pct = round((earned / total * 100.0), 1) if total else 0.0
    return {"total_points": total, "earned_points": earned, "percentage": pct}


def generate_report(results: List[Dict[str, Any]], meta: Dict[str, Any]) -> Dict[str, Any]:
    score = compute_score(results)
    summary = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "hostname": socket.gethostname(),
        "distro": detect_distro(),
        "ran_as_root": is_root(),
        **meta,
    }
    return {"summary": summary, "score": score, "checks": results}


def print_human_report(report: Dict[str, Any]) -> None:
    s = report["summary"]
    sc = report["score"]
    print("=" * 70)
    print("Linux Hardening Audit Report")
    print("-" * 70)
    print(f"Timestamp:      {s.get('timestamp')}")
    print(f"Hostname:       {s.get('hostname')}")
    dist = s.get("distro", {})
    print(f"OS:             {dist.get('PRETTY_NAME', dist.get('platform', 'unknown'))}")
    print(f"Ran as root:    {s.get('ran_as_root')}")
    print("-" * 70)
    print(f"Compliance:     {sc['earned_points']}/{sc['total_points']} points ({sc['percentage']}%)")
    print("=" * 70)
    for r in report["checks"]:
        status = "PASS" if r["pass"] else "FAIL"
        print(f"[{status}] {r['id']} - {r['title']} ({r['points']} pts)")
        print("  Evidence:")
        ev = r.get("evidence")
        if isinstance(ev, dict):
            for k, v in ev.items():
                print(f"    - {k}: {v}")
        elif isinstance(ev, list):
            for item in ev[:10]:
                print(f"    - {item}")
            if len(ev) > 10:
                print(f"    - ... and {len(ev) - 10} more")
        else:
            print(f"    - {ev}")
        if not r["pass"]:
            print("  Remediation:")
            for rec in r.get("remediation", [])[:5]:
                print(f"    * {rec}")
        print("-" * 70)


# ------------------------------ Main ----------------------------------


def main():
    parser = argparse.ArgumentParser(description="Linux Hardening Audit Tool")
    parser.add_argument("--json-out", help="Write JSON report to the given path", default=None)
    parser.add_argument("--fast", action="store_true", help="Skip slower checks (none are slow by default)")
    args = parser.parse_args()

    if platform.system().lower() != "linux":
        print("Warning: This tool targets Linux.", file=sys.stderr)

    checks = [
        check_firewall(),
        check_services(),
        check_ssh(),
        check_file_perms(),
        check_rootkit_indicators(),
    ]

    report = generate_report(checks, meta={"version": "1.0.0"})

    print_human_report(report)

    if args.json_out:
        try:
            with open(args.json_out, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)
            print(f"JSON report written to: {args.json_out}")
        except Exception as e:
            print(f"Failed to write JSON report: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
