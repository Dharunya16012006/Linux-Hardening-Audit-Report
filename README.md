# Linux-Hardening-Audit-Report

Linux Hardening Audit Tool
A Python-based security auditing script designed to help assess and harden Linux servers against common vulnerabilities. This tool checks for critical settings mapped to CIS Linux Server benchmarks, including:

Firewall status and configuration (UFW, Firewalld, Iptables)

Disabled unused or risky network services

SSH hardening parameters (root login, protocol, password auth)

Secure permissions for key system files (/etc/passwd, /etc/shadow, /etc/group, /etc/gshadow, /etc/ssh/sshd_config)

Rootkit and stealth indicators (suspicious ld.so.preload, UID 0 accounts, PATH hygiene, kernel modules)

The output is a human-readable console report (with compliance score and remediation steps for failed checks) and an optional JSON file for programmatic analysis. The tool is intended for quick self-assessment and scripting, not official compliance reporting—refer to CIS benchmarks for full security reviews.

Note: Run as root for most accurate results. Tested on modern Linux distributions.
