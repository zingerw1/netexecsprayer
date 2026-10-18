"""Interpret the raw text that nxc / native sprayers return."""

import re

from .protocols import NATIVE_PROTOCOLS


def parse_output(proto, output):
    """Classify an attempt's output → one of:
    pwned | valid | locked | must_change | fail."""
    if not output:
        return "fail"

    if "STATUS_ACCOUNT_LOCKED_OUT" in output or "LOCKED_OUT" in output:
        return "locked"
    if "STATUS_PASSWORD_MUST_CHANGE" in output:
        return "must_change"

    if proto in NATIVE_PROTOCOLS:
        if "AUTH SUCCESS" in output and "[+]" in output:
            return "pwned" if "Pwn3d!" in output else "valid"
        return "fail"

    if "Pwn3d!" in output:
        return "pwned"

    for line in output.splitlines():
        parts = line.strip().split()
        if len(parts) >= 5 and "[+]" in parts:
            return "valid"

    return "fail"


def explain_output(output):
    """Human-readable reasons extracted from a failed attempt's output."""
    checks = [
        ("STATUS_LOGON_FAILURE",        "Wrong credentials"),
        ("STATUS_ACCOUNT_LOCKED_OUT",   "Account locked out"),
        ("STATUS_ACCOUNT_DISABLED",     "Account disabled"),
        ("STATUS_PASSWORD_MUST_CHANGE", "Password must change"),
        ("STATUS_PASSWORD_EXPIRED",     "Password expired"),
        ("Connection refused",          "Service unreachable"),
        ("Connection timed out",        "Host timed out"),
        ("KDC_ERR_C_PRINCIPAL_UNKNOWN", "User not found in domain"),
        ("ACCESS DENIED",               "Access denied"),
        ("AUTH FAILED",                 "Authentication failed"),
    ]
    return [msg for marker, msg in checks if marker in output]


def banner(output):
    """Pull the one informative detail out of raw nxc / native output."""
    if not output:
        return ""
    for line in output.splitlines():
        if "[*]" in line:                        # nxc host / OS banner
            return line.split("[*]", 1)[1].strip()
    for line in output.splitlines():
        if "AUTH SUCCESS" in line and "—" in line:   # native success tail
            return line.split("—", 1)[1].strip()
    return ""


def short_detail(detail, limit=36):
    """Compress a verbose banner to something that fits on one line.
    Prefers host/domain (DC01 · sequel.htb); otherwise truncates."""
    if not detail:
        return ""
    name = re.search(r"name:([^)\s]+)", detail)
    dom  = re.search(r"domain:([^)\s]+)", detail)
    bits = [m.group(1) for m in (name, dom) if m]
    if bits:
        return " · ".join(dict.fromkeys(bits))
    return detail if len(detail) <= limit else detail[:limit - 1] + "…"
