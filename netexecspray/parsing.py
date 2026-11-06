"""Interpret the raw text that nxc / native sprayers return."""

import re

from .protocols import NATIVE_PROTOCOLS


def mask_secret(secret, is_hash):
    """The one secret-display format used everywhere a hash must not be
    shown in full — per-attempt log/UI lines (worker.py) and the wave/round
    header (cli.py) alike — so there's exactly one place to change how much
    of a hash is exposed, instead of two copies that can drift apart."""
    return f"(hash:{secret[:16]}…)" if is_hash else secret


CLOCK_SKEW_MARKER = "KRB_AP_ERR_SKEW"
CLOCK_SKEW_MSG = "clock skew with KDC — sync time (ntpdate/faketime) and retry"


def is_clock_skew(text):
    """spray_one() and spray_bulk() both need to recognise KDC clock skew as
    an operational problem (not a bad credential) before their own
    classification logic runs, so a --max-attempts charge isn't burned on an
    attempt that never really tested the password. Centralized for the same
    reason as _locked_or_must_change() — one spot to update, not two that
    can silently drift apart."""
    return CLOCK_SKEW_MARKER in (text or "")


def _locked_or_must_change(text):
    """The marker check parse_output() and parse_bulk_line() both need before
    their own pwned/valid/fail logic — kept in one place so a newly added
    Kerberos/NTLM error code only has to be taught here once, instead of
    risking the per-credential and --bulk paths classifying the same nxc
    output differently."""
    if ("STATUS_ACCOUNT_LOCKED_OUT" in text or "LOCKED_OUT" in text
            or "KDC_ERR_CLIENT_REVOKED" in text):
        return "locked"
    if "STATUS_PASSWORD_MUST_CHANGE" in text or "KDC_ERR_KEY_EXPIRED" in text:
        return "must_change"
    return None


def parse_output(proto, output):
    """Classify an attempt's output → one of:
    pwned | valid | locked | must_change | fail."""
    if not output:
        return "fail"

    marker = _locked_or_must_change(output)
    if marker:
        return marker

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


# one nxc line per credential it tried, e.g.:
#   SMB   10.129.232.128  445  DC01  [+] DC01\rose:KxEPkKe6R8su
#   SMB   10.129.232.128  445  DC01  [-] DC01\Guest:KxEPkKe6R8su STATUS_LOGON_FAILURE
# — used by --bulk, where one nxc invocation carries a whole userlist and the
# per-credential records have to be split back out of its combined output.
# The mark/user are delimited unambiguously (``[+]``/``[-]``, then up to the
# first ``:``), but the secret has no such delimiter of its own — a generic
# ``\S+`` capture truncates at the first space, mis-splitting a password
# that contains one. --bulk always sprays one known secret against the whole
# batch, so split on that literal secret (escaped) instead of guessing its
# shape.
_BULK_LINE_TEMPLATE = r"\[(?P<mark>[+-])\]\s+(?:[^\\\s]+\\)?(?P<user>[^:\s]+):{}(?P<rest>.*)$"


def split_bulk_output(output, secret):
    """Pull (mark, user, rest) out of each per-credential line nxc printed for
    a multi-user run against the one known `secret` this batch sprayed. Lines
    that don't match (banners, [*] host info, blank lines) are simply not
    credential results."""
    pattern = re.compile(_BULK_LINE_TEMPLATE.format(re.escape(secret)))
    hits = []
    for line in (output or "").splitlines():
        m = pattern.search(line)
        if m:
            hits.append((m.group("mark"), m.group("user"), m.group("rest").strip()))
    return hits


def parse_bulk_line(mark, rest):
    """Same classification as :func:`parse_output`, scoped to one already-split
    bulk-output line → pwned | valid | locked | must_change | fail."""
    marker = _locked_or_must_change(rest)
    if marker:
        return marker
    if mark != "+":
        return "fail"
    return "pwned" if "Pwn3d!" in rest else "valid"


def explain_output(output):
    """Human-readable reasons extracted from a failed attempt's output.

    Only called on the 'fail' branch (parse_output()/parse_bulk_line() already
    returned 'locked' or 'must_change' for anything _locked_or_must_change()
    matches), so none of its markers — STATUS_ACCOUNT_LOCKED_OUT, LOCKED_OUT,
    KDC_ERR_CLIENT_REVOKED, STATUS_PASSWORD_MUST_CHANGE, KDC_ERR_KEY_EXPIRED —
    belong here; they can never actually appear in output this function sees.
    KRB_AP_ERR_SKEW is excluded for the same reason: both spray_one() and
    spray_bulk() intercept and reclassify it as an operational error before
    ever reaching this 'fail' path."""
    checks = [
        ("STATUS_LOGON_FAILURE",        "Wrong credentials"),
        ("STATUS_ACCOUNT_DISABLED",     "Account disabled"),
        ("STATUS_PASSWORD_EXPIRED",     "Password expired"),
        ("Connection refused",          "Service unreachable"),
        ("Connection timed out",        "Host timed out"),
        ("KDC_ERR_C_PRINCIPAL_UNKNOWN", "User not found in domain"),
        ("KDC_ERR_PREAUTH_FAILED",      "Wrong credentials (Kerberos pre-auth)"),
        ("KRB_AP_ERR_TKT_EXPIRED",      "Kerberos ticket expired"),
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
