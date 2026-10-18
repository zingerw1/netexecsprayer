"""Input loading: targets (incl. CIDR expansion & DNS), credential/combo lists,
and resume parsing of a previous log."""

import ipaddress
import re
import socket
import sys
from pathlib import Path

from . import ui
from .theme import CYAN, RED, RESET, YELLOW, G_INFO, G_WARN


def load_list(value):
    """Resolve a -u/-p/target value into a list.

    * an existing file  → one item per non-blank line
    * otherwise         → a comma-separated inline list (``user1,user2``)

    A single value with no comma just comes back as ``[value]``. If a password
    itself contains a comma, put it in a file instead of using the inline form."""
    if not value:
        return []
    p = Path(value)
    if p.is_file():
        return [line.strip() for line in p.read_text().splitlines() if line.strip()]
    return [part.strip() for part in value.split(",") if part.strip()]


def load_combos(path):
    """Load a combo list of ``user:pass`` (or ``domain\\user:pass``) → [(user, secret)]."""
    p = Path(path)
    if not p.is_file():
        return []
    pairs = []
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        user, secret = line.split(":", 1)
        if user:
            pairs.append((user, secret))
    return pairs


def load_spray_file(path):
    """Load a mixed spray file and pool it into (users, passwords).

    Each non-blank, non-``#`` line is either::

        user:pass       → contributes a user AND a password
        user            → contributes a user only (bare username)

    All users and all discovered passwords are de-duplicated (order preserved)
    and returned separately, so the caller sprays every user × every password
    (classic password spraying), not the 1:1 pairing that :func:`load_combos`
    does. ``domain\\user:pass`` is fine — only the first ``:`` splits.
    """
    users, passwords = [], []
    p = Path(path)
    if not p.is_file():
        return [], []
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if ":" in line:
            user, pw = line.split(":", 1)
            if user:
                users.append(user)
            if pw:
                passwords.append(pw)
        else:
            users.append(line)
    return list(dict.fromkeys(users)), list(dict.fromkeys(passwords))


_RESUME_RE = re.compile(
    r"^\s*\d\d:\d\d:\d\d\s+\S+\s+(?P<label>\S+)\s+(?P<proto>\S+)\s+"
    r"(?P<target>\S+)\s+(?P<user>\S+)\s+(?P<secret>\S+)"
)


def load_prior_attempts(path):
    """Parse a previous clean log; return (seen_keys, locked_users).

    Seen keys are ``proto:target:user:secret`` so already-tried combos are
    skipped. Hash secrets are truncated in logs, so resume is reliable for
    password sprays."""
    seen, locked = set(), set()
    p = Path(path)
    if not p.is_file():
        return seen, locked
    for line in p.read_text(errors="replace").splitlines():
        m = _RESUME_RE.match(line)
        if not m:
            continue
        g = m.groupdict()
        seen.add(f"{g['proto']}:{g['target']}:{g['user']}:{g['secret']}")
        if g["label"].upper() == "LOCK":
            locked.add(g["user"])
    return seen, locked


# ── Targets ──────────────────────────────────────────────────────────────────
def is_ip(value):
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def resolve_domain(name, dns_timeout=5):
    try:
        socket.setdefaulttimeout(dns_timeout)
        results = socket.getaddrinfo(name, None, socket.AF_INET)
        return list(dict.fromkeys(r[4][0] for r in results))
    except socket.gaierror:
        return [name]


def expand_targets(raw_targets, resolve=False, expand_cidr=True, force=False):
    """Normalise targets: expand CIDRs to host IPs (so native sprayers and the
    job counter are correct), optionally resolve names, and de-duplicate."""
    expanded = []
    for raw in raw_targets:
        if "/" in raw:
            try:
                net = ipaddress.ip_network(raw, strict=False)
            except ValueError:
                net = None
            if net is not None:
                if net.num_addresses == 1:
                    expanded.append(str(net.network_address))
                elif not expand_cidr:
                    expanded.append(raw)              # hand the CIDR to nxc as-is
                else:
                    hosts = list(net.hosts()) or [net.network_address]
                    if len(hosts) > 1024 and not force:
                        ui.cprint(f"[!] {raw} expands to {len(hosts)} hosts — refusing "
                                  f"(use --force, or --no-expand-cidr for nxc-native)", RED)
                        sys.exit(2)
                    expanded.extend(str(h) for h in hosts)
                continue

        if is_ip(raw):
            expanded.append(raw)
            continue

        if resolve:
            ips = resolve_domain(raw)
            if ips == [raw]:
                ui.cprint(f"  {YELLOW}{G_WARN} could not resolve '{raw}' — using as-is{RESET}")
                expanded.append(raw)
            else:
                ui.cprint(f"  {CYAN}{G_INFO} resolved {raw} → {', '.join(ips)}{RESET}")
                expanded.extend(ips)
        else:
            expanded.append(raw)

    return list(dict.fromkeys(expanded))
