"""Input loading: targets (incl. CIDR expansion & DNS), credential/combo lists,
and resume parsing of a previous log."""

import ipaddress
import re
import socket
import sys
from pathlib import Path

from . import ui
from .theme import CYAN, RED, RESET, YELLOW, G_INFO, G_WARN


_HASH_RE = re.compile(r"^[0-9a-f]{32}$|^[0-9a-f]{32}:[0-9a-f]{32}$|^:[0-9a-f]{32}$",
                      re.IGNORECASE)

# worker.py's mask_secret() mask shape exactly — "(hash:" + secret[:16] + the
# ellipsis + ")". The content between "(hash:" and "…)" is deliberately NOT
# restricted to hex: -H's shape is never validated (cli.py explicitly lets
# --combo -H force non-NTLM hash formats like DCC2/AES256 Kerberos keys into
# hash mode too), so secret[:16] can contain anything, up to 16 characters
# (fewer if the raw value itself is shorter than 16 chars). What makes this
# shape distinctive enough to not false-positive on a real plaintext
# password is the literal "(hash:" prefix AND the U+2026 ellipsis character
# right before the closing paren — not the hex-ness of what's in between.
# Used to tell a masked hash entry apart from a literal plaintext password
# that merely starts with the text "(hash".
_HASH_MASK_RE = re.compile(r"^\(hash:.{1,16}…\)$")


def looks_like_hash(secret):
    """True if `secret` is shaped like an NTLM hash (NT-only, LM:NT, or :NT) —
    used to auto-detect hashes mixed in with plaintext passwords in -S/--combo
    files, where there's no -H flag to say so explicitly."""
    return bool(_HASH_RE.match(secret))


_LIST_FILE_EXTS = (".txt", ".lst", ".list", ".csv")


_IP_SHAPE_RE = re.compile(r"^\d+\.\d+\.\d+\.\d+/")


def _looks_like_missing_file(value, is_target):
    """None if `value` is fine as-is; otherwise "file" or "cidr", naming
    *why* it's probably not meant to be used as a literal value — so
    load_list() can warn with the right explanation instead of one generic
    "looks like a file path" message covering two different mistakes.

    Only applies when `value` has no comma (so it'd be returned as a single
    literal). Deliberately ignores backslash: ``DOMAIN\\user`` is a normal,
    valid -u value and not distinguishable here from a mistyped Windows path.

    The '/' check only applies to targets (``is_target``): a target shaped
    like a path and not a valid CIDR is almost certainly a typo'd file, but
    -u/-p legitimately allow '/' in a real username or password (e.g.
    ``DOMAIN/jdoe``, or a password containing one) — flagging those there
    would be a false positive on valid input, not a typo. A dotted-quad-
    shaped value that merely has a bad prefix/octet (``10.0.0.0/33``) is a
    typo'd CIDR, not a typo'd file path, and gets told apart from a value
    that isn't IP-shaped at all."""
    if "," in value:
        return None
    if value.lower().endswith(_LIST_FILE_EXTS):
        return "file"
    if is_target and "/" in value:
        try:
            ipaddress.ip_network(value, strict=False)
            return None
        except ValueError:
            return "cidr" if _IP_SHAPE_RE.match(value) else "file"
    return None


def load_list(value, is_target=False):
    """Resolve a -u/-p/-H/target value into a list.

    * an existing file  → one item per non-blank line
    * otherwise         → a comma-separated inline list (``user1,user2``)

    A single value with no comma just comes back as ``[value]``. If a password
    itself contains a comma, put it in a file instead of using the inline form.
    Pass ``is_target=True`` for the target argument — see
    :func:`_looks_like_missing_file` for why that one additionally checks '/'."""
    if not value:
        return []
    p = Path(value)
    if p.is_file():
        return [line.strip() for line in p.read_text().splitlines() if line.strip()]
    reason = _looks_like_missing_file(value, is_target)
    if reason == "cidr":
        ui.cprint(f"  {YELLOW}{G_WARN} '{value}' looks like an invalid CIDR (bad "
                  f"prefix or octet), not a real target — using it as a literal "
                  f"value instead, which will fail to resolve{RESET}")
    elif reason == "file":
        ui.cprint(f"  {YELLOW}{G_WARN} '{value}' looks like a file path but wasn't "
                  f"found (wrong directory? typo?) — using it as a literal value "
                  f"instead{RESET}")
    return [part.strip() for part in value.split(",") if part.strip()]


def load_combos(path):
    """Load a combo list of ``user:pass`` (or ``domain\\user:pass``) →
    [(user, secret, is_hash)]. Each line's secret is checked against
    :func:`looks_like_hash` so a hash dropped into a combo file alongside
    plaintext passwords (e.g. ``ansible_dev$:8d5363f881f1bb3bff9b0d64b8b76d7a``)
    is sprayed with -H instead of being sent as a literal -p password."""
    p = Path(path)
    if not p.is_file():
        return []
    pairs = []
    for line in p.read_text().splitlines():
        line = line.strip()
        if not line:
            continue
        if line.startswith("#"):
            # '#' isn't actually disallowed as the first character of a
            # real AD username, so a line shaped like a genuine entry
            # (contains ':') being dropped as a comment deserves a warning
            # instead of silent, lossy data loss — unlike a line with no
            # ':' at all, which couldn't have been a user:secret pair anyway.
            if ":" in line:
                ui.cprint(f"  {YELLOW}{G_WARN} '{line}' in {path} starts with "
                          f"'#' and is being treated as a comment, not a "
                          f"user:secret entry — rename the account if that "
                          f"wasn't intended{RESET}")
            continue
        if ":" not in line:
            continue
        user, secret = line.split(":", 1)
        if user:
            pairs.append((user, secret, looks_like_hash(secret)))
    return pairs


def load_spray_file(path):
    """Load a mixed spray file and pool it into (users, secrets).

    Each non-blank, non-``#`` line is either::

        user:pass       → contributes a user AND a password
        user            → contributes a user only (bare username)

    All users and all discovered secrets are de-duplicated (order preserved);
    users are returned as a plain list, secrets as [(value, is_hash)] pairs
    (see :func:`looks_like_hash`) so a hash dropped into the pool is sprayed
    with -H in its own round instead of being tried as a literal -p password.
    The caller still sprays every user × every secret (classic password
    spraying), not the 1:1 pairing that :func:`load_combos` does.
    ``domain\\user:pass`` is fine — only the first ``:`` splits.
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
    uniq_users = list(dict.fromkeys(users))
    uniq_secrets = [(pw, looks_like_hash(pw)) for pw in dict.fromkeys(passwords)]
    return uniq_users, uniq_secrets


_RESUME_RE = re.compile(
    r"^\s*\d\d:\d\d:\d\d\s+\S+\s+(?P<label>\S+)\s+(?P<proto>\S+)\s+"
    r"(?P<target>\S+)\s+(?P<user>\S+)\s+(?P<secret>\S+)"
)


def log_unescape(s):
    """Reverse results.py's log_escape() — a logged user/secret field had
    any literal space turned into "%20" so the \\S+ groups above could
    capture it whole instead of truncating at that space."""
    return s.replace("%20", " ")


def load_prior_attempts(path):
    """Parse a previous clean log; return (seen_keys, locked_users).

    Seen keys are ``proto:target:user:H|P:secret`` — matching worker.py's
    key format exactly, including its H/P marker, so a literal secret tried
    as plaintext in one run doesn't collide with the identical text tried as
    a hash in another (or vice versa). A hash secret is masked in the log
    (``(hash:...)`` — see worker.py's secret_display), so its reconstructed
    key can never exactly match a future run's real-secret key anyway;
    resume is only reliable for password sprays, same as before this marker
    was added — it just no longer causes a *wrong* match for a plaintext one.

    ``--use-kcache`` is a special case: its secret is always the real empty
    string, displayed in the log as the masked placeholder ``(ticket)`` —
    unlike a hash, that masking isn't lossy (there's nothing to lose), so
    it's unmasked back to "" here to exactly match the live run's key.

    A "skip" or "error" line is excluded from the reconstructed seen set
    entirely: "skip" means a combo this build/mode could never actually
    attempt (hash/kerberos/proxychains mismatch, max-attempts cap, or
    already-resumed), and "error" means an operational failure (timeout,
    unreachable, tool missing) — neither ever put a real credential on the
    wire. worker.py's live ``state.seen`` marking excludes both for the
    exact same reason (it un-marks a key right back out of `state.seen`
    the moment an attempt it reserved turns out to be operational, not
    real — see its comment at the equivalent point). Without this, a
    --resume run would treat a credential that was never put on the wire as
    already covered and silently skip it forever."""
    seen, locked = set(), set()
    p = Path(path)
    if not p.is_file():
        return seen, locked
    for line in p.read_text(errors="replace").splitlines():
        m = _RESUME_RE.match(line)
        if not m:
            continue
        g = m.groupdict()
        user = log_unescape(g["user"])
        label = g["label"]
        if label.upper() == "LOCK":
            locked.add(user)
        if label.lower() in ("skip", "error"):
            continue
        secret = log_unescape(g["secret"])
        if secret == "(ticket)":
            secret = ""
        # match mask_secret()'s exact mask shape, not just a "(hash" prefix —
        # a real plaintext password that happens to literally start with
        # that text (e.g. "(hashbrown99)") would otherwise be misread as a
        # hash entry and never resume-match its own live "P:"-keyed run.
        marker = "H" if _HASH_MASK_RE.match(secret) else "P"
        seen.add(f"{g['proto']}:{g['target']}:{user}:{marker}:{secret}")
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
