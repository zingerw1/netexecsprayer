"""Command-line interface and run orchestration."""

import argparse
import ipaddress
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
from .parsing import mask_secret
from .protocols import (ALL_PROTOCOLS, BUNDLES, KERBEROS_PROTOCOLS, LOCAL_AUTH_PROTOCOLS,
                        NATIVE_PROTOCOLS, NXC_PROTOCOLS, PORTS, SERVICES, expand_bundles)
from .results import (build_json, log_header, log_summary, write_csv, write_loot, write_report)
from .runners import KCACHE_USER, kcache_principal, read_lockout_policy
from .theme import (BOLD, CYAN, GRAY, G_INFO, G_RND, G_SECT, G_SKIP, G_WARN,
                    RESET, YELLOW, gradient_text, rule)
from .worker import preflight_checks, spray_bulk, spray_one


def _looks_like_ip(target):
    """True for a bare IPv4/IPv6 address (not a hostname/FQDN) - used to warn
    that -k/--kerberos against such a target will usually fail (see the
    kerberos target check in main())."""
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


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
     "netexecspray smb dc01.corp.local -u admin -H :32ed87bdb5fdc5e9cba88547376818d4\n"
     "  netexecspray all hosts.txt -u users.txt -H hashes.txt"
     "   # 1 hash/line (NT-only or LM:NT) -> all users x all hashes"),
    (("-U", "--userfile"),
     "netexecspray ad 10.10.10.0/24 -U users.txt -p 'Winter2025!' --safe"),
    (("--resume",),
     "netexecspray ad targets.txt -u users.txt -p p.txt --resume spray_prev.log"),
    (("-k", "--kerberos", "-d", "--domain", "--kdc-host"),
     "netexecspray smb dc01.corp.local -u users.txt -p 'Winter2025!' "
     "-k -d corp.local --kdc-host 10.10.10.1"),
    (("--use-kcache",),
     "KRB5CCNAME=/tmp/krb5cc_1000 netexecspray ad dc01.corp.local --use-kcache"
     "   # pass-the-ticket, no -u/-p needed"),
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
  %(prog)s smb dc01.corp.local -u users.txt -p 'Winter2025!' -k -d corp.local
  KRB5CCNAME=/tmp/krb5cc_1000 %(prog)s ad dc01.corp.local --use-kcache   # pass-the-ticket
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
    cred.add_argument("-H", "--hash", metavar="HASH",
                       help="NTLM hash for pass-the-hash (NT-only, LM:NT, or :NT). "
                            "Also accepts a comma-list or a file of one hash per line. "
                            "With --combo or --spray-file, forces every secret from "
                            "that file to be sprayed as a hash instead of relying on "
                            "shape auto-detection")
    cred.add_argument("-c", "--combo", "--creds", metavar="FILE", dest="combo",
                      help="File of user:pass per line (1:1 stuffing) — use instead of -u/-p. "
                           "Each secret is auto-detected as a hash or plaintext, so NTLM "
                           "hashes and real passwords can be mixed in the same file")
    cred.add_argument("-S", "--spray-file", metavar="FILE", dest="spray_file",
                      help="Mixed file of 'user:pass' and bare 'user' lines → spray "
                           "ALL users × ALL found secrets (pooled, not paired). Each secret "
                           "is auto-detected as a hash or plaintext, so NTLM hashes and real "
                           "passwords can be mixed in the same file")

    krb = parser.add_argument_group("kerberos")
    krb.add_argument("-k", "--kerberos", action="store_true",
                     help="Authenticate via Kerberos instead of NTLM (nxc-backed protocols; "
                          "requires -d/--domain)")
    krb.add_argument("-d", "--domain", metavar="DOMAIN",
                     help="AD domain for Kerberos authentication (e.g. corp.local)")
    krb.add_argument("--kdc-host", metavar="HOST", dest="kdc_host",
                     help="FQDN/IP of the KDC (domain controller); defaults to nxc's own "
                          "resolution from the domain")
    krb.add_argument("--use-kcache", action="store_true", dest="use_kcache",
                     help="Pass-the-ticket: use the Kerberos ticket in $KRB5CCNAME instead of "
                          "a password/hash. Implies -k; standalone (no -u/-p/-H/--combo needed)")

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
    tim.add_argument("--bulk", action="store_true",
                     help="Hand each wave's userlist to nxc in ONE invocation per "
                          "protocol/target instead of one process per credential. "
                          "Much faster for big userlists, but trades away --jitter/"
                          "--rate/--validate/local-auth auto-retry for that protocol+"
                          "wave (nxc runs the whole list itself) — --max-attempts/"
                          "--safe and --resume are still honored per user even in "
                          "bulk mode. Works fine with -k/--kerberos. nxc-backed "
                          "protocols + plaintext passwords only — hash mode, --combo, "
                          "and --use-kcache still spray one at a time.")

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
    """Return (users, secrets, combos) from the parsed args.

    ``secrets`` is a list of ``(value, is_hash)`` pairs; ``combos`` is a list
    of ``(user, value, is_hash)`` triples. Carrying the hash flag per-secret
    (rather than one global flag for the whole run) is what lets -S and
    --combo files mix plaintext passwords and hashes freely — each secret is
    auto-detected via :func:`looks_like_hash` there, since those formats have
    no separate flag to say "this one's a hash". -u/-p/-H is unambiguous: -p
    always means a literal password (even one shaped like a hash) and -H
    always means a hash, with no auto-detection overriding either choice."""

    # pass-the-ticket: no credentials to spray — a single pseudo-attempt per target
    if args.use_kcache:
        if (args.combo or args.spray_file or args.user or args.userfile
                or args.password or args.hash):
            parser.error("--use-kcache is standalone; don't combine it with "
                         "-u/-U/-p/-H/--combo/--spray-file")
        return [kcache_principal() or KCACHE_USER], [("", False)], []

    # pooled spray file: one file supplies both users and secrets → users × secrets
    if args.spray_file:
        if args.combo or args.user or args.userfile or args.password:
            parser.error("--spray-file is standalone; don't combine it with "
                         "-u/-U/-p/--combo")
        users, secrets = load_spray_file(args.spray_file)
        if not users:
            parser.error(f"No users loaded from {args.spray_file}")
        if not secrets:
            parser.error(f"{args.spray_file} has no 'user:pass' line to supply a "
                         "secret — add one, or spray with -u FILE -p PASS/-H HASH")
        if args.hash:
            # same override --combo + -H supports: force every secret this
            # file supplied to be sprayed as a hash, overriding
            # load_spray_file()'s looks_like_hash() auto-detection. Needed
            # for a hash shape the strict NTLM-only regex doesn't recognise
            # (AES256 Kerberos keys, DCC2, etc.), which would otherwise be
            # silently sprayed as -p plaintext with no way to correct it —
            # unlike --combo, -S had no such escape hatch.
            secrets = [(s, True) for s, _ in secrets]
        return users, secrets, []

    if args.combo:
        if args.user or args.userfile or args.password:
            parser.error("--combo is standalone; don't combine it with "
                         "-u/-U/-p (each combo line already carries its own "
                         "user:secret)")
        combos = load_combos(args.combo)
        if not combos:
            parser.error(f"No user:pass pairs loaded from {args.combo}")
        if args.hash:
            # -H here isn't a secret of its own — it forces every combo
            # secret to be sprayed as a hash, overriding load_combos()'s
            # regex auto-detection. Needed for a hash shape the strict
            # NTLM-only regex doesn't recognise (AES256 Kerberos keys, DCC2,
            # etc.), which would otherwise be silently sprayed as -p plaintext.
            combos = [(u, s, True) for u, s, _ in combos]
        users = list(dict.fromkeys(u for u, _, _ in combos))
        return users, [], combos

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

    if args.hash:
        secrets = [(h, True) for h in load_list(args.hash)]
        if not secrets:
            parser.error(f"No hashes loaded from {args.hash}")
    else:
        # -p is explicit and unambiguous (unlike -S/--combo, which have no
        # separate flag to say "this one's a hash") — a password that happens
        # to be shaped like a 32-hex NTLM hash is still a literal password
        # here, not an auto-detected hash to silently reroute through -H.
        secrets = [(s, False) for s in load_list(args.password)]
        if not secrets:
            parser.error("No passwords loaded")
    return users, secrets, []


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

    if args.use_kcache:
        args.kerberos = True   # --use-kcache implies -k
    elif args.kerberos and not args.domain:
        parser.error("--kerberos requires -d/--domain (or use --use-kcache for pass-the-ticket)")

    users, secrets, combos = _resolve_credentials(args, parser)

    requested = [p.strip().lower() for p in args.protocols.split(",") if p.strip()]
    protocols, unknown = expand_bundles(requested)
    if unknown:
        parser.error(f"Unknown protocol(s): {', '.join(unknown)}\n"
                     f"  nxc-backed : {', '.join(NXC_PROTOCOLS)}\n"
                     f"  native     : {', '.join(NATIVE_PROTOCOLS)}\n"
                     f"  bundles    : {', '.join(BUNDLES)}")

    if args.local_auth:
        no_local_auth = [p for p in protocols if p not in LOCAL_AUTH_PROTOCOLS]
        if no_local_auth:
            ui.cprint(f"  {YELLOW}{G_WARN} --local-auth has no effect for "
                      f"{', '.join(no_local_auth)} (nxc only supports it for "
                      f"{', '.join(sorted(LOCAL_AUTH_PROTOCOLS))}) — silently "
                      f"dropped for those protocols{RESET}")

    if args.kerberos:
        no_kerberos = [p for p in protocols if p not in KERBEROS_PROTOCOLS]
        if no_kerberos:
            ui.cprint(f"  {YELLOW}{G_WARN} -k/--kerberos has no effect for "
                      f"{', '.join(no_kerberos)} (nxc only supports Kerberos auth "
                      f"for {', '.join(KERBEROS_PROTOCOLS)}) — silently skipped "
                      f"for those protocols{RESET}")

    native_in_play = [p for p in protocols if p in NATIVE_PROTOCOLS]
    has_hash = any(h for _, h in secrets) or any(h for _, _, h in combos)
    # only -S/--combo (without an explicit -H override) auto-detect hash-ness
    # via looks_like_hash()'s shape guess — -H alone, or --combo + -H, is
    # always an explicit, intentional choice. The native-protocol skip below
    # applies either way (a hash is a hash to spray_one() regardless of how
    # it got marked is_hash=True) — only the *misclassification* warning
    # (wording below) is specific to the ambiguous, auto-detected case.
    auto_detected = ((args.spray_file or args.combo) and not args.hash) and has_hash
    all_native = native_in_play and len(native_in_play) == len(protocols)
    if has_hash and native_in_play:
        if auto_detected and not all_native:
            # skipped outright for native protocols (smtp/imap/pop3/mysql
            # don't support pass-the-hash) — otherwise only visible via
            # --verbose or grepping the log. Only said this way when there's
            # a real "elsewhere": if every selected protocol is native,
            # there's nowhere for it to go via -H either, so that part of
            # the message would itself be misleading (see the all_native
            # branch below for that case).
            ui.cprint(f"  {YELLOW}{G_WARN} a secret that looks like a hash (32-hex) "
                      f"will be skipped for {', '.join(native_in_play)} (native "
                      f"protocols don't support pass-the-hash) and sent via -H "
                      f"pass-the-hash elsewhere — if it's actually a literal "
                      f"password that happens to look like a hash, spray it "
                      f"separately with -p{RESET}")
        elif auto_detected and all_native:
            ui.cprint(f"  {YELLOW}{G_WARN} a secret that looks like a hash (32-hex) "
                      f"will be skipped entirely — every selected protocol "
                      f"({', '.join(native_in_play)}) is native and doesn't support "
                      f"pass-the-hash, so there's nowhere for it to be tried at all. "
                      f"If it's actually a literal password that happens to look "
                      f"like a hash, spray it separately with -p{RESET}")
        else:
            ui.cprint(f"  {YELLOW}{G_WARN} hash secrets will be skipped for "
                      f"{', '.join(native_in_play)} (native protocols don't "
                      f"support pass-the-hash){RESET}")
    elif auto_detected:
        # not skipped (no native protocols here), but still never tried as a
        # literal password against anything — the same misclassification
        # risk, just a different consequence (wrong auth mode, not no attempt).
        ui.cprint(f"  {YELLOW}{G_WARN} a secret that looks like a hash (32-hex) "
                  f"will be sprayed via -H pass-the-hash, not as a literal "
                  f"password — if it's actually a real password that happens "
                  f"to look like a hash, spray it separately with -p{RESET}")

    raw_targets = load_list(args.target, is_target=True)
    if not raw_targets:
        parser.error("No targets loaded")
    targets = expand_targets(raw_targets, resolve=args.resolve,
                             expand_cidr=not args.no_expand_cidr, force=args.force)

    if args.kerberos and not args.use_kcache:
        # Kerberos asks the KDC for a service ticket keyed on the target's
        # SPN (e.g. cifs/dc01.corp.local) - nxc builds that from whatever
        # string is given as the target, so a bare IP (typed directly, or
        # produced by --resolve/CIDR expansion) means nxc requests a ticket
        # for "cifs/10.10.10.1", which the KDC doesn't have and can't issue.
        # The usual fix is an /etc/hosts entry mapping the DC's IP to its
        # real hostname, then targeting that hostname instead of the IP.
        ip_targets = [t for t in targets if _looks_like_ip(t)]
        if ip_targets:
            sample = ", ".join(ip_targets[:3]) + (f" +{len(ip_targets) - 3} more"
                                                   if len(ip_targets) > 3 else "")
            ui.cprint(f"  {YELLOW}{G_WARN} -k/--kerberos against a bare IP target "
                      f"({sample}) will usually fail — Kerberos needs the KDC to "
                      f"issue a ticket for a hostname SPN, not an IP. Add the DC's "
                      f"hostname to /etc/hosts and target that hostname instead "
                      f"(don't combine with --resolve, which converts it back to "
                      f"an IP){RESET}")

    # No files are written unless asked for: --output enables the log file,
    # --out-dir / --report / --json each enable their own artifact.
    logfile = args.output

    # job total: combo mode drives its own pairs; otherwise users × passwords
    n_pairs = len(combos) if args.combo else len(users) * len(secrets)
    total   = len(protocols) * len(targets) * n_pairs
    with state.counter_lock:
        state.counter["total"] = total

    if args.use_kcache:
        secret_kind = "kerberos ticket (kcache)"
    elif args.combo:
        n_hash = sum(1 for _, _, h in combos if h)
        secret_kind = f"{len(combos)} combos" + (f" ({n_hash} hash)" if n_hash else "")
    else:
        n_hash  = sum(1 for _, h in secrets if h)
        n_plain = len(secrets) - n_hash
        parts = []
        if n_plain:
            parts.append(f"{n_plain} password" + ("" if n_plain == 1 else "s"))
        if n_hash:
            parts.append(f"{n_hash} hash" + ("" if n_hash == 1 else "es"))
        secret_kind = " + ".join(parts) if parts else "password"
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
        pu = users[0]
        if args.combo:
            _, ps, ph = combos[0]
        else:
            ps, ph = secrets[0]
        pol = read_lockout_policy(targets[0], pu, ps, ph, args.timeout,
                                  args.kerberos, args.domain, args.kdc_host, args.use_kcache)
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

    _run_spray(args, protocols, targets, users, secrets, combos, logfile)

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
    if args.bulk:         flags.append("bulk")
    if args.validate:     flags.append("validate")
    if args.max_attempts: flags.append(f"max{args.max_attempts}")
    if args.rate:         flags.append(f"{args.rate:g}/s")
    if args.proxychains:  flags.append("proxy")
    if args.kerberos:
        flags.append("kerberos(kcache)" if args.use_kcache else f"kerberos@{args.domain}")
    if flags:
        stats += dot + GRAY + " ".join(flags) + RESET

    ui.set_title("netexecspray · starting")
    ui.banner(__version__)
    ui.cprint("")
    ui.cprint(f"  {stats}")
    ui.cprint(f"  {GRAY}{tgt_str}  ·  {proto_desc}{RESET}")
    ui.cprint("")


# ── Spray loop ────────────────────────────────────────────────────────────────
def _submit(pool, protos, pairs, targets, args, logfile):
    """Queue every proto × (user,secret,is_hash) × target job onto the pool at
    once, so up to --threads attempts run concurrently. ``pairs`` carries the
    hash flag per-secret, so a pooled/combo file mixing hashes and plaintext
    passwords sends each to nxc as -H or -p correctly. Returns
    {future: (user, target)}.

    --bulk collapses a whole wave's users into one spray_bulk() job per
    protocol/target instead of one spray_one() job per credential — plain
    passwords only, and not for --combo (its 1:1 user:secret pairing doesn't
    fit nxc's userfile × passfile cross product) or --use-kcache (a ticket is
    one identity, not a userlist to spray). Kerberos (-k/--domain) is fine —
    nxc's own -u/-p bulk flags work the same under -k, just scoped per proto
    to KERBEROS_PROTOCOLS like the per-credential path already is. Everything
    this excludes still goes through the per-credential path below unchanged."""
    futures = {}
    kerberos = getattr(args, "kerberos", False)
    bulk_ok = (getattr(args, "bulk", False) and not args.combo
              and not getattr(args, "use_kcache", False)
              and pairs and not any(h for _, _, h in pairs))
    all_users = [u for u, _, _ in pairs]   # pairs is the same across every proto in this call

    for proto in protos:
        if (bulk_ok and proto not in NATIVE_PROTOCOLS
                and (not kerberos or proto in KERBEROS_PROTOCOLS)):
            # locked_users is read live (not hoisted) — an earlier proto in
            # this same loop can lock an account mid-run.
            with state.locked_lock:
                locked_now = [u for u in all_users if u in state.locked_users]
            users_here = [u for u in all_users if u not in locked_now]
            if locked_now:
                with state.counter_lock:
                    state.counter["total"] -= len(locked_now) * len(targets)
            if users_here:
                secret = pairs[0][1]
                for target in targets:
                    if state.abort.is_set():
                        return futures
                    # `total` stays at its per-user granularity here (one
                    # bulk job still represents len(users_here) users, and
                    # spray_bulk()'s `finally` adds that same count to `done`
                    # — collapsing `total` to 1 unit per job here would make
                    # `done` overtake `total` once the job completes).
                    fut = pool.submit(spray_bulk, proto, target, users_here, secret, logfile, args)
                    # name real accounts in this diagnostic label, not just a
                    # count — _drain() prints this verbatim on an unexpected
                    # exception, and "5-user bulk" tells an operator nothing
                    # about which 5 accounts were actually affected.
                    sample = ", ".join(users_here[:3])
                    if len(users_here) > 3:
                        sample += f", +{len(users_here) - 3} more"
                    futures[fut] = (f"bulk[{sample}]", target)
                    if args.delay > 0:
                        time.sleep(args.delay)
            continue

        for user, secret, is_hash in pairs:
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


def _run_spray(args, protocols, targets, users, secrets, combos, logfile):
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

    # one wave per secret round, or a single wave for combo mode. Each pair
    # carries its own is_hash flag now, so a round's secret (or a combo's
    # per-user secret) can be a hash or a plaintext password independently.
    if args.combo:
        waves = [("combo", None, None, combos)]
    else:
        waves = [(f"round {i + 1}/{len(secrets)}", s, h, [(u, s, h) for u in users])
                 for i, (s, h) in enumerate(secrets)]

    preflight_checks(protocols, targets, args, logfile)
    paced = args.lockout_delay > 0   # opt-in: one protocol section at a time

    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        for wi, (wlabel, wsecret, wis_hash, pairs) in enumerate(waves):
            if state.abort.is_set():
                break
            if len(waves) > 1 or args.combo:
                if wsecret:
                    tail = f"  {mask_secret(wsecret, wis_hash)}"
                else:
                    tail = f"  {len(pairs)} pairs"
                ui.cprint(f"\n{gradient_text(f'{G_RND} {wlabel}')}{GRAY}{tail}{RESET}")

            if paced:
                # pace between protocol sections (keeps attempts/account spread out)
                for proto in protocols:
                    if state.abort.is_set():
                        break
                    state.phase = f"{wlabel} · {proto}" if len(waves) > 1 else proto
                    _drain(_submit(pool, [proto], pairs, targets, args, logfile))
                    if proto != protocols[-1] and not state.abort.is_set():
                        ui.cprint(f"  {GRAY}… lockout delay {args.lockout_delay}s{RESET}")
                        time.sleep(args.lockout_delay)
            else:
                # fast path: submit the whole wave at once so all threads stay busy
                state.phase = wlabel if len(waves) > 1 else ""
                _drain(_submit(pool, protocols, pairs, targets, args, logfile))

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
