"""The record pipeline and every file sink.

:func:`record_result` is the single place an attempt becomes a stored record. It
appends to :data:`state.attempts`, files it under the right summary bucket, and
writes the clean log line — so the log, the terminal summary, the loot files,
the CSV, the report and the JSON all derive from one source of truth.
"""

import csv
import re
from datetime import datetime
from pathlib import Path

from . import state
from .parsing import banner
from .theme import ANSI

LOG_W = 98  # width of rules / framed header

# status → (glyph, fixed-width label) ; hits are UPPERCASE so they jump out
_LOG_TAG = {
    "pwned":       ("✓", "PWNED"),
    "valid":       ("◆", "VALID"),
    "locked":      ("⊘", "LOCK"),
    "must_change": ("!", "CHANGE"),
    "fail":        ("·", "fail"),
    "error":       ("✗", "error"),
    "skip":        ("○", "skip"),
}

# status → summary bucket (fail / skip live in state.attempts only)
_BUCKET = {"pwned": "access", "valid": "valid", "must_change": "valid",
           "locked": "locked", "error": "errors"}


# ── Log file writers ──────────────────────────────────────────────────────────
def log_write(logfile, text):
    """Append pre-formatted, colour-free text to the log (keeps indentation).
    A falsy `logfile` means logging is off → no file is created."""
    if not logfile:
        return
    with state.log_lock:
        with open(logfile, "a") as f:
            f.write(ANSI.sub("", text).rstrip() + "\n")


def log_escape(s):
    """Escape a space as "%20" in a fixed-width log column. _RESUME_RE (and
    any plain split-on-whitespace reader) captures a field as \\S+ — a
    literal space inside `user` or `secret_display` would otherwise truncate
    that field right there, corrupting resume's reconstructed dedup key (and
    silently defeating --resume for that credential). loaders.py's
    log_unescape() reverses this before using either field."""
    return s.replace(" ", "%20")


def log_attempt(logfile, status, proto, target, user, secret_display, detail="", ts=None):
    """Write one aligned, timestamped line describing a single attempt."""
    if not logfile:
        return
    glyph, label = _LOG_TAG.get(status, ("·", status))
    ts  = ts or datetime.now().strftime("%H:%M:%S")
    tag = f"{glyph} {label}"
    detail = ANSI.sub("", detail).replace("\n", " ").strip()
    if len(detail) > 60:
        detail = detail[:59] + "…"
    log_write(logfile, f"  {ts}  {tag:<9} {proto:<6} {target:<16} "
                       f"{log_escape(user):<18} {log_escape(secret_display):<22} {detail}")


def log_header(logfile, started, protocols, targets, users, secret_kind, total, cmd):
    if not logfile:
        return
    inner = LOG_W - 2
    tgt = ", ".join(targets[:3]) + (f"  +{len(targets) - 3} more" if len(targets) > 3 else "")
    lines = [
        "╭" + "─" * inner + "╮",
        "│" + "  netexecspray — multi-protocol password spray".ljust(inner) + "│",
        "╰" + "─" * inner + "╯",
        "",
        f"  started    {started}",
        f"  command    {cmd}",
        f"  protocols  {', '.join(protocols)}",
        f"  targets    {tgt}",
        f"  users      {len(users)}",
        f"  secret     {secret_kind}",
        f"  jobs       {total}",
        "",
        (f"  {'time':<8}  {'status':<9} {'proto':<6} {'target':<16} "
         f"{'user':<18} {'secret':<22} detail"),
        "  " + "─" * inner,
    ]
    log_write(logfile, "\n".join(lines))


def log_summary(logfile, results, attempts, done_n, elapsed, rate, finished, aborted=False):
    if not logfile:
        return
    sections = [("✓", "access", results["access"]), ("◆", "valid",  results["valid"]),
                ("⊘", "locked", results["locked"]), ("✗", "errors", results["errors"])]
    lines = ["", "  " + "─" * (LOG_W - 2), "",
             "  RESULTS" + ("  (aborted — partial)" if aborted else ""), ""]
    for _, name, items in sections:
        lines.append(f"  {name:<8} {len(items)}")
        for r in items:
            if name == "locked":
                lines.append(f"      {r['target']:<16} {r['user']}")
            elif name == "errors":
                lines.append(f"      {r['proto']:<6} {r['target']:<16} {r['user']}  ({r['detail']})")
            else:
                lines.append(f"      {fmt_rec(r)}")
    if not results["access"] and not results["valid"]:
        lines += ["", "  no valid credentials found"]

    roll = proto_rollup(attempts)
    if roll:
        lines += ["", "  per protocol", ""]
        for proto in sorted(roll):
            d = roll[proto]
            lines.append(f"      {proto:<6} hit {d['hit']:<4} fail {d['fail']:<5} err {d['err']}")

    lines += ["", f"  finished   {finished}  ·  {elapsed:.1f}s  ·  {rate:.1f}/s", ""]
    log_write(logfile, "\n".join(lines))


# ── Record pipeline ───────────────────────────────────────────────────────────
def record_result(logfile, status, proto, target, user, secret_display,
                  detail="", output="", secret_real=None):
    """Store a structured record, bucket it, and write the clean log line.

    `secret_display` is what's shown/logged on the terminal and in the plain
    log file (masked, e.g. "(hash:31d6cfe0…)"). `secret_real` — when given,
    for confirmed hits — is the actual plaintext/hash, used by the loot/CSV/
    JSON/report exporters so a successful credential is actually reusable.
    """
    rec = {
        "ts":     datetime.now().strftime("%H:%M:%S"),
        "status": status,
        "proto":  proto,
        "target": target,
        "user":   user,
        "secret": secret_display,
        "secret_full": secret_real if secret_real is not None else secret_display,
        "detail": ANSI.sub("", detail).replace("\n", " ").strip(),
        "host":   banner(output),
    }
    with state.results_lock:
        state.attempts.append(rec)
        bucket = _BUCKET.get(status)
        if bucket:
            state.results[bucket].append(rec)
    log_attempt(logfile, status, proto, target, user, secret_display, detail, ts=rec["ts"])
    return rec


def fmt_rec(rec, with_proto=True):
    """Human one-liner for a result record (no colour)."""
    head = f"{rec['proto']:<6} {rec['target']:<16} " if with_proto else ""
    line = f"{head}{rec['user']}:{rec['secret']}"
    if rec.get("detail"):
        line += f"  → {rec['detail']}"
    return line.rstrip()


def proto_rollup(attempts):
    """Per-protocol counts: proto → {hit, fail, err}."""
    roll = {}
    for r in attempts:
        d = roll.setdefault(r["proto"], {"hit": 0, "fail": 0, "err": 0})
        if r["status"] in ("pwned", "valid", "must_change"):
            d["hit"] += 1
        elif r["status"] == "error":
            d["err"] += 1
        elif r["status"] == "fail":
            d["fail"] += 1
    return roll


# ── Exporters ────────────────────────────────────────────────────────────────
def write_loot(valid_path, pwned_path, results):
    """valid.txt = user:secret (deduped); pwned.txt = proto target user:secret."""
    seen, valid_lines = set(), []
    for r in results["access"] + results["valid"]:
        pair = f"{r['user']}:{r.get('secret_full', r['secret'])}"
        if pair not in seen:
            seen.add(pair)
            valid_lines.append(pair)
    Path(valid_path).write_text("\n".join(valid_lines) + ("\n" if valid_lines else ""))

    pwned_lines = [f"{r['proto']} {r['target']} {r['user']}:{r.get('secret_full', r['secret'])}"
                   for r in results["access"]]
    Path(pwned_path).write_text("\n".join(pwned_lines) + ("\n" if pwned_lines else ""))


def write_csv(csv_path, attempts):
    with open(csv_path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["time", "status", "proto", "target", "user", "secret", "host", "detail"])
        for r in attempts:
            w.writerow([r["ts"], r["status"], r["proto"], r["target"],
                        r["user"], r.get("secret_full", r["secret"]), r.get("host", ""), r["detail"]])


def write_report(path, meta, results, attempts, elapsed, aborted=False):
    """A tidy Markdown engagement report."""
    def esc(cell):
        # a sprayed secret/detail can contain '|' or a newline — either
        # would otherwise split into extra columns or break the row
        # entirely when the .md report is rendered as a table.
        return str(cell).replace("|", "\\|").replace("\n", " ")

    def table(headers, rows):
        out = ["| " + " | ".join(headers) + " |",
               "| " + " | ".join("---" for _ in headers) + " |"]
        for row in rows:
            out.append("| " + " | ".join(esc(c) for c in row) + " |")
        return "\n".join(out)

    acc, val = results["access"], results["valid"]
    lk, er   = results["locked"], results["errors"]
    md = [
        "# netexecspray — spray report",
        "",
        f"- **Started:** {meta['started']}",
        f"- **Finished:** {meta['finished']}" + ("  _(aborted — partial results)_" if aborted else ""),
        f"- **Duration:** {elapsed:.1f}s",
        f"- **Command:** `{meta['cmd']}`",
        f"- **Protocols:** {', '.join(meta['protocols'])}",
        f"- **Targets:** {len(meta['targets'])}  ·  **Users:** {meta['users']}  ·  **Secret:** {meta['secret_kind']}",
        "",
        "## Summary",
        "",
        table(["Access", "Valid", "Locked", "Errors", "Attempts"],
              [[len(acc), len(val), len(lk), len(er), len(attempts)]]),
        "",
    ]
    if acc or val:
        md += ["## Findings", "",
               table(["Status", "Proto", "Target", "User", "Secret", "Detail"],
                     [[("ACCESS" if r in acc else "valid"), r["proto"], r["target"],
                       r["user"], r.get("secret_full", r["secret"]), r["detail"]] for r in acc + val]), ""]
    else:
        md += ["## Findings", "", "_No valid credentials found._", ""]

    roll = proto_rollup(attempts)
    if roll:
        md += ["## Per protocol", "",
               table(["Proto", "Hit", "Fail", "Error"],
                     [[p, roll[p]["hit"], roll[p]["fail"], roll[p]["err"]] for p in sorted(roll)]), ""]
    if lk:
        md += ["## Locked accounts", "",
               table(["Target", "User"], [[r["target"], r["user"]] for r in lk]), ""]

    Path(path).write_text("\n".join(md))


def build_json(meta, results, attempts, aborted=False):
    return {
        "started":      meta["started"],
        "finished":     meta["finished"],
        "command":      meta["cmd"],
        "protocols":    meta["protocols"],
        "targets":      meta["targets"],
        "users":        meta["users"],
        "secret_type":  meta["secret_kind"],
        "aborted":      aborted,
        "summary":      {k: len(v) for k, v in results.items()},
        "per_protocol": proto_rollup(attempts),
        "results":      {k: v for k, v in results.items()},
        "attempts":     attempts,
    }
