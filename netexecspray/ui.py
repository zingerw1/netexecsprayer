"""Terminal presentation: the live status bar, hit banners, summary table, and
modern niceties (window title, clickable paths, bell).

This is the *only* module that writes to stdout. ``--no-color`` is enforced here
by routing every write through :func:`theme.paint`, which strips colour when it
is disabled — so the rest of the package can build colourful strings freely.
"""

import math
import os
import sys
import time

from . import state
from . import theme
from .theme import (BOLD, CYAN, GRAY, GREEN, RED, RESET, WHITE, YELLOW,
                    G_ERR, G_HIT, G_INFO, G_LOCK, G_OK, G_SKIP, SPIN, TRACK,
                    GRAD_A, GRAD_B, gradient_text, mix, paint, rgb, rule, truecolor)
from .parsing import short_detail


# ── Geometry ─────────────────────────────────────────────────────────────────
def vlen(s):
    """Visible length, ignoring ANSI escape codes."""
    return len(theme.ANSI.sub("", s))


def pad(s, target):
    """Right-pad `s` to `target` visible columns (ANSI-aware)."""
    return s + " " * max(target - vlen(s), 0)


_SPARK = "▁▂▃▄▅▆▇"


def spark(values, width=12):
    """Tiny red→white sparkline of recent values (empty when nothing yet)."""
    if not values:
        return ""
    vals = values[-width:]
    lo, hi = min(vals), max(vals)
    span = (hi - lo) or 1
    out = []
    for v in vals:
        f = (v - lo) / span
        g = _SPARK[min(len(_SPARK) - 1, int(f * (len(_SPARK) - 1) + 0.5))]
        out.append((rgb(*mix(GRAD_A, GRAD_B, f)) + g) if truecolor() else g)
    return "".join(out) + (RESET if truecolor() else "")


def term_width():
    try:
        return os.get_terminal_size().columns
    except OSError:
        return 80


# ── Status bar ────────────────────────────────────────────────────────────────
def render_bar(done, total, width=14):
    """A slim one-row gradient bar — no shimmer, just a clean red→white fill."""
    frac = min(done / total, 1.0) if total else 0.0
    full = int(frac * width)

    if not truecolor():
        return f"{CYAN}{'━' * full}{GRAY}{'─' * (width - full)}{RESET}"

    cells = []
    for i in range(width):
        if i < full or frac >= 1.0:
            cells.append(rgb(*mix(GRAD_A, GRAD_B, i / max(width - 1, 1))) + "━")
        else:
            cells.append(TRACK + "─")
    return "".join(cells) + RESET


def tally():
    """Minimal live counter: › N valid  ✦ N admin (only what matters)."""
    with state.results_lock:
        a = len(state.results["access"])
        v = len(state.results["valid"])
    nval = a + v
    if not nval:
        return ""
    s = f"{CYAN}{G_HIT} {nval} valid{RESET}"
    if a:
        s += f"  {WHITE}{G_OK} {a} admin{RESET}"
    return s


def bar_str():
    """Build the live status line (coloured, no newline, no lock assumed)."""
    with state.counter_lock:
        done, total = state.counter["done"], state.counter["total"]

    pct     = int(done / total * 100) if total else 0
    elapsed = time.time() - state.start_time if state.start_time else 0
    speed   = done / elapsed if elapsed > 1 else 0
    eta_s   = int((total - done) / speed) if speed > 0.5 else 0

    with state.active_lock:
        active = list(state.active.values())

    # breathing spinner → red that flares toward white at each pulse peak
    if done >= total:
        spin = f"{GREEN}{G_OK}{RESET}"
    elif truecolor():
        bright = 120 + ((math.sin(time.time() * 5) + 1) / 2) * 135
        spin   = rgb(255, bright * 0.35, bright * 0.38) + SPIN[int(time.time() * 12) % len(SPIN)] + RESET
    else:
        spin = f"{CYAN}{SPIN[int(time.time() * 12) % len(SPIN)]}{RESET}"

    bar   = render_bar(done, total, width=20)
    clock = f"{int(elapsed // 60)}:{int(elapsed % 60):02d}"
    head  = f"{spin} {bar} {BOLD}{pct:>3}%{RESET}"

    t = tally()
    if t:
        head += f"   {t}"

    # right side: rate sparkline · rate · clock/eta  (dropped when space is tight)
    sl = spark(state.rate_hist)
    rate_s = f"{speed:.0f}/s" if speed >= 0.1 else ""
    eta_s_str = f" · {eta_s}s" if eta_s > 0 else ""
    bits = [b for b in [sl, rate_s, clock + eta_s_str] if b]
    tail_plain = "  ".join(bits)

    avail = term_width() - vlen(head) - 4
    if avail > 3 and vlen(tail_plain) > avail:
        tail_plain = spark(state.rate_hist) + f"  {clock}"
    tail = f"   {GRAY}{tail_plain}{RESET}" if avail > 3 else ""
    return head + tail


def redraw_unsafe():
    """Write the status bar to stdout. Caller must already hold print_lock."""
    if state.is_tty and state.start_time and state.counter["total"] > 0 and not state.stop_ticker.is_set():
        sys.stdout.write("\r\033[K" + paint(bar_str()))
        sys.stdout.flush()


def redraw():
    with state.print_lock:
        redraw_unsafe()


def ticker():
    """Keep the spinner / clock / rate sparkline alive while attempts run."""
    last_title = 0.0
    last_sample = state.start_time or time.time()
    last_done = 0
    while not state.stop_ticker.wait(0.07):
        redraw()
        now = time.time()
        if now - last_sample >= 0.5:    # sample attempts/sec for the sparkline
            with state.counter_lock:
                done = state.counter["done"]
            state.rate_hist.append((done - last_done) / (now - last_sample))
            del state.rate_hist[:-12]
            last_done, last_sample = done, now
        if now - last_title > 0.5:      # throttle title writes to avoid flicker
            set_title(title_text())
            last_title = now


# ── Modern terminal niceties ──────────────────────────────────────────────────
def set_title(text):
    """Set the terminal window / tab title (OSC 2). Ignored where unsupported."""
    if state.is_tty:
        try:
            with state.print_lock:
                sys.stdout.write(f"\033]2;{text}\007")
                sys.stdout.flush()
        except Exception:
            pass


def title_text():
    with state.counter_lock:
        done, total = state.counter["done"], state.counter["total"]
    pct = int(done / total * 100) if total else 0
    with state.results_lock:
        hits = len(state.results["access"]) + len(state.results["valid"])
    tag = f" · {hits} hit{'' if hits == 1 else 's'}" if hits else ""
    return f"netexecspray · {pct}% ({done}/{total}){tag}"


def hyperlink(label, url):
    """OSC 8 clickable hyperlink; falls back to the bare label when unsupported."""
    if not state.is_tty or not theme.USE_COLOR:
        return label
    return f"\033]8;;{url}\033\\{label}\033]8;;\033\\"


def file_link(path):
    """Clickable file:// link whose visible text is the path itself."""
    from pathlib import Path
    try:
        return hyperlink(str(path), Path(path).resolve().as_uri())
    except Exception:
        return str(path)


def bell():
    if state.bell_enabled and state.is_tty:
        try:
            sys.stdout.write("\a")
            sys.stdout.flush()
        except Exception:
            pass


# ── Printing ─────────────────────────────────────────────────────────────────
def cprint(msg, color="", bold=False):
    prefix = (BOLD if bold else "") + color
    with state.print_lock:
        if state.is_tty and state.start_time:
            sys.stdout.write("\r\033[K")   # erase status line
        print(paint(f"{prefix}{msg}{RESET}"), flush=True)
        redraw_unsafe()


_BANNER_W = 54


def _grad_word(text, shimmer=None):
    """Red→white gradient across `text`; a bright band glows at column `shimmer`."""
    if not truecolor():
        return BOLD + text + RESET
    n = max(len(text) - 1, 1)
    out = []
    for i, ch in enumerate(text):
        base = mix(GRAD_A, GRAD_B, i / n)
        if shimmer is not None:
            glow = math.exp(-(((i - shimmer) / 2.2) ** 2))
            base = mix(base, (255, 255, 255), glow * 0.9)
        out.append(rgb(*base) + ch)
    return BOLD + "".join(out) + RESET


def _banner_lines(version="", shimmer=None):
    """The thin framed banner as a list of 3 lines."""
    b = rgb(120, 30, 36) if truecolor() else GRAY
    word = _grad_word("netexecspray", shimmer)
    # top line = "╭─ "(3) word(12) " "(1) dashes(k) "─╮"(2)
    k = max(_BANNER_W - 18, 2)
    top = f"{b}╭─{RESET} {word} {b}{'─' * k}─╮{RESET}"
    sub = f"{GRAY}multi-protocol credential spray{RESET}"
    mid = f"{b}│{RESET} {pad(sub, _BANNER_W - 4)} {b}│{RESET}"
    bot = f"{b}╰{'─' * (_BANNER_W - 2)}╯{RESET}"
    return [top, mid, bot]


def logo(version=""):
    """Compact one-liner for narrow terminals / pipes / --no-color-less width."""
    if not state.is_tty or term_width() < _BANNER_W:
        return f"  {gradient_text('netexecspray')}"
    return "\n".join(_banner_lines(version))


def banner(version=""):
    """Print the startup banner — a one-shot shimmer reveal on a TTY, else static."""
    if not state.is_tty or term_width() < _BANNER_W or not truecolor():
        cprint(logo(version))
        return
    frames = 26
    with state.print_lock:
        lines = _banner_lines(version, shimmer=-4.0)
        sys.stdout.write("\n".join(lines) + "\n")
        for i in range(1, frames):
            time.sleep(0.016)
            p = -4.0 + 20.0 * (i / (frames - 1))
            sys.stdout.write("\033[3A")
            for ln in _banner_lines(version, shimmer=p):
                sys.stdout.write("\r\033[K" + paint(ln) + "\n")
            sys.stdout.flush()
        sys.stdout.write("\033[3A")
        for ln in _banner_lines(version):
            sys.stdout.write("\r\033[K" + paint(ln) + "\n")
        sys.stdout.flush()


def cprint_hit(rec, access):
    """Print a valid credential as one thin, aligned line (icon · creds · where)."""
    if access:
        bell()
    glyph = G_OK if access else G_HIT
    col   = WHITE if access else CYAN
    cred  = f"{BOLD}{col}{rec['user']}:{rec['secret']}{RESET}"
    detail = short_detail(rec.get("detail", ""))
    note   = detail or ("admin" if access else "")
    tail   = f"   {GRAY}{note}{RESET}" if note else ""
    cprint(f"  {col}{glyph}{RESET} {pad(cred, 28)}  "
           f"{GRAY}{rec['proto']:<5} {rec['target']}{RESET}{tail}")


def print_results_table(aborted, done_n, elapsed, rate, dot):
    """No summary when creds were found — they already printed live. Only a quiet
    line when nothing was found, so an empty run doesn't look broken."""
    with state.results_lock:
        hits = len(state.results["access"]) + len(state.results["valid"])
        lk   = len(state.results["locked"])
    if hits or lk:
        return
    cprint("")
    msg = "no valid credentials found" + (" (aborted)" if aborted else "")
    cprint(f"  {GRAY}{msg}{RESET}")
