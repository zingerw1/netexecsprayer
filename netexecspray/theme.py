"""The "redline" theme: palette, glyphs, and colour/gradient primitives.

Colours are *always* real escape codes here; ``--no-color`` is handled at the
output chokepoint in :mod:`ui` via :func:`paint`, which simply strips ANSI SGR
codes when :data:`USE_COLOR` is off. Keeping the constants immutable means every
module can use the bare names in f-strings without the import-rebinding trap.
"""

import re

from . import state

# ── Palette ─────────────────────────────────────────────────────────────────
# Semantic names resolve to a tight red / white / gray scheme: success reads as
# bright white, accents / info read as red, locked / danger stays pure red.
WHITE   = "\033[38;2;255;255;255m"   # pure white (97m reads grey on some terms)
GREEN   = "\033[38;2;255;255;255m"   # "success" → bright white
YELLOW  = "\033[38;2;255;150;120m"   # warn → warm coral (stays in the red family)
RED     = "\033[38;2;255;58;68m"     # vivid hot red
CYAN    = "\033[38;2;255;104;118m"   # accent / valid → bright red-pink
BLUE    = "\033[38;2;255;104;118m"
MAGENTA = "\033[38;2;255;255;255m"
GRAY    = "\033[38;2;176;176;184m"   # lighter secondary text (was dim)
BOLD    = "\033[1m"
DIM     = "\033[2m"
RESET   = "\033[0m"

# ── Glyphs (kept even with --no-color) ──────────────────────────────────────
G_OK   = "✦"   # access / pwned
G_HIT  = "›"   # valid auth-only
G_LOCK = "⊘"   # locked out
G_ERR  = "·"   # error
G_WARN = "!"   # must-change
G_INFO = "·"   # info
G_SKIP = "○"   # skipped
G_SECT = "▎"   # section accent
G_RND  = "✦"   # password round
SPIN   = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"

ANSI = re.compile(r"\033\[[0-9;]*m")   # SGR colour codes only (not cursor moves)

# ── Truecolor gradient endpoints (red → white) ──────────────────────────────
GRAD_A    = (255, 56, 64)     # vivid hot red
GRAD_B    = (255, 255, 255)   # pure white
GRAD_DARK = (70, 14, 18)      # dark-red tail for fading rules
TRACK     = "\033[38;2;58;18;22m"   # dim-red bar track

# ── Colour enable / disable ─────────────────────────────────────────────────
USE_COLOR = True


def set_no_color():
    """Disable all colour output for the rest of the run."""
    global USE_COLOR
    USE_COLOR = False


def paint(text):
    """Return `text` as-is, or with colour stripped when colour is disabled."""
    return text if USE_COLOR else ANSI.sub("", text)


def truecolor():
    """True when we may emit 24-bit colour (a real terminal, colour enabled)."""
    return state.is_tty and USE_COLOR


# ── Low-level colour maths ────────────────────────────────────────────────────
def rgb(r, g, b):
    return f"\033[38;2;{int(r)};{int(g)};{int(b)}m"


def mix(c1, c2, t):
    return tuple(c1[i] + (c2[i] - c1[i]) * t for i in range(3))


def gradient_text(text, c1=GRAD_A, c2=GRAD_B, bold=True):
    """Static per-character gradient. Falls back to bold/plain without truecolor."""
    if not truecolor():
        return (BOLD + text + RESET) if bold else text
    n = max(len(text) - 1, 1)
    b = BOLD if bold else ""
    out = [b + rgb(*mix(c1, c2, i / n)) + ch for i, ch in enumerate(text)]
    return "".join(out) + RESET


def rule(n):
    """A short rule that fades from the accent into the dark-red tail."""
    n = max(n, 0)
    if not truecolor():
        return f"{GRAY}{'─' * n}{RESET}"
    cells = []
    for i in range(n):
        t = i / max(n - 1, 1)
        r, g, b = mix(GRAD_A, GRAD_DARK, min(t * 1.4, 1.0))
        cells.append(rgb(r, g, b) + "─")
    return "".join(cells) + RESET
