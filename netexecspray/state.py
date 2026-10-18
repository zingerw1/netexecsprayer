"""Shared runtime state.

Every mutable value the sprayer threads touch lives here behind a lock, so the
rest of the package has one obvious place to look when reasoning about
concurrency. Import the module (``from . import state``) and reference
``state.<name>`` rather than importing the names directly — scalars such as
``start_time`` and ``phase`` are reassigned at runtime and must be read live.
"""

import sys
import threading

# ── Locks ─────────────────────────────────────────────────────────────────────
print_lock    = threading.Lock()   # serialises everything written to stdout
log_lock      = threading.Lock()   # serialises appends to the log file
results_lock  = threading.Lock()   # guards `attempts` / `results`
seen_lock     = threading.Lock()   # guards `seen`
counter_lock  = threading.Lock()   # guards `counter`
locked_lock   = threading.Lock()   # guards `locked_users`
user_att_lock = threading.Lock()   # guards `user_attempts`
active_lock   = threading.Lock()   # guards `active`
rate_lock     = threading.Lock()   # guards `rate_state`

# ── Results ─────────────────────────────────────────────────────────────────
# Every attempt lands in `attempts`; the buckets in `results` hold the SAME dict
# refs, so there is exactly one source of truth for every sink (log, UI, loot…).
attempts      = []
results       = {"access": [], "valid": [], "locked": [], "errors": []}

# ── Dedupe / progress ─────────────────────────────────────────────────────────
seen          = set()                 # proto:target:user:secret already attempted
counter       = {"done": 0, "total": 0}
locked_users  = set()                 # accounts observed locked → skipped
user_attempts = {}                    # user → attempts made (for --max-attempts)
active        = {}                    # thread id → "proto user@target"
rate_state    = {"next": 0.0}         # token-bucket cursor for --rate
rate_hist     = []                    # recent attempts/sec samples (status sparkline)

# ── Lifecycle flags ─────────────────────────────────────────────────────────
start_time    = 0.0                   # set when the spray loop begins
phase         = ""                    # live context shown in the status bar
bell_enabled  = False                 # ring the bell on access (set from --bell)
is_tty        = sys.stdout.isatty()
stop_ticker   = threading.Event()     # stop the live status-bar thread
abort         = threading.Event()     # Ctrl-C → stop submitting new work
