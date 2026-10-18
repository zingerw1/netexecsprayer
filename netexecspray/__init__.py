"""netexecspray — modern multi-protocol NetExec password sprayer.

Package layout:
  state     shared runtime state + locks
  theme     palette, glyphs, colour/gradient primitives (redline theme)
  protocols protocol catalogue + bundles
  parsing   classify / explain nxc & native output
  runners   talk to targets: nxc, validation, policy, native sprayers
  results   record pipeline + log/loot/csv/report/json sinks
  ui        all terminal output (status bar, hit banners, summary)
  loaders   targets, credential/combo lists, resume parsing
  worker    per-attempt spray logic + pre-flight probes
  cli       argument parsing + orchestration
"""

__version__ = "2.0.0"

from .cli import main  # noqa: E402,F401
