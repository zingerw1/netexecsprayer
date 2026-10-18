#!/usr/bin/env python3
"""netexecspray launcher.

The implementation now lives in the ``netexecspray/`` package (see its
``__init__`` for the module map). This shim keeps ``./netexecspray.py`` and any
symlink on PATH working; ``python -m netexecspray`` is equivalent.
"""

import os
import sys

# Resolve symlinks (realpath, not abspath) so the sibling `netexecspray/`
# package is found when this launcher is symlinked onto PATH, e.g. into
# ~/.local/bin. Inserting the repo dir at the front makes the real package win
# over any same-named stray module elsewhere on sys.path.
_REPO = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(0, _REPO)

from netexecspray.cli import main  # noqa: E402

if __name__ == "__main__":
    main()
