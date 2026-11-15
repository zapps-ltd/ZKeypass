"""ZKeypass - fully portable, offline password manager.

Run this file with Python 3.10 or newer:  python zkeypass.py
Everything ZKeypass reads or writes lives inside this folder.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def _remove_pre_rename_files():
    """Delete what a build from before the rename left in this folder when
    a new build was copied over it. Built copies only, these exact files
    only, quietly; data is never touched."""
    if not getattr(sys, "frozen", False):
        return
    root = os.path.dirname(os.path.abspath(sys.executable))
    for rel in ("ZKPass.exe",  # pre-rename name
                os.path.join("data", "zkpass_native_host.json")):  # pre-rename name
        path = os.path.join(root, rel)
        try:
            if os.path.isfile(path):
                os.remove(path)
        except OSError:
            pass


if __name__ == "__main__":
    _remove_pre_rename_files()
    from zkeypass_lib.app import main

    sys.exit(main())
