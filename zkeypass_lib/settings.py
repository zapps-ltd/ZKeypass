"""Settings kept in settings.json inside ZKeypass's data folder.

Deliberately excludes anything sensitive: preferences and window geometry
only.  No password is ever written here; Windows Hello keeps its own sealed
record in data\\quick_unlock.json (see winhello.py).
"""

import json
import os

from . import paths

DEFAULTS = {
    "last_vault": "",
    "last_folder": "",
    "recent_folders": [],
    "recent_vaults": [],
    "window_size": [1100, 720],
    "generator_length": 20,
    "generator_upper": True,
    "generator_lower": True,
    "generator_digits": True,
    "generator_symbols": True,
    "generator_extended": False,
    "generator_ambiguous": False,
    "passphrase_words": 5,
    "passphrase_separator": "-",
    "passphrase_capitalise": True,
    "passphrase_number": True,
    "clipboard_clear_seconds": 20,
    "auto_lock_minutes": 0,
    "max_age_days": 365,
    "weak_bits": 45,
    "totp_period": 30,
    # View menu: how the entry list is sorted, and which columns the entry
    # list and the Authenticator list show.  The name column is always shown.
    "sort_column": "title",
    "sort_descending": False,
    "entry_columns": ["username", "site", "group", "totp", "modified"],
    "authenticator_columns": ["code", "valid", "group", "username"],
    # Auto-type
    "autotype_enabled": True,
    "autotype_delay_ms": 20,
    "autotype_hotkey": "Ctrl+Alt+A",
    "autotype_minimise": False,
    # Browser integration
    "browser_enabled": False,
    "browser_port": 19455,
    "browser_ask": True,
    # Two-factor authenticator
    "totp_hotkey_enabled": True,
    "totp_hotkey": "Ctrl+Alt+T",
    "totp_announce_rotation": True,
    "totp_show_seconds": True,
    # Hardware security key
    "yubikey_slot": 1,
    "yubikey_ask": True,
    "passkey_algorithm": "ES256",
    # Network: off unless the user turns it on.  Only Suggest names uses it,
    # and it still asks each time unless "always" was chosen.
    "names_online_allowed": False,
    # Look: "dark" is the high-tech theme, "system" the plain Windows look.
    # Effects also stay still whenever Windows' own animations are off.
    "theme": "dark",
    # Interface language: a folder name in lang, or "" to follow Windows.
    "language": "",
    "visual_effects": True,
    # Notification area and Windows start (see tray.py and startup.py).
    "tray_enabled": True,
    "minimize_to_tray": True,
    "run_at_startup": False,
    "startup_unlock": False,
    # Spoken announcements: "auto" speaks only while a screen reader runs.
    "announce_actions": "auto",
}


RECENT_LIMIT = 8


def remember_recent(settings, path, limit=RECENT_LIMIT):
    """Keep a short most-recent-first list of databases in the settings."""
    path = os.path.abspath(path or "")
    if not path:
        return
    recent = [str(item) for item in (settings.get("recent_vaults") or [])]
    recent = [item for item in recent
              if os.path.normcase(os.path.abspath(item)) != os.path.normcase(path)]
    recent.insert(0, path)
    settings["recent_vaults"] = recent[:limit]
    settings["last_vault"] = path


def remember_folder(settings, path, limit=RECENT_LIMIT):
    """Remember the folder a file was chosen from, for later file dialogs."""
    folder = path if os.path.isdir(path) else os.path.dirname(path or "")
    if folder and os.path.isdir(folder):
        settings["last_folder"] = folder


class Settings(dict):
    def __init__(self, data=None):
        super().__init__(DEFAULTS)
        if data:
            self.update({key: value for key, value in data.items()
                         if key in DEFAULTS})

    @classmethod
    def load(cls):
        if not os.path.isfile(paths.SETTINGS_FILE):
            return cls()
        try:
            with open(paths.SETTINGS_FILE, "r", encoding="utf-8") as handle:
                return cls(json.load(handle))
        except (OSError, ValueError):
            return cls()

    def save(self):
        try:
            with open(paths.SETTINGS_FILE, "w", encoding="utf-8") as handle:
                json.dump(dict(self), handle, indent=2)
        except OSError:
            pass
