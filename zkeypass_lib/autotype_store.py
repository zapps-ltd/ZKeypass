"""Auto-type support for the two vault formats.

The sequences and window associations live in different places depending on
the format.  A KeePass database stores them in the entry's AutoType element,
which kdbx.py already reads and writes.  A ZKeypass vault stores them as hidden
entry attributes, using the same names a KeePass database would show if it
were exported, so a sequence survives both a conversion and a round trip.

Attribute names used in a ZKeypass vault:

    ZKeypass AutoType Enabled      "0" or absent means off
    ZKeypass AutoType Sequence     the default sequence for the entry
    ZKeypass AutoType Association  one per line, "window pattern|sequence"
"""

from . import autotype
from . import lang

ATTR_ENABLED = "ZKeypass AutoType Enabled"
ATTR_SEQUENCE = "ZKeypass AutoType Sequence"
ATTR_ASSOCIATION = "ZKeypass AutoType Association"

DEFAULT_SEQUENCE = autotype.DEFAULT_SEQUENCE


def _kdbx(entry):
    return isinstance(entry, dict) and "autotype" in entry


def autotype_settings(entry):
    """The auto-type settings of an entry, as a plain dictionary."""
    if _kdbx(entry):
        settings = entry.get("autotype") or {}
        return {
            "enabled": settings.get("enabled", True),
            "sequence": settings.get("sequence") or "",
            "associations": [list(pair) for pair in
                             settings.get("associations", []) or []],
        }
    return {"enabled": True, "sequence": "", "associations": []}


def sequence_of(record, associations=()):
    """The sequence to use, falling back to the KeePass default."""
    for window, sequence in associations:
        if sequence and autotype.window_matches(window, record.get("title") or ""):
            return sequence
    return record.get("autotype_sequence") or DEFAULT_SEQUENCE


def associations_for(vault, entry_id):
    """Read the associations of one entry in either format.

    Returns a list of [window pattern, sequence] pairs.
    """
    entry = getattr(vault, "_entries", {}).get(entry_id) \
        if hasattr(vault, "_entries") else None
    if entry is not None and _kdbx(entry):
        settings = entry.get("autotype") or {}
        return [list(pair) for pair in settings.get("associations", []) or []]
    pairs = []
    for attribute in vault.attributes(entry_id):
        if attribute["name"] != ATTR_ASSOCIATION:
            continue
        for line in (attribute["value"] or "").splitlines():
            if "|" in line:
                window, sequence = line.split("|", 1)
                pairs.append([window.strip(), sequence])
            elif line.strip():
                pairs.append([line.strip(), ""])
    return pairs


def set_associations(vault, entry_id, pairs):
    """Store the associations of one entry in either format."""
    entry = getattr(vault, "_entries", {}).get(entry_id) \
        if hasattr(vault, "_entries") else None
    if entry is not None and _kdbx(entry):
        settings = entry.get("autotype") or {}
        settings["associations"] = [[window, sequence]
                                    for window, sequence in pairs]
        entry["autotype"] = settings
        vault.dirty = True
        return
    existing = [attribute for attribute in vault.attributes(entry_id)
                if attribute["name"] == ATTR_ASSOCIATION]
    text = "\n".join(f"{window}|{sequence}" for window, sequence in pairs)
    if existing and text:
        vault.update_attribute(existing[0]["id"], ATTR_ASSOCIATION, text,
                               existing[0].get("hidden", 0))
        for extra in existing[1:]:
            vault.delete_attribute(extra["id"])
    elif existing:
        for attribute in existing:
            vault.delete_attribute(attribute["id"])
    elif text:
        vault.add_attribute(entry_id, ATTR_ASSOCIATION, text, False)


def set_sequence(vault, entry_id, sequence):
    """Store the default sequence of one entry in either format."""
    entry = getattr(vault, "_entries", {}).get(entry_id) \
        if hasattr(vault, "_entries") else None
    if entry is not None and _kdbx(entry):
        settings = entry.get("autotype") or {}
        settings["sequence"] = sequence
        entry["autotype"] = settings
        vault.dirty = True
        return
    existing = [attribute for attribute in vault.attributes(entry_id)
                if attribute["name"] == ATTR_SEQUENCE]
    if existing and sequence:
        vault.update_attribute(existing[0]["id"], ATTR_SEQUENCE, sequence,
                               existing[0].get("hidden", 0))
    elif existing:
        for attribute in existing:
            vault.delete_attribute(attribute["id"])
    elif sequence:
        vault.add_attribute(entry_id, ATTR_SEQUENCE, sequence, False)


def set_enabled(vault, entry_id, enabled):
    entry = getattr(vault, "_entries", {}).get(entry_id) \
        if hasattr(vault, "_entries") else None
    if entry is not None and _kdbx(entry):
        settings = entry.get("autotype") or {}
        settings["enabled"] = bool(enabled)
        entry["autotype"] = settings
        vault.dirty = True
        return
    existing = [attribute for attribute in vault.attributes(entry_id)
                if attribute["name"] == ATTR_ENABLED]
    text = "1" if enabled else "0"
    if existing:
        vault.update_attribute(existing[0]["id"], ATTR_ENABLED, text,
                               existing[0].get("hidden", 0))
    else:
        vault.add_attribute(entry_id, ATTR_ENABLED, text, False)


def is_enabled(vault, entry_id):
    entry = getattr(vault, "_entries", {}).get(entry_id) \
        if hasattr(vault, "_entries") else None
    if entry is not None and _kdbx(entry):
        return bool((entry.get("autotype") or {}).get("enabled", True))
    for attribute in vault.attributes(entry_id):
        if attribute["name"] == ATTR_ENABLED:
            return (attribute["value"] or "").strip() not in ("", "0", "false")
    return True


def sequence_setting(vault, entry_id):
    entry = getattr(vault, "_entries", {}).get(entry_id) \
        if hasattr(vault, "_entries") else None
    if entry is not None and _kdbx(entry):
        return (entry.get("autotype") or {}).get("sequence") or ""
    for attribute in vault.attributes(entry_id):
        if attribute["name"] == ATTR_SEQUENCE:
            return attribute["value"] or ""
    return ""


def candidates(vault):
    """Every entry that may be auto-typed, enriched for matching.

    Each record gets an extra "autotype" key holding enabled, sequence and
    associations, plus the sequences needed for the picker dialog.
    """
    out = []
    for record in vault.entries():
        entry_id = record.get("id")
        try:
            entry = getattr(vault, "_entries", {}).get(entry_id) \
                if hasattr(vault, "_entries") else None
            if entry is not None and _kdbx(entry):
                settings = entry.get("autotype") or {}
                record["autotype"] = {
                    "enabled": settings.get("enabled", True),
                    "sequence": settings.get("sequence") or "",
                    "associations": [list(pair) for pair in
                                     settings.get("associations", []) or []],
                }
            else:
                record["autotype"] = {
                    "enabled": is_enabled(vault, entry_id),
                    "sequence": sequence_setting(vault, entry_id),
                    "associations": associations_for(vault, entry_id),
                }
        except Exception:
            record["autotype"] = {"enabled": True, "sequence": "",
                                  "associations": []}
        out.append(record)
    return out


def type_entry(vault, record, title="", delay_ms=autotype.DEFAULT_DELAY_MS):
    """Type an entry into the window that currently has the focus.

    Returns a short report of what was typed.  Raises autotype.AutoTypeError
    with a readable message when Windows refuses the keystrokes.
    """
    from . import totp

    association_sequence = ""
    for window, sequence in (record.get("autotype") or {}).get("associations",
                                                               []):
        if sequence and autotype.window_matches(window, title):
            association_sequence = sequence
    sequence = (association_sequence
                or (record.get("autotype") or {}).get("sequence")
                or DEFAULT_SEQUENCE)
    code = totp.format_code(totp.current_code(record)) if record.get("totp_secret") else ""
    typed = autotype.play(sequence, record,
                          group_name=record.get("group_name") or "",
                          totp_code=code, delay_ms=delay_ms)
    return lang.t(
        "dialogs", "typed_characters_into",
        "Typed {typed} characters into {title}.",
        typed=typed,
        title=title or lang.t(
            "dialogs", "the_active_window",
            "the active window"))
