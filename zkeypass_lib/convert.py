"""Copy a vault between the two formats, and export its contents to plain files.

Two jobs live here.

save_as writes the open vault out as the other kind of database: a .zkp vault
becomes a KeePass .kdbx that KeePassXC can open, and a .kdbx becomes a .zkp
that only ZKeypass reads.  Groups, entries, custom attributes, attachments,
auto-type settings, passkeys, two-factor secrets and expiry dates all come
across, because every one of them is reachable through the same method names
on both vault classes.

export_vault writes the entries out as CSV, KeePass XML, HTML or plain text,
and can lay the attachments down beside the export as ordinary files.

Nothing here touches the network and nothing is written outside the folder
the caller names.
"""

import csv
import os
import time
from datetime import datetime, timezone
from xml.sax.saxutils import escape

from . import autotype_store, crypto, kdbx
from .kdbx_vault import KdbxVault
from .vault import Vault
from . import lang

# Attributes that describe auto-type settings are carried by autotype_store,
# not copied as ordinary custom fields, so that both formats stay tidy.
AUTOTYPE_PREFIX = "ZKeypass AutoType "

EXPORT_FORMATS = ("csv", "xml", "html", "text")
EXPORT_LABELS = lang.Labels("dialogs", "export_format_", {
    "csv": "Comma separated text, reopens in ZKeypass or any spreadsheet (*.csv)",
    "xml": "KeePass XML, imports into KeePassXC or KeePass 2 (*.xml)",
    "html": "Web page, readable in any browser (*.html)",
    "text": "Plain text, readable anywhere (*.txt)",
})
EXPORT_SUFFIXES = {"csv": ".csv", "xml": ".xml", "html": ".html", "text": ".txt"}


# --------------------------------------------------------------------- helpers

def _safe_name(text, fallback="entry"):
    cleaned = "".join(character for character in (text or "")
                      if character not in '\\/:*?"<>|').strip().strip(".")
    return (cleaned or fallback)[:80]


def _stamp(moment):
    if isinstance(moment, datetime):
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        try:
            return moment.timestamp()
        except (OverflowError, OSError, ValueError):
            return 0.0
    try:
        return float(moment or 0)
    except (TypeError, ValueError):
        return 0.0


def _record_for_copy(record, group_map):
    """The part of a record that save_entry understands, with a new group id."""
    copied = {
        "title": record.get("title") or "",
        "username": record.get("username") or "",
        "password": record.get("password") or "",
        "url": record.get("url") or "",
        "notes": record.get("notes") or "",
        "totp_secret": record.get("totp_secret") or "",
        "totp_digits": record.get("totp_digits") or 6,
        "totp_period": record.get("totp_period") or 30,
        "totp_algorithm": record.get("totp_algorithm") or "SHA1",
        "expires": record.get("expires") or 0,
        "favourite": 1 if record.get("favourite") else 0,
        "group_id": group_map.get(record.get("group_id")),
    }
    return copied


def _add_attribute(target, entry_id, name, value, hidden):
    """Add one custom attribute, keeping names unique in a KeePass database."""
    if isinstance(target, KdbxVault):
        taken = {item["name"] for item in target.attributes(entry_id)}
        final, counter = name, 2
        while final in taken:
            final = f"{name}_{counter}"
            counter += 1
    else:
        final = name
    target.add_attribute(entry_id, final, value, bool(hidden))


def _keep_times(target, entry_id, record):
    """Preserve creation and modification times when the target supports it."""
    if not isinstance(target, KdbxVault):
        return
    try:
        entry = target._entries.get(entry_id)
        if not entry:
            return
        times = entry.setdefault("times", {})
        made = _stamp(record.get("created"))
        changed = _stamp(record.get("modified"))
        if made:
            times["CreationTime"] = datetime.fromtimestamp(made, timezone.utc)
        if changed:
            times["LastModificationTime"] = datetime.fromtimestamp(
                changed, timezone.utc)
    except Exception:
        pass


# ------------------------------------------------------------------- copying

def copy_vault(source, target, include_attachments=True):
    """Copy every group and entry from one vault object into another.

    Returns a small dictionary of counts, which the interface turns into a
    sentence for the status bar.
    """
    group_map = {}
    for group in source.groups():
        group_map[group["id"]] = target.add_group(group["name"])

    counts = {"groups": len(group_map), "entries": 0, "attributes": 0,
              "attachments": 0, "passkeys": 0, "totp": 0, "skipped": []}

    for record in source.entries():
        source_id = record.get("id")
        new_id = target.save_entry(_record_for_copy(record, group_map))
        counts["entries"] += 1
        if record.get("totp_secret"):
            counts["totp"] += 1
        _keep_times(target, new_id, record)

        for attribute in source.attributes(source_id):
            name = attribute["name"]
            if name.startswith(AUTOTYPE_PREFIX):
                continue
            _add_attribute(target, new_id, name, attribute.get("value") or "",
                           attribute.get("hidden"))
            counts["attributes"] += 1

        if include_attachments:
            for attachment in source.attachments(source_id):
                payload = source.attachment_data(attachment["id"])
                if not payload:
                    continue
                target.add_attachment(new_id, attachment["name"], payload)
                counts["attachments"] += 1

        try:
            sequence = autotype_store.sequence_setting(source, source_id)
            pairs = autotype_store.associations_for(source, source_id)
            enabled = autotype_store.is_enabled(source, source_id)
            if sequence:
                autotype_store.set_sequence(target, new_id, sequence)
            if pairs:
                autotype_store.set_associations(target, new_id, pairs)
            if not enabled:
                autotype_store.set_enabled(target, new_id, False)
        except Exception as error:  # auto-type is a nicety, never fatal
            counts["skipped"].append(f"auto-type of {record.get('title')}: {error}")

        counts["passkeys"] += sum(
            1 for attribute in source.attributes(source_id)
            if attribute["name"] == "KPEX_PASSKEY_PRIVATE_KEY_PEM")
    return counts


def save_as(source, path, password, keyfile=None, challenge_response=None,
            kind=None, options=None, include_attachments=True):
    """Write the contents of source into a new file at path.

    kind is "kdbx" or "zkp"; when it is not given the file name decides.
    options may carry cipher, kdf, memory_kib, iterations and rounds for the
    new database.  Returns the new vault object and the copy counts.
    """
    options = dict(options or {})
    chosen = (kind or ("kdbx" if str(path).lower().endswith(".kdbx")
                       else "zkp")).lower()
    folder = os.path.dirname(os.path.abspath(path))
    if folder:
        os.makedirs(folder, exist_ok=True)

    if chosen == "kdbx":
        target_options = {key: value for key, value in options.items()
                          if key in ("cipher", "kdf", "memory_kib", "iterations",
                                     "parallelism", "rounds")}
        target = KdbxVault.create(path, password, keyfile, challenge_response,
                                  initial_group=False, **target_options)
    else:
        target = Vault.create(path, password, initial_group=False)
        cipher = options.get("cipher")
        kdf = options.get("kdf")
        if cipher in crypto.CIPHER_IDS or kdf in crypto.KDF_IDS:
            target.set_cryptography(cipher=cipher, kdf=kdf)

    counts = copy_vault(source, target, include_attachments)
    target.save(password)
    counts["path"] = path
    counts["format"] = chosen
    return target, counts


# ------------------------------------------------------------------ exporting

def _export_rows(vault, include_passwords=True):
    rows = []
    for record in vault.entries():
        rows.append({
            "title": record.get("title") or "",
            "username": record.get("username") or "",
            "password": (record.get("password") or "") if include_passwords else "",
            "url": record.get("url") or "",
            "notes": record.get("notes") or "",
            "totp": record.get("totp_secret") or "",
            "group": record.get("group_name") or "",
            "id": record.get("id"),
        })
    return rows


def export_csv(vault, path, include_passwords=True):
    headings = ["Title", "Username", "Password", "URL", "Notes", "TOTP", "Group"]
    with open(path, "w", encoding="utf-8-sig", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=headings, extrasaction="ignore")
        writer.writeheader()
        for row in _export_rows(vault, include_passwords):
            writer.writerow({"Title": row["title"], "Username": row["username"],
                             "Password": row["password"], "URL": row["url"],
                             "Notes": row["notes"], "TOTP": row["totp"],
                             "Group": row["group"]})
    return path


def export_xml(vault, path, include_passwords=True):
    """KeePass XML 1.0, which KeePassXC and KeePass 2 both import."""
    out = ['<?xml version="1.0" encoding="utf-8" standalone="yes"?>',
           '<KeePassFile>', '\t<Meta>',
           '\t\t<Generator>ZKeypass</Generator>',
           f'\t\t<DatabaseName>{escape(os.path.basename(path))}</DatabaseName>',
           '\t</Meta>', '\t<Root>', '\t\t<Group>',
           '\t\t\t<Name>ZKeypass export</Name>']
    body = []
    for row in _export_rows(vault, include_passwords):
        body.append("\t\t\t<Entry>")
        for tag, value in (("Title", row["title"]), ("UserName", row["username"]),
                           ("Password", row["password"]), ("URL", row["url"]),
                           ("Notes", row["notes"])):
            body.append(f"\t\t\t\t<String><Key>{tag}</Key>"
                        f"<Value>{escape(value)}</Value></String>")
        if row["totp"]:
            body.append("\t\t\t\t<String><Key>TOTP Seed</Key>"
                        f"<Value>{escape(row['totp'])}</Value></String>")
        if row["group"]:
            body.append("\t\t\t\t<String><Key>Group</Key>"
                        f"<Value>{escape(row['group'])}</Value></String>")
        body.append("\t\t\t</Entry>")
    text = "\n".join(out + body + ["\t\t</Group>", "\t</Root>",
                                        "</KeePassFile>", ""])
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write(text)
    return path


def export_html(vault, path, include_passwords=True):
    rows = _export_rows(vault, include_passwords)
    parts = ["<!DOCTYPE html>", '<html lang="en"><head>',
             '<meta charset="utf-8">',
             f"<title>ZKeypass export {escape(os.path.basename(path))}</title>",
             "<style>body{font-family:Segoe UI,Arial,sans-serif;margin:2em}"
             "table{border-collapse:collapse;width:100%}"
             "th,td{border:1px solid #999;padding:4px 8px;text-align:left}"
             "th{background:#eee}</style></head><body>",
             f"<h1>ZKeypass export</h1><p>{len(rows)} entries, written "
             f"{time.strftime('%Y-%m-%d %H:%M')}.</p>",
             "<table><tr><th>Title</th><th>Username</th><th>Password</th>"
             "<th>Web address</th><th>Group</th><th>Notes</th></tr>"]
    for row in rows:
        parts.append("<tr>" + "".join(
            f"<td>{escape(str(row[field]))}</td>" for field in
            ("title", "username", "password", "url", "group", "notes")) + "</tr>")
    parts += ["</table>", "<p>Keep this file somewhere safe: it holds your "
              "passwords in the clear unless you left them out.</p>",
              "</body></html>", ""]
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write("\n".join(parts))
    return path


def export_text(vault, path, include_passwords=True):
    rows = _export_rows(vault, include_passwords)
    lines = [f"ZKeypass export, {time.strftime('%Y-%m-%d %H:%M')}",
             f"{len(rows)} entries", ""]
    for row in rows:
        lines.append(row["title"] or "(no title)")
        if row["group"]:
            lines.append(f"  Group:      {row['group']}")
        if row["username"]:
            lines.append(f"  Username:   {row['username']}")
        if row["password"]:
            lines.append(f"  Password:   {row['password']}")
        if row["url"]:
            lines.append(f"  Web address: {row['url']}")
        if row["totp"]:
            lines.append(f"  Two-factor seed: {row['totp']}")
        if row["notes"]:
            for note_line in str(row["notes"]).splitlines() or [""]:
                lines.append(f"  Note:       {note_line}")
        lines.append("")
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        handle.write("\n".join(lines))
    return path


EXPORTERS = {"csv": export_csv, "xml": export_xml, "html": export_html,
             "text": export_text}


def export_attachments(vault, folder):
    """Write every attachment out as a file, under a folder per entry."""
    os.makedirs(folder, exist_ok=True)
    written = []
    for record in vault.entries():
        attachments = vault.attachments(record.get("id"))
        if not attachments:
            continue
        target_dir = os.path.join(folder, _safe_name(record.get("title")))
        os.makedirs(target_dir, exist_ok=True)
        for attachment in attachments:
            payload = vault.attachment_data(attachment["id"])
            target = os.path.join(target_dir, _safe_name(attachment["name"]))
            with open(target, "wb") as handle:
                handle.write(payload)
            written.append(target)
    return written


def export_vault(vault, path, kind="csv", include_passwords=True,
                 attachments_folder=None):
    """Write an export file, optionally with its attachments beside it."""
    kind = (kind or "csv").lower()
    if kind not in EXPORTERS:
        raise ValueError(f"Unknown export format '{kind}'.")
    folder = os.path.dirname(os.path.abspath(path))
    if folder:
        os.makedirs(folder, exist_ok=True)
    EXPORTERS[kind](vault, path, include_passwords)
    report = {"path": path, "entries": len(_export_rows(vault)),
              "attachments": []}
    if attachments_folder:
        report["attachments"] = export_attachments(vault, attachments_folder)
    return report
