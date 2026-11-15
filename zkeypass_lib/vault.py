"""Vault contents: an in-memory SQLite database encrypted into one file.

The whole database, including file attachments, lives in memory while the
vault is unlocked and is written out as a single AES-GCM blob.  Nothing is
spilled to disk, so attachments are as protected as the passwords beside them.
"""

import os
import sqlite3
import time

from . import crypto
from .totp import has_code as totp_has_code

SCHEMA = """
CREATE TABLE meta (
    key TEXT PRIMARY KEY,
    value TEXT
);
CREATE TABLE groups (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    icon TEXT DEFAULT ''
);
CREATE TABLE entries (
    id INTEGER PRIMARY KEY,
    group_id INTEGER REFERENCES groups(id) ON DELETE SET NULL,
    title TEXT DEFAULT '',
    username TEXT DEFAULT '',
    password TEXT DEFAULT '',
    url TEXT DEFAULT '',
    notes TEXT DEFAULT '',
    totp_secret TEXT DEFAULT '',
    totp_digits INTEGER DEFAULT 6,
    totp_period INTEGER DEFAULT 30,
    totp_algorithm TEXT DEFAULT 'SHA1',
    expires REAL DEFAULT 0,
    created REAL DEFAULT 0,
    modified REAL DEFAULT 0,
    favourite INTEGER DEFAULT 0
);
CREATE TABLE attributes (
    id INTEGER PRIMARY KEY,
    entry_id INTEGER REFERENCES entries(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    value TEXT DEFAULT '',
    hidden INTEGER DEFAULT 0
);
CREATE TABLE attachments (
    id INTEGER PRIMARY KEY,
    entry_id INTEGER REFERENCES entries(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    size INTEGER DEFAULT 0,
    data BLOB
);
"""

ENTRY_FIELDS = ("group_id", "title", "username", "password", "url", "notes",
                "totp_secret", "totp_digits", "totp_period", "totp_algorithm",
                "expires", "favourite")


class PasswordPair(str):
    """The master password, carried with an optional key file path.

    It behaves exactly like a string, so every existing call that hands the
    password to the vault keeps working, but the key file travels with it.
    """

    keyfile = None
    challenge_response = None

    def __new__(cls, password, keyfile=None, challenge_response=None):
        value = super().__new__(cls, password or "")
        value.keyfile = keyfile or None
        value.challenge_response = challenge_response or None
        return value


class Vault:
    """A decrypted vault. Use Vault.open or Vault.create to obtain one."""

    def __init__(self, connection, path=None):
        self.connection = connection
        self.path = path
        self.connection.row_factory = sqlite3.Row
        self.dirty = False

    # ------------------------------------------------------------- lifecycle

    @classmethod
    def create(cls, path, password, initial_group=True):
        connection = sqlite3.connect(":memory:")
        connection.executescript(SCHEMA)
        connection.execute("INSERT INTO meta (key, value) VALUES ('version', '1')")
        connection.execute("INSERT INTO meta (key, value) VALUES ('cipher', ?)",
                           (crypto.DEFAULT_CIPHER,))
        connection.execute("INSERT INTO meta (key, value) VALUES ('kdf', ?)",
                           (crypto.DEFAULT_KDF,))
        if initial_group:
            connection.execute("INSERT INTO groups (name, icon) VALUES (?, ?)",
                               ("General", ""))
        connection.commit()
        vault = cls(connection, path)
        vault.save(password)
        return vault

    @classmethod
    def open(cls, path, password):
        with open(path, "rb") as handle:
            blob = handle.read()
        plain = crypto.decrypt(blob, password)
        connection = sqlite3.connect(":memory:")
        connection.deserialize(plain)
        connection.row_factory = sqlite3.Row
        cls._migrate(connection)
        return cls(connection, path)

    def cryptography(self):
        """The cipher and key derivation function this vault was saved with."""
        stored = {}
        try:
            for row in self.connection.execute("SELECT key, value FROM meta"):
                stored[row["key"]] = row["value"]
        except Exception:
            pass
        return (stored.get("cipher") or crypto.DEFAULT_CIPHER,
                stored.get("kdf") or crypto.DEFAULT_KDF)

    def set_cryptography(self, cipher=None, kdf=None):
        """Choose the cipher and KDF used the next time this vault is saved."""
        for name, value in (("cipher", cipher), ("kdf", kdf)):
            if value:
                self.connection.execute(
                    "INSERT INTO meta (key, value) VALUES (?, ?) "
                    "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    (name, value))
        self.dirty = True

    @staticmethod
    def _migrate(connection):
        """Add anything a vault created by an older build is missing."""
        existing = {row["name"] for row in connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table'")}
        if not existing:
            connection.executescript(SCHEMA)
            connection.commit()
            return
        for statement in SCHEMA.strip().split(";"):
            text = statement.strip()
            if not text:
                continue
            table = text.split()[2].strip("(") if text.upper().startswith(
                "CREATE TABLE") else ""
            if table and table not in existing:
                connection.executescript(text)
        connection.execute(
            "INSERT OR IGNORE INTO meta (key, value) VALUES ('version', '1')")
        connection.commit()

    def close(self):
        try:
            self.connection.close()
        except Exception:
            pass

    def save(self, password, backup=True):
        if self.path is None:
            raise ValueError("The vault has no file path.")
        plain = self.connection.serialize()
        cipher, kdf = self.cryptography()
        blob = crypto.encrypt(plain, password, cipher=cipher, kdf=kdf)
        if backup and os.path.isfile(self.path):
            from . import paths

            paths.keep_backup(self.path)
        crypto.atomic_write(self.path, blob)
        self.dirty = False

    # ----------------------------------------------------------------- groups

    def groups(self):
        return [dict(row) for row in self.connection.execute(
            "SELECT * FROM groups ORDER BY name COLLATE NOCASE")]

    def group_name(self, group_id):
        row = self.connection.execute(
            "SELECT name FROM groups WHERE id = ?", (group_id,)).fetchone()
        return row["name"] if row else ""

    def add_group(self, name):
        cursor = self.connection.execute(
            "INSERT INTO groups (name) VALUES (?)", (name,))
        self.dirty = True
        return cursor.lastrowid

    def rename_group(self, group_id, name):
        self.connection.execute("UPDATE groups SET name = ? WHERE id = ?",
                                (name, group_id))
        self.dirty = True

    def delete_group(self, group_id):
        self.connection.execute(
            "UPDATE entries SET group_id = NULL WHERE group_id = ?", (group_id,))
        self.connection.execute("DELETE FROM groups WHERE id = ?", (group_id,))
        self.dirty = True

    # ---------------------------------------------------------------- entries

    def entries(self, group_id=None, search=None, favourites_only=False):
        sql = ["SELECT e.*, g.name AS group_name FROM entries e "
               "LEFT JOIN groups g ON g.id = e.group_id WHERE 1 = 1"]
        params = []
        if group_id is not None:
            sql.append("AND e.group_id = ?")
            params.append(group_id)
        if favourites_only:
            sql.append("AND e.favourite = 1")
        if search:
            like = f"%{search.lower()}%"
            sql.append(
                "AND (lower(e.title) LIKE ? OR lower(e.username) LIKE ? "
                "OR lower(e.url) LIKE ? OR lower(e.notes) LIKE ?)"
            )
            params.extend([like, like, like, like])
        sql.append("ORDER BY e.title COLLATE NOCASE")
        return [dict(row) for row in self.connection.execute(" ".join(sql), params)]

    def entries_with_totp(self, group_id=None, search=None):
        """Only the entries with a genuine setup key, for the Authenticator."""
        from . import totp

        return [entry for entry in self.entries(group_id=group_id, search=search)
                if totp.has_code(entry)]

    def entry_count(self):
        row = self.connection.execute("SELECT COUNT(*) AS n FROM entries").fetchone()
        return row["n"] if row else 0

    def get_entry(self, entry_id):
        row = self.connection.execute(
            "SELECT e.*, g.name AS group_name FROM entries e "
            "LEFT JOIN groups g ON g.id = e.group_id WHERE e.id = ?",
            (entry_id,)).fetchone()
        return dict(row) if row else None

    def save_entry(self, entry):
        """Insert when the entry has no id, otherwise update. Returns the id."""
        now = time.time()
        values = {field: entry.get(field) for field in ENTRY_FIELDS}
        values["title"] = values.get("title") or ""
        values["expires"] = values.get("expires") or 0
        values["favourite"] = 1 if values.get("favourite") else 0
        values["totp_digits"] = int(values.get("totp_digits") or 6)
        values["totp_period"] = int(values.get("totp_period") or 30)
        values["totp_algorithm"] = (values.get("totp_algorithm") or "SHA1").upper()

        if entry.get("id"):
            values["modified"] = now
            assignments = ", ".join(f"{field} = :{field}" for field in ENTRY_FIELDS)
            self.connection.execute(
                f"UPDATE entries SET {assignments}, modified = :modified "
                "WHERE id = :id", {**values, "id": entry["id"]})
            entry_id = entry["id"]
        else:
            values["created"] = now
            values["modified"] = now
            columns = ", ".join(["created", "modified", *ENTRY_FIELDS])
            placeholders = ", ".join(":" + name for name in
                                     ["created", "modified", *ENTRY_FIELDS])
            cursor = self.connection.execute(
                f"INSERT INTO entries ({columns}) VALUES ({placeholders})", values)
            entry_id = cursor.lastrowid
        self.dirty = True
        return entry_id

    def delete_entry(self, entry_id):
        self.connection.execute("DELETE FROM attributes WHERE entry_id = ?",
                                (entry_id,))
        self.connection.execute("DELETE FROM attachments WHERE entry_id = ?",
                                (entry_id,))
        self.connection.execute("DELETE FROM entries WHERE id = ?", (entry_id,))
        self.dirty = True

    def rename_entry(self, entry_id, title):
        """Change only the name of an entry."""
        self.connection.execute(
            "UPDATE entries SET title = ?, modified = ? WHERE id = ?",
            (title, time.time(), entry_id))
        self.dirty = True

    def duplicate_entry(self, entry_id):
        entry = self.get_entry(entry_id)
        if not entry:
            return None
        entry.pop("id")
        entry["title"] = f"{entry.get('title', '')} copy"
        new_id = self.save_entry(entry)
        for attribute in self.attributes(entry_id):
            self.add_attribute(new_id, attribute["name"], attribute["value"],
                               attribute["hidden"])
        for attachment in self.attachments(entry_id):
            data = self.attachment_data(attachment["id"])
            self.add_attachment(new_id, attachment["name"], data)
        return new_id

    def set_favourite(self, entry_id, favourite):
        self.connection.execute("UPDATE entries SET favourite = ? WHERE id = ?",
                                (1 if favourite else 0, entry_id))
        self.dirty = True

    def set_username(self, entry_id, username):
        """Change only the user name of an entry."""
        self.connection.execute(
            "UPDATE entries SET username = ?, modified = ? WHERE id = ?",
            (username, time.time(), entry_id))
        self.dirty = True

    def move_entry(self, entry_id, group_id):
        self.connection.execute("UPDATE entries SET group_id = ? WHERE id = ?",
                                (group_id, entry_id))
        self.dirty = True

    # ------------------------------------------------------------- attributes

    def attributes(self, entry_id):
        return [dict(row) for row in self.connection.execute(
            "SELECT * FROM attributes WHERE entry_id = ? ORDER BY name COLLATE NOCASE",
            (entry_id,))]

    def add_attribute(self, entry_id, name, value, hidden=False):
        cursor = self.connection.execute(
            "INSERT INTO attributes (entry_id, name, value, hidden) VALUES (?,?,?,?)",
            (entry_id, name, value, 1 if hidden else 0))
        self.dirty = True
        return cursor.lastrowid

    def update_attribute(self, attribute_id, name, value, hidden):
        self.connection.execute(
            "UPDATE attributes SET name = ?, value = ?, hidden = ? WHERE id = ?",
            (name, value, 1 if hidden else 0, attribute_id))
        self.dirty = True

    def delete_attribute(self, attribute_id):
        self.connection.execute("DELETE FROM attributes WHERE id = ?",
                                (attribute_id,))
        self.dirty = True

    # ------------------------------------------------------------ attachments

    def attachments(self, entry_id):
        return [dict(row) for row in self.connection.execute(
            "SELECT id, entry_id, name, size FROM attachments WHERE entry_id = ? "
            "ORDER BY name COLLATE NOCASE", (entry_id,))]

    def add_attachment(self, entry_id, name, data):
        cursor = self.connection.execute(
            "INSERT INTO attachments (entry_id, name, size, data) VALUES (?,?,?,?)",
            (entry_id, name, len(data), sqlite3.Binary(data)))
        self.dirty = True
        return cursor.lastrowid

    def attachment_data(self, attachment_id):
        row = self.connection.execute(
            "SELECT data FROM attachments WHERE id = ?", (attachment_id,)).fetchone()
        return bytes(row["data"]) if row else b""

    def delete_attachment(self, attachment_id):
        self.connection.execute("DELETE FROM attachments WHERE id = ?",
                                (attachment_id,))
        self.dirty = True

    def import_file(self, entry_id, source_path):
        with open(source_path, "rb") as handle:
            data = handle.read()
        return self.add_attachment(entry_id, os.path.basename(source_path), data)

    def export_attachment(self, attachment_id, destination_dir):
        row = self.connection.execute(
            "SELECT name FROM attachments WHERE id = ?", (attachment_id,)).fetchone()
        if not row:
            return None
        target = os.path.join(destination_dir, row["name"])
        with open(target, "wb") as handle:
            handle.write(self.attachment_data(attachment_id))
        return target

    # ---------------------------------------------------------------- reports

    def all_entries_for_audit(self):
        return self.entries()

    def statistics(self):
        entries = self.entries()
        return {
            "entries": len(entries),
            "groups": len(self.groups()),
            "with_totp": sum(1 for entry in entries if totp_has_code(entry)),
            "with_attachments": self.connection.execute(
                "SELECT COUNT(DISTINCT entry_id) AS n FROM attachments").fetchone()["n"],
            "favourites": sum(1 for entry in entries if entry.get("favourite")),
        }
