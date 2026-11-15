"""A Vault-compatible view over a real KeePass 2 (KDBX) database.

This module lets ZKeypass read and write .kdbx files directly, so the same
database can be opened by KeePassXC, KeePass 2 or any other compatible
program.  The class here exposes exactly the same method names as
vault.Vault, which means the graphical interface does not need to know
which format it is looking at.

Internally the KDBX model from kdbx.py is kept as plain dictionaries and
integers are handed out as temporary ids so the rest of the program can
refer to groups, entries, attributes and attachments in the usual way.

TOTP secrets live in an entry attribute called "TOTP Seed", the period and
digit count in "TOTP Settings" as "period;digits", exactly as KeePassXC
stores them, so codes keep working in both programs after a round trip.
"""

import os
import uuid as uuidlib
from datetime import datetime, timezone

from . import kdbx, paths
from . import lang

TOTP_SEED_ATTRIBUTE = "TOTP Seed"
TOTP_SETTINGS_ATTRIBUTE = "TOTP Settings"
TOTP_ALGORITHM_ATTRIBUTE = "TOTP Algorithm"

# KeePassXC 2.7, KeePassDX and KeePass2Android store the whole two-factor
# setting in one hidden attribute called "otp", holding an otpauth:// link.
OTP_ATTRIBUTE = "otp"

# Older spellings seen in imported databases.
TOTP_ALIASES = ("TOTP Secret", "TOTP secret", "OTP Seed", "otp_secret")

HIDDEN_ATTRIBUTES = ((TOTP_SEED_ATTRIBUTE, TOTP_SETTINGS_ATTRIBUTE,
                      TOTP_ALGORITHM_ATTRIBUTE, OTP_ATTRIBUTE) + TOTP_ALIASES)

STANDARD_FIELDS = ("Title", "UserName", "Password", "URL", "Notes")

FAVOURITE_TAG = "Favorite"


def _now():
    return datetime.now(timezone.utc)


def _stamp(moment, fallback=0.0):
    if isinstance(moment, datetime):
        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        try:
            return moment.timestamp()
        except (OverflowError, OSError, ValueError):
            return fallback
    return fallback


class KdbxVault:
    """A KeePass 2 database presented with the Vault interface."""

    format_name = "KeePass KDBX"
    extension = ".kdbx"

    def __init__(self, meta, root, path=None, password="", keyfile=None,
                 challenge_response=None):
        self.meta = meta or {}
        self.root = root
        self.path = path
        self.password = password
        self.keyfile = keyfile
        self.challenge_response = challenge_response
        self.dirty = False
        self._next_id = 1
        self._groups = {}
        self._entries = {}
        self._reindex()

    # ------------------------------------------------------------- lifecycle

    @classmethod
    def create(cls, path, password, keyfile=None, challenge_response=None,
               cipher=None, kdf=None, iterations=5, memory_kib=65536,
               parallelism=4, rounds=600000, format_version=None,
               initial_group=True):
        root = {
            "uuid": uuidlib.uuid4().bytes,
            "name": os.path.splitext(os.path.basename(path or "vault"))[0]
                    or "ZKeypass",
            "notes": "",
            "icon": 48,
            "times": _blank_times(),
            "expanded": True,
            "custom_data": {},
            "entries": [],
            "groups": [],
        }
        meta = {"name": root["name"], "description": "", "default_username": "",
                "generator": "ZKeypass", "history_max_items": 10,
                "history_max_size": 6291456, "custom_data": {},
                "format_version": (format_version or kdbx.VERSION_4),
                "cipher": (cipher or "aes256").lower(),
                "kdf": (kdf or "argon2id").lower(),
                "kdf_parameters": {},
                "iterations": iterations, "memory_kib": memory_kib,
                "parallelism": parallelism, "rounds": rounds,
                "public_custom_data": {}}
        vault = cls(meta, root, path, password, keyfile, challenge_response)
        general = {
            "uuid": uuidlib.uuid4().bytes,
            "name": "General",
            "notes": "",
            "icon": 48,
            "times": _blank_times(),
            "expanded": True,
            "custom_data": {},
            "entries": [],
            "groups": [],
        }
        if initial_group:
            root["groups"].append(general)
        vault._reindex()
        vault.save(password)
        return vault

    @classmethod
    def open(cls, path, password, keyfile=None, challenge_response=None):
        meta, root = kdbx.read_database(path, password, keyfile,
                                        challenge_response)
        return cls(meta, root, path, password, keyfile, challenge_response)

    def cryptography_summary(self):
        """A sentence describing how this database is encrypted and locked."""
        settings = self.meta.get("kdf_parameters") or {}
        if (self.meta.get("kdf") or "") in ("argon2id", "argon2d"):
            cost = (lang.t(
                "dialogs", "mib_of_memory_passes_lanes",
                "{memory} MiB of memory, {passes} passes, {lanes} lanes",
                memory=(int(settings.get('M') or 0) // (1024 * 1024)) or 0,
                passes=int(settings.get('I') or 0),
                lanes=int(settings.get('P') or 0)))
        elif "R" in settings:
            cost = lang.t(
                "dialogs", "aes_rounds",
                "{rounds} AES rounds",
                rounds=int(settings.get('R') or 0))
        else:
            cost = lang.t(
                "dialogs", "unknown_cost_settings",
                "unknown cost settings")
        locked_with = []
        if self.password:
            locked_with.append(lang.t(
                "dialogs", "a_master_password",
                "a master password"))
        if self.keyfile:
            locked_with.append(lang.t("dialogs", "a_key_file", "a key file"))
        if self.challenge_response:
            locked_with.append(lang.t(
                "dialogs", "a_security_key",
                "a security key"))
        return (lang.t(
            "dialogs", "unlocked_with",
            "{cipher}, {kdf} ({cost}), unlocked with {parts}.",
            cipher=kdbx.CIPHER_LABELS.get(self.meta.get('cipher'), self.meta.get('cipher')),
            kdf=kdbx.KDF_LABELS.get(self.meta.get('kdf'), self.meta.get('kdf')),
            cost=cost,
            parts=lang.t("dialogs", "and", " and ").join(locked_with) or lang.t(
                "dialogs", "nothing",
                "nothing")))

    def close(self):
        self.dirty = False

    def save(self, password=None, backup=True, iterations=None, memory_kib=None,
             parallelism=None, rounds=None, cipher=None, kdf=None):
        """Write the database, keeping whatever cryptography it already used.

        The cipher, the key derivation function and their cost settings are
        taken from the database that was opened, so a ChaCha20 or AES-KDF
        database stays ChaCha20 or AES-KDF.  Passing one of the keyword
        arguments overrides that choice for this save.
        """
        if self.path is None:
            raise ValueError("The vault has no file path.")
        if password:
            self.password = password
            carried = getattr(password, "keyfile", None)
            if carried:
                self.keyfile = carried
            carried_key = getattr(password, "challenge_response", None)
            if carried_key:
                self.challenge_response = carried_key
        self.meta["name"] = self.meta.get("name") or "ZKeypass"
        options = {
            "iterations": iterations or int(self.meta.get("iterations") or 5),
            "memory_kib": memory_kib or int(self.meta.get("memory_kib") or 65536),
            "parallelism": parallelism or int(self.meta.get("parallelism") or 4),
            "rounds": rounds or int(self.meta.get("rounds") or 600000),
        }
        if cipher:
            self.meta["cipher"] = cipher
        if kdf:
            self.meta["kdf"] = kdf
        if backup and os.path.isfile(self.path):
            self._backup()
        kdbx.write_database(self.path, self.meta, self.root, self.password,
                            self.keyfile,
                            challenge_response=self.challenge_response, **options)
        self.dirty = False

    def _backup(self):
        """Keep the previous copy of the database before it is replaced."""
        paths.keep_backup(self.path)

    # -------------------------------------------------------------- internals

    def _reindex(self):
        """(Re)number every group and entry and remember where each lives."""
        self._groups = {}
        self._entries = {}
        self._next_id = 1
        self._number_group(self.root)

    def _new_id(self):
        value = self._next_id
        self._next_id += 1
        return value

    def _number_group(self, group):
        group["_id"] = self._new_id()
        self._groups[group["_id"]] = group
        for entry in group.get("entries", []):
            entry["_id"] = self._new_id()
            entry["_group"] = group
            self._entries[entry["_id"]] = entry
        for child in group.get("groups", []):
            child["_parent"] = group
            self._number_group(child)

    def _group_of(self, group_id):
        return self._groups.get(group_id)

    def _entry_of(self, entry_id):
        return self._entries.get(entry_id)

    def _parents(self):
        """Map every group to its parent group id."""
        parents = {}
        for group in self._groups.values():
            for child in group.get("groups", []):
                parents[child.get("_id")] = group.get("_id")
        return parents

    # ----------------------------------------------------------------- groups

    def groups(self):
        out = []
        parents = self._parents()
        for group in self._groups.values():
            if group.get("_id") == self.root.get("_id"):
                continue
            name = group.get("name", "")
            parent_id = parents.get(group.get("_id"))
            parent = self._groups.get(parent_id)
            if parent and parent.get("_id") != self.root.get("_id"):
                name = f"{parent.get('name', '')}/{name}"
            out.append({"id": group.get("_id"), "name": name,
                        "icon": str(group.get("icon", 48))})
        out.sort(key=lambda item: item["name"].lower())
        return out

    def group_name(self, group_id):
        group = self._group_of(group_id)
        return group.get("name", "") if group else ""

    def add_group(self, name):
        parent = self._default_parent()
        group = {
            "uuid": uuidlib.uuid4().bytes,
            "name": name,
            "notes": "",
            "icon": 48,
            "times": _blank_times(),
            "expanded": True,
            "custom_data": {},
            "entries": [],
            "groups": [],
            "_parent": parent,
            "_id": self._new_id(),
        }
        parent.setdefault("groups", []).append(group)
        self._groups[group["_id"]] = group
        self.dirty = True
        return group["_id"]

    def _default_parent(self):
        for group in self.root.get("groups", []):
            return group
        return self.root

    def rename_group(self, group_id, name):
        group = self._group_of(group_id)
        if group:
            group["name"] = name
            group["times"] = {"LastModificationTime": _now(),
                              **(group.get("times") or {})}
            self.dirty = True

    def delete_group(self, group_id):
        group = self._group_of(group_id)
        if not group:
            return
        parent = group.get("_parent") or self.root
        for entry in group.get("entries", []):
            self._entries.pop(entry.get("_id"), None)
        if "groups" in parent:
            parent["groups"] = [child for child in parent["groups"]
                                if child is not group]
        if "entries" in parent:
            parent["entries"] = [item for item in parent["entries"]
                                 if item is not group]
        self._groups.pop(group_id, None)
        for child in group.get("groups", []):
            self._forget_group(child)
        for entry in group.get("entries", []):
            self._entries.pop(entry.get("_id"), None)
        self.dirty = True

    def _forget_group(self, group):
        for entry in group.get("entries", []):
            self._entries.pop(entry.get("_id"), None)
        self._groups.pop(group.get("_id"), None)
        for child in group.get("groups", []):
            self._forget_group(child)

    # ---------------------------------------------------------------- entries

    def _field_map(self, entry):
        return {key: value for key, value, _protect in entry.get("fields", [])}

    def _tags(self, entry):
        return [tag.strip() for tag in (entry.get("tags") or "").split(",")
                if tag.strip()]

    def _set_tag(self, entry, tag, present):
        tags = [item for item in self._tags(entry) if item.lower() != tag.lower()]
        if present:
            tags.append(tag)
        entry["tags"] = ", ".join(tags)

    def to_record(self, entry):
        fields = self._field_map(entry)
        two_factor = totp_from_fields(fields)
        period = two_factor["period"]
        digits = two_factor["digits"]
        times = entry.get("times") or {}
        group = entry.get("_group")
        return {
            "id": entry.get("_id"),
            "group_id": group.get("_id") if group else None,
            "group_name": group.get("name", "") if group else "",
            "title": fields.get("Title", ""),
            "username": fields.get("UserName", ""),
            "password": fields.get("Password", ""),
            "url": fields.get("URL", ""),
            "notes": fields.get("Notes", ""),
            "totp_secret": two_factor["secret"],
            "totp_digits": digits,
            "totp_period": period,
            "totp_algorithm": two_factor["algorithm"],
            "expires": _stamp(times.get("ExpiryTime")) if times.get("Expires") else 0,
            "created": _stamp(times.get("CreationTime")),
            "modified": _stamp(times.get("LastModificationTime")),
            "favourite": 1 if FAVOURITE_TAG in self._tags(entry) else 0,
        }

    def _group_entries(self, group):
        for entry in group.get("entries", []):
            yield entry
        for child in group.get("groups", []):
            yield from self._group_entries(child)

    def entries(self, group_id=None, search=None, favourites_only=False):
        records = []
        for entry in self._entries.values():
            record = self.to_record(entry)
            if group_id is not None and record["group_id"] != group_id:
                continue
            if favourites_only and not record["favourite"]:
                continue
            if search:
                needle = search.lower()
                haystack = " ".join((record["title"], record["username"],
                                     record["url"], record["notes"])).lower()
                if needle not in haystack:
                    continue
            records.append(record)
        records.sort(key=lambda item: (item["title"] or "").lower())
        return records

    def entries_with_totp(self, group_id=None, search=None):
        """Only the entries with a genuine setup key, for the Authenticator."""
        from . import totp

        return [entry for entry in self.entries(group_id=group_id, search=search)
                if totp.has_code(entry)]

    def entry_count(self):
        return len(self._entries)

    def get_entry(self, entry_id):
        entry = self._entry_of(entry_id)
        return self.to_record(entry) if entry else None

    def save_entry(self, entry):
        now = _now()
        entry_id = entry.get("id")
        if entry_id and entry_id in self._entries:
            target = self._entries[entry_id]
        else:
            group = self._group_of(entry.get("group_id")) or \
                self._default_parent() or self.root
            target = {
                "uuid": uuidlib.uuid4().bytes,
                "icon": 0,
                "tags": "",
                "times": _blank_times(),
                "fields": [],
                "binaries": {},
                "custom_data": {},
                "autotype": None,
                "history": [],
                "override_url": "",
                "foreground": "",
                "background": "",
                "_id": self._new_id(),
            }
            self._entries[target["_id"]] = target
            self._attach(target, group)
            entry_id = target["_id"]

        previous = self._field_map(target)
        fields = {}
        for key in STANDARD_FIELDS:
            fields[key] = entry.get({"Title": "title", "UserName": "username",
                                     "Password": "password", "URL": "url",
                                     "Notes": "notes"}[key], "") or ""
        for attribute in entry.get("_attributes", []) or []:
            fields[attribute["name"]] = attribute["value"]
        for name, value in (previous.items()):
            if name in HIDDEN_ATTRIBUTES or name in fields:
                continue
            if name not in STANDARD_FIELDS:
                fields[name] = value
        if entry.get("totp_secret"):
            seed = entry["totp_secret"].strip()
            period = int(entry.get("totp_period") or 30)
            digits = int(entry.get("totp_digits") or 6)
            algorithm = (entry.get("totp_algorithm") or "SHA1").upper() or "SHA1"
            fields[TOTP_SEED_ATTRIBUTE] = seed
            fields[TOTP_SETTINGS_ATTRIBUTE] = f"{period};{digits}"
            if algorithm != "SHA1":
                fields[TOTP_ALGORITHM_ATTRIBUTE] = algorithm
            else:
                fields.pop(TOTP_ALGORITHM_ATTRIBUTE, None)
            # Keep the one-attribute "otp" spelling in step when the database
            # was written that way, so KeePassXC 2.7 and the KeePass Android
            # ports keep showing the same code.
            if OTP_ATTRIBUTE in previous:
                from . import totp

                fields[OTP_ATTRIBUTE] = totp.build_otpauth_url(
                    entry.get("title") or "", entry.get("username") or "",
                    seed, digits=digits, period=period, algorithm=algorithm)
        else:
            fields.pop(TOTP_SEED_ATTRIBUTE, None)
            fields.pop(TOTP_SETTINGS_ATTRIBUTE, None)
            fields.pop(TOTP_ALGORITHM_ATTRIBUTE, None)
            fields.pop(OTP_ATTRIBUTE, None)

        target["fields"] = []
        for key in STANDARD_FIELDS:
            target["fields"].append([key, fields.pop(key, ""),
                                     key == "Password"])
        protected = (OTP_ATTRIBUTE, TOTP_SEED_ATTRIBUTE, TOTP_SETTINGS_ATTRIBUTE,
                     TOTP_ALGORITHM_ATTRIBUTE)
        for name in sorted(fields, key=str.lower):
            target["fields"].append([name, fields[name], name in protected])

        target["expires"] = entry.get("expires") or 0
        self._field_map(target)
        times = target.setdefault("times", _blank_times())
        times["LastModificationTime"] = now
        if entry.get("expires"):
            times["ExpiryTime"] = datetime.fromtimestamp(
                float(entry["expires"]), timezone.utc)
            times["Expires"] = True
        else:
            times["Expires"] = False
        self._set_tag(target, FAVOURITE_TAG, bool(entry.get("favourite")))
        new_group = self._group_of(entry.get("group_id"))
        if new_group and target.get("_group") is not new_group:
            self._detach(target)
            self._attach(target, new_group)
        self.dirty = True
        return entry_id

    def _attach(self, entry, group):
        group.setdefault("entries", []).append(entry)
        entry["_group"] = group

    def _detach(self, entry):
        group = entry.get("_group")
        if group and "entries" in group:
            group["entries"] = [item for item in group["entries"]
                                if item is not entry]
        entry.pop("_group", None)

    def delete_entry(self, entry_id):
        entry = self._entries.pop(entry_id, None)
        if entry:
            self._detach(entry)
            self.dirty = True

    def rename_entry(self, entry_id, title):
        """Change only the name, leaving every other field exactly as it is."""
        entry = self._entry_of(entry_id)
        if not entry:
            return
        fields = entry.setdefault("fields", [])
        for field in fields:
            if field[0] == "Title":
                field[1] = title
                break
        else:
            fields.insert(0, ["Title", title, False])
        entry.setdefault("times", _blank_times())["LastModificationTime"] = _now()
        self.dirty = True

    def duplicate_entry(self, entry_id):
        entry = self._entry_of(entry_id)
        if not entry:
            return None
        record = self.to_record(entry)
        record.pop("id", None)
        record["title"] = lang.t(
            "dialogs", "copy_2",
            "{title} copy",
            title=record.get('title', ''))
        record["_attributes"] = [
            {"name": item["name"], "value": item["value"]}
            for item in self.attributes(entry_id)]
        new_id = self.save_entry(record)
        for name, payload in (entry.get("binaries") or {}).items():
            self.add_attachment(new_id, name, payload)
        return new_id

    def set_favourite(self, entry_id, favourite):
        entry = self._entry_of(entry_id)
        if entry:
            self._set_tag(entry, FAVOURITE_TAG, bool(favourite))
            self.dirty = True

    def set_username(self, entry_id, username):
        """Change only the user name, leaving every other field as it is."""
        entry = self._entry_of(entry_id)
        if not entry:
            return
        fields = entry.setdefault("fields", [])
        for field in fields:
            if field[0] == "UserName":
                field[1] = username
                break
        else:
            fields.append(["UserName", username, False])
        entry.setdefault("times", _blank_times())["LastModificationTime"] = _now()
        self.dirty = True

    def move_entry(self, entry_id, group_id):
        entry = self._entry_of(entry_id)
        group = self._group_of(group_id)
        if entry and group:
            self._detach(entry)
            self._attach(entry, group)
            self.dirty = True

    # ------------------------------------------------------------- attributes

    @staticmethod
    def _attribute_id(entry_id, position):
        """A non-zero id that still says which field of which entry it is."""
        return (int(entry_id) << 16) | (position + 1)

    @staticmethod
    def _split_attribute_id(attribute_id):
        return int(attribute_id) >> 16, (int(attribute_id) & 0xFFFF) - 1

    def attributes(self, entry_id):
        entry = self._entry_of(entry_id)
        if not entry:
            return []
        out = []
        for position, (key, value, _protect) in enumerate(entry.get("fields", [])):
            if key in STANDARD_FIELDS or key in HIDDEN_ATTRIBUTES:
                continue
            out.append({"id": self._attribute_id(entry_id, position),
                        "entry_id": entry_id, "name": key,
                        "value": value, "hidden": 0})
        out.sort(key=lambda item: item["name"].lower())
        return out

    def add_attribute(self, entry_id, name, value, hidden=False):
        entry = self._entry_of(entry_id)
        if not entry:
            return None
        fields = entry.setdefault("fields", [])
        for position, item in enumerate(fields):
            if item[0] == name:
                item[1] = value
                item[2] = bool(hidden)
                self.dirty = True
                return self._attribute_id(entry_id, position)
        fields.append([name, value, bool(hidden)])
        self.dirty = True
        return self._attribute_id(entry_id, len(fields) - 1)

    def update_attribute(self, attribute_id, name, value, hidden=False):
        entry_id, position = self._split_attribute_id(attribute_id)
        entry = self._entry_of(entry_id)
        if not entry:
            return
        fields = entry.get("fields", [])
        if 0 <= position < len(fields) and fields[position][0] not in STANDARD_FIELDS:
            fields[position] = [name, value, bool(hidden)]
            self.dirty = True

    def delete_attribute(self, attribute_id):
        entry_id, position = self._split_attribute_id(attribute_id)
        entry = self._entry_of(entry_id)
        if not entry:
            return
        fields = entry.get("fields", [])
        if 0 <= position < len(fields) and fields[position][0] not in STANDARD_FIELDS:
            del fields[position]
            self.dirty = True

    # ------------------------------------------------------------ attachments

    def attachments(self, entry_id):
        entry = self._entry_of(entry_id)
        if not entry:
            return []
        out = []
        for position, name in enumerate(sorted(entry.get("binaries", {})),
                                        start=1):
            payload = entry["binaries"][name]
            out.append({"id": (entry_id, name), "entry_id": entry_id,
                        "name": name, "size": len(payload)})
        return out

    def add_attachment(self, entry_id, name, data):
        entry = self._entry_of(entry_id)
        if not entry:
            return None
        entry.setdefault("binaries", {})[name] = bytes(data)
        self.dirty = True
        return (entry_id, name)

    def attachment_data(self, attachment_id):
        if isinstance(attachment_id, tuple) and len(attachment_id) == 2:
            entry = self._entry_of(attachment_id[0])
            if entry:
                return entry.get("binaries", {}).get(attachment_id[1], b"")
        return b""

    def delete_attachment(self, attachment_id):
        if isinstance(attachment_id, tuple) and len(attachment_id) == 2:
            entry = self._entry_of(attachment_id[0])
            if entry:
                entry.get("binaries", {}).pop(attachment_id[1], None)
                self.dirty = True

    def import_file(self, entry_id, source_path):
        with open(source_path, "rb") as handle:
            data = handle.read()
        return self.add_attachment(entry_id, os.path.basename(source_path), data)

    def export_attachment(self, attachment_id, destination_dir):
        data = self.attachment_data(attachment_id)
        if not data or not isinstance(attachment_id, tuple):
            return None
        target = os.path.join(destination_dir, attachment_id[1])
        with open(target, "wb") as handle:
            handle.write(data)
        return target

    def attachment_name(self, attachment_id):
        if isinstance(attachment_id, tuple) and len(attachment_id) == 2:
            return attachment_id[1]
        return ""

    # ---------------------------------------------------------------- reports

    def all_entries_for_audit(self):
        return self.entries()

    def statistics(self):
        records = self.entries()
        return {
            "entries": len(records),
            "groups": len([item for item in self._groups.values()
                           if item.get("_id") != self.root.get("_id")]),
            "with_totp": sum(1 for item in records if _has_code(item)),
            "with_attachments": sum(1 for item in records
                                    if item.get("id") in self._entries
                                    and self._entries[item["id"]].get("binaries")),
            "favourites": sum(1 for item in records if item.get("favourite")),
        }

def _has_code(record):
    from . import totp

    return totp.has_code(record)


def totp_from_fields(fields):
    """Read a two-factor secret however the database happened to store it.

    Three layouts are in common use.  The classic KeePassXC pair of attributes
    "TOTP Seed" and "TOTP Settings".  The single hidden attribute "otp" holding
    a full otpauth:// link, which is what KeePassXC 2.7 writes and what
    KeePassDX and KeePass2Android use.  And an "otp" attribute holding a bare
    Base32 seed.  All three are read here, so an entry that shows a code in
    another program shows one in ZKeypass as well.
    """
    from . import totp

    secret = ""
    digits, period, algorithm = 6, 30, "SHA1"
    from_link = False

    def take(value):
        """Split a stored value into a seed and, for a link, its settings."""
        nonlocal secret, digits, period, algorithm, from_link
        text = (value or "").strip()
        if not text:
            return False
        if text.lower().startswith("otpauth://"):
            parsed = totp.parse_otpauth(text) or {}
            secret = parsed.get("secret") or ""
            digits = int(parsed.get("digits") or 6)
            period = int(parsed.get("period") or 30)
            algorithm = (parsed.get("algorithm") or "SHA1").upper()
            from_link = True
            return bool(secret)
        secret = text
        return True

    if not take(fields.get(OTP_ATTRIBUTE)):
        for name in (TOTP_SEED_ATTRIBUTE,) + TOTP_ALIASES:
            if take(fields.get(name)):
                break

    if secret and not from_link:
        settings = (fields.get(TOTP_SETTINGS_ATTRIBUTE) or "").split(";")
        try:
            period = int(settings[0])
        except (ValueError, IndexError):
            pass
        try:
            digits = int(settings[1])
        except (ValueError, IndexError):
            pass
        stored = (fields.get(TOTP_ALGORITHM_ATTRIBUTE) or "").upper()
        if stored:
            algorithm = stored

    return {"secret": secret, "digits": digits, "period": period,
            "algorithm": algorithm}


def _blank_times():
    now = _now()
    return {"LastModificationTime": now, "CreationTime": now,
            "LastAccessTime": now, "ExpiryTime": None, "Expires": False,
            "UsageCount": 0, "LocationChanged": now}


def is_kdbx(path):
    return bool(path) and path.lower().endswith(".kdbx")


def open_any(path, password, keyfile=None, challenge_response=None):
    """Open a vault of either format, choosing by the name then by the header."""
    if is_kdbx(path) or (keyfile and detect_format(path) != "zkp"):
        return KdbxVault.open(path, password, keyfile, challenge_response)
    from .vault import Vault
    return Vault.open(path, password)


def create_any(path, password, keyfile=None, challenge_response=None, **options):
    if is_kdbx(path) or (keyfile and detect_format(path) != "zkp"):
        return KdbxVault.create(path, password, keyfile, challenge_response,
                                **options)
    from .vault import Vault
    return Vault.create(path, password)


def detect_format(path):
    try:
        with open(path, "rb") as handle:
            head = handle.read(8)
    except OSError:
        return "unknown"
    if head[:4] == kdbx.SIG1.to_bytes(4, "little"):
        return "kdbx"
    from .crypto import MAGIC
    if head[:len(MAGIC)] == MAGIC:
        return "zkp"
    return "unknown"
