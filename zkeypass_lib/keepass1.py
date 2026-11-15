"""Read a KeePass 1.x `.kdb` database.

KeePass 1 files still turn up in old backups.  They are read here and brought
into the open database as new entries; ZKeypass does not write the old format.
The body is AES-256-CBC or Twofish-256-CBC (the Twofish code from phase 1),
chosen by a flag in the header.

Layout, all little-endian (KeePass 1 "KDB" format):

    0   signature 1   0x9AA2D903
    4   signature 2   0xB54BFB65
    8   flags         bit 1 SHA-2, 2 AES, 4 ArcFour, 8 Twofish
    12  version       0x0003xxxx
    16  master seed   16 bytes
    32  encryption IV 16 bytes
    48  group count   4 bytes
    52  entry count   4 bytes
    56  contents hash SHA-256 of the decrypted body, 32 bytes
    88  transform seed 32 bytes
    120 key rounds    4 bytes
    124 body          encrypted from here

The key is SHA-256 of the password, put through AES-KDF (encrypt the key with
the transform seed, that many rounds, then hash), then SHA-256 of the master
seed followed by that.  The body is a flat list of groups then entries, each a
run of (type, size, data) fields ended by a 0xFFFF field; group "levels" give
the tree.  KeePass's own "Meta-Info" bookkeeping entries are skipped.
"""

import hashlib
import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from . import twofish
from . import lang

SIGNATURE_1 = 0x9AA2D903
SIGNATURE_2 = 0xB54BFB65

FLAG_SHA2 = 1
FLAG_AES = 2
FLAG_ARCFOUR = 4
FLAG_TWOFISH = 8


class KeePass1Error(Exception):
    """A `.kdb` file that could not be read, with a plain-English reason."""


def is_kdb(path):
    """True when the file starts with the KeePass 1 signature."""
    try:
        with open(path, "rb") as handle:
            sig1, sig2 = struct.unpack("<II", handle.read(8))
        return sig1 == SIGNATURE_1 and sig2 == SIGNATURE_2
    except (OSError, struct.error):
        return False


def _transform_key(key, seed, rounds):
    """KeePass 1 AES-KDF: encrypt the key with the seed, that many rounds."""
    encryptor = Cipher(algorithms.AES(seed), modes.ECB()).encryptor()  # noqa: S305
    block = bytes(key)
    for _ in range(rounds):
        block = encryptor.update(block)
    block += encryptor.finalize()
    return hashlib.sha256(block).digest()


def _strip_pkcs7(data):
    if not data:
        return data
    pad = data[-1]
    if 1 <= pad <= 16 and data[-pad:] == bytes([pad]) * pad:
        return data[:-pad]
    return data


def _cstr(data):
    """A KeePass 1 string: UTF-8, with its terminating null removed."""
    return data.split(b"\x00", 1)[0].decode("utf-8", "replace")


def _fields(body, offset):
    """Yield (type, data) from offset until a 0xFFFF field; return the new
    offset after it."""
    fields = []
    while offset + 6 <= len(body):
        field_type, size = struct.unpack_from("<HI", body, offset)
        offset += 6
        data = body[offset:offset + size]
        offset += size
        fields.append((field_type, data))
        if field_type == 0xFFFF:
            break
    return fields, offset


def _group_paths(groups):
    """Full "parent/child" path for each group id, from the level column."""
    paths = {}
    stack = []
    for group in groups:
        level = group["level"]
        del stack[level:]
        stack.append(group["name"])
        paths[group["id"]] = "/".join(name for name in stack if name)
    return paths


def parse(path, password):
    """Return entry dictionaries from the `.kdb` file at path."""
    with open(path, "rb") as handle:
        raw = handle.read()
    if len(raw) < 124:
        raise KeePass1Error(lang.t(
            "errors", "this_file_is_too_short_to",
            "This file is too short to be a KeePass 1 database."))
    sig1, sig2, flags, _version = struct.unpack_from("<IIII", raw, 0)
    if sig1 != SIGNATURE_1 or sig2 != SIGNATURE_2:
        raise KeePass1Error(lang.t(
            "errors", "this_is_not_a_keepass_1",
            "This is not a KeePass 1 database."))
    master_seed = raw[16:32]
    iv = raw[32:48]
    group_count, entry_count = struct.unpack_from("<II", raw, 48)
    contents_hash = raw[56:88]
    transform_seed = raw[88:120]
    rounds = struct.unpack_from("<I", raw, 120)[0]
    body = raw[124:]

    if flags & FLAG_ARCFOUR:
        raise KeePass1Error(lang.t(
            "errors", "this_database_uses_the_arcfour_cipher",
            "This database uses the ArcFour cipher, which ZKeypass does not "
            "support."))

    key = _transform_key(hashlib.sha256(password.encode("utf-8")).digest(),
                         transform_seed, rounds)
    final_key = hashlib.sha256(master_seed + key).digest()

    if flags & FLAG_TWOFISH:
        plain = _strip_pkcs7(twofish.cbc_decrypt(final_key, iv, body))
    else:
        decryptor = Cipher(algorithms.AES(final_key), modes.CBC(iv)).decryptor()
        plain = _strip_pkcs7(decryptor.update(body) + decryptor.finalize())

    if hashlib.sha256(plain).digest() != contents_hash:
        raise KeePass1Error(lang.t(
            "errors", "that_password_did_not_unlock_the_2",
            "That password did not unlock the database. Check it and try "
            "again."))

    return _read_body(plain, group_count, entry_count)


def _read_body(plain, group_count, entry_count):
    offset = 0
    groups = []
    for _ in range(group_count):
        fields, offset = _fields(plain, offset)
        group = {"id": None, "name": "", "level": 0}
        for field_type, data in fields:
            if field_type == 0x0001:
                group["id"] = struct.unpack("<I", data)[0]
            elif field_type == 0x0002:
                group["name"] = _cstr(data)
            elif field_type == 0x0008:
                group["level"] = struct.unpack("<H", data)[0]
        groups.append(group)
    paths = _group_paths(groups)

    entries = []
    for _ in range(entry_count):
        fields, offset = _fields(plain, offset)
        record = {"title": "", "username": "", "password": "", "url": "",
                  "notes": "", "group_id": None}
        for field_type, data in fields:
            if field_type == 0x0002:
                record["group_id"] = struct.unpack("<I", data)[0]
            elif field_type == 0x0004:
                record["title"] = _cstr(data)
            elif field_type == 0x0005:
                record["url"] = _cstr(data)
            elif field_type == 0x0006:
                record["username"] = _cstr(data)
            elif field_type == 0x0007:
                record["password"] = _cstr(data)
            elif field_type == 0x0008:
                record["notes"] = _cstr(data)
        # KeePass keeps its own settings in a "Meta-Info" entry; skip it.
        if record["title"] == "Meta-Info" and record["username"] == "SYSTEM":
            continue
        entries.append({
            "title": record["title"] or lang.t(
                "dialogs", "imported_entry",
                "(imported entry)"),
            "username": record["username"],
            "password": record["password"],
            "url": record["url"],
            "notes": record["notes"],
            "totp_secret": "",
            "group_name": paths.get(record["group_id"], ""),
        })
    return entries
