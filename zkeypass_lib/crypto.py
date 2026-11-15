"""Master-key derivation and authenticated encryption for the vault file.

Uses only the 'cryptography' package, which ships as a portable wheel inside
the application folder.  The current vault file format is:

    magic        8 bytes   b"ZKPASS02"
    cipher id    1 byte    1 AES-256-GCM, 2 ChaCha20-Poly1305
    kdf id       1 byte    1 Argon2id, 2 scrypt, 3 PBKDF2-HMAC-SHA256
    salt length  2 bytes   big endian
    salt         as above
    nonce length 2 bytes   big endian
    nonce        as above
    ciphertext   ...       authenticated with the chosen AEAD, the whole
                           header above is used as additional data

Files written by the very first build began with b"ZKPASS01" and had no
cipher or KDF byte; they are still read, always as AES-256-GCM with Argon2id.
"""

import os
import struct

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from . import lang

# The first format wrote no cipher or KDF identifier, so it is recognised by
# its own magic and always means AES-256-GCM with Argon2id.
MAGIC_V1 = b"ZKPASS01"
MAGIC = b"ZKPASS02"
MAGIC_LEN = 8
SALT_LEN = 16
NONCE_LEN = 12
HEADER_LEN = len(MAGIC_V1) + SALT_LEN + NONCE_LEN

# Modest parameters: unlock stays under a second on an ordinary CPU while
# still costing an attacker 64 MiB and three passes per guess.
ARGON2_TIME_COST = 3
ARGON2_MEMORY_KIB = 65536
ARGON2_PARALLELISM = 4
KEY_LEN = 32

PBKDF2_ITERATIONS = 600_000

SCRYPT_N = 2 ** 15
SCRYPT_R = 8
SCRYPT_P = 1

# Identifier byte values stored in the file header.
CIPHER_IDS = {"aesgcm": 1, "chacha20poly1305": 2}
CIPHER_NAMES = {value: name for name, value in CIPHER_IDS.items()}
CIPHER_LABELS = lang.Labels("dialogs", "zkp_cipher_", {
    "aesgcm": "AES-256-GCM, hardware accelerated",
    "chacha20poly1305": "ChaCha20-Poly1305, stream cipher",
})
KDF_IDS = {"argon2id": 1, "scrypt": 2, "pbkdf2": 3}
KDF_NAMES = {value: name for name, value in KDF_IDS.items()}
KDF_LABELS = lang.Labels("dialogs", "zkp_kdf_", {
    "argon2id": "Argon2id, memory hard, recommended",
    "scrypt": "scrypt, memory hard alternative",
    "pbkdf2": "PBKDF2-HMAC-SHA256, widely compatible",
})
DEFAULT_CIPHER = "aesgcm"
DEFAULT_KDF = "argon2id"


def new_salt():
    return os.urandom(SALT_LEN)


def _argon2_available():
    try:
        Argon2id  # noqa: B018  (name lookup only)
        return True
    except NameError:
        return False


def derive_key(password, salt, kdf=DEFAULT_KDF, memory_kib=ARGON2_MEMORY_KIB,
               time_cost=ARGON2_TIME_COST, parallelism=ARGON2_PARALLELISM,
               iterations=PBKDF2_ITERATIONS, scrypt_n=SCRYPT_N,
               scrypt_r=SCRYPT_R, scrypt_p=SCRYPT_P):
    """Stretch the master password into a 32 byte key with the chosen KDF."""
    password = password.encode("utf-8")
    kdf = (kdf or DEFAULT_KDF).lower()
    if kdf == "argon2id" and _argon2_available():
        kdf_object = Argon2id(salt=salt, length=KEY_LEN, iterations=time_cost,
                              lanes=parallelism, memory_cost=memory_kib)
        return kdf_object.derive(password)
    if kdf in ("argon2id", "scrypt"):
        kdf_object = Scrypt(salt=salt, length=KEY_LEN, n=scrypt_n,
                            r=scrypt_r, p=scrypt_p)
        return kdf_object.derive(password)
    kdf_object = PBKDF2HMAC(algorithm=hashes.SHA256(), length=KEY_LEN,
                            salt=salt, iterations=iterations)
    return kdf_object.derive(password)


def _aead(cipher):
    cipher = (cipher or DEFAULT_CIPHER).lower()
    if cipher == "chacha20poly1305":
        return ChaCha20Poly1305, cipher
    return AESGCM, "aesgcm"


def encrypt(plaintext, password, cipher=DEFAULT_CIPHER, kdf=DEFAULT_KDF,
            **options):
    """Seal plaintext into a vault file with the chosen cipher and KDF."""
    aead_class, cipher_name = _aead(cipher)
    kdf_name = (kdf or DEFAULT_KDF).lower()
    if kdf_name not in KDF_IDS:
        raise VaultError(lang.t(
            "errors", "unknown_key_derivation_function",
            "Unknown key derivation function '{kdf}'.",
            kdf=kdf))
    salt = new_salt()
    nonce = os.urandom(NONCE_LEN)
    key = derive_key(password, salt, kdf_name, **options)
    header = (MAGIC + bytes([CIPHER_IDS[cipher_name], KDF_IDS[kdf_name]])
              + struct.pack(">H", len(salt)) + salt
              + struct.pack(">H", len(nonce)) + nonce)
    body = aead_class(key).encrypt(nonce, plaintext, header)
    return header + body


def decrypt(blob, password, **options):
    """Return vault plaintext or raise VaultError with a readable message."""
    if blob[:len(MAGIC_V1)] == MAGIC_V1:
        return _decrypt_v1(blob, password)
    if blob[:len(MAGIC)] != MAGIC:
        raise VaultError(lang.t(
            "errors", "this_is_not_a_zkeypass_vault",
            "This is not a ZKeypass vault file."))
    if len(blob) < MAGIC_LEN + 2 + 2:
        raise VaultError(lang.t(
            "errors", "this_zkeypass_vault_file_is_truncated",
            "This ZKeypass vault file is truncated."))
    cipher_name = CIPHER_NAMES.get(blob[MAGIC_LEN])
    kdf_name = KDF_NAMES.get(blob[MAGIC_LEN + 1])
    if cipher_name is None or kdf_name is None:
        raise VaultError(lang.t(
            "errors", "this_zkeypass_vault_uses_an_unknown",
            "This ZKeypass vault uses an unknown cipher or KDF."))
    salt_len = struct.unpack_from(">H", blob, MAGIC_LEN + 2)[0]
    position = MAGIC_LEN + 4
    salt = blob[position:position + salt_len]
    position += salt_len
    nonce_len = struct.unpack_from(">H", blob, position)[0]
    position += 2
    nonce = blob[position:position + nonce_len]
    position += nonce_len
    header = blob[:position]
    key = derive_key(password, salt, kdf_name, **options)
    aead_class, _ = _aead(cipher_name)
    try:
        return aead_class(key).decrypt(nonce, blob[position:], header)
    except Exception:
        raise VaultError(lang.t(
            "errors", "wrong_master_password_or_the_vault",
            "Wrong master password, or the vault file is damaged."))


def describe(blob):
    """Return (cipher, kdf) for a vault file without unlocking it."""
    if blob[:len(MAGIC_V1)] == MAGIC_V1:
        return "aesgcm", "argon2id"
    if blob[:len(MAGIC)] != MAGIC:
        return "unknown", "unknown"
    names = CIPHER_NAMES.get(blob[MAGIC_LEN]), KDF_NAMES.get(blob[MAGIC_LEN + 1])
    return names[0] or "unknown", names[1] or "unknown"


def _decrypt_v1(blob, password):
    """Read the original format, which had no cipher or KDF byte."""
    if len(blob) < HEADER_LEN:
        raise VaultError(lang.t(
            "errors", "this_zkeypass_vault_file_is_truncated",
            "This ZKeypass vault file is truncated."))
    salt = blob[len(MAGIC_V1): len(MAGIC_V1) + SALT_LEN]
    nonce = blob[len(MAGIC_V1) + SALT_LEN: HEADER_LEN]
    header = blob[:HEADER_LEN]
    key = derive_key(password, salt, DEFAULT_KDF)
    try:
        return AESGCM(key).decrypt(nonce, blob[HEADER_LEN:], header)
    except Exception:
        raise VaultError(lang.t(
            "errors", "wrong_master_password_or_the_vault",
            "Wrong master password, or the vault file is damaged."))


class VaultError(Exception):
    pass


def atomic_write(path, data):
    """Write bytes beside the target and rename, so a crash cannot truncate."""
    tmp = path + ".tmp"
    with open(tmp, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)


def pack_u32(value):
    return struct.pack(">I", value)
