"""Passkeys: WebAuthn credentials stored inside the vault.

A passkey is a private key kept next to an entry, together with its
credential identifier, the relying party it belongs to and the user handle
that the site knows it by.  This is the same arrangement KeePassXC uses, with
the same entry attribute names, so passkeys survive a round trip in either
direction.

Attribute names, exactly as KeePassXC writes them:

    KPEX_PASSKEY_CREDENTIAL_ID
    KPEX_PASSKEY_PRIVATE_KEY_PEM
    KPEX_PASSKEY_USERNAME
    KPEX_PASSKEY_RELYING_PARTY
    KPEX_PASSKEY_USER_HANDLE

This module also carries a small CBOR writer and the WebAuthn shapes that a
browser expects: the COSE public key, the authenticator data blob, and the
attestation and assertion objects.  Supported algorithms are ES256 (ECDSA
over NIST P-256, the one every site accepts), EdDSA (Ed25519) and RS256.
"""

import base64
import hashlib
import os
import struct
import time

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import (
    decode_dss_signature,
)
from . import lang

ATTR_CREDENTIAL_ID = "KPEX_PASSKEY_CREDENTIAL_ID"
ATTR_PRIVATE_KEY = "KPEX_PASSKEY_PRIVATE_KEY_PEM"
ATTR_USERNAME = "KPEX_PASSKEY_USERNAME"
ATTR_RELYING_PARTY = "KPEX_PASSKEY_RELYING_PARTY"
ATTR_USER_HANDLE = "KPEX_PASSKEY_USER_HANDLE"

PASSKEY_ATTRIBUTES = (ATTR_CREDENTIAL_ID, ATTR_PRIVATE_KEY, ATTR_USERNAME,
                      ATTR_RELYING_PARTY, ATTR_USER_HANDLE)

# COSE algorithm identifiers.
ALGORITHM_ES256 = -7
ALGORITHM_EDDSA = -8
ALGORITHM_RS256 = -257

ALGORITHM_NAMES = lang.Labels("dialogs", "passkey_alg_", {
    ALGORITHM_ES256: "ES256, ECDSA over NIST P-256",
    ALGORITHM_EDDSA: "EdDSA, Ed25519",
    ALGORITHM_RS256: "RS256, RSA with PKCS 1 version 1.5",
})
ALGORITHM_IDS = {"ES256": ALGORITHM_ES256, "EdDSA": ALGORITHM_EDDSA,
                 "RS256": ALGORITHM_RS256}

# Authenticator data flags.
FLAG_USER_PRESENT = 0x01
FLAG_USER_VERIFIED = 0x04
FLAG_ATTESTED = 0x40
FLAG_EXTENSION_DATA = 0x80

DEFAULT_TIMEOUT_MS = 60000


class PasskeyError(Exception):
    """Raised with a message meant to be shown to the user."""


# ------------------------------------------------------------------- helpers

def b64url_encode(data):
    return base64.urlsafe_b64encode(bytes(data)).rstrip(b"=").decode("ascii")


def b64url_decode(text):
    if isinstance(text, bytes):
        text = text.decode("ascii")
    padding_needed = (-len(text)) % 4
    return base64.urlsafe_b64decode(text + "=" * padding_needed)


def random_credential_id(length=32):
    return os.urandom(length)


def random_user_handle(length=32):
    return os.urandom(length)


# ---------------------------------------------------------------------- CBOR

def cbor_encode(value):
    """Encode the subset of CBOR that WebAuthn needs."""
    if isinstance(value, bool):
        return b"\xf5" if value else b"\xf4"
    if value is None:
        return b"\xf6"
    if isinstance(value, int):
        return _cbor_int(value)
    if isinstance(value, bytes):
        return _cbor_bytes(0x40, value)
    if isinstance(value, str):
        return _cbor_bytes(0x60, value.encode("utf-8"))
    if isinstance(value, (list, tuple)):
        out = _cbor_length(0x80, len(value))
        for item in value:
            out += cbor_encode(item)
        return out
    if isinstance(value, dict):
        out = _cbor_length(0xA0, len(value))
        for key, item in value.items():
            out += cbor_encode(key) + cbor_encode(item)
        return out
    raise PasskeyError(f"Cannot encode {type(value).__name__} as CBOR.")


def _cbor_int(value):
    if value >= 0:
        return _cbor_length(0x00, value)
    return _cbor_length(0x20, -1 - value)


def _cbor_length(major, length):
    """Length prefix. 'major' is the already shifted major type byte."""
    if length < 24:
        return bytes([major | length])
    if length < 0x100:
        return bytes([major | 24, length])
    if length < 0x10000:
        return bytes([major | 25]) + struct.pack(">H", length)
    if length < 0x100000000:
        return bytes([major | 26]) + struct.pack(">I", length)
    return bytes([major | 27]) + struct.pack(">Q", length)


def _cbor_bytes(major, data):
    return _cbor_length(major, len(data)) + bytes(data)


# ------------------------------------------------------------------ key pairs

def generate_private_key(algorithm="ES256"):
    """Create a new passkey private key for the chosen algorithm."""
    name = (algorithm or "ES256").upper()
    if name in ("ES256", "ECDSA", "EC"):
        return ec.generate_private_key(ec.SECP256R1())
    if name in ("EDDSA", "ED25519"):
        return ed25519.Ed25519PrivateKey.generate()
    if name in ("RS256", "RSA"):
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    raise PasskeyError(lang.t(
        "errors", "unsupported_passkey_algorithm",
        "Unsupported passkey algorithm '{algorithm}'.",
        algorithm=algorithm))


def algorithm_of(private_key):
    if isinstance(private_key, ec.EllipticCurvePrivateKey):
        return ALGORITHM_ES256
    if isinstance(private_key, ed25519.Ed25519PrivateKey):
        return ALGORITHM_EDDSA
    if isinstance(private_key, rsa.RSAPrivateKey):
        return ALGORITHM_RS256
    raise PasskeyError(lang.t(
        "errors", "the_stored_passkey_uses_an_unsupported",
        "The stored passkey uses an unsupported algorithm."))


def private_key_to_pem(private_key):
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")


def load_private_key(pem_or_bytes):
    text = pem_or_bytes.encode("utf-8") if isinstance(pem_or_bytes, str) \
        else pem_or_bytes
    try:
        return serialization.load_pem_private_key(text, password=None)
    except Exception as error:
        raise PasskeyError(lang.t(
            "errors", "that_passkey_could_not_be_read",
            "That passkey could not be read: {error}",
            error=error))


def cose_public_key(private_key):
    """The COSE_Key structure that identifies the public half of a passkey."""
    algorithm = algorithm_of(private_key)
    if algorithm == ALGORITHM_ES256:
        numbers = private_key.public_key().public_numbers()
        return cbor_encode({
            1: 2,                       # key type: elliptic curve
            3: algorithm,
            -1: 1,                      # curve: NIST P-256
            -2: numbers.x.to_bytes(32, "big"),
            -3: numbers.y.to_bytes(32, "big"),
        })
    if algorithm == ALGORITHM_EDDSA:
        raw = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw)
        return cbor_encode({1: 1, 3: algorithm, -1: 6, -2: raw})
    public_numbers = private_key.public_key().public_numbers()
    return cbor_encode({
        1: 3,                           # key type: RSA
        3: algorithm,
        -1: public_numbers.n.to_bytes(256, "big"),
        -2: public_numbers.e.to_bytes(3, "big"),
    })


def sign_challenge(private_key, data):
    """Sign with the passkey, returning the signature form WebAuthn wants.

    ES256 assertions carry a DER encoded ECDSA signature, EdDSA and RSA carry
    the raw signature bytes.
    """
    algorithm = algorithm_of(private_key)
    if algorithm == ALGORITHM_ES256:
        return private_key.sign(data, ec.ECDSA(hashes.SHA256()))
    if algorithm == ALGORITHM_EDDSA:
        return private_key.sign(data)
    return private_key.sign(data, padding.PKCS1v15(), hashes.SHA256())


def verify_challenge(public_key, data, signature):
    """Check a signature, used by the tests rather than by the program."""
    try:
        algorithm = algorithm_of(_public_as_private_like(public_key))
    except PasskeyError:
        algorithm = None
    if algorithm == ALGORITHM_ES256 or isinstance(
            public_key, ec.EllipticCurvePublicKey):
        public_key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        return True
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        public_key.verify(signature, data)
        return True
    if isinstance(public_key, rsa.RSAPublicKey):
        public_key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
        return True
    raise PasskeyError(lang.t(
        "errors", "the_passkey_public_key_is_of",
        "The passkey public key is of an unsupported type."))


def _public_as_private_like(public_key):
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return ec.generate_private_key(ec.SECP256R1())
    if isinstance(public_key, ed25519.Ed25519PublicKey):
        return ed25519.Ed25519PrivateKey.generate()
    if isinstance(public_key, rsa.RSAPublicKey):
        return rsa.generate_private_key(public_exponent=65537, key_size=2048)
    raise PasskeyError(lang.t(
        "errors", "unsupported_passkey_public_key",
        "Unsupported passkey public key."))


def signature_is_valid(private_key_pem, data, signature, der=True):
    """Checks a signature made with the key in the given PEM."""
    private_key = load_private_key(private_key_pem)
    public_key = private_key.public_key()
    if der and algorithm_of(private_key) == ALGORITHM_ES256:
        # Round trip through the raw form so both encodings are accepted.
        numbers = decode_dss_signature(signature)
        public_key.verify(_der_from_numbers(numbers), data, ec.ECDSA(hashes.SHA256()))
    return verify_challenge(public_key, data, signature)


def _der_from_numbers(numbers):
    from cryptography.hazmat.primitives.asymmetric.utils import \
        encode_dss_signature

    return encode_dss_signature(*numbers)


# --------------------------------------------------------- authenticator data

def authenticator_data(rp_id, flags=None, counter=0):
    """Build the blob a browser checks: rpIdHash, flags, counter."""
    if flags is None:
        flags = FLAG_USER_PRESENT | FLAG_USER_VERIFIED
    if isinstance(rp_id, str):
        rp_id = rp_id.encode("utf-8")
    return (hashlib.sha256(rp_id).digest() + bytes([flags])
            + struct.pack(">I", int(counter) & 0xFFFFFFFF))


def client_data_hash(kind, challenge, origin):
    """SHA-256 of the client data JSON a browser would build."""
    import json

    payload = json.dumps({"type": kind, "challenge": challenge,
                          "origin": origin, "crossOrigin": False},
                         separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).digest()


# --------------------------------------------------------------- records

def new_passkey(relying_party, username, user_handle=None, algorithm="ES256",
                credential_id=None):
    """Build the values for a brand new passkey."""
    if not relying_party:
        raise PasskeyError(lang.t(
            "errors", "a_passkey_needs_the_relying_party",
            "A passkey needs the relying party, usually the web address the "
            "passkey belongs to."))
    private_key = generate_private_key(algorithm)
    handle = user_handle or random_user_handle()
    return {
        "credential_id": credential_id or random_credential_id(),
        "private_key_pem": private_key_to_pem(private_key),
        "username": username or "",
        "relying_party": relying_party,
        "user_handle": handle,
        "algorithm": algorithm_of(private_key),
    }


def record_attributes(record):
    """The entry attributes that store one passkey."""
    return [
        {"name": ATTR_CREDENTIAL_ID, "value": b64url_encode(
            record["credential_id"] if isinstance(record["credential_id"], bytes)
            else b64url_decode(record["credential_id"])), "hidden": 1},
        {"name": ATTR_PRIVATE_KEY, "value": record["private_key_pem"], "hidden": 1},
        {"name": ATTR_USERNAME, "value": record.get("username") or "", "hidden": 1},
        {"name": ATTR_RELYING_PARTY,
         "value": record.get("relying_party") or "", "hidden": 1},
        {"name": ATTR_USER_HANDLE,
         "value": b64url_encode(record["user_handle"])
         if isinstance(record.get("user_handle"), bytes)
         else (record.get("user_handle") or ""), "hidden": 1},
    ]


def is_passkey_entry(entry):
    fields = {key: value for key, value, _protect in entry.get("fields", [])}
    return ATTR_PRIVATE_KEY in fields


def records_from_attributes(attributes):
    """Turn a flat attribute list into passkey records."""
    buckets = {}
    for attribute in attributes or []:
        name = attribute.get("name")
        if name not in PASSKEY_ATTRIBUTES:
            continue
        value = attribute.get("value") or ""
        key = _passkey_key(attribute)
        buckets.setdefault(key, {})[name] = value
    records = []
    for values in buckets.values():
        if not values.get(ATTR_PRIVATE_KEY):
            continue
        try:
            credential_id = b64url_decode(values.get(ATTR_CREDENTIAL_ID, ""))
        except Exception:
            credential_id = b""
        records.append({
            "credential_id": credential_id,
            "private_key_pem": values[ATTR_PRIVATE_KEY],
            "username": values.get(ATTR_USERNAME, ""),
            "relying_party": values.get(ATTR_RELYING_PARTY, ""),
            "user_handle": values.get(ATTR_USER_HANDLE, ""),
        })
    return records


def _passkey_key(attribute):
    """Group attributes that belong to the same passkey.

    KeePassXC keeps the credential id in its own attribute per passkey, so the
    grouping key is everything before that attribute's position in the list.
    When several passkeys share an entry they are separated by the credential
    id attribute, which is what this returns.
    """
    return attribute.get("group") or attribute.get("entry_id") or 0


def passkeys_for_entry(vault, entry_id):
    """Every passkey stored on an entry."""
    records = []
    current = {}
    for attribute in vault.attributes(entry_id):
        name = attribute["name"]
        if name == ATTR_CREDENTIAL_ID and current.get(ATTR_PRIVATE_KEY):
            records.append(current)
            current = {}
        if name in PASSKEY_ATTRIBUTES:
            current[name] = attribute["value"] or ""
    if current.get(ATTR_PRIVATE_KEY):
        records.append(current)
    out = []
    for values in records:
        try:
            credential_id = b64url_decode(values.get(ATTR_CREDENTIAL_ID, ""))
        except Exception:
            credential_id = b""
        out.append({
            "credential_id": credential_id,
            "private_key_pem": values[ATTR_PRIVATE_KEY],
            "username": values.get(ATTR_USERNAME, ""),
            "relying_party": values.get(ATTR_RELYING_PARTY, ""),
            "user_handle": values.get(ATTR_USER_HANDLE, ""),
        })
    return out


def store_passkey(vault, entry_id, record):
    """Save one passkey as hidden attributes on an entry."""
    for attribute in record_attributes(record):
        existing = [item for item in vault.attributes(entry_id)
                    if item["name"] == attribute["name"]]
        if existing and len(existing) == 1:
            vault.update_attribute(existing[0]["id"], attribute["name"],
                                   attribute["value"], True)
        else:
            vault.add_attribute(entry_id, attribute["name"], attribute["value"],
                                True)
    return record


def delete_passkey(vault, entry_id, index):
    """Remove one passkey from an entry, by its position in the list."""
    records = passkeys_for_entry(vault, entry_id)
    if not 0 <= index < len(records):
        return False
    wanted = records[index]
    wanted_id = b64url_encode(wanted["credential_id"])
    seen = 0
    for attribute in vault.attributes(entry_id):
        if attribute["name"] == ATTR_CREDENTIAL_ID:
            seen += 1
            continue
        if attribute["name"] in PASSKEY_ATTRIBUTES and seen == index + 1:
            vault.delete_attribute(attribute["id"])
    for attribute in vault.attributes(entry_id):
        if (attribute["name"] == ATTR_CREDENTIAL_ID
                and attribute["value"] == wanted_id):
            vault.delete_attribute(attribute["id"])
            break
    return True


def describe_passkeys(vault, entry_id):
    """Readable lines describing the passkeys on an entry."""
    lines = []
    for index, record in enumerate(passkeys_for_entry(vault, entry_id), start=1):
        try:
            algorithm = ALGORITHM_NAMES.get(
                algorithm_of(load_private_key(record["private_key_pem"])),
                "unknown algorithm")
        except PasskeyError:
            algorithm = lang.t("dialogs", "unreadable_key", "unreadable key")
        lines.append(
            lang.t(
                "dialogs", "passkey_user_credential",
                "Passkey {index}: {relying_party}, user {username}, "
                "{algorithm}, credential {credential_id}...",
                index=index,
                relying_party=record['relying_party'] or lang.t(
                    "dialogs", "no_relying_party",
                    "(no relying party)"),
                username=record['username'] or lang.t(
                    "dialogs", "none",
                    "(none)"),
                algorithm=algorithm,
                credential_id=b64url_encode(record['credential_id'])[:16]))
    return lines


# ------------------------------------------------------------- WebAuthn shape

def make_credential(private_key_pem, record, client_data_hash_value,
                    rp_id=None, counter=0, user_verified=True):
    """The values a browser needs when a passkey is first registered."""
    private_key = load_private_key(private_key_pem)
    rp_id = rp_id or record.get("relying_party") or ""
    flags = FLAG_USER_PRESENT | FLAG_ATTESTED
    if user_verified:
        flags |= FLAG_USER_VERIFIED
    auth_data = (hashlib.sha256(rp_id.encode("utf-8")).digest() + bytes([flags])
                 + struct.pack(">I", counter)
                 + b"\x00" * 16                       # AAGUID, none
                 + struct.pack(">H", len(record["credential_id"]))
                 + record["credential_id"]
                 + cose_public_key(private_key))
    attestation = cbor_encode({
        "fmt": "none",
        "attStmt": {},
        "authData": auth_data,
    })
    return {
        "credential_id": record["credential_id"],
        "attestation_object": attestation,
        "auth_data": auth_data,
        "public_key_cose": cose_public_key(private_key),
        "algorithm": algorithm_of(private_key),
        "user_handle": record.get("user_handle", ""),
        "user_name": record.get("username", ""),
    }


def get_assertion(private_key_pem, client_data_hash_value, rp_id, counter=0,
                  user_verified=True, user_present=True):
    """The values a browser needs to sign in with a passkey."""
    private_key = load_private_key(private_key_pem)
    flags = 0
    if user_present:
        flags |= FLAG_USER_PRESENT
    if user_verified:
        flags |= FLAG_USER_VERIFIED
    auth_data = authenticator_data(rp_id, flags, counter)
    signature = sign_challenge(private_key,
                              auth_data + client_data_hash_value)
    return {
        "signature": signature,
        "auth_data": auth_data,
        "algorithm": algorithm_of(private_key),
    }


def verify_assertion(private_key_pem, rp_id, client_data_hash_value,
                     signature, counter=0, user_verified=True):
    """Check an assertion, used by the tests."""
    flags = FLAG_USER_PRESENT | (FLAG_USER_VERIFIED if user_verified else 0)
    auth_data = authenticator_data(rp_id, flags, counter)
    public_key = load_private_key(private_key_pem).public_key()
    verify_challenge(public_key, auth_data + client_data_hash_value, signature)
    return True


def make_client_data(kind, challenge, origin):
    """The client data JSON, for completeness and for the tests."""
    import json

    return json.dumps({"type": kind, "challenge": challenge,
                       "origin": origin, "crossOrigin": False},
                      separators=(",", ":"))


def now_milliseconds():
    return int(time.time() * 1000)
