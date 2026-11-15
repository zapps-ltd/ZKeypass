"""RFC 4226 / RFC 6238 one-time password generation, implemented locally.

No third-party dependency: base32 decoding and HMAC come from the standard
library, which keeps the portable bundle small.
"""

import base64
import hashlib
import hmac
import struct
import time

ALGORITHMS = {"SHA1": hashlib.sha1, "SHA256": hashlib.sha256,
              "SHA512": hashlib.sha512}


def normalise_secret(secret):
    """Accept the usual typed forms: spaces, dashes, otpauth URLs, padding."""
    if not secret:
        return ""
    text = secret.strip()
    if text.lower().startswith("otpauth://"):
        from urllib.parse import parse_qs, urlparse

        query = parse_qs(urlparse(text).query)
        text = (query.get("secret") or [""])[0]
    text = text.replace(" ", "").replace("-", "").replace("=", "").upper()
    return text


def parse_otpauth(uri):
    """Split an otpauth:// URI into its parts, or None if it is not one.

    Accepts the "issuer:account" label form, and falls back to the issuer
    query parameter when the label carries no prefix.
    """
    if not uri or not uri.strip().lower().startswith("otpauth://"):
        return None
    from urllib.parse import parse_qs, unquote, urlparse

    parsed = urlparse(uri.strip())
    query = parse_qs(parsed.query)
    label = unquote(parsed.path.lstrip("/"))
    issuer = (query.get("issuer") or [""])[0].strip()
    account = label
    if ":" in label:
        prefix, _colon, rest = label.partition(":")
        if not issuer:
            issuer = prefix.strip()
        account = rest.strip()
    return {
        "secret": normalise_secret((query.get("secret") or [""])[0]),
        "issuer": issuer,
        "account": account,
        "digits": int((query.get("digits") or ["6"])[0] or 6),
        "period": int((query.get("period") or ["30"])[0] or 30),
        "algorithm": ((query.get("algorithm") or ["SHA1"])[0] or "SHA1").upper(),
    }


def is_valid_secret(secret):
    text = normalise_secret(secret)
    if not text:
        return False
    try:
        base64.b32decode(text + "=" * (-len(text) % 8))
        return True
    except Exception:
        return False


# Real setup keys are at least 80 bits (16 base32 letters); most are 160.
MIN_KEY_BYTES = 10


def usable_secret(secret):
    """True only for a setup key that can really make codes.

    Some databases carry an "otp" or "TOTP Seed" field on ordinary entries,
    holding something other than a setup key.  Anything that is not valid
    base32, or is shorter than a real key, is not counted as one.
    """
    text = normalise_secret(secret)
    if len(text) < 16:
        return False
    try:
        key = base64.b32decode(text + "=" * (-len(text) % 8))
    except Exception:
        return False
    return len(key) >= MIN_KEY_BYTES


def has_code(entry):
    """True when this entry has a genuine setup key and so a live code."""
    return bool(entry) and usable_secret(entry.get("totp_secret") or "")


def code_at(secret, timestamp=None, digits=6, period=30, algorithm="SHA1"):
    """Six digit code for a moment in time. Empty string if the seed is bad."""
    text = normalise_secret(secret)
    if not text:
        return ""
    try:
        key = base64.b32decode(text + "=" * (-len(text) % 8))
    except Exception:
        return ""
    counter = int((time.time() if timestamp is None else timestamp) // period)
    digest = hmac.new(key, struct.pack(">Q", counter),
                      ALGORITHMS.get(algorithm.upper(), hashlib.sha1)).digest()
    offset = digest[-1] & 0x0F
    chunk = digest[offset: offset + 4]
    value = struct.unpack(">I", chunk)[0] & 0x7FFFFFFF
    return str(value % (10 ** digits)).zfill(digits)


def current_code(entry, timestamp=None):
    return code_at(
        entry.get("totp_secret", ""),
        timestamp=timestamp,
        digits=int(entry.get("totp_digits") or 6),
        period=int(entry.get("totp_period") or 30),
        algorithm=entry.get("totp_algorithm") or "SHA1",
    )


def seconds_remaining(period=30, timestamp=None):
    """Whole seconds left in the current window, never zero.

    Floating point time makes a "just before the boundary" moment compute as
    a fraction over a whole second, which would round down to nothing; the
    ceiling keeps the countdown honest, and the floor of one stops a code
    being reported as already expired while it is still valid.
    """
    import math

    moment = time.time() if timestamp is None else timestamp
    period = int(period or 30)
    left = period - (moment % period)
    return max(1, min(period, int(math.ceil(left))))


def seconds_remaining_for(entry, timestamp=None):
    return seconds_remaining(int(entry.get("totp_period") or 30), timestamp)


def format_code(code):
    """Group the digits for easier reading aloud: 123 456."""
    if code and len(code) == 6:
        return f"{code[:3]} {code[3:]}"
    return code


def group_secret(secret, size=4):
    """Break a seed into readable groups: JBSW Y3DP EHPK 3PXP."""
    text = normalise_secret(secret)
    return " ".join(text[index: index + size]
                    for index in range(0, len(text), size))


def build_otpauth_url(issuer, account, secret, digits=6, period=30, algorithm="SHA1"):
    from urllib.parse import quote

    label = quote(f"{issuer}:{account}" if issuer else account)
    return (f"otpauth://totp/{label}?secret={normalise_secret(secret)}"
            f"&issuer={quote(issuer)}&digits={digits}&period={period}"
            f"&algorithm={algorithm}")
