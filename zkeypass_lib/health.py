"""Offline password audit: weak, reused, old, expired, incomplete entries.

No network calls and no third-party scoring library.  Strength comes from an
estimate of search space plus a small list of well-known bad patterns.
"""

import hashlib
import math
import re
import time
from . import lang

COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "abc123", "letmein",
    "monkey", "dragon", "iloveyou", "admin", "welcome", "login",
    "passw0rd", "p@ssw0rd", "qwerty123", "111111", "000000", "master",
    "sunshine", "princess", "football", "baseball", "trustno1",
}

SEQUENCES = ("abcdefghijklmnopqrstuvwxyz", "0123456789",
             "qwertyuiop", "asdfghjkl", "zxcvbnm")


def estimate_entropy(password):
    """Rough bits of entropy from the character pool actually used."""
    if not password:
        return 0.0
    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"[0-9]", password):
        pool += 10
    if re.search(r"[^A-Za-z0-9]", password):
        pool += 33
    bits = len(password) * math.log2(pool) if pool else 0.0
    lowered = password.lower()
    if lowered in COMMON_PASSWORDS:
        bits = min(bits, 8.0)
    if re.match(r"^(.)\1+$", password):
        bits = min(bits, 8.0)
    for sequence in SEQUENCES:
        for length in range(4, min(len(lowered), 12) + 1):
            for start in range(0, len(sequence) - length + 1):
                if sequence[start:start + length] in lowered:
                    bits = min(bits, length * 2.5)
    return bits


def strength_label(bits):
    if bits < 28:
        return lang.t("dialogs", "very_weak", "Very weak")
    if bits < 45:
        return lang.t("dialogs", "weak", "Weak")
    if bits < 60:
        return lang.t("dialogs", "reasonable", "Reasonable")
    if bits < 80:
        return lang.t("dialogs", "strong", "Strong")
    return lang.t("dialogs", "very_strong", "Very strong")


def password_fingerprint(password):
    """Hash used to spot reuse without keeping the password itself around."""
    if not password:
        return None
    return hashlib.sha256(password.encode("utf-8", "ignore")).hexdigest()


def audit(entries, weak_bits=45, reused_only_above=0, max_age_days=365,
          now=None):
    """Return a list of finding dictionaries, one per problem found.

    entries is an iterable of dictionaries with the keys used by the vault
    (title, username, password, url, expires, modified, group_name).
    """
    moment = time.time() if now is None else now
    findings = []

    fingerprints = {}
    for entry in entries:
        fingerprint = password_fingerprint(entry.get("password") or "")
        if fingerprint:
            fingerprints.setdefault(fingerprint, []).append(entry)

    for entry in entries:
        label = entry.get("title") or lang.t(
            "dialogs", "untitled",
            "(untitled)")
        password = entry.get("password") or ""

        if not password:
            findings.append({"kind": lang.t(
                "dialogs", "empty_password",
                "Empty password"), "entry": label,
                             "detail": lang.t(
                                 "dialogs", "no_password_stored_for_this_entry",
                                 "No password stored for this entry.")})
        else:
            bits = estimate_entropy(password)
            if bits < weak_bits:
                findings.append({
                    "kind": lang.t("dialogs", "weak_password", "Weak password"), "entry": label,
                    "detail": lang.t(
                        "dialogs", "about_bits_of_entropy",
                        "{strength_label}, about {bits:.0f} bits of entropy.",
                        strength_label=strength_label(bits),
                        bits=bits),
                })

        if password:
            group = fingerprints.get(password_fingerprint(password), [])
            if len(group) > 1:
                others = [other.get("title") or lang.t(
                    "dialogs", "untitled",
                    "(untitled)") for other in group
                          if other is not entry]
                findings.append({
                    "kind": lang.t(
                        "dialogs", "reused_password",
                        "Reused password"), "entry": label,
                    "detail": lang.t(
                        "dialogs", "same_password_as",
                        "Same password as: ") + ", ".join(others[:5]),
                })

        if not (entry.get("username") or "").strip():
            findings.append({"kind": lang.t(
                "dialogs", "missing_username",
                "Missing username"), "entry": label,
                             "detail": lang.t(
                                 "dialogs", "no_username_set",
                                 "No username set.")})
        if not (entry.get("url") or "").strip():
            findings.append({"kind": lang.t(
                "dialogs", "missing_web_address",
                "Missing web address"), "entry": label,
                             "detail": lang.t(
                                 "dialogs", "no_url_set",
                                 "No URL set.")})

        expires = entry.get("expires") or 0
        if expires and expires < moment:
            findings.append({"kind": lang.t(
                "dialogs", "expired_entry",
                "Expired entry"), "entry": label,
                             "detail": lang.t(
                                 "dialogs", "the_expiry_date_has_passed",
                                 "The expiry date has passed.")})

        modified = entry.get("modified") or 0
        if modified and max_age_days and \
                (moment - modified) > max_age_days * 86400:
            days = int((moment - modified) / 86400)
            findings.append({"kind": lang.t(
                "dialogs", "old_password",
                "Old password"), "entry": label,
                             "detail": lang.t(
                                 "dialogs", "not_changed_for_days",
                                 "Not changed for {days} days.",
                                 days=days)})

    findings.sort(key=lambda item: (item["kind"], item["entry"].lower()))
    return findings


def summarise(findings):
    counts = {}
    for finding in findings:
        counts[finding["kind"]] = counts.get(finding["kind"], 0) + 1
    return counts
