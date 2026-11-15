"""Character password and Diceware passphrase generation.

Uses random.SystemRandom, so output comes from the operating system's
cryptographic random source rather than the predictable Mersenne Twister.
"""

import math
import os
import random
import secrets

from . import paths
from . import lang

_SYSTEM_RANDOM = random.SystemRandom()

AMBIGUOUS = "Il1O0o|`'\""

SETS = {
    "upper": "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
    "lower": "abcdefghijklmnopqrstuvwxyz",
    "digits": "0123456789",
    "symbols": "!@#$%^&*()-_=+[]{}:;,.?/",
    "extended": "~\"'`|\\<>",
}


def build_alphabet(use_upper=True, use_lower=True, use_digits=True,
                   use_symbols=True, use_extended=False,
                   avoid_ambiguous=False):
    pool = ""
    for key, enabled in (("upper", use_upper), ("lower", use_lower),
                         ("digits", use_digits), ("symbols", use_symbols),
                         ("extended", use_extended)):
        if enabled:
            pool += SETS[key]
    if avoid_ambiguous:
        pool = "".join(character for character in pool
                       if character not in AMBIGUOUS)
    return pool


def generate_password(length=20, alphabet=None, **options):
    """Random string with at least one character from every chosen class."""
    if alphabet is None:
        alphabet = build_alphabet(**options)
    if not alphabet:
        raise ValueError(lang.t(
            "errors", "select_at_least_one_character_type",
            "Select at least one character type."))
    length = max(4, int(length))
    characters = [_SYSTEM_RANDOM.choice(alphabet) for _ in range(length)]
    _SYSTEM_RANDOM.shuffle(characters)
    return "".join(characters)


def entropy_bits(alphabet_size, length):
    if alphabet_size <= 1 or length <= 0:
        return 0.0
    return length * math.log2(alphabet_size)


def load_wordlist(name="eff_large.txt"):
    """Read a bundled wordlist. Returns [] when the file is absent."""
    path = os.path.join(paths.WORDLIST_DIR, name)
    if not os.path.isfile(path):
        candidates = [f for f in os.listdir(paths.WORDLIST_DIR)
                      if f.lower().endswith(".txt")] if os.path.isdir(paths.WORDLIST_DIR) else []
        if not candidates:
            return []
        path = os.path.join(paths.WORDLIST_DIR, candidates[0])
    words = []
    with open(path, "r", encoding="utf-8", errors="ignore") as handle:
        for line in handle:
            word = line.strip()
            if not word or word.startswith("#"):
                continue
            words.append(word.split("\t")[-1].strip() if "\t" in word else word)
    return words


def generate_passphrase(word_count=5, separator="-", capitalise=False,
                        add_number=False, wordlist=None):
    words = wordlist if wordlist is not None else load_wordlist()
    if not words:
        raise ValueError(
            lang.t(
                "errors", "no_wordlist_found_put_a_diceware",
                "No wordlist found. Put a Diceware or EFF wordlist .txt file "
                "in the wordlists folder.")
        )
    chosen = [_SYSTEM_RANDOM.choice(words) for _ in range(max(2, int(word_count)))]
    if capitalise:
        chosen = [word.capitalize() for word in chosen]
    phrase = separator.join(chosen)
    if add_number:
        phrase += separator + str(secrets.randbelow(10000)).zfill(4)
    return phrase, len(words)


def passphrase_entropy(word_count, dictionary_size):
    if dictionary_size <= 1:
        return 0.0
    return word_count * math.log2(dictionary_size)
