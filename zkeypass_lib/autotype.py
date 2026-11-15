"""Auto-type: send an entry's fields to whichever window has the focus.

This mirrors the way KeePass and KeePassXC auto-type works:

  * every entry may carry an auto-type sequence, a small template such as
    {USERNAME}{TAB}{PASSWORD}{ENTER}
  * every entry may carry window associations, patterns matched against the
    title of the active window
  * a global hot key (Control Alt A by default) picks the entry whose
    association matches the active window and types its sequence into it

Only the standard library is used.  Keystrokes are injected with SendInput
through ctypes, with unicode code units rather than virtual key codes, so
letters outside the current keyboard layout are still typed correctly.
"""

import ctypes
import re
import time
from ctypes import wintypes
from . import lang

ULONG_PTR = ctypes.c_ulonglong if ctypes.sizeof(ctypes.c_void_p) == 8 \
    else ctypes.c_ulong

KF_EXTENDED = 0x01
KEYEVENTF_EXTENDEDKEY = 0x0001
KEYEVENTF_KEYUP = 0x0002
KEYEVENTF_UNICODE = 0x0004

VK_SHIFT = 0x10
VK_CONTROL = 0x11
VK_MENU = 0x12
VK_TAB = 0x09
VK_RETURN = 0x0D
VK_BACK = 0x08
VK_ESCAPE = 0x1B
VK_DELETE = 0x2E
VK_INSERT = 0x2D
VK_HOME = 0x24
VK_END = 0x23
VK_LEFT = 0x25
VK_RIGHT = 0x27
VK_UP = 0x26
VK_DOWN = 0x28
VK_SPACE = 0x20
VK_ADD = 0x6B
VK_SUBTRACT = 0x6D

DEFAULT_SEQUENCE = "{USERNAME}{TAB}{PASSWORD}{ENTER}"
DEFAULT_DELAY_MS = 20

# Named keys that a sequence can ask for.
NAMED_KEYS = {
    "TAB": VK_TAB, "ENTER": VK_RETURN, "RETURN": VK_RETURN, "SPACE": VK_SPACE,
    "BACKSPACE": VK_BACK, "BS": VK_BACK, "ESC": VK_ESCAPE, "ESCAPE": VK_ESCAPE,
    "DELETE": VK_DELETE, "DEL": VK_DELETE, "INSERT": VK_INSERT, "INS": VK_INSERT,
    "HOME": VK_HOME, "END": VK_END, "LEFT": VK_LEFT, "RIGHT": VK_RIGHT,
    "UP": VK_UP, "DOWN": VK_DOWN, "ADD": VK_ADD, "SUBTRACT": VK_SUBTRACT,
    "PLUS": VK_ADD, "MINUS": VK_SUBTRACT,
    "F1": 0x70, "F2": 0x71, "F3": 0x72, "F4": 0x73, "F5": 0x74, "F6": 0x75,
    "F7": 0x76, "F8": 0x77, "F9": 0x78, "F10": 0x79, "F11": 0x7A, "F12": 0x7B,
}

# Fields a sequence can insert.
FIELD_KEYS = ("TITLE", "USERNAME", "PASSWORD", "URL", "NOTES", "TOTP", "TIME",
              "DATE", "UUID", "GROUP")

TOKEN_PATTERN = re.compile(r"\{([^{}]*)\}")

# Characters that have a meaning inside a sequence as a shortcut suffix.
MODIFIER_PREFIXES = ("+", "^", "%")


class AutoTypeError(Exception):
    """Raised with a message meant for the user."""


# ------------------------------------------------------------------ SendInput

class MOUSEINPUT(ctypes.Structure):
    _fields_ = [("dx", wintypes.LONG), ("dy", wintypes.LONG),
                ("mouseData", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
                ("time", wintypes.DWORD), ("dwExtraInfo", ULONG_PTR)]


class KEYBDINPUT(ctypes.Structure):
    _fields_ = [("wVk", wintypes.WORD), ("wScan", wintypes.WORD),
                ("dwFlags", wintypes.DWORD), ("time", wintypes.DWORD),
                ("dwExtraInfo", ULONG_PTR)]


class HARDWAREINPUT(ctypes.Structure):
    _fields_ = [("uMsg", wintypes.DWORD), ("wParamL", wintypes.WORD),
                ("wParamH", wintypes.WORD)]


class _INPUTUNION(ctypes.Union):
    _fields_ = [("ki", KEYBDINPUT), ("mi", MOUSEINPUT), ("hi", HARDWAREINPUT)]


class INPUT(ctypes.Structure):
    _anonymous_ = ("u",)
    _fields_ = [("type", wintypes.DWORD), ("u", _INPUTUNION)]


INPUT_KEYBOARD = 1
INPUT_SIZE = ctypes.sizeof(INPUT)


def _user32():
    return ctypes.WinDLL("user32", use_last_error=True)


def available():
    """True when keystrokes can be injected on this system."""
    try:
        _user32()
        return True
    except OSError:
        return False


def _send(inputs):
    user32 = _user32()
    count = len(inputs)
    array = (INPUT * count)(*inputs)
    sent = user32.SendInput(count, ctypes.byref(array), INPUT_SIZE)
    if sent != count:
        raise AutoTypeError(
            lang.t(
                "errors", "windows_accepted_only_of_keystrokes_another",
                "Windows accepted only {sent} of {count} keystrokes. Another "
                "program may be blocking simulated input.",
                sent=sent,
                count=count))


def _key_event(virtual_key, flags=0):
    event = INPUT()
    event.type = INPUT_KEYBOARD
    event.ki = KEYBDINPUT(wVk=virtual_key, wScan=0, dwFlags=flags,
                          time=0, dwExtraInfo=0)
    return event


def _unicode_event(code_unit, flags=0):
    event = INPUT()
    event.type = INPUT_KEYBOARD
    event.ki = KEYBDINPUT(wVk=0, wScan=code_unit, dwFlags=flags | KEYEVENTF_UNICODE,
                          time=0, dwExtraInfo=0)
    return event


def press_key(virtual_key, delay_ms=DEFAULT_DELAY_MS):
    """Press and release one virtual key."""
    _send([_key_event(virtual_key), _key_event(virtual_key, KEYEVENTF_KEYUP)])
    _pause(delay_ms)


def type_text(text, delay_ms=DEFAULT_DELAY_MS):
    """Type literal text using unicode keystrokes."""
    if not text:
        return
    events = []
    for character in text:
        for unit in _code_units(character):
            events.append(_unicode_event(unit))
            events.append(_unicode_event(unit, KEYEVENTF_KEYUP))
    for start in range(0, len(events), 64):
        _send(events[start:start + 64])
        _pause(delay_ms)


def _code_units(character):
    """Surrogate pairs for anything outside the basic plane."""
    data = character.encode("utf-16-le")
    return [int.from_bytes(data[index:index + 2], "little")
            for index in range(0, len(data), 2)]


def _pause(milliseconds):
    if milliseconds:
        time.sleep(milliseconds / 1000.0)


def press_with_modifiers(modifier, key):
    """Hold a modifier, tap a key, release the modifier."""
    _send([_key_event(modifier)])
    press_key(key)
    _send([_key_event(modifier, KEYEVENTF_KEYUP)])


# ------------------------------------------------------------- active window

def active_window_title():
    """Title of the window that currently has the focus, or an empty string."""
    user32 = _user32()
    handle = user32.GetForegroundWindow()
    if not handle:
        return ""
    length = user32.GetWindowTextLengthW(handle)
    buffer = ctypes.create_unicode_buffer(length + 2)
    user32.GetWindowTextW(handle, buffer, length + 1)
    return buffer.value


def _window_titles():
    """Every visible top level window title, for the picker dialog."""
    user32 = _user32()
    titles = []

    enum_proc = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND,
                                   wintypes.LPARAM)

    def collect(handle, _param):
        if not user32.IsWindowVisible(handle):
            return True
        length = user32.GetWindowTextLengthW(handle)
        if length <= 0:
            return True
        buffer = ctypes.create_unicode_buffer(length + 2)
        user32.GetWindowTextW(handle, buffer, length + 1)
        if buffer.value.strip():
            titles.append(buffer.value)
        return True

    user32.EnumWindows(enum_proc(collect), 0)
    return titles


def visible_window_titles():
    try:
        return sorted(set(_window_titles()), key=str.lower)
    except OSError:
        return []


# ----------------------------------------------------------- sequence parsing

def window_matches(pattern, title):
    """KeePass style window matching: * and ? wildcards, | alternatives.

    Matching ignores case, and a pattern that contains no wildcard matches
    anywhere inside the title, exactly as KeePass does.
    """
    if not pattern:
        return False
    title = (title or "").lower()
    for alternative in str(pattern).split("|"):
        alternative = alternative.strip().lower()
        if not alternative:
            continue
        if "*" in alternative or "?" in alternative:
            expression = "^" + re.escape(alternative).replace(r"\*", ".*") \
                .replace(r"\?", ".") + "$"
            if re.match(expression, title):
                return True
        elif alternative in title:
            return True
    return False


def split_sequence(sequence):
    """Turn a sequence into a flat list of parts, keeping literal runs.

    Returns a list of tuples: ("text", literal) or ("action", value) or
    ("field", name) or ("key", virtual_key) or ("delay", milliseconds).
    """
    sequence = sequence or ""
    parts = []
    position = 0
    while position < len(sequence):
        character = sequence[position]
        if character == "{":
            end = sequence.find("}", position)
            if end == -1:
                parts.append(("text", sequence[position:]))
                break
            parts.append(("command", sequence[position + 1:end]))
            position = end + 1
        else:
            # A literal run, but "+", "^" and "%" mark the followed
            # character as a modifier combination.
            if character in MODIFIER_PREFIXES and position + 1 < len(sequence):
                following = sequence[position + 1]
                if following == "{":
                    end = sequence.find("}", position)
                    if end == -1:
                        parts.append(("text", character))
                        position += 1
                        continue
                    parts.append(("modified", (character,
                                               sequence[position + 2:end])))
                    position = end + 1
                    continue
                parts.append(("modified", (character, following)))
                position += 2
                continue
            buffer = [character]
            position += 1
            while position < len(sequence) and sequence[position] not in "{+^%":
                buffer.append(sequence[position])
                position += 1
            parts.append(("text", "".join(buffer)))
    return parts


def entry_field(entry, name, group_name="", totp_code=""):
    """Resolve one field placeholder against an entry record."""
    name = name.upper()
    if name == "TITLE":
        return entry.get("title") or ""
    if name in ("USERNAME", "USER"):
        return entry.get("username") or ""
    if name in ("PASSWORD", "PASS"):
        return entry.get("password") or ""
    if name in ("URL", "URL:") or name == "URL":
        return entry.get("url") or ""
    if name == "NOTES":
        return entry.get("notes") or ""
    if name == "TOTP":
        return totp_code or ""
    if name == "GROUP":
        return group_name or entry.get("group_name") or ""
    if name == "TIME":
        return time.strftime("%H:%M:%S")
    if name == "DATE":
        return time.strftime("%Y-%m-%d")
    if name == "UUID":
        value = entry.get("uuid") or ""
        if isinstance(value, bytes):
            return value.hex()
        return str(value)
    return ""


def expand(sequence, entry, group_name="", totp_code=""):
    """Return the literal text a sequence produces, for previewing."""
    out = []
    for kind, value in split_sequence(sequence):
        if kind == "text":
            out.append(value)
        elif kind == "command":
            name = value.strip().upper()
            if name in FIELD_KEYS:
                out.append(entry_field(entry, name, group_name, totp_code))
            elif name in NAMED_KEYS:
                out.append("")
            elif name in ("S", "SPACE"):
                out.append(" ")
            elif len(name) == 1 and name in ("+", "^", "%"):
                out.append("")
        elif kind == "modified":
            _modifier, key = value
            if key.strip().upper() not in NAMED_KEYS and len(key) == 1:
                out.append(key)
    return "".join(out)


def play(sequence, entry, group_name="", totp_code="", delay_ms=DEFAULT_DELAY_MS,
         on_progress=None):
    """Type a sequence into the focused window.

    Returns the length of the literal text that was typed.  The sequence is
    executed step by step so that delays and key presses are intermixed with
    text in the order the user wrote them.
    """
    typed = 0
    for kind, value in split_sequence(sequence or DEFAULT_SEQUENCE):
        if kind == "text":
            type_text(value, delay_ms)
            typed += len(value)
        elif kind == "command":
            typed += _run_command(value, entry, group_name, totp_code, delay_ms)
        elif kind == "modified":
            modifier, key = value
            _run_modified(modifier, key, entry, group_name, totp_code, delay_ms)
        if on_progress:
            on_progress(typed)
    return typed


def _run_command(command, entry, group_name, totp_code, delay_ms):
    name = (command or "").strip().upper()
    if name in FIELD_KEYS:
        text = entry_field(entry, name, group_name, totp_code)
        type_text(text, delay_ms)
        return len(text)
    if name in ("S", "SPACE"):
        type_text(" ", delay_ms)
        return 1
    if name in ("TAB", "ENTER", "RETURN", "ESC", "ESCAPE", "BACKSPACE", "BS"):
        press_key(NAMED_KEYS[name], delay_ms)
        return 0
    if name in NAMED_KEYS:
        press_key(NAMED_KEYS[name], delay_ms)
        return 0
    if name.startswith("DELAY"):
        milliseconds = _delay_value(name)
        _pause(milliseconds)
        return 0
    if name == "CLEARFIELD":
        _send([_key_event(VK_CONTROL)])
        press_key(0x41)                      # Control A selects everything
        _send([_key_event(VK_CONTROL, KEYEVENTF_KEYUP)])
        press_key(VK_DELETE)
        return 0
    if name in ("BEEP", "VKEY"):
        return 0
    if name.isdigit():
        press_key(0x30 + int(name) % 10, delay_ms)
        return 0
    if len(name) == 1:
        type_text(command, delay_ms)
        return 1
    raise AutoTypeError(lang.t(
        "errors", "unknown_auto_type_command",
        "Unknown auto-type command {{{command}}}.",
        command=command))


def _delay_value(name):
    """{DELAY 500} or {DELAY=500} means half a second."""
    digits = re.findall(r"\d+", name)
    if not digits:
        return 100
    return min(int(digits[0]), 10000)


def _run_modified(modifier, key, entry, group_name, totp_code, delay_ms):
    modifier_key = {"+": VK_SHIFT, "^": VK_CONTROL, "%": VK_MENU}.get(modifier)
    if modifier_key is None:
        return
    name = (key or "").strip().upper()
    if name in FIELD_KEYS:
        text = entry_field(entry, name, group_name, totp_code)
        _send([_key_event(modifier_key)])
        type_text(text, delay_ms)
        _send([_key_event(modifier_key, KEYEVENTF_KEYUP)])
        return
    if name in NAMED_KEYS:
        press_with_modifiers(modifier_key, NAMED_KEYS[name])
        return
    if len(key or "") == 1:
        _send([_key_event(modifier_key)])
        type_text(key, delay_ms)
        _send([_key_event(modifier_key, KEYEVENTF_KEYUP)])


# ------------------------------------------------------------------ choosing

def associations_of(entry):
    """The window patterns an entry is willing to auto-type into."""
    settings = entry.get("autotype") or {}
    found = []
    for window, sequence in settings.get("associations", []) or []:
        if window:
            found.append(window)
    return found


def url_host_pattern(url):
    """A window pattern derived from an entry's web address."""
    if not url:
        return ""
    text = str(url).strip()
    text = re.sub(r"^[a-z][a-z0-9+.-]*://", "", text, flags=re.IGNORECASE)
    text = text.split("/")[0].split("?")[0]
    if "@" in text:
        text = text.split("@", 1)[1]
    text = text.split(":")[0]
    if text.startswith("www."):
        text = text[4:]
    if not text or "." not in text:
        return text
    return f"*{text}*"


def patterns_for(entry):
    """Every pattern to try for an entry, most specific first."""
    patterns = []
    for window in associations_of(entry):
        if window not in patterns:
            patterns.append(window)
    host = url_host_pattern(entry.get("url"))
    if host and host not in patterns:
        patterns.append(host)
    title = entry.get("title")
    if title and title not in patterns:
        patterns.append(f"*{title}*")
    return patterns


def best_match(entries, title):
    """Pick (entry, score) for the window title, or (None, 0).

    The score prefers an explicit association over a web address match, and
    a longer pattern over a shorter one.
    """
    best = None
    best_score = 0
    for entry in entries:
        if (entry.get("autotype") or {}).get("enabled") is False:
            continue
        associations = associations_of(entry)
        host = url_host_pattern(entry.get("url"))
        candidates = [(pattern, 100 + len(pattern)) for pattern in associations]
        if host:
            candidates.append((host, 50 + len(host)))
        title_pattern = entry.get("title")
        if title_pattern:
            candidates.append((f"*{title_pattern}*", len(title_pattern)))
        for pattern, score in candidates:
            if score > best_score and window_matches(pattern, title):
                best, best_score = entry, score
    return best, best_score


def sequence_for(entry, title=""):
    """The sequence to use for an entry in a given window."""
    settings = entry.get("autotype") or {}
    for window, sequence in settings.get("associations", []) or []:
        if sequence and window_matches(window, title):
            return sequence
    return settings.get("sequence") or DEFAULT_SEQUENCE


def validate_sequence(sequence):
    """Return a complaint about a sequence, or an empty string when it is fine."""
    if not sequence.strip():
        return ""
    if sequence.count("{") != sequence.count("}"):
        return lang.t(
            "dialogs", "a_command_in_the_sequence_is",
            "A command in the sequence is missing its closing brace.")
    try:
        for kind, value in split_sequence(sequence):
            if kind == "command":
                name = value.strip().upper()
                if name in FIELD_KEYS or name in NAMED_KEYS:
                    continue
                if name in ("S", "SPACE", "CLEARFIELD", "BEEP"):
                    continue
                if name.startswith("DELAY") or name.isdigit():
                    continue
                return lang.t("errors", "autotype_not_a_command",
                              "{{{command}}} is not a recognised command.",
                              command=value)
    except AutoTypeError as error:
        return str(error)
    return ""
