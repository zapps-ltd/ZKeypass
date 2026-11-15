"""Short, friendly names for entries, made from their web address.

Imported entries often carry no name, or a whole web address as their name,
such as "https://192.168.1.1:8080/login.html".  Read aloud in every row of
the list, that is a lot to listen to.  This module works out a short name
instead: "Google" for accounts.google.com, "Example" for mail.example.co.uk,
192.168.1.1 for a router page.

Everything is worked out from the address itself, on this computer.  ZKeypass
never goes on the network, so it does not fetch the page to read its title.
"""

import ipaddress
import re

# Names a domain does not spell well by itself, by the main part of the
# domain.  Anything not here is spelled from the domain: mybank -> Mybank.
BRANDS = {
    "google": "Google", "gmail": "Google", "youtube": "YouTube",
    "microsoft": "Microsoft", "live": "Microsoft", "outlook": "Outlook",
    "office": "Microsoft 365", "office365": "Microsoft 365",
    "xbox": "Xbox", "skype": "Skype", "bing": "Bing",
    "apple": "Apple", "icloud": "iCloud", "amazon": "Amazon",
    "facebook": "Facebook", "instagram": "Instagram", "whatsapp": "WhatsApp",
    "twitter": "Twitter", "x": "X", "linkedin": "LinkedIn",
    "github": "GitHub", "gitlab": "GitLab", "bitbucket": "Bitbucket",
    "paypal": "PayPal", "ebay": "eBay", "netflix": "Netflix",
    "spotify": "Spotify", "dropbox": "Dropbox", "reddit": "Reddit",
    "telegram": "Telegram", "discord": "Discord", "slack": "Slack",
    "zoom": "Zoom", "yahoo": "Yahoo", "adobe": "Adobe",
    "steampowered": "Steam", "steamcommunity": "Steam",
    "proton": "Proton", "protonmail": "Proton Mail", "tutanota": "Tuta",
    "wordpress": "WordPress", "cloudflare": "Cloudflare",
    "digitalocean": "DigitalOcean", "openai": "OpenAI",
    "anthropic": "Anthropic", "claude": "Claude", "nvaccess": "NV Access",
    "freedomscientific": "Freedom Scientific", "tiktok": "TikTok",
    "snapchat": "Snapchat", "pinterest": "Pinterest", "twitch": "Twitch",
    "epicgames": "Epic Games", "playstation": "PlayStation",
    "nintendo": "Nintendo", "samsung": "Samsung", "aliexpress": "AliExpress",
    "booking": "Booking.com", "airbnb": "Airbnb", "uber": "Uber",
}

# Two-part endings such as co.uk, where the name is the part before them.
SECOND_LEVEL = {
    "co", "com", "net", "org", "gov", "edu", "ac", "or", "ne", "go", "gob",
    "mil", "nic", "ltd", "plc", "me", "info", "biz",
}

# Names that mean "no name": treated the same as an empty name.
PLACEHOLDERS = {"", "unknown", "(unknown)", "untitled", "(untitled)",
                "no title", "(no title)", "none", "(none)", "new entry",
                "imported entry", "(imported entry)", "-", "?"}

_HOST = re.compile(r"^[a-z0-9-]+(\.[a-z0-9-]+)+$")


def site_of(address):
    """The host of a web address, with no scheme, port, path or www.

    "https://user@www.example.com:8443/a?b" -> "example.com".
    Returns "" for something that is not an address.
    """
    text = (address or "").strip()
    if not text:
        return ""
    lowered = text.lower()
    if "://" in lowered:
        lowered = lowered.split("://", 1)[1]
    lowered = re.split(r"[/?#\\]", lowered, maxsplit=1)[0]
    if "@" in lowered:
        lowered = lowered.rsplit("@", 1)[1]
    if lowered.startswith("[") and "]" in lowered:      # [::1]:8080
        return lowered[1:lowered.index("]")]
    if lowered.count(":") == 1:
        lowered = lowered.split(":", 1)[0]
    for prefix in ("www.", "m.", "mobile."):
        if lowered.startswith(prefix) and lowered.count(".") >= 2:
            lowered = lowered[len(prefix):]
    lowered = lowered.strip(".")
    if _is_ip(lowered) or lowered == "localhost" or _HOST.match(lowered):
        return lowered
    return ""


def _is_ip(text):
    try:
        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def looks_like_address(text):
    """True when a name is really a web address rather than a name."""
    text = (text or "").strip()
    if not text or " " in text:
        return False
    lowered = text.lower()
    if "://" in lowered or lowered.startswith("www."):
        return True
    return bool(site_of(text)) and ("." in text or ":" in text)


def is_placeholder(title):
    return (title or "").strip().lower() in PLACEHOLDERS


def friendly_name(address):
    """A short name for a web address, or "" when none can be made."""
    host = site_of(address)
    if not host:
        return ""
    if _is_ip(host) or host == "localhost":
        return host
    parts = host.split(".")
    if len(parts) >= 3 and parts[-2] in SECOND_LEVEL and len(parts[-1]) == 2:
        main = parts[-3]
    elif len(parts) >= 2:
        main = parts[-2]
    else:
        main = parts[0]
    if main in BRANDS:
        return BRANDS[main]
    words = [word for word in main.replace("_", "-").split("-") if word]
    return " ".join(word[:1].upper() + word[1:] for word in words) or host


def needs_name(entry):
    """True when the entry's name is missing, a placeholder, or an address."""
    title = (entry.get("title") or "").strip()
    return is_placeholder(title) or looks_like_address(title)


def suggest(entry):
    """The name to suggest for an entry, or "" when there is nothing better."""
    for source in (entry.get("url"), entry.get("title")):
        name = friendly_name(source)
        if name:
            return name
    return ""


def display_title(entry):
    """What the entry lists show as its name.

    A proper name is shown as it is.  A missing name, a placeholder such as
    "unknown", or a whole web address is shown as the short site name.
    Only when there is nothing to go on is the user name shown, and last of
    all the words "No name".
    """
    title = (entry.get("title") or "").strip()
    if title and not needs_name(entry):
        return title
    name = suggest(entry)
    if name:
        return name
    if title and not is_placeholder(title):
        return title
    return (entry.get("username") or "").strip() or "No name"


def display_site(entry):
    """The web address column: only the site, and only when it adds news.

    Empty when the name already says the same thing, so a screen reader is
    not made to read "Google, google.com" on every row.
    """
    site = site_of(entry.get("url"))
    if not site:
        return ""
    shown = display_title(entry).lower()
    main = friendly_name(entry.get("url")).lower()
    if site in shown or (main and main == shown):
        return ""
    return site


def display_titles(entries):
    """Shown names for a whole list, telling same-named entries apart.

    Two Google accounts would both read "Google"; they read
    "Google, ann@gmail.com" and "Google, work@company.com" instead.  When
    there is no user name to tell them apart, the site is added, and last
    of all a number.
    """
    shown = [display_title(entry) for entry in entries]
    counts = {}
    for name in shown:
        counts[name.lower()] = counts.get(name.lower(), 0) + 1
    result = []
    seen = {}
    for entry, name in zip(entries, shown):
        if counts[name.lower()] < 2:
            result.append(name)
            continue
        extra = (entry.get("username") or "").strip()
        if not extra or extra.lower() in name.lower():
            extra = site_of(entry.get("url"))
            if extra and extra.lower() in name.lower():
                extra = ""
        label = f"{name}, {extra}" if extra else name
        number = seen.get(label.lower(), 0) + 1
        seen[label.lower()] = number
        result.append(label if number == 1 else f"{label} ({number})")
    return result
