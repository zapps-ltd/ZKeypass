"""Look up a site's real name from its web page, only when the user asks.

ZKeypass does not go on the network by itself.  This module is used only from
the Suggest names window, after the user has agreed, and it only reads the
page title of each site.

What is sent: an ordinary request for the site's front page, such as
https://example.com/.  The path, query and anything after # in the stored
address are dropped first, since they can hold session codes or names.
Nothing from the database is sent: no user name, no password, no notes.
"""

import html
import ipaddress
import re
import ssl
import urllib.error
import urllib.request

from . import names
from . import lang

TIMEOUT_SECONDS = 6
MAX_BYTES = 65536
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ZKeypass name lookup"

_TITLE = re.compile(rb"<title[^>]*>(.*?)</title\s*>", re.I | re.S)
_CHARSET = re.compile(rb"charset=[\"']?([A-Za-z0-9_\-]+)", re.I)
_SPLIT = re.compile(r"\s+[|\-–—:·•]\s+|:\s+")
_GENERIC = {"home", "homepage", "home page", "login", "log in", "sign in",
            "signin", "welcome", "index", "untitled", "document", "loading",
            "redirecting", "just a moment...", "attention required!",
            "access denied", "403 forbidden", "404 not found", "error"}


def front_page(address):
    """The front page of the site in an address, or "" if there is none.

    "https://user@mail.example.com:8443/inbox?s=abc#x" becomes
    "https://mail.example.com:8443/".  An address with no scheme gets
    https first.
    """
    text = (address or "").strip()
    if not text:
        return ""
    scheme = "https"
    rest = text
    if "://" in text:
        scheme, rest = text.split("://", 1)
        scheme = scheme.lower()
        if scheme not in ("http", "https"):
            return ""
    hostport = re.split(r"[/?#\\]", rest, maxsplit=1)[0]
    if "@" in hostport:
        hostport = hostport.rsplit("@", 1)[1]
    if not names.site_of(hostport):
        return ""
    return f"{scheme}://{hostport.lower()}/"


def is_local(address):
    """True for this computer and the home network: routers, printers, NAS."""
    host = names.site_of(address)
    if host == "localhost" or host.endswith(".local") or host.endswith(".lan"):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return ip.is_private or ip.is_loopback or ip.is_link_local


def _read(url, local):
    request = urllib.request.Request(url, headers={
        "User-Agent": USER_AGENT, "Accept": "text/html,*/*;q=0.5"})
    context = None
    if url.startswith("https://") and local:
        # Routers and printers use their own certificates, which no browser
        # trusts either.  Only a page title is read, so that is accepted for
        # addresses on the home network, and nowhere else.
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS,
                                context=context) as response:
        body = response.read(MAX_BYTES)
        charset = response.headers.get_content_charset() or ""
    return body, charset


def fetch_title(address):
    """The page title of the site's front page, or "" with a reason.

    Returns (title, problem).  problem is "" when a title was read.
    """
    url = front_page(address)
    if not url:
        return "", lang.t("dialogs", "not_a_web_address", "not a web address")
    local = is_local(url)
    tries = [url]
    if url.startswith("https://"):
        tries.append("http://" + url[len("https://"):])
    problem = ""
    for attempt in tries:
        try:
            body, charset = _read(attempt, local)
        except urllib.error.HTTPError as error:
            problem = lang.t(
                "dialogs", "the_site_answered",
                "the site answered {code}",
                code=error.code)
            continue
        except (urllib.error.URLError, OSError, ValueError) as error:
            reason = getattr(error, "reason", error)
            problem = lang.t(
                "dialogs", "no_answer",
                "no answer ({reason})",
                reason=reason)
            continue
        match = _TITLE.search(body)
        if not match:
            problem = lang.t(
                "dialogs", "the_page_has_no_title",
                "the page has no title")
            continue
        if not charset:
            found = _CHARSET.search(body[:4096])
            charset = found.group(1).decode("ascii") if found else "utf-8"
        try:
            text = match.group(1).decode(charset, "replace")
        except LookupError:
            text = match.group(1).decode("utf-8", "replace")
        title = " ".join(html.unescape(text).split())
        if title:
            return title, ""
        problem = lang.t(
            "dialogs", "the_page_title_is_empty",
            "the page title is empty")
    return "", problem


def choose_name(title, address):
    """Pick the site's name out of a page title.

    "Sign in - Google Accounts" for google.com gives "Google Accounts";
    "Online Banking | My Bank" gives "My Bank".  A title that says nothing,
    such as "Login" or "Just a moment...", gives "".
    """
    title = (title or "").strip()
    if not title or title.lower() in _GENERIC:
        return ""
    parts = [part.strip() for part in _SPLIT.split(title) if part.strip()]
    parts = [part for part in parts if part.lower() not in _GENERIC] or parts
    brand = names.friendly_name(address).lower()
    if brand:
        squeezed = brand.replace(" ", "")
        matching = [part for part in parts
                    if squeezed in part.lower().replace(" ", "")]
        if matching:
            return _trim(min(matching, key=len))
    if len(parts) > 1:
        return _trim(parts[-1])
    return _trim(parts[0])


def _trim(text, limit=48):
    text = text.strip(" -|:")
    if len(text) <= limit:
        return text
    return text[:limit].rsplit(" ", 1)[0].rstrip(" ,.-") or text[:limit]
