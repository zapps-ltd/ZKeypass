"""About page in the zapps.ltd look: one HTML page, built each time it is
opened so the developers team is listed in a random order, and shown in
the default browser. Nothing on the page loads from the internet; its
links open only when they are clicked."""

import base64
import html
import os
import random

SUPPORT_EMAIL = "support@zapps.ltd"
HOME_PAGE = "https://zapps.ltd"
TEAM = ("Harith", "Mesar")

CSS = """
:root { color-scheme: light dark; --bg: #f4f6fb; --card: #ffffff;
  --text: #1a1e29; --muted: #4b5366; --accent: #1d5bbf; --on-accent: #ffffff;
  --border: #d8dce6; --focus: #ffb000; }
@media (prefers-color-scheme: dark) { :root { --bg: #11141b; --card: #1a1f2c;
  --text: #eef1f7; --muted: #bcc3d2; --accent: #8ab4ff; --on-accent: #0b1220;
  --border: #2c3346; } }
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text);
  font: 17px/1.6 "Segoe UI", system-ui, -apple-system, Roboto, sans-serif; }
main { max-width: 46rem; margin: 0 auto; padding: 1.5rem 1.1rem 2.5rem; }
.hero { background: linear-gradient(135deg, #1d5bbf, #6a3fc2); color: #ffffff;
  border-radius: 18px; padding: 1.6rem 1.5rem; margin-bottom: 1.25rem; }
.hero h1 { margin: 0 0 .35rem; font-size: 1.9rem; line-height: 1.25; }
.hero p { margin: .15rem 0; }
.hero { display: flow-root; }
.hero .mark { float: right; width: 4.5rem; height: 4.5rem; margin: -.3rem -.3rem .3rem .8rem; }
[dir="rtl"] .hero .mark { float: left; margin: -.3rem .8rem .3rem -.3rem; }
.hero .by { font-size: 1.15rem; font-weight: 600; }
section { background: var(--card); border: 1px solid var(--border);
  border-radius: 14px; padding: 1.1rem 1.4rem; margin: 0 0 1rem; }
h2 { margin: 0 0 .6rem; font-size: 1.3rem; color: var(--accent); }
ul { margin: .3rem 0; padding-inline-start: 1.3rem; }
li { margin-bottom: .4rem; }
a { color: var(--accent); }
.buttons { display: flex; flex-wrap: wrap; gap: .6rem; margin: .4rem 0 0; }
a.button { display: inline-block; background: var(--accent); color: var(--on-accent);
  padding: .65rem 1.15rem; border-radius: 10px; text-decoration: none; font-weight: 600; }
a.button.secondary { background: transparent; color: var(--accent);
  border: 2px solid var(--accent); }
a:focus-visible { outline: 3px solid var(--focus); outline-offset: 3px; }
footer { color: var(--muted); text-align: center; font-size: .95rem; margin-top: 1.4rem; }
@media (forced-colors: active) { .hero { background: Canvas; color: CanvasText;
  border: 1px solid CanvasText; } a.button { border: 2px solid LinkText; } }
"""


def _plain(key, default, **values):
    return default.format(**values) if values else default


def _block(item):
    if isinstance(item, (list, tuple)):
        return "<ul>%s</ul>" % "".join(
            "<li>%s</li>" % html.escape(str(x)) for x in item)
    return "<p>%s</p>" % html.escape(str(item))


def mark_image(svg_path):
    """The ZAPPS Z mark as a decorative image for the hero: empty alt text
    and aria-hidden, so screen readers skip it. Empty when the file is
    missing."""
    try:
        with open(svg_path, "rb") as handle:
            data = base64.b64encode(handle.read()).decode("ascii")
    except OSError:
        return ""
    return ('<img class="mark" src="data:image/svg+xml;base64,%s" alt=""'
            ' aria-hidden="true" width="72" height="72">' % data)


def build_html(app, version, sections, credits, license_line="", t=_plain,
               rtl=False, lang_code="en", static_team=False, mark="",
               ownership_line=""):
    """sections: [(heading, [paragraph or [items]])]; credits: [str]."""
    e = html.escape
    first, second = random.sample(TEAM, 2)
    title = t("title", "About {app}", app=app)
    out = ['<!DOCTYPE html>',
           '<html lang="%s" dir="%s">' % (e(lang_code), "rtl" if rtl else "ltr"),
           '<head>', '<meta charset="utf-8">',
           '<meta name="viewport" content="width=device-width, initial-scale=1">',
           '<title>%s</title>' % e(title), '<style>%s</style>' % CSS, '</head>',
           '<body>', '<main>', '<header class="hero">']
    if mark:
        out.append(mark)
    out += ['<h1>%s</h1>' % e(title),
           '<p class="by">%s</p>' % e(t("by", "By zapps-ltd"))]
    if version:
        out.append('<p>%s</p>' % e(t("version", "Version {version}", version=version)))
    out.append('</header>')
    for heading, blocks in sections:
        out.append('<section>')
        out.append('<h2>%s</h2>' % e(heading))
        out.extend(_block(b) for b in blocks)
        out.append('</section>')
    team = t("team", "zapps.ltd developers: {first} and {second}",
             first="\x00a", second="\x00b")
    team = e(team)
    if static_team:
        team = team.replace("\x00a", '<span id="team-first">%s</span>' % TEAM[0])
        team = team.replace("\x00b", '<span id="team-second">%s</span>' % TEAM[1])
    else:
        team = team.replace("\x00a", e(first)).replace("\x00b", e(second))
    out += ['<section>', '<h2>%s</h2>' % e(t("team_heading", "Developers team")),
            '<p>%s</p>' % team, '</section>',
            '<section>', '<h2>%s</h2>' % e(t("contact_heading", "Contact")),
            '<p class="buttons"><a class="button" href="mailto:%s">%s</a>'
            ' <a class="button secondary" href="%s">%s</a></p>' % (
                SUPPORT_EMAIL, e(t("email", "Email {email}", email=SUPPORT_EMAIL)),
                HOME_PAGE, e(t("home", "Visit zapps.ltd"))),
            '</section>']
    if credits or license_line or ownership_line:
        out += ['<section>', '<h2>%s</h2>' % e(t("credits_heading", "Credits and licenses"))]
        if credits:
            out.append(_block(list(credits)))
        if license_line:
            out.append(_block(license_line))
        if ownership_line:
            out.append(_block(ownership_line))
        out.append('</section>')
    out += ['<footer><p>%s</p></footer>' % e(t(
        "copyright", "Copyright © 2026 ZAPPS SOFTWARE LTD.")), '</main>']
    if static_team:
        out.append('<script>(function () { if (Math.random() < 0.5) {'
                   ' var a = document.getElementById("team-first"),'
                   ' b = document.getElementById("team-second");'
                   ' if (a && b) { var x = a.textContent; a.textContent = b.textContent;'
                   ' b.textContent = x; } } })();</script>')
    out += ['</body>', '</html>', '']
    return "\n".join(out)


def open_page(folder, page):
    """Write the page into folder (inside the app's own data) and open it
    in the default browser."""
    os.makedirs(folder, exist_ok=True)
    path = os.path.join(folder, "about.html")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(page)
    os.startfile(path)
    return path


def show_about():
    """The About page for ZKeypass in the current language, written into
    the data folder's _tmp. Nothing is fetched from the internet."""
    from . import APP_VERSION, lang, paths

    def t(key, default, **values):
        return lang.t("dialogs", "about_page_" + key, default, **values)

    copy_text = lang.t(
        "errors", "zkeypass_portable_offline_password_manager_pro",
        "ZKeypass  portable, offline password manager.\n\nProgram: "
                "{app_dir}\nData: {data_dir}\n\nSettings, backups, exports "
                "and temporary files all stay in the data folder. ZKeypass "
                "never goes online by itself; only Suggest names can look up "
                "page names, when you ask it to.",
        app_dir=paths.APP_DIR,
        data_dir=paths.DATA_DIR)
    blocks = []
    for part in copy_text.split("\n\n"):
        lines = [line.strip() for line in part.strip().split("\n") if line.strip()]
        if lines:
            blocks.append(lines[0] if len(lines) == 1 else lines)
    # Only the last part: the data stays in the data folder and ZKeypass
    # never goes online by itself. The name line and the folder paths are
    # not shown.
    blocks = blocks[-1:]
    credits = [
        "wxPython - wxWindows Library Licence",
        "cryptography - Apache License 2.0 or BSD 3-Clause License",
        "OpenSSL, inside cryptography - Apache License 2.0",
        "cffi - MIT No Attribution License (MIT-0)",
        "pycparser - BSD 3-Clause License",
        "typing_extensions - Python Software Foundation License",
        "PyWinRT (winrt) - MIT License",
        "EFF Large Wordlist (Electronic Frontier Foundation) - Creative Commons Attribution 3.0",
        "KeePassXC translations (password-manager terms) - GNU General Public License version 3",
        "Python - Python Software Foundation License",
        "PyInstaller (bootloader, in the built program) - GNU General Public License version 2 or later with the bootloader exception",
    ]
    page = build_html("ZKeypass", APP_VERSION,
                      [(t("this_copy_heading", "This copy"), blocks)], credits,
                      license_line=t("license",
                                     "{app} is free software under the GNU Affero General Public License, version 3 or later. This applies to the code of {app} only: every component listed above keeps its own license.",
                                     app="ZKeypass"),
                      t=t, rtl=lang.is_rtl(), lang_code=lang.current_code(),
                      mark=mark_image(os.path.join(paths.APP_DIR, "assets",
                                                   "zapps-mark.svg")),
                      ownership_line=t("ownership",
                                       "The ZAPPS name, the ZAPPS Z logo and the {app} icon are owned by ZAPPS SOFTWARE LTD. Copyright 2026 ZAPPS SOFTWARE LTD, all rights reserved. They are not covered by this software's open-source licence and may not be used for other software or modified versions without written permission.",
                                       app="ZKeypass"))
    return open_page(paths.TMP_DIR, page)
