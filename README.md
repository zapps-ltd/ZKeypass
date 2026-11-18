# ZKeypass

ZKeypass is a portable, offline password manager for Windows. It opens and saves KeePass databases (`.kdbx`) that work in KeePassXC and KeePass 2, and it can also keep a database in its own single-file format (`.zkp`). It is written in Python with wxPython, uses only ordinary Windows controls, and is built to be used equally well with a screen reader or with eyes and mouse.

Everything it writes stays in one folder beside the program. It never goes online by itself.

## Why it exists

Password managers are often hard to use with a screen reader, or want an account, a cloud service or an installer. ZKeypass is made for people who need to hear and drive every step from the keyboard, and for people who want their passwords in a file they own, on a USB stick if they like, in a format other programs can open.

## Features

Databases
- Opens, creates and saves KeePass databases (`*.kdbx`, KDBX 3 and 4) that open in KeePassXC, KeePass 2 and compatible programs. KDBX 2 and earlier are not supported.
- Keeps the cipher, key derivation and cost settings of a database when it is opened and saved again.
- Its own single encrypted file format (`*.zkp`) for ZKeypass only.
- Ciphers for KeePass databases: AES-256-CBC, ChaCha20, Twofish-256-CBC, and AES-128 for very old databases (KeePassXC 2.7 refuses to open AES-128 databases).
- Key derivation: Argon2id, Argon2d and AES-KDF for KeePass databases; Argon2id, scrypt and PBKDF2-HMAC-SHA256 for ZKeypass databases.
- Integrity: HMAC-SHA-256 block stream for KDBX 4; AES-256-GCM or ChaCha20-Poly1305 for ZKeypass databases.
- New database window with "Encryption method", "Password hardening" and "Unlock strength".
- Master password, optional key file (KeePass format, can be created in the program), and optional YubiKey, used together.
- "Keep a portable copy": copies a database into the data folder and opens the copy, leaving the original untouched.
- Recent databases list on the first window and in the Database menu.
- A backup copy before every save; the newest ten backups of each database are kept.
- Save a copy as: writes the open database as the other format, keeping groups, entries, extra fields, stored files, authenticator secrets, expiry dates, auto-type settings and passkeys. The copy gets its own password and can have a key file. The original is not changed.
- Export to a readable file: CSV, KeePass XML, HTML table or plain text, with or without passwords, and can write stored files beside the export. The program warns before it writes, because an export is not encrypted.
- Database and encryption details window.

Entries
- Title, user name, password, web address, notes, groups, favourites, duplicate, entry expiry date, and any number of extra fields, each of which can be hidden.
- Stored files inside the encrypted database: drag files onto the entry editor or the main window, or use "Add a file to this entry". "Save a stored file to disk" writes the file back byte for byte.
- Search box on the Entries page; sort by name, user name, site, group or date changed, ascending or descending; choose which columns are shown.
- Entry names: an entry with no name, a placeholder such as "unknown" or a whole web address gets a short readable name made from the address. "Suggest names for entries without one" lists them with suggestions you can untick. Where two entries would read the same, the user name is added.
- Context menu on the entry list: copy password, user name, verification code or web address; show the password character by character; open the address in the browser; edit; rename; set or change the user name; move to another group; duplicate; favourite; auto-type; delete.

Passwords
- Password generator: character passwords with selectable sets (upper case, lower case, digits, symbols, extended, no look-alike characters) and a chosen length, with a strength estimate.
- Passphrases with the bundled EFF large word list (7776 words): word count, separator, capitals and a number.
- Password check-up: lists weak passwords, reused passwords, passwords older than a chosen age, and entries missing a user name or web address, as plain sentences.

Verification codes (TOTP)
- A setup key or a full `otpauth://` link per entry; SHA-1, SHA-256 or SHA-512; six or eight digits; any period.
- Reads setup keys the way KeePassXC and KeePass Android ports write them, including "TOTP Seed" with "TOTP Settings", an `otp` attribute with an `otpauth://` link, and older names.
- Authenticator page (Control 2) with a live code for every entry that has a setup key, a search box, a group filter and a plain sentence under the list. Codes can be copied, read aloud, or shown as a setup key.
- Global hot key Control Alt T copies the code of the selected account from any program.
- No QR code scanning; setup keys arrive as text, as a link, or through an import.

Auto-type
- Per-entry sequences such as `{USERNAME}{TAB}{PASSWORD}{ENTER}` with placeholders for title, user name, password, web address, notes, verification code, date, time, group and identifier; `{TAB}`, `{ENTER}`, `{DELAY 500}`; and the `+`, `^`, `%` modifier prefixes.
- Window associations matched against the active window title, with `*` and `?` wildcards and `|` alternatives.
- Global hot key Control Alt A, changeable in Settings.

Passkeys
- Create a passkey inside an entry (ES256, EdDSA or RS256), show its public key, sign an assertion on request, remove it. Stored with the KeePassXC attribute names, so a KeePass database carries them both ways.

SSH agent
- A named-pipe agent (`\\.\pipe\zkeypass-agent`) that serves Ed25519, ECDSA and RSA private keys kept as stored files.

Browser integration
- Off by default. A service on `127.0.0.1`, or native messaging for a browser that starts the program itself.
- X25519 handshake, then messages sealed with ChaCha20-Poly1305. A browser can ask for logins for a site, a generated password or a verification code, store a new login, and lock the database.
- Pairing always asks you first; paired browsers are recorded inside the database.
- The protocol follows the message names of KeePassXC-Browser, but that extension seals its payloads with libsodium `crypto_box`, so it will not pair. An extension written for ZKeypass will.

Security keys, Windows Hello and start-up
- YubiKey HMAC-SHA1 challenge-response over USB, reached through Windows HID calls with no extra package. The answer joins the master password and key file; the challenge and answer are never stored. This path was tested against a software token; a real YubiKey was not available for testing.
- Windows Hello (PIN, fingerprint or face) to open a database you have already opened once with its password. See Privacy and security.
- Optional start with Windows, to the notification area and locked; optionally opening the current database at sign-in without asking, only if your Windows account has a sign-in password. A database that needs a security key always starts locked.
- Notification area icon (teal when a database is open, amber when locked) with Show, Settings and Quit.
- Automatic lock after a chosen time of no activity, lock with Control L, quit with Control Shift Q.
- Clipboard cleared after a chosen time (20 seconds by default).

Importing from other programs
- Opening a KeePass database is not an import; it is opened and saved in place.
- Tools, Import entries from: CSV (KeePassXC and other managers, headings mapped automatically), Bitwarden or Vaultwarden JSON (plain or password-protected), 1Password `.1pux`, 1Password OPVault folder, KeePass 1.x `.kdb` (AES or Twofish), Password Safe v3 `.psafe3`, Proton Pass (ZIP or JSON, not the PGP-encrypted export), Enpass JSON, and Dashlane "Unsecured Archive in JSON".
- Every import goes into a new group named Imported plus the date, leaves existing entries alone, and asks you to confirm the count first. ZKeypass does not write those formats; it only reads them.

## Accessibility

- Every control is an ordinary Windows control with a name; tab order follows the visual order; the menu bar reaches every command.
- Windows' own Open, Save and folder dialogs are used everywhere, which JAWS and NVDA already know.
- Every action says its result aloud and shows it on the status bar, whether it came from a menu, a button or a hot key, including global hot keys used in other programs. Self-refreshing summaries such as the entry count are not spoken.
- Spoken through JAWS (its COM interface; needs pywin32 or comtypes when run from source), NVDA (`nvdaControllerClient.dll`, 64-bit, if you place a copy in the `libs` folder; otherwise a Windows UI Automation notification) and Narrator (UI Automation). ZoomText or Fusion, Dolphin SuperNova or ScreenReader, and any screen reader that tells Windows it is running are detected.
- Settings, General, "Announce actions aloud": Automatically (default, speaks only while a screen reader runs), Always, or Never. Settings shows which screen reader is running.
- Help, Hotkeys list (F1) shows every shortcut in a read-only box.
- Keyboard model: Control Shift C copies the password, Control B the user name, Control T the verification code, Control U the web address. Control C is left alone so it copies selected text. Control 1 and Control 2 switch between Entries and Authenticator. F2 renames, Applications key or Shift+F10 opens the context menu, Alt plus the underlined letter works on buttons and menus.
- A dark theme that follows Windows high contrast (plain look) and can be turned off in Settings, "Look and start"; effects stay still when Windows animations are off.
- Message boxes read their message aloud as they open.

## Privacy and security

- Offline by default. ZKeypass never contacts the network by itself.
- Only one optional online feature exists: "Look up real names online" in the Suggest names window. It asks first ("Allow this time", "Always allow" or "Cancel"), opens only each site's front page to read its title, shows an activity list with a progress bar and a Stop button, and sends nothing from your database. Settings, General can turn the question off or back on.
- The browser service listens on `127.0.0.1` only and is off until you turn it on.
- Encrypted: databases and everything in them (entries, passwords, setup keys, passkeys, stored files), and their backups in `data\backups`. The Windows Hello record (`data\quick_unlock.json`) is sealed with a key that never leaves Windows Hello; it opens nothing on another computer, another Windows account or after a Windows PIN reset. The start-up record (`data\startup_unlock.json`, present only if you chose open-at-sign-in) is sealed with Windows data protection (DPAPI) for your account.
- Not encrypted, on purpose and with a warning each time: exports and stored files you save to disk. Delete them when you have finished. Key files are keys, kept wherever you choose.
- Not encrypted and secret-free: `data\settings.json` holds preferences and the paths of recently used databases.
- Copied passwords and codes are kept out of Windows clipboard history and cloud clipboard, are cleared after the set time and when ZKeypass closes. A later copy of your own is never wiped.
- Passwords are held in memory while a database is open, and Windows can write memory to its page file. Lock (Control L) when you step away.
- A backup opens with the master password it was saved with, so old backups age out after you change a master password.

## Requirements

- Windows 10 or 11, 64-bit.
- A build needs nothing else installed.
- From source: Python 3.14 (64-bit) and these packages: `wxPython`, `cryptography`, `cffi`, `pycparser`, `typing_extensions`, and `winrt-runtime` with `winrt-Windows.Foundation`, `winrt-Windows.Foundation.Collections`, `winrt-Windows.Security.Credentials` and `winrt-Windows.Storage.Streams` (Windows Hello). Optional: `pywin32` or `comtypes` for speech through JAWS.

## Running ZKeypass

A build is one `ZKeypass` folder:

    ZKeypass.exe     the launcher
    apps_files\      the program files; nothing in here needs opening
    data\            settings, backups, exports and temporary files

Double-click `ZKeypass.exe`. To update, paste a new build over the old one; a build ships its data folder empty, so your settings and data stay.

From source, in the project folder:

    python zkeypass.py

Source runs write into a `data` folder beside `zkeypass.py`. Other command lines:

    python zkeypass.py --startup                        straight to the notification area (what Windows runs at sign-in)
    python zkeypass.py --native-messaging --vault FILE  browser host mode
    python zkeypass.py --list-tools                     show the detection report

To make your own build, use PyInstaller in one-folder mode with the program folder as `apps_files`, the icon from `assets`, and the `lang`, `wordlists` and `assets` folders alongside the code.

## Using it, step by step

Opening a database. ZKeypass never shows a password box before you choose a file. The first window, "ZKeypass - choose a database", has the focus on the recent list.
1. Arrow to a database and press Enter to open it.
2. "Browse this computer for a database file..." always opens the Windows Open dialog.
3. "Open a database..." opens the highlighted recent row, or the Open dialog if the list is empty.
4. "Keep a portable copy..." copies a database into the data folder and opens the copy.
5. "Create a new database..." makes an empty one; the password you type is used straight away.
6. "Quit" closes without opening anything.

Windows file dialogs. Alt+N is the File name box (type a full path or folder, then Enter); Alt+D is the address bar; Backspace in the list goes up a folder; Shift+Tab from the list reaches This PC, drives and network places. Each dialog starts in the folder used last.

Authenticator. Open it with Control 2, the tab, the Authenticator menu or the button on the Entries page. Enter or Control T copies the selected code; R reads the setup key aloud; S copies it; E edits the entry; F5 refreshes; Space repeats the account and its code.

Importing. Tools, Import entries from, choose the program the file came from, pick the file, confirm the count. Save the database afterwards.

Start with Windows. Settings, Look and start, "Start ZKeypass when I sign in to Windows" adds one value named ZKeypass under `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`; unticking removes it. This is the only thing written outside the data folder.

## Folder layout and where things are stored

- `data\settings.json` preferences and recent databases.
- `data\backups` a copy of a database before every save.
- `data\exports` where saved stored files and exports start.
- `data\quick_unlock.json` the Windows Hello record.
- `data\startup_unlock.json` the open-at-sign-in record, only if enabled.
- `data\_tmp` temporary files, including ones libraries create (`TEMP`, `TMP` and `TMPDIR` are redirected here).
- `lang\<code>\<code>.lang` interface languages. `wordlists` the EFF word list. `libs` bundled Python packages (source runs).

Older builds kept data in `ZKeypass\data`; the first start of a newer build moves it beside `ZKeypass.exe`.

## Languages

ZKeypass has 21 interface languages: Arabic, Bengali, Chinese (Simplified and Traditional), English, French, German, Hindi, Indonesian, Italian, Japanese, Korean, Malay, Persian, Portuguese (Brazil and Portugal), Russian, Spanish, Thai, Turkish and Vietnamese. Right-to-left languages are supported.

Settings, General, Language chooses one; "Same as Windows" is the default and takes effect on the next start. Each language is one plain text file, `lang\<code>\<code>.lang`. To translate or correct one, copy the `en` folder, rename the folder and the file to your language code, and change the text after each equals sign; the notes at the top of the file explain the rest. Missing keys fall back to English.

## Limits

- KDBX 2 and earlier are not supported.
- AES-128 databases are read and written but KeePassXC 2.7 will not open them.
- The KeePassXC-Browser extension cannot pair (see Browser integration).
- The authenticator lists only entries in the open database; there is no QR scanning.
- Proton Pass's PGP-encrypted export cannot be read; export without encryption.

## Reporting problems and contact

Please report bugs, translation problems, ideas and security problems by email to support@zapps.ltd or through the contact page of https://zapps.ltd. Pull requests are not accepted. ZKeypass stays accessible: tab order, names and where focus lands are part of correctness.

ZKeypass is made by Harith and Mesar, the zapps.ltd developers, ZAPPS SOFTWARE LTD.

## License

ZKeypass is free software, licensed under the GNU Affero General Public License, version 3 or (at your option) any later version (AGPL-3.0-or-later). The full text is in the file LICENSE. In short: you may use, study, change and share it, but every copy and every modified version, including one that other people use over a network, must stay under the same license, must come with its complete source code, and must keep the copyright notices and the credits below. Nobody can make a closed version of it. Copyright (C) 2026 ZAPPS SOFTWARE LTD.

## Logo and icons

The ZAPPS name, the ZAPPS Z logo and the ZKeypass icon are owned by ZAPPS SOFTWARE LTD. Copyright 2026 ZAPPS SOFTWARE LTD, all rights reserved. They are not covered by this software's open-source licence and may not be used for other software or modified versions without written permission.

## Third-party software and credits

ZKeypass is built using:
- wxPython and wxWidgets (wxWindows Library Licence 3.1): the interface.
- cryptography (Apache-2.0 or BSD-3-Clause) with OpenSSL (Apache-2.0): encryption.
- cffi (MIT-0), pycparser (BSD-3-Clause), typing_extensions (PSF-2.0), PyWinRT (MIT): support libraries.
- Python (PSF-2.0) and PyInstaller (GPL-2.0-or-later with the bootloader exception) in builds.
- EFF Large Wordlist for Passphrases (CC BY 3.0 US): passphrase words.
- KeePassXC translations (GPL-2.0 or GPL-3.0): password-manager terms in several interface languages.
- KeePass and KDBX, KeePassXC, Bitwarden, Dashlane, Enpass, 1Password, Proton Pass, Password Safe and YubiKey formats and protocols, which ZKeypass follows and does not copy code from.

Names, authors, licenses, project links and the required notices are in THIRD_PARTY_NOTICES.md.
