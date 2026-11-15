# Third-party notices

ZKeypass is free software under the GNU Affero General Public License, version 3 or later (AGPL-3.0-or-later), Copyright (C) 2026 ZAPPS SOFTWARE LTD. It ships, bundles or loads the components below. Each keeps its own license and copyright. Versions are those in the bundled `libs` folder at the time of writing.

## Components shipped or bundled in a build

- wxPython (with wxWidgets), by Robin Dunn and the wxWidgets developers. The window toolkit for the whole interface. License: wxWindows Library Licence, version 3.1 (SPDX: wxWindows). https://wxpython.org and https://www.wxwidgets.org
- cryptography 50.0.2, by The Python Cryptographic Authority and individual contributors. AES, ChaCha20, Argon2, scrypt, PBKDF2, HMAC, X25519, ECDSA, Ed25519, RSA. License: Apache-2.0 OR BSD-3-Clause (you may choose either). https://github.com/pyca/cryptography
- OpenSSL 4.0.3, statically included in the cryptography wheel (listed in its software bill of materials), by The OpenSSL Project. License: Apache-2.0. https://www.openssl.org
- Rust crates compiled into the cryptography wheel. They are listed, with their licenses, in the file `cryptography-50.0.2.dist-info\sboms\cryptography-rust.cyclonedx.json` shipped in `libs`.
- cffi 2.1.1, by Armin Rigo and Maciej Fijalkowski. Calls C code from Python (needed by cryptography). License: MIT-0 (MIT No Attribution). https://github.com/python-cffi/cffi
- pycparser 3.11, by Eli Bendersky. Used by cffi. License: BSD-3-Clause. https://github.com/eliben/pycparser
- typing_extensions 4.16.0, by Guido van Rossum, Jukka Lehtosalo, Lukasz Langa, Michael Lee and contributors. Typing backports. License: PSF-2.0 (Python Software Foundation License 2.0). https://github.com/python/typing_extensions
- PyWinRT 3.2.1 (packages winrt-runtime, winrt-Windows.Foundation, winrt-Windows.Foundation.Collections, winrt-Windows.Security.Credentials, winrt-Windows.Storage.Streams), by Microsoft Corporation and David Lechner. Reaches Windows Hello. License: MIT. https://github.com/pywinrt/pywinrt
- Python, by the Python Software Foundation. The runtime in a build. License: PSF-2.0. It brings its own OpenSSL 3.5 (libssl-3.dll and libcrypto-3.dll, Apache-2.0), libffi (MIT) and SQLite (public domain), which are also in a build. https://www.python.org
- PyInstaller, by the PyInstaller Development Team. Used to make a build; its bootloader becomes part of `ZKeypass.exe`. License: GPL-2.0-or-later with a special exception that lets the bootloader be used in programs under any license. https://pyinstaller.org
- Microsoft Visual C++ runtime and Universal C runtime (VCRUNTIME140.dll, VCRUNTIME140_1.dll, MSVCP140.dll, ucrtbase.dll and the api-ms-win-*.dll files), by Microsoft, in a build. License: Microsoft redistributable terms. https://learn.microsoft.com/cpp/windows/redistributing-visual-cpp-files

Optional, not shipped by ZKeypass but used when installed in a source run or build:
- pywin32 by Mark Hammond and contributors (PSF-2.0, https://github.com/mhammond/pywin32) or comtypes by Thomas Heller and contributors (MIT, https://github.com/enthought/comtypes): speech through the JAWS COM interface.
- NVDA Controller Client (`nvdaControllerClient.dll`) by NV Access (LGPL-2.1, https://github.com/nvaccess/nvda): ZKeypass does not ship it; if you put your own copy in `libs`, ZKeypass loads it to speak through NVDA.
- JAWS (Freedom Scientific) is reached only through its public COM interface; nothing of it is included.

## Data

- EFF Large Wordlist for Passphrases (`wordlists\eff_large_wordlist.txt`, 7776 words), by the Electronic Frontier Foundation. Used for passphrases. License: Creative Commons Attribution 3.0 United States (CC-BY-3.0-US), EFF's license when the list was published in 2016 (EFF's current policy: https://www.eff.org/copyright). The copy here has the dice numbers removed; the words are unchanged. https://www.eff.org/deeplinks/2016/07/new-wordlists-random-passphrases
- KeePassXC translations, by the KeePassXC Team and translators. The password-manager terms (database, entry, group, master password, key file, auto-type, passkey and so on) in the interface languages were taken from KeePassXC's translation files where KeePassXC has one; other text is translated directly. License of KeePassXC: GPL-2.0-only OR GPL-3.0-only. https://github.com/keepassxreboot/keepassxc
- The ZKeypass icon and logo (assets folder) are the project's own work, covered by the license of ZKeypass (AGPL-3.0-or-later).

## Formats and protocols only followed

No code, text or data of these projects is copied. ZKeypass implements the public or documented behaviour so that files and messages are compatible.
- KeePass and the KDBX format 3 and 4, by Dominik Reichl; KDB (KeePass 1.x) format; KeePass XML export. https://keepass.info
- KeePassXC, by the KeePassXC Team: its attribute names for passkeys and one-time passwords, and the message names of KeePassXC-Browser. https://keepassxc.org
- Twofish, by Bruce Schneier, John Kelsey, Doug Whiting, David Wagner, Chris Hall and Niels Ferguson. ZKeypass has its own pure-Python implementation written from the published specification and checked against the official test vectors. The algorithm is in the public domain.
- Bitwarden and Vaultwarden JSON export (https://bitwarden.com), Dashlane archive (https://www.dashlane.com), Enpass JSON export (https://www.enpass.io), 1Password 1PUX and OPVault (https://1password.com), Proton Pass export (https://proton.me/pass), Password Safe v3 by Bruce Schneier and the Password Safe project (https://pwsafe.org): file formats read by the importers.
- YubiKey challenge-response over HID, by Yubico (https://www.yubico.com). Windows Hello, Windows data protection (DPAPI), the Windows clipboard, and UI Automation, by Microsoft.
- TOTP (RFC 6238), HOTP (RFC 4226), the `otpauth://` link format, WebAuthn/passkeys (COSE), the OpenSSH agent protocol, Diceware, and the Argon2, scrypt and ChaCha20-Poly1305 algorithms are open standards.

All product names belong to their owners and are used only to say what ZKeypass can read or work with.

## Licenses and compatibility with AGPL-3.0-or-later

These components keep their own licenses; ZKeypass's AGPL-3.0-or-later applies to ZKeypass's own code only.
- Compatible: MIT, MIT-0, BSD-3-Clause, Apache-2.0 (version 2.0 is compatible with GPL version 3 and so with AGPL version 3), PSF-2.0, wxWindows Library Licence 3.1 (LGPL-style with an exception; compatible), and CC-BY-3.0-US for the word list, which is a data file shipped beside the program and not linked into it.
- PyInstaller's bootloader: GPL-2.0-or-later with its exception, which allows it in programs under any license; the combination is compatible with AGPL-3.0.
- KeePassXC terms: the GPL-3.0-only option is compatible with AGPL-3.0 (GPL version 3 section 13 allows combining). The GPL-2.0-only option alone would not be, but KeePassXC offers GPL-3.0 as an alternative, so ZKeypass takes it under GPL-3.0.
- No incompatibility was found. CC-BY-3.0 is not formally listed by the FSF as one-way compatible with GPL-3.0, which is why the word list is kept as a separate data file under its own license, with attribution.

## Notices that must accompany copies

A copy of ZKeypass that includes these components must keep their license texts and copyright notices. The full texts are in the `licenses` folders under `libs\*.dist-info` (PyWinRT ships none there; its MIT text is at https://github.com/pywinrt/pywinrt/blob/main/LICENSE) and in the upstream projects. The notices that must be kept:

- cryptography: Copyright (c) Individual contributors. All rights reserved. Dual-licensed under Apache-2.0 and BSD-3-Clause. Under BSD: redistributions must retain the copyright notice, the list of conditions and the disclaimer, and in binary form reproduce them in the documentation or other materials provided; the names of the project and contributors may not be used to endorse derived products without permission.
- OpenSSL: Copyright (c) The OpenSSL Project Authors. Apache License 2.0; keep the license text and NOTICE content.
- pycparser: Copyright (c) 2008-2027, Eli Bendersky. All rights reserved. BSD-3-Clause, conditions as above.
- cffi: MIT No Attribution, by Armin Rigo and Maciej Fijalkowski; no notice is required, but the license file is kept.
- PyWinRT: Copyright (c) Microsoft Corporation. All rights reserved. Copyright (c) 2021-2026 David Lechner. MIT License: the copyright notice and this permission notice must be included in all copies or substantial portions of the software; the software is provided "as is", without warranty of any kind.
- typing_extensions and Python: Copyright (c) Python Software Foundation (and earlier holders: Stichting Mathematisch Centrum, CNRI, BeOpen, Zope Corporation). The PSF license agreement and copyright notice must be included.
- wxPython and wxWidgets: Copyright (c) Robin Dunn, Julian Smart and the wxWidgets developers. Under the wxWindows Library Licence 3.1, binary distributions may be made under the terms of your choice, provided the license text of wxWidgets is available to recipients.
- EFF Large Wordlist: Copyright (c) 2016 Electronic Frontier Foundation, licensed CC BY 3.0 US. Credit is given here and in the program's About page.
- PyInstaller: Copyright (c) PyInstaller Development Team. The bootloader exception text is in PyInstaller's COPYING.txt.
