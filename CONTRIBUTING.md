# Contributing

Start with [README.md](README.md), [README.zh.md](README.zh.md), and the [upstream attribution](THIRD_PARTY_NOTICES.md). This Windows x64 manager targets one exact reviewed client build.

## Local checks

Use Python 3.12 x64 and Node.js 22, or another Node version supported by the pinned Playwright dependency. The application uses Python's standard library.

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m unittest discover -s tests -q
npm install
npx playwright install chromium
npm test
```

The Python suite uses temporary data, memory credential/startup stores, fake sessions, and local HTTP servers. Browser tests use a local mock. Tests do not log in, install clients, change real startup settings, create services/TAPs, or disconnect VPNs. Do not replace fakes with a live bridge in automated tests.

Playwright normally uses its downloaded Chromium. To use an installed browser in the current shell:

```powershell
$env:VPN_TEST_CHANNEL = 'msedge' # or chrome
npm test
```

Alternatively, set `VPN_TEST_BROWSER` to an absolute browser executable path. Never commit developer-specific paths. Generated browser artifacts under `web/tests/artifacts/` are ignored by Git.

CI runs on Windows with Python 3.12, synthetic data, and a manager-only build that is not executed. It contains no installer inputs, credentials, or live gateways.

## Build

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-build.txt
.\.venv\Scripts\python.exe tools/build_package.py --distribution manager-only --check
.\.venv\Scripts\python.exe tools/build_package.py --distribution manager-only
```

`--distribution complete` or `both` also requires `--official-source` with the reviewed EXE/CMS/CRL set. Inputs are checked before packaging. Build commands do not install or run the official client. Keep official files outside Git and do not commit `build/` or `dist/`.

## Native and security changes

Maintain the vendored runtime and patch engine sources, then regenerate:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File vendor/multi-src/tools/Build.ps1
powershell.exe -NoProfile -ExecutionPolicy Bypass -File vendor/multi-src/tools/Build.ps1 -Check
```

The runtime difference is recorded in `vendor/multi-src/CreateOnly.diff`. Review any modification, copy the generated script byte-for-byte to `vendor/UniVPN-Multi.ps1`, and update helper/diagnostic hash pins only after review. Preserve the complete upstream license, original executable hashes, and vendored file bytes. Do not relax exact-build, path, ACL, reparse-point, process-birth, user/session, loopback, or ownership checks to pass a test.

Keep UAC/native creation outside the global state lock, with an operation lease covering its lifetime. Never reuse a source's opaque password reference in another runtime instance. Login continuations retain their endpoint revision. Dynamic tokens remain user input; avoid authentication retry loops.

Changes touching the actual client, registry, services, drivers, or routes need a separate, explicitly authorized manual check on a suitable machine. Report exactly what ran and its outcome. Building, passing mocks, a listening socket, or creating an instance does not prove multi-tunnel business traffic.

## Reports and pull requests

Include the manager version, client build/hash-check result, expected/actual behavior, and a synthetic reproduction when possible. Never attach runtime directories, vendor configurations, keys, accounts, passwords, dynamic tokens, or launch tokens. Redact private endpoints. Arrange a private channel before sharing sensitive security information.

Keep changes focused and include relevant regression coverage and remaining validation gaps. Preserve upstream credit and the distinction between original manager code, vendored Multi code, and official components.
