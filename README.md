# UniVPN Multi Plus

Built on **[UniVPN Multi by UsernameFull](https://github.com/UsernameFull/univpn-multi)**. This is an independent extension, not an official UniVPN or Leagsoft product. The original upstream copyright and license are retained. [Third-party notices](THIRD_PARTY_NOTICES.md).

[中文](README.zh.md) · [Releases](https://github.com/SIPSK/univpn-multi-plus/releases) · [Contributing](CONTRIBUTING.md)

One local page and tray icon for multiple native UniVPN connections on **Windows x64**. Version **0.2.5** supports the exact reviewed UniVPN **10781.19.0.1214** build; matching version text alone is insufficient because original executable hashes must also match. Packaged use needs no Docker, WSL, or separately installed Python.

## Use

1. Download the **Complete Windows x64** release and fully extract it.
2. Run `Setup.bat` once. A matching installed client is reused. If installation or replacement is needed, Setup opens the included, unmodified official installer. First disconnect and exit all UniVPN clients, then operate the installer yourself. When manually uninstalling an old version, choose to **keep user configuration and TAP drivers**. Setup does not uninstall or choose these options for you.
3. Use `Start.bat` daily. Enter accounts, passwords, and dynamic tokens in the local page. Closing the page leaves connections running; the tray reopens it. Disconnect managed connections before exiting the manager or using `Stop.bat`.

The manager-only package requires the matching official client already installed. A source checkout is not a Complete installation package.

All valid old configurations are imported with their original display names and independent IDs. Duplicate names or endpoints do not overwrite each other. On the first handoff, disconnect and exit original clients yourself; opening this tool does not forcibly disconnect them. Later, reopening the page leaves its managed connections running.

Click **Connect** to use a configuration. Its assigned resource stays reserved. When another instance is needed, the upstream native creation flow is used. If managed connections are online, a confirmation precedes temporary disconnection, one creation attempt, and one restoration attempt per saved connection. Cancel leaves connections alone. External or unknown connections, unfinished authentication, or missing saved credentials stop the process before interruption. Dynamic tokens remain user input, with no authentication retry loop.

Native saved passwords can only be reused in their original instance. A different assigned instance opens a blank login form when needed. **Save password** stores newly saved credentials in the current user's Windows Credential Manager. Per-connection automatic login and Windows login startup are separate, optional settings, initially off.

## Data and compatibility

The app installs under `%LOCALAPPDATA%\UniVPNManager\App`; runtime state and private vendor backups stay under `%LOCALAPPDATA%\UniVPNManager`. Share release archives, **not that runtime directory**. Do not post accounts, passwords, dynamic tokens, launch tokens, configurations, or key files in issues or screenshots.

The source repository contains no official installer or private VPN configurations. Official files in Complete releases retain their vendor terms and are not covered by this repository's MIT license. Windows routing, DNS, and gateway policies remain shared; instance isolation does not guarantee compatibility between arbitrary networks.

| Validation | Status |
| --- | --- |
| Two real concurrent tunnels, login, and dynamic-token authentication | Verified on the development machine |
| Creation of a third native instance | Verified on the development machine |
| Three/four concurrent tunnels carrying business traffic | Not verified |
| Other official builds, version replacement, and a fresh machine | Not verified |
| Unit and local browser mock tests | Automated; no real service, TAP, or VPN creation |

These results describe tested operations, not a guarantee for other gateways or machines.

## Development

Use Windows x64 and Python 3.12. Tests use temporary data and fake native interfaces; no installed UniVPN is required.

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m unittest discover -s tests -q
npm install
npx playwright install chromium
npm test
```

Build without official installer files:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-build.txt
.\.venv\Scripts\python.exe tools/build_package.py --distribution manager-only
```

For both package variants, supply the exact reviewed EXE/CMS/CRL set. Building checks hashes and does not download or execute those files:

```powershell
.\.venv\Scripts\python.exe tools/build_package.py --distribution both --official-source 'C:\path\to\reviewed-official-files'
```

`--check` validates the selected inputs without building. See [CONTRIBUTING.md](CONTRIBUTING.md) for native maintenance and browser selection.

## License and upstream

Original manager code: [MIT, copyright 2026 SIPSK](LICENSE). Vendored Multi code: [original MIT notice](vendor/LICENSE.univpn-multi), pinned to [`0d12fbbbdad25f00c5ab656fb37f2c0e2c8e5121`](https://github.com/UsernameFull/univpn-multi/tree/0d12fbbbdad25f00c5ab656fb37f2c0e2c8e5121). The documented `CreateOnly` adaptation does not replace the upstream project; [visit upstream](https://github.com/UsernameFull/univpn-multi) for the native implementation and maintenance guidance.
