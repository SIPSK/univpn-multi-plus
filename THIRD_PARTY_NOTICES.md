# Third-party notices

UniVPN Multi Plus is an independent extension of **[UniVPN Multi by UsernameFull](https://github.com/UsernameFull/univpn-multi)**, not an official UniVPN or Leagsoft product. The root [MIT license](LICENSE), copyright 2026 SIPSK, covers this project's original code; it does not replace the notices below.

## UniVPN Multi

- Upstream: <https://github.com/UsernameFull/univpn-multi>
- Fixed source revision: [`0d12fbbbdad25f00c5ab656fb37f2c0e2c8e5121`](https://github.com/UsernameFull/univpn-multi/tree/0d12fbbbdad25f00c5ab656fb37f2c0e2c8e5121)
- Original copyright: **Copyright (c) 2026 UniVPN Multi contributors**
- License: MIT, retained complete and unchanged in [vendor/LICENSE.univpn-multi](vendor/LICENSE.univpn-multi) and [vendor/multi-src/LICENSE](vendor/multi-src/LICENSE).
- Included code: `vendor/multi-src/` and generated `vendor/UniVPN-Multi.ps1`.

The runtime adaptation adds `-CreateOnly`: return after a verified Ready record without opening a client or waiting for input; errors propagate without a message box. [CreateOnly.diff](vendor/multi-src/CreateOnly.diff) records this change. The patch engine is byte-identical to upstream. Original executable checks and idle-client/TAP, mutex, destination, junction, and service ownership protections remain in place.

SHA256 provenance, checked against the fixed revision:

| File | Upstream | Included |
| --- | --- | --- |
| `UniVPN-Multi.ps1` | `bf166ae212af27a99f2bec248d0ff93aa1bc42e59929b8ba81097b20e5f6d665` | `e89190659105f451829bf67f5a0a8d609be120e01a484176a17f88ae64577230` |
| `src/PatchEngine.cs` | `ede84c5d4da0bbae03d2aaacdfc26b9d25cb57f47ac98402118ef12f6773783a` | Same |
| `src/Runtime.ps1` | `288461e3b443923db970eee098064763eb6d53b926dd49db14decf0012e55d3d` | `b56007e6e29095ac222266befec839ac424ee2f82d6ebeda96e5363dd70e02a9` |

The included script hash remains pinned independently in `tools/native-action.ps1` and `vendor/setup-selfcheck.json`. Do not update those pins without reviewing and rebuilding the source change.

## Official UniVPN components

The official client, installer, services, drivers, CMS, and CRL are vendor materials, **not covered by this repository's MIT license**. This source repository does not contain those binaries. Complete releases may include the exact reviewed installer files unchanged; vendor terms continue to apply. The manager-only package does not include that installer.

Supported reviewed client build: `10781.19.0.1214`. The original executable hashes remain:

| Original official file | SHA256 |
| --- | --- |
| `UniVPN.exe` | `24f90f30309ad4bcd6c2e81adf39e44a690c648d13455194971c01a08ad0d0b1` |
| `promote/UniVPNPromoteService.exe` | `e038021b055e659430876a7e270c6ef8e8f32346155c3197cc6e539477141b10` |
| `serviceclient/UniVPNCS.exe` | `cf07de7e0ffeb470859a5df8cbc33915ef642b407c7b42627ced94f5e166ec39` |

Official installation files are checked against `setup.py` and recorded in each package manifest. This project does not alter those reviewed originals; native clones use the separately attributed upstream patching code.

## Build and test tools

Python, PyInstaller, Node.js, Playwright, and test browsers are separate tools with their own licenses. They are not relicensed by this repository. Packaged executables include Python runtime components and notices supplied by their toolchain; review those terms when redistributing a binary build.
