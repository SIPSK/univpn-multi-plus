# Changelog

## 0.2.5 — 2026-10-30

First public source delivery of UniVPN Multi Plus, an independent extension of [UniVPN Multi](https://github.com/UsernameFull/univpn-multi).

- One local page and Windows tray icon for native connections.
- Import all valid legacy configurations with original names, independent IDs, duplicate endpoints, and deletion records.
- Reserve resources per configuration; keep native saved-password reuse within the original instance and open a blank login form for a new instance when needed.
- Confirm expansion before disconnecting saved owned sessions. Create once, restore each saved session once, and pause for user-entered dynamic tokens.
- Optional password storage in Windows Credential Manager, per-connection automatic login, and separate login startup, initially disabled.
- Bind login and expansion continuations to an endpoint revision, rejecting stale forms after a gateway edit.
- Keep early HTTP authentication rejections readable on Windows when a request body arrives late, with a bounded raw-body discard and no parsing or logging.
- Preserve fixed upstream provenance, its complete MIT notice, and the documented `CreateOnly` adaptation.
- Portable development commands and Windows CI for synthetic unit tests, browser mocks, and manager-only packaging.

Verified on the development machine: two real concurrent tunnels and dynamic-token authentication, plus creation of a third native instance. Three/four-way business traffic, other official builds, version replacement, and fresh-machine installation remain unverified. Synthetic tests and package construction do not substitute for those checks.
