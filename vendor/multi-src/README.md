# Bundled UniVPN Multi source

Copied from the reviewed local-fix snapshot of UsernameFull/univpn-multi.
The MIT license and attribution are retained in LICENSE.

The manager's only runtime adaptation is `-CreateOnly`: it retains the original
exact-build, idle-client/TAP, mutex, destination, patch, junction and service
ownership checks, then returns after a verified Ready record. It does not open
the client or wait for input. Errors terminate without a message box or prompt.
`PatchEngine.cs` is unchanged from the reviewed snapshot.

Build with `tools/Build.ps1`, check with `tools/Build.ps1 -Check`, then copy the
byte-identical generated `UniVPN-Multi.ps1` to the parent vendor directory.
Update the pinned vendor-script SHA256 in tools/native-action.ps1 only after
reviewing the source diff and repeating the read-only `-SelfTest`.

The manager invokes only the pinned script. For durable per-instance launchers,
it persists those exact verified bytes under the protected official installation
in `.univpn-multi/manager-runtime/`; it never replaces another client or script.
