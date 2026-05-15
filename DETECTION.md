# Detection Notes

Concept-level notes covering the ghosttype BOF (this repo) and the original Python tool ([xFreed0m/ghosttype](https://github.com/xFreed0m/ghosttype)). Both tools harvest credentials from AI coding tool conversation histories; their telemetry overlaps at the file-read layer.

## Threat Behavior Summary

| Phase | BOF (this repo) | Original tool |
|-------|-----------------|---------------|
| Execution | Inline COFF load into a C2 beacon process (any image) | `python3 -m ghosttype` / `ghosttype` CLI |
| Discovery | Env vars: `USERPROFILE`, `APPDATA`, `LOCALAPPDATA` | `Path.home()` resolution |
| File reads | `.claude\projects\*.jsonl`, Cursor `state.vscdb`, `.codex\*.sqlite`, ChatGPT `conversations-v3-*\*.data` | Same paths, cross-platform layout |
| SQLite access | `winsqlite3.dll` loaded at runtime via `LoadLibraryA`; DBs copied to `%TEMP%` before `sqlite3_open_v2` | Python stdlib `sqlite3`; reads in place via `mode=ro` URI |
| ChatGPT decryption | `crypt32!CryptUnprotectData` + `bcrypt!BCryptDecrypt` (AES-256-GCM) | macOS only: `security find-generic-password` + AES-128-CBC via `cryptography` |
| Output | NDJSON to beacon callback; no disk writes | `./ghosttype_report/findings.{json,csv}`; optional `--copy-sources` clones conversation files |
| Persistence | None | None |
| Network | None | None |

MITRE ATT&CK mapping:

| Technique | Name | Applicability |
|-----------|------|---------------|
| [T1552.001](https://attack.mitre.org/techniques/T1552/001/) | Unsecured Credentials: Credentials In Files | Primary technique. Credentials sit in plaintext or DPAPI-wrapped files. |
| [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System | The file-walk and bulk-read across multiple AI tool stores. |
| [T1140](https://attack.mitre.org/techniques/T1140/) | Deobfuscate/Decode Files or Information | BOF's ChatGPT path: DPAPI unwrap of the encrypted key, then AES-256-GCM decryption of conversation files. |
| [T1555](https://attack.mitre.org/techniques/T1555/) | Credentials from Password Stores (parent, no subtechnique) | ChatGPT/Electron path only. The `encrypted_key` in `Local State` is a DPAPI-protected Chromium Safe Storage key. Not relevant to Claude Code, Cursor, or Codex. |

## Telemetry Surfaces (Windows)

The BOF and a Windows-packaged build of the original tool both emit file-read activity that is unusual for the typical owning processes. Legitimate readers of each target path are a tiny known set, so anomaly-by-process is a high-signal detection. Tune by trusting signed publisher fields rather than process name.

| Target path | Legitimate readers | Common false positives |
|-------------|--------------------|-------------------------|
| `.claude\projects\*.jsonl` | `claude.exe` (Claude Code CLI / Node process); user's editor on explicit open | Backup agents (OneDrive sync, enterprise backup), Defender / EDR scanners, DLP agents |
| `state.vscdb` (Cursor) | `Cursor.exe` and Cursor helper processes | Same |
| `.codex\*.sqlite` | `codex.exe` / Node process running the Codex CLI | Same |
| `conversations-v3-*\*.data` | `ChatGPT.exe` (Electron main / helper) | Same |

Beyond file reads, several other Windows surfaces fire when the BOF runs:

| Surface | Source | Notes |
|---------|--------|-------|
| Image load: `winsqlite3.dll` | `DeviceImageLoadEvents` | Explicitly loaded by the BOF via `LoadLibraryA` (ghosttype.c:417). Loaded by very few processes overall. |
| Image load: `crypt32.dll`, `bcrypt.dll` | `DeviceImageLoadEvents` | Resolved by the C2 framework's COFF loader as `LIBRARY$Function` DFR imports; the actual `LoadLibraryA` call comes from the beacon process. |
| Combined load pattern | `DeviceImageLoadEvents` joined to `DeviceFileEvents` | `winsqlite3` plus `crypt32` plus `bcrypt` in one process, outside browsers, IDEs, and known DB tools, is rare. |
| Temp-file create | `DeviceFileEvents` | BOF calls `GetTempFileNameW` with prefix `gt` then `CopyFileW` to clone SQLite databases into `%TEMP%` before opening. A temp file whose contents match SQLite magic bytes (`SQLite format 3\0`) under a non-SQLite-using process is a clean indicator. |
| DPAPI activity | ETW `Microsoft-Windows-Crypto-DPAPI` (`DPAPIDefInformationEvent` 8193 / 8194), or EDR crypt-API hooks | Off by default. `4693` is master-key recovery (backups), not `CryptUnprotectData`. `4695` requires `CRYPTPROTECT_AUDIT`, which Chromium and Electron never set. |

## Telemetry Surfaces (macOS)

On macOS the original tool's ChatGPT path shells out to `/usr/bin/security find-generic-password -s "ChatGPT Safe Storage"`. Almost no legitimate process runs that command on a workstation; endpoint agents that capture process command lines (CrowdStrike Falcon, SentinelOne, Jamf Protect, osquery `processes`) catch it directly. False positives: password-manager imports, developer scripts that touch Electron keychains.

File-read coverage comes from ESF (`ES_EVENT_TYPE_NOTIFY_OPEN`) on `~/Library/Application Support/com.openai.chat/**` and `~/Library/Application Support/Cursor/**`. The baseline-by-process approach from the Windows section transfers directly.

## Process-Behavior Signals

Each signal below is noisy on its own. Run them as a panel:

- One process reading two or more of {Claude Code, Cursor, Codex, ChatGPT} paths within ~60 seconds. Legitimate apps read only their own store.
- Recursive directory walks under `\.claude\projects\` or `Cursor\User\workspaceStorage\` from a process that does not own those directories.
- A SQLite-shaped file appearing in `%TEMP%`, then read by the process that created it (the BOF's copy-then-open pattern).
- A non-Electron process calling `CryptUnprotectData` on a small blob extracted from `Local State` (the DPAPI-wrapped `encrypted_key`, prefixed with the 5-byte `DPAPI` tag), then `BCryptDecrypt` on `v10`/`v11`-prefixed bytes from `conversations-v3-*\*.data` (the AES-256-GCM ciphertext).

## Honeytoken Strategy

Conversation history files are an ideal place to plant canaries. The credential stores are read in their entirety by both tools, and any read of the canary value is a high-fidelity signal that some scanner ran. Recommended placements:

- A fake `~\.claude\projects\<random>\session.jsonl` containing a tripwire AWS access key and a SaaS canary token (e.g., a Thinkst Canarytokens AWS or generic key)
- An entry inserted into Cursor's `state.vscdb` under `cursorDiskKV` with key `composerData:canary` and a JSON value embedding a unique tripwire string
- A row in `~\.codex\state_5.sqlite` mimicking a Codex message containing a canary token
- A synthetic ChatGPT conversation `.data` file (requires the operator to encrypt with the user's Safe Storage key, but a plaintext sibling is enough to seed the file walk and trigger the AES-GCM path)

Distinct canary values per host let an alert pinpoint which workstation was scanned. Tripwire credentials should be uniquely keyed so they cannot collide with real production values; never filter on canary patterns in scanners.

## Original-Tool-Specific Signals

The Python tool, run as packaged, leaves more disk artifacts than the BOF:

- `ghosttype_report/findings.json` and `findings.csv` creation under the user's current working directory
- `ghosttype_report/sources/` populated with copies of conversation files when `--copy-sources` is set; a DLP rule on cluster-copies of `*.jsonl` or `state.vscdb` catches this
- A `python3` / `ghosttype` process whose command line contains `scan`, `--tool`, or `list-tools`

A repackaged single-file build (PyInstaller, Nuitka) hides the Python parent. The file-read fingerprint stays identical.

## Known Evasion Paths

Every detection above has a bypass. The cost varies; some signals always survive.

The DLL-load signal goes first. Only `winsqlite3.dll` is loaded directly by the BOF, so an operator who walks the PEB for an already-loaded copy or uses a manual loader removes that one image-load event. The `crypt32.dll` and `bcrypt.dll` loads ride on the C2 framework's COFF loader through its `LIBRARY$Function` DFR mechanism and cannot be stripped without forking the framework. A partial bypass therefore still leaves the `crypt32` plus `bcrypt` pair visible, and the file-read events stay put.

The "one process touches multiple AI stores" correlation falls apart when the operator splits work across separate beacons or staggers scans by minutes or hours. A correlation scoped to the host outlasts that pattern.

The temp-file indicator is durable because the BOF's copy step is not optional. Cursor and Codex hold open locks on their SQLite databases while the apps run, which is why the copy exists. Direct volume reads can sidestep `%TEMP%` in theory, but contended locks defeat that under live conditions on most workstations.

The crypto-API chain disappears wholesale if a more careful BOF skips DPAPI and BCrypt on-host and exfiltrates the encrypted `conversations-v3-*` bytes alongside the user's DPAPI master key for offline decryption on the operator's machine. The strongest signal then shifts to master-key access: a read of `%APPDATA%\Microsoft\Protect\<SID>\*` from a non-system process is rare in any environment.

A few things refuse to move. Environment variable lookups (`USERPROFILE`, `APPDATA`, `LOCALAPPDATA`) hide nothing at runtime because the resolved paths still go through `CreateFileW`. `--redact` and `i:1` only change what the operator sees, not what the defender records. AMSI is not engaged (no .NET, no PowerShell); ETW-TI catches the implant injection, not the credential sweep.

Three signals resist almost every bypass: file-read events on the AI stores, master-key access under `%APPDATA%\Microsoft\Protect`, and the SQLite-shaped temp-file artifact.

## Suggested Detection Stack

In rough priority order by signal-to-noise:

1. Process-anomaly rule on file reads of the AI conversation paths, baselined to the legitimate owning process per path
2. Honeytoken canary in the conversation stores; any read of a canary value is a confirmed scan
3. Image-load rule for `winsqlite3.dll` outside an allowlist of expected processes
4. Temp-file create of SQLite-magic content under a non-SQLite-using process
5. ETW `Microsoft-Windows-Crypto-DPAPI` events correlated with `BCryptDecrypt` (AES-GCM) on `v10`/`v11`-prefixed bytes, confined to the same process and short time window (requires ETW collection; Security event log alone is not sufficient)
6. Cross-store correlation: same process or same host reading two or more AI tool stores within 60 seconds
7. DLP rule on `ghosttype_report/` directory creation (catches the original tool, not the BOF)

Layers 1, 2, and 4 survive almost every operator-side bypass.
