# Detection Notes

Concept-level detection ideas for the ghosttype BOF (this repo) and the original Python tool ([xFreed0m/ghosttype](https://github.com/xFreed0m/ghosttype)). Both tools harvest credentials from AI coding tool conversation histories; their telemetry signatures differ but overlap meaningfully at the file-read layer.

This document does not ship production-ready rules. It enumerates the telemetry surfaces, ideas for detection logic, expected false-positive sources, and known evasion paths.

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
| [T1552.001](https://attack.mitre.org/techniques/T1552/001/) | Unsecured Credentials: Credentials In Files | Primary technique for both tools. Credentials live in plaintext or DPAPI-wrapped files that the tool reads as files. |
| [T1005](https://attack.mitre.org/techniques/T1005/) | Data from Local System | Covers the file-walk and bulk-read behavior across multiple AI tool stores. |
| [T1140](https://attack.mitre.org/techniques/T1140/) | Deobfuscate/Decode Files or Information | Applies to the BOF's ChatGPT path: DPAPI unwrap of the encrypted key, then AES-256-GCM decryption of conversation files. |
| [T1555](https://attack.mitre.org/techniques/T1555/) | Credentials from Password Stores (parent, no subtechnique) | Defensible for the ChatGPT/Electron path only. The `encrypted_key` field in `Local State` is a DPAPI-protected Chromium Safe Storage key, a password-store-style protected secret. Not applicable to Claude Code, Cursor, or Codex paths. |

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
| Image load: `winsqlite3.dll` | `DeviceImageLoadEvents` | Explicitly loaded by the BOF via `LoadLibraryA` (ghosttype.c:417). Loaded by very few processes overall, so the load itself is anomalous in most images. |
| Image load: `crypt32.dll`, `bcrypt.dll` | `DeviceImageLoadEvents` | Not loaded by the BOF directly. Resolved by the C2 framework's COFF loader as `LIBRARY$Function` DFR imports, which internally results in `LoadLibraryA` calls from the beacon process. Image-load events look identical to defenders. |
| Combined load pattern | `DeviceImageLoadEvents` joined to `DeviceFileEvents` | `winsqlite3` plus `crypt32` plus `bcrypt` loaded into a process that is not a browser, IDE, or known DB tool is rare. Strong correlation signal in a short time window. |
| Temp-file create | `DeviceFileEvents` | BOF calls `GetTempFileNameW` with prefix `gt` then `CopyFileW` to clone SQLite databases into `%TEMP%` before opening. A temp file whose contents match SQLite magic bytes (`SQLite format 3\0`) under a non-SQLite-using process is a clean indicator. |
| DPAPI activity | ETW `Microsoft-Windows-Crypto-DPAPI` (`DPAPIDefInformationEvent` 8193 / 8194), or EDR crypt-API hooks | Off by default. `4693` is master-key recovery (backups), not `CryptUnprotectData`. `4695` requires `CRYPTPROTECT_AUDIT`, which Chromium and Electron never set. |

## Telemetry Surfaces (macOS)

The original tool's ChatGPT path on macOS shells out to `/usr/bin/security find-generic-password -s "ChatGPT Safe Storage"`. This is uncommon outside of the user clicking through a Keychain prompt themselves. Endpoint agents that surface process command-line arguments (CrowdStrike Falcon, SentinelOne, Jamf Protect, osquery `processes` table) catch this trivially. False positives: legitimate password manager imports, developer scripts touching Electron app keychains.

File-read coverage on macOS comes from ESF (`ES_EVENT_TYPE_NOTIFY_OPEN`) on `~/Library/Application Support/com.openai.chat/**` and `~/Library/Application Support/Cursor/**`. Same baseline-by-process idea as Windows.

## Process-Behavior Signals

Several runtime signatures distinguish a credential sweep from incidental file access. None of these alone is reliable; in combination they are.

- One process reading from **two or more** of {Claude Code, Cursor, Codex, ChatGPT} paths within a short window (e.g., 60 seconds). Legitimate apps read only their own store.
- Recursive directory walks under `\.claude\projects\` or `Cursor\User\workspaceStorage\` from a process that does not own those directories.
- A SQLite-shaped file appearing in `%TEMP%` followed by a read on it from the process that created it (the BOF's copy-then-open pattern).
- A non-Electron process performing `CryptUnprotectData` on a small blob extracted from `Local State` (the DPAPI-wrapped `encrypted_key` value, prefixed with the 5-byte `DPAPI` tag), **followed by** a `BCryptDecrypt` call against `v10`/`v11`-prefixed bytes (the AES-256-GCM ciphertext from `conversations-v3-*\*.data`). The two-step chain inside one process is the high-fidelity ChatGPT decryption fingerprint.

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

A repackaged single-file build (PyInstaller, Nuitka) hides the Python parent but the file-read fingerprint remains identical.

## Known Evasion Paths

Every detection in the preceding sections can be eroded by a careful operator. The question worth asking for each one is not whether it can be bypassed but how much work the bypass costs and which signals survive.

The DLL-load signal is the easiest to chip away at. Only `winsqlite3.dll` is loaded directly by the BOF, so an operator who walks the PEB for an already-loaded copy, or who substitutes a manual loader, removes that single image-load event. The `crypt32.dll` and `bcrypt.dll` loads ride on the C2 framework's COFF loader through its `LIBRARY$Function` DFR mechanism and cannot be removed without forking the framework. Partial bypass therefore still leaves the `crypt32` plus `bcrypt` pair visible, and the file-read events remain regardless.

The "one process touches multiple AI stores" correlation falls apart when the operator splits work across separate beacons or staggers scans by minutes or hours. A correlation scoped to the host rather than a single process holds up better against that pattern.

The temp-file indicator is more durable than it looks because the BOF's copy step is not optional. Cursor and Codex keep their SQLite databases locked while the apps are running, which is why the copy exists. An operator could attempt a direct volume read to skip `%TEMP%`, but contended locks defeat that under live conditions on most workstations.

The crypto-API chain can be removed wholesale by a more careful BOF that skips DPAPI and BCrypt on-host and exfiltrates the encrypted `conversations-v3-*` bytes together with the user's DPAPI master key for offline decryption on the operator's machine. When that happens, the strongest signal shifts to master-key access itself: a read of `%APPDATA%\Microsoft\Protect\<SID>\*` from a non-system process is rare and high-fidelity in any environment.

A handful of things don't move. Hardcoded environment variable lookups (`USERPROFILE`, `APPDATA`, `LOCALAPPDATA`) hide nothing at runtime because the resolved paths still flow through `CreateFileW`, which file-event telemetry captures unconditionally. `--redact` and `i:1` only change what the operator sees in their output, not what the defender observes on the box. AMSI is not engaged because no .NET or PowerShell is involved, and ETW-TI fires on the beacon's parent injection rather than on the BOF, so it catches the implant rather than the sweep.

In short, file-read events, the `%APPDATA%\Microsoft\Protect` master-key access path, and the SQLite-shaped temp-file artifact are the three signals that resist nearly every bypass available to an operator working within the BOF model.

## Suggested Detection Stack

In rough priority order by signal-to-noise:

1. Process-anomaly rule on file reads of the AI conversation paths, baselined to the legitimate owning process per path
2. Honeytoken canary in the conversation stores; any read of a canary value is a confirmed scan
3. Image-load rule for `winsqlite3.dll` outside an allowlist of expected processes
4. Temp-file create of SQLite-magic content under a non-SQLite-using process
5. ETW `Microsoft-Windows-Crypto-DPAPI` events correlated with `BCryptDecrypt` (AES-GCM) on `v10`/`v11`-prefixed bytes, confined to the same process and short time window (requires ETW collection; Security event log alone is not sufficient)
6. Cross-store correlation: same process or same host reading two or more AI tool stores within 60 seconds
7. DLP rule on `ghosttype_report/` directory creation (catches the original tool, not the BOF)

Layers 1, 2, and 4 are the most resilient to the evasions listed above.
