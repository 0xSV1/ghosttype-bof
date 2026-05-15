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

Both tools map to MITRE ATT&CK techniques **T1552.001** (Unsecured Credentials: Credentials In Files), **T1555.003** (relocated from web browsers to AI conversation stores), **T1005** (Data from Local System), and, for the BOF's ChatGPT path, **T1140** (Deobfuscate/Decode Files).

## Telemetry Surfaces (Windows)

The BOF and a Windows-packaged build of the original tool both emit file-read activity that is unusual for the typical owning processes. The critical insight: legitimate readers of these files are a tiny known set, so anomaly-by-process is high signal.

Legitimate readers of the target paths:

- `.claude\projects\*.jsonl` — `claude.exe` (Claude Code CLI / Node process), the user's editor when they open the file
- `state.vscdb` (Cursor) — `Cursor.exe` and Cursor helper processes
- `.codex\*.sqlite` — `codex.exe` / Node process running the Codex CLI
- `conversations-v3-*\*.data` — `ChatGPT.exe` (Electron main / helper)

Anything else reading these files is suspect. The detection idea is a `DeviceFileEvents` baseline that lists the allowed `InitiatingProcessFileName` per target path and surfaces all violations. False positives: backup agents (OneDrive sync, enterprise backup), Defender / EDR scanners themselves, DLP agents. Tune by trusting their signed publisher fields rather than the process name.

The BOF's DLL loading pattern is also distinctive. `winsqlite3.dll` is system-provided but loaded by very few processes; combined with `crypt32.dll` and `bcrypt.dll` resolved via `LoadLibraryA` from a process that isn't browser, IDE, or known DB tooling, the combination is rare. `DeviceImageLoadEvents` joined to `DeviceFileEvents` within a small time window yields a strong correlation signal. The BOF also calls `GetTempFileNameW` and writes a SQLite copy to `%TEMP%` before opening — a temp-file create whose contents match SQLite magic bytes (`SQLite format 3\0`) under a non-SQLite-using process is a clean indicator.

DPAPI usage is auditable when subcategory `Other System Events` (or DPAPI-specific ETW providers) are enabled. Event 4693 fires on `CryptUnprotectData` for keys that the user originally protected; correlated with file reads of `conversations-v3-*` it is a high-confidence chain. Most environments leave DPAPI auditing off by default — flag this as a hardening prerequisite, not a default-on signal.

## Telemetry Surfaces (macOS)

The original tool's ChatGPT path on macOS shells out to `/usr/bin/security find-generic-password -s "ChatGPT Safe Storage"`. This is uncommon outside of the user clicking through a Keychain prompt themselves. Endpoint agents that surface process command-line arguments (CrowdStrike Falcon, SentinelOne, Jamf Protect, osquery `processes` table) catch this trivially. False positives: legitimate password manager imports, developer scripts touching Electron app keychains.

File-read coverage on macOS comes from ESF (`ES_EVENT_TYPE_NOTIFY_OPEN`) on `~/Library/Application Support/com.openai.chat/**` and `~/Library/Application Support/Cursor/**`. Same baseline-by-process idea as Windows.

## Process-Behavior Signals

Several runtime signatures distinguish a credential sweep from incidental file access. None of these alone is reliable; in combination they are.

- One process reading from **two or more** of {Claude Code, Cursor, Codex, ChatGPT} paths within a short window (e.g., 60 seconds). Legitimate apps read only their own store.
- Recursive directory walks under `\.claude\projects\` or `Cursor\User\workspaceStorage\` from a process that does not own those directories.
- A SQLite-shaped file appearing in `%TEMP%` followed by a read on it from the process that created it (the BOF's copy-then-open pattern).
- A non-Electron process performing `CryptUnprotectData` on bytes that begin with `v10` or `v11` (ChatGPT Safe Storage prefix).

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

These are the gaps an operator can exploit. Defenders should weight rules accordingly and prefer telemetry that survives the listed bypasses.

- **DLL load obfuscation.** The BOF resolves `winsqlite3`, `crypt32`, and `bcrypt` via `LoadLibraryA`/`GetProcAddress`, which surfaces in image-load telemetry. An operator can walk the PEB to find an already-loaded copy, or implement a manual loader to skip `LoadLibraryA` entirely. Image-load signals will silently disappear; file-read signals remain.
- **Process distribution.** The "one process reads multiple AI stores" correlation breaks if the operator splits work across separate beacons or schedules the scans minutes or hours apart. A time-window correlation rule on a host (rather than a process) is more durable.
- **Direct NTFS reads.** The temp-file pattern collapses if the operator reads the SQLite databases directly without the copy step (best-effort; locks may block this for in-use Cursor / Codex stores). The Cursor and Codex databases are sometimes locked while the app is running, which is why the copy step exists; under that constraint, the temp file is unavoidable for the BOF.
- **Offline decryption.** A more careful BOF would skip the DPAPI / BCrypt calls entirely and exfiltrate the encrypted `conversations-v3-*` bytes plus the user's DPAPI master key for offline decryption on the operator host. This removes the strongest crypto-API correlation signal. Detect on the master-key exfil instead (read of `%APPDATA%\Microsoft\Protect\<SID>\*`).
- **Path obfuscation.** Hardcoded environment variable lookups (`USERPROFILE`, `APPDATA`, `LOCALAPPDATA`) are visible in static analysis but not in runtime telemetry. There is no on-the-wire artifact to obfuscate; the actual file paths must still appear in `CreateFileW` calls, which is what file-event telemetry sees.
- **AMSI / ETW-TI.** BOFs do not load .NET or PowerShell, so AMSI is not engaged. ETW-TI events fire on the beacon's parent process injection, not on the BOF itself — useful for catching the initial implant, not the credential sweep specifically.
- **Output redaction.** The BOF and the original tool both support `--redact` / `i:1`. A redacted run still emits the same file-read telemetry; the redaction only affects what the operator sees, not what the defender observes.

## Suggested Detection Stack

In rough priority order by signal-to-noise:

1. Process-anomaly rule on file reads of the AI conversation paths, baselined to the legitimate owning process per path
2. Honeytoken canary in the conversation stores; any read of a canary value is a confirmed scan
3. Image-load rule for `winsqlite3.dll` outside an allowlist of expected processes
4. Temp-file create of SQLite-magic content under a non-SQLite-using process
5. DPAPI auditing on `conversations-v3-*` decryption (requires audit policy enabled)
6. Cross-store correlation: same process or same host reading two or more AI tool stores within 60 seconds
7. DLP rule on `ghosttype_report/` directory creation (catches the original tool, not the BOF)

Layers 1, 2, and 4 are the most resilient to the evasions listed above.
