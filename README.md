# GhostType BOF

Portable Beacon Object File that scans AI coding tool conversation histories on Windows for exposed credentials.

Compatible with any COFF-loader C2 framework: Cobalt Strike, Sliver, Havoc, Mythic, Brute Ratel, Fenrir, etc. Uses only the standard Beacon API surface (`BeaconDataParse`, `BeaconDataInt`, `BeaconPrintf`) and DFR conventions (`MODULE$Function`).

## Supported Tools

| Tool | Storage | Method |
|------|---------|--------|
| Claude Code CLI | `%USERPROFILE%\.claude\projects\*.jsonl`, `tasks\*.json`, `history.jsonl` | JSONL/JSON file walk |
| Cursor IDE | `%APPDATA%\Cursor\User\globalStorage\state.vscdb` + workspace DBs | SQLite via winsqlite3.dll |
| Codex CLI | `%USERPROFILE%\.codex\state_5.sqlite` + `logs_2.sqlite` | SQLite via winsqlite3.dll |
| ChatGPT Desktop | `%LOCALAPPDATA%\com.openai.chat\conversations-v3-*\*.data` | DPAPI + AES-256-GCM |
| Claude Desktop | `%APPDATA%\Claude` | Stub (detection only, no scanning) |

## Pattern Engine

- 24 prefix-based matchers (AWS, Anthropic, OpenAI, GitHub, Stripe, Slack, GCP, etc.)
- 7 structure matchers (JWT, PEM private keys, connection strings, Slack tokens, HashiCorp Vault tokens, Telegram bot tokens, GCP service accounts)
- 10 heuristic context-signal matchers with entropy filtering (threshold 3.0 bits/byte)
- Placeholder and example value rejection (AWS docs keys, `hunter2`, `your_*`, `<TOKEN>`, low-entropy strings)
- Dedup buffer prevents duplicate findings across files

## Build

Requires MinGW cross-compiler targeting x86_64 Windows:

```bash
x86_64-w64-mingw32-gcc -c -fno-builtin -o ghosttype.o ghosttype.c
```

Add `-O2 -Wall -Wextra -Werror` for reduced code size, standard, additional and 'treat warnings' as errors.

No compile-time dependencies. SQLite is loaded at runtime from `C:\Windows\System32\winsqlite3.dll` (present on all Windows 10+ systems). DPAPI and AES-GCM use `crypt32.dll` and `bcrypt.dll` (also system-provided).

## Arguments

Four packed integers. If no arguments are provided, all four default to 0 (scan everything, all time, full credential values, all confidence levels).

```
i:cmd              0=scan_all  1=claude_code  2=cursor  3=codex  4=chatgpt  5=list_tools
i:max_age_days     0=all files, N=only files modified within last N days
i:redact           0=full credential output, 1=mask values (show first/last 4 chars)
i:min_confidence   0=medium+high findings, 1=high confidence only
```

To scan with redacted output:

```
inline-execute ghosttype.o i:0 i:0 i:1 i:0
```

## Usage by Framework

### Cobalt Strike

```
beacon> inline-execute /path/to/ghosttype.o i:0 i:7 i:0 i:0
beacon> inline-execute /path/to/ghosttype.o i:5 i:0 i:0 i:0
```

### Sliver

Requires the `coff-loader` extension (`armory install coff-loader`) and an `extension.json` manifest declaring the four integer arguments. See the [Sliver BOF wiki](https://github.com/BishopFox/sliver/wiki/BOF-&-COFF-Support) for manifest format.

## Output Format

NDJSON (newline-delimited JSON). Each finding is one line, final line is a summary:

```json
{"tool":"claude_code","type":"aws_access_key","value":"AKIA...","file":"C:\\Users\\dev\\.claude\\projects\\...","severity":"critical","confidence":"high"}
{"tool":"cursor","type":"heuristic_api_key","value":"sk-...","file":"C:\\Users\\dev\\AppData\\Roaming\\Cursor\\...","severity":"medium","confidence":"medium"}
{"summary":true,"files_scanned":23,"findings":4}
```

Severity levels: `critical` (AWS keys, Anthropic keys, GitHub PATs, Stripe live keys, PEM private keys, Vault tokens), `high` (other high-confidence prefix/structure matches), `medium` (heuristic matches).

## Commands

| ID | Name | Description |
|----|------|-------------|
| 0 | scan_all | Scan all detected tools |
| 1 | claude_code | Scan Claude Code CLI only |
| 2 | cursor | Scan Cursor IDE only |
| 3 | codex | Scan Codex CLI only |
| 4 | chatgpt | Scan ChatGPT Desktop only |
| 5 | list_tools | Enumerate which tools are installed (no scanning) |

## Limits

- Max 200 findings per execution
- Max 50 files per tool
- Max 5 MB per file
- Max 20 Cursor workspace databases
- Dedup buffer: 32 KB (shared across all scanners)

## OPSEC Notes

- File reads only; no process injection, no network traffic, no child processes
- SQLite accessed via system-provided `winsqlite3.dll` (no DLL drop)
- Databases copied to `%TEMP%` before opening to avoid lock contention with running applications
- Temp files are deleted after use
- ChatGPT decryption uses DPAPI `CryptUnprotectData` (logged as Event ID 4693 if auditing is enabled)
- No registry writes, no named pipes, no service creation
- Synchronous execution: blocks the agent thread until complete (typically a few seconds)

## Credit

Based on [ghosttype](https://github.com/xFreed0m/ghosttype) by xFreed0m.

## License

MIT
