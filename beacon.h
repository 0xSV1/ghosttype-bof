/*
 * beacon.h - Minimal BOF compatibility header
 *
 * Provides the standard Beacon Object File API surface used by
 * Cobalt Strike, Sliver (COFFLoader), Mythic, Havoc, and other
 * COFF-loader-equipped C2 frameworks.
 *
 * Only declares the subset actually used by ghosttype.c.
 */
#ifndef BEACON_H
#define BEACON_H

#include <windows.h>

/* Argument parser */
typedef struct {
    char*  original;
    char*  buffer;
    int    length;
    int    size;
} datap;

/* Format buffer */
typedef struct {
    char*  original;
    char*  buffer;
    int    length;
    int    size;
} formatp;

/* Output type constants */
#define CALLBACK_OUTPUT      0x0
#define CALLBACK_OUTPUT_OEM  0x1E
#define CALLBACK_OUTPUT_UTF8 0x20
#define CALLBACK_ERROR       0x0D

/* Data API */
void  BeaconDataParse(datap* parser, char* buffer, int size);
int   BeaconDataInt(datap* parser);
short BeaconDataShort(datap* parser);
int   BeaconDataLength(datap* parser);
char* BeaconDataExtract(datap* parser, int* size);

/* Output API */
void  BeaconPrintf(int type, char* fmt, ...);
void  BeaconOutput(int type, char* data, int len);

/* Format API */
void  BeaconFormatAlloc(formatp* format, int maxsz);
void  BeaconFormatReset(formatp* format);
void  BeaconFormatFree(formatp* format);
void  BeaconFormatAppend(formatp* format, char* text, int len);
void  BeaconFormatPrintf(formatp* format, char* fmt, ...);
char* BeaconFormatToString(formatp* format, int* size);
void  BeaconFormatInt(formatp* format, int value);

/* Token API */
BOOL  BeaconUseToken(HANDLE token);
void  BeaconRevertToken(void);
BOOL  BeaconIsAdmin(void);

/* Utility */
void  toWideChar(char* src, wchar_t* dst, int max);

#endif /* BEACON_H */
