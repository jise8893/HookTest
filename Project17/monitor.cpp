
#include <Windows.h>
#include <tchar.h>
#include <stdio.h>
#include <conio.h>

#pragma warning (disable:4996)
#define OBJECT_NAME _T("Local\\INTERPRO")


#pragma pack(1)
typedef struct MMF
{
	wchar_t* buffer[MAX_PATH];
	char* cbuffer[32];
}MMF;

int main()
{
	HANDLE hMapping;
	MMF* P;
	wchar_t* buffer;
	while (1) {
		hMapping = OpenFileMapping(
			FILE_MAP_READ | FILE_MAP_WRITE, FALSE, OBJECT_NAME);
		P = (MMF*)MapViewOfFile(
			hMapping,
			PAGE_READONLY, 0, 0, 0);
		
		if (P != NULL) {
			printf("CALL %S : %s\n ", P->buffer,P->cbuffer);
			Sleep(5);
			UnmapViewOfFile(P);
			CloseHandle(hMapping);
			
		}
		Sleep(0);
	}


	return 0;
}