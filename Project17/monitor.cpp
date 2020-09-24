#include <Windows.h>
#include <tchar.h>
#include <stdio.h>
#include <conio.h>

#pragma warning (disable:4996)
#define OBJECT_NAME _T("Local\\INTERPRO")


int main()
{
	HANDLE hMapping;
	wchar_t * buffer;
	while (1) {
		hMapping = OpenFileMapping(
			FILE_MAP_READ | FILE_MAP_WRITE, FALSE, OBJECT_NAME);
		buffer = (wchar_t*)MapViewOfFile(
			hMapping,
			PAGE_READONLY, 0, 0, 0);
		if (buffer != NULL) {
			printf("CALL %S\n", buffer);
			UnmapViewOfFile(buffer);
			CloseHandle(hMapping);
		}
		
	}

	
	return 0;
}