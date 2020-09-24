// dllmain.cpp : DLL 애플리케이션의 진입점을 정의합니다.
#include "pch.h"
#include <stdio.h>
#include <iostream>
#include "detours.h"
#include <windows.h>
#include <string.h>
#include <iostream>
#include <tchar.h>
#define DLLBASIC_API extern "C" __declspec(dllexport)
#pragma warning (disable:4996)
#define PAGE_SIZE 0x1000

#define OBJECT_NAME _T("Local\\INTERPRO")
#pragma pack(1)
DLLBASIC_API typedef struct MMF {
    wchar_t buffer[MAX_PATH];
    char cbuffer[32];
}MMF;
static LONG dwSlept = 0;



static BOOL(WINAPI* TrueWPM)(HANDLE  hProcess,
    LPVOID  lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T  nSize,
    SIZE_T* lpNumberOfBytesWritten) = WriteProcessMemory;


DLLBASIC_API BOOL WINAPI WPM_HOOK(HANDLE  hProcess,
    LPVOID  lpBaseAddress,
    LPCVOID lpBuffer,
    SIZE_T  nSize,
    SIZE_T* lpNumberOfBytesWritten)
{
    wchar_t* buffer;
    DWORD dwBeg = GetTickCount();
    BOOL ret = TrueWPM(hProcess,
        lpBaseAddress,
        lpBuffer,
        nSize,
        lpNumberOfBytesWritten);
    DWORD dwEnd = GetTickCount();
    MMF* P;
    HANDLE hMapping;
    
    hMapping = CreateFileMapping(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, PAGE_SIZE, OBJECT_NAME);
    buffer = (wchar_t*)MapViewOfFile(hMapping, PAGE_READONLY, 0, 0, 0);
    P = (MMF*)MapViewOfFile(hMapping, PAGE_READONLY, 0, 0, 0);
    if (GetModuleFileNameW(nullptr, buffer, MAX_PATH)) {
        wcsncpy_s(P->buffer, MAX_PATH, buffer, MAX_PATH);
        std::cout << "success! " << std::endl;
        std::wcout << L"current process name: " << P->buffer << std::endl;
    }
    
    strncpy_s(P->cbuffer,32, "WriteProcessMemory API is used\n", 32);
    std::cout << P->cbuffer << std::endl;
    InterlockedExchangeAdd(&dwSlept, dwEnd - dwBeg);
    UnmapViewOfFile(P);
    CloseHandle(hMapping);
    return ret;
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved)
{
    LONG error;
    (void)hinst;
    (void)reserved;

    if (DetourIsHelperProcess()) {
        return TRUE;
    }

    if (dwReason == DLL_PROCESS_ATTACH) {
        DetourRestoreAfterWith();

        printf("WPM_HOOK" DETOURS_STRINGIFY(DETOURS_BITS) ".dll:"
            " Starting.\n");
        fflush(stdout);

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)TrueWPM, WPM_HOOK);
        error = DetourTransactionCommit();

        if (error == NO_ERROR) {
            printf("WPM_HOOK" DETOURS_STRINGIFY(DETOURS_BITS) ".dll:"
                " Detoured WriteProcessMemory().\n");
        }
        else {
            printf("WPM_HOOK" DETOURS_STRINGIFY(DETOURS_BITS) ".dll:"
                " Error detouring WriteProcessMemory: %ld\n", error);
        }
    }
    else if (dwReason == DLL_PROCESS_DETACH) {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&(PVOID&)TrueWPM, WPM_HOOK);
        error = DetourTransactionCommit();

        printf("WPM_HOOK" DETOURS_STRINGIFY(DETOURS_BITS) ".dll:"
            " Removed WriteProcessMemory() (result=%ld), slept %ld ticks. \n", error, dwSlept);
        fflush(stdout);
    }
    return TRUE;
}