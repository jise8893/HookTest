#include "pch.h"
#include <detours.h>
#include <stdio.h>
#include <processthreadsapi.h>
#include <winternl.h>
#include <iostream>
#include "atombomb.h"
#define DLLBASIC_API extern "C" __declspec(dllexport)
#pragma comment(lib, "detours.lib")
#define STATUS_SUCCESS               ((NTSTATUS)0x00000000L)


static pfNtAddAtomEx NtAddAtomEx =NULL;
static pNtQueueApcThread NtQueueApcThread=NULL;

DLLBASIC_API NTSTATUS NTAPI MyNtQueueApcThread(
    HANDLE ThreadHandle,
    PVOID ApcRoutine,
    PVOID ApcRoutineContext OPTIONAL,
    PVOID ApcStatusBlock OPTIONAL,
    PVOID ApcReserved OPTIONAL
) {
    printf("MyNtQueueApcThread is used\n");
    return NtQueueApcThread(ThreadHandle,
        ApcRoutine,
        ApcRoutineContext OPTIONAL,
        ApcStatusBlock OPTIONAL,
        ApcReserved OPTIONAL);
}

DLLBASIC_API NTSTATUS NTAPI MyNtAtomEx(
    PWSTR String,
    ULONG StringLength,
    PUSHORT Atom,
    ULONG Unknown
)
{
    printf("MyNtAtomEx is used\n");
    
    wprintf(L"%s\n", String);

    NtAddAtomEx(String,
        StringLength,
        Atom,
        Unknown);
    return STATUS_SUCCESS;
}

BOOL WINAPI DllMain(HINSTANCE hinst, DWORD dwReason, LPVOID reserved)
{
    
    (void)hinst;
    (void)reserved;
    HMODULE hMod = NULL;
    switch (dwReason)
    {

    case DLL_PROCESS_ATTACH:
        if (hMod != NULL)
        {
            hMod = GetModuleHandleA("ntdll.dll");
            NtAddAtomEx = (pfNtAddAtomEx)GetProcAddress(hMod, "NtAddAtomEx");
            NtQueueApcThread = (pNtQueueApcThread)GetProcAddress(hMod, "NtQueueApcThread");
        }
        DetourRestoreAfterWith();
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        if (NtAddAtomEx != NULL)
            DetourAttach(&(PVOID&)NtAddAtomEx, MyNtAtomEx);
        if (NtQueueApcThread != NULL)
            DetourAttach(&(PVOID&)NtQueueApcThread, MyNtQueueApcThread);

        printf("DLL_PROCESS_ATTACH\n");

        DetourTransactionCommit();
        break;
    case DLL_THREAD_ATTACH:
        printf("DLL_THREAD_ATTACH\n");
        break;
    case DLL_THREAD_DETACH:
        printf("DLL_THREAD_DETACH\n");
        break;
    case DLL_PROCESS_DETACH:
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        if (NtAddAtomEx != NULL)
            DetourDetach(&(PVOID&)NtAddAtomEx, MyNtAtomEx);
        if (NtQueueApcThread != NULL)
            DetourDetach(&(PVOID&)NtQueueApcThread, MyNtQueueApcThread);
        DetourTransactionCommit();
        printf("DLL_PROCESS_DETACH\n");
        break;
    }

    return TRUE;
}