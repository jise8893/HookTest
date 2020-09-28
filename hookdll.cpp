#include "pch.h"
#include <detours.h>
#include <stdio.h>
#include <processthreadsapi.h>

#define DLLBASIC_API extern "C" __declspec(dllexport)
#define HOOKDLL_PATH "C:\\Fast64.dll"  // DLL경로
#pragma comment(lib, "detours.lib")
//프로젝트 

typedef BOOL(WINAPI* pCreateProcessInternalW)(HANDLE hToken,
    LPCWSTR lpApplicationName,
    LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation,
    PHANDLE hNewToken);

BOOL WINAPI MyCreateProcessInternalW(HANDLE hToken,
    LPCWSTR lpApplicationName,
    LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation,
    PHANDLE hNewToken);

static pCreateProcessInternalW realCreateProcessInternalW;

HMODULE kern32dllmod = NULL;


static BOOL(WINAPI* TrueCreateProcessA)(
    LPCSTR                lpApplicationName,
    LPSTR                 lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL                  bInheritHandles,
    DWORD                 dwCreationFlags,
    LPVOID                lpEnvironment,
    LPCSTR                lpCurrentDirectory,
    LPSTARTUPINFOA        lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
    ) = CreateProcessA;


static BOOL(WINAPI* TrueCreateProcessW)(
    LPCWSTR               lpApplicationName,
    LPWSTR                lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL                  bInheritHandles,
    DWORD                 dwCreationFlags,
    LPVOID                lpEnvironment,
    LPCWSTR               lpCurrentDirectory,
    LPSTARTUPINFOW        lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
    ) = CreateProcessW;


DLLBASIC_API BOOL WINAPI HookCreateProcessA(
    LPCSTR                lpApplicationName,
    LPSTR                 lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL                  bInheritHandles,
    DWORD                 dwCreationFlags,
    LPVOID                lpEnvironment,
    LPCSTR                lpCurrentDirectory,
    LPSTARTUPINFOA        lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation)
{

    return DetourCreateProcessWithDllExA(lpApplicationName,
        lpCommandLine,
        lpProcessAttributes,
        lpThreadAttributes,
        bInheritHandles,
        dwCreationFlags,
        lpEnvironment,
        lpCurrentDirectory,
        lpStartupInfo,
        lpProcessInformation,
        HOOKDLL_PATH,
        TrueCreateProcessA);
}

DLLBASIC_API BOOL WINAPI HookCreateProcessW(
    LPCWSTR               lpApplicationName,
    LPWSTR                lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL                  bInheritHandles,
    DWORD                 dwCreationFlags,
    LPVOID                lpEnvironment,
    LPCWSTR               lpCurrentDirectory,
    LPSTARTUPINFOW        lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
)
{

    return DetourCreateProcessWithDll(lpApplicationName,
        lpCommandLine,
        lpProcessAttributes,
        lpThreadAttributes,
        bInheritHandles,
        dwCreationFlags,
        lpEnvironment,
        lpCurrentDirectory,
        lpStartupInfo,
        lpProcessInformation,
        HOOKDLL_PATH,
        TrueCreateProcessW);

}






BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    kern32dllmod = kern32dllmod = GetModuleHandle(TEXT("kernel32.dll"));
    switch (ul_reason_for_call)
    {

    case DLL_PROCESS_ATTACH:
        realCreateProcessInternalW = (pCreateProcessInternalW)(GetProcAddress(kern32dllmod, "CreateProcessInternalW"));
        DetourRestoreAfterWith();
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)realCreateProcessInternalW, MyCreateProcessInternalW);
        DetourAttach(&(PVOID&)TrueCreateProcessA, HookCreateProcessA);
        DetourAttach(&(PVOID&)TrueCreateProcessW, HookCreateProcessW);
  
       
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
        DetourDetach(&(PVOID&)realCreateProcessInternalW, MyCreateProcessInternalW);
        DetourDetach(&(PVOID&)TrueCreateProcessA, HookCreateProcessA);
        DetourDetach(&(PVOID&)TrueCreateProcessW, HookCreateProcessW);
        DetourTransactionCommit();
        printf("DLL_PROCESS_DETACH\n");
        break;
    }
    return TRUE;
}
BOOL WINAPI MyCreateProcessInternalW(HANDLE hToken,
    LPCWSTR lpApplicationName,
    LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation,
    PHANDLE hNewToken) {

    OutputDebugString(TEXT("[DCOM INJECTOR] Spawning one process!"));
    BOOL processCreated = FALSE;
    char buff[512];
    char* dllpath = NULL;

    // Save the previous value of the creation flags and make sure we add the create suspended BIT
    DWORD originalFlags = dwCreationFlags;
    dwCreationFlags = dwCreationFlags | CREATE_SUSPENDED;
    processCreated = realCreateProcessInternalW(hToken, lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation, hNewToken);
    if (processCreated) {

        // Now we need to detect if the new process is running on session 0 (i.e. service) or greater (interactive).
        // This is something that's gonna work only on win 7/Vista. Probably for windows 8 things will change.
        DWORD sessionId = -1;
        if (!ProcessIdToSessionId(lpProcessInformation->dwProcessId, &sessionId)) {
            DWORD err = GetLastError();
            // Something went wrong. Do not inject anything
            _snprintf_s(buff, sizeof(buff), "[DCOM INJECTOR] Cannot retrieve Session ID for pid %u. Error: %u. XXXX NOT INJECTING! XXXX", lpProcessInformation->dwProcessId, err);
            OutputDebugStringA(buff);
            // Do not inject anything
            return processCreated;
        }
        else {
            _snprintf_s(buff, sizeof(buff), "[DCOM INJECTOR] PID %u has session ID %u.", lpProcessInformation->dwProcessId, sessionId);
            OutputDebugStringA(buff);
        }

       
        dllpath = (char *)HOOKDLL_PATH;

        if (dllpath != NULL) {
            _snprintf_s(buff, sizeof(buff), "[DCOM INJECTOR] Injecting DLL %s into PID %u", dllpath, lpProcessInformation->dwProcessId);
            OutputDebugStringA(buff);

            // Allocate enough memory on the new process
            LPVOID baseAddress = (LPVOID)VirtualAllocEx(lpProcessInformation->hProcess, NULL, strlen(dllpath) + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

            // Copy the code to be injected
            WriteProcessMemory(lpProcessInformation->hProcess, baseAddress, dllpath, strlen(dllpath), NULL);

            OutputDebugStringA("[DCOM INJECTOR] DLL copied into host process memory space");

            kern32dllmod = GetModuleHandle(TEXT("kernel32.dll"));
            HANDLE loadLibraryAddress = GetProcAddress(kern32dllmod, "LoadLibraryA");
            if (loadLibraryAddress == NULL)
            {
                OutputDebugStringW(TEXT("[DCOM INJECTOR] LOADLIB IS NULL - XXXX"));
                //error
                return 0;
            }
            else {
                OutputDebugStringW(TEXT("[DCOM INJECTOR] LOAD LIB OK"));
            }

            // Create a remote thread the remote thread
            HANDLE  threadHandle = CreateRemoteThread(lpProcessInformation->hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddress, baseAddress, NULL, 0);
            if (threadHandle == NULL) {
                OutputDebugStringW(TEXT("[DCOM INJECTOR] REMTOE THREAD NOT OK XXXXX"));
            }
            else {
                OutputDebugStringW(TEXT("[DCOM INJECTOR] Remote thread created"));
                WaitForSingleObject(threadHandle, INFINITE);
            }

        }
        // Check if the process was meant to be stopped. If not, resume it now
        if ((originalFlags & CREATE_SUSPENDED) != CREATE_SUSPENDED) {
            // need to start it right away
            ResumeThread(lpProcessInformation->hThread);
            OutputDebugStringA("[DCOM INJECTOR] Thread resumed");
        }
    }
    else {
        DWORD error = GetLastError();
        _snprintf_s(buff, sizeof(buff), "[DCOM INJECTOR] Error creating process: %u. XXXX", error);
        OutputDebugStringA(buff);
    }
    return processCreated;
}
