
#include <stdio.h>
#include <windows.h>
#include "detours.h"


static BOOL (WINAPI * TruecreateprocessA)(
  LPCSTR lpApplicationName,
     LPSTR lpCommandLine,
  LPSECURITY_ATTRIBUTES lpProcessAttributes,
 LPSECURITY_ATTRIBUTES lpThreadAttributes,
 BOOL bInheritHandles,
   DWORD dwCreationFlags,
 LPVOID lpEnvironment,
LPCSTR lpCurrentDirectory,
  LPSTARTUPINFOA lpStartupInfo,
 LPPROCESS_INFORMATION lpProcessInformation
    ) = CreateProcessA;

static BOOL(WINAPI* TruecreateprocessW)(
    LPCWSTR lpApplicationName,
    LPWSTR lpCommandLine,
     LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
     DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
    ) = CreateProcessW;



BOOL WINAPI hookcreateA(LPCSTR lpApplicationName,
    LPSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCSTR lpCurrentDirectory,
    LPSTARTUPINFOA lpStartupInfo,
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
        "C:\\Fast32.dll",
     TruecreateprocessA);

 
}
BOOL WINAPI hookcreateW(LPCWSTR lpApplicationName,
    LPWSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCWSTR lpCurrentDirectory,
    LPSTARTUPINFOW lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation)
{

    return DetourCreateProcessWithDllExW(lpApplicationName,
        lpCommandLine,
        lpProcessAttributes,
        lpThreadAttributes,
        bInheritHandles,
        dwCreationFlags,
        lpEnvironment,
        lpCurrentDirectory,
        lpStartupInfo,
        lpProcessInformation,
        "C:\\Fast32.dll",
        TruecreateprocessW);


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

        printf("Fast" DETOURS_STRINGIFY(DETOURS_BITS) ".dll:"
               " Starting.\n");
        fflush(stdout);

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourAttach(&(PVOID&)TruecreateprocessA, hookcreateA);
        DetourAttach(&(PVOID&)TruecreateprocessW, hookcreateW);
        error = DetourTransactionCommit();

        if (error == NO_ERROR) {
            printf("fast" DETOURS_STRINGIFY(DETOURS_BITS) ".dll:"
                   " Detoured fast64.\n");
        }
        else {
            printf("fast" DETOURS_STRINGIFY(DETOURS_BITS) ".dll:"
                   " Error detouring Fast64: %ld\n", error);
        }
    }
    else if (dwReason == DLL_PROCESS_DETACH) {
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&(PVOID&)TruecreateprocessA, hookcreateA);
        DetourDetach(&(PVOID&)TruecreateprocessW, hookcreateW);
        error = DetourTransactionCommit();

        printf("fast" DETOURS_STRINGIFY(DETOURS_BITS) ".dll:"
               " Removed fast (result=%ld), slept ticks.\n", error);
        fflush(stdout);
    }
    return TRUE;
}

//
///////////////////////////////////////////////////////////////// End of File.
