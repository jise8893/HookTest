// dllmain.cpp : DLL 애플리케이션의 진입점을 정의합니다.
#include "pch.h"
#include <detours.h>

// 속도 확인하면서 명시적으로 바꿀 필요성 있을듯함
#define DLLBASIC_API extern "C" __declspec(dllexport)
#pragma comment(lib, "detours.lib")

//static INT(WINAPI* TrueMessageBoxA)(HWND hWnd, LPCSTR lpTextm, LPCSTR lpCaption, UINT uType) = MessageBoxA;
//DLLBASIC_API INT WINAPI HookTestMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
//    return TrueMessageBoxA(hWnd, "Hooking", lpCaption, uType);
//}

// TrueVirtualAllocEx = VirtualAllocEx를 지정해줍니다.
static LPVOID(WINAPI* TrueVirtualAllocEx)(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) = VirtualAllocEx;

DLLBASIC_API LPVOID WINAPI HookVirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
    OutputDebugString(L"VirtualAllocEx Hooking SUCCESS!");

    return TrueVirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DetourRestoreAfterWith();
        //DisableTreadLibraryCalls(hModule);

        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        //프로세스가 실제 함수 대신 후킹 함수를 호출해야한다고 믿게만듭니다.
        DetourAttach(&(PVOID&)TrueVirtualAllocEx, HookVirtualAllocEx);
        //DetourTransactionCommit();
        if (DetourTransactionCommit() != NO_ERROR) {
            OutputDebugString(L"VirtualAllocEx detoured UNsuccessfully");
        }
        else
            OutputDebugString(L"VirtualAllocEx detoured successfully");
        break;
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&(PVOID&)TrueVirtualAllocEx, HookVirtualAllocEx);
        DetourTransactionCommit();
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

