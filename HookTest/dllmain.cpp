// dllmain.cpp : DLL 애플리케이션의 진입점을 정의합니다.
#include "pch.h"
#include <detours.h>
#include <stdio.h>
#include <iostream>

// 속도 확인하면서 명시적으로 바꿀 필요성 있을듯함
#define DLLBASIC_API extern "C" __declspec(dllexport)
#pragma comment(lib, "detours.lib")

static INT(WINAPI* TrueMessageBoxA)(HWND hWnd, LPCSTR lpTextm, LPCSTR lpCaption, UINT uType) = MessageBoxA;

DLLBASIC_API INT WINAPI HookTestMessageBoxA(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) {
    return TrueMessageBoxA(hWnd, "Hooking", lpCaption, uType);
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
        DetourAttach(&(PVOID&)TrueMessageBoxA, HookTestMessageBoxA);
        DetourTransactionCommit();
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        DetourDetach(&(PVOID&)TrueMessageBoxA, HookTestMessageBoxA);
        DetourTransactionCommit();
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

