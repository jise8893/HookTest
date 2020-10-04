#include <iostream>
#include <processthreadsapi.h>
#include <winternl.h>
typedef NTSTATUS(NTAPI* pfNtAddAtomEx)(
    IN PWSTR String,
    IN ULONG StringLength,
    OUT PUSHORT Atom,
    ULONG Unknown
    );
typedef NTSTATUS(NTAPI* pNtQueueApcThread)(
    _In_ HANDLE ThreadHandle,
    _In_ PVOID ApcRoutine,
    _In_ PVOID ApcRoutineContext OPTIONAL,
    _In_ PVOID ApcStatusBlock OPTIONAL,
    _In_ PVOID ApcReserved OPTIONAL
    );
