PVOID GetKernelModuleBase(PCSTR ModuleName)
{
    ULONG bytes = 0;
    ZwQuerySystemInformation(SystemModuleInformation, NULL, 0, &bytes);

    if (bytes == 0)
        return NULL;

    PRTL_PROCESS_MODULES modules = (PRTL_PROCESS_MODULES)ExAllocatePoolWithTag(NonPagedPool, bytes, 'mbmK');
    if (!modules)
        return NULL;

    NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, modules, bytes, &bytes);
    if (!NT_SUCCESS(status)) {
        ExFreePoolWithTag(modules, 'mbmK');
        return NULL;
    }

    PVOID base = NULL;
    for (ULONG i = 0; i < modules->NumberOfModules; i++) {
        if (_stricmp((CHAR*)modules->Modules[i].FullPathName + modules->Modules[i].OffsetToFileName, ModuleName) == 0) {
            base = modules->Modules[i].ImageBase;
            break;
        }
    }

    ExFreePoolWithTag(modules, 'mbmK');
    return base;
}

BOOLEAN DataCompare(const UCHAR* data, const UCHAR* pattern, const CHAR* mask)
{
    for (; *mask; ++mask, ++data, ++pattern) {
        if (*mask == 'x' && *data != *pattern)
            return FALSE;
    }
    return TRUE;
}

PVOID FindPattern(PVOID base, PCSTR pattern, PCSTR mask)
{
    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)base;
    PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((PUCHAR)base + dosHeader->e_lfanew);
    DWORD size = ntHeaders->OptionalHeader.SizeOfImage;

    for (DWORD i = 0; i < size - strlen(mask); i++) {
        PUCHAR addr = (PUCHAR)base + i;
        if (DataCompare(addr, (PUCHAR)pattern, mask))
            return addr;
    }
    return NULL;
}

ULONG64 ResolveRelativeAddress(PUCHAR instruction, ULONG offsetOffset, ULONG instructionLength)
{
    LONG offset = *(PLONG)(instruction + offsetOffset);
    return (ULONG64)(instruction + instructionLength + offset);
}

VOID DisableNmiHandling()
{
    DbgPrint("[nmi_blocker] Initializing NMI block routine...\n");

    PVOID ntBase = GetKernelModuleBase("ntoskrnl.exe");
    if (!ntBase) {
        DbgPrint("[nmi_blocker] Failed to locate ntoskrnl base address.\n");
        return;
    }

    // E8 ?? ?? ?? ?? 83 CB FF 48 8B D6
    PCSTR pattern = "\xE8\x00\x00\x00\x00\x83\xCB\xFF\x48\x8B\xD6";
    PCSTR mask = "x????xxxxxx";

    PUCHAR match = (PUCHAR)FindPattern(ntBase, pattern, mask);
    if (!match) {
        DbgPrint("[nmi_blocker] Pattern not found in ntoskrnl.\n");
        return;
    }

    DbgPrint("[nmi_blocker] Pattern located at: 0x%p\n", match);

    // KiInitializeIdt
    ULONG64 firstCallTarget = ResolveRelativeAddress(match, 1, 5);
    DbgPrint("[nmi_blocker] First resolved address: 0x%llx\n", firstCallTarget);

    // KiInterruptInitTable
    ULONG64 secondCallTarget = ResolveRelativeAddress((PUCHAR)(firstCallTarget + 0x1A), 3, 7);
    DbgPrint("[nmi_blocker] Second resolved address (target IDT struct): 0x%llx\n", secondCallTarget);

    // Patch the IDT entries to redirect NMI handlers
    *(PULONG64)(secondCallTarget + 0x38) = *(PULONG64)(secondCallTarget + 0x1A0);
    *(PULONG64)(secondCallTarget + 0x40) = *(PULONG64)(secondCallTarget + 0x1A8);

    DbgPrint("[nmi_blocker] IDT entry modified. NMI should now be blocked or redirected.\n");
}