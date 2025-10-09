#include <windows.h>
#include <iostream>
#include <ole2.h>
#include <psapi.h>
#include <vector>
#include <string>
#include <cstring>


static ULONG64 vtableOffset;

typedef LONG(NTAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);

typedef struct tagGETCLIPBDATA
{
    UINT uFmtRet;
    BOOL fGlobalHandle;
    union
    {
        HANDLE hLocale;
        HANDLE hPalette;
    };
} GETCLIPBDATA, * PGETCLIPBDATA;

typedef HANDLE(NTAPI* pNtUserGetClipboardData)(
    UINT fmt,
    PGETCLIPBDATA pgcd
    );

typedef NTSTATUS(APIENTRY* pNtUserCreateLocalMemHandle)(
    HANDLE 	hMem,
    LPVOID 	pData,
    DWORD64 cbData,
    DWORD* pcbData
    );


HMODULE win32udll = LoadLibrary(L"win32u.dll");
pNtUserGetClipboardData NtUserGetClipboardData = (pNtUserGetClipboardData)GetProcAddress(win32udll, "NtUserGetClipboardData");
pNtUserCreateLocalMemHandle NtUserCreateLocalMemHandle = (pNtUserCreateLocalMemHandle)GetProcAddress(win32udll, "NtUserCreateLocalMemHandle");

void lowVersionGetCurrentClipboradContent() {
    OpenClipboard(NULL);
    GETCLIPBDATA data = { 0 };

    HANDLE hMem = NtUserGetClipboardData(CF_UNICODETEXT, &data);

    if (data.fGlobalHandle){
        LPVOID r3Mem = CreateLocalMemHandle(hMem);
        CloseClipboard();
    }
}

LPVOID CreateLocalMemHandle(HANDLE hMem) {
    DWORD dwBytes;
    // 先报错拿到size
    if (NtUserCreateLocalMemHandle(hMem, NULL, 0, &dwBytes) != 0xC0000023) {
        return 0;
    }
    // 分配内存
    HGLOBAL R3Mem = GlobalAlloc(0, dwBytes);
    if (!R3Mem) return 0;

    // 将hMem复制到R3内存
    if(NtUserCreateLocalMemHandle(hMem, R3Mem, dwBytes,0) < 0) {
		GlobalFree(R3Mem);
		return 0;
	}

    return R3Mem;
}

CHAR* wideToUtf8(const WCHAR* src) {
    int size = WideCharToMultiByte(65001, 0, src, -1, nullptr, 0, nullptr, nullptr);
    if (size <= 0) return nullptr;
    CHAR* out = (CHAR*)malloc(size);
    if (!out) return nullptr;
    WideCharToMultiByte(65001, 0, src, -1, out, size, nullptr, nullptr);
    return out;
}

void PrintRemoteUnicodeString(HANDLE hProcess, ULONG64 remotePtr) {
    WCHAR buffer[0x2000] = { 0 };
    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(hProcess, (LPCVOID)remotePtr, buffer, sizeof(buffer) - sizeof(WCHAR), &bytesRead))
        return;

    CHAR* utf8 = wideToUtf8(buffer);
    if (utf8) {
        std::cout << "[+] -----------------------------------\n " << utf8 << std::endl;
        free(utf8);
    }
}

DWORD getSvchostPid()
{
    SC_HANDLE scm = OpenSCManagerA(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE | SC_MANAGER_CONNECT);
    if (!scm) return 0;
    DWORD bytesNeeded = 0;
    DWORD servicesReturned = 0;
    DWORD resume = 0;
    BOOL ok = EnumServicesStatusExA(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, NULL, 0, &bytesNeeded, &servicesReturned, &resume, NULL);
    if (bytesNeeded == 0) { CloseServiceHandle(scm); return 0; }
    std::vector<char> buf(bytesNeeded);
    ok = EnumServicesStatusExA(scm, SC_ENUM_PROCESS_INFO, SERVICE_WIN32, SERVICE_STATE_ALL, reinterpret_cast<LPBYTE>(buf.data()), (DWORD)buf.size(), &bytesNeeded, &servicesReturned, &resume, NULL);
    if (!ok) { CloseServiceHandle(scm); return 0; }
    ENUM_SERVICE_STATUS_PROCESSA* services = reinterpret_cast<ENUM_SERVICE_STATUS_PROCESSA*>(buf.data());
    for (DWORD i = 0; i < servicesReturned; ++i) {
        const char* name = services[i].lpServiceName;
        if (name && std::strstr(name, "cbdhsvc")) {
            SC_HANDLE svc = OpenServiceA(scm, name, SERVICE_QUERY_STATUS);
            if (!svc) continue;
            SERVICE_STATUS_PROCESS ssp = { 0 };
            DWORD needed = 0;
            if (QueryServiceStatusEx(svc, SC_STATUS_PROCESS_INFO, reinterpret_cast<LPBYTE>(&ssp), sizeof(ssp), &needed)) {
                DWORD pid = ssp.dwProcessId;
                CloseServiceHandle(svc);
                CloseServiceHandle(scm);
                if (pid != 0) return pid;
            }
            else {
                CloseServiceHandle(svc);
            }
        }
    }
    CloseServiceHandle(scm);
    return 0;
}

ULONG64 getVtableOffset(LPOSVERSIONINFOW version) {
    ULONG64 offset = 0;
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    auto RtlGetVersion = (RtlGetVersionPtr)GetProcAddress(ntdll, "RtlGetVersion");
    RtlGetVersion(version);

    switch (version->dwBuildNumber) {
    case 22000: offset = 0xAE160; break;
    case 18362: offset = 0x910C8; break;
    case 17134: offset = 0x7D860; break;
    case 17763: offset = 0x92070; break;
    case 19041:
        offset = (version->dwPlatformId == 1) ? 0x97150 : 0x92070;
        break;
    case 20348: offset = 0xAE160; break;
    case 22621:
        switch (version->dwPlatformId) {
        case 4541: offset = 0xB9128; break;
        case 4249: offset = 0xB4128; break;
        default: offset = 0xAF120; break;
        }
        break;
    case 26100:
        switch (version->dwPlatformId) {
        case 5074: offset = 0x8EEC8; break;
        case 3624:
        case 2454: offset = 0x93EC8; break;
        case 1882: offset = 0x8EEC8; break;
        default: offset = 0x87ED0; break;
        }
        break;
    default: break;
    }

    return offset;
}

LPVOID getCUnicodeTextFormatVtable(HANDLE hProcess, LPVOID* dllBase) {
    DWORD bytesNeeded = 0;
    HMODULE datatransferDLL = nullptr;

    EnumProcessModules(hProcess, nullptr, 0, &bytesNeeded);
    auto mods = (HMODULE*)malloc(bytesNeeded);
    if (EnumProcessModules(hProcess, mods, bytesNeeded, &bytesNeeded)) {
        for (size_t i = 0; i < bytesNeeded / sizeof(HMODULE); i++) {
            char baseName[MAX_PATH] = { 0 };
            if (K32GetModuleBaseNameA(hProcess, mods[i], baseName, MAX_PATH)) {
                if (_stricmp(baseName, "windows.applicationmodel.datatransfer.dll") == 0) {
                    datatransferDLL = mods[i];
                    *dllBase = datatransferDLL;
                    free(mods);
                    return (LPVOID)((ULONG64)datatransferDLL + vtableOffset);
                }
            }
        }
    }
    free(mods);
    return nullptr;
}

int wmain() {

    OSVERSIONINFOW version = { sizeof(OSVERSIONINFOW) };

    vtableOffset = getVtableOffset(&version);

    if (version.dwMajorVersion < 10) {
        lowVersionGetCurrentClipboradContent();
        return 0;
    }

    DWORD pid = getSvchostPid();
    if (!pid) {
        std::cout << "[-] Failed to find cbdhsvc process" << std::endl;
        return -1;
    }

    HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!hProcess) {
        std::cout << "[-] Failed to open process: " << GetLastError() << std::endl;
        return -1;
    }

    LPVOID dllBase = nullptr;
    LPVOID vtable = getCUnicodeTextFormatVtable(hProcess, &dllBase);
    if (!vtable || !dllBase) {
        std::cout << "[-] Failed to locate vtable or datatransfer.dll" << std::endl;
        CloseHandle(hProcess);
        return -1;
    }

    std::cout << "[+] vtable: 0x" << std::hex << vtable << std::endl;

    MEMORY_BASIC_INFORMATION mbi = { 0 };
    LPBYTE queryBase = nullptr;

    while (VirtualQueryEx(hProcess, queryBase, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.RegionSize == 0) break;

        if (mbi.State != MEM_COMMIT || mbi.Type != MEM_PRIVATE || mbi.Protect != PAGE_READWRITE) {
            queryBase += mbi.RegionSize;
            continue;
        }

        auto buffer = (BYTE*)malloc(mbi.RegionSize);
        SIZE_T bytesRead = 0;
        if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer, mbi.RegionSize, &bytesRead)) {
            for (SIZE_T j = 0; j + 0x20 < bytesRead; ++j) {
                if (*(buffer + j + 0x20) == 1) {
                    LPVOID lpmem = nullptr;
                    if (ReadProcessMemory(hProcess, (LPCVOID)((ULONG64)mbi.BaseAddress + j), &lpmem, sizeof(LPVOID), nullptr)) {
                        if (lpmem == vtable) {
                            LPVOID remoteStringPtr = nullptr;
                            if (ReadProcessMemory(hProcess, (LPCVOID)((ULONG64)mbi.BaseAddress + j + 0x18), &remoteStringPtr, sizeof(LPVOID), nullptr)) {
                                PrintRemoteUnicodeString(hProcess, (ULONG64)remoteStringPtr);
                            }
                        }
                    }
                }
            }
        }
        free(buffer);
        queryBase += mbi.RegionSize;
    }

    CloseHandle(hProcess);
    system("pause");
    return 0;
}