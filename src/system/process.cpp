#include <windows.h>
#include <tlhelp32.h>

#include <process.h>

std::wstring getparentprocess() {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE) return L"";

    PROCESSENTRY32 pe{};
    pe.dwSize = sizeof(pe);

    DWORD pid = GetCurrentProcessId();
    DWORD ppid = 0;

    if (Process32First(snapshot, &pe)) {
        do {
            if (pe.th32ProcessID == pid) {
                ppid = pe.th32ParentProcessID;
                break;
            }
        } while (Process32Next(snapshot, &pe));
    }

    if (!ppid) {
        CloseHandle(snapshot);
        return L"";
    }

    pe.dwSize = sizeof(pe);
    if (Process32First(snapshot, &pe)) {
        do {
            if (pe.th32ProcessID == ppid) {
                std::wstring exe = pe.szExeFile;
                CloseHandle(snapshot);

                // strip .exe extension
                size_t len = exe.length();
                return (len > 4 && exe.substr(len - 4) == L".exe") ? exe.substr(0, len - 4) : exe;
            }
        } while (Process32Next(snapshot, &pe));
    }

    CloseHandle(snapshot);
    return L"";
}

std::wstring mapshellname(const std::wstring& exe) {
    return exe;
}
