#pragma once
#define NOMINMAX
#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <vector>
#include <algorithm>
#include <iostream>

// ---- helpers -------------------------------------------------------------

static std::string toLower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return (char)std::tolower(c); });
    return s;
}

static bool containsAny(const std::string& haystackLower, const std::vector<std::string>& needlesLower) {
    for (const auto& n : needlesLower) {
        if (haystackLower.find(n) != std::string::npos) return true;
    }
    return false;
}

struct MacroHit {
    std::string source;   // "process", "window", "installed"
    std::string name;     // what matched
    DWORD pid = 0;        // only for process hits
};

// ---- 1. running processes (covers 198M Macro / Zenith Macro running in background) ----
static std::vector<MacroHit> scanRunningProcesses(const std::vector<std::string>& keywordsLower) {
    std::vector<MacroHit> hits;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return hits;

    PROCESSENTRY32 entry{};
    entry.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(snap, &entry)) {
        do {
            std::string exeName = entry.szExeFile;
            std::string lower = toLower(exeName);
            if (containsAny(lower, keywordsLower)) {
                hits.push_back({ "process", exeName, entry.th32ProcessID });
            }
        } while (Process32Next(snap, &entry));
    }
    CloseHandle(snap);
    return hits;
}

// ---- 2. window titles (catches macro GUIs even if the exe itself is renamed) ----
struct EnumContext {
    const std::vector<std::string>* keywords;
    std::vector<MacroHit>* hits;
};

static BOOL CALLBACK enumWindowsProc(HWND hwnd, LPARAM lParam) {
    auto* ctx = reinterpret_cast<EnumContext*>(lParam);
    if (!IsWindowVisible(hwnd)) return TRUE;

    char title[256];
    int len = GetWindowTextA(hwnd, title, sizeof(title));
    if (len <= 0) return TRUE;

    std::string lower = toLower(std::string(title, len));
    if (containsAny(lower, *ctx->keywords)) {
        DWORD pid = 0;
        GetWindowThreadProcessId(hwnd, &pid);
        ctx->hits->push_back({ "window", std::string(title, len), pid });
    }
    return TRUE;
}

static std::vector<MacroHit> scanWindowTitles(const std::vector<std::string>& keywordsLower) {
    std::vector<MacroHit> hits;
    EnumContext ctx{ &keywordsLower, &hits };
    EnumWindows(enumWindowsProc, reinterpret_cast<LPARAM>(&ctx));
    return hits;
}

// ---- 3. installed programs via the Uninstall registry keys ----
// Catches macro software that is installed but not currently running.
static void scanUninstallKey(HKEY root, const std::wstring& subKey, const std::vector<std::string>& keywordsLower, std::vector<MacroHit>& hits) {
    HKEY hKey;
    if (RegOpenKeyExW(root, subKey.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) return;

    wchar_t nameBuf[256];
    DWORD index = 0;
    DWORD nameLen = 256;

    while (RegEnumKeyExW(hKey, index, nameBuf, &nameLen, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
        HKEY subHKey;
        if (RegOpenKeyExW(hKey, nameBuf, 0, KEY_READ, &subHKey) == ERROR_SUCCESS) {
            wchar_t displayName[512];
            DWORD size = sizeof(displayName);
            if (RegQueryValueExW(subHKey, L"DisplayName", nullptr, nullptr, reinterpret_cast<LPBYTE>(displayName), &size) == ERROR_SUCCESS) {
                int utf8Len = WideCharToMultiByte(CP_UTF8, 0, displayName, -1, nullptr, 0, nullptr, nullptr);
                std::string name(utf8Len, 0);
                WideCharToMultiByte(CP_UTF8, 0, displayName, -1, name.data(), utf8Len, nullptr, nullptr);

                std::string lower = toLower(name);
                if (containsAny(lower, keywordsLower)) {
                    hits.push_back({ "installed", name, 0 });
                }
            }
            RegCloseKey(subHKey);
        }
        index++;
        nameLen = 256;
    }
    RegCloseKey(hKey);
}

static std::vector<MacroHit> scanInstalledPrograms(const std::vector<std::string>& keywordsLower) {
    std::vector<MacroHit> hits;
    // 64-bit apps
    scanUninstallKey(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", keywordsLower, hits);
    // 32-bit apps on 64-bit Windows
    scanUninstallKey(HKEY_LOCAL_MACHINE, L"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall", keywordsLower, hits);
    // per-user installs
    scanUninstallKey(HKEY_CURRENT_USER, L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall", keywordsLower, hits);
    return hits;
}

// ---- combined entry point ----
static const std::vector<std::string> macroKeywords = {
    "198m macro",      // "198M Macros"
    "198macro",
    "zenith macro",    // "Zenith Macros"
};

static void runMacroScan() {
    std::cout << "\n[Macro Scan] Checking running processes, window titles, and installed programs...\n";

    auto procHits = scanRunningProcesses(macroKeywords);
    auto winHits = scanWindowTitles(macroKeywords);
    auto installHits = scanInstalledPrograms(macroKeywords);

    size_t total = procHits.size() + winHits.size() + installHits.size();

    for (const auto& h : procHits)
        std::cout << "[!] Running process match: " << h.name << " (PID " << h.pid << ")\n";
    for (const auto& h : winHits)
        std::cout << "[!] Window title match: " << h.name << " (PID " << h.pid << ")\n";
    for (const auto& h : installHits)
        std::cout << "[!] Installed program match: " << h.name << "\n";

    if (total == 0)
        std::cout << "No macro software traces found.\n";
    else
        std::cout << "Total traces found: " << total << "\n";
}
