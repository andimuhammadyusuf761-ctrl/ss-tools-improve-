#pragma once
#define NOMINMAX
#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <vector>
#include <algorithm>
#include <iostream>
#include <filesystem>
#include <Shellapi.h>

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
    std::string path;     // executable, install folder, or best evidence path
};

static std::string queryProcessPath(DWORD pid) {
    HANDLE process = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!process) return {};

    char path[MAX_PATH * 4]{};
    DWORD size = static_cast<DWORD>(sizeof(path));
    std::string result;
    if (QueryFullProcessImageNameA(process, 0, path, &size)) {
        result.assign(path, size);
    }
    CloseHandle(process);
    return result;
}

static std::string wideToUtf8Local(const wchar_t* value) {
    if (!value || !value[0]) return {};
    int utf8Len = WideCharToMultiByte(CP_UTF8, 0, value, -1, nullptr, 0, nullptr, nullptr);
    if (utf8Len <= 1) return {};
    std::string out(static_cast<size_t>(utf8Len - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value, -1, out.data(), utf8Len, nullptr, nullptr);
    return out;
}

static std::string readRegistryString(HKEY key, const wchar_t* valueName) {
    wchar_t buf[1024]{};
    DWORD type = 0;
    DWORD size = sizeof(buf);
    if (RegQueryValueExW(key, valueName, nullptr, &type, reinterpret_cast<LPBYTE>(buf), &size) != ERROR_SUCCESS) return {};
    if (type != REG_SZ && type != REG_EXPAND_SZ) return {};
    return wideToUtf8Local(buf);
}

static std::string stripCommandToPath(std::string value) {
    if (value.empty()) return {};
    value.erase(std::remove(value.begin(), value.end(), '\0'), value.end());
    if (!value.empty() && value.front() == '"') {
        size_t endQuote = value.find('"', 1);
        if (endQuote != std::string::npos) return value.substr(1, endQuote - 1);
    }

    std::string lower = toLower(value);
    size_t exePos = lower.find(".exe");
    if (exePos != std::string::npos) return value.substr(0, exePos + 4);
    return value;
}

static std::string parentFolderOf(const std::string& path) {
    if (path.empty()) return {};
    std::error_code ec;
    std::filesystem::path p(path);
    if (std::filesystem::is_directory(p, ec)) return p.string();
    if (p.has_parent_path()) return p.parent_path().string();
    return {};
}

static bool is198mOrZenith(const MacroHit& hit) {
    std::string lower = toLower(hit.name + " " + hit.path);
    return lower.find("198m macro") != std::string::npos ||
           lower.find("198macro") != std::string::npos ||
           lower.find("zenith macro") != std::string::npos;
}

static bool isAutoHotkey(const MacroHit& hit) {
    std::string lower = toLower(hit.name + " " + hit.path);
    return lower.find("autohotkey") != std::string::npos ||
           lower.find("auto hotkey") != std::string::npos ||
           lower.find(".ahk") != std::string::npos;
}

static bool openEvidencePath(const MacroHit& hit) {
    std::string target = is198mOrZenith(hit) ? hit.path : parentFolderOf(hit.path);
    if (target.empty() && isAutoHotkey(hit)) {
        target = "C:\\Program Files\\AutoHotkey";
    }
    if (target.empty()) return false;

    HINSTANCE result = ShellExecuteA(nullptr, "open", target.c_str(), nullptr, nullptr, SW_SHOWNORMAL);
    return reinterpret_cast<intptr_t>(result) > 32;
}

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
                hits.push_back({ "process", exeName, entry.th32ProcessID, queryProcessPath(entry.th32ProcessID) });
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
        ctx->hits->push_back({ "window", std::string(title, len), pid, queryProcessPath(pid) });
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
            std::string name = readRegistryString(subHKey, L"DisplayName");
            if (!name.empty()) {
                std::string lower = toLower(name);
                if (containsAny(lower, keywordsLower)) {
                    std::string path;
                    if (lower.find("198m macro") != std::string::npos ||
                        lower.find("198macro") != std::string::npos ||
                        lower.find("zenith macro") != std::string::npos) {
                        path = stripCommandToPath(readRegistryString(subHKey, L"DisplayIcon"));
                        if (path.empty()) path = stripCommandToPath(readRegistryString(subHKey, L"UninstallString"));
                        if (path.empty()) path = readRegistryString(subHKey, L"InstallLocation");
                    } else {
                        path = readRegistryString(subHKey, L"InstallLocation");
                        if (path.empty()) path = stripCommandToPath(readRegistryString(subHKey, L"DisplayIcon"));
                        if (path.empty()) path = stripCommandToPath(readRegistryString(subHKey, L"UninstallString"));
                    }
                    hits.push_back({ "installed", name, 0, path });
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
    "auto hotkey",
    "autohotkey",
    ".ahk",
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
