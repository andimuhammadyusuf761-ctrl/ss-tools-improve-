#pragma once
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <algorithm>
#include <cstdio>
#include <memory>

#include "Console.h"
#include "Util.h"

// =====================================================================
// System-level forensic checks -- OS artifacts left behind by a cheat
// client or its injector even after the jar/client itself has been
// deleted. Ported from the MeowModAnalyzer PowerShell tool's
// Check-PrefetchFiles / Check-StartupFolder / Check-RecentJarFiles /
// Check-ScheduledTasks / Check-SuspiciousProcesses / Check-HostsFileManipulation
// idea set, reimplemented natively in C++ (registry + filesystem APIs,
// with schtasks.exe shelled out to for scheduled-task enumeration since
// there's no lightweight native Task Scheduler COM wrapper worth adding
// as a dependency here).
//
// Every check here is best-effort and read-only. Several need admin to
// see everything (Prefetch, other users' scheduled tasks) -- this is
// noted per-finding rather than failing silently.
// =====================================================================
namespace sysforensics {

    namespace fs = std::filesystem;

    using Severity = util::Severity;
    using Finding = util::Finding;
    using util::toLowerA;

    // Client/injector name fragments to look for across all the checks
    // below. Deliberately the same family of names already tracked in
    // CheatStrings.h / main.cpp's per-client pattern lists, kept short
    // here since these checks match against file/process/task *names*
    // rather than full class-path strings.
    static const std::vector<std::string> knownClientFragments = {
        "novaclient", "crystalpvphelper", "noqwdclient", "skateclient",
        "argon", "doomsday", "meteorclient", "meteor-client", "wurst",
        "impactclient", "impact-client", "sigmaclient", "sigma-client",
        "rusherhack", "vapeclient", "vape-client", "liquidbounce",
        "kamiblue", "bleachhack", "inertia-client", "futureclient",
        "aristois", "fdpclient", "seppuku", "injector", "cheatinjector",
        "198m macro", "198macro", "zenith macro",
    };

    static bool containsKnownClient(const std::string& lower) {
        for (const auto& f : knownClientFragments) {
            if (lower.find(f) != std::string::npos) return true;
        }
        return false;
    }

    static fs::path expandEnv(const std::wstring& raw) {
        wchar_t buf[MAX_PATH * 2];
        DWORD n = ExpandEnvironmentStringsW(raw.c_str(), buf, MAX_PATH * 2);
        if (n == 0) return fs::path();
        return fs::path(std::wstring(buf, n - 1));
    }

    // ---- 1. Prefetch traces -------------------------------------------
    // C:\Windows\Prefetch holds a record ("NAME-HASH.pf") of every .exe
    // that has run on the system, even if it was deleted immediately
    // after. This is the single most useful "it ran here at some point"
    // artifact for a standalone injector/loader .exe. Reading the folder
    // itself only needs admin on some hardened configs; listing it is
    // usually fine as a regular user.
    static std::vector<Finding> checkPrefetchTraces() {
        std::vector<Finding> out;
        fs::path prefetchDir = expandEnv(L"%WINDIR%\\Prefetch");
        std::error_code ec;
        if (!fs::exists(prefetchDir, ec)) {
            out.push_back({ Severity::Info, "Prefetch folder not accessible (may need Administrator)." });
            return out;
        }

        bool anyHit = false;
        for (auto& entry : fs::directory_iterator(prefetchDir, fs::directory_options::skip_permission_denied, ec)) {
            if (ec) break;
            std::string name = toLowerA(entry.path().filename().string());
            if (containsKnownClient(name)) {
                anyHit = true;
                out.push_back({ Severity::Danger, "Prefetch trace of a known cheat/injector executable: " + entry.path().filename().string() });
            }
        }
        if (!anyHit) out.push_back({ Severity::Info, "No known cheat/injector executables found in Prefetch history." });
        return out;
    }

    // ---- 2. Startup folder + Run registry keys -------------------------
    // Persistence mechanisms: things set to launch automatically at
    // logon. A cheat/macro tool that wants to survive reboots (or an
    // injector staged to run before Minecraft) commonly lands here.
    static std::vector<Finding> checkStartupPersistence() {
        std::vector<Finding> out;
        bool anyHit = false;

        // Startup folders (current user + all users)
        std::vector<fs::path> startupDirs = {
            expandEnv(L"%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"),
            expandEnv(L"%PROGRAMDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"),
        };
        std::error_code ec;
        for (const auto& dir : startupDirs) {
            if (!fs::exists(dir, ec)) continue;
            for (auto& entry : fs::directory_iterator(dir, fs::directory_options::skip_permission_denied, ec)) {
                if (ec) break;
                std::string name = toLowerA(entry.path().filename().string());
                if (containsKnownClient(name)) {
                    anyHit = true;
                    out.push_back({ Severity::Danger, "Startup folder entry matches a known client: " + entry.path().filename().string() });
                }
            }
        }

        // HKCU/HKLM ...\Run and RunOnce keys
        struct RegRoot { HKEY hive; const wchar_t* subkey; const char* label; };
        static const RegRoot roots[] = {
            { HKEY_CURRENT_USER,  L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",     "HKCU\\...\\Run" },
            { HKEY_CURRENT_USER,  L"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce", "HKCU\\...\\RunOnce" },
            { HKEY_LOCAL_MACHINE, L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",     "HKLM\\...\\Run" },
        };

        for (const auto& root : roots) {
            HKEY key;
            if (RegOpenKeyExW(root.hive, root.subkey, 0, KEY_READ, &key) != ERROR_SUCCESS) continue;

            wchar_t valueName[256];
            BYTE valueData[2048];
            DWORD index = 0;
            while (true) {
                DWORD nameLen = 256;
                DWORD dataLen = sizeof(valueData);
                DWORD type = 0;
                LONG r = RegEnumValueW(key, index++, valueName, &nameLen, nullptr, &type, valueData, &dataLen);
                if (r == ERROR_NO_MORE_ITEMS) break;
                if (r != ERROR_SUCCESS) continue;
                if (type != REG_SZ && type != REG_EXPAND_SZ) continue;

                std::wstring data(reinterpret_cast<wchar_t*>(valueData));
                int len = WideCharToMultiByte(CP_UTF8, 0, data.c_str(), -1, nullptr, 0, nullptr, nullptr);
                std::string dataA(len > 0 ? len - 1 : 0, '\0');
                if (len > 0) WideCharToMultiByte(CP_UTF8, 0, data.c_str(), -1, dataA.data(), len, nullptr, nullptr);

                std::string lower = toLowerA(dataA);
                if (containsKnownClient(lower)) {
                    anyHit = true;
                    out.push_back({ Severity::Danger, std::string(root.label) + " autorun entry looks suspicious: " + dataA });
                }
            }
            RegCloseKey(key);
        }

        if (!anyHit) out.push_back({ Severity::Info, "No suspicious autorun/startup entries found." });
        return out;
    }

    // ---- 3. Recently accessed .jar files -------------------------------
    // Windows' "Recent Items" (jump lists / shell recent folder) records
    // file shortcuts for recently opened files, including jars opened
    // directly (double-clicked, dragged into a mods folder via Explorer).
    static std::vector<Finding> checkRecentJarFiles() {
        std::vector<Finding> out;
        fs::path recentDir = expandEnv(L"%APPDATA%\\Microsoft\\Windows\\Recent");
        std::error_code ec;
        if (!fs::exists(recentDir, ec)) {
            out.push_back({ Severity::Info, "Recent Items folder not accessible." });
            return out;
        }

        bool anyHit = false;
        int jarShortcutCount = 0;
        for (auto& entry : fs::directory_iterator(recentDir, fs::directory_options::skip_permission_denied, ec)) {
            if (ec) break;
            std::string name = toLowerA(entry.path().filename().string());
            if (name.size() > 8 && name.substr(name.size() - 8) == ".jar.lnk") {
                jarShortcutCount++;
                if (containsKnownClient(name)) {
                    anyHit = true;
                    out.push_back({ Severity::Danger, "Recently opened jar matches a known client name: " + entry.path().filename().string() });
                }
            }
        }
        if (!anyHit) {
            out.push_back({ Severity::Info, "No recently opened .jar files match known client names (" +
                std::to_string(jarShortcutCount) + " jar shortcut(s) total)." });
        }
        return out;
    }

    // ---- 4. Scheduled tasks ---------------------------------------------
    // Another persistence path, separate from the Run keys, and one some
    // cheat installers/injectors specifically prefer since Task Scheduler
    // entries are less commonly audited by players. Shells out to
    // schtasks.exe /query (read-only) rather than adding a Task
    // Scheduler COM dependency.
    static std::vector<Finding> checkScheduledTasks() {
        std::vector<Finding> out;

        HANDLE readPipe, writePipe;
        SECURITY_ATTRIBUTES sa{ sizeof(sa), nullptr, TRUE };
        if (!CreatePipe(&readPipe, &writePipe, &sa, 0)) {
            out.push_back({ Severity::Info, "Could not enumerate scheduled tasks (pipe creation failed)." });
            return out;
        }
        SetHandleInformation(readPipe, HANDLE_FLAG_INHERIT, 0);

        STARTUPINFOW si{};
        si.cb = sizeof(si);
        si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        si.hStdOutput = writePipe;
        si.hStdError = writePipe;
        PROCESS_INFORMATION pi{};

        std::wstring cmd = L"schtasks.exe /query /fo LIST";
        std::vector<wchar_t> mutableCmd(cmd.begin(), cmd.end());
        mutableCmd.push_back(L'\0');

        BOOL ok = CreateProcessW(nullptr, mutableCmd.data(), nullptr, nullptr, TRUE,
            CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
        CloseHandle(writePipe);

        if (!ok) {
            CloseHandle(readPipe);
            out.push_back({ Severity::Info, "Could not run schtasks.exe to enumerate scheduled tasks." });
            return out;
        }

        std::string output;
        char buf[4096];
        DWORD bytesRead;
        while (ReadFile(readPipe, buf, sizeof(buf), &bytesRead, nullptr) && bytesRead > 0) {
            output.append(buf, bytesRead);
        }
        CloseHandle(readPipe);
        WaitForSingleObject(pi.hProcess, 5000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);

        std::istringstream stream(output);
        std::string line;
        bool anyHit = false;
        while (std::getline(stream, line)) {
            std::string lower = toLowerA(line);
            if (containsKnownClient(lower)) {
                anyHit = true;
                out.push_back({ Severity::Danger, "Scheduled task entry looks suspicious: " + line });
            }
        }
        if (!anyHit) out.push_back({ Severity::Info, "No suspicious scheduled tasks found." });
        return out;
    }

    // ---- 5. Hosts file tampering ----------------------------------------
    // Some cheat clients/injectors edit the hosts file to blackhole
    // anti-cheat telemetry or update-check domains. Any non-comment,
    // non-localhost entry is worth a look; this doesn't try to maintain
    // a domain blocklist, it just surfaces what's there for the operator.
    static std::vector<Finding> checkHostsFile() {
        std::vector<Finding> out;
        fs::path hostsPath = expandEnv(L"%WINDIR%\\System32\\drivers\\etc\\hosts");
        std::ifstream f(hostsPath);
        if (!f.is_open()) {
            out.push_back({ Severity::Info, "Could not read hosts file." });
            return out;
        }

        std::string line;
        int customEntries = 0;
        bool anyHit = false;
        while (std::getline(f, line)) {
            std::string trimmed = line;
            trimmed.erase(0, trimmed.find_first_not_of(" \t\r\n"));
            if (trimmed.empty() || trimmed[0] == '#') continue;
            if (trimmed.find("127.0.0.1") == 0 || trimmed.find("::1") == 0) {
                // still check what's being redirected even for localhost entries
            }
            customEntries++;
            std::string lower = toLowerA(trimmed);
            if (lower.find("hypixel") != std::string::npos || lower.find("anticheat") != std::string::npos ||
                lower.find("grim") != std::string::npos || lower.find("vulcan") != std::string::npos ||
                lower.find("negativity") != std::string::npos) {
                anyHit = true;
                out.push_back({ Severity::Danger, "Hosts file entry blackholes an anti-cheat/server domain: " + trimmed });
            }
        }
        if (!anyHit) {
            out.push_back({ Severity::Info, customEntries == 0
                ? "Hosts file has no custom entries."
                : "Hosts file has " + std::to_string(customEntries) + " custom entrie(s), none matching known anti-cheat domains." });
        }
        return out;
    }

    // ---- 6. Suspicious running processes --------------------------------
    // Broader net than the memory scan's javaw.exe target: catches
    // standalone injector/loader .exe files, cheat-panel launchers, or
    // macro tools that are running as their own separate process rather
    // than inside the JVM.
    static std::vector<Finding> checkSuspiciousProcesses() {
        std::vector<Finding> out;
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) {
            out.push_back({ Severity::Info, "Could not enumerate running processes." });
            return out;
        }

        PROCESSENTRY32 entry{};
        entry.dwSize = sizeof(entry);
        bool anyHit = false;
        if (Process32First(snap, &entry)) {
            do {
                std::string name = toLowerA(entry.szExeFile);
                if (containsKnownClient(name)) {
                    anyHit = true;
                    out.push_back({ Severity::Danger, "Running process matches a known client/injector name: " +
                        std::string(entry.szExeFile) + " (PID " + std::to_string(entry.th32ProcessID) + ")" });
                }
            } while (Process32Next(snap, &entry));
        }
        CloseHandle(snap);
        if (!anyHit) out.push_back({ Severity::Info, "No suspicious standalone processes running." });
        return out;
    }

} // namespace sysforensics
