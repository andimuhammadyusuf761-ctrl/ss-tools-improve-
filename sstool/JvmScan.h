#pragma once
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <vector>
#include <regex>
#include <algorithm>
#include <cstdio>
#include <cctype>
#include <cwctype>

#include "Console.h"
#include "Util.h"

// Some cheat-injection methods work by launching (or relaunching)
// Minecraft's JVM with extra command-line flags rather than modifying any
// jar on disk -- a -javaagent that bytecode-patches classes in memory at
// load time, or a debug/bootclasspath flag that bypasses the normal
// classloader. None of that shows up in a mods-folder scan or even a
// memory string scan if the agent is careful. This module reads the
// running java/javaw process's command line and flags known-suspicious
// patterns, the same signal the MeowModAnalyzer PowerShell tool's
// Invoke-JvmScan looks for.
//
// Win32 doesn't expose another process's command line directly, and
// reading it manually means walking the target's PEB via
// NtQueryInformationProcess -- undocumented, and needs matching bitness
// with the target. Shelling out to PowerShell's Get-CimInstance (WMI) is
// the same technique Task Manager's "Command line" column and the
// original tool both effectively use, so that's what this does.
namespace jvmscan {

    struct JavaProcessInfo {
        DWORD pid = 0;
        std::wstring exeName;
    };

    inline std::vector<JavaProcessInfo> findJavaProcesses() {
        std::vector<JavaProcessInfo> found;
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) return found;

        PROCESSENTRY32W entry{};
        entry.dwSize = sizeof(entry);
        if (Process32FirstW(snap, &entry)) {
            do {
                std::wstring name = entry.szExeFile;
                std::transform(name.begin(), name.end(), name.begin(), ::towlower);
                if (name == L"java.exe" || name == L"javaw.exe") {
                    found.push_back({ entry.th32ProcessID, entry.szExeFile });
                }
            } while (Process32NextW(snap, &entry));
        }
        CloseHandle(snap);
        return found;
    }

    // Retrieves a process's full command line via WMI (through
    // PowerShell). Returns an empty string if it couldn't be read
    // (access denied, PowerShell missing, etc.) -- callers should treat
    // that as "unknown" rather than "clean".
    inline std::string getCommandLine(DWORD pid) {
        std::string cmd = "powershell -NoProfile -WindowStyle Hidden -Command "
            "\"(Get-CimInstance Win32_Process -Filter 'ProcessId=" + std::to_string(pid) + "').CommandLine\"";

        FILE* pipe = _popen(cmd.c_str(), "r");
        if (!pipe) return {};

        std::string result;
        char buf[512];
        while (fgets(buf, sizeof(buf), pipe)) result += buf;
        _pclose(pipe);

        // trim trailing whitespace/newlines
        while (!result.empty() && std::isspace((unsigned char)result.back())) result.pop_back();
        return result;
    }

    struct JvmFinding {
        util::Severity severity;
        std::string text;
    };

    inline std::vector<JvmFinding> analyzeCommandLine(const std::string& cmdLine) {
        std::vector<JvmFinding> findings;
        if (cmdLine.empty()) return findings;

        static const std::vector<std::string> legitAgentMarkers = {
            "jmxremote", "yjp", "jrebel", "newrelic", "jacoco", "theseus"
        };

        try {
            std::regex agentRe(R"(-javaagent:([^\s"]+))");
            auto begin = std::sregex_iterator(cmdLine.begin(), cmdLine.end(), agentRe);
            for (auto it = begin; it != std::sregex_iterator(); ++it) {
                std::string agentPath = (*it)[1].str();
                std::string lowerPath = agentPath;
                std::transform(lowerPath.begin(), lowerPath.end(), lowerPath.begin(), ::tolower);

                bool isLegit = std::any_of(legitAgentMarkers.begin(), legitAgentMarkers.end(),
                    [&](const std::string& m) { return lowerPath.find(m) != std::string::npos; });

                if (!isLegit) {
                    findings.push_back({ util::Severity::Danger, "JVM agent injected -- -javaagent:" + agentPath });
                }
            }
        } catch (const std::regex_error&) { /* malformed cmdline text, skip agent parsing */ }

        struct FlagCheck { const char* flag; const char* desc; };
        static const FlagCheck suspiciousFlags[] = {
            { "-Xbootclasspath/p:", "prepends to bootstrap classpath, overrides core Java classes" },
            { "-Xbootclasspath/a:", "appends to bootstrap classpath, injects below the classloader" },
            { "-agentlib:jdwp",     "JDWP debug agent -- remote debugging enabled" },
            { "-agentpath:",        "native agent loaded -- bypasses the Java sandbox" },
        };
        for (const auto& sf : suspiciousFlags) {
            if (cmdLine.find(sf.flag) != std::string::npos) {
                findings.push_back({ util::Severity::Warning, std::string("Suspicious JVM flag -- ") + sf.flag + " (" + sf.desc + ")" });
            }
        }
        return findings;
    }

} // namespace jvmscan
