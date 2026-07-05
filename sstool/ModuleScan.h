#pragma once
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <vector>
#include <algorithm>
#include <cctype>

#include "Console.h"
#include "Util.h"

// =====================================================================
// Loaded-module (DLL) scan for a target java/javaw process.
//
// This is a different signal from PatternScan.h's memory string search:
// that catches cheat *strings* sitting in the JVM heap, this catches
// cheat *code* that got into the process a different way -- a native DLL
// injected via CreateRemoteThread/SetWindowsHookEx/manual mapping, e.g.
// an aim-assist/ESP helper implemented as a native module, or an
// injector that never touches a jar on disk at all. Ported in spirit
// from the Python memory-scanner tool's scan_modules(), but where that
// tool only enumerated modules for later use, this adds the actual
// suspicion heuristics (there's no code-signing database to check
// against here, so this is deliberately conservative -- flagged does
// not mean confirmed malicious, the operator still reviews the path).
// =====================================================================
namespace modulescan {

    using Severity = util::Severity;

    struct ModuleFinding {
        Severity severity;
        std::string name;
        std::string path;
        std::string reason;
    };

    using util::toLowerA;

    // Name fragments commonly seen in injector / hook / cheat-helper DLLs.
    // Kept short and generic on purpose -- these are meant to raise an
    // eyebrow, not convict; the operator still reviews the path.
    static const std::vector<std::string> suspiciousNameFragments = {
        "inject", "hook", "cheat", "hack", "loader", "bypass",
        "aimassist", "aim_assist", "triggerbot", "espoverlay",
        "wallhack", "kernelcheat", "d3d9hook", "d3d11hook", "opengl32hook",
        "xinput1_3", // classic proxy-DLL hijack name used by some injectors
    };

    // Directories a *legitimate* module loaded into a java.exe/javaw.exe
    // process should live under: the JRE/JDK bundled with the launcher,
    // Windows system directories, and common legitimate native-library
    // drop points (LWJGL/JOML extract natives next to the game or into a
    // per-version natives folder under .minecraft).
    static bool isTrustedLocation(const std::string& pathLower) {
        static const std::vector<std::string> trustedFragments = {
            "\\windows\\system32\\",
            "\\windows\\syswow64\\",
            "\\windows\\winsxs\\",
            "\\jre\\bin\\",
            "\\jdk\\bin\\",
            "\\java\\jre",
            "\\eclipse adoptium\\",
            "\\microsoft\\jdk\\",
            "\\.minecraft\\bin\\",
            "\\.minecraft\\versions\\",
            "\\.minecraft\\natives",
            "\\appdata\\local\\packages\\", // MS Store Java/launcher installs
            "\\program files\\",
            "\\program files (x86)\\",
        };
        for (const auto& f : trustedFragments) {
            if (pathLower.find(f) != std::string::npos) return true;
        }
        return false;
    }

    static bool isTempOrUserDrop(const std::string& pathLower) {
        static const std::vector<std::string> tempFragments = {
            "\\appdata\\local\\temp\\",
            "\\windows\\temp\\",
            "\\downloads\\",
            "\\desktop\\",
            "\\public\\",
        };
        for (const auto& f : tempFragments) {
            if (pathLower.find(f) != std::string::npos) return true;
        }
        return false;
    }

    // A short, all-hex or random-looking module name (no dictionary-ish
    // words) is a common byproduct of injectors that rename their payload
    // DLL per-build to dodge static blocklists, e.g. "a1b2c3d4.dll".
    static bool looksRandomlyNamed(const std::string& nameNoExtLower) {
        if (nameNoExtLower.size() < 6 || nameNoExtLower.size() > 20) return false;
        int hexCount = 0, digitCount = 0;
        for (char c : nameNoExtLower) {
            if (std::isxdigit((unsigned char)c)) hexCount++;
            if (std::isdigit((unsigned char)c)) digitCount++;
        }
        // Mostly hex characters AND has at least a couple digits -- plain
        // words like "opengl32" won't trip this since it fails the ratio.
        double hexRatio = (double)hexCount / (double)nameNoExtLower.size();
        return hexRatio > 0.85 && digitCount >= 3;
    }

    struct RawModule {
        std::string name;
        std::string path;
    };

    static std::vector<RawModule> enumerateModules(DWORD pid) {
        std::vector<RawModule> modules;
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (snap == INVALID_HANDLE_VALUE) return modules;

        MODULEENTRY32W me{};
        me.dwSize = sizeof(me);
        if (Module32FirstW(snap, &me)) {
            do {
                auto wToA = [](const wchar_t* w) -> std::string {
                    int len = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
                    std::string s(len > 0 ? len - 1 : 0, '\0');
                    if (len > 0) WideCharToMultiByte(CP_UTF8, 0, w, -1, s.data(), len, nullptr, nullptr);
                    return s;
                };
                modules.push_back({ wToA(me.szModule), wToA(me.szExePath) });
            } while (Module32NextW(snap, &me));
        }
        CloseHandle(snap);
        return modules;
    }

    static std::vector<ModuleFinding> scanProcessModules(DWORD pid) {
        std::vector<ModuleFinding> findings;
        auto modules = enumerateModules(pid);

        for (const auto& m : modules) {
            std::string nameLower = toLowerA(m.name);
            std::string pathLower = toLowerA(m.path);
            std::string nameNoExt = nameLower;
            auto dot = nameNoExt.rfind(".dll");
            if (dot != std::string::npos) nameNoExt = nameNoExt.substr(0, dot);

            bool trusted = isTrustedLocation(pathLower);
            bool tempDrop = isTempOrUserDrop(pathLower);

            std::string matchedFragment;
            for (const auto& frag : suspiciousNameFragments) {
                if (nameLower.find(frag) != std::string::npos) { matchedFragment = frag; break; }
            }

            if (!matchedFragment.empty()) {
                findings.push_back({ Severity::Danger, m.name, m.path,
                    "Module name contains suspicious keyword \"" + matchedFragment + "\"" });
                continue;
            }

            if (tempDrop) {
                findings.push_back({ Severity::Danger, m.name, m.path,
                    "Loaded from a user-writable/temp location, not a standard install path" });
                continue;
            }

            if (looksRandomlyNamed(nameNoExt)) {
                findings.push_back({ Severity::Warning, m.name, m.path,
                    "Randomized-looking filename, consistent with injector payload naming" });
                continue;
            }

            if (!trusted) {
                findings.push_back({ Severity::Warning, m.name, m.path,
                    "Loaded from a non-standard location outside the JRE/system directories" });
            }
        }
        return findings;
    }

} // namespace modulescan
