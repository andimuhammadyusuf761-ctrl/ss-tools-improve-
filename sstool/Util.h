#pragma once
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <string>
#include <vector>
#include <algorithm>
#include <cctype>

// =====================================================================
// Shared helpers used across every scan module.
//
// Previously each of ModuleScan.h / SystemForensics.h / MacroSignature.h
// carried its own private copy of toLowerA()/wideToUtf8() and its own
// Severity enum. That worked but meant four near-identical definitions
// to keep in sync, and no scan module's findings could be printed with
// a single shared renderer in Console.h. This header is the one place
// those now live.
// =====================================================================
namespace util {

    // ---- Severity ----------------------------------------------------
    // Used by every scan module's Finding struct so main.cpp can render
    // results through a single con::finding() call instead of each scan
    // function hand-rolling its own "if Danger -> bad() else if Warning
    // -> warn() else info()" chain.
    enum class Severity { Info, Warning, Danger };

    struct Finding {
        Severity severity;
        std::string text;
    };

    // ---- string helpers ------------------------------------------------
    inline std::string toLowerA(std::string s) {
        std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return (char)std::tolower(c); });
        return s;
    }

    inline std::string wideToUtf8(const std::wstring& w) {
        if (w.empty()) return {};
        int len = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
        std::string s(len > 0 ? len - 1 : 0, '\0');
        if (len > 0) WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, s.data(), len, nullptr, nullptr);
        return s;
    }

    inline bool containsAny(const std::string& haystackLower, const std::vector<std::string>& needlesLower) {
        for (const auto& n : needlesLower) {
            if (haystackLower.find(n) != std::string::npos) return true;
        }
        return false;
    }

    // Is the current process running elevated (as Administrator)?
    // Several scans (Prefetch, other users' scheduled tasks, full memory
    // read access) are meaningfully weaker without this, so the banner
    // surfaces it up front rather than each scan silently returning less.
    inline bool isRunningElevated() {
        BOOL isElevated = FALSE;
        HANDLE token = nullptr;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token)) {
            TOKEN_ELEVATION elevation{};
            DWORD size = sizeof(elevation);
            if (GetTokenInformation(token, TokenElevation, &elevation, sizeof(elevation), &size)) {
                isElevated = elevation.TokenIsElevated;
            }
            CloseHandle(token);
        }
        return isElevated == TRUE;
    }

} // namespace util
