#pragma once
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <string>
#include <vector>
#include <set>
#include <fstream>
#include <algorithm>
#include <cctype>

#include "Console.h"
#include "Util.h"

// =====================================================================
// Executable-level signatures for the "198macros"-family macro tool,
// derived from static analysis of a captured sample:
//
//   - The sample leaks its own build path via an embedded PDB string:
//     "...\Macros\x64\Release\macros-unprotected.pdb" -- the project is
//     literally called "Macros", built unprotected and then run through
//     a packer/virtualizer (VMProtect-style .vlizer/.vm_sec sections),
//     but this string sits outside the virtualized region and survives
//     in the packed binary.
//   - RTTI leftover for a C++ class literally named "Macro"
//     (mangled: ".?AVMacro@@").
//   - It phones home to a HWID-keyed license server (literal
//     "/hwidLogin" string, plus a statically linked libcurl + full
//     WinSock stack).
//   - Behaviorally, it imports both SetWindowsHookExW (global input
//     hook, for keybind listening) AND SendInput (synthetic mouse/
//     keyboard events, for the actual macro playback) from USER32.dll.
//     That specific combination is unusual for anything that isn't a
//     macro tool or input injector -- legitimate games/launchers read
//     input, they don't synthesize it system-wide.
//
// Both checks below work directly off the on-disk .exe, so renaming the
// process (which defeats ProcessScan.h's name-based match) doesn't help:
// the embedded strings and import table travel with the file.
// =====================================================================
namespace macrosig {

    using Severity = util::Severity;
    using Finding = util::Finding;
    using util::toLowerA;
    using util::wideToUtf8;

    // ---- shared file I/O -------------------------------------------------
    static bool readFileBytes(const std::wstring& path, std::vector<uint8_t>& out) {
        std::ifstream f(path, std::ios::binary);
        if (!f.is_open()) return false;
        f.seekg(0, std::ios::end);
        std::streamoff size = f.tellg();
        if (size <= 0) return false;
        f.seekg(0, std::ios::beg);
        out.resize((size_t)size);
        f.read(reinterpret_cast<char*>(out.data()), size);
        return true;
    }

    static bool bytesContain(const std::vector<uint8_t>& haystack, const std::string& needle) {
        if (needle.empty() || haystack.size() < needle.size()) return false;
        auto it = std::search(haystack.begin(), haystack.end(), needle.begin(), needle.end());
        return it != haystack.end();
    }

    // ---- #2: known static strings from the leaked build ------------------
    // Kept as an exact, fairly long literal match (not a short/generic
    // fragment) specifically so this doesn't false-positive on unrelated
    // binaries -- these strings are unique to this developer's build.
    static const std::vector<std::string> knownStaticStrings = {
        "macros-unprotected.pdb",
        ".?AVMacro@@",
        "/hwidLogin",
    };

    static std::vector<Finding> checkKnownStaticStrings(const std::wstring& exePath) {
        std::vector<Finding> out;
        std::vector<uint8_t> data;
        if (!readFileBytes(exePath, data)) {
            out.push_back({ Severity::Info, "Could not read file to check static strings." });
            return out;
        }

        for (const auto& needle : knownStaticStrings) {
            if (bytesContain(data, needle)) {
                out.push_back({ Severity::Danger,
                    "Matches known 198macros build signature: embedded string \"" + needle + "\"" });
            }
        }
        return out;
    }

    // ---- #3: manual PE import-table parse ---------------------------------
    // Minimal, read-only PE32+ import directory parser -- just enough to
    // list "DLL -> imported function name" pairs. No external PE library
    // dependency, consistent with the rest of this tool.
    struct ImportEntry {
        std::string dll;
        std::string func;
    };

    static bool rvaToOffset(const std::vector<uint8_t>& img, DWORD rva, DWORD& fileOffset) {
        auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(img.data());
        if (img.size() < sizeof(IMAGE_DOS_HEADER) || dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
        size_t ntOffset = (size_t)dos->e_lfanew;
        if (ntOffset + sizeof(IMAGE_NT_HEADERS64) > img.size()) return false;

        auto nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(img.data() + ntOffset);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return false;

        auto sectionBase = reinterpret_cast<const IMAGE_SECTION_HEADER*>(
            reinterpret_cast<const uint8_t*>(&nt->OptionalHeader) + nt->FileHeader.SizeOfOptionalHeader);

        for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
            const auto& sec = sectionBase[i];
            if (rva >= sec.VirtualAddress && rva < sec.VirtualAddress + sec.Misc.VirtualSize) {
                fileOffset = rva - sec.VirtualAddress + sec.PointerToRawData;
                return true;
            }
        }
        return false;
    }

    static std::vector<ImportEntry> parseImports(const std::wstring& exePath) {
        std::vector<ImportEntry> imports;
        std::vector<uint8_t> img;
        if (!readFileBytes(exePath, img)) return imports;
        if (img.size() < sizeof(IMAGE_DOS_HEADER)) return imports;

        auto dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(img.data());
        if (dos->e_magic != IMAGE_DOS_SIGNATURE) return imports;

        size_t ntOffset = (size_t)dos->e_lfanew;
        if (ntOffset + sizeof(IMAGE_NT_HEADERS64) > img.size()) return imports;

        auto nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(img.data() + ntOffset);
        if (nt->Signature != IMAGE_NT_SIGNATURE) return imports;
        if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return imports; // x64 only

        const auto& importDir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
        if (importDir.VirtualAddress == 0 || importDir.Size == 0) return imports;

        DWORD descOffset;
        if (!rvaToOffset(img, importDir.VirtualAddress, descOffset)) return imports;

        const IMAGE_IMPORT_DESCRIPTOR* desc =
            reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(img.data() + descOffset);

        while (descOffset + sizeof(IMAGE_IMPORT_DESCRIPTOR) <= img.size() && desc->Name != 0) {
            DWORD nameOff;
            if (!rvaToOffset(img, desc->Name, nameOff) || nameOff >= img.size()) break;
            std::string dllName(reinterpret_cast<const char*>(img.data() + nameOff));

            DWORD thunkRva = desc->OriginalFirstThunk ? desc->OriginalFirstThunk : desc->FirstThunk;
            DWORD thunkOff;
            if (rvaToOffset(img, thunkRva, thunkOff)) {
                const IMAGE_THUNK_DATA64* thunk =
                    reinterpret_cast<const IMAGE_THUNK_DATA64*>(img.data() + thunkOff);
                size_t curOff = thunkOff;
                while (curOff + sizeof(IMAGE_THUNK_DATA64) <= img.size() && thunk->u1.AddressOfData != 0) {
                    if (!IMAGE_SNAP_BY_ORDINAL64(thunk->u1.Ordinal)) {
                        DWORD ibnOff;
                        if (rvaToOffset(img, (DWORD)thunk->u1.AddressOfData, ibnOff) &&
                            ibnOff + 2 < img.size()) {
                            const char* funcName = reinterpret_cast<const char*>(img.data() + ibnOff + 2);
                            imports.push_back({ dllName, std::string(funcName) });
                        }
                    }
                    curOff += sizeof(IMAGE_THUNK_DATA64);
                    thunk++;
                }
            }

            descOffset += sizeof(IMAGE_IMPORT_DESCRIPTOR);
            desc = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(img.data() + descOffset);
        }

        return imports;
    }

    // Flags the specific SetWindowsHookExW + SendInput combination from
    // USER32.dll. Either import alone is common (lots of legitimate
    // software installs a hook, or synthesizes input for accessibility/
    // automation reasons) -- it's having *both* in the same binary that's
    // the macro-tool tell.
    static std::vector<Finding> checkHookSendInputCombo(const std::wstring& exePath) {
        std::vector<Finding> out;
        auto imports = parseImports(exePath);
        if (imports.empty()) {
            out.push_back({ Severity::Info, "Could not parse import table (not x64 PE, or unreadable)." });
            return out;
        }

        bool hasHook = false, hasSendInput = false, hasAsyncKeyState = false;
        for (const auto& imp : imports) {
            std::string dllLower = toLowerA(imp.dll);
            if (dllLower.find("user32") == std::string::npos) continue;
            if (imp.func == "SetWindowsHookExW" || imp.func == "SetWindowsHookExA") hasHook = true;
            if (imp.func == "SendInput") hasSendInput = true;
            if (imp.func == "GetAsyncKeyState") hasAsyncKeyState = true;
        }

        if (hasHook && hasSendInput) {
            out.push_back({ Severity::Danger,
                "Imports both SetWindowsHookExW (global input hook) and SendInput (synthetic input) -- "
                "characteristic of a macro/auto-clicker tool, not a normal application" });
        } else if (hasSendInput && hasAsyncKeyState) {
            out.push_back({ Severity::Warning,
                "Imports SendInput alongside GetAsyncKeyState (key-state polling) -- consistent with "
                "keybind-triggered input automation, worth a closer look" });
        }
        return out;
    }

    // Convenience wrapper: full signature check for one executable path.
    static std::vector<Finding> checkExecutable(const std::wstring& exePath) {
        std::vector<Finding> out;
        auto stringHits = checkKnownStaticStrings(exePath);
        auto importHits = checkHookSendInputCombo(exePath);
        out.insert(out.end(), stringHits.begin(), stringHits.end());
        out.insert(out.end(), importHits.begin(), importHits.end());
        return out;
    }

    // ---- process-wide sweep -----------------------------------------------
    // Runs the signature checks above against every running process' exe
    // on disk, not just ones already matching a name/window-title keyword --
    // that's the whole point, since renaming the exe is the first thing
    // someone does to dodge ProcessScan.h's keyword match. Trusted system
    // directories are skipped purely for scan speed (thousands of Windows
    // binaries would otherwise be read+parsed on every run for no benefit).
    struct ProcessMatch {
        DWORD pid;
        std::string processName;
        std::string exePath;
        Finding finding;
    };

    static bool isTrustedSystemPath(const std::string& lowerPath) {
        static const std::vector<std::string> trusted = {
            "\\windows\\system32\\", "\\windows\\syswow64\\", "\\windows\\winsxs\\",
            "\\program files\\windowsapps\\",
        };
        for (const auto& t : trusted) {
            if (lowerPath.find(t) != std::string::npos) return true;
        }
        return false;
    }

    static std::vector<ProcessMatch> scanAllProcessesForSignatures() {
        std::vector<ProcessMatch> matches;
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) return matches;

        PROCESSENTRY32 entry{};
        entry.dwSize = sizeof(entry);
        if (Process32First(snap, &entry)) {
            do {
                HANDLE proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, entry.th32ProcessID);
                if (!proc) continue;

                wchar_t pathBuf[MAX_PATH];
                DWORD pathLen = MAX_PATH;
                bool gotPath = QueryFullProcessImageNameW(proc, 0, pathBuf, &pathLen);
                CloseHandle(proc);
                if (!gotPath) continue;

                std::wstring wpath(pathBuf, pathLen);
                std::string pathUtf8 = wideToUtf8(wpath);
                if (isTrustedSystemPath(toLowerA(pathUtf8))) continue;

                auto findings = checkExecutable(wpath);
                for (const auto& f : findings) {
                    if (f.severity == Severity::Info) continue; // skip "couldn't parse" noise here
                    matches.push_back({ entry.th32ProcessID, entry.szExeFile, pathUtf8, f });
                }
            } while (Process32Next(snap, &entry));
        }
        CloseHandle(snap);
        return matches;
    }

} // namespace macrosig
