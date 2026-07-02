#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#include <string>
#include <vector>
#include <iostream>
#include <algorithm>

// Finds every running javaw.exe / java.exe process, and lets the operator
// pick one instead of typing a raw PID blind. Replaces the plain
// `std::cin >> pid` in main.cpp's runMemoryScan().
//
// Why: a bare PID prompt has two failure modes that both look like a clean
// scan afterwards -
//   1. Typo / stale PID -> OpenProcess fails -> "Invalid Process." Fine,
//      loud failure, no harm.
//   2. Typo that happens to match a DIFFERENT running process -> OpenProcess
//      SUCCEEDS against the wrong target -> pattern_scan finds 0 traces ->
//      operator sees "Found 0 traces" and reads that as "this player is
//      clean," when actually the real javaw.exe was never scanned at all.
// (2) is the dangerous one because it's silent. This resolver removes it by
// only ever handing back a PID that was independently confirmed, via
// GetModuleBaseNameW, to belong to an actual java executable.

struct JavaProcCandidate {
    DWORD pid = 0;
    std::wstring exeName;   // "javaw.exe" or "java.exe"
    std::wstring windowTitle; // best-effort, may be empty
};

// best-effort: grab a visible window title owned by this pid, so the
// operator has something more recognizable than a bare number to go on
// (Minecraft's window title is usually the profile/version string).
static std::wstring findWindowTitleForPid(DWORD pid) {
    struct Ctx { DWORD pid; std::wstring title; } ctx{ pid, L"" };

    EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
        auto* c = reinterpret_cast<Ctx*>(lParam);
        DWORD windowPid = 0;
        GetWindowThreadProcessId(hwnd, &windowPid);
        if (windowPid != c->pid || !IsWindowVisible(hwnd)) return TRUE;

        wchar_t buf[256];
        int len = GetWindowTextW(hwnd, buf, 256);
        if (len > 0) {
            c->title.assign(buf, len);
            return FALSE; // found one, stop enumerating
        }
        return TRUE;
    }, reinterpret_cast<LPARAM>(&ctx));

    return ctx.title;
}

static std::vector<JavaProcCandidate> findJavaProcesses() {
    std::vector<JavaProcCandidate> found;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return found;

    PROCESSENTRY32W entry{};
    entry.dwSize = sizeof(PROCESSENTRY32W);

    if (Process32FirstW(snap, &entry)) {
        do {
            std::wstring exe = entry.szExeFile;
            std::wstring lower = exe;
            std::transform(lower.begin(), lower.end(), lower.begin(), ::towlower);

            if (lower == L"javaw.exe" || lower == L"java.exe") {
                JavaProcCandidate c;
                c.pid = entry.th32ProcessID;
                c.exeName = exe;
                c.windowTitle = findWindowTitleForPid(c.pid);
                found.push_back(std::move(c));
            }
        } while (Process32NextW(snap, &entry));
    }
    CloseHandle(snap);
    return found;
}

// Confirms a HANDLE genuinely points at a java/javaw executable before
// pattern_scan ever touches it. This is the check that closes failure mode
// (2) above: even if the caller got the PID from manual entry rather than
// the picker below, this still catches "right number, wrong process."
static bool verifyIsJavaProcess(HANDLE hProcess) {
    wchar_t path[MAX_PATH];
    DWORD len = GetModuleBaseNameW(hProcess, nullptr, path, MAX_PATH);
    if (len == 0) return false;

    std::wstring name(path, len);
    std::transform(name.begin(), name.end(), name.begin(), ::towlower);
    return name == L"javaw.exe" || name == L"java.exe";
}

// Interactive picker: lists every javaw.exe/java.exe currently running,
// tags each with its window title when one is found, and lets the operator
// choose by list index instead of transcribing a PID by hand. Falls back to
// manual PID entry (still verified) if nothing is found or the operator
// wants a specific PID not in the list.
//
// Returns an OpenProcess handle (caller must CloseHandle), or nullptr.
static HANDLE resolveJavawTarget() {
    auto candidates = findJavaProcesses();

    if (candidates.empty()) {
        std::wcout << L"No javaw.exe / java.exe processes found running.\n";
        std::wcout << L"Enter PID manually (0 to cancel): ";
        DWORD pid;
        std::cin >> pid;
        if (pid == 0) return nullptr;

        HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
        if (!h) {
            std::wcout << L"Invalid Process.\n";
            return nullptr;
        }
        if (!verifyIsJavaProcess(h)) {
            std::wcout << L"PID " << pid << L" exists but is not javaw.exe/java.exe. Refusing to scan.\n";
            CloseHandle(h);
            return nullptr;
        }
        return h;
    }

    std::wcout << L"\nJava processes found:\n";
    for (size_t i = 0; i < candidates.size(); i++) {
        std::wcout << L"  " << (i + 1) << L". PID " << candidates[i].pid
                    << L"  [" << candidates[i].exeName << L"]";
        if (!candidates[i].windowTitle.empty())
            std::wcout << L"  \"" << candidates[i].windowTitle << L"\"";
        std::wcout << L"\n";
    }
    std::wcout << L"  " << (candidates.size() + 1) << L". Enter a PID manually instead\n";
    std::wcout << L"Select: ";

    size_t choice;
    std::cin >> choice;

    DWORD pid = 0;
    if (choice >= 1 && choice <= candidates.size()) {
        pid = candidates[choice - 1].pid;
    } else if (choice == candidates.size() + 1) {
        std::wcout << L"Minecraft PID: ";
        std::cin >> pid;
    } else {
        std::wcout << L"Invalid selection.\n";
        return nullptr;
    }

    HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!h) {
        std::wcout << L"Invalid Process.\n";
        return nullptr;
    }
    if (!verifyIsJavaProcess(h)) {
        std::wcout << L"PID " << pid << L" exists but is not javaw.exe/java.exe. Refusing to scan.\n";
        CloseHandle(h);
        return nullptr;
    }
    return h;
}
