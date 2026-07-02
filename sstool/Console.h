#pragma once
#include <Windows.h>
#include <iostream>
#include <string>

// Minimal colored-output helper so scan results are easier to scan visually
// (plain white walls of text made it easy to miss a single "[!]" line in a
// report with hundreds of entries). Falls back gracefully -- if the console
// handle is invalid (e.g. redirected to a file) colors are just skipped.
namespace con {

    enum class Color {
        Default = -1,
        Gray = FOREGROUND_INTENSITY,
        Red = FOREGROUND_RED | FOREGROUND_INTENSITY,
        Green = FOREGROUND_GREEN | FOREGROUND_INTENSITY,
        Yellow = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY,
        Cyan = FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY,
        White = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY,
    };

    inline void set(Color c) {
        static HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
        if (h == INVALID_HANDLE_VALUE || c == Color::Default) return;
        SetConsoleTextAttribute(h, static_cast<WORD>(c));
    }

    inline void reset() { set(Color::White); }

    inline void line(const std::string& text, Color c) {
        set(c);
        std::cout << text << "\n";
        reset();
    }

    inline void header(const std::string& text) {
        std::cout << "\n";
        line(std::string(text.size() + 4, '='), Color::Cyan);
        line("  " + text, Color::Cyan);
        line(std::string(text.size() + 4, '='), Color::Cyan);
    }

} // namespace con
