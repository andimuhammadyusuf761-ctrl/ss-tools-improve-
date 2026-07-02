#pragma once
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <iostream>
#include <string>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <thread>
#include <algorithm>

// ============================================================
//  Console.h  --  Rich console UI helpers
//  Provides: colors, banners, step progress, spinners, dividers
// ============================================================
namespace con {

    // ---- Color palette -----------------------------------------
    enum class Color {
        Default  = -1,
        Gray     = FOREGROUND_INTENSITY,
        DarkGray = 8,
        Red      = FOREGROUND_RED | FOREGROUND_INTENSITY,
        Green    = FOREGROUND_GREEN | FOREGROUND_INTENSITY,
        Yellow   = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_INTENSITY,
        Cyan     = FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY,
        Magenta  = FOREGROUND_RED | FOREGROUND_BLUE | FOREGROUND_INTENSITY,
        Blue     = FOREGROUND_BLUE | FOREGROUND_INTENSITY,
        White    = FOREGROUND_RED | FOREGROUND_GREEN | FOREGROUND_BLUE | FOREGROUND_INTENSITY,
    };

    inline HANDLE hStdOut() {
        static HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
        return h;
    }

    inline void set(Color c) {
        if (hStdOut() == INVALID_HANDLE_VALUE || c == Color::Default) return;
        SetConsoleTextAttribute(hStdOut(), static_cast<WORD>(c));
    }

    inline void reset() { set(Color::White); }

    inline constexpr int UiWidth = 68;
    inline constexpr const char* Credit = "ss tools by nosaka&aruel";

    // Print text in a color, then reset
    inline void print(const std::string& text, Color c, bool newline = false) {
        set(c);
        std::cout << text;
        if (newline) std::cout << "\n";
        reset();
    }

    inline void line(const std::string& text, Color c) {
        print(text, c, true);
    }

    // ---- UI Elements -------------------------------------------

    inline void divider(char ch = '-', int width = UiWidth, Color c = Color::DarkGray);

    inline void titleCard(const std::string& title, const std::string& subtitle) {
        divider('=', UiWidth, Color::Cyan);
        set(Color::Cyan);
        std::cout << "  " << title << "\n";
        set(Color::Gray);
        std::cout << "  " << subtitle << "\n";
        set(Color::Magenta);
        std::cout << "  " << Credit << "\n";
        divider('=', UiWidth, Color::Cyan);
        reset();
    }

    inline void menuHeader(const std::string& text) {
        divider('=', UiWidth, Color::Cyan);
        set(Color::Cyan);
        std::cout << "  " << text << "\n";
        divider('=', UiWidth, Color::Cyan);
        reset();
    }

    // Full-width horizontal divider
    inline void divider(char ch, int width, Color c) {
        set(c);
        std::cout << std::string(width, ch) << "\n";
        reset();
    }

    // Section header with thick border
    inline void header(const std::string& text, Color c = Color::Cyan) {
        std::cout << "\n";
        divider('=', UiWidth, c);
        set(c);
        // Center the text in the current UI width.
        int pad = (UiWidth - 2 - (int)text.size()) / 2;
        if (pad < 0) pad = 0;
        std::cout << "  " << std::string(pad, ' ') << text << "\n";
        divider('=', UiWidth, c);
        reset();
    }

    // Sub-section header with thin border
    inline void subheader(const std::string& text, Color c = Color::Cyan) {
        std::cout << "\n";
        set(c);
        std::cout << "  >> " << text << "\n";
        divider('-', UiWidth, c);
        reset();
    }

    // Labeled box (like a "tip" or "warning" callout)
    inline void box(const std::string& label, const std::string& text, Color c = Color::Yellow) {
        set(c);
        std::cout << "  [ " << label << " ] ";
        reset();
        std::cout << text << "\n";
    }

    // Step indicator: "  Step 2/4  Scan Memory"
    inline void step(int current, int total, const std::string& desc) {
        std::cout << "\n";
        divider('-', UiWidth, Color::DarkGray);
        set(Color::Cyan);
        std::cout << "  Step " << current << "/" << total << "  ";
        set(Color::White);
        std::cout << desc << "\n";
        divider('-', UiWidth, Color::DarkGray);
        reset();
    }

    // Status prefix icons
    inline void ok(const std::string& text)   { set(Color::Green);  std::cout << "  [+] "; reset(); std::cout << text << "\n"; }
    inline void warn(const std::string& text) { set(Color::Yellow); std::cout << "  [!] "; reset(); std::cout << text << "\n"; }
    inline void bad(const std::string& text)  { set(Color::Red);    std::cout << "  [x] "; reset(); std::cout << text << "\n"; }
    inline void info(const std::string& text) { set(Color::Cyan);   std::cout << "  [*] "; reset(); std::cout << text << "\n"; }
    inline void dim(const std::string& text)  { set(Color::Gray);   std::cout << "      " << text; reset(); std::cout << "\n"; }

    // Numbered menu item
    inline void menuItem(int n, const std::string& text, Color c = Color::White) {
        set(Color::Cyan);
        std::cout << "    [" << n << "] ";
        set(c);
        std::cout << text << "\n";
        reset();
    }

    // Prompt line: "  > Enter choice: "
    inline void prompt(const std::string& text) {
        set(Color::Yellow);
        std::cout << "\n  > " << text;
        reset();
        std::cout << " ";
    }

    // Inline spinner for long operations (call repeatedly, clears itself)
    inline void spinnerTick(const std::string& msg) {
        static int frame = 0;
        static const char* frames[] = { "|", "/", "-", "\\" };
        set(Color::Cyan);
        std::cout << "\r  " << frames[frame++ % 4] << "  ";
        reset();
        std::cout << msg << "   " << std::flush;
    }

    inline void spinnerClear() {
        std::cout << "\r" << std::string(70, ' ') << "\r" << std::flush;
    }

    // Progress bar: "  [=========>    ] 70%"
    inline void progressBar(int done, int total, int width = 40) {
        if (total == 0) return;
        done = std::clamp(done, 0, total);
        width = std::max(width, 1);
        int filled = std::clamp((done * width) / total, 0, width);
        int pct = std::clamp((done * 100) / total, 0, 100);

        set(Color::Cyan);
        std::cout << "\r  [";
        set(Color::Green);
        std::cout << std::string(filled, '=');
        if (filled < width) {
            std::cout << ">";
            set(Color::DarkGray);
            std::cout << std::string(std::max(width - filled - 1, 0), ' ');
        }
        set(Color::Cyan);
        std::cout << "] ";
        set(Color::White);
        std::cout << std::setw(3) << pct << "% (" << done << "/" << total << ")   " << std::flush;
        reset();
    }

    // Final summary banner
    inline void resultSummary(bool clean, int hits, const std::string& context) {
        std::cout << "\n";
        if (clean) {
            divider('=', UiWidth, Color::Green);
            set(Color::Green);
            std::cout << "  RESULT:  CLEAN -- No " << context << " found.\n";
            divider('=', UiWidth, Color::Green);
        } else {
            divider('=', UiWidth, Color::Red);
            set(Color::Red);
            std::cout << "  RESULT:  FLAGGED -- " << hits << " " << context << " detected.\n";
            divider('=', UiWidth, Color::Red);
        }
        reset();
    }

} // namespace con
