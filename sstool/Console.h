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

    // Full-width horizontal divider
    inline void divider(char ch = '-', int width = 60, Color c = Color::DarkGray) {
        set(c);
        std::cout << std::string(width, ch) << "\n";
        reset();
    }

    // Section header with thick border
    inline void header(const std::string& text, Color c = Color::Cyan) {
        std::cout << "\n";
        divider('=', 60, c);
        set(c);
        // Center the text in 60 chars
        int pad = (58 - (int)text.size()) / 2;
        if (pad < 0) pad = 0;
        std::cout << "  " << std::string(pad, ' ') << text << "\n";
        divider('=', 60, c);
        reset();
    }

    // Sub-section header with thin border
    inline void subheader(const std::string& text, Color c = Color::Cyan) {
        std::cout << "\n";
        set(c);
        std::cout << "  >> " << text << "\n";
        divider('-', 60, c);
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
        divider('-', 60, Color::DarkGray);
        set(Color::Cyan);
        std::cout << "  Step " << current << "/" << total << "  ";
        set(Color::White);
        std::cout << desc << "\n";
        divider('-', 60, Color::DarkGray);
        reset();
    }

    // Status prefix icons
    inline void ok(const std::string& text)   { set(Color::Green);  std::cout << "  [+] "; reset(); std::cout << text << "\n"; }
    inline void warn(const std::string& text) { set(Color::Yellow); std::cout << "  [!] "; reset(); std::cout << text << "\n"; }
    inline void bad(const std::string& text)  { set(Color::Red);    std::cout << "  [x] "; reset(); std::cout << text << "\n"; }
    inline void info(const std::string& text) { set(Color::Cyan);   std::cout << "  [*] "; reset(); std::cout << text << "\n"; }
    inline void dim(const std::string& text)  { set(Color::Gray);   std::cout << "      " << text; reset(); std::cout << "\n"; }

    // Unified finding renderer: every scan module (ModuleScan, SystemForensics,
    // MacroSignature, ...) now shares util::Severity, so results can be printed
    // through one call instead of each scan function hand-rolling its own
    // "if Danger -> bad() else if Warning -> warn() else info()" chain.
    template <typename SeverityT>
    inline void finding(SeverityT severity, const std::string& text) {
        switch (static_cast<int>(severity)) {
            case 2: bad(text);  break; // Danger
            case 1: warn(text); break; // Warning
            default: info(text); break; // Info
        }
    }

    // A short colored tag, e.g. "[DANGER]" / "[WARN]" / "[INFO]" -- used
    // when a finding needs to sit inline with other context on the same
    // line rather than owning the whole line via finding()/bad()/warn().
    template <typename SeverityT>
    inline std::string badge(SeverityT severity) {
        switch (static_cast<int>(severity)) {
            case 2: return "[DANGER]";
            case 1: return "[WARN]";
            default: return "[INFO]";
        }
    }

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
        int filled = (done * width) / total;
        int pct = (done * 100) / total;

        set(Color::Cyan);
        std::cout << "\r  [";
        set(Color::Green);
        std::cout << std::string(filled, '=');
        if (filled < width) {
            std::cout << ">";
            set(Color::DarkGray);
            std::cout << std::string(width - filled - 1, ' ');
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
            divider('=', 60, Color::Green);
            set(Color::Green);
            std::cout << "  RESULT:  CLEAN -- No " << context << " found.\n";
            divider('=', 60, Color::Green);
        } else {
            divider('=', 60, Color::Red);
            set(Color::Red);
            std::cout << "  RESULT:  FLAGGED -- " << hits << " " << context << " detected.\n";
            divider('=', 60, Color::Red);
        }
        reset();
    }

    // ---- Boxed banner --------------------------------------------------
    // Draws a bordered box of fixed inner width, one centered line per
    // entry in `lines`. Used for the startup banner; kept separate from
    // header() since the banner needs multiple centered lines instead of
    // header()'s single title line.
    inline void box(const std::vector<std::string>& lines, int width = 60, Color c = Color::Cyan) {
        std::cout << "\n";
        set(c);
        std::cout << "  +" << std::string(width - 2, '-') << "+\n";
        for (const auto& line : lines) {
            int pad = (width - 2 - (int)line.size());
            int left = pad / 2;
            int right = pad - left;
            if (left < 0) left = 0;
            if (right < 0) right = 0;
            std::cout << "  |" << std::string(left, ' ') << line << std::string(right, ' ') << "|\n";
        }
        std::cout << "  +" << std::string(width - 2, '-') << "+\n";
        reset();
    }

    // "  Key ......... value" -- aligned status line, used for the
    // banner's "Admin: yes/no" / "Scans: read-only" style status rows.
    inline void statusLine(const std::string& key, const std::string& value, Color valueColor = Color::White, int keyWidth = 18) {
        set(Color::Gray);
        std::cout << "    " << key;
        int pad = keyWidth - (int)key.size();
        if (pad > 0) std::cout << std::string(pad, '.');
        std::cout << " ";
        set(valueColor);
        std::cout << value << "\n";
        reset();
    }

} // namespace con
