#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include "Console.h"
#include "PatternScan.h"
#include "ProcessScan.h"
#include "ModsScan.h"
#include "JvmScan.h"
#include "JavaProcessResolve.h"
#include <filesystem>
#include <cstdlib>
#include <string>
#include <iostream>

// =====================================================================
// Pattern lists
// =====================================================================

std::vector<std::string_view> novaPatterns = {
    "aHR0cDovL2FwaS5ub3ZhY2xpZW50LmxvbC93ZWJob29rLnR4dA==",
    "novaclient",
    "addFri",
    "antiAttack",
    "/assets/font/font.ttf",
    "Lithium is not initialized! Skipping event: ",
    "Error in hash"
};

std::vector<std::string_view> crystalPatterns = {
    "net.crystalpvphelper",
    "crystalpvphelper",
    "net.crystalpvphelper.module.ModuleManager",
    "net.crystalpvphelper.module.modules.combat.AnchorMacro",
    "net.crystalpvphelper.module.modules.combat.TriggerBot",
    "net.crystalpvphelper.module.modules.combat.AutoMace",
    "net.crystalpvphelper.module.modules.combat.WTap",
    "net.crystalpvphelper.module.modules.combat.Hitboxes",
    "net.crystalpvphelper.module.modules.combat.AimAssist",
    "net.crystalpvphelper.module.modules.combat.AutoInventoryTotem",
    "net.crystalpvphelper.module.modules.combat.AutoStun",
    "--- CrystalPvPHelper Commands ---",
    ".bind <module> <key> - Bind a module to a key",
    "Automated anchor explosion macro for Crystal PvP",
    "Automated Mace combat with density, breach, and crit mechanics",
    "Automatically breaks shields with an axe",
    "Expands player hitboxes and applies fake rotations",
    "Automatically attacks entities in crosshair",
    "Automatically resets sprint on hit for extra knockback"
};

std::vector<std::string_view> skatePatterns = {
    "hack.skate.client",
    "noqwdclient",
    "hack.skate.client.features.impl.combat.AnchorMacro",
    "hack.skate.client.features.impl.combat.AutoCrystal",
    "hack.skate.client.features.impl.combat.AutoCrystalV2",
    "hack.skate.client.features.impl.combat.AutoDoubleHand",
    "hack.skate.client.features.impl.combat.TriggerBot",
    "hack.skate.client.features.impl.combat.CrystalOptimizer",
    "hack.skate.client.features.impl.combat.BreachSwap",
    "hack.skate.client.features.impl.combat.AimAssistV2",
    "hack.skate.client.features.impl.client.SelfDestruct",
    "hack.skate.client.features.impl.client.ClickGUI",
    "Advanced smooth aim with movement prediction and AC bypass",
    "Bypasses stray's Anti-TriggerBot",
    "Stray Bypass"
};

std::vector<std::string_view> argonPatterns = {
    "dev.lvstrng.argon",
    "dev.lvstrng.argon.mixin",
    "dev.lvstrng.argon.module.ModuleManager",
    "dev.lvstrng.argon.module.modules.combat.AnchorMacro",
    "dev.lvstrng.argon.module.modules.combat.TriggerBotV2",
    "dev.lvstrng.argon.module.modules.combat.ShieldDisabler",
    "dev.lvstrng.argon.module.modules.combat.MaceStun",
    "dev.lvstrng.argon.module.modules.combat.AutoHitCrystal",
    "dev.lvstrng.argon.module.modules.combat.HoverTotem",
    "dev.lvstrng.argon.module.modules.client.SelfDestruct",
    "dev.lvstrng.argon.utils.EncryptedString"
};

std::vector<std::string_view> universalPatterns = {
    "Auto Crystal",
    "Self Destruct",
    "Auto Anchor",
    "Auto Loot Yeeter",
    "CwCrystal.class",
    "ADH.class",
    "ModuleManager.class",
    "AnchorMacro.class",
    "TriggerBot.class",
    "AutoDoubleHand.class",
    "AutoInventoryTotem.class",
    "AutoCrystal.class",
    "SelfDestruct.class",
    "ClickGUI.class"
};

// =====================================================================
// Helpers
// =====================================================================

static void waitEnter() {
    con::dim("Press Enter to continue...");
    std::cin.ignore(10000, '\n');
    std::cin.get();
}

// Read a single integer, return -1 on bad input
static int readInt() {
    int v = -1;
    if (!(std::cin >> v)) {
        std::cin.clear();
        std::cin.ignore(10000, '\n');
        return -1;
    }
    return v;
}

// =====================================================================
// Step-by-step: Memory Scan
// =====================================================================
void runMemoryScan() {
    con::header("MEMORY SCAN  --  Live Cheat Detection");

    // --- Step 1: Pick process ---
    con::step(1, 3, "Select Minecraft Process");
    con::dim("Looking for running java/javaw processes...\n");

    HANDLE handle = resolveJavawTarget();
    if (!handle) {
        con::bad("No process selected. Returning to main menu.");
        waitEnter();
        return;
    }

    // --- Step 2: Pick client ---
    con::step(2, 3, "Select Cheat Client to Scan For");
    con::dim("Choose a specific client for a faster, lower-noise scan,");
    con::dim("or scan All to cast the widest net.\n");

    struct ClientEntry { const char* name; const char* note; };
    static const ClientEntry clients[] = {
        { "Nova Client",                       "memory strings + encoded webhook URL"    },
        { "CrystalPvPHelper",                  "full package tree + command strings"     },
        { "Noqwd / Skate Client (AutoCrystal)","full package tree + AutoCrystal modules" },
        { "Argon",                             "encrypted strings, disguised mod id"     },
        { "All  (widest coverage)",            "all of the above + universal class names"},
    };

    for (int i = 0; i < 5; i++) {
        con::set(con::Color::Cyan);
        std::cout << "    [" << (i + 1) << "] ";
        con::set(con::Color::White);
        std::cout << clients[i].name;
        con::set(con::Color::Gray);
        std::cout << "  --  " << clients[i].note << "\n";
        con::reset();
    }

    con::prompt("Enter choice (1-5):");
    int option = readInt();

    std::vector<std::string_view> scannable;
    if      (option == 1) { scannable = novaPatterns; }
    else if (option == 2) { scannable = crystalPatterns; }
    else if (option == 3) { scannable = skatePatterns; }
    else if (option == 4) { scannable = argonPatterns; }
    else if (option == 5) {
        scannable.insert(scannable.end(), novaPatterns.begin(),    novaPatterns.end());
        scannable.insert(scannable.end(), crystalPatterns.begin(), crystalPatterns.end());
        scannable.insert(scannable.end(), skatePatterns.begin(),   skatePatterns.end());
        scannable.insert(scannable.end(), argonPatterns.begin(),   argonPatterns.end());
        scannable.insert(scannable.end(), universalPatterns.begin(),universalPatterns.end());
    } else {
        con::bad("Invalid choice. Returning to main menu.");
        CloseHandle(handle);
        waitEnter();
        return;
    }

    // --- Step 3: Scan ---
    con::step(3, 3, "Scanning Process Memory");
    con::info("Scanning " + std::to_string(scannable.size()) + " pattern(s) in both UTF-8 and UTF-16LE forms...");
    con::dim("(This may take a few seconds depending on how much RAM Minecraft is using)\n");

    auto results = pattern_scan(handle, scannable);
    CloseHandle(handle);

    // --- Results ---
    con::subheader("Scan Results");

    size_t utf16Hits = 0;
    size_t boundaryHits = 0;
    for (const auto& r : results) {
        if (r.wasUtf16)    utf16Hits++;
        if (r.wasBoundary) boundaryHits++;
    }

    if (!results.empty()) {
        for (const auto& r : results) {
            con::set(con::Color::Red);
            std::cout << "  [x] ";
            con::set(con::Color::White);
            std::cout << "\"" << r.pattern << "\"";
            con::set(con::Color::Gray);
            if (r.wasUtf16)    std::cout << "  [utf-16]";
            if (r.wasBoundary) std::cout << "  [boundary]";
            std::cout << "  @ 0x" << std::hex << std::uppercase << r.address << std::dec << "\n";
            con::reset();
        }
    }

    // Stat line
    std::cout << "\n";
    con::divider('-', 60);
    if (utf16Hits > 0) {
        con::info(std::to_string(utf16Hits) + " hit(s) only visible as UTF-16 Java strings (would be missed by a basic ASCII scan)");
    }
    if (boundaryHits > 0) {
        con::info(std::to_string(boundaryHits) + " hit(s) found straddling a memory region boundary");
    }

    con::resultSummary(results.empty(), (int)results.size(), "cheat client traces");
    waitEnter();
}

// =====================================================================
// Step-by-step: Mods Folder Scan
// =====================================================================
void runModsFolderScanMenu() {
    con::header("MODS FOLDER SCAN  --  Static JAR Analysis");

    // --- Step 1: Path ---
    con::step(1, 2, "Enter Mods Folder Path");

    wchar_t* userProfile = _wgetenv(L"USERPROFILE");
    std::filesystem::path defaultPath = userProfile
        ? std::filesystem::path(userProfile) / L"AppData" / L"Roaming" / L".minecraft" / L"mods"
        : std::filesystem::path();

    con::dim("What this scan checks:");
    con::dim("  - Cheat/macro class names and package paths inside each .jar");
    con::dim("  - Obfuscation heuristics (numeric, single-letter, fullwidth class names)");
    con::dim("  - Dangerous bytecode (Runtime.exec, HTTP exfil, HTTP download)");
    con::dim("  - Known cheat obfuscators (Skidfuscator, Paramorphism, etc.)");
    con::dim("  - Fake mod identity (jar claiming to be a legit mod but containing cheat code)");
    std::cout << "\n";

    if (!defaultPath.empty()) {
        con::info("Default path: " + defaultPath.string());
    }
    con::prompt("Paste mods folder path (or press Enter for default):");

    std::cin.ignore();
    std::string input;
    std::getline(std::cin, input);

    std::filesystem::path modsPath = input.empty() ? defaultPath : std::filesystem::path(input);
    if (modsPath.empty()) {
        con::bad("No path given and no default found. Returning.");
        waitEnter();
        return;
    }

    std::error_code ec;
    if (!std::filesystem::exists(modsPath, ec) || !std::filesystem::is_directory(modsPath, ec)) {
        con::bad("Path does not exist or is not a folder: " + modsPath.string());
        waitEnter();
        return;
    }

    // --- Step 2: Scan ---
    con::step(2, 2, "Analyzing .jar Files");

    std::vector<std::filesystem::path> jars;
    for (auto& entry : std::filesystem::directory_iterator(modsPath, ec)) {
        if (!entry.is_regular_file()) continue;
        std::string ext = entry.path().extension().string();
        std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
        if (ext == ".jar") jars.push_back(entry.path());
    }

    if (jars.empty()) {
        con::warn("No .jar files found in that folder.");
        waitEnter();
        return;
    }

    con::info("Found " + std::to_string(jars.size()) + " jar(s). Scanning...\n");

    int flaggedCount = 0;
    for (int i = 0; i < (int)jars.size(); i++) {
        con::progressBar(i, (int)jars.size());
        modscan::JarReport r = modscan::scanSingleJar(jars[i]);
        if (!r.findings.empty()) {
            flaggedCount++;
            std::cout << "\n";  // newline after progress bar before report
            modscan::printReport(r);
        }
    }
    con::progressBar((int)jars.size(), (int)jars.size());
    std::cout << "\n";

    con::resultSummary(flaggedCount == 0, flaggedCount,
        std::to_string(flaggedCount) + "/" + std::to_string(jars.size()) + " jar(s) flagged");
    waitEnter();
}

// =====================================================================
// Step-by-step: JVM Flags Scan
// =====================================================================
void runJvmFlagsScan() {
    con::header("JVM FLAGS SCAN  --  Agent Injection Detection");

    con::step(1, 2, "Locating Java Processes");
    con::dim("Checks the JVM command line of every running java/javaw for:");
    con::dim("  -javaagent  (bytecode-patches classes in memory at load time)");
    con::dim("  -Xbootclasspath/p  (overrides core Java classes)");
    con::dim("  -agentlib:jdwp  (JDWP remote debug port open)");
    con::dim("  -agentpath  (native agent, bypasses Java sandbox)\n");

    auto procs = jvmscan::findJavaProcesses();
    if (procs.empty()) {
        con::warn("No running java/javaw process found. Is Minecraft open?");
        waitEnter();
        return;
    }

    con::info("Found " + std::to_string(procs.size()) + " java process(es).");

    con::step(2, 2, "Reading JVM Command Lines");
    con::dim("(Queries WMI via PowerShell -- may take a moment)\n");

    bool anyFinding = false;

    for (const auto& p : procs) {
        std::string exeNameA(p.exeName.begin(), p.exeName.end());

        con::subheader("PID " + std::to_string(p.pid) + "  (" + exeNameA + ")");

        std::string cmdLine = jvmscan::getCommandLine(p.pid);

        if (cmdLine.empty()) {
            con::warn("Couldn't read command line (access denied, or WMI/PowerShell unavailable).");
            con::dim("Treat this as UNKNOWN, not clean.");
            continue;
        }

        // Print the raw command line (truncated if long)
        std::string display = cmdLine.size() > 200 ? cmdLine.substr(0, 200) + "..." : cmdLine;
        con::dim("CMD: " + display);
        std::cout << "\n";

        auto findings = jvmscan::analyzeCommandLine(cmdLine);
        if (findings.empty()) {
            con::ok("No suspicious JVM flags or unrecognized agents found.");
        } else {
            anyFinding = true;
            for (const auto& f : findings) {
                if (f.severity == con::Color::Red)    con::bad(f.text);
                else if (f.severity == con::Color::Yellow) con::warn(f.text);
                else con::info(f.text);
            }
        }
    }

    con::resultSummary(!anyFinding, anyFinding ? 1 : 0, "suspicious JVM flags");
    waitEnter();
}

// =====================================================================
// Step-by-step: Macro Software Scan
// =====================================================================
void runMacroSoftwareScan() {
    con::header("MACRO SOFTWARE SCAN  --  198M / Zenith Detection");

    con::step(1, 3, "What This Scan Checks");
    con::dim("Looks for macro software in three places:");
    con::dim("  1. Running processes (exe name match)");
    con::dim("  2. Open window titles (catches renamed executables)");
    con::dim("  3. Installed programs via Windows registry");
    std::cout << "\n";
    con::dim("Keywords searched: '198m macro', '198macro', 'zenith macro'\n");

    con::step(2, 3, "Scanning Running Processes & Window Titles");

    static const std::vector<std::string> macroKeywords = {
        "198m macro", "198macro", "zenith macro"
    };

    auto procHits    = scanRunningProcesses(macroKeywords);
    auto winHits     = scanWindowTitles(macroKeywords);

    if (!procHits.empty()) {
        con::subheader("Running Process Matches");
        for (const auto& h : procHits)
            con::bad("Process: " + h.name + "  (PID " + std::to_string(h.pid) + ")");
    } else {
        con::ok("No macro processes running.");
    }

    if (!winHits.empty()) {
        con::subheader("Window Title Matches");
        for (const auto& h : winHits)
            con::bad("Window: \"" + h.name + "\"  (PID " + std::to_string(h.pid) + ")");
    } else {
        con::ok("No macro-related window titles found.");
    }

    con::step(3, 3, "Scanning Installed Programs (Registry)");

    auto installHits = scanInstalledPrograms(macroKeywords);

    if (!installHits.empty()) {
        con::subheader("Installed Program Matches");
        for (const auto& h : installHits)
            con::bad("Installed: " + h.name);
    } else {
        con::ok("No macro software found in installed programs.");
    }

    int total = (int)(procHits.size() + winHits.size() + installHits.size());
    con::resultSummary(total == 0, total, "macro software trace(s)");
    waitEnter();
}

// =====================================================================
// Startup banner
// =====================================================================
static void printBanner() {
    // Enable ANSI / virtual terminal (Windows 10+)
    DWORD mode = 0;
    GetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), &mode);
    SetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE), mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);

    con::set(con::Color::Cyan);
    std::cout << "\n";
    std::cout << "  ============================================================\n";
    std::cout << "  |                                                          |\n";
    std::cout << "  |            SS TOOL  --  by lvstrng  v1.3                |\n";
    std::cout << "  |         Minecraft Screenshare / Cheat Detection          |\n";
    std::cout << "  |                                                          |\n";
    std::cout << "  ============================================================\n";
    con::reset();
    std::cout << "\n";
    con::dim("  Run as Administrator for full memory read access.");
    con::dim("  All scans are read-only -- nothing is modified on this PC.\n");
}

// =====================================================================
// Main menu
// =====================================================================
int main() {
    printBanner();

    while (true) {
        con::divider('=', 60, con::Color::Cyan);
        con::set(con::Color::Cyan);
        std::cout << "  MAIN MENU\n";
        con::divider('=', 60, con::Color::Cyan);
        std::cout << "\n";

        struct MenuItem { const char* label; const char* desc; };
        static const MenuItem items[] = {
            { "Memory Scan",        "Scan live Minecraft RAM for cheat client strings"    },
            { "Mods Folder Scan",   "Static analysis of .jar files for cheat code"        },
            { "JVM Flags Scan",     "Detect injected -javaagent and suspicious JVM flags" },
            { "Macro Scan",         "Check for 198M / Zenith macro software"              },
            { "Exit",               ""                                                    },
        };

        for (int i = 0; i < 5; i++) {
            con::set(con::Color::Cyan);
            std::cout << "    [" << (i + 1) << "] ";
            con::set(con::Color::White);
            std::cout << items[i].label;
            if (items[i].desc[0]) {
                con::set(con::Color::Gray);
                std::cout << "  --  " << items[i].desc;
            }
            std::cout << "\n";
            con::reset();
        }

        con::prompt("Choose an option (1-5):");
        int choice = readInt();
        std::cout << "\n";

        if      (choice == 1) runMemoryScan();
        else if (choice == 2) runModsFolderScanMenu();
        else if (choice == 3) runJvmFlagsScan();
        else if (choice == 4) runMacroSoftwareScan();
        else if (choice == 5) break;
        else {
            con::warn("Invalid choice. Please enter 1-5.");
        }
    }

    std::cout << "\n";
    con::divider('=', 60, con::Color::Gray);
    con::dim("  Exiting SS Tool. Goodbye.");
    con::divider('=', 60, con::Color::Gray);
    std::cout << "\n";

    return 0;
}
