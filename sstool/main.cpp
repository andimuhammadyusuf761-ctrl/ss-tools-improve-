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
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>

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

// --- Shared across multiple clients (class-file signatures, behavioral strings, known package roots) ---
std::vector<std::string_view> universalPatterns = {
    // ---- .class file names (original set) ----
    "CwCrystal.class",
    "ADH.class",
    "ModuleManager.class",
    "AnchorMacro.class",
    "TriggerBot.class",
    "AutoDoubleHand.class",
    "AutoInventoryTotem.class",
    "AutoCrystal.class",
    "SelfDestruct.class",
    "ClickGUI.class",

    // ---- Crystal / AutoCrystal ----
    "AutoCrystal",
    "autocrystal",
    "Auto Crystal",
    "auto crystal",
    "cw crystal",
    "JDWP.VirtualMachine.AllModules",
    "dontPlaceCrystal",
    "dontBreakCrystal",
    "AutoHitCrystal",
    "autohitcrystal",
    "canPlaceCrystalServer",
    "CrystalAura",
    "autoCrystalPlaceClock",
    "WalksyCrystalOptimizerMod",
    "WalksyOptimizer",
    "WalskyOptimizer",

    // ---- Anchor ----
    "AutoAnchor",
    "autoanchor",
    "auto anchor",
    "DoubleAnchor",
    "HasAnchor",
    "anchortweaks",
    "anchor macro",
    "Anchor Macro",
    "safe anchor",
    "safeanchor",
    "SafeAnchor",
    "AirAnchor",
    "anchorMacro",
    "AnchorAura",
    "AnchorFill",
    "AnchorPlace",
    "AnchorAction",
    "Places two anchors for massive damage",
    "double_anchor",
    "safe_anchor",

    // ---- Totem ----
    "AutoTotem",
    "autototem",
    "auto totem",
    "InventoryTotem",
    "inventorytotem",
    "HoverTotem",
    "hover totem",
    "legittotem",
    "OffhandTotem",
    "TotemSwitch",
    "REOFFHAND_TOTEM",
    "Hover Totem",
    "Auto Inventory Totem",
    "Force Totem",
    "Only On Pop",
    "Hover Totem",

    // ---- Pot / Armor ----
    "AutoPot",
    "autopot",
    "auto pot",
    "speedPotSlot",
    "strengthPotSlot",
    "AutoArmor",
    "autoarmor",
    "auto armor",
    "AutoPotRefill",
    "auto_pot_refill",
    "healPotSlot",
    "auto_neth_pot",
    "AutoNethPot",

    // ---- Shield / Axe ----
    "ShieldDisabler",
    "ShieldBreaker",
    "Breaking shield with axe...",
    "preventSwordBlockBreaking",
    "preventSwordBlockAttack",
    "Require Hold Axe",

    // ---- Double Hand / Mace ----
    "AutoDoubleHand",
    "autodoublehand",
    "auto double hand",
    "AutoMace",
    "MaceSwap",
    "SpearSwap",
    "StunSlam",
    "Failed to switch to mace after axe!",
    "mace_swap",
    "stun_slam",
    "Mace Priority",

    // ---- Aim / TriggerBot ----
    "AimAssist",
    "aimassist",
    "aim assist",
    "aim_assist",
    "triggerbot",
    "trigger bot",
    "trigger_bot",
    "Silent Rotations",
    "SilentRotations",
    "SilentAim",
    "AimBot",
    "AutoAim",
    "AimLock",
    "HeadSnap",
    "BowAimbot",
    "Smooth Rotations",
    "Rotation Speed",

    // ---- KillAura / Combat ----
    "KillAura",
    "ClickAura",
    "MultiAura",
    "ForceField",
    "LegitAura",
    "WTap",
    "auto_dtap",
    "AutoDtap",
    "JumpReset",
    "Donut",
    "axespam",
    "axe spam",
    "findKnockbackSword",
    "attackRegisteredThisClick",
    "invokeDoAttack",
    "invokeDoItemUse",
    "invokeOnMouseButton",
    "TargetStrafe",
    "AutoWeapon",
    "AutoSword",
    "AutoCrit",
    "CritBypass",
    "AlwaysCrit",
    "CriticalHit",
    "AutoClicker",
    "DoubleClicker",
    "JitterClick",
    "ButterflyClick",
    "CPSBoost",

    // ---- Reach / Hitbox ----
    "ReachHack",
    "ExtendReach",
    "LongReach",
    "HitboxExpand",
    "onPushOutOfBlocks",
    "onIsGlowing",
    "Entity.isGlowing",
    "invokeOnMouseButton",

    // ---- Velocity / AntiKB ----
    "AntiKB",
    "NoKnockback",
    "Antiknockback",
    "GrimVelocity",
    "GrimDisabler",
    "VelocitySpoof",
    "KBReduce",

    // ---- Fake / Spoof ----
    "FakeInv",
    "FakeLag",
    "fakePunch",
    "Fake Punch",
    "FakeLatency",
    "FakePing",
    "pingspoof",
    "ping spoof",
    "SpoofRotation",
    "PositionSpoof",
    "PackSpoof",
    "swapBackToOriginalSlot",

    // ---- Web / Pearl ----
    "webmacro",
    "web macro",
    "AntiWeb",
    "AutoWeb",
    "auto_web",
    "KeyPearl",
    "key_pearl",
    "AutoPearl",
    "AutoGap",

    // ---- Movement / Flight ----
    "FlyHack",
    "CreativeFlight",
    "BoatFly",
    "PacketFly",
    "AirJump",
    "SpeedHack",
    "BHop",
    "BunnyHop",
    "AntiFall",
    "NoFallDamage",
    "SafeFall",
    "StepHack",
    "FastClimb",
    "AutoStep",
    "HighStep",
    "WaterWalk",
    "LiquidWalk",
    "LavaWalk",
    "NoSlow",
    "NoSlowdown",
    "NoWeb",
    "NoSoulSand",
    "ElytraSpeed",
    "InstantElytra",
    "ElytraSwap",
    "NoJumpDelay",

    // ---- Building / Mining ----
    "ScaffoldWalk",
    "FastBridge",
    "BuildHelper",
    "AutoBridge",
    "Nuker",
    "NukerLegit",
    "InstantBreak",
    "GhostHand",
    "NoSwing",
    "PlaceAssist",
    "AirPlace",
    "AutoPlace",
    "InstantPlace",
    "FastPlace",
    "setBlockBreakingCooldown",
    "getBlockBreakingCooldown",
    "blockBreakingCooldown",
    "onBlockBreaking",
    "setItemUseCooldown",
    "AutoBreach",
    "AutoCity",
    "Burrow",
    "SelfTrap",
    "HoleFiller",
    "AntiSurround",
    "AntiBurrow",

    // ---- ESP / Visuals ----
    "PlayerESP",
    "MobESP",
    "ItemESP",
    "StorageESP",
    "ChestESP",
    "Tracers",
    "NameTagsHack",
    "XRayHack",
    "OreFinder",
    "OreESP",
    "NewChunks",
    "ChunkBorders",
    "TunnelFinder",
    "TargetHUD",
    "WallHack",

    // ---- Macro state strings ----
    "DOUBLE_ESCAPE",
    "DOUBLE_RIGHTCLICK_FIRST",
    "DOUBLE_RIGHTCLICK_SECOND",
    "POST_CYCLE_DELAY",
    "PLACE_OBI",
    "WAIT_OBI",
    "PLACE_CRYSTAL",
    "BREAK_CRYSTAL",
    "ROTATING_DOWN",
    "ROTATING_BACK",
    "REFILLING",
    "PLANTING",
    "BONEMEALING",
    "macro_198",
    "quick_strike",
    "walksy_optimizer",
    "auto_dtap",
    "REOFFHAND_TOTEM",

    // ---- Misc module names ----
    "LootYeeter",
    "Loot Yeeter",
    "Auto Loot Yeeter",
    "ChestStealer",
    "FastXP",
    "FastExp",
    "AutoFirework",
    "BedAura",
    "AutoBed",
    "BedBomb",
    "BedPlace",
    "BowSpam",
    "AutoBow",
    "PopSwitch",
    "AutoSprint",
    "AntiAFK",
    "AutoRespawn",
    "BaseFinder",
    "invsee",
    "ItemExploit",
    "FreezePlayer",
    "GameSpeed",
    "SpeedTimer",
    "PacketMine",
    "PacketWalk",
    "PacketSneak",
    "PacketCancel",
    "PacketDupe",
    "PacketSpam",
    "AutoEat",
    "AutoMine",
    "AutoTPA",
    "InvManager",
    "InvMovebypass",
    "PopSwitch",

    // ---- Self-destruct / hide ----
    "selfdestruct",
    "self destruct",
    "Self Destruct",
    "SelfDestruct",
    "HideClient",
    "AuthBypass",
    "obfuscatedAuth",
    "LicenseCheckMixin",

    // ---- Anti-cheat bypass strings ----
    "GrimBypass",
    "VulcanBypass",
    "MatrixBypass",
    "AACBypass",
    "VerusDisabler",
    "IntaveBypass",
    "WatchdogBypass",
    "Bypasses stray's Anti-TriggerBot",
    "Stray Bypass",

    // ---- Malware / exfil indicators ----
    "SessionStealer",
    "TokenLogger",
    "TokenGrabber",
    "DiscordToken",
    "RemoteAccess",
    "ReverseShell",
    "C2Server",
    "Backdoor",
    "KeyLogger",
    "POT_CHEATS",
    "arrayOfString",

    // ---- Known client package roots ----
    "lvstrng",
    "dqrkis",
    "dqrkis.xyz",
    "Dqrkis Client",
    "LWFH Crystal",
    "imgui.binding",
    "JNativeHook",
    "GlobalScreen",
    "NativeKeyListener",
    "client-refmap.json",
    "cheat-refmap.json",
    "phantom-refmap.json",
    "meteordevelopment",
    "cc/novoline",
    "com/alan/clients",
    "club/maxstats",
    "wtf/moonlight",
    "me/zeroeightsix/kami",
    "net/ccbluex",
    "today/opai",
    "net/minecraft/injection",
    "org/chainlibs/module/impl/modules",
    "xyz/greaj",
    "com/cheatbreaker",
    "com/moonsworth",
    "doomsdayclient",
    "DoomsdayClient",
    "novaclient",
    "api.novaclient.lol",
    "vape.gg",
    "vapeclient",
    "VapeClient",
    "VapeLite",
    "intent.store",
    "IntentClient",
    "riseclient.com",
    "meteor-client",
    "meteorclient",
    "liquidbounce",
    "fdp-client",
    "net.ccbluex",
    "novoware",
    "aristois",
    "impactclient",
    "pandaware",
    "astolfo",
    "konas",
    "rusherhack",
    "inertia",
    "exhibition",
    "dev.krypton",
    "dev/krypton",
    "skid.krypton",
    "skid/krypton",
    "VirginClient",
    "CatleanClient",
    "catlean",
    "ArgonClient",
    "Asteria",
    "AsteriaClient",
    "Prestige",
    "PrestigeClient",
    "prestigeclient.vip",
    "gypsy",
    "GypsyClient",
    "Xenon",
    "XenonClient",
    "GrimClient",
    "aHR0cDovL2FwaS5ub3ZhY2xpZW50LmxvbC93ZWJob29rLnR4dA==",

    // ---- Behavioral signatures ----
    "Automatically switches to sword when hitting with totem",
    "Automatically resets sprint on hit for extra knockback",
};

// =====================================================================
// Helpers
// =====================================================================

static void waitEnter() {
    con::dim("Press Enter to continue...");
    if (std::cin.rdbuf()->in_avail() > 0) std::cin.ignore(10000, '\n');
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

static void discardLine() {
    std::cin.ignore(10000, '\n');
}

static std::string currentLocalDateTime() {
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
    localtime_s(&tm, &t);

    std::ostringstream out;
    out << std::put_time(&tm, "%Y-%m-%d %H:%M:%S");
    return out.str();
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
    con::dim("Scanner version: SS TOOLS v1.4");
    con::dim("Scan date/time: " + currentLocalDateTime());
    con::dim("Strings checked: " + std::to_string(scannable.size()));
    con::dim("Strings found: " + std::to_string(results.size()) + " string(s)");

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

    wchar_t* userProfileRaw = nullptr;
    size_t userProfileLen = 0;
    _wdupenv_s(&userProfileRaw, &userProfileLen, L"USERPROFILE");
    std::filesystem::path defaultPath = userProfileRaw
        ? std::filesystem::path(userProfileRaw) / L"AppData" / L"Roaming" / L".minecraft" / L"mods"
        : std::filesystem::path();
    free(userProfileRaw);

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

    discardLine();
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
    int findingCount = 0;

    for (const auto& p : procs) {
        std::string exeNameA = jvmscan::wideToUtf8(p.exeName);

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
            findingCount += (int)findings.size();
            for (const auto& f : findings) {
                if (f.severity == con::Color::Red)    con::bad(f.text);
                else if (f.severity == con::Color::Yellow) con::warn(f.text);
                else con::info(f.text);
            }
        }
    }

    con::resultSummary(!anyFinding, findingCount, "suspicious JVM flag(s)");
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
    con::dim("When a match is found, this scan opens the evidence location.");
    con::dim("  - AutoHotkey / generic macro hits open their folder");
    con::dim("  - 198M Macro / Zenith Macro hits open the app itself");
    std::cout << "\n";
    con::dim("Keywords searched: '198m macro', '198macro', 'zenith macro', 'autohotkey', '.ahk'\n");

    con::step(2, 3, "Scanning Running Processes & Window Titles");

    static const std::vector<std::string> macroKeywords = {
        "198m macro", "198macro", "zenith macro", "auto hotkey", "autohotkey", ".ahk"
    };

    auto procHits    = scanRunningProcesses(macroKeywords);
    auto winHits     = scanWindowTitles(macroKeywords);

    if (!procHits.empty()) {
        con::subheader("Running Process Matches");
        for (const auto& h : procHits) {
            con::bad("Process: " + h.name + "  (PID " + std::to_string(h.pid) + ")");
            if (!h.path.empty()) con::dim("Path: " + h.path);
        }
    } else {
        con::ok("No macro processes running.");
    }

    if (!winHits.empty()) {
        con::subheader("Window Title Matches");
        for (const auto& h : winHits) {
            con::bad("Window: \"" + h.name + "\"  (PID " + std::to_string(h.pid) + ")");
            if (!h.path.empty()) con::dim("Path: " + h.path);
        }
    } else {
        con::ok("No macro-related window titles found.");
    }

    con::step(3, 3, "Scanning Installed Programs (Registry)");

    auto installHits = scanInstalledPrograms(macroKeywords);

    if (!installHits.empty()) {
        con::subheader("Installed Program Matches");
        for (const auto& h : installHits) {
            con::bad("Installed: " + h.name);
            if (!h.path.empty()) con::dim("Path: " + h.path);
        }
    } else {
        con::ok("No macro software found in installed programs.");
    }

    int total = (int)(procHits.size() + winHits.size() + installHits.size());
    if (total > 0) {
        con::subheader("Opening Evidence");
        int opened = 0;
        std::vector<MacroHit> allHits;
        allHits.insert(allHits.end(), procHits.begin(), procHits.end());
        allHits.insert(allHits.end(), winHits.begin(), winHits.end());
        allHits.insert(allHits.end(), installHits.begin(), installHits.end());

        for (const auto& hit : allHits) {
            if (openEvidencePath(hit)) {
                opened++;
                if (is198mOrZenith(hit)) con::ok("Opened app for: " + hit.name);
                else con::ok("Opened folder for: " + hit.name);
            } else {
                con::warn("Could not auto-open evidence for: " + hit.name);
            }
        }
        con::info("Opened " + std::to_string(opened) + "/" + std::to_string(total) + " evidence location(s).");
    }
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

    std::cout << "\n";
    con::titleCard("SS TOOLS  v1.4", "Minecraft Screenshare / Cheat Detection");
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
        con::menuHeader("MAIN MENU  --  choose a step-by-step scan");
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
            std::cout << "    " << (i + 1) << ". ";
            con::set(i == 4 ? con::Color::Yellow : con::Color::White);
            std::cout << items[i].label;
            if (items[i].desc[0]) {
                con::set(con::Color::Gray);
                std::cout << "  --  " << items[i].desc;
            }
            std::cout << "\n";
            con::reset();
        }

        con::prompt("Choose an option (1-5), then follow the guided steps:");
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
    con::divider('=', con::UiWidth, con::Color::Gray);
    con::dim("  Exiting SS Tool. Goodbye.");
    con::divider('=', con::UiWidth, con::Color::Gray);
    std::cout << "\n";

    return 0;
}
