#include <Windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <string_view>
#include <tlhelp32.h>
#include "PatternScan.h"

// Updated strings for Minecraft 1.8.9 - 1.21.11
std::vector<std::string_view> novaPatterns = {
    "aHR0cDovL2FwaS5ub3ZhY2xpZW50LmxvbC93ZWJob29rLnR4dA==",
    "novaclient",
    "addFri",
    "antiAttack",
    "/assets/font/font.ttf",
    "Lithium is not initialized! Skipping event: ",
    "Error in hash"
};

std::vector<std::string_view> universalPatterns = {
    // Original
    "Auto Crystal", "Self Destruct", "Auto Anchor", "Auto Loot Yeeter",
    "CwCrystal.class", "ADH.class", "ModuleManager.class",

    // Expanded common cheats (1.8.9 - 1.21+)
    "AimAssist", "AutoCrystal", "CrystalAura", "KillAura", "TriggerBot",
    "SilentAim", "Reach", "ReachHack", "ShieldBreaker", "ShieldDisabler",
    "AutoTotem", "AutoAnchor", "DoubleAnchor", "SafeAnchor", "AirAnchor",
    "AutoBed", "BedAura", "FastPlace", "AutoClicker", "AutoEat", "AutoMine",
    "FlyHack", "SpeedHack", "BHop", "NoKnockback", "AntiKB", "Freecam",
    "XRayHack", "PlayerESP", "BlockESP", "AutoGap", "AutoPearl",
    "GrimBypass", "VulcanBypass", "PacketMine", "FakeLag",

    // Macro-specific (198M, Zenith, etc.)
    "198m", "198macros", "198M", "198 Macro", "anchor macro", "crystal macro",
    "Zenith", "ZenithMacros", "zenith macro", "double anchor", "safe anchor place",
    "PLACE CHARGE EXPLODE", "mace macro", "sword macro", "cart macro",
    "AutoCrit", "StunSlam", "PopSwitch", "MaceSwap", "HoverTotem",

    // More generic / obfuscated hints
    "AutoHitCrystal", "AnchorTweaks", "NoBounce", "FastXP", "AutoBridge",
    "WTap", "FakeInv", "PacketFly", "AxeSpam", "BowAimbot",

    // Argon Client .class files
    "BooleanSetting.class", "KeybindSetting.class", "MinMaxSetting.class", "ModeSetting.class",
    "NumberSetting.class", "Setting.class", "StringSetting.class",
    "AnimationUtils.class", "BlockUtils.class", "ColorUtils.class", "CrystalUtils.class",
    "DamageUtils.class", "EncryptedString.class", "FakeInvScreen.class", "InventoryUtils.class",
    "KeyUtils.class", "MathUtils.class", "MouseSimulation.class", "ProjectionUtils.class",
    "RenderUtils.class", "RotationUtils.class", "TextRenderer.class",

    // Process Hacker detectable strings (advanced/generic)
    "memory region", "VirtualProtect", "NtReadVirtualMemory", "NtWriteVirtualMemory",
    "CreateRemoteThread", "LoadLibraryA", "GetProcAddress", "RtlMoveMemory",
    "hooked", "detour", "jmp ", "ret ", "shellcode", "inject", "DLL_PROCESS_ATTACH",
    "Minecraft.jar", "client.jar", "forge.jar", "fabric.jar", "optifine.jar",
    "-javaagent", "-noverify", "-Xbootclasspath/a", "-Xmx", "-Xms",
    "obfuscated", "encrypted", "hidden", "bypass", "anticheat", "detection",
    "ghost client", "external client", "internal client", "cheat engine",
    "AutoClicker.exe", "Macro.exe", "Killaura.exe", "Aimbot.exe",
    "ProcessHacker.exe", "x64dbg.exe", "ollydbg.exe", "ida.exe",
    "cheat-client", "hacked-client", "utility-mod", "module-manager",
    "eventbus", "onEnable", "onDisable", "onUpdate", "onPacket",
    "render2D", "render3D", "drawRect", "drawString", "drawCircle",
    "GL11", "GL_BLEND", "GL_DEPTH_TEST", "GL_ALPHA_TEST",
    "sendPacket", "receivePacket", "playerMove", "attackEntity",
    "getMouseOver", "getLookVec", "getEyeHeight", "isSneaking", "isSprinting",
    "setSprinting", "setSneaking", "setMotionX", "setMotionY", "setMotionZ",
    "onWorldLoad", "onPlayerJoin", "onPlayerLeave", "onChat",
    "keybind", "toggle", "bind", "config", "settings", "gui", "menu",
    "module", "category", "arraylist", "hud", "watermark", "font",
    "theme", "profile", "account", "friend", "enemy", "target",
    "hitbox", "boundingbox", "renderbox", "tracer", "esp", "chams",
    "wallhack", "fullbright", "nofog", "nosky", "norender", "nooverlay",
    "itemesp", "chestesp", "storageesp", "tracers", "waypoints",
    "timer", "tps", "ping", "fps", "cps", "bypassed", "patched",
    "exploit", "vulnerability", "crash", "kick", "ban", "debug", "log",
    "console", "command", "prefix", "binds", "keybinds", "aliases",
    "script", "lua", "javascript", "python", "autoit", "ahk",
    "dll injection", "code caves", "IAT hook", "EAT hook", "inline hook",
    "VEH hook", "APC injection", "thread hijacking", "manual map",
    "shellcode injection", "remote thread", "process hollowing",
    "PEB walk", "TEB walk", "SSDT hook", "shadow hook", "kernel hook",
    "driver", "rootkit", "hypervisor", "VMProtect", "Themida", "Obsidium",
    "Packer", "Crypter", "Protector", "Virtualizer", "Anti-VM", "Anti-Debug",
    "Anti-Dump", "Anti-Tamper", "checksum", "hash", "CRC32", "MD5", "SHA1",
    "AES", "XOR", "RC4", "Base64", "obf", "enc", "dec", "str_decrypt",
    "string_encrypt", "string_obfuscate", "string_decode", "string_encode",
    "byte array", "byte code", "bytecode manipulation", "class transformer",
    "mixin", "mixins", "mixin.json", "tweakclass", "coremod", "eventhandler",
    "eventlistener", "eventpriority", "subscribeevent", "registerevent",
    "postevent", "cancellable", "eventcancel", "eventbus", "eventmanager",
    "ReflectionHelper", "Unsafe", "sun.misc.Unsafe", "java.lang.instrument",
    "Instrumentation", "Agent", "attach", "VirtualMachine", "tools.jar",
    "JVMTI", "JNI", "native method", "native code", "System.loadLibrary",
    "System.load", "Runtime.getRuntime().exec", "ProcessBuilder",
    "File.createTempFile", "File.deleteOnExit", "URLClassLoader",
    "NetworkManager", "PacketEvent", "SendPacketEvent", "ReceivePacketEvent",
    "PlayerMoveEvent", "AttackEntityEvent", "UseItemEvent", "BlockChangeEvent",
    "WorldEvent", "RenderEvent", "TickEvent", "ClientTickEvent", "ServerTickEvent",
    "PlayerTickEvent", "LivingUpdateEvent", "RenderLivingEvent", "RenderWorldLastEvent",
    "RenderGameOverlayEvent", "GuiScreenEvent", "MouseEvent", "KeyboardEvent",
    "onKeyInput", "onMouseInput", "onGuiOpen", "onRenderTick", "onClientDisconnect",
    "onClientConnect", "onPlayerDeath", "onAttack", "onUpdateWalkingPlayer",
    "sendChatMessage", "displayChatMessage", "addChatMessage", "printChatMessage",
    "getMinecraft().player", "getMinecraft().world", "getMinecraft().currentScreen",
    "getMinecraft().getConnection()", "getMinecraft().getRenderManager()",
    "getMinecraft().getTextureManager()", "getMinecraft().fontRenderer",
    "getMinecraft().gameSettings", "getMinecraft().isSingleplayer()",
    "getMinecraft().isFullScreen()", "getMinecraft().getDebugFPS()",
    "getMinecraft().getIntegratedServer()", "getMinecraft().getNetHandler()",
    "getMinecraft().getRenderViewEntity()", "getMinecraft().getRenderPartialTicks()",
    "getMinecraft().getRenderPosX()", "getMinecraft().getRenderPosY()",
    "getMinecraft().getRenderPosZ()", "getMinecraft().getRenderViewEntity().posX",
    "getMinecraft().getRenderViewEntity().posY", "getMinecraft().getRenderViewEntity().posZ",
    "getMinecraft().getRenderViewEntity().rotationYaw", "getMinecraft().getRenderViewEntity().rotationPitch",
    "getMinecraft().getRenderViewEntity().prevRotationYaw", "getMinecraft().getRenderViewEntity().prevRotationPitch",
    "getMinecraft().getRenderViewEntity().lastTickPosX", "getMinecraft().getRenderViewEntity().lastTickPosY",
    "getMinecraft().getRenderViewEntity().lastTickPosZ", "getMinecraft().getRenderViewEntity().getDistanceSq",
    "getMinecraft().getRenderViewEntity().getDistance", "getMinecraft().getRenderViewEntity().getEyeHeight",
    "getMinecraft().getRenderViewEntity().getHealth()", "getMinecraft().getRenderViewEntity().getMaxHealth()",
    "getMinecraft().getRenderViewEntity().isDead", "getMinecraft().getRenderViewEntity().isAlive",
    "getMinecraft().getRenderViewEntity().isInvisible", "getMinecraft().getRenderViewEntity().isSneaking",
    "getMinecraft().getRenderViewEntity().isSprinting", "getMinecraft().getRenderViewEntity().isCollidedHorizontally",
    "getMinecraft().getRenderViewEntity().isCollidedVertically", "getMinecraft().getRenderViewEntity().onGround",
    "getMinecraft().getRenderViewEntity().fallDistance", "getMinecraft().getRenderViewEntity().motionX",
    "getMinecraft().getRenderViewEntity().motionY", "getMinecraft().getRenderViewEntity().motionZ",
    "getMinecraft().getRenderViewEntity().rotationYawHead", "getMinecraft().getRenderViewEntity().prevRotationYawHead",
    "getMinecraft().getRenderViewEntity().renderYawOffset", "getMinecraft().getRenderViewEntity().prevRenderYawOffset",
    "getMinecraft().getRenderViewEntity().getHeldItemMainhand()", "getMinecraft().getRenderViewEntity().getHeldItemOffhand()",
    "getMinecraft().getRenderViewEntity().getArmorInventoryList()", "getMinecraft().getRenderViewEntity().getAbsorptionAmount()",
    "getMinecraft().getRenderViewEntity().getFoodStats()", "getMinecraft().getRenderViewEntity().getUniqueID()",
    "getMinecraft().getRenderViewEntity().getName()", "getMinecraft().getRenderViewEntity().getDisplayName()",
    "getMinecraft().getRenderViewEntity().getCustomNameTag()", "getMinecraft().getRenderViewEntity().isCustomNameVisible()",
    "getMinecraft().getRenderViewEntity().getAlwaysRenderNameTag()", "getMinecraft().getRenderViewEntity().getHealth()",
    "getMinecraft().getRenderViewEntity().getMaxHealth()", "getMinecraft().getRenderViewEntity().getAbsorptionAmount()",
    "getMinecraft().getRenderViewEntity().getFoodStats().getFoodLevel()", "getMinecraft().getRenderViewEntity().getFoodStats().getSaturationLevel()",
    "getMinecraft().getRenderViewEntity().getFoodStats().getExhaustion()", "getMinecraft().getRenderViewEntity().getFoodStats().getFoodTimer()",
    "getMinecraft().getRenderViewEntity().getFoodStats().getFoodLevel()", "getMinecraft().getRenderViewEntity().getFoodStats().getSaturationLevel()",
    "getMinecraft().getRenderViewEntity().getFoodStats().getExhaustion()", "getMinecraft().getRenderViewEntity().getFoodStats().getFoodTimer()",
    "getMinecraft().getRenderViewEntity().getHeldItemMainhand().getItem()", "getMinecraft().getRenderViewEntity().getHeldItemOffhand().getItem()",
    "getMinecraft().getRenderViewEntity().getHeldItemMainhand().getDisplayName()", "getMinecraft().getRenderViewEntity().getHeldItemOffhand().getDisplayName()",
    "getMinecraft().getRenderViewEntity().getHeldItemMainhand().getUnlocalizedName()", "getMinecraft().getRenderViewEntity().getHeldItemOffhand().getUnlocalizedName()",
    "getMinecraft().getRenderViewEntity().getHeldItemMainhand().getItemDamage()", "getMinecraft().getRenderViewEntity().getHeldItemOffhand().getItemDamage()",
    "getMinecraft().getRenderViewEntity().getHeldItemMainhand().getMaxDamage()", "getMinecraft().getRenderViewEntity().getHeldItemOffhand().getMaxDamage()",
    "getMinecraft().getRenderViewEntity().getHeldItemMainhand().isStackable()", "getMinecraft().getRenderViewEntity().getHeldItemOffhand().isStackable()",
    "getMinecraft().getRenderViewEntity().getHeldItemMainhand().isEmpty()", "getMinecraft().getRenderViewEntity().getHeldItemOffhand().isEmpty()",
    "getMinecraft().getRenderViewEntity().getHeldItemMainhand().getCount()", "getMinecraft().getRenderViewEntity().getHeldItemOffhand().getCount()",
    "getMinecraft().getRenderViewEntity().getHeldItemMainhand().getMaxStackSize()", "getMinecraft().getRenderViewEntity().getHeldItemOffhand().getMaxStackSize()",
    "getMinecraft().getRenderViewEntity().getHeldItemMainhand().hasEffect()", "getMinecraft().getRenderViewEntity().getHeldItemOffhand().hasEffect()",
    "getMinecraft().getRenderViewEntity().getHeldItemMainhand().isEnchanted()", "getMinecraft().getRenderViewEntity().getHeldItemOffhand().isEnchanted()",
    "getMinecraft().getRenderViewEntity().getHeldItemMainhand().getEnchantmentTagList()", "getMinecraft().getRenderViewEntity().getHeldItemOffhand().getEnchantmentTagList()",
    "getMinecraft().getRenderViewEntity().getHeldItemMainhand().getDisplayName()", "getMinecraft().getRenderViewEntity().getHeldItemOffhand().getDisplayName()",
    "getMinecraft().getRenderViewEntity().getHeldItemMainhand().getTooltip()", "getMinecraft().getRenderViewEntity().getHeldItemOffhand().getTooltip()",
    "getMinecraft().getRenderViewEntity().getHeldItemMainhand().getRarity()", "getMinecraft().getRenderViewEntity().getHeldItemOffhand().getRarity()",
    "getMinecraft().getRenderViewEntity().getHeldItemMainhand().getRegistryName()", "getMinecraft().getRenderViewEntity().getHeldItemOffhand().getRegistryName()",
    "getMinecraft().getRenderViewEntity().getHeldItemMainhand().getTranslationKey()", "getMinecraft().getRenderViewEntity().getHeldItemOffhand().getTranslationKey()",
    "getMinecraft().getRenderViewEntity().getHeldItemMainhand().getCreativeTab()", "getMinecraft().getRenderViewEntity().getHeldItemOffhand().getCreativeTab()",
    "getMinecraft().getRenderViewEntity().getHeldItemMainhand().isDamageable()", "getMinecraft().getRenderViewEntity().getHeldItemOffhand().isDamageable()",
    "getMinecraft().getRenderViewEntity().getHeldItemMainhand().isRepairable()", "getMinecraft().getRenderViewEntity().getHeldItemOffhand().isRepairable()",
    "getMinecraft().getRenderViewEntity().getHeldItemMainhand().isPotion()", "getMinecraft().getRenderViewEntity().getHeldItemOffhand().isPotion()",
    "getMinecraft().getRenderViewEntity().getHeldItemMainhand().isFood()", "getMinecraft().getRenderViewEntity().getHeldItemOffhand().isFood()",
    "getMinecraft().getRenderViewEntity().getHeldItemMainhand().isShield()", "getMinecraft().getRenderViewEntity().getHeldItemOffhand().isShield()",
    "getMinecraft().getRenderViewEntity().getHeldItemMainhand().isBow()", "getMinecraft().getRenderViewEntity().getHeldItemOffhand().isBow()",
    "getMinecraft().getRenderViewEntity().getHeldItemMainhand().isCrossbow()", "getMinecraft().getRenderViewEntity().getHeldItemOffhand().isCrossbow()",
    "getMinecraft().getRenderViewEntity().getHeldItemMainhand().isTrident()", "getMinecraft().getRenderViewEntity().getHeldItemOffhand().isTrident()",
    "getMinecraft().getRenderViewEntity().getHeldItemMainhand().isBlock()", "getMinecraft().getRenderViewEntity().getHeldItemOffhand().isBlock()",
    "getMinecraft().getRenderViewEntity().getHeldItemMainhand().isArmor()", "getMinecraft().getRenderViewEntity().getHeldItemOffhand().isArmor()",
    "getMinecraft().getRenderViewEntity().getHeldItemMainhand().isTool()", "getMinecraft().getRenderViewEntity().getHeldItemOffhand().isTool()",
    "getMinecraft().getRenderViewEntity().getHeldItemMainhand().isWeapon()", "getMinecraft().getRenderViewEntity().getHeldItemOffhand().isWeapon()"
};

std::vector<std::string_view> macroPatterns = {
    // 198M Macros
    "198M", "198m", "198Macros", "198m_back", "198m.com", "198M_Macro",
    // Zenith Macros
    "Zenith", "ZenithMacros", "Zenith Macros", "PLACECHARGEEXPLODE", "PLACECHARGEFLICKGLOW", "PLACECHARGEPOP+PLACEEXPLODE",
    "PLACECHARGEPEARL", "zenithmacros.store", "Zenith.exe",
    // General Macro/AHK
    "AutoHotkey", "AHK", "Macro", "Anchor Macro", "Aim Assist", "Auto Clicker", "Fast Crystal", "Double Anchor"
};

std::vector<std::string> clientList = {
    "Nova Client",
    "Universal (Wurst, Meteor, LiquidBounce, etc.)",
    "Macros (198M, Zenith, etc.)",
    "Scan All"
};

DWORD FindProcessId(const std::string& processName) {
    PROCESSENTRY32 processInfo;
    processInfo.dwSize = sizeof(processInfo);

    HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (processesSnapshot == INVALID_HANDLE_VALUE)
        return 0;

    Process32First(processesSnapshot, &processInfo);
    if (!processName.compare(processInfo.szExeFile)) {
        CloseHandle(processesSnapshot);
        return processInfo.th32ProcessID;
    }

    while (Process32Next(processesSnapshot, &processInfo)) {
        if (!processName.compare(processInfo.szExeFile)) {
            CloseHandle(processesSnapshot);
            return processInfo.th32ProcessID;
        }
    }

    CloseHandle(processesSnapshot);
    return 0;
}

void scanProcesses() {
    std::cout << "\n--- External Process Scan ---\n";
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe32)) {
        do {
            std::string procName = pe32.szExeFile;
            bool flagged = false;
            
            if (procName.find("Zenith") != std::string::npos || 
                procName.find("198M") != std::string::npos ||
                procName.find("AutoHotkey") != std::string::npos ||
                procName.find("Macro") != std::string::npos ||
                procName.find("Wurst") != std::string::npos ||
                procName.find("Meteor") != std::string::npos) {
                flagged = true;
            }

            if (flagged) {
                std::cout << "[!] Flagged Process Found: " << procName << " (PID: " << pe32.th32ProcessID << ")\n";
            }
        } while (Process32Next(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
    std::cout << "--- Process Scan Complete ---\n\n";
}

int main() {
    std::cout << "========================================\n";
    std::cout << "   Improved SS Tool | 1.8.9 - 1.21.11   \n";
    std::cout << "      Updated with 198M & Zenith        \n";
    std::cout << "========================================\n";

    scanProcesses();

    DWORD pid = FindProcessId("javaw.exe");
    if (pid == 0) {
        std::cout << "\n[!] javaw.exe process not found. Please ensure Minecraft is running.\n";
        std::cout << "\nPress Enter to exit...";
        std::cin.ignore();
        std::cin.get();
        return 1;
    }

    std::cout << "[*] Found javaw.exe with PID: " << pid << "\n";

    HANDLE handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);

    if (!handle) {
        std::cout << "\n[!] Invalid Process or Access Denied. Run as Administrator.\n";
        std::cout << "\nPress Enter to exit...";
        std::cin.ignore();
        std::cin.get();
        return 1;
    } else {
        std::cout << "\nSelect Scan Mode: \n";
        for (int i = 0; i < clientList.size(); i++)
            std::cout << (i + 1) << ". " << clientList.at(i) << "\n";

        int option;
        std::cin >> option;

        std::vector<std::string_view> scannable;
        switch (option) {
            case 1: scannable = novaPatterns; break;
            case 2: scannable = universalPatterns; break;
            case 3: scannable = macroPatterns; break;
            case 4: 
                scannable.insert(scannable.end(), novaPatterns.begin(), novaPatterns.end());
                scannable.insert(scannable.end(), universalPatterns.begin(), universalPatterns.end());
                scannable.insert(scannable.end(), macroPatterns.begin(), macroPatterns.end());
                break;
            default: scannable = universalPatterns; break;
        }

        std::cout << "\n[*] Scanning memory for " << scannable.size() << " patterns...\n";
        auto results = pattern_scan(handle, scannable);

        std::cout << "\n[+] Scan Complete. Found " << std::dec << results.size() << " traces.\n";
    }

    std::cout << "\nPress Enter to exit...";
    std::cin.ignore();
    std::cin.get();

    CloseHandle(handle);
    return 0;
}
