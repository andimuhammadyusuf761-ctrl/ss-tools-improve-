# SS-Tool
Screenshare tool for minecraft

A pattern-scan string scanner for... any program really, but made for minecraft.
Also does a system-level scan for known macro software (running processes, window titles, installed programs),
a static jar-file analyzer for the mods folder, and a JVM command-line scanner for injected agents.

# How to use?

- Open the .exe
- Pick an action from the menu:
  1. Scan a Minecraft process for cheat client traces (live memory)
  2. Scan a mods folder for cheat client traces (jar analysis)
  3. Scan for suspicious JVM flags / injected java agents
  4. Scan this PC for macro software (198M Macros / Zenith Macros, running or installed)
  5. Exit
- For option 1: enter the program ID (you can get this by doing this in the following image)
![image](https://github.com/user-attachments/assets/f203e8cd-fabd-4134-a81f-f7480066425f)
- Select the client to scan for:
  1. Nova Client
  2. CrystalPvPHelper
  3. Noqwd / Skate Client (incl. AutoCrystal)
  4. Argon
  5. All (Might not work for all clients)
- Now wait...

Note on Argon: it encrypts most of its display strings at runtime and disguises
its Fabric mod id as `immediatelyfast` to impersonate the real ImmediatelyFast
mod. The patterns for it are fully-qualified `dev.lvstrng.argon` package/class
names rather than display text, since those are what's actually still readable
in plaintext memory.

## Mods folder scan (option 2)

Extracts and statically inspects every `.jar` in a mods folder (default:
`%USERPROFILE%\AppData\Roaming\.minecraft\mods`), including nested jars
under `META-INF/jars/` (Fabric jar-in-jar). It catches things the live
memory scan can't, because the client doesn't even need to be running:

- known cheat/macro identifiers in class names, strings, and mod metadata
- fullwidth-Unicode lookalike characters used to dodge plain string scans
  (e.g. `Ａｕｔｏ Ｃｒｙｓｔａｌ`) — decoded and normalized back to ASCII
  automatically rather than needing a hardcoded fullwidth variant of every pattern
- obfuscation ratios (numeric/unicode/single-letter/gibberish class names,
  known bytecode obfuscators like Skidfuscator or Zelix)
- `Runtime.exec()`, HTTP file-download, and HTTP-exfiltration call
  signatures in the bytecode
- suspicious/hollow nested jars, and jars that claim a known-legitimate
  mod ID (e.g. `sodium`, `lithium`) while containing dangerous code
- where the jar was downloaded from, if Windows recorded it (the
  NTFS `Zone.Identifier` mark-of-the-web)

This requires `tar.exe` (bundled with Windows 10 1803+ / Windows 11) to be
on PATH, since jars are ZIP files and this avoids shipping a separate
zip/inflate library.

## JVM flag scan (option 3)

Some injection methods relaunch Minecraft's JVM with extra flags instead of
touching any file on disk — a `-javaagent` that patches bytecode in memory,
or a debug/bootclasspath flag that bypasses the normal classloader. This
reads the running `java`/`javaw` process's command line (via WMI) and flags
unrecognized `-javaagent`, `-Xbootclasspath`, `-agentlib:jdwp`, and
`-agentpath` usage.

Note on the macro scan: 198M Macros / Zenith Macros are distributed informally
(no public installer), so there's no fixed, official process name to match
exactly. The scan looks for `"198m"` / `"macro"` / `"zenith macro"` as
substrings in running process names, visible window titles, and the Windows
uninstall registry — it's a best-effort heuristic, not a guarantee. If you get
a confirmed exe name or window title from a real catch, add it as an exact
pattern in `macroKeywords` in `ProcessScan.h`.

# How do I add my own strings?

- Do NOT DM me
- Actually learn C++. Just for the purpose of adding strings to this tool it's very simple.
- Use C++20 with Multi-Byte Character Set
- Prefer fully-qualified package/class names (e.g. `net.example.module.Foo`)
  over short display text — they're effectively guaranteed to never occur in
  vanilla Minecraft, so they're the safest zero-false-positive signal.
- Live-memory patterns (`main.cpp`) need to be zero-false-positive, since
  they run against a whole live process. Jar-scan patterns
  (`CheatStrings.h`) run against static file contents instead and can
  afford to be a bit broader, similar to the existing `jarContentStrings`.

# Contributing
- You must check if the string doesn't exist in the Vanilla game.
- Prefer long/specific strings (full package paths, full descriptions) over
  short generic words that could coincidentally show up elsewhere.
- You must check the code and debug it for any bugs, otherwise your pull request will not be accepted.

# Credits
The mods-folder scan, obfuscation heuristics, fullwidth-Unicode evasion
detection, and JVM flag scan were ported to C++ from MeowModAnalyzer, a
PowerShell mod-analysis tool by MeowTonynoh, and adapted to this project's
architecture.

