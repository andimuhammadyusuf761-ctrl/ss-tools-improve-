#pragma once
#define NOMINMAX
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <string>
#include <vector>
#include <set>
#include <optional>
#include <algorithm>
#include <cctype>
#include <cstring>
#include <filesystem>

#include "CheatStrings.h"
#include "JarUtil.h"
#include "Console.h"

// =====================================================================
// Static analysis of .jar files in a mods folder.
//
// This is a different signal from the live memory scan in PatternScan.h:
// the memory scanner catches a client that is *currently running*, while
// this catches one that is *installed*, even disabled or not yet loaded,
// and also flags things a live-memory string scan can't see at all --
// obfuscation ratios, Runtime.exec()/HTTP calls in the bytecode, jars
// pretending to be a different, legitimate mod, etc.
//
// Ported from the MeowModAnalyzer PowerShell tool's Invoke-ModScan /
// Invoke-ObfuscationScan / Invoke-BypassScan, adapted to C++. Jars are
// ZIP files; rather than add a zip/inflate library dependency, extraction
// is done by shelling out to tar.exe (bundled with Windows 10 1803+ and
// Windows 11), see JarUtil.h.
// =====================================================================
namespace modscan {

    namespace fs = std::filesystem;

    enum class Severity { Info, Warning, Danger };

    struct Finding {
        Severity severity;
        std::string text;
    };

    static std::string toLowerStr(std::string s) {
        std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return (char)std::tolower(c); });
        return s;
    }

    // Substring match with a lightweight word-boundary check (mirrors the
    // PowerShell tool's (?<![A-Za-z])pattern(?![A-Za-z]) regex) so a short
    // pattern like "Donut" doesn't match inside an unrelated identifier.
    static bool boundaryContains(const std::string& haystack, const std::string& needle) {
        size_t pos = 0;
        while ((pos = haystack.find(needle, pos)) != std::string::npos) {
            bool leftOk = (pos == 0) || !std::isalpha((unsigned char)haystack[pos - 1]);
            size_t endPos = pos + needle.size();
            bool rightOk = (endPos >= haystack.size()) || !std::isalpha((unsigned char)haystack[endPos]);
            if (leftOk && rightOk) return true;
            ++pos;
        }
        return false;
    }

    // ---- fullwidth-Unicode evasion detection --------------------------
    // Some clients render display strings using fullwidth Unicode lookalike
    // characters (e.g. "Ａｕｔｏ Ｃｒｙｓｔａｌ") specifically so a plain
    // ASCII string scan misses them. Fullwidth Latin letters/digits sit at
    // a fixed +0xFEE0 offset from their ASCII equivalent, so instead of
    // hardcoding a fullwidth twin of every cheat string (as the original
    // tool does), we decode UTF-8, normalize any fullwidth run back to
    // ASCII, and match it against the same jarContentStrings set.
    static std::vector<std::string> extractNormalizedFullwidthRuns(const std::string& content) {
        std::vector<std::string> runs;
        std::string current;

        size_t i = 0;
        while (i < content.size()) {
            unsigned char c = content[i];
            char32_t cp = 0;
            size_t len = 0;

            if ((c & 0x80) == 0) { cp = c; len = 1; }
            else if ((c & 0xE0) == 0xC0 && i + 1 < content.size()) {
                cp = (c & 0x1F) << 6 | (content[i + 1] & 0x3F);
                len = 2;
            } else if ((c & 0xF0) == 0xE0 && i + 2 < content.size()) {
                cp = (c & 0x0F) << 12 | (content[i + 1] & 0x3F) << 6 | (content[i + 2] & 0x3F);
                len = 3;
            } else if ((c & 0xF8) == 0xF0 && i + 3 < content.size()) {
                cp = (c & 0x07) << 18 | (content[i + 1] & 0x3F) << 12 | (content[i + 2] & 0x3F) << 6 | (content[i + 3] & 0x3F);
                len = 4;
            } else {
                len = 1; // invalid byte, skip
            }

            bool isFullwidthAlnum =
                (cp >= 0xFF21 && cp <= 0xFF3A) || // fullwidth A-Z
                (cp >= 0xFF41 && cp <= 0xFF5A) || // fullwidth a-z
                (cp >= 0xFF10 && cp <= 0xFF19);   // fullwidth 0-9

            if (isFullwidthAlnum) {
                current += (char)(cp - 0xFEE0);
            } else {
                if (current.size() >= 2) runs.push_back(current);
                current.clear();
            }
            i += len;
        }
        if (current.size() >= 2) runs.push_back(current);
        return runs;
    }

    // Resolves normalized fullwidth runs back to the cheat string they were
    // disguising, same heuristic as the PowerShell tool: pick the shortest
    // known cheat string that contains the run, otherwise keep the run
    // itself if it's long enough to not be a coincidence.
    static std::set<std::string> resolveFullwidthRuns(const std::vector<std::string>& runs) {
        std::set<std::string> resolved;
        for (const auto& run : runs) {
            const std::string* best = nullptr;
            for (const auto& cheat : jarContentStrings) {
                if (cheat.find(run) != std::string::npos) {
                    if (!best || cheat.size() < best->size()) best = &cheat;
                }
            }
            if (best) resolved.insert(*best);
            else if (run.size() >= 6) resolved.insert(run);
        }
        return resolved;
    }

    // ---- known cheat obfuscators (bytecode obfuscator identity, not the
    // Minecraft cheat client itself) --------------------------------------
    static const std::vector<std::pair<std::string, std::vector<std::string>>> kCheatObfuscators = {
        { "Skidfuscator",   { "dev/skidfuscator", "Skidfuscator", "skidfuscator.dev" } },
        { "Paramorphism",   { "Paramorphism", "paramorphism-", "dev/paramorphism" } },
        { "Radon",          { "ItzSomebody/Radon", "me/itzsomebody/radon", "Radon Obfuscator" } },
        { "Caesium",        { "sim0n/Caesium", "Caesium Obfuscator", "dev/sim0n/caesium" } },
        { "Bozar",          { "vimasig/Bozar", "Bozar Obfuscator", "com/bozar" } },
        { "Branchlock",     { "Branchlock", "branchlock.dev" } },
        { "Binscure",       { "Binscure", "com/binscure" } },
        { "SuperBlaubeere", { "superblaubeere", "superblaubeere27" } },
        { "Qprotect",       { "Qprotect", "QProtect", "mdma.dev/qprotect" } },
        { "Zelix",          { "ZKMFLOW", "ZKM", "ZelixKlassMaster", "com/zelix" } },
        { "Stringer",       { "StringerJavaObfuscator", "com/licel/stringer" } },
        { "JNIC",           { "JNIC", "jnic.obf", "jnic-obfuscator" } },
        { "Scuti",          { "ScutiObf", "scuti.obf" } },
        { "Smoke",          { "SmokeObf", "smoke.obf" } },
    };

    static const std::vector<std::string> kKnownLegitModIds = {
        "vmp-fabric", "vmp", "lithium", "sodium", "iris", "fabric-api",
        "modmenu", "ferrite-core", "lazydfu", "starlight", "entityculling",
        "memoryleakfix", "krypton", "c2me-fabric", "smoothboot-fabric",
        "immediatelyfast", "noisium", "threadtweak",
    };

    static const std::vector<std::string> kMavenPrefixes = {
        "com_", "org_", "net_", "io_", "dev_", "gs_", "xyz_", "app_", "me_", "tv_", "uk_", "be_", "fr_", "de_",
    };

    static bool isSuspiciousNestedJarName(const std::string& jarBaseName) {
        std::string lower = toLowerStr(jarBaseName);
        if (lower.find_first_of("0123456789") != std::string::npos) return false;
        for (const auto& pfx : kMavenPrefixes) {
            if (lower.rfind(pfx, 0) == 0) return false;
        }
        if (jarBaseName.size() > 20) return false;
        return true;
    }

    // Per-class-name obfuscation stats, tallied across every .class file
    // found (including inside nested jars).
    struct ClassNameStats {
        int total = 0;
        int numeric = 0, unicode = 0, fullwidth = 0;
        int singleLetter = 0, twoLetter = 0;
        int gibberish = 0, noVowel = 0, confusion = 0;
        int singleCharPathSegs = 0;
        int maxConsecutiveSingleSegs = 0; // for "heavy obfuscation" (a/b/c.class style)
    };

    static void tallyClassName(const std::string& relPath, ClassNameStats& s) {
        s.total++;
        size_t slash = relPath.find_last_of('/');
        std::string fileName = (slash == std::string::npos) ? relPath : relPath.substr(slash + 1);
        std::string base = fileName.substr(0, fileName.size() - 6); // strip ".class"

        bool allDigits = !base.empty() && std::all_of(base.begin(), base.end(), [](unsigned char c) { return std::isdigit(c); });
        if (allDigits) s.numeric++;

        bool hasNonAscii = std::any_of(base.begin(), base.end(), [](unsigned char c) { return c >= 0x80; });
        if (hasNonAscii) s.unicode++;

        auto fwRuns = extractNormalizedFullwidthRuns(base);
        if (!fwRuns.empty()) s.fullwidth++;

        bool allAlpha = !base.empty() && std::all_of(base.begin(), base.end(), [](unsigned char c) { return std::isalpha(c); });
        if (allAlpha && base.size() == 1) s.singleLetter++;
        if (allAlpha && base.size() == 2) s.twoLetter++;

        bool confusionChars = !base.empty() && std::all_of(base.begin(), base.end(), [](unsigned char c) {
            return c == 'I' || c == 'l' || c == '1' || c == 'O' || c == '0';
        });
        bool allUnderscore = !base.empty() && std::all_of(base.begin(), base.end(), [](unsigned char c) { return c == '_'; });
        if (confusionChars || allUnderscore) s.confusion++;

        if (allAlpha && base.size() >= 3 && base.size() <= 8) {
            int vowels = (int)std::count_if(base.begin(), base.end(), [](unsigned char c) {
                c = std::tolower(c);
                return c == 'a' || c == 'e' || c == 'i' || c == 'o' || c == 'u';
            });
            if (vowels == 0) s.noVowel++;

            int longestConsonantRun = 0, run = 0;
            for (unsigned char c : base) {
                bool isVowel = strchr("aeiouAEIOU", c) != nullptr;
                run = isVowel ? 0 : run + 1;
                longestConsonantRun = std::max(longestConsonantRun, run);
            }
            double vowelRatio = (double)vowels / base.size();
            if (longestConsonantRun >= 3 && vowelRatio < 0.3) s.gibberish++;
        }

        // path-segment single-char tally, for both the "single-char package"
        // stat and the consecutive-run "heavy obfuscation" stat.
        std::vector<std::string> segs;
        std::string cur;
        for (char c : relPath.substr(0, slash == std::string::npos ? 0 : slash)) {
            if (c == '/') { segs.push_back(cur); cur.clear(); }
            else cur += c;
        }
        if (!cur.empty()) segs.push_back(cur);

        int consecutive = 0, maxConsecutive = 0;
        for (const auto& seg : segs) {
            if (seg.size() == 1) {
                s.singleCharPathSegs++;
                consecutive++;
                maxConsecutive = std::max(maxConsecutive, consecutive);
            } else {
                consecutive = 0;
            }
        }
        s.maxConsecutiveSingleSegs = std::max(s.maxConsecutiveSingleSegs, maxConsecutive);
    }

    // Recursively extracts nested jars found under META-INF/jars/ (the
    // Fabric "jar-in-jar" convention) so their classes get scanned too.
    static void extractNestedJars(const fs::path& root, int depthRemaining, std::vector<fs::path>& allExtractRoots) {
        if (depthRemaining <= 0) return;
        fs::path nestedDir = root / "META-INF" / "jars";
        if (!fs::exists(nestedDir)) return;

        std::error_code ec;
        for (auto& entry : fs::directory_iterator(nestedDir, ec)) {
            if (!entry.is_regular_file()) continue;
            if (toLowerStr(entry.path().extension().string()) != ".jar") continue;

            fs::path nestedOut = entry.path();
            nestedOut += L"_x";
            if (jarutil::extractArchive(entry.path(), nestedOut)) {
                allExtractRoots.push_back(nestedOut);
                extractNestedJars(nestedOut, depthRemaining - 1, allExtractRoots);
            }
        }
    }

    struct JarReport {
        std::string jarName;
        std::string modId;
        std::string modName;
        std::string modVersion;
        int classCount = 0;
        std::vector<Finding> findings;
        std::set<std::string> matchedStrings;
        std::optional<std::string> downloadSource; // friendly name, if Zone.Identifier present
    };

    static std::optional<std::string> readJsonStringField(const std::string& json, const std::string& field) {
        std::string key = "\"" + field + "\"";
        size_t idPos = json.find(key);
        if (idPos == std::string::npos) return std::nullopt;
        size_t colon = json.find(':', idPos + key.size());
        if (colon == std::string::npos) return std::nullopt;
        size_t q1 = json.find('"', colon + 1);
        size_t q2 = (q1 == std::string::npos) ? std::string::npos : json.find('"', q1 + 1);
        if (q1 == std::string::npos || q2 == std::string::npos) return std::nullopt;
        return json.substr(q1 + 1, q2 - q1 - 1);
    }

    static bool isKnownLegitModId(const std::string& modId) {
        if (modId.empty()) return false;
        std::string lower = toLowerStr(modId);
        return std::find(kKnownLegitModIds.begin(), kKnownLegitModIds.end(), lower) != kKnownLegitModIds.end();
    }

    static bool isHighConfidenceCheatString(const std::string& s) {
        static const std::vector<std::string> highConfidence = {
            "novaclient", "vape.gg", "vapeclient", "VapeLite", "meteor-client",
            "liquidbounce", "fdp-client", "AutoCrystal", "AutoHitCrystal",
            "Anchor Macro", "TriggerBot", "AimAssist", "SilentAim",
            "SelfDestruct", "AuthBypass", "LicenseCheckMixin", "dqrkis",
            "Dqrkis Client", "ArgonClient", "CatleanClient", "PrestigeClient",
            "dev.krypton", "skid.krypton", "phantom-refmap.json", "cheat-refmap.json",
        };
        return std::find(highConfidence.begin(), highConfidence.end(), s) != highConfidence.end();
    }

    inline JarReport scanSingleJar(const fs::path& jarPath) {
        JarReport report;
        report.jarName = jarPath.filename().string();

        if (auto url = jarutil::readDownloadHostUrl(jarPath)) {
            report.downloadSource = jarutil::classifyDownloadSource(*url);
        }

        fs::path extractRoot = jarutil::makeTempDir(jarPath.stem().wstring());
        if (!jarutil::extractArchive(jarPath, extractRoot)) {
            report.findings.push_back({ Severity::Warning, "Couldn't extract this jar for inspection (corrupt or unsupported archive)" });
            jarutil::removeDirBestEffort(extractRoot);
            return report;
        }

        std::vector<fs::path> extractRoots = { extractRoot };
        extractNestedJars(extractRoot, /*depth*/ 3, extractRoots);

        bool hasNestedJars = extractRoots.size() > 1;
        int outerClassCount = 0;
        {
            std::error_code ec;
            for (auto& e : fs::directory_iterator(extractRoot, ec)) {
                if (e.path().extension() == ".class") outerClassCount++;
            }
        }

        ClassNameStats stats;
        std::string contentSample;
        const size_t kSampleCap = 300000;
        bool runtimeExecFound = false, httpDownloadFound = false, httpExfilFound = false;
        std::set<std::string> fullwidthResolved;
        std::string outerModId;

        for (const auto& root : extractRoots) {
            std::error_code ec;
            for (auto it = fs::recursive_directory_iterator(root, fs::directory_options::skip_permission_denied, ec);
                 it != fs::recursive_directory_iterator(); it.increment(ec)) {
                if (ec) break;
                if (!it->is_regular_file()) continue;

                fs::path rel = it->path().lexically_relative(root);
                std::string relStr = rel.generic_string();
                std::string ext = toLowerStr(it->path().extension().string());
                std::string fname = it->path().filename().string();

                if (ext == ".class") {
                    tallyClassName(relStr, stats);
                    report.classCount++;
                } else if (relStr != "fabric.mod.json" && ext != ".json" && fname != "MANIFEST.MF") {
                    continue; // only inspect class files, mod metadata, and the manifest
                }

                std::string bytes = jarutil::readFileBytes(it->path());
                if (bytes.empty()) continue;

                if (relStr == "fabric.mod.json") {
                    if (auto id = readJsonStringField(bytes, "id")) {
                        outerModId = *id;
                        report.modId = *id;
                    }
                    if (auto name = readJsonStringField(bytes, "name")) report.modName = *name;
                    if (auto version = readJsonStringField(bytes, "version")) report.modVersion = *version;
                }

                // cheat-string content matching applies to class files, mod
                // metadata (fabric.mod.json etc.), and the manifest alike --
                // display strings and config keys can live in any of them.
                for (const auto& s : jarContentStrings) {
                    if (bytes.find(s) != std::string::npos) report.matchedStrings.insert(s);
                }
                for (const auto& s : jarNamePatterns) {
                    if (boundaryContains(relStr, s)) report.matchedStrings.insert(s);
                }

                if (ext == ".class") {
                    if (bytes.find("java/lang/Runtime") != std::string::npos &&
                        bytes.find("getRuntime") != std::string::npos &&
                        bytes.find("exec") != std::string::npos) {
                        runtimeExecFound = true;
                    }
                    if (bytes.find("openConnection") != std::string::npos &&
                        bytes.find("HttpURLConnection") != std::string::npos &&
                        bytes.find("FileOutputStream") != std::string::npos) {
                        httpDownloadFound = true;
                    }
                    if (bytes.find("openConnection") != std::string::npos &&
                        bytes.find("setDoOutput") != std::string::npos &&
                        bytes.find("getOutputStream") != std::string::npos &&
                        bytes.find("getProperty") != std::string::npos) {
                        httpExfilFound = true;
                    }

                    if (contentSample.size() < kSampleCap && bytes.size() < 100000) {
                        contentSample.append(bytes);
                        auto runs = extractNormalizedFullwidthRuns(bytes);
                        auto resolved = resolveFullwidthRuns(runs);
                        fullwidthResolved.insert(resolved.begin(), resolved.end());
                    }
                }
            }
        }

        for (const auto& r : extractRoots) jarutil::removeDirBestEffort(r);

        report.matchedStrings.insert(fullwidthResolved.begin(), fullwidthResolved.end());

        // ---- obfuscation heuristics (percent-of-classes thresholds, same
        // cutoffs as the PowerShell tool) ------------------------------
        if (stats.total >= 5) {
            auto pct = [&](int n) { return (int)((n * 100.0) / stats.total); };
            if (pct(stats.numeric) >= 20)  report.findings.push_back({ Severity::Warning, "Numeric class names -- " + std::to_string(pct(stats.numeric)) + "% of classes have numeric-only names" });
            if (pct(stats.unicode) >= 10)  report.findings.push_back({ Severity::Warning, "Unicode class names -- " + std::to_string(pct(stats.unicode)) + "% of classes use non-ASCII characters" });
            if (stats.fullwidth > 0)       report.findings.push_back({ Severity::Danger, "Fullwidth Unicode class names -- " + std::to_string(stats.fullwidth) + " classes use lookalike full-width characters to evade string scans" });
            if (stats.total >= 10 && pct(stats.singleLetter) >= 15) report.findings.push_back({ Severity::Warning, "Single-letter class names -- " + std::to_string(pct(stats.singleLetter)) + "%" });
            if (stats.total >= 10 && pct(stats.twoLetter) >= 20)    report.findings.push_back({ Severity::Warning, "Two-letter class names -- " + std::to_string(pct(stats.twoLetter)) + "%" });
            if (pct(stats.gibberish) >= 5)  report.findings.push_back({ Severity::Warning, "Gibberish class names -- " + std::to_string(pct(stats.gibberish)) + "% have no vowels / consonant clusters" });
            if (pct(stats.noVowel) >= 8)    report.findings.push_back({ Severity::Warning, "No-vowel class names -- " + std::to_string(pct(stats.noVowel)) + "%" });
            if (pct(stats.confusion) >= 3)  report.findings.push_back({ Severity::Warning, "Confusion-char names (Il1O0/_) -- " + std::to_string(pct(stats.confusion)) + "%" });
            if (stats.singleCharPathSegs >= 6) report.findings.push_back({ Severity::Warning, "Single-char package paths -- " + std::to_string(stats.singleCharPathSegs) + " path segments like a/b/c" });
            if (stats.total >= 10 && stats.maxConsecutiveSingleSegs >= 3) {
                report.findings.push_back({ Severity::Danger, "Heavy obfuscation -- deeply nested single-letter package path (a/b/c/... style)" });
            }
        }

        for (const auto& [obfName, markers] : kCheatObfuscators) {
            for (const auto& marker : markers) {
                if (contentSample.find(marker) != std::string::npos) {
                    report.findings.push_back({ Severity::Warning, "Known cheat obfuscator detected -- " + obfName + " (matched: " + marker + ")" });
                    break;
                }
            }
        }

        // ---- dangerous behavior / jar-structure checks ------------------
        if (runtimeExecFound) report.findings.push_back({ Severity::Danger, "Runtime.exec() call found -- can run arbitrary OS commands" });
        if (httpDownloadFound) report.findings.push_back({ Severity::Danger, "HTTP file download call found -- fetches and writes files from a remote server at runtime" });
        if (httpExfilFound) report.findings.push_back({ Severity::Danger, "HTTP POST exfiltration call found -- sends data to an external server" });

        if (hasNestedJars) {
            std::error_code ec;
            for (auto& entry : fs::directory_iterator(extractRoot / "META-INF" / "jars", ec)) {
                std::string base = entry.path().stem().string();
                if (isSuspiciousNestedJarName(base)) {
                    report.findings.push_back({ Severity::Warning, "Suspicious nested JAR -- no version, unknown dependency: " + entry.path().filename().string() });
                }
            }
            if (extractRoots.size() == 2 && outerClassCount < 3) {
                report.findings.push_back({ Severity::Danger, "Hollow shell -- only " + std::to_string(outerClassCount) + " own class(es), wraps a nested jar entirely" });
            }
        }

        bool hasDangerFinding = std::any_of(report.findings.begin(), report.findings.end(), [](const Finding& f) { return f.severity == Severity::Danger; });
        bool knownLegitMod = isKnownLegitModId(outerModId);
        if (!outerModId.empty() && hasDangerFinding && knownLegitMod) {
            report.findings.push_back({ Severity::Danger, "Fake mod identity -- claims to be '" + outerModId + "' but contains dangerous code" });
        }

        if (!report.matchedStrings.empty()) {
            bool anyHighConfidence = std::any_of(report.matchedStrings.begin(), report.matchedStrings.end(), isHighConfidenceCheatString);
            if (knownLegitMod && !hasDangerFinding) {
                report.matchedStrings.clear();
            } else if (anyHighConfidence || report.matchedStrings.size() >= 2 || hasDangerFinding) {
                report.findings.push_back({ Severity::Danger, std::to_string(report.matchedStrings.size()) + " cheat/macro identifier(s) matched -- see list below" });
            } else {
                report.matchedStrings.clear();
            }
        }

        return report;
    }

    inline void printReport(const JarReport& r) {
        if (r.findings.empty() && !r.downloadSource) return;

        // Count severity for the header label
        int dangers  = 0, warnings = 0;
        for (const auto& f : r.findings) {
            if (f.severity == Severity::Danger)  dangers++;
            if (f.severity == Severity::Warning) warnings++;
        }

        // Header: jar name + severity badge
        std::cout << "\n";
        con::divider('-', 60, con::Color::DarkGray);
        con::set(dangers > 0 ? con::Color::Red : con::Color::Yellow);
        std::cout << "  JAR: " << r.jarName;
        con::set(con::Color::Gray);
        std::cout << "  (" << dangers << " danger, " << warnings << " warning)\n";
        con::divider('-', 60, con::Color::DarkGray);
        con::reset();

        if (r.downloadSource) {
            con::dim("Downloaded via: " + *r.downloadSource);
        }
        if (!r.modId.empty() || !r.modVersion.empty() || r.classCount > 0) {
            std::string meta = "Mod metadata:";
            if (!r.modName.empty()) meta += " name=" + r.modName;
            if (!r.modId.empty()) meta += " id=" + r.modId;
            if (!r.modVersion.empty()) meta += " version=" + r.modVersion;
            if (r.classCount > 0) meta += " classes=" + std::to_string(r.classCount);
            con::dim(meta);
        }

        for (const auto& f : r.findings) {
            if      (f.severity == Severity::Danger)  con::bad(f.text);
            else if (f.severity == Severity::Warning)  con::warn(f.text);
            else                                       con::info(f.text);
        }

        if (!r.matchedStrings.empty()) {
            std::string joined;
            int shown = 0;
            for (const auto& s : r.matchedStrings) {
                if (shown >= 25) { joined += " ..."; break; }
                if (shown++) joined += ", ";
                joined += s;
            }
            con::dim("Matches: " + joined);
        }
    }

    inline void runModsFolderScan(const std::wstring& modsPathStr) {
        fs::path modsPath(modsPathStr);
        std::error_code ec;
        if (!fs::exists(modsPath, ec) || !fs::is_directory(modsPath, ec)) {
            con::line("Invalid mods folder path.", con::Color::Red);
            return;
        }

        std::vector<fs::path> jars;
        for (auto& entry : fs::directory_iterator(modsPath, ec)) {
            if (!entry.is_regular_file()) continue;
            std::string ext = toLowerStr(entry.path().extension().string());
            if (ext == ".jar") jars.push_back(entry.path());
        }

        std::cout << "\nScanning " << jars.size() << " jar file(s) in " << modsPath.string() << "...\n";

        int flaggedCount = 0;
        for (const auto& jar : jars) {
            std::cout << "." << std::flush;
            JarReport r = scanSingleJar(jar);
            if (!r.findings.empty()) {
                flaggedCount++;
                printReport(r);
            }
        }

        std::cout << "\n\n";
        if (flaggedCount == 0) {
            con::line("No suspicious mods found.", con::Color::Green);
        } else {
            con::line(std::to_string(flaggedCount) + " of " + std::to_string(jars.size()) + " jar(s) flagged -- review the report above.", con::Color::Red);
        }
    }

} // namespace modscan
