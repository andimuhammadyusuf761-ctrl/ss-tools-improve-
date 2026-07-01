# Improved SS Tool (1.8.9 - 1.21.11)

Alat ini telah diperbarui untuk mendukung deteksi cheat Minecraft versi terbaru hingga **1.21.11**, dengan fokus khusus pada deteksi macro eksternal dan string client populer.

## Fitur Baru
1.  **Dukungan Versi Luas**: Mendukung Minecraft 1.8.9 hingga 1.21.11.
2.  **Deteksi Macro Khusus**:
    *   **198M Macros**: Deteksi string terkait 198M, 198m_back, dan 198m.com.
    *   **Zenith Macros**: Deteksi string unik seperti `PLACECHARGEEXPLODE`, `PLACECHARGEFLICKGLOW`, dan domain `zenithmacros.store`.
3.  **Process Scanner**: Menambahkan pemindaian proses eksternal untuk mendeteksi aplikasi macro (Zenith, 198M, AutoHotkey) yang berjalan di latar belakang.
4.  **Updated String Database**:
    *   **Combat**: AimAssist, AutoCrystal, CrystalAura, KillAura, TriggerBot, SilentAim, Reach, ReachHack, ShieldBreaker, ShieldDisabler, AutoTotem, AutoAnchor, DoubleAnchor, SafeAnchor, AirAnchor, AutoBed, BedAura, FastPlace, AutoClicker, AutoEat, AutoMine, GrimBypass, VulcanBypass, PacketMine, FakeLag, AutoHitCrystal, AnchorTweaks, NoBounce, FastXP, AutoBridge, WTap, FakeInv, PacketFly, AxeSpam, BowAimbot, dll.
    *   **Movement**: FlyHack, SpeedHack, BHop, NoKnockback, AntiKB, Freecam, XRayHack, PlayerESP, BlockESP, AutoGap, AutoPearl, dll.
    *   **Clients**: Meteor, Wurst, LiquidBounce, Aristois, Impact, Future, Argon (termasuk utilitas seperti AnimationUtils, BlockUtils, CrystalUtils, dll.), dll.

## Cara Penggunaan
1.  Jalankan alat dengan hak akses Administrator.
2.  Alat akan secara otomatis memindai proses yang mencurigakan di sistem.
3.  Alat akan secara otomatis mendeteksi **PID (Process ID)** dari `javaw.exe` (proses utama Minecraft). Jika tidak ditemukan, Anda akan diminta untuk memastikan Minecraft sedang berjalan.
4.  Pilih mode pemindaian:
    *   **1**: Nova Client
    *   **2**: Universal (Wurst, Meteor, LiquidBounce, dll.)
    *   **3**: Macros (198M, Zenith, AHK)
    *   **4**: Scan All (Semua database)
5.  Hasil akan menampilkan alamat memori di mana string terdeteksi.

## Disclaimer
Alat ini dibuat untuk tujuan edukasi dan bantuan dalam moderasi server (Screen Share). Penggunaan alat ini harus sesuai dengan kebijakan komunitas masing-masing.
    *   **Advanced/Process Hacker Detectable**: Deteksi string terkait manipulasi memori (`VirtualProtect`, `NtReadVirtualMemory`), injeksi (`CreateRemoteThread`, `LoadLibraryA`), hooking (`hooked`, `detour`), indikator obfuscation (`obfuscated`, `encrypted`), tanda-tanda debugger (`x64dbg`, `ollydbg`), dan pola bytecode Java yang mencurigakan (misalnya, `getMinecraft().player`, `onPacket`, `eventbus`).

### Cara Membuat `standalone.exe` (Visual Studio):
1.  Buka proyek `sstool.sln` di Visual Studio.
2.  Pilih konfigurasi `Release` dan platform `x64`.
3.  Klik kanan pada proyek `sstool` di Solution Explorer, lalu pilih `Properties`.
4.  Navigasi ke `Configuration Properties` -> `C/C++` -> `Code Generation`.
5.  Ubah `Runtime Library` menjadi `Multi-threaded (/MT)` untuk static linking.
6.  Navigasi ke `Configuration Properties` -> `Linker` -> `System`.
7.  Ubah `SubSystem` menjadi `Console (/SUBSYSTEM:CONSOLE)`.
8.  Navigasi ke `Configuration Properties` -> `Linker` -> `Advanced`.
9.  Set `Image Has Safe Exception Handlers` menjadi `No (/SAFESEH:NO)` (mungkin diperlukan untuk beberapa konfigurasi).
10. Bangun proyek (`Build Solution`). File `standalone.exe` akan ditemukan di folder `Release` atau `x64\Release`.

### Cara Membangun Secara Otomatis di GitHub:
1.  Buat repositori baru di GitHub.
2.  Unggah seluruh isi folder ini ke repositori tersebut.
3.  GitHub akan secara otomatis mendeteksi file `.github/workflows/build.yml`.
4.  Buka tab **Actions** di repositori GitHub Anda.
5.  Pilih workflow **Build Standalone EXE**.
6.  Setelah selesai, Anda dapat mengunduh file `.exe` dari bagian **Artifacts** di bawah ringkasan build.
