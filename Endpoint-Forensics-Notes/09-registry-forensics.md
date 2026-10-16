---
day: 09
title: 'Registry forensics: hive, last write time, hive kotor, zona waktu, jaringan, USB, autostart, dan akun lokal'
researched_on: 2026-10-16
versions_checked: 'Windows 11 23H2 (host kasus, build 22631) dan Windows 10/11 umumnya; Microsoft Learn Windows 11 release information (diperbarui 2026-10-13; 23H2 = build 22631, 24H2 = 26100, 25H2 = 26200); EZ Tools 2026.5.0 (RECmd .NET 4 dan .NET 9, Registry Explorer hanya .NET 9, RLA); RECmd DFIRBatch.reb v2.22; RegistryPlugins (KnownNetworks, USBSTOR, USB, SCSI, MountedDevices, WindowsPortableDevices, VolumeInfoCache, TaskCache, Services, SAM, SAMBuiltin, ProfileList, TimeZoneInformation); spesifikasi format file registry Windows (msuhanov/regf, format log baru sejak Windows 8.1); Microsoft Learn Registry Hives (ms.date 2018-05-31), RegQueryInfoKeyW, KEY_SET_INFORMATION_CLASS, TIME_ZONE_INFORMATION, Can''t set time zone automatically (ms.date 2026-02-12), Windows Time Service Tools and Settings (ms.date 2025-09-18), event 4616, DEVPKEY_Device_InstallDate dan FirstInstallDate (ms.date 2022-06-23), Services registry tree (ms.date 2024-09-18), Interactive logon cache (berlaku Windows 10 dan 11); Sysinternals Autoruns (dipublikasikan 2026-06-17); MITRE ATT&CK T1547.001 v2.1 (diubah 2026-05-12, ATT&CK v20)'
---

# Day 09: Registry forensics (hive, last write time, hive kotor, zona waktu, jaringan, USB, autostart, akun lokal)

Cakupan: membaca hive registry dari image atau koleksi triage untuk menjawab konfigurasi waktu host, jaringan yang pernah dipakai, perangkat penyimpanan yang pernah dicolok, autostart, dan akun lokal, termasuk cara menangani hive kotor, arti dan batas last write time, zona waktu yang berbeda antar parser, dan cara memisahkan jejak responder dari jejak pengguna dan penyerang.

## Ide inti

Registry adalah database konfigurasi Windows, bukan log. Ia menyimpan keadaan terakhir: jaringan apa yang pernah dikenal, perangkat apa yang pernah dipasang, program apa yang dijalankan saat boot atau logon, akun lokal apa yang ada. Waktu yang disimpannya sangat terbatas. Setiap key punya satu last write time, yaitu kapan key itu atau salah satu nilainya terakhir berubah; nilai sendiri tidak punya timestamp. Beberapa key menyimpan waktu di dalam nilainya, tetapi umumnya hanya "pertama" dan "terakhir", bukan riwayat lengkap, dan formatnya tidak seragam: sebagian UTC, sebagian waktu lokal host. Di atas itu, hive yang diambil dari sistem yang masih menyala sering kotor: perubahan terakhir masih di transaction log dan belum ditulis ke file hive. Karena itu setiap jawaban dari registry punya tiga bagian: nilai dan key yang dibaca dari hive yang sudah direkonsiliasi, apa arti waktunya (dan zonanya), dan artefak lain yang menguatkan atau membatasinya.

Kamu sudah mengenal pola ini dari NOC. `show running-config` di router menunjukkan konfigurasi saat ini, bukan siapa yang mengubah baris tertentu dan kapan; yang ada hanya satu cap "last configuration change" untuk seluruh blok. Tabel tetangga dan inventaris transceiver hanya menyimpan keadaan terakhir: SFP yang pernah dicolok tercatat, tetapi hanya waktu pasang dan cabut yang terakhir. Engineer yang membaca file startup-config dari flash tanpa tahu ada perubahan yang belum di-`write memory` akan melihat konfigurasi lama. Registry bekerja dengan logika yang sama, dengan satu perbedaan penting: perubahan yang "belum disimpan" ke hive tidak hilang, tetapi tersimpan di transaction log di sebelahnya, dan alat yang benar memainkannya ulang sebelum dibaca.

```
pertanyaan investigasi
  |
  v
PILIH HIVE      SYSTEM (waktu, USB, service) | SOFTWARE (jaringan, Run, task, profil)
                SAM (akun lokal) | NTUSER.DAT per user (Run user, MountPoints2)
  |
  v
REKONSILIASI    hive + .LOG1/.LOG2 -> replay (RECmd default, RLA, Registry Explorer)
                control set aktif dari Select\Current
  |
  v
BACA            nilai + last write key (UTC) + waktu di dalam nilai (UTC atau LOKAL?)
  |
  v
KORELASI        event log, $MFT, Prefetch, log jaringan, case notes responder
  |
  v
kalimat temuan: fakta | arti waktu dan zonanya | pelaku (pengguna, penyerang, responder) | batas
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan sekitar 1.200 karyawan dan data pribadi sekitar 400 ribu pelanggan broadband. Kasusnya `INC-2026-019`: email dari `billing@vendor-tagihan.example` dengan lampiran `Tagihan-Okt-2026.zip` (berisi `Tagihan-Okt-2026.js`) diterima sembilan mailbox Senin 2026-10-12 pukul 15:58, lalu dijalankan di tiga laptop staf penagihan. Laptop ketiga, `JKT-WS-0412` milik `rizky.saputra` (`10.10.41.23`, Windows 11, tanpa EDR, tanpa Sysmon, masih di OU lama dengan audit bawaan), dibawa rapat di luar kantor sejak Senin dan baru tersambung ke jaringan kantor Selasa 2026-10-13 pukul 17:10. DNS sinkhole menemukannya pukul 17:12, port switch-nya dimatikan pukul 17:20. Yoga Pratama, analyst L2 yang memegang bukti, mengambil memori laptop itu pukul 17:45 sampai 17:58 (E13) dengan WinPmem dari USB bukti `USB-E-10`, lalu login konsol dengan `adm.yoga` pukul 18:00 dan mengambil triage KAPE dari SSD eksternal `USB-E-11` pukul 18:02 sampai 18:29 (E14). Dari E14 sudah diketahui bahwa lampiran dijalankan Senin pukul 20:14:21 WIB (Prefetch `WSCRIPT.EXE`), `upd.ps1` dibuat 20:14:37, task `\SysCacheUpdate` terdaftar 20:14:39, dan event 4104 pertama tercatat 20:14:52 (Day 03 bagian 2.5). Laptop di-image Kamis 2026-10-15 pukul 09:00 (E16) lalu di-reimage. Memo retainer PT Forensik Digital Contoh menulis satu kalimat yang mengganjal: aktivitas laptop itu selama di luar kantor tidak terlihat di memori maupun log.

Rabu 2026-10-21 pukul 16:00 Yoga membuat salinan kerja internal `E16-W1` di `\\jkt-evid01\cases\INC-2026-019\work\` setelah memverifikasi hash master. Kamis 2026-10-22 pukul 09:00, Sari Kusuma (technical lead) yang sedang menyusun after-action report untuk post-incident review menulis kepadamu di kanal `#inc-2026-019`:

> "Pagi. E16-W1 sudah siap. Aku perlu beberapa jawaban dari registry laptop Rizky untuk after-action report. Pertama, retainer kirim daftar USB dari hive E14 dan isinya cuma flashdisk pribadi Rizky; USB Yoga tidak muncul sama sekali, padahal jelas dicolok. Kenapa beda, dan waktu dari registry sebenarnya bisa dipegang sejauh mana? Kedua, semua waktu Senin malam kita tulis WIB; tolong pastikan zona waktu dan jam laptop itu benar, karena laptopnya di luar kantor. Ketiga, laptop itu pakai jaringan apa saja dari Senin sampai Selasa 17:10? Keempat, perangkat USB apa saja yang pernah dicolok, dan pisahkan mana yang punya kita. Kelima, selain `\SysCacheUpdate`, ada autostart lain? Keenam, akun lokal: ada akun baru? Dan `ir-admin` dipakai kapan? Aku butuh sebelum jam 14:00."

Pesan itu memuat enam pertanyaan:

1. Kenapa hasil dari hive E14 berbeda dengan yang diharapkan, dan sejauh mana waktu dari registry bisa dipegang?
2. Apakah zona waktu dan jam laptop benar, sehingga waktu Senin malam bisa ditulis WIB?
3. Jaringan apa yang dipakai laptop dari Senin sampai Selasa 17:10?
4. Perangkat USB apa yang pernah dicolok, dan mana yang milik responder?
5. Adakah autostart lain selain `\SysCacheUpdate`?
6. Adakah akun lokal baru, dan kapan `ir-admin` dipakai?

Pertanyaan 1 dijawab di bagian 1.1 dan 1.2, pertanyaan 2 di bagian 1.3, pertanyaan 3 di bagian 1.4, pertanyaan 4 di bagian 1.5, pertanyaan 5 di bagian 1.6, dan pertanyaan 6 di bagian 1.7. Bagian 2 berisi perintah, hasil parse, dan jawaban yang kamu kirim ke Sari.

**Kapan relevan:** hampir setiap investigasi host Windows yang menanyakan konfigurasi dan riwayat mesin: zona waktu dan sumber waktu, jaringan dan lokasi, perangkat removable, autostart dan service, akun lokal dan profil, terutama di host tanpa EDR atau saat event log tidak mencatat kategori yang dibutuhkan.
**Kapan bukan jawaban:** untuk urutan kejadian yang rapat dan lengkap (registry hanya menyimpan pertama dan terakhir, event log dan `$J` lebih tepat; Day 05 dan Day 08), untuk membuktikan file disalin ke USB atau dibuka (aktivitas pengguna di Day 10, file system di Day 08), untuk isi koneksi jaringan (log jaringan, memori), dan untuk persistence di luar registry seperti WMI subscription atau file di folder Startup (Day 11).

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (salinan kerja, target dan module KAPE, RECmd dan batch file, BAM, UserAssist, Shimcache, `$MFT`, jejak responder) tidak diulang. Tabel ini memuat istilah registry yang dipakai Day ini; kolom padanan memakai analogi NOC dan SOC.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| Hive | File berisi satu kelompok key dan nilai registry (SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER.DAT per user) | Satu file konfigurasi per subsistem perangkat |
| Key dan value | Key adalah "folder" bertingkat; value adalah pasangan nama, tipe, dan data di dalam key | Blok konfigurasi dan baris di dalamnya |
| Last write time | Satu FILETIME UTC per key: kapan key atau salah satu nilainya terakhir berubah | Cap "last configuration change" untuk satu blok, tanpa tahu baris mana |
| Control set dan `Select\Current` | Hive SYSTEM menyimpan satu atau lebih `ControlSet00N`; `Select\Current` menunjuk yang dipakai saat boot terakhir | Pilihan startup-config mana yang dipakai saat boot |
| Transaction log (`.LOG1`, `.LOG2`) | File di sebelah hive yang menampung perubahan sebelum ditulis ke file hive utama | Journal commit yang belum ditulis ke startup-config |
| Hive kotor (dirty hive) | Hive yang belum merekonsiliasi perubahan di transaction log; dibaca tanpa replay, isinya tertinggal | Membaca startup-config dari flash padahal ada perubahan yang belum di-`write memory` |
| NetworkList profile | Key per jaringan yang pernah dikenal, dengan nama (SSID atau domain), tipe, kategori, dan waktu pertama serta terakhir tersambung | Riwayat uplink atau SSID yang pernah dipakai perangkat, hanya pertama dan terakhir |
| Device properties `{83da6326-...}` | Properti perangkat Plug and Play berisi waktu install, first install, last arrival, dan last removal | Log "transceiver inserted/removed" yang hanya menyimpan kejadian terakhir |
| `MountedDevices` dan `MountPoints2` | Pemetaan huruf drive dan volume GUID ke perangkat (sistem), dan volume yang di-mount di sesi user tertentu (per user) | Tabel port ke perangkat, dan sesi login yang aktif saat perangkat dicolok |
| Autostart registry | Lokasi registry yang membuat program berjalan saat boot atau logon: Run, RunOnce, Services, Winlogon, TaskCache | Startup-config dan skrip yang otomatis jalan saat perangkat boot |
| SAM dan RID | Hive akun lokal; setiap akun punya subkey menurut RID (bagian akhir SID) dengan nilai biner `F` dan `V` | Database user lokal perangkat (`username ... privilege`) |
| `ProfileList` | Key di SOFTWARE yang memetakan SID ke folder profil di `C:\Users` | Tabel pemetaan ID pelanggan ke nama |
| Cached logon | Verifier logon akun domain yang disimpan lokal supaya akun itu bisa login saat domain controller tidak terjangkau | Kredensial lokal cadangan saat server AAA tidak terjangkau |

### 1.1 Hive, lokasi, dan control set: dari pertanyaan ke file

Pertanyaan pertama Sari dimulai dari hal paling dasar: daftar USB retainer dibuat dari hive mana, dan apakah hive itu menjawab pertanyaan yang tepat.

Registry adalah basis data hierarkis tempat Windows dan aplikasi menyimpan konfigurasi, tersusun dari key, subkey, dan nilai [S3]. Hive adalah kelompok key, subkey, dan nilai registry dengan file pendukung yang dimuat saat Windows boot atau saat user login. Sebagian besar file pendukung hive sistem ada di `%SystemRoot%\System32\Config`; setiap user yang login mendapat hive profil sendiri (`Ntuser.dat`) yang muncul di bawah `HKEY_USERS` [S9]. Microsoft juga mencatat bahwa file tanpa ekstensi adalah salinan lengkap data hive, sedangkan ekstensi `.log` adalah transaction log perubahan [S9]. Tabel berikut memetakan hive ke pertanyaan; cari kolom kanan untuk tahu hive mana yang harus ada di koleksi sebelum mulai.

| Hive | Lokasi file | Pertanyaan yang dijawab di Day ini |
|---|---|---|
| SYSTEM | `C:\Windows\System32\config\SYSTEM` | Nama host, zona waktu, sumber waktu, service dan driver, perangkat USB dan SCSI, interface TCP/IP, huruf drive (`MountedDevices`), waktu shutdown terakhir |
| SOFTWARE | `...\config\SOFTWARE` | Versi OS, jaringan yang pernah dikenal (`NetworkList`), Run dan RunOnce mesin, TaskCache, Winlogon, `ProfileList`, Windows Portable Devices |
| SAM | `...\config\SAM` | Akun lokal, waktu logon terakhir, ganti password, jumlah logon, anggota grup lokal |
| SECURITY | `...\config\SECURITY` | Kebijakan keamanan lokal dan cached logon akun domain (tidak dibedah di Day ini) |
| NTUSER.DAT | `C:\Users\<user>\NTUSER.DAT` | Run dan RunOnce user, `MountPoints2` (volume yang di-mount di sesi user itu) |
| UsrClass.dat | `C:\Users\<user>\AppData\Local\Microsoft\Windows\UsrClass.dat` | ShellBags dan aktivitas user lain (Day 10) |

Hive sistem menjawab pertanyaan tentang mesin; hive user menjawab pertanyaan tentang sesi user tertentu [S1]. Konsekuensinya praktis: pertanyaan "USB mana yang dicolok" butuh SYSTEM dan SOFTWARE, sedangkan "di sesi siapa USB itu di-mount" butuh NTUSER.DAT setiap profil, termasuk profil akun responder.

Hive SYSTEM menyimpan control set (`ControlSet001`, kadang `ControlSet002`). Di host yang menyala, Windows menampilkan yang aktif sebagai `CurrentControlSet`; di hive offline nama itu tidak ada, jadi baca `SYSTEM\Select\Current` untuk tahu control set mana yang dipakai saat boot terakhir. Batch DFIRBatch RECmd memuat entri `Select` (nilai `Current`, `Default`, `Failed`, `LastKnownGood`) dan menulis banyak path dengan pola `ControlSet00*` sehingga semua control set ikut terbaca [S6]. Day 08 bagian 2.3 memakai langkah yang sama untuk `NtfsDisableLastAccessUpdate`.

Alat yang dipakai Day ini ada dua, dengan peran berbeda. RECmd adalah alat baris perintah untuk mencari dan mengekstrak registry dari banyak hive sekaligus dengan batch file dan plugin; Registry Explorer adalah penampil GUI dengan pencarian, dukungan banyak hive, plugin, dan kemampuan membuka file yang terkunci [S2]. Per 2026-10-16 keduanya versi 2026.5.0; RECmd tersedia untuk .NET 4 dan .NET 9, sedangkan Registry Explorer hanya .NET 9 karena alat GUI kini hanya menargetkan .NET 9 [S2]. Plugin RECmd ada di repo RegistryPlugins, termasuk `KnownNetworks`, `USBSTOR`, `USB`, `SCSI`, `MountedDevices`, `WindowsPortableDevices`, `VolumeInfoCache`, `TaskCache`, `Services`, `SAM`, `SAMBuiltin`, `ProfileList`, dan `TimeZoneInformation` [S7]. Plugin itulah yang menerjemahkan nilai biner menjadi kolom yang bisa dibaca; tanpa plugin, kamu hanya melihat byte.

### 1.2 Last write time dan hive kotor: apa yang bisa dipegang dari waktu registry

Daftar USB retainer kosong dari perangkat Yoga karena dua masalah yang sering datang bersamaan: hive E14 kotor, dan kueri yang dipakai hanya melihat satu key. Masalah kedua dibahas di bagian 1.5. Masalah pertama adalah dasar untuk semua waktu registry.

**Last write time.** Microsoft mendefinisikannya sebagai waktu terakhir key atau salah satu nilainya diubah [S11]. Spesifikasi format file registry menulis bahwa timestamp ini disimpan di key node sebagai FILETIME UTC, dan struktur value tidak punya field timestamp sama sekali [S10]. Tiga akibatnya:

- Last write time key `Run` pukul 20:14 berarti "sesuatu di key ini berubah pukul 20:14", bukan "nilai X ditambahkan pukul 20:14". Bila key punya banyak nilai, waktu itu tidak menunjuk nilai tertentu.
- Last write time yang lebih tua dari jendela insiden adalah petunjuk kuat bahwa key itu tidak diubah selama insiden, karena menambah, mengubah, atau menghapus nilai memperbaruinya.
- Petunjuk itu bukan bukti mutlak. API kernel menyediakan kelas `KeyWriteTimeInformation` untuk menetapkan write time sebuah key [S12], sehingga last write time bisa dipalsukan oleh kode yang punya hak cukup, sama seperti timestamp file (Day 08 bagian 1.3). Kuatkan dengan artefak lain.

Ada juga key yang last write time-nya berubah oleh Windows sendiri tanpa ada perubahan yang berarti bagi investigasi, misalnya karena pembaruan driver atau data runtime. Contohnya muncul di bagian 2.6 (key `Tasks\{GUID}` sebuah task). Karena itu last write time paling berguna bila dibaca bersama isi key: bila isinya hanya satu nilai yang relevan, waktunya bermakna; bila isinya data yang terus diperbarui, waktunya hanya menunjukkan pembaruan terakhir.

**Waktu di dalam nilai.** Beberapa key menyimpan waktu di dalam datanya, dan inilah sumber salah baca paling umum karena formatnya berbeda-beda. Tabel berikut adalah yang dipakai Day ini; perhatikan kolom zona, karena satu timeline yang mencampur kolom ini tanpa konversi akan bergeser tujuh jam di sebagian barisnya.

| Sumber waktu | Format | Zona | Rujukan |
|---|---|---|---|
| Last write time key | FILETIME | UTC | [S10][S11] |
| Device properties USB (`0064` sampai `0067`) | FILETIME (`DEVPROP_TYPE_FILETIME`) | UTC | [S23][S24][S26] |
| `NetworkList\Profiles` `DateCreated`, `DateLastConnected` | SYSTEMTIME 16 byte | Lokal host | [S8][S17][S18] |
| `Tcpip\...\Interfaces` `LeaseObtainedTime` | Detik sejak 1970-01-01 | UTC (epoch) | [S21] |
| SAM nilai `F` (last logon, password last set) | FILETIME | UTC (cek tampilan plugin) | [S34] |
| `Control\Windows` `ShutdownTime` | FILETIME | UTC | [S6] |
| `C:\Windows\INF\setupapi.dev.log` (file, bukan registry) | Teks `yyyy/mm/dd hh:mm:ss.sss` | Lokal host | [S30] |

**Hive kotor dan transaction log.** Menurut spesifikasi format, hive dianggap kotor bila checksum base block salah atau bila primary sequence number tidak sama dengan secondary sequence number; yang pertama dinaikkan di awal penulisan dan yang kedua di akhir, jadi keduanya sama setelah penulisan berhasil [S10]. Sejak Windows 8.1 dipakai format log baru: perubahan disimpan sebagai entri log di `.LOG1` dan `.LOG2` (Windows bergantian menulis ke keduanya), dan flush dianggap berhasil begitu data kotor tersimpan di log, sementara penulisan ke file hive utama bisa ditunda sampai sekitar satu jam [S10]. Selama jendela itu, perubahan terbaru hanya ada di log.

Itulah yang terjadi pada E14. Koleksi KAPE dimulai pukul 18:02, hanya 19 menit setelah `USB-E-10` dicolok (17:43) dan satu menit setelah `USB-E-11` dicolok (18:01). Data perangkat itu masih di transaction log SYSTEM dan NTUSER.DAT `adm.yoga` saat disalin. KAPE menyalin `.LOG1` dan `.LOG2` bersama hive, jadi datanya ada di E14; yang hilang adalah langkah replay di alat retainer. Sebaliknya, E16 diambil dari disk setelah laptop dimatikan normal Kamis pukul 08:44, sehingga hive-nya bersih. Satu prinsip kecil dari sini: perubahan yang lebih tua dari sekitar satu jam sebelum koleksi live biasanya sudah ada di hive utama; yang berisiko adalah perubahan menit-menit terakhir, dan pada koleksi IR menit terakhir sering berisi jejak responder sendiri.

Cara menangani hive kotor:

- RECmd membaca transaction log untuk hive kotor secara default; opsi `--nl` mematikannya [S5].
- RLA adalah alat tunggal untuk memainkan ulang transaction log dan menyimpan salinan hive yang sudah bersih ke folder `--out`, berguna untuk alat lain yang tidak bisa memproses log sendiri [S2][S5].
- Registry Explorer bisa menambahkan data dari transaction log ke hive saat dimuat [S39]. `[komunitas]` Panduan praktisi menyebut Registry Explorer menampilkan pertanyaan apakah log akan dimainkan ulang ketika hive kotor dimuat bersama `.LOG1` dan `.LOG2`; teks dialog dan perilakunya cek di versi lab-mu.
- Apa pun alatnya, replay dilakukan pada salinan di folder kerja, bukan pada salinan kerja yang di-mount read-only.

**Data yang sudah dihapus.** RECmd secara default memulihkan key dan value yang sudah dihapus (`--recover`, default true) [S5]. Spesifikasi format menyebut sel yang tidak teralokasi bisa memuat sisa beberapa record lama, dan transaction log bisa memuat sisa halaman kotor sebelumnya [S10]. Hasil pemulihan itu petunjuk, bukan keadaan resmi registry: tandai di laporan sebagai data terhapus yang dipulihkan.

### 1.3 Zona waktu dan jam host

Pertanyaan kedua Sari terdengar sederhana, tetapi berisi dua pertanyaan yang berbeda: zona waktu apa yang dipakai laptop, dan apakah jam laptop (jam UTC internalnya) benar saat itu.

**Zona waktu tidak mengubah waktu UTC.** Prefetch, `$MFT`, event log, dan last write time menyimpan FILETIME UTC. Waktu `WSCRIPT.EXE` di Prefetch E14 adalah 13:14:21 UTC; menuliskannya sebagai 20:14:21 WIB adalah konversi tetap UTC+7, tidak peduli zona apa yang dipasang di laptop. Zona waktu host baru penting untuk artefak yang menyimpan waktu lokal: `NetworkList`, `setupapi.dev.log`, waktu `RegistrationInfo` di XML task (Day 03 bagian 2.5), dan teks log aplikasi. Untuk artefak itu, salah zona menggeser waktu tanpa pesan galat apa pun.

**Membaca zona waktu.** Key `SYSTEM\ControlSet00N\Control\TimeZoneInformation` menyimpan zona host; batch DFIRBatch membacanya dengan plugin `TimeZoneInfo` [S6]. Nilai `Bias` mengikuti rumus Microsoft: UTC sama dengan waktu lokal ditambah bias, dalam menit [S13]. Untuk WIB (UTC+7), bias adalah -420 menit, tersimpan sebagai DWORD `0xFFFFFE5C`. Nama nilai lain di key ini (misalnya `TimeZoneKeyName` dan `ActiveTimeBias`) dibaca apa adanya dari hive; definisi setiap zona yang tersedia ada di `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Time Zones\<nama zona>` dengan nilai biner `TZI` [S13].

**Apakah zona bisa berubah sendiri saat laptop dibawa pergi?** Bisa, bila fitur "Set time zone automatically" aktif. Microsoft mendokumentasikan pengaturannya di `SYSTEM\CurrentControlSet\Services\tzautoupdate\Start`: nilai 3 mengaktifkan, nilai 4 mematikan; fitur ini juga bergantung pada izin lokasi di `SOFTWARE\Microsoft\Windows\CurrentVersion\CapabilityAccessManager\ConsentStore\location\Value` (`Allow` atau `Deny`) [S14]. Untuk laptop yang dibawa ke luar kota, baca keduanya: bila `tzautoupdate` mati, zona tidak berpindah otomatis dan last write time `TimeZoneInformation` membantu memastikan tidak ada perubahan manual di jendela insiden.

**Apakah jam laptop benar?** Registry hanya memberi konfigurasinya. Workstation domain biasanya bertipe NT5DS, artinya menyinkronkan waktu dari hierarki domain; nilainya di `SYSTEM\CurrentControlSet\Services\W32Time\Parameters\Type` (NT5DS, NTP, AllSync, atau NoSync) [S15]. Di luar kantor tanpa VPN, laptop NT5DS tidak bisa menghubungi domain controller, sehingga jamnya berjalan sendiri dari jam perangkat keras. Dokumentasi Microsoft juga menyebut fitur secure time seeding (`UtilizeSslTimeData`, default 1 di Windows klien) yang bisa memakai timestamp SSL untuk mengoreksi jam yang sangat meleset [S15]. Bukti bahwa jam tidak melompat diambil dari luar registry:

- Event 4616 ("system time was changed") selalu dicatat, terlepas dari pengaturan subcategory Audit Security State Change, dan perubahan rutin oleh Windows Time service tercatat dengan Subject `LOCAL SERVICE` dari `svchost.exe` [S16][S38]. Karena tidak bergantung pada GPO audit, event ini tetap ada di laptop dengan audit bawaan seperti `JKT-WS-0412`.
- Koreksi kecil tidak selalu menghasilkan 4616: bila selisih di bawah `MaxAllowedPhaseOffset` (default 300 detik untuk anggota domain), W32Time menyesuaikan jam perlahan lewat clock rate, bukan menyetel langsung [S15]. Ketiadaan 4616 berarti tidak ada lompatan besar, bukan selisih nol.
- Selisih nyata diukur dengan membandingkan waktu yang ditulis laptop dengan sumber luar yang tersinkron: konteks waktu yang dicatat responder (Day 01 bagian 2.1) dan, untuk saat laptop tersambung ke jaringan kantor, waktu lease DHCP di registry (`LeaseObtainedTime`, detik sejak 1970 [S21]) dibandingkan log DHCP server.

### 1.4 Jaringan: NetworkList, interface, dan sesi

Pertanyaan ketiga Sari adalah inti kalimat retainer "tidak terlihat di log": laptop memakai jaringan yang tidak lewat proxy, DNS, atau firewall PT JAB. Registry bisa menunjukkan jaringan apa saja itu.

**`NetworkList\Profiles`.** Di `SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles\{GUID}` ada satu key per jaringan yang pernah dikenal, dengan `ProfileName` (SSID untuk Wi-Fi, nama domain untuk jaringan domain), `Description`, `NameType`, `Category`, `DateCreated`, dan `DateLastConnected` [S19][S20]. `DateCreated` adalah waktu pertama sistem tersambung ke jaringan itu dan `DateLastConnected` waktu terakhir tersambung [S19]. Arti kode yang dipakai praktisi: `NameType` `0x47` Wi-Fi, `0x06` kabel, `0x17` broadband seluler; `Category` 0 Public, 1 Private, 2 Domain [S18][S19][S20]. Satu penyusun skrip forensik menyebut kode `NameType` itu berasal dari internet dan belum bisa ia validasi sendiri [S20], jadi anggap sebagai kesepakatan praktisi dan cocokkan dengan sumber lain (nama jaringan, event log).

**Waktu NetworkList adalah waktu lokal.** API Network List Manager mengembalikan waktu dibuat dan waktu tersambung sebagai waktu lokal [S17], praktisi menulis bahwa nilai di registry disimpan sebagai waktu lokal, bukan UTC [S18], dan plugin `KnownNetworks` RECmd membuat tanggal dari SYSTEMTIME tanpa konversi dengan keterangan bahwa waktu ditampilkan dalam waktu lokal [S8]. Akibatnya, kolom ini adalah satu-satunya kolom di output RECmd Day ini yang tidak UTC. Di laptop ber-zona WIB, `DateLastConnected` 15:52 berarti 15:52 WIB, bukan 22:52 WIB.

**`Signatures`.** Di `NetworkList\Signatures\Managed` dan `\Unmanaged` ada entri yang dihubungkan ke profil lewat `ProfileGuid`, dengan `DefaultGatewayMac`, `DnsSuffix`, dan `FirstNetwork` [S8][S20]. MAC gateway berguna untuk membedakan dua jaringan dengan SSID sama, dan praktisi menyebut MAC itu bisa dipakai menemukan lokasi fisik access point [S18]. Mengirim MAC ke basis data lokasi pihak ketiga berarti membocorkan data kasus; lakukan hanya bila perlu dan disetujui.

**Batas utama: hanya pertama dan terakhir.** Profil tidak menyimpan setiap sesi; di antara `DateCreated` dan `DateLastConnected` bisa ada banyak sesi yang tidak tercatat di key ini [S19]. Selain itu, `DateLastConnected` adalah awal sesi terakhir, bukan akhirnya: sesi yang dimulai 15:52 bisa berlangsung sampai jauh setelahnya. Untuk sesi dan waktu putus, pakai event log. Microsoft mendokumentasikan event WLAN-AutoConfig 8000 (mulai menyambung ke jaringan nirkabel, dengan nama profil dan SSID) dan 8002 (gagal menyambung) [S22]. `[komunitas]` Event sukses tersambung dan terputus di channel `Microsoft-Windows-WLAN-AutoConfig/Operational` lazim disebut 8001 dan 8003 oleh praktisi; cek ID dan isi field-nya di image dan di lab sebelum ditulis di laporan.

**Interface TCP/IP.** `SYSTEM\ControlSet00N\Services\Tcpip\Parameters\Interfaces\{GUID}` menyimpan konfigurasi IP per adapter, termasuk alamat dari DHCP (`DhcpIPAddress`), server DHCP (`DhcpServer`), dan waktu lease (`LeaseObtainedTime`, `LeaseTerminatesTime`) dalam detik sejak tengah malam 1 Januari 1970 [S21]; DFIRBatch membaca key ini sebagai "Network Configuration (IPv4)" [S6]. Dokumentasi yang menjelaskan nilai lease ini berasal dari era Windows Server 2003; formatnya di Windows 11 cek di lab sebelum dipakai untuk kesimpulan presisi detik. Key ini hanya menyimpan lease terakhir per adapter, jadi adapter Wi-Fi menunjukkan jaringan Wi-Fi terakhir, bukan semua.

**Volume data per jaringan.** SRUM mencatat pemakaian jaringan per aplikasi per jam dan bisa dipetakan ke profil jaringan dengan bantuan hive SOFTWARE (Day 07 bagian 1.6). Registry menjawab "jaringan apa", SRUM menjawab "berapa banyak dan aplikasi apa".

### 1.5 USB dan perangkat penyimpanan

Pertanyaan keempat Sari meminta dua hal: daftar perangkat, dan pemisahan perangkat milik responder. Bagian ini juga menjelaskan masalah kedua di daftar retainer.

**Rantai key.** Tidak ada satu key yang menjawab "perangkat apa, kapan, huruf drive apa, di sesi siapa". Rantainya [S26][S27][S28]:

1. `SYSTEM\ControlSet00N\Enum\USBSTOR`: perangkat penyimpanan USB kelas mass storage, dengan nama vendor dan produk di nama key dan nomor seri di nama subkey.
2. `SYSTEM\ControlSet00N\Enum\USB`: perangkat USB berdasarkan VID dan PID, termasuk yang bukan penyimpanan.
3. `SOFTWARE\Microsoft\Windows Portable Devices\Devices` dan `SOFTWARE\Microsoft\Windows Search\VolumeInfoCache`: nama ramah dan label volume; DFIRBatch membaca keduanya dengan plugin masing-masing [S6][S28].
4. `SYSTEM\MountedDevices`: pemetaan huruf drive (`\DosDevices\E:`) dan volume GUID ke perangkat [S28].
5. `NTUSER.DAT\Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2`: volume GUID yang di-mount di sesi user itu; DFIRBatch membacanya per NTUSER [S6].
6. Di luar registry: `setupapi.dev.log` untuk pemasangan pertama (waktu lokal [S30]) dan event log.

**Perangkat UASP tidak selalu ada di USBSTOR.** `[komunitas, belum terkonfirmasi dokumentasi Microsoft]` Drive yang memakai protokol USB Attached SCSI (driver `uaspstor.sys`, banyak SSD eksternal USB 3) terdaftar di `Enum\SCSI`, bukan `Enum\USBSTOR`, sehingga kueri yang hanya membaca USBSTOR melewatkan perangkat yang paling relevan untuk kasus exfiltration [S29]. DFIRBatch sendiri memuat entri `Enum\SCSI` dengan plugin `SCSI` di kategori Devices, di samping USBSTOR dan USB [S6]. Uji di lab dengan SSD UASP sebelum mengandalkan perilaku ini; yang pasti, kueri USB harus membaca ketiga key.

**Waktu per perangkat.** Last write time key perangkat tidak bisa diandalkan untuk waktu colok, karena hanya menunjukkan perubahan terakhir pada key itu [S26]. Waktu yang lebih tepat ada di properti perangkat `Properties\{83da6326-97a6-4088-9453-a1923f573b29}\<nomor>`. Nomor subkey adalah property ID dalam heksadesimal, dan definisinya ada di header `devpkey.h`: 100 (`0064`) `DEVPKEY_Device_InstallDate`, 101 (`0065`) `DEVPKEY_Device_FirstInstallDate`, 102 (`0066`) `DEVPKEY_Device_LastArrivalDate`, 103 (`0067`) `DEVPKEY_Device_LastRemovalDate` [S25]. Microsoft mendefinisikan InstallDate sebagai waktu instance perangkat terakhir di-install, yang berubah setiap kali driver diperbarui (misalnya lewat Windows Update), sedangkan FirstInstallDate tidak berubah oleh pembaruan driver [S23][S24]. Jadi untuk "kapan pertama kali dicolok", pakai `0065`, bukan `0064`. Semua nilai ini FILETIME UTC [S23][S26]. Tetap hanya terakhir: `0066` dan `0067` menyimpan colok dan cabut terakhir, bukan riwayat [S26][S27].

**Nomor seri.** Serial yang karakter keduanya `&` adalah serial buatan Windows karena perangkat tidak melaporkan serial unik; serial seperti ini tidak bisa dicocokkan ke perangkat fisik dengan yakin [S1]. Praktisi memperlakukan heuristik ini sebagai indikator, bukan identifikasi pasti [S26].

**Volume serial dari event log.** Channel `Microsoft-Windows-Partition/Diagnostic` event 1006 memuat salinan boot record (`Vbr0`) volume yang tersambung, dan nomor seri volume (VSN) bisa dibaca dari offset `0x48` untuk NTFS, `0x43` untuk FAT32, dan `0x64` untuk exFAT [S26]. VSN inilah yang bisa dicocokkan dengan LNK dan Jump List (Day 10) atau dengan catatan toolkit responder. Ketersediaan channel bergantung build dan konfigurasi, dan log bisa berputar [S26]. Channel DriverFrameworks-UserMode/Operational mati secara default, jadi umumnya tidak bisa diandalkan [S27].

**Siapa yang mencolok.** `MountPoints2` membuktikan volume itu di-mount di profil user tertentu, bukan siapa yang memegang perangkatnya [S27]. Ini penting untuk jejak responder: USB yang dicolok Yoga saat sesi Rizky masih terbuka akan muncul di `MountPoints2` milik Rizky. Pemisahannya dilakukan dengan case notes, label volume, VSN, dan waktu, sama seperti pemisahan jejak responder di Day 07 bagian 1.5.

**Batas paling penting.** Registry dan log membuktikan perangkat dikenali atau di-mount, bukan file apa yang disalin [S26][S27]. Untuk pertanyaan file, lanjutkan ke LNK, Jump List, ShellBags (Day 10) dan file system (Day 08).

### 1.6 Autostart di registry: Run keys, services, dan TaskCache

Pertanyaan kelima Sari adalah pertanyaan eradication: bila ada persistence kedua selain `\SysCacheUpdate`, reimage tetap menghapusnya, tetapi laporan harus menyebutnya dan IOC-nya harus dicari di host lain.

**Run dan RunOnce.** MITRE ATT&CK T1547.001 mencantumkan `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` dan `RunOnce`, `HKLM\Software\Microsoft\Windows\CurrentVersion\Run` dan `RunOnce`, `RunOnceEx` (tidak dibuat default sejak Vista), `RunServices` dan `RunServicesOnce`, `Policies\Explorer\Run` di HKLM dan HKCU, nilai `load` di `HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows`, `BootExecute` di `Session Manager`, dan pengalihan folder Startup lewat `User Shell Folders` dan `Shell Folders` [S4]. DFIRBatch memuat Run dan RunOnce untuk SOFTWARE (termasuk `WOW6432Node`) dan NTUSER, serta `Policies\Explorer\Run` di kategori Autoruns [S6]. Key HKLM ada di hive SOFTWARE; key HKCU ada di NTUSER.DAT setiap user, jadi baca semua profil.

**Winlogon dan Image File Execution Options.** DFIRBatch membaca nilai `Shell` dan `Userinit` di `Microsoft\Windows NT\CurrentVersion\WinLogon` (SOFTWARE dan NTUSER) serta `Image File Execution Options\*` dan `SilentProcessExit\*` di kategori Threat Hunting [S6]. Winlogon dibahas ATT&CK sebagai sub-teknik terpisah, T1547.004 [S4].

**Services.** `HKLM\SYSTEM\CurrentControlSet\Services\<nama>` menyimpan informasi setiap service dan driver. Nilai `Start` menentukan kapan dimuat (`0x0` boot, `0x1` system, `0x2` automatic, `0x3` demand, `0x4` disabled), `Type` menentukan jenisnya (`0x1` kernel driver, `0x2` file system driver, `0x10` Win32 own process, `0x20` Win32 share process), dan `ImagePath` menunjuk binary [S32]. DFIRBatch membacanya dengan plugin `Services` [S6]. Yang dicari: service atau driver dengan last write time di jendela insiden, `ImagePath` di lokasi yang bisa ditulis user, atau binary yang menjalankan interpreter.

**TaskCache.** Setiap scheduled task membuat dua key di `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache`: `Tree\<nama task>` dengan nilai `Id`, `Index`, dan `SD`, dan `Tasks\{GUID}` (GUID sama dengan `Id`) berisi detail eksekusi seperti Actions dan Triggers; salinan XML task ada di `C:\Windows\System32\Tasks` [S31]. Microsoft juga mendokumentasikan teknik menyembunyikan task dengan menghapus nilai `SD` dari key Tree, yang membuat task hilang dari `schtasks /query` dan Task Scheduler tetapi tetap terlihat di registry; rekomendasinya adalah memeriksa key Tree yang tidak punya `SD` [S31]. DFIRBatch membaca `TaskCache\Tasks` dengan plugin `TaskCache` [S6]. Di laptop tanpa 4698 dan tanpa channel TaskScheduler (Day 05 bagian 2.7), TaskCache dan file XML adalah sumber utama tentang task.

**Kriteria membaca.** Lokasi user-writable (`%APPDATA%`, `%TEMP%`, `C:\Users\Public`, `C:\ProgramData`), interpreter dengan argumen panjang (`powershell.exe -enc`, `mshta.exe`, `rundll32.exe` dengan DLL di folder user), dan nama yang meniru proses sistem adalah alasan untuk memeriksa, bukan vonis. OneDrive per-user, misalnya, sah walaupun berjalan dari `AppData\Local`. Vonis datang dari pembanding: image standar IT, entri yang sama di host lain (hunt Day 04), tanda tangan dan hash binary.

**Autoruns untuk sistem offline.** Autorunsc, versi baris perintah Autoruns, bisa menampilkan hampir semua kategori autostart (`-a *`), menghitung hash (`-h`), memverifikasi tanda tangan (`-s`), mencetak CSV (`-c`), menampilkan timestamp UTC (`-t`), dan menerima `-z` untuk menentukan sistem Windows offline yang dipindai [S33]. Itu pembanding yang baik untuk hasil RECmd, karena cakupan kategorinya lebih luas (termasuk WMI dan scheduled task). Folder Startup dan WMI subscription bukan registry; keduanya dibahas di Day 11.

### 1.7 Akun lokal: SAM, ProfileList, dan cached logon

Pertanyaan keenam Sari punya dua bagian: apakah penyerang membuat akun lokal, dan kapan akun responder dipakai.

**SAM.** Di `SAM\Domains\Account\Users` setiap akun punya subkey bernama RID dengan nilai biner `F` dan `V`, ditambah subkey `Names` [S34]. Menurut dokumentasi format, nilai `F` memuat antara lain last logon (offset 8), password last set (24), account expires (32, dengan `0x7fffffffffffffff` berarti tidak pernah), last password failure (40), RID (48), user account control flags (56), jumlah password gagal (64), dan jumlah logon (66), semuanya FILETIME untuk field waktu [S34]. Nilai `V` memuat username, full name, comment, profile path, dan hash LM serta NTLM [S34]. RID 500 adalah Administrator bawaan, 501 Guest, dan akun buatan mulai sekitar 1000 [S1]. RECmd menerjemahkan semuanya lewat plugin `SAM`, sedangkan keanggotaan grup bawaan seperti Administrators dibaca lewat `SAMBuiltin` [S6][S7].

Batas SAM:

- SAM hanya akun lokal. Akun domain tidak ada di sana; aktivitasnya di host terlihat dari event log, `ProfileList`, dan folder profil.
- Nilai `V` memuat hash password akun lokal [S34]. Image disk yang berisi SAM dan SYSTEM adalah bukti yang berisi kredensial; perlakukan aksesnya seperti data sensitif.
- Celah nomor RID bukan indikasi sendiri, karena RID juga dipakai objek lain seperti grup lokal. Bandingkan dengan host lain dari image yang sama.

**ProfileList.** `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList` memetakan SID ke path profil (`ProfileImagePath`); DFIRBatch membacanya dengan plugin `ProfileList` [S6][S7]. Ini cara cepat menerjemahkan SID di event log, BAM, atau Recycle Bin ke nama user (Day 08 bagian 2.5 memakainya untuk SID Andi). Waktu pembuatan folder profil di `$MFT` (Day 08) memberi perkiraan kapan akun pertama kali login di host itu.

**Cached logon.** Akun domain bisa login tanpa domain controller bila informasi logonnya pernah di-cache di host itu. Default efektif di komputer klien adalah 10 logon; informasi itu tidak kedaluwarsa, hanya tertimpa oleh user ke-11, dan Microsoft menyebut penyerang yang bisa membaca file system bisa mencoba brute force atas informasi yang di-cache itu [S35]. Dokumentasi menyebut data itu dienkripsi dan disimpan di registry sistem tanpa merinci lokasinya [S35]. Untuk forensik, dua hal penting: logon akun domain di laptop yang terputus dari jaringan hanya mungkin bila akun itu pernah login di sana, dan image laptop menyimpan verifier logon semua akun yang di-cache, termasuk akun admin responder.

## 2. Contoh artefak dan langkah praktis di PT JAB

Semua isi bagian ini fiktif dan merupakan keluaran ilustrasi. Nama kolom CSV dan format nilai bisa berbeda antar versi RECmd dan plugin; cocokkan dengan versi di lab-mu. Output RECmd memakai UTC kecuali kolom NetworkList yang memakai waktu lokal host (bagian 1.4); laporan PT JAB memakai WIB (UTC+7), jadi setiap waktu penting ditulis keduanya sekali. Perintah ditulis untuk lingkungan PT JAB; untuk latihan, jalankan hanya di VM lab terisolasi (bagian 3).

### 2.1 Menyiapkan E16-W1 dan mengambil hive

Langkah ini menyiapkan bahan untuk semua jawaban ke Sari. Pukul 09:12 kamu memverifikasi hash `E16-W1` (cocok dengan master, `d3a8...`), lalu me-mount volume sistemnya read-only sebagai `G:` di `JKT-DFIR01` dengan alat mount image yang sudah tercatat di inventaris alat (prinsipnya di Day 02 bagian 1.5). Hive dan event log diambil dengan KAPE ke folder kerja lokal supaya ada copylog dengan SHA-1 setiap file.

```
C:\DFIR\tools\KAPE\kape.exe --tsource G: --target RegistryHives,EventLogs --tdest C:\DFIR\work\INC-2026-019\E16-W1\reg --tflush
```

- `--tsource G:`: volume sistem E16-W1 yang di-mount read-only.
- `--target RegistryHives,EventLogs`: hive sistem dan user beserta transaction log-nya, dan file `.evtx`. Target `RegistryHives` sudah dipakai di Day 08 bagian 2.1; isi persis kedua target cek dengan `kape.exe --tdetail` di versi KapeFiles yang dibekukan untuk kasus ini.
- `--tdest ... --tflush`: folder baru khusus E16-W1, aman dikosongkan.

Variabel PowerShell yang dipakai ulang di bagian 2.2 sampai 2.7:

```powershell
$ez  = 'C:\DFIR\tools\EZTools-2026-10-15'                        # EZ Tools 2026.5.0, dibekukan selama kasus
$e16 = 'C:\DFIR\work\INC-2026-019\E16-W1\reg\G'                   # hasil Targets; nama subfolder volume cek di hasil KAPE
$e14 = 'C:\DFIR\work\INC-2026-019\E14-W1\reg'                     # hive dari E14-W1 (disalin dari F: read-only)
$out = '\\jkt-evid01\cases\INC-2026-019\analysis\E16-W1\EZ-2026.5.0\Registry'
```

Case notes untuk langkah ini:

```
INC-2026-019 | Case notes forensik | <kamu> | TZ catatan: UTC+7 (WIB)
2026-10-22 09:00  Permintaan Sari: zona waktu/jam, jaringan Senin-Selasa 17:10, USB, autostart lain,
                  akun lokal JKT-WS-0412 dari E16-W1; tenggat 14:00.
2026-10-22 09:12  E16-W1: hash cocok dengan master E16 (d3a8...). Mount read-only sebagai G:.
2026-10-22 09:20  KAPE Targets RegistryHives,EventLogs -> reg lokal. Selesai 09:23, 214 file.
                  Konteks dari case notes lain (Yoga, Selasa 13 Okt):
                  17:43 USB-E-10 dicolok di sesi rizky.saputra (sesi masih terbuka);
                  17:44 elevasi UAC dengan ir-admin untuk WinPmem; 17:45-17:58 memori E13; 17:59 USB-E-10 dicabut;
                  18:00 login konsol adm.yoga; 18:01 USB-E-11 dicolok; 18:02-18:29 KAPE E14; 18:35 USB-E-11 dicabut.
                  Kamis 15 Okt 08:40 konteks waktu (+3 s vs jam analyst), laptop dimatikan normal, 09:00 image E16.
2026-10-22 09:30  Mulai parsing (2.2-2.7).
```

**Cara membaca hasil:** baris 09:20 adalah daftar tindakan responder yang akan dicari di registry. Setiap jejak yang cocok dengan baris itu diberi label responder di bagian 2.8, bukan dihapus.

**Kapan gagal:** hive diambil tanpa `.LOG1` dan `.LOG2`, misalnya dengan menyalin file hive saja dari image. Untuk E16 itu tidak terlalu berbahaya karena hive bersih, tetapi kebiasaan itu fatal untuk koleksi live seperti E14 (bagian 2.2).

### 2.2 RECmd dengan DFIRBatch, dan kenapa E14 berbeda

Langkah ini menjawab pertanyaan pertama Sari. Pertama, parse semua hive E16-W1 dengan batch DFIRBatch.

```powershell
& "$ez\RECmd\RECmd.exe" -d "$e16" --bn "$ez\RECmd\BatchExamples\DFIRBatch.reb" --csv "$out" --csvf E16-W1_RECmd.csv
```

- `-d`: mencari hive secara rekursif di folder hasil KAPE, jadi SYSTEM, SOFTWARE, SAM, SECURITY, dan semua NTUSER.DAT diproses sekaligus [S5].
- `--bn`: batch file yang menentukan key dan nilai yang dibaca; wajib bersama `--csv` [S5]. `DFIRBatch.reb` v2.22 memuat entri yang dipakai Day ini dengan kategori System Info, Devices, Autoruns, Services, User Accounts, dan Threat Hunting [S6].
- `--csvf`: nama file CSV; kolom kategori di dalamnya dipakai untuk memfilter per bagian di bawah. Lokasi folder `BatchExamples` di hasil Get-ZimmermanTools cek di instalasi-mu.
- Transaction log dipakai otomatis untuk hive kotor; `--recover` (default true) ikut memulihkan key dan nilai terhapus [S5].

Keluaran ilustrasi (ringkas, dari console):

```
Processing hive G:\Windows\System32\config\SYSTEM       Dirty: False
Processing hive G:\Windows\System32\config\SOFTWARE     Dirty: False
Processing hive G:\Windows\System32\config\SAM          Dirty: False
Processing hive G:\Users\rizky.saputra\NTUSER.DAT       Dirty: False
Processing hive G:\Users\adm.yoga\NTUSER.DAT            Dirty: False
Processing hive G:\Users\ir-admin\NTUSER.DAT            Dirty: False
Found 3,962 key/value pairs across 9 files
```

Teks pesan console berbeda antar versi; yang penting adalah status kotor tiap hive dan jumlah baris. Semua hive E16 bersih, sesuai shutdown normal Kamis pukul 08:44.

Kedua, ulangi untuk hive E14-W1 dua kali, dengan dan tanpa transaction log, untuk melihat apa yang dilihat retainer.

```powershell
& "$ez\RECmd\RECmd.exe" -d "$e14" --bn "$ez\RECmd\BatchExamples\DFIRBatch.reb" --csv "$out\E14-cmp" --csvf E14-W1_replay.csv
& "$ez\RECmd\RECmd.exe" -d "$e14" --bn "$ez\RECmd\BatchExamples\DFIRBatch.reb" --csv "$out\E14-cmp" --csvf E14-W1_nolog.csv --nl
```

Keluaran ilustrasi (baris kategori Devices dan nilai yang relevan saja):

```
                                     E14 tanpa log (--nl)   E14 dengan replay      E16
SYSTEM status                        Dirty: True            Dirty: True (replay)   Dirty: False
NTUSER.DAT adm.yoga status           Dirty: True            Dirty: True (replay)   Dirty: False
USBSTOR Kingston DataTraveler        ada                    ada                    ada
USBSTOR SanDisk Ultra (USB-E-10)     tidak ada              ada (0066 10:43:12)    ada (0067 10:59:20)
SCSI PortableSSD (USB-E-11)          tidak ada              ada (0066 11:01:03)    ada (0067 11:35:18)
MountPoints2 adm.yoga {9b4e...}      tidak ada              ada                    ada
```

**Cara membaca hasil:**

- Tanpa log, E14 hanya menunjukkan flashdisk pribadi Rizky, persis daftar retainer. Data `USB-E-10` (dicolok 17:43, 19 menit sebelum koleksi) dan `USB-E-11` (18:01) masih di transaction log saat KAPE menyalin hive, sesuai penundaan penulisan ke hive utama hingga sekitar satu jam di format log Windows 8.1 ke atas [S10].
- Dengan replay, kedua perangkat muncul. `USB-E-10` di E14 belum punya waktu cabut yang lengkap dan `USB-E-11` belum dicabut saat E14 diambil; waktu cabut keduanya baru lengkap di E16. Ini cocok dengan urutan di case notes.
- Bahkan setelah replay, `USB-E-11` tidak ada di USBSTOR, karena tercatat di `Enum\SCSI` (bagian 2.5). Kueri retainer yang hanya membaca USBSTOR akan tetap melewatkannya.

Kalimat untuk Sari: "Daftar retainer dibuat dari hive E14 tanpa memainkan ulang transaction log. Koleksi E14 dimulai beberapa menit setelah Yoga mencolok dua USB, dan data perangkat itu masih di transaction log; dengan replay keduanya muncul, dan di E16 (laptop dimatikan normal) datanya lengkap. Satu perangkat lagi, SSD `USB-E-11`, tercatat di key SCSI, bukan USBSTOR, sehingga harus dicari di dua tempat."

**Variasi:** bila retainer memakai alat yang tidak bisa memainkan ulang log, kirim salinan hive yang sudah bersih dari RLA, bukan memintanya mengganti alat:

```powershell
& "$ez\RECmd\RLA.exe" --d "$e14" --out "C:\DFIR\work\INC-2026-019\E14-W1\reg-clean"
```

`--out` hanya berisi hive kotor yang sudah dimainkan ulang, kecuali `--ca` (default true) yang menyalin juga hive yang tidak kotor [S5]. Lokasi `RLA.exe` di folder EZ Tools cek di instalasi-mu. Hash hive hasil RLA dicatat sebagai turunan, bukan bukti.

**Kapan gagal:** RECmd dijalankan dengan `--nl` untuk "mempercepat" atau karena kebiasaan, atau hive disalin manual tanpa log; hasilnya terlihat normal dan tidak ada galat, hanya isinya tertinggal.

### 2.3 Identitas, zona waktu, dan jam laptop

Langkah ini menjawab pertanyaan kedua Sari. Filter CSV RECmd untuk kategori System Info:

```powershell
$r = Import-Csv "$out\E16-W1_RECmd.csv"
$r | Where-Object Category -eq 'System Info' |
  Select-Object Description, KeyPath, ValueName, ValueData, LastWriteTimestamp | Format-Table -AutoSize
```

Nama kolom (`Category`, `KeyPath`, `ValueData`, `LastWriteTimestamp`) cek di header CSV versi-mu. Keluaran ilustrasi, disederhanakan:

```
KeyPath                                              ValueName                     ValueData                        LastWrite (UTC)
Select                                               Current                       1                                2026-03-02 03:11:20
ControlSet001\Control\ComputerName\ComputerName      ComputerName                  JKT-WS-0412                      2026-03-02 03:40:51
Microsoft\Windows NT\CurrentVersion                  ProductName                   Windows 10 Enterprise            2026-09-09 02:17:33
Microsoft\Windows NT\CurrentVersion                  DisplayVersion                23H2
Microsoft\Windows NT\CurrentVersion                  CurrentBuild                  22631
ControlSet001\Control\TimeZoneInformation            TimeZoneKeyName               SE Asia Standard Time            2026-03-02 03:21:57
ControlSet001\Control\TimeZoneInformation            Bias                          0xFFFFFE5C (-420)
ControlSet001\Control\TimeZoneInformation            ActiveTimeBias                0xFFFFFE5C (-420)
ControlSet001\Services\tzautoupdate                  Start                         4                                2026-03-02 03:25:10
ControlSet001\Services\W32Time\Parameters            Type                          NT5DS                            2026-03-02 03:58:02
ControlSet001\Control\Windows                        ShutdownTime                  2026-10-15 01:44:52              2026-10-15 01:44:52
```

**Cara membaca hasil:**

- `Select\Current` = 1, jadi semua path SYSTEM dibaca dari `ControlSet001`.
- `ProductName` menulis Windows 10 padahal `CurrentBuild` 22631 adalah Windows 11 versi 23H2 [S37]. Ini bukan kesalahan image: sebagian nilai di `CurrentVersion` sengaja tidak diubah saat upgrade ke Windows 11 demi kompatibilitas aplikasi, dan Microsoft menyarankan memakai API atau nomor build, bukan `ProductName` [S36]. Tulis versi OS dari `CurrentBuild` dan `DisplayVersion`.
- Zona `SE Asia Standard Time` dengan bias -420 menit sama dengan UTC+7 (UTC = lokal + bias [S13]). Last write time key itu 2026-03-02, hari laptop dipasang, sehingga tidak ada perubahan zona selama insiden (dengan batas di bagian 1.2). `tzautoupdate` bernilai 4 (mati) [S14], jadi zona tidak berpindah otomatis saat laptop dibawa ke Cikarang; di dalam Pulau Jawa pun zonanya tetap WIB.
- `Type` NT5DS: laptop menyinkronkan waktu dari hierarki domain [S15]. Selama di luar kantor tanpa VPN, laptop tidak bisa menghubungi domain controller.
- `ShutdownTime` 2026-10-15 01:44:52 UTC (08:44:52 WIB) cocok dengan case notes: laptop dimatikan Yoga setelah mencatat konteks waktu pukul 08:40. Ini jejak responder.

Zona waktu benar. Pertanyaan berikutnya adalah jam UTC laptop. Dua pembanding diambil dari luar registry:

```powershell
$evt = Import-Csv (Get-ChildItem '\\jkt-evid01\cases\INC-2026-019\analysis\E16-W1\EZ-2026.5.0\EventLogs' -Filter '*EvtxECmd_Output.csv').FullName
$evt | Where-Object { $_.EventId -eq '4616' -and $_.TimeCreated -ge '2026-10-12' -and $_.TimeCreated -lt '2026-10-15 01:45' } |
  Select-Object TimeCreated, UserName, ExecutableInfo, PayloadData1, PayloadData2
$r | Where-Object { $_.KeyPath -like '*Tcpip\Parameters\Interfaces*' -and $_.ValueName -in 'DhcpIPAddress','DhcpServer','LeaseObtainedTime' } |
  Select-Object KeyPath, ValueName, ValueData
```

Output EvtxECmd E16-W1 dibuat dengan cara yang sama seperti Day 05 bagian 2.1; nama kolom payload cek di CSV-mu. Keluaran ilustrasi:

```
(4616: tidak ada baris dalam rentang 2026-10-12 00:00 sampai 2026-10-15 01:45 UTC)

KeyPath                                                         ValueName          ValueData
...\Interfaces\{3c1f9d2e-...}  (adapter kabel)                  DhcpIPAddress      10.10.41.23
...\Interfaces\{3c1f9d2e-...}                                   DhcpServer         10.10.0.10
...\Interfaces\{3c1f9d2e-...}                                   LeaseObtainedTime  0x6ACE0399 (1791886233)
...\Interfaces\{8a72b5c4-...}  (adapter Wi-Fi)                  DhcpIPAddress      192.168.99.27
...\Interfaces\{8a72b5c4-...}                                   DhcpServer         192.168.99.1
...\Interfaces\{8a72b5c4-...}                                   LeaseObtainedTime  0x6ACDF13C (1791881532)
```

**Cara membaca hasil:**

- Tidak ada 4616 dari Senin sampai laptop dimatikan. Karena event ini selalu dicatat [S16], jam laptop tidak pernah disetel langsung dalam jendela itu, baik oleh pengguna, penyerang, maupun W32Time. Koreksi kecil di bawah 300 detik tetap mungkin terjadi diam-diam [S15].
- `LeaseObtainedTime` adapter kabel 1791886233 detik sejak 1970 [S21] sama dengan 2026-10-13 10:10:33 UTC, atau 17:10:33 WIB. NOC mengirim baris log DHCP server kantor Jakarta (tersinkron ke `jkt-ntp01`): lease `10.10.41.23` untuk MAC laptop itu pukul 17:10:31 WIB. Jam laptop lebih cepat sekitar 2 detik pada Selasa sore, dan +3 detik Kamis pagi (Day 01 bagian 2.1).
- `LeaseObtainedTime` adapter Wi-Fi 1791881532 sama dengan 08:52:12 UTC (15:52:12 WIB), lease terakhir Wi-Fi sebelum laptop masuk kantor. Bagian 2.4 menunjukkan jaringan apa itu.

Kalimat untuk Sari: "Waktu Prefetch, `$MFT`, dan event log disimpan dalam UTC dan dikonversi tetap ke WIB, jadi 20:14:21 WIB tidak bergantung pada pengaturan laptop. Zona laptop memang WIB sejak dipasang dan tidak berpindah otomatis. Jam laptop tidak bisa diukur langsung Senin malam; yang bisa diukur adalah selisih +2 detik Selasa 17:10 (registry DHCP vs log DHCP server) dan +3 detik Kamis 08:40, tanpa satu pun penyetelan jam di antaranya, sehingga waktu Senin malam bisa dipegang dengan ketelitian beberapa detik."

**Variasi:** di host yang sering dibawa ke luar zona (misalnya staf POP Medan yang ke Jakarta), baca juga izin lokasi di `CapabilityAccessManager\ConsentStore\location` [S14] dan cari perubahan last write time `TimeZoneInformation` di jendela kasus.

**Kapan gagal:** zona host dipakai untuk "mengoreksi" waktu yang sudah UTC, sehingga waktu Prefetch digeser dua kali; atau ketiadaan 4616 ditulis sebagai "jam tepat", padahal hanya berarti tidak ada lompatan.

### 2.4 Jaringan Senin sampai Selasa 17:10

Langkah ini menjawab pertanyaan ketiga Sari. Ambil baris plugin `KnownNetworks` (DFIRBatch: "Network Connections", kategori System Info [S6]) dan lihat file detail plugin yang dibuat RECmd di folder output.

```powershell
$r | Where-Object { $_.KeyPath -like '*NetworkList*' } | Select-Object -First 1 KeyPath, PluginDetailFile
Import-Csv (Join-Path $out (($r | Where-Object KeyPath -like '*NetworkList*' | Select-Object -First 1).PluginDetailFile)) |
  Sort-Object LastConnectedLOCAL -Descending | Format-Table -AutoSize
```

Nama kolom file detail plugin (misalnya `FirstConnectedLOCAL`, `LastConnectedLOCAL`) dan nama kolom `PluginDetailFile` cek di output versi-mu; yang pasti, plugin menampilkan waktu sebagai waktu lokal [S8]. Keluaran ilustrasi, ditambah kolom `Category` yang dibaca langsung dari key profil di Registry Explorer karena plugin tidak membacanya [S8]:

```
NetworkName        NameType   Category  FirstConnected (lokal WIB)  LastConnected (lokal WIB)  GatewayMac          DnsSuffix
corp.jab.example   Wired      2 Domain  2026-03-02 10:15:08         2026-10-13 17:10:29        02:1b:00:0a:29:01   corp.jab.example
HP-Rizky           Wireless   0 Public  2026-08-17 14:22:40         2026-10-13 15:52:10        02:5a:9e:61:0b:7a   <none>
BajaRaya-Guest     Wireless   0 Public  2026-10-12 09:41:12         2026-10-13 13:02:47        02:5a:1c:7e:30:11   <none>
Kenanga-Hotel      Wireless   0 Public  2026-10-12 18:47:05         2026-10-13 06:58:30        02:5a:44:19:c0:02   <none>
RUMAH-SAPUTRA      Wireless   1 Private 2026-03-07 19:20:41         2026-10-12 07:33:18        02:5a:d0:3e:77:15   <none>
```

**Cara membaca hasil:**

- Lima jaringan pernah dikenal laptop ini. Dua di antaranya baru pertama kali dipakai Senin: `BajaRaya-Guest` pukul 09:41 dan `Kenanga-Hotel` pukul 18:47. Rizky mengonfirmasi lewat Sari bahwa ia rapat di kantor pelanggan korporat PT Baja Raya Contoh di Cikarang dan menginap di Hotel Kenanga Contoh. `HP-Rizky` adalah hotspot ponselnya, sudah dipakai sejak Agustus. `RUMAH-SAPUTRA` adalah Wi-Fi rumahnya, terakhir Senin pagi sebelum berangkat.
- Waktu kolom ini sudah WIB karena laptop ber-zona WIB dan nilainya waktu lokal [S8][S17][S18]. Jangan menambah tujuh jam.
- Tabel ini hanya memberi sesi pertama dan terakhir per jaringan [S19]. `LastConnected` `Kenanga-Hotel` Selasa 06:58 tidak berarti laptop hanya tersambung pagi itu; dan `LastConnected` `HP-Rizky` 15:52 tidak memberi tahu kapan hotspot terputus.

Sesi di antaranya disusun dari event WLAN-AutoConfig di E16-W1. Microsoft mendokumentasikan event 8000 (mulai menyambung) dan 8002 (gagal) di channel itu [S22]; event sukses sambung dan putus yang dipakai di bawah adalah ID yang lazim dipakai praktisi (8001 dan 8003) dan dicek isinya di CSV sebelum dipakai.

```powershell
$evt | Where-Object { $_.Channel -like '*WLAN-AutoConfig*' -and $_.EventId -in '8001','8003' -and
                      $_.TimeCreated -ge '2026-10-12' -and $_.TimeCreated -lt '2026-10-13 10:15' } |
  Sort-Object TimeCreated | Select-Object TimeCreated, EventId, PayloadData1, PayloadData2
```

Keluaran ilustrasi, diringkas menjadi sesi (WIB):

| Jaringan | Tersambung | Terputus | Yang terjadi di jendela ini |
|---|---|---|---|
| `RUMAH-SAPUTRA` | Senin 07:33:18 | Senin 08:05:40 | Laptop dibawa berangkat |
| `BajaRaya-Guest` | Senin 09:41:12 | Senin 17:32:55 | Email diterima 15:58 lewat jaringan tamu pelanggan |
| `Kenanga-Hotel` | Senin 18:47:05 | Selasa 00:12:31 | Lampiran dijalankan 20:14:21; task dan beacon dimulai |
| `Kenanga-Hotel` | Selasa 06:58:30 | Selasa 07:46:12 | Beacon berlanjut |
| `BajaRaya-Guest` | Selasa 08:52:40 | Selasa 12:05:19 | Beacon berlanjut |
| `BajaRaya-Guest` | Selasa 13:02:47 | Selasa 15:40:03 | Beacon berlanjut |
| `HP-Rizky` | Selasa 15:52:10 | Selasa 17:04:55 | Perjalanan kembali ke kantor |
| `corp.jab.example` (kabel) | Selasa 17:10:29 | port dimatikan 17:20 | DNS ke sinkhole 17:12:04 |

**Cara membaca hasil:**

- Setiap `DateCreated` dan `DateLastConnected` di registry cocok dengan satu baris sesi di event log. Dua sumber yang ditulis oleh komponen berbeda saling menguatkan.
- Lampiran dijalankan saat laptop tersambung ke Wi-Fi hotel. Seluruh beacon sejak Senin 20:14 sampai Selasa 17:04 lewat tiga jaringan yang bukan milik PT JAB, sehingga tidak ada di proxy, DNS, atau firewall PT JAB. Itulah penjelasan kalimat retainer "tidak terlihat di log".
- Jeda tanpa koneksi (Senin 17:32 sampai 18:47, Selasa dini hari, dan jeda singkat lain) cocok dengan laptop ditutup atau tidur. Jumlah beacon per jaringan bisa dihitung dari 4104 berulang (Day 03 bagian 2.5), dan volumenya dari SRUM (Day 07 bagian 1.6).
- `DnsSuffix` `corp.jab.example` dan kategori Domain hanya muncul untuk jaringan kantor; jaringan lain tidak terautentikasi ke domain.

**Variasi:** bila channel WLAN sudah berputar dan tidak mencakup Senin, jawabannya turun menjadi "pertama dan terakhir per jaringan dari registry; sesi di antaranya tidak bisa dipastikan". Tulis batas itu apa adanya.

**Kapan gagal:** kolom NetworkList diperlakukan sebagai UTC seperti kolom lain dan dikonversi ke WIB, sehingga lampiran tampak dibuka saat laptop masih di kantor pelanggan; atau `DateLastConnected` dibaca sebagai waktu putus.

### 2.5 Perangkat USB: tiga perangkat, dua milik responder

Langkah ini menjawab pertanyaan keempat Sari. Ambil semua baris kategori Devices dari E16:

```powershell
$r | Where-Object Category -eq 'Devices' | Select-Object Description, KeyPath, ValueName, ValueData, LastWriteTimestamp, PluginDetailFile
```

Keluaran ilustrasi, disusun ulang dari file detail plugin `USBSTOR`, `SCSI`, `USB`, `WindowsPortableDevices`, `VolumeInfoCache`, dan `MountedDevices` (waktu properti UTC, WIB di kurung):

```
[A] Enum\USBSTOR\Disk&Ven_Kingston&Prod_DataTraveler_3.0&Rev_PMAP\60A44C3FAE21F171B9230021&0
    Label volume (WPD/VolumeInfoCache): RIZKY
    0065 FirstInstall   2026-05-20 01:12:44   (08:12:44)
    0064 Install        2026-05-20 01:12:44
    0066 LastArrival    2026-10-09 02:15:07   (Jumat 09:15:07)
    0067 LastRemoval    2026-10-09 02:41:52   (Jumat 09:41:52)

[B] Enum\USBSTOR\Disk&Ven_SanDisk&Prod_Ultra&Rev_1.00\4C530001250913104477&0
    Label volume: USB-E-10          Volume GUID: {6f1d2a40-...}
    0065 FirstInstall   2026-10-13 10:43:12   (Selasa 17:43:12)
    0064 Install        2026-10-13 10:43:12
    0066 LastArrival    2026-10-13 10:43:12   (Selasa 17:43:12)
    0067 LastRemoval    2026-10-13 10:59:20   (Selasa 17:59:20)

[C] Enum\SCSI\Disk&Ven_Contoh&Prod_PortableSSD&Rev_0100\7&2f8c1a3b&0&000000
    Enum\USB\VID_<vendor>&PID_<produk>\E11A0472C9      (perangkat induk USB, serial dari perangkat)
    Label volume: USB-E-11          Volume GUID: {9b4e7c13-...}
    0065 FirstInstall   2026-10-13 11:01:03   (Selasa 18:01:03)
    0064 Install        2026-10-13 11:01:03
    0066 LastArrival    2026-10-13 11:01:03   (Selasa 18:01:03)
    0067 LastRemoval    2026-10-13 11:35:18   (Selasa 18:35:18)

MountedDevices: \DosDevices\E:  -> {9b4e7c13-...} (USB-E-11)
                \??\Volume{6f1d2a40-...}  -> _??_USBSTOR#Disk&Ven_SanDisk&Prod_Ultra...
                \??\Volume{9b4e7c13-...}  -> _??_SCSI#Disk&Ven_Contoh&Prod_PortableSSD...
```

Lalu `MountPoints2` per profil dari baris NTUSER:

```
rizky.saputra  ...\MountPoints2\{6f1d2a40-...}   LastWrite 2026-10-13 10:43:15   (USB-E-10)
rizky.saputra  ...\MountPoints2\{d81a0c5e-...}   LastWrite 2026-10-09 02:15:10   (Kingston RIZKY)
adm.yoga       ...\MountPoints2\{9b4e7c13-...}   LastWrite 2026-10-13 11:01:06   (USB-E-11)
```

Terakhir, VSN dari event 1006 channel Partition/Diagnostic di E16-W1 (dibaca dari `Vbr0` pada offset `0x48`, volume NTFS [S26]): `USB-E-10` `7D3B0C52`, `USB-E-11` `3A7F21C9`, Kingston `F0C2-1A57` (FAT32, offset `0x43`).

**Cara membaca hasil:**

- Perangkat [B] dan [C] adalah milik responder. Buktinya lima hal yang saling cocok: waktu colok dan cabut sama dengan case notes Yoga (17:43 sampai 17:59, 18:01 sampai 18:35), label volume `USB-E-10` dan `USB-E-11` (label dibuat Yoga saat menyiapkan toolkit, bisa diubah siapa saja sehingga tidak berdiri sendiri), VSN cocok dengan catatan inventaris toolkit, `USB-E-11` memakai huruf `E:` sama seperti perintah KAPE di E14, dan tidak ada perangkat lain dalam jendela insiden.
- `USB-E-10` muncul di `MountPoints2` milik `rizky.saputra`, bukan Yoga. Itu bukan berarti Rizky yang mencolok: saat itu sesi Rizky masih terbuka dan Yoga memakainya untuk mengambil memori dengan elevasi UAC (bagian 2.7). `MountPoints2` menunjuk sesi tempat volume di-mount, bukan orangnya [S27]. Tanpa case notes, baris ini bisa salah dibaca sebagai "Rizky mencolok USB 17:43".
- `USB-E-11` hanya ada di `Enum\SCSI` dan `Enum\USB`, tidak di USBSTOR, sesuai perilaku perangkat UASP yang dilaporkan praktisi [S29]. Instance ID di `Enum\SCSI` berbentuk buatan Windows; serial yang bisa dicocokkan ke perangkat fisik ada di key `Enum\USB` induknya. Hubungan kedua key itu cek di lab dengan SSD yang sama.
- `\DosDevices\E:` kini menunjuk `USB-E-11`, karena `E:` terakhir dipakai perangkat itu. `USB-E-10` juga memakai `E:` sebelumnya; jejaknya tetap ada di entri `\??\Volume{...}`. Pemetaan huruf drive hanya menyimpan pemilik terakhir.
- Perangkat [A] milik Rizky, terakhir dicolok Jumat 2026-10-09, tiga hari sebelum email phishing. Ia di luar jendela insiden dan tidak relevan untuk pertanyaan Sari; registry juga tidak membuktikan file apa pun disalin ke perangkat itu [S26][S27]. Tidak dianalisis lebih jauh tanpa permintaan dan dasar yang jelas, karena menyangkut data pribadi karyawan.
- Untuk [B] dan [C], `0064` sama dengan `0065` karena driver perangkat belum pernah diperbarui sejak dipasang pertama kali [S23][S24].

**Variasi:** `setupapi.dev.log` E16-W1 memuat bagian "Device Install" untuk [B] dan [C] dengan waktu 2026/10/13 17:43:12 dan 18:01:03, sudah dalam waktu lokal (WIB) [S30]. Cocokkan, dan jangan menambah tujuh jam.

**Kapan gagal:** kueri hanya membaca USBSTOR; `0064` dipakai sebagai waktu pertama dicolok padahal bisa berubah oleh pembaruan driver; atau last write time key perangkat dipakai sebagai waktu colok.

### 2.6 Autostart selain `\SysCacheUpdate`

Langkah ini menjawab pertanyaan kelima Sari. Ambil kategori Autoruns, Services, dan Threat Hunting:

```powershell
$r | Where-Object Category -in 'Autoruns','Threat Hunting' |
  Select-Object HiveType, KeyPath, ValueName, ValueData, LastWriteTimestamp | Format-Table -AutoSize
```

Keluaran ilustrasi (waktu UTC):

```
HiveType  KeyPath                                                    ValueName      ValueData                                                             LastWrite
SOFTWARE  Microsoft\Windows\CurrentVersion\Run                       SecurityHealth %windir%\system32\SecurityHealthSystray.exe                           2026-03-02 04:02:18
SOFTWARE  Microsoft\Windows\CurrentVersion\Run                       JABDocSync     "C:\Program Files\JAB\DocSync\jabdocsync.exe" /tray                  2026-03-02 04:02:18
SOFTWARE  WOW6432Node\Microsoft\Windows\CurrentVersion\Run           (kosong)                                                                             2026-03-02 03:47:30
SOFTWARE  Microsoft\Windows\CurrentVersion\RunOnce                   (kosong)                                                                             2026-10-12 00:31:09
NTUSER    (rizky.saputra) Software\...\CurrentVersion\Run            OneDrive       "C:\Users\rizky.saputra\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background  2026-10-08 05:12:44
NTUSER    (rizky.saputra) Software\...\CurrentVersion\RunOnce        (kosong)                                                                             2026-08-17 07:10:02
NTUSER    (adm.yoga) Software\...\CurrentVersion\Run                 OneDrive       "C:\Users\adm.yoga\AppData\Local\Microsoft\OneDrive\OneDrive.exe" /background       2026-06-18 02:41:37
SOFTWARE  Microsoft\Windows NT\CurrentVersion\WinLogon               Shell          explorer.exe                                                          2026-10-13 11:00:12
SOFTWARE  Microsoft\Windows NT\CurrentVersion\WinLogon               Userinit       C:\Windows\system32\userinit.exe,
SOFTWARE  Microsoft\Windows NT\CurrentVersion\Image File Execution Options\*  (tidak ada nilai Debugger)
```

**Cara membaca hasil:**

- Run mesin berisi dua entri yang dikenal di image standar IT PT JAB (Windows Security dan aplikasi internal JAB DocSync), last write sejak pemasangan. Run user berisi OneDrive per-user di kedua profil. OneDrive berjalan dari `AppData\Local`, lokasi yang bisa ditulis user, tetapi path, argumen, dan binary-nya sama dengan yang ditemukan di hunt enam penerima (Day 04); lokasi user-writable adalah alasan memeriksa, bukan vonis.
- Last write `RunOnce` mesin Senin 2026-10-12 00:31 UTC (07:31 WIB) sedangkan key itu kosong. Waktu itu sama dengan boot Senin pagi; Windows dan installer memakai RunOnce lalu menghapus nilainya setelah dijalankan, jadi key kosong dengan last write baru adalah hal biasa. Tetap dicatat dan dicocokkan dengan boot di event log, bukan diabaikan. Nilai yang dipulihkan RECmd (`--recover`) dari key ini tidak ada.
- Last write `WinLogon` Selasa 11:00:12 UTC (18:00:12 WIB) dengan `Shell` dan `Userinit` bawaan. Waktunya sama dengan login konsol `adm.yoga`; key Winlogon juga menyimpan nilai seperti nama user terakhir yang login (DFIRBatch membaca `LastUsedUsername` dan sejenisnya [S6]), sehingga logon interaktif mengubah last write-nya. Ini contoh last write yang berubah oleh nilai lain, bukan oleh persistence (bagian 1.2).

Lalu service dengan last write di jendela insiden:

```powershell
$svc = $r | Where-Object Category -eq 'Services'
$svc | Where-Object { $_.LastWriteTimestamp -ge '2026-10-12' -and $_.LastWriteTimestamp -lt '2026-10-15 01:45' } |
  Select-Object KeyPath, LastWriteTimestamp, PluginDetailFile
```

Keluaran ilustrasi (dari file detail plugin `Services`):

```
Name                  Start  Type        ImagePath                                   LastWrite (UTC)
<driver WinPmem>      3      0x1 kernel  <path driver yang diekstrak WinPmem>        2026-10-13 10:45:06
```

**Cara membaca hasil:** satu-satunya service baru di jendela insiden adalah driver kernel WinPmem, last write Selasa 17:45:06 WIB, cocok dengan event 7045 di log System pada detik yang sama dan dengan case notes memori E13. Ini jejak responder, sama polanya dengan laptop Andi (Day 05 bagian 2.6). Nama service, path driver, dan apakah WinPmem menghapus key service setelah selesai bergantung versi WinPmem; cek di lab. Tidak ada 4697 karena audit Security System Extension tidak aktif di laptop ini (Day 05 bagian 2.7), tetapi 7045 di log System tetap ada.

Terakhir, TaskCache:

```powershell
$r | Where-Object { $_.KeyPath -like '*Schedule\TaskCache*' } | Select-Object KeyPath, LastWriteTimestamp, PluginDetailFile
```

Keluaran ilustrasi (gabungan plugin `TaskCache` dan pembacaan key `Tree` di Registry Explorer):

```
Tree\SysCacheUpdate                                    Id {4e0b2c71-...}  SD ada   LastWrite 2026-10-12 13:14:39
Tasks\{4e0b2c71-...}   Path \SysCacheUpdate                                         LastWrite 2026-10-15 01:29:41
Tree\OneDrive Standalone Update Task-S-1-5-21-...-4153  SD ada                      LastWrite 2026-08-17 07:12:55
Tree\JAB\DocSync Update                                SD ada                       LastWrite 2026-03-02 04:05:31
(task lain: bawaan \Microsoft\Windows\...; tidak ada key Tree tanpa SD)
```

**Cara membaca hasil:**

- `Tree\SysCacheUpdate` last write 13:14:39 UTC (20:14:39 WIB), sama dengan `RegistrationInfo` di XML task (Day 03 bagian 2.5) dan dua detik setelah `upd.ps1` dibuat. Tiga sumber (XML, registry, `$MFT`) sepakat tentang waktu pendaftaran.
- `Tasks\{GUID}` task yang sama punya last write Kamis 01:29:41 UTC (08:29:41 WIB), dekat run terakhir sebelum laptop dimatikan. Pola ini cocok dengan Windows yang memperbarui data runtime task di key itu, tetapi sumber yang diperiksa tidak mendokumentasikannya; uji di lab (bagian 3) sebelum menulisnya di laporan. Pelajarannya tetap: last write key itu bukan waktu pembuatan task.
- Tidak ada key `Tree` tanpa `SD`, jadi tidak ada task tersembunyi dengan teknik yang didokumentasikan Microsoft [S31]. Task non-Microsoft lain dikenal: OneDrive per-user dan updater JAB DocSync.

Kalimat untuk Sari: "Di registry tidak ada autostart lain milik penyerang. Run, RunOnce, Winlogon, IFEO, service, dan TaskCache hanya berisi entri image standar, OneDrive, task `\SysCacheUpdate`, dan driver WinPmem dari pengambilan memori kita Selasa 17:45. Folder Startup dan WMI tidak ada di registry dan diperiksa terpisah."

**Variasi:** jalankan autorunsc atas volume offline sebagai pembanding cakupan, misalnya `autorunsc64.exe -a * -c -h -s -t -z <path Windows offline> <profil>` di `JKT-DFIR01` [S33]. Argumen persis `-z` cek di bantuan autorunsc versi-mu. Verifikasi tanda tangan memeriksa file di image yang di-mount, bukan di workstation analisis; pastikan path yang dilaporkan menunjuk `G:`.

**Kapan gagal:** hanya membaca Run di SOFTWARE dan lupa NTUSER setiap profil; menganggap key kosong dengan last write baru sebagai bukti penghapusan oleh penyerang tanpa memeriksa boot dan installer; atau menyebut driver WinPmem sebagai "service mencurigakan" karena lupa membaca case notes.

### 2.7 Akun lokal, profil, dan `ir-admin`

Langkah ini menjawab pertanyaan keenam Sari. Ambil kategori User Accounts:

```powershell
$r | Where-Object Category -eq 'User Accounts' | Select-Object KeyPath, PluginDetailFile -Unique
```

Keluaran ilustrasi, plugin `SAM` (waktu UTC):

```
RID   UserName            Disabled  LastLogon            PasswordLastSet      LoginCount  BadPwdCount  LastPwdFailure
500   Administrator       True      (never)              2026-03-02 03:09:44  0           0            (never)
501   Guest               True      (never)              (never)              0           0            (never)
503   DefaultAccount      True      (never)              (never)              0           0            (never)
504   WDAGUtilityAccount  True      (never)              2026-03-02 03:09:46  0           0            (never)
1003  ir-admin            False     2026-10-13 10:44:02  2026-03-02 03:58:27  1           0            (never)
```

Plugin `SAMBuiltin`, anggota grup lokal Administrators:

```
S-1-5-21-1170352869-2716430598-904518337-500     (Administrator lokal, nonaktif)
S-1-5-21-1170352869-2716430598-904518337-1003    (ir-admin)
S-1-5-21-2847193650-1938475021-3765120984-512    (JAB\Domain Admins)
S-1-5-21-2847193650-1938475021-3765120984-7701   (JAB\WS-Admins)
```

Plugin `ProfileList`, ditambah waktu pembuatan folder profil dari `$MFT` E16-W1 (Day 08):

```
SID                                                    ProfileImagePath            Folder dibuat (UTC)
S-1-5-21-2847193650-1938475021-3765120984-4153         C:\Users\rizky.saputra      2026-03-02 05:21:09
S-1-5-21-2847193650-1938475021-3765120984-5107         C:\Users\adm.yoga           2026-06-18 02:40:52
S-1-5-21-1170352869-2716430598-904518337-1003          C:\Users\ir-admin           2026-10-13 10:44:05
(S-1-5-18, -19, -20: profil sistem)
```

**Cara membaca hasil:**

- Tidak ada akun lokal baru. Akun yang aktif hanya `ir-admin`; empat lainnya akun bawaan yang nonaktif. Anggota Administrators hanya akun bawaan, `ir-admin`, dan dua grup domain yang sesuai standar PT JAB (`WS-Admins` adalah grup admin workstation; anggotanya dicek di AD, bukan di laptop).
- RID `ir-admin` 1003 sama dengan di laptop Dewi dari image yang sama (Day 07 bagian 2.5), jadi celah RID 1000 sampai 1002 adalah bawaan proses image, bukan akun yang dihapus penyerang. Konfirmasi ke tim IT bila perlu dicantumkan.
- `ir-admin` LastLogon Selasa 10:44:02 UTC (17:44:02 WIB), LoginCount 1, dan folder profilnya dibuat 17:44:05. Itu satu-satunya pemakaian akun itu di laptop ini: elevasi UAC untuk WinPmem di sesi Rizky, satu menit setelah `USB-E-10` dicolok. Apakah elevasi UAC dengan kredensial akun lain memperbarui `LastLogon`, menambah `LoginCount`, dan membuat profil perlu diuji di lab (bagian 3).
- `PasswordLastSet` `ir-admin` 2026-03-02, hari laptop dipasang. Prosedur PT JAB mengganti password akun itu setelah setiap pemakaian, tetapi laptop ini tetap terisolasi sampai di-image lalu di-reimage, sehingga password Maret masih tersimpan (sebagai hash) di SAM E16. Bila password `ir-admin` sama di semua laptop dari image yang sama, hash di E16 berlaku untuk host lain. Itu pertanyaan untuk tim IT, dan jawabannya menentukan apakah perlu rotasi massal.
- Profil `adm.yoga` sudah ada sejak 2026-06-18, dari kunjungan Yoga untuk uji coba onboarding agen (ada tiket IT). Karena itu logon konsol `adm.yoga` Selasa 18:00, saat port switch sudah mati, bisa berhasil dengan cached logon [S35]. Konsekuensinya, image E16 juga menyimpan verifier cached logon `adm.yoga`; ini salah satu alasan password `adm.yoga` dirotasi Kamis.

Kalimat untuk Sari: "Tidak ada akun lokal baru di laptop Rizky dan tidak ada perubahan anggota grup Administrators. `ir-admin` dipakai sekali, Selasa 17:44 WIB, oleh Yoga untuk mengambil memori; `adm.yoga` login 18:00 dengan cached logon untuk KAPE. Satu tindak lanjut: password `ir-admin` di laptop ini tidak berubah sejak Maret; tim IT perlu memastikan password itu unik per host."

**Variasi:** di host yang dicurigai punya akun lokal buatan penyerang, bandingkan `PasswordLastSet` dan waktu pembuatan folder profil, karena event 4720 bisa sudah berputar. SAM tetap menyimpan akun itu sampai dihapus.

**Kapan gagal:** menyimpulkan "penyerang tidak punya hak admin" dari ketiadaan akun lokal baru. SAM tidak mencatat eskalasi hak; itu dijawab event log, artefak eksekusi, dan memori (Day 05, Day 07).

### 2.8 Jawaban untuk Sari

Tabel ini adalah keluaran akhir yang dikirim ke Sari pukul 13:40. Kolom "Pelaku" memakai tiga nilai yang disepakati sejak Day 05 (pengguna, penyerang, responder).

| Pertanyaan | Jawaban | Pelaku | Sumber | Keyakinan dan batas |
|---|---|---|---|---|
| Kenapa daftar USB retainer beda? | Hive E14 kotor dan dibaca tanpa replay; `USB-E-11` di key SCSI, bukan USBSTOR | Responder (USB) | RECmd E14 dengan dan tanpa `--nl`, E16 | Tinggi |
| Zona dan jam laptop | WIB sejak pemasangan, tidak otomatis berpindah; jam +2 s Selasa 17:10, +3 s Kamis 08:40, tanpa penyetelan jam di antaranya | - | `TimeZoneInformation`, `tzautoupdate`, `W32Time`, 4616, `LeaseObtainedTime` vs log DHCP | Tinggi untuk zona; jam Senin malam disimpulkan dari batas Selasa dan Kamis |
| Jaringan Senin sampai Selasa 17:10 | `BajaRaya-Guest`, `Kenanga-Hotel` (saat lampiran dijalankan), `HP-Rizky`; lalu jaringan kantor 17:10:29 | Pengguna (koneksi), penyerang (trafik C2 di atasnya) | NetworkList, WLAN-AutoConfig, interface TCP/IP | Tinggi; isi dan volume trafik tidak dari registry |
| USB | Kingston milik Rizky (terakhir Jumat 9 Oktober); `USB-E-10` 17:43-17:59 dan `USB-E-11` 18:01-18:35 milik responder | Pengguna; responder | USBSTOR, SCSI, USB, properti `0065`-`0067`, MountedDevices, MountPoints2, label, VSN 1006 | Tinggi; registry tidak membuktikan file disalin |
| Autostart lain | Tidak ada milik penyerang; driver WinPmem milik responder | Responder | Run, RunOnce, Winlogon, IFEO, Services, TaskCache, 7045 | Tinggi untuk registry; Startup folder dan WMI di Day 11 |
| Akun lokal | Tidak ada akun baru; `ir-admin` dipakai sekali 17:44; `adm.yoga` cached logon 18:00 | Responder | SAM, SAMBuiltin, ProfileList, `$MFT` profil | Tinggi; tindak lanjut password `ir-admin` |

Pernyataan yang menyertai tabel:

- **Tidak ditemukan, dengan cakupan penuh hive:** autostart registry lain, akun lokal baru, perubahan anggota Administrators, perubahan zona waktu, penyetelan jam, task tersembunyi tanpa `SD`.
- **Tidak bisa dijawab dari registry:** data apa yang dikirim ke C2 lewat jaringan hotel dan hotspot, apakah ada file yang disalin ke USB mana pun, dan persistence di luar registry.
- **Tindak lanjut:** pastikan password `ir-admin` unik per host; tambahkan langkah "replay transaction log dan baca USBSTOR, SCSI, USB" ke checklist analisis registry yang dikirim ke retainer.

## 3. Lab praktik (di VM lab terisolasi)

**Prasyarat:** `LAB-WS01` (`172.16.50.10`, Windows 11, snapshot `bersih-2026-10-15`) dan `LAB-DFIR01` (`172.16.50.20`) di jaringan host-only `172.16.50.0/24`; EZ Tools dan KAPE versi yang sama dengan toolkit; satu flashdisk lab kosong yang tidak pernah dipakai untuk data lain (dilabeli `LAB-USB09`) atau USB virtual yang di-pass-through hypervisor; folder kasus `CASE-2026-LAB-009`. Semua aktivitas jinak, tanpa sampel. Catat setiap langkah di `case-notes.md` dengan waktu WIB dan UTC.

1. **Baseline.** Kembalikan `LAB-WS01` ke snapshot. Catat `Get-Date -Format o`, `Get-TimeZone`, dan `w32tm /query /status`.
2. **Aktivitas yang waktunya diketahui.** Di `LAB-WS01`, buat akun lokal `lab-uji09` dan login sekali; sebagai `lab-uji09`, tambahkan nilai Run `LabRun09` di HKCU yang menjalankan `notepad.exe`; buat task `\LabTask09` yang menjalankan `cmd.exe /c echo lab09`; colok `LAB-USB09`, buka isinya di Explorer, lalu cabut dengan aman. Catat menit setiap langkah.
3. **Jaringan kedua.** Tambahkan adapter host-only kedua di jaringan lab lain, sambungkan sebentar, lalu putus. Catat waktu.
4. **Koleksi live (hive kotor).** Kurang dari lima menit setelah langkah 2 dan 3, koleksi dengan KAPE target `RegistryHives,EventLogs` dari disk lab ke disk virtual kedua. Jalankan RECmd DFIRBatch dua kali, dengan dan tanpa `--nl`. Catat entri yang hanya muncul dengan replay.
5. **Koleksi setelah shutdown (hive bersih).** Matikan `LAB-WS01` normal, mount disk-nya read-only di `LAB-DFIR01`, ulangi KAPE dan RECmd. Bandingkan status kotor setiap hive dengan langkah 4.
6. **RLA.** Jalankan RLA atas hasil langkah 4 ke folder `reg-clean`, buka salah satu hive di Registry Explorer, dan catat apakah Registry Explorer masih menawarkan replay.
7. **Waktu dan zona.** Cocokkan properti `0065`, `0066`, `0067` `LAB-USB09` dengan catatan langkah 2. Tentukan apakah perangkat terdaftar di USBSTOR atau SCSI. Cocokkan `DateCreated` dan `DateLastConnected` jaringan kedua dengan catatan langkah 3, dan buktikan kolom itu waktu lokal.
8. **Uji perilaku yang belum terdokumentasi.** Catat last write `Tree\LabTask09` dan `Tasks\{GUID}`, biarkan task berjalan beberapa kali, lalu koleksi ulang: apakah last write `Tasks\{GUID}` ikut berubah? Ulangi pengambilan memori tiruan dengan elevasi UAC memakai akun admin lokal kedua (`lab-ir09`): apakah `LastLogon`, `LoginCount`, dan folder profil akun itu berubah?
9. **Variasi zona.** Ubah zona `LAB-WS01` ke `(UTC+08:00)` sementara, sambungkan ulang jaringan kedua, koleksi, lalu bandingkan: kolom Prefetch dan last write tetap UTC, kolom NetworkList bergeser satu jam. Kembalikan snapshot setelahnya.

**Hasil yang sebaiknya tersimpan:**

- Case notes dengan waktu setiap aktivitas dan setiap koleksi.
- Dua CSV RECmd (dengan dan tanpa `--nl`) dan daftar perbedaannya.
- Tabel status kotor hive: koleksi live vs setelah shutdown.
- Hasil uji perilaku langkah 8 (task runtime, elevasi UAC) untuk build lab-mu.
- Satu paragraf kesimpulan: kolom mana yang UTC dan mana yang lokal, dengan bukti dari langkah 9.

**Variasi tantangan:** colok dua flashdisk berbeda di dua sesi user berbeda (`lab-uji09` dan akun admin), lalu tulis kalimat temuan untuk setiap perangkat yang memisahkan "di-mount di sesi siapa" dari "siapa yang mencolok". Tulis juga apa yang tidak bisa dibuktikan registry tentang file yang mungkin disalin.

## 4. Troubleshooting

Tabel ini memuat masalah yang sering muncul saat membaca registry dari image atau koleksi triage. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Perangkat atau nilai Run terbaru tidak muncul | Hive kotor dibaca tanpa replay | Pastikan `.LOG1`/`.LOG2` ikut dikoleksi; RECmd tanpa `--nl`; atau RLA (bagian 2.2) |
| SSD eksternal tidak ada di daftar USB | Perangkat UASP terdaftar di `Enum\SCSI` | Baca USBSTOR, SCSI, dan USB (bagian 2.5) |
| Waktu NetworkList tampak tujuh jam meleset | Kolom waktu lokal diperlakukan sebagai UTC | Jangan konversi kolom NetworkList; cek zona host (bagian 1.4, 2.4) |
| Waktu "pertama dicolok" berubah setelah Windows Update | Memakai `0064` (InstallDate) | Pakai `0065` (FirstInstallDate) (bagian 1.5) |
| Nilai SYSTEM dibaca dari control set yang salah | `CurrentControlSet` tidak ada di hive offline | Baca `Select\Current` (bagian 1.1) |
| Versi OS tertulis Windows 10 di laptop Windows 11 | `ProductName` tidak diubah saat upgrade | Pakai `CurrentBuild` dan `DisplayVersion` (bagian 2.3) |
| Plugin RECmd gagal dimuat | DLL plugin diblokir setelah ekstrak ZIP dengan alat Windows | `Unblock-File .\Plugins\*.dll` [S5] |
| Hasil batch kosong untuk satu kategori | Batch yang dipakai tidak memuat key itu | Cek `KeyPath` di file `.reb` sebelum menyimpulkan "tidak ada" |
| USB tidak tertaut ke user mana pun | NTUSER.DAT profil tertentu tidak ikut diparse | Pastikan semua profil di `ProfileList` punya NTUSER.DAT di koleksi |
| Hive tidak bisa dibuka | File rusak, salinan tidak lengkap, atau bukan hive | Cek ukuran dan hash terhadap copylog; ambil ulang dari salinan kerja |

## 5. Kesalahan umum dan jebakan

- **Mengira last write time key adalah waktu nilai tertentu ditambahkan.** Itu waktu perubahan terakhir key atau salah satu nilainya (bagian 1.2) [S11].
- **Mengabaikan transaction log.** Hive dari koleksi live hampir selalu menyimpan perubahan menit terakhir di log; tanpa replay, perubahan itu hilang dari analisis [S5][S10].
- **Mencampur zona waktu.** Sebagian besar output UTC, tetapi NetworkList dan `setupapi.dev.log` lokal [S8][S30]. Tulis zona di setiap kolom timeline.
- **Membaca USBSTOR saja.** Perangkat UASP terlewat `[komunitas]` [S29]; DFIRBatch membaca SCSI dan USB juga [S6].
- **Memakai `0064` sebagai pertama kali dicolok.** Microsoft mendefinisikannya sebagai install terakhir yang berubah saat driver diperbarui [S23].
- **Menyamakan `MountPoints2` dengan pelaku.** Ia menunjuk sesi tempat volume di-mount, bukan orangnya [S27]; jejak responder di sesi pengguna adalah contoh klasik.
- **Mengira registry membuktikan file disalin ke USB.** Registry membuktikan perangkat dikenali dan di-mount [S26][S27].
- **Menyimpulkan "tidak ada hak admin" dari SAM.** SAM hanya akun lokal dan tidak mencatat eskalasi.
- **Lupa bahwa image berisi kredensial.** SAM memuat hash akun lokal [S34] dan host menyimpan cached logon akun domain [S35].
- `[komunitas, belum terkonfirmasi]` Praktisi menyebut last write time key `Tasks\{GUID}` di TaskCache berubah setiap kali task berjalan. Day ini mengamati pola itu di contoh kasus, tetapi sumber yang diperiksa tidak mendokumentasikannya; uji di lab sebelum dipakai.

## 6. Catatan terkini

Bagian ini menampung detail versi dan perubahan yang bisa berubah lagi. Berguna saat membuka sumbernya, tetapi tidak mengubah langkah analisis di atas.

- **EZ Tools 2026.5.0** (dicek 2026-10-16): RECmd tersedia untuk .NET 4 dan .NET 9; Registry Explorer hanya .NET 9 karena alat GUI kini hanya menargetkan .NET 9; RLA terdaftar sebagai alat terpisah untuk memainkan ulang transaction log [S2]. Batch komprehensif bernama `DFIRBatch.reb` (sebelumnya disebut Kroll Batch), v2.22 [S5][S6].
- **Format transaction log baru sejak Windows 8.1**: penulisan ke file hive utama bisa ditunda sampai sekitar satu jam setelah data tersimpan di log [S10]. Hive dari Windows 7 memakai format lama dengan perilaku berbeda.
- **Windows 11**: `ProductName` di `CurrentVersion` tetap menulis Windows 10; jawaban yang diteruskan dari Microsoft Developer Support (Oktober 2021) menyebut permintaan mengubahnya ditolak demi kompatibilitas [S36]. Per 2026-10-13, Windows 11 versi 23H2 (build 22631) dijadwalkan berakhir layanannya untuk edisi Enterprise dan Education pada 2026-11-10 [S37].
- **Event 4616** didokumentasikan di halaman arsip Microsoft (Windows 10) sebagai selalu dicatat terlepas dari pengaturan subcategory [S16]; perilakunya di build Windows 11 terbaru cek di lab.
- **Dokumentasi `LeaseObtainedTime`** yang ditemukan berasal dari referensi TCP/IP Windows Server 2003 [S21]; format di Windows 11 perlu dicek di lab.
- **Autoruns** di Microsoft Learn bertanggal publikasi 2026-06-17 [S33]. **ATT&CK T1547.001** versi 2.1, diubah 2026-05-12, di ATT&CK v20 [S4].

## 7. Cheat sheet

```
HIVE         SYSTEM (waktu, service, USB/SCSI, Tcpip, MountedDevices, ShutdownTime) | SOFTWARE (OS, NetworkList,
             Run, TaskCache, Winlogon, ProfileList, WPD) | SAM (akun lokal) | NTUSER.DAT (Run user, MountPoints2)
CONTROL SET  Select\Current -> ControlSet00N  (offline tidak ada CurrentControlSet)
LAST WRITE   per KEY, FILETIME UTC; key atau salah satu nilainya berubah; value tanpa timestamp; bisa dipalsukan
HIVE KOTOR   koleksi live -> .LOG1/.LOG2 WAJIB ikut; RECmd replay default (--nl mematikan); RLA --d <dir> --out <dir>
             risiko terbesar: perubahan +/- 1 jam terakhir sebelum koleksi (sering jejak responder)
RECMD        RECmd.exe -d <folder hive> --bn ...\BatchExamples\DFIRBatch.reb --csv <out> [--csvf nama.csv]
ZONA         UTC: last write, 0064-0067, SAM F, ShutdownTime, LeaseObtainedTime (epoch 1970)
             LOKAL: NetworkList DateCreated/DateLastConnected, setupapi.dev.log, XML task RegistrationInfo
WAKTU HOST   TimeZoneInformation (UTC = lokal + Bias; WIB = -420 = 0xFFFFFE5C) | tzautoupdate Start 3 on / 4 off
             W32Time\Parameters Type (NT5DS/NTP/AllSync/NoSync) | 4616 selalu dicatat | lease DHCP vs log server
JARINGAN     NetworkList\Profiles (ProfileName, NameType 0x47/0x06/0x17, Category 0/1/2, first/last LOKAL)
             Signatures (ProfileGuid, DefaultGatewayMac, DnsSuffix) | Tcpip\...\Interfaces (lease terakhir/adapter)
             sesi: WLAN-AutoConfig/Operational (8000 mulai, 8002 gagal; sambung/putus cek ID) | volume: SRUM
USB          USBSTOR + SCSI (UASP) + USB | Properties\{83da6326-...}\0065 first, 0064 install(berubah), 0066 arrival,
             0067 removal (terakhir saja) | WPD/VolumeInfoCache label | MountedDevices huruf (pemilik terakhir)
             MountPoints2 = sesi, bukan orang | Partition/Diagnostic 1006 -> VSN | serial char-2 '&' = buatan Windows
AUTOSTART    Run/RunOnce (SOFTWARE + WOW6432Node + NTUSER tiap profil) | Policies\Explorer\Run | Winlogon Shell/Userinit
             IFEO/SilentProcessExit | Services (Start 0-4, Type 0x1/0x2/0x10/0x20, ImagePath) | TaskCache Tree (SD!) + Tasks
             pembanding: autorunsc -a * -c -h -s -t -z ...
AKUN         SAM Users\<RID> F (logon, pwdLastSet, count) V (nama, hash!) | SAMBuiltin (Administrators)
             ProfileList (SID -> folder) | cached logon default 10 di klien
BATAS        registry = keadaan + pertama/terakhir; bukan riwayat, bukan isi, bukan "file disalin"
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "Last write time key `Tree\SysCacheUpdate` adalah Senin 20:14:39 WIB, dan last write `Tasks\{GUID}` untuk task yang sama adalah Kamis 08:29:41 WIB. Jadi task itu dibuat ulang Kamis pagi." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Last write time hanya berarti key atau salah satu nilainya terakhir berubah pada waktu itu, bukan bahwa key dibuat atau nilai tertentu ditambahkan saat itu. `Tree\SysCacheUpdate` cocok dengan `RegistrationInfo` XML task dan `$MFT` `upd.ps1`, sehingga waktu pendaftaran Senin 20:14:39 didukung tiga sumber. Last write `Tasks\{GUID}` yang dekat dengan run terakhir sebelum shutdown cocok dengan pembaruan data runtime task, perilaku yang perlu diuji di lab sebelum ditulis di laporan. Lihat bagian 1.2 dan 2.6.

</details>

**2. Skenario keputusan.** Retainer mengirim daftar USB dari hive E14 laptop Rizky yang hanya berisi flashdisk pribadi Rizky. Tindakan mana yang tepat?

- A. Menyimpulkan case notes Yoga keliru, karena registry tidak mencatat USB responder.
- B. Memparse ulang hive E14 dengan transaction log dimainkan ulang, membaca USBSTOR, SCSI, dan USB, membandingkannya dengan E16, lalu mengirim salinan hive bersih dari RLA ke retainer.
- C. Menulis bahwa USB responder tidak pernah dicolok ke laptop itu.

<details><summary>Jawaban</summary>

B. E14 diambil beberapa menit setelah kedua USB dicolok, sehingga datanya masih di transaction log; alat yang tidak memainkan ulang log melihat hive yang tertinggal. Setelah replay keduanya muncul, dan SSD `USB-E-11` tercatat di `Enum\SCSI`, bukan USBSTOR. A keliru karena case notes, label, VSN, dan E16 sepakat; kesalahannya di cara membaca hive. C keliru karena "tidak terlihat di satu kueri" tidak sama dengan "tidak terjadi". Lihat bagian 1.2, 1.5, dan 2.2.

</details>

**3. Pertanyaan jebakan.** "Semua output EZ Tools memakai UTC, jadi `DateLastConnected` `HP-Rizky` 15:52:10 harus ditulis 22:52:10 WIB." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Nilai NetworkList disimpan dalam waktu lokal host, API Network List Manager juga mengembalikan waktu lokal, dan plugin `KnownNetworks` RECmd menampilkannya tanpa konversi sebagai waktu lokal. Laptop ber-zona WIB, jadi 15:52:10 sudah WIB. Menambah tujuh jam akan menaruh koneksi hotspot di malam hari, bertentangan dengan lease DHCP Wi-Fi 15:52:12 WIB dan event WLAN. Lihat bagian 1.4 dan 2.4.

</details>

**4. Skenario keputusan.** `MountPoints2` di NTUSER.DAT `rizky.saputra` memuat volume GUID `USB-E-10` dengan last write Selasa 17:43:15 WIB. Kalimat temuan mana yang tepat?

- A. "Rizky mencolok USB pukul 17:43, kemungkinan untuk menyalin data."
- B. "Volume `USB-E-10` di-mount di sesi `rizky.saputra` pukul 17:43; menurut case notes, label volume, VSN, dan waktu, perangkat itu USB bukti yang dicolok Yoga untuk mengambil memori saat sesi Rizky masih terbuka (jejak responder)."
- C. "Baris ini jejak responder, jadi dihapus dari timeline."

<details><summary>Jawaban</summary>

B. `MountPoints2` menunjuk sesi tempat volume di-mount, bukan orang yang mencolok, dan atribusinya ke responder didukung case notes, label, VSN, dan waktu. A keliru karena menyimpulkan pelaku dan niat dari satu key. C keliru karena jejak responder diberi label, bukan dihapus, supaya pembaca laporan bisa memeriksanya. Lihat bagian 1.5 dan 2.5.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Dimas Prasetyo (IC), dalam tiga kalimat, kenapa waktu Senin 20:14:21 WIB tetap bisa dipegang walaupun laptop Rizky di luar kantor dan tidak tersinkron ke domain.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Windows menyimpan waktu Prefetch dalam UTC, jadi 20:14:21 WIB adalah konversi tetap dan tidak bergantung pada pengaturan zona laptop, yang memang WIB sejak dipasang. Yang bisa salah hanya jam internal laptop, dan kami mengukurnya: selisih 2 detik Selasa sore dari lease DHCP dibanding log server, 3 detik Kamis pagi, tanpa satu pun penyetelan jam yang tercatat di antaranya. Jadi waktu Senin malam benar dengan ketelitian beberapa detik, cukup untuk semua kesimpulan di laporan."

Kesalahan yang sering muncul:
- Mengatakan zona waktu laptop "mengoreksi" waktu Prefetch, padahal Prefetch sudah UTC.
- Mengklaim jam Senin malam diukur langsung, padahal disimpulkan dari batas Selasa dan Kamis.
- Menulis "tidak ada 4616 berarti jam tepat", padahal koreksi kecil tidak menghasilkan 4616.

</details>

**6. Pertanyaan jebakan.** "SAM laptop Rizky tidak memuat akun lokal baru dan anggota Administrators tidak berubah, jadi penyerang tidak pernah punya hak admin di laptop itu." Benarkah?

<details><summary>Jawaban</summary>

Tidak. SAM hanya memuat akun lokal dan keanggotaan grup lokal; ia tidak mencatat eskalasi hak, pemakaian token, atau eksploitasi. Ketiadaan akun baru hanya menjawab "apakah penyerang membuat akun lokal". Pertanyaan hak admin dijawab event log, artefak eksekusi, dan memori. Lihat bagian 1.7 dan 2.7.

</details>

**7. Interview question (English).** "You receive registry hives from a live triage collection. How do you process them, and how far do you trust registry timestamps?"

<details><summary>Sample answer</summary>

"First I make sure the transaction logs were collected with each hive, because a hive copied from a running system is usually dirty: since Windows 8.1 the most recent changes can sit in the .LOG1 and .LOG2 files for up to about an hour before they reach the primary file. I parse with a tool that replays the logs, RECmd does it by default, or I produce clean copies with RLA for other tools, and I compare with and without replay when it matters. Then I treat timestamps carefully. A key's last write time is a single UTC value that tells me the key or one of its values changed, not which value or why, and it can be set deliberately. Times stored inside values vary: device install and arrival times are UTC FILETIMEs, while NetworkList dates and setupapi logs are in local time. So I label the time zone of every column, I read the host's time zone and time source, and I corroborate anything important with event logs, file system metadata or external logs before it goes into a report."

What makes this answer strong: it starts with collection completeness, names the concrete risk window, separates key last write time from times inside values, calls out the local-time exceptions, and ends with corroboration.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | SANS: Windows Forensic Analysis poster (hive, key, last write, USB, SAM) | https://www.sans.org/posters/windows-forensic-analysis/ | sekunder (SANS) | diakses 2026-10-09 | Sedang-tinggi. Struktur hive, hive sistem vs user, serial `&`, RID akun bawaan. Isi poster di balik login |
| S2 | Eric Zimmerman tools: RECmd, Registry Explorer, RLA | https://ericzimmerman.github.io/ | primer | diakses 2026-10-09, dicek ulang 2026-10-16 | Tinggi. Versi 2026.5.0; RECmd .NET 4 dan .NET 9, Registry Explorer hanya .NET 9 dan menangani file terkunci; RLA untuk replay transaction log |
| S3 | Microsoft Learn: Registry | https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry | primer | diakses 2026-10-09 | Tinggi untuk struktur dasar registry |
| S4 | MITRE ATT&CK T1547.001 Registry Run Keys / Startup Folder | https://attack.mitre.org/techniques/T1547/001/ | primer | versi 2.1, diubah 2026-05-12 (ATT&CK v20); diakses 2026-10-10, dicek ulang 2026-10-16 | Tinggi. Daftar Run, RunOnce, RunOnceEx, RunServices, Policies\Explorer\Run, `load`, `BootExecute`, Shell Folders, folder Startup; Winlogon di T1547.004 |
| S5 | RECmd README (termasuk RLA) | https://raw.githubusercontent.com/EricZimmerman/RECmd/master/README.md | primer | diakses 2026-10-16 | Tinggi. Opsi `-d`, `-f`, `--bn`, `--csv`, `--nl` (default false), `--recover` (default true), `--vss`; RLA `--d`, `--f`, `--out`, `--ca`; `Unblock-File` untuk plugin; DFIR Batch (sebelumnya Kroll Batch) |
| S6 | RECmd BatchExamples: DFIRBatch.reb | https://raw.githubusercontent.com/EricZimmerman/RECmd/master/BatchExamples/DFIRBatch.reb | primer | v2.22; diakses 2026-10-16 | Tinggi. Entri TimeZoneInformation, ComputerName, NetworkList (`KnownNetworks`), Tcpip Interfaces, USBSTOR, USB, SCSI, MountedDevices, WPD, VolumeInfoCache, MountPoints2, Run/RunOnce, Services, TaskCache, Winlogon, IFEO, SAM, ProfileList, Select, ShutdownTime, ProductName |
| S7 | GitHub EricZimmerman/RegistryPlugins | https://github.com/EricZimmerman/RegistryPlugins | primer | diakses 2026-10-16 | Tinggi. Daftar plugin: KnownNetworks, USBSTOR, USB, SCSI, MountedDevices, WindowsPortableDevices, VolumeInfoCache, TaskCache, Services, SAM, SAMBuiltin, ProfileList, TimeZoneInformation |
| S8 | RegistryPlugin.KnownNetworks (KnownNetworks.cs) | https://raw.githubusercontent.com/EricZimmerman/RegistryPlugins/master/RegistryPlugin.KnownNetworks/KnownNetworks.cs | primer (kode sumber plugin) | diakses 2026-10-16 | Tinggi. Membaca Profiles dan Signatures (Managed/Unmanaged, `DefaultGatewayMac`, `DnsSuffix`, `ProfileGuid`, `FirstNetwork`); SYSTEMTIME tanpa konversi, ditampilkan sebagai waktu lokal; `Category` tidak dibaca |
| S9 | Microsoft Learn: Registry Hives | https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives | primer | ms.date 2018-05-31, diperbarui 2025-03-11; diakses 2026-10-16 | Tinggi. Definisi hive, hive profil user, lokasi `System32\Config`, arti ekstensi (tanpa ekstensi, `.alt`, `.log`, `.sav`) |
| S10 | Windows registry file format specification (msuhanov/regf) | https://raw.githubusercontent.com/msuhanov/regf/master/Windows%20registry%20file%20format%20specification.md | primer (spesifikasi hasil reverse engineering) | diakses 2026-10-16 | Tinggi. Hive kotor (checksum, sequence number), format log lama dan baru (Windows 8.1+), LOG1/LOG2 bergantian, penundaan tulis hingga sekitar satu jam, last written timestamp FILETIME UTC di key node, value tanpa timestamp, sisa record di sel tak teralokasi |
| S11 | Microsoft Learn: RegQueryInfoKeyW | https://learn.microsoft.com/en-us/windows/win32/api/winreg/nf-winreg-regqueryinfokeyw | primer | ms.date 2018-12-05, diperbarui 2026-05-15; diakses 2026-10-16 | Tinggi. Last write time = terakhir key atau salah satu nilainya diubah |
| S12 | Microsoft Learn: KEY_SET_INFORMATION_CLASS (wdm.h) | https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ne-wdm-_key_set_information_class | primer | ms.date 2018-04-30; diakses 2026-10-16 | Tinggi. `KeyWriteTimeInformation` untuk menetapkan write time key |
| S13 | Microsoft Learn: TIME_ZONE_INFORMATION | https://learn.microsoft.com/en-us/windows/win32/api/timezoneapi/ns-timezoneapi-time_zone_information | primer | ms.date 2018-12-05; diakses 2026-10-16 | Tinggi. Bias dalam menit, UTC = lokal + bias; definisi zona di `Time Zones\<nama>` dengan nilai `TZI` |
| S14 | Microsoft Learn: Can't set time zone automatically | https://learn.microsoft.com/en-us/troubleshoot/windows-client/shell-experience/cannot-set-timezone-automatically | primer | ms.date 2026-02-12; diakses 2026-10-16 | Tinggi. `tzautoupdate\Start` 3 aktif, 4 mati; izin lokasi `ConsentStore\location\Value`; berlaku Windows 10 |
| S15 | Microsoft Learn: Windows Time Service Tools and Settings | https://learn.microsoft.com/en-us/windows-server/networking/windows-time-service/windows-time-service-tools-and-settings | primer | ms.date 2025-09-18; diakses 2026-10-16 | Tinggi. `W32Time\Parameters\Type` (NT5DS default anggota domain), `MaxAllowedPhaseOffset` 300 s anggota domain, koreksi perlahan vs setel langsung, `UtilizeSslTimeData` |
| S16 | Microsoft Learn: 4616(S) The system time was changed | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4616 | primer (arsip) | ms.date 2021-09-07; diakses 2026-10-16 | Tinggi. Selalu dicatat terlepas dari subcategory; koreksi rutin oleh LOCAL SERVICE/svchost; PreviousTime dan NewTime UTC |
| S17 | Microsoft Learn: INetwork::GetTimeCreatedAndConnected | https://learn.microsoft.com/en-us/windows/win32/api/netlistmgr/nf-netlistmgr-inetwork-gettimecreatedandconnected | primer | ms.date 2018-12-05; diakses 2026-10-16 | Tinggi untuk API: mengembalikan waktu lokal saat jaringan dibuat dan tersambung. Penyimpanan di registry disimpulkan bersama [S8][S18] |
| S18 | Dr. Datenschutz (intersoft consulting): Daten verraten alle jemals verbundenen Netzwerke | https://www.dr-datenschutz.de/daten-verraten-alle-jemals-verbundenen-netzwerke/ | sekunder (praktisi) | 2019-08-30 (>3 tahun); diakses 2026-10-16 | Sedang. Path Profiles, waktu lokal bukan UTC, `NameType` 0x47/0x06/0x17, `Category` 0/1/2, MAC gateway untuk lokasi access point |
| S19 | Cyber Triage: How to Find Evidence of Network Windows Registry | https://www.cybertriage.com/?p=27764 | sekunder (vendor alat) | 2025-04-17, ditinjau 2026; diakses 2026-10-16 | Sedang. `DateCreated` pertama dan `DateLastConnected` terakhir, `Category`, `ProfileName`, Signatures, interface Tcpip; hanya pertama dan terakhir |
| S20 | Plaso: parser winreg_plugins networks (NetworkList) | https://plaso-fork.readthedocs.io/en/latest/_modules/plaso/parsers/winreg_plugins/networks.html | primer (kode sumber proyek) | diakses 2026-10-16 | Sedang-tinggi. Profiles dan Signatures, `ProfileGuid`, `DefaultGatewayMac`, `DnsSuffix`, peta `NameType`. Halaman berupa fork dokumentasi Plaso |
| S21 | Microsoft Learn: Appendix A: TCP/IP Configuration Parameters (Windows Server 2003) | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc739819(v=ws.10) | primer (arsip) | ms.date 2010-05-26 (>3 tahun); diakses 2026-10-16 | Sedang-tinggi. `LeaseObtainedTime`, `LeaseTerminatesTime` detik sejak 1970, `Lease`, `DhcpIPAddress`, `DhcpServer`; perilaku Windows 11 perlu dicek |
| S22 | Microsoft Learn: 802.11 Wireless Connectivity (event WLAN-AutoConfig) | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2008-R2-and-2008/cc727690(v=ws.10) | primer (arsip) | ms.date 2010-02-02 (>3 tahun); diakses 2026-10-16 | Sedang. Event 8000 (mulai menyambung) dan 8002 (gagal) dengan profil dan SSID; ID sukses sambung dan putus tidak tercantum |
| S23 | Microsoft Learn: DEVPKEY_Device_InstallDate | https://learn.microsoft.com/en-us/windows-hardware/drivers/install/devpkey-device-installdate | primer | ms.date 2022-06-23; diakses 2026-10-16 | Tinggi. Waktu instance perangkat terakhir di-install; berubah setiap pembaruan driver; FILETIME |
| S24 | Microsoft Learn: DEVPKEY_Device_FirstInstallDate | https://learn.microsoft.com/en-us/windows-hardware/drivers/install/devpkey-device-firstinstalldate | primer | ms.date 2022-06-23; diakses 2026-10-16 | Tinggi. Waktu pertama di-install; tidak berubah oleh pembaruan driver |
| S25 | mingw-w64 headers: devpkey.h | https://raw.githubusercontent.com/mingw-w64/mingw-w64/master/mingw-w64-headers/include/devpkey.h | primer (header publik, tiruan SDK) | diakses 2026-10-16 | Tinggi. GUID `83da6326-...`: InstallDate 100, FirstInstallDate 101, LastArrivalDate 102, LastRemovalDate 103 |
| S26 | Elcomsoft: USB Device Forensics on Windows 10 and 11 | https://blog.elcomsoft.com/2026/02/usb-device-forensics-on-windows-10-and-11/ | sekunder (vendor forensik) | 2026-02-25; diakses 2026-10-16 | Sedang-tinggi. Key USB/USBSTOR/WPDBUSENUM, `0x64`-`0x67` UTC, Partition/Diagnostic 1006 dan offset VSN, last write tidak menunjuk nilai, bukti perangkat bukan transfer file |
| S27 | IT-Connect: Forensic Windows Part 15, Tracing USB Device History | https://www.it-connect.tech/forensic-windows-part-15-tracing-usb-device-history/ | sekunder (praktisi) | 2026-10-09; diakses 2026-10-16 | Sedang. Rantai MountPoints2, MountedDevices, USBSTOR, setupapi; MountPoints2 bukan bukti pencolok; registry hanya koneksi terakhir; DriverFrameworks mati default |
| S28 | Magnet Forensics: Artifact Profile, USB Devices | https://www.magnetforensics.com/blog/artifact-profile-usb-devices/ | sekunder (vendor alat) | 2016-03-10 (>3 tahun); diakses 2026-10-16 | Sedang. USB, USBSTOR, Windows Portable Devices, MountedDevices, MountPoints2; setupapi waktu lokal |
| S29 | Security Ronin: usb-forensic README | https://docs.rs/crate/usb-forensic/0.2.0/source/README.md | komunitas (proyek alat sumber terbuka) | 2026; diakses 2026-10-16 | Rendah-sedang. Perangkat UASP (`uaspstor.sys`) terdaftar di `Enum\SCSI`, bukan USBSTOR; belum dikonfirmasi dokumentasi Microsoft |
| S30 | Microsoft Learn: Format of a Text Log Section Header (SetupAPI) | https://learn.microsoft.com/en-us/windows-hardware/drivers/install/format-of-a-text-log-section-header | primer | ms.date 2017-04-20; diakses 2026-10-16 | Tinggi. Timestamp `yyyy/mm/dd hh:mm:ss.sss` dalam waktu lokal |
| S31 | Microsoft Security Blog: Tarrask malware uses scheduled tasks for defense evasion | https://www.microsoft.com/en-us/security/blog/2022/04/12/tarrask-malware-uses-scheduled-tasks-for-defense-evasion/ | primer (vendor) | 2022-04-12 (>3 tahun); diakses 2026-10-16 | Tinggi. TaskCache `Tree` (`Id`, `Index`, `SD`) dan `Tasks\{GUID}`, XML di `System32\Tasks`, task tersembunyi tanpa `SD`, 4698 tidak diaudit default |
| S32 | Microsoft Learn: HKLM\SYSTEM\CurrentControlSet\Services Registry Tree | https://learn.microsoft.com/en-us/windows-hardware/drivers/install/hklm-system-currentcontrolset-services-registry-tree | primer | ms.date 2024-09-18; diakses 2026-10-16 | Tinggi. `Start` 0-4, `Type` 0x1/0x2/0x10/0x20, `ImagePath`, `ErrorControl` |
| S33 | Microsoft Learn: Autoruns (Sysinternals) | https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns | primer | dipublikasikan 2026-06-17; diakses 2026-10-16 | Tinggi. Opsi autorunsc `-a`, `-c`, `-h`, `-m`, `-s`, `-t`, `-z` (sistem offline) |
| S34 | winreg-kb: Security Accounts Manager (SAM) keys, Domains | https://winreg-kb.readthedocs.io/en/latest/sources/security-accounts-manager-keys/Domains.html | primer (dokumentasi format, reverse engineering) | diakses 2026-10-16 | Sedang-tinggi. Subkey RID, nilai `F` (offset last logon, pwdLastSet, accountExpires, badPasswordTime, RID, flags, badPwdCount, logonCount) dan `V` (nama, hash LM dan NTLM); zona UTC tidak disebut eksplisit |
| S35 | Microsoft Learn: Interactive logon, Number of previous logons to cache | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/interactive-logon-number-of-previous-logons-to-cache-in-case-domain-controller-is-not-available | primer (arsip) | ms.date 2018-08-27; diakses 2026-10-16 | Tinggi. Default efektif klien 10, tidak kedaluwarsa, risiko brute force, disimpan terenkripsi di registry; berlaku Windows 10 dan 11 |
| S36 | Microsoft Q&A: Windows 11 Product Name in registry | https://learn.microsoft.com/en-us/answers/questions/555857/windows-11-product-name-in-registry | komunitas (jawaban yang diteruskan dari Microsoft Developer Support) | 2021-10-13; diakses 2026-10-16 | Sedang. Sebagian nilai `CurrentVersion` tidak diubah saat upgrade ke Windows 11; pakai API atau nomor build |
| S37 | Microsoft Learn: Windows 11 release information | https://learn.microsoft.com/en-us/windows/release-health/windows11-release-information | primer | diperbarui 2026-10-13; diakses 2026-10-16 | Tinggi. Build per versi (21H2 22000 sampai 26H2 26300) dan tanggal akhir layanan |
| S38 | Microsoft Learn: Audit Security State Change | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-security-state-change | primer (arsip) | ms.date 2021-09-06; diakses 2026-10-16 | Tinggi. Subcategory memuat 4608, 4616, 4621; volume rendah |
| S39 | HackMD (chinhnamdo): catatan Registry Explorer dan transaction log | https://hackmd.io/@chinhnamdo/H1aW5MKtA | komunitas (catatan belajar) | diakses 2026-10-16 | Rendah-sedang. Registry Explorer menambahkan data transaction log ke hive; bisa ada `.LOG1` dan `.LOG2` |

**Catatan sumber:** fakta inti last write time, transaction log, zona waktu, pengaturan waktu host, properti perangkat, service, TaskCache, Autoruns, dan cached logon berasal dari dokumentasi Microsoft [S9]-[S16][S21]-[S24][S30]-[S33][S35]-[S38], spesifikasi format [S10][S34], header publik [S25], dan kode sumber plugin [S6]-[S8][S20]. Beberapa klaim lebih lemah dan ditulis apa adanya. Penyimpanan waktu NetworkList sebagai waktu lokal disimpulkan dari API Microsoft [S17], kode plugin RECmd [S8], dan praktisi [S18]; satu contoh dekode dari vendor lain sempat menyebut UTC, jadi buktikan di lab (bagian 3, langkah 9). Perilaku perangkat UASP di `Enum\SCSI` hanya dari sumber komunitas [S29] dan didukung adanya entri SCSI di DFIRBatch [S6]. ID event WLAN sukses sambung dan putus tidak ditemukan di dokumentasi Microsoft yang diperiksa [S22]. Pembaruan last write `Tasks\{GUID}` saat task berjalan, dan efek elevasi UAC terhadap `LastLogon`, `LoginCount`, dan folder profil di SAM, belum terdokumentasi di sumber yang diperiksa dan harus diuji di lab. Day lama menulis subkey `0064` sebagai first install; Day ini mengikuti header `devpkey.h` dan dokumentasi Microsoft [S23]-[S25] yang menempatkan first install di `0065` dan install terakhir di `0064`. Semua isi PT JAB, termasuk SSID, lokasi rapat, MAC, alamat IP DHCP, serial perangkat, VSN, SID, RID, nama grup domain, dan waktu, adalah contoh fiktif.
