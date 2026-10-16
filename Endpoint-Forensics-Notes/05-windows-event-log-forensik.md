---
day: 05
title: 'Windows event log untuk forensik: channel, logon session, eksekusi dan task, audit policy, EvtxECmd, dan memisahkan responder dari penyerang'
researched_on: 2026-10-16
versions_checked: 'Halaman event Security di Microsoft Learn (arsip Windows 10, diperbarui 2026-04): 4624 ms.date 2021-09-07 (event versi 2 sejak Windows 10), 4625 ms.date 2026-03-29, 4648, 4672, 4688 (ms.date 2022-01-24), 4697, 4698 (field tambahan sejak Windows 10 1903), 4720, 4732, 1102; System Audit Policy recommendations (ms.date 2025-06-13, Audit Logon Success dan Failure bawaan sejak Windows 10 1809); Command line process auditing (ms.date 2025-05-12); Sysmon (terbit 2026-09-10, Windows 11 dan Server 2019 ke atas, event ID 1-29 dan 255); about_Logging_Windows (PowerShell 7.6, ms.date 2026-01-18) dan about_Logging (Windows PowerShell 5.1, ms.date 2024-01-09); EvtxECmd 2026.5.0 (.NET 4.7.2 dan .NET 9) dan Timeline Explorer 2026.5.0 (.NET 9); repo evtx maps (dicek 2026-10-16); Velociraptor artifact Windows.EventLogs.PowershellScriptblock (dokumentasi 0.77.x)'
---

# Day 05: Windows event log untuk forensik (logon, eksekusi, task, audit policy, dan pembersihan log)

Cakupan: membaca event log Windows dari image atau koleksi untuk merekonstruksi logon session, eksekusi, persistence lewat task dan service, dan PowerShell, memisahkan aktivitas responder dari aktivitas penyerang, menilai apakah ketiadaan event berarti ketiadaan aktivitas, dan mencari tanda pembersihan log.

## Ide inti

Event log Windows bukan rekaman semua yang terjadi di host, melainkan rekaman apa yang host itu dikonfigurasi untuk dicatat, selama file log-nya belum berputar. Isi log Security ditentukan audit policy; isi log PowerShell ditentukan kebijakan script block logging; Sysmon hanya ada bila dipasang dan hanya mencatat yang diizinkan konfigurasinya. Karena itu setiap investigasi event log punya dua langkah yang tidak boleh ditukar urutannya. Langkah pertama adalah memetakan apa yang memang dicatat dan sampai kapan (channel, audit policy, rentang waktu tiap file). Langkah kedua baru merekonstruksi cerita, dan kuncinya adalah logon session: satu Logon ID menyatukan logon, hak istimewa, proses, task, dan logoff milik satu sesi, sehingga kamu bisa menjawab "siapa melakukan apa" tanpa menebak dari nama akun saja. Responder juga meninggalkan jejak di log yang sama, jadi pemisahan "kita" dan "mereka" adalah bagian dari analisis, bukan catatan kaki.

Kamu sudah mengenal polanya dari NOC. Log perangkat hanya berisi apa yang dikonfigurasi lewat `logging` dan `aaa accounting`; bila accounting perintah tidak dinyalakan, tidak ada catatan siapa mengetik `reload`, dan itu bukan berarti tidak ada yang mengetiknya. Buffer log berputar dan menimpa yang lama. Setiap sesi TACACS atau RADIUS punya session ID yang menyatukan start, perintah, dan stop, dan dengan ID itulah kamu memisahkan sesi engineer yang sedang troubleshoot dari sesi orang yang tidak dikenal. Perintah `clear logging` juga tercatat. Event log Windows bekerja dengan logika yang sama: audit policy adalah konfigurasi accounting-nya, Logon ID adalah session ID-nya, dan event 1102 serta 104 adalah jejak `clear logging`-nya.

```
image / koleksi (salinan kerja, read-only)
  |
  v
1. PETAKAN APA YANG DICATAT
   file .evtx per channel -> rentang waktu tiap file (rotasi?)
   audit policy / GPO / Sysmon / script block logging -> event apa yang MUNGKIN ada
   1102, 104, 4719, lompatan record -> pernah dibersihkan atau diubah?
  |
  v
2. PARSE: EvtxECmd + maps -> CSV (UTC) -> Timeline Explorer / PowerShell
  |
  v
3. SUSUN SESI: 4624/4625/4672/4634/4647 per Logon ID, logon type, sumber
  |
  v
4. ISI SESI: 4688 / Sysmon 1 (proses), 4698 / 106 / 200-201 (task), 7045 / 4697 (service),
            4104 (isi PowerShell), Sysmon 3 / 22 (jaringan)
  |
  v
5. PISAHKAN PELAKU: pengguna | penyerang | responder (akun, Logon ID, induk proses, path, case notes)
  |
  v
timeline WIB + "yang tidak tercatat dan kenapa"
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan sekitar 1.200 karyawan dan data pribadi sekitar 400 ribu pelanggan broadband di sistem billing. Kasusnya `INC-2026-019`: email dari `billing@vendor-tagihan.example` dengan lampiran `Tagihan-Okt-2026.zip` (berisi `Tagihan-Okt-2026.js`) masuk ke 9 mailbox pada Senin 2026-10-12 pukul 15:58. Salah satu yang menjalankannya adalah `andi.pratama`, staf penagihan Jakarta, di laptop `JKT-WS-0388` (`10.10.23.88`, Windows 11, Microsoft Defender for Endpoint, Sysmon). Penyerang memasang scheduled task `\SysCacheUpdate` yang menjalankan `C:\Users\andi.pratama\AppData\Roaming\SysCache\upd.ps1`, berkomunikasi dengan C2 `cdn-sync.example.net` (`203.0.113.77:443`), membaca password akun service `svc_billing` dari skrip `C:\Users\andi.pratama\Documents\export-tagihan.ps1`, lalu memakainya untuk SSH ke server billing `jkt-billing01` (`10.20.5.21`) Selasa dini hari. Alert pertama `SOC-2026-0203` muncul Selasa 09:47. Selasa siang Yoga Pratama, analyst L2 yang memegang bukti, mengambil memori laptop itu di tempat. Kamis 2026-10-15 pukul 09:00 laptop di-image (bukti `INC-2026-019-E15`) lalu di-reimage. Laptop kedua yang relevan di Day ini, `JKT-WS-0412` milik `rizky.saputra` (tanpa EDR), sudah dikoleksi dengan KAPE Selasa malam (E14) dan diolah kemarin (Day 03).

Jumat 2026-10-16 pukul 08:10 Yoga membuat salinan kerja `E15-W1` di `\\jkt-evid01\cases\INC-2026-019\work\` setelah memverifikasi hash master. Pukul 08:30 Sari Kusuma, technical lead, menulis kepadamu di kanal `#inc-2026-019`:

> "Pagi. E15-W1 sudah siap, hash cocok. Hari ini aku perlu timeline laptop Andi dari event log: siapa login dan kapan, apa saja yang dijalankan, dan bagaimana task `\SysCacheUpdate` dibuat. Laporan awal retainer menyebut 'aktivitas akun admin lokal pada 13 Oktober siang', dan Pak Agus langsung tanya apakah penyerang sempat punya hak admin. Tolong pisahkan mana aktivitas Yoga dan mana penyerang. Retainer juga tanya apakah ada RDP atau logon dari host lain, dan apakah log pernah dibersihkan. Satu lagi: di E14 laptop Rizky tidak ada 4698 sama sekali, padahal task-nya jelas ada. Kalau nanti ada yang tanya 'kenapa tidak ada di log', aku mau jawabannya sudah siap. Draf sebelum jam 14:00 ya."

Pesan itu memuat enam pertanyaan:

1. Log apa saja yang ada di E15-W1, sampai kapan isinya, dan bagaimana membacanya tanpa salah kolom?
2. Siapa login ke laptop Andi, kapan, dengan cara apa, dan adakah RDP atau logon dari host lain?
3. Apa yang dijalankan, dan bagaimana task `\SysCacheUpdate` dibuat?
4. Aktivitas akun admin lokal Selasa siang itu milik siapa, dan apakah penyerang sempat punya hak admin?
5. Kenapa E14 tidak punya 4698, dan apa artinya bagi kesimpulan?
6. Apakah log pernah dibersihkan atau dimanipulasi?

Pertanyaan 1 dijawab di bagian 1.1 dan 1.7, pertanyaan 2 di bagian 1.2, pertanyaan 3 di bagian 1.3, pertanyaan 4 di bagian 1.4, pertanyaan 5 di bagian 1.5, dan pertanyaan 6 di bagian 1.6. Bagian 2 berisi perintah, hasil parse, dan timeline yang kamu kirim ke Sari.

**Kapan relevan:** hampir setiap investigasi endpoint Windows: rekonstruksi logon dan sesi, eksekusi, persistence lewat task dan service, aktivitas PowerShell, lateral movement yang memakai autentikasi Windows, dan pemeriksaan pembersihan log, terutama saat host sudah di-image atau dikoleksi dan tidak bisa ditanya lagi.
**Kapan bukan jawaban:** saat pertanyaannya tentang isi file, file yang dihapus, atau apa yang dibaca dari disk tanpa jejak skrip (file system dan artefak eksekusi di Day 07 dan Day 08); saat audit policy tidak mencatat kategori yang dibutuhkan atau log sudah berputar (sumber lain: SIEM, EDR, artefak disk); dan saat yang dibutuhkan adalah deteksi real-time, karena Day ini membaca log setelah kejadian, bukan menulis rule.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day 01-04 (salinan kerja, hash bukti, case notes, triage collection, container KAPE, `!EZParser`, hunt) tidak diulang. Tabel ini memuat istilah event log yang dipakai di Day ini; kolom padanan memakai analogi NOC dan SOC.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| Channel dan file `.evtx` | Satu aliran log (Security, System, Sysmon/Operational, dan seterusnya) yang disimpan sebagai satu file `.evtx` dengan ukuran maksimum | Satu buffer `logging` per fasilitas di perangkat, dengan ukuran yang dikonfigurasi |
| Audit policy (advanced, per subcategory) | Konfigurasi yang menentukan event Security mana yang ditulis Windows | Konfigurasi `aaa accounting` dan `logging`: yang tidak dikonfigurasi tidak tercatat |
| Logon session dan Logon ID | Sesi yang dibuat setiap logon berhasil; Logon ID heksadesimal mengikat event lain ke sesi itu | Session ID di accounting TACACS/RADIUS yang menyatukan start, perintah, dan stop |
| Logon type | Angka di 4624/4625 yang menyebut cara logon (2 konsol, 3 jaringan, 10 RDP, dan seterusnya) | Jenis akses ke perangkat: console, VTY lewat SSH, atau SNMP |
| Linked Logon ID dan elevated token | Pasangan sesi untuk akun admin saat UAC aktif; satu sesi terbatas, satu sesi penuh | Dua level privilege dalam satu login: user mode lalu `enable` |
| Script block logging (4104) | Pencatatan isi kode PowerShell yang diproses, termasuk hasil decode `-enc` | Accounting perintah yang mencatat perintah persis yang diketik, bukan hanya nama sesinya |
| Sysmon | Service dan driver Sysinternals yang menulis event proses, jaringan, file, dan registry ke channel sendiri | Sensor NetFlow tambahan yang dipasang di link tertentu: hanya ada bila dipasang dan dikonfigurasi |
| Map EvtxECmd | File yang memetakan field XML tiap event ke kolom CSV yang seragam | Template parsing syslog yang mengubah pesan vendor menjadi field |
| Pembersihan log (1102, 104) | Event yang ditulis saat sebuah log dikosongkan, berisi akun yang melakukannya | Jejak `clear logging` di log perangkat |
| Rotasi dan retensi channel | Event lama ditimpa saat file mencapai ukuran maksimum | Buffer log yang berputar dan menimpa data lama |

### 1.1 Channel dan file `.evtx`: apa yang dicatat di mana

Pertanyaan pertama Sari dimulai dari inventaris, bukan dari filter. Sebelum mencari 4698, kamu harus tahu file mana yang ada di E15-W1 dan sampai tanggal berapa isinya.

Event log Windows terbagi ke channel, dan setiap channel disimpan sebagai file `.evtx` di `C:\Windows\System32\winevt\Logs\` [S1]. Nama file memakai `%4` sebagai pengganti garis miring, misalnya `Microsoft-Windows-Sysmon%4Operational.evtx` untuk channel `Microsoft-Windows-Sysmon/Operational`. Tabel berikut memetakan channel yang paling sering dipakai ke pertanyaan forensik yang dijawabnya; perhatikan kolom kanan, karena di situlah syarat agar event itu ada.

| Channel | Pertanyaan forensik | Event kunci | Syarat agar ada |
|---|---|---|---|
| Security | Siapa login, kapan, dari mana, dengan hak apa; akun dan grup berubah; proses dan task dibuat; log dihapus | 4624, 4625, 4634, 4647, 4648, 4672, 4688, 4697, 4698, 4720, 4728, 4732, 4719, 1102 | Audit policy per subcategory (bagian 1.5) |
| System | Service dipasang atau berubah; sistem nyala atau mati; driver; log lain dibersihkan | 7045, 7034, 7036, 7040, 6005, 6006, 1074, 104 | Bawaan |
| Application | Error aplikasi; sebagian log antivirus | bervariasi | Bawaan, isi bergantung aplikasi |
| Microsoft-Windows-PowerShell/Operational | Isi kode Windows PowerShell 5.1 yang dijalankan | 4103, 4104 | Script block logging atau module logging; tanpa itu hanya blok yang dianggap mencurigakan [S20][S21] |
| PowerShellCore/Operational | Isi kode PowerShell 7 | 4104 | Provider PowerShell 7 terdaftar dan script block logging aktif [S6] |
| Microsoft-Windows-Sysmon/Operational | Proses (1), koneksi jaringan (3), file dibuat (11), registry (12-14), DNS (22), dan lainnya | 1, 3, 11, 13, 22 | Sysmon dipasang; sebagian event (3, 7) mati tanpa konfigurasi [S5] |
| Microsoft-Windows-TaskScheduler/Operational | Task didaftarkan, diubah, dihapus, dijalankan | 106, 140, 141, 200, 201 | Channel history aktif; beberapa sumber menyebut mati secara bawaan (bagian 1.5) |
| Microsoft-Windows-TerminalServices-* | Sesi RDP | LocalSessionManager 21-25; RemoteConnectionManager 1149 | Bawaan pada host yang menerima RDP |
| Microsoft-Windows-WinRM/Operational | Remote management (lateral movement) | bervariasi | Bawaan bila WinRM dipakai |

Dua hal yang sering terlewat. Pertama, PowerShell 7 menulis ke channel berbeda (`PowerShellCore/Operational`) dari Windows PowerShell 5.1 (`Microsoft-Windows-PowerShell/Operational`) [S6][S20]; host yang punya keduanya punya dua tempat untuk dicari. Kedua, timestamp Sysmon dalam UTC [S5], dan output EvtxECmd juga dalam UTC, sehingga laporan PT JAB yang memakai WIB (UTC+7) selalu butuh konversi yang ditulis eksplisit.

Sebagian event bergantung versi Windows dan audit policy. Pastikan event yang kamu andalkan memang muncul di VM lab dengan build yang sama sebelum memakainya untuk kesimpulan kasus.

### 1.2 Logon session: Logon ID, logon type, dan siapa sebenarnya yang login

Pertanyaan kedua Sari ("siapa login, kapan, dengan cara apa") dijawab dari event logon di log Security, tetapi satu event 4624 saja belum menjawabnya. Yang perlu disusun adalah sesi.

Event 4624 ditulis di komputer yang diakses, tempat sesi dibuat; untuk logon jaringan seperti akses share, itu komputer pemilik resource [S3][S18]. Event 4625 ditulis di komputer tempat percobaan logon dilakukan dan mencatat setiap kegagalan [S7]. Tabel berikut memuat event logon yang dipakai untuk menyusun sesi.

| Event ID | Arti | Catatan forensik |
|---|---|---|
| 4624 | Logon sukses | LogonType menentukan sifat logon; `TargetLogonId` mengikat event lain ke sesi ini [S3] |
| 4625 | Logon gagal | `Status` dan `SubStatus` menyebut alasannya; rangkaian kegagalan lalu sukses dari sumber yang sama menandakan brute force (T1110) [S7] |
| 4634 / 4647 | Logoff / logoff yang diminta pengguna | Pasangkan dengan 4624 lewat Logon ID untuk durasi sesi |
| 4648 | Logon dengan kredensial eksplisit | `runas`, task, atau alat yang memakai kredensial lain; ditulis di host tempat proses itu berjalan, dengan nama server tujuan (`localhost` bila lokal) [S8] |
| 4672 | Hak istimewa sensitif diberikan ke sesi baru | Muncul untuk sesi dengan hak seperti SeDebugPrivilege atau SeSecurityPrivilege; setiap logon SYSTEM memicunya [S9] |

Logon type adalah kunci tafsir. Daftar resmi di halaman 4624 memuat sebelas nilai [S3]; tabel berikut menambahkan contoh situasi yang biasa ditemui.

| LogonType | Nama | Contoh situasi |
|---|---|---|
| 0 | System | Hanya akun System, misalnya saat startup |
| 2 | Interactive | Login di konsol atau layar fisik, termasuk Switch user |
| 3 | Network | Akses share SMB, PsExec, WMI remote, WinRM |
| 4 | Batch | Proses yang berjalan atas nama pengguna tanpa interaksi, misalnya task dengan kredensial tersimpan |
| 5 | Service | Service yang dijalankan Service Control Manager dengan akun tertentu |
| 7 | Unlock | Membuka kunci layar |
| 8 | NetworkCleartext | Autentikasi jaringan yang menerima password belum di-hash, misalnya IIS basic auth |
| 9 | NewCredentials | `runas /netonly`: identitas lokal sama, kredensial untuk koneksi keluar berbeda |
| 10 | RemoteInteractive | RDP |
| 11 | CachedInteractive | Login domain memakai kredensial cache saat DC tidak terjangkau |
| 12 / 13 | CachedRemoteInteractive / CachedUnlock | Varian cache untuk RDP dan unlock |

Field yang menentukan tafsir sebuah sesi [S3]:

- **`TargetUserName` dan `TargetDomainName`:** akun yang login. Bagian Subject di event yang sama biasanya akun yang melaporkan logon (sering akun komputer atau SYSTEM), bukan orang yang login. Salah ambil bagian ini adalah kesalahan klasik saat membaca CSV (bagian 1.7).
- **`TargetLogonId`:** Logon ID sesi baru. Nilai yang sama muncul di 4672, di `SubjectLogonId` atau `TargetLogonId` pada 4688, 4698, dan event lain yang dibuat sesi itu, serta di field `LogonId` Sysmon.
- **`TargetLinkedLogonId`:** pasangan sesi; `0x0` bila tidak ada pasangan. Untuk akun admin dengan UAC aktif, satu logon biasanya menghasilkan dua 4624 yang saling menunjuk: satu sesi terbatas dan satu sesi penuh. Field ini ada sejak event versi 2 (Windows 10) [S3].
- **`ElevatedToken`:** "Yes" berarti sesi itu punya hak administrator [S3].
- **`IpAddress` dan `WorkstationName`:** dari mana. Isinya bergantung protokol: logon jaringan Kerberos sering tanpa nama workstation, dan logon NTLM tanpa detail TCP/IP. `127.0.0.1` atau `::1` berarti lokal [S3].
- **`AuthenticationPackageName` dan `LogonProcessName`:** NTLM, Kerberos, atau Negotiate, dan proses logon tepercaya yang dipakai [S3].

Untuk 4625, kode `Status` dan `SubStatus` adalah informasi paling berguna. Yang paling sering ditemui [S7]: `0xC000006D` (nama pengguna atau informasi autentikasi salah), `0xC000006A` (password salah untuk akun yang ada), `0xC0000064` (akun tidak ada, rangkaiannya bisa berarti enumerasi akun), `0xC0000072` (akun dinonaktifkan), `0xC0000234` (akun terkunci), `0xC000015B` (akun tidak diberi hak logon type itu di mesin ini), dan `0xC0000193` (akun kedaluwarsa). Rangkaian `0xC000006A` untuk satu akun berbeda maknanya dari rangkaian `0xC0000064` untuk banyak nama akun.

Untuk RDP, jejaknya tersebar di tiga channel. RemoteConnectionManager 1149 mencatat akun dan alamat sumber saat koneksi jaringan RDP terbentuk; map EvtxECmd memberinya deskripsi "RDP network connection established" [S24], dan event ini sendiri belum membuktikan logon berhasil. Security 4624 dengan LogonType 10 membuktikan logon berhasil, dan LocalSessionManager 21 ("Session logon succeeded") mencatat akun, alamat sumber, dan nomor sesi [S24]; event 22 sampai 25 mencatat shell dimulai, logoff, disconnect, dan reconnect. Rekonstruksi RDP memadukan ketiganya; cek event ID TerminalServices di build lab-mu, karena perilakunya bisa berbeda antar versi.

Di `JKT-WS-0388`, hasil penyusunan sesi (bagian 2.3) menunjukkan sesuatu yang penting untuk Sari: penyerang tidak pernah membuat sesi sendiri. Tidak ada 4624 type 3 atau 10 dari host lain dalam rentang kasus, tidak ada 1149, dan tidak ada 4648. Semua aktivitas penyerang berjalan di dalam sesi interaktif Andi yang dibuat Senin pagi. Artinya, pertanyaan "siapa" tidak bisa dijawab dari nama akun saja; harus dari rantai proses di dalam sesi itu (bagian 1.3).

### 1.3 Eksekusi dan persistence: 4688, Sysmon, task, service, dan PowerShell

Pertanyaan ketiga Sari ("apa yang dijalankan, dan bagaimana task dibuat") dijawab oleh beberapa sumber yang saling melengkapi. Tidak ada satu event yang menceritakan semuanya; yang dicari adalah rangkaian yang konsisten antar sumber.

Tabel berikut memetakan sumber eksekusi dan persistence; baca kolom "Yang tidak dicatat", karena di situlah celah yang harus ditulis di laporan.

| Sumber | Event | Yang dicatat | Yang tidak dicatat |
|---|---|---|---|
| Security | 4688 | Proses baru, induk, akun pembuat dan akun target, Token Elevation Type, Mandatory Label; command line hanya bila setting terpisah aktif [S10][S4] | Apa pun saat Audit Process Creation mati; isi skrip yang dijalankan interpreter |
| Sysmon | 1 | Proses baru dengan command line penuh proses dan induknya, hash image, `ProcessGuid` yang tetap unik walau PID dipakai ulang, dan GUID sesi [S5] | Apa pun di luar filter konfigurasi; host tanpa Sysmon |
| Sysmon | 3, 22, 11 | Koneksi jaringan per proses (mati bawaan), query DNS per proses, file dibuat atau ditimpa [S5] | Isi trafik; pembacaan file |
| Security | 4698, 4699, 4702 | Task dibuat, dihapus, diubah; 4698 memuat nama task dan XML lengkapnya, dan sejak Windows 10 1903 juga `ClientProcessId` dan `ParentProcessId` [S11] | Apa pun saat Audit Other Object Access Events mati |
| TaskScheduler/Operational | 106, 140, 141, 200, 201 | Task didaftarkan (dengan konteks pengguna), diperbarui, dihapus, action dimulai, task selesai [S24] | Isi action di 106; apa pun saat channel mati |
| System | 7045 | Service baru: nama, path image (`ImagePath`), start type, akun [S24] | Siapa yang memasang (map tidak punya kolom pengguna) |
| Security | 4697 | Service baru dengan akun pemasang, nama file service, tipe, start type, akun service [S15] | Perubahan path setelah pemasangan; apa pun saat Audit Security System Extension mati |
| PowerShell/Operational | 4104 | Isi script block yang diproses, termasuk hasil decode `-enc`; blok panjang dipecah ke beberapa event dengan `ScriptBlockId` sama [S20][S24] | Isi saat logging mati, kecuali blok yang dianggap mencurigakan [S21] |
| PowerShell/Operational | 4103 | Detail eksekusi pipeline untuk modul yang di-log (module logging) [S6] | Modul yang tidak diaktifkan |

Beberapa detail field yang mengubah tafsir:

- **Token Elevation Type di 4688** [S10]: `%%1936` token penuh (UAC mati, akun Administrator bawaan, service, atau SYSTEM); `%%1937` token elevated (pengguna memilih Run as administrator atau program selalu meminta hak admin); `%%1938` token terbatas (program berjalan tanpa elevation). Proses penyerang di sesi pengguna biasa akan bernilai `%%1938`.
- **Command line di 4688** butuh dua setting: Audit Process Creation aktif, dan "Include command line in process creation events" di `Administrative Templates\System\Audit Process Creation`. Keduanya tidak aktif secara bawaan, dan command line yang tercatat bisa memuat password dalam teks biasa [S4].
- **XML di 4698** sama dengan isi file task di `C:\Windows\System32\Tasks\`, tetapi tercatat pada saat pembuatan. Bila file task kemudian diubah atau dihapus, 4698 masih menyimpan versi awalnya [S11]. Microsoft menyarankan memperhatikan task di root Task Scheduler Library (nama seperti `\NAMA_TASK`) dan task dengan `<LogonType>Password</LogonType>`, karena password akun itu tersimpan dan bisa diambil dengan hak admin [S11].
- **7045 tanpa nama pemasang.** Map EvtxECmd untuk 7045 hanya memetakan nama, start type, akun, dan `ImagePath` [S24]. Untuk tahu siapa yang memasang, pasangkan dengan 4697 (bila Audit Security System Extension aktif) atau dengan proses yang berjalan pada detik yang sama. Microsoft menyarankan memperhatikan service yang file-nya di luar `%windir%` atau Program Files, tipe kernel driver (`0x1`, `0x2`, `0x8`), dan start type Boot atau System [S15].
- **4104 menyimpan isi, bukan hanya nama.** Script block logging mencatat isi semua script block yang diproses, baik interaktif maupun otomasi [S6][S20]. Konsekuensinya dua arah: skrip penyerang yang di-encode terbaca utuh, tetapi skrip sah yang berisi password juga tersimpan di log. Karena itu Microsoft menyarankan Protected Event Logging bila script block logging dipakai di luar keperluan diagnostik [S6][S20].

Rangkaian akun dan grup juga termasuk persistence. Tabel berikut memuat event manajemen akun yang relevan; 4720 dan 4732 ditulis di domain controller, member server, dan workstation [S12][S13].

| Event ID | Arti | Catatan |
|---|---|---|
| 4720 | Akun pengguna dibuat | Field atribut membantu menilai akun aneh; `Primary Group ID` selain 513 atau `Password Last Set` di masa depan layak diperiksa [S12] |
| 4722 | Akun diaktifkan | |
| 4724 | Reset password | |
| 4728 / 4732 / 4756 | Anggota ditambah ke grup keamanan global / lokal / universal | Satu event per anggota; 4732 untuk grup lokal seperti Administrators, dan untuk grup lokal nama anggota biasanya `-` sehingga yang dibaca adalah SID-nya [S13] |
| 4738 | Akun diubah | |
| 4740 | Akun terkunci | |

Pembuatan akun dan penambahan ke grup admin adalah persistence (ATT&CK T1136 Create Account) dan privilege escalation klasik. Event-nya hanya ada bila subcategory yang sesuai diaudit (bagian 1.5). Di `JKT-WS-0388` tidak ada 4720 atau 4732 dalam rentang kasus, dan karena Security Group Management diaudit di laptop itu, ketiadaannya bermakna.

Di laptop Andi, rangkaiannya Senin sore terbaca dari empat channel sekaligus (bagian 2.4): Sysmon 11 mencatat ZIP disimpan dan `.js` diekstrak, Sysmon 1 dan 4688 mencatat `wscript.exe` lalu `powershell.exe -enc`, Sysmon 11 mencatat `upd.ps1` dibuat, 4104 mencatat isi perintah yang di-encode, lalu 4698 dan 106 mencatat task dibuat dari proses PowerShell yang sama. Rangkaian ini melengkapi artefak eksekusi di disk (Prefetch, Amcache) yang dibahas di Day 07.

### 1.4 Aktivitas responder di log yang sama

Pertanyaan keempat Sari berasal dari kalimat retainer "aktivitas akun admin lokal pada 13 Oktober siang". Kalimat itu benar, tetapi pelakunya responder. Bila tidak dipisahkan, DPO bisa menyimpulkan penyerang punya hak admin, dan kesimpulan itu mengubah penilaian dampak.

Setiap tindakan responder di host yang menyala meninggalkan jejak: logon, proses, service atau driver, file. Di `JKT-WS-0388` ada tiga kelompok jejak responder:

1. Selasa sekitar 12:31 sampai 12:37: paket investigasi dan `getfile` lewat live response Defender. Prosesnya berjalan sebagai SYSTEM dari sensor Defender; nama proses dan pola induknya cocokkan dengan riwayat Action center dan dengan pengujian di lab, bukan ditebak dari nama.
2. Selasa 12:38 sampai 12:55: Yoga datang ke lantai 3 dengan drive USB bukti `USB-E-07`. Andi mengunci layar, Yoga masuk lewat Switch user dengan akun admin lokal khusus IR `ir-admin` (passwordnya diganti setelah setiap pemakaian), membuka Command Prompt sebagai administrator, menjalankan WinPmem dari `E:\tools\` dengan output ke `E:\INC-2026-019\`, menghitung hash dengan `certutil`, lalu sign out.
3. Kamis 08:46 sampai 08:47: Yoga masuk lagi dengan `ir-admin` untuk mematikan laptop sebelum image E15 pukul 09:00.

Cara membedakan responder dari penyerang tidak bergantung pada satu tanda. Kombinasi yang dipakai:

- **Akun dan sesi:** `ir-admin` hanya dipakai tim IR, dan setiap pemakaiannya tercatat di case notes. Sesi responder punya Logon ID sendiri, terpisah dari sesi Andi `0x3A1F2C` tempat semua proses penyerang berjalan.
- **Waktu:** jejak responder cocok menit demi menit dengan case notes dan evidence log (E01 diambil 12:42 sampai 12:53).
- **Path dan media:** image proses responder berada di `E:\` (drive USB bukti), bukan di profil pengguna atau folder sementara.
- **Induk proses:** proses responder berinduk ke `cmd.exe` yang dibuka di sesi `ir-admin` dengan token elevated (`%%1937`); proses penyerang berinduk ke `wscript.exe`, ke `powershell.exe` dari task, atau ke layanan Task Scheduler, dengan token terbatas (`%%1938`).

Satu jejak responder perlu disiapkan jawabannya sebelum ada yang bertanya: alat akuisisi memori memuat driver kernel, dan pemuatan driver lewat Service Control Manager meninggalkan 7045 bertipe kernel driver (dan 4697 bila auditnya aktif). Dibaca tanpa konteks, itu persis pola yang disarankan Microsoft untuk diwaspadai [S15]. Nama service yang dibuat bergantung versi WinPmem; cek nama dan tipe service itu di lab dengan versi alat yang sama dengan toolkit IR, supaya tim punya pembanding sebelum melihatnya di kasus.

Jawaban untuk Agus mengikuti dari sini: hak admin di laptop itu hanya dipakai oleh responder. Sesi Andi tidak pernah mendapat 4672 dan semua proses penyerang bertoken terbatas, jadi sejauh yang tercatat di event log, penyerang bekerja dengan hak pengguna biasa Andi.

### 1.5 Audit policy: ketiadaan event dimulai dari konfigurasi

Pertanyaan kelima Sari (E14 tanpa 4698) adalah pertanyaan konfigurasi. Log Security hanya berisi subcategory yang diaudit; sebelum menulis "tidak ada event", cek dulu apakah event itu memang bisa ada di host tersebut.

Microsoft menerbitkan tabel nilai bawaan audit policy untuk Windows client, berdampingan dengan rekomendasi baseline [S19]. Tabel berikut merangkum subcategory yang dipakai di Day ini, nilai bawaannya, dan isi GPO audit PT JAB; baca kolom ketiga, karena itulah kondisi laptop yang tidak terkena GPO.

| Event | Subcategory | Bawaan Windows client [S19] | GPO `JAB-WS-Audit` |
|---|---|---|---|
| 4624, 4625, 4648 | Audit Logon | Success dan Failure sejak Windows 10 1809; sebelumnya Success saja | Success, Failure |
| 4634, 4647 | Audit Logoff | Success | Success |
| 4672 | Audit Special Logon | Success | Success |
| 4688 | Audit Process Creation | Tidak aktif; command line butuh setting terpisah yang juga tidak aktif [S4][S17] | Success, dengan command line |
| 4720, 4722, 4724, 4738, 4740 | Audit User Account Management | Success | Success |
| 4728, 4732, 4756 | Audit Security Group Management | Tidak aktif (kolom bawaan kosong) | Success |
| 4698, 4699, 4702 | Audit Other Object Access Events | Tidak aktif (kolom bawaan kosong) [S16] | Success |
| 4697 | Audit Security System Extension | Tidak aktif (kolom bawaan kosong) | Success |
| 5140, 5145 | Audit File Share, Audit Detailed File Share | Tidak aktif; 5145 sangat bising | Tidak |
| 1102 | Other Events | Ditulis setiap kali log Security dibersihkan [S14] | |
| 4104 | Script block logging (kebijakan PowerShell, bukan audit policy) | Tidak aktif; Windows PowerShell tetap mencatat blok yang dianggap mencurigakan dengan level Warning [S21] | Aktif |
| System 7045 | Bukan audit policy | Bawaan dari Service Control Manager | |
| TaskScheduler 106, 200, 201 | Bukan audit policy | Bergantung status channel history (lihat di bawah) | Diaktifkan lewat skrip startup |

Tiga catatan untuk tabel ini:

- **Tafsir lama perlu dikoreksi.** Catatan lama di topik ini menulis bahwa Security Group Management "sering aktif" di build modern. Tabel bawaan Microsoft tidak menunjukkan nilai bawaan untuk subcategory itu di client [S19], jadi tanpa GPO, 4728 dan 4732 sebaiknya dianggap tidak ada.
- **Advanced audit bisa tertimpa basic audit.** Bila GPO memakai Advanced Audit Policy Configuration, pastikan setting itu tidak ditimpa basic audit policy; event 4719 ditulis saat setting tertimpa, dan "Audit: Force audit policy subcategory settings" mencegahnya [S4]. 4719 juga yang dicari bila curiga audit policy dimatikan di host.
- **TaskScheduler/Operational belum tentu aktif.** Beberapa sumber praktisi menyebut history Task Scheduler mati secara bawaan di Windows 10 dan 11, dan menyalakannya dengan "Enable All Tasks History" atau `wevtutil set-log Microsoft-Windows-TaskScheduler/Operational /enabled:true` [S25]. Catatan lama topik ini menyebut channel itu aktif bawaan. Dua klaim ini tidak sejalan dan belum dikonfirmasi dokumentasi Microsoft, jadi tentukan dari bukti: ada atau tidaknya event 106 dan 200 di file `.evtx` host itu, bukan dari asumsi build.

Di lab, `auditpol /get /category:*` di VM korban menampilkan kebijakan yang berlaku. Di kasus nyata kamu sering hanya punya koleksi atau image. Kebijakan audit tersimpan di hive SECURITY (nilai `PolAdtEv`); bila parser registry versi lab-mu tidak menerjemahkannya, simpulkan dari event yang ada dan dari sisi Active Directory. Contohnya: tidak ada satu pun 4688 dalam log yang mencakup berminggu-minggu berarti Process Creation tidak diaudit, bukan berarti tidak ada proses. Dari sisi AD, cek GPO apa yang terpasang ke OU host itu.

Itulah yang terjadi pada `JKT-WS-0412`. GPO `JAB-WS-Audit` (advanced audit policy di tabel di atas, "Force audit policy subcategory settings", script block logging, ukuran maksimum log Security 256 MB, dan skrip startup yang menyalakan channel TaskScheduler/Operational) hanya terpasang di OU `OU=Workstations-EDR,OU=Jakarta,DC=corp,DC=jab,DC=example`. Workstation dipindah ke OU itu bersamaan dengan onboarding Defender dan pemasangan Sysmon. Laptop Rizky belum di-onboard, sehingga masih di OU lama `OU=Workstations,OU=Jakarta,DC=corp,DC=jab,DC=example` dan berjalan dengan audit bawaan: ada logon, logoff, special logon, dan manajemen akun, tetapi tidak ada 4688, 4697, atau 4698, dan tidak ada Sysmon. Event 4104 yang ada di E14 adalah blok yang dicatat otomatis dengan level Warning (bagian 2.7). Jawaban ke Sari: E14 tidak punya 4698 karena laptop itu tidak pernah dikonfigurasi untuk mencatatnya; bukti task di laptop itu adalah file XML task dan 4104, yang sudah dibaca di Day 03 bagian 2.5.

Sysmon mengisi celah yang sama dari sisi lain: EID 1 memuat command line, hash, dan proses induk walaupun 4688 mati [S5]. Karena itu, saat menilai sebuah host, tulis di catatan kasus sumber eksekusi mana yang tersedia: 4688 dengan atau tanpa command line, Sysmon, atau tidak ada keduanya.

### 1.6 Pembersihan log, rotasi, dan cara membaca celah

Pertanyaan terakhir Sari ("pernah dibersihkan?") dijawab dengan tiga pemeriksaan, karena log bisa hilang dengan tiga cara yang berbeda maknanya: dibersihkan, berputar, atau tidak pernah ditulis.

Tabel berikut memuat event yang ditulis saat log dibersihkan atau konfigurasinya diubah.

| Event ID | Channel | Arti |
|---|---|---|
| 1102 | Security | Log audit Security dibersihkan; provider `Microsoft-Windows-Eventlog`, berisi SID, nama akun, dan Logon ID yang membersihkan [S14] |
| 104 | System | Sebuah log dibersihkan; provider `Microsoft-Windows-Eventlog`, field `Channel` menyebut log mana dan field Subject menyebut akunnya [S24] |
| 4719 | Security | Audit policy sistem diubah, termasuk saat setting advanced tertimpa [S4] |

Penghapusan log (T1070.001) meninggalkan jejak sendiri. Microsoft menyebut 1102 sebagai event yang biasanya tidak perlu terlihat, karena hampir tidak ada alasan membersihkan log Security secara manual [S14]. Ketiadaan log yang diharapkan ditambah adanya 1102 atau 104 adalah sinyal kuat upaya anti-forensik. Sebaliknya, ketiadaan 1102 dan 104 tidak membuktikan log utuh: penyerang dengan hak cukup tinggi bisa memakai cara lain yang tidak meninggalkan event ini (Day 21 membahas keluarga tekniknya).

Tiga pemeriksaan yang dijalankan untuk setiap image atau koleksi:

1. **Event pembersihan dan perubahan audit:** cari 1102 dan 4719 di Security, dan 104 di System. Catat akun dan Logon ID-nya, lalu pasangkan dengan sesi di bagian 1.2.
2. **Rentang waktu per file:** event paling awal dan paling akhir di setiap channel. Bila event paling awal di Security lebih baru dari awal kasus, sebagian kasus tidak tercatat lagi di host, entah karena rotasi biasa atau karena dibersihkan. Bedakan dengan melihat ukuran maksimum log dan kepadatan event.
3. **Kontinuitas di dalam file:** nomor record (`EventRecordID`) di satu file normalnya berurutan, dan waktu tidak mundur jauh. Lompatan nomor atau waktu yang mundur di tengah file layak diperiksa. EvtxECmd punya opsi `--tdt` untuk deteksi selisih waktu antar record (bawaan 1 detik) [S22]; baca keluaran console-nya.

Ada satu fakta yang membuat pemeriksaan pertama lebih tajam: hak untuk melihat dan membersihkan log Security adalah SeSecurityPrivilege, salah satu hak sensitif yang memicu 4672 saat diberikan ke sesi [S9]. Sesi pengguna biasa tanpa 4672 tidak memegang hak itu. Di `JKT-WS-0388`, penyerang bekerja di sesi Andi yang tidak punya 4672, sehingga dari sesi itu ia tidak bisa membersihkan Security.

Keterbatasan umum event log yang harus selalu ditulis di laporan:

- **Rotasi:** channel punya ukuran maksimum; event lama tertimpa. Log Security di host sibuk bisa hanya menyimpan beberapa hari, dan Sysmon dengan konfigurasi luas berputar lebih cepat lagi.
- **Audit policy:** banyak event hanya ada bila diaudit (bagian 1.5). Ketiadaan event tidak membuktikan ketiadaan aktivitas.
- **Penghapusan dan manipulasi:** meninggalkan 1102 atau 104 bila memakai cara biasa. Volume Shadow Copy dan koleksi historis (Day 03) kadang memuat log sebelum dibersihkan, dan salinan di SIEM tidak ikut terhapus.
- **Pembacaan file tidak tercatat:** tanpa object access auditing dan SACL di file, membaca file tidak menghasilkan event apa pun. Di kasus ini, pembacaan `export-tagihan.ps1` hanya terlihat karena dilakukan oleh skrip PowerShell yang isinya tercatat di 4104.
- **Waktu:** timestamp di `.evtx` dan di output EvtxECmd dalam UTC; perhatikan konversi zona saat merekonstruksi (Day 13).

### 1.7 EvtxECmd dan maps: dari `.evtx` ke CSV tanpa salah kolom

Bagian kedua pertanyaan pertama Sari ("membaca tanpa salah kolom") menyangkut alat. Event Viewer cukup untuk satu event; untuk ratusan ribu event dari belasan channel, kamu butuh CSV yang seragam.

EvtxECmd (EZ Tools, versi 2026.5.0 untuk .NET 4.7.2 dan .NET 9) memparse `.evtx` menjadi CSV, JSON, atau XML [S2][S22]. Opsi yang dipakai di Day ini [S22]: `-f` satu file atau `-d` satu folder; `--csv` folder output dan `--csvf` nama file; `--inc` dan `--exc` untuk memasukkan atau membuang event ID tertentu; `--sd` dan `--ed` untuk rentang tanggal dalam UTC; `--maps` lokasi maps (bawaannya folder `Maps` di working directory); `--dedupe` (bawaan true, file dengan SHA-1 sama hanya diproses sekali); `--vss` untuk memproses shadow copy di drive target; `--sync` untuk mengunduh maps terbaru; dan `--tdt` untuk deteksi selisih waktu.

Kekuatan EvtxECmd ada di maps. Setiap map adalah file `Channel_Provider_EventID.map` yang berisi XPath ke field event dan menuliskan hasilnya ke kolom tetap: `UserName`, `RemoteHost`, `ExecutableInfo`, dan `PayloadData1` sampai `PayloadData6`; channel, provider, dan event ID bersama-sama membuat map unik, karena event ID yang sama bisa dipakai provider berbeda [S23]. Akibatnya, arti satu kolom berbeda untuk setiap event. Tabel berikut berisi isi kolom untuk event yang dipakai di Day ini, dari map yang diperiksa; perhatikan baris 4624, karena kolom `UserName`-nya bukan orang yang login.

| Event | `UserName` | `RemoteHost` | `ExecutableInfo` | `PayloadData` |
|---|---|---|---|---|
| Security 4624 | Subject (akun yang melaporkan, sering `JKT-WS-0388$`) | `WorkstationName (IpAddress)` | `ProcessName` | 1: `Target:` akun yang login; 2: `LogonType` (angka mentah, tanpa terjemahan); 3: `LogonId` target; 4: paket autentikasi; 5: proses logon |
| Security 4698 | Subject (pembuat task) | | | 1: `TaskName`; 2: `TaskContent` (XML) |
| System 7045 | (tidak dipetakan) | | `ImagePath` | 1: nama service; 2: start type; 3: akun |
| System 104 | Subject (yang membersihkan) | | | 1: kalimat yang menyebut channel yang dibersihkan |
| TaskScheduler 106 | `UserContext` | | | 1: `Task:` nama task |
| TaskScheduler 201 | | | `ActionName` | 1: nama task; 2: instance ID |
| PowerShell 4104 | | | | 1: `Path` (kosong bila kode tidak dari file); 2: `ScriptBlockText` |
| Sysmon 1 | `User` (dan `ParentUser`) | | `CommandLine` | 1: PID dan ProcessGuid; 3: hash; 4: proses induk; 5: PID dan GUID induk; 6: command line induk |
| RemoteConnectionManager 1149 | domain dan akun | alamat sumber | | |
| LocalSessionManager 21 | `User` | `Address` | | 1: Session ID |

Sumber tabel: map di repo evtx yang diperiksa pada 2026-10-16 [S24]. Map bisa berubah saat diperbarui; itulah alasan versi maps dicatat dan dibekukan per kasus (Day 02 bagian 2.3).

Tiga akibat praktis:

- **Field yang tidak dipetakan tetap ada di kolom `Payload`** (XML atau JSON lengkap event). Contohnya `MessageNumber`, `MessageTotal`, dan `ScriptBlockId` di 4104, serta `LogonId` dan `Image` di Sysmon 1, tidak punya kolom sendiri di map yang diperiksa [S24]. Filter dengan `Payload -match` untuk field itu.
- **Map bisa di-override tanpa mengubah aslinya:** salin map lalu beri awalan `1_` pada nama file; karena maps dimuat urut abjad, versi custom yang dipakai [S23]. Catat override seperti ini di case notes, karena retainer yang memakai maps standar akan melihat kolom berbeda.
- **Nama kolom CSV** (`TimeCreated`, `EventId`, `Channel`, `Computer`, `MapDescription`, `Payload`, `Level`, `EventRecordId`, `SourceFile`, dan seterusnya) cocokkan dengan header CSV versi EvtxECmd-mu sebelum menulis filter.

EvtxECmd juga dipakai di pipeline Day 03 lewat Module `!EZParser`. Di Day ini ia dijalankan langsung, supaya versi maps dan opsi tercatat jelas untuk E15-W1.

## 2. Contoh dan langkah praktis di PT JAB

Semua isi bagian ini fiktif dan merupakan keluaran ilustrasi. Kolom CSV di keluaran diringkas supaya muat; nama kolom, format waktu, dan isi `Payload` bisa berbeda antar versi EvtxECmd dan maps, jadi cocokkan dengan versi di lab-mu. Waktu di CSV dalam UTC; teks penjelasan memakai WIB (UTC+7). Perintah ditulis untuk lingkungan PT JAB; untuk latihan, jalankan hanya di VM lab terisolasi (bagian 3).

### 2.1 Parse semua event log E15-W1

Langkah ini menjawab bagian pertama pertanyaan pertama Sari: log apa saja yang ada. E15-W1 di-mount read-only sebagai `G:` di `JKT-DFIR01` dengan alat mount image yang sudah diuji tim (alat, versi, dan mode read-only dicatat di case notes). EvtxECmd dijalankan dari folder EZ Tools yang dibekukan untuk kasus ini (Day 02 bagian 2.2), dengan maps di folder yang sama.

```
C:\DFIR\tools\EZTools-2026-10-15\net9\EvtxECmd\EvtxECmd.exe -d G:\Windows\System32\winevt\Logs --maps C:\DFIR\tools\EZTools-2026-10-15\net9\EvtxECmd\Maps --csv \\jkt-evid01\cases\INC-2026-019\analysis\E15-W1\EZ-2026.5.0\EventLogs --csvf E15-W1_evtx.csv
```

- `-d G:\Windows\System32\winevt\Logs`: semua `.evtx` di folder log image, dibaca dari volume read-only.
- `--maps ...\Maps`: lokasi maps ditulis eksplisit, supaya tidak bergantung pada working directory saat perintah dijalankan [S22].
- `--csv` dan `--csvf`: satu CSV gabungan di area kerja kasus, di folder yang namanya memuat nomor bukti dan versi alat (Day 02 bagian 1.6).

Keluaran ilustrasi (ringkas, dari console):

```
Processing G:\Windows\System32\winevt\Logs\Security.evtx ...                                   64,212 events
Processing G:\Windows\System32\winevt\Logs\Microsoft-Windows-Sysmon%4Operational.evtx ...      41,876 events
Processing G:\Windows\System32\winevt\Logs\System.evtx ...                                       4,517 events
Processing G:\Windows\System32\winevt\Logs\Microsoft-Windows-TaskScheduler%4Operational.evtx ... 3,288 events
Processing G:\Windows\System32\winevt\Logs\Microsoft-Windows-PowerShell%4Operational.evtx ...    1,903 events
Processing G:\Windows\System32\winevt\Logs\Microsoft-Windows-TerminalServices-LocalSessionManager%4Operational.evtx ...  96 events
Processing G:\Windows\System32\winevt\Logs\Microsoft-Windows-TerminalServices-RemoteConnectionManager%4Operational.evtx ... 12 events
... (131 file lain: 58,402 events)
Processed 138 files. Total events: 174,306
```

**Cara membaca hasil:** 7 file yang disebut ditambah 131 file lain sama dengan 138 file, dan 64.212 + 41.876 + 4.517 + 3.288 + 1.903 + 96 + 12 + 58.402 = 174.306 event. Channel Sysmon, PowerShell, dan TaskScheduler ada dan berisi, sesuai GPO `JAB-WS-Audit` dan Sysmon yang terpasang. Tidak ada file `PowerShellCore%4Operational.evtx` berisi event, jadi PowerShell 7 tidak dipakai di laptop ini. Catat jumlah ini di case notes; retainer yang memparse image yang sama harus mendapat angka yang sama.

**Variasi:** untuk iterasi cepat, proses satu file dengan `-f`, misalnya `-f G:\Windows\System32\winevt\Logs\Security.evtx --csv ... --csvf security.csv`, atau batasi event ID dengan `--inc 4624,4625,4634,4647,4648,4672`; cek format daftar event ID dengan menjalankan `EvtxECmd.exe` tanpa argumen. Untuk host yang masih hidup (bukan image), `--vss` ikut memproses shadow copy di drive target [S22].

**Kapan gagal:** maps tidak ditemukan karena `--maps` tidak ditulis dan perintah dijalankan dari folder lain, sehingga kolom `PayloadData` kosong walaupun `Payload` terisi. Gejala lain: file `.evtx` yang rusak sebagian; EvtxECmd tetap memproses record yang bisa dibaca, dan pesan error di console harus dicatat.

### 2.2 Profil cakupan dan pemeriksaan pembersihan

Langkah ini menjawab pertanyaan keenam Sari dan menjadi dasar semua kalimat "tidak ditemukan" sesudahnya: sampai tanggal berapa setiap channel mencatat, dan apakah ada event pembersihan atau perubahan audit.

```powershell
$e = Import-Csv '\\jkt-evid01\cases\INC-2026-019\analysis\E15-W1\EZ-2026.5.0\EventLogs\E15-W1_evtx.csv'
$e | Group-Object Channel | ForEach-Object {
    $t = $_.Group.TimeCreated | Sort-Object
    [pscustomobject]@{ Channel = $_.Name; Jumlah = $_.Count; Pertama = $t[0]; Terakhir = $t[-1] }
} | Sort-Object Jumlah -Descending | Select-Object -First 5 | Format-Table -AutoSize
$e | Where-Object { ($_.Channel -eq 'Security' -and $_.EventId -in '1102','4719') -or
                    ($_.Channel -eq 'System'   -and $_.EventId -eq '104') } | Measure-Object
```

- `Group-Object Channel`: satu baris per channel, lalu waktu pertama dan terakhir dari kolom `TimeCreated`. Format waktu EvtxECmd berurutan dari tahun ke detik, sehingga urutan teks sama dengan urutan waktu.
- Filter kedua menghitung 1102 dan 4719 di Security dan 104 di System. `EventId` dibandingkan sebagai teks karena `Import-Csv` membaca semua kolom sebagai teks.

Keluaran ilustrasi:

```
Channel                                    Jumlah Pertama                     Terakhir
-------                                    ------ -------                     --------
Security                                    64212 2026-09-29 03:14:52.1180331 2026-10-15 01:47:31.4402176
Microsoft-Windows-Sysmon/Operational        41876 2026-10-04 14:37:10.0021734 2026-10-15 01:47:40.7719052
System                                       4517 2026-07-14 02:20:41.5512807 2026-10-15 01:47:52.0098116
Microsoft-Windows-TaskScheduler/Operational  3288 2026-09-21 23:51:07.3310482 2026-10-15 01:36:03.0127755
Microsoft-Windows-PowerShell/Operational     1903 2026-09-02 01:44:19.9061223 2026-10-15 01:36:04.2290148

Count    : 0
```

**Cara membaca hasil:**

- Semua channel penting mencakup Senin 2026-10-12 sampai Kamis 2026-10-15 08:47 WIB (01:47 UTC), saat laptop dimatikan. Event Security paling awal Selasa 2026-09-29, dua minggu sebelum email masuk. Sysmon paling awal Minggu 2026-10-04 21:37 WIB: Sysmon berputar lebih cepat, tetapi tetap mencakup seluruh kasus. Aktivitas Sysmon sebelum tanggal itu hanya ada di SIEM.
- Nol 1102, nol 4719, nol 104 di seluruh rentang file.
- Kontinuitas: urutkan Security berdasarkan `EventRecordId` lalu cek selisih antar baris; di E15-W1 tidak ada lompatan nomor dan console EvtxECmd tidak melaporkan selisih waktu. Nama kolom nomor record cocokkan dengan header CSV-mu.

Kalimat untuk Sari: "Tidak ada tanda log dibersihkan atau audit policy diubah di `JKT-WS-0388`: tidak ada 1102, 104, atau 4719, nomor record Security berurutan, dan semua channel mencakup seluruh periode kasus. Penyerang bekerja di sesi Andi tanpa hak membersihkan log Security."

**Variasi:** di host yang dicurigai dibersihkan, bandingkan rentang dan jumlah event per jam di file lokal dengan salinan di SIEM untuk periode yang sama; selisihnya adalah yang hilang di host (latihan lanjutan di Day 21).

**Kapan gagal:** hanya mencari 1102 di log Security, padahal penyerang yang membersihkan Sysmon atau PowerShell meninggalkan 104 di System, bukan 1102.

### 2.3 Menyusun sesi logon

Langkah ini menjawab pertanyaan kedua Sari. Filter pertama mengambil semua 4624 sejak Senin untuk akun yang bukan akun sistem atau akun komputer; filter kedua mengambil semua event yang menyebut `ir-admin`.

```powershell
$e | Where-Object { $_.Channel -eq 'Security' -and $_.EventId -eq '4624' -and $_.TimeCreated -ge '2026-10-12' -and
                    $_.PayloadData1 -notmatch 'SYSTEM|LOCAL SERVICE|NETWORK SERVICE|DWM-|UMFD-|\$$' } |
  Sort-Object TimeCreated | Select-Object TimeCreated, PayloadData1, PayloadData2, PayloadData3, RemoteHost | Format-Table -AutoSize
$e | Where-Object { $_.Payload -match 'ir-admin' } |
  Sort-Object TimeCreated | Select-Object TimeCreated, Channel, EventId, MapDescription | Format-Table -AutoSize
```

- `PayloadData1` dipakai untuk akun yang login, bukan `UserName`, karena map 4624 menaruh Subject di `UserName` (bagian 1.7).
- Regex `notmatch` membuang akun bawaan sistem (SYSTEM, LOCAL SERVICE, NETWORK SERVICE, sesi `DWM-` dan `UMFD-`) dan akun yang berakhiran `$` (akun komputer).
- `Payload -match 'ir-admin'`: mencari di XML lengkap, sehingga event apa pun yang menyebut akun itu ikut, termasuk yang map-nya tidak punya kolom akun.

Keluaran ilustrasi (filter pertama, kolom diringkas):

```
TimeCreated              PayloadData1                    PayloadData2  PayloadData3       RemoteHost
2026-10-12 00:58:14.40   Target: JAB\andi.pratama        LogonType 2   LogonId: 0x3A1F2C  JKT-WS-0388 (127.0.0.1)
2026-10-12 06:02:40.11   Target: JAB\andi.pratama        LogonType 7   LogonId: 0x5B77E1  JKT-WS-0388 (127.0.0.1)
2026-10-13 01:12:05.62   Target: JAB\andi.pratama        LogonType 7   LogonId: 0x7D2A90  JKT-WS-0388 (127.0.0.1)
2026-10-13 05:38:41.27   Target: JKT-WS-0388\ir-admin    LogonType 2   LogonId: 0x9C04A7  JKT-WS-0388 (127.0.0.1)
2026-10-13 05:38:41.27   Target: JKT-WS-0388\ir-admin    LogonType 2   LogonId: 0x9C04D2  JKT-WS-0388 (127.0.0.1)
2026-10-15 01:46:20.83   Target: JKT-WS-0388\ir-admin    LogonType 2   LogonId: 0xE3D115  JKT-WS-0388 (127.0.0.1)
2026-10-15 01:46:20.83   Target: JKT-WS-0388\ir-admin    LogonType 2   LogonId: 0xE3D140  JKT-WS-0388 (127.0.0.1)
```

Keluaran ilustrasi (filter kedua):

```
TimeCreated              Channel                                EventId  MapDescription
2026-10-13 05:38:29.90   Security                               4625     Failed logon
2026-10-13 05:38:41.27   Security                               4624     Successful logon
2026-10-13 05:38:41.27   Security                               4624     Successful logon
2026-10-13 05:38:41.27   Security                               4672     Special privileges assigned to new logon
2026-10-13 05:41:50.06   Security                               4688     Process created
2026-10-13 05:42:07.51   Microsoft-Windows-Sysmon/Operational   1        Process creation
2026-10-13 05:42:08.02   Security                               4697     A service was installed in the system
2026-10-13 05:53:40.38   Microsoft-Windows-Sysmon/Operational   1        Process creation
2026-10-13 05:55:10.17   Security                               4647     User initiated logoff
2026-10-15 01:46:20.83   Security                               4624     Successful logon
2026-10-15 01:46:20.83   Security                               4624     Successful logon
2026-10-15 01:46:20.83   Security                               4672     Special privileges assigned to new logon
2026-10-15 01:47:30.64   System                                 1074     (shutdown dimulai)
```

**Cara membaca hasil:**

- Senin 07:58:14 WIB Andi login interaktif (type 2), Logon ID `0x3A1F2C`. `TargetLinkedLogonId` di `Payload` bernilai `0x0` dan `ElevatedToken` "No": Andi pengguna biasa tanpa hak admin, dan tidak ada 4672 untuk sesi ini.
- Senin 13:02:40 dan Selasa 08:12:05 WIB: unlock (type 7). Unlock membuat Logon ID singkat sendiri, tetapi proses Andi tetap berjalan di sesi `0x3A1F2C`. Mengunci layar tidak menghasilkan 4624; yang terlihat hanya unlock-nya.
- Selasa 12:38:29 WIB ada 4625 untuk `ir-admin` dengan `Status` `0xC000006D` dan `SubStatus` `0xC000006A` (password salah untuk akun yang ada) [S7], dua belas detik kemudian berhasil. Case notes Yoga mencatat salah ketik password pertama.
- Setiap login `ir-admin` menghasilkan dua 4624 pada detik yang sama, saling menunjuk lewat `TargetLinkedLogonId`; hanya yang berlogon ID `0x9C04D2` (dan `0xE3D140` hari Kamis) yang `ElevatedToken` "Yes" dan punya 4672. Ini pola akun admin dengan UAC, bukan dua orang login.
- Tidak ada 4624 type 3 atau 10 dari host lain, tidak ada 4648, dan file RemoteConnectionManager hanya berisi 12 event dari Juni 2026 saat laptop disiapkan IT, tanpa satu pun di rentang kasus. Jawaban ke retainer: tidak ada RDP atau logon jaringan dari host lain ke laptop ini selama kasus. Logon type 3 dari akun komputer dan layanan manajemen yang dibuang filter sudah ditinjau terpisah dan sesuai pola harian sebelum kasus.

**Variasi:** pasangkan setiap 4624 dengan 4634 atau 4647 berdasarkan Logon ID untuk durasi sesi; sesi `ir-admin` Selasa berlangsung 12:38:41 sampai 12:55:10 WIB. Untuk host server, tambahkan pengelompokan per `RemoteHost` dan per logon type untuk melihat sumber yang tidak lazim.

**Kapan gagal:** memakai kolom `UserName` untuk 4624, sehingga semua logon tampak dilakukan `JKT-WS-0388$`; atau membaca logon type sebagai teks yang sudah diterjemahkan, padahal map 4624 menuliskan angka mentah tanpa lookup [S24].

### 2.4 Rantai eksekusi Senin sore dan pembuatan task

Langkah ini menjawab pertanyaan ketiga Sari. Rentang waktunya dipilih dari pivot yang sudah diketahui: email masuk 15:58 WIB dan alert EDR menunjuk `wscript.exe` sekitar 16:05.

```powershell
$e | Where-Object { $_.TimeCreated -ge '2026-10-12 09:04:00' -and $_.TimeCreated -lt '2026-10-12 09:07:00' -and (
      ($_.Channel -like '*Sysmon*' -and $_.EventId -in '1','3','11','22') -or
      ($_.Channel -eq 'Security' -and $_.EventId -eq '4698') -or
      ($_.Channel -like '*TaskScheduler*' -and $_.EventId -eq '106') -or
      ($_.Channel -like '*PowerShell*' -and $_.EventId -eq '4104') ) } |
  Sort-Object TimeCreated | Select-Object TimeCreated, Channel, EventId, ExecutableInfo, PayloadData1
```

- Rentang 09:04 sampai 09:07 UTC sama dengan 16:04 sampai 16:07 WIB.
- Event ID disaring bersama channel-nya, karena angka yang sama dipakai channel lain dengan arti berbeda (Sysmon 1 berbeda dari event 1 di Application).
- 4688 sengaja tidak diambil di sini karena isinya sama dengan Sysmon 1; dipakai sebagai konfirmasi di variasi.

Keluaran ilustrasi (kolom diringkas menjadi satu kolom "Ringkasan"):

```
TimeCreated (UTC)       Sumber        EID   Ringkasan
2026-10-12 09:04:48.71  Sysmon        11    OUTLOOK.EXE membuat C:\Users\andi.pratama\Downloads\Tagihan-Okt-2026.zip
2026-10-12 09:05:09.33  Sysmon        11    explorer.exe membuat C:\Users\andi.pratama\AppData\Local\Temp\Temp1_Tagihan-Okt-2026.zip\Tagihan-Okt-2026.js
2026-10-12 09:05:11.08  Sysmon        1     "C:\Windows\System32\WScript.exe" "C:\Users\andi.pratama\AppData\Local\Temp\Temp1_Tagihan-Okt-2026.zip\Tagihan-Okt-2026.js"  | induk explorer.exe | PID 5820
2026-10-12 09:05:17.42  Sysmon        1     powershell.exe -NoP -W Hidden -enc <base64 dipotong>  | induk wscript.exe | PID 6136
2026-10-12 09:05:19.15  Sysmon        11    powershell.exe membuat C:\Users\andi.pratama\AppData\Roaming\SysCache\upd.ps1
2026-10-12 09:05:24.60  PowerShell    4104  Path: (kosong) | blok 1 dari 1 | isi: menulis upd.ps1, mendaftarkan task SysCacheUpdate
2026-10-12 09:06:02.27  Security      4698  TaskName: \SysCacheUpdate
2026-10-12 09:06:02.29  TaskScheduler 106   Task: \SysCacheUpdate | JAB\andi.pratama
2026-10-12 09:06:04.88  Sysmon        22    powershell.exe query cdn-sync.example.net
2026-10-12 09:06:05.12  Sysmon        3     powershell.exe -> 203.0.113.77:443
```

**Cara membaca hasil:**

- ZIP disimpan dari Outlook 16:04:48 WIB, `.js` diekstrak Explorer 16:05:09 ke folder sementara di `AppData\Local\Temp\`, dan dua detik kemudian `wscript.exe` menjalankannya. Nama folder `Temp1_<nama zip>` adalah perilaku umum Explorer saat membuka file langsung dari arsip; nama persisnya cek di build lab.
- `powershell.exe -enc` (PID 6136) berinduk ke `wscript.exe`, menulis `upd.ps1` dua detik kemudian, dan isi perintah yang di-encode terbaca utuh di 4104 pukul 16:05:24. `Path` kosong karena kode datang dari command line, bukan dari file.
- Semua proses ini bertoken terbatas (`%%1938` di 4688 pasangannya) dan memakai Logon ID `0x3A1F2C` di field `LogonId` Sysmon (lihat `Payload`): ini sesi Andi, dijalankan oleh lampiran, bukan oleh sesi baru.
- 4698 dan 106 pada detik yang sama. `ClientProcessId` di 4698 bernilai 6136, sama dengan PID `powershell.exe -enc` di Sysmon 1. Itu mengikat pembuatan task ke proses yang dijalankan lampiran, bukan hanya ke akun Andi [S11].
- DNS ke `cdn-sync.example.net` dan koneksi pertama ke `203.0.113.77:443` tiga detik setelah task terdaftar, cocok dengan log proxy.

XML task dari `PayloadData2` 4698, dibaca langsung (dipotong ke bagian penting):

```xml
<RegistrationInfo><Date>2026-10-12T16:06:02</Date><Author>JAB\andi.pratama</Author></RegistrationInfo>
<Triggers>
  <TimeTrigger><Repetition><Interval>PT15M</Interval></Repetition><StartBoundary>2026-10-12T16:21:02</StartBoundary></TimeTrigger>
  <LogonTrigger>...</LogonTrigger>
</Triggers>
<Principals><Principal id="Author"><UserId>JAB\andi.pratama</UserId><LogonType>InteractiveToken</LogonType></Principal></Principals>
<Actions><Exec><Command>powershell.exe</Command>
  <Arguments>-NoProfile -WindowStyle Hidden -File "C:\Users\andi.pratama\AppData\Roaming\SysCache\upd.ps1"</Arguments></Exec></Actions>
```

**Cara membaca XML:** task berada di root library (`\SysCacheUpdate`), pola yang disarankan Microsoft untuk diperhatikan [S11]. Principal memakai `InteractiveToken`, bukan `Password`, sehingga task berjalan di sesi Andi yang sedang login dan tidak menyimpan password. Task yang berjalan dengan token interaktif tidak diharapkan membuat sesi baru; bila task didaftarkan dengan password tersimpan, cari logon type 4 (Batch). Cek perilaku ini di lab. Waktu `RegistrationInfo` ditulis tanpa zona dan cocok dengan WIB; selalu bandingkan dengan waktu event (UTC) sebelum menyimpulkan zonanya. Trigger pertama 16:21:02, lalu setiap 15 menit; di TaskScheduler ada 258 pasang event 200 dan 201 untuk task ini, satu per eksekusi dari Senin 16:21 sampai Kamis 08:36 WIB, dengan `powershell.exe` yang berinduk ke `svchost.exe` layanan Task Scheduler (cek baris perintah induknya di Sysmon 1).

**Variasi:** konfirmasi rantai yang sama dari 4688 (`NewProcessName`, `ParentProcessName`, `CommandLine`, `TokenElevationType`) untuk kasus host tanpa Sysmon. Untuk 4104 yang terpecah, kelompokkan berdasarkan `ScriptBlockId` dari `Payload`, urutkan berdasarkan `MessageNumber`, dan gabungkan sebelum dibaca.

**Kapan gagal:** filter waktu ditulis dalam WIB padahal CSV dalam UTC, sehingga rentang 16:04 sampai 16:07 menghasilkan nol baris dan disimpulkan "tidak ada aktivitas".

### 2.5 Malam dan dini hari: skrip kredensial dan SSH

Langkah ini melengkapi pertanyaan ketiga dengan dua kejadian yang paling penting bagi DPO: kapan password `svc_billing` dibaca, dan kapan dipakai.

```powershell
$e | Where-Object { ($_.Channel -like '*PowerShell*' -and $_.EventId -eq '4104' -and $_.Payload -match 'export-tagihan') -or
                    ($_.Channel -like '*Sysmon*' -and $_.EventId -eq '1' -and $_.ExecutableInfo -match 'ssh\.exe') } |
  Where-Object { $_.TimeCreated -ge '2026-10-12' } |
  Sort-Object TimeCreated | Select-Object TimeCreated, EventId, PayloadData1, ExecutableInfo
```

Keluaran ilustrasi (kolom diringkas):

```
TimeCreated (UTC)       EID   Ringkasan
2026-10-12 07:02:11.54  4104  Path: C:\Users\andi.pratama\Documents\export-tagihan.ps1
2026-10-12 16:40:17.09  4104  Path: C:\Users\andi.pratama\AppData\Roaming\SysCache\upd.ps1 | isi: mencari kata password, svc, ssh di Documents dan Desktop, membaca export-tagihan.ps1
2026-10-12 19:14:31.77  1     "C:\Windows\System32\OpenSSH\ssh.exe" svc_billing@10.20.5.21 | induk powershell.exe | user JAB\andi.pratama
```

**Cara membaca hasil:**

- Senin 14:02:11 WIB: 4104 dengan `Path` `export-tagihan.ps1`. Ini Andi sendiri menjalankan skrip ekspor laporan seperti biasa, dua jam sebelum lampiran dibuka. Baris ini bukan aktivitas penyerang, tetapi penting: isi skrip, termasuk password `svc_billing`, ikut tersimpan di log PowerShell setiap kali skrip itu dijalankan. CSV E15-W1 ditandai sensitif di evidence log karena alasan ini [S6][S20].
- Senin 23:40:17 WIB: 4104 dari `upd.ps1` (dijalankan task pukul 23:36) yang mencari kata kunci di Documents dan Desktop lalu membaca `export-tagihan.ps1`. Pembacaan file itu sendiri tidak meninggalkan event; yang tercatat adalah kode yang membacanya (bagian 1.6).
- Selasa 02:14:31 WIB (Senin 19:14:31 UTC): `ssh.exe` ke `10.20.5.21` dengan akun `svc_billing`, berinduk ke `powershell.exe` dari task yang berjalan pukul 02:06. Sysmon 3 pada detik yang sama mencatat koneksi ke port 22. SSH tidak memakai autentikasi Windows, sehingga di laptop tidak ada 4648 atau 4624 untuk login ini; bukti sisi tujuannya ada di log SSH `jkt-billing01`.

**Variasi:** cari semua 4104 yang memuat `ConvertTo-SecureString` dengan `-AsPlainText` atau kata `password` untuk menemukan skrip lain yang menyimpan kredensial dalam teks biasa; hasilnya bahan perbaikan, bukan bagian dari insiden.

**Kapan gagal:** tanggal UTC dibaca sebagai tanggal lokal, sehingga SSH Selasa 02:14 WIB dilaporkan terjadi "Senin malam". Di laporan, tulis keduanya sekali, lalu WIB.

### 2.6 Memisahkan responder dari penyerang

Langkah ini menjawab pertanyaan keempat Sari dan Agus. Hasil filter `ir-admin` di bagian 2.3 dicocokkan dengan case notes Yoga dan evidence log, lalu dirangkum dalam tabel yang dikirim ke Sari. Baca kolom "Penanda", karena kolom itulah yang membuat pemisahannya bisa diperiksa orang lain.

| Waktu (WIB) | Event | Akun dan sesi | Pelaku | Penanda |
|---|---|---|---|---|
| Selasa 12:31-12:37 | Proses sensor Defender (SYSTEM) | SYSTEM | Responder | Cocok dengan riwayat Action center: paket investigasi 12:31, `getfile` 12:36 |
| Selasa 12:38:29 | 4625 `0xC000006D` / `0xC000006A` | `ir-admin` | Responder | Salah ketik password, tercatat di case notes |
| Selasa 12:38:41 | 4624 type 2 (pasangan `0x9C04A7` / `0x9C04D2`), 4672 | `ir-admin` | Responder | Switch user di konsol; Yoga di lantai 3 sejak 12:38 |
| Selasa 12:41:50 | 4688 `cmd.exe`, `%%1937` | `ir-admin`, `0x9C04D2` | Responder | Command Prompt sebagai administrator |
| Selasa 12:42:07 | Sysmon 1 `E:\tools\winpmem_mini_x64.exe E:\INC-2026-019\E01_JKT-WS-0388_mem.raw` | `ir-admin` | Responder | Image di drive USB `USB-E-07`; E01 di evidence log 12:42-12:53 |
| Selasa 12:42:08 | 4697 dan System 7045, tipe kernel driver | `ir-admin` (dari 4697) | Responder | Driver akuisisi memori; nama service sesuai versi WinPmem di toolkit (dicocokkan di lab) |
| Selasa 12:53:40 | Sysmon 1 `certutil -hashfile E:\INC-2026-019\E01_JKT-WS-0388_mem.raw SHA256` | `ir-admin` | Responder | Hash dicatat di case notes |
| Selasa 12:55:10 | 4647 | `ir-admin` | Responder | Sign out |
| Kamis 08:46:20-08:47:52 | 4624 type 2, 4672, System 1074, 6006 | `ir-admin` | Responder | Shutdown sebelum image E15 pukul 09:00 |
| Senin 16:05-16:06 | Sysmon 1, 11, 4104, 4698, 106 | `andi.pratama`, `0x3A1F2C`, `%%1938` | Penyerang (lewat lampiran) | Induk `wscript.exe`, folder sementara arsip |
| Senin 16:21 sampai Kamis 08:36 | TaskScheduler 200/201, 4104 `upd.ps1`, Sysmon 3 | `andi.pratama` | Penyerang (task) | Tiap 15 menit, induk layanan Task Scheduler |
| Selasa 02:14:31 | Sysmon 1 `ssh.exe` | `andi.pratama` | Penyerang | Induk `powershell.exe` dari task |

**Cara membaca hasil:** semua jejak hak admin (4672, `%%1937`, 4697 dan 7045) milik sesi `ir-admin`, dan setiap barisnya punya pasangan di case notes atau evidence log. Semua jejak penyerang berada di sesi Andi dengan token terbatas.

Kalimat untuk Sari dan Agus: "Aktivitas akun admin lokal Selasa 12:38 sampai 12:55 dan Kamis 08:46 adalah Yoga mengambil memori dan mematikan laptop, sesuai case notes dan evidence log. Di event log tidak ada tanda penyerang mendapat hak admin di laptop ini: semua aktivitasnya berjalan di sesi pengguna biasa Andi. Batasnya: event log tidak melihat eksploitasi yang tidak membuat proses, logon, atau service baru; analisis memori E01 oleh retainer juga tidak menemukan akses ke LSASS."

**Variasi:** buat tabel serupa sebagai lampiran tetap di setiap laporan forensik PT JAB: daftar semua tindakan responder di host, dengan akun, waktu, dan jejak yang diharapkan. Retainer bisa mencoretnya dari temuan tanpa bertanya.

**Kapan gagal:** case notes responder tidak mencatat waktu dan akun, sehingga 7045 kernel driver Selasa siang tidak bisa dibuktikan milik siapa dan terpaksa dilaporkan sebagai "tidak diketahui".

### 2.7 Kontras dengan `JKT-WS-0412`: kenapa E14 tidak punya 4698

Langkah ini menjawab pertanyaan kelima Sari dengan angka, memakai output EvtxECmd dari E14-W1 yang sudah dibuat di Day 03.

```powershell
$k = Import-Csv (Get-ChildItem \\jkt-evid01\cases\INC-2026-019\analysis\E14-W1\EZ-2026.5.0\EventLogs -Filter '*EvtxECmd_Output.csv').FullName
'4624','4688','4697','4698','4104','106' | ForEach-Object {
    $id = $_; [pscustomobject]@{ EventId = $id; Jumlah = ($k | Where-Object EventId -eq $id).Count } }
($k | Where-Object Channel -like '*Sysmon*').Count
$k | Where-Object { $_.EventId -eq '4104' -and $_.Payload -match 'SysCache' } |
  Sort-Object TimeCreated | Select-Object -First 3 TimeCreated, Level
```

Keluaran ilustrasi:

```
EventId Jumlah
------- ------
4624      9128
4688         0
4697         0
4698         0
4104       214
106          0
0

TimeCreated                 Level
-----------                 -----
2026-10-12 13:14:52.0331870 Warning
2026-10-12 13:14:52.0418226 Warning
2026-10-12 13:29:53.1170539 Warning
```

**Cara membaca hasil:**

- Ribuan 4624 ada, jadi log Security tidak kosong dan tidak dibersihkan; yang tidak ada adalah seluruh subcategory Process Creation, Security System Extension, dan Other Object Access Events. Nol untuk satu event bisa kebetulan; nol untuk satu subcategory selama berminggu-minggu adalah konfigurasi.
- Nol event Sysmon: Sysmon tidak terpasang. Nol 106: channel TaskScheduler/Operational tidak aktif di laptop itu.
- 4104 yang cocok dengan `SysCache` berlevel Warning, sesuai pencatatan otomatis blok yang dianggap mencurigakan saat script block logging tidak aktif [S21]. Isinya cukup untuk mengenali loader yang sama, tetapi tidak menjamin semua blok tercatat. Nilai teks kolom `Level` cocokkan dengan CSV versi-mu.
- Dari sisi AD, `JKT-WS-0412` berada di `OU=Workstations,OU=Jakarta,...`, di luar jangkauan `JAB-WS-Audit` (bagian 1.5).

Kalimat untuk Sari: "E14 tidak punya 4698 karena `JKT-WS-0412` tidak pernah dikonfigurasi mencatatnya: laptop itu di OU lama tanpa GPO audit, tanpa Sysmon, dan tanpa history Task Scheduler. Bukti pembuatan task di laptop itu adalah XML task (`RegistrationInfo` Senin 20:14:39) dan 4104 berlevel Warning sejak 20:14:52. Tindak lanjut: pindahkan workstation yang belum di-onboard ke cakupan audit yang sama, tanpa menunggu EDR."

**Variasi:** jalankan hitungan yang sama untuk setiap host di kasus sebagai baris pertama laporan per host, sehingga pembaca tahu sejak awal sumber apa yang tersedia.

**Kapan gagal:** menulis "task dibuat tanpa jejak" atau "penyerang menghapus 4698" tanpa memeriksa konfigurasi; kedua kalimat itu salah dan akan dipatahkan siapa pun yang membaca GPO.

### 2.8 Timeline untuk Sari

Timeline ini adalah keluaran akhir yang dikirim ke Sari pukul 13:20. Kolom "Pelaku" memakai tiga nilai yang disepakati (pengguna, penyerang, responder), dan kolom "Sumber" menyebut event persisnya supaya retainer bisa memeriksa ulang.

| Waktu (WIB) | Kejadian | Pelaku | Sumber |
|---|---|---|---|
| Senin 07:58:14 | Andi login interaktif, sesi `0x3A1F2C` | Pengguna | 4624 type 2 |
| Senin 14:02:11 | Andi menjalankan `export-tagihan.ps1` (berisi password `svc_billing`) | Pengguna | 4104 |
| Senin 16:04:48 | `Tagihan-Okt-2026.zip` disimpan ke Downloads dari Outlook | Pengguna | Sysmon 11 |
| Senin 16:05:09-16:05:11 | `.js` diekstrak ke folder sementara dan dijalankan `wscript.exe` | Penyerang (lewat lampiran) | Sysmon 11, Sysmon 1, 4688 |
| Senin 16:05:17-16:05:24 | `powershell.exe -enc`, `upd.ps1` dibuat, isi perintah terbaca | Penyerang | Sysmon 1, Sysmon 11, 4104 |
| Senin 16:06:02 | Task `\SysCacheUpdate` dibuat oleh PID 6136 | Penyerang | 4698, TaskScheduler 106 |
| Senin 16:06:04-16:06:05 | DNS dan koneksi pertama ke C2 | Penyerang | Sysmon 22, Sysmon 3 |
| Senin 16:21 sampai Kamis 08:36 | Task berjalan tiap 15 menit (258 kali) | Penyerang | TaskScheduler 200/201, 4104 |
| Senin 23:40:17 | Loader mencari kata kunci dan membaca `export-tagihan.ps1` | Penyerang | 4104 |
| Selasa 02:14:31 | `ssh.exe` dengan `svc_billing` ke `10.20.5.21` | Penyerang | Sysmon 1, Sysmon 3, 4688 |
| Selasa 08:12:05 | Andi membuka kunci layar | Pengguna | 4624 type 7 |
| Selasa 12:31-12:55 | Paket investigasi, `getfile`, memori E01, hash | Responder | Bagian 2.6 |
| Kamis 08:47:30 | Laptop dimatikan untuk image E15 | Responder | System 1074, 6006 |

Pernyataan yang menyertai timeline:

- **Tidak ditemukan, dengan cakupan penuh:** RDP atau logon jaringan dari host lain, akun lokal baru atau penambahan ke grup Administrators, service lain selain milik responder, pembersihan log, dan perubahan audit policy. Semua subcategory yang relevan diaudit dan semua channel mencakup periode kasus.
- **Tidak bisa dijawab dari event log:** file apa lagi yang dibaca loader selain yang tampak di 4104, data apa yang dikirim ke C2 (log proxy dan memori), dan apakah ada file yang dibuat lalu dihapus (file system, Day 08).
- **Keyakinan:** tinggi untuk rangkaian Senin sore, task, dan SSH (tiga sumber atau lebih yang saling cocok); tinggi untuk pemisahan responder (cocok dengan case notes dan evidence log).

## 3. Lab praktik (di VM lab terisolasi)

**Prasyarat:** `LAB-WS01` (Windows 11, Sysmon dengan event 3 dan 22 aktif, audit policy diperluas seperti Day 02 bagian 1.4) dikembalikan ke snapshot `bersih-2026-10-15`; `LAB-DFIR01` dengan EvtxECmd dan Timeline Explorer; jaringan host-only `172.16.50.0/24` (`LAB-WS01` `172.16.50.10`, `LAB-DFIR01` `172.16.50.20`); folder kasus `CASE-2026-LAB-005` dengan `case-notes.md`. Semua aktivitas jinak dan dicatat jamnya (WIB) sebelum dijalankan. Perintah di bawah ditulis sebagai teks untuk dijalankan di VM lab.

1. **Catat konfigurasi.** Di `LAB-WS01`, simpan keluaran `auditpol /get /category:*`, `sysmon -c`, dan `wevtutil gl Microsoft-Windows-TaskScheduler/Operational` ke folder kasus. Ini "apa yang mungkin tercatat" untuk lab-mu (bagian 1.5).
2. **Logon dengan berbagai tipe.** Login konsol dengan akun lab biasa (type 2), kunci lalu buka layar (type 7), jalankan `runas /netonly /user:LAB\uji cmd.exe` (type 9), akses `\\172.16.50.10\C$` dari `LAB-DFIR01` dengan akun admin lab (type 3 di `LAB-WS01`), lalu RDP dari `LAB-DFIR01` ke `LAB-WS01` (type 10, 1149, 21, 22). Ketik satu password salah dengan sengaja untuk mendapat 4625.
3. **Akun dan grup.** Buat akun lokal `lab-uji05` dan tambahkan ke grup Administrators (4720, 4732). Catat SID-nya.
4. **Task dan service.** Buat task `\LabTask05` yang menjalankan `notepad.exe` tiap 15 menit dengan `schtasks`, dan service uji dengan `sc create` yang menunjuk ke program jinak. Cari 4698, 106, 200/201, 7045, dan 4697.
5. **PowerShell.** Jalankan satu perintah jinak lewat `powershell.exe -EncodedCommand` (misalnya hasil encode dari `Get-Date`) dan satu skrip `.ps1` yang berisi string password palsu. Cari keduanya di 4104 dan perhatikan bahwa string password palsu ikut tersimpan.
6. **Aktivitas "responder".** Login dengan akun admin lain, jalankan satu program dari disk virtual kedua (pengganti USB bukti), lalu sign out. Ini latihan memisahkan jejak responder.
7. **Matikan satu audit.** Matikan Audit Process Creation (`auditpol /set /subcategory:"Process Creation" /success:disable`), jalankan `notepad.exe`, lalu nyalakan lagi. Perhatikan 4719 dan celah 4688 sementara Sysmon 1 tetap ada.
8. **Pembersihan (di snapshot).** Bersihkan channel Sysmon dengan `wevtutil cl Microsoft-Windows-Sysmon/Operational`, lalu Security dengan `wevtutil cl Security`. Cari 104 di System dan 1102 di Security beserta akunnya.
9. **Koleksi dan parse.** Ekspor log dengan `wevtutil epl` atau koleksi KAPE seperti Day 03, salin ke `LAB-DFIR01` lewat disk virtual, hash, lalu parse dengan EvtxECmd (bagian 2.1). Jalankan profil cakupan (bagian 2.2) dan susun sesi (bagian 2.3).
10. **Rekonstruksi.** Tulis timeline lab dalam WIB yang memadukan minimal empat channel, dengan kolom Pelaku (kamu sebagai "pengguna", langkah 6 sebagai "responder"). Kembalikan snapshot.

**Hasil yang sebaiknya tersimpan:**

- Konfigurasi audit, Sysmon, dan status channel TaskScheduler sebelum aktivitas.
- Tabel logon type 2, 3, 7, 9, 10 dengan Logon ID, sumber, dan durasi sesi; satu 4625 dengan Status dan SubStatus-nya.
- 4720 dan 4732 untuk akun uji; 4698, 106, 200/201, 7045, dan 4697 untuk task dan service uji.
- 4104 untuk perintah `-EncodedCommand` (isi terbaca) dan skrip berisi password palsu.
- Bukti celah 4688 saat audit dimatikan, berikut 4719.
- 104 dan 1102 dengan akun yang membersihkan.
- Timeline lab dengan kolom Pelaku, dan catatan isi kolom CSV yang ternyata berbeda dari tabel bagian 1.7 di versi alat-mu.

**Variasi tantangan:** ulangi langkah 2 sampai 5 di VM yang hanya memakai audit bawaan dan tanpa Sysmon (snapshot lain), lalu tulis tabel "apa yang hilang" seperti bagian 2.7. Tantangan kedua: ambil koleksi yang mencakup VSS (Day 03) setelah langkah 8, dan tulis apa yang dikembalikan shadow copy dari log yang sudah dibersihkan.

## 4. Troubleshooting

Tabel ini memuat masalah yang sering muncul saat membaca event log hasil koleksi atau image. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Event yang diharapkan tidak ada | Audit policy tidak aktif; channel mati; rotasi | Cek konfigurasi (bagian 1.5); cek rentang waktu file (bagian 2.2) |
| Seluruh subcategory nol (4688, 4698) | Subcategory tidak diaudit; GPO tidak terpasang ke OU host | Hitung per event ID (bagian 2.7); cek OU dan GPO dari sisi AD |
| 4688 tanpa command line | Setting command line tidak aktif | Normal bila setting tidak aktif [S4]; pakai Sysmon 1 bila ada |
| Semua 4624 tampak milik akun komputer | Membaca kolom `UserName` (Subject) | Pakai `PayloadData1` (Target) di CSV EvtxECmd (bagian 1.7) |
| Dua 4624 pada detik yang sama untuk satu login | Pasangan sesi admin dengan UAC | Cek `TargetLinkedLogonId` dan `ElevatedToken` (bagian 2.3) |
| `PayloadData` kosong, `Payload` terisi | Maps tidak dimuat atau tidak ada map untuk event itu | Tulis `--maps` eksplisit; perbarui maps sesuai prosedur pembekuan; baca `Payload` |
| 4104 terpotong atau tidak bisa dibaca | Script block panjang dipecah ke beberapa event | Gabungkan berdasarkan `ScriptBlockId` dan `MessageNumber` dari `Payload` |
| PowerShell 7 tidak terlihat | Channel `PowerShellCore/Operational` tidak diparse atau provider tidak terdaftar | Cek file dan provider; script block logging PowerShell 7 punya kebijakan sendiri [S6] |
| Timestamp membingungkan | UTC vs lokal | Event log UTC; konversi eksplisit, tulis keduanya sekali (Day 13) |
| Banyak 4624 tidak relevan | Logon layanan dan sistem (type 5, akun `$`) | Filter logon type dan akun; fokus 2, 3, 7, 9, 10 |
| RDP tidak lengkap | Event tersebar di beberapa channel | Padukan 1149, 4624 type 10, dan 21/22 (bagian 1.2) |
| 7045 kernel driver tanpa penjelasan | Alat responder (akuisisi memori) atau driver penyerang | Cocokkan dengan case notes dan 4697; bandingkan dengan hasil uji alat di lab (bagian 1.4) |

## 5. Kesalahan umum dan jebakan

- **Menyimpulkan dari satu event.** Rekonstruksi butuh rangkaian lintas channel dan sesi yang disatukan Logon ID.
- **Mengira ketiadaan event berarti ketiadaan aktivitas.** Bisa audit mati, channel mati, rotasi, atau penghapusan. Petakan dulu apa yang memang dicatat (bagian 1.5 dan 2.2).
- **Mengabaikan LogonType.** 4624 tanpa tipe kehilangan arti: interaktif, jaringan, dan RDP adalah cerita yang berbeda.
- **Membaca Subject sebagai orang yang login.** Di 4624, orangnya ada di New Logon (Target), bukan Subject.
- **Menganggap nama akun sama dengan pelaku.** Penyerang yang menumpang sesi pengguna memakai akun pengguna itu; pemisahannya lewat rantai proses, bukan nama akun.
- **Melaporkan jejak responder sebagai temuan.** Logon admin lokal, driver akuisisi memori, dan `certutil` dari USB bukti adalah jejak tim sendiri. Siapkan tabel responder sebelum laporan dibaca orang lain (bagian 2.6).
- **Lupa zona waktu.** Event log dan output EvtxECmd dalam UTC; tanggal juga bisa bergeser (Selasa 02:14 WIB adalah Senin 19:14 UTC).
- **Melewatkan 1102 dan 104.** Pembersihan log adalah temuan penting, bukan sekadar celah, dan 104 ada di System, bukan di channel yang dibersihkan.
- **Lupa bahwa log PowerShell bisa menyimpan password.** Skrip sah berisi kredensial ikut tercatat di 4104; perlakukan CSV-nya sebagai data sensitif.
- **Memakai catatan lama tentang nilai bawaan audit.** Tabel bawaan Microsoft untuk client tidak mengaktifkan Security Group Management, Process Creation, atau Other Object Access Events [S19].
- `[komunitas, belum terkonfirmasi]` Praktisi menilai TaskScheduler 106 dan System 7045 sebagai sumber persistence yang andal karena ada tanpa audit tambahan, sementara 4698 butuh audit. Untuk 7045 ini sejalan dengan dokumentasi (System, bawaan); untuk 106, beberapa sumber how-to justru menyebut history Task Scheduler mati secara bawaan di Windows 10 dan 11 [S25]. Tentukan dari isi `.evtx` host, bukan dari asumsi.

## 6. Catatan terkini

Bagian ini menampung detail versi dan perubahan sumber yang bisa berubah lagi. Berguna saat membuka dokumen sumbernya, tetapi tidak mengubah langkah di atas.

- **Halaman event Security di Microsoft Learn** kini berada di bagian arsip "previous versions" Windows 10, dengan pembaruan metadata April 2026. Isi teknisnya masih berlaku untuk Windows 11. Halaman 4625 diperbarui 2026-03-29 [S7]; halaman lain bertanggal 2021-2022.
- **4624 versi 2 (Windows 10)** menambahkan bagian Logon Information, Restricted Admin Mode, Virtual Account, Elevated Token, Linked Logon ID, dan Network Account Name/Domain [S3]. **4688 versi 2** menambahkan Target Subject, Mandatory Label, dan Creator Process Name [S10]. **4698 sejak Windows 10 1903** menambahkan `ClientProcessStartKey`, `ClientProcessId`, `ParentProcessId`, `RpcCallClientLocality`, dan `FQDN` [S11].
- **Audit Logon bawaan** menjadi Success dan Failure sejak Windows 10 1809; sebelumnya Success saja [S19].
- **Sysmon** halaman terbit 2026-09-10, mendukung Windows 11 dan Server 2019 ke atas, dengan event ID 1 sampai 29 dan 255; contoh konfigurasi memakai `schemaversion` 4.82 [S5].
- **PowerShell 7.6** mencatat ke `PowerShellCore/Operational` dengan GPO di `Administrative Templates > PowerShell Core`; Windows PowerShell 5.1 mencatat ke `Microsoft-Windows-PowerShell/Operational` dengan GPO di `Administrative Templates > Windows Components > Windows PowerShell` [S6][S20].
- **EZ Tools 2026.5.0:** EvtxECmd tersedia untuk .NET 4.7.2 dan .NET 9; Timeline Explorer hanya .NET 9 [S2]. Maps EvtxECmd diperbarui terpisah dari biner (`--sync`), dan `Provider` wajib di map sejak Desember 2020 [S22][S23].
- **Velociraptor** artifact `Windows.EventLogs.PowershellScriptblock` memakai level Warning sebagai bawaan pencarian dan bisa membaca VSS lewat parameter `VSSAnalysisAge`; halaman dokumentasinya menyarankan pembaruan ke 0.77.3 karena beberapa CVE di 0.77.2 [S21].
- Channel dan event ID inti stabil antar Windows 10 dan 11; sebagian event TerminalServices dan status channel TaskScheduler bergantung versi dan konfigurasi.

## 7. Cheat sheet

```
CHANNEL    Security | System | PowerShell/Operational (5.1) | PowerShellCore/Operational (7) | Sysmon/Operational
           TaskScheduler/Operational | TerminalServices-* | WinRM ; file: winevt\Logs\*.evtx ("/" -> "%4")
URUTAN     petakan dulu (file, rentang waktu, audit, Sysmon, 1102/104/4719) -> parse -> sesi -> isi sesi -> pelaku
LOGON      4624 sukses (TargetLogonId, LogonType, LinkedLogonId, ElevatedToken) | 4625 gagal (Status/SubStatus)
           4634/4647 logoff | 4648 explicit creds | 4672 hak sensitif (admin, SYSTEM)
TYPE       2 konsol | 3 jaringan | 4 batch | 5 service | 7 unlock | 8 cleartext | 9 runas /netonly | 10 RDP | 11 cache
4625       C000006A pw salah | C0000064 akun tak ada | C000006D salah umum | C0000072 disabled | C0000234 locked
AKUN       4720 buat | 4722 aktif | 4724 reset pw | 4728/4732/4756 tambah grup | 4738 ubah | 4740 lock
EKSEKUSI   4688 (+cmdline bila GPO; %%1936 penuh / %%1937 elevated / %%1938 terbatas) | Sysmon 1 (cmdline, induk, hash, ProcessGuid)
TASK       4698/4699/4702 (XML lengkap; 1903+: ClientProcessId) | TS 106 daftar / 140-141 ubah-hapus / 200-201 jalan-selesai
SERVICE    System 7045 (tanpa pemasang) | Security 4697 (dengan pemasang; butuh audit) ; kernel driver = cek responder dulu
POWERSHELL 4104 isi blok (gabung ScriptBlockId+MessageNumber; Warning = otomatis) | 4103 module logging ; bisa memuat password
JARINGAN   Sysmon 3 koneksi (mati bawaan) | Sysmon 22 DNS | SSH keluar tidak membuat 4648/4624 di sumber
RDP        RCM 1149 koneksi (belum bukti logon) | 4624 type 10 | LSM 21-25
BERSIH     Security 1102 | System 104 (Channel = log yang dibersihkan) | 4719 audit policy berubah | cek rentang & EventRecordID
AUDIT      bawaan client: Logon S+F (1809+), Logoff, Special Logon, User Acct Mgmt ; TIDAK: Process Creation, Other Object Access,
           Security Group Mgmt, Security System Extension ; force subcategory settings
PARSE      EvtxECmd -d <Logs> --maps <Maps> --csv <dir> --csvf <f> [--inc/--exc ID] [--sd/--ed UTC] [--vss] [--tdt]
           4624: UserName=Subject, PayloadData1=Target ; field tak dipetakan -> kolom Payload ; waktu UTC
PELAKU     akun + Logon ID + induk proses + path/media + token + cocok case notes -> pengguna | penyerang | responder
BATAS      rotasi | audit/channel mati | penghapusan | baca file tak tercatat ; ketiadaan event != ketiadaan aktivitas
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "E14 dari `JKT-WS-0412` tidak berisi satu pun 4698, jadi penyerang pasti menghapus event pembuatan task, atau task itu dibuat dengan cara yang tidak tercatat." Benarkah?

<details><summary>Jawaban</summary>

Tidak. 4698 hanya ditulis bila Audit Other Object Access Events aktif, dan subcategory itu tidak aktif secara bawaan di Windows client. Laptop Rizky berada di OU lama di luar GPO audit, sehingga seluruh subcategory itu (dan Process Creation) bernilai nol, sementara ribuan 4624 tetap ada dan tidak ada 1102 atau 104. Bukti task di laptop itu adalah XML task dan 4104 berlevel Warning. Lihat bagian 1.5 dan 2.7.

</details>

**2. Skenario keputusan.** Gilang, analyst L1, membuka CSV EvtxECmd dari E15-W1 dan melapor: "Semua 4624 di laptop Andi dilakukan oleh `JKT-WS-0388$`, jadi akun komputer yang login, bukan Andi." Respons mana yang tepat?

- A. Setuju, lalu tambahkan temuan "akun komputer dipakai untuk logon interaktif" ke laporan.
- B. Jelaskan bahwa map 4624 menaruh Subject (akun yang melaporkan logon) di kolom `UserName`, sedangkan akun yang login ada di `PayloadData1` (`Target:`); susun ulang sesi dari kolom itu beserta logon type dan Logon ID.
- C. Abaikan kolom akun dan susun sesi hanya dari waktu.

<details><summary>Jawaban</summary>

B. Di 4624, bagian Subject biasanya akun komputer atau SYSTEM yang melaporkan logon, dan map EvtxECmd menaruhnya di `UserName`; orang yang login ada di New Logon, yang dipetakan ke `PayloadData1`. A keliru karena membaca kolom yang salah lalu melaporkan temuan yang tidak ada. C keliru karena tanpa akun, logon type, dan Logon ID, sesi responder dan sesi pengguna tidak bisa dipisahkan. Lihat bagian 1.7 dan 2.3.

</details>

**3. Pertanyaan jebakan.** "Ada 7045 bertipe kernel driver di `JKT-WS-0388` Selasa 12:42 WIB. Driver kernel di workstation adalah pola rootkit, jadi penyerang sempat punya hak admin." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Driver itu dimuat oleh alat akuisisi memori yang dijalankan Yoga dari `USB-E-07` dalam sesi `ir-admin`, cocok dengan 4697 (pemasang `ir-admin`), Sysmon 1 dengan image di `E:\`, case notes, dan evidence log E01 12:42 sampai 12:53. Pola itu memang pantas diwaspadai bila tanpa konteks, karena itulah responder harus mencatat tindakannya dan menguji jejak alatnya di lab. Lihat bagian 1.4 dan 2.6.

</details>

**4. Skenario keputusan.** Laporan awal retainer menulis "aktivitas akun admin lokal pada 13 Oktober siang" tanpa penjelasan, dan DPO bertanya apakah penyerang punya hak admin. Apa yang kamu kirim?

- A. Konfirmasi bahwa penyerang punya hak admin, karena ada 4672 dan proses elevated hari itu.
- B. Tabel yang memetakan setiap jejak hak admin ke sesi `ir-admin` (Logon ID, waktu, path di USB bukti, token elevated) dan ke case notes serta evidence log, plus pernyataan bahwa semua aktivitas penyerang berada di sesi pengguna biasa Andi, beserta batas pernyataan itu.
- C. Hapus baris-baris itu dari timeline karena hanya aktivitas tim sendiri.

<details><summary>Jawaban</summary>

B. Pemisahan harus bisa diperiksa orang lain: akun, Logon ID, waktu, induk proses, path, dan pasangan di case notes. A keliru karena 4672 dan token elevated hari itu milik sesi responder, bukan sesi penyerang. C keliru karena jejak responder adalah bagian dari bukti; menghapusnya membuat timeline tidak bisa dicocokkan dengan log asli dan menimbulkan pertanyaan baru. Lihat bagian 1.4 dan 2.6.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Agus Setiawan (DPO), dalam tiga kalimat, kenapa kalimat "tidak ada di event log" tidak sama dengan "tidak terjadi", dan bagaimana pembacaan `export-tagihan.ps1` Senin 23:40 tetap terlihat.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Windows hanya mencatat apa yang memang diatur untuk dicatat, dan catatan lama bisa tertimpa, jadi 'tidak ada di log' bisa berarti tidak terjadi, tidak diatur untuk dicatat, atau sudah tertimpa; karena itu kami selalu memeriksa pengaturannya dulu. Membuka sebuah file, misalnya, tidak dicatat sama sekali di laptop karyawan kita. Pembacaan file berisi password Senin malam tetap terlihat karena dilakukan oleh skrip PowerShell, dan isi skrip itu tercatat lengkap, termasuk perintah yang membuka file tersebut."

Kesalahan yang sering muncul:
- Menjelaskan nama subcategory audit dan event ID, padahal yang dibutuhkan DPO adalah arti kesimpulannya.
- Menyatakan "log membuktikan file itu tidak disalin ke tempat lain", padahal pembacaan dan pengiriman file tidak tercatat di event log.
- Tidak menyebut bahwa pengaturan sudah diperiksa, sehingga kalimat "tidak ditemukan" terdengar seperti janji.

</details>

**6. Pertanyaan jebakan.** "Di CSV EvtxECmd, `ssh.exe` ke `10.20.5.21` tercatat pada 2026-10-12 19:14:31, jadi SSH ke server billing terjadi Senin malam pukul 19:14." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Waktu di output EvtxECmd dan di Sysmon adalah UTC. 19:14:31 UTC Senin sama dengan Selasa 02:14:31 WIB, cocok dengan log SSH di `jkt-billing01`. Salah membaca zona menggeser kejadian ke hari yang berbeda dan bisa mengubah penilaian kapan password mulai dipakai. Lihat bagian 1.1 dan 2.5.

</details>

**7. Interview question (English).** "How do you use Windows event logs to reconstruct what happened on a compromised workstation, and what are their limits?"

<details><summary>Sample answer</summary>

"I start by mapping what the host could have recorded before I search for anything: which .evtx files exist, the time range each one covers, the audit policy and whether Sysmon and script block logging were on, and whether there's any 1102, 104 or 4719. Then I parse everything with EvtxECmd to UTC and build logon sessions from 4624 and 4625, using logon type and Logon ID rather than just account names, because an attacker riding a user's session looks like that user. Inside each session I follow process creation from 4688 or Sysmon 1, persistence from 4698, Task Scheduler and 7045, and PowerShell content from 4104, and I correlate the IDs, like the client process ID in 4698 matching the PowerShell process that created the task. I also separate our own responder activity, local admin logons and memory acquisition drivers, using case notes. The limits are that logs only contain what was configured, they rotate, file reads usually aren't recorded, and a clean result has to state its coverage. So 'not in the logs' always comes with 'and here's why it would or wouldn't be there'."

What makes this answer strong: it puts configuration and coverage before searching, uses sessions and IDs instead of names, names concrete events across several channels, treats responder artifacts as part of the analysis, and states limits in a way a stakeholder can act on.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Microsoft Learn: Advanced security audit policy settings | https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-audit-policy-settings | primer | diakses 2026-10-09 | Tinggi. Event ID, channel, dan lokasi log |
| S2 | Eric Zimmerman tools: EvtxECmd dan Timeline Explorer | https://ericzimmerman.github.io/ | primer | diakses 2026-10-09, dicek ulang 2026-10-16 | Tinggi. Versi 2026.5.0; CLI .NET 4.7.2 dan .NET 9; GUI hanya .NET 9; custom maps |
| S3 | Microsoft Learn: 4624(S) An account was successfully logged on | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624 | primer | ms.date 2021-09-07; diakses 2026-10-10, dicek ulang 2026-10-16 | Tinggi. Logon type 0-13, field versi 2, Linked Logon ID, Elevated Token, catatan isi field jaringan |
| S4 | Microsoft Learn: Command line process auditing | https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing | primer | ms.date 2025-05-12; diakses 2026-10-10, dicek ulang 2026-10-16 | Tinggi. Dua setting untuk command line 4688, peringatan password di command line, 4719, force subcategory settings |
| S5 | Microsoft Learn: Sysmon | https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon | primer | terbit 2026-09-10; diakses 2026-10-10, dicek ulang 2026-10-16 | Tinggi. Event ID 1-29 dan 255, UTC, ProcessGuid, event 3 mati bawaan, SHA1 bawaan |
| S6 | Microsoft Learn: about_Logging_Windows (PowerShell 7.6) | https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows | primer | ms.date 2026-01-18; diakses 2026-10-10, dicek ulang 2026-10-16 | Tinggi. Module logging, script block logging, channel `PowerShellCore/Operational`, Protected Event Logging |
| S7 | Microsoft Learn: 4625(F) An account failed to log on | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625 | primer | ms.date 2026-03-29; diakses 2026-10-16 | Tinggi. Tempat event ditulis, kode Status/SubStatus |
| S8 | Microsoft Learn: 4648(S) A logon was attempted using explicit credentials | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4648 | primer | ms.date 2021-09-07; diakses 2026-10-16 | Tinggi. Pemicu (task, RunAs), Target Server Name, korelasi Logon GUID |
| S9 | Microsoft Learn: 4672(S) Special privileges assigned to new logon | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4672 | primer | ms.date 2021-09-07; diakses 2026-10-16 | Tinggi. Daftar hak sensitif; SeSecurityPrivilege untuk melihat dan membersihkan log Security |
| S10 | Microsoft Learn: 4688(S) A new process has been created | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688 | primer | ms.date 2022-01-24; diakses 2026-10-16 | Tinggi. Versi event, Token Elevation Type, Mandatory Label, command line kosong secara bawaan |
| S11 | Microsoft Learn: 4698(S) A scheduled task was created | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4698 | primer | ms.date 2021-09-07; diakses 2026-10-16 | Tinggi. Task Content XML, field tambahan sejak 1903, saran task di root dan LogonType Password |
| S12 | Microsoft Learn: 4720(S) A user account was created | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4720 | primer | ms.date 2021-09-07; diakses 2026-10-16 | Tinggi. Atribut akun baru dan nilai yang layak diperiksa |
| S13 | Microsoft Learn: 4732(S) A member was added to a security-enabled local group | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4732 | primer | ms.date 2021-09-07; diakses 2026-10-16 | Tinggi. Satu event per anggota; nama anggota `-` untuk grup lokal |
| S14 | Microsoft Learn: 1102(S) The audit log was cleared | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102 | primer | ms.date 2021-09-07; diakses 2026-10-16 | Tinggi. Provider Microsoft-Windows-Eventlog, field Subject, saran investigasi |
| S15 | Microsoft Learn: 4697(S) A service was installed in the system | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4697 | primer | ms.date 2021-09-07; diakses 2026-10-16 | Tinggi. Field service, tipe dan start type, saran untuk path, kernel driver, dan akun |
| S16 | Microsoft Learn: Audit Other Object Access Events | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-other-object-access-events | primer | ms.date 2021-09-06; diakses 2026-10-16 | Tinggi. Daftar event (4698-4702 dan lainnya); tabel di halaman ini adalah rekomendasi, bukan nilai bawaan |
| S17 | Microsoft Learn: Audit Process Creation | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-process-creation | primer | ms.date 2022-03-16; diakses 2026-10-16 | Tinggi. Event 4688 dan 4696; volume event |
| S18 | Microsoft Learn: Audit Logon | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-logon | primer | ms.date 2021-09-06; diakses 2026-10-16 | Tinggi. Event 4624, 4625, 4648, 4675; event ditulis di host yang diakses |
| S19 | Microsoft Learn: System Audit Policy recommendations | https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/audit-policy-recommendations | primer | ms.date 2025-06-13; diakses 2026-10-16 | Tinggi. Tabel nilai bawaan Windows client dan server; Audit Logon Success dan Failure sejak 1809 |
| S20 | Microsoft Learn: about_Logging (Windows PowerShell 5.1) | https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging?view=powershell-5.1 | primer | ms.date 2024-01-09; diakses 2026-10-16 | Tinggi. Channel `Microsoft-Windows-PowerShell/Operational`, 4104, GPO dan registry script block logging |
| S21 | Velociraptor: Windows.EventLogs.PowershellScriptblock | https://docs.velociraptor.app/artifact_references/pages/windows.eventlogs.powershellscriptblock | primer (dokumentasi proyek) | diakses 2026-10-16 | Sedang-tinggi. Level Warning tercatat walau script block logging mati bila kata kunci mencurigakan terdeteksi; parameter `LogLevel`, `VSSAnalysisAge` |
| S22 | GitHub: EricZimmerman/evtx (README EvtxECmd) | https://github.com/EricZimmerman/evtx | primer (repo resmi) | diakses 2026-10-16 | Tinggi. Opsi `-f`, `-d`, `--csv`, `--csvf`, `--inc`, `--exc`, `--sd`, `--ed`, `--maps`, `--vss`, `--dedupe`, `--sync`, `--tdt`, `--met` |
| S23 | GitHub: evtx Maps README | https://raw.githubusercontent.com/EricZimmerman/evtx/master/evtx/Maps/!!!!README.md | primer (repo resmi) | diakses 2026-10-16 | Tinggi. Struktur map, kolom target, konvensi nama, `Provider` wajib sejak Desember 2020, override dengan awalan `1_` |
| S24 | GitHub: evtx Maps (map 4624, 4698, 7045, 104, 106, 201, 4104, Sysmon 1, 1149, 21) | https://github.com/EricZimmerman/evtx/tree/master/evtx/Maps | primer (repo resmi) | diakses 2026-10-16 | Tinggi untuk isi kolom per map pada tanggal akses; map bisa berubah |
| S25 | NinjaOne: How to enable or disable Task Scheduler history | https://www.ninjaone.com/blog/enable-or-disable-task-scheduler-history/ | komunitas (blog vendor how-to) | diperbarui 2026-03-20; diakses 2026-10-16 | Rendah-sedang. History Task Scheduler mati bawaan di Windows 10 dan 11; perintah `wevtutil set-log` |

**Catatan sumber:** event ID inti, field, dan logon type di Day ini berasal dari halaman event Microsoft yang kini berada di arsip Windows 10 tetapi masih berlaku untuk Windows 11 [S3][S7]-[S15]. Nilai bawaan audit policy diambil dari tabel System Audit Policy recommendations [S19]; tabel di halaman per subcategory [S16][S17][S18] adalah rekomendasi, bukan nilai bawaan. Klaim lama bahwa Security Group Management "sering aktif" di build modern dikoreksi berdasarkan [S19]. Klaim bahwa Windows PowerShell mencatat blok mencurigakan dengan level Warning walau script block logging mati sebelumnya dirujuk ke dokumentasi PowerShell, tetapi halaman about_Logging yang diperiksa [S6][S20] tidak memuatnya; kini dirujuk ke dokumentasi artifact Velociraptor [S21], dan daftar kata kuncinya tidak didokumentasikan di sumber yang diperiksa. Status bawaan channel TaskScheduler/Operational belum dikonfirmasi Microsoft: sumber how-to [S25] menyebut mati, catatan lama topik ini menyebut aktif; Day ini memilih menentukannya dari isi `.evtx`. Event 22-25 LocalSessionManager, 6005, 6006, 1074, 7034, 7036, 7040, 140, 141, dan 200 berasal dari versi lama Day ini tanpa halaman primer yang diperiksa ulang; perilakunya cek di build lab. Bahwa alat akuisisi memori memuat driver lewat Service Control Manager sehingga menghasilkan 7045 dan 4697 adalah penalaran dari sifat alat yang memuat driver kernel, dan nama service-nya harus dicek di lab dengan versi alat yang sama. Nama kolom CSV selain yang dipetakan map (misalnya `Level`, `EventRecordId`) perlu dicocokkan dengan header versi EvtxECmd yang dipakai. Semua isi PT JAB, termasuk waktu, Logon ID, PID, jumlah event, isi GPO, OU, nama akun `ir-admin`, dan hasil parse, adalah contoh fiktif.
