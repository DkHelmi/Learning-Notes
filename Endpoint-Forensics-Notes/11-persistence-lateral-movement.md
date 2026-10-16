---
day: 11
title: 'Persistence dan lateral movement di host: autostart, service, task, WMI subscription, dan jejak RDP, SMB, WinRM, PsExec'
researched_on: 2026-10-16
versions_checked: 'Windows 10/11; EZ Tools 2026.5.0 (RECmd, EvtxECmd, PECmd, MFTECmd, Registry Explorer); Velociraptor 0.77.3 (Windows.Persistence.PermanentWMIEvents); Sysmon 15.x (schemaversion 4.82, publikasi 2026-09-10); PsExec (PsTools, publikasi 2023-04-11); event log Microsoft Learn; MITRE ATT&CK T1547.001, T1543.003, T1053.005, T1546.003, T1021, T1569.002'
---

# Day 11: Persistence dan lateral movement di host

Cakupan: menemukan dan menafsirkan jejak persistence dan lateral movement pada satu host dari registry, event log, file system, repository WMI, dan artefak klien, lengkap dengan keterbatasan tiap jejak.

## Ide inti

Persistence dan lateral movement adalah dua pertanyaan berbeda yang dijawab dari kumpulan artefak yang hampir sama. Persistence menanyakan "bagaimana kode penyerang bertahan hidup di host ini setelah reboot atau logoff", dan jejaknya ada di lokasi autostart: Run key, service, scheduled task, Startup folder, dan WMI event subscription. Lateral movement menanyakan "host ini terhubung dengan host lain ke arah mana", dan jejaknya terbelah menjadi dua sisi: host sebagai tujuan (ada logon jaringan atau RDP masuk, lalu service atau proses muncul) dan host sebagai sumber (ada artefak klien yang menyimpan nama host tujuan). Kunci kerjanya satu: tidak ada satu artefak pun yang cukup. Sebuah Run key tanpa event pembuatnya hanya membuktikan nilai itu ada sekarang, bukan kapan dibuat atau oleh siapa. Satu 4624 type 3 hanya membuktikan ada logon jaringan, bukan apa yang dikerjakannya. Persistence dan lateral movement yang meyakinkan selalu berupa beberapa artefak yang sepakat pada waktu, akun, dan proses yang sama.

Kamu sudah mengenal pola ini dari NOC. Saat gangguan merambat antar perangkat, tidak ada satu tabel yang menjawab semuanya. Tabel MAC di switch menunjukkan sebuah host pernah terlihat di sebuah port, RADIUS accounting menunjukkan sesi login lewat AAA, NetFlow menunjukkan trafiknya mengalir ke mana, dan log perubahan konfigurasi menunjukkan ada baris yang ditambahkan supaya perangkat tetap berperilaku tertentu setelah reboot. Masing-masing sepotong. Engineer yang berpengalaman tidak menyimpulkan dari satu tabel; ia menautkan session ID, MAC, IP, dan waktu sampai keempatnya menunjuk kejadian yang sama. Di host Windows, Logon ID menggantikan session ID, dan korelasi yang sama yang membuat sebuah temuan layak ditulis.

```
dua pertanyaan, satu kumpulan artefak
  |
  +-- PERSISTENCE: kode penyerang bertahan di host ini?
  |     Run key | Service (7045) | Task (file + 106/4698) | Startup folder | WMI subscription
  |     tiap mekanisme punya >1 jejak -> korelasi memberi KAPAN dan OLEH APA
  |
  +-- LATERAL (tujuan): host ini dimasuki dari mana?
  |     4624 type 3/10 | 1149/21/25 | 5145 (ADMIN$/IPC$) | 7045 PSEXESVC | WmiPrvSE | wsmprovhost
  |
  +-- LATERAL (sumber): host ini dipakai ke mana?
        Terminal Server Client\Default MRU | bitmap cache | 4648 | Prefetch PsExec/wmic
        MountPoints2 / share yang di-mount
  |
  v
korelasi (waktu + akun + Logon ID + proses) -> temuan + keyakinan + "yang hilang dan kenapa"
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan sekitar 1.200 karyawan dan data pribadi 400 ribu pelanggan broadband. Kasusnya `INC-2026-017`, insiden ransomware SEV-1: Jumat 2026-10-09 pukul 21:31:58 sampai 22:17:04, file di share `Keuangan` pada file server `JKT-FS01` dienkripsi menjadi ekstensi `.lck` dari workstation `JKT-WS-0457` (`budi.santoso`, `10.10.45.57`). Investigasi mundur menemukan akses awal Rabu 2026-10-07 sekitar 03:10 lewat server aplikasi lama yang menghadap internet `jkt-dmz-app01` (`10.20.9.20`, tanpa EDR), lalu dump kredensial dan pemakaian ulang local admin, lalu Kamis 2026-10-08 pergerakan lateral ke workstation Keuangan `JKT-WS-0441` (`siti.rahayu`, `10.10.44.41`) dan dari sana ke `JKT-WS-0457`. Keduanya workstation Jakarta dengan Microsoft Defender for Endpoint dan Sysmon, di OU yang menerima GPO audit lengkap. Jumat terjadi exfil sekitar 6 GB dari `JKT-WS-0457` (18:40 sampai 20:10), tamper antivirus (20:52), penghapusan shadow copy di `JKT-WS-0441` (21:05), lalu enkripsi. Sabtu 2026-10-10 containment selesai; kedua workstation diisolasi lewat EDR tanpa dimatikan, memori dan paket investigasi diambil, dan Senin 2026-10-12 pukul 09:00 keduanya di-image sebelum rebuild. Rebuild ditunda karena tim tertarik ke insiden lain, sehingga image tersimpan utuh. Senin 2026-10-26 pukul 09:00, menjelang post-incident review dan sebelum kedua host akhirnya dibangun ulang, Sari Kusuma (technical lead) menulis kepadamu di kanal `#inc-2026-017`:

> "Sebelum kita rebuild dua laptop ini, Bu Nina minta bedah forensik lengkap untuk PIR. Pakai E05-W1 (`JKT-WS-0457`) dan E06-W1 (`JKT-WS-0441`). Yang saya butuh: tiap laptop ini dimasuki lewat teknik apa dan dari host mana? Apakah salah satunya dipakai untuk loncat ke host lain, dan ke mana? Persistence apa yang mereka tanam di tiap host, kapan dibuat, dan oleh proses apa? Bisa tidak kita tunjukkan ini PsExec, ini WMI, ini RDP, dari jejaknya saja? Ada persistence yang tidak kelihatan di registry atau task, misalnya di WMI? Dan mana jejak yang sudah mereka hapus tapi masih bisa kita buktikan pernah ada? Terakhir, seberapa yakin kita, dan apa yang memang tidak bisa dijawab dari disk?"

Pesan itu memuat enam pertanyaan:

1. Tiap workstation dimasuki lewat teknik apa, dari host mana (host sebagai tujuan)?
2. Apakah workstation dipakai untuk bergerak ke host lain, dan ke mana (host sebagai sumber)?
3. Persistence apa yang dipasang di tiap host, kapan, dan oleh proses apa?
4. Bisakah metode (PsExec, WMI, WinRM, RDP, task jarak jauh) dibedakan dari jejaknya?
5. Mana jejak yang dihapus, dan bagaimana membuktikan persistence pernah ada meski kini hilang?
6. Seberapa yakin jawabannya, dan apa yang tidak bisa dijawab dari disk?

Pertanyaan 1 dijawab di bagian 1.2, pertanyaan 2 di bagian 1.3, pertanyaan 3 di bagian 1.1, pertanyaan 4 di bagian 1.4 dan 1.5, pertanyaan 5 di bagian 1.6, dan pertanyaan 6 di bagian 1.7. Bagian 2 berisi perintah parsing, hasil ilustrasi, dan jawaban tertulis yang kamu kirim ke Sari untuk PIR.

**Kapan relevan:** setelah triage atau image menemukan host yang dicurigai, untuk menentukan persistence yang dipasang, jalur masuk dari host lain, dan jalur keluar ke host lain, sebagai bahan scoping, eradication, dan detection engineering.
**Kapan bukan jawaban:** Day ini bukan tentang kompromi domain menyeluruh (pergerakan lewat DC, GPO, atau Kerberos ditangani dengan log DC dan AD, bukan hanya artefak host), bukan tentang membangun teknik serangan (semua dibahas dari sisi jejak), dan bukan pengganti log jaringan untuk membuktikan trafik yang tidak menyentuh event host.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (Prefetch, Amcache, Shimcache, BAM, SRUM, `$MFT`, `$J`, Run key, service, scheduled task, Logon ID, logon type, 4624, 4688, 4698, 7045, 4104, Sysmon, last write time, jejak responder, chain of custody, salinan kerja, read-only mount) tidak diulang. Tabel berikut hanya memuat istilah baru Day ini. Kolom padanan memakai analogi NOC dan SOC yang sama di semua Day.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| Lateral movement | Perpindahan penyerang dari satu host ke host lain memakai akses dan kredensial yang didapat | Gangguan yang merambat dari satu perangkat ke perangkat tetangga lewat koneksi yang sudah ada |
| Host sebagai tujuan | Host yang dimasuki dari host lain; jejaknya logon jaringan atau RDP masuk lalu aktivitas | Perangkat yang menerima sesi masuk dari perangkat lain |
| Host sebagai sumber | Host yang dipakai untuk mengakses host lain; jejaknya artefak klien yang menyimpan tujuan | Perangkat tempat engineer membuka sesi keluar ke perangkat lain |
| WMI event subscription | Persistence lewat tiga objek WMI (filter, consumer, binding) yang menjalankan aksi saat pemicu terpenuhi | Script otomasi di perangkat yang berjalan setiap kali kondisi tertentu terpenuhi, disimpan di luar konfigurasi utama |
| PSEXESVC | Service yang dibuat PsExec di host tujuan untuk menjalankan perintah, lalu dihapus | Daemon sementara yang dipasang alat remote untuk menjalankan perintah lalu dibersihkan |
| Named pipe | Kanal komunikasi antar-proses yang dipakai alat remote (PsExec, WMI) untuk stdin, stdout, stderr | Sesi kontrol terpisah dari kanal data pada satu koneksi |
| ADMIN$ dan IPC$ | Admin share bawaan (`C:\Windows`) dan share komunikasi antar-proses, dipakai alat remote | Antarmuka manajemen tersembunyi yang selalu ada di perangkat, bukan port layanan biasa |

### 1.1 Persistence: lokasi, jejak ganda, dan cara menentukan kapan dan oleh apa

Pertanyaan ketiga Sari ("persistence apa, kapan, oleh apa") dijawab dengan memeriksa semua lokasi autostart secara sistematis, lalu untuk tiap temuan menjawab dua hal: kapan dibuat dan oleh proses apa. Memeriksa satu lokasi saja (misalnya hanya Run key) adalah kesalahan yang sering membuat persistence terlewat.

Tabel berikut memetakan mekanisme persistence yang umum ke jejaknya dan ID teknik ATT&CK [S5]; baca kolom "Jejak forensik", karena tiap mekanisme punya lebih dari satu, dan korelasinya yang memberi keyakinan.

| Mekanisme | ATT&CK | Jejak forensik |
|---|---|---|
| Registry Run/RunOnce | T1547.001 | Nilai di SOFTWARE (mesin) atau NTUSER (pengguna); event pembuatan bila audit registry aktif; Sysmon 12/13 bila dikonfigurasi |
| Service | T1543.003 | Key `ControlSet00x\Services\<nama>` di SYSTEM; System 7045; Security 4697 bila audit aktif; Sysmon 12/13 |
| Scheduled task | T1053.005 | File XML di `C:\Windows\System32\Tasks\`; TaskScheduler 106; Security 4698 bila audit aktif; key `TaskCache` di SOFTWARE |
| Startup folder | T1547.001 | File di folder Startup per pengguna dan semua pengguna; MFT; Sysmon 11 |
| WMI event subscription | T1546.003 | Objek di repository WMI (`OBJECTS.DATA`); WMI-Activity/Operational 5861; Sysmon 19, 20, 21 bila Sysmon aktif |
| Winlogon (Shell, Userinit) | T1547.004 | Nilai di key Winlogon di SOFTWARE; last write key |

Lokasi Run dan RunOnce yang resmi ada empat [S1]: `HKLM\Software\Microsoft\Windows\CurrentVersion\Run`, `HKLM\...\RunOnce`, `HKCU\...\Run`, dan `HKCU\...\RunOnce`. Run dijalankan setiap kali pengguna login, RunOnce dijalankan sekali lalu nilainya dihapus (kecuali nama nilai diawali tanda seru untuk menunda penghapusan sampai perintah selesai), dan nilai di `HKLM\...\RunOnce` hanya dijalankan saat anggota grup Administrators login setelah reboot [S1]. Nilai berupa command line maksimal 260 karakter, dan urutan jalannya tidak dijamin [S1]. Startup folder per pengguna adalah `C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup` dan untuk semua pengguna `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp` [S2].

Untuk tiap persistence yang ditemukan, jawab dua hal:

- **Kapan dibuat.** Untuk service, event 7045 memberi waktu pemasangan [S9]. Untuk task, waktu paling sulit dipalsukan adalah timestamp FN file XML di `Tasks\` (file system, dibahas di Day 08), didukung 106 dan 4698 [S4]. Untuk Run key, yang ada hanya last write time key induknya (registry, dibahas di Day 09), yang bergeser bila nilai lain di key yang sama berubah, sehingga perkiraannya lemah; perkuat dengan MFT waktu file payload dibuat.
- **Oleh proses apa.** Bila Audit Process Creation aktif, 4688 atau Sysmon 1 pada detik yang sama menunjukkan proses pembuat dan induknya. Event 4698 sejak Windows 10 1903 memuat `ClientProcessId` dan `ParentProcessId`, yang menautkan task ke proses yang membuatnya [S4]. Event 7045 sendiri tidak memuat akun pemasang; pasangkan dengan 4697 (bila Audit Security System Extension aktif) atau dengan proses yang berjalan pada detik yang sama [S9].

Prinsipnya: satu artefak jarang cukup. Run key plus MFT file payload plus 4688 pembuatnya adalah bukti kuat; Run key sendiri hanya membuktikan nilai itu ada saat image diambil.

### 1.2 Lateral movement: host sebagai tujuan (masuk)

Pertanyaan pertama Sari ("dimasuki lewat teknik apa, dari mana") dijawab dari jejak yang menandakan host ini menerima sesi dari host lain. Tiap teknik meninggalkan kombinasi logon dan artefak yang khas.

Tabel berikut memetakan teknik akses jarak jauh ke jejaknya di host tujuan; baca kolom "Logon type", karena itu pembeda cepat antara akses jaringan dan akses interaktif jarak jauh.

| Teknik | ATT&CK | Logon type (4624) | Jejak pendukung di tujuan |
|---|---|---|---|
| SMB / admin share | T1021.002 | 3 (Network) | 5140/5145 ADMIN$ dan IPC$ bila audit aktif; file ditulis ke `C:\Windows` |
| PsExec (service execution) | T1569.002 | 3 | System 7045 service `PSEXESVC`; System 7036 service Running lalu Stopped; `C:\Windows\PSEXESVC.exe`; 5145 IPC$ ke pipe `PSEXESVC`, `-stdin`, `-stdout`, `-stderr` |
| WMI remote | T1047 | 3 | Proses `WmiPrvSE.exe` berinduk `svchost.exe -k DcomLaunch`; koneksi masuk port 135 lalu high port |
| WinRM / PowerShell remoting | T1021.006 | 3 | Proses `wsmprovhost.exe` (host penyedia WinRM); koneksi masuk port 5985/5986 |
| Scheduled task jarak jauh | T1053.005 | 3 | 4624 type 3 lalu 4698/106; task dijalankan oleh layanan Task Scheduler |
| RDP | T1021.001 | 10 (RemoteInteractive) | RemoteConnectionManager 1149 (dan 261); LocalSessionManager 21/24/25; 4778/4779 reconnect/disconnect |

Logon type 3 adalah akses jaringan: akses share SMB, PsExec, WMI, dan WinRM semuanya menghasilkan 4624 type 3 di host tujuan, dengan `Source Network Address` berisi IP host sumber (field ini bisa kosong untuk logon Kerberos tertentu, dan logon NTLM tidak memuat detail TCP/IP) [S6]. Logon type 10 adalah RDP: pengguna login dari jauh lewat Terminal Services atau Remote Desktop [S6]. Field `Restricted Admin Mode` pada 4624 hanya terisi untuk logon type 10, bernilai "Yes" bila kredensial dikirim dalam mode Restricted Admin [S6]; ini berguna untuk menilai apakah RDP dipakai dengan teknik yang menghindari pengiriman password.

Rekonstruksi RDP masuk menautkan tiga channel: RemoteConnectionManager mencatat listener menerima koneksi (261) dan autentikasi pengguna berhasil (1149); LocalSessionManager mencatat sesi (21 logon berhasil, 24 disconnect, 25 reconnect); Security 4624 type 10 membuktikan logon berhasil dengan IP sumber [S7][S18]. Event 4778 ditulis saat sesi disambung kembali, memuat Account Name, Session Name (misalnya `RDP-Tcp#N`), Client Name, dan Client Address, dan juga muncul untuk Fast User Switching [S19]. Satu 1149 sendiri belum membuktikan logon berhasil; ia hanya menandakan koneksi terbentuk.

PsExec punya pola yang paling khas di tujuan karena ia bekerja dengan memasang service. JPCERT mendokumentasikan jejaknya: System 7045 service `PSEXESVC` (demand start, LocalSystem, `%SystemRoot%\PSEXESVC.exe`), System 7036 service masuk Running lalu Stopped, Security 4624 type 3 dan 4672, Security 5140/5145 akses ADMIN$ ke `PSEXESVC.exe` dan IPC$ ke nama relatif `PSEXESVC` serta `PSEXESVC-<host sumber>-<PID sumber>-stdin`, `-stdout`, `-stderr`, lalu penghapusan file dan service setelah selesai (4660, 4674) [S10]. File di disk: `C:\Windows\PSEXESVC.exe` dan `C:\Windows\Prefetch\PSEXESVC.EXE-<RANDOM>.pf` dengan entri USN dan MFT masing-masing [S10]. Dokumentasi PsExec menegaskan opsi `-r` mengganti nama service yang dibuat, sehingga nama `PSEXESVC` bisa disamarkan; karena itu pola (service sementara, named pipe stdin/stdout/stderr, file di `C:\Windows`) lebih tahan daripada nama service [S11].

### 1.3 Lateral movement: host sebagai sumber (keluar)

Pertanyaan kedua Sari ("dipakai untuk loncat ke mana") dijawab dari artefak klien, yaitu jejak yang tertinggal di host yang memulai koneksi keluar. Artefak ini sering lebih tahan daripada log di tujuan karena tersimpan di registry pengguna dan file cache.

Tabel berikut memetakan teknik ke jejak sumbernya; baca kolom "Yang tersimpan", karena di situlah nama host tujuan sering terbaca utuh.

| Teknik keluar | Jejak di host sumber | Yang tersimpan |
|---|---|---|
| RDP keluar | `HKCU\Software\Microsoft\Terminal Server Client\Default` (nilai MRU), subkey `Servers\<host>` (`UsernameHint`); bitmap cache; Prefetch MSTSC.EXE | Host tujuan (FQDN atau IP) dan username yang dipakai |
| PsExec keluar | Prefetch `PSEXEC.EXE`; UserAssist; key `HKU\<SID>\Software\Sysinternals\PsExec\EulaAccepted`; 4648 | Bukti PsExec dijalankan; host tujuan di command line bila 4688/Sysmon 1 ada |
| WMI remote keluar | Prefetch `WMIC.EXE`; 4688/Sysmon 1 dengan `wmic /NODE:` | Host tujuan di command line |
| schtasks jarak jauh keluar | Prefetch `SCHTASKS.EXE`; 4648 menyebut host tujuan dan akun | Host dan akun di 4648 dan command line |
| Share yang di-mount | `HKCU\...\Explorer\MountPoints2`; ShellBags | Path UNC share yang pernah diakses |

Key `Terminal Server Client\Default` menyimpan daftar MRU koneksi RDP keluar: nilai `MRU0` adalah tujuan terakhir, lalu nilai lain bergeser nomornya, dan isinya bisa FQDN atau IP host yang di-RDP dari sini [S12]. Microsoft mendokumentasikan key ini sebagai tempat daftar koneksi yang tidak bisa dibersihkan dari UI [S12]; subkey `Servers\<host>` dengan nilai `UsernameHint` menyimpan username yang dipakai ke host itu, meski detail `Servers` dan `UsernameHint` berasal dari analisis praktisi, bukan dokumentasi Microsoft, jadi buktikan di lab. Bitmap cache RDP (`bcacheNN.bmc` di `AppData\Local\Microsoft\Terminal Server Client\Cache`) dan Prefetch `MSTSC.EXE` melengkapinya [S10].

Event 4648 (logon dengan kredensial eksplisit) ditulis di host tempat proses dijalankan, paling sering untuk konfigurasi batch seperti scheduled task atau perintah `RUNAS`, dan juga saat alat remote memakai kredensial berbeda; field `Target Server Name` memuat nama server tujuan (`localhost` bila lokal), dan `Process Name` memuat proses yang memakai kredensial itu [S8]. Karena itu 4648 di host sumber adalah jejak kuat untuk schtasks dan PsExec jarak jauh yang menyebut akun lain.

### 1.4 Mengenali metode: pola PsExec, WMI, WinRM, RDP, dan task jarak jauh

Pertanyaan keempat Sari ("bisa tidak kita tunjukkan ini PsExec, ini WMI") dijawab dengan mencocokkan kombinasi jejak, bukan satu tanda. Mengenali metode penting karena mengubah rekomendasi deteksi: deteksi untuk service sementara berbeda dari deteksi untuk WMI atau WinRM.

Tabel berikut adalah kartu pembeda: kombinasi yang, bila muncul bersama, menunjuk satu metode. Semua berasal dari dokumentasi primer dan analisis JPCERT [S10][S11].

| Metode | Proses kunci di tujuan | Port | Tanda pembeda utama |
|---|---|---|---|
| PsExec | `PSEXESVC.exe` (atau nama `-r`) | 445 | 7045 service demand start LocalSystem `%SystemRoot%\PSEXESVC.exe`; pipe IPC$ `-stdin/-stdout/-stderr` [S10][S11] |
| WMI remote | `WmiPrvSE.exe` induk `svchost.exe -k DcomLaunch` | 135 lalu high port | Tidak ada service baru; `WmiPrvSE` jalan sebagai NETWORK SERVICE; WMI-Activity 5857/5860 [S10] |
| WinRM / PS remoting | `wsmprovhost.exe` | 5985/5986 | Koneksi HTTP ke 5985/5986; proses anak berinduk `wsmprovhost.exe`; WinRM/Operational 91, 169 [S10][S13][S20] |
| RDP | sesi interaktif (`rdpclip.exe`, `tstheme.exe`) | 3389 | 4624 type 10; 1149 lalu 21; `TSTHEME.EXE`/`RDPCLIP.EXE` Prefetch [S10] |
| schtasks jarak jauh | layanan Task Scheduler lalu executable task | 135 lalu high port | 4624 type 3 lalu 4698/106; tidak ada service PsExec [S10] |

Dua catatan yang membedakan metode mirip:

- **WMI tidak memasang service.** Berbeda dari PsExec, eksekusi WMI jarak jauh tidak membuat 7045; yang muncul adalah `WmiPrvSE.exe` yang dijalankan `svchost.exe -k DcomLaunch` sebagai NETWORK SERVICE, dengan koneksi masuk ke port 135 lalu high port [S10]. Kalau kamu melihat 4624 type 3 tanpa service baru tetapi dengan `WmiPrvSE.exe` muncul pada detik yang sama, itu pola WMI.
- **WinRM memakai port dan proses sendiri.** WinRM 2.0 memakai port default 5985 untuk HTTP dan 5986 untuk HTTPS, dan service WinRM baru start otomatis pada Windows Server 2008 ke atas (di client lama harus distart manual), tanpa listener bawaan sampai dikonfigurasi [S20]. Di sisi deteksi, proses anak yang berinduk `wsmprovhost.exe` bersamaan dengan koneksi masuk ke 5985/5986 adalah pola eksekusi masuk lewat PowerShell remoting [S13].

### 1.5 WMI event subscription: persistence yang tak terlihat di registry dan task

Pertanyaan keempat Sari juga menyinggung "persistence di WMI", dan ini layak subbagian sendiri karena tidak muncul di Run key, service, maupun scheduled task, sehingga sering terlewat.

WMI permanent event consumer adalah konsumen yang menerima event sampai registrasinya dibatalkan [S14]. Ia terdiri dari tiga objek: sebuah filter (`__EventFilter`, berisi query pemicu, misalnya "setiap interval tertentu" atau "saat proses tertentu mulai"), sebuah consumer (instance dari kelas consumer standar, yang menentukan aksi), dan sebuah binding (`__FilterToConsumerBinding`) yang menautkan keduanya [S14]. Saat event cocok, WMI otomatis memuat objek consumer ke memori; biasanya saat startup atau saat event pemicu terjadi [S14]. Kelas consumer standar yang perlu dikenali [S15]: `ActiveScriptEventConsumer` (menjalankan script), `CommandLineEventConsumer` (menjalankan proses dalam konteks local system), `LogFileEventConsumer`, `NTEventLogEventConsumer`, dan `SMTPEventConsumer`. Dua yang pertama adalah yang paling sering dipakai untuk persistence, karena menjalankan kode.

Jejaknya ada di dua tempat, tergantung apakah Sysmon aktif:

- **Dengan Sysmon:** EID 19 mencatat registrasi WMI event filter (namespace, nama filter, ekspresi), EID 20 mencatat registrasi consumer (nama, log, tujuan), dan EID 21 mencatat binding consumer ke filter (nama consumer dan path filter) [S6]. Map EvtxECmd untuk Sysmon 21 memetakan field `Operation`, `Consumer`, dan `Filter` [S18].
- **Tanpa Sysmon:** channel `Microsoft-Windows-WMI-Activity/Operational` mencatat aktivitas WMI. Map EvtxECmd menamai event 5861 "WMI Registration of Permanent Event Consumer" dan 5860 "WMI Registration of Temporary Event Consumer" [S18]. Event 5861 dilaporkan menandakan binding filter ke consumer pada build Windows modern, meski halaman Microsoft resmi untuk 5861 tidak diperoleh; perlakukan ini sebagai indikator yang dikonfirmasi lewat map EvtxECmd dan praktisi, bukan dari spesifikasi primer, dan buktikan isinya di lab [komunitas, belum terkonfirmasi].

Pada image offline (tanpa host hidup), registrasi tersimpan di file repository WMI `C:\Windows\System32\wbem\Repository\OBJECTS.DATA`. Artifact Velociraptor `Windows.Persistence.PermanentWMIEvents` menyusuri binding lalu menautkan filter dan consumer, tetapi memakai plugin `wmi()` yang membaca service WMI di host hidup, dengan namespace default `root/subscription` dan `root/default`, jadi tidak mem-parse file offline [S16]. Untuk file offline, alat yang membaca `OBJECTS.DATA` langsung dipakai, misalnya `wmi-parser` dari woanware, port C# dari WMI_Forensics (PyWMIPersistenceFinder) milik David Pany, yang mencari consumer dan binding dengan keyword lalu mengekspor CSV [S21][S22]. Alat ini mencari FilterToConsumerBinding lewat pencarian keyword, bukan parsing penuh repository, dan penulisnya menyebut deteksi binding yang terhapus di unallocated belum teruji [S22]; verifikasi silang dengan metode kedua bila temuan penting.

### 1.6 Memisahkan jejak responder, dan membuktikan persistence yang dihapus

Pertanyaan kelima Sari ("mana jejak yang dihapus, dan bagaimana membuktikan pernah ada") punya dua sisi: jejak yang sengaja ditinggalkan responder, dan jejak penyerang yang dihapus.

Sisi responder sama dengan Day sebelumnya: live response dan koleksi Sabtu meninggalkan jejak di kedua host (akun admin lokal khusus IR, driver akuisisi memori yang memuat lewat Service Control Manager sehingga menghasilkan 7045 bertipe kernel driver, dan proses koleksi). Dibedakan dari penyerang dengan akun, waktu yang cocok dengan case notes, path media bukti (`E:\`), dan induk proses yang berakar pada sesi responder, bukan pada layanan task atau proses penyerang. Day 07 bagian 1.5 menjelaskan pemisahan ini; prinsipnya dilabeli, bukan dihapus.

Sisi penyerang: penyerang ransomware rutin menghapus jejak sebelum enkripsi, dan persistence sering dihapus setelah dipakai. Tabel berikut memuat cara persistence yang dihapus masih bisa dibuktikan pernah ada; baca kolom "Bukti sisa", karena itu yang dipakai saat registry atau file sudah bersih.

| Dihapus | Bukti sisa |
|---|---|
| Service dihapus dari registry | System 7045 di event log masih mencatat pemasangan; 4697 bila audit aktif |
| Task dihapus | TaskScheduler 141 (task dihapus); 4699 bila audit aktif; 4698 awal menyimpan XML lengkap meski file kemudian hilang [S4] |
| File payload dihapus | USN `$J` FileDelete (Day 08); MFT entry yang dipakai ulang; VSS bila ada (Day 03) |
| WMI binding dihapus | Pencarian `OBJECTS.DATA` di unallocated (belum teruji, [S22]); Sysmon 19-21 di event log bila Sysmon aktif |
| Log Security dibersihkan | 1102 di Security; 104 di System; celah nomor EventRecordID |

Event 4698 menyimpan Task Content XML lengkap pada saat pembuatan, sehingga bila file task kemudian diubah atau dihapus, 4698 masih memegang versi awalnya [S4]. Ini pasangan yang kuat: file task hilang, tetapi 4698 membuktikan task itu pernah ada, lengkap dengan action dan trigger-nya. Tidak adanya 1102 atau 104 bukan bukti log utuh; 104 ada di channel System, bukan di channel yang dibersihkan, dan log bisa berputar penuh tanpa pernah dibersihkan.

### 1.7 Keyakinan, korelasi, dan yang tidak bisa dijawab disk

Pertanyaan terakhir Sari ("seberapa yakin, apa yang tidak bisa dijawab disk") adalah soal menulis temuan dengan jujur. Tiga aturan yang dipakai:

- **Satu artefak jarang cukup.** Persistence dan lateral movement paling meyakinkan saat registry, event, file, dan waktu sepakat. Tulis keyakinan tinggi hanya saat beberapa sumber independen menunjuk kejadian yang sama; tulis keyakinan sedang bila hanya satu sumber dan sebutkan sumber apa yang hilang.
- **Ketiadaan event dimulai dari konfigurasi.** Sebelum menulis "tidak ada RDP masuk", pastikan audit dan channel yang dibutuhkan memang aktif di host itu. Di kasus ini kedua workstation ber-EDR dan audit lengkap, sehingga ketiadaan event bermakna; di host tanpa audit (seperti laptop di Day 05 dan Day 09), ketiadaan hanya berarti tidak tercatat.
- **Disk tidak membuktikan trafik yang tidak menyentuh host.** Logon dan artefak klien membuktikan koneksi yang terekam event atau registry. Untuk trafik yang tidak meninggalkan jejak host (misalnya tunneling lewat port lain), jawabannya ada di log jaringan, firewall, dan proxy, bukan di disk.

Untuk `INC-2026-017`, dua workstation ber-EDR dengan audit lengkap memberi keyakinan tinggi pada rantai lateral masuk dan persistence; sisi sumber (RDP keluar dan share yang di-mount) juga tinggi karena artefak klien lengkap. Yang tetap bergantung pada sumber lain: trafik exfil 6 GB dari `JKT-WS-0457` terbukti dari log proxy dan firewall, bukan dari disk, dan penulisan `.lck` ke `JKT-FS01` terlihat dari event 5145 di file server (host terpisah yang tidak di-image di sini), bukan dari disk workstation.

## 2. Contoh dan langkah praktis di PT JAB

Semua isi bagian ini fiktif dan merupakan keluaran ilustrasi. Perintah dijalankan di workstation analisis forensik internal `JKT-DFIR01` atas salinan kerja image, di-mount read-only. Cocokkan nama field, event ID, path, dan nama service dengan versi alat dan build Windows di lab-mu; angka di keluaran dihitung agar konsisten. Narasi memakai WIB (UTC+7); setiap keluaran alat diberi label zona waktunya, karena EvtxECmd, RECmd, dan PECmd menulis waktu dalam UTC (UTC = WIB dikurangi 7 jam).

Nomor bukti yang dipakai di Day ini (ditetapkan untuk `INC-2026-017`): memori diambil Sabtu 2026-10-10, image disk Senin 2026-10-12 pukul 09:00 sebelum rebuild, lalu rebuild ditunda. `INC-2026-017-E05` adalah image disk `JKT-WS-0457` dan `-E06` image disk `JKT-WS-0441`; salinan kerja internal `E05-W1` dan `E06-W1` dibuat Yoga setelah verifikasi hash master.

### 2.1 Menyiapkan salinan kerja dan mengambil artefak

Langkah ini menyiapkan kedua salinan kerja tanpa menulis ke master. Dilakukan Senin 2026-10-26 pukul 09:10, setelah pesan Sari.

```
# verifikasi hash salinan kerja terhadap master
Get-FileHash -Path E05-W1.vhdx -Algorithm SHA256
Get-FileHash -Path E06-W1.vhdx -Algorithm SHA256
# mount read-only (huruf drive contoh), lalu parse dari drive itu
```

| Langkah | Tujuan |
|---|---|
| Verifikasi hash | Memastikan salinan kerja identik dengan master sebelum analisis |
| Mount read-only | Mencegah perubahan pada salinan kerja; hash tetap pembuktinya |
| Parse ke folder kasus | Semua output ke `\\jkt-evid01\cases\INC-2026-017\analysis\` agar tidak menyentuh salinan kerja |

**Cara membaca hasil:** hash cocok berarti salinan kerja siap dianalisis. Artefak yang diambil dari tiap image: hive registry (SOFTWARE, SYSTEM, dan NTUSER tiap pengguna), event log (`.evtx`), `$MFT` dan `$J`, file di `C:\Windows\System32\Tasks\`, dan repository WMI `C:\Windows\System32\wbem\Repository\`.

**Kapan gagal:** `Mount-DiskImage` di Windows me-mount read-write secara bawaan. Pastikan opsi read-only dipakai, atau mount di VM analisis dengan lapisan read-only; hash sebelum dan sesudah membuktikan tidak ada perubahan.

### 2.2 Autostart registry dengan RECmd

Langkah ini menjawab bagian pertanyaan ketiga Sari untuk persistence di registry. RECmd dengan batch mengumpulkan banyak lokasi autostart sekaligus.

```
RECmd.exe --bn DFIRBatch.reb -d C:\DFIR\work\INC-2026-017\E06-W1\Windows\System32\config ^
  --csv \\jkt-evid01\cases\INC-2026-017\analysis\E06-W1\RECmd\ --csvf E06-W1_registry.csv
```

- `--bn DFIRBatch.reb`: batch (versi 2.22) yang mencakup Run (NTUSER, SYSTEM, Group Policy), RunOnce, Services, Scheduled Tasks (TaskCache), Startup Programs, WinLogon, Terminal Server Client, Sysinternals EULA, dan MountPoints2 [S17].
- `-d ...\config`: folder hive SYSTEM dan SOFTWARE; untuk key NTUSER arahkan ke hive pengguna.
- `--csv` dan `--csvf`: folder output dan nama file.

Keluaran ilustrasi (baris autostart yang menonjol di `JKT-WS-0441`; RECmd menulis last write dalam UTC, jadi 07:24:41 UTC = 14:24:41 WIB):

```
HiveType  Category   Description              KeyPath\ValueName                           Data                                           LastWrite (UTC)
SOFTWARE  Autoruns   Run (SYSTEM)             ...\CurrentVersion\Run\MsEdgeSync            C:\ProgramData\MsEdgeSync\sync.exe             2026-10-08 07:24:41
SOFTWARE  Autoruns   Scheduled Tasks          ...\Schedule\TaskCache\Tasks                \Microsoft\Windows\Servicing\SystemSync       2026-10-08 07:24:55
NTUSER    User Act.  Terminal Server Client   ...\Terminal Server Client\Default\MRU0      10.10.45.57                                    2026-10-08 12:02:10
```

**Cara membaca hasil:** nilai Run `MsEdgeSync` menunjuk ke `C:\ProgramData\MsEdgeSync\sync.exe`, lokasi user-writable dengan nama yang menyamar sebagai komponen Edge; ini kandidat persistence. Last write key memberi perkiraan waktu (Kamis 2026-10-08 14:24:41 WIB), tetapi lemah karena bisa bergeser; perkuat dengan MFT waktu `sync.exe` dibuat dan dengan 4688 pembuatnya (bagian 2.4). Baris `Terminal Server Client\Default\MRU0` = `10.10.45.57` adalah jejak sumber, bukan persistence: `JKT-WS-0441` pernah mem-RDP ke `JKT-WS-0457` (bagian 2.7).

**Kapan gagal:** nilai Run yang menunjuk `Userinit` atau `Shell` di Winlogon dengan nilai standar bukan temuan; hanya nilai nonstandar yang diperiksa. Bandingkan dengan nilai default yang diketahui.

### 2.3 Service persistence: 7045 dan registry

Langkah ini memeriksa service di `JKT-WS-0457`, host encryptor, dari dua sisi: event log (kapan dipasang) dan registry (konfigurasi lengkap).

```
EvtxECmd.exe -f ...\System.evtx --csv ...\E05-W1\EventLogs\ --csvf E05-W1_System.csv --maps ...\Maps
```

Keluaran ilustrasi (7045 dari channel System, map `System_Service-Control-Manager_7045`; waktu UTC, tambah 7 jam untuk WIB) [S18]:

```
TimeCreated (UTC)     EventId  ServiceName   ImagePath                                StartType    AccountName
2026-10-08 12:11:30    7045    WinHlpSvc      C:\ProgramData\WinHlpSvc\hlpsvc.exe       Auto start   LocalSystem
2026-10-10 05:42:08    7045    pmem           C:\Windows\winpmem.sys                    Demand       LocalSystem
```

- Baris pertama: service `WinHlpSvc` dengan `ImagePath` di `C:\ProgramData` (di luar `%windir%` dan Program Files), start otomatis, dipasang Kamis 2026-10-08 12:11:30 UTC (19:11:30 WIB). Ini pola persistence yang disarankan Microsoft untuk diwaspadai (file di luar folder sistem, start Boot/System atau Auto) [S9].
- Baris kedua: service `pmem` dengan `ImagePath` `.sys`, Demand start, dipasang Sabtu 2026-10-10 05:42:08 UTC (12:42:08 WIB), cocok dengan jendela akuisisi memori responder. Ini driver WinPmem, bukan penyerang; nama service bergantung versi alat, jadi dicocokkan dengan toolkit IR, bukan ditebak.

Dari registry (`ControlSet001\Services\WinHlpSvc`) dibaca `ImagePath`, `Start`, `Type`, dan `ObjectName`. Event 7045 tidak memuat akun pemasang [S9]; karena audit aktif, pasangkan dengan 4697 dan dengan 4688 pada detik yang sama untuk menemukan proses pembuatnya.

**Cara membaca hasil:** `WinHlpSvc` adalah persistence service penyerang. Waktu pemasangan Kamis 19:11:30 WIB jatuh sembilan menit setelah RDP masuk dari `JKT-WS-0441` pukul 19:02 WIB (bagian 2.6), di dalam sesi RDP itu, sehingga pemasangan tertaut ke sesi lateral. `pmem` adalah jejak responder.

**Kapan gagal:** service yang dihapus penyerang tidak ada lagi di registry, tetapi 7045 di System masih ada. Bila 7045 juga hilang karena log berputar, cek VSS dan koleksi triage yang lebih awal.

### 2.4 Scheduled task: file XML, 106, dan 4698

Langkah ini memeriksa task di `JKT-WS-0441`, memakai tiga sumber yang saling menguatkan.

```
# file XML task (dibaca dari salinan kerja)
type ...\E06-W1\Windows\System32\Tasks\Microsoft\Windows\Servicing\SystemSync
# event
EvtxECmd.exe -f ...\Microsoft-Windows-TaskScheduler%4Operational.evtx --csv ... --maps ...
EvtxECmd.exe -f ...\Security.evtx --csv ... --maps ...
```

Keluaran ilustrasi (gabungan file XML, TaskScheduler 106, dan Security 4698). Tanggal `RegistrationInfo` di XML task ditulis dalam waktu lokal host (WIB), sedangkan CSV EvtxECmd dalam UTC:

```
File XML \Microsoft\Windows\Servicing\SystemSync:
  RegistrationInfo Date : 2026-10-08T14:24:55 (lokal, WIB)
  Author                : JKT-WS-0441\Administrator
  Action Command        : C:\ProgramData\MsEdgeSync\sync.exe
  Trigger               : interval PT30M + LogonTrigger
  Principal UserId      : S-1-5-18 (SYSTEM)
TaskScheduler 106 (UTC) : 2026-10-08 07:24:55  task registered, user JKT-WS-0441\Administrator
Security 4698 (UTC)     : 2026-10-08 07:24:55  TaskName \Microsoft\Windows\Servicing\SystemSync
  SubjectUserName       : Administrator (lokal)  SubjectLogonId 0x2E55A1
  ClientProcessId       : 4820
  ParentProcessId       : 4312
```

**Cara membaca hasil:** task `\Microsoft\Windows\Servicing\SystemSync` menyamar di path yang terlihat resmi, menjalankan `sync.exe` yang sama dengan Run key (bagian 2.2), setiap 30 menit dan saat logon. Event 4698 memuat `ClientProcessId` 4820 dan `ParentProcessId` 4312 (field ini ada sejak Windows 10 1903) [S4], yang menautkan pembuatan task ke proses tertentu; telusuri PID 4820 di 4688 atau Sysmon 1 untuk tahu proses apa dan induknya. Akun pembuatnya local Administrator dengan `SubjectLogonId` `0x2E55A1`, Logon ID yang sama dengan logon jaringan PsExec pukul 12:08:14 WIB (bagian 2.6): task dibuat dari dalam sesi PsExec yang masih terbuka, dan pada 4688 PID 4312 adalah `PSEXESVC.exe` yang menjadi induk `cmd.exe` PID 4820. Waktu FN file XML (Day 08) mengonfirmasi Kamis 07:24:55 UTC (14:24:55 WIB) dan sulit dipalsukan. Tiga sumber sepakat, jadi keyakinan tinggi.

**Variasi:** task yang dibuat lewat COM atau API (tanpa menjalankan `schtasks.exe`) tidak meninggalkan command line `schtasks` di 4688, tetapi tetap menghasilkan file XML di `Tasks\`, 106, dan 4698; jangan simpulkan "bukan task" hanya karena tidak ada `schtasks.exe` di artefak eksekusi.

**Kapan gagal:** di host tanpa GPO audit (seperti laptop di Day 05 dan Day 09), 4698 tidak ada dan channel TaskScheduler bisa mati; andalkan file XML dan `TaskCache` di registry.

### 2.5 WMI event subscription: Sysmon dan repository offline

Langkah ini menjawab bagian pertanyaan keempat Sari tentang persistence di WMI, memeriksa dua sumber: Sysmon (karena kedua host ber-Sysmon) dan repository offline.

```
# dari Sysmon (bila aktif)
EvtxECmd.exe -f ...\Microsoft-Windows-Sysmon%4Operational.evtx --csv ... --maps ...
# dari repository offline pada salinan kerja
wmi-parser.exe -i ...\E05-W1\Windows\System32\wbem\Repository\OBJECTS.DATA
```

Keluaran ilustrasi (Sysmon 19/20/21 di `JKT-WS-0457`, semua 2026-10-08 sekitar 12:11 UTC atau 19:11 WIB) [S6][S18]:

```
EventId 19 (WmiEventFilter)   : Name "HlpFilter"  Query "SELECT * FROM __InstanceModificationEvent WITHIN 300 WHERE ..."
EventId 20 (WmiEventConsumer) : Name "HlpConsumer"  Type CommandLineEventConsumer  Executable C:\ProgramData\WinHlpSvc\hlpsvc.exe
EventId 21 (ConsumerToFilter) : Consumer "...HlpConsumer"  Filter "...HlpFilter"
```

Keluaran ilustrasi (`wmi-parser` atas `OBJECTS.DATA`) [S21][S22]:

```
Consumer : CommandLineEventConsumer  Name=HlpConsumer  Arguments=C:\ProgramData\WinHlpSvc\hlpsvc.exe
Filter   : HlpFilter  Query=SELECT * FROM __InstanceModificationEvent WITHIN 300 WHERE ...
Binding  : HlpConsumer <-> HlpFilter
```

**Cara membaca hasil:** ketiga objek (filter, consumer, binding) membentuk satu subscription yang menjalankan `hlpsvc.exe`, payload yang sama dengan service `WinHlpSvc` (bagian 2.3), lewat `CommandLineEventConsumer` dalam konteks local system [S15]. Ini jalur kedua untuk payload yang sama di host ini: penyerang memasang dua jalur (service dan WMI) agar satu yang terlewat tetap menghidupkan payload. Pola yang sama terlihat di `JKT-WS-0441` dengan pasangan Run key dan task. Sysmon 21 memetakan `Consumer` dan `Filter` [S18]; repository offline mengonfirmasinya tanpa host hidup. Dua sumber sepakat, jadi temuan WMI kuat meski WMI tidak muncul di Run key atau Tasks.

**Kapan gagal:** `wmi-parser` mencari dengan keyword, bukan parsing penuh, dan deteksi binding terhapus di unallocated belum teruji [S22]; untuk binding yang dicurigai dihapus, verifikasi silang dengan alat kedua dan dengan Sysmon 19-21 di event log.

### 2.6 Lateral movement masuk: host sebagai tujuan

Langkah ini menjawab pertanyaan pertama Sari, menyusun logon masuk di tiap host dan menautkannya ke aktivitas yang mengikuti.

Keluaran ilustrasi untuk `JKT-WS-0441` (host internal pertama), dari Security dan System (waktu UTC; 05:08:14 UTC = 12:08:14 WIB):

```
2026-10-08 05:08:14  4624 type3  AccountName=Administrator  Source=10.20.9.20  LogonId=0x2E55A1  AuthPkg=NTLM
2026-10-08 05:08:14  4672        Special privileges  LogonId=0x2E55A1
2026-10-08 05:08:15  5145        Share=IPC$  Object=PSEXESVC-JKT-DMZ-APP01-...-stdin  SID S-1-5-21-...-Administrator
2026-10-08 05:08:16  7045        ServiceName=PSEXESVC  ImagePath=C:\Windows\PSEXESVC.exe  Demand  LocalSystem
```

**Cara membaca hasil:** rangkaian ini adalah PsExec masuk dari `jkt-dmz-app01` (`10.20.9.20`) memakai local admin yang dipakai ulang: 4624 type 3 dengan NTLM dari IP sumber, 4672, 5145 ke pipe IPC$ `PSEXESVC-...-stdin`, lalu 7045 service `PSEXESVC` [S10]. IP sumber `10.20.9.20` adalah server akses awal, jadi `JKT-WS-0441` adalah foothold internal pertama. Sekitar dua jam kemudian, pukul 14:24 WIB, Run key dan task dibuat dari dalam sesi dengan Logon ID `0x2E55A1` yang sama (bagian 2.2 dan 2.4).

Keluaran ilustrasi untuk `JKT-WS-0457` (host encryptor), dari RemoteConnectionManager, LocalSessionManager, dan Security (waktu UTC; 12:02 UTC = 19:02 WIB):

```
2026-10-08 12:02:11  RemoteConnectionManager 1149  User=JAB\budi.santoso  Source=10.10.44.41
2026-10-08 12:02:12  4624 type10  AccountName=budi.santoso  Source=10.10.44.41  LogonId=0x7A3C40
2026-10-08 12:02:12  LocalSessionManager 21  Session logon succeeded  Source=10.10.44.41
```

**Cara membaca hasil:** `JKT-WS-0457` dimasuki lewat RDP (type 10) dari `JKT-WS-0441` (`10.10.44.41`) pukul 19:02 WIB dengan akun domain `budi.santoso`, bukan dari server DMZ. Kredensial `budi.santoso` kemungkinan didapat dari dump kredensial sebelumnya; cara mendapatkannya tidak terlihat di disk kedua host ini. Jadi jalur lateralnya bertingkat: `jkt-dmz-app01` lalu `JKT-WS-0441` lalu `JKT-WS-0457`. Event 1149 lalu 4624 type 10 lalu LSM 21 membuktikan RDP berhasil [S7][S18].

**Kapan gagal:** audit File Share (5140/5145) bising dan sering mati; tanpa itu, akses ADMIN$ dan IPC$ tidak tercatat, dan pola PsExec harus disimpulkan dari 7045 plus file `PSEXESVC.exe` di `C:\Windows` saja. Di kedua host ini audit aktif, jadi 5145 tersedia.

### 2.7 Lateral movement keluar: host sebagai sumber

Langkah ini menjawab pertanyaan kedua Sari, memeriksa artefak klien untuk tujuan keluar.

Keluaran ilustrasi untuk `JKT-WS-0441` sebagai sumber (RECmd dan PECmd; waktu UTC):

```
NTUSER Terminal Server Client\Default\MRU0  : 10.10.45.57
NTUSER Terminal Server Client\Servers\10.10.45.57\UsernameHint : JAB\budi.santoso
AppData\Local\Microsoft\Terminal Server Client\Cache\bcache24.bmc : ada
Prefetch MSTSC.EXE-<RANDOM>.pf  LastRun 2026-10-08 12:02:08
```

**Cara membaca hasil:** `JKT-WS-0441` dipakai untuk RDP keluar ke `10.10.45.57` (`JKT-WS-0457`) dengan akun `budi.santoso`; MRU, `UsernameHint`, bitmap cache, dan Prefetch `MSTSC.EXE` sepakat pada waktu yang sama (19:02 WIB) dengan 1149/4624 type 10 di host tujuan (bagian 2.6) [S10][S12]. `UsernameHint` berasal dari analisis praktisi, jadi diperlakukan sebagai pendukung, bukan bukti utama.

Keluaran ilustrasi untuk `JKT-WS-0457` sebagai sumber (MountPoints2 dan ShellBags; waktu UTC):

```
NTUSER Explorer\MountPoints2\##JKT-FS01#Keuangan : ada
ShellBags : \\JKT-FS01\Keuangan  (terakhir diakses 2026-10-09 14:30 UTC = 21:30 WIB)
```

**Cara membaca hasil:** `JKT-WS-0457` memetakan share `\\JKT-FS01\Keuangan`, target enkripsi. Penulisan `.lck` ke share itu terlihat dari event 5145 di `JKT-FS01` (host terpisah, tidak di-image di sini) yang mencatat sumber `10.10.45.57`, bukan dari disk `JKT-WS-0457`. Inilah batas disk (bagian 1.7): disk workstation menunjukkan share pernah diakses, log file server menunjukkan file apa yang ditulis dari mana.

**Kapan gagal:** MRU RDP dan MountPoints2 di NTUSER bisa dibersihkan penyerang; ketiadaannya bukan bukti tidak ada koneksi keluar. Korelasi dengan 4648, Prefetch, dan log jaringan.

### 2.8 Tabel korelasi dan jawaban untuk Sari

Tabel berikut menyatukan temuan dua host untuk PIR. Baca kolom "Keyakinan dan sumber", karena itu yang membedakan temuan kuat dari dugaan.

| Temuan | Host | Waktu (WIB) | Keyakinan dan sumber |
|---|---|---|---|
| Masuk PsExec dari `jkt-dmz-app01` | `JKT-WS-0441` | 2026-10-08 12:08 | Tinggi: 4624 type3 + 5145 IPC$ pipe + 7045 PSEXESVC |
| Persistence Run key + task (`sync.exe`) | `JKT-WS-0441` | 2026-10-08 14:24 | Tinggi: Run + file XML + 106 + 4698 + MFT FN |
| RDP keluar ke `JKT-WS-0457` | `JKT-WS-0441` | 2026-10-08 19:02 | Tinggi: MRU + bitmap cache + MSTSC Prefetch |
| Masuk RDP dari `JKT-WS-0441` | `JKT-WS-0457` | 2026-10-08 19:02 | Tinggi: 1149 + 4624 type10 + LSM 21 |
| Persistence service + WMI subscription (`hlpsvc.exe`) | `JKT-WS-0457` | 2026-10-08 19:11 | Tinggi: 7045 + registry Services + Sysmon 19-21 + OBJECTS.DATA |
| Share `\\JKT-FS01\Keuangan` di-mount | `JKT-WS-0457` | 2026-10-09 21:30 | Sedang di disk; penulisan `.lck` dari 5145 di `JKT-FS01` |

Jawaban tertulis yang dikirim ke Sari untuk PIR:

```
INC-2026-017 | Temuan forensik host (persistence dan lateral) | Senin 2026-10-26 untuk PIR
Dari: <kamu> (L2 forensik) | Untuk: Sari Kusuma (TL), via PIR Nina Kartika
Sumber bukti: E05-W1 (JKT-WS-0457), E06-W1 (JKT-WS-0441). Semua waktu WIB (UTC+7).

JALUR LATERAL (bertingkat):
- jkt-dmz-app01 (10.20.9.20) -> JKT-WS-0441 (10.10.44.41): PsExec, local admin dipakai ulang, Kamis 2026-10-08 12:08.
- JKT-WS-0441 -> JKT-WS-0457 (10.10.45.57): RDP akun budi.santoso, Kamis 2026-10-08 19:02.
- JKT-WS-0457 -> JKT-FS01: SMB ke share Keuangan (bukti di 5145 JKT-FS01, bukan di disk).

PERSISTENCE:
- JKT-WS-0441: Run key MsEdgeSync + task \Microsoft\Windows\Servicing\SystemSync, keduanya sync.exe
  di C:\ProgramData\MsEdgeSync\, dibuat Kamis 2026-10-08 14:24 dari dalam sesi PsExec
  (file XML + 106 + 4698 sepakat, Logon ID sama dengan logon PsExec 12:08).
- JKT-WS-0457: service WinHlpSvc (7045, Kamis 19:11:30, sembilan menit setelah RDP masuk) + WMI
  subscription HlpFilter/HlpConsumer (Sysmon 19-21 + OBJECTS.DATA), keduanya hlpsvc.exe.
- Pola: dua jalur per host untuk satu payload per host.
- Startup folder dicek di kedua host: tidak ada temuan.

KEYAKINAN DAN BATAS:
- Lateral masuk dan persistence: keyakinan tinggi (dua host ber-EDR, audit lengkap).
- Exfil 6 GB dan penulisan .lck: dari log proxy/firewall dan 5145 JKT-FS01, bukan dari disk workstation.
- Jejak responder (akun IR, service pmem driver WinPmem) dipisahkan, tidak dihitung sebagai penyerang.
```

**Kapan gagal:** menuliskan "empat mekanisme persistence" tanpa menegaskan pasangannya menjalankan payload yang sama akan membuat PIR menghitung empat ancaman berbeda; sebutkan bahwa Run key dan task di `JKT-WS-0441` menunjuk `sync.exe`, sedangkan service dan WMI di `JKT-WS-0457` menunjuk `hlpsvc.exe`.

## 3. Lab praktik (di VM lab terisolasi)

**Prasyarat:** dua VM Windows lab dengan Sysmon dan audit lengkap (satu "sumber", satu "tujuan"), VM analisis forensik, snapshot bersih. Semua aktivitas lab jinak memakai fitur administrasi biasa; tidak ada sampel liar. Folder kasus lab `CASE-2026-LAB-011`.

1. **Pasang persistence jinak di VM tujuan.** Buat Run key, satu scheduled task, satu service, dan satu WMI event subscription yang semuanya menjalankan program jinak (misalnya `notepad.exe` atau skrip yang menulis timestamp ke file). Catat waktu tiap pembuatan.
2. **Simulasi lateral jinak.** Dari VM sumber, lakukan RDP ke VM tujuan dengan akun lab dan buka Notepad; lalu jalankan satu perintah informasi sederhana (misalnya `hostname`) ke VM tujuan memakai PsExec dari Sysinternals, sebagai admin biasa. Catat waktu dan arah.
3. **Kumpulkan artefak.** Dari snapshot VM tujuan, ambil hive registry, event log, `$MFT`, `$J`, folder `Tasks\`, dan `OBJECTS.DATA`. Dari VM sumber, ambil NTUSER dan Prefetch.
4. **Temukan persistence.** Parse dengan RECmd (Run, Services, TaskCache, Startup, WinLogon), EvtxECmd (7045, 106, 4698, Sysmon 19-21), dan alat `OBJECTS.DATA`. Untuk tiap mekanisme, tentukan kapan dibuat dan oleh proses apa (bagian 2.2 sampai 2.5).
5. **Rekonstruksi lateral masuk di VM tujuan.** Temukan RDP masuk (1149 + 4624 type 10 + LSM 21) dan PsExec (7045 PSEXESVC + 5145 pipe + file `C:\Windows\PSEXESVC.exe`). Tentukan IP sumber (bagian 2.6).
6. **Cek lateral keluar di VM sumber.** Periksa `Terminal Server Client\Default` MRU, `UsernameHint`, bitmap cache, Prefetch `MSTSC.EXE` dan `PSEXEC.EXE`, dan key EULA Sysinternals (bagian 2.7).
7. **Buktikan yang dihapus.** Hapus satu persistence (service atau task) dan file payload-nya di VM tujuan, lalu kumpulkan ulang. Buktikan jejaknya masih ada: 7045 atau 141 di event log, 4698 yang menyimpan XML awal, USN FileDelete, atau Sysmon 19-21 (bagian 1.6).
8. **Timeline dan laporan.** Susun timeline lintas artefak dan tabel korelasi (bagian 2.8), lalu tulis jawaban PIR singkat dengan kolom keyakinan.

**Hasil yang sebaiknya tersimpan:**

- Empat mekanisme persistence ditemukan, masing-masing dengan waktu dan proses pembuat.
- Lateral masuk (RDP dan PsExec) direkonstruksi dengan IP sumber.
- Lateral keluar diperiksa di artefak klien VM sumber.
- Minimal satu persistence dihapus lalu dibuktikan pernah ada dari kombinasi artefak.
- Tabel korelasi dengan kolom keyakinan tersimpan sebagai laporan.

**Variasi tantangan:** buat WMI event subscription dengan `CommandLineEventConsumer`, lalu buktikan keberadaannya dari dua sumber independen (Sysmon 19-21 dan `OBJECTS.DATA` offline). Tulis kalimat yang bisa dipakai di laporan untuk menyatakan temuan WMI beserta batasnya.

## 4. Troubleshooting

Tabel ini memuat masalah yang sering muncul saat memburu persistence dan lateral movement. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Persistence registry tanpa waktu dan pembuat | Audit registry tidak aktif | Pakai last write key (lemah), MFT file payload, dan 7045/106/4698 |
| Task tidak ada di 4698 | Audit Other Object Access mati, atau task dibuat via COM | Baca file XML di `Tasks\` dan TaskCache di registry; 106 bila channel aktif |
| 7045 ada, tetapi service tidak di registry | Service dihapus setelah dipakai | 7045 di System cukup untuk pemasangan; cek USN dan VSS untuk file |
| RDP masuk tidak lengkap | Event tersebar di tiga channel | Padukan 1149/261, 4624 type 10, LSM 21/25, 4778 |
| WMI subscription tak terlihat di registry/task | Memang tidak ada di sana | Cek Sysmon 19-21 dan parse `OBJECTS.DATA` offline |
| Tidak ada jejak lateral keluar | Host bukan sumber, atau artefak klien dibersihkan | Cek MRU RDP, MountPoints2, Prefetch, 4648; korelasi log jaringan |
| Service WinPmem atau driver IR disangka penyerang | Jejak responder | Cocokkan nama service dan waktu dengan toolkit IR dan case notes |

## 5. Kesalahan umum dan jebakan

- **Mengandalkan satu artefak.** Korelasikan registry, event, file, repository WMI, dan waktu; satu Run key atau satu 4624 jarang cukup.
- **Memeriksa satu lokasi persistence saja.** Penyerang sering memasang lebih dari satu jalur untuk payload yang sama (di kasus ini Run key dan task di `JKT-WS-0441`, service dan WMI subscription di `JKT-WS-0457`). Periksa semua lokasi secara sistematis.
- **Mengira ketiadaan event berarti tidak ada kejadian.** Bisa audit mati, channel mati, atau log dibersihkan; mulai dari konfigurasi audit host itu.
- **Tidak membedakan host sumber dan tujuan.** Artefak klien (MRU RDP) menandakan sumber, logon masuk (4624 type 10) menandakan tujuan; arah menentukan cerita.
- **Menyimpulkan metode dari satu tanda.** 7045 saja belum tentu PsExec; WMI tidak membuat service sama sekali. Cocokkan kombinasi (bagian 1.4).
- **Menyalin nilai kredensial** yang muncul di command line alat lateral atau di task `LogonType Password`. Catat keberadaannya, jangan salin nilainya ke laporan [S4].
- **Mengabaikan WMI.** Subscription tidak muncul di Run key atau Tasks; tanpa Sysmon atau parsing `OBJECTS.DATA`, persistence ini terlewat [S14][S22].

## 6. Catatan terkini

Bagian ini menampung detail versi dan sumber yang bisa berubah; tidak mengubah alur analisis di atas.

- **EZ Tools 2026.5.0** (RECmd, EvtxECmd, PECmd, MFTECmd, Registry Explorer, Timeline Explorer) tersedia dalam build .NET 4 (4.7.2) dan .NET 9; Registry Explorer dan Timeline Explorer hanya .NET 9 [S3]. Nama kolom CSV dan isi map bisa berubah antar versi; cocokkan dengan versi lab.
- **Sysmon** publikasi 2026-09-10 mencatat WMI lewat EID 19 (filter), 20 (consumer), dan 21 (consumer ke filter); EID 12/13 untuk registry; EID 17/18 untuk named pipe [S6]. EID 3 (network) mati bawaan dan harus dikonfigurasi.
- **Velociraptor 0.77.3** memperbaiki beberapa CVE; artifact `Windows.Persistence.PermanentWMIEvents` memakai plugin `wmi()` yang membaca host hidup, bukan file offline, dengan namespace default `root/subscription` dan `root/default` [S16].
- **WMI-Activity/Operational 5861** dipetakan EvtxECmd sebagai registrasi permanent event consumer [S18]; halaman Microsoft resmi untuk event ini tidak diperoleh saat riset, jadi isinya dibuktikan di lab. Tracing WMI yang lebih dalam (channel Trace) mati bawaan dan diaktifkan dengan `wevtutil.exe sl Microsoft-Windows-WMI-Activity/Trace /e:true` [S23].
- **PsExec** (dokumentasi 2023-04-11) berjalan di Windows 8.1 ke atas dan Windows Server 2012 ke atas; opsi `-r` mengganti nama service, dan password dan perintah dienkripsi saat dikirim ke host tujuan [S11].

## 7. Cheat sheet

```
PERSISTENCE  Run/RunOnce (HKLM/HKCU, 4 key) | Service (SYSTEM + 7045 + 4697) | Task (file Tasks + 106 + 4698 + TaskCache)
             Startup folder (MFT) | WMI subscription (Sysmon 19/20/21 + OBJECTS.DATA) | Winlogon
KAPAN/SIAPA  service: 7045 | task: FN file XML + 106 + 4698(ClientProcessId) | Run: last write key (lemah) + MFT payload
             pembuat: 4688/Sysmon 1 detik sama; 7045 tanpa akun -> pasangkan 4697
LATERAL IN   SMB/PsExec/WMI/WinRM -> 4624 type3 | RDP -> type10 + 1149/261 + LSM 21/25 + 4778
             PsExec: 7045 PSEXESVC + 5145 pipe stdin/stdout/stderr + C:\Windows\PSEXESVC.exe
             WMI: WmiPrvSE induk svchost -k DcomLaunch, port 135, TANPA service baru
             WinRM: wsmprovhost.exe, port 5985/5986
LATERAL OUT  RDP: NTUSER Terminal Server Client\Default MRU0 + Servers\<host>\UsernameHint + bcacheNN.bmc + MSTSC.pf
             tool: Prefetch PSEXEC/WMIC/SCHTASKS + 4648 (TargetServerName) + MountPoints2
METODE       cocokkan KOMBINASI, bukan 1 tanda: service+pipe=PsExec | WmiPrvSE tanpa service=WMI | 5985/6=WinRM
HILANG       service/task dihapus -> 7045/141 + 4698(XML awal) + USN FileDelete + VSS | log -> 1102/104 + celah EventRecordID
KORELASI     registry + event + file + OBJECTS.DATA + waktu + Logon ID ; 1 artefak jarang cukup
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "Di `JKT-WS-0457` tidak ada event 7045 untuk nama service yang mencurigakan, jadi tidak ada eksekusi jarak jauh di host ini." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Tidak semua eksekusi jarak jauh memasang service. WMI remote tidak membuat 7045; yang muncul adalah `WmiPrvSE.exe` berinduk `svchost.exe -k DcomLaunch` dengan koneksi masuk ke port 135. WinRM memakai `wsmprovhost.exe` dan port 5985/5986. RDP memakai logon type 10 tanpa service. Ketiadaan 7045 hanya menyingkirkan pola PsExec, bukan semua lateral movement. Lihat bagian 1.2 dan 1.4.

</details>

**2. Skenario keputusan.** Kamu menemukan Run key yang menunjuk `C:\ProgramData\MsEdgeSync\sync.exe` di `JKT-WS-0441`. Last write key-nya Kamis 2026-10-08 14:24 WIB. Langkah mana yang paling tepat untuk menegaskan kapan dan oleh apa persistence ini dibuat?

- A. Pakai last write time key sebagai waktu pembuatan, karena itu waktu paling akurat untuk Run key.
- B. Korelasikan dengan waktu FN file `sync.exe` di MFT dan dengan 4688 atau Sysmon 1 pada detik yang sama, lalu lihat apakah task dengan payload sama juga dibuat saat itu.
- C. Abaikan waktunya, karena Run key tidak pernah bisa diberi waktu.

<details><summary>Jawaban</summary>

B. Last write time key bergeser bila nilai lain di key yang sama berubah, sehingga perkiraannya lemah; perkuat dengan MFT waktu file payload dibuat dan dengan proses pembuat di 4688 atau Sysmon 1. A keliru karena memperlakukan last write sebagai waktu pasti pembuatan nilai itu. C keliru karena waktu tetap bisa diperkirakan dari artefak pendukung. Lihat bagian 1.1 dan 2.2.

</details>

**3. Pertanyaan jebakan.** "Nilai `10.10.45.57` di `Terminal Server Client\Default\MRU0` pada `JKT-WS-0441` membuktikan ada RDP masuk ke `JKT-WS-0441` dari `10.10.45.57`." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Key `Terminal Server Client\Default` adalah artefak klien: ia menyimpan tujuan RDP keluar dari host ini, bukan sumber RDP masuk. Jadi nilai itu berarti `JKT-WS-0441` mem-RDP ke `10.10.45.57` (`JKT-WS-0457`), menjadikannya host sumber ke arah itu. RDP masuk dibuktikan dari 4624 type 10, 1149, dan LocalSessionManager 21 di host tujuan. Lihat bagian 1.3 dan 2.7.

</details>

**4. Skenario keputusan.** Penyerang menghapus service persistence dan file payload-nya di VM tujuan sebelum enkripsi. Kombinasi mana yang paling kuat untuk membuktikan service itu pernah ada?

- A. Hanya registry `ControlSet001\Services`, karena di situ service terdaftar.
- B. System 7045 (dan 4697 bila audit aktif) untuk pemasangan, ditambah USN `$J` FileDelete dan MFT untuk file payload, dan VSS bila ada.
- C. Tidak ada cara; service yang dihapus hilang sepenuhnya.

<details><summary>Jawaban</summary>

B. Registry sudah bersih karena service dihapus, jadi A gagal. System 7045 di event log masih mencatat pemasangan meski registry bersih, 4697 menambah akun pemasang bila audit aktif, dan USN FileDelete serta MFT membuktikan file payload pernah ada lalu dihapus; VSS kadang memulihkan keduanya. C keliru karena jejak di event log, USN, dan VSS justru dirancang bertahan lebih lama dari registry live. Lihat bagian 1.6 dan 4.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Sari, dalam tiga kalimat, kenapa menemukan dua mekanisme persistence (service `WinHlpSvc` dan WMI subscription) di `JKT-WS-0457` tidak berarti ada dua ancaman berbeda.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Service `WinHlpSvc` dan WMI subscription `HlpConsumer` sama-sama menjalankan `C:\ProgramData\WinHlpSvc\hlpsvc.exe`, jadi ini satu payload dengan dua jalur untuk bertahan hidup, bukan dua malware. Penyerang memasang lebih dari satu jalur supaya kalau satu dibersihkan, yang lain tetap menghidupkan payload; pola yang sama ada di `JKT-WS-0441` dengan Run key dan task untuk `sync.exe`. Untuk eradication, kedua jalur harus dihapus bersama file-nya, dan kita verifikasi ulang host benar bersih sebelum rebuild dianggap selesai."

Kesalahan yang sering muncul:
- Menghitung tiap mekanisme sebagai ancaman terpisah di laporan PIR.
- Tidak menyebut bahwa payload-nya satu file yang sama.
- Lupa bahwa membersihkan satu jalur saja menyisakan yang lain.

</details>

**6. Pertanyaan jebakan.** "Disk `JKT-WS-0457` tidak menunjukkan file apa yang ditulis ke `JKT-FS01`, jadi kita tidak bisa membuktikan host ini yang mengenkripsi share `Keuangan`." Benarkah?

<details><summary>Jawaban</summary>

Tidak sepenuhnya. Benar bahwa disk workstation tidak mencatat isi yang ditulis ke share di host lain; itu batas disk. Tetapi penulisan massal `.lck` ke `\\JKT-FS01\Keuangan` dari sumber `10.10.45.57` terbukti dari event 5145 di file server `JKT-FS01`, dan disk `JKT-WS-0457` menunjukkan share itu di-mount (MountPoints2 dan ShellBags). Dua sumber dari host berbeda yang sepakat memberi keyakinan tinggi, meski bukti kuncinya ada di file server, bukan di disk workstation. Lihat bagian 1.7 dan 2.7.

</details>

**7. Interview question (English).** "An attacker moved laterally to a workstation. Walk me through how you'd tell whether they used PsExec, WMI, WinRM, or RDP, from host artifacts alone."

<details><summary>Sample answer</summary>

"I match combinations of artifacts, not single signs, because each method leaves a distinct footprint on the destination. PsExec installs a temporary service, so I look for a 7045 for PSEXESVC or a renamed service pointing to C:\Windows, plus 5145 access to the IPC$ named pipes ending in stdin, stdout, and stderr. WMI installs no service at all, so I look for WmiPrvSE.exe spawned by svchost -k DcomLaunch with an inbound connection on port 135. WinRM uses wsmprovhost.exe with inbound traffic on 5985 or 5986, and child processes parented to it. RDP is a type 10 logon with a 1149 then a LocalSessionManager 21, and client-side it leaves the Terminal Server Client MRU and a bitmap cache on the source host. For all of them I confirm the direction with logon type and source address, and I always check whether auditing was even enabled before I call something absent."

What makes this answer strong: it ties each method to a specific, verifiable combination, distinguishes service-based from serviceless techniques, separates source from destination, and ends by checking audit coverage before treating an absence as evidence.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Microsoft Learn: Run and RunOnce Registry Keys | https://learn.microsoft.com/en-us/windows/win32/setupapi/run-and-runonce-registry-keys | primer | ms.date 2024-07-19; diakses 2026-10-16 | Tinggi. Empat key Run/RunOnce, perilaku RunOnce (hapus sebelum jalan, prefiks `!` dan `*`), batas 260 karakter, urutan tak tentu |
| S2 | MITRE ATT&CK: T1547.001 Registry Run Keys / Startup Folder | https://attack.mitre.org/techniques/T1547/001/ | primer | versi 2.1, dimodifikasi 2026-05-12; diakses 2026-10-16 | Tinggi. Path Run/RunOnce lengkap dan path Startup folder per pengguna dan semua pengguna |
| S3 | Eric Zimmerman tools (EZ Tools) | https://ericzimmerman.github.io/ | primer | diakses 2026-10-16 | Tinggi. Versi 2026.5.0 RECmd, EvtxECmd, PECmd, MFTECmd, Registry Explorer, Timeline Explorer; .NET 4.7.2 dan .NET 9 |
| S4 | Microsoft Learn: 4698(S) A scheduled task was created | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4698 | primer | ms.date 2021-09-07; diakses 2026-10-16 | Tinggi. Task Content XML, field 1903 (ClientProcessId, ParentProcessId), saran task di root dan LogonType Password |
| S5 | MITRE ATT&CK: T1546.003, T1543.003, T1053.005, T1021, T1569.002 | https://attack.mitre.org/techniques/T1546/003/ | primer | diakses 2026-10-16 | Tinggi. Definisi teknik persistence dan lateral movement |
| S6 | Microsoft Learn: Sysmon | https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon | primer | publikasi 2026-09-10; diakses 2026-10-16 | Tinggi. EID 12/13 registry, 17/18 pipe, 19/20/21 WMI; EID 3 mati bawaan |
| S7 | Microsoft Learn: 4624(S) An account was successfully logged on | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624 | primer | ms.date 2021-09-07; diakses 2026-10-16 | Tinggi. Logon type 3 dan 10, Restricted Admin Mode (hanya type 10), field Network Information bisa kosong untuk Kerberos/NTLM |
| S8 | Microsoft Learn: 4648(S) A logon was attempted using explicit credentials | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4648 | primer | ms.date 2021-09-07; diakses 2026-10-16 | Tinggi. Ditulis di host proses berjalan; RunAs dan task; Target Server Name; Process Name |
| S9 | Microsoft Learn: 4697 / 7045 (service installed) | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4697 | primer | ms.date 2021-09-07; diakses 2026-10-16 | Tinggi. Field service, saran path di luar folder sistem dan kernel driver; 7045 tanpa akun pemasang |
| S10 | JPCERT/CC: Tool Analysis Result Sheet (PsExec, wmic, WinRM, mstsc, schtasks) | https://jpcertcc.github.io/ToolAnalysisResultSheet/ | sekunder (CERT) | diakses 2026-10-16 | Tinggi. Jejak sumber dan tujuan per alat: 7045 PSEXESVC, pipe IPC$ stdin/stdout/stderr, WmiPrvSE, event RDP, Prefetch; OS uji tidak selalu disebut |
| S11 | Microsoft Learn: PsExec (Sysinternals) | https://learn.microsoft.com/en-us/sysinternals/downloads/psexec | primer | ms.date 2023-03-30; diakses 2026-10-16 | Tinggi. Opsi `-r` ganti nama service, `-s`, `-c`; password dan perintah dienkripsi saat dikirim; jalan di Win 8.1+ dan Server 2012+ |
| S12 | Microsoft Learn: Remove entries from Remote Desktop Connection Computer box | https://learn.microsoft.com/en-us/troubleshoot/windows-server/remote/remove-entries-from-remote-desktop-connection-computer | primer | ms.date 2026-02-12; diakses 2026-10-16 | Tinggi. `HKCU\...\Terminal Server Client\Default` nilai MRU (MRU0 terbaru), FQDN atau IP tujuan RDP; `Servers`/`UsernameHint` tidak di halaman ini |
| S13 | Elastic Security: Incoming Execution via PowerShell Remoting | https://www.elastic.co/guide/en/security/current/incoming-execution-via-powershell-remoting.html | sekunder (vendor) | versi rule 216; diakses 2026-10-16 | Sedang-tinggi. Proses anak berinduk `wsmprovhost.exe` + koneksi masuk 5985/5986; investigasi process tree |
| S14 | Microsoft Learn: Receiving Events at All Times (permanent event consumer) | https://learn.microsoft.com/en-us/windows/win32/wmisdk/receiving-events-at-all-times | primer | ms.date 2018-05-31; diakses 2026-10-16 | Tinggi. Tiga komponen (__EventFilter, consumer, __FilterToConsumerBinding); dimuat saat startup atau event pemicu |
| S15 | Microsoft Learn: Standard Consumer Classes | https://learn.microsoft.com/en-us/windows/win32/wmisdk/standard-consumer-classes | primer | ms.date 2018-05-31; diakses 2026-10-16 | Tinggi. ActiveScriptEventConsumer, CommandLineEventConsumer (jalan di local system context), dan lainnya |
| S16 | Velociraptor: Windows.Persistence.PermanentWMIEvents | https://docs.velociraptor.app/artifact_references/pages/windows.persistence.permanentwmievents/ | primer (dokumentasi proyek) | diakses 2026-10-16 | Sedang-tinggi. Plugin `wmi()` (host hidup), namespace default `root/subscription` dan `root/default`; tidak mem-parse file offline; saran update 0.77.3 |
| S17 | GitHub: EricZimmerman/RECmd DFIRBatch.reb | https://raw.githubusercontent.com/EricZimmerman/RECmd/master/BatchExamples/DFIRBatch.reb | primer (repo resmi) | versi 2.22; diakses 2026-10-16 | Tinggi. KeyPath Run/RunOnce, Services, Scheduled Tasks (TaskCache), Startup, WinLogon, Terminal Server Client, Sysinternals EulaAccepted, MountPoints2 |
| S18 | GitHub: EvtxECmd Maps (7045, 4648, 5145, 4698, TaskScheduler, Sysmon 19-21, WMI-Activity 5860/5861, RDP channels) | https://github.com/EricZimmerman/evtx/tree/master/evtx/Maps | primer (repo resmi) | diakses 2026-10-16 | Tinggi untuk isi kolom per map pada tanggal akses; 5861 "Permanent Event Consumer", Sysmon 21 memetakan Consumer dan Filter; map bisa berubah |
| S19 | Microsoft Learn: 4778(S) A session was reconnected to a Window Station | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4778 | primer | ms.date 2021-09-07; diakses 2026-10-16 | Tinggi. Field Account Name, Session Name, Client Name, Client Address; RDP reconnect dan Fast User Switching |
| S20 | Microsoft Learn: Installation and configuration for Windows Remote Management | https://learn.microsoft.com/en-us/windows/win32/winrm/installation-and-configuration-for-windows-remote-management | primer | ms.date 2024-07-15; diakses 2026-10-16 | Tinggi. Port default WinRM 2.0 5985 (HTTP) dan 5986 (HTTPS); service start otomatis Server 2008+, manual di client lama; tanpa listener bawaan |
| S21 | GitHub: woanware/wmi-parser | https://github.com/woanware/wmi-parser | primer (repo) | v0.0.1; diakses 2026-10-16 | Sedang. Parse `OBJECTS.DATA` offline untuk consumer dan filter; port C# dari WMI_Forensics, ekspor CSV |
| S22 | GitHub: davidpany/WMI_Forensics (PyWMIPersistenceFinder) | https://github.com/davidpany/WMI_Forensics | primer (repo) | proyek 2017; diakses 2026-10-16 | Sedang. Cari FilterToConsumerBinding di `OBJECTS.DATA` dengan keyword; deteksi binding terhapus di unallocated belum teruji |
| S23 | Microsoft Learn: Tracing WMI Activity | https://learn.microsoft.com/en-us/windows/win32/wmisdk/tracing-wmi-activity | primer | ms.date 2018-05-31; diakses 2026-10-16 | Tinggi. Trace WMI mati bawaan, diaktifkan `wevtutil sl Microsoft-Windows-WMI-Activity/Trace /e:true` |

**Catatan sumber:** event ID inti, logon type, field, dan path registry berasal dari halaman Microsoft Learn yang diperiksa [S1][S4][S6][S7]-[S9][S12][S14]-[S15][S19][S20][S23]. Pola jejak tiap alat lateral (PsExec, WMI, WinRM, RDP, schtasks) di host sumber dan tujuan mengikuti analisis JPCERT/CC [S10], yang halamannya tidak selalu menyebut versi OS uji; pola service PsExec dikuatkan dokumentasi PsExec [S11]. Isi kolom map EvtxECmd, termasuk pemetaan WMI-Activity 5861 sebagai registrasi permanent event consumer dan Sysmon 21 sebagai consumer ke filter, benar pada tanggal akses dan bisa berubah antar versi [S18]; halaman Microsoft resmi khusus event 5861 tidak diperoleh saat riset, jadi maknanya diperlakukan sebagai indikator yang dikuatkan map dan praktisi, bukan dari spesifikasi primer, dan harus dibuktikan di lab. Detail `Servers\<host>\UsernameHint` pada key Terminal Server Client berasal dari analisis praktisi, bukan halaman Microsoft [S12], jadi diperlakukan sebagai pendukung. Alat parsing `OBJECTS.DATA` offline [S21][S22] memakai pencarian keyword, bukan parsing penuh, sehingga temuan penting diverifikasi silang. Semua isi PT JAB, termasuk waktu, IP, Logon ID, nama service `WinHlpSvc`, nama task, nama WMI filter dan consumer, payload `sync.exe` dan `hlpsvc.exe`, nomor bukti `INC-2026-017-E05`/`-E06`, dan hasil parse, adalah contoh fiktif yang disusun agar konsisten dengan fakta insiden, bukan kejadian nyata.
