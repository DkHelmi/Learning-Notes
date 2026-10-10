---
day: 05
title: 'Windows event log untuk forensik: channel penting, event ID kunci, EvtxECmd, dan membaca cerita dari log'
researched_on: 2026-10-10
versions_checked: 'Windows 10/11 event logs; EvtxECmd (EZ Tools, .NET 9); Sysmon (Sysinternals); rujukan Day 01-04'
---

# Day 05: Windows event log untuk forensik

Cakupan: membaca Windows event log hasil koleksi untuk merekonstruksi logon, perubahan akun, service, task, PowerShell, RDP, dan pembersihan log.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- menyebut channel event log Windows yang penting untuk forensik dan pertanyaan yang dijawab masing-masing.
- mengenali event ID kunci untuk logon, akun, service, scheduled task, PowerShell, dan RDP.
- memparse `.evtx` dengan EvtxECmd dan membacanya di Timeline Explorer.
- merekonstruksi rangkaian aktivitas dari beberapa channel, bukan satu event tunggal.
- menjelaskan keterbatasan event log: apa yang tidak dicatat, rotasi, dan pembersihan.

## 2. Konteks singkat

Event log adalah artefak forensik yang paling kaya konteks waktu dan identitas di Windows. Berbeda dari sudut pandang SIEM yang fokus pada deteksi real-time, di forensik kamu membaca log setelah kejadian untuk merekonstruksi apa yang terjadi: siapa login, kapan, dari mana, program apa yang jalan, service dan task apa yang dibuat, dan apakah ada upaya menghapus jejak.

Banyak event ID di Day ini juga dipakai untuk membuat alert di SIEM. Di sini sudutnya forensik: tidak untuk membuat alert, tetapi untuk menjawab pertanyaan investigasi dari log yang sudah ada, termasuk log yang dikumpulkan triage (Day 03-04).

**Kapan dipakai:** hampir setiap investigasi endpoint Windows; rekonstruksi logon, eksekusi, persistence, dan pembersihan.
**Kapan terbatas:** saat log sudah dirotasi, dinonaktifkan, atau dihapus; saat audit policy tidak mencatat yang dibutuhkan (bagian 3.7).

## 3. Konsep inti

### 3.1 Channel event log yang penting

Event log Windows terbagi ke channel; file `.evtx` ada di `C:\Windows\System32\winevt\Logs\` [S1]:

| Channel | Pertanyaan forensik | Event kunci |
|---|---|---|
| Security | Siapa login, kapan, dari mana; akun dibuat; log dihapus | 4624, 4625, 4634, 4647, 4648, 4672, 4688, 4698, 4720, 4728, 4732, 1102 |
| System | Service dipasang/berhenti; sistem nyala/mati; driver | 7045, 7034, 7036, 7040, 6005, 6006, 1074, 104 |
| Application | Error aplikasi; sebagian log antivirus | bervariasi |
| Microsoft-Windows-PowerShell/Operational | Isi script PowerShell | 4103, 4104 |
| Microsoft-Windows-Sysmon/Operational | Proses, network, dll. (bila Sysmon dipasang) | 1 proses dibuat, 3 koneksi jaringan, 11 file dibuat, 13 nilai registry di-set, dll. |
| Microsoft-Windows-TaskScheduler/Operational | Scheduled task dibuat/dijalankan | 106, 140, 141, 200, 201 |
| Microsoft-Windows-TerminalServices-* | Sesi RDP | LocalSessionManager 21-25; RemoteConnectionManager 1149 |
| Microsoft-Windows-WinRM/Operational | Remote management (lateral movement) | bervariasi |

Sebagian event bergantung versi Windows dan audit policy; pastikan event yang kamu andalkan memang muncul di VM lab sebelum memakainya di kasus.

### 3.2 Event ID logon (Security)

| Event ID | Arti | Catatan forensik |
|---|---|---|
| 4624 | Logon sukses | LogonType menentukan sifat logon (tabel di bawah) |
| 4625 | Logon gagal | Brute force, salah kredensial; field IP sumber untuk logon jaringan |
| 4634 / 4647 | Logoff / logoff diinisiasi user | Durasi sesi (pasangkan dengan 4624) |
| 4648 | Logon dengan kredensial eksplisit | runas, kredensial alternatif; juga muncul di host sumber saat tool remote memakai kredensial lain |
| 4672 | Hak istimewa saat logon | Logon admin |

Logon adalah titik awal banyak investigasi: kapan akun mulai aktif, dari mana, dan dengan hak apa. LogonType adalah kuncinya [S3]:

| LogonType | Nama | Contoh situasi |
|---|---|---|
| 2 | Interactive | Login di konsol atau layar fisik |
| 3 | Network | Akses share SMB, PsExec, WMI remote, WinRM |
| 4 | Batch | Scheduled task yang berjalan sebagai user |
| 5 | Service | Service yang start dengan akun tertentu |
| 7 | Unlock | Membuka kunci layar |
| 8 | NetworkCleartext | Autentikasi jaringan dengan kredensial cleartext (misalnya IIS basic auth) |
| 9 | NewCredentials | `runas /netonly`; identitas lokal sama, kredensial jaringan berbeda |
| 10 | RemoteInteractive | RDP |
| 11 | CachedInteractive | Login domain memakai kredensial cache saat DC tidak terjangkau |

Field lain yang sering menentukan tafsir: `IpAddress` dan `WorkstationName` (dari mana), `TargetLogonId` (untuk memasangkan dengan logoff dan event lain di sesi yang sama), `AuthenticationPackageName` (NTLM atau Kerberos), dan `ElevatedToken` (Windows 10 ke atas).

### 3.3 Event ID akun dan grup (Security)

| Event ID | Arti |
|---|---|
| 4720 | Akun user dibuat |
| 4722 | Akun diaktifkan |
| 4724 | Reset password |
| 4728 / 4732 / 4756 | User ditambah ke grup global/lokal/universal yang disetujui |
| 4738 | Akun diubah |
| 4740 | Akun terkunci |

Pembuatan akun dan penambahan ke grup admin adalah persistence (ATT&CK T1136 Create Account) dan privilege escalation klasik; event ini membuktikannya bila audit User Account Management dan Security Group Management aktif (bagian 3.7).

### 3.4 Event ID service dan task

| Channel | Event ID | Arti |
|---|---|---|
| System | 7045 | Service baru dipasang (persistence, T1543.003) |
| System | 7034 / 7036 / 7040 | Service crash / state berubah / start type berubah |
| TaskScheduler/Operational | 106 | Task didaftarkan |
| TaskScheduler/Operational | 140 / 141 | Task diperbarui / dihapus |
| TaskScheduler/Operational | 200 / 201 | Task action dijalankan / selesai |
| Security | 4698 / 4699 / 4702 | Task dibuat / dihapus / diubah (butuh audit) |

Scheduled task punya dua sumber: Security 4698 (butuh audit) dan TaskScheduler 106 (bawaan). Keduanya saling melengkapi; 106 sering ada saat 4698 tidak, karena channel TaskScheduler aktif secara bawaan sedangkan 4698 butuh audit Other Object Access Events.

### 3.5 Event ID pembersihan jejak

| Event ID | Channel | Arti |
|---|---|---|
| 1102 | Security | Audit log dibersihkan |
| 104 | System | Event log (channel tertentu) dibersihkan |

Penghapusan log (T1070.001) meninggalkan jejak sendiri: event 1102 dan 104 mencatat bahwa log dibersihkan, siapa, dan kapan. Ketiadaan log yang diharapkan plus adanya 1102/104 adalah sinyal kuat upaya anti-forensik.

### 3.6 Keterbatasan event log

- **Rotasi:** channel punya ukuran maksimum; event lama tertimpa. Log Security di host sibuk bisa hanya menyimpan beberapa hari.
- **Audit policy:** banyak event (4688 command line, 4698) hanya ada bila audit diaktifkan (bagian 3.7). Ketiadaan event tidak membuktikan ketiadaan aktivitas.
- **Penghapusan:** penyerang bisa menghapus (meninggalkan 1102/104) atau, lebih canggih, memanipulasi. VSS dan koleksi historis (Day 03) kadang memulihkan log yang dihapus.
- **Waktu:** timestamp dalam UTC di `.evtx`; perhatikan zona saat merekonstruksi (Day 13 timeline).

Prinsip forensik: event log menjawab banyak pertanyaan, tetapi ketiadaan event harus ditafsirkan hati-hati (rotasi, audit mati, atau penghapusan).

### 3.7 Audit policy menentukan isi log

Security log hanya berisi kategori yang diaudit. Sebelum menyimpulkan "tidak ada event", cek dulu apakah kategori itu memang dicatat di host tersebut [S1]:

| Event | Subcategory audit | Catatan |
|---|---|---|
| 4624, 4625, 4634, 4647, 4648 | Logon, Logoff | Umumnya aktif untuk success; failure bergantung versi dan GPO |
| 4672 | Special Logon | Umumnya aktif |
| 4688 | Process Creation | Tidak aktif secara default. Command line hanya tercatat bila GPO "Include command line in process creation events" diaktifkan [S4] |
| 4720, 4722, 4724, 4738, 4740 | User Account Management | Sering aktif untuk success di build modern; pastikan di GPO |
| 4728, 4732, 4756 | Security Group Management | Sama seperti di atas |
| 4698, 4699, 4702 | Other Object Access Events | Tidak aktif secara default |
| 5140, 5145 | File Share, Detailed File Share | Tidak aktif secara default; 5145 sangat bising |
| 1102 | (selalu) | Dicatat saat Security log dibersihkan |
| 4104 (PowerShell/Operational) | Script Block Logging (GPO PowerShell) | Tidak aktif secara default, tetapi PowerShell 5 ke atas tetap mencatat script block yang dianggap mencurigakan dengan level Warning [S7] |

Di lab, `auditpol /get /category:*` di VM korban menampilkan kebijakan yang berlaku. Di kasus nyata kamu sering hanya punya koleksi; kebijakan audit tersimpan di hive SECURITY (nilai `PolAdtEv`), dan bila tidak bisa dibaca, simpulkan dari event yang ada: misalnya tidak ada satu pun 4688 dalam log berarti Process Creation tidak diaudit, bukan berarti tidak ada proses. Cek apakah parser registry di versi lab-mu menerjemahkan `PolAdtEv`.

Sysmon (bila dipasang) mengisi celah yang sama dari sisi lain: EID 1 memuat command line, hash, dan parent process meski 4688 mati [S6]. Karena itu, saat menilai sebuah host, tulis di catatan kasus sumber eksekusi mana yang tersedia: 4688 dengan atau tanpa command line, Sysmon, atau tidak ada keduanya.

### 3.8 EvtxECmd: parsing untuk analisis

EvtxECmd (EZ Tools) memparse `.evtx` menjadi CSV atau JSON yang bisa dibaca di Timeline Explorer [S2]. Kelebihannya atas Event Viewer: menggabungkan banyak file, menormalkan field (termasuk map yang mengekstrak field penting dari XML event), dan menghasilkan output yang bisa difilter dan ditimeline. EvtxECmd dipakai di pipeline Day 03-04 (via Module `!EZParser`) dan langsung di Day ini.

## 4. Artefak, perintah, dan cara membacanya

> Perintah dijalankan di VM analisis atas koleksi (Day 03-04). Keluaran berlabel ilustrasi. Event ID perlu dicek bila bergantung versi/audit.

### 4.1 Parse satu channel dengan EvtxECmd

```
EvtxECmd.exe -f ".\triage\...\winevt\Logs\Security.evtx" --csv ".\analysis" --csvf security.csv
```

- `-f` satu file; `--csv` folder output; `--csvf` nama file.
- Untuk banyak file sekaligus, pakai `-d` (direktori) alih-alih `-f`.
- Cek path `winevt\Logs` dalam struktur koleksi KAPE/Velociraptor lab.

Keluaran ilustrasi (kolom yang dinormalkan):

```
TimeCreated           EventId  Channel   Computer    MapDescription            UserName       RemoteHost
2026-10-02T14:01:10Z  4624     Security  WIN-LAB01   Successful logon          LAB\alice      192.168.56.20
2026-10-02T14:03:11Z  4688     Security  WIN-LAB01   Process created           LAB\alice
```

EvtxECmd menambahkan `MapDescription` yang menjelaskan event, memudahkan membaca dibanding XML mentah.

### 4.2 Parse semua log koleksi

```
EvtxECmd.exe -d ".\triage\...\winevt\Logs" --csv ".\analysis" --csvf all_evtx.csv
```

- Memparse semua `.evtx` di folder menjadi satu CSV. Berguna untuk timeline lintas channel (Day 13).
- Buka di Timeline Explorer, filter kolom `EventId` dan `Channel` untuk fokus.

### 4.3 Membaca logon dan sesi

Di Timeline Explorer atas CSV Security, filter `EventId` 4624 dan 4634/4647:
- Cari 4624 dengan LogonType 10 (RDP) atau 3 (network) dari IP tidak lazim.
- Pasangkan 4624 (logon) dengan 4634/4647 (logoff) berdasarkan Logon ID untuk durasi sesi.
- 4672 setelah 4624 menandai sesi dengan hak admin.

Cara membaca: satu 4624 tidak bercerita banyak; rangkaian 4625 berulang lalu 4624 sukses dari IP yang sama menandakan brute force berhasil (T1110). Rekonstruksi butuh beberapa event.

### 4.4 Membaca eksekusi dan task

- Security 4688 (bila audit aktif): proses baru dengan command line (bila setting command line aktif, bagian 3.7). Filter `NewProcessName` dan `CommandLine`.
- System 7045: service baru. Filter dan periksa `ServiceFileName` untuk lokasi tidak lazim, misalnya `C:\Users\...`, `C:\ProgramData\...`, atau `%TEMP%`.
- TaskScheduler 106: task didaftarkan. Periksa nama task dan action.
- PowerShell 4104: isi script block. Filter untuk pola mencurigakan seperti `DownloadString`, `IEX`, `FromBase64String`, atau `-EncodedCommand`. Script panjang dipecah ke beberapa 4104 dengan `ScriptBlockId` sama; gabungkan sebelum dibaca.

Event eksekusi dari log melengkapi artefak eksekusi lain (Prefetch, Amcache) yang dibahas Day 07.

### 4.5 Membaca RDP (lateral movement)

Sesi RDP tersebar di beberapa channel:
- TerminalServices-LocalSessionManager/Operational: 21 (logon sukses sesi), 22 (shell start), 23 (logoff), 24 (disconnect), 25 (reconnect).
- TerminalServices-RemoteConnectionManager/Operational: 1149 (koneksi masuk, sebelum autentikasi).
- Security 4624 LogonType 10.

Rekonstruksi RDP memadukan ketiganya: 1149 (ada koneksi), 4624 type 10 (logon berhasil), 21/22 (sesi dimulai). Cek event ID TerminalServices di versi Windows lab.

### 4.6 Mendeteksi pembersihan log

```
# cari event 1102 (Security cleared) dan 104 (log cleared) di CSV
```

Di Timeline Explorer, filter `EventId` 1102 (Security) dan 104 (System/lainnya). Kehadiran event ini menandai log dibersihkan, dengan user dan waktu. Padukan dengan gap di timeline (periode tanpa event yang seharusnya ada) sebagai bukti anti-forensik. Koleksi dari VSS (Day 03) kadang memiliki log sebelum dibersihkan.

## 5. Lab praktik

**Prasyarat:** koleksi triage dari VM korban (Day 03/04) yang berisi event log; VM analisis dengan EvtxECmd dan Timeline Explorer; aktivitas jinak sudah dijalankan di korban (logon, buat user lab, buat service/task, jalankan PowerShell).

1. **Parse.** Parse Security, System, PowerShell/Operational, dan TaskScheduler/Operational dari koleksi dengan EvtxECmd (bagian 4.1-4.2). Buka di Timeline Explorer.
2. **Logon.** Temukan logon-mu sendiri (4624), tentukan LogonType, dan pasangkan dengan logoff untuk durasi sesi (bagian 4.3).
3. **Akun.** Temukan pembuatan user lab (4720) dan penambahan ke grup (4728/4732), bila kamu membuatnya.
4. **Eksekusi dan task.** Temukan service (7045) dan task (106/4698) yang kamu buat; periksa path dan action.
5. **PowerShell.** Temukan script PowerShell yang kamu jalankan (4104).
6. **Pembersihan (opsional, di snapshot).** Bersihkan satu channel log di VM korban (`wevtutil cl`), kumpulkan ulang, dan temukan event 1102/104 plus gap. Kembalikan snapshot.
7. **Rekonstruksi.** Tulis timeline mini: dari logon sampai eksekusi, memadukan minimal tiga channel. Catat event ID dan waktunya.

**Hasil yang sebaiknya tersimpan:**
- Empat channel diparse dan dibaca di Timeline Explorer.
- Logon ditemukan dengan LogonType dan durasi sesi.
- Pembuatan akun/service/task yang diuji ditemukan.
- Script PowerShell uji ditemukan di 4104.
- (Opsional) Pembersihan log menghasilkan 1102/104 dan gap.
- Timeline mini lintas tiga channel tertulis.

**Variasi tantangan:** ambil satu koleksi yang mencakup VSS (Day 03). Bandingkan log Security dari partisi live dengan versi di VSS: apakah ada event di VSS yang hilang dari live (mungkin karena rotasi atau pembersihan)? Tulis apa yang VSS tambahkan untuk rekonstruksi.

## 6. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Event yang diharapkan tidak ada | Audit policy tidak aktif; rotasi | Cek audit (bagian 3.7); periksa rentang waktu log |
| 4688 tanpa command line | Setting command line tidak aktif | Normal bila setting command line tidak aktif (bagian 3.7) |
| EvtxECmd tidak mengenali field | Map belum ada untuk event itu | Perbarui EvtxECmd dan maps; field tetap ada di payload |
| Timestamp membingungkan | UTC vs lokal | Event log UTC; konversi saat timeline (Day 13) |
| Banyak 4624 tidak relevan | Logon layanan/sistem (type 5) | Filter LogonType; fokus 2, 3, 10 |
| RDP tidak lengkap | Event tersebar di beberapa channel | Padukan TerminalServices dan Security 4624 (bagian 4.5) |

## 7. Kesalahan umum dan jebakan

- **Menyimpulkan dari satu event.** Rekonstruksi butuh rangkaian lintas channel.
- **Mengira ketiadaan event berarti ketiadaan aktivitas.** Bisa rotasi, audit mati, atau penghapusan.
- **Mengabaikan LogonType.** 4624 tanpa tipe kehilangan arti (interaktif vs network vs RDP).
- **Lupa zona waktu.** Event log UTC; salah konversi merusak timeline.
- **Melewatkan 1102/104.** Pembersihan log adalah temuan penting, bukan sekadar gap.
- `[komunitas, belum terkonfirmasi]` Praktisi menilai TaskScheduler 106 dan System 7045 sebagai sumber persistence yang andal karena ada tanpa audit tambahan, sementara 4698 butuh audit. Ini konsisten dengan perilaku channel bawaan (bagian 3.7); cek di versi Windows lab.

## 8. Catatan terkini

- Channel dan event ID inti stabil antar Windows 10/11, tetapi sebagian event TerminalServices dan audit bergantung versi dan kebijakan, perlu dicek.
- EvtxECmd dengan maps menormalkan field penting dari XML; perbarui maps agar `MapDescription` lengkap [S2].
- Event log UTC; timeline lintas artefak (Day 13) menyatukan zona.
- Day 06 (review) menggabungkan Day 01-05; Day 07 masuk ke artefak eksekusi yang melengkapi event log.

## 9. Cheat sheet

```
CHANNEL    Security | System | PowerShell/Operational | Sysmon/Operational | TaskScheduler/Operational | TerminalServices-* | WinRM
LOGON      4624 sukses (+LogonType 2/3/10) | 4625 gagal | 4634/4647 logoff | 4648 explicit creds | 4672 admin
AKUN       4720 buat | 4722 aktif | 4724 reset pw | 4728/4732 tambah grup | 4738 ubah | 4740 lock
EKSEKUSI   Security 4688 (+cmdline bila audit) | System 7045 service | TaskSched 106 task | PowerShell 4104 script
TASK       TaskSched 106 register / 140-141 update-delete / 200-201 run ; Security 4698/4699/4702 (butuh audit)
PEMBERSIHAN Security 1102 (audit cleared) | System/lainnya 104 (log cleared) ; + gap di timeline
RDP        TS-LocalSessionManager 21-25 | TS-RemoteConnectionManager 1149 | Security 4624 type 10
PARSE      EvtxECmd -f/-d ... --csv ... ; Timeline Explorer filter EventId/Channel ; waktu UTC
BATAS      rotasi | audit mati | penghapusan ; ketiadaan event != ketiadaan aktivitas
```

## 10. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Microsoft Learn: Windows security audit events / event log reference | https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-audit-policy-settings | primer | diakses 2026-10-09 | Tinggi. Event ID dan channel |
| S2 | Eric Zimmerman tools: EvtxECmd | https://ericzimmerman.github.io/ | primer | diakses 2026-10-09 (Day 02) | Tinggi. Parsing .evtx, maps |
| S3 | Microsoft Learn: 4624(S) An account was successfully logged on | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624 | primer | diakses 2026-10-10 | Tinggi. LogonType dan field |
| S4 | Microsoft Learn: Command line process auditing | https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing | primer | diakses 2026-10-10 | Tinggi. Setting command line 4688 |
| S6 | Microsoft Learn: Sysmon | https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon | primer | diakses 2026-10-10 | Tinggi. Event ID Sysmon |
| S7 | Microsoft Learn: about_Logging_Windows (PowerShell) | https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows | primer | diakses 2026-10-10 | Tinggi. Script block logging |
| S5 | Endpoint-Forensics Day 03-04 (koleksi event log) | (lokal) | rujukan internal | 2026-10-09 | Sumber log yang diparse |

**Catatan sumber:** event ID inti di Day ini stabil dan didokumentasikan Microsoft [S1][S3]. Status default tiap subcategory audit berbeda antar versi Windows dan baseline GPO, jadi tabel bagian 3.7 adalah pola umum; pastikan dengan `auditpol` di VM lab. Event ID TerminalServices bergantung versi. Dukungan parser untuk nilai `PolAdtEv` dan path `winevt\Logs` di dalam koleksi perlu dicek.
