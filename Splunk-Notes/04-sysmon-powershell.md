---
day: 04
title: 'Sysmon dan PowerShell di Splunk: process tree, koneksi, registry, DNS, dan script block'
researched_on: 2026-10-14
versions_checked: 'Splunk Add-on for Sysmon 5.0.1 (Splunkbase, rilis 6 Juli 2026; Splunk Enterprise dan Cloud 9.2 sampai 10.6; CIM 6.x); Splunk Add-on for Microsoft Windows 11.0.3; halaman data source research.splunk.com untuk Sysmon EventID 1, 3, 10, 11, 13, 22 dan PowerShell 4104 (diperbarui 2026-05-13, diuji dengan add-on Sysmon 5.0.1); detection ESCU Detect Credential Dumping through LSASS access v16 (2026-09-08); Microsoft Learn Sysmon (terbit 2026-09-10); Microsoft Learn about_Logging PowerShell 5.1 (diperbarui 2025-09-29) dan about_Logging_Windows PowerShell 7.6 (diperbarui 2026-01-19); BOTS v3; Splunk Enterprise 10.6; ES 8.7.0; CIM 6.4'
---

# Day 04: Sysmon dan PowerShell di Splunk (process tree, koneksi, registry, DNS, dan script block)

Cakupan: cara log Sysmon dan PowerShell Operational masuk ke Splunk, isi event Sysmon 1, 3, 10, 11, 13, dan 22, cara menyusun process tree dari `ProcessGuid` dan `ParentProcessGuid`, serta cara membaca PowerShell script block logging (4104) dan module logging (4103) termasuk script yang terpecah menjadi beberapa event.

## Ide inti

Log Windows Security menjawab siapa masuk dan apa yang diubah. Sysmon dan PowerShell logging menjawab pertanyaan berikutnya: proses apa yang berjalan, siapa induknya, ke mana ia menghubungi, apa yang ia tulis ke disk dan registry, nama apa yang ia resolve, dan apa isi script yang dijalankan. Dua hal membuat keduanya berbeda dari 4688. Pertama, `ProcessGuid`: identitas proses yang unik dan tidak dipakai ulang, sehingga rantai induk dan anak bisa disusun dari log tanpa menebak. Kedua, `ScriptBlockText`: isi script apa adanya setelah dibongkar oleh engine PowerShell, bukan hanya baris perintah yang terlihat di command line.

Harga dari kekayaan itu adalah ketergantungan pada konfigurasi. Sysmon bukan log bawaan Windows: ia service dan driver tambahan, dan event mana yang ditulis ditentukan file konfigurasi XML yang dipasang di host itu. PowerShell script block logging juga mati secara default dan dinyalakan lewat Group Policy atau registry. Artinya cakupan datamu bisa berbeda per host, dan pertanyaan pertama di setiap investigasi adalah "host ini memang mengirim event yang aku cari, atau event itu tidak pernah ditulis?".

Kamu sudah mengenal pola ini dari sisi jaringan. Syslog perangkat selalu ada, tetapi NetFlow dan port mirror hanya ada di perangkat yang memang dikonfigurasi, dengan sampling dan capture filter yang kamu tentukan sendiri. Sysmon adalah NetFlow-nya endpoint: sensor tambahan yang kaya tetapi selektif, dan apa yang dibuang filter di host tidak bisa dipulihkan dari Splunk. `ProcessGuid` berperan seperti correlation ID atau Acct-Session-Id: nomor yang menyatukan banyak baris log menjadi satu objek, berbeda dari PID yang seperti nomor port, habis lalu dipakai ulang. Script block logging adalah command accounting penuh: bukan hanya nama perintah, tetapi seluruh isinya.

```
Sysmon service + driver  (file konfigurasi XML menentukan event mana ditulis)
  -> channel Microsoft-Windows-Sysmon/Operational
PowerShell  (GPO: Turn on Module Logging, Turn on PowerShell Script Block Logging)
  -> channel Microsoft-Windows-PowerShell/Operational
  -> universal forwarder: input WinEventLog://<channel>, renderXml true
  -> add-on (parser)
       Sysmon     : sourcetype=XmlWinEventLog
                    source=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
       PowerShell : sourcetype=XmlWinEventLog
                    source=XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  -> field mentah : ProcessGuid, ParentProcessGuid, Image, CommandLine, GrantedAccess,
                    TargetFilename, TargetObject, QueryName, ScriptBlockText
  -> field CIM    : process_guid, parent_process_guid, process_name, process_exec,
                    dest, user, query, registry_path
```

Situasi yang dipakai sepanjang Day ini adalah lanjutan tiket SOC-2026-0217 di PT Jaringan Anak Bangsa (PT JAB, ISP fiktif dengan domain AD `JAB`). Shift malam sudah mengeskalasi temuan dari log Windows Security: sesi RDP `adm.rina` ke `JKT-JUMP01` dari `10.30.14.22` pada 01:52 dengan Logon ID `0x5a3f21c`, sesi elevated, `net group` menambahkan `budi.santoso` ke Domain Admins pada 01:57, dan task baru `\OneDriveSyncCheck` pada 02:03. Analyst L2 on-call membalas di tiket:

> "Oke, aku ambil alih. Yang aku butuh sekarang bukan 4688 lagi. Dari sesi itu, aku mau tahu rantai prosesnya sampai ke akar, apa yang dihubungi keluar, apakah ada yang menyentuh LSASS, file dan registry apa yang berubah, dan isi script PowerShell-nya. Oh ya, kenapa `JKT-WS-0412` tidak muncul sama sekali di index `sysmon`, padahal 4625 dari host itu ada?"

Pesan itu memuat lima pertanyaan:

1. Kenapa sebuah host ada di `wineventlog` tetapi tidak ada di `sysmon`, dan bagaimana memastikan event yang kucari memang ditulis?
2. Event Sysmon itu masuk dengan sourcetype dan source apa, dan nama field mana yang bisa kuandalkan?
3. Bagaimana menyusun rantai proses dari log, dan kenapa `ProcessGuid` lebih bisa dipercaya daripada PID?
4. Apa yang dilakukan proses itu di jaringan, ke proses lain, ke disk, ke registry, dan ke DNS?
5. Apa isi script PowerShell yang dijalankan, dan kenapa isinya bisa terlihat terpotong?

Pertanyaan 1 dijawab di bagian 1.1, pertanyaan 2 di bagian 1.2, pertanyaan 3 di bagian 1.3, pertanyaan 4 di bagian 1.4 sampai 1.7, dan pertanyaan 5 di bagian 1.8. Bagian 2 menjalankan semuanya sebagai search.

**Kapan relevan:** investigasi satu host Windows setelah ada sinyal awal (alert, logon aneh, laporan user), rekonstruksi rantai eksekusi dan persistence, mencari credential access dan koneksi keluar dari proses tertentu, serta menilai apakah sebuah script PowerShell berbahaya atau pekerjaan admin yang sah.
**Kapan bukan jawaban:** saat Sysmon tidak terpasang atau konfigurasinya tidak mencakup event yang dibutuhkan, saat pertanyaannya tentang identitas dan perubahan akun (itu log Windows Security di Day 03), saat kamu butuh volume byte dan durasi sesi jaringan (Sysmon tidak mencatatnya, pakai log firewall dan proxy di Day 05), atau saat host yang dicurigai tidak punya PowerShell logging sama sekali sehingga satu-satunya jejak script ada di command line proses.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dasar Splunk dari Day 01 dan 02 (index, sourcetype, source, `stats`, `eval`) dan istilah Windows dari Day 03 (Event ID, audit policy, Logon ID, format klasik dan XML) tidak diulang. Tabel ini memuat istilah Sysmon dan PowerShell logging yang dipakai Day ini; kolom padanan memakai hal yang sudah kamu kuasai dari NOC dan SOC.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| Sysmon | Service dan driver tambahan dari Sysinternals yang menulis aktivitas proses, jaringan, file, dan registry ke event log Windows | Sensor tambahan seperti NetFlow atau port mirror: kaya, tetapi hanya ada di perangkat yang dikonfigurasi |
| Channel `Microsoft-Windows-Sysmon/Operational` | Tempat Sysmon menulis event di Windows | Buffer log khusus satu fitur di perangkat, terpisah dari syslog umum |
| File konfigurasi Sysmon | XML berisi aturan include dan exclude per event ID yang menentukan apa yang dicatat | Capture filter di sniffer atau access-list di SPAN: yang tidak lolos filter hilang di sumber |
| `RuleName` | Nama aturan konfigurasi yang menyebabkan event itu ditulis | Nama ACE di access-list yang membuat paket tercatat |
| `ProcessGuid` dan `ParentProcessGuid` | Identitas unik satu proses dan induknya, tidak dipakai ulang | Correlation ID atau Acct-Session-Id: satu objek, banyak baris log |
| `ProcessId` (PID) | Nomor proses dari Windows, dipakai ulang setelah proses mati | Nomor port ephemeral: habis lalu dipakai lagi oleh pemilik lain |
| Process tree | Rantai induk dan anak yang disusun dari banyak event proses | Call flow yang direkonstruksi dari banyak baris log sesi |
| `IntegrityLevel` | Tingkat hak proses (Low, Medium, High, System) | Privilege level perintah di perangkat (level 1 vs level 15) |
| `Hashes`, `IMPHASH` | Hash file image proses, beberapa algoritma sekaligus | Checksum image firmware untuk memastikan file yang sama |
| `GrantedAccess` | Bitmask hak yang diminta saat satu proses membuka proses lain | Bitmask flag di field protokol: dibaca per bit, bukan per nilai utuh |
| `CallTrace` | Tumpukan pemanggilan yang menghasilkan akses antar proses | Jejak modul yang memicu sebuah aksi, dibaca untuk tahu asal perintah |
| `Initiated` | Penanda apakah koneksi dimulai dari host ini (outbound) atau diterima | Arah flow di NetFlow: siapa yang memulai sesi |
| `QueryName`, `QueryStatus`, `QueryResults` | Nama yang di-resolve, kode hasil, dan jawaban dari query DNS satu proses | Log query di resolver, tetapi dengan nama proses peminta |
| Script block | Satu blok kode PowerShell yang diproses engine, isinya dicatat oleh event 4104 | Command accounting penuh di TACACS+, isi perintah apa adanya |
| `ScriptBlockId`, `MessageNumber`, `MessageTotal` | ID satu script block dan nomor bagian dari total bagian bila script terlalu panjang untuk satu event | Dokumen multi-halaman: "halaman 2 dari 3" yang harus disusun dulu |
| Module logging (4103) | Pencatatan pemanggilan pipeline per module PowerShell | Accounting per perintah: tercatat apa yang dipanggil, bukan seluruh isinya |
| Protected event logging | Enkripsi isi event sensitif di host dengan kunci publik, didekripsi di tempat terpisah | Log terenkripsi di perangkat yang baru bisa dibaca di kolektor aman |

### 1.1 Sysmon adalah sensor yang isinya ditentukan konfigurasi

`JKT-WS-0412` ada di `wineventlog` tetapi tidak ada di `sysmon`. Di PT JAB itu wajar: Sysmon baru terpasang di server Windows dan sekitar 40 persen workstation. Ini perbedaan paling penting antara Day 03 dan Day ini. Di log Windows Security, yang menentukan ada atau tidaknya event adalah audit policy. Di Sysmon, yang menentukan adalah apakah service-nya terpasang, dan kalau terpasang, apa isi file konfigurasinya.

Sysmon adalah system service plus device driver yang tetap aktif melewati reboot dan menulis aktivitas sistem ke event log Windows. Ia mencatat process creation dengan command line lengkap untuk proses dan induknya, hash file image, GUID proses supaya event tetap bisa dikorelasikan walaupun Windows memakai ulang PID, GUID sesi logon supaya event dalam satu sesi bisa disatukan, serta opsional koneksi jaringan dengan proses asalnya [S1]. Di Windows Vista ke atas, event disimpan di `Applications and Services Logs/Microsoft/Windows/Sysmon/Operational`, dan timestamp event memakai UTC [S1]. Sysmon tidak menganalisis event yang ia hasilkan dan tidak berusaha menyembunyikan diri dari penyerang [S1].

Pemasangan dan konfigurasi dilakukan dari command line: `sysmon64 -i <configfile>` untuk memasang, `sysmon64 -c <configfile>` untuk mengubah konfigurasi service yang sudah jalan, `sysmon64 -c` tanpa argumen untuk melihat konfigurasi aktif, dan `sysmon64 -s` untuk mencetak skema event beserta nama field tiap event [S1]. Konfigurasi juga dimuat ulang otomatis bila berubah di registry [S1]. Untuk analyst, tiga perintah pertama itu yang penting: saat sebuah event "tidak ada", kamu minta tim endpoint menjalankan `sysmon64 -c` di host itu dan membaca hasilnya.

Isi konfigurasi menentukan event mana yang ditulis. Setiap event punya tag filter sendiri di bawah `EventFiltering`, misalnya `ProcessCreate` untuk event 1, `NetworkConnect` untuk event 3, `ProcessAccess` untuk event 10, `FileCreate` untuk event 11, `RegistryEvent` untuk event 12, 13, dan 14, serta `DnsQuery` untuk event 22 [S1]. Atribut `onmatch` menentukan artinya: `include` berarti hanya yang cocok dicatat, `exclude` berarti semua dicatat kecuali yang cocok, dan aturan exclude menang atas include [S1]. Aturan bisa diberi nama, dan nama itu muncul di field `RuleName` event hasilnya [S1]. Itu sebabnya `RuleName` berguna saat triage: ia menyebutkan aturan mana yang membuat event ini ada.

Beberapa default yang mengubah cara kamu membaca data kosong [S1]:

- Event 3 (network connection) mati secara default dan harus dinyalakan lewat konfigurasi.
- Event 7 (image loaded) mati secara default dan sangat besar volumenya bila dinyalakan tanpa filter.
- Event 10 (process access) bisa menghasilkan log sangat banyak karena utilitas diagnostik rutin membuka proses lain, sehingga Microsoft menyarankan hanya menyalakannya dengan filter yang membuang akses yang diharapkan.
- Event 22 (DNS query) baru tersedia karena telemetry-nya ditambahkan di Windows 8.1, jadi tidak ada di Windows 7 dan sebelumnya.
- Entry `DnsLookup` yang default `True` membuat Sysmon melakukan reverse DNS lookup, yang mengisi `DestinationHostname` di event 3; banyak konfigurasi publik mematikannya karena menambah beban dan noise.
- Halaman yang sama menyebut dua hal berbeda soal hash: tabel configuration entry mencantumkan `HashAlgorithms` default `None`, sedangkan contoh pemasangan menyebut default menghash image proses dengan SHA1. Jangan bergantung pada default; minta `HashAlgorithms` diisi eksplisit di konfigurasi PT JAB dan catat nilainya.

Tabel berikut adalah katalog event Sysmon yang dipakai di Day ini beserta tag konfigurasinya; pakai kolom tag saat meminta tim endpoint memeriksa atau mengubah cakupan [S1].

| Event ID | Nama | Tag konfigurasi | Isi inti yang dipakai saat investigasi |
|---|---|---|---|
| 1 | Process creation | `ProcessCreate` | `Image`, `CommandLine`, `ParentImage`, `ParentCommandLine`, `ProcessGuid`, `ParentProcessGuid`, `User`, `IntegrityLevel`, `Hashes`, `LogonId` |
| 3 | Network connection | `NetworkConnect` | `Image`, `ProcessGuid`, `SourceIp`, `DestinationIp`, `DestinationPort`, `DestinationHostname`, `Protocol`, `Initiated` |
| 10 | ProcessAccess | `ProcessAccess` | `SourceImage`, `TargetImage`, `SourceProcessGUID`, `TargetProcessGUID`, `GrantedAccess`, `CallTrace` |
| 11 | FileCreate | `FileCreate` | `Image`, `ProcessGuid`, `TargetFilename`, `CreationUtcTime` |
| 13 | RegistryEvent (Value Set) | `RegistryEvent` | `Image`, `ProcessGuid`, `TargetObject`, `Details`, `EventType` |
| 22 | DNSEvent (DNS query) | `DnsQuery` | `Image`, `ProcessGuid`, `QueryName`, `QueryStatus`, `QueryResults` |

Event lain yang sering ikut dipasang dan berguna sebagai lapisan kedua: 5 (process terminated) untuk menghitung durasi proses, 8 (CreateRemoteThread) dan 25 (ProcessTampering) untuk injeksi, 12 dan 14 untuk pembuatan, penghapusan, dan penggantian nama objek registry, 15 (FileCreateStreamHash) untuk mark of the web pada file hasil unduhan, serta 17 dan 18 untuk named pipe [S1]. Sysmon juga mencatat perubahan konfigurasinya sendiri sebagai event 16, yang berguna saat kamu curiga cakupan berubah di tengah insiden [S1].

Dua catatan untuk registry. Sysmon memakai singkatan nama root key: `HKEY_LOCAL_MACHINE` menjadi `HKLM`, `HKEY_USERS` menjadi `HKU`, `HKEY_LOCAL_MACHINE\System\ControlSet00x` menjadi `HKLM\System\CurrentControlSet`, dan `HKEY_LOCAL_MACHINE\Classes` menjadi `HKCR` [S1]. Jadi search yang mencari `HKEY_LOCAL_MACHINE` tidak akan cocok dengan isi `TargetObject`. Lalu untuk event 13, Microsoft menyebut nilai yang direkam adalah nilai registry bertipe DWORD dan QWORD [S1]; untuk tipe lain, isi `Details` di versi-mu perlu dicek di lab karena sebagian tipe tampil sebagai keterangan, bukan isi sebenarnya.

### 1.2 Dari channel Sysmon ke Splunk: satu sourcetype, dua lapis nama field

Analyst L2 bertanya field mana yang bisa diandalkan. Jawabannya sama bentuknya dengan Day 03: ada nama field mentah dari XML event, dan ada nama field CIM yang diisi add-on.

Event Sysmon diambil universal forwarder lewat input `WinEventLog` pada channel `Microsoft-Windows-Sysmon/Operational`, lalu diparsing Splunk Add-on for Sysmon. Halaman data source di research.splunk.com yang diuji dengan add-on 5.0.1 mencatat semua event Sysmon dengan `sourcetype=XmlWinEventLog` dan `source=XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`, dengan `EventID` sebagai pembeda jenis event [S2][S3][S4][S5][S6][S7][S9]. Pola penamaannya identik dengan add-on Windows: sourcetype generik, channel dibedakan lewat `source`. PowerShell Operational ditangani add-on yang berbeda, Splunk Add-on for Microsoft Windows 11.0.3, dengan `sourcetype=XmlWinEventLog` dan `source=XmlWinEventLog:Microsoft-Windows-PowerShell/Operational` [S8].

Konsekuensinya sama dengan Day 03: contoh dan dataset lama memakai penamaan berbeda. BOTS v3 menyimpan event Sysmon dengan sourcetype `xmlwineventlog:microsoft-windows-sysmon/operational` [S18], dan artikel Lantern tentang process tree juga masih memakai nama itu di contohnya [S17]. Search yang menyaring sourcetype gaya lama tidak akan menemukan data dari add-on modern, dan sebaliknya. Untuk data baru, saring dengan `source` lalu `EventCode`.

Tabel berikut memetakan nama field yang paling sering dipakai; perhatikan kolom CIM, karena di sanalah search lintas sumber bisa ditulis sekali untuk Sysmon dan 4688 [S2][S3][S4][S5][S6][S7].

| Arti | Field mentah Sysmon | Field CIM dari add-on |
|---|---|---|
| Host tempat event terjadi | `Computer` | `dest` |
| Path lengkap proses | `Image` | `process_exec`, `process_path` |
| Nama file proses saja | tidak ada, harus diambil dari `Image` | `process_name` |
| Baris perintah | `CommandLine` | `process` |
| Identitas proses | `ProcessGuid`, `ProcessId` | `process_guid`, `process_id` |
| Identitas induk | `ParentProcessGuid`, `ParentImage` | `parent_process_guid`, `parent_process_name`, `parent_process_exec` |
| Akun pemilik proses | `User` | `user` |
| Hak proses | `IntegrityLevel` | `process_integrity_level` |
| Hash image | `Hashes`, `MD5`, `SHA256`, `IMPHASH` | `process_hash` |
| Tujuan koneksi | `DestinationIp`, `DestinationPort` | `dest_ip`, `dest_port` |
| Hak akses antar proses | `GrantedAccess` | `granted_access` |
| File yang dibuat | `TargetFilename` | `file_name`, `file_path` |
| Objek registry | `TargetObject`, `Details` | `registry_path`, `registry_key_name`, `registry_value_data` |
| Query DNS | `QueryName` | `query` |
| Jenis event | `EventID`, `EventCode` | `signature_id`, `signature` |

Dua jebakan di tabel ini yang terlihat di daftar field resmi. Pertama, tidak semua event punya `user` berisi nama akun. Daftar field event 10 hanya memuat `user_id` (SID), tanpa nama akun [S4], dan event 11 mencantumkan `user` sebagai required output field padahal field itu tidak ada di daftar field yang benar-benar terekstrak [S5]. Jadi untuk event selain 1, jangan berasumsi kolom akun terisi; cek dulu dengan `fieldsummary`. Kedua, event 22 mencantumkan `answer` dan `answer_count` sebagai required output field, sementara daftar field terekstrak hanya memuat `query`, `query_count`, `reply_code_id`, dan `src` [S7]. Artinya pemetaan ke data model Network Resolution bisa tidak lengkap di versi add-on tertentu, dan jawaban DNS tetap harus dibaca dari `QueryResults`.

**Tanpa ES:** semua search di Day ini jalan di app Search & Reporting dengan `index=sysmon` dan `index=powershell`. Add-on Sysmon 5.0.1 memetakan event ke data model Endpoint, Network Resolution, Network Traffic, dan Change [S10], sehingga di lingkungan dengan ES dan CIM terakselerasi kamu bisa memakai `tstats` atas data model itu (Day 25). Detection ESCU juga ditulis dengan macro `sysmon`, yang harus didefinisikan dulu menunjuk ke index dan source Sysmon di lingkunganmu sebelum detection-nya jalan (Day 18 untuk macro, Day 45 untuk ESCU). Tanpa ES, ganti macro itu dengan filter index dan source langsung.

### 1.3 Process tree dari log: ProcessGuid dan ParentProcessGuid

Pertanyaan L2 adalah rantai proses sampai ke akar. Di Day 03 kita berhenti di 4688 karena PID heksadesimal bisa dipakai ulang. Sysmon menyelesaikan itu.

Event 1 adalah process creation dan memuat informasi lengkap tentang proses baru: command line penuh sebagai konteks eksekusi, serta `ProcessGUID` yang unik untuk proses itu di seluruh domain sehingga korelasi event jadi mudah [S1]. Daftar field dari add-on 5.0.1 memperlihatkan pasangan yang dibutuhkan untuk menyusun pohon: `ProcessGuid`, `ProcessId`, `Image`, `CommandLine`, `CurrentDirectory`, `User`, `LogonGuid`, `LogonId`, `IntegrityLevel`, `Hashes`, `OriginalFileName`, `ParentProcessGuid`, `ParentProcessId`, `ParentImage`, `ParentCommandLine`, `TerminalSessionId`, dan `RuleName` [S2].

Cara menyusun pohonnya sederhana: setiap event 1 adalah satu simpul yang menyimpan nomor dirinya (`ProcessGuid`) dan nomor induknya (`ParentProcessGuid`). Untuk naik ke atas, cari event yang `ProcessGuid`-nya sama dengan `ParentProcessGuid` simpul sekarang. Untuk turun ke bawah, cari event yang `ParentProcessGuid`-nya sama dengan `ProcessGuid` simpul sekarang. Lantern menyebut cara manual ini berulang dan memakan waktu, lalu menawarkan jalan pintas dengan app PSTree yang tidak didukung resmi, sehingga kompatibilitas versinya tanggung jawab pemakainya [S17].

Empat hal yang membatasi pohon hasil log, dan semuanya pernah membuat analyst salah simpul:

- **Pohon hanya sedalam rentang waktu search.** Induk yang dibuat jauh sebelum rentang waktu tidak punya event 1 di hasil, sehingga rantainya seolah terputus. Lebarkan rentang ke belakang, jangan menyimpulkan prosesnya tidak berinduk.
- **Proses yang berjalan sebelum Sysmon dipasang tidak punya event 1.** Di host yang Sysmon-nya baru dipasang, `services.exe` dan `explorer.exe` yang sudah jalan tidak akan pernah muncul sebagai simpul.
- **`ParentProcessGuid` adalah induk saat proses dibuat.** Bila induk mati, Windows tidak mengubah catatan itu, tetapi juga tidak ada hubungan baru. Teknik yang sengaja memutus hubungan induk, misalnya proses yang dibuat lewat perantara, membuat pohon terlihat rapi padahal eksekusi sebenarnya datang dari tempat lain.
- **PID boleh sama, GUID tidak.** Dua proses berbeda di rentang waktu yang sama bisa memakai `ProcessId` yang sama bila yang pertama sudah mati. Selalu kelompokkan dengan GUID, dan pakai PID hanya untuk tampilan.

Satu jembatan ke Day 03 yang sangat berguna: event 1 memuat `LogonId` dan `LogonGuid`, dan Microsoft menyebut GUID sesi disertakan supaya event dalam satu sesi logon bisa dikorelasikan [S1]. Logon ID di Day 03 untuk sesi `adm.rina` adalah `0x5a3f21c`. Dengan itu kamu bisa mengambil semua proses yang dibuat dalam sesi RDP itu saja, tanpa mencampur proses sesi lain di host yang sama. Format penulisan Logon ID di event Sysmon perlu dicek di lab-mu, dan samakan huruf besar-kecilnya dengan `lower()` seperti di Day 03 bagian 2.5.

### 1.4 Event 3: koneksi jaringan yang membawa nama prosesnya

Pertanyaan "apa yang dihubungi" biasanya dijawab firewall atau proxy. Bedanya, event 3 menyebutkan proses yang membuat koneksi.

Event 3 mencatat koneksi TCP dan UDP di host, mati secara default, dan setiap koneksi terhubung ke prosesnya lewat `ProcessId` dan `ProcessGuid`; event ini juga memuat nama host dan IP sumber serta tujuan, nomor port, dan status IPv6 [S1]. Deskripsi data source Splunk menambahkan bahwa event ini memuat metadata proses yang membuat koneksi [S3]. Field yang terekstrak add-on mencakup `SourceIp`, `SourcePort`, `DestinationIp`, `DestinationPort`, `DestinationHostname`, `DestinationPortName`, `Protocol`, `Initiated`, `Image`, `ProcessGuid`, dan `User`, dengan pemetaan CIM ke `src`, `dest`, `dest_port`, `transport`, `direction`, dan `app` [S3].

Tiga batas yang harus kamu ingat sebelum memakai event 3 sebagai pengganti log jaringan:

- **Tidak ada volume dan durasi.** Event 3 adalah catatan "koneksi ini dibuat", bukan flow record. Tidak ada jumlah byte, jumlah paket, atau lama sesi. Untuk pertanyaan eksfiltrasi berbasis volume, kamu tetap butuh firewall atau proxy (Day 05).
- **`DestinationHostname` berasal dari reverse lookup, bukan dari nama yang diminta aplikasi.** Nilainya bergantung pada entry `DnsLookup` di konfigurasi [S1]. Nama domain yang sebenarnya diminta ada di event 22.
- **Hanya host yang Sysmon-nya menyalakan `NetworkConnect`.** Di PT JAB, bila `JKT-DC01` memakai konfigurasi tanpa `NetworkConnect`, tidak ada event 3 dari DC walaupun host itu jelas berkomunikasi.

Nilai praktisnya tetap besar: dari satu `ProcessGuid` kamu bisa menjawab "apakah proses ini pernah keluar, ke mana, dan port apa", yang tidak bisa dijawab log firewall karena firewall hanya melihat IP host.

### 1.5 Event 10: satu proses membuka proses lain, termasuk LSASS

Ini bagian yang paling sering diminta L2 di insiden kredensial.

Event 10 melaporkan saat sebuah proses membuka proses lain, operasi yang biasanya dilanjutkan dengan query informasi atau membaca dan menulis address space proses target; Microsoft menyebut ini memungkinkan deteksi alat yang membaca memori proses seperti `lsass.exe` untuk mencuri kredensial, dan mengingatkan volumenya bisa besar bila ada utilitas diagnostik yang rutin membuka proses lain, sehingga sebaiknya dinyalakan dengan filter [S1]. Field intinya: `SourceImage`, `TargetImage`, `SourceProcessGUID`, `TargetProcessGUID`, `SourceProcessId`, `TargetProcessId`, `SourceThreadId`, `GrantedAccess`, dan `CallTrace` [S4].

`GrantedAccess` adalah bitmask, bukan kategori. Nilainya ditulis dalam heksadesimal, misalnya `0x1f3fff` di contoh event resmi yang memperlihatkan alat membuka `winlogon.exe` dengan hak sangat luas [S4]. Detection ESCU untuk akses LSASS versi 16 (8 September 2026) tidak lagi mencocokkan nilai utuh, tetapi memeriksa bit: nilai heksadesimal diubah ke desimal dengan `tonumber(replace(GrantedAccess,"0x",""),16)`, lalu `bit_and` dipakai untuk menguji `PROCESS_VM_READ` (16, yaitu `0x10`) dan `PROCESS_QUERY_LIMITED_INFORMATION` (4096, yaitu `0x1000`), dengan `PROCESS_QUERY_INFORMATION` (1024, yaitu `0x400`) boleh ada atau tidak [S11]. Logika itu menangkap pasangan nilai klasik `0x1010` dan `0x1410` sekaligus variannya, karena `0x1410` memang gabungan `0x1000`, `0x400`, dan `0x10`.

Kenapa ini penting dipahami, bukan dihafal: pencocokan nilai utuh gagal begitu alat meminta kombinasi hak yang sedikit berbeda, dan sebaliknya banyak akses sah ke LSASS juga punya bit baca memori. Halaman detection itu sendiri menyebut alat lain bisa mengakses LSASS untuk alasan yang sah, sehingga triage tetap diperlukan dan detection-nya menyediakan macro filter untuk pengecualian [S11]. Di PT JAB, kandidat pengecualian yang wajar adalah agen EDR, backup, dan alat monitoring; daftarnya harus dirawat sebagai lookup dengan pemilik, bukan ditulis langsung di dalam search.

`CallTrace` berisi tumpukan modul yang memicu akses, misalnya jalur lewat `ntdll.dll` dan `KERNELBASE.dll` sampai alamat yang tidak dikenali [S4]. Nilai utamanya bukan untuk filter, tetapi untuk cerita di tiket: akses yang berasal dari alamat tanpa modul yang dikenali lebih mencurigakan daripada akses yang jelas datang dari API resmi. Satu lagi: event 10 tidak memuat nama akun, hanya `user_id` berisi SID [S4], jadi jangan harap kolom user terisi.

### 1.6 Event 11 dan 13: file yang dibuat dan registry yang diubah

Setelah tahu proses mana yang mencurigakan, dua pertanyaan berikutnya adalah apa yang ia tinggalkan di disk dan apa yang ia ubah supaya bertahan.

Event 11 dicatat saat file dibuat atau ditimpa, dan Microsoft menyebutnya berguna untuk memantau lokasi autostart seperti folder Startup serta direktori temporary dan download yang sering dipakai malware saat infeksi awal [S1]. Field yang dipakai: `TargetFilename` (path file), `CreationUtcTime`, `Image` dan `ProcessGuid` (proses pembuat), serta `RuleName`; pemetaan CIM mengisi `file_name`, `file_path`, dan `file_create_time` [S5]. Contoh event resminya memperlihatkan proses di folder Downloads yang membuat file sertifikat di direktori yang sama [S5], pola yang sama bentuknya dengan script yang ditulis ke folder Temp.

Event 13 mencatat perubahan nilai registry (`EventType` bernilai `SetValue`), dengan `TargetObject` berisi path lengkap nilai registry dan `Details` berisi nilai yang ditulis [S1][S6]. Add-on memetakannya ke `registry_path`, `registry_key_name`, `registry_value_name`, `registry_value_data`, dan `registry_hive` [S6]. Ingat singkatan root key dari bagian 1.1 saat menulis filter.

Pasangan dua event ini menutup celah yang ditinggalkan Day 03. Di Day 03, service baru terlihat sebagai 7045 di log System dan scheduled task sebagai 4698, keduanya bergantung audit dan logging Windows. Event 13 memberi lapisan kedua: pembuatan service juga meninggalkan jejak di `HKLM\System\CurrentControlSet\Services\<nama>\ImagePath`, dan autostart klasik di `...\CurrentVersion\Run`. Bila 7045 hilang karena satu dan lain hal, event 13 bisa menyelamatkan rekonstruksi, dan sebaliknya.

Batasnya: event 12, 13, dan 14 hanya ada bila `RegistryEvent` dikonfigurasi, dan konfigurasi publik biasanya hanya memasukkan sebagian kunci registry yang menarik supaya volumenya masuk akal. Jadi "tidak ada event 13 untuk kunci itu" paling sering berarti kunci itu tidak termasuk daftar yang dipantau, bukan bahwa tidak ada perubahan.

### 1.7 Event 22: DNS query dengan nama proses peminta

Pertanyaan "nama apa yang diresolve" biasanya dijawab log resolver. Event 22 menjawabnya dari sisi host, lengkap dengan proses peminta.

Event 22 dihasilkan saat sebuah proses menjalankan query DNS, baik hasilnya sukses maupun gagal, dari cache maupun tidak [S1]. Deskripsi data source Splunk menyebut isinya domain yang diminta, IP sumber, tipe query, dan data respons [S7]. Field yang terekstrak: `QueryName`, `QueryStatus`, `QueryResults`, `Image`, `ProcessGuid`, dan `ProcessId`, dengan CIM `query`, `query_count`, `reply_code_id`, dan `src` [S7]. Contoh event resminya memperlihatkan proses sistem meminta sebuah nama dengan `QueryStatus` 9003 dan `QueryResults` kosong [S7]; kode status bukan nol berarti query gagal, dan arti tiap kode perlu dicocokkan ke daftar kode error DNS Windows sebelum dipakai di detection.

Nilai event 22 untuk investigasi ada pada gabungan nama dan proses. Log resolver tahu host mana yang bertanya, tetapi tidak tahu proses mana. Dari event 22 kamu bisa membedakan `powershell.exe` yang meminta nama eksternal dari browser yang melakukan hal yang sama. Karena query dari cache juga tercatat, event 22 kadang memuat nama yang tidak pernah terlihat di resolver internal.

Batasnya tiga: hanya host yang Sysmon-nya menyalakan `DnsQuery`, tidak ada di Windows 7 dan sebelumnya [S1], dan volumenya besar sehingga konfigurasi publik biasanya membuang nama-nama yang sangat ramai. Untuk pertanyaan yang mencakup seluruh jaringan termasuk perangkat tanpa Sysmon, log resolver internal tetap sumber utama (Day 05).

### 1.8 PowerShell: script block logging (4104) dan module logging (4103)

Pertanyaan terakhir L2 adalah isi script. Inilah yang tidak bisa dijawab command line proses saja, karena perintah yang terlihat sering hanya pembungkus berisi blob base64.

PowerShell menulis log operasinya ke event log Windows. Saat script block logging aktif, PowerShell mencatat isi semua script block yang diproses ke channel `Microsoft-Windows-PowerShell/Operational` sebagai event 4104 (`0x1008`) dengan level Verbose, Opcode `Create`, Task `CommandStart`, dan keyword `Runspace`; sekali dinyalakan, setiap sesi PowerShell baru ikut mencatat [S12]. Penyalaannya lewat Group Policy "Turn on PowerShell Script Block Logging" di Administrative Templates > Windows Components > Windows PowerShell, atau lewat registry dengan `EnableScriptBlockLogging` bernilai 1 di bawah `HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging` [S12]. Module logging dinyalakan lewat "Turn on Module Logging" dengan daftar module diisi `*` untuk semua module, atau `EnableModuleLogging` bernilai 1 dengan nilai `ModuleNames` berisi `*`; dokumentasi Splunk menyarankan menyalakan juga command line process auditing supaya 4688 ikut membawa command line, dan menyebut event yang perlu dicek untuk membuktikan logging berjalan adalah 4103, 4104, 4688 dengan nama proses PowerShell, dan 7045 dengan nama proses PowerShell [S16]. Module logging mencatat pemanggilan perintah dan sebagian isi script, jadi ia pelengkap, bukan pengganti 4104 [S15].

Empat perilaku 4104 yang menentukan cara kamu menulis search:

- **Script panjang dipecah menjadi beberapa event.** Pesan 4104 dimulai dengan teks "Creating Scriptblock text" diikuti nomor bagian dan total bagian, dan memuat ScriptBlock ID berbentuk GUID; bila satu script block terlalu besar untuk satu event ETW, PowerShell memecah script itu menjadi beberapa bagian [S14]. Di Splunk, bagian itu muncul sebagai field `MessageNumber`, `MessageTotal`, dan `ScriptBlockId`, bersama `ScriptBlockText` dan `Path` [S8]. Membaca satu event saja berarti membaca satu bagian script.
- **Sebagian script block dicatat walaupun fitur ini mati.** PowerShell otomatis mencatat script block yang isinya memuat pola yang sering dipakai script berbahaya, dan Microsoft menyebutnya catatan upaya terakhir, bukan pengganti logging penuh maupun antivirus; perilaku ini bisa dimatikan dengan menyetel `EnableScriptBlockLogging` ke 0 atau menonaktifkan policy-nya [S14]. Jadi adanya beberapa 4104 di sebuah host bukan bukti bahwa script block logging sudah aktif di host itu.
- **Isi script bisa memuat data sensitif.** Microsoft menyarankan menyalakan Protected Event Logging bila script block logging dipakai untuk hal selain diagnostik, karena kredensial dan data sensitif bisa ikut tertulis di event log [S12]. Bila itu dipakai, isi event terenkripsi dengan standar CMS dan harus didekripsi dengan kunci privat di tempat yang aman; dokumentasi Splunk menyebut Splunk Enterprise tidak mendukung protected event logging, sehingga event harus didekripsi sebelum masuk [S12][S16]. Di Splunk, index `powershell` perlu pembatasan akses dengan alasan yang sama seperti command line di Day 03 (Day 44).
- **PowerShell 7 menulis ke channel lain.** Untuk PowerShell 7, log berada di grup Application and Services Logs dengan nama `PowerShellCore`, event 4104 ditulis ke `PowerShellCore/Operational`, dan policy-nya ada di Administrative Templates > PowerShell Core; provider-nya pun harus diregistrasi dulu dengan `$PSHOME\RegisterManifest.ps1` sebelum event bisa ditulis [S13]. Host yang sudah memakai PowerShell 7 tidak akan menambah event di channel Windows PowerShell.

Soal volume, Splunk Threat Research menyebut script block logging menghasilkan data yang sangat banyak, sehingga pendekatan hunting mereka tidak terlalu selektif pada keyword dan memakai skor untuk memunculkan script yang menarik; contoh bobot yang mereka sebut adalah `$DoIt` (fungsi Cobalt Strike) dengan fidelity tinggi dan `IEX` dengan bobot rendah karena terlalu umum [S15]. Pola indikator lain yang mereka pakai antara lain `GetProcAddress`, isi base64, `system.management.automation.amsi`, `system.reflection.assembly`, mutex, dan pemakaian memory stream [S15]. Mereka juga memilih 4104 sebagai fokus karena memberi visibilitas paling rinci atas script yang dieksekusi di endpoint [S15].

## 2. Contoh SPL dan langkah praktis

Semua keluaran di bagian ini adalah keluaran ilustrasi, bukan hasil eksekusi. Asumsi PT JAB: index `sysmon` dan `powershell`, Splunk Add-on for Sysmon 5.0.1, Splunk Add-on for Microsoft Windows 11.0.3, format XML, Splunk Enterprise 10.6, tanpa ES. Rentang waktu memakai jam absolut karena investigasinya terikat satu malam, bukan karena datanya statis.

### 2.1 Cek cakupan dulu: host mana yang punya Sysmon dan event apa yang masuk

Sebelum menjawab apa pun, pastikan host yang diinvestigasi memang mengirim event yang kamu butuhkan.

**Tujuan:** inventaris event Sysmon per source dan event ID dalam 24 jam terakhir.

```
index=sysmon earliest=-24h
| stats count dc(host) AS jumlah_host BY source EventCode
| sort source - count
```

| Bagian | Penjelasan |
|---|---|
| `index=sysmon earliest=-24h` | Filter paling murah: index dan waktu di awal pipeline |
| `BY source EventCode` | Satu baris per kombinasi channel dan jenis event |
| `dc(host)` | Berapa host yang benar-benar mengirim event itu, bukan hanya berapa event |
| `sort source - count` | Event terbanyak di atas untuk tiap channel |

Keluaran ilustrasi:

```
source                                              EventCode  count     jumlah_host
XmlWinEventLog:Microsoft-Windows-Sysmon/Operational  1          1412880   214
XmlWinEventLog:Microsoft-Windows-Sysmon/Operational  3          980114    198
XmlWinEventLog:Microsoft-Windows-Sysmon/Operational  11         655201    214
XmlWinEventLog:Microsoft-Windows-Sysmon/Operational  22         410233    186
XmlWinEventLog:Microsoft-Windows-Sysmon/Operational  13         88402     214
XmlWinEventLog:Microsoft-Windows-Sysmon/Operational  10         12044     31
```

**Cara membaca hasil:** event 1, 11, dan 13 datang dari 214 host, sedangkan event 3 dari 198 dan event 22 dari 186. Selisihnya adalah host dengan konfigurasi tanpa `NetworkConnect` atau `DnsQuery`, dan itu harus ditulis di tiket sebagai batas bukti. Event 10 hanya dari 31 host: kemungkinan sengaja dibatasi ke server penting karena volumenya. Jumlah host juga alat cek cepat kalau konfigurasi baru disebar: event yang hanya muncul dari sedikit host berarti konfigurasinya belum merata.
**Variasi (host yang ada di Windows log tetapi tidak di Sysmon):**

```
| tstats count where (index=sysmon OR index=wineventlog) earliest=-24h BY index host
| chart sum(count) OVER host BY index
| fillnull value=0
| where sysmon = 0
```

`tstats` di sini aman karena `index` dan `host` adalah indexed field (Day 25). Hasilnya daftar host seperti `JKT-WS-0412` yang mengirim Windows Security tetapi belum punya Sysmon.
**Kapan gagal:** `EventCode` bukan indexed field, jadi inventaris per event ID tidak bisa dipercepat dengan `tstats`; pada index besar jalankan di rentang lebih pendek. Bila data lama memakai sourcetype gaya lama, tambahkan `sourcetype=*sysmon*` ke filter atau cek dengan `| stats count BY sourcetype`.

### 2.2 Naik ke akar: dari satu proses ke induknya

L2 mulai dari satu proses yang sudah diketahui dari Day 03, yaitu `net.exe` yang menjalankan `net group`.

**Tujuan:** menemukan induk langsung sebuah proses dengan mencocokkan `ParentProcessGuid` ke `ProcessGuid`.

```
index=sysmon source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 host=JKT-JUMP01
    earliest="10/14/2026:01:45:00" latest="10/14/2026:03:00:00"
    [ search index=sysmon source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
        host=JKT-JUMP01 Image="*\\net.exe"
        earliest="10/14/2026:01:45:00" latest="10/14/2026:03:00:00"
      | fields ParentProcessGuid
      | rename ParentProcessGuid AS ProcessGuid
      | format ]
| table _time Image CommandLine ProcessGuid ParentProcessGuid ParentImage User IntegrityLevel
```

- Subsearch dijalankan lebih dulu: ia mengambil `ParentProcessGuid` dari semua `net.exe`, mengganti namanya menjadi `ProcessGuid`, lalu `format` mengubahnya menjadi kondisi filter untuk search luar.
- `rename` di dalam subsearch adalah intinya. Tanpa itu, filter yang dihasilkan mencari `ParentProcessGuid`, bukan `ProcessGuid`, sehingga kamu mendapat saudara-saudaranya, bukan induknya.
- Rentang waktu ditulis di dua tempat, karena subsearch tidak otomatis mewarisi rentang search luar.

Keluaran ilustrasi:

```
_time                Image                             CommandLine                  ProcessGuid                             ParentProcessGuid                       ParentImage                        User          IntegrityLevel
2026-10-14 01:54:02  C:\Windows\System32\cmd.exe       "C:\Windows\system32\cmd.exe" {9b2f1d6e-5c2e-690e-2b00-000000002a00}  {9b2f1d6e-5c17-690e-1a00-000000002a00}  C:\Windows\explorer.exe            JAB\adm.rina  High
```

**Cara membaca hasil:** induk `net.exe` adalah `cmd.exe` yang dibuat 01:54:02 oleh `explorer.exe`, berjalan sebagai `JAB\adm.rina` dengan integrity High. Integrity High cocok dengan 4672 di Day 03: sesi itu memang elevated. Untuk naik satu tingkat lagi, ulangi search yang sama dengan `Image="*\\cmd.exe"` di subsearch, atau langsung pakai `ProcessGuid` induknya.
**Variasi:** ganti isi subsearch dengan `ProcessGuid="{...}"` dan hapus `rename` bila kamu sudah punya GUID anak dan hanya ingin induknya.
**Kapan gagal:** subsearch punya batas jumlah hasil dan waktu jalan; bila proses yang dicari muncul ribuan kali, kumpulkan GUID-nya dulu lalu tempel manual. Bila induk dibuat sebelum rentang waktu, barisnya tidak ada walaupun `ParentProcessGuid` di anak terisi; lebarkan rentang sebelum menyimpulkan.

### 2.3 Tabel satu tingkat untuk seluruh sesi, lalu disusun menjadi pohon

Menaiki pohon satu per satu lambat. Untuk sesi yang sudah diketahui, lebih cepat menarik semua simpul sekaligus.

**Tujuan:** satu baris per proses dalam rentang investigasi, berisi nama proses, nama induk, kedua GUID, dan perintahnya.

```
index=sysmon source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 host=JKT-JUMP01
    earliest="10/14/2026:01:45:00" latest="10/14/2026:03:00:00"
| rex field=Image "\x5c(?<nama>[^\x5c]+)$"
| rex field=ParentImage "\x5c(?<induk>[^\x5c]+)$"
| eval jam=strftime(_time, "%H:%M:%S")
| table jam induk ParentProcessGuid nama ProcessGuid User IntegrityLevel CommandLine
| sort jam
```

| Bagian | Penjelasan |
|---|---|
| `rex field=Image "\x5c(?<nama>[^\x5c]+)$"` | Ambil nama file dari path. `\x5c` adalah backslash dalam notasi hex, jadi kamu tidak perlu berurusan dengan berlapis-lapis escape [S17] |
| `[^\x5c]+$` | Satu atau lebih karakter bukan backslash di akhir string, yaitu nama file |
| `eval jam=strftime(...)` | Kolom waktu yang pendek supaya tabel terbaca |
| `sort jam` | Urut waktu, sehingga induk hampir selalu berada di atas anaknya |

Keluaran ilustrasi (kolom `CommandLine` dipotong agar terbaca):

```
jam       induk            ParentProcessGuid                       nama             ProcessGuid                             User          IntegrityLevel  CommandLine
01:53:11  userinit.exe     {9b2f1d6e-5c05-690e-0900-000000002a00}  explorer.exe     {9b2f1d6e-5c17-690e-1a00-000000002a00}  JAB\adm.rina  High            C:\Windows\Explorer.EXE
01:54:02  explorer.exe     {9b2f1d6e-5c17-690e-1a00-000000002a00}  cmd.exe          {9b2f1d6e-5c2e-690e-2b00-000000002a00}  JAB\adm.rina  High            "C:\Windows\system32\cmd.exe"
01:57:05  cmd.exe          {9b2f1d6e-5c2e-690e-2b00-000000002a00}  net.exe          {9b2f1d6e-5d41-690e-3c00-000000002a00}  JAB\adm.rina  High            net group "Domain Admins" budi.santoso /add /domain
01:57:05  net.exe          {9b2f1d6e-5d41-690e-3c00-000000002a00}  net1.exe         {9b2f1d6e-5d41-690e-4d00-000000002a00}  JAB\adm.rina  High            C:\Windows\system32\net1 group ...
01:58:40  cmd.exe          {9b2f1d6e-5c2e-690e-2b00-000000002a00}  powershell.exe   {9b2f1d6e-5d9c-690e-5e00-000000002a00}  JAB\adm.rina  High            powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4A...
```

**Cara membaca hasil:** satu rantai utuh terlihat, `explorer.exe` lalu `cmd.exe` lalu dua anak, `net.exe` dan `powershell.exe`. Baris `net1.exe` adalah perilaku normal Windows: `net.exe` memanggil `net1.exe` untuk mengerjakan subcommand, jadi jangan dilaporkan sebagai temuan terpisah. Baris terakhir adalah yang paling penting: `powershell.exe` dengan `-nop -w hidden -enc`, yaitu tanpa profil, jendela tersembunyi, dan perintah terenkode. Blob base64-nya bisa didekode dengan pola di Day 11 bagian 2.1, tetapi isi sebenarnya lebih baik diambil dari 4104 di bagian 2.8.
**Variasi (hanya proses dari satu sesi logon):** tambahkan `LogonId` ke filter untuk memisahkan sesi `adm.rina` dari sesi lain di host yang sama, misalnya `| where lower(LogonId) = "0x5a3f21c"`. Cek dulu format penulisan `LogonId` di data-mu, karena ia bisa tersimpan sebagai heksadesimal atau desimal.
**Variasi (pohon siap baca):** bila app PSTree terpasang, Lantern memakai pola `| pstree child=child parent=parent detail=detail` dengan `child` dan `parent` berisi nama proses beserta PID-nya [S17]. App itu tidak didukung resmi, jadi jangan menggantungkan proses kerja padanya.
**Kapan gagal:** bila add-on sudah mengisi `process_name` dan `parent_process_name`, dua `rex` di atas tidak perlu; pakai field CIM itu saja. Di data lama tanpa field CIM, `rex` inilah jalan keluarnya. Proses yang dibuat sebelum rentang waktu tidak punya baris, sehingga rantai bisa terlihat terputus di tengah.

### 2.4 Apa yang dihubungi proses itu

Sekarang ikuti `ProcessGuid` PowerShell ke event lain. Mulai dari jaringan.

**Tujuan:** merangkum koneksi keluar dari satu proses, dengan perintahnya ikut tampil tanpa `join`.

```
index=sysmon source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" host=JKT-JUMP01
    EventCode IN (1, 3) earliest="10/14/2026:01:45:00" latest="10/14/2026:03:00:00"
| stats values(eval(if(EventCode=1, CommandLine, null()))) AS perintah
        values(eval(if(EventCode=3, DestinationIp.":".DestinationPort, null()))) AS tujuan
        values(eval(if(EventCode=3, DestinationHostname, null()))) AS nama_tujuan
        values(eval(if(EventCode=3, Initiated, null()))) AS keluar
        count(eval(EventCode=3)) AS n_koneksi
        min(_time) AS mulai BY ProcessGuid Image
| where n_koneksi > 0
| eval mulai=strftime(mulai, "%H:%M:%S")
| sort mulai
```

| Bagian | Penjelasan |
|---|---|
| `EventCode IN (1, 3)` | Operator `IN` di command `search`; dua jenis event ditarik sekali jalan |
| `values(eval(if(...)))` | Ambil nilai hanya dari event yang sesuai, sehingga satu `stats` menggantikan `join` |
| `BY ProcessGuid Image` | Pengelompokan berdasarkan identitas proses, bukan PID |
| `count(eval(EventCode=3))` lalu `where n_koneksi > 0` | Buang proses yang tidak pernah membuat koneksi |

Keluaran ilustrasi:

```
ProcessGuid                             Image                                                        perintah                                          tujuan              nama_tujuan              keluar  n_koneksi  mulai
{9b2f1d6e-5d9c-690e-5e00-000000002a00}  C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe    powershell.exe -nop -w hidden -enc SQBFAFgA...    203.0.113.77:443    cdn-update.example.net   true    6          01:58:40
```

**Cara membaca hasil:** proses PowerShell yang sama dengan bagian 2.3 membuat enam koneksi keluar ke `203.0.113.77` port 443 mulai 01:59. `Initiated` bernilai true berarti host ini yang memulai, bukan menerima. Kolom `perintah` ikut terisi karena event 1 dan event 3 berbagi `ProcessGuid`: inilah manfaat GUID yang tidak bisa diberikan PID.
**Variasi:** untuk mencari proses yang tidak lazim membuka koneksi di seluruh fleet, hilangkan filter host dan pakai `stats dc(dest_ip) AS tujuan_unik count BY process_name` lalu bandingkan dengan daftar proses yang biasa keluar.
**Kapan gagal:** bila `NetworkConnect` tidak aktif di host itu, hasilnya kosong walaupun koneksi jelas ada; buktikan dengan bagian 2.1. Tidak ada kolom byte atau durasi di event 3, jadi pertanyaan "berapa banyak data yang keluar" harus dijawab log firewall atau proxy (Day 05). `DestinationHostname` kosong bila `DnsLookup` dimatikan.

### 2.5 Siapa menyentuh LSASS

Pertanyaan kredensial dijawab event 10, dengan cara membaca bit, bukan mencocokkan nilai.

**Tujuan:** menemukan proses yang membuka `lsass.exe` dengan hak baca memori.

```
index=sysmon source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=10
    TargetImage="*\\lsass.exe" earliest=-24h
| eval akses=tonumber(replace(GrantedAccess, "0x", ""), 16)
| eval vm_read=bit_and(akses, 16)
| eval query_limited=bit_and(akses, 4096)
| where vm_read == 16 AND query_limited == 4096
| stats count min(_time) AS pertama max(_time) AS terakhir values(GrantedAccess) AS hak
        values(SourceProcessGUID) AS guid_sumber BY dest SourceImage TargetImage
| eval pertama=strftime(pertama, "%Y-%m-%d %H:%M:%S"), terakhir=strftime(terakhir, "%Y-%m-%d %H:%M:%S")
| sort - count
```

| Bagian | Penjelasan |
|---|---|
| `TargetImage="*\\lsass.exe"` | Hanya akses ke LSASS; wildcard di depan karena path bisa berbeda |
| `tonumber(replace(GrantedAccess, "0x", ""), 16)` | Buang awalan `0x` lalu baca sisanya sebagai heksadesimal |
| `bit_and(akses, 16)` | Uji bit `PROCESS_VM_READ` (`0x10`) |
| `bit_and(akses, 4096)` | Uji bit `PROCESS_QUERY_LIMITED_INFORMATION` (`0x1000`) |
| `where vm_read == 16 AND query_limited == 4096` | Keduanya harus ada; pola ini menangkap `0x1010` dan `0x1410` sekaligus [S11] |

Keluaran ilustrasi:

```
dest        SourceImage                                                  TargetImage                   count  pertama              terakhir             hak      guid_sumber
JKT-JUMP01  C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe    C:\Windows\system32\lsass.exe  1      2026-10-14 02:00:31  2026-10-14 02:00:31  0x1410   {9b2f1d6e-5d9c-690e-5e00-000000002a00}
```

**Cara membaca hasil:** `guid_sumber` sama dengan `ProcessGuid` PowerShell di bagian 2.3 dan 2.4. Satu proses yang sama membuat koneksi keluar lalu membuka memori LSASS pada 02:00:31. Itu bukan lagi perubahan grup biasa, melainkan dugaan credential access, dan sudah cukup untuk mengangkat tiket ke penanganan insiden. Ambil juga `CallTrace` event itu untuk tiket.
**Variasi (menurunkan noise):** tambahkan daftar proses sah lewat lookup, misalnya `| search NOT [| inputlookup lsass_akses_sah.csv | fields SourceImage | format ]`, dan rawat lookup itu dengan pemilik yang jelas (Day 12 untuk lookup).
**Kapan gagal:** bila `ProcessAccess` tidak dikonfigurasi, tidak ada event 10 sama sekali. Bila dikonfigurasi tanpa filter, agen EDR dan alat monitoring menghasilkan ribuan baris; detection resmi pun menyediakan macro filter untuk pengecualian [S11]. Event 10 tidak memuat nama akun, hanya SID di `user_id` [S4], jadi jangan harap kolom user terisi. Akses yang hanya membaca informasi proses tanpa bit baca memori tidak akan muncul, dan itu memang disengaja.

### 2.6 File dan registry yang berubah dari proses yang sama

Pertanyaan berikutnya: apa yang ditinggalkan proses itu.

**Tujuan:** menampilkan file yang dibuat dan nilai registry yang diubah oleh satu proses dalam satu tabel.

```
index=sysmon source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" host=JKT-JUMP01
    EventCode IN (11, 13) ProcessGuid="{9b2f1d6e-5d9c-690e-5e00-000000002a00}"
    earliest="10/14/2026:01:45:00" latest="10/14/2026:03:00:00"
| eval jenis=case(EventCode=11, "file dibuat", EventCode=13, "registry ".EventType)
| eval objek=case(EventCode=11, TargetFilename, EventCode=13, TargetObject)
| eval isi=case(EventCode=11, CreationUtcTime, EventCode=13, Details)
| table _time jenis objek isi RuleName
| sort _time
```

- `case(...)` dipakai dua kali supaya satu kolom `objek` berisi path file atau path registry sesuai jenis event.
- `RuleName` disertakan karena ia menyebutkan aturan konfigurasi Sysmon yang membuat event itu tercatat, yang membantu menjelaskan kenapa sebuah perubahan muncul dan yang lain tidak.
- Filter `ProcessGuid` membuat hasil terbatas pada satu proses; tanpa itu, event 11 di host sibuk bisa ratusan ribu baris.

Keluaran ilustrasi:

```
_time                jenis                objek                                                                          isi                                                                      RuleName
2026-10-14 02:01:05  file dibuat          C:\Users\adm.rina\AppData\Local\Temp\svc-update.ps1                            2026-10-14 02:01:05.112                                                  TempScripts
2026-10-14 02:02:50  registry SetValue    HKU\S-1-5-21-...-1174\Software\Microsoft\Windows\CurrentVersion\Run\OneDrvSync  "powershell.exe -ep bypass -w hidden -f C:\Users\adm.rina\...\svc-update.ps1"  AutorunRun
```

**Cara membaca hasil:** proses yang sama menulis script ke folder Temp lalu memasang autostart yang menjalankan script itu. Ini pasangan klasik drop plus persistence, dan cocok dengan task `\OneDriveSyncCheck` yang muncul sebagai 4698 di Day 03: dua jalur persistence sekaligus, satu lewat Run key dan satu lewat scheduled task.
**Variasi (persistence di seluruh host):**

```
index=sysmon source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13 earliest=-24h
    (TargetObject="*\\CurrentVersion\\Run*" OR TargetObject="*\\CurrentControlSet\\Services\\*\\ImagePath")
| stats count values(Details) AS nilai values(Image) AS proses min(_time) AS pertama BY dest TargetObject
```

Hasilnya juga menjadi lapisan kedua untuk 7045 di Day 03: service baru biasanya meninggalkan jejak di `ImagePath`.
**Kapan gagal:** `RegistryEvent` dan `FileCreate` yang tidak dikonfigurasi berarti tidak ada event, dan konfigurasi publik biasanya hanya memasukkan sebagian kunci yang menarik. Microsoft hanya menjamin nilai bertipe DWORD dan QWORD yang direkam di `Details` [S1], jadi untuk nilai bertipe lain cek di lab apakah isinya benar-benar tampil. Search yang mencari `HKEY_LOCAL_MACHINE` tidak cocok karena Sysmon memakai singkatan `HKLM`.

### 2.7 Nama yang diresolve oleh proses itu

Event 22 melengkapi gambar: nama apa yang diminta, bukan hanya IP yang dihubungi.

**Tujuan:** merangkum query DNS per proses di satu host, termasuk yang gagal.

```
index=sysmon source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=22 host=JKT-JUMP01
    earliest="10/14/2026:01:45:00" latest="10/14/2026:03:00:00"
| stats count min(_time) AS pertama values(QueryStatus) AS status values(QueryResults) AS hasil
        BY Image QueryName
| eval pertama=strftime(pertama, "%H:%M:%S")
| sort pertama
```

- `BY Image QueryName`: pasangan proses dan nama. Satu nama yang diminta banyak proses berbeda punya arti berbeda dari satu proses yang meminta banyak nama.
- `values(QueryStatus)`: kode hasil; nilai bukan nol berarti query gagal, dan artinya dicocokkan ke daftar kode error DNS Windows [S7].
- `values(QueryResults)`: jawaban yang diterima proses, berguna saat resolver internal tidak mencatat nama itu karena jawabannya datang dari cache.

Keluaran ilustrasi:

```
Image                                                        QueryName                 count  pertama   status  hasil
C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe    cdn-update.example.net    3      01:59:12  0       203.0.113.77
C:\Program Files\Internal\agent\agent.exe                    telemetry.jab.example     41     01:45:08  0       10.20.8.21
C:\Windows\System32\svchost.exe                              wpad.corp.jab.example     12     01:46:02  9003    -
```

**Cara membaca hasil:** `cdn-update.example.net` diminta oleh `powershell.exe` dan jawabannya `203.0.113.77`, IP yang sama dengan tujuan koneksi di bagian 2.4. Dua temuan itu saling mengunci: nama domain untuk dicari di threat intel, dan IP untuk diblokir. Baris `wpad` dengan status 9003 adalah noise jaringan biasa, bukan temuan.
**Variasi (label subdomain panjang di seluruh fleet):**

```
index=sysmon source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=22 earliest=-24h
| rex field=QueryName "^(?<label>[^\.]+)\."
| eval panjang=len(label)
| where panjang >= 30
| stats count dc(dest) AS n_host values(Image) AS proses BY QueryName
| sort - count
```

Label pertama yang sangat panjang adalah pola klasik tunneling atau exfiltrasi lewat DNS. Ambang 30 karakter adalah titik awal; ukur dulu distribusi panjang label di jaringanmu sendiri sebelum menetapkannya.
**Kapan gagal:** host tanpa `DnsQuery` di konfigurasi tidak menghasilkan event 22, dan Windows 7 atau lebih lama tidak punya telemetry-nya [S1]. Volume event 22 besar sehingga konfigurasi sering membuang nama yang ramai; untuk pertanyaan lintas jaringan termasuk perangkat tanpa Sysmon, pakai log resolver internal (Day 05).

### 2.8 Isi script PowerShell: menyatukan 4104 yang terpecah

Sekarang pertanyaan terakhir L2. Blob base64 di command line tidak perlu didekode manual kalau script block logging aktif.

**Tujuan:** menyusun kembali isi script dari beberapa event 4104 per `ScriptBlockId`.

```
index=powershell source="XmlWinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4104
    host=JKT-JUMP01 earliest="10/14/2026:01:45:00" latest="10/14/2026:03:00:00"
| eval nomor=tonumber(MessageNumber), total=tonumber(MessageTotal)
| sort 0 ScriptBlockId nomor
| stats min(_time) AS mulai max(total) AS bagian_total list(ScriptBlockText) AS bagian
        values(Path) AS path BY host ScriptBlockId
| eval script=mvjoin(bagian, "")
| eval panjang=len(script)
| eval mulai=strftime(mulai, "%H:%M:%S")
| table mulai host ScriptBlockId bagian_total panjang path script
| sort mulai
```

| Bagian | Penjelasan |
|---|---|
| `nomor`, `total` | `MessageNumber` dan `MessageTotal` diubah ke angka supaya bisa diurutkan dengan benar |
| `sort 0 ScriptBlockId nomor` | Urutkan bagian script sesuai nomornya; `0` menghilangkan batas 10.000 baris pada `sort` |
| `list(ScriptBlockText)` | `list()` mempertahankan urutan hasil `sort`, berbeda dengan `values()` yang mengurutkan dan membuang duplikat |
| `mvjoin(bagian, "")` | Rangkai bagian menjadi satu teks tanpa pemisah |
| `BY host ScriptBlockId` | Satu baris per script block; `ScriptBlockId` adalah pengikatnya [S8] |

Keluaran ilustrasi (kolom `script` dipotong):

```
mulai     host        ScriptBlockId                           bagian_total  panjang  path  script
01:58:41  JKT-JUMP01  a4d7c2e1-93f8-4a6b-9c11-77e0b5d2f014    3             61244    -     function New-Mutex { ... } $b=[System.Convert]::FromBase64String("...") ; [System.Reflection.Assembly]::Load($b) ...
01:58:44  JKT-JUMP01  c81b55a0-2e4f-4d19-8b73-0a9f1c66d2aa    1             212      -     Get-ChildItem C:\Users\adm.rina\Documents -Recurse | Measure-Object
```

**Cara membaca hasil:** script block pertama terdiri dari tiga bagian dan panjangnya lebih dari 61 ribu karakter; membaca satu event saja akan memberi kesan script pendek dan tidak berbahaya. Setelah disatukan, isinya memuat `FromBase64String` dan `Reflection.Assembly.Load`, yaitu memuat kode ke memori, pola yang memang dipakai Splunk Threat Research sebagai indikator [S15]. `Path` berisi `-` karena script dijalankan dari memori, bukan dari file di disk; script dari file akan memperlihatkan path-nya. Script block kedua tidak berbahaya dan justru berguna sebagai pembanding.
**Variasi (skor keyword untuk hunting):** tambahkan setelah `eval script=...`:

```
| eval s=lower(script)
| eval skor=if(match(s, "frombase64string"), 3, 0)
      + if(match(s, "system\.reflection\.assembly"), 3, 0)
      + if(match(s, "downloadstring|invoke-webrequest|net\.webclient"), 2, 0)
      + if(match(s, "\biex\b|invoke-expression"), 2, 0)
      + if(match(s, "-enc|-encodedcommand"), 2, 0)
| where skor >= 4
| table mulai host ScriptBlockId skor panjang script
```

Bobotnya mengikuti cara Splunk Threat Research: indikator spesifik diberi bobot tinggi, indikator umum seperti `IEX` diberi bobot rendah karena terlalu sering muncul di pekerjaan sah [S15].
**Variasi (module logging):** 4103 tidak punya halaman data source resmi, jadi cek dulu field yang terisi sebelum menulis search serius:

```
index=powershell source="XmlWinEventLog:Microsoft-Windows-PowerShell/Operational" EventCode=4103
    host=JKT-JUMP01 earliest=-24h
| fieldsummary maxvals=3
| table field count distinct_count values
```

**Kapan gagal:** bila script block logging tidak aktif, yang muncul hanya sebagian script yang isinya mirip pola berbahaya sebagai catatan upaya terakhir [S14], sehingga hasil search terlihat sepi padahal aktivitas PowerShell banyak. Bila protected event logging dipakai, isi `ScriptBlockText` terenkripsi dan harus didekripsi sebelum masuk Splunk [S12][S16]. `list()` dibatasi 100 nilai, jadi script dengan lebih dari 100 bagian tidak lengkap; untuk kasus itu tampilkan per bagian. Host yang memakai PowerShell 7 menulis ke channel `PowerShellCore/Operational`, bukan ke channel ini [S13]. Perhatikan juga batas panjang event di Splunk: bila `ScriptBlockText` sangat panjang, cek setelan truncate untuk sourcetype itu sebelum menyimpulkan script terpotong di sumber.

### 2.9 Satu linimasa untuk tiket

Langkah terakhir: gabungkan tiga index menjadi satu urutan waktu yang bisa ditempel ke tiket.

**Tujuan:** linimasa satu host dari Windows Security, Sysmon, dan PowerShell dalam satu tabel.

```
index IN (wineventlog, sysmon, powershell) host=JKT-JUMP01
    earliest="10/14/2026:01:45:00" latest="10/14/2026:03:00:00"
    EventCode IN (4624, 4672, 4698, 1, 3, 10, 11, 13, 22, 4104)
| eval ringkas=case(
    EventCode=4624, "logon type ".LogonType." dari ".IpAddress." (".TargetUserName.")",
    EventCode=4672, "hak istimewa untuk sesi ".SubjectLogonId,
    EventCode=4698, "task baru: ".TaskName,
    EventCode=1, "proses: ".Image." :: ".CommandLine,
    EventCode=3, "koneksi: ".DestinationIp.":".DestinationPort,
    EventCode=10, "akses proses: ".SourceImage." ke ".TargetImage." (".GrantedAccess.")",
    EventCode=11, "file: ".TargetFilename,
    EventCode=13, "registry: ".TargetObject,
    EventCode=22, "dns: ".QueryName,
    EventCode=4104, "script block ".MessageNumber."/".MessageTotal." id ".ScriptBlockId)
| table _time index EventCode ringkas
| sort _time
```

- `index IN (...)`: tiga index sekaligus; tanpa itu kamu harus menyalin hasil dari tiga search berbeda.
- `case(...)` panjang adalah intinya: setiap jenis event diringkas menjadi satu kalimat pendek sehingga linimasa bisa dibaca orang yang tidak hafal field.
- Urutan event ID di `case` tidak perlu sama dengan di filter, tetapi keduanya harus memuat himpunan yang sama; event yang tidak ada di `case` akan menghasilkan `ringkas` kosong.

Keluaran ilustrasi (dipotong):

```
_time                index        EventCode  ringkas
2026-10-14 01:52:07  wineventlog  4624       logon type 10 dari 10.30.14.22 (adm.rina)
2026-10-14 01:52:07  wineventlog  4672       hak istimewa untuk sesi 0x5a3f21c
2026-10-14 01:54:02  sysmon       1          proses: C:\Windows\System32\cmd.exe :: "C:\Windows\system32\cmd.exe"
2026-10-14 01:57:05  sysmon       1          proses: C:\Windows\System32\net.exe :: net group "Domain Admins" budi.santoso /add /domain
2026-10-14 01:58:40  sysmon       1          proses: ...\powershell.exe :: powershell.exe -nop -w hidden -enc SQBFAFgA...
2026-10-14 01:58:41  powershell   4104       script block 1/3 id a4d7c2e1-93f8-4a6b-9c11-77e0b5d2f014
2026-10-14 01:59:12  sysmon       22         dns: cdn-update.example.net
2026-10-14 01:59:14  sysmon       3          koneksi: 203.0.113.77:443
2026-10-14 02:00:31  sysmon       10         akses proses: ...\powershell.exe ke C:\Windows\system32\lsass.exe (0x1410)
2026-10-14 02:01:05  sysmon       11         file: C:\Users\adm.rina\AppData\Local\Temp\svc-update.ps1
2026-10-14 02:02:50  sysmon       13         registry: HKU\...\CurrentVersion\Run\OneDrvSync
2026-10-14 02:03:40  wineventlog  4698       task baru: \OneDriveSyncCheck
```

**Cara membaca hasil:** urutannya menjelaskan dirinya sendiri, dari logon RDP sampai persistence. Linimasa seperti ini yang dibaca orang di luar SOC, jadi simpan di tiket apa adanya, lalu tambahkan satu paragraf kesimpulan di atasnya.
**Variasi:** tambahkan `| eval urut=strftime(_time, "%H:%M:%S")` dan `| fields urut index EventCode ringkas` supaya tabel lebih sempit saat ditempel ke tiket, atau tambahkan `host` bila linimasanya mencakup lebih dari satu host.
**Kapan gagal:** nama field berbeda per sumber, jadi `case` harus disesuaikan dengan field yang benar-benar ada di instance-mu; field yang tidak ada membuat hasil `case` kosong, bukan error. Rentang waktu yang lebar pada tiga index sekaligus bisa berat; sempitkan ke jam kejadian. Bila jam host tidak sinkron, urutan di linimasa bisa menipu; bandingkan `_time` dan `_indextime` bila ada kejanggalan.

**Ringkasan untuk tiket SOC-2026-0217:** sesi RDP `adm.rina` di `JKT-JUMP01` menjalankan `cmd.exe` lalu dua anak, `net.exe` (menambahkan `budi.santoso` ke Domain Admins) dan `powershell.exe` dengan perintah terenkode dan jendela tersembunyi. Proses PowerShell itu, `ProcessGuid` `{9b2f1d6e-5d9c-690e-5e00-000000002a00}`, memuat kode ke memori lewat `Reflection.Assembly.Load`, meresolve `cdn-update.example.net`, membuat enam koneksi ke `203.0.113.77:443`, membuka memori `lsass.exe` dengan `GrantedAccess` `0x1410`, menulis `svc-update.ps1` ke folder Temp, dan memasang autostart di Run key, sementara task `\OneDriveSyncCheck` dibuat pada 02:03. Dugaan credential access membuat tiket ini naik dari triage ke penanganan insiden. Batas bukti yang harus ditulis di tiket: `JKT-WS-0412` tidak punya Sysmon sehingga pergerakan ke host itu tidak terpantau dengan cara yang sama, dan event 10 hanya aktif di sebagian host.

## 3. Lab praktik

Lab memakai dua sumber: BOTS v3 (dataset statis dengan penamaan sourcetype gaya lama) dan VM Windows lab terisolasi milikmu dengan snapshot. Semua perintah Windows dan PowerShell di bawah dijalankan di VM lab, bukan di mesin kerja, dan semua nama domain memakai rentang dokumentasi.

1. **Rentang waktu BOTS v3.** Jalankan `| tstats min(_time) AS awal max(_time) AS akhir where index=botsv3 sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" earliest=0 | eval awal=strftime(awal, "%F %T"), akhir=strftime(akhir, "%F %T")`. Catat rentangnya dan pakai di semua search berikutnya. Repo dataset memang menyarankan `earliest=0` supaya time picker tidak menyembunyikan event [S18].
2. **Inventaris event.** Dengan rentang dari langkah 1, jalankan `index=botsv3 sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational" | stats count BY EventCode | sort - count`. Catat event ID mana yang ada dan mana yang tidak: itu cerminan konfigurasi Sysmon pembuat dataset.
3. **Process tree di data nyata.** Pilih satu event `EventCode=1` dengan `Image` berisi `powershell.exe`, catat `ProcessGuid` dan `ParentProcessGuid`, lalu naik ke atas sampai menemukan proses yang induknya tidak ada di dataset. Tulis satu kalimat kenapa rantainya berhenti di sana.
4. **Bandingkan dengan PID.** Untuk host yang sama di BOTS v3, jalankan `| stats dc(ProcessGuid) AS n_guid BY ProcessId | where n_guid > 1 | sort - n_guid`. Ini bukti terukur bahwa PID dipakai ulang dan GUID tidak.
5. **Pasang Sysmon di VM.** Pasang dengan konfigurasi publik sebagai titik awal (Lantern menyebut konfigurasi SwiftOnSecurity dan Olaf Hartong sebagai titik awal yang lazim [S17]), lalu jalankan `sysmon64 -c` dan simpan hasilnya. Pastikan `NetworkConnect`, `ProcessAccess`, `FileCreate`, `RegistryEvent`, dan `DnsQuery` memang aktif, dan isi `HashAlgorithms` secara eksplisit.
6. **Nyalakan PowerShell logging.** Aktifkan "Turn on Module Logging" dengan daftar module `*` dan "Turn on PowerShell Script Block Logging" di Local Group Policy [S12][S16]. Catat juga versi PowerShell di VM, karena PowerShell 7 menulis ke channel lain [S13].
7. **Input forwarder.** Siapkan input berikut (cek default `inputs.conf` add-on versi-mu dulu):

   ```
   [WinEventLog://Microsoft-Windows-Sysmon/Operational]
   disabled = 0
   renderXml = true
   index = sysmon

   [WinEventLog://Microsoft-Windows-PowerShell/Operational]
   disabled = 0
   renderXml = true
   index = powershell
   ```

8. **Buat event uji yang jinak.** Di VM: jalankan `cmd.exe` lalu dari dalamnya `powershell.exe` (menghasilkan rantai dua tingkat), buat file di folder Temp dengan `New-Item`, tulis satu nilai registry uji di `HKCU\Software\LabTest`, resolve satu nama dokumentasi dengan `Resolve-DnsName lab.example.test`, buka satu koneksi ke port yang kamu dengarkan sendiri di host lab, dan jalankan `Get-Process lsass` (ini membuka LSASS hanya untuk query informasi, tanpa bit baca memori).
9. **Uji logika bitmask.** Jalankan search bagian 2.5 di data VM. Hasilnya harus kosong walaupun langkah 8 menyentuh LSASS, karena `Get-Process` tidak meminta `PROCESS_VM_READ`. Lalu jalankan versi tanpa `where` dan catat nilai `GrantedAccess` yang muncul beserta prosesnya. Simpan daftar itu sebagai calon allowlist.
10. **Script block multi-bagian.** Buat satu file script jinak yang panjang (misalnya komentar panjang ditambah beberapa fungsi sederhana) sampai `MessageTotal` lebih dari 1, jalankan, lalu susun ulang dengan search bagian 2.8. Bandingkan `len(script)` hasil penyatuan dengan ukuran file aslinya.
11. **Catatan upaya terakhir.** Matikan script block logging, jalankan script jinak yang memuat pola seperti `[System.Convert]::FromBase64String` atas string yang tidak berbahaya, lalu cek apakah tetap ada 4104 yang muncul [S14]. Nyalakan kembali setelah selesai dan catat hasilnya.
12. **Ukur volume.** Jalankan `index=sysmon host=<vm> | timechart span=1h count BY EventCode` selama lab berjalan. Catat event mana yang paling boros; angka ini yang kamu pakai saat bicara dengan tim endpoint soal cakupan konfigurasi.

**Hasil yang sebaiknya tersimpan:**

- Rentang waktu BOTS v3 yang terverifikasi dan daftar event ID Sysmon yang ada di dataset itu.
- Satu process tree BOTS v3 yang sudah ditelusuri sampai berhenti, beserta alasan berhentinya.
- Angka dari langkah 4: berapa `ProcessId` yang dipakai lebih dari satu proses.
- Isi `sysmon64 -c` dari VM lab sebagai catatan cakupan sensor.
- Daftar nilai `GrantedAccess` yang muncul di lab beserta prosesnya, sebagai dasar allowlist.
- Satu script block multi-bagian yang berhasil disusun ulang, dengan `MessageTotal` dan panjang akhirnya.
- Jawaban terbukti untuk pertanyaan: apakah 4104 tetap muncul saat script block logging mati.
- Tabel volume per event ID per jam dari VM lab.

**Variasi tantangan:** jadikan search bagian 2.5 sebuah scheduled alert (Day 09) dengan throttle per `SourceImage` dan pengecualian dari lookup, lalu tulis satu paragraf tentang kenapa alert akses LSASS perlu allowlist yang dirawat sementara alert perubahan grup admin di Day 03 tidak.

## 4. Troubleshooting

Tabel ini untuk saat search tidak mengembalikan yang kamu harapkan; mulai dari kolom gejala.

| Gejala | Kemungkinan penyebab | Cara memeriksa atau memperbaiki |
|---|---|---|
| `index=sysmon` kosong untuk sebuah host | Sysmon tidak terpasang, atau input forwarder belum ada | Bandingkan daftar host di `sysmon` dan `wineventlog` dengan variasi di bagian 2.1 |
| Event 1 ada, event 3 tidak ada | `NetworkConnect` mati (default Sysmon) | Minta hasil `sysmon64 -c` di host itu; cek tag `NetworkConnect` [S1] |
| Event 10 hanya dari sedikit host | Dikonfigurasi terbatas karena volumenya besar | Normal; tulis sebagai batas bukti, jangan simpulkan tidak ada akses proses [S1] |
| Search `sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational"` kosong di data baru | Add-on modern memakai sourcetype generik `XmlWinEventLog` | Saring dengan `source="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"` [S2] |
| `process_name` dan `parent_process_name` kosong | Add-on Sysmon belum terpasang di search head, atau data dari sourcetype lama | Pakai `rex` atas `Image` dan `ParentImage` seperti di bagian 2.3 |
| Rantai proses terputus di tengah | Induk dibuat sebelum rentang waktu, atau sebelum Sysmon dipasang | Lebarkan rentang; cek kapan Sysmon mulai menulis di host itu |
| Satu `ProcessId` menunjuk dua proses berbeda | PID dipakai ulang Windows | Kelompokkan dengan `ProcessGuid`, bukan `ProcessId` [S1] |
| Filter registry `HKEY_LOCAL_MACHINE*` tidak cocok | Sysmon memakai singkatan `HKLM`, `HKU`, `HKCR` | Tulis filter dengan singkatan itu [S1] |
| `Details` di event 13 tidak berisi nilai yang diharapkan | Nilai yang dijamin terekam adalah DWORD dan QWORD | Cek tipe nilainya; untuk tipe lain verifikasi di lab [S1] |
| `DestinationHostname` kosong di event 3 | `DnsLookup` dimatikan di konfigurasi | Ambil nama domain dari event 22 [S1] |
| Kolom user kosong di event 10, 11, 13, 22 | Hanya event 1 yang membawa `User`; lainnya `user_id` berisi SID | Ambil akun dari event 1 dengan `ProcessGuid` yang sama [S4][S5] |
| 4104 ada tetapi isinya tampak pendek | Script terpecah menjadi beberapa bagian | Satukan per `ScriptBlockId` urut `MessageNumber` (bagian 2.8) [S8][S14] |
| 4104 sangat sedikit padahal PowerShell dipakai | Script block logging tidak aktif; yang muncul hanya catatan upaya terakhir | Cek policy dan registry `EnableScriptBlockLogging` [S12][S14] |
| 4104 tidak muncul di host yang sudah dikonfigurasi | Host memakai PowerShell 7 yang menulis ke `PowerShellCore/Operational` | Tambahkan input untuk channel itu [S13] |
| Isi `ScriptBlockText` tidak terbaca | Protected event logging mengenkripsi isi event | Dekripsi di luar Splunk sebelum ingest [S12][S16] |

## 5. Kesalahan umum dan jebakan

- Menganggap tidak ada event berarti tidak ada aktivitas. Di Sysmon, yang menentukan adalah apakah service-nya terpasang dan apa isi konfigurasinya; event 3, 7, 10, dan 22 sering sengaja dibatasi [S1].
- Menyusun process tree dari `ProcessId`. PID dipakai ulang, dan itu sebabnya `ProcessGuid` ada [S1].
- Menyimpulkan sebuah proses tidak berinduk karena baris induknya tidak ada di hasil. Paling sering itu hanya rentang waktu yang terlalu sempit.
- Memperlakukan event 3 sebagai flow record. Tidak ada byte, paket, atau durasi di event itu; pertanyaan volume dijawab log firewall dan proxy.
- Mencocokkan `GrantedAccess` sebagai nilai utuh. Ia bitmask; detection resmi memeriksa bit `0x10` dan `0x1000` [S11].
- Menganggap setiap akses ke LSASS adalah serangan. Agen EDR, backup, dan alat monitoring juga membukanya, dan halaman detection resmi menyebut kebutuhan tuning [S11].
- Menilai script dari satu event 4104. Script panjang dipecah menjadi beberapa bagian, dan bagian pertama sering terlihat tidak berbahaya [S14].
- Menyimpulkan script block logging aktif hanya karena ada 4104. PowerShell tetap mencatat sebagian script yang isinya mirip pola berbahaya walaupun fitur ini mati [S14].
- Memakai `values()` saat menyatukan bagian script. `values()` mengurutkan dan membuang duplikat, sehingga urutan baris script rusak; pakai `list()` setelah `sort`.
- Melupakan sensitivitas isi log. Command line dan isi script bisa memuat password, dan Microsoft secara khusus menyarankan protected event logging untuk alasan itu [S12]. Index `powershell` dan `sysmon` perlu pembatasan akses (Day 44).
- Memakai contoh lama apa adanya. Artikel dan dataset lama memakai sourcetype `xmlwineventlog:microsoft-windows-sysmon/operational` dan nama add-on lama; keduanya tidak cocok dengan add-on 5.0.1 [S17][S18].
- `[komunitas, belum terkonfirmasi]` Forum praktisi melaporkan bahwa add-on Sysmon memetakan banyak event ID sekaligus ke dataset Processes di data model Endpoint, dan bahwa untuk event akses atau injeksi antar proses field `parent_process_*` terisi dari proses target, bukan dari induk sebenarnya. Daftar field event 10 memang memuat `parent_process_guid` dan `parent_process_name` di samping `process_*` [S4], jadi arah pemetaannya perlu dibuktikan di lab sebelum dipakai di detection.

## 6. Catatan terkini

Bagian ini menampung versi dan tanggal sumber. Tidak ada yang mengubah search di atas, kecuali bila instance-mu masih memakai add-on lama.

- Splunk Add-on for Sysmon di Splunkbase adalah versi 5.0.1, rilis 6 Juli 2026, didukung Splunk, kompatibel dengan Splunk Enterprise dan Cloud 9.2 sampai 10.6 dan CIM 6.x, serta memetakan event ke data model Endpoint, Network Resolution, Network Traffic, dan Change [S10]. Halaman itu tidak mencantumkan daftar sourcetype maupun versi Sysmon yang diuji, jadi nama source dan sourcetype di Day ini diambil dari halaman data source research.splunk.com [S2][S9].
- Halaman data source research.splunk.com untuk Sysmon dan PowerShell 4104 diperbarui 13 Mei 2026 dan menyebut add-on pendukungnya: Splunk Add-on for Sysmon 5.0.1 untuk event Sysmon, dan Splunk Add-on for Microsoft Windows 11.0.3 untuk 4104 [S4][S5][S6][S7][S8].
- Hasil pencarian masih memunculkan dokumentasi add-on Sysmon versi 4.0.x (rilis 2024, CIM 5.2, Sysmon 15.0 sebagai versi yang diuji). Angka itu tertinggal dari Splunkbase; bila instance-mu memakai 4.0.x, periksa ulang nama field CIM sebelum memakai search di Day ini.
- Add-on komunitas lama bernama Splunk Add-on for Microsoft Sysmon berbeda dari add-on yang didukung Splunk. Artikel Lantern tentang process tree masih memakai nama lama itu dan sourcetype gaya lama di contohnya [S17], jadi sesuaikan sebelum menyalin.
- Halaman Sysmon di Microsoft Learn terbit 10 September 2026 dan menyebutkan dukungan Windows 11 ke atas untuk client serta Windows Server 2019 ke atas untuk server; contoh konfigurasi di halaman itu memakai `schemaversion` 4.82 [S1]. Nomor versi binary Sysmon tidak tercantum di halaman yang dibuka, jadi catat versinya sendiri saat memasang di lab.
- Dokumentasi logging PowerShell terpisah menurut versi: halaman 5.1 diperbarui 29 September 2025 dan memakai channel `Microsoft-Windows-PowerShell/Operational` [S12], sedangkan halaman PowerShell 7.6 diperbarui 19 Januari 2026 dan memakai channel `PowerShellCore/Operational` dengan policy di Administrative Templates > PowerShell Core [S13].
- Detection ESCU untuk akses LSASS yang dipakai sebagai acuan logika bitmask ada di versi 16, diperbarui 8 September 2026, dan memetakan diri ke teknik credential dumping LSASS memory [S11]. Versi sebelumnya mencocokkan nilai `GrantedAccess` `0x1010` dan `0x1410` secara langsung; dua pendekatan itu masih beredar di tulisan lama.
- BOTS v3 dirilis dengan lisensi CC0 dan memuat sourcetype `xmlwineventlog:microsoft-windows-sysmon/operational`; repo-nya menyarankan `earliest=0` saat mencari karena datanya sudah terindeks dengan waktu aslinya [S18]. Halaman repo tidak menyebut rentang tanggalnya, jadi tentukan sendiri dengan langkah 1 di bagian 3.

## 7. Cheat sheet

```
SOURCE   Sysmon      XmlWinEventLog:Microsoft-Windows-Sysmon/Operational   sourcetype=XmlWinEventLog
         PowerShell  XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
         BOTS v3     sourcetype="xmlwineventlog:microsoft-windows-sysmon/operational"  (earliest=0)

EVENT    1  proses baru   Image, CommandLine, ProcessGuid, ParentProcessGuid, User, IntegrityLevel, LogonId
         3  koneksi       DestinationIp, DestinationPort, Initiated   (mati secara default)
         10 akses proses  SourceImage, TargetImage, GrantedAccess, CallTrace   (volume besar, perlu filter)
         11 file dibuat   TargetFilename, CreationUtcTime
         13 registry set  TargetObject, Details, EventType   (HKLM | HKU | HKCR disingkat)
         22 dns query     QueryName, QueryStatus, QueryResults   (tidak ada di Windows 7)

CIM      process_guid | parent_process_guid | process_name | process_exec | process
         dest | user | granted_access | registry_path | query | signature_id

TREE     ke atas : ParentProcessGuid anak = ProcessGuid induk
         ke bawah: ProcessGuid induk = ParentProcessGuid anak
         nama    : rex field=Image "\x5c(?<nama>[^\x5c]+)$"
         sesi    : LogonId event 1 = TargetLogonId 4624

LSASS    akses=tonumber(replace(GrantedAccess,"0x",""),16)
         bit_and(akses,16)=PROCESS_VM_READ (0x10)
         bit_and(akses,4096)=PROCESS_QUERY_LIMITED_INFORMATION (0x1000)
         0x1410 = 0x1000 + 0x400 + 0x10

PS LOG   4104 script block (Verbose)  ScriptBlockText, ScriptBlockId, MessageNumber/MessageTotal, Path
         4103 module logging          cek field dengan fieldsummary
         gabung: sort 0 ScriptBlockId nomor | list(ScriptBlockText) | mvjoin(bagian,"")
         GPO : Windows Components > Windows PowerShell > Turn on Module Logging
                                                        Turn on PowerShell Script Block Logging
         PowerShell 7 -> channel PowerShellCore/Operational

CEK      sysmon64 -c   (konfigurasi aktif)    sysmon64 -s   (skema dan nama field)
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** Search event 3 di `JKT-DC01` tidak mengembalikan hasil apa pun selama seminggu. Analyst menyimpulkan DC itu tidak pernah membuat koneksi keluar. Benarkah?

<details><summary>Jawaban</summary>

Tidak. Event 3 (network connection) mati secara default di Sysmon dan hanya ada bila tag `NetworkConnect` dinyalakan di konfigurasi host itu. Hasil kosong paling mungkin berarti event itu tidak pernah ditulis, bukan bahwa koneksi tidak ada. Buktikan dengan inventaris per event ID dan jumlah host, lalu minta hasil `sysmon64 -c` dari host itu. Lihat bagian 1.1, 1.4, dan 2.1.

</details>

**2. Skenario keputusan.** Kamu perlu menyusun rantai induk dan anak dari sebuah proses di host yang punya Sysmon dan 4688 sekaligus. Mana yang dipakai sebagai kunci pengelompokan?

- A. `ProcessId` dari 4688, karena 4688 selalu ada di semua host Windows.
- B. `ProcessGuid` dan `ParentProcessGuid` dari Sysmon event 1, dan PID hanya untuk tampilan.
- C. Nama proses dan nama induk, karena lebih mudah dibaca.

<details><summary>Jawaban</summary>

B. `ProcessGuid` unik per proses dan tidak dipakai ulang, sehingga rantai bisa disusun tanpa ambiguitas; Microsoft menyebut GUID itu ada justru supaya korelasi tetap benar walaupun Windows memakai ulang PID. A keliru karena PID dipakai ulang, dan di rentang waktu yang sama satu PID bisa menunjuk dua proses berbeda. C keliru karena satu nama proses bisa muncul puluhan kali dengan induk berbeda. Lihat bagian 1.3 dan 2.3.

</details>

**3. Pertanyaan jebakan.** "Ada beberapa event 4104 dari `JKT-WS-0309`, berarti script block logging sudah aktif di host itu dan semua script akan tercatat." Benarkah?

<details><summary>Jawaban</summary>

Tidak. PowerShell otomatis mencatat sebagian script block yang isinya memuat pola yang sering dipakai script berbahaya, walaupun script block logging tidak dinyalakan; Microsoft menyebutnya catatan upaya terakhir. Jadi adanya beberapa 4104 bukan bukti cakupan penuh. Buktikan dengan policy atau nilai registry `EnableScriptBlockLogging` di host itu, bukan dengan jumlah event. Lihat bagian 1.8 dan 2.8.

</details>

**4. Skenario keputusan.** Satu event 4104 menampilkan `ScriptBlockText` yang berakhir di tengah kalimat, dengan `MessageNumber` 1 dan `MessageTotal` 3. Langkah yang tepat?

- A. Simpulkan script-nya pendek dan tidak berbahaya karena isi yang terlihat biasa saja.
- B. Kelompokkan per `ScriptBlockId`, urutkan dengan `MessageNumber`, lalu rangkai `ScriptBlockText` dengan `list()` dan `mvjoin()`.
- C. Minta tim endpoint menaikkan ukuran maksimum event di Windows supaya script tidak terpecah.

<details><summary>Jawaban</summary>

B. Script block yang terlalu besar untuk satu event ETW dipecah PowerShell menjadi beberapa bagian, dan di Splunk bagian itu muncul sebagai `MessageNumber` dari `MessageTotal` dengan `ScriptBlockId` yang sama sebagai pengikat. A adalah kesalahan yang paling sering terjadi: bagian pertama sering berisi definisi fungsi yang tampak jinak. C tidak menyelesaikan masalah karena pemecahan itu perilaku PowerShell, bukan setelan ukuran log; yang perlu dicek di sisi Splunk adalah setelan truncate sourcetype bila satu event terlihat terpotong. Pakai `list()` setelah `sort`, bukan `values()`, supaya urutannya tidak rusak. Lihat bagian 1.8 dan 2.8.

</details>

**5. Jelaskan ulang.** Jelaskan kepada admin Windows yang bertanya "kami sudah mengaktifkan 4688 dengan command line, kenapa masih perlu Sysmon?" dalam tiga kalimat.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "4688 dengan command line sudah membantu, tetapi ia memakai PID yang dipakai ulang Windows, sehingga menyusun rantai induk dan anak dari banyak event jadi rapuh; Sysmon memberi `ProcessGuid` yang unik per proses sehingga rantai itu bisa disusun dengan pasti. Sysmon juga mencatat hal yang tidak ada di log Security sama sekali: koneksi keluar beserta proses asalnya, akses satu proses ke memori proses lain, file yang dibuat, nilai registry yang diubah, dan query DNS per proses. Konsekuensinya ada di sisi kalian: cakupannya ditentukan file konfigurasi, jadi kita perlu sepakat event mana yang aktif di kelompok host mana, dan saya butuh hasil `sysmon64 -c` supaya laporan insiden bisa menyebutkan batas buktinya."

Kesalahan yang sering muncul:
- Menjual Sysmon sebagai pengganti log Security. Keduanya saling melengkapi: identitas dan perubahan akun tetap di Security log.
- Lupa menyebut biaya dan cakupan, sehingga tim endpoint merasa diminta menyalakan semuanya.
- Menyebut Sysmon sebagai alat pencegahan. Ia hanya mencatat, tidak menganalisis dan tidak memblokir.

</details>

**6. Pertanyaan jebakan.** "Detection akses LSASS cukup mencari `GrantedAccess=0x1410`, karena itu nilai yang dipakai alat credential dumping." Benarkah?

<details><summary>Jawaban</summary>

Tidak. `GrantedAccess` adalah bitmask, jadi kombinasi hak yang berbeda menghasilkan nilai berbeda walaupun artinya sama berbahaya; detection resmi mengubah nilainya ke desimal lalu memeriksa bit `PROCESS_VM_READ` (`0x10`) dan `PROCESS_QUERY_LIMITED_INFORMATION` (`0x1000`), dengan `PROCESS_QUERY_INFORMATION` (`0x400`) boleh ada atau tidak. Mencocokkan satu nilai utuh akan melewatkan varian, dan sebaliknya banyak akses sah ke LSASS juga punya bit baca memori, sehingga allowlist tetap diperlukan. Lihat bagian 1.5 dan 2.5.

</details>

**7. Interview question (English).** "You see a suspicious PowerShell process on a Windows server. Walk me through how you'd use Sysmon and PowerShell logs in Splunk to work out what it did."

<details><summary>Sample answer</summary>

"First I'd check coverage: which Sysmon event IDs that host actually sends, and whether script block logging is on, because Sysmon content depends entirely on its config file and several events are off by default. Then I'd take the process GUID from the Sysmon process creation event rather than the PID, since Windows reuses PIDs, and walk the parent chain up to the logon session, matching the Sysmon logon ID against the 4624 target logon ID. With that GUID I'd pivot across the other Sysmon events: network connections for where it went, DNS queries for the names it resolved, file creates and registry value sets for what it dropped and how it persists, and process access events against lsass.exe, where I'd test the granted access bitmask rather than matching one value. For the script itself I'd pull the 4104 events, group them by script block ID and order them by message number, then join the text, because long scripts are split across events and the first part usually looks harmless. Finally I'd build one timeline across the Windows Security, Sysmon and PowerShell indexes for the ticket, and state the evidence limits explicitly: which hosts have no Sysmon, and which event IDs are filtered out in their config."

What makes this answer strong: it starts with coverage instead of assuming the data exists, uses process GUID and logon ID to stitch events together, shows that granted access is a bitmask and that 4104 is multi-part, and ends with a deliverable plus the limits of the evidence.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Microsoft Learn: Sysmon (Sysinternals) | https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon | primer | terbit 2026-09-10; diakses 2026-10-14 | Tinggi. Daftar event, tag konfigurasi, default, singkatan registry, ProcessGuid |
| S2 | Splunk Security Content: Data Source Sysmon EventID 1 | https://research.splunk.com/sources/b375f4d1-d7ca-4bc0-9103-294825c0af17/ | primer (Splunk) | diperbarui 2026-05-13; diakses 2026-10-14 | Tinggi. Source, sourcetype, daftar field dan field CIM |
| S3 | Splunk Security Content: Data Source Sysmon EventID 3 | https://research.splunk.com/sources/01d84dff-4e26-422c-9389-6a579ee6e75b/ | primer (Splunk) | diakses 2026-10-14 | Tinggi. Field koneksi dan pemetaan CIM |
| S4 | Splunk Security Content: Data Source Sysmon EventID 10 | https://research.splunk.com/sources/659cd5a8-148a-4c59-ade1-05f41ac1b096/ | primer (Splunk) | diakses 2026-10-14 | Tinggi. GrantedAccess, CallTrace, hanya `user_id` tanpa nama akun |
| S5 | Splunk Security Content: Data Source Sysmon EventID 11 | https://research.splunk.com/sources/f3db9179-f4f5-416d-bc03-39f4d4ff699e/ | primer (Splunk) | diakses 2026-10-14 | Tinggi. TargetFilename dan field file CIM; `user` tercantum sebagai required tetapi tidak ada di daftar field |
| S6 | Splunk Security Content: Data Source Sysmon EventID 13 | https://research.splunk.com/sources/19cd00ee-f65f-48ca-bb08-64aac28638ce/ | primer (Splunk) | diperbarui 2026-05-13; diakses 2026-10-14 | Tinggi. TargetObject, Details, field registry CIM |
| S7 | Splunk Security Content: Data Source Sysmon EventID 22 | https://research.splunk.com/sources/911538b2-eba7-4d3e-85e8-d82d380c37bf/ | primer (Splunk) | diperbarui 2026-05-13; diakses 2026-10-14 | Tinggi. QueryName, QueryStatus, QueryResults; contoh status bukan nol |
| S8 | Splunk Security Content: Data Source Powershell Script Block Logging 4104 | https://research.splunk.com/sources/5cfd0c72-d989-47a0-92f9-6edc6f8d3564/ | primer (Splunk) | diperbarui 2026-05-13; diakses 2026-10-14 | Tinggi. Source PowerShell Operational, ScriptBlockText, ScriptBlockId, MessageNumber, MessageTotal |
| S9 | Splunk Security Content: Windows Data Sources | https://research.splunk.com/sources/platforms/windows | primer (Splunk) | diakses 2026-10-14 | Tinggi. Daftar event Sysmon yang punya halaman data source dan add-on pendukungnya |
| S10 | Splunkbase: Splunk Add-on for Sysmon | https://splunkbase.splunk.com/app/5709 | primer | versi 5.0.1, 2026-07-06; diakses 2026-10-14 | Tinggi untuk versi, kompatibilitas, dan data model tujuan |
| S11 | Splunk Security Content: Detection Detect Credential Dumping through LSASS access | https://research.splunk.com/endpoint/2c365e57-4414-4540-8dc0-73ab10729996 | primer (Splunk) | versi 16, 2026-09-08; diakses 2026-10-14 | Tinggi. Logika bitmask GrantedAccess dan catatan false positive |
| S12 | Microsoft Learn: about_Logging (Windows PowerShell 5.1) | https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging?view=powershell-5.1 | primer | diperbarui 2025-09-29; diakses 2026-10-14 | Tinggi. 4104, channel, level, GPO dan registry, protected event logging |
| S13 | Microsoft Learn: about_Logging_Windows (PowerShell 7.6) | https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows | primer | diperbarui 2026-01-19; diakses 2026-10-14 | Tinggi. Channel PowerShellCore/Operational dan policy PowerShell Core |
| S14 | Microsoft DevBlogs: PowerShell the Blue Team | https://devblogs.microsoft.com/powershell/powershell-the-blue-team/ | primer | diakses 2026-10-14 | Sedang-tinggi. Script block dipecah menjadi beberapa bagian; pencatatan otomatis script mencurigakan sebagai catatan upaya terakhir |
| S15 | Splunk blog: Hunting for Malicious PowerShell using Script Block Logging | https://www.splunk.com/en_us/blog/security/hunting-for-malicious-powershell-using-script-block-logging.html | sekunder (Splunk) | diakses 2026-10-14 | Sedang-tinggi. Volume 4104, pendekatan skor keyword, module logging sebagai pelengkap |
| S16 | Splunk Docs: Configure PowerShell logging (Splunk UBA, add other data) | https://help.splunk.com/en/security-offerings/splunk-user-behavior-analytics/get-data-in/5.4.5/add-other-data-to-splunk-uba | primer (Splunk) | diakses 2026-10-14 | Tinggi. GPO module logging dan script block logging, daftar event verifikasi 4103/4104/4688/7045, catatan protected event logging |
| S17 | Splunk Lantern: Visualizing processes and their parent/child relationships | https://lantern.splunk.com/Security/Use_Cases/Threat_Hunting/Visualizing_processes_and_their_parent%2F%2Fchild_relationships | primer (Splunk) | diakses 2026-10-14 | Sedang-tinggi. Pola `rex` dengan `\x5c`, pstree, nama add-on dan sourcetype gaya lama |
| S18 | GitHub splunk/botsv3 | https://github.com/splunk/botsv3 | primer | diakses 2026-10-14 | Tinggi. Daftar sourcetype termasuk Sysmon gaya lama, saran `earliest=0`, lisensi CC0 |

**Catatan sumber:** halaman dokumentasi Splunk Add-on for Sysmon di docs.splunk.com (daftar sourcetype, release notes, dan pemetaan field CIM per event) tidak dapat dibuka saat riset, sehingga penamaan source dan sourcetype serta nama field CIM di Day ini bersandar pada halaman data source research.splunk.com dan Splunkbase; cocokkan dengan halaman source type add-on 5.0.1 di dokumentasi resmi saat tersedia. Hasil pencarian masih memunculkan versi add-on 4.0.x sebagai yang terbaru, sedangkan Splunkbase menyebut 5.0.1; yang dipakai di Day ini adalah angka dari halaman Splunkbase yang dibuka. Nomor versi binary Sysmon tidak tercantum di halaman Microsoft yang dibuka, dan halaman itu menyebut default `HashAlgorithms` dua kali dengan isi berbeda (`None` di tabel configuration entry, SHA1 di contoh pemasangan), jadi keduanya perlu dipastikan di lab. Arti kode `QueryStatus` selain nol belum dicocokkan ke daftar kode error DNS Windows. Nama field dan perilaku event 4103 (module logging) tidak punya halaman data source resmi di research.splunk.com, sehingga Day ini hanya menyebut cara menyalakannya dan menyarankan `fieldsummary` sebelum menulis search. Klaim bahwa `net.exe` memanggil `net1.exe` sebagai perilaku normal Windows berasal dari pengalaman lapangan dan perlu dikonfirmasi di lab-mu sendiri.
