---
day: 03
title: 'Log Windows Security di Splunk: logon, akun, proses, dan field Subject/target'
researched_on: 2026-10-14
versions_checked: 'Splunk Enterprise 10.6; Splunk Add-on for Microsoft Windows 11.0.3 (Splunkbase, rilis 1 Okt 2026); research.splunk.com data source Windows Security dan System (diuji dengan add-on 11.0.3); Microsoft Learn audit events (arsip Windows 10, diperbarui Apr-Mei 2026) dan Appendix L (diperbarui Feb 2026); BOTS v1 (Windows add-on 4.8.3); ES 8.7.0; CIM 6.4'
---

# Day 03: Log Windows Security di Splunk (logon, akun, proses, dan field Subject/target)

Cakupan: cara log Windows Security dan System masuk ke Splunk (format klasik dan XML, sourcetype dan source), event logon, kredensial, hak istimewa, perubahan akun dan grup, proses, persistence, dan penghapusan log, serta cara membaca dua akun dalam satu event tanpa salah orang.

## Ide inti

Hampir setiap event di log Windows Security menjawab empat hal: akun siapa, di komputer mana, lewat cara apa (logon type, proses, kredensial), dan hasilnya apa (berhasil, gagal, kode status). Kesulitannya bukan menghafal event ID, tetapi membaca akun yang benar. Banyak event memuat dua akun sekaligus: Subject (yang meminta atau melaporkan aksi) dan target (akun yang login, akun yang dibuat, atau grup yang diubah). Di Splunk, dua akun itu bisa muncul sebagai satu field multivalue, dan nama field-nya berbeda antara format klasik dan XML. Salah memilih akun berarti salah orang yang dieskalasi.

Kamu sudah mengenal pola ini dari log AAA di router dan TACACS+. Satu baris accounting menyebut siapa yang login, ke perangkat mana, lewat jalur apa (console, vty, SSH), dari IP mana, dan perintah apa yang dijalankan. Windows Security log adalah versi yang lebih rinci: logon type berperan seperti jalur login, Logon ID seperti nomor sesi, dan event perubahan grup seperti accounting perintah konfigurasi. Bedanya, satu event Windows bisa mencatat dua identitas, dan sourcetype (parser) di Splunk menentukan nama field yang kamu lihat.

```
Event di DC / server / workstation
  -> audit policy: event ini diaudit atau tidak? (tidak diaudit = tidak pernah ada)
  -> universal forwarder: input WinEventLog://Security, renderXml true/false
  -> Splunk Add-on for Microsoft Windows (sourcetype = parser)
       XML    : sourcetype=XmlWinEventLog  source=XmlWinEventLog:Security
       klasik : sourcetype=WinEventLog     source=WinEventLog:Security
  -> field mentah  : SubjectUserName, TargetUserName, LogonType, IpAddress  (XML)
                     Account_Name (dua nilai), Logon_Type, Source_Network_Address (klasik)
  -> field CIM     : user, src, dest, action, signature_id
```

Situasi yang dipakai sepanjang Day ini: pukul 02.10, analyst L1 shift malam di SOC PT Jaringan Anak Bangsa (PT JAB, ISP fiktif dengan domain AD `JAB`) menulis di channel SOC:

> "Alert 'Windows login gagal >= 20 dalam 10 menit' bunyi untuk JKT-JUMP01, sudah aku buka tiket SOC-2026-0217. Anehnya kolom akun di hasil alert isinya dua: JKT-JUMP01$ dan svc_backup. Terus waktu aku scroll, jam 01.52 ada 4624 logon type 10 adm.rina ke JKT-JUMP01 dari 10.30.14.22, itu kan subnet Bandung, padahal Rina orang Jakarta. Jam 01.57 di JKT-DC01 ada 4728, budi.santoso masuk Domain Admins. Mana yang perlu aku eskalasi ke L2?"

Pesan itu memuat lima pertanyaan:

1. Event yang dibutuhkan ada di sourcetype dan source apa, dan kenapa nama field-nya berbeda-beda?
2. Kenapa ada event yang tidak muncul sama sekali, misalnya command line di 4688?
3. Login gagal itu sebenarnya akun mana yang gagal, dan kenapa?
4. Apakah logon type 10 dari subnet Bandung wajar, dan apa yang dilakukan sesi itu?
5. Siapa yang menambahkan budi.santoso ke Domain Admins, dan adakah jejak lain (task, service, log dihapus)?

Pertanyaan 1 dijawab di bagian 1.1, pertanyaan 2 di bagian 1.2, pertanyaan 3 di bagian 1.4 dan 1.5, pertanyaan 4 di bagian 1.3 dan 1.6, dan pertanyaan 5 di bagian 1.7 dan 1.8. Bagian 2 menjalankan semuanya sebagai search.

**Kapan relevan:** triage alert login (gagal massal, login dari lokasi tak lazim), review akun admin dan perubahan grup, investigasi lateral movement dan persistence di host Windows, serta permintaan audit seperti "siapa menambahkan akun ke grup admin bulan ini".
**Kapan bukan jawaban:** saat audit policy tidak mengaktifkan subkategori yang dibutuhkan, saat pertanyaannya tentang isi proses secara rinci (koneksi jaringan per proses, isi script PowerShell, hash file; itu wilayah Sysmon dan PowerShell logging di Day 04), atau saat host tidak mengirim log ke Splunk sama sekali.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dasar Splunk dari Day 01 dan 02 (index, sourcetype, source, host, `stats`, `eval`) tidak diulang. Tabel ini memuat istilah Windows dan add-on yang dipakai di Day ini; kolom padanan memakai analogi dari pekerjaan NOC dan SOC. Baca kolom arti dulu, lalu kembali ke sini saat menemukan istilah yang terlupa.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| Security log (channel `Security`) | Log audit Windows: logon, akun, grup, proses, kebijakan | Log AAA/TACACS+ perangkat |
| System log (channel `System`) | Log sistem Windows; di Day ini dipakai untuk 7045 (service baru) | Syslog sistem perangkat |
| Event ID (`EventCode` di Splunk) | Nomor jenis kejadian, misalnya 4624 logon berhasil | Kode pesan syslog vendor (`%SEC_LOGIN-5-LOGIN_SUCCESS`) |
| Audit policy | Pengaturan subkategori audit yang menentukan event mana ditulis | Konfigurasi `aaa accounting`: yang tidak dikonfigurasi tidak tercatat |
| Format klasik vs XML | Event dirender sebagai teks "Label: nilai" atau sebagai XML; diatur `renderXml` di input | Dua template parsing untuk log vendor yang sama |
| `WinEventLog` / `XmlWinEventLog` | Sourcetype generik dari add-on Windows; channel dibedakan lewat `source` | Parser per format, dengan nama file asal sebagai pembeda |
| Subject | Akun yang meminta atau melaporkan aksi | Operator yang mengetik perintah di TACACS+ |
| Target (New Logon, Account For Which Logon Failed, New Account, Member) | Akun yang menjadi objek aksi: yang login, yang gagal, yang dibuat, yang ditambahkan | User yang dibuat atau diubah oleh perintah itu |
| Logon type | Angka yang menyebut cara logon: lokal, jaringan, RDP, service | Jalur login: console, vty, SSH, PPP |
| Logon ID | Nomor heksadesimal sesi logon, dipakai mengaitkan event dalam satu sesi | Nomor sesi atau Acct-Session-Id RADIUS |
| Status / Sub Status | Kode NTSTATUS penyebab logon gagal | Kode alasan reject RADIUS |
| SID | Identitas unik akun atau grup yang tidak pernah dipakai ulang | Nomor pelanggan internal yang tidak berubah walau nama diganti |
| Field multivalue | Satu field Splunk berisi lebih dari satu nilai dalam satu event | Satu kolom berisi dua nomor dalam satu baris CDR |
| Field CIM (`user`, `src`, `dest`, `action`) | Nama field standar yang diisi add-on supaya search lintas vendor seragam | Normalisasi format log di SIEM mana pun |

### 1.1 Dari Event Viewer ke Splunk: format, sourcetype, dan source

Analyst L1 PT JAB melihat field `Account_Name` di alert lama, padahal saat mencari manual di event terbaru yang muncul `TargetUserName`. Keduanya benar; yang berbeda adalah format event.

Universal forwarder membaca channel Windows (Security, System, dan lainnya) lewat input `WinEventLog`. Opsi `renderXml` menentukan bentuk event yang dikirim: XML mentah, atau teks klasik seperti tampilan Event Viewer. Splunk Add-on for Microsoft Windows lalu menerapkan parser yang sesuai. Di add-on modern, sourcetype dibuat generik (`XmlWinEventLog` atau `WinEventLog`) dan nama channel dipindah ke `source`. Halaman data source di research.splunk.com yang diuji dengan add-on 11.0.3 mencatat event Security sebagai `source=XmlWinEventLog:Security` dengan `sourcetype=XmlWinEventLog`, dan event System (7045) sebagai `source=XmlWinEventLog:System` [S5][S6][S14]. Splunk Lantern menjelaskan mekanismenya: add-on mengubah sourcetype asal yang spesifik, misalnya `XmlWinEventLog:Security`, menjadi `XmlWinEventLog` yang generik [S8].

Konsekuensinya untuk search: data lama dan dataset latihan bisa memakai penamaan lama. BOTS v1 dibuat dengan add-on Windows 4.8.3 dan menyimpan event Security dengan `sourcetype=WinEventLog:Security` [S15]. Search yang menyaring `sourcetype=WinEventLog:Security` tidak akan menemukan event dari add-on modern, dan sebaliknya. Untuk data baru, saring dengan `source`.

Tabel berikut memetakan penamaan yang akan kamu temui; cari baris yang cocok dengan data di instance-mu sebelum menulis search.

| Situasi | `sourcetype` | `source` |
|---|---|---|
| Add-on modern, format XML (yang dipakai PT JAB) | `XmlWinEventLog` | `XmlWinEventLog:Security`, `XmlWinEventLog:System` |
| Add-on modern, format klasik | `WinEventLog` | `WinEventLog:Security`, `WinEventLog:System` |
| Data lama atau BOTS v1 (add-on 4.8.3) | `WinEventLog:Security`, `WinEventLog:System` | `WinEventLog:Security` |

Nama field juga berbeda. Format XML memakai nama elemen `<Data Name="...">` dari event aslinya, misalnya `SubjectUserName`, `TargetUserName`, `LogonType`, `IpAddress`, `TargetLogonId` [S1]. Format klasik membuat field dari label teks ("Account Name:", "Logon Type:"), sehingga muncul `Account_Name`, `Logon_Type`, `Source_Network_Address`, `Logon_ID`. Daftar field 4624 di research.splunk.com menunjukkan add-on 11.0.3 juga menambahkan beberapa nama gaya klasik pada event XML, misalnya `Logon_Type`, `Target_User_Name`, `Logon_ID`, `src_ip`, dan `Source_Workstation`, di samping field CIM `user`, `dest`, `action`, dan `signature_id` [S5]. Cek nama persis di instance-mu dengan `| fieldsummary` sebelum mengandalkan satu nama.

Tabel berikut adalah kamus singkat yang paling sering dipakai; perhatikan kolom klasik, karena di sanalah dua akun bercampur dalam satu field.

| Arti | Format XML | Format klasik (umum) |
|---|---|---|
| Akun Subject | `SubjectUserName`, `SubjectDomainName`, `SubjectLogonId` | nilai pertama `Account_Name`, `Account_Domain`, `Logon_ID` |
| Akun target pada 4624/4625 | `TargetUserName`, `TargetDomainName`, `TargetLogonId` | nilai kedua `Account_Name`, `Account_Domain`, `Logon_ID` |
| Logon type | `LogonType` | `Logon_Type` |
| IP asal | `IpAddress` | `Source_Network_Address` |
| Nama komputer asal | `WorkstationName` | `Workstation_Name` |
| Proses baru pada 4688 | `NewProcessName`, `CommandLine`, `ParentProcessName` | `New_Process_Name`, `Process_Command_Line`, `Creator_Process_Name` |

Nama klasik di tabel mengikuti label teks event dengan spasi menjadi garis bawah. Urutan nilai multivalue dan nama persisnya perlu dicek di lab dengan data klasik (BOTS v1 cocok untuk ini).

### 1.2 Audit policy: event yang tidak diaudit tidak pernah ada

Analyst PT JAB ingin melihat command line `net.exe` dari sesi adm.rina, tetapi field `CommandLine` di 4688 kosong di sebagian host. Itu bukan masalah Splunk.

Windows hanya menulis event untuk subkategori audit yang aktif. Microsoft mengingatkan bahwa perilaku logging bawaan berbeda per versi dan edisi, banyak setelan audit di Group Policy berstatus Not Configured, dan sebagian event baru muncul setelah kebijakan audit diatur eksplisit di Advanced Audit Policy Configuration [S4]. Splunk tidak bisa mencari event yang tidak pernah ditulis.

4688 adalah contoh paling jelas karena butuh dua setelan [S3][S16]:

1. **Audit Process Creation** (Advanced Audit Configuration > Detailed Tracking) supaya 4688 ditulis. Bawaannya Not configured.
2. **Include command line in process creation events** (Administrative Templates > System > Audit Process Creation) supaya field command line terisi. Tanpa setelan ini, field itu kosong.

Microsoft juga mengingatkan dua hal. Pertama, command line ditulis dalam teks biasa dan bisa memuat password atau data pribadi, sehingga siapa pun yang bisa membaca Security log bisa membacanya [S16]. Di Splunk, ini berarti index `wineventlog` perlu pembatasan akses (Day 44). Kedua, setelan Advanced Audit Policy bisa ditimpa setelan audit dasar; event 4719 tercatat bila kebijakan audit berubah [S16].

Tabel berikut memetakan event di Day ini ke subkategori audit yang harus aktif; pakai sebagai daftar periksa saat sebuah event "tidak ada".

| Event | Subkategori audit (Microsoft) | Catatan |
|---|---|---|
| 4624, 4625, 4648 | Audit Logon (4625 juga Audit Account Lockout) | Ditulis di komputer yang diakses [S1][S2][S10] |
| 4672 | Audit Special Logon | Muncul untuk setiap logon SYSTEM juga, jadi volumenya besar [S11] |
| 4720, 4722, 4724 | Audit User Account Management | Di DC untuk akun domain, di host untuk akun lokal [S17] |
| 4728, 4732, 4756 | Audit Security Group Management | Satu event per anggota yang ditambahkan [S9] |
| 4688 | Audit Process Creation | Command line butuh setelan tambahan [S3] |
| 4698 | Audit Other Object Access Events | Isi task dalam XML di field `TaskContent` [S12] |
| 1102 | Other Events | Ditulis saat Security log dihapus [S13] |

### 1.3 4624 dan logon type: jalur masuk sebuah sesi

Logon adm.rina ke JKT-JUMP01 jam 01.52 bertipe 10. Sebelum menilai wajar atau tidak, kamu perlu tahu arti angka itu.

4624 ditulis di komputer yang diakses setiap kali sesi logon dibuat [S1]. Field `LogonType` menyebut caranya. Tabel berikut dari dokumentasi Microsoft [S1]; kolom terakhir adalah cara membacanya saat triage.

| Logon type | Nama | Arti | Yang biasa dicek saat triage |
|---|---|---|---|
| 2 | Interactive | Login langsung di komputer itu | Siapa yang duduk di depan server? |
| 3 | Network | Akses dari jaringan (share, RPC, banyak autentikasi) | Volume tinggi dan normal; nilai dari `IpAddress` dan akun |
| 4 | Batch | Proses atas nama user tanpa interaksi, misalnya scheduled task | Akun service yang dipakai task |
| 5 | Service | Service dijalankan oleh Service Control Manager | Akun service yang tidak biasa |
| 7 | Unlock | Workstation dibuka kuncinya | Jarang menarik sendiri |
| 8 | NetworkCleartext | Login jaringan dengan password tidak di-hash ke paket autentikasi | Aplikasi lama atau basic auth |
| 9 | NewCredentials | Token di-clone dengan kredensial baru untuk koneksi keluar | Identitas lokal sama, identitas jaringan berbeda (`TargetOutboundUserName`) |
| 10 | RemoteInteractive | Login lewat Remote Desktop | Dari IP mana, akun apa, jam berapa |
| 11 | CachedInteractive | Login dengan kredensial tersimpan tanpa menghubungi DC | Laptop di luar kantor |

Microsoft juga mendaftar tipe 0 (System, hanya akun SYSTEM saat startup), 12 (CachedRemoteInteractive), dan 13 (CachedUnlock) [S1].

Beberapa field di 4624 versi 2 (Windows 10 dan sesudahnya) membantu menilai sesi [S1]:

- `ElevatedToken`: "Yes" berarti sesi itu elevated dan punya hak administrator. Microsoft menyarankan memantau logon akun admin lewat field ini.
- `RestrictedAdminMode`: hanya terisi untuk logon tipe 10.
- `TargetLinkedLogonId`: Logon ID sesi pasangan. Akun admin bisa menghasilkan dua sesi berpasangan, jadi satu login RDP bisa terlihat sebagai dua 4624 dengan dua Logon ID.
- `IpAddress`, `IpPort`, `WorkstationName`: terisi tergantung protokol. Microsoft mencatat logon jaringan dengan Kerberos biasanya tanpa nama workstation, sedangkan logon NTLM tanpa detail TCP/IP [S1].

Untuk situasi PT JAB, tipe 10 ke jump host itu sendiri wajar, karena jump host memang untuk RDP. Yang tidak wajar adalah kombinasi akun admin, subnet Bandung, dan jam 01.52. Penilaian "tidak wajar" butuh baseline: apakah adm.rina pernah RDP dari 10.30.0.0/16 dalam 30 hari terakhir? Bagian 2.4 menjawabnya.

### 1.4 4625 dan Status/Sub Status: kenapa login gagal

Alert 4625 di JKT-JUMP01 bisa berarti serangan, bisa juga satu scheduled task dengan password lama. Kode status yang membedakannya.

4625 ditulis di komputer tempat percobaan logon dilakukan, untuk setiap kegagalan logon [S2]. Field `Status` berisi alasan gagal, `SubStatus` berisi informasi tambahan, dan `FailureReason` versi teksnya. Contoh event di research.splunk.com memperlihatkan pola yang sering muncul: `Status=0xc000006d` dengan `SubStatus=0xc000006a` untuk password salah [S6]. Jadi `Status` sering berisi kode umum, dan detailnya ada di `SubStatus`; selalu ambil keduanya.

Tabel berikut berisi kode yang paling berguna saat triage, dari rekomendasi pemantauan Microsoft [S2]. Cari kolom "Arti untuk triage" untuk menentukan langkah berikutnya.

| Kode | Arti | Arti untuk triage |
|---|---|---|
| `0xC000006D` | Username atau informasi autentikasi salah | Kode umum; lihat `SubStatus` |
| `0xC000006A` | Username benar, password salah | Bila banyak berturut-turut pada akun kritis atau service: tebakan password atau password lama di konfigurasi |
| `0xC0000064` | Username tidak ada | Banyak berturut-turut bisa berarti enumerasi akun |
| `0xC0000234` | Akun terkunci | Dampak dari kegagalan sebelumnya; cari sumber kegagalan awal |
| `0xC0000072` | Akun dinonaktifkan | Ada yang mencoba memakai akun yang seharusnya mati |
| `0xC0000193` | Akun kedaluwarsa | Sama, untuk akun kontraktor yang habis masa berlakunya |
| `0xC000006F` | Login di luar jam yang diizinkan | Pelanggaran kebijakan jam login |
| `0xC0000070` | Login dari workstation yang tidak diizinkan | Akun dibatasi ke host tertentu, dicoba dari host lain |
| `0xC000015B` | Logon type tidak diizinkan di komputer itu | Misalnya akun service dipakai untuk RDP |
| `0xC000005E`, `0xC0000192` | Tidak ada logon server, atau Netlogon tidak berjalan | Biasanya masalah infrastruktur, bukan serangan |

Microsoft menyarankan memantau semua 4625 untuk akun lokal dan akun service, karena akun itu seharusnya tidak terkunci [S2]. Microsoft juga menyarankan mencocokkan logon type dengan jenis akun: tipe 4 atau 5 yang dipakai anggota grup admin domain patut dicurigai [S2].

Pola yang membedakan serangan dan salah konfigurasi:

- **Tebakan password ke satu akun:** satu sumber, satu akun, banyak `0xC000006A`.
- **Password spraying:** satu sumber, banyak akun berbeda, sedikit percobaan per akun.
- **Enumerasi akun:** banyak `0xC0000064` dari satu sumber.
- **Password lama di konfigurasi:** satu akun service, logon type 4 atau 5, interval sangat teratur, sumbernya komputer itu sendiri. Ini kasus svc_backup di PT JAB.

Event 4740 (akun terkunci) ditulis terpisah dan termasuk daftar event yang disarankan dipantau [S4].

### 1.5 Subject vs target dan field multivalue

Kolom akun di alert PT JAB berisi dua nilai, JKT-JUMP01$ dan svc_backup. Itu bukan dua akun yang gagal login.

Event 4624 dan 4625 punya dua blok akun [S1][S2]:

- **Subject:** akun yang melaporkan atau meminta logon. Pada logon lokal oleh service atau task, Subject biasanya akun komputer (`JKT-JUMP01$`) dengan SID `S-1-5-18` dan Logon ID `0x3e7`, yaitu SYSTEM. Contoh XML di dokumentasi Microsoft memperlihatkan pasangan ini [S1][S2]. Pada logon jaringan, Subject sering kosong (`-`, NULL SID) [S5].
- **Target:** akun yang login (New Logon) atau yang gagal login (Account For Which Logon Failed).

Microsoft menyarankan memakai akun target (New Logon) untuk hampir semua pemantauan 4624, dan memakai Subject hanya untuk hal seperti domain asal atau konvensi nama [S1].

Di format klasik, dua blok itu berlabel sama ("Account Name:"), sehingga add-on mengekstraknya menjadi satu field `Account_Name` dengan dua nilai. Hal yang sama terjadi pada `Account_Domain` dan `Logon_ID`. Konsekuensinya di SPL:

| Operasi | Yang terjadi pada field multivalue | Dampak |
|---|---|---|
| `stats count BY Account_Name` | Event dihitung sekali untuk setiap nilai | JKT-JUMP01$ ikut terhitung sebagai "akun yang gagal" |
| `stats dc(Account_Name)` | Dua nilai dihitung dua akun | Jumlah akun unik terlihat dua kali lipat |
| `search Account_Name=svc_backup` | Cocok bila salah satu nilai cocok | Hasil benar, tetapi kolom tampilan tetap berisi dua nilai |
| `where Account_Name="svc_backup"` | Perbandingan pada field multivalue bisa tidak sesuai harapan | Pilih satu nilai dulu dengan `mvindex` |

Ada tiga cara aman:

1. Pakai format XML dan field yang jelas: `TargetUserName` untuk akun target, `SubjectUserName` untuk Subject.
2. Di data klasik, periksa dulu `mvcount(Account_Name)`. Bila 2, nilai pertama biasanya Subject dan nilai kedua target, karena urutannya mengikuti urutan blok di teks event. Urutan ini perlu dicek di lab.
3. Pakai field CIM `user` bila add-on mengisinya dari akun target. Cek dengan `table user SubjectUserName TargetUserName` sebelum mengandalkannya; Day 24 bagian 1.6 membahas `user` yang menjadi multivalue di data model Authentication.

Pola dua akun tidak hanya di logon. Di 4688 versi 2 ada Creator Subject dan Target Subject [S3]. Di 4720 ada Subject (pembuat) dan New Account (akun baru) [S17]. Di 4728 dan 4732, `TargetUserName` berisi nama grup, bukan akun manusia, sedangkan akun yang ditambahkan ada di `MemberName` dan `MemberSid` [S9]. Jadi arti "target" berubah per event; baca deskripsi event sebelum memilih field.

### 1.6 4648 dan 4672: kredensial eksplisit dan hak istimewa

Sesi adm.rina di JKT-JUMP01 bertipe RDP. Pertanyaan berikutnya: apakah sesi itu punya hak admin, dan apakah dari sesi itu ada yang memakai kredensial lain?

**4672 (Special privileges assigned to new logon)** ditulis untuk logon baru yang menerima salah satu hak sensitif, antara lain `SeDebugPrivilege`, `SeTcbPrivilege`, `SeBackupPrivilege`, `SeRestorePrivilege`, `SeTakeOwnershipPrivilege`, `SeLoadDriverPrivilege`, `SeImpersonatePrivilege`, dan `SeSecurityPrivilege` [S11]. Setiap logon SYSTEM memicu event ini, jadi volumenya besar. Microsoft menyarankan memantau 4672 yang Subject-nya bukan LOCAL SYSTEM, NETWORK SERVICE, atau LOCAL SERVICE, dan bukan akun admin yang memang diharapkan [S11]. 4672 tidak punya blok target: akunnya ada di Subject. Untuk mengaitkannya dengan 4624, cocokkan `SubjectLogonId` di 4672 dengan `TargetLogonId` di 4624 [S1][S11].

**4648 (A logon was attempted using explicit credentials)** ditulis saat sebuah proses mencoba logon dengan menyebut kredensial akun secara eksplisit. Microsoft menyebut kasus paling umum adalah konfigurasi batch seperti scheduled task dan perintah `RUNAS`, dan event ini juga muncul rutin dalam operasi normal [S10]. Field-nya: Subject (yang meminta), akun yang kredensialnya dipakai (`TargetUserName`), server tujuan (`TargetServerName`, berisi `localhost` bila lokal), dan proses (`ProcessName`) [S10]. Nilai 4648 untuk investigasi: bila Subject adalah akun karyawan biasa dan kredensial yang dipakai adalah akun admin atau akun service, artinya seseorang memegang kredensial yang bukan miliknya.

Logon ID adalah benang yang menjahit satu sesi: 4624 membuka sesi dengan `TargetLogonId`, 4672 menempel hak istimewa dengan `SubjectLogonId` yang sama, dan 4688 dari sesi itu membawa `SubjectLogonId` yang sama sebagai Creator Subject [S1][S3]. Logon ID bisa dipakai ulang setelah reboot, jadi selalu batasi waktu (Day 13 bagian 2.1 memakai `maxspan` untuk alasan yang sama).

### 1.7 Perubahan akun dan grup: 4720 sampai 4756

Event 4728 jam 01.57 di JKT-DC01 adalah inti eskalasi. Kamu perlu membaca tiga identitas: siapa yang mengubah, akun siapa yang ditambahkan, dan ke grup apa.

Tabel berikut merangkum event akun dan grup di Day ini. Kolom "Akun di field" menunjukkan di mana tiap identitas berada; inilah tempat orang paling sering salah baca.

| Event | Arti | Pelaku | Objek | Prioritas menurut Microsoft |
|---|---|---|---|---|
| 4720 | Akun user dibuat | `SubjectUserName` | `TargetUserName`, `TargetSid` (akun baru) | Low [S4] |
| 4722 | Akun user diaktifkan | `SubjectUserName` | `TargetUserName` | Low [S4] |
| 4724 | Percobaan reset password akun | `SubjectUserName` | `TargetUserName` | Medium [S4] |
| 4728 | Anggota ditambahkan ke grup global security-enabled | `SubjectUserName` | `MemberName`, `MemberSid`; grup di `TargetUserName` | Low [S4] |
| 4732 | Anggota ditambahkan ke grup lokal security-enabled | `SubjectUserName` | `MemberName`, `MemberSid`; grup di `TargetUserName` | Low [S4] |
| 4756 | Anggota ditambahkan ke grup universal security-enabled | `SubjectUserName` | `MemberName`, `MemberSid`; grup di `TargetUserName` | Low [S4] |

Rincian dari dokumentasi Microsoft yang mengubah cara menulis search:

- Prioritas Low di Appendix L berarti event diselidiki bila muncul tidak terduga atau jumlahnya jauh di atas baseline; prioritas High berarti satu kejadian pun diselidiki [S4]. Untuk grup kritis seperti Administrators, Domain Admins, dan Enterprise Admins, Microsoft menyarankan memantau setiap penambahan anggota [S9]. Jadi prioritas event bergantung pada grupnya, bukan pada event ID-nya.
- Satu event ditulis untuk setiap anggota yang ditambahkan, dan 4735 (grup diubah) biasanya muncul tepat sebelum 4732 [S9].
- `MemberName` berisi distinguished name, misalnya `CN=Budi Santoso,OU=Staff,DC=corp,DC=jab,DC=example`. Untuk grup lokal, field ini biasanya berisi `-` walaupun anggotanya akun domain, jadi pakai `MemberSid` [S9].
- `TargetSid` di 4732 adalah SID grup, sedangkan `TargetSid` di 4720 adalah SID akun baru [S9][S17]. Untuk mengaitkan "akun dibuat lalu dimasukkan ke grup", cocokkan `TargetSid` dari 4720 dengan `MemberSid` dari 4728/4732/4756.
- 4720 punya atribut yang layak dicek pada akun baru, misalnya `PrimaryGroupId` selain 513 atau `SidHistory` yang terisi [S17].

Dokumentasi yang dibuka untuk Day ini adalah halaman 4732; pola field 4728 dan 4756 serupa, dan nama field persisnya perlu dicek di lab-mu.

### 1.8 Proses, persistence, dan log yang dihapus: 4688, 4698, 7045, 1102

Setelah tahu sesi adm.rina mengubah grup, L2 akan bertanya apa lagi yang dijalankan sesi itu dan apakah ada yang ditanam untuk bertahan.

**4688 (A new process has been created)** ditulis setiap proses dimulai [S3]. Field pentingnya: `NewProcessName` (path proses baru), `ParentProcessName` (Creator Process Name, ditambahkan di versi 2), `CommandLine` (kosong tanpa setelan di bagian 1.2), `TokenElevationType`, dan `MandatoryLabel` [S3]. `TokenElevationType` `%%1937` berarti token elevated, misalnya program dijalankan dengan Run as administrator; Microsoft menyarankan memantau nilai ini di workstation standar bila akunnya akun manusia [S3]. Nilai `NewProcessId` dan `ProcessId` dalam heksadesimal dan bisa dipakai ulang oleh Windows, jadi menyusun pohon proses dari 4688 rapuh; Day 04 memakai `ProcessGuid` Sysmon untuk itu.

**4698 (A scheduled task was created)** ditulis setiap task baru dibuat [S12]. `TaskName` berisi path task di Task Scheduler Library, dan `TaskContent` berisi definisi task dalam XML, termasuk elemen `<Command>` yang dijalankan [S12]. Microsoft menyarankan memantau semua pembuatan task di komputer kritis, task di root library (nama seperti `\NAMA_TASK`), dan task yang `TaskContent`-nya memuat `<LogonType>Password</LogonType>` karena password akun task disimpan dan bisa diambil oleh admin [S12]. Di Windows 10 1903 ke atas, event ini membawa field tambahan seperti `ClientProcessId` dan `ParentProcessId` [S12]. Daftar field di research.splunk.com untuk 4698 juga memuat nama gaya klasik `Task_Name` dan `Task_Content` [S18], jadi cek mana yang terisi di data-mu.

**7045 (service baru terpasang)** ada di log System, bukan Security. Di add-on 11.0.3 sumbernya `XmlWinEventLog:System`, dengan field `ServiceName`, `ImagePath`, `ServiceType`, `StartType`, dan `AccountName` [S14]. `AccountName` adalah akun yang menjalankan service, bukan orang yang memasangnya. `ImagePath` yang berisi `powershell.exe`, `cmd.exe /c`, atau path di folder user adalah sinyal kuat. Contoh event di research.splunk.com sendiri memperlihatkan `ImagePath` berisi perintah PowerShell tersembunyi [S14].

**1102 (The audit log was cleared)** ditulis setiap Security log dihapus. Microsoft menyebut event ini biasanya tidak terlihat dan menyarankan menyelidiki setiap kemunculannya [S13]. Appendix L memberinya prioritas Medium to High [S4]. Struktur XML-nya berbeda: akun pelaku ada di `UserData > LogFileCleared`, bukan `EventData`, dan provider-nya `Microsoft-Windows-Eventlog` [S13]. Add-on 11.0.3 tetap mengekstrak `SubjectUserName` dari situ menurut daftar field research.splunk.com [S19]. Karena Splunk sudah menyimpan salinan event sebelum log dihapus di host, 1102 di Splunk adalah bukti, bukan kehilangan; yang hilang hanya event yang belum sempat dikirim forwarder.

## 2. Contoh SPL dan langkah praktis

Semua keluaran di bagian ini adalah keluaran ilustrasi, bukan hasil eksekusi. Asumsi PT JAB: index `wineventlog`, add-on Windows 11.0.3, format XML (`sourcetype=XmlWinEventLog`, `source=XmlWinEventLog:Security` dan `XmlWinEventLog:System`), Splunk Enterprise 10.6. Bagian 2.3 memakai format klasik untuk memperlihatkan field multivalue. Semua search jalan di app Search & Reporting tanpa ES.

### 2.1 Cek format dan field sebelum menulis search

Sebelum menjawab pertanyaan analyst L1, pastikan dulu event apa yang benar-benar ada dan dalam format apa.

**Tujuan:** melihat kombinasi sourcetype, source, dan event ID yang masuk 24 jam terakhir.

```
index=wineventlog earliest=-24h
| stats count BY sourcetype source EventCode
| sort sourcetype source - count
```

- `stats count BY sourcetype source EventCode`: satu baris per kombinasi; inilah inventaris cepat.
- `sort sourcetype source - count`: kelompokkan per source, event terbanyak di atas.

Keluaran ilustrasi (dipotong):

```
sourcetype       source                    EventCode  count
WinEventLog      WinEventLog:Security      4625       312
XmlWinEventLog   XmlWinEventLog:Security   4624       1840211
XmlWinEventLog   XmlWinEventLog:Security   4672       902554
XmlWinEventLog   XmlWinEventLog:Security   4625       4120
XmlWinEventLog   XmlWinEventLog:Security   4688       611093
XmlWinEventLog   XmlWinEventLog:System     7045       3
```

**Cara membaca hasil:** baris pertama memperlihatkan masih ada forwarder yang mengirim format klasik. Alert lama yang memakai `Account_Name` mungkin dibuat untuk host-host itu. Cari host-nya dengan `index=wineventlog sourcetype=WinEventLog | stats count BY host`.
**Variasi:** `| fieldsummary maxvals=3` setelah filter satu event ID untuk melihat nama field yang terisi dan contoh nilainya.
**Kapan gagal:** rentang 24 jam di index besar bisa berat; untuk inventaris rutin pakai `tstats` (Day 25), tetapi `EventCode` bukan indexed field, jadi `tstats` hanya bisa sampai `sourcetype` dan `source`.

### 2.2 Login gagal: siapa, kenapa, dari mana

Ini jawaban untuk alert SOC-2026-0217 di JKT-JUMP01.

**Tujuan:** merangkum 4625 per akun target, logon type, dan kode status.

```
index=wineventlog source="XmlWinEventLog:Security" EventCode=4625 host=JKT-JUMP01 earliest=-6h
| stats count min(_time) AS first_seen max(_time) AS last_seen values(IpAddress) AS ip_asal
        BY TargetUserName LogonType Status SubStatus
| eval first_seen=strftime(first_seen, "%Y-%m-%d %H:%M:%S"), last_seen=strftime(last_seen, "%Y-%m-%d %H:%M:%S")
| sort - count
```

| Bagian | Penjelasan |
|---|---|
| `source="XmlWinEventLog:Security" EventCode=4625` | Filter channel dan event di awal pipeline, paling murah |
| `BY TargetUserName LogonType Status SubStatus` | Akun target (bukan Subject), cara logon, dan alasan gagal dalam satu baris |
| `values(IpAddress) AS ip_asal` | Semua IP asal untuk kombinasi itu |
| `strftime(...)` | Waktu dibuat terbaca; `stats` menyimpan `_time` sebagai epoch |

Keluaran ilustrasi:

```
TargetUserName  LogonType  Status      SubStatus   count  first_seen           last_seen            ip_asal
svc_backup      4          0xc000006d  0xc000006a  412    2026-10-13 22:30:04  2026-10-14 02:05:34  -
adm.rina        10         0xc000006d  0xc000006a  2      2026-10-14 01:50:41  2026-10-14 01:51:12  10.30.14.22
```

**Cara membaca hasil:** svc_backup gagal 412 kali dengan logon type 4 (batch), alasan password salah, tanpa IP asal. Dalam 3 jam 35 menit (22:30:04 sampai 02:05:34, 12.930 detik), 412 kegagalan berarti kira-kira satu percobaan setiap 31 detik. Pola teratur, akun service, logon batch lokal: sangat cocok dengan scheduled task yang masih memakai password lama. Ini benign, tetapi tetap butuh tiket perbaikan ke pemilik svc_backup. Baris kedua lebih penting: dua kali gagal RDP sebagai adm.rina dari 10.30.14.22 tepat sebelum 4624 jam 01.52. Untuk logon batch lokal, kolom IP asal biasanya kosong, `-`, atau loopback; cek di lab.
**Variasi (spraying):** ganti `host=JKT-JUMP01` dengan semua host, lalu `stats dc(TargetUserName) AS akun_unik count BY IpAddress | where akun_unik >= 10`. Banyak akun dari satu IP dengan sedikit percobaan per akun adalah pola spraying.
**Kapan gagal:** host yang mengirim format klasik tidak punya `TargetUserName`; jalankan versi klasik di bagian 2.3 untuk host itu.

### 2.3 Memisahkan Subject dan target di format klasik

Alert lama PT JAB memakai `Account_Name` dan menampilkan JKT-JUMP01$ bersama svc_backup. Search ini memperlihatkan kenapa dan cara memperbaikinya.

**Tujuan:** memecah `Account_Name` multivalue menjadi akun Subject dan akun target.

```
index=wineventlog sourcetype=WinEventLog source="WinEventLog:Security" EventCode=4625 earliest=-6h
| eval n_akun=mvcount(Account_Name)
| eval akun_subject=if(n_akun=2, mvindex(Account_Name, 0), null())
| eval akun_target=if(n_akun=2, mvindex(Account_Name, 1), Account_Name)
| stats count BY host n_akun akun_subject akun_target Logon_Type
```

- `mvcount(Account_Name)`: jumlah nilai di field itu. Nilai 2 berarti dua blok akun terekstrak.
- `mvindex(Account_Name, 0)` dan `mvindex(Account_Name, 1)`: ambil nilai pertama dan kedua (indeks mulai dari 0).
- `if(n_akun=2, ..., Account_Name)`: bila hanya satu nilai, pakai nilai itu sebagai target supaya baris tidak hilang.

Keluaran ilustrasi:

```
host         n_akun  akun_subject  akun_target  Logon_Type  count
JKT-WS-0412  2       JKT-WS-0412$  svc_backup   4           96
```

**Cara membaca hasil:** setelah dipecah, jelas bahwa akun yang gagal adalah svc_backup; JKT-WS-0412$ hanya Subject yang melaporkan (SYSTEM menjalankan task). Search yang memakai `stats count BY Account_Name` akan menghitung 96 event ini dua kali, sekali untuk tiap nilai.
**Kapan gagal:** urutan nilai multivalue tidak selalu dijamin sama di semua versi add-on; uji di lab dengan event yang Subject-nya kamu ketahui. Event dengan Subject `-` bisa menghasilkan nilai kosong yang dibuang, sehingga `n_akun=1`.

### 2.4 Logon type 10 dari sumber yang belum pernah terlihat

Logon adm.rina dari 10.30.14.22 perlu dibandingkan dengan kebiasaannya.

**Tujuan:** menemukan pasangan akun dan IP RDP yang muncul 24 jam terakhir tetapi tidak pernah muncul dalam 29 hari sebelumnya.

```
index=wineventlog source="XmlWinEventLog:Security" EventCode=4624 LogonType=10 earliest=-30d
| eval periode=if(_time >= relative_time(now(), "-24h"), "baru", "baseline")
| stats count(eval(periode="baseline")) AS n_baseline count(eval(periode="baru")) AS n_baru
        max(_time) AS terakhir values(host) AS ke_host BY TargetUserName IpAddress
| where n_baru > 0 AND n_baseline = 0
| eval terakhir=strftime(terakhir, "%Y-%m-%d %H:%M:%S")
```

| Bagian | Penjelasan |
|---|---|
| `LogonType=10` | Hanya RDP |
| `relative_time(now(), "-24h")` | Batas antara periode baru dan baseline |
| `count(eval(periode="baseline"))` | Hitung bersyarat di dalam `stats` |
| `where n_baru > 0 AND n_baseline = 0` | Pasangan akun dan IP yang benar-benar baru |

Keluaran ilustrasi:

```
TargetUserName  IpAddress     n_baseline  n_baru  terakhir             ke_host
adm.rina        10.30.14.22   0           1       2026-10-14 01:52:07  JKT-JUMP01
```

**Cara membaca hasil:** adm.rina belum pernah RDP dari subnet Bandung selama baseline. Itu belum bukti kompromi (bisa saja sedang dinas di Bandung), tetapi bersama dua kegagalan sebelumnya di bagian 2.2 dan jamnya, cukup untuk lanjut ke sesi itu.
**Variasi:** ganti `IpAddress` dengan `host` untuk mencari akun yang RDP ke server yang belum pernah ia sentuh.
**Kapan gagal:** IP dinamis (VPN, DHCP) membuat semua IP terlihat baru; tambahkan lookup IP ke lokasi atau subnet. Rentang 30 hari pada 4624 bisa berat; untuk detection rutin, pakai summary atau data model (Day 25, 40).

### 2.5 Satu sesi: 4624, 4672, dan proses yang dijalankan

Sekarang ikuti sesi adm.rina jam 01.52 di JKT-JUMP01.

**Tujuan:** mengelompokkan 4624, 4672, dan 4688 berdasarkan Logon ID yang sama.

```
index=wineventlog source="XmlWinEventLog:Security" host=JKT-JUMP01 EventCode IN (4624, 4672, 4688)
    earliest="10/14/2026:01:45:00" latest="10/14/2026:02:30:00"
| eval logon_id=lower(if(EventCode=4624, TargetLogonId, SubjectLogonId))
| eval detail=case(EventCode=4624, "logon type ".LogonType." dari ".IpAddress,
                   EventCode=4672, "privileges: ".PrivilegeList,
                   EventCode=4688, NewProcessName." ".CommandLine)
| stats values(TargetUserName) AS akun_target values(SubjectUserName) AS akun_subject
        list(EventCode) AS eid list(detail) AS rincian BY logon_id
| where isnotnull(mvfind(eid, "^4624$"))
```

- `EventCode IN (4624, 4672, 4688)`: operator `IN` di command `search`.
- `lower(...)`: Logon ID heksadesimal bisa berbeda huruf besar-kecil antar event; samakan dulu.
- `if(EventCode=4624, TargetLogonId, SubjectLogonId)`: di 4624 sesi baru ada di blok target; di 4672 dan 4688 sesi itu muncul sebagai Subject (bagian 1.6).
- `list(...)`: menyimpan urutan dan duplikat, berbeda dengan `values()` yang mengurutkan dan membuang duplikat. `list()` dibatasi 100 nilai.
- `where isnotnull(mvfind(eid, "^4624$"))`: hanya Logon ID yang punya event pembuka sesi di rentang ini.

Keluaran ilustrasi:

```
logon_id    akun_target  akun_subject  eid    rincian
0x5a3f21c   adm.rina     adm.rina      4624   logon type 10 dari 10.30.14.22
                                       4672   privileges: SeSecurityPrivilege SeBackupPrivilege SeRestorePrivilege SeTakeOwnershipPrivilege SeDebugPrivilege ...
                                       4688   C:\Windows\System32\cmd.exe
                                       4688   C:\Windows\System32\net.exe net group "Domain Admins" budi.santoso /add /domain
```

**Cara membaca hasil:** sesi RDP adm.rina dari Bandung mendapat hak istimewa admin, lalu menjalankan `net group ... /add /domain`. Kolom `akun_subject` berisi adm.rina karena di 4672 dan 4688 akun sesi tercatat sebagai Subject. Perintah `net group` di sesi ini cocok dengan 4728 jam 01.57 di DC.
**Kapan gagal:** `CommandLine` kosong bila setelan command line belum aktif (bagian 1.2). Akun admin dengan sesi berpasangan bisa membuat proses tercatat di Logon ID pasangan; cek `TargetLinkedLogonId` di 4624 dan ulangi untuk Logon ID itu.

### 2.6 Siapa menambahkan siapa ke grup admin

Search ini menjawab bagian terakhir pesan analyst L1.

**Tujuan:** menampilkan semua penambahan anggota ke grup kritis, dengan pelaku, anggota, dan grup di kolom yang benar.

```
index=wineventlog source="XmlWinEventLog:Security" EventCode IN (4728, 4732, 4756) earliest=-24h
| eval grup=TargetUserName, pelaku=SubjectUserName
| eval anggota=if(isnull(MemberName) OR MemberName="-", MemberSid, MemberName)
| search grup IN ("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators")
| table _time host EventCode pelaku anggota grup
```

- `grup=TargetUserName`: di event grup, `TargetUserName` adalah nama grup (bagian 1.7).
- `if(isnull(MemberName) OR MemberName="-", MemberSid, MemberName)`: untuk grup lokal `MemberName` berisi `-`, jadi pakai SID. `coalesce()` tidak cukup karena `-` bukan null.
- `search grup IN (...)`: filter setelah `eval` memakai command `search` dengan `IN`; nilai tidak peka huruf besar-kecil di `search`.

Keluaran ilustrasi:

```
_time                host        EventCode  pelaku    anggota                                               grup
2026-10-14 01:57:13  JKT-DC01    4728       adm.rina  CN=Budi Santoso,OU=Staff,DC=corp,DC=jab,DC=example    Domain Admins
```

**Cara membaca hasil:** pelaku adm.rina, dari sesi yang sudah ditelusuri di bagian 2.5, menambahkan akun staf biasa ke Domain Admins pukul 01.57. Tanpa change request yang cocok, ini alasan eskalasi ke L2.
**Variasi (akun baru langsung masuk grup):**

```
index=wineventlog source="XmlWinEventLog:Security" EventCode IN (4720, 4728, 4732, 4756) earliest=-24h
| eval sid_akun=if(EventCode=4720, TargetSid, MemberSid)
| stats count(eval(EventCode=4720)) AS dibuat count(eval(in(EventCode, "4728", "4732", "4756"))) AS masuk_grup
        values(TargetUserName) AS nama_dan_grup min(_time) AS mulai max(_time) AS selesai BY sid_akun
| where dibuat > 0 AND masuk_grup > 0 AND (selesai - mulai) <= 3600
```

Kolom `nama_dan_grup` sengaja berisi campuran nama akun (dari 4720) dan nama grup (dari event grup), karena `TargetUserName` berarti hal berbeda di dua event itu.
**Kapan gagal:** grup kritis dengan nama lokal lain (misalnya diganti bahasa) tidak tertangkap daftar nama; lebih aman memakai SID grup terkenal. Grup bersarang (grup dimasukkan ke grup admin) memberi hak tanpa akun individu muncul di `MemberName`.

### 2.7 Persistence dan penghapusan log dalam satu tampilan

Langkah terakhir sebelum eskalasi: apakah ada task, service, atau log yang dihapus di host terkait?

**Tujuan:** menampilkan 4698, 7045, dan 1102 dari Security dan System dalam satu tabel.

```
index=wineventlog host IN (JKT-JUMP01, JKT-DC01) earliest="10/14/2026:01:30:00" latest="10/14/2026:03:00:00"
    ((source="XmlWinEventLog:Security" EventCode IN (4698, 1102)) OR (source="XmlWinEventLog:System" EventCode=7045))
| eval jenis=case(EventCode=4698, "task baru", EventCode=7045, "service baru", EventCode=1102, "Security log dihapus")
| eval rincian=case(EventCode=4698, TaskName, EventCode=7045, ServiceName." = ".ImagePath." (run as ".AccountName.")", EventCode=1102, "-")
| eval pelaku=if(in(EventCode, "4698", "1102"), SubjectUserName, "tidak tercatat di EventData")
| table _time host jenis pelaku rincian
```

- Dua kelompok kondisi digabung dengan `OR` di dalam tanda kurung supaya `source` dan `EventCode` tidak tertukar pasangannya.
- `pelaku`: 4698 dan 1102 punya Subject; 7045 tidak mencatat siapa yang memasang service di `EventData` (`AccountName` adalah akun yang menjalankan service). `UserID` di bagian System event berisi SID; cek isinya di lab.

Keluaran ilustrasi:

```
_time                host        jenis       pelaku    rincian
2026-10-14 02:03:40  JKT-JUMP01  task baru   adm.rina  \OneDriveSyncCheck
```

**Cara membaca hasil:** satu task baru di root library, dibuat oleh sesi yang sama, enam menit setelah perubahan grup. Ambil `TaskContent` event itu untuk melihat `<Command>`-nya, lalu masukkan ke tiket. Tidak ada 1102, jadi log Security di dua host itu utuh untuk rentang ini.
**Kapan gagal:** task yang dibuat lewat cara yang tidak memicu 4698 (misalnya audit Other Object Access tidak aktif), atau service yang dipasang dengan cara yang tidak menulis 7045. Pakai Sysmon EID 13 untuk perubahan registry service sebagai lapisan kedua (Day 04).

**Ringkasan untuk tiket SOC-2026-0217:** alert login gagal svc_backup adalah benign (password lama di task, buat tiket perbaikan). Eskalasikan ke L2 sebagai tiket baru: RDP adm.rina dari 10.30.14.22 yang belum pernah terlihat, sesi elevated, `net group` ke Domain Admins untuk budi.santoso, dan task baru di JKT-JUMP01. Sertakan Logon ID `0x5a3f21c` dan search bagian 2.5 sampai 2.7.

## 3. Lab praktik

Lab memakai dua sumber: BOTS v1 (format klasik, data statis dari 2016; ukur rentangnya dulu dengan cara Day 01 bagian 2.5) dan VM Windows lab terisolasi milikmu (format XML). Semua perintah Windows di bawah dijalankan di VM lab dengan snapshot, bukan di mesin kerja.

1. **Rentang waktu BOTS v1.** Jalankan `| tstats min(_time) AS awal max(_time) AS akhir where index=botsv1 sourcetype="WinEventLog:Security" | eval awal=strftime(awal, "%F %T"), akhir=strftime(akhir, "%F %T")`. Catat rentangnya dan pakai di semua search berikutnya. Jangan memakai `earliest=-7d` pada dataset ini.
2. **Inventaris event BOTS v1.** Dengan rentang dari langkah 1 (misalnya `earliest="08/01/2016:00:00:00" latest="09/01/2016:00:00:00"`), jalankan `index=botsv1 sourcetype="WinEventLog:Security" | stats count BY EventCode | sort - count`. Catat lima event terbanyak.
3. **Field multivalue di data klasik.** Pada 4624 BOTS v1, jalankan `| eval n=mvcount(Account_Name) | stats count BY n`. Ambil satu event dengan `n=2`, buka event mentahnya, dan pastikan nilai pertama `Account_Name` adalah Subject. Lakukan hal yang sama untuk `Logon_ID`. Simpan hasilnya sebagai catatan "urutan multivalue di versi add-on ini".
4. **Distribusi logon type.** Jalankan `stats count BY Logon_Type host` untuk 4624 BOTS v1. Tulis satu kalimat per logon type yang muncul: wajar atau tidak untuk jenis host itu.
5. **Siapkan VM lab.** Di VM Windows, aktifkan audit dengan `auditpol /set /subcategory:"Logon" /success:enable /failure:enable`, `auditpol /set /subcategory:"Process Creation" /success:enable`, `auditpol /set /subcategory:"Security Group Management" /success:enable`, `auditpol /set /subcategory:"User Account Management" /success:enable`, dan `auditpol /set /subcategory:"Other Object Access Events" /success:enable`. Aktifkan juga setelan Include command line in process creation events di Local Group Policy. Nama subkategori bisa berbeda di Windows berbahasa lain; cek dengan `auditpol /list /subcategory:*`.
6. **Input forwarder.** Di forwarder VM, siapkan input berikut (cek default `inputs.conf` add-on versi-mu dulu):

   ```
   [WinEventLog://Security]
   disabled = 0
   renderXml = true
   index = wineventlog

   [WinEventLog://System]
   disabled = 0
   renderXml = true
   index = wineventlog
   ```

7. **Buat event uji.** Di VM: lima kali login gagal ke akun lokal uji dengan password salah, satu kali dengan username yang tidak ada, buat akun `labuser01` (`net user labuser01 <password> /add`), masukkan ke Administrators (`net localgroup Administrators labuser01 /add`), buat task jinak (`schtasks /create /tn LabTask /tr "cmd.exe /c echo lab" /sc once /st 23:59`), lalu hapus Security log dari Event Viewer.
8. **Temukan semuanya di Splunk.** Jalankan versi bagian 2.2, 2.6, dan 2.7 dengan host VM-mu. Bandingkan `SubStatus` untuk password salah dan username tidak ada. Pastikan 4732 menampilkan `MemberName` berisi `-` dan `MemberSid` berisi SID labuser01.
9. **Bandingkan format.** Ubah `renderXml = false` untuk Security, restart forwarder, ulangi langkah 7 sebagian, lalu bandingkan nama field event yang sama dalam dua format. Kembalikan ke `true` setelah selesai.

**Hasil yang sebaiknya tersimpan:**

- Rentang waktu BOTS v1 yang terverifikasi dan lima event ID terbanyaknya.
- Catatan urutan nilai `Account_Name` dan `Logon_ID` di data klasik.
- Tabel pasangan nama field klasik dan XML untuk 4624, 4625, 4688, dan 4732 dari lab-mu sendiri.
- Tangkapan nilai `Status`/`SubStatus` untuk password salah dan username tidak ada.
- Satu search "akun baru masuk grup admin" yang sudah diuji menangkap labuser01.
- Bukti 1102 terekam di Splunk dengan `SubjectUserName` yang benar walau log di VM sudah kosong.

**Variasi tantangan:** jadikan search bagian 2.6 sebuah scheduled alert (Day 09) yang hanya memicu untuk grup kritis, dengan throttle per `anggota`. Lalu tulis satu paragraf: kenapa alert ini sebaiknya dipicu per kejadian, sedangkan alert 4625 sebaiknya berbasis ambang.

## 4. Troubleshooting

Tabel ini untuk saat search tidak mengembalikan yang kamu harapkan; mulai dari kolom gejala.

| Gejala | Kemungkinan penyebab | Cara memeriksa atau memperbaiki |
|---|---|---|
| Search `sourcetype=WinEventLog:Security` kosong di data baru | Add-on modern memakai sourcetype generik | Saring dengan `source="XmlWinEventLog:Security"` atau `source="WinEventLog:Security"` [S8] |
| `TargetUserName` tidak ada | Event dikirim format klasik | Cek `sourcetype`; pakai `Account_Name` dengan `mvindex`, atau ubah `renderXml` |
| Jumlah akun unik terlihat dua kali lipat | `Account_Name` multivalue dihitung per nilai | `mvcount`, lalu pilih nilai target (bagian 2.3) |
| 4688 ada tetapi `CommandLine` kosong | Setelan command line tidak aktif | Aktifkan Include command line in process creation events [S16] |
| 4688 tidak ada sama sekali | Audit Process Creation tidak aktif | `auditpol /get /subcategory:"Process Creation"` di host [S16] |
| Event audit hilang setelah GPO diterapkan | Setelan audit dasar menimpa Advanced Audit Policy | Aktifkan setelan force subcategory dan cek 4719 [S16] |
| `MemberName` berisi `-` | Grup lokal | Pakai `MemberSid` [S9] |
| Logon ID tidak cocok antar event | Beda huruf besar-kecil, atau sesi berpasangan | `lower()`; cek `TargetLinkedLogonId` [S1] |
| 7045 tidak ditemukan dengan filter Security | 7045 ada di log System | `source="XmlWinEventLog:System"` [S14] |
| Search BOTS v1 kosong | Rentang waktu relatif pada data 2016 | Pakai rentang absolut dari lab langkah 1 |

## 5. Kesalahan umum dan jebakan

- Menghitung `Account_Name` klasik tanpa memecah multivalue. Akun komputer (`HOST$`) dan SYSTEM ikut terhitung sebagai "akun yang gagal login".
- Menganggap `TargetUserName` selalu berarti akun manusia. Di 4728, 4732, dan 4756, field itu berisi nama grup [S9].
- Menganggap Subject di 4625 adalah penyerang. Subject adalah pihak yang melaporkan atau meminta logon, sering SYSTEM; sumber percobaan ada di `IpAddress` dan `WorkstationName` [S2].
- Menilai 4625 hanya dari `Status`. `0xC000006D` adalah kode umum; detailnya di `SubStatus` [S6].
- Menyamakan logon type 3 dengan "login mencurigakan dari jaringan". Tipe 3 adalah logon paling umum; nilainya ada pada akun dan sumber, bukan tipenya [S1].
- Mengandalkan 4688 untuk pohon proses. PID heksadesimal dipakai ulang, dan tanpa setelan command line isinya tipis; Sysmon lebih tepat (Day 04).
- Menganggap event tidak ada berarti aktivitas tidak terjadi. Periksa dulu audit policy host itu [S4].
- Memprioritaskan event dari angka prioritas Appendix L saja. 4728 berprioritas Low, tetapi penambahan ke Domain Admins tetap layak diselidiki satu per satu [S4][S9].
- Menulis search dengan `sourcetype=WinEventLog:Security` dari contoh lama lalu menyimpulkan "tidak ada login gagal". Cek dulu penamaan sourcetype di instance-mu (bagian 1.1).
- `[komunitas, belum terkonfirmasi]` Forum praktisi sering menyebut bahwa mengganti `renderXml` di tengah jalan membuat satu host punya dua sourcetype sekaligus, sehingga alert hanya melihat separuh data. Belum dikonfirmasi dokumentasi resmi yang dibuka untuk Day ini; uji di lab langkah 9.

## 6. Catatan terkini

Bagian ini menampung versi dan tanggal sumber. Tidak ada yang mengubah search di atas, kecuali bila instance-mu masih memakai add-on lama.

- Splunk Add-on for Microsoft Windows terbaru di Splunkbase adalah 11.0.3, dirilis 1 Oktober 2026, kompatibel dengan Splunk Enterprise dan Cloud 9.3 sampai 10.6 [S7]. Halaman Splunkbase mencantumkan kompatibilitas CIM 5.x, sedangkan acuan catatan ini CIM 6.4; cek matriks kompatibilitas add-on sebelum mengandalkan pemetaan ke data model Authentication atau Endpoint.
- Halaman Splunkbase yang sama mengingatkan bahwa versi 5.0.0 membawa perubahan yang tidak kompatibel ke belakang dan butuh langkah upgrade terdokumentasi, serta bahwa versi 6.0.0 menyerap add-on DNS dan Active Directory yang dulu terpisah [S7]. Perubahan penamaan sourcetype di bagian 1.1 berasal dari era ini.
- Halaman data source research.splunk.com untuk event Security dan System sudah diuji dengan add-on 11.0.3 dan dimutakhirkan Mei 2026 [S5][S6][S14].
- Dokumentasi event audit Microsoft yang dipakai di Day ini berada di bagian arsip Windows 10 (previous-versions), tetapi masih diperbarui pada April dan Mei 2026 dan tetap menjadi acuan resmi arti field [S1][S2][S3]. 4624 versi 2 (Windows 10) menambahkan `ElevatedToken`, `RestrictedAdminMode`, `VirtualAccount`, dan `TargetLinkedLogonId`; 4688 versi 2 menambahkan Target Subject dan Creator Process Name [S1][S3].
- Appendix L diperbarui Februari 2026 dan menambahkan catatan bahwa perilaku logging bawaan berbeda per versi dan edisi Windows [S4].
- BOTS v1 dibuat dengan Splunk Enterprise 6.5.2 dan add-on Windows 4.8.3, dirilis dengan lisensi CC0 [S15].

## 7. Cheat sheet

```
SOURCE (add-on modern)   XmlWinEventLog:Security | XmlWinEventLog:System   sourcetype=XmlWinEventLog
BOTS v1 / data lama      sourcetype="WinEventLog:Security"
XML vs KLASIK            TargetUserName vs Account_Name (2 nilai: Subject, target)
                         LogonType vs Logon_Type | IpAddress vs Source_Network_Address

LOGON TYPE  2 lokal | 3 jaringan | 4 batch/task | 5 service | 7 unlock
            8 cleartext | 9 NewCredentials | 10 RDP | 11 cached
4625        Status 0xC000006D umum -> lihat SubStatus
            0xC000006A pwd salah | 0xC0000064 user tak ada | 0xC0000234 terkunci
            0xC0000072 disabled | 0xC0000193 expired | 0xC000015B logon type ditolak

SESI        4624 TargetLogonId = 4672 SubjectLogonId = 4688 SubjectLogonId
4648        kredensial eksplisit (runas, task): Subject vs TargetUserName
GRUP        4728 global | 4732 lokal | 4756 universal
            pelaku=SubjectUserName  anggota=MemberName/MemberSid  grup=TargetUserName
AKUN        4720 dibuat (TargetSid = akun baru) | 4722 aktif | 4724 reset pwd
PERSIST     4698 task (TaskName, TaskContent) | 7045 service (System: ServiceName, ImagePath)
JEJAK       1102 Security log dihapus (pelaku di UserData) -> selalu selidiki
AUDIT       4688 butuh Audit Process Creation + Include command line

MULTIVALUE  eval n=mvcount(Account_Name) | eval tgt=mvindex(Account_Name,1)
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** Alert PT JAB menampilkan dua akun untuk satu event 4625 di format klasik: JKT-JUMP01$ dan svc_backup. Analyst L1 menyimpulkan dua akun gagal login. Benarkah?

<details><summary>Jawaban</summary>

Tidak. 4625 punya dua blok akun: Subject (yang melaporkan atau meminta logon) dan Account For Which Logon Failed (target). Di format klasik keduanya berlabel "Account Name", sehingga add-on mengekstraknya menjadi satu field `Account_Name` dengan dua nilai. JKT-JUMP01$ adalah Subject, akun komputer yang mewakili SYSTEM menjalankan task; svc_backup adalah akun yang benar-benar gagal. Pecah dengan `mvcount` dan `mvindex`, atau pakai `TargetUserName` di format XML. Lihat bagian 1.5 dan 2.3.

</details>

**2. Skenario keputusan.** Search `index=wineventlog sourcetype="WinEventLog:Security" EventCode=4625` di instance PT JAB yang baru di-upgrade mengembalikan nol hasil, padahal kemarin ada ratusan. Langkah pertama yang paling tepat?

- A. Simpulkan tidak ada login gagal dan tutup alert.
- B. Periksa kombinasi `sourcetype` dan `source` yang masuk, karena add-on modern memakai sourcetype generik dan memindahkan nama channel ke `source`.
- C. Minta tim Windows mengaktifkan ulang audit Logon di semua host.

<details><summary>Jawaban</summary>

B. Add-on modern mengubah sourcetype spesifik menjadi `XmlWinEventLog` atau `WinEventLog`, dan channel dibedakan lewat `source`, jadi filter sourcetype lama tidak lagi cocok. Search inventaris di bagian 2.1 akan langsung memperlihatkannya. A keliru karena nol hasil di sini adalah masalah filter, bukan bukti tidak ada kejadian. C mungkin diperlukan bila event memang tidak ditulis, tetapi itu bukan langkah pertama; cek dulu apakah data ada dengan nama lain. Lihat bagian 1.1 dan 2.1.

</details>

**3. Pertanyaan jebakan.** "4672 punya akun di blok Subject, jadi akun itu yang memberi hak istimewa ke sesi lain." Benarkah?

<details><summary>Jawaban</summary>

Tidak. 4672 tidak punya blok target; akun di Subject adalah akun yang menerima hak istimewa pada logon baru. Karena itu 4672 dikaitkan ke 4624 dengan mencocokkan `SubjectLogonId` di 4672 dengan `TargetLogonId` di 4624. Arti "Subject" berubah per event, jadi baca deskripsi event dulu. Lihat bagian 1.6 dan 2.5.

</details>

**4. Skenario keputusan.** Search grup admin menampilkan 4732 dengan `MemberName` bernilai `-`. Bagaimana menentukan akun yang ditambahkan?

- A. Anggap event rusak dan abaikan.
- B. Pakai `TargetUserName`, karena field itu berisi akun target.
- C. Pakai `MemberSid`, karena untuk grup lokal `MemberName` biasanya berisi `-` walau anggotanya akun domain.

<details><summary>Jawaban</summary>

C. Microsoft mencatat `MemberName` di 4732 biasanya `-` untuk grup lokal, sehingga identitas anggota ada di `MemberSid`. A keliru karena event itu valid dan justru penting. B keliru karena di event grup `TargetUserName` adalah nama grup, bukan anggota. `coalesce()` juga tidak membantu karena `-` bukan null; pakai `if()` seperti di bagian 2.6. Lihat bagian 1.7 dan 2.6.

</details>

**5. Jelaskan ulang.** Jelaskan kepada analyst L1 yang baru masuk, dalam tiga kalimat, kenapa alert login gagal svc_backup di JKT-JUMP01 kemungkinan benign tetapi logon adm.rina tidak.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Kegagalan svc_backup bertipe logon 4 (batch), alasan password salah, tanpa IP asal, dan berulang kira-kira tiap 31 detik selama berjam-jam, polanya scheduled task yang masih memakai password lama. Logon adm.rina bertipe 10 (RDP) dari subnet Bandung yang belum pernah dipakai akun itu selama 30 hari, didahului dua kegagalan, lalu sesinya elevated dan menjalankan `net group` untuk menambahkan akun ke Domain Admins. Yang pertama cukup tiket perbaikan ke pemilik akun service, yang kedua harus dieskalasi ke L2 dengan Logon ID dan search pendukungnya."

Kesalahan yang sering muncul:
- Menilai dari jumlah event saja: 412 kegagalan terlihat lebih seram daripada dua kegagalan dan satu sukses.
- Menganggap logon type 10 ke jump host otomatis mencurigakan, padahal jump host memang untuk RDP; yang aneh adalah kombinasi akun, sumber, waktu, dan aktivitas sesudahnya.
- Lupa menyebut bahwa alert benign tetap butuh tindakan (perbaikan password task).

</details>

**6. Pertanyaan jebakan.** "Ada 1102 di Splunk untuk JKT-DC01, artinya semua bukti di DC itu sudah hilang." Benarkah?

<details><summary>Jawaban</summary>

Tidak sepenuhnya. 1102 berarti Security log di host itu dihapus, dan Microsoft menyarankan menyelidiki setiap kemunculannya. Namun event yang sudah dikirim forwarder sebelum penghapusan tetap tersimpan di Splunk; yang hilang hanya event yang belum terkirim. Pelaku penghapusan tercatat di `UserData > LogFileCleared`, yang diekstrak add-on sebagai `SubjectUserName`. Lihat bagian 1.8.

</details>

**7. Interview question (English).** "Walk me through how you'd investigate a suspicious RDP logon to a server using Windows Security logs in Splunk."

<details><summary>Sample answer</summary>

"First I'd confirm how the data is indexed, because modern versions of the Windows add-on use a generic sourcetype and keep the channel in the source field, and field names differ between classic and XML format. Then I'd look at the 4624 with logon type 10: the target account, the source IP, and whether that account-and-IP pair appears in a 30-day baseline. I'd check the 4625s just before it, using SubStatus rather than Status to see why they failed. Next I'd take the target logon ID from the 4624 and follow it through 4672 for privileges and 4688 for the processes started in that session, keeping in mind that in those events the session account shows up as the Subject. Finally I'd look for follow-on changes such as 4728 or 4732 group additions, 4698 scheduled tasks, 7045 services in the System log, and any 1102 log clearing, and I'd note which audit policies were actually enabled so the gaps are explicit in the ticket."

What makes this answer strong: it starts with data validation instead of assuming field names, uses the logon ID to stitch one session together, shows awareness of Subject versus target, and states the audit-policy limits of the evidence.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Microsoft Learn: 4624(S) An account was successfully logged on | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624 | primer | diperbarui 2026-04-27; diakses 2026-10-14 | Tinggi. Logon type, field versi 2, rekomendasi pemantauan |
| S2 | Microsoft Learn: 4625(F) An account failed to log on | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625 | primer | 2026-03-29, diperbarui 2026-05-01; diakses 2026-10-14 | Tinggi. Kode Status/Sub Status dan rekomendasi |
| S3 | Microsoft Learn: 4688(S) A new process has been created | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688 | primer | diperbarui 2026-04-27; diakses 2026-10-14 | Tinggi. Field, versi event, TokenElevationType |
| S4 | Microsoft Learn: Appendix L, Events to Monitor | https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/appendix-l--events-to-monitor | primer | 2025-05-30, diperbarui 2026-02-16; diakses 2026-10-14 | Tinggi. Prioritas event dan catatan audit bawaan |
| S5 | Splunk Security Content: Data Source Windows Event Log Security 4624 | https://research.splunk.com/sources/08682968-0366-4882-9559-fe4fe018a846/ | primer (Splunk) | 2026-05-13; diakses 2026-10-14 | Tinggi. Source, sourcetype, daftar field add-on 11.0.3 |
| S6 | Splunk Security Content: Data Source Windows Event Log Security 4625 | https://research.splunk.com/sources/365a02c2-7d18-4baf-b76e-d90c20bbe6ed/ | primer (Splunk) | diakses 2026-10-14 | Tinggi. Contoh Status dan SubStatus |
| S7 | Splunkbase: Splunk Add-on for Microsoft Windows | https://splunkbase.splunk.com/app/742 | primer | versi 11.0.3, 2026-10-01; diakses 2026-10-14 | Tinggi untuk versi dan kompatibilitas |
| S8 | Splunk Lantern: Using ingest actions with source types that are renamed with props and transforms | https://lantern.splunk.com/Splunk_Platform/Product_Tips/Data_Management/Using_ingest_actions_with_source_types_that_are_renamed_with_props_and_transforms | primer (Splunk) | tanggal tidak tercantum; diakses 2026-10-14 | Sedang-tinggi. Penjelasan rename sourcetype add-on Windows |
| S9 | Microsoft Learn: 4732(S) A member was added to a security-enabled local group | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4732 | primer | diperbarui 2026-04-27; diakses 2026-10-14 | Tinggi. MemberName, MemberSid, TargetUserName sebagai grup |
| S10 | Microsoft Learn: 4648(S) A logon was attempted using explicit credentials | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4648 | primer | diperbarui 2026-04-27; diakses 2026-10-14 | Tinggi |
| S11 | Microsoft Learn: 4672(S) Special privileges assigned to new logon | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4672 | primer | diperbarui 2026-04-27; diakses 2026-10-14 | Tinggi. Daftar hak sensitif |
| S12 | Microsoft Learn: 4698(S) A scheduled task was created | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4698 | primer | diperbarui 2026-04-27; diakses 2026-10-14 | Tinggi. TaskName, TaskContent, rekomendasi |
| S13 | Microsoft Learn: 1102(S) The audit log was cleared | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-1102 | primer | diperbarui 2026-04-27; diakses 2026-10-14 | Tinggi. Struktur UserData |
| S14 | Splunk Security Content: Data Source Windows Event Log System 7045 | https://research.splunk.com/sources/614dedc8-8a14-4393-ba9b-6f093cbcd293/ | primer (Splunk) | diakses 2026-10-14 | Tinggi. Source System dan field service |
| S15 | GitHub splunk/botsv1 | https://github.com/splunk/botsv1 | primer | 2016 (dataset); diakses 2026-10-14 | Tinggi. Sourcetype dan versi add-on pembuat dataset |
| S16 | Microsoft Learn: Command line process auditing | https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing | primer | 2025-05-12, diperbarui 2025-09-23; diakses 2026-10-14 | Tinggi. Dua setelan untuk 4688 dan peringatan data sensitif |
| S17 | Microsoft Learn: 4720(S) A user account was created | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4720 | primer | diperbarui 2026-04-27; diakses 2026-10-14 | Tinggi. TargetSid akun baru dan atribut yang layak dicek |
| S18 | Splunk Security Content: Data Source Windows Event Log Security 4698 | https://research.splunk.com/sources/32c06703-02d3-47ec-8856-b0dc3045866c/ | primer (Splunk) | diakses 2026-10-14 | Sedang. Daftar field memuat nama gaya klasik walau source XML |
| S19 | Splunk Security Content: Data Source Windows Event Log Security 1102 | https://research.splunk.com/sources/8db7b91a-6d7a-40e7-bfac-06f8e901a9cb/ | primer (Splunk) | diakses 2026-10-14 | Tinggi. Field SubjectUserName dari UserData |

**Catatan sumber:** halaman dokumentasi add-on Windows di docs.splunk.com (daftar sourcetype dan catatan upgrade) tidak dapat dibuka saat riset, sehingga penamaan sourcetype di bagian 1.1 bersandar pada research.splunk.com, Lantern, dan GitHub BOTS v1; cocokkan dengan halaman sourcetype add-on 11.0.3 di dokumentasi resmi. Nama field format klasik (`Account_Name`, `Source_Network_Address`, `Process_Command_Line`, dan lainnya) dan urutan nilai multivalue belum dikonfirmasi sumber primer yang dibuka dan perlu dicek di lab dengan BOTS v1. Pola field 4728 dan 4756 disimpulkan dari halaman 4732; halaman Microsoft untuk dua event itu tidak dibuka. Daftar field 4698 di research.splunk.com memuat nama gaya klasik walau source-nya XML, sehingga perlu dicek mana yang terisi di data nyata.
