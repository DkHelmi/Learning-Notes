---
day: 06
title: 'Log Linux dan identitas cloud di Splunk: linux_secure, auditd, Entra ID sign-in, dan M365 audit'
researched_on: 2026-10-14
versions_checked: 'Splunk Enterprise 10.6; Splunk Add-on for Unix and Linux 10.3.4 (Splunkbase app 833, rilis 1 Sep 2026, kompatibilitas CIM 6.x); Splunk Add-on for Microsoft Cloud Services 6.3.3 (Splunkbase app 3110, 10 Sep 2026, CIM 5.x); Splunk Add-on for Microsoft Office 365 6.1.1 (Splunkbase app 4055, 30 Sep 2026, CIM 5.x); Splunk Common Information Model 8.7.0 (Splunkbase, 2 Sep 2026); research.splunk.com data source Linux Secure dan Linux Auditd Add User (keduanya 13 Mei 2026, diuji dengan add-on Unix 10.3.4); Microsoft Learn AADSTS error codes (diperbarui Jun 2026), troubleshoot sign-in errors (Feb 2026), troubleshoot Conditional Access (Mei 2026), kategori diagnostic settings Entra (Mei 2026), tabel Azure Monitor SigninLogs (Agu 2026); Sudoers Manual (sudo.ws); BOTS v2 (Unix add-on 6.0.0, CIM 4.12.0); ES 8.7.0'
---

# Day 06: Log Linux dan identitas cloud di Splunk (linux_secure, auditd, Entra ID sign-in, dan M365 audit)

Cakupan: cara log autentikasi Linux dan log identitas cloud masuk ke Splunk, cara membaca sshd, sudo, dan auditd tanpa kehilangan jejak identitas yang berpindah, cara membaca sign-in Entra ID beserta kode kesalahan dan status Conditional Access, dan cara menemukan inbox rule serta perubahan role di log M365 Management Activity.

## Ide inti

Log Linux dan log identitas cloud menjawab empat pertanyaan yang sama dengan log Windows (akun siapa, di mana, lewat cara apa, hasilnya apa), tetapi batas identitasnya bergeser. Di Linux, identitas adalah angka: UID, GID, dan nomor sesi. Angka itu bisa berganti di tengah sesi lewat `sudo` atau `su`, sehingga satu baris log menyebut "root" padahal yang mengetik adalah akun biasa. Di identitas cloud, hostnya hilang sama sekali: autentikasi diputuskan di sisi Microsoft, yang kamu terima hanya catatan hasilnya, dan "di mana" menyusut menjadi satu alamat IP ditambah tebakan geografis. Konsekuensinya pertanyaan triage juga bergeser: bukan lagi "apakah host ini dikompromikan", tetapi "apakah sesi ini sah, dan apakah ada kebijakan yang benar-benar menghentikan sesuatu".

Pola ini sudah kamu kerjakan di sisi AAA jaringan. Baris `Accepted password` dan `Failed password` dari sshd berperan seperti Access-Accept dan Access-Reject dari RADIUS: satu baris per keputusan, dengan akun, alamat asal, dan metode. Baris `sudo` berperan seperti command accounting TACACS+: mencatat perintah yang diminta, bukan apa yang dikerjakan perintah itu. Entra ID sign-in adalah RADIUS yang di-outsource ke pihak ketiga: kamu tidak bisa membaca konfigurasi servernya, hanya menerima record yang disediakan API, dan alasan reject datang sebagai kode numerik vendor yang harus dicari artinya. M365 Management Activity bukan log trafik, melainkan log perubahan konfigurasi platform, lebih dekat ke log perubahan dial plan daripada ke CDR. Batas analoginya ada di dua tempat: `sudo` berhenti mencatat begitu yang dijalankan adalah shell, dan sebagian kode kesalahan Entra sebenarnya adalah interupsi normal dalam alur login, bukan kegagalan.

```
LINUX
  /var/log/secure (RHEL) atau /var/log/auth.log (Debian)
    -> universal forwarder monitor file
    -> Splunk Add-on for Unix and Linux   sourcetype=linux_secure
         program penulis : sshd | sudo | su | useradd | groupadd | pam
         field CIM       : user, src, dest, action, process, pid, src_port
  /var/log/audit/audit.log
    -> sourcetype=linux_audit atau auditd (lewat ausearch), satu event per type
         uid  = identitas efektif saat aksi
         auid = identitas login asli, tetap walau sudah sudo

IDENTITAS CLOUD
  Entra ID -> diagnostic settings -> Event Hub
    -> Splunk Add-on for Microsoft Cloud Services   sourcetype=azure:monitor:aad
         category = SignInLogs | NonInteractiveUserSignInLogs
                    ServicePrincipalSignInLogs | AuditLogs | ...
  Office 365 Management Activity API
    -> Splunk Add-on for Microsoft Office 365       sourcetype=o365:management:activity
         Workload = Exchange | AzureActiveDirectory | SharePoint | ...

  kunci penyambung : alamat IP, nama akun, rentang waktu
  yang hilang      : isi sesi setelah root shell (Linux), proses dan host (cloud)
```

Situasi yang dipakai sepanjang Day ini: pukul 08.40, SOC lead PT Jaringan Anak Bangsa (PT JAB, ISP menengah fiktif) membuka tiket SOC-2026-0244 dan menulis di channel SOC:

> "Tiga hal dari laporan pagi. Satu, alert 'SSH login gagal banyak' untuk jkt-bastion01 bunyi sepanjang malam, dan katanya ada satu yang akhirnya Accepted. Dua, bagian keuangan melapor Fitri tidak menerima beberapa email tagihan dari pelanggan korporat, padahal pengirimnya bilang sudah kirim dan tidak ada bounce. Tiga, dari tenant M365 ada yang bilang Budi sekarang punya role admin Exchange, padahal tidak ada change request. Ini satu rangkaian atau tiga kejadian terpisah?"

Pesan itu memuat enam pertanyaan:

1. Log Linux dan log identitas cloud masuk lewat add-on dan sourcetype apa, dan nama field mana yang aman dipakai?
2. Dari ribuan baris login gagal sshd, mana yang pemindaian internet dan mana yang benar-benar perlu ditindak?
3. Setelah seseorang masuk, siapa yang menjadi root, dan apa yang dijalankan dari sesi itu?
4. Apakah ada akun baru dibuat di host itu, dan kenapa `linux_secure` tidak selalu memperlihatkannya?
5. Di Entra ID, apa arti kode kesalahan yang muncul, dan apakah Conditional Access benar-benar menghentikan sesuatu?
6. Di M365, siapa yang membuat inbox rule di mailbox Fitri dan siapa yang memberi role Exchange Administrator ke Budi?

Pertanyaan 1 dijawab di bagian 1.1, pertanyaan 2 di bagian 1.2, pertanyaan 3 di bagian 1.3, pertanyaan 4 di bagian 1.4, pertanyaan 5 di bagian 1.5 dan 1.6, dan pertanyaan 6 di bagian 1.7. Bagian 1.8 membahas cara menyambung ketiganya, dan bagian 2 menjalankan semuanya sebagai search.

**Kapan relevan:** triage alert login ke server Linux dan bastion, review akun dan hak sudo, investigasi business email compromise dan persistence di tenant M365, menjawab pertanyaan "siapa yang memberi akses ini", serta hunting akun service yang dipakai manusia.
**Kapan bukan jawaban:** saat pertanyaannya tentang isi trafik atau proses di host Windows (itu wilayah Day 03, Day 04, dan Day 05); saat auditd tidak punya aturan untuk aksi yang kamu cari, sehingga event-nya tidak pernah ditulis; dan saat kejadiannya terjadi di aplikasi SaaS yang tidak mengirim audit log ke Splunk sama sekali.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dasar Splunk dari Day 01 dan 02 (index, sourcetype, source, host, `stats`, `eval`) tidak diulang. Tabel ini memuat istilah Linux, Entra ID, dan M365 yang dipakai di Day ini; kolom padanan memakai hal yang sudah kamu kerjakan di NOC dan SOC. Baca kolom arti sekali, lalu kembali ke sini saat sebuah nama field terasa asing.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| `/var/log/secure` dan `/var/log/auth.log` | File log autentikasi Linux; nama berbeda antara keluarga RHEL dan Debian | Log AAA lokal di perangkat, bukan di server AAA pusat |
| `linux_secure` | Sourcetype add-on Unix dan Linux untuk file log autentikasi itu | Parser log vendor untuk satu format teks |
| `auid` (audit login UID) | UID akun yang pertama kali login, dipertahankan walau sudah `sudo` | Nomor sesi RADIUS yang tetap walau user masuk enable mode |
| `uid` efektif | UID yang berlaku saat aksi dijalankan | Privilege level yang sedang aktif di perangkat |
| `sudo` log entry | Satu baris per perintah yang diminta lewat sudo, berisi TTY, PWD, USER, COMMAND | Command accounting TACACS+ |
| auditd | Subsistem audit kernel Linux yang menulis event sesuai aturan | Capture di sisi perangkat: lengkap, mahal, butuh filter |
| `type=` di auditd | Jenis record audit, misalnya `ADD_USER`, `EXECVE`, `PROCTITLE` | Kode pesan syslog per jenis kejadian |
| Entra ID (dulu Azure AD) | Direktori identitas Microsoft tempat autentikasi M365 diputuskan | Server RADIUS yang dikelola pihak ketiga |
| `category` di `azure:monitor:aad` | Jenis log Entra yang dikirim lewat diagnostic settings | Kelas accounting record yang kamu pilih untuk dikirim |
| Sign-in error code (AADSTS) | Kode numerik alasan hasil sign-in; 0 berarti berhasil | Kode alasan reject RADIUS |
| Conditional Access (CA) | Kebijakan yang menilai kondisi sign-in lalu mengizinkan, memblokir, atau meminta syarat tambahan | ACL atau policy di NAS, tetapi dievaluasi di sisi provider |
| `conditionalAccessStatus` | Hasil evaluasi CA pada satu sign-in: `success`, `failure`, atau `notApplied` | Status "policy matched" di perangkat, dengan opsi "tidak ada policy yang cocok" |
| Interactive vs non-interactive sign-in | User memasukkan faktor sendiri, atau klien memakai token atas nama user | Login manual operator vs sesi otomatis yang memakai kredensial tersimpan |
| Service principal | Identitas aplikasi di tenant, login dengan secret atau sertifikat | Akun service di perangkat, tanpa manusia di belakangnya |
| Office 365 Management Activity API | API audit lintas layanan M365 yang menjadi sumber `o365:management:activity` | Feed log perubahan konfigurasi platform |
| `Workload` | Layanan M365 asal event, misalnya `Exchange` atau `AzureActiveDirectory` | Subsistem asal pesan syslog |
| Inbox rule | Aturan di mailbox yang memindahkan, meneruskan, atau menghapus email otomatis | Call forwarding di PBX pelanggan |

### 1.1 Tiga add-on, tiga jalur masuk yang berbeda

Analyst PT JAB mencari login gagal di satu index dan menemukan ribuan baris, lalu mencari sign-in Entra di index yang sama dan tidak menemukan apa pun. Penyebabnya bukan filter, tetapi tiga jalur ingest yang berbeda.

**Linux lewat file.** Splunk Add-on for Unix and Linux membaca file log langsung di host lewat universal forwarder. Halaman source type add-on versi 10.3.4 mendaftar `linux_secure` sebagai "Linux security log file" dengan pemetaan ke data model Authentication, Network Sessions, dan Change, serta `linux_audit` sebagai "Linux audit log file" dengan pemetaan Authentication dan Change [S1]. Di daftar yang sama ada `auditd`, yaitu log auditd yang sudah diterjemahkan dengan `ausearch` lewat script `rlog.sh`, tanpa pemetaan CIM [S1]. Halaman data source Linux Secure di research.splunk.com menyebut sumbernya `/var/log/secure` dengan `sourcetype=linux_secure` dan app pendukung Splunk Add-on for Unix and Linux 10.3.4 [S3].

**Entra ID lewat Event Hub.** Entra ID tidak dibaca per file. Kamu mengaktifkan diagnostic settings di tenant, memilih kategori log, lalu mengalirkannya ke sebuah event hub; Splunk Add-on for Microsoft Cloud Services yang membaca event hub itu dan menulisnya sebagai `sourcetype=azure:monitor:aad` [S7][S15]. Detection Entra di research.splunk.com menyebut pola ini secara eksplisit lewat macro `azure_monitor_aad` yang berisi `sourcetype=azure:monitor:aad`, dan menambahkan bahwa analytic-nya ditulis untuk kategori Signin log [S15].

**M365 lewat API.** Splunk Add-on for Microsoft Office 365 memanggil Office 365 Management Activity API dan Service Communications API. Halaman add-on di dokumentasi Splunk menyebut API pertama menyediakan audit log untuk Azure Active Directory, SharePoint Online, dan Exchange Online, ditambah event Data Loss Prevention dan Message Trace, dan bahwa add-on ini menggantikan modular input Office 365 Management API yang dulu ada di Splunk Add-on for Microsoft Cloud Services [S24]. Sourcetype-nya `o365:management:activity` [S17][S19].

Tabel berikut memetakan tiga jalur itu; cari baris yang cocok dengan pertanyaanmu sebelum memilih index dan sourcetype.

| Yang dicari | Add-on | Sourcetype | Index di PT JAB | Jalur masuk |
|---|---|---|---|---|
| Login SSH, sudo, akun Linux | Splunk Add-on for Unix and Linux 10.3.4 | `linux_secure` | `linux` | File monitor di host [S1][S3] |
| Event audit kernel Linux | add-on yang sama | `linux_audit` atau `auditd` | `linux` | File monitor, atau script `rlog.sh` [S1] |
| Sign-in dan audit Entra ID | Splunk Add-on for Microsoft Cloud Services 6.3.3 | `azure:monitor:aad` | `o365` | Diagnostic settings ke event hub [S7][S15] |
| Audit M365 (Exchange, AAD, SharePoint) | Splunk Add-on for Microsoft Office 365 6.1.1 | `o365:management:activity` | `o365` | Management Activity API [S8][S24] |

Dua konsekuensi yang langsung memengaruhi search. Pertama, event Entra ID muncul di dua tempat dengan isi berbeda: audit directory lewat Management Activity API tercatat sebagai `o365:management:activity` dengan `Workload=AzureActiveDirectory`, sedangkan sign-in tercatat sebagai `azure:monitor:aad`. Praktisi di forum Splunk melaporkan event audit Entra masuk dengan `source=audit_azureactivedirectory` dan `sourcetype=o365:management:activity`, dan mereka tidak mendapatkan data sign-in dari add-on Office 365 itu [S23]. Jadi kalau kamu mencari sign-in di `o365:management:activity`, hasilnya memang kosong. Kedua, ketiga sumber punya keterlambatan berbeda: file log Linux datang dalam hitungan detik, sedangkan data berbasis API datang dalam batch. Detection Office 365 dan Entra di research.splunk.com dijadwalkan setiap jam dengan rentang `-70m` sampai `-10m`, artinya Splunk sengaja tidak memeriksa sepuluh menit terakhir karena datanya belum lengkap [S17][S19]. Ukur sendiri selisihnya di instance-mu dengan `_indextime` (Day 01 bagian 2.2).

Nama field juga tidak seragam. Tiga lapis penamaan yang akan kamu temui:

| Sumber | Nama field mentah | Nama yang dipakai saat search |
|---|---|---|
| `linux_secure` | tidak ada skema tetap; add-on mengekstrak dari teks | Field CIM: `user`, `src`, `dest`, `action`, `process`, `pid`, `src_port`, `vendor_action` [S3] |
| `auditd` | `type`, `uid`, `auid`, `ses`, `exe`, `terminal`, `res`, `id` | Sama, ditambah field terjemahan huruf besar `UID`, `AUID`, `ID` [S4] |
| `azure:monitor:aad` | JSON bersarang: `properties.status.errorCode`, `properties.ipAddress` | Biasanya diratakan dulu dengan `rename properties.* AS *` [S15] |
| `o365:management:activity` | JSON dengan array: `Parameters{}.Name`, `ModifiedProperties{}.NewValue`, `Actor{}.ID` | Array diakses dengan `mvfind` dan `mvindex` [S17][S19] |

Field JSON bersarang di dua sourcetype terakhir punya titik di namanya, jadi di dalam `eval` namanya wajib dibungkus kutip tunggal: `'properties.status.errorCode'`, bukan `"properties.status.errorCode"`. Aturan kutip ini dibahas lagi di Day 11.

### 1.2 `linux_secure`: satu file teks, banyak program penulis

Alert PT JAB menghitung baris `Failed password` di jkt-bastion01 dan menghasilkan angka ribuan. Sebelum menilai, kamu perlu tahu baris itu ditulis siapa.

`linux_secure` bukan log satu aplikasi. File `/var/log/secure` (atau `/var/log/auth.log` di keluarga Debian) adalah tempat semua program yang memakai facility `authpriv` menulis: sshd, sudo, su, PAM, `useradd`, `groupadd`, dan lainnya. Satu sourcetype memuat banyak format baris, dan field `process` yang diisi add-on adalah cara memisahkannya. Daftar field di halaman data source research.splunk.com untuk `linux_secure` memuat `action`, `app`, `dest`, `dvc`, `pid`, `process`, `src`, `src_port`, `sshd_protocol`, `user`, `user_name`, dan `vendor_action`, di samping field metadata Splunk [S3]. Contoh event di halaman itu adalah satu baris sshd yang menerima login dengan password [S3].

Bentuk baris sshd yang paling sering dipakai saat triage:

| Pola baris | Arti | Yang dicek |
|---|---|---|
| `Accepted password for <user> from <ip> port <n> ssh2` | Login berhasil dengan password | Akun apa, dari mana, dan apakah akun itu memang boleh pakai password |
| `Accepted publickey for <user> from <ip> port <n> ssh2: RSA SHA256:<fp>` | Login berhasil dengan kunci publik | Fingerprint kunci: sudah terdaftar atau baru |
| `Failed password for <user> from <ip> port <n> ssh2` | Password salah untuk akun yang ada | Rasio gagal terhadap akun, dan apakah berakhir dengan sukses |
| `Failed password for invalid user <user> from <ip>` | Akun yang dicoba tidak ada | Banyak akun berbeda dari satu IP berarti enumerasi |
| `Invalid user <user> from <ip> port <n>` | Baris terpisah untuk akun tidak ada | Sering muncul berpasangan dengan baris `Failed password` |
| `Connection closed by authenticating user <user> <ip> port <n> [preauth]` | Sesi ditutup sebelum autentikasi selesai | Pemindaian otomatis, atau klien yang menyerah |
| `Disconnected from invalid user <user> <ip> port <n> [preauth]` | Sama, untuk akun tidak ada | Volume besar dan biasanya jinak |

Dua hal membuat angka "ribuan login gagal" sering salah ditafsirkan. Pertama, satu percobaan bisa menghasilkan lebih dari satu baris (`Invalid user`, `Failed password`, lalu `Connection closed ... [preauth]`), sehingga menghitung baris bukan menghitung percobaan. Hitung dengan `dc()` pada kombinasi yang unik, atau sadari bahwa angkanya adalah batas atas. Kedua, server yang bisa dijangkau dari internet selalu menerima pemindaian; yang menarik bukan jumlahnya, tetapi rasio gagal terhadap sukses dan apakah akunnya ada.

Satu jebakan ingest yang khas: bila log dikirim lewat relay syslog, field `host` di Splunk bisa berisi nama relay, bukan server asalnya. Praktisi di forum Splunk melaporkan tepat kasus ini: seluruh field terekstrak kecuali hostname, karena `host` menunjukkan nama server syslog [S22]. Forum yang sama juga mencatat bahwa `linux_secure` berbasis syslog dan polanya sangat mirip syslog biasa, sehingga Splunk sering tidak bisa mengenalinya otomatis dan sourcetype perlu ditetapkan eksplisit di `inputs.conf` [S22]. Kedua hal itu belum dikonfirmasi dokumentasi primer yang dibuka untuk Day ini; uji di lab.

### 1.3 `sudo` dan `su`: identitas yang berpindah di tengah sesi

Setelah tahu siapa yang masuk ke jkt-bastion01, pertanyaan berikutnya adalah siapa yang menjadi root dan apa yang dijalankan. Di sini `sudo` membantu, tetapi hanya sampai batas tertentu.

Sudoers Manual menyebut sudoers mencatat percobaan yang berhasil maupun gagal, dan secara bawaan menulisnya lewat `syslog(3)`, bisa diubah ke file lewat setelan `syslog` dan `logfile` [S6]. Setelan `log_allowed` dan `log_denied` keduanya aktif secara bawaan, sehingga perintah yang diizinkan dan yang ditolak sama-sama tercatat [S6].

Untuk perintah yang berhasil dijalankan, urutan field di baris log menurut manual itu adalah `date`, `hostname`, `progname`, `username`, `TTY`, `CHROOT`, `PWD`, `USER`, `GROUP`, `TSID`, `ENV`, lalu `COMMAND` [S6]. Tiga catatan dari manual yang perlu diingat: `hostname` dan `progname` hanya muncul bila logging lewat syslog, `CHROOT` hanya muncul bila root directory ditentukan, dan `TSID` hanya muncul bila I/O logging aktif [S6]. Jadi jangan menulis regex yang mengasumsikan semua field selalu ada.

Untuk perintah yang ditolak, alasan ditulis tepat setelah nama user. Manual mendaftar empat pesan yang paling sering kamu lihat [S6]:

- `user NOT in sudoers`: user tidak terdaftar di sudoers.
- `user NOT authorized on host`: user terdaftar, tetapi tidak boleh menjalankan perintah di host ini.
- `command not allowed`: user boleh menjalankan perintah di host ini, tetapi tidak perintah itu.
- `N incorrect password attempts`: password gagal terlalu sering; jumlahnya mengikuti setelan `passwd_tries`.

Keterbatasan yang paling penting untuk investigasi: `sudo` mencatat perintah yang diminta, bukan apa yang dikerjakan perintah itu. Begitu seseorang menjalankan `sudo /bin/bash` atau `sudo su -`, semua aktivitas sesudahnya terjadi di dalam shell root dan tidak menghasilkan baris `sudo` lagi. Dari sudut `linux_secure`, jejaknya berhenti di satu baris. Inilah alasan bagian 1.4 ada: untuk melihat ke dalam shell itu, kamu butuh auditd. I/O logging sudo (`log_input` dan `log_output`) bisa menutup sebagian celah ini, tetapi manual menyebut fitur itu tidak aktif secara bawaan [S6].

`su` menulis barisnya sendiri di file yang sama, biasanya lewat PAM, dengan pola seperti `session opened for user root by <user>(uid=<n>)`. Bentuk persisnya berbeda antar distro dan versi PAM, jadi cek di lab-mu sebelum menulis regex.

Pembuatan akun juga lewat file ini. `useradd` dan `groupadd` menulis baris ke `authpriv`, dan di keluarga Red Hat barisnya memuat nama akun baru beserta UID, GID, home directory, dan shell. Praktisi di forum Red Hat menyebut informasi user baru, grup baru, dan perubahan grup saat `useradd` dijalankan memang dicatat di `/var/log/secure` [S25]. Format persis baris itu tidak terdokumentasi di sumber primer yang dibuka untuk Day ini dan berbeda antar versi shadow-utils; catat formatnya sendiri dari lab lalu pakai di regex. Yang stabil dan layak dicari apa pun formatnya: akun baru dengan UID 0, akun baru yang langsung masuk grup `wheel` atau `sudo`, dan akun baru dengan shell interaktif padahal namanya terlihat seperti akun service.

### 1.4 auditd: sensor lengkap yang isinya ditentukan aturan

Jejak `sudo` di jkt-bastion01 berhenti di `/bin/bash`. Untuk tahu apa yang dijalankan di dalam shell itu, kamu perlu auditd, dengan dua syarat: aturan auditnya ada, dan log-nya masuk Splunk.

auditd adalah subsistem audit kernel Linux. Seperti audit policy di Windows (Day 03 bagian 1.2), yang tidak diatur tidak dicatat: tanpa aturan `-a` atau `-w` yang relevan, event-nya tidak pernah ditulis, dan tidak ada search yang bisa menemukannya. Berbeda dengan Windows, beberapa jenis record ditulis tanpa aturan tambahan karena berasal dari program user-space yang memanggil audit secara langsung, misalnya `useradd` yang menulis record `ADD_USER`.

Penamaan sourcetype-nya tidak tunggal, dan ini sering menjadi sumber search kosong:

| Sourcetype | Asal | Catatan |
|---|---|---|
| `linux_audit` | File `audit.log` mentah, dibaca add-on Unix dan Linux | Dipetakan ke Authentication dan Change [S1] |
| `auditd` | Keluaran `ausearch` lewat script `rlog.sh` di add-on yang sama | Tanpa pemetaan CIM di tabel source type [S1]; dipakai halaman data source dan detection Splunk [S4][S5] |
| `linux:audit` | App Linux Auditd yang terpisah | Disebut di forum Splunk sebagai sourcetype yang benar untuk app itu, bukan `linux:auditd`; mengubah sourcetype tidak memperbaiki event yang sudah masuk [S22] |

Cek mana yang ada di instance-mu sebelum menulis detection, karena detection siap pakai dari Splunk memakai `auditd`.

Satu kejadian di auditd pecah menjadi beberapa record dengan `type` berbeda yang berbagi satu ID event: `SYSCALL`, `EXECVE`, `PROCTITLE`, `PATH`, `CWD`, dan record khusus seperti `ADD_USER` atau `USER_AUTH`. Halaman data source Linux Auditd Add User mencatat `separator=type`, artinya pemisahan event mengikuti field `type` [S4]. Konsekuensinya: satu perintah bisa muncul sebagai beberapa event Splunk, dan menghitung `count` berarti menghitung record, bukan perintah.

Field yang paling penting dibaca benar, dari daftar field halaman itu [S4]:

| Field | Arti | Kenapa penting |
|---|---|---|
| `type` | Jenis record, misalnya `ADD_USER` | Penentu bentuk sisa field |
| `uid` | UID efektif saat aksi dijalankan | Setelah `sudo`, nilainya 0 untuk semua orang |
| `auid` | UID akun yang pertama kali login di sesi itu | Satu-satunya field yang masih menyebut manusia aslinya |
| `ses` | Nomor sesi audit | Mengelompokkan semua aksi dalam satu sesi login |
| `exe` | Path biner yang menjalankan aksi, misalnya `/usr/sbin/useradd` | Membedakan aksi lewat tool resmi dan lewat cara lain |
| `terminal` | TTY asal, misalnya `pts/1` | Mengaitkan ke sesi SSH |
| `res` | Hasil: `success` atau `failed` | Membedakan percobaan dan keberhasilan |
| `id` dan `ID` | ID objek numerik, dan versi terjemahannya | Bisa berisi `unknown(1002)` bila nama belum bisa diterjemahkan |
| `UID`, `AUID` | Versi nama dari `uid` dan `auid` | Lebih enak dibaca, tetapi `auid` numerik lebih aman untuk `stats` |

Contoh event `ADD_USER` di halaman itu memperlihatkan pola yang persis dibutuhkan untuk kasus PT JAB: `uid` 0, `auid` 1000, `exe` berisi `/usr/sbin/useradd`, `terminal` `pts/1`, `res` `success`, dan field terjemahan `UID="root"`, `AUID="ubuntu"`, `ID="unknown(1002)"` [S4]. Dua pelajaran dari satu event itu. Pertama, `uid=0` dan `AUID="ubuntu"` berada di event yang sama: pelakunya ubuntu, yang sedang berjalan sebagai root. Kedua, `ID="unknown(1002)"` memperlihatkan field terjemahan bisa gagal menerjemahkan karena akunnya baru dibuat; pakai `id` numerik lalu cocokkan sendiri.

Untuk melihat perintah yang dijalankan, detection Linux Auditd Add User Account dari Splunk memakai field `proctitle` dengan filter `proctitle IN ("*useradd*", "*adduser*")`, dan menyebut syarat implementasinya adalah memasukkan event auditd jenis SYSCALL, TYPE, EXECVE, dan PROCTITLE lewat Splunk Add-on for Unix and Linux lalu menormalkannya ke CIM [S5]. Satu hal yang perlu kamu cek sendiri di lab: nilai `proctitle` di auditd dikodekan heksadesimal ketika perintahnya memuat spasi, sehingga filter berbasis teks hanya bekerja bila ada yang mendekodekannya lebih dulu. Jalankan `| table proctitle` pada data-mu dan lihat bentuknya sebelum mengandalkan pola teks.

### 1.5 Entra ID sign-in: hasil keputusan yang diambil di luar jaringanmu

Sampai di sini semua masih di host yang kamu kelola. Pertanyaan tentang mailbox Fitri membawa kita ke tempat yang tidak punya host.

Yang masuk ke Splunk sebagai `azure:monitor:aad` adalah apa yang kamu pilih di diagnostic settings tenant, bukan seluruh log Entra. Kategori yang tersedia didokumentasikan Microsoft, dan empat yang paling relevan untuk SOC [S9]:

| Kategori | Isi | Kenapa perlu |
|---|---|---|
| `SignInLogs` | Sign-in interaktif: user memasukkan username dan password, atau melewati tantangan MFA | Sumber utama triage login |
| `NonInteractiveUserSignInLogs` | Sign-in atas nama user oleh aplikasi klien yang memakai token atau code, tanpa user memasukkan faktor | Tempat sebagian besar volume berada, dan tempat legacy client sering muncul |
| `ServicePrincipalSignInLogs` | Sign-in aplikasi dan service principal yang memakai sertifikat atau client secret | Satu-satunya tempat melihat kredensial aplikasi dipakai |
| `AuditLogs` | Perubahan di tenant: user, grup, aplikasi, lisensi | Pendamping log sign-in untuk pertanyaan "siapa mengubah apa" |

Microsoft juga mendaftar kategori lain seperti `ManagedIdentitySignInLogs`, `ProvisioningLogs`, `ADFSSignInLogs`, `RiskyUsers`, `UserRiskEvents`, `RiskyServicePrincipals`, `ServicePrincipalRiskEvents`, dan `MicrosoftGraphActivityLogs`; sebagian bergantung lisensi atau produk tambahan [S9]. Yang paling sering menjadi lubang buta: detection siap pakai untuk kegagalan login Entra memfilter `category=SignInLogs` [S15], sehingga sign-in service principal dan non-interaktif tidak pernah dilihat detection itu. Detection terpisah memang ada, dan yang untuk service principal memfilter `category=ServicePrincipalSignInLogs` [S16]. Kalau tenant-mu tidak mengirim kategori itu, detection-nya diam tanpa error.

Nama field punya dua lapis yang perlu dibedakan. Di Log Analytics, tabel `SigninLogs` memakai nama kolom berhuruf besar: `ResultType` berisi "the 5-6 digit error code that's generated during a sign-in event" dengan nilai 0 berarti berhasil, `ResultDescription` berisi pesan atau alasan kegagalan, `Status` berisi kode dan deskripsi error, `ConditionalAccessStatus`, `ConditionalAccessPolicies`, `Location`, `LocationDetails`, `IPAddress`, `AppDisplayName`, `ClientAppUsed`, `DeviceDetail`, `UserPrincipalName`, `UserAgent`, `AutonomousSystemNumber`, `IsInteractive`, `RiskLevelDuringSignIn`, dan `AuthenticationRequirement` [S10]. Di Splunk lewat event hub, nilai yang sama datang sebagai JSON bersarang di bawah `properties`, misalnya `properties.status.errorCode` dan `properties.conditionalAccessStatus`; detection Splunk meratakannya dengan `rename properties.* AS *` sebelum memakai nama pendek [S15]. Jadi dokumentasi Microsoft dan contoh SPL Splunk menyebut hal yang sama dengan dua nama, dan keduanya perlu kamu kenali.

Kode kesalahan adalah inti pembacaan sign-in. Tabel berikut berisi kode yang paling sering muncul di antrean triage, dengan deskripsi dari referensi AADSTS Microsoft; cari kolom terakhir untuk menentukan langkah berikutnya.

| Kode | Nama dan arti ringkas | Arti untuk triage |
|---|---|---|
| `0` | Berhasil | Nilai `ResultType` 0 berarti sukses; semua nilai lain adalah kegagalan atau interupsi [S10] |
| `50126` | InvalidUserNameOrPassword, kredensial salah. Microsoft menambahkan bahwa sejumlah error ini normal karena user salah ketik [S11] | Banyak berturut-turut pada satu akun berarti tebakan password; banyak akun dari satu IP berarti spraying |
| `50034` | UserAccountNotFound, akun tidak ada di direktori [S11] | Banyak akun berbeda dari satu sumber berarti enumerasi |
| `50053` | Akun terkunci karena terlalu banyak percobaan, atau sign-in diblokir karena datang dari IP dengan aktivitas jahat. Microsoft menyebut dua sebab ini memakai kode yang sama supaya penyerang tidak bisa membedakannya [S11] | Jangan simpulkan "akun terkunci" dari kode ini saja; buka detail event-nya |
| `50055` | InvalidPasswordExpiredPassword, password kedaluwarsa [S11] | Biasanya operasional, tetapi akun service yang kena ini berarti ada integrasi yang akan rusak |
| `50057` | UserDisabled, akun dinonaktifkan [S11] | Ada yang mencoba memakai akun yang seharusnya mati |
| `50074` | UserStrongAuthClientAuthNRequiredInterrupt, MFA diminta dan user tidak melewatinya [S11] | Bila berpasangan dengan `50126` yang berhasil ditebak, berarti MFA yang menahan |
| `50076` | UserStrongAuthClientAuthNRequired, MFA wajib karena perubahan konfigurasi admin, penegakan per user, atau karena user berpindah lokasi [S11] | Sering muncul setelah kebijakan baru diterapkan |
| `50079` | UserStrongAuthEnrollmentRequired, user harus mendaftarkan metode MFA dulu [S11] | Akun yang belum mendaftar MFA adalah target empuk |
| `50140` | KmsiInterrupt, interupsi "Keep me signed in". Microsoft menyebut ini bagian normal alur sign-in [S11] | Bukan kegagalan; sering menjadi kode paling banyak di tenant |
| `50158` | External security challenge not satisfied, user dialihkan ke halaman lain atau penyedia lain. Microsoft menyebut kode ini sendiri tidak menandakan user gagal sign-in [S11] | Bukan kegagalan; cek event lanjutannya |
| `53003` | BlockedByConditionalAccess, akses diblokir kebijakan Conditional Access [S11][S13] | Ini kegagalan yang berarti kontrol bekerja; cek kebijakan mana |
| `500121` | User tidak menyelesaikan prompt MFA. Microsoft menyebut ini sering muncul bila user belum selesai menyiapkan MFA [S12] | Banyak berturut-turut bisa berarti MFA fatigue atau push bombing |
| `70046` | Sesi kedaluwarsa atau pemeriksaan autentikasi ulang gagal. Bisa terjadi bila kebijakan CA mewajibkan autentikasi ulang pada tingkat risiko tertentu [S12] | Operasional, kecuali muncul berbarengan dengan sinyal risiko |

Dua kode terakhir di tabel dan `50140` serta `50158` adalah alasan kenapa menghitung "semua sign-in dengan kode selain 0" sebagai login gagal menghasilkan angka yang jauh lebih besar daripada kenyataan. Microsoft juga mencatat `50058` (UserInformationNotProvided) adalah error yang normal muncul saat user belum sign-in, dan di kasus itu field User bisa berisi object ID atau GUID, bukan username [S11][S12]. Kalau search-mu mengelompokkan per user dan menemukan baris dengan nilai seperti `00000000-0000-0000`, kemungkinan itu penyebabnya.

### 1.6 Conditional Access dan lokasi: dua field yang paling sering disalahbaca

Setelah tahu akun Fitri berhasil login dari luar, pertanyaan wajarnya adalah "kenapa tidak diblokir". Jawabannya ada di satu field yang mudah dibaca salah.

`conditionalAccessStatus` punya tiga nilai: `success`, `failure`, dan `notApplied` [S10]. `notApplied` tidak berarti "diizinkan kebijakan". Artinya tidak ada kebijakan yang kondisinya terpenuhi untuk sign-in itu, sehingga tidak ada kebijakan yang dievaluasi. Sign-in lewat protokol lama yang tidak tercakup kebijakan, aplikasi yang dikecualikan, atau user yang berada di luar scope semuanya berakhir di `notApplied`. Dalam laporan bulanan, `notApplied` yang tinggi adalah temuan sendiri: sebagian besar sign-in tenant tidak pernah disentuh kebijakan apa pun.

Microsoft juga memperingatkan hal yang kontraintuitif tentang daftar kebijakan di dalam event. Subbagian `appliedConditionalAccessPolicies` menyimpan kebijakan yang terkait sign-in itu, tetapi dokumentasi Microsoft menyebut bagian itu berjudul "applied" padahal kebijakan yang tidak diterapkan juga muncul di sana, dengan satu entri per kebijakan [S14]. Jadi menghitung jumlah entri di daftar itu bukan menghitung kebijakan yang berlaku; yang menentukan adalah nilai hasil per entri. Kebijakan dalam mode report-only juga muncul di daftar yang sama tanpa memblokir apa pun.

Untuk menemukan kebijakan yang benar-benar memblokir, Microsoft mengarahkan ke tab Conditional Access di event sign-in, yang menampilkan kebijakan yang menyebabkan interupsi, dan mencatat kebijakan Conditional Access hanya berlaku bila semua kondisi terpenuhi atau tidak dikonfigurasi [S13]. Kode kesalahan keluarga 53000 adalah penanda paling jelas di Splunk; Microsoft mendaftar `53000` DeviceNotCompliant, `53001` DeviceNotDomainJoined, `53002` ApplicationUsedIsNotAnApprovedApp, `53003` BlockedByConditionalAccess, `53004` ProofUpBlockedDueToRisk, dan `53009` untuk aplikasi yang harus menegakkan kebijakan proteksi Intune [S13]. Ada juga `530035` BlockedBySecurityDefaults, yang menandakan permintaan diblokir security defaults, bukan kebijakan CA buatan sendiri [S11]. Membedakan keduanya penting saat menjawab auditor.

Field lokasi perlu kehati-hatian serupa. Dokumentasi tabel `SigninLogs` menyebut `Location` adalah kode negara dua huruf dan menambahkan bahwa tergantung alamat IP, nilainya tidak selalu bisa diuraikan sampai tingkat kota atau wilayah; `LocationDetails` berisi kota, state, negara, dan koordinat; sedangkan `AutonomousSystemNumber` berisi ASN jaringan yang dipakai pelaku [S10]. Tiga jebakan praktis yang mengikuti:

- Deteksi "impossible travel" yang hanya memakai kode negara akan berteriak untuk VPN korporat, operator seluler yang IP-nya ter-geolokasi di kota lain, dan layanan cloud yang keluar lewat region berbeda. Pakai ASN bersama kode negara, lalu bandingkan dengan kebiasaan akun itu.
- Sign-in non-interaktif sering membawa lokasi yang tidak masuk akal karena yang mengirim token adalah layanan, bukan orang.
- `RiskLevelDuringSignIn` dan field risiko lain berisi nilai `hidden` bila tenant tidak berlisensi Entra ID Protection tingkat yang dibutuhkan [S10][S14]. `hidden` bukan "tidak berisiko"; itu "tidak dinilai".

Field `ClientAppUsed` menutup gambaran ini. Dokumentasi menyebutnya sebagai klien lama yang dipakai untuk aktivitas sign-in, dengan contoh nilai Browser, Exchange ActiveSync, Modern clients, IMAP, MAPI, SMTP, dan POP [S10]. Nilai seperti IMAP4, POP3, atau SMTP pada akun karyawan biasa adalah sinyal kuat, karena protokol itu umumnya tidak mendukung MFA modern; sign-in yang berhasil lewat jalur itu sering juga ber-`conditionalAccessStatus` `notApplied`.

### 1.7 M365 Management Activity: satu sourcetype, banyak layanan

Pertanyaan tentang email Fitri yang hilang dan role Budi dijawab di sourcetype yang sama, `o365:management:activity`, tetapi di dua `Workload` berbeda.

Satu sourcetype menampung audit dari banyak layanan M365, dan field `Workload` adalah pemisahnya: `Exchange` untuk operasi mailbox, `AzureActiveDirectory` untuk perubahan direktori, `SharePoint` dan lainnya untuk layanan masing-masing [S17][S19]. Field `Operation` menyebut aksinya, `UserId` akun yang melakukan, `ClientIP` alamat asalnya, dan `ResultStatus` hasilnya.

**Inbox rule dan forwarding.** Detection O365 Email New Inbox Rule Created dari Splunk memfilter `Workload=Exchange` dengan `Operation` berisi `New-InboxRule` atau `Set-InboxRule`, lalu memeriksa parameter yang menandakan forwarding, penghapusan, atau penyembunyian [S17]. Detection O365 New Email Forwarding Rule Created mempersempitnya ke tiga parameter: `ForwardTo`, `ForwardAsAttachmentTo`, dan `RedirectTo`, dan mencarinya dengan `mvfind` pada field `Parameters{}.Name` [S18]. Ada detection terpisah yang memakai operasi `UpdateInboxRules`, bukan `New-InboxRule`, untuk aturan forwarding yang diaktifkan belakangan.

Bentuk datanya menentukan cara menulis SPL. Parameter cmdlet Exchange tidak datang sebagai field tersendiri, melainkan sebagai array objek yang di Splunk menjadi dua field multivalue sejajar, `Parameters{}.Name` dan `Parameters{}.Value`. Untuk mengambil nilai sebuah parameter, kamu mencari posisinya di field nama dengan `mvfind`, lalu memakai posisi itu pada field nilai dengan `mvindex`. Asumsinya kedua field berurutan sama; itu benar bila add-on mempertahankan urutan array, dan perlu kamu buktikan sendiri dengan satu event yang sudah kamu kenal.

Parameter yang sering muncul bersama di aturan business email compromise, dan yang membuat sebuah aturan patut dicurigai:

| Parameter | Arti | Kenapa mencurigakan |
|---|---|---|
| `ForwardTo`, `ForwardAsAttachmentTo`, `RedirectTo` | Alamat tujuan penerusan | Tujuan di luar tenant berarti data keluar [S18] |
| `DeleteMessage` | Hapus pesan yang cocok | Menghilangkan bukti dari mailbox korban |
| `MoveToFolder`, `CopyToFolder` | Pindahkan ke folder lain | Folder berkategori jarang dibuka dipakai untuk menyembunyikan [S17] |
| `MarkAsRead` | Tandai sudah dibaca | Korban tidak melihat notifikasi |
| `Name` | Nama aturan | Nama satu karakter, titik, atau karakter acak adalah pola khas penyembunyian |

Detection O365 BEC Email Hiding Rule Created dari Splunk memberi skor berdasarkan entropi dan panjang nama aturan, apakah aturan menandai pesan sudah dibaca, dan apakah pesan dipindahkan ke folder seperti RSS atau Conversation History; macro-nya memakai `sourcetype=o365:management:activity`. Pendekatan itu berguna, tetapi untuk triage L1 cukup tiga pertanyaan: tujuannya di dalam atau di luar tenant, siapa yang membuat, dan dari IP mana.

**Perubahan role.** Detection O365 Privileged Role Assigned memfilter `Workload=AzureActiveDirectory` dengan `Operation` berisi `Add member to role.` atau `Add eligible member to role.` (perhatikan titik di akhir nilainya, yang memang bagian dari nilai field) [S19]. Pemetaan field di detection itu adalah peta yang paling berguna untuk dihafal: akun yang menerima role ada di `ObjectId`, pelaku ada di `Actor{}.ID`, nama role ada di `ModifiedProperties{}.NewValue` pada entri yang namanya cocok dengan `Role.DisplayName`, dan ID template role ada di entri `Role.TemplateId` [S19]. Detection itu lalu mencocokkan `Role.TemplateId` ke lookup `privileged_azure_ad_roles` untuk menilai apakah role-nya istimewa, dan hanya meneruskan hasil yang targetnya bertipe User [S19].

Dua catatan dari halaman detection yang sama. `Actor{}.ID` adalah field multivalue yang bisa memuat beberapa bentuk identitas pelaku sekaligus, dan detection memilih elemennya berdasarkan tipe aktor (User atau ServicePrincipal), jadi mengambil elemen pertama saja belum tentu memberi identitas yang kamu mau; cek isinya di data-mu [S19]. Lalu false positive yang disebut Microsoft dan Splunk sama: admin memang menetapkan role sebagai pekerjaan normal, dan Privileged Identity Management membuat alert jenis ini kurang akurat karena role diberikan dan dicabut otomatis sesuai jadwal [S19]. Artinya alert ini bernilai hanya bila kamu punya cara memeriksa change request.

### 1.8 Menyambung tiga sumber, dan apa yang tetap tidak terlihat

Tiga sumber di Day ini tidak punya satu kunci bersama seperti Logon ID di Windows. Yang ada tiga kunci yang lebih lemah, dan kekuatannya justru muncul saat dipakai bersama.

Alamat IP adalah penyambung paling langsung: `src` di `linux_secure`, `properties.ipAddress` di `azure:monitor:aad`, dan `ClientIP` di `o365:management:activity`. Satu IP publik yang muncul di log SSH dan di sign-in tenant pada rentang waktu berdekatan adalah sinyal yang jauh lebih kuat daripada masing-masing sendiri. Nama akun adalah penyambung kedua, tetapi bentuknya berbeda: akun Linux adalah nama pendek (`svc_radius`), akun cloud adalah UPN (`fitri.handayani@jab.example`), dan service principal bukan keduanya. Buat pemetaan ini sebagai lookup dengan pemilik yang jelas, jangan ditebak di setiap search. Waktu adalah penyambung ketiga, dan paling rawan: log cloud datang terlambat dalam batch, sehingga kronologi yang kamu susun sepuluh menit setelah kejadian hampir selalu belum lengkap.

Yang tetap tidak terlihat dari ketiga sumber ini, dan harus kamu tulis eksplisit di tiket supaya tidak dibaca sebagai "tidak terjadi":

- Aktivitas di dalam shell root bila auditd tidak punya aturan untuk itu, atau bila `linux_audit` tidak dikirim dari host itu.
- Pembacaan file di Linux, kecuali ada watch rule auditd untuk path itu. Kredensial yang dibaca dari file konfigurasi adalah kejadian paling sering terlewat.
- Isi email. Management Activity API mencatat bahwa aturan dibuat dan pesan diakses, bukan isinya.
- Sign-in yang kategorinya tidak dikirim ke event hub, terutama `NonInteractiveUserSignInLogs` dan `ServicePrincipalSignInLogs`.
- Perangkat dan lokasi sebenarnya di sisi cloud; yang ada hanya apa yang bisa disimpulkan dari IP dan user agent.

**Tanpa ES:** semua yang dibahas di Day ini berjalan di Splunk Enterprise biasa, di app Search & Reporting. Yang ditambahkan Enterprise Security adalah normalisasi lintas sumber lewat data model Authentication dan Change (Day 23 dan Day 24), detection siap pakai yang sudah membawa threshold dan risk score seperti yang dirujuk di bagian 1.5 sampai 1.7, serta Asset & Identity yang memetakan akun Linux dan UPN cloud ke satu orang. Di PT JAB, Asset & Identity belum lengkap, jadi pemetaan akun untuk sementara dikerjakan dengan lookup buatan sendiri (Day 12).

## 2. Contoh SPL dan langkah praktis

Semua keluaran di bagian ini adalah keluaran ilustrasi, bukan hasil eksekusi. Asumsi PT JAB: index `linux` dengan `sourcetype=linux_secure` dan `sourcetype=auditd` dari Splunk Add-on for Unix and Linux 10.3.4, index `o365` dengan `sourcetype=azure:monitor:aad` dari Splunk Add-on for Microsoft Cloud Services 6.3.3 dan `sourcetype=o365:management:activity` dari Splunk Add-on for Microsoft Office 365 6.1.1, Splunk Enterprise 10.6, tanpa ES. Domain mail tenant `jab.example`.

### 2.1 Inventaris: apa yang benar-benar masuk, dan selisih waktunya

Sebelum menjawab pesan SOC lead, pastikan dulu keempat sourcetype benar-benar ada dan seberapa terlambat masing-masing.

**Tujuan:** melihat volume, jumlah host, dan event terakhir per sourcetype dalam 24 jam.

```
index=linux OR index=o365 earliest=-24h
| stats count dc(host) AS host_unik min(_time) AS awal max(_time) AS akhir BY index sourcetype
| eval awal=strftime(awal, "%F %T"), akhir=strftime(akhir, "%F %T")
| sort index - count
```

| Bagian | Penjelasan |
|---|---|
| `index=linux OR index=o365` | Dua index sekaligus; filter index tetap yang paling murah |
| `dc(host)` | Berapa host mengirim sourcetype itu, bukan berapa event |
| `max(_time) AS akhir` | Event terbaru; selisihnya dengan jam sekarang adalah keterlambatan kasar |

Keluaran ilustrasi (search dijalankan pukul 08.40):

```
index   sourcetype                count     host_unik  awal                 akhir
linux   auditd                    9120447   6          2026-10-13 08:40:02  2026-10-14 08:39:59
linux   linux_secure              184203    42         2026-10-13 08:40:11  2026-10-14 08:39:58
o365    azure:monitor:aad         402119    1          2026-10-13 08:40:00  2026-10-14 08:31:07
o365    o365:management:activity  51208     1          2026-10-13 08:38:50  2026-10-14 08:28:14
```

**Cara membaca hasil:** `linux_secure` datang dari 42 host, tetapi `auditd` hanya dari 6. Artinya untuk 36 host lain, jejak di dalam shell root tidak ada sama sekali, dan itu harus disebut saat menutup tiket. Dua sourcetype cloud punya `host_unik` 1 karena yang mengirim adalah heavy forwarder, bukan perangkat asal. Event terbaru `azure:monitor:aad` berumur 9 menit dan `o365:management:activity` berumur 12 menit, sedangkan sumber Linux berumur hitungan detik. Jadi alert cloud yang memeriksa 10 menit terakhir akan sering mendapat nol hasil bukan karena sepi, tetapi karena datanya belum sampai.
**Variasi:** tambahkan `| stats ... BY index sourcetype source` untuk melihat `source` di sisi cloud; event audit Entra lewat Management Activity API sering muncul dengan `source=audit_azureactivedirectory` [S23].
**Kapan gagal:** `dc(host)` pada 24 jam di index besar lebih baik dijalankan dengan `tstats` (Day 25), karena `index`, `sourcetype`, dan `host` adalah indexed field.

Satu langkah lagi khusus untuk Entra: kategori mana yang benar-benar dikirim tenant.

```
index=o365 sourcetype=azure:monitor:aad earliest=-24h
| stats count BY category operationName
| sort - count
```

Keluaran ilustrasi:

```
category                      operationName      count
NonInteractiveUserSignInLogs  Sign-in activity   317157
SignInLogs                    Sign-in activity   42607
ServicePrincipalSignInLogs    Sign-in activity   41107
AuditLogs                     (bervariasi)       1248
```

**Cara membaca hasil:** empat kategori dari 402.119 event, dan sign-in interaktif hanya 42.607 dari seluruhnya, yaitu sekitar 11 persen. Detection yang hanya memfilter `category=SignInLogs` [S15] melewatkan 89 persen volume, termasuk seluruh sign-in service principal. Kalau sebuah kategori tidak muncul di tabel ini, kategori itu tidak diaktifkan di diagnostic settings tenant, dan tidak ada SPL yang bisa menebusnya [S9].

### 2.2 sshd: memisahkan pemindaian internet dari percobaan yang perlu ditindak

Ini jawaban untuk bagian pertama pesan SOC lead.

**Tujuan:** merangkum kegagalan sshd di jkt-bastion01 per sumber, memisahkan akun yang ada dan akun yang tidak ada, lalu mengukur jeda antar percobaan.

```
index=linux sourcetype=linux_secure host=jkt-bastion01 process=sshd action=failure
    earliest="10/13/2026:20:00:00" latest="10/14/2026:06:00:00"
| eval jenis=if(match(_raw, "(?i)invalid user"), "akun tidak ada", "akun ada, password salah")
| stats count dc(user) AS akun_unik min(_time) AS awal max(_time) AS akhir BY src jenis
| eval jeda_detik=if(count > 1, round((akhir - awal) / (count - 1), 1), null())
| eval awal=strftime(awal, "%F %T"), akhir=strftime(akhir, "%F %T")
| sort - count
```

| Bagian | Penjelasan |
|---|---|
| `process=sshd action=failure` | `process` memisahkan program penulis di dalam satu sourcetype; `action` adalah field CIM yang diisi add-on [S3] |
| `match(_raw, "(?i)invalid user")` | Membedakan akun yang tidak ada dari password salah; teks ini ada di `_raw`, bukan di field tersendiri |
| `dc(user)` | Jumlah akun berbeda per sumber; pembeda utama spraying dan tebakan satu akun |
| `(akhir - awal) / (count - 1)` | Jeda rata-rata antar percobaan; `count - 1` karena yang dihitung adalah selang, bukan kejadian |

Keluaran ilustrasi:

```
src             jenis                     count  akun_unik  awal                 akhir                jeda_detik
203.0.113.45    akun ada, password salah  1284   3          2026-10-13 22:14:03  2026-10-14 03:02:51  13.5
203.0.113.45    akun tidak ada            882    41         2026-10-13 22:14:11  2026-10-14 03:02:44  19.7
192.0.2.118     akun ada, password salah  3      1          2026-10-14 02:46:51  2026-10-14 02:47:11  10.0
```

**Cara membaca hasil:** 203.0.113.45 menghasilkan 2.166 kegagalan selama hampir lima jam, dengan 41 nama akun yang tidak ada dan tiga yang ada, berjeda belasan detik yang sangat teratur. Itu profil pemindaian otomatis dari internet: ramai, lama, tidak selektif, dan tidak berhasil. Baris ketiga yang justru penting: tiga kegagalan dalam 20 detik untuk satu akun yang ada, lalu berhenti. Berhenti setelah tiga percobaan hampir selalu berarti salah satu dari dua hal, yaitu penyerang menyerah, atau percobaan keempat berhasil. Bagian 2.3 menentukan yang mana.
**Variasi:** tambahkan `values(user) AS contoh_akun` untuk melihat nama akun yang dicoba; daftar yang berisi `root`, `admin`, `oracle`, `test` menguatkan dugaan pemindaian.
**Kapan gagal:** menghitung baris bukan menghitung percobaan, karena satu percobaan bisa menulis beberapa baris (bagian 1.2). Angka di atas adalah batas atas. Host yang log-nya lewat relay syslog bisa punya `host` yang salah; cek dengan `stats count BY host` lebih dulu [S22].

### 2.3 Gagal lalu berhasil: pola yang paling layak dieskalasi

**Tujuan:** menemukan pasangan sumber dan host yang punya kegagalan sshd lalu keberhasilan dalam rentang yang sama.

```
index=linux sourcetype=linux_secure process=sshd earliest=-24h
| stats count(eval(action="failure")) AS gagal count(eval(action="success")) AS sukses
        values(user) AS akun min(_time) AS awal max(_time) AS akhir BY src dest
| where gagal >= 3 AND sukses > 0
| eval rentang_menit=round((akhir - awal) / 60, 1)
| eval awal=strftime(awal, "%F %T"), akhir=strftime(akhir, "%F %T")
| sort - gagal
```

- `count(eval(action="failure"))`: hitung bersyarat di dalam satu `stats`, sehingga gagal dan sukses muncul di baris yang sama.
- `BY src dest`: `dest` adalah host tujuan menurut daftar field `linux_secure` [S3]; mengelompokkan per pasangan sumber dan tujuan mencegah dua host tercampur.
- `where gagal >= 3 AND sukses > 0`: ambang tiga kegagalan sengaja rendah, karena yang dicari bukan volume tetapi urutan.

Keluaran ilustrasi:

```
src            dest            gagal  sukses  akun        awal                 akhir                rentang_menit
192.0.2.118    jkt-bastion01   3      1       svc_radius  2026-10-14 02:46:51  2026-10-14 02:47:19  0.5
```

**Cara membaca hasil:** 203.0.113.45 hilang dari hasil karena tidak pernah berhasil, walau kegagalannya 2.166. 192.0.2.118 muncul dengan tiga gagal dan satu sukses dalam 28 detik untuk akun `svc_radius`. Inilah yang dieskalasi, bukan yang ramai.
**Variasi:** periksa metode login yang dipakai akun itu dibandingkan kebiasaannya:

```
index=linux sourcetype=linux_secure process=sshd action=success host=jkt-bastion01
    earliest="10/13/2026:20:00:00" latest="10/14/2026:06:00:00"
| eval metode=case(match(_raw, "Accepted publickey"), "publickey",
                   match(_raw, "Accepted password"), "password",
                   true(), "metode lain")
| table _time host user src src_port metode
| sort _time
```

```
_time                host           user          src           src_port  metode
2026-10-13 21:04:18  jkt-bastion01  andi.pratama  10.10.22.41   51208     publickey
2026-10-14 02:47:19  jkt-bastion01  svc_radius    192.0.2.118   49711     password
2026-10-14 05:58:02  jkt-bastion01  andi.pratama  10.10.22.41   52663     publickey
```

Tiga anomali menumpuk di satu baris: akun service yang login interaktif, memakai password padahal admin manusia memakai publickey, dan dari IP publik padahal yang lain dari subnet kantor. Masing-masing sendiri lemah; bertiga cukup untuk eskalasi.
**Kapan gagal:** `values(user)` membuang duplikat dan mengurutkan, jadi kamu tidak bisa tahu akun mana yang gagal dan mana yang berhasil dari kolom itu. Untuk itu pecah per akun, atau pakai `list()` yang mempertahankan urutan tetapi dibatasi 100 nilai (Day 03 bagian 2.5 memakai pola ini).

### 2.4 `sudo`: perintah yang diminta, dan titik jejaknya berhenti

**Tujuan:** menampilkan semua baris `sudo` di jkt-bastion01 pada rentang sesi itu, termasuk yang ditolak.

```
index=linux sourcetype=linux_secure process=sudo host=jkt-bastion01
    earliest="10/14/2026:02:40:00" latest="10/14/2026:04:00:00"
| rex field=_raw "sudo:\s+(?<pemanggil>\S+)\s+:\s+(?!\w+=)(?<alasan>[^;]+?)\s*;"
| rex field=_raw "TTY=(?<tty>[^\s;]+)"
| rex field=_raw "PWD=(?<pwd>[^\s;]+)"
| rex field=_raw "USER=(?<jadi_user>[^\s;]+)"
| rex field=_raw "COMMAND=(?<perintah>.+)$"
| eval hasil=if(isnotnull(alasan), "ditolak: ".alasan, "diizinkan")
| table _time host pemanggil tty pwd jadi_user hasil perintah
| sort _time
```

- `(?!\w+=)` adalah negative lookahead yang mencegah `alasan` ikut menangkap `TTY=pts/0`. Tanpa itu, baris yang berhasil akan terlihat seperti baris yang ditolak dengan alasan "TTY=pts/0".
- Lima `rex` terpisah, bukan satu regex panjang, karena manual sudoers menyebut sebagian field hanya muncul pada kondisi tertentu (`CHROOT`, `TSID`) [S6]. Satu regex yang mengharuskan semua field hadir akan gagal mencocokkan sebagian baris.
- `isnotnull(alasan)`: baris yang ditolak punya alasan, baris yang diizinkan tidak.

Keluaran ilustrasi:

```
_time                host           pemanggil   tty    pwd                hasil                           perintah
2026-10-14 02:48:05  jkt-bastion01  svc_radius  pts/0  /home/svc_radius   diizinkan                       /bin/bash
2026-10-14 03:06:44  jkt-bastion01  nginxd      pts/1  /tmp               ditolak: user NOT in sudoers    /usr/bin/cat /etc/shadow
```

Kolom `jadi_user` berisi `root` di kedua baris dan dihilangkan dari tampilan di atas supaya tabel tetap terbaca; sertakan di search aslinya.

**Cara membaca hasil:** hanya dua baris dalam 80 menit, dan keduanya memberi informasi berbeda. Baris pertama adalah titik jejak berhenti: 46 detik setelah login, `svc_radius` mendapat shell root, dan semua yang dikerjakan sesudahnya tidak lagi menulis baris `sudo` (bagian 1.3). Baris kedua jauh lebih menarik daripada isinya: ada akun bernama `nginxd` di host ini yang mencoba membaca `/etc/shadow` dari `/tmp` lewat TTY lain. Akun itu tidak ada di daftar akun yang dikenal PT JAB. Penolakan sudoers tidak menghentikan apa pun yang penting; yang penting adalah akun itu ada.
**Variasi:** untuk seluruh estate, cari akun yang mendapat shell lewat sudo: `| search perintah IN ("/bin/bash", "/bin/sh", "/bin/su", "/usr/bin/su") | stats count BY host pemanggil perintah`. Daftar hasilnya adalah daftar host yang jejak sudo-nya tidak bisa dipercaya.
**Kapan gagal:** bila sudoers dikonfigurasi menulis ke file sendiri lewat setelan `logfile`, barisnya tidak ada di `/var/log/secure` sama sekali [S6]. Cek `sudoers` di host, bukan hanya Splunk.

### 2.5 auditd: akun baru, dan siapa sebenarnya yang membuatnya

Akun `nginxd` dari bagian 2.4 harus dijelaskan asalnya. `linux_secure` mungkin memuat baris `useradd`, tetapi auditd memberi identitas pelaku dengan lebih pasti.

**Tujuan:** menampilkan semua record `ADD_USER` di host itu beserta identitas efektif dan identitas login aslinya.

```
index=linux sourcetype=auditd host=jkt-bastion01 type=ADD_USER
    earliest="10/14/2026:02:40:00" latest="10/14/2026:04:00:00"
| table _time host type auid AUID uid UID ses terminal exe id ID res
| sort _time
```

Keluaran ilustrasi:

```
_time                host           type      auid  AUID        uid  UID   ses  terminal  exe                id    ID             res
2026-10-14 02:51:36  jkt-bastion01  ADD_USER  1001  svc_radius  0    root  7    pts/0     /usr/sbin/useradd  1002  unknown(1002)  success
```

**Cara membaca hasil:** `uid=0` dan `UID="root"` berarti aksinya dijalankan sebagai root, tetapi `auid=1001` dan `AUID="svc_radius"` menyebut siapa yang login di sesi itu. Inilah gunanya `auid`: identitas asli tetap terbawa walau sudah lewat `sudo` (bagian 1.4). `terminal=pts/0` dan `ses=7` cocok dengan sesi SSH yang dibuka pukul 02:47:19 di bagian 2.3, jadi rantainya lengkap tanpa perlu menebak. `ID="unknown(1002)"` bukan kerusakan: akun 1002 baru saja dibuat sehingga terjemahan nama belum tersedia saat event ditulis [S4]. Pakai `id` numerik untuk mencocokkannya ke akun `nginxd`.
**Variasi:** untuk melihat apa yang dijalankan di dalam shell root, pakai record `PROCTITLE`:

```
index=linux sourcetype=auditd host=jkt-bastion01 type=PROCTITLE
    earliest="10/14/2026:02:47:00" latest="10/14/2026:04:00:00"
| stats count min(_time) AS awal BY auid proctitle
| eval awal=strftime(awal, "%F %T")
| sort awal
```

```
auid  proctitle                                        count  awal
1001  bash                                             1      2026-10-14 02:48:05
1001  useradd -m -s /bin/bash nginxd                   1      2026-10-14 02:51:36
1001  usermod -aG wheel nginxd                         1      2026-10-14 02:52:02
1002  cat /etc/shadow                                  1      2026-10-14 03:06:44
1001  cat /home/svc_radius/.config/billing/m365.env    1      2026-10-14 03:09:51
```

Baris terakhir adalah temuan terpenting di seluruh tiket ini, dan tidak muncul di satu pun search sebelumnya: sebuah file berisi kredensial integrasi M365 dibaca dari sesi yang sama. Itu yang menyambungkan kejadian di Linux ke bagian 2.8.
**Kapan gagal:** nilai `proctitle` dikodekan heksadesimal ketika perintahnya memuat spasi, sehingga tabel di atas hanya seperti itu bila ada yang mendekodekannya; cek bentuk aslinya dengan `| table proctitle` sebelum memakai pola teks (bagian 1.4). Record `PROCTITLE` juga hanya ada bila aturan audit yang memicunya terpasang. Pembacaan file tidak tercatat kecuali ada watch rule untuk path itu, jadi bila baris terakhir tidak muncul, itu bisa berarti tidak terjadi atau tidak diaudit; tulis mana yang kamu ketahui di tiket.

### 2.6 Entra ID: kegagalan per akun, dan arti kodenya

Sekarang pindah ke keluhan tentang email Fitri.

**Tujuan:** menemukan akun yang punya banyak kegagalan sign-in lalu satu keberhasilan dari IP yang sama.

```
index=o365 sourcetype=azure:monitor:aad category=SignInLogs
    earliest="10/14/2026:00:00:00" latest="10/14/2026:06:00:00"
| rename properties.* AS *
| eval kode='status.errorCode'
| eval hasil=if(kode=0, "berhasil", "gagal")
| stats count(eval(hasil="gagal")) AS gagal count(eval(hasil="berhasil")) AS berhasil
        values(eval(if(hasil="gagal", kode, null()))) AS kode_gagal
        values(clientAppUsed) AS client_app values(conditionalAccessStatus) AS ca
        min(_time) AS awal max(_time) AS akhir BY userPrincipalName ipAddress location
| where gagal >= 5 AND berhasil > 0
| eval awal=strftime(awal, "%F %T"), akhir=strftime(akhir, "%F %T")
| sort - gagal
```

| Bagian | Penjelasan |
|---|---|
| `rename properties.* AS *` | Meratakan JSON bersarang supaya nama field menjadi pendek, pola yang dipakai detection Splunk [S15] |
| `eval kode='status.errorCode'` | Kutip tunggal karena nama field masih memuat titik setelah `rename` |
| `if(kode=0, ...)` | Nilai 0 berarti berhasil; semua nilai lain kegagalan atau interupsi [S10] |
| `values(eval(if(...)))` | Mengumpulkan kode hanya dari baris yang gagal, bukan dari semua baris |

Keluaran ilustrasi:

```
userPrincipalName            ipAddress       location  gagal  berhasil  kode_gagal  client_app  ca          awal                 akhir
fitri.handayani@jab.example  203.0.113.212   SG        18     1         50126       IMAP4       notApplied  2026-10-14 01:12:08  2026-10-14 01:21:44
```

**Cara membaca hasil:** 18 kegagalan `50126` (username atau password salah) dari 01:12:08 sampai 01:20:55, yaitu 527 detik dengan 17 selang, kira-kira satu percobaan setiap 31 detik, lalu satu keberhasilan pada 01:21:44. Pola tebakan password yang berhasil. Dua kolom terakhir menjelaskan kenapa MFA tidak menahannya: `client_app` berisi `IMAP4`, protokol lama yang umumnya tidak mendukung MFA modern, dan `ca` berisi `notApplied`, artinya tidak ada kebijakan Conditional Access yang kondisinya terpenuhi untuk sign-in itu (bagian 1.6). Jadi bukan kebijakannya gagal, melainkan tidak ada kebijakan yang dievaluasi.
**Variasi:** untuk mengerti sebaran kode di tenant sendiri, hitung dulu:

```
index=o365 sourcetype=azure:monitor:aad category=SignInLogs earliest=-24h
| rename properties.* AS *
| stats count dc(userPrincipalName) AS akun dc(ipAddress) AS ip BY 'status.errorCode'
| sort - count
```

```
status.errorCode  count  akun  ip
0                 39227  1142  3104
50140             1902   840   1611
50126             841    311   402
50158             402    198   297
50074             211    164   188
53003             18     7     9
50053             4      2     3
50057             2      2     2
```

Dari 42.607 sign-in interaktif, 3.380 berkode selain 0. Tetapi 1.902 di antaranya `50140` (interupsi "Keep me signed in") dan 402 `50158` (dialihkan ke tantangan eksternal), dua kode yang Microsoft sebut bagian normal alur sign-in dan bukan tanda user gagal [S11]. Keduanya berjumlah 2.304, yaitu 68 persen dari seluruh "kegagalan". Alert yang hanya memfilter `errorCode != 0` akan membawa angka itu ke antrean triage setiap hari.
**Kapan gagal:** kalau `properties.status.errorCode` tidak ada di data-mu, cek apakah add-on versi-mu memakai nama lain, atau apakah yang kamu lihat sebenarnya kolom `ResultType` dari jalur Log Analytics (bagian 1.5). Akun yang berisi GUID alih-alih UPN biasanya berasal dari event `50058`, saat user belum menyelesaikan sign-in [S12].

### 2.7 Conditional Access: apa yang benar-benar dihentikan

**Tujuan:** mengukur berapa sign-in yang tidak pernah dievaluasi kebijakan, dan kebijakan mana yang benar-benar memblokir.

```
index=o365 sourcetype=azure:monitor:aad category=SignInLogs earliest=-24h
| rename properties.* AS *
| stats count count(eval('status.errorCode'=53003)) AS blokir_53003
        dc(userPrincipalName) AS akun BY conditionalAccessStatus
| eval persen=round(count / 426.07, 1)
```

- `count(eval('status.errorCode'=53003))`: kode keluarga 53000 adalah penanda blokir Conditional Access [S13].
- Pembagi `426.07` adalah seperseratus dari total 42.607, cara cepat mengubah jumlah menjadi persen; di search sesungguhnya pakai `eventstats sum(count) AS total` lalu `count / total * 100` supaya tidak ada angka yang dipatok.

Keluaran ilustrasi:

```
conditionalAccessStatus  count  blokir_53003  akun  persen
success                  33385  0             1098  78.4
notApplied               9204   0             412   21.6
failure                  18     18            7     0.0
```

**Cara membaca hasil:** 9.204 sign-in, 21,6 persen dari seluruhnya, berstatus `notApplied`: tidak ada kebijakan yang dievaluasi sama sekali. Itu bukan 9.204 pelanggaran, tetapi juga bukan 9.204 sign-in yang aman; itu wilayah tenant yang tidak tersentuh kontrol, dan sign-in Fitri lewat IMAP4 ada di dalamnya. Hanya 18 sign-in yang benar-benar diblokir, semuanya berkode `53003`. Angka 18 ini yang biasanya dikutip sebagai "Conditional Access bekerja"; angka 9.204 yang perlu masuk laporan bulanan.
**Variasi:** untuk tahu kebijakan mana yang memblokir, buka array kebijakan di dalam event:

```
index=o365 sourcetype=azure:monitor:aad category=SignInLogs earliest=-24h
| rename properties.* AS *
| where 'status.errorCode'=53003
| eval nama_kebijakan='appliedConditionalAccessPolicies{}.displayName',
       hasil_kebijakan='appliedConditionalAccessPolicies{}.result'
| eval pasangan=mvzip(nama_kebijakan, hasil_kebijakan, " = ")
| mvexpand pasangan
| search pasangan="*= failure"
| stats count dc(userPrincipalName) AS akun BY pasangan
```

```
pasangan                                              count  akun
Wajib MFA untuk sign-in dari luar Indonesia = failure 11     5
Wajib device compliant untuk portal admin = failure   7      3
```

`mvzip` menyatukan dua field multivalue sejajar menjadi satu, lalu `mvexpand` memecahnya menjadi satu baris per kebijakan. Cara ini perlu dipakai karena satu event memuat beberapa kebijakan, dan Microsoft mencatat kebijakan yang tidak diterapkan juga muncul di array yang sama [S14]; tanpa menyaring `result = failure`, daftarnya akan memuat kebijakan yang tidak melakukan apa pun. Nama field di dalam array perlu kamu cek di data sendiri, karena bergantung cara add-on memecah JSON.
**Cara membaca hasil variasi ini:** dua kebijakan menahan 18 sign-in, dan tidak ada satu pun kebijakan yang menyebut legacy authentication. Itu penjelasan langsung untuk `notApplied` di sign-in Fitri, dan menjadi rekomendasi konkret di tiket, bukan sekadar temuan.
**Kapan gagal:** `mvzip` mengandalkan kedua field punya jumlah nilai dan urutan yang sama. Bila add-on memecah array dengan cara lain, hasilnya akan salah pasang tanpa error; buktikan dengan satu event yang sudah kamu baca manual.

### 2.8 M365: inbox rule forwarding dan perubahan role

**Tujuan:** menemukan inbox rule yang meneruskan email keluar, dengan pembuat dan tujuannya.

```
index=o365 sourcetype=o365:management:activity Workload=Exchange
    Operation IN ("New-InboxRule", "Set-InboxRule", "UpdateInboxRules")
    earliest="10/14/2026:00:00:00" latest="10/14/2026:06:00:00"
| eval nama_param='Parameters{}.Name', nilai_param='Parameters{}.Value'
| eval i_fwd=mvfind(nama_param, "^(ForwardTo|ForwardAsAttachmentTo|RedirectTo)$")
| where isnotnull(i_fwd)
| eval tujuan=mvindex(nilai_param, i_fwd)
| eval i_nama=mvfind(nama_param, "^Name$")
| eval nama_rule=if(isnotnull(i_nama), mvindex(nilai_param, i_nama), "(tanpa nama)")
| eval keluar_tenant=if(match(tujuan, "(?i)@jab\.example$"), "tidak", "ya")
| table _time UserId ClientIP Operation nama_rule tujuan keluar_tenant ResultStatus
| sort _time
```

| Bagian | Penjelasan |
|---|---|
| `Operation IN (...)` | Operator `IN` di command `search`; nilainya tidak peka huruf besar-kecil di sini |
| `mvfind(nama_param, "^(ForwardTo\|...)$")` | Mencari posisi parameter forwarding di field nama, pola yang dipakai detection Splunk [S18] |
| `mvindex(nilai_param, i_fwd)` | Mengambil nilai di posisi yang sama; mengandalkan dua field multivalue berurutan sama |
| `keluar_tenant` | Satu kolom yang langsung memisahkan aturan jinak dari yang perlu ditindak |

Keluaran ilustrasi:

```
_time                UserId                       ClientIP        Operation      nama_rule  tujuan                               keluar_tenant  ResultStatus
2026-10-14 01:24:02  fitri.handayani@jab.example  203.0.113.212   New-InboxRule  .          arsip.keuangan@mail-archive.example   ya             True
```

**Cara membaca hasil:** dua menit setelah sign-in IMAP4 di bagian 2.6, dari IP yang sama, sebuah inbox rule bernama `.` dibuat di mailbox Fitri untuk meneruskan email ke alamat di luar tenant. Nama satu karakter adalah pola khas penyembunyian: aturan seperti itu hampir tidak terlihat di daftar rule Outlook. `ResultStatus` berisi `True` karena operasi Exchange dicatat sebagai hasil cmdlet, bukan sebagai `Success`; jangan menulis filter `ResultStatus=Success` untuk workload ini tanpa memeriksa nilainya dulu.
**Variasi:** ambil juga parameter penyembunyian untuk menilai keparahannya: `| eval i_hapus=mvfind(nama_param, "^(DeleteMessage|MoveToFolder|MarkAsRead)$")` lalu tampilkan nilainya. Aturan yang meneruskan sekaligus memindahkan dan menandai sudah dibaca dibuat untuk tidak diketahui pemilik mailbox [S17].
**Kapan gagal:** `mvfind` mengembalikan posisi kemunculan pertama saja, jadi aturan dengan dua parameter forwarding sekaligus hanya memperlihatkan satu. Kalau `Parameters{}.Name` dan `Parameters{}.Value` tidak sejajar di data-mu, kolom tujuan akan berisi nilai parameter lain tanpa ada error; uji dengan satu event yang sudah kamu baca manual.

Sekarang bagian ketiga pesan SOC lead.

**Tujuan:** menampilkan semua pemberian role direktori, dengan pelaku, penerima, dan nama role di kolom yang benar.

```
index=o365 sourcetype=o365:management:activity Workload=AzureActiveDirectory
    Operation IN ("Add member to role.", "Add eligible member to role.")
    earliest="10/14/2026:00:00:00" latest="10/14/2026:06:00:00"
| eval nama_prop='ModifiedProperties{}.Name', nilai_prop='ModifiedProperties{}.NewValue'
| eval i_role=mvfind(nama_prop, "^Role\.DisplayName$")
| eval role=if(isnotnull(i_role), mvindex(nilai_prop, i_role), "(tidak terbaca)")
| eval pelaku=mvjoin('Actor{}.ID', " / ")
| table _time pelaku ObjectId role Operation ResultStatus ClientIP
| sort _time
```

- `ObjectId` adalah akun yang menerima role, dan `Actor{}.ID` adalah pelakunya [S19].
- `mvjoin('Actor{}.ID', " / ")` menampilkan semua bentuk identitas pelaku sekaligus, bukan memilih satu. Detection Splunk memilih elemen berdasarkan tipe aktor; sampai kamu tahu elemen mana yang kamu butuh, menampilkan semuanya lebih aman daripada `mvindex(..., 0)` yang bisa memberi GUID [S19].
- Nama role tidak punya field sendiri: ia disimpan sebagai pasangan nama dan nilai di array `ModifiedProperties`, jadi pola `mvfind` lalu `mvindex` dipakai lagi [S19].

Keluaran ilustrasi:

```
_time                pelaku                                               ObjectId                  role                    Operation            ResultStatus  ClientIP
2026-10-14 03:18:47  jab-billing-sync / 7f3a1c92-...                      budi.santoso@jab.example  Exchange Administrator  Add member to role.  Success       192.0.2.118
```

**Cara membaca hasil:** pelakunya bukan manusia, melainkan service principal `jab-billing-sync`, yaitu integrasi billing. Service principal tidak seharusnya memberi role admin ke akun karyawan. `ClientIP` berisi 192.0.2.118, IP yang sama dengan sumber login SSH di bagian 2.3, dan waktunya sembilan menit setelah file `m365.env` dibaca di bagian 2.5. Rantainya jelas: kredensial integrasi diambil dari host Linux lalu dipakai untuk membuat persistence di tenant.
**Variasi:** periksa sign-in service principal itu untuk memastikan kredensialnya memang dipakai dari luar:

```
index=o365 sourcetype=azure:monitor:aad category=ServicePrincipalSignInLogs
    earliest="10/13/2026:00:00:00" latest="10/14/2026:06:00:00"
| rename properties.* AS *
| stats count values(ipAddress) AS ip min(_time) AS awal max(_time) AS akhir BY servicePrincipalName
| where count > 0
```

Baseline service principal biasanya sangat sempit: satu atau dua IP tetap milik sistem yang memanggilnya. IP baru pada identitas aplikasi hampir selalu berarti kredensialnya dipakai dari tempat lain.
**Kapan gagal:** kalau kategori `ServicePrincipalSignInLogs` tidak dikirim tenant (bagian 2.1), search ini kosong dan ketiadaan hasilnya tidak membuktikan apa pun. Pemberian role lewat Privileged Identity Management juga memunculkan `Add eligible member to role.` secara rutin, jadi tanpa cara memeriksa change request alert ini akan berisik [S19].

### 2.9 Satu linimasa untuk tiket

**Tujuan:** menyusun satu tabel kronologis dari empat sourcetype, dibatasi pada dua alamat dan dua akun yang relevan.

```
index=linux OR index=o365 earliest="10/14/2026:00:00:00" latest="10/14/2026:06:00:00"
    ((sourcetype=linux_secure host=jkt-bastion01 (process=sshd OR process=sudo))
     OR (sourcetype=auditd host=jkt-bastion01 type IN (ADD_USER, PROCTITLE))
     OR (sourcetype=azure:monitor:aad category IN (SignInLogs, ServicePrincipalSignInLogs))
     OR (sourcetype=o365:management:activity Operation IN ("New-InboxRule", "Add member to role.")))
| rename properties.ipAddress AS ip_cloud, properties.userPrincipalName AS upn,
         properties.servicePrincipalName AS spn
| eval akun=coalesce(user, upn, spn, UserId, AUID)
| eval alamat=coalesce(src, ip_cloud, ClientIP)
| eval kejadian=case(
      sourcetype="linux_secure" AND process="sshd", "ssh ".action,
      sourcetype="linux_secure" AND process="sudo", "sudo",
      sourcetype="auditd", "auditd ".type,
      sourcetype="azure:monitor:aad", "entra ".category,
      sourcetype="o365:management:activity", Operation,
      true(), sourcetype)
| where in(alamat, "192.0.2.118", "203.0.113.212") OR in(akun, "svc_radius", "nginxd")
| table _time alamat akun kejadian host
| sort _time
```

- `rename` dipakai lebih dulu untuk tiga field cloud supaya `coalesce` tidak perlu memuat nama bertitik.
- `coalesce(user, upn, spn, UserId, AUID)`: satu kolom akun dari lima nama berbeda. Urutannya menentukan: yang paling spesifik di depan.
- `where ... OR in(akun, ...)`: filter alamat saja tidak cukup, karena record auditd tidak punya alamat IP sama sekali. Tanpa cabang kedua, langkah paling penting di linimasa justru terbuang.

Keluaran ilustrasi:

```
_time                alamat         akun                         kejadian                          host
2026-10-14 01:12:08  203.0.113.212  fitri.handayani@jab.example  entra SignInLogs                  
2026-10-14 01:21:44  203.0.113.212  fitri.handayani@jab.example  entra SignInLogs                  
2026-10-14 01:24:02  203.0.113.212  fitri.handayani@jab.example  New-InboxRule                     
2026-10-14 02:46:51  192.0.2.118    svc_radius                   ssh failure                       jkt-bastion01
2026-10-14 02:47:19  192.0.2.118    svc_radius                   ssh success                       jkt-bastion01
2026-10-14 02:48:05  192.0.2.118    svc_radius                   sudo                              jkt-bastion01
2026-10-14 02:51:36                 svc_radius                   auditd ADD_USER                   jkt-bastion01
2026-10-14 03:06:44                 nginxd                       sudo                              jkt-bastion01
2026-10-14 03:09:51                 svc_radius                   auditd PROCTITLE                  jkt-bastion01
2026-10-14 03:12:33  192.0.2.118    jab-billing-sync             entra ServicePrincipalSignInLogs  
2026-10-14 03:18:47  192.0.2.118    jab-billing-sync             Add member to role.               
```

**Cara membaca hasil:** linimasa ini menjawab pertanyaan terakhir SOC lead, dan jawabannya adalah dua kejadian terpisah, bukan satu. Tiga baris pertama memakai 203.0.113.212 dan satu identitas cloud; itu business email compromise terhadap Fitri yang masuk lewat protokol lama tanpa kebijakan Conditional Access. Delapan baris berikutnya memakai 192.0.2.118 dan bergerak dari host Linux ke tenant; itu rantai berbeda yang dimulai dari akun service dengan password lemah di bastion. Alert login gagal 2.166 kali dari 203.0.113.45 tidak muncul di linimasa sama sekali, karena tidak pernah berhasil.
**Kapan gagal:** kolom `_time` dari sumber cloud adalah waktu kejadian menurut Microsoft, sedangkan urutan kedatangannya di Splunk berbeda (bagian 2.1). Linimasa yang disusun kurang dari 15 menit setelah kejadian terakhir hampir selalu belum lengkap; catat jam pembuatan linimasa di tiket.

**Ringkasan untuk tiket SOC-2026-0244:** alert SSH login gagal dari 203.0.113.45 adalah pemindaian internet tanpa keberhasilan, cukup dicatat dan ditutup sebagai benign dengan rekomendasi membatasi akses SSH bastion ke subnet manajemen. Eskalasikan dua insiden terpisah ke L2. Pertama, kompromi `svc_radius` di jkt-bastion01 dari 192.0.2.118, dengan akun baru `nginxd` di grup `wheel`, pembacaan file kredensial `m365.env`, sign-in service principal `jab-billing-sync` dari IP yang sama, dan pemberian role Exchange Administrator ke budi.santoso; sertakan `ses=7`, `auid=1001`, dan search bagian 2.3 sampai 2.8. Kedua, business email compromise terhadap fitri.handayani lewat IMAP4 dari 203.0.113.212 dengan inbox rule forwarding bernama `.`; sertakan search bagian 2.6 dan 2.8. Tambahkan dua temuan kontrol: 21,6 persen sign-in tenant berstatus `notApplied` dan tidak ada kebijakan Conditional Access yang memblokir legacy authentication, dan auditd hanya aktif di 6 dari 42 host Linux.

## 3. Lab praktik (di VM lab terisolasi)

Lab memakai tiga sumber: BOTS v2 (dataset statis, memuat `linux_secure`, `linux_audit`, dan `auditd` [S20]), VM Linux lab milikmu sendiri, dan data sintetis `makeresults` untuk sisi cloud. Semua perintah Linux dijalankan di VM lab bersnapshot, bukan di mesin kerja. Sisi cloud tidak dilatih dengan tenant sungguhan: contoh JSON dibuat sendiri, karena kamu tidak perlu menyentuh tenant produksi untuk melatih pembacaan field.

1. **Rentang waktu BOTS v2.** README BOTS v2 tidak mencantumkan periode datanya [S20], jadi temukan sendiri: `| tstats min(_time) AS awal max(_time) AS akhir where index=botsv2 sourcetype=linux_secure | eval awal=strftime(awal, "%F %T"), akhir=strftime(akhir, "%F %T")`. Catat hasilnya dan pakai sebagai rentang absolut di semua langkah BOTS berikutnya. Jangan memakai `earliest=-7d` pada dataset ini.
2. **Inventaris program penulis.** Dengan rentang dari langkah 1, jalankan `index=botsv2 sourcetype=linux_secure | stats count BY process | sort - count`. Catat program apa saja yang menulis ke sourcetype ini di dataset itu, dan bandingkan dengan daftar di bagian 1.2.
3. **Bentuk baris sshd.** Ambil satu event `Accepted`, satu `Failed password`, satu `Failed password for invalid user`, dan satu `[preauth]` dari BOTS v2. Tulis sendiri tabel pasangan "pola baris" dan "field yang terisi" untuk keempatnya. Ini yang akan kamu pakai sebagai acuan regex nanti.
4. **Hitung percobaan, bukan baris.** Pada satu IP penyerang di BOTS v2, bandingkan `stats count` dengan `stats dc(_raw)` dan dengan `stats count BY user`. Tulis satu paragraf: berapa selisihnya, dan kenapa angka mana yang pantas ditulis di tiket.
5. **Siapkan VM Linux.** Di VM lab, pastikan sshd menulis ke file yang dipantau, lalu aktifkan auditd dan tambahkan dua aturan: satu watch rule untuk file kredensial buatan (`-w /root/lab-secret.env -p r -k labsecret`) dan satu untuk eksekusi (`-a always,exit -F arch=b64 -S execve -k labexec`). Nama file aturan dan cara memuatnya berbeda antar distro; cek `auditctl -l` setelah memuat.
6. **Input forwarder.** Siapkan input berikut di forwarder VM, setelah membandingkan dengan `inputs.conf` bawaan add-on versi-mu (sourcetype wajib ditetapkan eksplisit, karena `linux_secure` berbasis syslog dan sering tidak dikenali otomatis [S22]):

   ```
   [monitor:///var/log/secure]
   disabled = 0
   sourcetype = linux_secure
   index = linux

   [monitor:///var/log/audit/audit.log]
   disabled = 0
   sourcetype = linux_audit
   index = linux
   ```

7. **Buat event uji.** Di VM: lima kali SSH gagal ke akun lab yang ada, lima kali ke akun yang tidak ada, lalu satu login berhasil dengan password. Dari sesi itu jalankan `sudo /bin/bash`, lalu di dalam shell root buat akun `labuser01`, masukkan ke grup sudo atau wheel, dan baca `/root/lab-secret.env`. Terakhir, dari akun `labuser01`, coba `sudo cat /etc/shadow` supaya ada satu penolakan sudoers.
8. **Temukan semuanya di Splunk.** Jalankan versi bagian 2.2, 2.3, 2.4, dan 2.5 dengan host VM-mu. Pastikan `auid` di record `ADD_USER` berisi UID akun yang login, bukan 0, dan catat nilai `ses` dan `terminal`-nya. Lalu buktikan titik buta bagian 1.3: hitung berapa baris `sudo` yang ada untuk seluruh rangkaian langkah 7, dan berapa aksi yang sebenarnya kamu lakukan.
9. **Bentuk `proctitle`.** Jalankan `index=linux sourcetype=linux_audit type=PROCTITLE | table _time proctitle | head 20`. Catat apakah nilainya teks atau heksadesimal. Bila heksadesimal, tulis satu `eval` yang mendekodekannya dan simpan sebagai catatan; tanpa itu, filter berbasis teks seperti yang dipakai detection Splunk [S5] tidak akan cocok di data-mu.
10. **Latih field Entra tanpa tenant.** Buat event sintetis lalu jalankan logika bagian 2.6 di atasnya:

    ```
    | makeresults format=csv data="upn,ip,kode,ca,app
    fitri@jab.example,203.0.113.212,50126,notApplied,IMAP4
    fitri@jab.example,203.0.113.212,0,notApplied,IMAP4
    budi@jab.example,198.51.100.10,53003,failure,Browser
    andi@jab.example,10.10.22.41,50140,success,Browser
    andi@jab.example,10.10.22.41,0,success,Browser"
    | eval hasil=if(kode=0, "berhasil", "gagal")
    | stats count(eval(hasil="gagal")) AS gagal count(eval(hasil="berhasil")) AS berhasil
            values(kode) AS kode values(ca) AS ca BY upn ip app
    ```

    Hasil yang diharapkan: tiga baris, dan hanya `fitri@jab.example` yang punya gagal sekaligus berhasil. Lalu tambahkan satu baris berkode `50158` dan periksa apakah logikamu menghitungnya sebagai kegagalan; perbaiki sampai kode interupsi tidak lagi ikut terhitung.
11. **Latih array parameter M365.** Buat satu event dengan dua field multivalue sejajar (`makeresults` lalu `eval nama=split("Name,ForwardTo,MarkAsRead", ","), nilai=split(".,arsip@luar.example,True", ",")`), lalu jalankan pola `mvfind` dan `mvindex` dari bagian 2.8. Setelah berhasil, acak urutan salah satu field dan lihat apa yang terjadi pada kolom tujuan. Catat gejalanya, karena di data nyata kesalahan ini tidak memunculkan error.

**Hasil yang sebaiknya tersimpan:**

- Rentang waktu BOTS v2 yang terverifikasi dan daftar `process` yang menulis ke `linux_secure` di dataset itu.
- Tabel pola baris sshd dan field yang terisi, dari data lab-mu sendiri.
- Angka perbandingan "jumlah baris" dan "jumlah percobaan" untuk satu IP penyerang, dengan satu paragraf penjelasan.
- Satu record `ADD_USER` dari lab-mu dengan `auid`, `ses`, dan `terminal` yang sudah kamu cocokkan ke sesi SSH-nya.
- Angka "berapa baris sudo untuk berapa aksi nyata", sebagai bukti titik buta yang akan kamu kutip saat menulis tiket.
- Catatan bentuk `proctitle` di lab-mu, beserta `eval` pendekodean bila diperlukan.
- Logika kode kesalahan Entra yang sudah tidak menghitung `50140` dan `50158` sebagai kegagalan.
- Catatan gejala salah pasang `mvfind` dan `mvindex` saat urutan array berubah.

**Variasi tantangan:** jadikan search bagian 2.3 sebuah scheduled alert (Day 09) dengan throttle per `src`, lalu tulis satu paragraf: kenapa alert ini sebaiknya berbasis urutan (gagal lalu sukses) dan bukan ambang jumlah kegagalan, dan apa yang terjadi pada alert itu bila penyerang berhasil di percobaan pertama.

## 4. Troubleshooting

Tabel ini untuk saat search tidak mengembalikan yang kamu harapkan; mulai dari kolom gejala.

| Gejala | Kemungkinan penyebab | Cara memeriksa atau memperbaiki |
|---|---|---|
| `sourcetype=linux_secure` kosong padahal file ada | Sourcetype tidak ditetapkan eksplisit, event masuk sebagai `syslog` | Tetapkan `sourcetype` di `inputs.conf`; cek `stats count BY sourcetype` pada index itu [S22] |
| Field `user`, `src`, `action` tidak terisi | Add-on Unix dan Linux belum terpasang di search head | Pasang add-on; field `linux_secure` adalah extraction search-time dari add-on [S1][S3] |
| `host` berisi nama server syslog, bukan server asal | Log dikirim lewat relay | Cek `stats count BY host`; perbaiki di sisi relay atau tetapkan `host` dari isi event [S22] |
| Semua baris sudo terlihat "ditolak" dengan alasan `TTY=...` | Regex alasan ikut menangkap pasangan nama dan nilai | Tambahkan negative lookahead `(?!\w+=)` (bagian 2.4) |
| Jejak berhenti setelah satu baris `sudo` | Yang dijalankan adalah shell, bukan satu perintah | Lanjutkan dengan auditd `PROCTITLE` dan `EXECVE` (bagian 2.5) [S5] |
| `sourcetype=auditd` kosong, `linux_audit` ada | Dua sourcetype berasal dari jalur berbeda | Cek jalur mana yang dipakai; detection Splunk memakai `auditd` [S1][S4] |
| Detection auditd dari Splunk tidak pernah memicu | `proctitle` berisi heksadesimal, bukan teks | Dekode dulu, atau filter pada `EXECVE` (bagian 1.4) |
| `ID` di auditd berisi `unknown(<angka>)` | Nama akun belum bisa diterjemahkan saat event ditulis | Pakai `id` numerik lalu cocokkan sendiri [S4] |
| Sign-in Entra tidak ada di `o365:management:activity` | Sign-in datang dari add-on Cloud Services, bukan add-on Office 365 | Cari di `sourcetype=azure:monitor:aad` [S15][S23] |
| `properties.status.errorCode` tidak ada | Belum di-flatten, atau nama field berbeda | `rename properties.* AS *`; cek dengan `| fieldsummary` [S15] |
| `eval kode=properties.status.errorCode` memberi hasil aneh | Nama field bertitik tanpa kutip tunggal | Pakai `'properties.status.errorCode'` (Day 11) |
| Jumlah login gagal Entra jauh lebih besar dari dugaan | Kode interupsi ikut terhitung | Kecualikan `50140`, `50158`, dan kode interupsi lain [S11] |
| Detection sign-in Entra diam tanpa error | Kategori yang dibutuhkan tidak dikirim tenant | `stats count BY category`; bandingkan dengan diagnostic settings [S9] |
| Kolom tujuan inbox rule berisi nilai parameter lain | `Parameters{}.Name` dan `Parameters{}.Value` tidak sejajar | Buktikan dengan satu event yang sudah dibaca manual (bagian 2.8) |
| `ResultStatus=Success` tidak menemukan operasi Exchange | Operasi cmdlet Exchange memakai nilai lain, misalnya `True` | Cek `stats count BY Workload ResultStatus` dulu |
| Search cloud 10 menit terakhir sering nol hasil | Data berbasis API datang dalam batch | Geser rentang alert seperti detection Splunk, `-70m` sampai `-10m` [S17][S19] |

## 5. Kesalahan umum dan jebakan

- Menilai serangan SSH dari jumlah baris. Satu percobaan bisa menulis beberapa baris, dan server yang terbuka ke internet selalu ramai. Yang menentukan adalah rasio gagal terhadap sukses dan apakah akunnya ada (bagian 1.2 dan 2.2).
- Menganggap jejak `sudo` sebagai daftar lengkap aktivitas istimewa. `sudo` mencatat perintah yang diminta; begitu yang diminta adalah shell, catatannya berhenti [S6].
- Memakai `uid` sebagai identitas pelaku di auditd. Setelah `sudo`, semua orang ber-`uid` 0. Yang menyebut manusia aslinya adalah `auid` [S4].
- Menganggap event auditd tidak ada berarti aksinya tidak terjadi. Tanpa aturan audit yang relevan, event-nya tidak pernah ditulis, terutama untuk pembacaan file (bagian 1.4 dan 1.8).
- Mencari sign-in Entra di `o365:management:activity`. Dua jalur ingest berbeda; sign-in ada di `azure:monitor:aad` [S15][S23].
- Memfilter `category=SignInLogs` lalu menyimpulkan tidak ada aktivitas mencurigakan. Sign-in non-interaktif dan service principal ada di kategori lain, dan sering jauh lebih besar volumenya [S9].
- Menghitung semua `errorCode` selain 0 sebagai login gagal. `50140` dan `50158` adalah interupsi normal dalam alur sign-in menurut Microsoft [S11].
- Membaca `conditionalAccessStatus` bernilai `notApplied` sebagai "diizinkan kebijakan". Artinya tidak ada kebijakan yang dievaluasi, dan itu temuan tersendiri (bagian 1.6).
- Menghitung entri di `appliedConditionalAccessPolicies` sebagai kebijakan yang berlaku. Microsoft mencatat kebijakan yang tidak diterapkan juga muncul di daftar itu [S14].
- Menjadikan kode negara dua huruf sebagai dasar deteksi impossible travel. Dokumentasi menyebut nilainya tidak selalu bisa diuraikan sampai tingkat kota, dan VPN serta operator seluler membuatnya berpindah tanpa orangnya berpindah [S10].
- Membaca `hidden` di field risiko sebagai "tidak berisiko". Itu berarti tenant tidak berlisensi untuk menilai risiko itu [S10][S14].
- Menganggap `TargetUserName` dan padanannya selalu berarti akun manusia. Di event role M365, penerima ada di `ObjectId` dan pelaku di `Actor{}.ID`, sedangkan nama role tersimpan sebagai pasangan nama dan nilai di array `ModifiedProperties` [S19].
- Mengambil `mvindex('Actor{}.ID', 0)` lalu memakainya sebagai identitas pelaku. Field itu multivalue dengan beberapa bentuk identitas; detection Splunk memilih elemennya berdasarkan tipe aktor [S19].
- Mengabaikan nama inbox rule. Nama satu karakter atau titik adalah pola penyembunyian, dan detection Splunk memang memberi skor pada entropi serta panjang nama [S17].
- Menutup alert pemberian role sebagai false positive karena "pasti PIM". PIM memang membuat alert ini berisik, tetapi yang membedakan hanya pemeriksaan ke change request, bukan dugaan [S19].

## 6. Catatan terkini

Bagian ini menampung versi dan tanggal sumber. Tidak ada yang mengubah search di atas, kecuali bila instance-mu memakai add-on versi lama.

- Splunk Add-on for Unix and Linux terbaru di Splunkbase adalah 10.3.4, dirilis 1 September 2026, kompatibel dengan Splunk Enterprise dan Cloud 9.4 sampai 10.6, dengan kompatibilitas CIM 6.x [S2]. Dokumentasi add-on kini berada di situs GitHub Pages Splunk, bukan di docs.splunk.com [S1].
- Splunk Add-on for Microsoft Cloud Services terbaru adalah 6.3.3, dirilis 10 September 2026, dengan kompatibilitas CIM 5.x [S7]. Splunk Add-on for Microsoft Office 365 terbaru adalah 6.1.1, dirilis 30 September 2026, juga CIM 5.x [S8].
- App Splunk Common Information Model di Splunkbase sudah di versi 8.7.0 (2 September 2026) [S21], sedangkan ketiga add-on di atas masih mencantumkan kompatibilitas CIM 5.x atau 6.x. Selisih ini normal, tetapi cek matriks kompatibilitas add-on sebelum mengandalkan pemetaan ke data model Authentication dan Change.
- Halaman data source research.splunk.com untuk Linux Secure dan Linux Auditd Add User keduanya bertanggal 13 Mei 2026 dan diuji dengan add-on Unix dan Linux 10.3.4 [S3][S4].
- Detection Entra ID di research.splunk.com masih memakai nama lama "Azure AD" di judulnya walau produknya sudah berganti nama menjadi Microsoft Entra ID [S15][S16]. Dua nama itu perlu dikenali karena dokumentasi, nama field, dan nilai `category` masih bercampur: sourcetype-nya `azure:monitor:aad`, sedangkan dokumentasi Microsoft sudah sepenuhnya memakai "Entra".
- Detection O365 Privileged Role Assigned diperbarui 22 September 2026 (versi 12), sedangkan detection inbox rule dan forwarding diperbarui 13 Mei 2026 [S17][S18][S19]. Ketiganya disabled secara bawaan dan dijadwalkan setiap jam dengan rentang `-70m` sampai `-10m`.
- Referensi kode AADSTS Microsoft diperbarui Juni 2026, halaman troubleshoot sign-in errors Februari 2026, halaman troubleshoot Conditional Access Mei 2026, halaman kategori diagnostic settings Mei 2026, dan tabel Azure Monitor `SigninLogs` Agustus 2026 [S10][S11][S12][S13][S9].
- Daftar kategori diagnostic settings Entra terus bertambah; per halaman yang dibuka sudah ada kategori untuk agent identity (`RiskyAgents`, `AgentRiskEvents`) dan `MicrosoftGraphActivityLogs`, serta `MicrosoftServicePrincipalSignInLogs` yang masih preview dan oleh Microsoft sendiri disebut tidak esensial untuk investigasi keamanan [S9].
- BOTS v2 dibuat dengan Splunk Enterprise 7.2.1, Splunk Add-on for Unix and Linux 6.0.0, dan CIM 4.12.0, dirilis dengan lisensi CC0 [S20]. Nama field `linux_secure` di dataset itu bisa berbeda dari add-on 10.3.4; bandingkan sebelum memindahkan search dari lab ke produksi.

## 7. Cheat sheet

```
LINUX                index=linux
  linux_secure       /var/log/secure (RHEL) | /var/log/auth.log (Debian)
                     pisahkan dengan process=sshd | sudo | su | useradd
                     field CIM: user src dest action process pid src_port
  sshd               Accepted password|publickey ... from <ip> port <n>
                     Failed password [for invalid user] <user> from <ip>
                     Connection closed by ... [preauth]  = pemindaian
  sudo               <user> : TTY= ; CHROOT= ; PWD= ; USER= ; GROUP= ; TSID= ; ENV= ; COMMAND=
                     tolak: user NOT in sudoers | user NOT authorized on host
                            command not allowed | N incorrect password attempts
                     sudo /bin/bash  = jejak berhenti di sini
  auditd             sourcetype=auditd | linux_audit | linux:audit (app lain)
                     type=ADD_USER | EXECVE | PROCTITLE | SYSCALL | USER_AUTH
                     uid  = efektif (0 setelah sudo)
                     auid = identitas login asli  <- pakai ini
                     ses terminal exe res id/ID

ENTRA ID             index=o365 sourcetype=azure:monitor:aad
  category           SignInLogs (interaktif) | NonInteractiveUserSignInLogs
                     ServicePrincipalSignInLogs | ManagedIdentitySignInLogs | AuditLogs
  flatten            | rename properties.* AS *     lalu 'status.errorCode' (kutip tunggal)
  kode               0 berhasil
                     50126 pwd salah | 50034 akun tak ada | 50053 terkunci/IP jahat
                     50055 pwd expired | 50057 disabled
                     50074 MFA tidak dilewati | 50076 MFA wajib | 50079 belum enroll MFA
                     500121 tidak selesaikan MFA | 70046 sesi expired
                     53003 diblokir CA (53000-53009) | 530035 security defaults
                     BUKAN kegagalan: 50140 KMSI | 50158 challenge eksternal | 50058 belum sign-in
  CA                 conditionalAccessStatus = success | failure | notApplied
                     notApplied = tidak ada kebijakan dievaluasi, bukan "diizinkan"
                     appliedConditionalAccessPolicies memuat yang TIDAK diterapkan juga
  lokasi             Location = kode negara 2 huruf | LocationDetails = kota/koordinat
                     AutonomousSystemNumber = ASN | clientAppUsed: IMAP4/POP3/SMTP = legacy
                     RiskLevel* = hidden berarti tidak dinilai, bukan aman

M365                 index=o365 sourcetype=o365:management:activity
  pisahkan           Workload = Exchange | AzureActiveDirectory | SharePoint
  inbox rule         Operation = New-InboxRule | Set-InboxRule | UpdateInboxRules
                     Parameters{}.Name / Parameters{}.Value  (sejajar, pakai mvfind + mvindex)
                     ForwardTo ForwardAsAttachmentTo RedirectTo DeleteMessage
                     MoveToFolder MarkAsRead Name
  role               Operation = "Add member to role." | "Add eligible member to role."
                     penerima = ObjectId | pelaku = Actor{}.ID (multivalue)
                     role = ModifiedProperties{}.NewValue di entri Role.DisplayName
                     ResultStatus Exchange bisa "True", bukan "Success"

PENYAMBUNG           src (linux) = properties.ipAddress (entra) = ClientIP (m365)
                     akun: nama pendek (linux) vs UPN (cloud) vs service principal
                     data cloud datang dalam batch: alert pakai -70m sampai -10m
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Skenario keputusan.** Dua alert masuk pagi yang sama untuk host Linux yang sama. Alert A: 2.166 kegagalan SSH dari satu IP publik selama hampir lima jam, 41 nama akun yang tidak ada, nol keberhasilan. Alert B: tiga kegagalan SSH dari IP publik lain dalam 20 detik untuk satu akun service yang ada, lalu satu keberhasilan dengan password. Mana yang kamu kerjakan lebih dulu?

<details><summary>Jawaban</summary>

B, dan selisih prioritasnya besar. Alert A adalah profil pemindaian otomatis dari internet: ramai, lama, tidak selektif, dan tanpa keberhasilan, jadi nilainya hanya sebagai masukan untuk membatasi akses SSH. Alert B punya tiga hal yang menumpuk dalam satu baris: akun service yang login interaktif, memakai password padahal admin manusia memakai publickey, dan dari IP publik. Berhenti setelah tiga percobaan hampir selalu berarti penyerang menyerah atau percobaan berikutnya berhasil, dan di sini jelas berhasil. Jumlah event adalah ukuran kebisingan, bukan ukuran risiko. Lihat bagian 1.2, 2.2, dan 2.3.

</details>

**2. Pertanyaan jebakan.** "Di record auditd ini `uid=0` dan `UID="root"`, jadi yang membuat akun baru adalah root. Tidak ada jejak siapa orangnya." Benarkah?

<details><summary>Jawaban</summary>

Tidak. `uid` adalah identitas efektif saat aksi dijalankan, dan setelah `sudo` nilainya 0 untuk siapa pun. Yang menyebut manusia aslinya adalah `auid`, audit login UID, yang dipertahankan sepanjang sesi walaupun identitas efektifnya sudah berganti. Di contoh halaman data source Splunk, satu record `ADD_USER` memuat `uid` 0 bersama `AUID="ubuntu"` di event yang sama. Pakai juga `ses` dan `terminal` dari record itu untuk mencocokkannya ke sesi SSH yang membukanya. Lihat bagian 1.4 dan 2.5.

</details>

**3. Pertanyaan jebakan.** Search `index=o365 sourcetype=o365:management:activity` dijalankan untuk mencari sign-in Entra ID yang mencurigakan dan mengembalikan nol hasil. Analyst menyimpulkan tidak ada sign-in mencurigakan. Di mana kesalahannya?

<details><summary>Jawaban</summary>

Dua sumber Microsoft masuk lewat dua jalur berbeda. `o365:management:activity` berasal dari Office 365 Management Activity API lewat Splunk Add-on for Microsoft Office 365, dan memuat audit perubahan (termasuk audit directory Entra dengan `Workload=AzureActiveDirectory`), bukan log sign-in. Sign-in Entra datang dari diagnostic settings tenant ke event hub, dibaca Splunk Add-on for Microsoft Cloud Services, dan tersimpan sebagai `sourcetype=azure:monitor:aad`. Nol hasil di sini adalah masalah sourcetype, bukan bukti tidak ada kejadian. Lihat bagian 1.1 dan 1.5.

</details>

**4. Skenario keputusan.** Laporan bulanan tenant M365 PT JAB menulis "Conditional Access memblokir 18 sign-in berisiko bulan ini". Dari data yang sama, 21,6 persen sign-in berstatus `notApplied`. Angka mana yang perlu kamu bawa ke manajemen, dan kenapa?

- A. Angka 18, karena itu bukti kontrol bekerja.
- B. Angka 21,6 persen, karena `notApplied` berarti tidak ada kebijakan yang dievaluasi sama sekali untuk sign-in itu.
- C. Keduanya tidak perlu; yang penting hanya jumlah sign-in yang berhasil.

<details><summary>Jawaban</summary>

B, dengan angka 18 sebagai pelengkap. `notApplied` bukan "diizinkan kebijakan", melainkan "tidak ada kebijakan yang kondisinya terpenuhi", sehingga 21,6 persen sign-in itu adalah wilayah tenant yang tidak tersentuh kontrol. Di kasus PT JAB, sign-in lewat IMAP4 yang berhasil setelah 18 kali tebakan password ada tepat di dalam kelompok itu, dan tidak ada satu pun kebijakan yang menyebut legacy authentication. A keliru karena 18 adalah ukuran seberapa sering kebijakan yang ada tersentuh, bukan ukuran cakupannya. C keliru karena menghilangkan satu-satunya angka yang bisa ditindaklanjuti. Lihat bagian 1.6 dan 2.7.

</details>

**5. Pertanyaan jebakan.** Alert "login Entra ID gagal" di PT JAB memakai filter `properties.status.errorCode != 0` dan setiap hari membawa ribuan hasil ke antrean. Apakah itu berarti tenant sedang diserang setiap hari?

<details><summary>Jawaban</summary>

Tidak. Dari 3.380 sign-in berkode selain 0 dalam contoh di catatan ini, 1.902 berkode `50140` dan 402 berkode `50158`, yaitu 2.304 atau sekitar 68 persen. Microsoft menyebut `50140` adalah interupsi "Keep me signed in" dan bagian normal alur sign-in, dan `50158` adalah pengalihan ke tantangan keamanan eksternal yang sendirinya tidak menandakan user gagal sign-in. Kode `50058` juga normal muncul saat user belum menyelesaikan sign-in, dan di kasus itu field user bisa berisi GUID. Alert yang berguna menyaring kode yang memang berarti kegagalan kredensial atau penolakan kebijakan, misalnya `50126`, `50034`, `50053`, dan keluarga `53000`. Lihat bagian 1.5 dan 2.6.

</details>

**6. Jelaskan ulang.** Jelaskan kepada analyst L1 yang baru masuk, dalam tiga kalimat, kenapa jejak `sudo` di `linux_secure` tidak cukup untuk menjawab "apa yang dilakukan penyerang setelah masuk", dan apa yang harus dicek sesudahnya.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "`sudo` mencatat satu baris per perintah yang diminta, dengan TTY, direktori kerja, akun tujuan, dan perintahnya, jadi selama penyerang menjalankan perintah satu per satu jejaknya lengkap. Masalahnya begitu dia menjalankan `sudo /bin/bash` atau `sudo su -`, semua aktivitas sesudahnya terjadi di dalam shell root dan tidak menulis baris `sudo` lagi, sehingga di kasus jkt-bastion01 hanya ada dua baris untuk 80 menit aktivitas. Setelah itu yang harus dicek adalah auditd di host yang sama, terutama record `PROCTITLE` dan `EXECVE`, dengan `auid` sebagai identitas pelaku; kalau auditd tidak aktif di host itu, tulis eksplisit di tiket bahwa periode itu tidak terpantau, bukan bahwa tidak ada aktivitas."

Kesalahan yang sering muncul:
- Menyimpulkan penyerang hanya menjalankan satu perintah karena hanya ada satu baris `sudo`.
- Lupa bahwa auditd juga bisa kosong: tanpa aturan yang relevan, event-nya tidak pernah ditulis, terutama untuk pembacaan file.
- Memakai `uid` sebagai identitas pelaku di auditd, padahal setelah `sudo` nilainya 0 untuk semua orang.
- Menulis "tidak ditemukan aktivitas lain" di tiket, padahal yang benar adalah "tidak ada data untuk periode itu di host itu".

</details>

**7. Interview question (English).** "You get an alert that a user mailbox has a new forwarding rule. Walk me through how you'd investigate it in Splunk."

<details><summary>Sample answer</summary>

"I'd start with the rule itself in the Office 365 management activity data: the operation, who created it, the client IP, and the destination, because the single most important question is whether the destination is inside or outside the tenant. The parameters don't come as separate fields, they come as two parallel multivalue arrays, so I'd locate the forwarding parameter by name and read the value at the same index, and I'd also check for the hiding parameters, delete, move to folder, and mark as read, since a rule that forwards and hides was built so the owner wouldn't notice. Then I'd pivot on the client IP into the sign-in logs, which live in a different sourcetype because they come through the Event Hub rather than the management API, and look at what happened just before the rule was created: how many failures, which error codes, which client app, and what the Conditional Access status was. If the client app is a legacy protocol like IMAP or POP and the Conditional Access status is notApplied, that tells me MFA never got a chance to apply, and that's both the root cause and the fix. Finally I'd check whether the same identity or IP did anything else, especially directory changes like adding a member to a privileged role, and I'd note explicitly in the ticket which sign-in categories the tenant actually sends, because non-interactive and service principal sign-ins are a separate category and their absence isn't evidence."

What makes this answer strong: it starts from the question that decides severity (inside or outside the tenant), shows awareness that the parameter arrays have to be read by index, knows the two sourcetypes come from two different ingest paths, reads notApplied correctly as a coverage gap rather than an approval, and ends by stating the limits of the available data instead of implying the investigation was complete.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Splunk Add-on for Unix and Linux: Source types | https://splunk.github.io/splunk-add-on-for-unix-and-linux/Sourcetypes/ | primer (Splunk) | add-on 10.3.4; diakses 2026-10-14 | Tinggi. Tabel sourcetype, script, dan pemetaan CIM untuk `linux_secure`, `linux_audit`, `auditd` |
| S2 | Splunkbase: Splunk Add-on for Unix and Linux | https://splunkbase.splunk.com/app/833 | primer | versi 10.3.4, 2026-09-01; diakses 2026-10-14 | Tinggi untuk versi dan kompatibilitas platform serta CIM 6.x |
| S3 | Splunk Security Content: Data Source Linux Secure | https://research.splunk.com/sources/9a47d88b-1b17-49ce-a0ef-b440ddbd98bb/ | primer (Splunk) | 2026-05-13, versi 3; diakses 2026-10-14 | Tinggi. Source `/var/log/secure`, sourcetype, 35 field, contoh baris sshd |
| S4 | Splunk Security Content: Data Source Linux Auditd Add User | https://research.splunk.com/sources/30f79353-e1d2-4585-8735-1e0359559f3f/ | primer (Splunk) | 2026-05-13, versi 3; diakses 2026-10-14 | Tinggi. Field auditd, `separator=type`, contoh `ADD_USER` dengan `uid` 0 dan `AUID` |
| S5 | Splunk Security Content: Detection Linux Auditd Add User Account | https://research.splunk.com/endpoint/aae66dc0-74b4-4807-b480-b35f8027abb4/ | primer (Splunk) | 2026-05-13, versi 10; diakses 2026-10-14 | Tinggi. Filter `proctitle`, syarat jenis event auditd yang perlu dikirim |
| S6 | Sudoers Manual (sudoers.man) | https://www.sudo.ws/docs/man/sudoers.man/ | primer | diakses 2026-10-14 | Tinggi. Urutan field log, pesan penolakan, `log_allowed`, `log_denied`, syslog bawaan |
| S7 | Splunkbase: Splunk Add-on for Microsoft Cloud Services | https://splunkbase.splunk.com/app/3110 | primer | versi 6.3.3, 2026-09-10; diakses 2026-10-14 | Tinggi untuk versi dan kompatibilitas CIM 5.x |
| S8 | Splunkbase: Splunk Add-on for Microsoft Office 365 | https://splunkbase.splunk.com/app/4055/ | primer | versi 6.1.1, 2026-09-30; diakses 2026-10-14 | Tinggi untuk versi dan kompatibilitas CIM 5.x |
| S9 | Microsoft Learn: Logs available for streaming from Microsoft Entra ID | https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-diagnostic-settings-logs-options | primer | diperbarui 2026-05-12; diakses 2026-10-14 | Tinggi. Daftar dan arti setiap kategori diagnostic settings |
| S10 | Microsoft Learn: Azure Monitor Logs reference, tabel SigninLogs | https://learn.microsoft.com/en-us/azure/azure-monitor/reference/tables/signinlogs | primer | 2026-08-27; diakses 2026-10-14 | Tinggi. Arti `ResultType`, `Status`, `ConditionalAccessStatus`, `Location`, `ClientAppUsed`, field risiko |
| S11 | Microsoft Learn: Microsoft Entra authentication and authorization error codes | https://learn.microsoft.com/en-us/entra/identity-platform/reference-error-codes | primer | diperbarui 2026-06-15; diakses 2026-10-14 | Tinggi. Deskripsi AADSTS yang dipakai di tabel bagian 1.5 |
| S12 | Microsoft Learn: How to troubleshoot sign-in errors | https://learn.microsoft.com/en-us/entra/identity/monitoring-health/howto-troubleshoot-sign-in-errors | primer | diperbarui 2026-02-26; diakses 2026-10-14 | Tinggi. Detail yang disimpan saat triage, `50058`, `500121`, `70046`, `90025` |
| S13 | Microsoft Learn: Troubleshooting sign-in problems with Conditional Access | https://learn.microsoft.com/en-us/entra/identity/conditional-access/troubleshoot-conditional-access | primer | diperbarui 2026-05-01; diakses 2026-10-14 | Tinggi. Tab Conditional Access, tabel kode 53000-53009, syarat kebijakan berlaku |
| S14 | Microsoft Learn: Learn about the monitoring and health activity log schemas | https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-activity-log-schemas | primer | diperbarui 2026-06-15; diakses 2026-10-14 | Tinggi. `appliedConditionalAccessPolicies` memuat kebijakan yang tidak diterapkan; field risiko dan `hidden` |
| S15 | Splunk Security Content: Detection Azure AD High Number Of Failed Authentications For User | https://research.splunk.com/cloud/630b1694-210a-48ee-a450-6f79e7679f2c/ | primer (Splunk) | 2026-05-13, versi 13; diakses 2026-10-14 | Tinggi. Macro `azure_monitor_aad`, pola `rename properties.* AS *`, `category=SignInLogs` |
| S16 | Splunk Security Content: Detection Azure AD Service Principal Authentication | https://research.splunk.com/cloud/5a2ec401-60bb-474e-b936-1e66e7aa4060/ | primer (Splunk) | 2026-05-13, versi 12; diakses 2026-10-14 | Tinggi. `category=ServicePrincipalSignInLogs` |
| S17 | Splunk Security Content: Detection O365 Email New Inbox Rule Created | https://research.splunk.com/cloud/449f525a-7b42-47be-96a7-d9724e336c19 | primer (Splunk) | 2026-05-13, versi 6; diakses 2026-10-14 | Tinggi. `Workload=Exchange`, parameter inbox rule, jadwal `-70m` sampai `-10m` |
| S18 | Splunk Security Content: Detection O365 New Email Forwarding Rule Created | https://research.splunk.com/cloud/68469fd0-1315-44ba-b7e4-e92847bb76d6 | primer (Splunk) | 2026-05-13, versi 10; diakses 2026-10-14 | Tinggi. Pola `mvfind` pada `Parameters{}.Name` untuk tiga parameter forwarding |
| S19 | Splunk Security Content: Detection O365 Privileged Role Assigned | https://research.splunk.com/cloud/db435700-4ddc-4c23-892e-49e7525d7d39 | primer (Splunk) | 2026-09-22, versi 12; diakses 2026-10-14 | Tinggi. Operasi role, `ObjectId`, `Actor{}.ID`, `ModifiedProperties{}`, false positive PIM |
| S20 | GitHub splunk/botsv2 | https://github.com/splunk/botsv2 | primer | 2017 (dataset); diakses 2026-10-14 | Tinggi. Daftar sourcetype memuat `linux_secure`, `linux_audit`, `auditd`; versi add-on pembuat; lisensi CC0 |
| S21 | Splunkbase: Splunk Common Information Model | https://splunkbase.splunk.com/app/1621 | primer | versi 8.7.0, 2026-09-02; diakses 2026-10-14 | Tinggi untuk versi app CIM |
| S22 | Splunk Community: "sourcetype linux secure fields not extracted" dan thread sourcetype `linux:audit` | https://community.splunk.com/t5/Splunk-Search/sourcetype-linux-secure-fields-not-extracted/td-p/148400 | komunitas | tanggal tidak tercatat (thread lama); diakses 2026-10-14 | Rendah-sedang. Sourcetype perlu ditetapkan eksplisit, `host` berisi nama relay syslog, nama sourcetype app auditd |
| S23 | Splunk Community: "Not getting Entra ID logs, Splunk Add-on for Microsoft Office 365" | https://community.splunk.com/t5/All-Apps-and-Add-ons/Not-getting-Entra-ID-logs-Splunk-Add-on-for-Microsoft-Office-365/td-p/752464 | komunitas | tanggal tidak tercatat; diakses 2026-10-14 | Sedang. Audit Entra masuk sebagai `source=audit_azureactivedirectory` di `o365:management:activity`, tanpa data sign-in |
| S24 | Splunk Docs: Microsoft Office 365 (Splunk Supported Add-ons) | https://help.splunk.com/en/data-management/integrate-data-with-add-ons/splunk-supported-add-ons/splunk-supported-add-ons/microsoft-office-365 | primer (Splunk) | tanggal tidak tercantum; diakses 2026-10-14 | Sedang-tinggi. API yang dipakai, cakupan audit AAD, SharePoint, Exchange, dan penggantian modular input di add-on Cloud Services |
| S25 | Red Hat Learn forum: Log Files | https://learn.redhat.com/t5/Platform-Linux/Log-Files/m-p/49598 | komunitas | tanggal tidak tercatat; diakses 2026-10-14 | Rendah-sedang. User baru, grup baru, dan perubahan grup dari `useradd` dicatat di `/var/log/secure` |

**Catatan sumber:** format persis baris `useradd` dan `groupadd` di `/var/log/secure` tidak terdokumentasi di sumber primer yang dibuka untuk Day ini; yang ada hanya keterangan bahwa informasi itu dicatat di file tersebut [S25], sehingga formatnya perlu dicatat sendiri dari lab (bagian 1.3). Pola baris `su` lewat PAM juga belum dikonfirmasi sumber primer dan berbeda antar distro. Nama field di dalam array `appliedConditionalAccessPolicies` setelah add-on memecah JSON (`displayName`, `result`) disimpulkan dari nama properti di skema Microsoft [S14] dan perlu dicek di data sendiri, karena cara pemecahan array menentukan nama akhirnya. Pengkodean heksadesimal nilai `proctitle` di auditd tidak disebut halaman detection Splunk yang dibuka [S5] dan ditulis di sini sebagai hal yang harus diperiksa di lab, bukan sebagai fakta terkonfirmasi. Daftar field `linux_secure` di [S3] adalah field yang muncul pada satu contoh event sshd, bukan jaminan semua field itu terisi untuk baris `sudo` atau `useradd`. Klaim bahwa `host` bisa berisi nama relay syslog dan bahwa sourcetype `linux_secure` sering tidak dikenali otomatis hanya bersumber dari forum komunitas [S22]; keduanya mudah diuji di lab.
