---
day: 12
title: 'Serangan AD bagian 2: DCSync, golden dan silver ticket, AD CS, jalur serangan, dan pemulihan AD'
researched_on: 2026-10-15
versions_checked: 'MITRE ATT&CK v20 (T1003.006 v1.1, T1558.001 v1.2, T1558.002 v1.1, diubah 24 Oktober 2025; T1649 v1.2, diubah 4 Agustus 2026); Microsoft Learn AD Forest Recovery, Reset the krbtgt password (ms.date 2025-05-21) dan Determine how to recover the forest (ms.date 2023-07-10); event 4662 (ms.date 2021-09-07), 4768 (ms.date 2021-10-20) dan 4769 (ms.date 2021-09-07) dengan pembaruan field Januari 2025; Securing PKI Appendix A (arsip, 2016); KB5014754 (diperbarui 10 September 2025); Microsoft Entra Connect Accounts and permissions (ms.date 2025-04-09) dan Prerequisites (ms.date 2026-01-16); CISA CM0050 (Maret 2025); CISA AA20-245A (revisi 24 September 2020); panduan bersama Detecting and mitigating Active Directory compromises (edisi September 2026); BloodHound CE docs (diakses 2026-10-15)'
---

# Day 12: Serangan AD bagian 2 (DCSync, golden dan silver ticket, AD CS, jalur serangan, dan pemulihan AD)

Cakupan: mengenali serangan yang mengambil alih domain (DCSync, golden dan silver ticket, penyalahgunaan AD CS), mendeteksinya dari log DC dan CA untuk scoping, menilai kapan domain harus dianggap dikuasai, memakai pemetaan jalur serangan untuk mengukur blast radius, lalu memilih antara eviction terkoordinasi dan pemulihan forest dari backup, termasuk keputusan waktu reset krbtgt.

## Ide inti

Day 11 membahas serangan yang mencuri kredensial satu akun. Day ini membahas titik ketika penyerang tidak lagi membutuhkan akun tertentu, karena ia sudah memegang rahasia yang dipakai domain untuk mempercayai siapa pun: hash semua akun lewat DCSync, kunci `krbtgt` yang bisa membuat tiket apa saja, atau sertifikat yang diterima DC sebagai bukti identitas akun berhak tinggi. Pada titik itu pertanyaan IR berubah. Bukan lagi "akun mana yang harus direset", tetapi "rahasia mana di domain ini yang masih bisa dipercaya", dan jawaban jujurnya sering "tidak ada sampai semua yang bisa dipalsukan diganti". Karena itu respons di Day ini selalu terdiri dari dua bagian yang tidak bisa dipisah: menutup jalan yang dipakai (template sertifikat, akun, host), lalu mengganti seluruh fondasi kepercayaan yang mungkin sudah disalin (krbtgt, akun Tier 0, akun sinkronisasi), dengan urutan dan waktu yang direncanakan.

Kamu sudah mengenal pola ini dari NOC. Bayangkan kunci TACACS server dan kunci master yang dipakai menandatangani konfigurasi semua router bocor. Mengganti password satu engineer tidak ada artinya, karena pemegang kunci master bisa membuat kredensial atau konfigurasi baru yang diterima perangkat mana pun. Yang harus dilakukan adalah mengganti kunci master di semua perangkat secara terencana, dengan risiko sebagian perangkat menolak sesi lama selama proses, lalu memastikan tidak ada salinan kunci lama yang masih diterima. Bedanya, di AD kunci master ada beberapa (krbtgt, CA, akun replikasi), dan semuanya bisa disalin tanpa jejak di perangkat yang memakainya.

```
akses awal ke satu host (staf helpdesk)
  |
  v
enumerasi AD: siapa bisa apa  ------>  jalur: template sertifikat salah konfigurasi
  |
  v
sertifikat atas nama admin  --> TGT sebagai admin (PKINIT, 4768 tipe 16)
  |
  v
DCSync dari host bukan DC (4662 dengan GUID replikasi)
  |
  +--> hash semua akun, termasuk krbtgt  --> golden ticket mungkin dibuat
  |
  v
domain dianggap dikuasai
  |
  +-- eviction terkoordinasi: tutup jalur, rotasi Tier 0, krbtgt dua kali, pantau
  +-- pemulihan forest dari backup: bila DC atau AD tidak bisa dipercaya lagi
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan domain AD `corp.jab.example` (NetBIOS `JAB`), dua DC (`JKT-DC01`, `JKT-DC02`), dan sinkronisasi ke Microsoft Entra ID lewat Entra Connect dengan password hash sync di server `JKT-SYNC01` (`10.20.2.45`). Log keamanan DC masuk ke Splunk index `wineventlog`. PT JAB memakai Defender for Endpoint Plan 2, tetapi lisensi Microsoft 365 E3-nya tidak mencakup Defender for Identity, sehingga deteksi serangan AD bertumpu pada log DC dan rule Splunk.

Insidennya `INC-2026-024`. Kamis 2026-11-12, staf IT Helpdesk Teguh Wibowo (`teguh.wibowo`, workstation `JKT-WS-0483`, `10.10.48.83`) memasang installer palsu alat remote support dari `anyremote-download.example.net`. Senin 2026-11-16 pukul 01:17, rule Splunk "Replikasi direktori dari akun bukan DC" yang baru aktif sejak 2026-11-02 memicu alert `SOC-2026-0250`: akun Domain Admin `adm.agung` (milik Agung Prabowo, Lead Infrastruktur) meminta replikasi direktori ke `JKT-DC01` dari `10.10.48.83`. Analyst L1 Gilang Ramadhan mengeskalasi ke L2 on-call Yoga Pratama pukul 01:24. Yoga mengonfirmasi bahwa Agung tidak pernah login dari workstation helpdesk dan bahwa TGT `adm.agung` pukul 01:14 diminta dengan sertifikat dari CA baru `JKT-CA01`, lalu menelepon IC Dimas Prasetyo. Dimas menyatakan SEV-1 pukul 02:05, memberi tahu Direktur Teknologi Hendra Wijaya, dan mengaktifkan retainer PT Forensik Digital Contoh. Yoga menjadi technical lead. Pukul 09:10, Hendra menulis di kanal `#inc-2026-024`:

> "Dim, update 08:00 sudah saya baca, tapi banyak yang saya tidak paham. Apa sebenarnya yang diambil lewat 'DCSync' itu, dan bagaimana kita tahu itu terjadi? Bagaimana akun staf helpdesk bisa jadi domain admin, sertifikat apa yang dimaksud? Retainer bilang golden ticket mungkin sudah dibuat dan password admin yang tadi pagi diganti tidak cukup, kenapa bisa? Infrastruktur bilang reset krbtgt dua kali bisa membuat banyak layanan error; kapan itu dilakukan? Apakah Microsoft 365 ikut kena karena AD disinkronkan ke cloud? Retainer juga bilang 'domain harus dianggap dikuasai' dan menyarankan membangun ulang AD dari backup. Seberapa luas sebenarnya akses penyerang, dan bagaimana kita memutuskan bangun ulang atau tidak?"

Pesan itu memuat tujuh pertanyaan:

1. Apa yang diambil lewat DCSync?
2. Bagaimana tahu DCSync terjadi?
3. Bagaimana akun helpdesk bisa menjadi domain admin lewat sertifikat?
4. Kenapa mengganti password admin tidak cukup, dan apa itu golden ticket?
5. Kapan dan bagaimana krbtgt direset?
6. Apakah Microsoft 365 dan Entra ID ikut terdampak?
7. Seberapa luas akses penyerang, dan kapan AD dibangun ulang dari backup?

Pertanyaan 1 dijawab di bagian 1.1, pertanyaan 2 di bagian 1.2, pertanyaan 3 di bagian 1.3, pertanyaan 4 di bagian 1.4, pertanyaan 5 di bagian 1.5, pertanyaan 6 di bagian 1.6, dan pertanyaan 7 di bagian 1.7. Bagian 2 berisi query deteksi, memo keputusan, rencana eviction, dan hasil pemetaan jalur serangan PT JAB.

**Kapan relevan:** setiap kali ada tanda akun Tier 0 dipakai dari tempat yang tidak wajar, replikasi direktori dari host yang bukan DC, sertifikat berhak tinggi yang diterbitkan tanpa permintaan sah, atau tiket Kerberos yang tidak cocok dengan pola; juga saat menyiapkan rule deteksi AD dan prosedur pemulihan AD sebelum insiden.
**Kapan bukan jawaban:** Day ini tidak membahas pencurian kredensial satu akun lewat Kerberoasting, AS-REP roasting, pass-the-hash, dan pass-the-ticket (Day 11), juga tidak membahas ransomware yang menyebar lewat GPO setelah domain dikuasai (Day 14). Day ini juga bukan panduan pemulihan forest langkah demi langkah; prosedur itu panjang, spesifik lingkungan, dan harus dilatih sebelum dibutuhkan.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (containment, eradication, scoping, blast radius, krbtgt, golden ticket, reset dua kali, tiket Kerberos yang tetap berlaku, revoke sessions) tidak diulang. Tabel berikut memuat istilah baru Day ini. Kolom padanan memakai analogi NOC dan SOC yang sama di semua Day IR.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| DCSync | Meniru DC untuk meminta data replikasi, termasuk hash password, dari DC asli | Menyamar sebagai router peer untuk menerima seluruh tabel routing dan kunci sesi |
| Hak replikasi | Hak `Replicating Directory Changes` dan `Replicating Directory Changes All` pada objek domain | Izin menarik seluruh konfigurasi dari perangkat inti, bukan hanya membaca status |
| Silver ticket | Tiket layanan palsu yang dibuat dengan hash akun layanan, tanpa menghubungi DC | Kartu akses palsu untuk satu ruangan, dibuat dengan kunci ruangan itu sendiri |
| AD CS | Layanan CA Microsoft yang menerbitkan sertifikat untuk pengguna dan perangkat domain | PKI internal yang menerbitkan sertifikat perangkat dan pengguna |
| Template sertifikat | Aturan di AD CS: siapa boleh meminta, untuk apa sertifikat dipakai, dan siapa yang menentukan identitas di dalamnya | Template konfigurasi provisioning perangkat |
| SAN (subject alternative name) | Identitas alternatif di sertifikat yang bisa dipakai DC untuk memetakan sertifikat ke akun | Field identitas tambahan di kartu akses |
| PKINIT | Meminta TGT Kerberos dengan sertifikat, bukan password | Login perangkat dengan sertifikat, bukan password |
| Golden certificate | Sertifikat palsu yang dibuat dengan private key CA curian | Kunci master pencetak kartu akses dicuri |
| Tier 0 (Control Plane) | Akun, grup, dan server yang mengendalikan identitas seluruh domain: DC, CA, Entra Connect, akun admin domain | Perangkat dan akun yang mengendalikan seluruh jaringan inti |
| Jalur serangan (attack path) | Rangkaian hak dan hubungan yang memungkinkan akun biasa mencapai Tier 0 | Rantai akses dari port pelanggan sampai router inti |
| Eviction | Mengusir penyerang dari domain yang tetap berjalan: menutup jalur dan mengganti semua rahasia yang mungkin disalin | Mengganti semua kunci dan menutup celah tanpa mematikan jaringan |
| Pemulihan forest | Memulihkan AD dari backup yang dipercaya, biasanya dalam isolasi, lalu membangun ulang DC | Membangun ulang seluruh core dari konfigurasi yang diketahui bersih |

### 1.1 DCSync: penyerang mengambil buku kunci, bukan satu kunci

Pertanyaan pertama Hendra ("apa yang diambil?") perlu dijawab dengan cara kerja replikasi AD, karena itulah yang disalahgunakan.

DC saling bertukar perubahan direktori lewat protokol replikasi (MS-DRSR, antarmuka DRSUAPI). DCSync adalah teknik meniru proses replikasi itu dari host yang bukan DC, sehingga DC asli mengirim data password dari AD, termasuk hash saat ini dan riwayat hash untuk akun seperti KRBTGT dan Administrator [S1]. Hash itu bisa dipakai untuk membuat golden ticket atau mengganti password akun [S1]. ATT&CK mencatat teknik ini sebagai T1003.006 [S1].

DCSync tidak butuh kode di DC. Yang dibutuhkan hanya akun yang memegang hak replikasi. Secara default hak itu dimiliki anggota Administrators, Domain Admins, Enterprise Admins, dan akun komputer DC [S1]. Dua hak yang menentukan adalah `Replicating Directory Changes` (GUID `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2`) dan `Replicating Directory Changes All` (GUID `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`); yang kedua mengizinkan replikasi data rahasia domain [S6][S7].

Ada satu pemegang hak replikasi yang sering terlupa: akun konektor AD DS milik Entra Connect. Untuk password hash sync, akun itu diberi kedua hak replikasi tersebut [S12]. Pada instalasi express, akun ini dibuat dengan awalan `MSOL_`, password panjang yang tidak kedaluwarsa [S12]. Artinya replikasi dari server Entra Connect adalah perilaku normal, dan sekaligus menjadikan akun dan server itu sasaran bernilai tinggi.

Jadi jawaban untuk Hendra: penyerang kemungkinan besar sudah memegang hash semua akun domain, termasuk `krbtgt`, akun admin, akun layanan, dan akun komputer. Ia tidak perlu menebak password siapa pun lagi. Itu sebabnya retainer menyebut domain "harus dianggap dikuasai" (bagian 1.7).

### 1.2 Mendeteksi DCSync: replikasi dari host yang bukan DC

Pertanyaan kedua Hendra ("bagaimana kita tahu?") dijawab dengan log DC, karena DCSync meninggalkan jejak di DC yang dimintai data, bukan di host penyerang.

**Event 4662.** Event "An operation was performed on an object" dibuat di DC setiap kali operasi dilakukan pada objek AD, hanya bila subkategori Audit Directory Service Access aktif dan SACL objek itu mencakup operasi tersebut [S5]. Field yang dipakai [S5]:

- `Account Name` dan `Logon ID` peminta operasi. Logon ID bisa dikorelasikan dengan event 4624 yang memuat Logon ID yang sama.
- `Object Type`; untuk objek domain nilainya kelas `domainDNS`, yang memang direkomendasikan untuk dipantau.
- `Accesses` dan `Access Mask`; hak tambahan (extended right) tercatat sebagai `Control Access` dengan mask `0x100`.
- `Properties`, berisi GUID hak atau properti yang dipakai. GUID replikasi dari bagian 1.1 muncul di field ini.

**Logika deteksi.** Permintaan replikasi yang sah datang dari akun komputer DC dan dari akun konektor Entra Connect di server sinkronisasi. Semua 4662 dengan GUID replikasi dari akun lain adalah kandidat DCSync. Karena 4662 tidak memuat IP sumber, Logon ID-nya dikorelasikan dengan 4624 logon type 3 di DC yang sama untuk mendapatkan IP host peminta [S5]. Deteksi ATT&CK untuk teknik ini juga berfokus pada penyalahgunaan API replikasi dari endpoint yang bukan DC [S1].

Tiga hal yang membuat deteksi ini gagal tanpa disadari:

- **Audit tidak aktif.** Tanpa Audit Directory Service Access dan SACL yang tepat di objek domain, 4662 tidak pernah dibuat [S5]. Cek konfigurasi ini di lab dan di DC produksi sebelum mengandalkan rule apa pun.
- **Pengecualian terlalu lebar.** Mengecualikan akun `MSOL_` di semua host berarti DCSync memakai akun itu dari host lain tidak terlihat. Pengecualian yang benar adalah pasangan akun dan host sumber: akun `MSOL_` hanya wajar dari IP server Entra Connect.
- **Volume.** 4662 sangat banyak bila SACL lebar. Rule menyaring di field `Properties` untuk dua GUID replikasi, bukan menarik semua 4662.

Ini cara deteksi yang dijanjikan di Day 06 bagian 1.4. Di `INC-2026-024`, rule itu yang memicu `SOC-2026-0250`; query lengkap dan keluarannya ada di bagian 2.1.

### 1.3 AD CS: dari staf helpdesk ke domain admin lewat template sertifikat

Pertanyaan ketiga Hendra menyentuh bagian AD yang paling jarang diaudit di organisasi menengah: CA internal.

**Kenapa sertifikat bisa menjadi kredensial.** Sertifikat diikat ke identitas, sehingga bisa dipakai sebagai kredensial akun [S4]. Pengguna dan mesin dengan hak enrollment bisa meminta sertifikat dari enterprise CA; nilai EKU menentukan apakah sertifikat boleh dipakai untuk autentikasi, dan nilai SAN menentukan identitas alternatif pemiliknya [S4]. Template yang salah konfigurasi bisa membiarkan pengguna menyamar sebagai akun berhak tinggi lewat nilai SAN [S4].

**Template yang salah konfigurasi.** Riset SpecterOps "Certified Pre-Owned" (2021) mengelompokkan kesalahan konfigurasi AD CS. Kelompok yang dikenal sebagai ESC1 terjadi bila semua kondisi berikut terpenuhi sekaligus [S17]:

- enterprise CA memberi hak enrollment ke pengguna berhak rendah, dan security descriptor template juga memberi hak enrollment ke mereka;
- persetujuan manajer (manager approval) tidak aktif, dan tidak ada tanda tangan yang diwajibkan;
- EKU template mengizinkan autentikasi (misalnya Client Authentication, Smart Card Logon, Any Purpose, atau tanpa EKU);
- template mengizinkan peminta mengisi SAN sendiri (opsi "Supply in the request").

Di PT JAB, CA enterprise `JKT-CA01` (`10.20.2.40`) baru dipasang 2026-10-20 untuk proyek Wi-Fi 802.1X kantor. Vendor menduplikasi template User menjadi `JAB-WiFi-User`, memberi hak enrollment ke Domain Users, dan mengaktifkan "Supply in the request" supaya nama perangkat bisa dimasukkan. Keempat kondisi terpenuhi.

**Jejak di log.** Ada dua tempat:

- **CA.** Event 4886 (permintaan diterima, dengan Request ID, peminta, dan atribut) dan 4887 (permintaan disetujui dan sertifikat diterbitkan, dengan subject dan SKI) [S10]. Keduanya hanya dibuat bila audit filter CA untuk "Issue and manage certificate requests" aktif [S10]. Microsoft menyarankan penerbitan sertifikat untuk pengguna penting dipantau [S10]. Event 4898 dan 4899 mencatat template yang dimuat atau diubah, dan 4885 mencatat perubahan audit filter itu sendiri [S10].
- **DC.** Event 4768 (TGT diminta) mencatat `Pre-Authentication Type`; nilai 15, 16, atau 17 adalah autentikasi sertifikat, dan field `Certificate Issuer Name`, `Certificate Serial Number`, `Certificate Thumbprint` terisi [S8]. Microsoft menyarankan memantau `Pre-Authentication Type` yang tidak sesuai kebiasaan, misalnya bukan 2 di organisasi yang hanya memakai password [S8].

Di `INC-2026-024`, audit filter `JKT-CA01` belum diaktifkan sejak pemasangan, sehingga 4886 dan 4887 tidak ada. Bukti penerbitan diambil dari database CA itu sendiri (bagian 2.2), dan jejak pemakaiannya dari 4768 di DC: TGT `adm.agung` pukul 01:14:05 dengan tipe pre-authentication 16, issuer `corp-JKT-CA01-CA`, dari `10.10.48.83`.

**Sertifikat bertahan setelah reset password.** Sertifikat curian atau palsu bisa dipakai selama masa berlakunya, bahkan setelah password direset [S4]. SpecterOps menegaskan bahwa reset password akun yang terkompromi atau reimage mesinnya tidak cukup; sertifikat yang terkait harus diidentifikasi dan dibatalkan [S17]. Untuk sertifikat yang memang diterbitkan CA, pembatalannya dengan revoke dan publikasi CRL; DC mencatat kegagalan logon dengan sertifikat yang dicabut sebagai kode `0x3E` di 4768 [S8].

**Golden certificate.** Bila private key CA dicuri, penyerang bisa membuat sertifikat untuk pengguna mana pun, sertifikat itu berlaku selama sertifikat CA berlaku, dan tidak bisa dicabut karena CA tidak pernah menerbitkannya [S17]. Dalam keadaan itu SpecterOps menyebut seluruh AD CS kemungkinan harus dibangun ulang [S17]. Karena itu pertanyaan scoping pertama untuk CA adalah apakah ada tanda akses ke private key CA, bukan hanya sertifikat mana yang diterbitkan.

**Pemetaan sertifikat yang lebih ketat.** Pembaruan Windows sejak Mei 2022 (KB5014754) menambahkan ekstensi SID ke sertifikat dari enterprise CA dan memperketat cara DC memetakan sertifikat ke akun; DC masuk mode Full Enforcement dengan pembaruan Februari 2025, dan opsi kembali ke mode kompatibilitas berakhir dengan pembaruan September 2025 [S11]. DC mencatat event 39, 40, dan 41 di log System bila pemetaan gagal atau SID tidak cocok [S11]. Catatan ini tidak menilai varian penyalahgunaan template mana yang tertutup oleh enforcement; template yang salah konfigurasi tetap diperlakukan sebagai celah yang harus diperbaiki.

### 1.4 Golden ticket dan silver ticket: kenapa ganti password admin tidak cukup

Pertanyaan keempat Hendra punya jawaban yang sudah disinggung di Day 05 bagian 1.5 (tiket yang sudah terbit tetap berlaku) dan Day 06 bagian 1.4 (krbtgt). Di Day ini yang ditambahkan adalah bentuk tiket palsu dan cara mencarinya.

**Golden ticket.** Penyerang yang memegang hash KRBTGT bisa memalsukan TGT untuk akun mana pun di AD [S2]. Dengan TGT palsu itu ia meminta tiket layanan (TGS) ke DC; langkah ini tetap melewati KDC di DC [S2]. Karena TGT dibuat sendiri, ganti password akun admin tidak berpengaruh: TGT palsu tidak bergantung pada password akun yang disamar.

**Silver ticket.** Penyerang yang memegang hash akun layanan (misalnya akun yang menjalankan SQL atau file share) bisa memalsukan tiket layanan untuk layanan itu saja, tanpa menghubungi KDC [S3]. Cakupannya sempit, tetapi deteksinya lebih sulit karena tidak ada jejak di DC [S3]. Setelah DCSync, hash akun komputer dan akun layanan ikut tersalin, sehingga silver ticket ke server mana pun mungkin.

**Mencari tanda pemakaian.** Tanpa sensor khusus identitas, PT JAB hanya punya log DC dan log host. ATT&CK menyarankan beberapa analitik [S2][S3]:

- TGS yang diminta tanpa TGT sebelumnya untuk akun dan sumber yang sama (golden ticket);
- umur tiket dan jenis enkripsi yang tidak wajar, misalnya RC4 di domain yang biasanya memakai AES (golden ticket);
- field yang tidak wajar di event logon (golden dan silver ticket);
- logon ke layanan di host target tanpa interaksi KDC yang sepadan, dan akses akun layanan di luar cakupan biasanya (silver ticket).

Event 4769 di DC memuat `Ticket Encryption Type`, `Client Address`, dan `Logon GUID` yang bisa dikorelasikan dengan 4624 di host target [S9]. Microsoft menyarankan memantau jenis enkripsi selain `0x11` dan `0x12` (keluarga AES) [S9]. Sejak pembaruan kumulatif 14 Januari 2025, Windows Server 2016 ke atas menampilkan versi baru 4768 dan 4769 dengan field tambahan seperti kunci yang tersedia untuk akun dan hash tiket [S8][S9].

Batas yang harus ditulis jujur di scope statement: analitik ini heuristik. Tidak menemukan apa pun bukan bukti golden ticket tidak dibuat, terutama bila penyerang belum memakainya. Karena itu keputusan reset krbtgt didasarkan pada fakta bahwa hash krbtgt mungkin sudah tersalin, bukan pada ditemukannya tiket palsu.

### 1.5 Reset krbtgt saat kompromi aktif: dua kali, kapan reset kedua?

Pertanyaan kelima Hendra adalah keputusan dengan trade-off nyata. Prinsip reset dua kali, dampaknya, dan cakupan akun RODC sudah ada di Day 06 bagian 1.4; di sini fokusnya pada waktu reset kedua saat penyerang mungkin sedang memakai golden ticket.

**Kenapa waktunya penting.** Riwayat password krbtgt berisi dua password terakhir [S13]. Setelah reset pertama, kunci lama masih ada di riwayat, sehingga tiket yang dibuat dengan kunci lama belum tentu langsung tertolak. Reset kedua menghapus kunci lama dari riwayat [S13]. Selama jeda di antara keduanya, penyerang yang memegang kunci lama mungkin masih bisa memakainya.

**Yang ditulis sumber primer.** Panduan pemulihan forest Microsoft meminta reset dilakukan dua kali dengan jeda 10 jam, sesuai default Maximum lifetime for user ticket dan service ticket, dan lebih lama bila nilai itu diubah [S13]. CISA CM0050 meminta reset pertama tereplikasi sebelum reset kedua, menunggu minimal 10 jam, dan memeriksa kesehatan replikasi lebih dulu; CM0050 tidak membahas reset beruntun saat kompromi aktif [S15]. AA20-245A meminta reset pertama tereplikasi sebelum reset kedua tanpa menyebut lama jedanya [S16]. ATT&CK menulis langkah yang sama untuk menahan golden ticket: ubah sekali, paksa replikasi, lalu ubah lagi [S2].

**Pendapat lain.** Teks STIG Windows Server dari DISA, yang terbaca lewat mirror pihak ketiga, menyebut perubahan dua kali secara cepat memaksa klien, termasuk layanan aplikasi, untuk autentikasi ulang, dan hal itu diinginkan bila ada dugaan kompromi [S22]. Panduan praktisi FRSecure mendeskripsikan cara cepat itu sebagai metode darurat, tetapi menolak merekomendasikannya dalam keadaan apa pun karena risiko kerusakan tambahan, pemulihan yang lebih lama, dan hilangnya bukti forensik saat server harus di-restart [S23]. [komunitas] Pendapat praktisi ini belum dikonfirmasi sumber primer, tetapi konsisten dengan dampak yang ditulis CM0050 [S15].

**Cara PT JAB memutuskan.** Dari sumber-sumber itu, PT JAB memakai jalur standar sebagai default dan jalur cepat sebagai pemicu tertulis:

| | Jalur standar (default) | Jalur cepat (hanya dengan pemicu) |
|---|---|---|
| Dasar | Microsoft [S13], CM0050 [S15], AA20-245A [S16] | STIG DISA [S22]; ditolak praktisi [S23] |
| Jeda | Replikasi terverifikasi, lalu minimal 10 jam | Segera setelah replikasi reset pertama terverifikasi |
| Harga | Kunci lama mungkin masih berguna bagi penyerang sampai reset kedua | Semua tiket gugur sekaligus; layanan yang bergantung pada AD perlu autentikasi ulang atau restart |
| Kompensasi | Host penyerang terisolasi, jalur masuk ditutup, akun Tier 0 dirotasi, pemantauan 4769 ketat | Jendela pemeliharaan, daftar layanan yang harus di-restart, tim aplikasi siaga |
| Pemicu | Tidak ada tanda pemakaian tiket palsu | Ada tanda pemakaian tiket palsu atau akun Tier 0 dipakai dari host tak dikenal setelah reset pertama |

Di kedua jalur, reset pertama dilakukan setelah scope cukup dan jalur masuk ditutup. Reset yang terlalu dini, sementara penyerang masih memegang akses lain, adalah kesalahan umum yang disebut AA20-245A: penyerang bisa memakai kredensial lain, membuat yang baru, atau memalsukan tiket lagi [S16].

**Rahasia lain di AD.** Panduan pemulihan forest Microsoft menambahkan: bila database AD di DC writable terkompromi, KDS root key baru perlu dibuat setelah pemulihan dan semua gMSA dibuat ulang, tergantung skenarionya [S14]. DCSync membaca data dari database itu, jadi pertanyaan ini masuk ke rencana eviction, bukan ditunda.

### 1.6 Entra ID dan Microsoft 365: jembatan sinkronisasi

Pertanyaan keenam Hendra ("apakah Microsoft 365 ikut kena?") dijawab dengan melihat apa yang menghubungkan AD ke cloud di PT JAB.

Entra Connect memakai tiga akun: akun konektor AD DS untuk membaca dan menulis AD, akun layanan ADSync untuk menjalankan layanan sinkronisasi, dan akun konektor Microsoft Entra untuk menulis ke Entra ID; akun terakhir memegang role khusus Directory Synchronization Accounts [S12]. Microsoft meminta server Entra Connect diperlakukan sebagai komponen Tier 0 dan dikeraskan sebagai aset Control Plane [S21]. Alasannya ditulis langsung: penyerang yang menguasai server Entra Connect bisa memanipulasi pengguna di Entra ID, misalnya me-reset password pengguna; MFA untuk semua akun berhak tinggi mencegah reset itu berujung pada pengambilalihan akun [S21]. Microsoft juga menyarankan mematikan soft matching dan hard match takeover bila tidak dipakai, karena keduanya bisa dipakai untuk mengambil alih objek cloud [S21]. Panduan bersama lima negara tentang kompromi AD memasukkan penyalahgunaan Entra Connect sebagai salah satu teknik yang dibahas [S20].

Jadi jawabannya bertingkat:

- **Domain admin AD tidak otomatis admin Entra ID.** Akun cloud berhak tinggi di PT JAB adalah akun cloud terpisah dengan MFA, bukan akun AD yang disinkronkan.
- **Server dan akun Entra Connect masuk scope.** Domain admin bisa login ke `JKT-SYNC01`. Pertanyaan scoping: apakah ada logon tak wajar ke `JKT-SYNC01` dan apakah ada perubahan objek Entra ID yang diinisiasi akun sinkronisasi di luar siklus biasa. Pemeriksaan sign-in dan audit log Entra memakai langkah Day 10 bagian 2.1 dan 2.3.
- **Rotasi masuk rencana eviction.** Password akun konektor AD DS dirotasi, dan kredensial akun konektor Microsoft Entra ditangani sesuai panduan Microsoft untuk versi Entra Connect yang dipakai; cek prosedurnya di dokumentasi versi-mu sebelum jam H, karena metode autentikasinya sedang berubah (bagian 6).

### 1.7 Seberapa luas, dan kapan membangun ulang: jalur serangan dan keputusan pemulihan

Pertanyaan terakhir Hendra menggabungkan scoping dan keputusan terbesar di insiden AD.

**Memetakan jalur, bukan hanya jejak.** Jejak log menunjukkan jalur yang sudah dipakai. Penyerang yang masih punya akses akan memakai jalur lain bila jalur pertama ditutup, jadi defender perlu peta semua jalur dari akun biasa ke Tier 0. BloodHound memakai teori graf untuk menunjukkan hubungan tersembunyi dan sering tidak disengaja di AD dan Entra ID; edisi Community dipakai tim uji penetrasi, dan defender memakainya untuk memahami hubungan berhak di lingkungannya [S18]. Collector resminya, SharpHound CE, mengambil keanggotaan grup, trust, hak yang bisa disalahgunakan pada objek AD, link GPO, struktur OU dari DC, serta anggota grup admin lokal dan sesi aktif dari komputer domain [S19]. Dua catatan untuk IR:

- Penyerang memakai jenis enumerasi yang sama. Di `INC-2026-024`, telemetri EDR `JKT-WS-0483` menunjukkan proses installer palsu berulang kali terhubung ke port LDAP kedua DC pada Jumat 2026-11-13 22:05 sampai 22:19 dan menulis arsip zip berisi file JSON di folder Temp. Pemetaan oleh defender menunjukkan apa yang kemungkinan dilihat penyerang malam itu.
- Pemetaan oleh defender dilakukan dari host admin yang tidak termasuk scope, dicatat di case notes, dan diberi tahu ke SOC supaya tidak memicu eskalasi palsu.

**Kapan domain dianggap dikuasai.** PT JAB memakai aturan tertulis: domain dianggap dikuasai bila salah satu terbukti, yaitu DCSync berhasil, akses ke DC atau `ntds.dit`, private key CA kemungkinan dicuri, atau akun Tier 0 dipakai penyerang dengan hak penuh. Konsekuensinya bukan otomatis bangun ulang, tetapi semua rahasia Tier 0 diperlakukan sebagai terpapar dan keputusan eviction atau pemulihan harus dibuat eksplisit.

**Eviction atau pemulihan forest.** Pemulihan forest berarti memulihkan minimal satu DC per domain dari backup dan mengembalikan domain ke keadaan backup terakhir yang dipercaya, dengan kehilangan semua objek dan perubahan setelah backup itu [S14]. Microsoft menyarankan backup yang diambil beberapa hari sebelum kejadian, dengan trade-off: backup yang lebih baru menyelamatkan lebih banyak data tetapi menaikkan risiko membawa kembali data berbahaya; bila waktu kejadian tidak diketahui, investigasi lanjutan dibutuhkan untuk menemukan backup yang menyimpan keadaan aman terakhir [S14]. Pemulihan sebaiknya dilakukan dalam isolasi, dengan semua DC writable dimatikan sebelum DC yang dipulihkan kembali ke produksi [S14].

PT JAB memakai kriteria berikut untuk memilih:

| Kondisi | Eviction terkoordinasi cukup | Pemulihan forest dipertimbangkan |
|---|---|---|
| Waktu dan jalur masuk ke Tier 0 | Diketahui dengan keyakinan tinggi | Tidak diketahui; backup aman terakhir tidak bisa ditentukan |
| Perubahan di AD oleh penyerang | Bisa didaftar dan dibalik (akun, grup, ACL, GPO, template) | Tidak bisa didaftar lengkap, atau skema dan konfigurasi diubah |
| DC | Tidak ada tanda kode penyerang di DC | Ada tanda kode, persistence, atau perubahan sistem di DC |
| CA | Hanya sertifikat yang diterbitkan disalahgunakan | Private key CA mungkin dicuri: AD CS juga harus dibangun ulang [S17] |
| Kesiapan | Prosedur rotasi Tier 0 dan krbtgt sudah dipahami tim | Prosedur pemulihan forest sudah pernah dilatih, password DSRM dan backup tersedia [S14] |

Di `INC-2026-024`, jalur masuk ke Tier 0 diketahui (template `JAB-WiFi-User`), waktu kompromi Tier 0 diketahui (Senin 01:12), akses penyerang ke Tier 0 berlangsung sekitar satu jam sebelum host-nya diisolasi, dan retainer belum menemukan tanda kode di DC atau akses ke private key CA. Memo keputusan di bagian 2.4 memilih eviction terkoordinasi dengan pemicu yang mengubahnya menjadi pemulihan forest.

## 2. Contoh artefak dan langkah praktis di PT JAB

Semua isi bagian ini fiktif dan merupakan keluaran ilustrasi. Query Splunk memakai nama field dari event XML Windows (`SubjectUserName`, `SubjectLogonId`, `TargetLogonId`, `IpAddress`, `PreAuthType`); add-on Windows di Splunk bisa memakai nama lain, jadi cocokkan dengan data di lingkunganmu.

### 2.1 Query: replikasi direktori dari akun bukan DC

Query ini adalah rule yang memicu `SOC-2026-0250` dan menjawab pertanyaan kedua Hendra. Saat insiden, rentangnya dilebarkan untuk mencari pemakaian lain sebelum alert.

**Tujuan:** menemukan setiap sesi yang meminta hak replikasi ke DC, beserta akun dan IP sumbernya, lalu menyisakan yang tidak cocok dengan daftar sumber sah.

```
index=wineventlog host IN ("JKT-DC01","JKT-DC02")
  ((EventCode=4662 (Properties="*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*" OR Properties="*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*"))
   OR (EventCode=4624 LogonType=3))
  earliest="11/09/2026:00:00:00" latest="11/16/2026:09:00:00"
| eval logon_id=if(EventCode=4662, SubjectLogonId, TargetLogonId)
| eval account=if(EventCode=4662, SubjectUserName, null())
| eval src_ip=if(EventCode=4624, replace(IpAddress, "^::ffff:", ""), null())
| stats values(account) as account values(src_ip) as src_ip count(eval(EventCode=4662)) as repl min(_time) as first max(_time) as last by host logon_id
| where repl > 0
| stats count as sessions sum(repl) as repl min(first) as first max(last) as last by account src_ip host
| where NOT match(account, "^JKT-DC0[12]\$$")
| lookup jab_replikasi_sah.csv account src_ip OUTPUT keterangan
| eval status=if(isnull(keterangan), "TIDAK DIKENAL", keterangan)
| convert ctime(first) ctime(last)
```

Penjelasan tiap bagian:

- Baris pertama sampai ketiga mengambil 4662 dengan salah satu GUID replikasi [S6][S7] dan 4624 logon type 3 di kedua DC. Logon type 3 dipakai karena permintaan replikasi datang lewat jaringan.
- `logon_id` menyatukan `SubjectLogonId` dari 4662 dengan `TargetLogonId` dari 4624, karena Logon ID adalah penghubung kedua event [S5].
- `stats` pertama per DC dan Logon ID menggabungkan akun (dari 4662) dengan IP (dari 4624). `where repl > 0` membuang sesi jaringan yang tidak meminta replikasi.
- `stats` kedua meringkas per akun, IP, dan DC.
- Akun komputer DC dibuang dengan regex, sedangkan pengecualian lain lewat lookup `jab_replikasi_sah.csv` yang berisi pasangan akun dan IP (misalnya akun konektor Entra Connect dengan IP `JKT-SYNC01`), bukan akun saja (bagian 1.2).

Keluaran ilustrasi:

```
account              src_ip        host      sessions  repl  first                 last                  status
MSOL_7c1e2a9b4d3f    10.20.2.45    JKT-DC01      1734  3468  11/09/2026 00:01:12   11/16/2026 08:59:40   Entra Connect JKT-SYNC01
MSOL_7c1e2a9b4d3f    10.20.2.45    JKT-DC02       286   572  11/09/2026 03:15:02   11/16/2026 07:44:19   Entra Connect JKT-SYNC01
adm.agung            10.10.48.83   JKT-DC01         1     2  11/16/2026 01:16:30   11/16/2026 01:16:31   TIDAK DIKENAL
```

Cara membaca hasil:

- Dua baris `MSOL_` berasal dari IP server sinkronisasi dan cocok dengan lookup. Setiap sesi menghasilkan dua 4662 karena kedua GUID muncul (`repl` sama dengan dua kali `sessions`: 1734 kali 2 adalah 3468, 286 kali 2 adalah 572). Polanya rutin sepanjang minggu.
- Baris `adm.agung` adalah satu sesi dari workstation helpdesk dengan dua 4662, pukul 01:16:30 dan 01:16:31. Tidak ada sesi lain sebelum Senin, sehingga DCSync ini yang pertama dalam rentang tujuh hari yang diperiksa.
- Tidak ada baris `MSOL_` dari IP selain `10.20.2.45`. Kalau ada, akun konektor sudah disalahgunakan dan scope bertambah.

**Variasi:** ganti `earliest` ke 90 hari untuk hunting retrospektif, atau tambahkan `| where status="TIDAK DIKENAL"` untuk dijadikan rule terjadwal tiap 5 menit.

**Kapan gagal:** audit Directory Service Access atau SACL objek domain tidak aktif, sehingga 4662 tidak pernah ada [S5]; logon tidak tercatat sebagai 4624 di DC yang sama (misalnya log DC kedua tidak masuk Splunk); atau penyerang memakai host yang memang ada di lookup, misalnya menguasai `JKT-SYNC01` sendiri.

### 2.2 Dari mana sertifikat itu datang: 4768 dan database CA

Langkah ini menjawab pertanyaan ketiga Hendra dengan dua sumber, karena audit CA tidak aktif.

**Tujuan pertama:** menemukan setiap TGT akun Tier 0 yang diminta dengan sertifikat.

```
index=wineventlog host IN ("JKT-DC01","JKT-DC02") EventCode=4768 PreAuthType IN (15,16,17)
  earliest="10/20/2026:00:00:00" latest="11/16/2026:09:00:00"
| lookup jab_tier0_accounts.csv account AS TargetUserName OUTPUT tier
| where tier="0"
| eval src_ip=replace(IpAddress, "^::ffff:", "")
| table _time host TargetUserName src_ip PreAuthType Status CertIssuerName CertSerialNumber
```

Penjelasan: `PreAuthType` 15, 16, dan 17 adalah tipe pre-authentication untuk autentikasi sertifikat [S8]. Lookup `jab_tier0_accounts.csv` berisi akun anggota Domain Admins, Enterprise Admins, Administrator bawaan, dan akun konektor Entra Connect. Rentang dimulai sejak `JKT-CA01` dipasang.

Keluaran ilustrasi:

```
_time                 host      TargetUserName  src_ip        PreAuthType  Status  CertIssuerName     CertSerialNumber
11/16/2026 01:14:05   JKT-DC01  adm.agung       10.10.48.83   16           0x0     corp-JKT-CA01-CA   6100000187b2e4c1a9f03d5e0000000000bb
11/16/2026 03:02:47   JKT-DC02  adm.agung       10.10.48.83   16           0x3E    corp-JKT-CA01-CA   6100000187b2e4c1a9f03d5e0000000000bb
```

Cara membaca hasil: tidak satu pun akun Tier 0 PT JAB memakai smart card atau sertifikat untuk logon, jadi baris apa pun di sini adalah anomali. Baris pertama adalah TGT yang dipakai untuk DCSync dua menit kemudian. Baris kedua menunjukkan percobaan ulang dengan sertifikat yang sama dari host yang sama pukul 03:02:47, ditolak dengan `0x3E`, kode yang menandai logon dengan sertifikat yang dicabut [S8]. Percobaan itu datang setelah isolasi `JKT-WS-0483` pukul 02:20, sehingga Yoga memeriksa ulang status isolasi dan menemukan aplikasi installer palsu memakai jalur yang masih diizinkan oleh isolasi selektif; isolasi diubah menjadi penuh pukul 03:10.

**Tujuan kedua:** melihat semua sertifikat yang diterbitkan `JKT-CA01` sejak dipasang, dari database CA.

```
certutil -view -restrict "RequestID>=1" -out "RequestID,RequesterName,CommonName,CertificateTemplate,NotBefore,NotAfter,SerialNumber" csv > jkt-ca01-issued.csv
```

Perintah dijalankan Yoga di `JKT-CA01` dengan akun admin CA, dan hasilnya disimpan sebagai bukti `INC-2026-024-E04` dengan hash. `-view` membaca database CA, `-restrict` menyaring baris, dan `-out` memilih kolom. Nama kolom dan isi kolom template bisa berbeda per versi (template versi 2 bisa tampil sebagai OID), jadi cek daftar kolom dengan `certutil -schema` di versi-mu. ATT&CK menyebut `certsrv.msc` dan `certutil.exe` sebagai alat untuk meninjau sertifikat dan konfigurasi CA [S4].

Keluaran ilustrasi (diringkas, 312 baris sertifikat Wi-Fi yang sah tidak ditampilkan):

```
RequestID  RequesterName       CommonName      CertificateTemplate  NotBefore          NotAfter
1186       JAB\teguh.wibowo    teguh.wibowo    JAB-WiFi-User        11/10/2026 09:41   11/10/2027 09:41
1187       JAB\teguh.wibowo    adm.agung       JAB-WiFi-User        11/16/2026 01:12   11/16/2027 01:12
```

Cara membaca hasil: Request 1186 adalah enrollment Wi-Fi Teguh yang sah saat roll-out. Request 1187 diminta akun Teguh tetapi berisi identitas `adm.agung`, satu tahun masa berlaku. Detail SAN request 1187 dibuka dengan `certutil -view` untuk Request ID itu dan disalin ke case notes. Pencarian yang sama untuk semua request dengan CommonName atau SAN yang berbeda dari peminta menghasilkan satu baris saja, yaitu 1187.

**Kapan gagal:** penyerang punya akses admin ke CA dan menghapus baris database; Microsoft menandai event 4896 (baris dihapus dari database sertifikat) sebagai kritis tinggi karena bisa berarti penyerang menutupi jejak setelah menerbitkan sertifikat [S10]. Event itu juga hanya ada bila audit CA aktif.

### 2.3 Mencari tanda pemakaian golden ticket

Langkah ini menjawab pertanyaan keempat Hendra secara praktis: apakah ada tiket layanan yang diminta tanpa TGT yang sepadan.

**Tujuan:** menemukan pasangan akun dan IP yang meminta TGS (4769) tanpa TGT (4768) dari pasangan yang sama dalam 10 jam sebelumnya, sesuai analitik ATT&CK [S2].

```
index=wineventlog host IN ("JKT-DC01","JKT-DC02") EventCode IN (4768,4769) Status=0x0
  earliest="11/15/2026:16:00:00" latest="11/18/2026:12:00:00"
| eval user=lower(mvindex(split(TargetUserName, "@"), 0))
| eval src=replace(IpAddress, "^::ffff:", "")
| eval tgt_time=if(EventCode=4768, _time, null())
| sort 0 user src _time
| streamstats last(tgt_time) as last_tgt by user src
| where EventCode=4769 AND _time >= strptime("11/16/2026:02:00:00", "%m/%d/%Y:%H:%M:%S")
| where isnull(last_tgt) OR (_time - last_tgt) > 36000
| stats count min(_time) as first max(_time) as last values(ServiceName) as services values(TicketEncryptionType) as etype by user src
| convert ctime(first) ctime(last)
```

Penjelasan tiap bagian:

- `user` dinormalkan karena 4769 menulis akun dalam format `user@REALM`, sedangkan 4768 menulis nama akun saja [S8][S9].
- Data diambil mulai 10 jam sebelum periode yang diperiksa (16:00 Minggu), tetapi hanya 4769 sejak 02:00 Senin yang dinilai. Tanpa jeda awal ini, setiap TGT yang diminta sebelum rentang akan tampak hilang.
- `streamstats last(tgt_time)` membawa waktu TGT terakhir per pasangan akun dan IP ke setiap baris berikutnya. 36000 detik adalah 10 jam, umur default tiket.
- `etype` ditampilkan supaya RC4 (`0x17`) di domain yang biasanya AES langsung terlihat [S9].

Keluaran ilustrasi:

```
user           src           count  first                 last                  services          etype
fajar.nugraha  10.30.12.15       4  11/17/2026 08:12:40   11/17/2026 08:13:02   JKT-FS01$ ...     0x12
```

Cara membaca hasil: satu baris, `fajar.nugraha` dari `10.30.12.15`. TGT Fajar pagi itu diminta dari `10.30.12.71` (Wi-Fi kantor Bandung) pukul 07:58, lalu laptopnya pindah ke kabel dan IP berubah. Enkripsi AES, layanan wajar, dan Fajar mengonfirmasi lewat telepon. Baris ini dijelaskan dan ditutup. Tidak ada baris lain, termasuk tidak ada aktivitas dari `10.10.48.83` setelah isolasi penuh 03:10.

Hasil ini ditulis di scope statement sebagai "tidak ditemukan tanda pemakaian tiket palsu dengan analitik yang tersedia", bukan "tidak ada golden ticket" (bagian 1.4).

**Variasi:** ganti `stats` terakhir dengan `where etype="0x17"` untuk mencari tiket RC4, atau ganti filter menjadi akun di `jab_tier0_accounts.csv` saja untuk pemantauan ketat di antara dua reset krbtgt.

**Kapan gagal:** sumber TGT dan TGS berbeda karena NAT, VPN, atau perpindahan jaringan (seperti baris Fajar); log salah satu DC tidak lengkap; atau penyerang memakai silver ticket yang tidak menyentuh DC sama sekali [S3].

### 2.4 Memo keputusan: eviction atau pemulihan forest

Memo ini menjawab pertanyaan terakhir Hendra. Disiapkan Dimas dan Yoga bersama retainer, dikirim Senin 14:30, diputuskan Hendra 15:15.

```
INC-2026-024 | Memo keputusan pemulihan AD | Senin 2026-11-16 14:30 WIB
Untuk: Hendra Wijaya (executive sponsor) | Dari: Dimas Prasetyo (IC), Yoga Pratama (TL)
Dikonsultasikan: PT Forensik Digital Contoh (retainer), Agung Prabowo (Lead Infrastruktur)
Severity: SEV-1 sejak 02:05

STATUS DOMAIN: DIANGGAP DIKUASAI (DCSync berhasil 01:16, akun Tier 0 dipakai)

FAKTA
- Jalur: installer palsu di JKT-WS-0483 (Kamis 12/11) -> enumerasi AD (Jumat 22:05)
  -> sertifikat atas nama adm.agung dari template JAB-WiFi-User (Senin 01:12)
  -> TGT adm.agung via sertifikat (01:14) -> DCSync dari 10.10.48.83 (01:16)
- Ditahan: JKT-WS-0483 diisolasi 02:20 (penuh 03:10); template ditarik dari CA 02:40;
  sertifikat 1187 dicabut dan CRL dipublikasi 02:45; audit CA diaktifkan 03:00;
  adm.agung direset dua kali 02:50 (akun yang sedang dipakai penyerang; tidak
  menunggu scope lengkap karena DCSync sudah berhasil dan kerusakan berjalan).
- Tidak ditemukan sejauh ini: tanda kode penyerang di DC; akses ke private key CA;
  perubahan grup, ACL, GPO, atau akun baru di AD; tanda tiket palsu (bagian 2.3).

PILIHAN
A. Pemulihan forest dari backup Kamis 2026-11-12 (sebelum akses awal)
   + Fondasi AD dari keadaan yang diketahui sebelum kompromi
   - Semua perubahan AD sejak Kamis hilang; seluruh layanan login berhenti
     perkiraan 2-3 hari; prosedur belum pernah dilatih di PT JAB
B. Eviction terkoordinasi, Selasa 2026-11-17 jam H 20:00 (rekomendasi IC dan retainer)
   + Domain tetap berjalan; jalur masuk dan perubahan penyerang yang diketahui
     bisa dibalik
   - Bergantung pada keyakinan bahwa tidak ada persistence yang belum ditemukan
   Isi: rotasi semua akun Tier 0 dan akun Entra Connect, krbtgt dua kali (jalur
   standar, bagian 1.5), KDS root key dan gMSA, perbaikan jalur dari pemetaan
   (bagian 2.6), pemantauan ketat 30 hari.

KEPUTUSAN (Hendra Wijaya, 15:15)
- Pilihan B.
- Delegasi: IC boleh menjalankan reset krbtgt kedua segera (jalur cepat) bila
  ada tanda tiket palsu atau akun Tier 0 dipakai dari host tak dikenal setelah
  reset pertama.
- Pemicu kembali ke pilihan A (diputuskan exec sponsor): tanda kode atau
  persistence di DC, tanda akses ke private key CA, atau perubahan AD oleh
  penyerang yang tidak bisa didaftar lengkap.
- Agung Prabowo menyiapkan latihan pemulihan forest di lab sebelum 2026-12-31.
```

Cara membaca elemennya:

- **"Dianggap dikuasai" ditulis sebagai status, bukan opini.** Status itu yang membuat rotasi seluruh Tier 0 tidak diperdebatkan lagi.
- **Pilihan A tidak ditolak, hanya ditunda dengan pemicu.** Bila salah satu pemicu muncul, keputusan berpindah tanpa rapat baru.
- **Kelemahan pilihan B ditulis terang-terangan.** Executive sponsor memutuskan dengan tahu bahwa eviction bergantung pada kelengkapan scoping.

**Kapan gagal:** memo ditulis sebelum pemeriksaan DC dan CA selesai, sehingga daftar "tidak ditemukan" hanya berarti "belum dicari".

### 2.5 Rencana eviction jam H

Rencana ini menjalankan pilihan B dan menjawab pertanyaan kelima dan keenam Hendra. Kolom R dan A mengikuti RACI PT JAB (Day 02 bagian 2.2). Perhatikan jeda antara dua baris krbtgt.

| Waktu | Tindakan | R | A | Verifikasi |
|---|---|---|---|---|
| Selasa 19:30 | Go/no-go: akses ke kedua DC dan `JKT-SYNC01` diuji dari host admin di luar scope, daftar layanan yang bergantung pada AD dan tim aplikasi siaga | Semua | IC | Setiap pelaksana menjawab "siap" |
| 20:00 | Rotasi semua akun Tier 0 (anggota Domain Admins dan Enterprise Admins, Administrator bawaan), masing-masing dua kali | Agung | IC | `PasswordLastSet` semua akun di jam H |
| 20:10 | Rotasi password akun konektor AD DS Entra Connect, lalu uji siklus sinkronisasi | Agung | IC | Sinkronisasi berhasil; tidak ada error ekspor |
| 20:20 | Reset krbtgt pertama di `JKT-DC01` | Agung | IC | Atribut `pwdLastSet` krbtgt berubah |
| 20:25 sampai 21:00 | Cek kesehatan replikasi ke `JKT-DC02` | Agung | IC | `repadmin /replsummary` tanpa kegagalan; `pwdLastSet` sama di kedua DC |
| 21:00 sampai Rabu 08:00 | Pemantauan ketat query bagian 2.1, 2.2, dan 2.3 untuk akun Tier 0 tiap 15 menit | SOC on-call | IC | Hasil tiap putaran di case notes |
| Rabu 08:00 | Reset krbtgt kedua (11 jam 40 menit setelah reset pertama, di atas 10 jam) | Agung | IC | `pwdLastSet` berubah; replikasi dicek ulang |
| Rabu 08:30 | Uji layanan yang bergantung pada AD; restart layanan yang gagal autentikasi | Tim aplikasi | Hendra (dampak layanan) | Daftar layanan hijau |
| Kamis 2026-11-19 | KDS root key baru dan pembuatan ulang dua gMSA monitoring, sesuai skenario di panduan Microsoft [S14] | Agung | IC | Layanan pemakai gMSA berjalan dengan akun baru |
| Kamis sampai Jumat | Perbaikan jalur dari bagian 2.6 | Agung, Yoga | IC | Pemetaan ulang tidak menemukan jalur yang sama |

Cara membaca elemennya:

- **Akun Tier 0 dan akun konektor dirotasi sebelum krbtgt.** Kalau krbtgt direset lebih dulu sementara penyerang masih memegang hash akun admin, ia bisa meminta TGT baru yang sah dengan hash itu.
- **Jeda krbtgt mengikuti jalur standar** (bagian 1.5), dengan pemantauan ketat di antaranya dan delegasi jalur cepat di memo.
- **Uji layanan punya A Hendra**, karena reset krbtgt bisa mengganggu layanan yang bergantung pada AD [S15].

**Kapan gagal:** replikasi antar DC sudah bermasalah sebelum jam H dan tidak dicek; reset kedua lalu dilakukan sebelum reset pertama sampai di DC lain. CM0050 meminta kesehatan replikasi diverifikasi lebih dulu [S15].

### 2.6 Hasil pemetaan jalur serangan

Pemetaan ini menjawab bagian "seberapa luas" pertanyaan terakhir Hendra. Yoga menjalankan collector resmi BloodHound CE dari host admin di luar scope pada Selasa siang, setelah memberi tahu SOC. Tabel berikut adalah jalur ke Tier 0 yang ditemukan beserta perbaikannya.

| No | Jalur yang ditemukan | Dipakai penyerang? | Perbaikan | Status |
|---|---|---|---|---|
| 1 | Domain Users boleh enroll ke `JAB-WiFi-User` yang mengizinkan peminta mengisi SAN, dengan EKU Client Authentication | Ya | Template ditarik dari CA; dibuat ulang tanpa "Supply in the request", enrollment hanya untuk grup Wi-Fi | Selesai Senin 02:40 (penarikan), Kamis (template baru) |
| 2 | Grup IT Helpdesk punya hak reset password pada OU yang berisi akun `adm.*` | Tidak terlihat | Akun Tier 0 dipindah ke OU terpisah; delegasi helpdesk hanya untuk OU pengguna biasa | Selesai Kamis |
| 3 | Akun Domain Admin punya sesi aktif di dua workstation non-Tier 0 (`JKT-WS-0302`, `JKT-WS-0487`) | Tidak terlihat | Pembatasan logon akun Tier 0 hanya ke DC, `JKT-JUMP01`, dan server Tier 0 | Selesai Jumat |
| 4 | Grup IT Infrastruktur adalah admin lokal `JKT-SYNC01` | Tidak terlihat | Admin lokal `JKT-SYNC01` hanya akun Tier 0, sesuai saran Microsoft [S21] | Selesai Jumat |

Cara membaca elemennya:

- **Kolom "Dipakai penyerang?"** dipisah dari keberadaan jalur. Jalur 2 sampai 4 tidak terlihat dipakai, tetapi penyerang yang sempat mengenumerasi AD kemungkinan melihatnya, jadi semuanya diperbaiki dalam rangkaian eviction.
- **Jalur 3 menjelaskan kenapa sesi admin di workstation biasa berbahaya:** setiap workstation dengan sesi Tier 0 adalah pintu ke Tier 0 bila workstation itu terkompromi.

**Kapan gagal:** pemetaan dijalankan dari host dalam scope, atau hasilnya tidak diulang setelah perbaikan, sehingga jalur yang dikira tertutup ternyata masih ada lewat grup bersarang.

## 3. Lab praktik (di VM lab terisolasi)

Lab ini memakai lab Windows dengan satu atau dua DC, satu VM Windows anggota domain, Splunk, dan bila memungkinkan satu server AD CS enterprise. Semua langkah di VM lab dengan snapshot. Lab ini tidak menjalankan alat serangan; tujuannya menyiapkan telemetri, memeriksa konfigurasi, dan melatih keputusan. Jangan memakai data, nama, atau kejadian dari pekerjaan nyata.

1. **Audit replikasi.** Aktifkan Audit Directory Service Access di DC lab dan periksa SACL objek domain. Tambahkan DC kedua atau tunggu replikasi normal, lalu cari 4662 dengan dua GUID replikasi di Splunk. Catat akun apa yang muncul dalam keadaan normal; daftar itu menjadi isi lookup `jab_replikasi_sah.csv` versi-mu.
2. **Korelasi Logon ID.** Jalankan query bagian 2.1 dengan field dari add-on-mu. Pastikan setiap baris 4662 punya pasangan 4624 dengan IP. Bila tidak, cari tahu kenapa (logon di DC lain, field berbeda nama).
3. **Audit CA dan template.** Di server AD CS lab, aktifkan audit filter CA untuk penerbitan dan perubahan konfigurasi. Daftar semua template yang diterbitkan CA dan periksa untuk setiap template: siapa yang boleh enroll, apakah manager approval aktif, EKU-nya, dan apakah peminta boleh mengisi subject atau SAN. Tandai template yang memenuhi semua kondisi di bagian 1.3.
4. **Telemetri enrollment sah.** Minta satu sertifikat sah untuk akunmu sendiri dari template User di lab, lalu temukan 4886 dan 4887 di CA. Bila lab punya autentikasi sertifikat, temukan 4768 dengan `PreAuthType` 16 di DC.
5. **Reset krbtgt di lab.** Ikuti prosedur Microsoft untuk reset krbtgt di lab dengan dua DC: reset pertama, cek replikasi, catat apa yang terjadi pada sesi yang sudah login di VM anggota (misalnya akses share dengan tiket lama), lalu reset kedua setelah jeda yang kamu tetapkan. Catat semua error autentikasi yang muncul dan berapa lama sampai hilang.
6. **Pemetaan jalur.** Jalankan collector resmi BloodHound CE di lab sesuai dokumentasinya. Buat satu jalur sengaja (misalnya grup biasa dengan hak reset password pada akun admin lab), temukan jalurnya di BloodHound, perbaiki, lalu jalankan ulang dan pastikan jalurnya hilang.
7. **Memo.** Tulis memo keputusan dengan format bagian 2.4 untuk skenario lab: DCSync terdeteksi dari host lab, tanpa tanda kode di DC.

**Hasil yang sebaiknya tersimpan:**

- `latihan/day12-audit.md` berisi konfigurasi audit DC dan CA, daftar akun replikasi sah, dan query bagian 2.1 versi lab-mu dengan hasilnya.
- Tabel pemeriksaan template dari langkah 3.
- Catatan langkah 5: urutan, waktu, dan error yang muncul selama reset krbtgt.
- Tangkapan jalur BloodHound sebelum dan sesudah perbaikan.
- `latihan/day12-memo.md` berisi memo keputusan langkah 7.

**Variasi tantangan:** matikan audit Directory Service Access di salah satu DC lab, lalu ulangi langkah 2. Apa yang hilang dari hasil, dan bagaimana kamu tahu deteksi sedang buta tanpa menunggu insiden?

## 4. Troubleshooting

Tabel ini memuat masalah yang sering muncul saat mendeteksi dan menangani serangan AD tingkat domain. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa atau memperbaiki |
|---|---|---|
| Rule DCSync tidak pernah menghasilkan apa pun, bahkan untuk replikasi DC normal | Audit Directory Service Access atau SACL objek domain tidak aktif | Uji dengan replikasi normal di lab; cek kebijakan audit DC [S5] |
| Rule DCSync berbunyi terus | Akun konektor Entra Connect atau DC tidak dikecualikan | Kecualikan pasangan akun dan IP sumber, bukan akun saja [S12] |
| 4662 ada, tetapi IP sumber tidak ketemu | 4624 dengan Logon ID yang sama ada di DC lain atau field berbeda nama | Korelasikan per DC; cek nama field Logon ID di add-on |
| Tidak ada 4886 dan 4887 di CA | Audit filter CA tidak aktif | Aktifkan audit filter; ambil bukti dari database CA [S10] |
| Sertifikat dicabut, tetapi masih dipakai | CRL baru belum dipublikasi atau belum terbaca DC | Publikasikan CRL; pantau 4768 dengan kode `0x3E` [S8] |
| Layanan error setelah reset krbtgt | Tiket lama gugur; layanan tidak meminta tiket baru otomatis | Restart layanan sesuai daftar; jadwalkan di jendela pemeliharaan [S15] |
| Reset krbtgt gagal | Password filter kustom di DC | Ikuti panduan Microsoft untuk password filter [S13] |
| Query golden ticket banyak hasil | IP berubah karena VPN, NAT, atau perpindahan jaringan | Jelaskan per baris; batasi ke akun Tier 0 untuk pemantauan ketat |
| Pemetaan jalur memicu alert SOC | Enumerasi defender mirip enumerasi penyerang | Beri tahu SOC sebelumnya; catat host, akun, dan waktu di case notes |

## 5. Kesalahan umum dan jebakan

- Hanya mereset password akun admin yang dipakai penyerang setelah DCSync. Semua hash domain mungkin sudah tersalin, termasuk krbtgt [S1][S2].
- Mereset password akun yang memakai sertifikat curian dan menganggap selesai. Sertifikat tetap berlaku sampai dicabut atau kedaluwarsa [S4][S17].
- Mengecualikan akun `MSOL_` dari rule DCSync di semua host. Akun itu memegang hak replikasi dan bisa disalahgunakan dari host lain [S12].
- Menyimpulkan "tidak ada golden ticket" dari query heuristik yang tidak menemukan apa pun (bagian 1.4).
- Mereset krbtgt sebelum akun Tier 0 lain dirotasi dan jalur masuk ditutup, atau sebelum scope cukup. AA20-245A menyebut reset dini sebagai kesalahan umum [S16].
- Mereset krbtgt kedua tanpa memastikan reset pertama sudah tereplikasi [S13][S15][S16].
- Menganggap Entra ID aman karena akun admin cloud terpisah, tanpa memeriksa server dan akun Entra Connect [S21].
- Memasang CA enterprise tanpa mengaktifkan audit dan tanpa meninjau template yang dibuat vendor.
- Memutuskan pemulihan forest tanpa tahu backup mana yang aman, atau tanpa pernah melatih prosedurnya [S14].
- Menjalankan pemetaan jalur dari host yang termasuk scope.

## 6. Catatan terkini

Bagian ini menampung detail versi dan perubahan yang bisa memengaruhi cara membaca log atau menjalankan prosedur di Day ini.

- **Event 4768 dan 4769** di Windows Server 2016 ke atas tampil dalam versi baru setelah pembaruan kumulatif 14 Januari 2025, dengan field tambahan seperti tipe enkripsi yang didukung, kunci yang tersedia, dan hash tiket [S8][S9]. Rule yang dibuat sebelum 2025 mungkin perlu disesuaikan dengan nama field baru di add-on-mu.
- **KB5014754**: DC masuk mode Full Enforcement pemetaan sertifikat dengan pembaruan Februari 2025 (FAQ menyebut 11 Februari 2025), dan pembaruan 9 September 2025 mengakhiri dukungan nilai registry `StrongCertificateBindingEnforcement` [S11].
- **Entra Connect Sync**: Microsoft mewajibkan upgrade ke versi 2.6.84.0 atau lebih baru dan konfigurasi autentikasi berbasis aplikasi sebelum 7 April 2027; autentikasi lama dipensiunkan [S21]. Prosedur rotasi kredensial akun konektor Entra bisa berbeda antara metode lama dan baru.
- **Panduan bersama lima negara** "Detecting and mitigating Active Directory compromises" pertama terbit September 2024 dan diperbarui September 2026; halaman Cyber Centre Kanada mendaftar 19 teknik, termasuk penyalahgunaan AD CS, golden certificate, DCSync, golden dan silver ticket, penyalahgunaan Entra Connect, dan shadow credentials [S20]. Isi teknis edisi 2026 perlu dibaca langsung untuk melengkapi analitik di Day ini.
- **MITRE ATT&CK** yang diperiksa adalah v20. T1649 terakhir diubah 4 Agustus 2026 [S4].
- **BloodHound** v8.0 memperkenalkan OpenGraph untuk collector kustom di luar AD dan Entra ID [S18].

## 7. Cheat sheet

```
DCSYNC = meniru replikasi DC dari host bukan DC -> hash semua akun termasuk krbtgt
  hak: Replicating Directory Changes      1131f6aa-9c07-11d1-f79f-00c04fc2dcd2
       Replicating Directory Changes All  1131f6ad-9c07-11d1-f79f-00c04fc2dcd2
  pemilik sah: akun komputer DC, akun konektor Entra Connect (MSOL_) dari server sync
  deteksi: 4662 di DC (Audit DS Access + SACL) + GUID di Properties
           Logon ID -> 4624 logon type 3 -> IP sumber
  kecualikan PASANGAN akun+IP, bukan akun saja

AD CS (ESC1): enroll oleh user biasa + tanpa manager approval + EKU autentikasi
              + peminta isi SAN  => sertifikat atas nama siapa pun
  CA: 4886 diterima | 4887 diterbitkan | 4898/4899 template | 4885 audit filter
      | 4896 baris DB dihapus  (semua butuh audit filter CA)
  DC: 4768 PreAuthType 15/16/17 + CertIssuer/Serial/Thumbprint; 0x3E = sertifikat dicabut
  sertifikat tetap berlaku setelah reset password -> revoke + CRL
  private key CA dicuri (golden certificate) -> bangun ulang AD CS

GOLDEN TICKET: TGT palsu dari hash krbtgt; TGS tetap lewat DC
  cari: 4769 tanpa 4768 akun+IP <= 10 jam | etype bukan 0x11/0x12 | field aneh
SILVER TICKET: TGS palsu dari hash akun layanan; TIDAK lewat DC; cari di host target
  heuristik: tidak ketemu != tidak ada

KRBTGT: rotasi Tier 0 + akun sync DULU, lalu krbtgt
  standar: reset 1 -> cek replikasi -> >= 10 jam -> reset 2   (Microsoft, CISA)
  cepat: reset 2 segera setelah replikasi, hanya dengan pemicu (STIG DISA; ditolak praktisi)
  + KDS root key baru dan gMSA dibuat ulang bila DB AD terkompromi

ENTRA CONNECT = Tier 0; admin server sync bisa memanipulasi user Entra
  rotasi konektor AD DS, cek konektor Entra; MFA admin; matikan soft/hard match bila tak perlu

DOMAIN DIANGGAP DIKUASAI bila: DCSync | akses DC/ntds.dit | key CA | Tier 0 dipakai penuh
  eviction: jalur+waktu diketahui, perubahan bisa dibalik, DC dan key CA bersih
  pemulihan forest: backup aman diketahui, kehilangan perubahan sejak backup, isolasi, sudah dilatih
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "Setelah DCSync terdeteksi, password `adm.agung` sudah direset dua kali pukul 02:50, jadi akses penyerang ke domain sudah tertutup." Benarkah?

<details><summary>Jawaban</summary>

Tidak. DCSync mengambil hash dari AD, termasuk hash `krbtgt`, akun admin lain, akun layanan, dan akun komputer. Dengan hash `krbtgt`, penyerang bisa memalsukan TGT untuk akun mana pun, dan TGT palsu tidak bergantung pada password akun yang disamar. Sertifikat atas nama `adm.agung` juga tetap berlaku sampai dicabut. Karena itu domain dianggap dikuasai dan seluruh Tier 0, akun Entra Connect, dan krbtgt masuk rencana eviction. Lihat bagian 1.1, 1.3, dan 1.4.

</details>

**2. Skenario keputusan.** Rule DCSync PT JAB berbunyi puluhan kali sehari untuk akun `MSOL_7c1e2a9b4d3f`. Seorang analyst mengusulkan perbaikan. Mana yang tepat?

- A. Kecualikan akun `MSOL_7c1e2a9b4d3f` dari rule karena itu akun Entra Connect.
- B. Kecualikan pasangan akun `MSOL_7c1e2a9b4d3f` dan IP `JKT-SYNC01`, sehingga akun yang sama dari host lain tetap memicu alert.
- C. Matikan rule dan andalkan EDR di workstation.

<details><summary>Jawaban</summary>

B. Akun konektor AD DS memegang hak replikasi untuk password hash sync, sehingga replikasi dari server sinkronisasi adalah perilaku normal; tetapi akun yang sama dipakai dari host lain adalah tanda penyalahgunaan. A membuat rule buta terhadap penyalahgunaan akun itu. C keliru karena DCSync meninggalkan jejak di DC, bukan selalu di host penyerang, dan host penyerang bisa saja tanpa EDR. Lihat bagian 1.1, 1.2, dan 2.1.

</details>

**3. Pertanyaan jebakan.** "Query golden ticket di bagian 2.3 tidak menemukan apa pun dari host penyerang, jadi golden ticket tidak pernah dibuat dan krbtgt tidak perlu direset." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Analitik itu heuristik: TGS tanpa TGT sebelumnya, jenis enkripsi yang tidak wajar, dan field yang aneh. Tidak menemukan apa pun hanya berarti tidak terlihat tanda pemakaian dengan analitik yang tersedia; penyerang bisa belum memakainya. Keputusan reset krbtgt didasarkan pada fakta bahwa hash krbtgt mungkin sudah tersalin lewat DCSync. Lihat bagian 1.4 dan 2.3.

</details>

**4. Skenario keputusan.** Selasa 20:20 reset krbtgt pertama sudah dilakukan dan tereplikasi. Pukul 23:40, query pemantauan menemukan TGS untuk akun Administrator bawaan dari IP yang tidak dikenal, tanpa TGT sebelumnya. Apa yang dilakukan IC?

- A. Menunggu sampai Rabu 08:00 sesuai rencana, karena jeda 10 jam adalah panduan Microsoft.
- B. Memakai delegasi di memo: reset krbtgt kedua segera setelah replikasi reset pertama terverifikasi, menyiagakan tim aplikasi, menahan host sumber, dan memperbarui scope.
- C. Membangun ulang forest dari backup malam itu juga tanpa melibatkan executive sponsor.

<details><summary>Jawaban</summary>

B. Memo sudah menulis pemicu jalur cepat: tanda tiket palsu setelah reset pertama. Selama kunci lama masih di riwayat, tiket dari kunci lama mungkin masih berguna bagi penyerang, jadi menunggu berarti membiarkan akses aktif. Harganya gangguan layanan, yang sudah disetujui lewat delegasi. A keliru karena jeda standar adalah default untuk keadaan tanpa tanda pemakaian. C keliru karena pemulihan forest punya pemicu sendiri (tanda di DC, key CA, atau perubahan yang tidak bisa didaftar) dan diputuskan executive sponsor. Host sumber juga harus ditahan dan scope diperbarui, karena IP tak dikenal berarti akses yang belum ditemukan. Lihat bagian 1.5, 2.4, dan 2.5.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Hendra Wijaya, dalam tiga kalimat, kenapa staf helpdesk bisa menjadi domain admin lewat sertifikat, dan kenapa mengganti password tidak menghentikannya.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "CA baru kita untuk Wi-Fi punya template yang membolehkan semua karyawan meminta sertifikat dan sekaligus menulis sendiri nama pemilik di dalamnya, jadi penyerang di laptop Teguh meminta sertifikat bertuliskan nama Agung dan DC menerimanya sebagai Agung. Sertifikat itu seperti kartu akses yang dicetak resmi: tetap berlaku walaupun password Agung diganti, sampai kartunya kita batalkan, yang sudah kita lakukan pukul 02:45. Template itu sudah ditarik, dan kami sedang memeriksa template lain dan menyalakan pencatatan di CA supaya penerbitan seperti ini langsung terlihat."

Kesalahan yang sering muncul:
- Memakai istilah seperti ESC1, SAN, EKU, atau PKINIT yang tidak dibutuhkan Hendra.
- Tidak menyebut bahwa sertifikat sudah dibatalkan, sehingga terdengar masih terbuka.
- Menyalahkan Teguh atau vendor, padahal yang perlu Hendra ketahui adalah penyebab dan tindakannya.

</details>

**6. Pertanyaan jebakan.** "Domain sudah dianggap dikuasai, jadi kita wajib membangun ulang AD dari backup." Benarkah?

<details><summary>Jawaban</summary>

Tidak otomatis. "Dianggap dikuasai" berarti semua rahasia Tier 0 diperlakukan sebagai terpapar dan keputusan pemulihan harus eksplisit. Eviction terkoordinasi cukup bila jalur dan waktu kompromi diketahui, perubahan penyerang bisa didaftar dan dibalik, dan tidak ada tanda di DC atau pada private key CA. Pemulihan forest dipertimbangkan bila syarat itu tidak terpenuhi, dengan harga hilangnya semua perubahan AD sejak backup, risiko memilih backup yang salah, dan prosedur yang harus sudah dilatih. Lihat bagian 1.7 dan 2.4.

</details>

**7. Interview question (English).** "You detect a DCSync from a workstation using a Domain Admin account. Walk me through your first 24 hours."

<details><summary>Sample answer</summary>

"First I confirm it: a 4662 on a domain controller with the replication GUIDs, from an account and source that aren't a DC or our Entra Connect server, correlated through the logon ID to a 4624 with the workstation's IP. Then I treat it as a domain compromise, because DCSync means the attacker probably has every hash, including krbtgt. In the first hours I contain the path we can see: isolate the workstation, find how a workstation got domain admin rights, close that path, for example a misconfigured certificate template, revoke any certificate issued through it, and preserve DC, CA and endpoint evidence. I don't rush to rotate everything piecemeal, because rotating one account while the attacker holds others just tips them off. Instead I scope: check other replication sources, certificate logons for Tier 0 accounts, changes to groups, ACLs and GPOs, signs of code on DCs or access to the CA key, and the sync server. Then I present the executive sponsor with a decision: a coordinated eviction, which rotates all Tier 0 accounts, the sync accounts and krbtgt twice with replication checks between resets, or a forest recovery from a known-good backup if we can't trust the DCs or can't list the attacker's changes. Throughout, I monitor Kerberos activity for Tier 0 accounts, and I'm explicit that not finding a forged ticket doesn't prove none exists."

What makes this answer strong: it starts with verification instead of assumption, explains why DCSync means domain compromise, separates immediate containment from coordinated eviction, names concrete evidence sources, and frames the rebuild question as an executive decision with criteria.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | MITRE ATT&CK: OS Credential Dumping: DCSync (T1003.006) | https://attack.mitre.org/techniques/T1003/006/ | primer | v1.1, diubah 2025-10-24 (ATT&CK v20); diakses 2026-10-15 | Tinggi. Cara kerja lewat MS-DRSR/DRSUAPI, data yang diambil, pemilik hak default, mitigasi hak replikasi, deteksi dari endpoint bukan DC |
| S2 | MITRE ATT&CK: Steal or Forge Kerberos Tickets: Golden Ticket (T1558.001) | https://attack.mitre.org/techniques/T1558/001/ | primer | v1.2, diubah 2025-10-24; diakses 2026-10-15 | Tinggi. TGT palsu dari hash KRBTGT, TGS tetap lewat KDC, analitik deteksi, mitigasi reset dua kali dengan replikasi |
| S3 | MITRE ATT&CK: Steal or Forge Kerberos Tickets: Silver Ticket (T1558.002) | https://attack.mitre.org/techniques/T1558/002/ | primer | v1.1, diubah 2025-10-24; diakses 2026-10-15 | Tinggi. Cakupan sempit, tanpa KDC, analitik deteksi |
| S4 | MITRE ATT&CK: Steal or Forge Authentication Certificates (T1649) | https://attack.mitre.org/techniques/T1649/ | primer | v1.2, diubah 2026-08-04; diakses 2026-10-15 | Tinggi. EKU dan SAN, template salah konfigurasi, sertifikat bertahan setelah reset password, golden certificate, peninjauan dengan certsrv.msc dan certutil |
| S5 | Microsoft Learn: 4662(S, F) An operation was performed on an object | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4662 | primer (dokumentasi vendor, arsip) | ms.date 2021-09-07; diakses 2026-10-15 | Tinggi. Syarat audit dan SACL, field, Logon ID untuk korelasi 4624, access mask Control Access, rekomendasi memantau domainDNS |
| S6 | Microsoft Learn: DS-Replication-Get-Changes extended right | https://learn.microsoft.com/en-us/windows/win32/adschema/r-ds-replication-get-changes | primer | ms.date 2018-05-31; diakses 2026-10-15 | Tinggi. Rights-GUID `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` |
| S7 | Microsoft Learn: DS-Replication-Get-Changes-All extended right | https://learn.microsoft.com/en-us/windows/win32/adschema/r-ds-replication-get-changes-all | primer | ms.date 2018-05-31; diakses 2026-10-15 | Tinggi. Rights-GUID `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2`, replikasi data rahasia domain |
| S8 | Microsoft Learn: 4768(S, F) A Kerberos authentication ticket (TGT) was requested | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768 | primer (dokumentasi vendor, arsip) | ms.date 2021-10-20, pembaruan event Januari 2025; diakses 2026-10-15 | Tinggi. Tipe pre-authentication 15/16/17, field sertifikat, kode `0x3E`, rekomendasi pemantauan |
| S9 | Microsoft Learn: 4769(S, F) A Kerberos service ticket was requested | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769 | primer (dokumentasi vendor, arsip) | ms.date 2021-09-07, pembaruan event Januari 2025; diakses 2026-10-15 | Tinggi. Field, jenis enkripsi, Logon GUID, rekomendasi memantau selain AES |
| S10 | Microsoft Learn: Securing PKI, Appendix A: Events to Monitor | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-r2-and-2012/dn786423(v=ws.11) | primer (dokumentasi vendor, arsip) | ms.date 2016-08-31 (lebih dari 3 tahun, arsip); diakses 2026-10-15 | Sedang-tinggi. Daftar event CA 4885-4900, audit filter yang dibutuhkan, tingkat kritis. Dokumen arsip; nomor event masih dipakai di Windows Server terbaru menurut sumber sekunder, cek di CA versi-mu |
| S11 | Microsoft Support: KB5014754, Certificate-based authentication changes on Windows domain controllers | https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16 | primer | diperbarui 2025-09-10; diakses 2026-10-15 | Tinggi. Ekstensi SID, pemetaan kuat, jadwal enforcement, event 39/40/41 |
| S12 | Microsoft Learn: Microsoft Entra Connect, Accounts and permissions | https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions | primer | ms.date 2025-04-09; diakses 2026-10-15 | Tinggi. Tiga akun, hak replikasi untuk password hash sync, akun `MSOL_`, role Directory Synchronization Accounts |
| S13 | Microsoft Learn: AD Forest Recovery, Reset the krbtgt password | https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password | primer | ms.date 2025-05-21; diakses 2026-10-15 | Tinggi. Dua kali, jeda 10 jam sesuai umur tiket, riwayat dua password |
| S14 | Microsoft Learn: AD Forest Recovery, Determine how to recover the forest | https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-determine-how-to-recover | primer | ms.date 2023-07-10; diakses 2026-10-15 | Tinggi. Data yang hilang, pemilihan backup dan trade-off, isolasi, password yang harus diketahui, KDS root key dan gMSA bila database terkompromi |
| S15 | CISA Eviction Strategies Tool: CM0050 Reset KRBTGT Password Twice | https://www.cisa.gov/eviction-strategies-tool/info-countermeasures/CM0050 | primer | Maret 2025; diakses 2026-10-15 | Tinggi. Replikasi sebelum reset kedua, minimal 10 jam, cek kesehatan replikasi, dampak ke aplikasi dan klien non-Windows |
| S16 | CISA: Technical Approaches to Uncovering and Remediating Malicious Activity (AA20-245A) | https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-245a | primer | revisi 2020-09-24 (lebih dari 3 tahun); diakses 2026-10-15 | Tinggi. Reset krbtgt dua kali dengan replikasi di antaranya; reset dini sebagai kesalahan umum |
| S17 | SpecterOps: Certified Pre-Owned (Will Schroeder, Lee Christensen) | https://specterops.io/blog/2021/06/17/certified-pre-owned/ | sekunder | 2021-06-17 (lebih dari 3 tahun); diakses 2026-10-15 | Tinggi untuk definisi kondisi ESC1, sertifikat bertahan setelah reset, golden certificate dan pembangunan ulang AD CS |
| S18 | BloodHound documentation: Introduction to BloodHound | https://bloodhound.specterops.io/get-started/introduction | primer (dokumentasi vendor) | diakses 2026-10-15 | Tinggi. Teori graf untuk hubungan di AD dan Entra ID, pemakaian oleh defender, OpenGraph v8.0 |
| S19 | BloodHound documentation: SharpHound Community Edition | https://bloodhound.specterops.io/collect-data/ce-collection/sharphound | primer (dokumentasi vendor) | diakses 2026-10-15 | Tinggi. Data yang dikumpulkan dari DC dan komputer domain |
| S20 | Canadian Centre for Cyber Security: Joint guidance on detecting and mitigating Active Directory compromises | https://www.cyber.gc.ca/en/news-events/joint-guidance-detecting-and-mitigating-active-directory-compromises | primer | diubah 2026-09-15; diakses 2026-10-15 | Sedang. Halaman pengumuman: lembaga penyusun dan daftar teknik. Isi teknis panduan lengkap belum dibaca untuk Day ini |
| S21 | Microsoft Learn: Microsoft Entra Connect, Prerequisites and hardware | https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-install-prerequisites | primer | ms.date 2026-01-16; diakses 2026-10-15 | Tinggi. Tier 0 dan Control Plane, risiko manipulasi pengguna Entra, MFA, soft match dan hard match takeover, kewajiban upgrade sebelum 7 April 2027 |
| S22 | EventSentry: validasi krbtgt (mirror teks STIG Windows Server DISA, V-254427, V-205877, V-225006) | https://www.eventsentry.com/validationscripts/guid/18ef977d-1c89-4ea7-ac53-0438873cb1db | sekunder (mirror teks STIG) | diakses 2026-10-15 | Sedang. Teks STIG tentang perubahan dua kali secara cepat bila ada dugaan kompromi, dibaca lewat mirror pihak ketiga, bukan situs DISA |
| S23 | FRSecure: KRBTGT Password Reset Guide | https://frsecure.com/?p=32923 | komunitas (panduan praktisi) | 2025; diakses 2026-10-15 | Sedang. Metode cepat sebagai metode darurat yang tidak direkomendasikan, alasan, dan urutan mode skrip reset |

**Catatan sumber:** rule DCSync di bagian 2.1 (korelasi 4662 dengan 4624 lewat Logon ID dan pengecualian pasangan akun dan IP), aturan "domain dianggap dikuasai", tabel kriteria eviction dan pemulihan forest di bagian 1.7, dan pembagian jalur standar dan jalur cepat reset krbtgt di bagian 1.5 adalah susunan catatan ini dari sumber yang disebut, bukan daftar resmi. Pernyataan bahwa reset krbtgt dua kali secara cepat diinginkan saat dugaan kompromi hanya bersumber dari teks STIG DISA yang dibaca lewat mirror [S22] dan bertentangan dengan jeda yang diminta Microsoft dan CISA [S13][S15][S16]; cek teks STIG yang berlaku di situs resmi DISA bila keputusan ini akan dipakai. Query golden ticket di bagian 2.3 adalah penerapan analitik ATT&CK [S2] dengan jendela 10 jam dari umur tiket default [S13], dan perlu diuji di lab karena pola TGT dan TGS bisa berbeda per lingkungan. Sintaks `certutil -view` dan nama kolomnya perlu dicek dengan `certutil -schema` di CA versi-mu. Bahwa akun konektor Entra memerlukan prosedur rotasi berbeda setelah perpindahan ke autentikasi berbasis aplikasi perlu dicek di dokumentasi Entra Connect versi yang dipakai. Isi teknis panduan bersama lima negara edisi September 2026 belum dipakai di Day ini [S20]. Semua isi PT JAB, termasuk nama host, akun, nomor request, nomor seri sertifikat, dan hasil query, adalah contoh fiktif.
