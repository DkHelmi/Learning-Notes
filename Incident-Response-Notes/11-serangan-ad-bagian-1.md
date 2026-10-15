---
day: 11
title: 'Serangan AD bagian 1: Kerberoasting, AS-REP roasting, pass-the-hash, dan pass-the-ticket dari sudut IR'
researched_on: 2026-10-15
versions_checked: 'MITRE ATT&CK v20.0 (T1558.003 dan T1558.004 diperbarui 24 Oktober 2025; T1550.002 dan T1550.003 diperbarui 12 Mei 2026); Microsoft Learn event 4768, 4769, 4624, 4776, 4648 (halaman arsip, updated_at 2026-04-27); Microsoft Learn Protected Users Security Group (ms.date 2025-06-27); Microsoft Learn Group Managed Service Accounts overview (ms.date 2025-07-01); Microsoft Learn DeviceLogonEvents (ms.date 2026-08-24); Microsoft Security Blog, guidance to help mitigate Kerberoasting (11 Oktober 2024); Microsoft support CVE-2026-20833 (diperbarui 14 April 2026); CISA/ASD Detecting and Mitigating Active Directory Compromises (revisi 15 September 2026); adsecurity.org honeypot SPN (8 Februari 2017, komunitas)'
---

# Day 11: Serangan AD bagian 1 (Kerberoasting, AS-REP roasting, pass-the-hash, dan pass-the-ticket dari sudut IR)

Cakupan: mengenali empat teknik Active Directory yang berpusat pada kredensial Kerberos dan NTLM dari sudut responder, yaitu membaca jejaknya di log untuk scoping, menilai sejauh mana kredensial yang dicuri membawa penyerang, dan menahan serta membersihkan akun yang terlibat sebelum penyerang mencapai kendali domain.

## Ide inti

Keempat teknik di Day ini punya satu benang merah: penyerang tidak menebak password di pintu depan, melainkan meminta sesuatu yang memang boleh diminta siapa saja di domain, lalu memecahkannya atau memakai ulang bentuk kredensial yang sudah ada. Kerberoasting dan AS-REP roasting meminta tiket atau balasan yang terenkripsi dengan kunci turunan password akun, lalu memecahkannya offline di mesin penyerang sehingga domain controller tidak melihat ribuan percobaan password. Pass-the-hash dan pass-the-ticket tidak memecahkan apa pun: penyerang memakai hash atau tiket yang sudah dicuri sebagai pengganti password. Bagi responder, artinya satu hal: begitu salah satu teknik ini muncul di scope, pertanyaannya bukan hanya "akun mana yang dipakai", tetapi "sampai mana kredensial itu membawa penyerang, dan apakah ia sudah menyentuh sesuatu yang bisa memberi kunci ke seluruh domain".

Kamu sudah mengenal pola ini dari jaringan. Akun service di AD seperti kunci yang dititipkan ke kontraktor supaya alat mereka bisa masuk ke beberapa ruang server sekaligus. Masalahnya, kunci itu sering dibuat bertahun-tahun lalu, passwordnya pendek dan tidak pernah diganti, dan dititipkan ke terlalu banyak ruang. Kerberoasting ibarat seseorang meminta salinan gembok ruang itu secara sah dari resepsionis, membawanya pulang, dan mencungkilnya pelan-pelan di rumah, jauh dari CCTV lobi. Setelah kuncinya terbuka, pass-the-ticket adalah memakai kartu akses yang sudah jadi tanpa perlu lagi menunjukkan KTP di setiap pintu. Batas analoginya: kunci fisik hanya membuka satu gedung, sedangkan satu akun service yang salah konfigurasi bisa menjadi pijakan ke banyak server, dan dari sana ke kunci induk gedung.

```
akun domain biasa dikuasai (phishing, infostealer, dll.)
  |
  +-- minta TGS untuk SPN akun service      -> 4769 etype 0x17 (RC4)   [Kerberoasting]
  +-- minta AS-REP akun tanpa pre-auth       -> 4768 PreAuthType 0      [AS-REP roasting]
  |                                              crack OFFLINE (tak terlihat di DC)
  v
password akun service terbuka
  |
  +-- overpass-the-hash: hash -> TGT baru    -> 4624 type 9 seclogo (host sumber)
  +-- pass-the-ticket: pakai tiket curian    -> 4769/4624 tanpa 4768 pendahulu
  +-- pass-the-hash: hash NTLM langsung      -> 4624 type 3, NTLM, 4776 di DC
  |
  v
gerak lateral ke server tempat akun itu berhak
  |
  v
scoping: sampai mana kredensial membawa? sudah menyentuh DC atau domain admin?
  -- belum --> contain & eradicate akun (reset 2x, batasi, rotasi)
  -- ya    --> naik ke penanganan kompromi domain (krbtgt, lihat Day 06; Day 12)
```

Situasi yang dipakai sepanjang Day ini adalah `INC-2026-023` di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan domain `JAB` (`corp.jab.example`), dua domain controller `JKT-DC01` dan `JKT-DC02`, EDR Microsoft Defender for Endpoint Plan 2 di server dan workstation Windows, dan log keamanan DC yang dikirim ke Splunk index `wineventlog`. PT JAB memakai lisensi Microsoft 365 E3, sehingga tidak punya Microsoft Defender for Identity; deteksi serangan AD bertumpu pada event log DC di Splunk dan EDR di endpoint. Senin 2026-11-02 pukul 11:35, sebuah alert bernomor `SOC-2026-0240` berbunyi: akun umpan (honeypot) `svc-sql-honey` yang sengaja dipasang SOC diminta tiketnya. Dimas Prasetyo, SOC lead dan IC, menulis ke technical lead Rudi Hartanto di kanal `#inc-2026-023`:

> "Rud, alert honeypot Kerberos akhirnya bunyi. Tolong bantu saya pahami. Apa sih Kerberoasting itu, dan kenapa yang disasar akun service, bukan akun orang? Alert ini membuktikan apa, dan dari host mana penyerang menjalankannya? Ada tidak akun lain yang bisa diserang bahkan tanpa password sama sekali? Kalau misalnya password `svc_backup` sampai kebobol, apa yang bisa dia lakukan tanpa login normal? Seberapa jauh akun itu bisa membawa dia? Lalu bagaimana kita menahannya, dan perlu tidak kita reset krbtgt seperti yang ramai dibahas? Dan karena kita tidak punya Defender for Identity, dari mana sebenarnya kita tahu semua ini?"

Pesan itu memuat tujuh pertanyaan:

1. Apa itu Kerberoasting, dan kenapa akun service yang disasar?
2. Alert honeypot ini membuktikan apa, dan dari host mana?
3. Apakah ada akun yang bisa diserang tanpa password?
4. Kalau password akun service kebobol, apa yang bisa dilakukan tanpa login normal?
5. Seberapa jauh akun itu membawa penyerang?
6. Bagaimana menahan dan membersihkannya, dan perlukah reset krbtgt?
7. Dari mana kita tahu semua ini tanpa Defender for Identity?

Pertanyaan 1 dijawab di bagian 1.1 dan 1.2, pertanyaan 2 di bagian 1.2 dan bagian 2, pertanyaan 3 di bagian 1.3, pertanyaan 4 di bagian 1.4, pertanyaan 5 di bagian 1.5, pertanyaan 6 di bagian 1.6, dan pertanyaan 7 di bagian 1.7. Bagian 2 berisi query deteksi, penilaian blast radius, dan rencana containment PT JAB.

**Kapan relevan:** saat alert atau hunting menampilkan permintaan tiket Kerberos yang tidak wajar, logon service account dari host asing, atau tanda pemakaian ulang kredensial; dan saat menilai apakah satu akun yang dicuri bisa menjadi jalan ke seluruh domain.
**Kapan bukan jawaban:** Day ini tidak membahas DCSync, golden dan silver ticket, AD CS, atau pemulihan AD menyeluruh setelah kompromi domain; itu Day 12. Day ini juga bukan panduan menyerang: fokusnya membaca jejak dan merespons, bukan menjalankan teknik.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (tiket Kerberos yang tetap berlaku sampai kedaluwarsa di Day 05 bagian 1.5, krbtgt dan reset dua kali di Day 06 bagian 1.4, scope statement, blast radius, containment, eradication) tidak diulang. Tabel berikut memuat istilah baru Day ini. Kolom padanan memakai analogi NOC dan SOC yang sama di semua Day IR.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| KDC | Key Distribution Center, layanan di DC yang menerbitkan tiket Kerberos | Server AAA yang mengeluarkan izin akses |
| TGT | Ticket Granting Ticket, tiket awal untuk meminta tiket layanan | Token sesi awal setelah login ke portal |
| TGS | Ticket Granting Service ticket, tiket untuk satu layanan tertentu | Izin akses ke satu perangkat spesifik |
| SPN | Service Principal Name, nama unik satu instance layanan di AD | Label layanan di inventaris, misalnya `MSSQLSvc/host:1433` |
| etype (encryption type) | Algoritma enkripsi tiket: `0x17` RC4, `0x11` AES128, `0x12` AES256 | Jenis sandi pada payload; RC4 jauh lebih mudah dipecahkan |
| Kerberoasting | Minta TGS akun service lalu pecahkan password-nya offline | Ambil salinan gembok lalu cungkil di rumah |
| AS-REP roasting | Minta balasan autentikasi akun tanpa pre-auth lalu pecahkan offline | Pintu yang memberi struk terenkripsi sebelum KTP dicek |
| Pre-authentication | Bukti password yang dikirim sebelum KDC mengeluarkan TGT | Verifikasi KTP sebelum struk dicetak |
| NTLM hash | Representasi password yang dipakai protokol NTLM untuk autentikasi | Sidik kunci yang bisa dipakai tanpa kunci aslinya |
| Pass-the-hash (PtH) | Autentikasi NTLM memakai hash curian, tanpa password | Memakai sidik kunci untuk membuka pintu |
| Pass-the-ticket (PtT) | Memakai TGT atau TGS curian langsung | Memakai kartu akses yang sudah jadi |
| Overpass-the-hash | Memakai hash untuk membuat TGT Kerberos baru | Menukar sidik kunci dengan kartu akses resmi |
| Honeypot SPN | Akun umpan dengan SPN palsu; permintaan tiketnya pasti mencurigakan | Nomor pelanggan jebakan yang tak pernah dipakai |
| gMSA | Group Managed Service Account, akun service dengan password panjang yang dikelola otomatis | Kunci yang passwordnya diganti sistem otomatis |
| Protected Users | Grup AD yang memaksa akun anggotanya hanya pakai AES dan tak boleh NTLM | Daftar akun yang dikunci ke sandi kuat saja |

### 1.1 Kerberos ringkas: di mana password akun ikut terbawa ke dalam tiket

Pertanyaan pertama Dimas butuh dasar singkat sebelum masuk ke serangannya. Kerberos bekerja dengan dua langkah: klien membuktikan diri ke KDC di domain controller dan menerima TGT (tercatat sebagai event 4768), lalu memakai TGT itu untuk meminta TGS bagi layanan tertentu (event 4769). Setiap TGS sebagian dienkripsi dengan kunci yang diturunkan dari password akun yang memiliki layanan tersebut, supaya hanya layanan itu yang bisa membacanya [S1].

Dua sifat itu yang nanti dieksploitasi. Pertama, meminta TGS untuk sebuah SPN adalah operasi normal: akun domain mana pun yang memegang TGT valid bisa meminta tiket layanan untuk SPN apa pun [S1]. Kedua, bila tiket diterbitkan dengan RC4 (etype `0x17`), pemecahannya jauh lebih cepat daripada AES, karena RC4 tidak memakai salt atau hashing berulang saat mengubah password menjadi kunci [S10].

Istilah resmi: event 4768 adalah "A Kerberos authentication ticket (TGT) was requested" dan 4769 adalah "A Kerberos service ticket was requested"; keduanya hanya muncul di domain controller [S2][S3].

### 1.2 Kerberoasting: meminta yang sah, memecahkan di tempat gelap

Pertanyaan pertama dan kedua Dimas terjawab di sini. Kerberoasting (ATT&CK T1558.003) adalah langkah berikut dari 1.1: penyerang yang sudah memegang satu akun domain biasa meminta TGS untuk SPN milik akun service, lalu membawa tiket itu keluar dan memecahkannya offline untuk mendapat password plaintext [S1]. Akun service yang disasar karena dua alasan: akun seperti itu sering berhak tinggi (admin di beberapa server, kadang lebih), dan password-nya sering dibuat bertahun lalu, pendek, dan tidak pernah diganti [S10].

Yang membuat teknik ini berbahaya bagi defender adalah pemecahannya terjadi di mesin penyerang. Domain controller hanya melihat satu permintaan tiket yang sah; tidak ada ribuan event kegagalan login seperti pada brute force biasa. Jejak yang tersisa di DC adalah event 4769 dengan `TicketEncryptionType` `0x17` (RC4), dan pola satu akun meminta tiket untuk banyak SPN berbeda dalam waktu singkat [S1][S8]. ATT&CK menyarankan memantau 4769 untuk RC4 dan menandai akun yang meminta jumlah tiket layanan tidak wajar dalam waktu pendek [S1].

Karena 4769 sangat banyak di lingkungan normal, deteksi yang andal dibangun dari dua arah. Pertama, mempersempit: menyaring etype `0x17`, membuang akun komputer (nama berakhiran `$`) dan akun service yang memang masih memakai RC4, lalu mencari satu akun yang meminta banyak SPN [S9]. Kedua, umpan: sebuah akun honeypot dengan SPN palsu dan `adminCount=1` yang dibuat agar tampak menarik bagi penyerang, sehingga permintaan tiket apa pun untuknya hampir pasti berarti Kerberoasting, bukan lalu lintas normal. Teknik umpan ini dipopulerkan praktisi [S9], dan mekanismenya hanya memanfaatkan field 4769 yang didokumentasikan Microsoft [S3]. Di `INC-2026-023`, alert `SOC-2026-0240` justru datang dari honeypot `svc-sql-honey` itu. Dari sudut IR, satu hit honeypot mengubah dugaan menjadi kepastian dan langsung memberi dua fakta scoping: akun mana yang dipakai meminta dan dari IP mana (field Client Address di 4769) [S3][S9].

### 1.3 AS-REP roasting: akun yang memberi bahan sebelum membuktikan password

Pertanyaan ketiga Dimas ("ada akun yang bisa diserang tanpa password?") mengenai AS-REP roasting (ATT&CK T1558.004). Secara default, Kerberos meminta pre-authentication: klien mengirim timestamp terenkripsi dengan kunci password-nya sebelum KDC menerbitkan TGT, sehingga KDC tidak mengeluarkan bahan terenkripsi ke penyerang yang belum membuktikan password [S4]. Sebagian akun lama disetel "Do not require Kerberos preauthentication", biasanya demi kompatibilitas aplikasi tua. Untuk akun seperti itu, KDC mengembalikan AS-REP yang sebagian dienkripsi dengan kunci password tanpa minta bukti apa pun lebih dulu, dan penyerang bisa memecahkannya offline persis seperti Kerberoasting [S5].

Jejaknya ada di event 4768 dengan `Pre-Authentication Type` bernilai `0`, yang berarti logon tanpa pre-authentication [S4]. ATT&CK menyarankan memantau 4768 dengan Pre-Auth Type 0, mengaitkannya dengan 4769 berikutnya, dan menandai permintaan RC4 (etype `0x17`) serta enumerasi berlebih atas akun dengan setelan itu [S5]. Dari sudut IR, menemukan satu akun pre-auth 0 yang diminta dari host yang sama dengan Kerberoasting adalah sinyal bahwa penyerang sedang menyapu semua jalur password yang murah sekaligus. Di `INC-2026-023`, akun lama `svc_scanner` (pemindai inventaris warisan) kebetulan pre-auth-nya mati dan ikut diminta.

### 1.4 Pass-the-hash dan pass-the-ticket: memakai ulang, bukan memecahkan

Pertanyaan keempat Dimas ("kalau password kebobol, apa yang bisa dilakukan tanpa login normal?") sebenarnya mencakup dua keluarga teknik yang perlu dibedakan dari roasting. Roasting menghasilkan password plaintext. Pass-the-hash dan pass-the-ticket tidak memecahkan apa pun; keduanya memakai bentuk kredensial yang sudah ada.

Pass-the-hash (ATT&CK T1550.002) adalah autentikasi sebagai pengguna memakai hash password NTLM tanpa password plaintext [S6]. Pass-the-ticket (ATT&CK T1550.003) memakai TGT atau TGS curian langsung; TGS hanya membuka satu layanan, sedangkan TGT bisa dipakai meminta TGS untuk layanan apa pun yang bisa dijangkau akun itu [S7]. Varian overpass-the-hash memakai hash untuk membuat tiket Kerberos baru, yang lalu dipakai sebagai pass-the-ticket [S6][S7].

Jejaknya berbeda dari roasting dan ada di host, bukan di DC saja:

- **Pass-the-hash** meninggalkan autentikasi NTLM anomali: event 4624 dengan Logon Type 3 (network) memakai NTLM, sering tanpa event logon domain yang menyertainya, terutama dari sistem lateral atau lewat alat administrasi bawaan [S6]. Di DC, event 4776 ("The computer attempted to validate the credentials for an account") mencatat validasi kredensial NTLM untuk akun domain, dengan field Source Workstation yang menunjukkan dari mesin mana upaya itu datang [S11].
- [komunitas] **Overpass-the-hash** sering memunculkan event 4624 dengan Logon Type 9 (NewCredentials), Logon Process `seclogo`, dan Authentication Package `Negotiate` di host sumber, pola yang dipakai alat seperti sekurlsa::pth menurut rule Sigma komunitas [S13]. Positif palsu yang diketahui: perintah `runas /netonly` yang sah menghasilkan pola sama, jadi harus ditimbang dengan konteks [S13]. Pola ini belum terkonfirmasi di dokumentasi Microsoft; uji di lab-mu sebelum dijadikan alert.
- **Pass-the-ticket** terlihat sebagai pemakaian tiket tanpa 4768 pendahulu yang wajar: permintaan TGS (4769) atau akses yang tidak cocok dengan pola logon interaktif, dari host atau akun yang tidak diharapkan [S7].

Field 4624 yang penting untuk membedakan: Logon Type (3 network, 9 NewCredentials), Authentication Package (NTLM, Kerberos, Negotiate), Package Name untuk NTLM (NTLM V1 atau V2), dan Key Length yang selalu 0 untuk Kerberos [S12]. Logon Type 9 (NewCredentials) dipakai saat pemanggil menggandakan token dan memakai kredensial lain untuk koneksi keluar [S12], sehingga di lingkungan yang jarang memakai `runas /netonly` volumenya kecil dan cocok dijadikan sinyal; cek baseline di lingkunganmu.

### 1.5 Menilai blast radius kredensial: sampai mana akun itu membawa

Pertanyaan kelima Dimas ("seberapa jauh akun itu membawa?") adalah inti pekerjaan IR di serangan AD. Password yang dicrack hanya berbahaya sejauh hak akun itu, jadi scoping berarti memetakan hak akun service sebelum memutuskan containment.

Untuk setiap akun service yang mungkin terkompromi, responder memeriksa empat hal:

1. **SPN yang terpasang**, karena itu menunjukkan layanan dan server yang terkait akun.
2. **Keanggotaan grup**, terutama grup berhak tinggi (Domain Admins, Account Operators, Backup Operators) dan grup yang memberi akses luas.
3. **Hak lokal di server**, misalnya anggota local Administrators di mana saja. Akun backup atau monitoring sering dijadikan local admin di banyak server sekaligus; satu akun seperti itu bisa menjadi jalan ke seluruh fleet server walau bukan domain admin.
4. **Riwayat pemakaian sah**, supaya login setelah containment bisa dibedakan dari login penyerang.

Panduan bersama CISA dan ASD memasukkan Kerberoasting dan AS-REP roasting di antara 17 teknik yang paling sering dipakai menyerang AD [S14], dan mitigasi yang konsisten di ATT&CK dan Microsoft adalah membatasi hak akun service, menghindari keanggotaan grup berhak tinggi, dan menghapus SPN yang tidak perlu [S1][S10], justru karena blast radius itu. Di `INC-2026-023`, `svc_backup` bukan domain admin, tetapi anggota local Administrators di `JKT-FS01` dan server backup `JKT-BKP01`. Itu membuat insiden ini serius (akses ke data backup), tetapi tetap di bawah ambang kompromi domain, selama tidak ada bukti akun domain admin atau DC tersentuh. Perbedaan itulah yang memisahkan penanganan Day ini dari penanganan kompromi domain di Day 12.

### 1.6 Menahan dan membersihkan akun: reset dua kali, batasi, dan kapan krbtgt

Pertanyaan keenam Dimas soal containment dan krbtgt. Untuk akun yang kredensialnya dicrack, langkahnya mirip containment akun di Day 05 bagian 1.5 (disable, reset password dua kali untuk mengurangi pass-the-hash, cabut sesi), dengan tambahan khusus akun service.

- **Akun service tidak bisa sekadar dinonaktifkan** tanpa mematikan aplikasi yang bergantung padanya. Rotasi password dikoordinasikan dengan pemilik aplikasi, dan kredensial baru dipasang di aplikasi pada saat yang sama (pola yang sama dengan `svc_billing` di Day 05).
- **Reset dua kali** dipakai karena hash password lama masih bisa dipakai pass-the-hash; dasarnya sama dengan containment akun di Day 05 bagian 1.5.
- **Perbaikan jangka panjang** mengubah akun agar tidak bisa di-roast lagi: pindah ke gMSA atau dMSA yang password-nya panjang dan dikelola otomatis (gMSA memakai password yang dikelola sistem, dan Microsoft menyebut panjang 120 karakter), paksa AES dan hentikan RC4, serta hapus SPN yang tidak perlu [S10][S15]. Bila belum bisa pindah, password manual minimal 14 karakter dan sebaiknya jauh lebih panjang [S10]. Perlu dicatat, AES saja bukan solusi; password lemah tetap bisa di-brute force walau tiketnya AES [S10].
- **Protected Users dan akun berhak tinggi**: memasukkan akun admin interaktif ke grup Protected Users memaksa AES, melarang NTLM, dan membatasi umur TGT ke empat jam [S16]. Jangan memasukkan akun service atau akun komputer ke grup ini, karena proteksinya tidak berlaku di host yang menyimpan password-nya dan bisa memutus layanan [S16].

**Soal krbtgt**: reset krbtgt tidak diperlukan hanya karena akun service di-roast. krbtgt dipakai menandatangani semua TGT; menggantinya relevan bila penyerang sudah bisa memalsukan TGT, yaitu setelah kompromi domain (golden ticket, DCSync), yang dibahas di Day 12. Di `INC-2026-023`, karena tidak ada bukti akun domain admin, DC, atau pemalsuan tiket, krbtgt tidak direset; keputusan ini dicatat beserta pemicu yang akan mengubahnya, mengikuti pola Day 06 bagian 1.4. Yang diubah justru pemicunya: bila kemudian ditemukan akses ke DC atau TGT dengan masa berlaku tidak wajar, penanganan naik ke prosedur kompromi domain.

### 1.7 Deteksi tanpa Defender for Identity: bertumpu pada event log DC dan EDR

Pertanyaan ketujuh Dimas menyangkut keterbatasan nyata PT JAB. Microsoft Defender for Identity adalah sensor yang membaca lalu lintas dan event di domain controller dan memberi alert siap pakai untuk Kerberoasting dan sejenisnya, misalnya alert dengan external ID 2410 untuk dugaan paparan SPN [S10]. PT JAB di lisensi Microsoft 365 E3 tidak punya produk itu, sehingga deteksi dibangun sendiri dari dua sumber yang sudah ada:

- **Event log keamanan DC ke Splunk** (`wineventlog`): 4768, 4769, 4776, dan 4648 dari `JKT-DC01` dan `JKT-DC02`. Ini sumber utama untuk roasting dan untuk melihat permintaan tiket.
- **EDR Defender for Endpoint di endpoint**: alert dan timeline perangkat (misalnya akses ke LSASS dan proses mencurigakan), serta tabel advanced hunting `DeviceLogonEvents` untuk logon per host, lengkap dengan konteks token saat logon [S17].

Konsekuensinya, PT JAB harus menyiapkan auditing dan konten deteksi sendiri (termasuk honeypot SPN), dan kualitas deteksi bergantung pada kelengkapan audit policy di DC. Perubahan default RC4 yang sedang bergulir juga mengubah baseline: Microsoft menonaktifkan RC4 sebagai default KDC untuk akun tanpa `msDS-SupportedEncryptionTypes` eksplisit, dengan fase audit mulai 13 Januari 2026 dan enforcement default mulai 14 April 2026, disertai event audit KDC bernomor 201 sampai 209 [S18]. Artinya, begitu lingkungan bergerak ke AES, munculnya tiket RC4 menjadi sinyal yang lebih tajam, tetapi selama masa transisi masih ada RC4 sah yang harus dikecualikan.

## 2. Contoh artefak dan langkah praktis di PT JAB

Semua isi bagian ini fiktif dan merupakan keluaran ilustrasi. Query Splunk memakai index `wineventlog` dengan nama field hasil parsing TA Windows (`EventCode`, `Account_Name`, `Service_Name`, `Client_Address`, `Ticket_Encryption_Type`, `Pre_Authentication_Type`); nama persisnya bergantung add-on, jadi cocokkan dengan field di deployment-mu. KQL dijalankan di advanced hunting Defender. Tidak ada alat serangan yang dijalankan; jejak dibaca dari log.

### 2.1 Kerberoasting: hit honeypot dan anomali satu akun banyak SPN

Query ini menjawab pertanyaan pertama dan kedua Dimas: membuktikan Kerberoasting dan menemukan host sumbernya.

**Tujuan:** melihat permintaan TGS RC4 untuk akun umpan, lalu memetakan semua SPN yang diminta akun yang sama.

```
index=wineventlog (EventCode=4769 Ticket_Encryption_Type=0x17)
earliest="11/02/2026:00:00:00" latest="11/02/2026:23:59:59"
| rename Account_Name as user, Service_Name as spn, Client_Address as src
| eval src=replace(src,"::ffff:","")
| eval honeypot=if(spn=="svc-sql-honey","YA","-")
| stats count values(honeypot) as honeypot dc(spn) as spn_unik values(spn) as spn_list
        min(_time) as first max(_time) as last by user, src
| where NOT match(user,"\$$")
| sort - spn_unik
| convert ctime(first) ctime(last)
```

Penjelasan tiap bagian:

- `Ticket_Encryption_Type=0x17` menyaring tiket RC4, yang seharusnya menjadi pengecualian begitu lingkungan memakai AES [S9].
- `honeypot` menandai permintaan untuk SPN umpan `svc-sql-honey`. Satu baris "YA" sudah cukup menjadi bukti kuat.
- `dc(spn) as spn_unik` menghitung berapa SPN berbeda diminta satu akun; angka tinggi dalam waktu pendek adalah pola Kerberoasting [S1].
- `NOT match(user,"\$$")` membuang akun komputer (berakhiran `$`), yang wajar meminta banyak tiket [S9].

Keluaran ilustrasi:

```
user             src           count  honeypot  spn_unik  first                 last
bayu.firmansyah  10.10.42.24      19  YA              18   11/02/2026 11:33:41   11/02/2026 11:34:07
MSSQLSvc-app     10.20.5.30        6  -                1    11/02/2026 03:00:12   11/02/2026 21:00:09
```

Cara membaca hasil:

- `bayu.firmansyah` dari `10.10.42.24` (`JKT-WS-0424`) meminta 19 tiket RC4 untuk 18 SPN berbeda, termasuk honeypot, dalam 26 detik. Ini Kerberoasting, dan host sumbernya adalah workstation NOC milik Bayu. Akun Bayu sendiri kemungkinan sudah dikuasai penyerang; itu menjadi titik scoping berikutnya.
- Baris kedua adalah positif palsu yang wajar: satu akun aplikasi meminta satu SPN RC4 berulang dari server database, pola layanan tetap, bukan sapuan banyak SPN.

**Variasi:** untuk hunting rutin tanpa honeypot, ganti filter honeypot dengan ambang `spn_unik > 10` per akun per jam, dan kecualikan akun yang memang masih RC4 lewat lookup, mengikuti saran mempersempit volume 4769 [S9].

**Kapan gagal:** bila penyerang meminta tiket AES, bukan RC4, query ini tidak menangkapnya. Honeypot dan deteksi anomali volume tetap berguna karena tidak bergantung pada etype; sebagian alat meminta AES justru untuk menghindari filter RC4.

### 2.2 AS-REP roasting: akun tanpa pre-authentication

Query ini menjawab pertanyaan ketiga Dimas.

**Tujuan:** menemukan permintaan TGT tanpa pre-authentication, yang menandakan akun yang bisa di-AS-REP roast.

```
index=wineventlog EventCode=4768 Pre_Authentication_Type=0
earliest="11/02/2026:00:00:00" latest="11/02/2026:23:59:59"
| rename Account_Name as user, Client_Address as src, Ticket_Encryption_Type as etype
| eval src=replace(src,"::ffff:","")
| stats count values(etype) as etype min(_time) as first max(_time) as last by user, src
| convert ctime(first) ctime(last)
```

Penjelasan tiap bagian:

- `Pre_Authentication_Type=0` berarti TGT diminta tanpa pre-authentication, pola akun "Do not require Kerberos preauthentication" [S4].
- Menampilkan `etype` membantu melihat apakah balasan RC4 (`0x17`), yang paling mudah dipecahkan.
- Mengelompokkan per `user` dan `src` menunjukkan siapa yang diminta dan dari mana.

Keluaran ilustrasi:

```
user          src           count  etype   first                 last
svc_scanner   10.10.42.24       1   0x17   11/02/2026 11:34:52   11/02/2026 11:34:52
```

Cara membaca hasil: `svc_scanner` diminta dari `10.10.42.24`, host yang sama dengan Kerberoasting di 2.1, kurang dari satu menit setelahnya, dengan balasan RC4. Pola ini memperkuat bahwa satu penyerang di `JKT-WS-0424` sedang menyapu semua jalur password murah. `svc_scanner` masuk daftar akun yang password-nya harus dianggap terkompromi.

**Variasi:** jalankan enumerasi akun dengan setelan pre-auth mati sebagai baseline rutin (lewat query direktori oleh tim Infrastruktur), supaya daftar akun rentan diketahui sebelum insiden dan setelannya dicabut bila tidak perlu [S5].

**Kapan gagal:** bila audit "Kerberos Authentication Service" tidak aktif di DC, event 4768 tidak terkumpul. Ini salah satu alasan audit policy DC harus diverifikasi sebagai bagian kesiapan (bagian 1.7).

### 2.3 Pass-the-ticket dan overpass-the-hash: pemakaian kredensial yang dicrack

Query ini menjawab pertanyaan keempat Dimas. Saat tim masih menyusun scope, password lama `svc_backup` yang lemah sudah terpecahkan, dan pukul 12:43 alert `SOC-2026-0243` (logon `svc_backup` dari host di luar baseline) berbunyi. Dimas menaikkan severity ke SEV-2 pukul 12:55.

**Tujuan:** menemukan logon `svc_backup` dari host yang tidak wajar dan pola NewCredentials di host penyerang.

```
index=wineventlog EventCode=4624 Logon_Type IN (3,9)
Account_Name=svc_backup
earliest="11/02/2026:00:00:00" latest="11/02/2026:14:00:00"
| rename Computer as dest, Source_Network_Address as src, Logon_Type as type,
         Authentication_Package as authpkg, Logon_Process as logonproc
| eval src=replace(src,"::ffff:","")
| stats count values(authpkg) as authpkg values(logonproc) as logonproc
        values(dest) as dest min(_time) as first by src, type
| convert ctime(first)
```

Penjelasan tiap bagian:

- `Logon_Type IN (3,9)`: 3 adalah logon jaringan (dipakai pass-the-hash dan pass-the-ticket ke server lain), 9 adalah NewCredentials (pola overpass-the-hash di host sumber) [S12].
- `Authentication_Package` membedakan NTLM dari Kerberos; `Logon_Process` `seclogo` dengan `Negotiate` pada type 9 adalah pola overpass menurut rule Sigma komunitas [S13].
- Mengelompokkan per `src` dan `type` menunjukkan dari mana dan ke mana.

Keluaran ilustrasi:

```
src           type  authpkg    logonproc  dest                   count  first
10.10.42.24      9   Negotiate  seclogo    JKT-WS-0424                1   11/02/2026 12:38:50
10.10.42.24      3   Kerberos   Kerberos   JKT-BKP01                  4   11/02/2026 12:41:12
10.10.42.24      3   Kerberos   Kerberos   JKT-FS01                   2   11/02/2026 12:52:40
10.20.3.15       3   Kerberos   Kerberos   JKT-BKP01                 56   11/02/2026 00:00:03
```

Cara membaca hasil:

- Baris pertama (type 9, `seclogo`, `Negotiate` di `JKT-WS-0424`) adalah overpass-the-hash: penyerang menukar hash `svc_backup` menjadi TGT baru di host Bayu pukul 12:38.
- Dua baris berikutnya adalah pass-the-ticket: `svc_backup` dipakai dari `10.10.42.24` ke `JKT-BKP01` dan `JKT-FS01`. Ini anomali, karena `svc_backup` seharusnya hanya berjalan dari server backup, bukan dari workstation NOC.
- Baris terakhir adalah pemakaian sah: `svc_backup` dari server backup `10.20.3.15` ke `JKT-BKP01`, berjumlah besar dan rutin. Membandingkannya menegaskan mana yang penyerang dan mana yang normal.

**Variasi:** lengkapi dengan EDR. Akses ke LSASS dan proses mencurigakan dilihat di alert dan timeline perangkat `JKT-WS-0424`; logon per host bisa ditarik dari `DeviceLogonEvents` [S17]:

```kusto
DeviceLogonEvents
| where DeviceName startswith "JKT-WS-0424"
| where Timestamp between (datetime(2026-11-02 00:00) .. datetime(2026-11-02 14:00))
| where LogonType in ("Network","Interactive")
| project Timestamp, AccountName, LogonType, Protocol, RemoteIP, RemoteDeviceName,
          InitiatingProcessFileName, IsLocalAdmin
| order by Timestamp asc
```

**Kapan gagal:** logon type 9 juga dihasilkan `runas /netonly` yang sah, jadi jangan menilainya sendirian; kaitkan dengan akun yang memang sedang dicurigai dan dengan pemakaian dari host yang tidak wajar [S13].

### 2.4 Menilai blast radius `svc_backup`

Query ini menjawab pertanyaan kelima Dimas: sampai mana `svc_backup` membawa penyerang.

**Tujuan:** memetakan semua tujuan yang pernah diakses `svc_backup` dan tanda akun lain yang mungkin ikut.

```
index=wineventlog (EventCode=4624 OR EventCode=4768 OR EventCode=4769)
Account_Name=svc_backup
earliest="10/03/2026:00:00:00" latest="11/02/2026:14:00:00"
| eval dest=coalesce(Computer, Service_Name)
| eval src=replace(coalesce(Source_Network_Address, Client_Address),"::ffff:","")
| stats count min(_time) as first max(_time) as last values(EventCode) as codes by dest, src
| sort - count
| convert ctime(first) ctime(last)
```

Penjelasan tiap bagian:

- Menggabung 4624, 4768, dan 4769 memberi gambaran lengkap: logon, permintaan TGT, dan permintaan TGS atas nama akun itu.
- Rentang 30 hari membangun baseline: tujuan dan sumber yang wajar untuk `svc_backup` selama sebulan.
- Mengelompokkan per `dest` dan `src` memisahkan pemakaian rutin (server backup, tetap) dari yang baru (workstation Bayu, muncul 2026-11-02).

Keluaran ilustrasi (diringkas):

```
dest         src           count   codes       first                 last
JKT-BKP01    10.20.3.15      2840   4624 4769   10/03/2026 00:00:03   11/02/2026 13:45:02
JKT-FS01     10.20.3.15      1190   4624 4769   10/03/2026 00:05:11   11/02/2026 13:30:08
JKT-BKP01    10.10.42.24        4   4624 4769   11/02/2026 12:41:12   11/02/2026 12:49:50
JKT-FS01     10.10.42.24        2   4624        11/02/2026 12:52:40   11/02/2026 12:55:01
```

Cara membaca hasil: `svc_backup` secara sah hanya dipakai dari `10.20.3.15` (server backup) ke `JKT-BKP01` dan `JKT-FS01`. Dua baris dari `10.10.42.24` adalah pemakaian penyerang, terbatas pada dua server itu, dan baru muncul Senin 2026-11-02 siang. Tidak ada tujuan lain, tidak ada logon ke DC, dan tidak ada akun domain admin yang muncul dari host yang sama. Blast radius `svc_backup` adalah local admin di `JKT-FS01` dan `JKT-BKP01`; serius karena menyentuh data backup, tetapi belum kompromi domain. Hak akun ini (local admin di dua server) dicatat sebagai temuan akar untuk perbaikan.

**Variasi:** periksa juga keanggotaan grup `svc_backup` dan SPN-nya di direktori (lewat tim Infrastruktur), karena hak bisa lebih luas dari yang terlihat di log logon, sesuai prinsip membatasi hak akun service [S1][S10].

**Kapan gagal:** bila penyerang memakai tiket di server yang log-nya tidak dikirim ke Splunk, akses itu tidak muncul. Karena itu scoping dilengkapi daftar hak akun dari direktori, bukan hanya dari log.

### 2.5 Rencana containment jam H dan eradication akun service

Rencana ini menjawab pertanyaan keenam Dimas. Kolom R dan A mengikuti RACI PT JAB (Day 02 bagian 2.2). Baca kolom "Verifikasi"; tindakan tanpa verifikasi hanya perintah.

| Menit | Tindakan | R (pelaksana) | A | Verifikasi |
|---|---|---|---|---|
| H-30 | Go/no-go: kredensial baru `svc_backup` dan `svc_scanner` disiapkan bersama pemilik aplikasi; daftar host target dikonfirmasi | Semua | IC | Setiap pelaksana menjawab "siap" |
| H+0 | Isolasi `JKT-WS-0424` lewat Defender; reset dua kali dan revoke sessions akun `bayu.firmansyah` | Yoga, Infrastruktur | IC | Status isolasi; `Enabled` dan `PasswordLastSet` akun |
| H+0 | Reset `svc_backup` dua kali dan pasang kredensial baru di agen backup; batasi login `svc_backup` hanya dari server backup | Tim Infrastruktur, pemilik backup | IC | Job backup tetap jalan; login dari host lain ditolak |
| H+2 | Nonaktifkan `svc_scanner` bila layanannya sudah tidak dipakai; bila masih, reset dua kali dan aktifkan pre-authentication | Tim Infrastruktur | IC | Setelan pre-auth; aplikasi scanner diuji |
| H+2 | Blok IP C2 atau tujuan keluar `JKT-WS-0424` yang ditemukan di proxy dan firewall; cari sesi `svc_backup` yang masih hidup di `JKT-FS01` dan `JKT-BKP01` | NOC, Yoga | IC | Tidak ada sesi aktif tersisa |
| H+10 | Validasi: tidak ada logon baru `svc_backup` atau `bayu.firmansyah` dari host di luar baseline; honeypot tidak diminta lagi | Rudi | IC | Query 2.1, 2.3, 2.4 |

Cara membaca elemennya:

- **Reset `svc_backup` dikoordinasikan dengan pemilik backup**, karena password baru harus dipasang di agen pada saat yang sama; ini sama dengan pola akun service di Day 05.
- **Membatasi sumber login** (hanya dari server backup) menutup jalur pass-the-ticket dari workstation, bukan hanya mengganti password.
- **krbtgt tidak ada di rencana**, sesuai bagian 1.6; pemicunya dipantau terpisah.

Eradication jangka panjang yang masuk after-action: pindahkan `svc_backup` ke gMSA, hentikan RC4 untuk akun service dan paksa AES, hapus SPN yang tidak perlu, keluarkan `svc_backup` dari local Administrators di server yang tidak membutuhkannya, dan masukkan akun admin interaktif ke Protected Users [S10][S15][S16].

### 2.6 Update scope ke IC

Update ini dikirim Rudi pukul 13:20 Senin, sepuluh menit sebelum jam H 13:30, memakai pola scope statement: terkonfirmasi, belum diketahui, dan batas visibilitas.

```
INC-2026-023 | Scope v2 | Senin 2026-11-02 13:20 WIB | SEV-2 sejak 12:55 (SEV-3 11:50)
Disusun: Rudi Hartanto (TL) | Disetujui: Dimas Prasetyo (IC)

TERKONFIRMASI
- JKT-WS-0424 (bayu.firmansyah) dikuasai penyerang sejak Senin pagi; dari host ini:
  Kerberoasting 18 SPN (11:33) termasuk honeypot, AS-REP roast svc_scanner (11:34).
- Password svc_backup dan svc_scanner dicrack offline; svc_backup dipakai
  overpass/pass-the-ticket ke JKT-BKP01 (12:41) dan JKT-FS01 (12:52).
- Blast radius svc_backup: local admin di JKT-FS01 dan JKT-BKP01 saja.

BELUM DIKETAHUI
- data backup di JKT-BKP01 yang diakses atau disalin (audit file sedang diperiksa)
- cara awal JKT-WS-0424 dikuasai (triage host berjalan)

BATAS VISIBILITAS
- tidak ada Defender for Identity; deteksi dari wineventlog DC dan EDR
- tiket AES tidak tertangkap filter RC4; honeypot dan anomali volume menutup sebagian

PEMICU NAIK KE KOMPROMI DOMAIN (tertulis)
- logon atau akses svc_backup/akun lain ke JKT-DC01 atau JKT-DC02
- akun Domain Admins dipakai dari host dalam scope
- tanda pemalsuan tiket (TGT masa berlaku tak wajar, DCSync)
Bila terjadi: aktifkan prosedur kompromi domain (reset krbtgt, lihat Day 12 bagian 1.5).
```

Cara membaca elemennya:

- **Blast radius ditulis eksplisit** (local admin di dua server), sehingga keputusan severity bisa dipertanggungjawabkan.
- **Pemicu naik ke kompromi domain** mengubah ketidakpastian menjadi aturan, mengikuti pola scope statement Day 03 dan keputusan krbtgt Day 06.

## 3. Lab praktik (di VM lab terisolasi)

Lab ini memakai domain controller lab, satu VM Windows anggota domain, dan Splunk yang menerima `wineventlog`. Semua di VM lab dengan snapshot. Tidak ada alat serangan yang dijalankan: tiket diminta lewat perintah bawaan Windows (`klist`), yang bukan alat serangan, lalu event yang muncul dibaca di Splunk. Jangan memakai data, nama, atau kejadian dari pekerjaan nyata.

1. **Aktifkan audit dan kirim ke Splunk.** Pastikan subkategori "Kerberos Authentication Service" dan "Kerberos Service Ticket Operations" aktif di DC, lalu kirim Security log ke Splunk. Cek event 4768 dan 4769 muncul.
2. **Buat akun service lemah.** Buat akun lab `svc-lab-sql`, pasang satu SPN dengan `setspn`, dan beri password pendek yang kamu catat. Setel akun agar mendukung RC4. Dari VM anggota domain, minta tiket layanan itu dengan `klist get <SPN>` (perintah bawaan). Di Splunk, temukan 4769 dengan `Ticket_Encryption_Type=0x17` untuk SPN itu, dan catat field Account Name dan Client Address.
3. **Buat honeypot SPN.** Buat akun `svc-lab-honey` dengan SPN palsu dan `adminCount=1`. Minta tiketnya dengan `klist get`, lalu buat alert Splunk yang berbunyi untuk setiap 4769 ke SPN itu. Pastikan alert berbunyi dan mencatat host sumber.
4. **AS-REP roasting.** Buat akun `svc-lab-legacy`, aktifkan "Do not require Kerberos preauthentication". Picu permintaan TGT untuk akun itu, lalu temukan 4768 dengan `Pre_Authentication_Type=0` di Splunk.
5. **Baseline pass-the-ticket.** Catat dari host dan akun mana logon type 3 dan 9 muncul dalam sehari normal di lab, supaya kamu tahu seperti apa baseline sebelum mencoba membedakan anomali.
6. **Blast radius.** Jadikan `svc-lab-sql` local admin di satu VM anggota, lalu petakan lewat query 2.4 (versi lab) semua tujuan yang pernah diaksesnya. Tulis satu paragraf: sampai mana akun ini membawa bila password-nya bocor.

**Hasil yang sebaiknya tersimpan:**

- `latihan/day11-queries.spl` berisi query 4769 RC4 + honeypot, 4768 pre-auth 0, dan logon type 3/9.
- Cuplikan event 4769 (RC4) dan 4768 (pre-auth 0) dari lab, dengan field penting ditandai.
- Definisi alert honeypot dan bukti alert berbunyi.
- `latihan/day11-blast-radius.md` berisi peta tujuan `svc-lab-sql` dan penilaian blast radius-nya.

**Variasi tantangan:** setel `svc-lab-sql` agar hanya mendukung AES, lalu ulangi langkah 2. Apakah filter RC4 masih menangkapnya? Kontrol deteksi apa yang tetap bekerja (honeypot, anomali volume) saat penyerang memakai AES?

## 4. Troubleshooting

Tabel ini memuat masalah yang sering muncul saat mendeteksi dan menilai serangan ini. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa atau memperbaiki |
|---|---|---|
| Tidak ada 4769 sama sekali di Splunk | Audit "Kerberos Service Ticket Operations" tidak aktif, atau Security log DC tidak dikirim | Aktifkan subkategori audit di DC; verifikasi forwarder [S3] |
| Alert RC4 membanjir positif palsu | Masih ada akun atau sistem sah memakai RC4 (NetApp, trust tanpa AES) | Kecualikan lewat lookup; andalkan honeypot dan anomali volume [S9] |
| Penyerang tidak muncul di filter RC4 | Tiket diminta dengan AES | Pakai honeypot dan deteksi volume yang tidak bergantung etype; perketat baseline [S9] |
| Logon type 9 ramai tapi semua jinak | `runas /netonly` sah atau aplikasi tertentu | Kaitkan dengan akun yang dicurigai dan host tak wajar, jangan dinilai sendiri [S13] |
| 4768 pre-auth 0 tidak pernah muncul | Tidak ada akun pre-auth mati, atau audit AS tidak aktif | Verifikasi audit; enumerasi akun pre-auth mati dari direktori [S4][S5] |
| Akun service direset, aplikasi mati | Kredensial baru belum dipasang di aplikasi | Rotasi dikerjakan bersama pemilik aplikasi dengan rollback; pertimbangkan gMSA [S15] |
| Akun masih dipakai setelah disable | Tiket atau hash yang sudah terbit masih berlaku | Reset dua kali, cabut sesi, batasi sumber login, pantau kedaluwarsa (Day 05 bagian 1.5) |
| Ragu apakah sudah kompromi domain | Belum dicek akses ke DC dan akun domain admin | Terapkan pemicu di scope statement; cek logon ke `JKT-DC01/02` dan pemakaian Domain Admins |

## 5. Kesalahan umum dan jebakan

- Mengira Kerberoasting menghasilkan banyak event kegagalan login. Pemecahan terjadi offline; DC hanya melihat permintaan tiket yang sah [S1].
- Menganggap tiket AES aman dari crack. AES hanya memperlambat; password lemah tetap bisa dipecahkan [S10].
- Memblok atau mereset satu akun yang di-roast lalu menganggap selesai, tanpa menilai blast radius dan akun lain yang mungkin ikut dicrack [S1][S5].
- Lupa bahwa AS-REP roasting tidak butuh password sama sekali; akun pre-auth mati bocor walau password-nya tidak pernah dipakai login [S5].
- Mengira disable akun langsung memutus semua akses. Tiket dan hash yang sudah terbit masih berlaku; perlu reset dua kali dan pembatasan sumber (Day 05 bagian 1.5).
- Menilai logon type 9 sebagai pasti jahat. `runas /netonly` sah memicu pola yang sama [S13].
- Mereset krbtgt refleks setiap kali ada serangan Kerberos. krbtgt relevan untuk kompromi domain (pemalsuan TGT), bukan untuk Kerberoasting akun service; lihat Day 06 bagian 1.4 dan Day 12 bagian 1.5.
- Memasukkan akun service atau komputer ke Protected Users. Proteksinya tidak berlaku di host penyimpan password dan bisa memutus layanan [S16].
- Mengandalkan filter RC4 saja. Begitu lingkungan ke AES, penyerang pun bisa minta AES; honeypot dan anomali volume harus tetap ada [S9].

## 6. Catatan terkini

Bagian ini menampung detail versi dan perilaku produk yang bisa berubah. Berguna saat memakai fitur yang disebut, tetapi tidak mengubah cara membaca jejak serangan.

- **Default RC4 KDC sedang berubah (CVE-2026-20833)**: default `DefaultDomainSupportedEncTypes` bergerak ke AES-SHA1 untuk akun tanpa `msDS-SupportedEncryptionTypes` eksplisit, dengan fase audit mulai 13 Januari 2026 dan default enforcement mulai 14 April 2026, disertai event audit KDC 201 sampai 209 dan registry `RC4DefaultDisablementPhase` [S18]. Cek fase yang berlaku di domain-mu, karena itu menentukan apakah munculnya RC4 sudah anomali atau masih transisi.
- **Nonaktif RC4 default di klien dan server baru**: Microsoft menyebut rencana menonaktifkan RC4 secara default di Windows 11 24H2 dan Windows Server 2025 [S10]. dMSA (delegated Managed Service Account) baru di Windows Server 2025 menjadi opsi pengganti akun service standalone [S10].
- **Event 4768 dan 4769 versi baru**: setelah Security Cumulative Update 14 Januari 2025, Windows Server 2016 ke atas menampilkan event 4768 dan 4769 versi 2 dengan field tambahan seperti `MSDS-SupportedEncryptionTypes`, `Available Keys`, dan hash tiket [S2][S3]. Nama field hasil parsing bisa berbeda antar versi; cek di deployment-mu.
- **ATT&CK v20.0**: T1558.003 dan T1558.004 pada versi teknik 1.3 dan 1.2 (diperbarui 24 Oktober 2025); T1550.002 dan T1550.003 pada versi 2.0 (diperbarui 12 Mei 2026) [S1][S5][S6][S7]. Nomor teknik dan subteknik stabil, tetapi strategi deteksinya bisa berubah antar versi.
- **Defender for Identity**: produk ini memberi alert siap pakai untuk serangan ini (misalnya external ID 2410), tetapi butuh lisensi yang tidak dimiliki PT JAB; karena itu deteksi dibangun dari event log DC dan EDR [S10].

## 7. Cheat sheet

```
KERBEROASTING (T1558.003): minta TGS SPN akun service -> crack OFFLINE
  jejak: 4769 Ticket_Encryption_Type=0x17 (RC4) | satu akun, banyak SPN, waktu pendek
  honeypot SPN (adminCount=1): request apa pun = kepastian, bukan dugaan
  buang akun komputer ($), kecualikan RC4 sah via lookup

AS-REP ROASTING (T1558.004): akun pre-auth MATI -> AS-REP terenkripsi -> crack OFFLINE
  jejak: 4768 Pre_Authentication_Type=0 (+ etype 0x17)
  tak butuh password korban sama sekali

PASS-THE-HASH (T1550.002): hash NTLM -> auth tanpa password
  jejak: 4624 type 3 + NTLM tanpa logon domain menyertai | 4776 di DC (Source Workstation)
PASS-THE-TICKET (T1550.003): TGT/TGS curian dipakai langsung (TGS=1 layanan, TGT=semua)
OVERPASS-THE-HASH: hash -> TGT baru
  jejak: 4624 type 9 NewCredentials, Logon_Process=seclogo, Negotiate (host sumber)
  POSITIF PALSU: runas /netonly

etype: 0x17 RC4 (mudah crack) | 0x11 AES128 | 0x12 AES256
event: 4768 TGT (DC) | 4769 TGS (DC) | 4624 logon (host) | 4776 NTLM (DC) | 4648 explicit cred

BLAST RADIUS akun service: SPN | grup (DA/BackupOp) | local admin di mana | riwayat sah
  bukan DA != aman: local admin di banyak server = jalan ke fleet

CONTAIN/ERADIKASI akun: disable/reset 2x (anti PtH) + cabut sesi + batasi sumber login
  jangka panjang: gMSA/dMSA (pass 120 char) | paksa AES, matikan RC4 | hapus SPN tak perlu
  | keluarkan dari local admin | Protected Users utk akun admin (BUKAN service/komputer)
  krbtgt: HANYA utk kompromi domain (pemalsuan TGT), bukan roasting -> Day 12

PT JAB: tanpa Defender for Identity -> deteksi dari wineventlog DC + EDR + honeypot
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "Kerberoasting pasti terlihat sebagai banyak kegagalan login di domain controller, jadi kalau tidak ada lonjakan 4771 atau 4625, berarti tidak ada Kerberoasting." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Kerberoasting hanya meminta TGS yang sah, lalu memecahkan password offline di mesin penyerang, sehingga DC tidak melihat percobaan password apa pun. Jejaknya justru event 4769 yang berhasil, biasanya dengan encryption type `0x17` (RC4) dan satu akun meminta banyak SPN dalam waktu singkat. Ketiadaan lonjakan kegagalan login bukan bukti tidak ada Kerberoasting. Lihat bagian 1.2 dan 2.1.

</details>

**2. Skenario keputusan.** Honeypot `svc-sql-honey` diminta tiketnya dari `JKT-WS-0424`. Apa langkah pertama yang paling tepat?

- A. Langsung reset krbtgt dua kali, karena ada serangan Kerberos di domain.
- B. Perlakukan akun yang meminta (`bayu.firmansyah`) dan host `JKT-WS-0424` sebagai titik scoping: petakan semua SPN yang diminta, cari AS-REP roasting dari host yang sama, dan nilai akun service mana yang password-nya harus dianggap terkompromi.
- C. Blok IP `JKT-WS-0424` di firewall dan anggap selesai.

<details><summary>Jawaban</summary>

B. Hit honeypot memberi dua fakta scoping (akun peminta dan host sumber); langkah berikutnya memetakan sejauh mana serangan dan akun service mana yang bocor, lalu menilai blast radius sebelum containment. A keliru karena krbtgt relevan untuk kompromi domain (pemalsuan TGT), bukan untuk Kerberoasting akun service, dan belum ada bukti itu. C hanya mengobati gejala: workstation diblok, tetapi password akun service yang mungkin sudah dicrack tetap bisa dipakai dari host lain. Lihat bagian 1.2, 1.5, dan 1.6.

</details>

**3. Pertanyaan jebakan.** "Akun `svc_scanner` passwordnya kuat dan panjang, jadi aman dari AS-REP roasting." Benarkah?

<details><summary>Jawaban</summary>

Tidak sepenuhnya. AS-REP roasting mengeksploitasi setelan "Do not require Kerberos preauthentication": KDC mengembalikan AS-REP terenkripsi tanpa meminta bukti password lebih dulu, sehingga penyerang bisa mencoba memecahkannya offline. Password yang sangat panjang memang membuat pemecahan jauh lebih sulit, tetapi sumber masalahnya adalah setelan pre-auth yang mati, bukan panjang password. Perbaikan yang benar adalah mengaktifkan pre-authentication bila tidak ada alasan kuat mematikannya, bukan hanya mengandalkan panjang password. Lihat bagian 1.3.

</details>

**4. Skenario keputusan.** Query menunjukkan `svc_backup` login (type 3, Kerberos) dari `10.10.42.24` ke `JKT-BKP01`, padahal `svc_backup` biasanya hanya berjalan dari server backup `10.20.3.15`. Apa yang bisa kamu simpulkan dan lakukan?

- A. Tidak apa-apa, selama autentikasinya Kerberos dan bukan NTLM, berarti sah.
- B. Ini tanda pass-the-ticket atau overpass-the-hash: akun service dipakai dari host yang tidak wajar. Masukkan `svc_backup` ke daftar kredensial terkompromi, petakan semua tujuan yang pernah diaksesnya, dan batasi sumber login-nya saat containment.
- C. Hapus akun `svc_backup` sekarang juga supaya penyerang kehilangan akses.

<details><summary>Jawaban</summary>

B. Protokol Kerberos tidak membuktikan keabsahan; yang anomali adalah akun service dipakai dari workstation NOC, bukan dari server backup. Pola ini konsisten dengan pass-the-ticket atau overpass-the-hash. A keliru karena Kerberos justru yang dipakai overpass-the-hash. C berbahaya karena menghapus akun service mematikan backup dan menghilangkan jejak; yang benar adalah reset dua kali terkoordinasi dengan pemilik aplikasi dan membatasi sumber login. Lihat bagian 1.4, 1.5, dan 2.5.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Bambang Hartono (Manajer NOC) dalam tiga kalimat, kenapa satu akun `svc_backup` yang bukan domain admin tetap bisa menjadi masalah besar.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "`svc_backup` memang bukan admin seluruh domain, tetapi dia punya hak administrator lokal di beberapa server penting sekaligus, termasuk server file dan server backup. Artinya, kalau passwordnya bocor, penyerang bisa masuk ke semua server itu dan menyentuh data backup kita, tanpa perlu menjadi admin domain. Karena itu kami menilai dampaknya dari ke mana saja akun ini bisa masuk, bukan cuma dari namanya, dan kami batasi dari mana dia boleh dipakai."

Kesalahan yang sering muncul:
- Mengira "bukan domain admin" otomatis berarti risiko kecil.
- Memakai istilah seperti "pass-the-ticket" atau "blast radius" yang tidak dibutuhkan manajer NOC.
- Tidak menyebut data backup, yang justru membuat Bambang paham kenapa ini serius.

</details>

**6. Pertanyaan jebakan.** "Begitu kita beralih ke AES dan mematikan RC4, Kerberoasting tidak mungkin lagi, jadi deteksi 4769 bisa dimatikan." Benarkah?

<details><summary>Jawaban</summary>

Tidak. AES memperlambat pemecahan, tetapi password akun service yang lemah tetap bisa di-brute force walau tiketnya AES, dan penyerang bisa saja meminta tiket AES. Mematikan RC4 menghilangkan satu filter deteksi yang mudah, bukan serangannya; justru deteksi yang tidak bergantung etype (honeypot SPN dan anomali satu akun meminta banyak SPN) menjadi makin penting. Yang benar adalah mempertahankan deteksi 4769 dan menjadikan munculnya RC4 sebagai sinyal tambahan yang lebih tajam setelah lingkungan memakai AES. Lihat bagian 1.2, 1.7, dan 2.1.

</details>

**7. Interview question (English).** "During an incident you find Kerberoasting activity from a compromised workstation. Walk me through how you decide whether this has become a domain compromise."

<details><summary>Sample answer</summary>

"First I treat the account that issued the ticket requests and the host it came from as my scoping anchors. From the domain controller's 4769 events I map every SPN that account requested, and I check 4768 for pre-authentication type 0 in case AS-REP roasting happened in the same sweep, so I know which service accounts' passwords I must now assume are cracked. For each of those service accounts I assess blast radius: its SPNs, its group memberships, and crucially where it is a local administrator, because an account that isn't a domain admin can still be local admin across many servers. Then I look for actual use of those credentials: network logons from unusual source hosts, overpass-the-hash patterns like logon type 9 with the seclogo process, and any logon toward a domain controller or any use of a Domain Admins account. The line I draw is this: as long as there's no evidence of access to a DC, no domain admin account used from the compromised scope, and no sign of ticket forgery, I treat it as a credential-theft incident contained at the service-account level, and I don't reset krbtgt. If any of those triggers appears, I escalate to a domain-compromise procedure, which is where krbtgt rotation and a broader recovery come in. I write those triggers into the scope statement so the decision isn't re-argued at three in the morning."

What makes this answer strong: it anchors scoping on account and host, separates roasting from credential reuse, assesses blast radius beyond group names, names concrete event evidence, and draws an explicit, written line between a contained incident and domain compromise instead of resetting krbtgt reflexively.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | MITRE ATT&CK T1558.003 Kerberoasting | https://attack.mitre.org/techniques/T1558/003/ | primer | ATT&CK v20.0, teknik v1.3, diperbarui 2025-10-24; diakses 2026-10-15 | Tinggi. Mekanisme, deteksi 4769 RC4 dan volume, mitigasi (AES, password panjang, gMSA, batasi hak) |
| S2 | Microsoft Learn: 4768(S, F) A Kerberos authentication ticket (TGT) was requested | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768 | primer (dokumentasi vendor) | ms.date 2021-10-20, updated_at 2026-04-27; diakses 2026-10-15 | Tinggi. Field, Pre-Authentication Type 0, tabel etype, hanya di DC |
| S3 | Microsoft Learn: 4769(S, F) A Kerberos service ticket was requested | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769 | primer (dokumentasi vendor) | ms.date 2021-09-07, updated_at 2026-04-27; diakses 2026-10-15 | Tinggi. Field, Ticket Encryption Type 0x17/0x12, Client Address, rekomendasi monitoring |
| S4 | Microsoft Learn: event 4768 bagian Pre-Authentication types dan monitoring | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768 | primer (dokumentasi vendor) | sama dengan S2 | Tinggi. Pre-Auth Type 0 sebagai risiko; pre-auth normal type 2 |
| S5 | MITRE ATT&CK T1558.004 AS-REP Roasting | https://attack.mitre.org/techniques/T1558/004/ | primer | ATT&CK v20.0, teknik v1.2, diperbarui 2025-10-24; diakses 2026-10-15 | Tinggi. Mekanisme, deteksi 4768 pre-auth 0 dan RC4, mitigasi audit dan AES |
| S6 | MITRE ATT&CK T1550.002 Use Alternate Authentication Material: Pass the Hash | https://attack.mitre.org/techniques/T1550/002/ | primer | ATT&CK v20.0, subteknik v2.0, diperbarui 2026-05-12; diakses 2026-10-15 | Tinggi. NTLM logon type 3 anomali, overpass-the-hash, mitigasi UAC dan batasi akun |
| S7 | MITRE ATT&CK T1550.003 Pass the Ticket | https://attack.mitre.org/techniques/T1550/003/ | primer | ATT&CK v20.0, subteknik v2.0, diperbarui 2026-05-12; diakses 2026-10-15 | Tinggi. TGS vs TGT, deteksi 4769 tanpa 4768 pendahulu, silver/golden ticket disinggung |
| S8 | MITRE ATT&CK Detection Strategy DET0157 (Kerberoasting) | https://attack.mitre.org/detectionstrategies/DET0157/ | primer | ATT&CK v20.0; diakses 2026-10-15 | Tinggi. 4769 + RC4 + volume tidak wajar + baseline per akun |
| S9 | adsecurity.org: Detecting Kerberoasting Activity Part 2 (honeypot) | https://adsecurity.org/?p=3513 | komunitas | 2017-02-08; diakses 2026-10-15 | Sedang. Honeypot SPN, mempersempit 4769 ke 0x17, kecuali akun komputer; selaras dengan S1 dan S3 |
| S10 | Microsoft Security Blog: guidance to help mitigate Kerberoasting | https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/ | sekunder (vendor) | 2024-10-11; diakses 2026-10-15 | Tinggi. RC4 tanpa salt, AES bukan solusi tunggal, gMSA 120 char, dMSA, min 14 char, hapus SPN, Defender for Identity 2410 |
| S11 | Microsoft Learn: 4776(S, F) The computer attempted to validate the credentials for an account | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4776 | primer (dokumentasi vendor) | ms.date 2021-09-13, updated_at 2026-04-27; diakses 2026-10-15 | Tinggi. Validasi NTLM di DC, Source Workstation, kode error |
| S12 | Microsoft Learn: 4624(S) An account was successfully logged on | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624 | primer (dokumentasi vendor) | ms.date 2021-09-07, updated_at 2026-04-27; diakses 2026-10-15 | Tinggi. Logon Type 3 dan 9, Authentication Package, Package Name NTLM, Key Length |
| S13 | SigmaHQ: Successful Overpass the Hash Attempt | https://detection.fyi/sigmahq/sigma/windows/builtin/security/account_management/win_security_overpass_the_hash | komunitas | rule 2018-02-12, diperbarui 2021-11-27; diakses 2026-10-15 | Sedang. 4624 type 9 + seclogo + Negotiate; positif palsu runas /netonly |
| S14 | CISA/ASD: Detecting and Mitigating Active Directory Compromises | https://www.cisa.gov/resources-tools/resources/detecting-and-mitigating-active-directory-compromises | primer | revisi 2026-09-15 (asli September 2024); diakses 2026-10-15 | Tinggi untuk cakupan: 17 teknik serangan AD termasuk Kerberoasting dan AS-REP roasting. Isi rinci PDF tidak dikutip di Day ini |
| S15 | Microsoft Learn: Group Managed Service Accounts overview | https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-managed-service-accounts/group-managed-service-accounts/group-managed-service-accounts-overview | primer (dokumentasi vendor) | ms.date 2025-07-01; diakses 2026-10-15 | Tinggi. Password dikelola otomatis, selalu konfigurasi AES untuk MSA, WS2012+ |
| S16 | Microsoft Learn: Protected Users Security Group | https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group | primer (dokumentasi vendor) | ms.date 2025-06-27; diakses 2026-10-15 | Tinggi. AES only, tanpa NTLM/DES/RC4, TGT 240 menit, jangan tambahkan akun service atau komputer |
| S17 | Microsoft Learn: DeviceLogonEvents table (advanced hunting) | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicelogonevents-table | primer (dokumentasi vendor) | ms.date 2026-08-24; diakses 2026-10-15 | Tinggi. Kolom LogonType, Protocol, RemoteIP, konteks token lsass (TokenHasDomainAdminSid dll.) |
| S18 | Microsoft support: Manage Kerberos KDC usage of RC4 for service account ticket issuance (CVE-2026-20833) | https://support.microsoft.com/topic/1ebcda33-720a-4da8-93c1-b0496e1910dc | primer (dokumentasi vendor) | diperbarui 2026-04-14 (asli 2026-01-13); diakses 2026-10-15 | Tinggi. Default AES-SHA1, fase audit Jan 2026 dan enforcement Apr 2026, event 201-209, RC4DefaultDisablementPhase |

**Catatan sumber:** honeypot SPN di bagian 1.2 dan 2.1 bersumber komunitas (adsecurity.org [S9]) tetapi mekanisme dasarnya selaras dengan field 4769 di dokumentasi Microsoft [S3]; pola overpass-the-hash (logon type 9, seclogo) di bagian 1.4 dan 2.3 bersumber komunitas (Sigma [S13]) dan ditandai demikian, dengan positif palsu `runas /netonly` disebut eksplisit. Nama field hasil parsing di query (`Ticket_Encryption_Type`, `Pre_Authentication_Type`, `Account_Name`) bergantung add-on Splunk dan versi event (4768 dan 4769 versi 2 sejak Januari 2025 [S2][S3]); cocokkan dengan field di deployment-mu. Pemisahan antara insiden tingkat akun service dan kompromi domain, termasuk keputusan tidak mereset krbtgt, adalah susunan catatan ini dari sumber yang disebut dan dari keputusan Day 06, bukan daftar resmi satu sumber. Bahwa lisensi Microsoft 365 E3 tidak mencakup Defender for Identity perlu dicek di halaman lisensi Microsoft yang berlaku. Semua isi PT JAB, termasuk nomor insiden, akun, host, dan hasil query, adalah contoh fiktif.
