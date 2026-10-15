---
day: 13
title: 'Review Minggu 2: insiden per lapis kepercayaan dari email sampai domain, peta konsep, glosarium, dan lab gabungan'
researched_on: 2026-10-15
versions_checked: 'RFC 7489 dan RFC 9989 DMARC (Mei 2026); Microsoft Learn halaman yang dirujuk Day 08-12 (ms.date 2023-07-10 sampai 2026-10-01), termasuk Anti-spam message headers, Zero-hour auto purge, Respond to a compromised email account, MailItemsAccessed, audit log retention, Entra data retention, Refresh tokens, Continuous access evaluation, Token theft playbook, Protected Users, Entra Connect accounts dan prerequisites, AD Forest Recovery; Microsoft support CVE-2026-20833 (diperbarui 14 April 2026) dan KB5014754 (diperbarui 10 September 2025); MITRE ATT&CK v20; CISA CM0050 (Maret 2025); CISA AA20-245A (revisi 24 September 2020); FBI IC3 I-091124-PSA (11 September 2024); CISA, NSA, FBI, MS-ISAC Phishing Guidance (Oktober 2023); SpecterOps Certified Pre-Owned (Juni 2021)'
---

# Day 13: Review Minggu 2, insiden per lapis kepercayaan dari email sampai domain

Cakupan: ringkasan Day 08-12 (phishing, BEC dan mailbox, identitas Entra ID, serangan AD tingkat akun, serangan AD tingkat domain), peta konsep lima lapis kepercayaan, empat benang yang ditelusuri lewat `INC-2026-020` sampai `INC-2026-024`, glosarium, dan lab gabungan berupa paket insiden, tabletop mini, dan uji lisan.

## Ide inti

Minggu pertama membahas siklus IR: urutan tahap, siapa memutuskan, dan kapan sebuah tahap boleh dianggap selesai. Minggu kedua memakai siklus yang sama untuk lima jenis insiden, dan kelimanya ternyata satu pola yang diulang di lapis yang berbeda: email, mailbox, identitas cloud, akun AD, dan domain. Di setiap lapis, penyerang yang berhasil masuk memegang atau menanam sesuatu yang tidak ikut hilang saat password diganti: salinan email yang belum diklik, inbox rule dan consent aplikasi, session cookie dan metode MFA, hash dan tiket Kerberos, sampai hash `krbtgt` dan sertifikat. Karena itu empat pertanyaan yang sama diajukan di setiap insiden: apa yang dipegang penyerang, apa yang ia tanam supaya bisa kembali, sampai mana itu membawanya, dan log mana yang bisa membuktikan ketiganya. Makin dalam lapisnya, makin besar rahasia yang harus diganti, makin besar gangguan layanannya, dan makin tinggi keputusan bisnis yang dibutuhkan.

Kamu sudah mengenal pola ini dari NOC. Saat akun TACACS seorang engineer bocor, mencabut akses akun itu belum memutus sesi yang sedang terbuka; untuk itu NOC mengirim Disconnect-Message ke perangkat, sama seperti revoke sessions di Entra ID. Filter alarm yang sempat dipasang diam-diam di NMS tetap bekerja walau password sudah diganti, seperti inbox rule. Kunci API read-only yang terlanjur diberikan ke portal "vendor" tidak ikut hangus, seperti consent OAuth. Dan bila yang tersalin adalah kunci master yang menandatangani semua kartu akses gedung, mengganti kartu satu orang tidak ada artinya; kunci masternya yang harus diganti, dua kali, dengan semua kartu yang beredar ikut gugur. Itulah `krbtgt`. Bedanya dengan NOC: semua "kunci" itu bisa disalin tanpa jejak di perangkat yang memakainya, sehingga jawaban jujur tentang scope sering berupa batas bawah, bukan angka pasti.

```
lapis kepercayaan            insiden contoh     yang bertahan setelah ganti password
-----------------------------------------------------------------------------------
1 email          (Day 08)    INC-2026-020       salinan pesan, kredensial yang terkirim
2 mailbox        (Day 09)    INC-2026-021       inbox rule, forwarding, consent OAuth
3 identitas cloud(Day 10)    INC-2026-022       cookie dan token, metode MFA asing
4 akun AD        (Day 11)    INC-2026-023       hash, tiket Kerberos, hak lokal akun
5 domain AD      (Day 12)    INC-2026-024       hash krbtgt, sertifikat, akun Tier 0
-----------------------------------------------------------------------------------
di setiap lapis:  apa yang dipegang? | apa yang ditanam? | sampai mana? | log apa?
makin dalam:      rahasia makin besar -> gangguan layanan makin besar -> A makin tinggi
siklus tetap Day 01-06: declare -> scoping -> bukti -> containment -> eradication -> recovery
```

Situasi yang dipakai di Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan sekitar 1.200 karyawan, Microsoft 365 E3 dengan Defender for Office 365 Plan 2 dan Defender for Endpoint Plan 2, dan AD on-premises `corp.jab.example` yang disinkronkan ke Entra ID. Senin, 23 November 2026 pagi, setelah perbaikan jalur serangan `INC-2026-024` selesai Jumat lalu dan pemantauan ketatnya masih berjalan, Direktur Teknologi Hendra Wijaya menulis ke SOC lead dan incident commander (IC) Dimas Prasetyo:

> "Dim, dalam sebulan terakhir kita punya lima insiden, dari 020 sampai 024. Kamis nanti saya harus menjelaskannya di rapat direksi yang membahas rencana keamanan 2027. Tolong siapkan untuk saya: apa yang terjadi di setiap insiden dalam satu kalimat, seberapa parah, dan siapa yang memutuskan langkah besarnya. Apakah ini lima kejadian terpisah atau ada pola yang sama? Saya juga mau paham kenapa di hampir setiap insiden 'ganti password' ternyata tidak cukup. Kenapa kadang password langsung direset detik itu juga, dan kadang kalian menunggu jam H, sampai helpdesk dua kali disebut 'terlalu cepat'? Terakhir, apa yang selama ini tidak bisa kita lihat, dan perbaikan apa yang sudah diusulkan tim dari kelima insiden itu?"

Pesan itu memuat lima permintaan:

1. Satu kalimat per insiden, tingkat keparahan, dan pemilik keputusan besar.
2. Apakah kelimanya terpisah atau satu pola.
3. Kenapa ganti password hampir tidak pernah cukup.
4. Kapan password direset segera dan kapan menunggu jam H.
5. Apa yang tidak terlihat, dan perbaikan apa yang sudah diusulkan.

Permintaan 1 dijawab di bagian 1.7, permintaan 2 di bagian 1.6 dan 1.7, permintaan 3 di bagian 1.8, permintaan 4 di bagian 1.9, dan permintaan 5 di bagian 1.10. Bagian 1.1 sampai 1.5 meringkas Day 08-12 sebagai bahannya, dan bagian 2-4 memintamu menerapkan pola yang sama pada kasus lanjutan dan inject tabletop.

**Kapan relevan:** sebelum masuk Day 14 dan seterusnya (ransomware, server Linux, dan cloud memakai empat pertanyaan yang sama), sebelum menangani insiden identitas pertama sebagai L2, dan sebelum interview yang menanyakan "bagaimana kamu memastikan penyerang benar-benar keluar dari akun atau domain".
**Kapan bukan jawaban:** review ini tidak menambah aturan atau fakta baru. Bila ada yang terasa baru, kembali ke Day asalnya. Review ini juga tidak memutuskan anggaran; daftar perbaikan di bagian 1.10 adalah usulan yang sudah tercatat di masing-masing insiden, dan keputusannya tetap di executive sponsor.

## 1. Ringkasan, peta konsep, dan glosarium

### 1.1 Day 08: analisis email dan phishing

- Phishing datang sebagai kampanye. Urutannya: asal pesan dari header dan autentikasi, pemetaan semua penerima dan siapa yang berinteraksi, lalu purge dan penanganan pengguna yang terkena (Day 08 bagian Ide inti).
- Header `Received` dibaca dari atas dan hanya dipercaya sampai hop pertama yang ditulis server milik sendiri atau penyedia email. Envelope (`MAIL FROM`, Return-Path) bisa berbeda dari `From` yang dilihat pengguna [S3].
- SPF memeriksa IP terhadap domain envelope, DKIM membuktikan domain `d=` dan isi yang tidak berubah, dan DMARC meminta salah satunya lolos dengan domain yang aligned ke `From`. DMARC tidak menangani nama tampilan dan lookalike domain [S1]. RFC 9989 (Mei 2026) menggantikan RFC 7489 dan menjadikan DMARC Proposed Standard [S2].
- Tiga tingkat paparan: menerima, klik, dan mengirim kredensial. `POST` ke halaman form di log proxy yang mendekripsi TLS membedakan klik dari pengiriman kredensial (Day 08 bagian 1.4).
- Membuka URL phishing dari jaringan kantor memberi tahu penyerang; URL yang berisi identitas penerima tidak boleh dikirim ke layanan scan publik. Lampiran dinilai dari hash dulu (Day 08 bagian 1.5).
- ZAP hanya bekerja untuk pesan dalam 48 jam terakhir, dan pada default anti-spam policy verdict phishing hanya memindahkan pesan ke Junk [S7]. Remediation di Threat Explorer (Plan 2) menjalankan soft delete atau hard delete dengan status per pesan di Action center [S5]; tanpa Plan 2, search and purge di Purview dibatasi 10 item per mailbox per tindakan [S6].
- Purge tidak membatalkan klik. Pengguna yang mengirim kredensial diserahkan ke penanganan akun, dan untuk credential phishing reset serta revoke sessions dijalankan segera (Day 08 bagian 1.7) [S8].

### 1.2 Day 09: BEC dan kompromi mailbox M365

- BEC menumpang percakapan pembayaran yang sah lewat akun email asli [S13]. Jalur yang paling sering: AiTM mencuri session cookie setelah MFA, lalu penyerang mencari thread pembayaran, membuat inbox rule penyembunyi, dan membalas thread itu [S14].
- DMARC `p=reject` pada `jab.example` justru menjelaskan kenapa penyerang membobol mailbox asli: email dari mailbox Fitri lolos autentikasi seperti email sah (Day 09 bagian 1.1).
- Unified Audit Log punya tiga batas: aksi yang tidak dicatat secara default, misalnya `SearchQueryInitiated` (Day 09 bagian 1.2); jeda 30 menit sampai 24 jam [S12]; dan masa simpan menurut lisensi pengguna, Audit Standard 180 hari untuk log sejak 17 Oktober 2023 [S11].
- Inbox rule dan forwarding tersimpan di server, sehingga tidak hilang saat password diganti, laptop diganti, atau Outlook diinstal ulang (Day 09 bagian 1.3). Aturan tersembunyi dan forwarding level mailbox ikut dicek [S9].
- Consent OAuth memberi aplikasi akses setingkat akun; reset password dan MFA tidak efektif terhadapnya [S12].
- `MailItemsAccessed` membedakan sync (per folder, seluruh isi folder dianggap terkompromi) dan bind (per email, `InternetMessageId`). Angka yang terbukti adalah batas bawah: bila akses tidak pasti, anggap data terkompromi [S10].
- Enam langkah Microsoft untuk akun yang terkompromi: disable atau reset, revoke sessions, tinjau metode MFA, aplikasi, peran admin, serta forwarding dan inbox rule [S9]. PT JAB menjalankannya serentak di jam H setelah bukti diekspor.
- Uang, pelanggan, dan data pribadi punya pemilik keputusan sendiri: Keuangan dan bank untuk dana, kanal kedua (telepon di kontrak) untuk pelanggan, DPO dan Legal untuk UU PDP Pasal 46 (Day 09 bagian 1.7).

### 1.3 Day 10: kompromi identitas Entra ID

- Yang dipakai mengakses layanan Microsoft 365 adalah token, bukan password. Password dan MFA hanya diperiksa saat token diterbitkan, sehingga AiTM tidak mengalahkan MFA, tetapi mengambil hasilnya [S14][S19].
- Sign-in log terbagi interactive dan non-interactive; pemutaran ulang token banyak tercatat di non-interactive, karena sign-in itu dilakukan aplikasi memakai token tanpa faktor baru [S15]. Entra ID menyimpan log 7 hari di Free dan 30 hari di P1 atau P2, dan upgrade lisensi tidak mengembalikan data yang sudah lewat [S16]. PT JAB (P1) mengalirkan log ke Splunk dan menyimpannya satu tahun.
- Detail sebagian besar deteksi risiko butuh P2; tenant tanpa P2 hanya melihat "Additional risk detected" [S20].
- Session ID yang sama dari jaringan lain, tanpa `deviceId`, adalah indikator AiTM yang lebih kuat daripada lokasi negara (Day 10 bagian 1.3).
- Ganti password oleh pengguna tidak mencabut cookie dan token yang tidak berbasis password; hanya pencabutan semua refresh token oleh admin yang mencabut semua kelas [S17]. CAE memperpendek celah untuk layanan yang mendukungnya, dengan jeda sampai 15 menit dan token berumur sampai 28 jam untuk klien yang mendukung CAE [S18].
- Persistence di identitas: metode MFA baru, perangkat terdaftar, inbox rule dan forwarding, serta consent aplikasi [S19]. Pencabutan diverifikasi di sign-in log, bukan dari keluaran perintah (Day 10 bagian 1.4).
- Conditional Access yang menutup jalur AiTM adalah syarat yang tidak bisa dipenuhi token curian dari VPS, misalnya perangkat compliant, kebijakan registrasi security info [S21], dan authentication strength phishing-resistant untuk admin, bukan prompt MFA yang lebih sering (Day 10 bagian 1.7).

### 1.4 Day 11: serangan AD bagian 1

- Kerberoasting meminta tiket layanan untuk SPN akun service lalu memecahkannya offline, sehingga DC hanya melihat permintaan tiket yang sah; jejaknya 4769 dengan etype `0x17` dan satu akun meminta banyak SPN [S23][S26].
- AS-REP roasting menyasar akun dengan pre-authentication dimatikan; jejaknya 4768 dengan Pre-Authentication Type `0` [S24].
- Pass-the-hash dan pass-the-ticket tidak memecahkan apa pun, tetapi memakai ulang hash atau tiket. Jejaknya ada di host dan DC: 4624 logon type 3 dengan NTLM, 4776 di DC, dan pemakaian tiket tanpa 4768 pendahulu [S25] (Day 11 bagian 1.4).
- Password yang dicrack berbahaya sejauh hak akunnya. Blast radius akun service dipetakan dari SPN, keanggotaan grup, hak lokal di server, dan riwayat pemakaian sah (Day 11 bagian 1.5).
- Akun service dirotasi bersama pemilik aplikasi, direset dua kali, dan dibatasi sumber login-nya. Perbaikan jangka panjang: gMSA atau dMSA, AES, hapus SPN yang tidak perlu [S26]. Protected Users untuk akun admin interaktif, bukan untuk akun service [S27].
- Reset krbtgt tidak dibutuhkan hanya karena akun service di-roast; krbtgt relevan setelah penyerang bisa memalsukan TGT (Day 11 bagian 1.6).
- Tanpa Defender for Identity, deteksi bertumpu pada event log DC di Splunk dan EDR. Perubahan default RC4 KDC (fase audit 13 Januari 2026, enforcement 14 April 2026) mengubah baseline: RC4 makin menjadi anomali [S28].

### 1.5 Day 12: serangan AD bagian 2

- DCSync meniru replikasi dari host yang bukan DC dan mengambil hash semua akun, termasuk `krbtgt` [S29]. Pemegang hak replikasi yang sah: akun komputer DC dan akun konektor Entra Connect untuk password hash sync [S33].
- Deteksinya 4662 dengan GUID hak replikasi di DC, dikorelasikan ke 4624 lewat Logon ID untuk mendapat IP. Event itu hanya ada bila Audit Directory Service Access dan SACL objek domain aktif [S32]. Pengecualian ditulis per pasangan akun dan IP, bukan per akun (Day 12 bagian 1.2).
- Template AD CS yang salah konfigurasi (ESC1) membiarkan pengguna biasa meminta sertifikat atas nama admin [S38]. Sertifikat tetap bisa dipakai setelah password direset, sehingga harus dicabut [S31]; golden certificate dari private key CA curian tidak bisa dicabut sama sekali [S38].
- Golden ticket memalsukan TGT dengan hash krbtgt; silver ticket memalsukan tiket satu layanan tanpa menyentuh KDC (Day 12 bagian 1.4) [S30]. Analitik deteksinya heuristik, jadi "tidak ditemukan" bukan "tidak ada" (Day 12 bagian 1.4).
- Reset krbtgt dua kali dengan replikasi terverifikasi dan jeda minimal 10 jam sebagai jalur standar [S34][S36][S37]; jalur cepat hanya dengan pemicu tertulis (Day 12 bagian 1.5). Akun Tier 0 dan akun konektor dirotasi sebelum krbtgt.
- Server Entra Connect adalah Tier 0; penyerang yang menguasainya bisa memanipulasi pengguna di Entra ID [S40].
- Domain yang dianggap dikuasai tidak otomatis dibangun ulang. Pilihan eviction terkoordinasi atau pemulihan forest dari backup ditentukan dari apakah jalur, waktu, dan perubahan penyerang diketahui, kondisi DC dan CA, dan kesiapan prosedur [S35].

### 1.6 Peta konsep

Peta berikut menggabungkan diagram Day 08-12 dalam satu gambar. Pakai sebagai satu-satunya bantuan saat uji lisan di bagian 2-4. Baris adalah lapis kepercayaan; kolom menjawab empat pertanyaan dari Ide inti.

```
LAPIS            DIPEGANG / DITANAM PENYERANG        DICABUT DENGAN                      LOG UTAMA
---------------------------------------------------------------------------------------------------------
1 Email          salinan pesan di mailbox lain,      purge soft delete + blok dengan     message trace, Threat
  (Day 08)       klik, kredensial terkirim (POST)    log; reset+revoke pengirim POST     Explorer, proxy, DNS,
                                                                                         UrlClickEvents
2 Mailbox        sesi AiTM, inbox rule, forwarding,  disable akun, revoke, cabut         UAL (jeda s.d. 24 jam),
  (Day 09)       consent OAuth, app password         consent, disable rule, hapus MFA    MailItemsAccessed
3 Identitas      cookie dan refresh token, metode    revoke sessions (semua kelas),      sign-in interactive +
  cloud (Day 10) MFA asing, perangkat, consent       hapus metode/perangkat, CA          non-interactive, audit
4 Akun AD        password dicrack, hash NTLM,        reset 2x, batasi sumber login,      4768, 4769, 4624, 4776,
  (Day 11)       tiket Kerberos, hak lokal           gMSA/AES, hapus SPN                 EDR DeviceLogonEvents
5 Domain AD      hash semua akun (DCSync), krbtgt,   rotasi Tier 0 + konektor, krbtgt    4662 + 4624, 4768 tipe
  (Day 12)       sertifikat, jalur ke Tier 0         2x, cabut sertifikat, tutup jalur   15/16/17, DB CA, 4769
---------------------------------------------------------------------------------------------------------
NAIK LAPIS bila: kredensial terkirim -> cek identitas | akun admin tersentuh -> cek AD
                 akses ke DC / hak replikasi / sertifikat Tier 0 -> domain dianggap dikuasai
SIKLUS TETAP (Day 01-06): scope cukup -> bukti -> containment serentak -> verifikasi -> eradication
```

Tiga hal yang terlihat bila peta dibaca dari atas ke bawah:

- **Setiap lapis punya "naik lapis" sendiri.** Kredensial yang terkirim di lapis email membawa insiden ke lapis identitas (Day 08 bagian 1.7). Akun admin milik korban membawa pertanyaan ke AD (Day 10 bagian 1.6). Akses ke DC atau tanda pemalsuan tiket membawa insiden akun AD ke penanganan kompromi domain (Day 11 bagian 2.6).
- **Kolom "dicabut dengan" selalu lebih dari satu tindakan.** Itu sebabnya containment di semua lapis dijalankan serentak, sama dengan prinsip jam H di Day 05 bagian 1.7.
- **Kolom log berbeda per lapis.** Analyst yang hanya membuka satu konsol akan melihat satu lapis saja, dan insiden yang menyeberang lapis tampak selesai padahal belum.

### 1.7 Lima insiden dalam satu tabel

Tabel berikut menjawab permintaan pertama dan kedua Hendra. Semua waktu WIB dan semua fakta diambil dari Day 08-12; kolom terakhir menunjuk bagian tempat fakta itu ditulis. Baca per baris: kalimat ringkas, jalur severity, siapa memutuskan, dan bentuk containment.

| Insiden | Satu kalimat | Severity | Pemilik keputusan besar | Containment | Asal |
|---|---|---|---|---|---|
| `INC-2026-020` (Rabu 2026-10-21) | Kampanye phishing kredensial ke 34 mailbox dari lookalike domain; satu pengguna (`lestari.putri`) mengirim password | SEV-3 sejak 09:40; ditinjau ulang setelah hasil sign-in Lestari | Dimas (IC); technical lead Rudi | Blok domain, IP, dan pengirim 09:50 sampai 09:52; reset dan revoke Lestari 09:55; soft delete 10:05 (32 berhasil, 2 sudah dihapus pengguna) | Day 08 bagian 1.4, 2.5, 2.6 |
| `INC-2026-021` (Senin 2026-10-26) | Mailbox `fitri.handayani` diambil alih lewat AiTM, dipakai mengirim tiga permintaan rekening baru ke pelanggan korporat | SEV-2 sejak 09:50 | Dimas (IC); Hendra untuk dampak pelanggan; Keuangan dan bank untuk dana; DPO dan Legal untuk data pribadi | Jam H 11:45: disable akun, revoke, cabut consent, disable inbox rule, hapus MFA asing | Day 09 bagian 1.7, 2.6 |
| `INC-2026-022` (Kamis 2026-10-29) | Session cookie `rina.wulandari` dicuri lewat AiTM, penyerang mendaftarkan metode MFA telepon dan mencoba `adm.rina` (gagal) | SEV-2 sejak 08:50; tetap SEV-2 setelah penilaian `adm.rina` | Dimas (IC); L2 Sari | Satu jendela 09:30 dari `jkt-bastion01`: revoke sessions, hapus metode telepon, reset kedua Rina, reset dua kali dan revoke `adm.rina` | Day 10 bagian 1.6, 2.4, 2.5 |
| `INC-2026-023` (Senin 2026-11-02) | Dari `JKT-WS-0424` milik `bayu.firmansyah`, penyerang melakukan Kerberoasting dan AS-REP roasting, lalu memakai `svc_backup` ke `JKT-BKP01` dan `JKT-FS01` | SEV-3 11:50, naik SEV-2 12:55 setelah `svc_backup` dipakai dari host di luar baseline | Dimas (IC); technical lead Rudi | Jam H 13:30: isolasi host, reset dua kali dan pembatasan sumber login `svc_backup`, tangani `svc_scanner`; krbtgt tidak direset | Day 11 bagian 2.3, 2.5, 2.6 |
| `INC-2026-024` (Senin 2026-11-16) | Dari workstation helpdesk `teguh.wibowo`, penyerang memakai template AD CS yang salah konfigurasi untuk sertifikat atas nama `adm.agung`, lalu DCSync | SEV-1 sejak 02:05; domain dianggap dikuasai | Dimas (IC) untuk containment malam itu; Hendra memilih eviction terkoordinasi (15:15) dan mendelegasikan jalur cepat krbtgt ke IC dengan pemicu | Isolasi host, tarik template, cabut sertifikat Senin dini hari; jam H eviction Selasa 2026-11-17 20:00 dengan reset krbtgt 20:20 dan Rabu 08:00 | Day 12 bagian 2.2, 2.4, 2.5 |

Jawaban untuk "lima kejadian terpisah atau satu pola" harus dipisah menjadi dua klaim yang berbeda tingkat keyakinannya:

- **Sebagai insiden, kelimanya ditangani terpisah.** Setiap insiden punya titik masuk, infrastruktur, dan akun yang berbeda di Day asalnya, dan catatan kelima insiden tidak memuat bukti yang menghubungkan pelakunya. Menyatakan "satu pelaku" tanpa bukti sama kelirunya dengan menulis hipotesis sebagai fakta (Day 03 bagian 1.3).
- **Sebagai pola, kelimanya sama.** Semuanya menyerang identitas, bukan server. BEC di `INC-2026-021` tidak membutuhkan malware di laptop korban, perangkat Rina di `INC-2026-022` tidak menunjukkan tanda mencurigakan, dan di `INC-2026-023` dan `INC-2026-024` yang dicuri adalah bentuk kredensial (hash, tiket, sertifikat). Pola ini yang relevan untuk rapat direksi.

### 1.8 Benang pertama: apa yang bertahan setelah ganti password

Permintaan ketiga Hendra dijawab dengan satu tabel yang menelusuri kelima insiden. Kolom "Bukti di insiden" menunjukkan bahwa ini bukan teori: di setiap insiden ada akses yang terbukti atau dianggap bertahan setelah password diganti.

| Lapis | Yang bertahan | Kenapa tidak ikut hilang | Bukti di insiden | Asal |
|---|---|---|---|---|
| Email | Kredensial yang sudah terkirim, salinan pesan di Junk | Purge menghapus kesempatan klik berikutnya, bukan akibat klik sebelumnya; ZAP default hanya ke Junk [S7] | Hadi membuka pesan dari folder Junk pukul 09:48, 26 menit setelah ZAP | Day 08 bagian 1.6 |
| Mailbox | Consent OAuth, inbox rule | Aplikasi memegang izinnya sendiri [S12]; aturan tersimpan di server | "Mail Sync Helper" masih membaca email Fitri pukul 09:58, delapan belas menit setelah reset helpdesk 09:40 | Day 09 bagian 1.4 |
| Identitas cloud | Cookie dan token yang tidak berbasis password, metode MFA asing | Ganti password oleh pengguna tidak mencabut kelas token itu [S17]; menambah metode MFA tidak otomatis hilang [S19] | Metode telepon `+1 555 0163` terdaftar sejak Rabu 17:04:55, tetap ada setelah reset helpdesk 08:45 | Day 10 bagian 1.4, 1.5 |
| Akun AD | Hash password lama, tiket Kerberos yang sudah terbit, hak lokal akun | Hash lama bisa dipakai pass-the-hash sampai direset dua kali [S22][S25]; tiket berlaku sampai kedaluwarsa (Day 05 bagian 1.5) | `svc_backup` dipakai dengan pass-the-ticket ke dua server; reset dua kali ditambah pembatasan sumber login | Day 11 bagian 1.6, 2.5 |
| Domain AD | Hash `krbtgt`, sertifikat atas nama admin, akun Tier 0 dan konektor | TGT palsu tidak bergantung pada password akun yang disamar [S30]; sertifikat berlaku sampai dicabut atau kedaluwarsa [S31] | Sertifikat 1187 atas nama `adm.agung` dicoba lagi pukul 03:02:47 dan ditolak `0x3E` karena sudah dicabut | Day 12 bagian 1.3, 1.4, 2.2 |

Pelajaran dari tabel ini untuk direksi: "password sudah diganti" adalah jawaban untuk satu baris saja. Pernyataan yang benar setelah containment berbentuk daftar: apa yang dicabut, bagaimana diverifikasi, dan apa yang belum bisa dipastikan. Itulah sebabnya checklist pemulihan akun di Day 10 bagian 2.8 berisi sembilan langkah dengan kolom verifikasi, bukan satu langkah reset.

### 1.9 Benang kedua: reset segera atau menunggu jam H

Permintaan keempat Hendra menyentuh aturan yang terlihat bertentangan. Prinsipnya satu: reset kredensial adalah tindakan containment, dan waktunya ditentukan oleh apakah kredensial itu satu-satunya akses penyerang yang diketahui.

| Insiden | Keputusan waktu | Alasan | Asal |
|---|---|---|---|
| `INC-2026-020` | Reset dan revoke Lestari segera, 09:55 | Akses penyerang yang diketahui hanya password yang baru dicuri; setiap menit penundaan adalah menit password itu bisa dipakai | Day 08 bagian 1.7 |
| `INC-2026-021` | Reset helpdesk 09:40 dicatat sebagai terlalu dini; semua tindakan lain di jam H 11:45 | Penyerang sudah punya jalan lain (consent aplikasi, inbox rule, sesi), sehingga reset sendirian hanya memberi tahu penyerang, kesalahan yang sama dengan reset dini di Day 05 bagian 1.5 [S37] | Day 09 bagian 1.4, 2.6 |
| `INC-2026-022` | Reset helpdesk 08:45 sebelum IC; containment identitas lengkap di satu jendela 09:30 | Reset saja tidak mencabut semua kelas token dan tidak menghapus metode MFA asing; revoke dijalankan eksplisit [S17] | Day 10 bagian 1.4, 2.4 |
| `INC-2026-023` | Reset `svc_backup` dua kali di jam H 13:30, bersama pemilik backup | Akun service dipakai aplikasi; kredensial baru harus dipasang di agen pada saat yang sama, dan sumber login dibatasi | Day 11 bagian 2.5 |
| `INC-2026-024` | Rotasi semua akun Tier 0 dan konektor sebelum reset krbtgt; krbtgt dua kali dengan jeda 11 jam 40 menit | Penyerang yang masih memegang hash admin bisa meminta TGT sah baru bila krbtgt direset lebih dulu; jeda mengikuti umur tiket [S34][S36] | Day 12 bagian 1.5, 2.5 |

Dua catatan yang perlu disampaikan ke direksi:

- **"Terlalu cepat" bukan kritik ke helpdesk, tetapi ke prosedur.** Di `INC-2026-021` dan `INC-2026-022`, helpdesk menjalankan permintaan pengguna sebelum IC memberi instruksi. Day 09 bagian 2.6 mencatat ini sebagai dasar perubahan prosedur helpdesk: reset untuk akun yang sedang diinvestigasi hanya dilakukan dalam jam H.
- **Segera dan serentak tidak bertentangan.** Di `INC-2026-020` jam H-nya adalah "sekarang", karena scope akses penyerang sudah lengkap: satu password. Di insiden lain scope-nya lebih dari satu jalan, sehingga semua jalan ditutup bersamaan.

### 1.10 Benang ketiga: yang tidak terlihat, dan perbaikan yang sudah diusulkan

Permintaan terakhir Hendra punya dua bagian. Tabel pertama berisi batas visibilitas yang muncul di Day 08-12. Baca kolom "Akibat di insiden": batas visibilitas selalu harus ditulis di scope statement, bukan disimpan sebagai pengetahuan analyst.

| Batas | Sumber | Akibat di insiden | Asal |
|---|---|---|---|
| Entra ID P1: log 30 hari, detail risiko butuh P2 | [S16][S20] | Tanpa salinan di Splunk, kompromi yang ditemukan di minggu kelima tidak punya sign-in log; ID Protection tidak memberi detail AiTM | Day 10 bagian 1.2 |
| Audit M365: jeda sampai 24 jam, masa simpan Standard 180 hari | [S11][S12] | Pencarian audit `INC-2026-021` diulang 24 jam kemudian sebelum validasi dianggap lengkap | Day 09 bagian 1.2, 2.6 |
| Aksi mailbox yang tidak dicatat default | Day 09 bagian 1.2 | Tidak adanya `SearchQueryInitiated` tidak membuktikan penyerang tidak mencari kata "rekening" | Day 09 bagian 1.2 |
| Tanpa Defender for Identity | Day 11 bagian 1.7 | Deteksi serangan AD dibangun sendiri dari 4768, 4769, 4776, honeypot SPN, dan EDR | Day 11 bagian 1.7 |
| Audit Directory Service Access dan audit filter CA | [S32] | 4662 hanya ada bila audit dan SACL aktif; audit filter `JKT-CA01` belum aktif sejak dipasang, sehingga penerbitan sertifikat dibaca dari database CA | Day 12 bagian 1.2, 1.3 |
| Safe Links hanya untuk tautan yang dibungkus; reputasi domain baru | Day 08 bagian 1.4 | Klik Rina ke domain AiTM yang baru didaftarkan diizinkan | Day 08 bagian 1.4; Day 10 bagian 1.1 |

Tabel kedua berisi perbaikan yang sudah diusulkan di masing-masing insiden. Ini bukan daftar baru; setiap baris sudah tercatat di Day asalnya, dan statusnya ditulis apa adanya.

| Insiden | Usulan | Status di catatan insiden | Asal |
|---|---|---|---|
| `INC-2026-020` | Tindakan verdict phishing di anti-spam policy diubah dari Junk ke karantina | Dibawa ke review insiden | Day 08 bagian 2.6 |
| `INC-2026-021` | Reset untuk akun yang diinvestigasi hanya di jam H; prosedur helpdesk diubah | Dicatat sebagai pelajaran di update 13:30 | Day 09 bagian 2.6 |
| `INC-2026-022` | Kebijakan CA-10 (registrasi security info), CA-11 (admin phishing-resistant dari `JKT-JUMP01`), CA-12 (M365 dari perangkat terkelola), CA-13 (token protection pilot), semuanya report-only dulu | Usulan; lisensi P2 untuk kebijakan berbasis risiko dicatat sebagai keputusan anggaran executive sponsor | Day 10 bagian 1.7, 2.6 |
| `INC-2026-023` | `svc_backup` ke gMSA, hentikan RC4 untuk akun service, hapus SPN tidak perlu, keluarkan dari local Administrators yang tidak perlu, akun admin interaktif ke Protected Users | Masuk after-action | Day 11 bagian 2.5 |
| `INC-2026-024` | Template baru tanpa "Supply in the request", akun Tier 0 di OU terpisah, pembatasan logon Tier 0, admin lokal `JKT-SYNC01` hanya Tier 0, audit CA aktif, latihan pemulihan forest di lab | Perbaikan jalur selesai Kamis dan Jumat; latihan pemulihan forest sebelum 2026-12-31 | Day 12 bagian 2.4, 2.6 |

Satu pola yang bisa dibawa Hendra ke direksi: sebagian usulan menutup jalan yang dipakai penyerang (template `JAB-WiFi-User`, tindakan anti-spam policy), sebagian menutup celah deteksi (audit CA, kebijakan CA report-only), dan sebagian memperbaiki prosedur (reset oleh helpdesk, latihan pemulihan forest). Memprioritaskannya adalah keputusan executive sponsor; tugas tim adalah memastikan setiap usulan punya asal yang bisa ditelusuri ke insiden.

### 1.11 Glosarium

Definisi di bawah ditulis dengan kata sendiri untuk keperluan belajar, bukan definisi resmi. Kolom terakhir adalah pasangan yang paling sering membuat jawaban interview keliru.

| Istilah | Penjelasan singkat | Sering tertukar dengan |
|---|---|---|
| Envelope (`MAIL FROM`) | Alamat yang dipakai server saat transaksi SMTP, tampil sebagai Return-Path | Alamat `From` yang dilihat pengguna |
| Header `Received` | Jejak setiap server yang menerima pesan, ditambahkan di atas | Bukti asal pesan (hop bawah bisa dipalsukan) |
| SPF | Daftar IP yang boleh mengirim untuk domain envelope | Bukti pengirim sah |
| DKIM | Tanda tangan domain `d=` atas header dan isi | Bukti domain `From` asli |
| DMARC dan alignment | Kebijakan pemilik domain `From`; SPF atau DKIM harus lolos dengan domain yang sejajar | Perlindungan dari lookalike domain |
| Lookalike domain | Domain mirip milik organisasi | Spoofing domain organisasi sendiri |
| Kampanye phishing | Banyak pesan dengan ciri sama ke banyak penerima | Satu laporan satu insiden |
| ZAP | Tindakan otomatis atas pesan yang belakangan dinilai berbahaya, 48 jam | Purge penuh oleh admin |
| Purge (soft dan hard delete) | Menarik salinan email dari banyak mailbox oleh admin | Membatalkan klik yang sudah terjadi |
| Detonation | Menjalankan lampiran atau URL di sandbox | Membuka lampiran di laptop analyst |
| BEC | Penipuan transfer dana lewat akun email asli atau tiruan | Phishing kredensial biasa |
| AiTM | Proxy yang meneruskan login asli dan menyimpan session cookie setelah MFA | MFA fatigue |
| Unified Audit Log | Log audit gabungan layanan Microsoft 365 | Sign-in log Entra ID |
| Inbox rule berbahaya | Aturan mailbox yang menyembunyikan atau meneruskan email | Forwarding level mailbox (dicek terpisah) |
| Consent OAuth | Izin aplikasi mengakses data atas nama pengguna | Kredensial pengguna |
| `MailItemsAccessed` sync dan bind | Akses per folder (sync) dan per email (bind) | Daftar lengkap email yang dibaca (angkanya batas bawah) |
| Access token | Token berumur pendek untuk satu resource, default satu jam | Refresh token |
| Refresh token dan session cookie | Artefak berumur panjang untuk mendapat token baru | Password |
| Sign-in non-interactive | Sign-in oleh aplikasi memakai token, tanpa faktor baru | Aktivitas yang tidak penting |
| Session ID | Identifier yang mengikat sign-in dalam satu sesi | Correlation ID |
| CAE | Pencabutan token hampir real time untuk layanan yang mendukung | Revoke sessions (pemicunya) |
| Security info | Metode MFA dan pemulihan yang terdaftar di akun | Password |
| Conditional Access | Syarat penerbitan token: siapa, dari mana, perangkat, metode | Prompt MFA |
| Authentication strength | Jenis metode MFA yang diterima, misalnya phishing-resistant | Frekuensi sign-in |
| Kerberoasting | Minta tiket layanan akun service, pecahkan offline | Brute force login di DC |
| AS-REP roasting | Minta balasan autentikasi akun tanpa pre-auth, pecahkan offline | Kerberoasting (butuh akun domain dulu) |
| Pass-the-hash | Autentikasi NTLM memakai hash curian | Password cracking |
| Pass-the-ticket dan overpass-the-hash | Memakai tiket curian; menukar hash menjadi TGT baru | Golden ticket |
| Honeypot SPN | Akun umpan yang permintaan tiketnya pasti mencurigakan | Akun service sungguhan |
| gMSA | Akun service dengan password panjang yang dikelola otomatis | Akun service biasa dengan password panjang |
| Protected Users | Grup yang memaksa AES, melarang NTLM, TGT empat jam | Grup untuk akun service |
| DCSync | Meniru replikasi DC untuk mengambil hash semua akun | Mencuri `ntds.dit` dari disk |
| Hak replikasi | `Replicating Directory Changes` dan `... All` pada objek domain | Hak admin domain (pemegangnya bisa berbeda) |
| Golden ticket | TGT palsu dari hash krbtgt | Silver ticket |
| Silver ticket | Tiket satu layanan palsu dari hash akun layanan, tanpa KDC | Golden ticket |
| Template sertifikat (ESC1) | Template yang membiarkan peminta mengisi SAN dan berlaku untuk autentikasi | Template Wi-Fi biasa |
| Golden certificate | Sertifikat palsu dari private key CA curian | Sertifikat curian yang bisa dicabut |
| Tier 0 | Akun, grup, dan server yang mengendalikan identitas domain | Semua server penting |
| Domain dianggap dikuasai | Status yang membuat semua rahasia Tier 0 diperlakukan terpapar | Keputusan otomatis membangun ulang AD |
| Eviction | Mengusir penyerang dari domain yang tetap berjalan | Pemulihan forest |
| Pemulihan forest | Memulihkan AD dari backup tepercaya dalam isolasi | Restore satu DC |

## 2-4. Lab gabungan dan troubleshooting

Lab ini merapikan latihan Day 08-12 menjadi satu paket, lalu mengujinya dengan tabletop mini dan uji lisan. Semua dikerjakan sebagai dokumen untuk PT JAB. Jangan memakai data, nama, atau kejadian dari pekerjaan nyata.

### Bagian A: brief lima insiden untuk Hendra

Tulis brief satu halaman yang menjawab kelima permintaan Hendra, dengan bentuk berikut. Baris pertama diberikan sebagai contoh.

```
Insiden       | Lapis     | Satu kalimat (tanpa istilah teknis)                  | SEV   | A keputusan besar | Yang bertahan setelah reset | Usulan perbaikan
INC-2026-020  | email     | email palsu "password kedaluwarsa" ke 34 karyawan,   | SEV-3 | Dimas (IC)        | password yang terkirim      | phishing ke karantina,
              |           | satu orang mengisi password, sudah direset 15 menit |       |                   |                             | bukan Junk
...
```

Setelah lengkap, jalankan tiga pengecekan:

- Setiap kalimat bisa dibaca direksi tanpa glosarium. Bandingkan dengan pesan ke pengguna di Day 08 bagian 2.6 yang tidak memakai istilah teknis.
- Setiap nama di kolom A cocok dengan RACI Day 02 bagian 2.2, terutama keputusan yang berdampak pada pelanggan atau pihak ketiga.
- Setiap usulan punya asal di tabel bagian 1.10; tidak ada usulan baru yang muncul tanpa insiden.

### Bagian B: paket lanjutan `INC-2026-020`

Day 08 sengaja tidak menetapkan hasil pemeriksaan sign-in `lestari.putri` setelah ia mengirim password pukul 08:32:05. Tulis dua versi lanjutan; semua detail yang tidak ada di Day 08 kamu karang sendiri dan tandai sebagai fiktif.

| Versi | Anggapan | Artefak yang ditulis | Format dari |
|---|---|---|---|
| A | Tidak ada sign-in penyerang sebelum reset 09:55 | Query timeline sign-in dan hasilnya, penilaian dengan tingkat keyakinan, keputusan severity | Day 10 bagian 2.1 dan 2.5 |
| B | Ada sign-in sukses dari ASN hosting pukul 08:40 dengan session ID baru, lalu inbox rule dibuat | Timeline sign-in, cek inbox rule dan forwarding, analisis `MailItemsAccessed`, rencana jam H, checklist pemulihan akun, keputusan severity | Day 10 bagian 2.1 dan 2.8; Day 09 bagian 2.1, 2.3, 2.6 |

Pertanyaan yang harus terjawab di versi B: apakah reset 09:55 sudah cukup, apa yang harus ditambahkan, dan apakah reset itu termasuk "terlalu dini" seperti di `INC-2026-021`. Jawabannya bergantung pada apa yang diketahui pukul 09:55, bukan pada apa yang diketahui setelahnya; tulis keduanya terpisah.

### Bagian C: tabletop mini

Jalankan lima inject berikut, sendiri atau bersama rekan. Setiap inject adalah "bagaimana bila", bukan kejadian yang benar-benar terjadi. Untuk setiap inject, tulis keputusanmu, siapa A-nya, apakah insiden naik lapis atau naik severity, dan bagian Day yang menjadi dasarnya.

1. **`INC-2026-020`, Rabu 10:50.** Log proxy menunjukkan `POST` ke `sso.jab-akun.example.net` dari host yang alamat penggunanya tidak ada di daftar 34 penerima.
2. **`INC-2026-021`, Selasa 2026-10-27 10:00.** Pencarian audit ulang 24 jam setelah jam H menemukan satu record `MailItemsAccessed` dari `AppId` "Mail Sync Helper" pukul 11:52 Senin, tujuh menit setelah jam H.
3. **`INC-2026-022`, Kamis 10:00.** Sebelum Sari menulis penilaian `adm.rina`, query ulang menunjukkan sign-in `adm.rina` dari `198.51.100.152` pukul 17:31:08 ternyata sukses, bukan gagal.
4. **`INC-2026-023`, Senin 14:10.** Setelah jam H 13:30, Rudi menemukan 4624 `svc_backup` ke `JKT-DC01` dari `10.10.42.24` pukul 12:58 yang terlewat karena log DC kedua terlambat masuk Splunk.
5. **`INC-2026-024`, Selasa 22:30.** Di antara dua reset krbtgt, rule di Day 12 bagian 2.1 menampilkan akun `MSOL_` meminta replikasi dari IP selain `10.20.2.45`.

Petunjuk: inject 1 menguji pemetaan kampanye dan forwarding internal (Day 08 bagian 1.3 dan 1.4), inject 2 menguji jeda audit dan verifikasi pencabutan (Day 09 bagian 1.2; Day 10 bagian 1.4), inject 3 menguji kesimpulan dengan tingkat keyakinan dan kenaikan severity (Day 10 bagian 1.6), inject 4 menguji pemicu naik ke kompromi domain yang ditulis di scope (Day 11 bagian 2.6), dan inject 5 menguji pengecualian per pasangan akun dan IP serta delegasi jalur cepat (Day 12 bagian 1.2, 1.5, dan 2.4).

### Bagian D: uji lisan lima menit

Rekam dirimu menjawab pesan Hendra di bagian Ide inti dalam lima menit, dengan peta konsep bagian 1.6 sebagai satu-satunya bantuan. Lalu jawab tiga pertanyaan tanpa catatan:

- "Kenapa `MailItemsAccessed` disebut batas bawah, bukan batas atas?" (Day 09 bagian 1.5)
- "Kenapa akun Tier 0 dirotasi sebelum krbtgt, bukan sesudahnya?" (Day 12 bagian 2.5)
- "Kenapa di `INC-2026-023` krbtgt tidak direset, padahal serangannya juga memakai Kerberos?" (Day 11 bagian 1.6)

Catat bagian yang membuatmu ragu; itu daftar yang perlu diulang sebelum masuk Day 14.

**Hasil yang sebaiknya tersimpan:**

- `latihan/day13-brief-direksi.md` berisi brief lima insiden dan hasil tiga pengecekan bagian A.
- `latihan/day13-inc020-lanjutan.md` berisi versi A dan versi B bagian B, dengan detail karangan ditandai fiktif.
- `latihan/day13-tabletop.md` berisi keputusan, A, perubahan lapis atau severity, dan dasar untuk lima inject.
- Daftar topik yang masih lemah dari uji lisan, beserta Day yang perlu diulang.

### Troubleshooting paket

Tabel ini memuat masalah yang biasa muncul saat paket di atas disusun. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa atau memperbaiki |
|---|---|---|
| Brief menyebut "password sudah diganti, aman" untuk satu insiden | Hanya satu lapis yang diperiksa | Cocokkan dengan tabel bagian 1.8; tulis apa yang dicabut dan bagaimana diverifikasi |
| Versi B paket `INC-2026-020` tidak menyebut consent aplikasi atau metode MFA | Checklist dibaca sebagai daftar reset, bukan daftar persistence | Pakai checklist Day 10 bagian 2.8 baris per baris dengan kolom verifikasi |
| Jawaban tabletop menyebut "tidak ditemukan, jadi tidak ada" | Batas visibilitas tidak ditulis | Tambahkan sumber log dan batasnya dari tabel pertama bagian 1.10 |
| Inject 4 dijawab dengan reset `svc_backup` sekali lagi | Pemicu naik ke kompromi domain tidak dibaca | Buka scope v2 di Day 11 bagian 2.6; akses ke DC mengubah insiden, bukan hanya akun |
| Inject 5 dijawab dengan menghapus pengecualian `MSOL_` dari rule | Pengecualian dipahami per akun, bukan per pasangan akun dan IP | Day 12 bagian 1.2; akun konektor dari IP lain adalah scope baru |
| Brief direksi berisi daftar tool dan nama event | Fokus pada cara, bukan keputusan | Ceritakan per insiden: apa yang terjadi, siapa memutuskan, apa yang tersisa, apa yang diusulkan |

## 5. Kesalahan umum dan jebakan

Kesalahan berikut muncul di lebih dari satu Day minggu ini; tiap butir menyebut Day asalnya.

- Menganggap ganti password menutup akses penyerang. Consent aplikasi, inbox rule, token yang tidak berbasis password, metode MFA asing, tiket Kerberos, dan sertifikat semuanya bertahan (Day 09, Day 10, Day 11, Day 12) [S12][S17][S31].
- Me-reset kredensial sebelum scope diketahui saat penyerang punya jalan lain, atau sebaliknya menunda reset saat password curian adalah satu-satunya akses (Day 08, Day 09, Day 10) [S37].
- Menganggap MFA mencegah pengambilalihan akun. AiTM mengambil cookie setelah MFA berhasil (Day 09, Day 10) [S14].
- Menganggap SPF, DKIM, atau DMARC yang lolos berarti email aman, atau DMARC `p=reject` melindungi dari mailbox asli yang dibobol (Day 08, Day 09) [S1].
- Membaca angka dari log sebagai batas atas: jumlah email di `MailItemsAccessed`, tidak adanya baris penyerang setelah revoke, atau tidak ditemukannya golden ticket (Day 09, Day 10, Day 12) [S10].
- Mengandalkan satu konsol atau satu jenis log: tab sign-in interactive saja, filter RC4 saja, atau audit tanpa memperhitungkan jeda (Day 09, Day 10, Day 11).
- Mengecualikan akun dari rule deteksi tanpa menyertakan host sumbernya (Day 12).
- Mereset krbtgt refleks setiap ada serangan Kerberos, atau mereset krbtgt sebelum akun Tier 0 dirotasi (Day 11, Day 12).
- Menutup alert yang menyentuh persistence identitas tanpa verifikasi ke pengguna lewat kanal kedua, seperti `SOC-2026-0230` (Day 10) [S19].
- Menyimpulkan "aman" atau "dikuasai" tanpa tingkat keyakinan. Kesimpulan ditulis dari bukti, dengan batas visibilitas (Day 10, Day 12).

## 6. Catatan terkini

Bagian ini mengumpulkan status dokumen dan perubahan produk yang dipakai Day 08-12. Tidak mengubah isi review, tetapi berguna saat ditanya "versi mana yang kamu pakai".

- **DMARC** menjadi Proposed Standard lewat RFC 9989 (Mei 2026), menggantikan RFC 7489; tag `pct` dihapus dan konsep alignment tetap sama [S2]. Materi lama yang menyebut `pct=` masih banyak beredar.
- **Message trace** memakai `Get-MessageTraceV2`: data 90 hari, maksimal 10 hari per query [S4]. Pengalaman eDiscovery dan Content Search klasik dipensiunkan 31 Agustus 2025 [S6].
- **Audit M365 Standard** disimpan 180 hari untuk log sejak 17 Oktober 2023 [S11], dan `MailItemsAccessed` kini bagian dari Audit Standard untuk lisensi E3 dan E5 [S10].
- **Entra ID**: kebijakan CA untuk registrasi security info juga berlaku saat registrasi Windows Hello for Business mulai 6 Juli 2026 [S21]. Token theft playbook bertanggal Juli 2023 dan sebagian tautannya masih memakai nama Azure AD [S19].
- **Kerberos RC4**: default KDC bergerak ke AES untuk akun tanpa `msDS-SupportedEncryptionTypes` eksplisit, fase audit sejak 13 Januari 2026 dan enforcement default sejak 14 April 2026 [S28].
- **Pemetaan sertifikat** di DC masuk Full Enforcement dengan pembaruan Februari 2025, dan opsi kembali ke mode kompatibilitas berakhir dengan pembaruan September 2025 [S39].
- **Entra Connect Sync** wajib di-upgrade ke versi 2.6.84.0 atau lebih baru dengan autentikasi berbasis aplikasi sebelum 7 April 2027 [S40].
- **MITRE ATT&CK** yang dipakai Day 11 dan 12 adalah v20 [S23][S29].

## 7. Cheat sheet

```
EMPAT PERTANYAAN DI SETIAP LAPIS
  apa yang DIPEGANG? | apa yang DITANAM? | SAMPAI MANA? | LOG apa yang membuktikan?

LAPIS DAN YANG BERTAHAN SETELAH GANTI PASSWORD
  email      kredensial terkirim, salinan di Junk (ZAP default)    -> purge + reset/revoke
  mailbox    inbox rule, forwarding, consent OAuth, app password    -> 6 langkah Microsoft serentak
  identitas  cookie/token non-password, MFA asing, perangkat        -> revoke (semua kelas) + hapus
  akun AD    hash lama, tiket terbit, hak lokal                     -> reset 2x + batasi sumber + gMSA
  domain     krbtgt, sertifikat, Tier 0, konektor Entra Connect     -> Tier 0 dulu, lalu krbtgt 2x

NAIK LAPIS: kredensial terkirim -> identitas | akun admin korban -> AD
  | akses DC / hak replikasi / sertifikat admin -> domain dianggap dikuasai

RESET SEGERA bila password curian = satu-satunya akses yang diketahui (phishing kredensial)
RESET DI JAM H bila penyerang punya jalan lain (sesi, consent, rule, tiket, hash)
  helpdesk mendahului IC = pelajaran prosedur, bukan kesalahan orang

LOG DAN BATASNYA
  M365 audit: jeda s.d. 24 jam | Standard 180 hari | aksi non-default (SearchQueryInitiated)
  Entra: P1 30 hari (Free 7) | detail risiko butuh P2 | non-interactive = replay token
  AD: tanpa MDI -> 4768/4769/4776/4624 + honeypot + EDR | 4662 butuh audit DS + SACL
  CA: 4886/4887 butuh audit filter; tanpa itu baca database CA
  angka dari log = BATAS BAWAH; "tidak ditemukan" != "tidak ada"

KEPUTUSAN
  IC: declare, severity, containment akun/host, revoke, reset
  exec sponsor: pelanggan dan dana (BEC), gangguan layanan (krbtgt), eviction vs forest recovery
  delegasi bersyarat: jalur cepat krbtgt ke IC dengan pemicu tertulis
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "Di kelima insiden, password akun yang terlibat sudah direset, jadi akses penyerang sudah tertutup di semuanya." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Reset password hanya menutup satu jenis akses. Di `INC-2026-021`, aplikasi "Mail Sync Helper" masih membaca email Fitri delapan belas menit setelah reset, karena consent OAuth tidak bergantung pada password. Di `INC-2026-022`, metode MFA telepon penyerang tetap terdaftar dan cookie yang tidak berbasis password tidak ikut dicabut oleh ganti password. Di `INC-2026-023`, hash lama dan tiket yang sudah terbit tetap berguna sampai reset dua kali dan pembatasan sumber login. Di `INC-2026-024`, TGT palsu dari hash krbtgt dan sertifikat atas nama admin tidak bergantung pada password akun yang disamar. Lihat bagian 1.8.

</details>

**2. Skenario keputusan.** Rabu 09:00, log proxy menunjukkan seorang staf mengirim `POST` ke halaman login tiruan sepuluh menit lalu. Belum ada tanda lain apa pun dari akun itu. Apa langkah yang tepat?

- A. Reset password dan revoke sessions akun itu sekarang, lalu periksa sign-in log, metode MFA, dan aktivitas mailbox sejak 08:50.
- B. Tunda reset sampai jam H supaya penyerang tidak sadar, sambil memantau akun itu.
- C. Nonaktifkan akun dan tunggu sampai scoping seluruh kampanye selesai sebelum melakukan apa pun yang lain.

<details><summary>Jawaban</summary>

A. Akses penyerang yang diketahui hanya password yang baru dicuri, sehingga setiap menit penundaan adalah menit password itu bisa dipakai; itu sebabnya reset dan revoke Lestari di `INC-2026-020` dijalankan segera. Pemeriksaan sesudahnya menentukan apakah penyerang sempat masuk dan menanam sesuatu. B keliru karena prinsip jam H berlaku bila penyerang sudah punya jalan lain yang harus ditutup bersamaan, seperti di `INC-2026-021`; di sini belum ada jalan lain yang diketahui. C keliru karena menonaktifkan akun tidak mencabut token yang sudah terbit dan menunda pemeriksaan yang justru menentukan langkah berikutnya. Lihat bagian 1.1 dan 1.9.

</details>

**3. Pertanyaan jebakan.** "PT JAB memakai DMARC `p=reject` untuk `jab.example`, jadi pelanggan korporat terlindung dari email BEC yang mengatasnamakan staf Keuangan PT JAB." Benarkah?

<details><summary>Jawaban</summary>

Tidak. DMARC melindungi dari pemalsuan alamat `@jab.example` oleh server lain. Di `INC-2026-021`, email palsu dikirim dari mailbox Fitri yang asli, sehingga lolos autentikasi seperti email sah; DMARC `p=reject` justru menjelaskan kenapa penyerang repot membobol mailbox asli. DMARC juga tidak menangani lookalike domain seperti di `INC-2026-020`. Perlindungan pelanggan dari BEC datang dari verifikasi perubahan rekening lewat kanal kedua, yang menyelamatkan Rp 487,5 juta milik PT Sentosa Makmur Contoh. Lihat bagian 1.1 dan 1.2.

</details>

**4. Skenario keputusan.** Seorang manajer melapor bahwa akunnya mungkin dipakai orang lain sejak enam minggu lalu. Sumber mana yang paling tepat untuk menyusun timeline sign-in dan aktivitas mailbox di PT JAB?

- A. Sign-in log di portal Entra ID, karena itu sumber resmi Microsoft.
- B. Salinan sign-in log dan audit Entra ID di Splunk (disimpan satu tahun), ditambah Unified Audit Log untuk mailbox (Audit Standard 180 hari), dengan mencatat jeda audit dan batas visibilitasnya.
- C. Riwayat deteksi risiko ID Protection, karena itu yang menandai login AiTM.

<details><summary>Jawaban</summary>

B. Dengan lisensi P1, Entra ID hanya menyimpan sign-in log dan audit log 30 hari, dan upgrade lisensi tidak mengembalikan data yang sudah lewat; karena itu PT JAB mengalirkannya ke Splunk. Aktivitas mailbox ada di Unified Audit Log yang masa simpannya mengikuti lisensi pengguna, 180 hari untuk Audit Standard. A keliru karena data enam minggu lalu sudah tidak ada di portal. C keliru karena tanpa P2 detail deteksi risiko hanya tampil sebagai "Additional risk detected", dan deteksi AiTM di ID Protection butuh lisensi yang tidak dimiliki PT JAB. Lihat bagian 1.2, 1.3, dan 1.10.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Bambang Hartono (Manajer NOC), dalam tiga kalimat, kenapa `krbtgt` tidak direset di `INC-2026-023` tetapi direset dua kali di `INC-2026-024`, padahal keduanya serangan ke AD.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Di insiden pertama, penyerang mencuri kunci satu akun service, jadi yang kita ganti adalah kunci akun itu dan kita batasi ruang mana saja yang boleh dibukanya. Di insiden kedua, penyerang menyalin kunci master yang dipakai domain untuk menandatangani semua kartu akses, sehingga ia bisa mencetak kartu siapa pun sendiri, dan satu-satunya cara membatalkannya adalah mengganti kunci master itu dua kali dengan jeda supaya kartu lama benar-benar tidak diterima. Mengganti kunci master membuat semua kartu yang beredar ikut gugur dan beberapa layanan harus login ulang, jadi kita hanya melakukannya bila ada bukti kunci master itu tersalin, seperti DCSync di insiden kedua."

Kesalahan yang sering muncul:
- Menjawab "karena insiden kedua lebih parah" tanpa menyebut apa yang tersalin.
- Tidak menyebut harga reset krbtgt (gangguan layanan), sehingga terdengar seperti tindakan yang bisa dilakukan kapan saja.
- Memakai istilah "TGT", "hash", atau "DCSync" tanpa padanan yang dikenal NOC.

</details>

**6. Pertanyaan jebakan.** "Di `INC-2026-022`, tidak ada sign-in sukses `adm.rina` dari jaringan penyerang, jadi laporan cukup menulis `adm.rina` aman dan tidak perlu disentuh." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Kesimpulan ditulis dengan tingkat keyakinan: tidak ada bukti `adm.rina` dipakai penyerang, dengan keyakinan sedang, karena penyerang jelas mencoba login ke akun itu pukul 17:31:08 dan log tidak mencatat password apa yang dicoba. Karena harganya hanya beberapa menit kerja, reset dua kali dan revoke sessions `adm.rina` tetap dijalankan sebagai pencegahan. Itu berbeda dengan menyatakan `adm.rina` terkompromi, yang akan menaikkan severity tanpa bukti. Lihat bagian 1.7 dan Day 10 bagian 1.6.

</details>

**7. Interview question (English).** "A user with MFA enabled clicked a phishing link and their account was taken over. How do you scope it and make sure the attacker is fully out?"

<details><summary>Sample answer</summary>

"First I'd stop assuming MFA protected them: adversary-in-the-middle kits relay the real login and steal the session cookie after MFA succeeds, so the attacker holds tokens, not just a password. I scope in layers. In the identity layer I pull both interactive and non-interactive sign-ins and look for the same session ID reused from a different network or ASN without a device ID, then check the audit log for new MFA methods, registered devices, app consents and role changes. In the mailbox layer I check inbox rules including hidden ones, mailbox forwarding, and MailItemsAccessed, treating the count as a lower bound. If the user has an admin account, I check its sign-ins and directory activity separately and write the conclusion with a confidence level. Containment happens in one window: revoke all refresh tokens and cookies, remove attacker MFA methods and consents, disable malicious rules, reset the password twice on-prem for a synced account, and only then re-enable the account. A password reset alone isn't enough, because it doesn't revoke every token class or remove anything the attacker planted. I verify in the sign-in logs that old sessions are rejected, watch the account for a couple of weeks, and propose Conditional Access changes that block token replay, like requiring a managed device, rather than just prompting for MFA more often."

What makes this answer strong: it explains why MFA didn't stop the attack, scopes by layer with concrete log artefacts, separates the admin account question, executes containment as one coordinated window, and verifies revocation from logs instead of trusting a command's output.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | RFC 7489: Domain-based Message Authentication, Reporting, and Conformance (DMARC) | https://www.rfc-editor.org/rfc/rfc7489.html | primer | Maret 2015 (Informational, digantikan RFC 9989); diakses 2026-10-15 | Tinggi untuk konsep alignment, syarat lolos, dan batas (nama tampilan, lookalike); dirangkum dari Day 08 |
| S2 | RFC 9989: Domain-Based Message Authentication, Reporting, and Conformance (DMARC) | https://www.rfc-editor.org/info/rfc9989 | primer | Mei 2026; diakses 2026-10-15 | Tinggi. Proposed Standard, menggantikan RFC 7489, penghapusan `pct` |
| S3 | Microsoft Learn: Anti-spam message headers in Microsoft 365 | https://learn.microsoft.com/en-us/defender-office-365/message-headers-eop-mdo | primer (dokumentasi vendor) | ms.date 2026-07-27; diakses 2026-10-15 | Tinggi. 5321.MailFrom dan 5322.From, `Authentication-Results`, `compauth` |
| S4 | Microsoft Learn: Get-MessageTraceV2 | https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-messagetracev2 | primer (dokumentasi vendor) | diperbarui 2026-02-27; diakses 2026-10-15 | Tinggi. 90 hari, 10 hari per query |
| S5 | Microsoft Learn: Remediate malicious email that was delivered in Office 365 | https://learn.microsoft.com/en-us/defender-office-365/remediate-malicious-email-delivered-office-365 | primer (dokumentasi vendor) | ms.date 2025-09-16; diakses 2026-10-15 | Tinggi. Soft dan hard delete, Action center |
| S6 | Microsoft Learn: Find and delete email messages in eDiscovery | https://learn.microsoft.com/en-us/purview/edisc-search-mailbox-data | primer (dokumentasi vendor) | ms.date 2026-06-19; diakses 2026-10-15 | Tinggi. Batas 10 item per mailbox, pensiun eDiscovery klasik |
| S7 | Microsoft Learn: Zero-hour auto purge in Microsoft Defender for Office 365 | https://learn.microsoft.com/en-us/defender-office-365/zero-hour-auto-purge | primer (dokumentasi vendor) | ms.date 2026-06-01; diakses 2026-10-15 | Tinggi. Jendela 48 jam, tindakan per verdict dan policy |
| S8 | CISA, NSA, FBI, MS-ISAC: Phishing Guidance: Stopping the Attack Cycle at Phase One (PDF) | https://www.cisa.gov/sites/default/files/2025-03/Phishing%20Guidance%20-%20Stopping%20the%20Attack%20Cycle%20at%20Phase%20One%20508.pdf | primer | Oktober 2023; diakses 2026-10-15 | Tinggi. Langkah respons setelah phishing berhasil |
| S9 | Microsoft Learn: Respond to a compromised email account in Microsoft 365 | https://learn.microsoft.com/en-us/defender-office-365/responding-to-a-compromised-email-account | primer (dokumentasi vendor) | ms.date 2026-07-03; diakses 2026-10-15 | Tinggi. Enam langkah pemulihan, inbox rule dan forwarding |
| S10 | Microsoft Learn: Use MailItemsAccessed to investigate compromised accounts | https://learn.microsoft.com/en-us/purview/audit-log-investigate-accounts | primer (dokumentasi vendor) | ms.date 2026-06-19; diakses 2026-10-15 | Tinggi. Sync dan bind, anggapan data terkompromi, Audit Standard |
| S11 | Microsoft Learn: Manage audit log retention policies | https://learn.microsoft.com/en-us/purview/audit-log-retention-policies | primer (dokumentasi vendor) | ms.date 2026-06-19; diakses 2026-10-15 | Tinggi. Standard 180 hari sejak 17 Oktober 2023 |
| S12 | Microsoft Learn: Detect and remediate illicit consent grants | https://learn.microsoft.com/en-us/defender-office-365/detect-and-remediate-illicit-consent-grants | primer (dokumentasi vendor) | ms.date 2026-07-03; diakses 2026-10-15 | Tinggi. Reset password tidak efektif terhadap consent, jeda audit 30 menit sampai 24 jam |
| S13 | FBI IC3: Business Email Compromise, The $55 Billion Scam (I-091124-PSA) | https://www.ic3.gov/PSA/2024/PSA240911 | primer | 2024-09-11; diakses 2026-10-15 | Tinggi. Definisi BEC, verifikasi kanal kedua. Konteks Amerika Serikat |
| S14 | Microsoft Security Blog: From cookie theft to BEC, attackers use AiTM phishing sites as entry point to further financial fraud | https://www.microsoft.com/en-us/security/blog/2022/07/12/from-cookie-theft-to-bec-attackers-use-aitm-phishing-sites-as-entry-point-to-further-financial-fraud/ | sekunder (laporan vendor) | 2022-07-12 (lebih dari 3 tahun); diakses 2026-10-15 | Sedang-tinggi. Mekanisme AiTM, bukan kerentanan MFA |
| S15 | Microsoft Learn: Non-interactive sign-in logs | https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-noninteractive-sign-ins | primer (dokumentasi vendor) | ms.date 2026-02-09; diakses 2026-10-15 | Tinggi. Definisi sign-in non-interactive, pengelompokan |
| S16 | Microsoft Learn: Microsoft Entra data retention | https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-reports-data-retention | primer (dokumentasi vendor) | ms.date 2026-01-06; diakses 2026-10-15 | Tinggi. 7 hari Free, 30 hari P1/P2, tidak retroaktif |
| S17 | Microsoft Learn: Refresh tokens in the Microsoft identity platform | https://learn.microsoft.com/en-us/entra/identity-platform/refresh-tokens | primer (dokumentasi vendor) | ms.date 2025-11-05; diakses 2026-10-15 | Tinggi. Tabel pencabutan per kelas token |
| S18 | Microsoft Learn: Continuous access evaluation in Microsoft Entra | https://learn.microsoft.com/en-us/entra/identity/conditional-access/concept-continuous-access-evaluation | primer (dokumentasi vendor) | ms.date 2026-04-08; diakses 2026-10-15 | Tinggi. Jeda sampai 15 menit, token sampai 28 jam |
| S19 | Microsoft Learn: Token theft playbook | https://learn.microsoft.com/en-us/security/operations/token-theft-playbook | primer (dokumentasi vendor) | ms.date 2023-07-28 (lebih dari 2 tahun); diakses 2026-10-15 | Tinggi untuk alur investigasi dan bentuk persistence |
| S20 | Microsoft Learn: What are risk detections? (ID Protection) | https://learn.microsoft.com/en-us/entra/id-protection/concept-identity-protection-risks | primer (dokumentasi vendor) | ms.date 2026-04-22; diakses 2026-10-15 | Tinggi. "Additional risk detected" tanpa P2 |
| S21 | Microsoft Learn: Control security information registration with Conditional Access | https://learn.microsoft.com/en-us/entra/identity/conditional-access/policy-all-users-security-info-registration | primer (dokumentasi vendor) | ms.date 2026-03-24; diakses 2026-10-15 | Tinggi. User action Register security information, perubahan 6 Juli 2026 |
| S22 | Microsoft Learn: Revoke user access in an emergency in Microsoft Entra ID | https://learn.microsoft.com/en-us/entra/identity/users/users-revoke-access | primer (dokumentasi vendor) | ms.date 2026-06-19; diakses 2026-10-15 | Tinggi. Reset dua kali untuk akun hybrid, revoke sessions |
| S23 | MITRE ATT&CK T1558.003 Kerberoasting | https://attack.mitre.org/techniques/T1558/003/ | primer | ATT&CK v20.0, diperbarui 2025-10-24; diakses 2026-10-15 | Tinggi. Mekanisme dan deteksi 4769 RC4 |
| S24 | MITRE ATT&CK T1558.004 AS-REP Roasting | https://attack.mitre.org/techniques/T1558/004/ | primer | ATT&CK v20.0, diperbarui 2025-10-24; diakses 2026-10-15 | Tinggi. Deteksi 4768 pre-auth 0 |
| S25 | MITRE ATT&CK T1550.002 Use Alternate Authentication Material: Pass the Hash | https://attack.mitre.org/techniques/T1550/002/ | primer | ATT&CK v20.0, diperbarui 2026-05-12; diakses 2026-10-15 | Tinggi. NTLM logon type 3 anomali, overpass-the-hash |
| S26 | Microsoft Security Blog: guidance to help mitigate Kerberoasting | https://www.microsoft.com/en-us/security/blog/2024/10/11/microsofts-guidance-to-help-mitigate-kerberoasting/ | sekunder (vendor) | 2024-10-11; diakses 2026-10-15 | Tinggi. RC4, gMSA dan dMSA, hapus SPN |
| S27 | Microsoft Learn: Protected Users Security Group | https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/protected-users-security-group | primer (dokumentasi vendor) | ms.date 2025-06-27; diakses 2026-10-15 | Tinggi. AES saja, tanpa NTLM, jangan untuk akun service |
| S28 | Microsoft support: Manage Kerberos KDC usage of RC4 for service account ticket issuance (CVE-2026-20833) | https://support.microsoft.com/topic/1ebcda33-720a-4da8-93c1-b0496e1910dc | primer (dokumentasi vendor) | diperbarui 2026-04-14; diakses 2026-10-15 | Tinggi. Fase audit Januari 2026 dan enforcement April 2026 |
| S29 | MITRE ATT&CK: OS Credential Dumping: DCSync (T1003.006) | https://attack.mitre.org/techniques/T1003/006/ | primer | v1.1, diubah 2025-10-24 (ATT&CK v20); diakses 2026-10-15 | Tinggi. Cara kerja dan data yang diambil |
| S30 | MITRE ATT&CK: Steal or Forge Kerberos Tickets: Golden Ticket (T1558.001) | https://attack.mitre.org/techniques/T1558/001/ | primer | v1.2, diubah 2025-10-24; diakses 2026-10-15 | Tinggi. TGT palsu dari hash krbtgt |
| S31 | MITRE ATT&CK: Steal or Forge Authentication Certificates (T1649) | https://attack.mitre.org/techniques/T1649/ | primer | v1.2, diubah 2026-08-04; diakses 2026-10-15 | Tinggi. Sertifikat bertahan setelah reset password |
| S32 | Microsoft Learn: 4662(S, F) An operation was performed on an object | https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4662 | primer (dokumentasi vendor, arsip) | ms.date 2021-09-07; diakses 2026-10-15 | Tinggi. Syarat audit dan SACL, Logon ID |
| S33 | Microsoft Learn: Microsoft Entra Connect, Accounts and permissions | https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/reference-connect-accounts-permissions | primer | ms.date 2025-04-09; diakses 2026-10-15 | Tinggi. Hak replikasi akun konektor untuk password hash sync |
| S34 | Microsoft Learn: AD Forest Recovery, Reset the krbtgt password | https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-reset-the-krbtgt-password | primer | ms.date 2025-05-21; diakses 2026-10-15 | Tinggi. Dua kali, jeda 10 jam |
| S35 | Microsoft Learn: AD Forest Recovery, Determine how to recover the forest | https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/forest-recovery-guide/ad-forest-recovery-determine-how-to-recover | primer | ms.date 2023-07-10; diakses 2026-10-15 | Tinggi. Pemilihan backup, isolasi, trade-off |
| S36 | CISA Eviction Strategies Tool: CM0050 Reset KRBTGT Password Twice | https://www.cisa.gov/eviction-strategies-tool/info-countermeasures/CM0050 | primer | Maret 2025; diakses 2026-10-15 | Tinggi. Replikasi sebelum reset kedua, minimal 10 jam |
| S37 | CISA: Technical Approaches to Uncovering and Remediating Malicious Activity (AA20-245A) | https://www.cisa.gov/news-events/cybersecurity-advisories/aa20-245a | primer | revisi 2020-09-24 (lebih dari 3 tahun); diakses 2026-10-15 | Tinggi. Reset dini sebagai kesalahan umum, krbtgt dengan replikasi di antaranya |
| S38 | SpecterOps: Certified Pre-Owned (Will Schroeder, Lee Christensen) | https://specterops.io/blog/2021/06/17/certified-pre-owned/ | sekunder | 2021-06-17 (lebih dari 3 tahun); diakses 2026-10-15 | Tinggi untuk kondisi ESC1 dan golden certificate |
| S39 | Microsoft Support: KB5014754, Certificate-based authentication changes on Windows domain controllers | https://support.microsoft.com/en-us/topic/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers-ad2c23b0-15d8-4340-a468-4d4f3b188f16 | primer | diperbarui 2025-09-10; diakses 2026-10-15 | Tinggi. Jadwal enforcement pemetaan sertifikat |
| S40 | Microsoft Learn: Microsoft Entra Connect, Prerequisites and hardware | https://learn.microsoft.com/en-us/entra/identity/hybrid/connect/how-to-connect-install-prerequisites | primer | ms.date 2026-01-16; diakses 2026-10-15 | Tinggi. Server Entra Connect sebagai Tier 0, kewajiban upgrade sebelum 7 April 2027 |

**Catatan sumber:** Day ini tidak memakai sumber baru; setiap klaim berasal dari Day 08-12 dan sumber yang sama dirujuk ulang. Peta lima lapis di bagian 1.6, empat pertanyaan per lapis, tabel lima insiden dan tiga benang di bagian 1.7 sampai 1.10, serta glosarium adalah susunan catatan ini, bukan model resmi salah satu sumber; definisi di glosarium adalah parafrase untuk belajar. Hal yang masih perlu dicek di Day asalnya tetap berlaku: throttling `MailItemsAccessed` (Day 09), nama sourcetype dan field Splunk untuk log Entra (Day 10), pola overpass-the-hash yang bersumber komunitas (Day 11), dan isi teknis panduan bersama lima negara tentang kompromi AD edisi September 2026 (Day 12). Semua isi PT JAB, termasuk timeline kelima insiden, inject tabletop di bagian 2-4, rapat direksi, dan nama orang, adalah contoh fiktif.
