---
day: 08
title: 'Analisis email dan phishing: header, SPF/DKIM/DMARC, triage URL dan lampiran secara aman, dan purge'
researched_on: 2026-10-15
versions_checked: 'RFC 7208 SPF (April 2014); RFC 6376 DKIM (September 2011); RFC 7489 DMARC (Maret 2015, digantikan RFC 9989); RFC 9989 DMARC (Mei 2026, Proposed Standard); RFC 8601 Authentication-Results (Mei 2019); Microsoft Learn, Anti-spam message headers (ms.date 2026-07-27); Get-MessageTraceV2 (diperbarui 2026-02-27); Remediate malicious email delivered in Office 365 (ms.date 2025-09-16); Find and delete email messages in eDiscovery (ms.date 2026-06-19); Zero-hour auto purge (ms.date 2026-06-01); Configure user reported message settings (ms.date 2026-09-28); UrlClickEvents table (ms.date 2026-06-04); CISA, NSA, FBI, MS-ISAC Phishing Guidance (Oktober 2023)'
---

# Day 08: Analisis email dan phishing (header, SPF/DKIM/DMARC, triage URL dan lampiran secara aman, dan purge)

Cakupan: membaca header email untuk menentukan asal pesan, memahami apa yang dibuktikan dan tidak dibuktikan SPF, DKIM, dan DMARC, memetakan satu kampanye phishing dari laporan pengguna sampai daftar penerima dan pengguna yang klik, menganalisis URL dan lampiran tanpa membahayakan organisasi, menarik email dari semua mailbox, dan menyerahkan pengguna yang terkena ke penanganan akun.

## Ide inti

Email phishing adalah insiden yang datang sebagai kampanye, bukan sebagai satu kejadian. Satu laporan dari pengguna hampir selalu berarti puluhan salinan yang sama sudah ada di mailbox lain, dan sebagian kecil penerimanya mungkin sudah klik. Karena itu analisis phishing selalu menjawab tiga pertanyaan secara berurutan: pesan ini sebenarnya dari mana (header dan autentikasi), siapa saja yang menerima dan siapa yang berinteraksi (pemetaan kampanye), dan bagaimana menarik semua salinan lalu menangani pengguna yang sudah terkena (purge dan serah terima). Satu pesan yang dianalisis sangat dalam tidak berguna bila 33 salinan lainnya masih menunggu diklik.

Kamu sudah mengenal pola berpikir ini dari NOC. Header `Received` email dibaca seperti hasil traceroute atau AS path: urutan hop yang dilewati pesan, yang hanya bisa dipercaya sampai hop pertama milikmu sendiri. SPF mirip ROA di RPKI: pemilik domain menyatakan IP mana yang boleh mengirim atas nama domain itu. DMARC mirip route origin validation: pengumuman hanya sah bila asalnya cocok dengan yang dinyatakan pemilik. Dan menarik email dari semua mailbox mirip menarik konfigurasi yang salah dari semua router lewat NMS: cepat dan serentak, tetapi tidak membatalkan akibat yang sudah terjadi di perangkat yang sempat menjalankannya. Bedanya, di jaringan kamu memiliki semua router. Di email, pengirim, domain, dan halaman tujuan sepenuhnya milik penyerang, dan semuanya bisa lolos pemeriksaan teknis dengan sempurna.

```
laporan pengguna / alert
  |
  v
1. asal pesan        header: Received, Return-Path, From, Reply-To, Message-ID
                     autentikasi: SPF, DKIM, DMARC, compauth  (pass != aman)
  |
  v
2. pemetaan kampanye  pengirim, subjek, URL, IP pengirim  ->  semua penerima
                      siapa klik (Safe Links, proxy, DNS), siapa kirim kredensial (POST)
  |
  v
3. analisis payload   URL dan lampiran: dari lingkungan terpisah, scan privat, hash dulu
  |
  v
4. tindakan           blok (domain, IP, pengirim) + purge semua salinan
                      pengguna yang kirim kredensial -> penanganan akun
  |
  v
5. komunikasi         ke pengguna, ke pelapor, update ke IC
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan sekitar 1.200 karyawan. Email karyawan ada di Microsoft 365 dengan Defender for Office 365 Plan 2, domain email `jab.example`, dan AD on-premises disinkronkan ke Entra ID. Rabu, 21 Oktober 2026, sekitar 08:14 WIB, 34 mailbox karyawan menerima email dari "IT Helpdesk JAB" dengan subjek "[PENTING] Password Microsoft 365 Anda kedaluwarsa hari ini". Sejak 08:40 masuk enam laporan lewat tombol Report di Outlook (`SOC-2026-0210` sampai `SOC-2026-0215`). Analyst L1 Gilang Ramadhan mengeskalasi ke analyst L2 Rudi Hartanto pukul 09:12. Pukul 09:30, IC Dimas Prasetyo menulis ke Rudi:

> "Rud, sudah enam laporan email 'password M365 kedaluwarsa'. Pengirimnya 'IT Helpdesk JAB', itu benar dari kita atau bukan? Gilang bilang SPF-nya pass, berarti asli kan? Berapa orang yang terima, siapa yang sudah klik, dan ada yang sudah memasukkan password? Link-nya boleh saya buka sebentar buat lihat halamannya? Emailnya bisa ditarik dari semua mailbox? Katanya Microsoft sudah otomatis memindahkan, berarti cukup? Lalu yang sudah memasukkan password kita apakan?"

Pesan itu memuat tujuh pertanyaan:

1. Apakah email itu benar dari PT JAB?
2. Apakah SPF pass berarti asli?
3. Berapa orang yang menerima?
4. Siapa yang klik, dan siapa yang memasukkan password?
5. Apakah link boleh dibuka untuk dilihat?
6. Bagaimana menarik email dari semua mailbox, dan apakah tindakan otomatis Microsoft sudah cukup?
7. Apa yang dilakukan untuk pengguna yang sudah memasukkan password?

Pertanyaan 1 dijawab di bagian 1.1, pertanyaan 2 di bagian 1.2, pertanyaan 3 di bagian 1.3, pertanyaan 4 di bagian 1.4, pertanyaan 5 di bagian 1.5, pertanyaan 6 di bagian 1.6, dan pertanyaan 7 di bagian 1.7. Bagian 2 berisi artefak yang dihasilkan Rudi pagi itu.

**Kapan relevan:** setiap kali email mencurigakan dilaporkan pengguna atau terdeteksi alat, dan setiap kali insiden lain (ransomware, kompromi akun, BEC) mungkin dimulai dari email, sehingga titik masuknya harus dipastikan dan salinan lain harus ditarik.
**Kapan bukan jawaban:** analisis email tidak menjawab apa yang dilakukan penyerang setelah mendapat password atau setelah lampiran dijalankan. Untuk itu alurnya pindah ke penanganan akun (sign-in log, sesi, mailbox) atau ke host (live response dan containment, Day 04 dan Day 05). Analisis email juga bukan tempat menilai siapa yang "ceroboh"; pengguna yang melapor cepat adalah sensor terbaik yang kamu punya.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (insiden, severity, IC, scoping, IOC, containment, DNS sinkhole, revoke session) tidak diulang. Tabel berikut memuat istilah baru Day ini. Kolom padanan memakai analogi NOC dan SOC yang sama di semua Day IR.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| Envelope (RFC 5321) | Alamat yang dipakai server saat transaksi SMTP: `MAIL FROM` (Return-Path) dan `RCPT TO` | Header paket di lapisan transport, tidak dilihat aplikasi |
| Header pesan (RFC 5322) | Field di dalam pesan yang dilihat pengguna: `From`, `To`, `Subject`, `Date`, `Reply-To` | Isi payload yang ditampilkan ke pengguna |
| Header `Received` | Jejak setiap server yang menerima pesan, ditambahkan di atas oleh setiap hop | Hasil traceroute atau AS path |
| SPF | Daftar IP yang boleh mengirim untuk domain di `MAIL FROM`, dipublikasikan di DNS | ROA di RPKI: AS mana yang boleh mengumumkan prefix |
| DKIM | Tanda tangan kriptografis atas header dan body, dengan kunci publik di DNS domain penanda tangan (`d=`) | Tanda tangan digital pada firmware dari vendor |
| DMARC | Kebijakan pemilik domain `From`: lolos bila SPF atau DKIM lolos dan domainnya sejajar (aligned) dengan domain `From` | Route origin validation: asal pengumuman harus cocok dengan ROA |
| Alignment | Kesesuaian domain yang lolos SPF atau DKIM dengan domain di `From` | Prefix yang diumumkan cocok dengan AS di ROA |
| `Authentication-Results` | Header yang ditulis server penerima tentang hasil SPF, DKIM, DMARC | Hasil validasi RPKI yang dicatat router penerima |
| compauth | Hasil autentikasi gabungan Microsoft 365 berdasarkan SPF, DKIM, DMARC, dan sinyal lain | Skor gabungan dari beberapa pemeriksaan otomatis |
| Lookalike domain | Domain mirip milik organisasi (`jab-support.example.net` vs `jab.example`) | Prefix palsu yang mirip prefix pelanggan |
| Kampanye phishing | Sekumpulan pesan dengan ciri yang sama (pengirim, subjek, URL, infrastruktur) ke banyak penerima | Satu gangguan massal dengan banyak tiket pelanggan |
| Credential phishing | Phishing yang bertujuan mencuri username dan password lewat halaman login tiruan | Pelanggan yang diarahkan ke portal palsu untuk menyerahkan PIN |
| Safe Links | Fitur Defender for Office 365 yang membungkus URL dan memeriksanya saat diklik | Proxy transparan yang memeriksa setiap koneksi saat dibuat |
| ZAP (zero-hour auto purge) | Tindakan otomatis Microsoft 365 atas pesan yang belakangan dinilai berbahaya, dalam 48 jam setelah dikirim | Rule otomatis yang menarik konfigurasi bila belakangan diketahui salah |
| Purge (remediation email) | Memindahkan atau menghapus salinan email dari banyak mailbox sekaligus oleh admin | Menarik massal konfigurasi salah dari semua perangkat lewat NMS |
| Detonation | Menjalankan lampiran atau membuka URL di sandbox untuk melihat perilakunya | Menguji perangkat RMA di lab sebelum dipasang |

### 1.1 Header email: dari mana pesan ini sebenarnya datang

Pertanyaan pertama Dimas ("itu benar dari kita?") dijawab dari header, bukan dari nama pengirim yang tampil. Nama tampilan "IT Helpdesk JAB" bisa ditulis siapa saja.

Satu email membawa dua lapis alamat. **Envelope** dipakai server saat transaksi SMTP: perintah `MAIL FROM` menentukan alamat balasan untuk bounce, yang di pesan terlihat sebagai `Return-Path`. **Header pesan** berisi `From`, `To`, `Reply-To`, dan `Subject` yang ditampilkan ke pengguna. Keduanya tidak harus sama, dan penyerang memanfaatkan perbedaan itu. Microsoft menyebut domain `MAIL FROM` sebagai `5321.MailFrom` atau P1 sender dan domain `From` sebagai `5322.From` atau P2 sender, yaitu alamat yang dilihat penerima di aplikasi email [S6].

Urutan membaca header di PT JAB:

1. **`Received` dari atas ke bawah.** Setiap server menambahkan header `Received` di atas pesan, sehingga yang paling atas adalah hop terakhir (server penerima milikmu) dan yang paling bawah adalah klaim hop pertama. Hanya hop yang ditulis server milikmu atau penyedia emailmu yang bisa dipercaya. Header `Received` di bawahnya ditulis server lain, termasuk server penyerang, dan bisa berisi apa saja. Yang paling berguna adalah hop pertama yang ditulis Microsoft 365: di situ tercatat IP server yang benar-benar menyerahkan pesan.
2. **`Return-Path` dibanding `From`.** Domain yang berbeda bukan bukti phishing (layanan newsletter sah sering memakai domain bounce sendiri), tetapi menjelaskan kenapa SPF bisa lolos untuk domain yang bukan domain `From`.
3. **`Reply-To`.** Bila berbeda dari `From`, balasan pengguna pergi ke alamat lain. Ini pola klasik BEC dan phishing yang mengharap balasan.
4. **`Message-ID` dan `Date`.** `Message-ID` dipakai untuk mencari pesan yang sama di message trace dan alat lain. `Date` ditulis klien atau server pengirim dan biasanya dalam UTC; WIB adalah UTC+7.
5. **Header hasil pemeriksaan penerima**: `Authentication-Results` dan `X-Forefront-Antispam-Report` (bagian 1.2 dan 2.1).

Satu hal tentang kepercayaan: `Authentication-Results` tidak punya proteksi integritas. RFC 8601 meminta server perbatasan menghapus header itu bila datang dari luar dengan authserv-id milik organisasi sendiri, dan meminta pembacanya memeriksa authserv-id sebelum memercayai isinya [S5]. Artinya, kalau ada dua header `Authentication-Results`, yang dipercaya adalah yang ditulis server penerimamu sendiri, bukan yang dibawa pesan dari luar.

Di `INC-2026-020`, header menunjukkan pesan diserahkan oleh `203.0.113.105` (`mail.notif-portal.example.net`), `Return-Path` di `bounce.notif-portal.example.net`, `From` di `jab-support.example.net`, dan tidak ada satu pun hop milik PT JAB sebelum Microsoft 365 menerima pesan. Email itu bukan dari PT JAB. Header lengkap dan cara membacanya ada di bagian 2.1.

### 1.2 SPF, DKIM, DMARC: apa yang dibuktikan dan apa yang tidak

Pertanyaan kedua Dimas ("SPF pass berarti asli?") adalah salah paham yang paling sering muncul di triage phishing. Jawabannya: SPF pass hanya membuktikan IP pengirim diizinkan oleh domain di envelope, bukan bahwa pengirimnya PT JAB.

Tabel berikut adalah ringkasan apa yang diperiksa setiap mekanisme. Baca kolom "Tidak membuktikan", karena di situlah penyerang bekerja.

| Mekanisme | Memeriksa | Membuktikan | Tidak membuktikan |
|---|---|---|---|
| SPF | IP pengirim terhadap record SPF domain di `MAIL FROM` (dan identitas HELO) [S1] | IP itu diizinkan mengirim untuk domain envelope | Apa pun tentang domain `From` yang dilihat pengguna |
| DKIM | Tanda tangan atas header dan body, kunci publik di `<selector>._domainkey.<domain d=>` [S2] | Domain `d=` bertanggung jawab atas pesan dan bagian yang ditandatangani tidak berubah | Bahwa `d=` sama dengan domain `From`, atau bahwa pesannya aman |
| DMARC | Apakah SPF atau DKIM lolos dengan domain yang aligned ke domain `From`, lalu kebijakan pemilik domain `From` [S3][S4] | Domain `From` benar-benar dipakai oleh pihak yang diizinkan pemiliknya | Bahwa domain `From` bukan domain penyerang sendiri; lookalike domain tidak tertangani |

Detail yang perlu diingat dari standarnya:

- **SPF** memeriksa identitas `MAIL FROM` dan HELO; RFC 7208 tidak menyarankan memakai record SPF untuk identitas lain. Hasilnya `none`, `neutral`, `pass`, `fail`, `softfail`, `temperror`, atau `permerror`, dan evaluasi dibatasi maksimal 10 mekanisme yang memicu query DNS (`include`, `a`, `mx`, `ptr`, `exists`, `redirect`); lewat dari itu hasilnya `permerror` [S1].
- **DKIM**: domain penanda tangan tidak harus cocok dengan field lain di pesan, dan verifikasi hanya menyatakan bagian yang di-hash tidak berubah, tidak menyatakan hal lain. Server yang memodifikasi pesan di tengah jalan bisa membuat tanda tangan gagal [S2].
- **DMARC**: pesan lolos bila minimal satu dari SPF atau DKIM lolos dan menghasilkan domain yang aligned. Untuk DKIM yang dibandingkan adalah `d=`, untuk SPF adalah domain `MAIL FROM`. Mode relaxed (default) cukup sama organisasinya, mode strict harus sama persis. Kebijakan `p=none` hanya meminta laporan, `p=quarantine` dan `p=reject` meminta penerima menahan atau menolak [S3]. RFC 7489 juga menyatakan DMARC tidak menangani penyalahgunaan nama tampilan dan domain mirip [S3].

Microsoft 365 menuliskan hasilnya di `Authentication-Results`, misalnya `spf=pass ... smtp.mailfrom=<domain>`, `dkim=pass ... header.d=<domain>`, `dmarc=<hasil> action=<tindakan> header.from=<domain>`, ditambah `compauth` dengan kode alasan tiga digit [S6]. Beberapa nilai yang sering muncul saat triage [S6]:

- `dmarc=none`: domain `From` tidak punya record DMARC.
- `dmarc=bestguesspass`: tidak ada record DMARC, tetapi pesan akan lolos seandainya ada.
- `action=oreject`: muncul pada pesan yang gagal DMARC dengan kebijakan `p=reject`. Halaman header Microsoft tidak menjelaskan arti persisnya, jadi cek lokasi akhir pesan (Inbox, Junk, karantina) di Threat Explorer, jangan menyimpulkan pesan pasti ditolak.
- `compauth=fail reason=000`: gagal DMARC dengan kebijakan `quarantine` atau `reject`. `reason=001`: gagal autentikasi implisit, yaitu domain tidak memublikasikan record atau kebijakannya lemah. `reason=601`: domain pengirim adalah accepted domain organisasimu sendiri (spoofing dari dalam ke dalam).
- Microsoft juga menyebut pesan tetap bisa dikirim ke Inbox walaupun `compauth` gagal, bila penilaian lain tidak menganggapnya mencurigakan [S6].

Dari situ, dua pola penyerang yang paling sering terlihat:

1. **Domain sendiri yang lolos semua.** Penyerang mendaftarkan domain, memasang SPF dan DKIM dengan benar, lalu mengirim. SPF dan DKIM lolos, DMARC lolos atau `none`. Semua hijau, tetapi domainnya milik penyerang.
2. **Lookalike domain di `From`, domain lain di envelope.** Yang terjadi di `INC-2026-020`: SPF dan DKIM lolos untuk `notif-portal.example.net`, sedangkan `From` memakai `jab-support.example.net` yang tidak punya record DMARC, sehingga hasilnya `dmarc=none` dan `compauth=fail reason=001`, tetapi pesan tetap terkirim.

Pola yang tidak bisa dipakai penyerang di sini justru spoofing langsung `@jab.example`. PT JAB memublikasikan DMARC `p=reject` untuk `jab.example`, sehingga email yang mengaku dari `it-helpdesk@jab.example` tanpa SPF atau DKIM yang aligned akan gagal DMARC dan ditangani sebagai spoofing. Panduan bersama CISA, NSA, FBI, dan MS-ISAC menyarankan DMARC diaktifkan untuk email masuk dan diatur ke `reject` untuk email keluar karena alasan ini [S13]. Itu juga sebabnya penyerang memilih domain mirip.

### 1.3 Memetakan kampanye: dari satu laporan ke semua penerima

Pertanyaan ketiga Dimas ("berapa orang yang terima?") adalah langkah scoping untuk email. Enam laporan bukan enam insiden; enam laporan adalah enam sensor yang melihat satu kampanye.

**Laporan pengguna sebagai sensor.** Di Microsoft 365, tombol Report bawaan Outlook mengirim pesan yang dilaporkan ke Microsoft, ke reporting mailbox organisasi, atau keduanya, sesuai pengaturan User reported settings; default-nya keduanya, dan bila reporting mailbox belum diisi, yang dipakai adalah mailbox global admin [S11]. Dokumentasi Microsoft meminta reporting mailbox didaftarkan sebagai SecOps mailbox di advanced delivery policy supaya laporan tidak ikut difilter, dan supaya pesan simulasi phishing yang dilaporkan tidak memicu penugasan training [S11]. Untuk investigasi otomatis dari laporan pengguna, alert policy "Email reported by user as malware or phish" harus aktif dan tidak di-resolve otomatis oleh aturan tuning [S11]. Di PT JAB, reporting mailbox adalah `phishing-report@jab.example`, dan setiap laporan membuat alert di antrean SOC.

**Dari ciri ke kampanye.** Dari satu pesan yang dilaporkan, ambil ciri yang stabil lalu cari semua pesan yang cocok:

| Ciri | Kenapa dipakai | Kelemahan |
|---|---|---|
| Alamat dan domain pengirim (`From` dan `MAIL FROM`) | Paling cepat, biasanya sama di satu gelombang | Penyerang bisa merotasi alamat per batch |
| Subjek | Mudah dicari di message trace | Bisa divariasikan per penerima |
| IP server pengirim | Menangkap pesan dari infrastruktur yang sama walau alamatnya beda | Layanan email massal dipakai banyak pengirim sah |
| Domain URL di body | Yang menentukan apakah pengguna dalam bahaya | Tidak terlihat di message trace biasa; butuh Threat Explorer atau log URL |
| Hash lampiran | Tepat untuk lampiran yang sama | Penyerang mudah mengubah hash per penerima |

Alatnya:

- **Message trace** mencari pesan yang lewat Exchange Online berdasarkan pengirim, penerima, subjek, IP, atau `Message-ID`. Di PowerShell, `Get-MessageTraceV2` menggantikan `Get-MessageTrace`; data bisa dicari sampai 90 hari ke belakang, tetapi satu query hanya mengembalikan maksimal 10 hari data, default 1.000 hasil dan maksimal 5.000, dengan waktu keluaran dalam UTC [S7]. Contohnya di bagian 2.2.
- **Threat Explorer** (Defender for Office 365 Plan 2) menampilkan pesan beserta URL, lokasi pengiriman saat ini (Inbox, Junk, karantina, terhapus), dan tindakan susulan seperti ZAP, dan dari situ juga bisa langsung menjalankan remediation [S8][S10].

Di `INC-2026-020`, pencarian berdasarkan domain `From` dan IP pengirim menemukan 34 pesan ke 34 penerima, dikirim antara 08:14 dan 08:19 WIB. Itulah scope kampanye: 34 mailbox yang harus ditarik dan 34 orang yang perlu diperiksa interaksinya.

### 1.4 Siapa yang klik, dan siapa yang menyerahkan password

Pertanyaan keempat Dimas memisahkan tiga tingkat paparan, dan tindakan untuk masing-masing berbeda:

| Tingkat | Artinya | Tindakan |
|---|---|---|
| Menerima | Pesan ada di mailbox | Purge (bagian 1.6) |
| Klik | Pengguna membuka halaman phishing | Pastikan tidak ada pengiriman kredensial atau unduhan; tanyakan ke pengguna |
| Mengirim kredensial | Pengguna mengisi form login tiruan dan mengirimnya | Penanganan akun segera (bagian 1.7) |

Sumber data untuk membedakannya saling melengkapi; tidak ada satu sumber yang melihat semuanya.

- **Safe Links.** Klik pada URL yang dibungkus Safe Links tercatat, dan di advanced hunting tersedia di tabel `UrlClickEvents` dengan field `Url`, `AccountUpn`, `ActionType` (klik diizinkan atau diblok), `IsClickedThrough` (pengguna menembus halaman peringatan), `ThreatTypes` (verdict saat klik), `IPAddress`, dan `NetworkMessageId` untuk menghubungkan klik dengan pesannya [S12]. Kelebihannya: mencakup klik dari ponsel dan dari luar kantor. Keterbatasannya: hanya klik lewat tautan yang dibungkus, dan tidak melihat apa yang terjadi setelah halaman terbuka.
- **Log proxy.** Proxy kantor melihat permintaan ke halaman phishing dari jaringan kantor. Perbedaan yang paling penting adalah metode HTTP: `GET` berarti halaman dibuka, `POST` ke halaman form berarti ada data yang dikirim. Ini hanya bisa dilihat bila proxy mendekripsi TLS untuk kategori tujuan itu; tanpa dekripsi, yang terlihat hanya nama host dan jumlah byte, dan pengiriman kredensial hanya bisa diduga dari pola byte keluar. Di PT JAB, proxy mendekripsi trafik ke kategori domain baru dan tidak terkategori.
- **Log DNS.** Menunjukkan host mana yang me-resolve domain phishing, termasuk yang tidak lewat proxy. Resolve belum berarti halaman dibuka.
- **Pengguna sendiri.** Pertanyaan langsung ("apakah kamu mengisi password di halaman itu?") tetap perlu, tetapi jawabannya dicatat sebagai keterangan, bukan bukti. Pengguna yang takut sering menjawab "tidak".

Di `INC-2026-020`, data tiga sumber menghasilkan tiga orang yang perlu diperhatikan. `lestari.putri` (Customer Service Jakarta, `JKT-WS-0466`, `10.10.46.66`) membuka halaman pukul 08:31:12 dan mengirim `POST` pukul 08:32:05: kredensial hampir pasti terkirim. `nur.aini` (Keuangan Jakarta, `JKT-WS-0471`, `10.10.47.71`) membuka halaman pukul 08:47:40 tanpa `POST`. `hadi.kurniawan` (Bandung) mengklik dari Outlook di ponsel pukul 09:48 dan diblok Safe Links, karena verdict URL sudah berubah. Query dan cara membacanya ada di bagian 2.3 dan 2.4.

### 1.5 Triage URL dan lampiran secara aman

Pertanyaan kelima Dimas ("link-nya boleh saya buka sebentar?") jawabannya tidak, setidaknya tidak dari laptop kantornya. Bukan hanya karena bisa ada malware, tetapi karena membuka halaman phishing juga memberi informasi ke penyerang.

**Kenapa membuka URL itu berisiko, walau hanya "melihat":**

- URL phishing sering membawa identitas penerima. Di `INC-2026-020`, parameter `u=` berisi alamat email penerima yang di-encode base64 (`bGVzdGFyaS5wdXRyaUBqYWIuZXhhbXBsZQ==` adalah `lestari.putri@jab.example`). Membuka URL itu dari jaringan PT JAB memberi tahu penyerang bahwa salinan milik Lestari dibuka, dari IP PT JAB.
- Kunjungan dari IP organisasi target, di luar pola penerima biasa, bisa menjadi tanda bagi penyerang bahwa kampanyenya sedang dianalisis.
- `[komunitas, belum terkonfirmasi]` Praktisi melaporkan bahwa kit phishing sering memakai daftar blokir IP untuk mengarahkan peneliti dan sandbox ke halaman sah, sehingga halaman bisa tampak tidak berbahaya dari satu lokasi dan berbahaya dari lokasi lain. Seberapa umum perilaku ini belum terkonfirmasi sumber primer; anggap saja hasil "bersih" dari satu lokasi belum final.

**Layanan scan publik juga punya risiko.** Riset Positive Security (2022) menemukan URL sensitif, termasuk link reset password, undangan, dan invoice, bisa dicari publik di urlscan.io karena alat keamanan dan playbook SOAR mengirim setiap link dari email masuk sebagai scan publik; satu bug di integrasi SOAR bahkan memaksa visibilitas publik [S14]. Untuk triage phishing, itu berarti URL yang berisi alamat email karyawan atau token unik tidak boleh dikirim sebagai scan publik.

**Urutan triage URL di PT JAB:**

1. Ambil URL asli dari header atau body (bukan dengan mengklik), lalu buka bungkus Safe Links bila ada.
2. Hapus atau ganti identitas penerima dari parameter URL sebelum dikirim ke mana pun.
3. Cek reputasi domain dan IP lewat pencarian (bukan kunjungan): umur domain, sertifikat, apakah sudah dikenal.
4. Bila halaman perlu dilihat, buka dari lingkungan analisis terpisah dengan jalur internet yang tidak terkait PT JAB, atau pakai layanan scan dengan visibilitas privat atau unlisted.
5. Catat hasil (screenshot, domain akhir setelah redirect, form yang dipakai) sebagai bukti di folder insiden.

**Lampiran.** Prinsipnya sama: jangan dibuka di workstation biasa, dan jangan diunggah ke layanan publik sebelum dipikirkan. Langkah aman:

1. Hitung hash dan cari hash itu di layanan reputasi. Mencari hash tidak membocorkan isi file; mengunggah file bisa membuat isinya dapat diakses pihak lain, termasuk dokumen internal yang ikut terlampir.
2. Periksa ekstensi dan tipe sebenarnya. Pada email `INC-2026-019` (Day 03 sampai Day 05), lampiran `Tagihan-Okt-2026.zip` berisi `Tagihan-Okt-2026.js`, yaitu skrip yang dijalankan Windows Script Host, bukan dokumen tagihan. Panduan CISA menyarankan denylist untuk ekstensi berisiko seperti `.scr`, `.exe`, `.pif`, dan `.cpl`, serta file yang ekstensinya disamarkan [S13].
3. Detonation dilakukan di sandbox, baik milik penyedia email (Safe Attachments) atau sandbox internal yang terisolasi. Analisis malware yang lebih dalam diserahkan ke tim atau pihak yang mengkhususkan diri, seperti disarankan panduan CISA [S13].

### 1.6 Purge: menarik email dari semua mailbox, dan batas tindakan otomatis

Pertanyaan keenam Dimas punya dua bagian: bisakah email ditarik, dan apakah ZAP sudah cukup.

**ZAP.** Zero-hour auto purge bekerja otomatis di semua mailbox Exchange Online: bila setelah pengiriman sebuah pesan dinilai phishing, spam, atau malware, ZAP bertindak atas pesan yang sudah ada di mailbox, dengan pencarian terbatas pada email yang dikirim dalam 48 jam terakhir, dan pengguna tidak diberi tahu [S10]. Yang sering disalahpahami adalah tindakannya [S10]:

- Untuk verdict **phishing** (bukan high confidence), tindakan ZAP mengikuti pengaturan anti-spam policy. Pada default anti-spam policy, tindakannya memindahkan pesan ke folder Junk Email; pada preset Standard dan Strict, pesan dikarantina.
- Untuk **high confidence phishing** dan **malware**, pesan dikarantina.
- ZAP bisa dikalahkan allowlist dan mail flow rule.

Jadi ZAP yang "sudah jalan" bisa berarti pesan hanya pindah ke Junk, masih bisa dibuka, dan link-nya masih bisa diklik. Di `INC-2026-020`, PT JAB masih memakai default anti-spam policy: pukul 09:22 ZAP memindahkan 32 pesan ke Junk, dan pukul 09:48 Hadi membuka salah satunya dari folder Junk di ponselnya. Safe Links memblok kliknya, tetapi itu keberuntungan urutan waktu, bukan kontrol yang direncanakan.

**Remediation oleh admin.** Dengan Defender for Office 365 Plan 2, pesan dipilih di Threat Explorer (manual atau seluruh hasil query) lalu diberi tindakan: move to junk, move to inbox, move to deleted items, soft delete, atau hard delete [S8]. Hal yang perlu diketahui [S8]:

- **Soft delete** memindahkan pesan ke Recoverable Items\Deletions; masih bisa dipulihkan pengguna dan admin. **Hard delete** mem-purge pesan; admin masih bisa memulihkannya lewat single item recovery.
- Pesan di Inbox, Junk, Deleted Items, Recoverable Items\Deletions, dan karantina bisa ditindak. Pesan yang sudah di-hard-delete pengguna, pesan on-premises atau eksternal, dan pesan yang gagal terkirim tidak bisa ditindak.
- Pelaksana dengan izin yang cukup bisa langsung menjalankan tindakan; tanpa izin itu, tindakan masuk antrean persetujuan dua langkah. Persetujuan butuh peran Search and Purge.
- Setiap remediation membuat alert "Administrative action submitted by an Administrator" dan investigasi, dan riwayatnya ada di Action center selama 30 hari dengan status per pesan (berhasil, gagal, sudah di tujuan).
- Ada batas: maksimal 50 remediation aktif bersamaan per organisasi, dan aturan 40 persen penerima untuk remediation besar.

**Tanpa Plan 2.** Organisasi tanpa Threat Explorer memakai search and purge di Microsoft Purview: buat pencarian dengan `New-ComplianceSearch`, jalankan, lalu `New-ComplianceSearchAction -Purge -PurgeType SoftDelete` atau `HardDelete` [S9]. Batasnya lebih ketat: maksimal 10 item per mailbox per tindakan (100 item bila memakai Microsoft Graph pada kasus eDiscovery dengan fitur premium), maksimal 50.000 mailbox per pencarian, tidak menghapus item yang tidak terindeks, dan pesan di mailbox dengan hold tetap disimpan sampai hold berakhir [S9]. Purge yang sudah dijalankan tidak bisa dibatalkan, jadi hasil pencarian diverifikasi dulu (jumlah dan isi) sebelum purge [S9]. Untuk menjalankan cmdlet purge, dokumentasi terbaru meminta modul Exchange Online PowerShell versi 3.9.0 atau lebih baru dan `Connect-IPPSSession -EnableSearchOnlySession` [S9]. Microsoft sendiri menyarankan prosedur remediation Defender bila organisasi punya Plan 2 [S9].

**Soft atau hard delete?** Di PT JAB, purge kampanye phishing memakai soft delete. Pesan hilang dari pandangan pengguna, tetapi masih bisa dipulihkan bila ternyata ada pesan sah yang ikut tertarik karena query terlalu luas, dan salinan pesan tetap tersedia sebagai bukti. Sebelum purge, satu salinan pesan lengkap (format `.eml` atau `.msg`) dari reporting mailbox disimpan ke folder bukti insiden.

**Purge tidak membatalkan klik.** Purge menghapus kesempatan klik berikutnya. Pengguna yang sudah mengirim password, sudah meneruskan pesan ke alamat pribadi, atau sudah menjalankan lampiran tetap harus ditangani terpisah.

### 1.7 Setelah purge: pengguna yang terkena, blok, dan komunikasi

Pertanyaan terakhir Dimas ("yang sudah memasukkan password kita apakan?") membawa insiden keluar dari email.

Panduan CISA untuk respons setelah phishing berhasil (kredensial bocor atau malware berjalan) berisi enam langkah: menyediakan ulang akun yang diduga atau terbukti terkompromi, mengaudit akses akun itu untuk memastikan penyerang tidak lagi punya akses, mengisolasi workstation yang terdampak, menganalisis malware, mengeradikasi malware, lalu memulihkan sistem dan memastikan fungsinya normal [S13]. Untuk credential phishing, yang relevan adalah dua langkah pertama.

Di PT JAB, alurnya mengikuti dua playbook:

1. `JAB-PB-02` Phishing dan BEC menangani emailnya: pemetaan kampanye, blok, purge, komunikasi.
2. Setiap pengguna dengan tingkat "mengirim kredensial" diserahkan ke `JAB-PB-03` Kompromi akun: reset password, revoke sessions, periksa apakah metode MFA atau perangkat baru didaftarkan, lalu periksa log sign-in dan aktivitas mailbox sejak waktu pengiriman kredensial. Pemeriksaan sign-in dan mailbox itu adalah investigasi tersendiri dan tidak dibahas di Day ini.

Satu perbedaan dengan Day 05 bagian 1.5 perlu dicatat. Di `INC-2026-019`, reset kredensial ditunda ke jam H karena penyerang sudah di dalam dengan beberapa akses, dan reset satu akun hanya memberi tahu dia. Di credential phishing, akses penyerang yang diketahui adalah password yang baru saja dicuri, dan setiap menit penundaan adalah menit di mana password itu bisa dipakai. Karena itu reset dan revoke sessions untuk Lestari dijalankan segera. Bila pemeriksaan sign-in kemudian menunjukkan penyerang sudah masuk dan bergerak, pertimbangan Day 05 berlaku lagi untuk akses berikutnya.

**Blok.** Untuk halaman phishing, blok dijalankan segera setelah kampanye terpetakan, tidak menunggu jam H, karena tujuannya mencegah pengguna berikutnya mengirim password, dan penyerang sudah tahu laporan pengguna adalah risiko biasa kampanyenya. Prinsip Day 05 bagian 1.6 tetap dipakai: blok dengan logging. Di PT JAB:

- Domain halaman phishing di proxy (kategori diblok) dan di DNS sinkhole `jkt-sink01` (`10.20.99.99`), sehingga host yang masih mencoba membuka tercatat.
- IP halaman phishing di firewall perimeter, dengan logging.
- Domain dan alamat pengirim di Tenant Allow/Block List supaya gelombang berikutnya dari pengirim yang sama ditolak.

**Komunikasi.** Pelapor diberi tahu laporannya benar dan sudah ditangani; ini yang membuat mereka melapor lagi. Seluruh 34 penerima diberi tahu bahwa email itu phishing, sudah ditarik, dan siapa pun yang sempat mengisi password diminta segera menghubungi SOC. Pesan dikirim dari alamat yang dikenal pengguna, tanpa link, dan tidak meminta pengguna mengklik apa pun, supaya tidak mengajari pola yang sama dengan phishing.

**Kapan insiden email selesai.** `INC-2026-020` dianggap selesai di sisi email bila: semua salinan yang bisa ditindak sudah ditarik dan status per pesan terverifikasi di Action center; blok terpasang dan log blok dipantau; semua pengguna di tingkat "klik" sudah dikonfirmasi; dan semua pengguna di tingkat "mengirim kredensial" sudah diserahkan ke `JAB-PB-03`. Status akun Lestari menentukan apakah severity insiden tetap atau naik.

## 2. Contoh artefak dan langkah praktis di PT JAB

Semua isi bagian ini fiktif dan merupakan keluaran ilustrasi. Query Splunk memakai index PT JAB dengan field mengikuti CIM (`url`, `http_method`, `src`, `user`, `bytes_out` untuk proxy; `query` dan `src` untuk DNS); cocokkan dengan add-on yang kamu pakai.

### 2.1 Header email yang dilaporkan

Header ini menjawab pertanyaan 1 dan 2 Dimas. Diambil dari salinan pesan di reporting mailbox, diringkas (beberapa header internal Microsoft dihapus dan nama server Microsoft dipendekkan).

```
Received: from MX0P123MB0001.prod.outlook.com (2603:10b6:...) by
 MX0P123MB0042.prod.outlook.com with HTTPS; Wed, 21 Oct 2026 01:14:09 +0000
Received: from EOP-EDGE-01.mail.protection.outlook.com (10.167.0.10) by
 MX0P123MB0001.prod.outlook.com with Microsoft SMTP Server; Wed, 21 Oct 2026 01:14:08 +0000
Received: from mail.notif-portal.example.net (203.0.113.105) by
 EOP-EDGE-01.mail.protection.outlook.com (10.167.0.10) with Microsoft SMTP Server;
 Wed, 21 Oct 2026 01:14:07 +0000
Received: from helpdesk-srv (unknown [10.1.1.5]) by mail.notif-portal.example.net;
 Wed, 21 Oct 2026 01:13:58 +0000
Authentication-Results: spf=pass (sender IP is 203.0.113.105)
 smtp.mailfrom=bounce.notif-portal.example.net; dkim=pass (signature was verified)
 header.d=notif-portal.example.net; dmarc=none action=none
 header.from=jab-support.example.net;compauth=fail reason=001
Return-Path: bounce-7731@bounce.notif-portal.example.net
From: "IT Helpdesk JAB" <it-helpdesk@jab-support.example.net>
Reply-To: <noreply@jab-support.example.net>
To: <lestari.putri@jab.example>
Subject: [PENTING] Password Microsoft 365 Anda kedaluwarsa hari ini
Date: Wed, 21 Oct 2026 01:13:58 +0000
Message-ID: <20261021011358.4f2a9c@notif-portal.example.net>
X-Forefront-Antispam-Report: CIP:203.0.113.105;CTRY:;LANG:id;SCL:1;SRV:;IPV:NLI;
 SFV:NSPM;H:mail.notif-portal.example.net;PTR:mail.notif-portal.example.net;
 DIR:INB;SFTY:9.25
```

Link di body (setelah bungkus Safe Links dibuka): `https://sso.jab-akun.example.net/owa/?u=bGVzdGFyaS5wdXRyaUBqYWIuZXhhbXBsZQ==`

Cara membaca elemennya:

- **`Received` ketiga dari atas** adalah hop yang bisa dipercaya: server Microsoft 365 mencatat bahwa pesan diserahkan oleh `203.0.113.105` yang menyebut dirinya `mail.notif-portal.example.net`, pukul 01:14:07 UTC atau 08:14:07 WIB. `Received` paling bawah ditulis server pengirim sendiri; isinya (`helpdesk-srv`, `10.1.1.5`) tidak bisa diverifikasi dan tidak dipakai sebagai fakta.
- **Tidak ada hop milik PT JAB** sebelum Microsoft 365 menerima pesan. Email karyawan PT JAB yang sah dikirim dari tenant Microsoft 365 PT JAB sendiri, sehingga akan tercatat sebagai pesan internal (`DIR:INT`), bukan pesan masuk dari internet (`DIR:INB`) [S6].
- **`Authentication-Results`**: SPF lolos untuk `bounce.notif-portal.example.net`, DKIM lolos untuk `notif-portal.example.net`, tetapi domain `From` adalah `jab-support.example.net`. Dengan alignment relaxed, kedua domain yang lolos tidak satu organisasi dengan domain `From`, dan domain `From` tidak punya record DMARC (`dmarc=none`). `compauth=fail reason=001` adalah kegagalan autentikasi implisit [S6]. Pesan tetap masuk Inbox karena `SFV:NSPM` (dinilai bukan spam saat itu) [S6].
- **`From` dan `Reply-To`** memakai lookalike domain `jab-support.example.net`. Domain email PT JAB adalah `jab.example`.
- **`IPV:NLI`** berarti IP pengirim tidak ada di daftar reputasi mana pun saat pesan diterima; infrastruktur baru [S6].
- **`SFTY:9.25`** adalah first contact safety tip: penerima belum pernah menerima email dari alamat ini [S6]. Tanda ini hanya muncul bila first contact safety tip diaktifkan di anti-phishing policy.
- **Parameter `u=`** di link berisi `lestari.putri@jab.example` dalam base64. Setiap penerima mendapat link unik.

**Kapan gagal:** header yang dianalisis diambil dari pesan yang sudah diteruskan pengguna sebagai email biasa (bukan lewat tombol Report atau sebagai lampiran). Penerusan biasa mengganti header dengan header pengguna yang meneruskan, sehingga asal pesan aslinya hilang. Minta pengguna memakai tombol Report, atau ambil salinan asli lewat Threat Explorer.

### 2.2 Message trace: berapa mailbox yang menerima

Langkah ini menjawab pertanyaan 3 Dimas.

**Tujuan:** mencari semua pesan dari domain pengirim yang sama dalam rentang waktu kampanye, lalu menghitung penerima dan status pengirimannya.

```powershell
Connect-ExchangeOnline
Get-MessageTraceV2 -StartDate "10/21/2026 00:00" -EndDate "10/21/2026 03:00" `
  -FromIP 203.0.113.105 -ResultSize 5000 |
  Select-Object Received, SenderAddress, RecipientAddress, Subject, Status, FromIP |
  Sort-Object Received
```

Penjelasan tiap bagian:

- `-StartDate` dan `-EndDate` mengikuti format tanggal regional mesin yang menjalankan perintah. Rentang di atas ditulis dalam UTC (00:00 sampai 03:00 UTC adalah 07:00 sampai 10:00 WIB); cek pengaturan zona waktu sesimu, karena keluaran cmdlet selalu UTC [S7].
- `-FromIP` menangkap semua pesan dari server pengirim yang sama, termasuk bila alamat pengirim dirotasi. Variasinya `-SenderAddress` untuk alamat tertentu, atau `-Subject` dengan `-SubjectFilterType StartsWith` [S7].
- `-ResultSize 5000` adalah nilai maksimal; default 1.000 [S7].

Keluaran ilustrasi (diringkas):

```
Received              SenderAddress                       RecipientAddress            Status
--------              -------------                       ----------------            ------
10/21/2026 1:14:07 AM it-helpdesk@jab-support.example.net lestari.putri@jab.example   Delivered
10/21/2026 1:14:07 AM it-helpdesk@jab-support.example.net nur.aini@jab.example        Delivered
...
10/21/2026 1:19:31 AM it-helpdesk@jab-support.example.net hadi.kurniawan@jab.example  Delivered
(34 baris, semua Delivered)
```

Cara membaca hasil: 34 baris, semua `Delivered`, pertama 01:14:07 UTC dan terakhir 01:19:31 UTC (08:14:07 sampai 08:19:31 WIB). Tidak ada yang `FilteredAsSpam` atau `Quarantined`, sehingga semua pesan sempat ada di Inbox. Status message trace adalah status saat pengiriman; tindakan ZAP setelahnya tidak terlihat di sini dan dicek di Threat Explorer [S10].

**Variasi:** di Threat Explorer, filter tampilan All email dengan domain pengirim dan rentang waktu yang sama, lalu tambahkan kolom URL domain dan lokasi pengiriman terbaru. Tampilan ini sekaligus menunjukkan berapa pesan yang sudah dipindahkan ZAP (kolom tindakan tambahan bernilai ZAP) [S10].

**Kapan gagal:** penyerang mengirim gelombang kedua dari IP lain dengan domain `From` yang sama. Ulangi pencarian dengan `-SenderAddress` atau domain URL, jangan hanya dengan IP.

### 2.3 Log proxy dan DNS: siapa yang membuka halaman dan siapa yang mengirim data

Query ini menjawab pertanyaan 4 Dimas untuk host di jaringan kantor.

**Tujuan:** menampilkan setiap host dan pengguna yang mengakses domain phishing, dan apakah ada permintaan `POST`.

```
index=proxy (dest="jab-akun.example.net" OR dest="*.jab-akun.example.net")
earliest="10/21/2026:08:00:00" latest="10/21/2026:10:30:00"
| stats min(_time) as first_seen max(_time) as last_seen values(http_method) as methods
    sum(bytes_out) as bytes_out count by src user
| eval kredensial_terkirim=if(isnotnull(mvfind(methods, "^POST$")), "kemungkinan", "tidak terlihat")
| sort first_seen
| convert ctime(first_seen) ctime(last_seen)
```

Penjelasan tiap bagian:

- `dest` memakai domain halaman phishing, termasuk subdomain (`sso.jab-akun.example.net`).
- `values(http_method)` mengumpulkan semua metode per host dan pengguna. `methods` adalah field multivalue, sehingga dicek dengan `mvfind` dan regex `^POST$`, bukan perbandingan string biasa.
- `sum(bytes_out)` membantu menilai bila proxy tidak mendekripsi TLS: pengiriman form biasanya menambah byte keluar.

Keluaran ilustrasi:

```
src          user           first_seen           last_seen            methods   bytes_out  count  kredensial_terkirim
10.10.46.66  lestari.putri  10/21/2026 08:31:12  10/21/2026 08:32:06  GET       4102       9      kemungkinan
                                                                      POST
10.10.47.71  nur.aini       10/21/2026 08:47:40  10/21/2026 08:47:41  GET       1874       6      tidak terlihat
```

Cara membaca hasil:

- `lestari.putri` membuka halaman pukul 08:31:12 lalu mengirim `POST` pukul 08:32:05, satu menit kemudian. Pola ini sesuai dengan mengisi form login. Kredensial dianggap terkirim sampai terbukti sebaliknya.
- `nur.aini` hanya `GET`. Halaman terbuka, tidak ada data form yang terlihat dikirim. Rudi tetap menelepon Nur untuk konfirmasi dan mencatat jawabannya.
- Hadi tidak muncul, karena ia membuka dari ponsel di luar jaringan kantor. Itu dijawab Safe Links (bagian 2.4), bukan proxy.

**Variasi DNS:** jalankan query yang sama di `index=dns query="*jab-akun.example.net"` dan bandingkan daftar `src`. Host yang muncul di DNS tetapi tidak di proxy perlu dijelaskan: memakai jalur internet lain, diblok proxy sebelum halaman terbuka, atau hanya pratinjau link.

**Kapan gagal:** pengguna membuka link dari rumah tanpa VPN, atau dari ponsel. Proxy dan DNS kantor tidak melihatnya. Karena itu klik Safe Links dan pertanyaan langsung ke pengguna tetap diperlukan.

### 2.4 Klik Safe Links di advanced hunting

Query ini melengkapi bagian 2.3 untuk klik dari luar jaringan kantor. Ditulis dalam KQL di advanced hunting Defender XDR; tabelnya hanya terisi bila Defender for Office 365 dipakai [S12].

```
UrlClickEvents
| where Timestamp between (datetime(2026-10-21T01:00:00Z) .. datetime(2026-10-21T04:00:00Z))
| where Url has "jab-akun.example.net"
| project Timestamp, AccountUpn, ActionType, IsClickedThrough, ThreatTypes, IPAddress, Workload
| order by Timestamp asc
```

Penjelasan tiap bagian:

- Rentang waktu dalam UTC (08:00 sampai 11:00 WIB).
- `ActionType` menunjukkan apakah klik diizinkan atau diblok Safe Links atau kebijakan tenant; `IsClickedThrough` menunjukkan apakah pengguna memilih tetap lanjut dari halaman peringatan [S12]. Cek nilai `ActionType` yang muncul di tenant-mu; contoh di dokumentasi memakai `ClickAllowed`.
- `IPAddress` adalah IP publik perangkat yang klik [S12]. IP di luar rentang kantor PT JAB menandakan klik dari luar.

Keluaran ilustrasi:

```
Timestamp             AccountUpn                  ActionType    IsClickedThrough  ThreatTypes  IPAddress        Workload
2026-10-21 01:31:10Z  lestari.putri@jab.example   ClickAllowed  false                          (IP kantor)      Email
2026-10-21 01:47:38Z  nur.aini@jab.example        ClickAllowed  false                          (IP kantor)      Email
2026-10-21 02:48:15Z  hadi.kurniawan@jab.example  ClickBlocked  false             Phish        198.51.100.117   Email
```

Cara membaca hasil: dua klik pertama diizinkan karena saat itu URL belum dikenal berbahaya, dan waktunya cocok dengan log proxy (beda dua detik karena klik tercatat sebelum halaman dimuat). Klik Hadi pukul 09:48 WIB dari `198.51.100.117` (jaringan seluler) diblok dengan verdict `Phish`, karena verdict URL sudah berubah sejak sekitar 09:20. Tidak ada `IsClickedThrough` bernilai true.

**Kapan gagal:** pengguna menyalin URL ke browser alih-alih mengkliknya, atau email dibuka di klien yang tidak didukung Safe Links. Klik itu tidak tercatat di tabel ini.

### 2.5 Purge kampanye dan cara membaca hasilnya

Langkah ini menjawab pertanyaan 6 Dimas. Dijalankan Rudi pukul 10:05 setelah satu salinan `.eml` disimpan ke `/evidence/INC-2026-020/` di `jkt-evid01`.

**Di Threat Explorer (jalur utama PT JAB):** tampilan All email, filter domain pengirim `jab-support.example.net` dan tanggal 21 Oktober 2026, pilih seluruh hasil query, lalu Take action dengan Soft delete, beri nama remediation `INC-2026-020 purge`. Pantau di Action center, tab History [S8].

**Jalur cadangan tanpa Plan 2 (Security & Compliance PowerShell):**

```powershell
Connect-IPPSSession -EnableSearchOnlySession
$q = '(From:it-helpdesk@jab-support.example.net) AND (Received:10/21/2026..10/21/2026) AND (Subject:"Password Microsoft 365 Anda kedaluwarsa")'
New-ComplianceSearch -Name "INC-2026-020" -ExchangeLocation All -ContentMatchQuery $q
Start-ComplianceSearch -Identity "INC-2026-020"
Get-ComplianceSearch -Identity "INC-2026-020" | Format-List Status, Items
New-ComplianceSearchAction -SearchName "INC-2026-020" -Purge -PurgeType SoftDelete
Get-ComplianceSearchAction -Identity "INC-2026-020_Purge"
```

Penjelasan tiap bagian:

- `-EnableSearchOnlySession` dibutuhkan untuk tindakan purge di modul versi 3.9.0 atau lebih baru [S9].
- Query memakai properti `From`, `Received`, dan `Subject` seperti contoh di dokumentasi [S9]. Makin spesifik query, makin kecil risiko pesan sah ikut terhapus.
- `Get-ComplianceSearch` dijalankan sebelum purge untuk memastikan jumlah item cocok dengan message trace (34). Bila jumlahnya jauh berbeda, query diperbaiki dulu.
- Objek purge diberi nama `<nama pencarian>_Purge`, dan statusnya dicek dengan `Get-ComplianceSearchAction` [S9].

Keluaran ilustrasi dari Action center (jalur Threat Explorer):

```
Remediation: INC-2026-020 purge | Action: Soft delete | Decided by: rudi.hartanto | Status: Completed
Email count: 34 | Remediable: 32 | Not remediable: 2
Action logs:  Success 32 | Failed 0 | Already in destination 0
Not remediable: 2 pesan, lokasi hard-deleted (dihapus permanen oleh pengguna)
```

Cara membaca hasil:

- **32 berhasil** termasuk pesan yang sebelumnya dipindahkan ZAP ke Junk.
- **2 tidak bisa ditindak** karena sudah dihapus permanen oleh pengguna sendiri; tidak ada lagi pesan yang bisa diklik. Kedua pengguna itu tetap masuk daftar konfirmasi, karena menghapus pesan tidak menjelaskan apakah mereka sempat klik.
- **Completed** berarti remediation selesai untuk semua pesan yang bisa ditindak, bukan berarti tidak ada yang terkena.

**Kapan gagal:** query pencarian terlalu luas (misalnya hanya `Subject:"Password"`) sehingga email sah dari tim IT ikut tertarik; atau terlalu sempit sehingga gelombang kedua dengan subjek berbeda tertinggal. Bandingkan selalu jumlah hasil pencarian dengan message trace sebelum menjalankan purge.

### 2.6 Update ke IC dan pesan ke pengguna

Update ini dikirim Rudi ke Dimas pukul 10:30 dan menjawab ketujuh pertanyaan dalam satu tempat. Polanya sama dengan update containment di Day 05 bagian 2.5: terverifikasi, belum, berikutnya.

```
INC-2026-020 | Update 10:30 | SEV-3 (dinyatakan 09:40) | untuk Dimas Prasetyo
ASAL: bukan dari PT JAB. Lookalike domain jab-support.example.net, dikirim dari
  203.0.113.105. SPF/DKIM pass untuk notif-portal.example.net, tidak aligned;
  dmarc=none; compauth=fail reason=001.
KAMPANYE: 34 penerima, terkirim 08:14-08:19. Halaman phishing
  sso.jab-akun.example.net (198.51.100.110), link unik per penerima.
PAPARAN:
- Kirim kredensial: lestari.putri (POST 08:32:05). Diserahkan ke JAB-PB-03:
  password direset dan sesi dicabut 09:55; pemeriksaan sign-in berjalan.
- Klik tanpa kirim: nur.aini (dikonfirmasi lisan 10:12, tidak mengisi apa pun).
- Klik diblok Safe Links: hadi.kurniawan 09:48 (dibuka dari folder Junk di ponsel).
- Penerima lain: belum ada indikasi klik di proxy, DNS, maupun Safe Links.
TINDAKAN TERVERIFIKASI: blok domain di proxy dan sinkhole 09:50; blok IP di firewall
  perimeter 09:50; pengirim diblok di Tenant Allow/Block List 09:52; soft delete
  10:05 selesai (32 berhasil, 2 sudah dihapus permanen pengguna).
ALERT TERKAIT: SOC-2026-0210 sampai 0215 (laporan pengguna 08:40-09:05), 0216 (ZAP
  09:22), 0217 (rule Splunk POST ke domain baru, 09:25), 0218 dan 0219 (laporan
  pengguna 09:45 dan 09:52). Semua digabung ke INC-2026-020.
BELUM: hasil pemeriksaan sign-in akun Lestari. Severity ditinjau ulang setelah itu.
CATATAN: ZAP 09:22 hanya memindahkan ke Junk (default anti-spam policy).
  Usulan perbaikan: tindakan phishing ke karantina. Dibawa ke review insiden.
Update berikutnya: 12:00 atau segera bila ada temuan sign-in.
```

Pesan ke 34 penerima, dikirim dari `soc@jab.example` pukul 10:40:

```
Subjek: Email "Password Microsoft 365 Anda kedaluwarsa" pagi ini adalah phishing

Pagi ini kamu menerima email dari "IT Helpdesk JAB" yang meminta login ulang.
Email itu bukan dari PT JAB dan sudah kami hapus dari mailbox.
Bila kamu sempat membuka link dan mengisi password, hubungi SOC sekarang di
ext. 1199. Tidak perlu khawatir disalahkan; makin cepat kami tahu, makin mudah
ditangani. Terima kasih untuk rekan-rekan yang sudah melapor lewat tombol Report.
```

Cara membaca elemennya:

- **Paparan dibagi per tingkat** (kirim kredensial, klik, diblok, menerima), sehingga Dimas tahu siapa yang butuh tindakan apa.
- **Usulan perbaikan ditulis**, tetapi tidak dijalankan di tengah insiden; perubahan policy anti-spam dibahas di review insiden.
- **Pesan ke pengguna tidak berisi link** dan memberi satu tindakan yang jelas. Kalimat "tidak perlu khawatir disalahkan" menjaga pengguna tetap mau melapor.

## 3. Lab praktik (di VM lab terisolasi)

Lab ini memakai mailbox uji di tenant lab atau tenant developer Microsoft 365 bila ada, server DNS lab, dan Splunk. Semua domain memakai `*.lab.test` atau domain dokumentasi. Jangan memakai email, domain, atau data dari pekerjaan nyata, dan jangan mengunjungi atau mengirim URL phishing sungguhan.

1. **Membaca header.** Kirim email dari akun pribadi ke mailbox uji lab, lalu ekspor header lengkapnya. Tandai setiap `Received` yang bisa dipercaya dan yang tidak, tulis IP hop pertama yang dicatat penerima, dan konversi semua waktu ke WIB.
2. **SPF, DKIM, DMARC di DNS lab.** Di zona DNS lab, buat record SPF, kunci DKIM, dan DMARC untuk `pengirim.lab.test`. Kirim email dari server SMTP lab dengan tiga variasi: semua benar; `MAIL FROM` di domain lain dengan `From` tetap `pengirim.lab.test`; dan `From` memakai domain mirip `pengirim-lab.test`. Catat `Authentication-Results` dan hasil DMARC untuk ketiganya, dan tulis satu kalimat kenapa variasi ketiga lolos atau tidak.
3. **Pemetaan kampanye.** Kirim 10 email dengan subjek sama ke mailbox uji. Cari semuanya dengan message trace (atau log server SMTP lab bila tidak ada tenant), lalu buat daftar penerima, waktu, dan status.
4. **Klik dan POST.** Di VM web lab, pasang halaman login tiruan sederhana di `login.lab.test` yang hanya mencatat permintaan (tanpa menyimpan password sungguhan). Dari VM Windows lab, buka halaman itu lalu kirim form dengan data palsu. Pastikan log proxy atau web server masuk ke Splunk, lalu jalankan query bagian 2.3 dan bedakan `GET` dan `POST`.
5. **Triage URL aman.** Buat URL ke `login.lab.test` dengan parameter `u=` berisi alamat email uji dalam base64. Tulis prosedur triage tertulis mengikuti bagian 1.5: cara mengambil URL tanpa klik, cara menghapus identitas penerima, dan lingkungan yang dipakai untuk melihat halaman.
6. **Purge.** Bila ada tenant lab dengan peran yang sesuai, jalankan pencarian dan soft delete untuk 10 email dari langkah 3 dengan jalur bagian 2.5, lalu cek hasilnya. Bila tidak ada tenant, tulis rencana purge lengkap dengan query, verifikasi jumlah, dan kriteria berhasil.

**Hasil yang sebaiknya tersimpan:**

- `latihan/day08-header.md` berisi header dari langkah 1 dengan anotasi hop.
- Tabel hasil langkah 2: tiga variasi, hasil SPF, DKIM, DMARC, dan penjelasannya.
- Cuplikan query dan hasil langkah 4 yang menunjukkan perbedaan `GET` dan `POST`.
- `latihan/day08-triage-url.md` berisi prosedur triage URL dari langkah 5.
- `latihan/day08-update.md` berisi update ke IC dengan format bagian 2.6 untuk kasus lab-mu.

**Variasi tantangan:** ulangi langkah 2 dengan email yang diteruskan lewat server perantara yang menambahkan footer ke body. Apa yang terjadi pada DKIM dan DMARC? Kenapa organisasi dengan `p=reject` kadang kehilangan email sah dari mailing list?

## 4. Troubleshooting

Tabel ini memuat masalah yang sering muncul saat menganalisis dan menarik email phishing. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa atau memperbaiki |
|---|---|---|
| Header yang dianalisis menunjukkan pengirim adalah karyawan sendiri | Pengguna meneruskan email biasa, bukan melaporkannya | Pakai salinan dari reporting mailbox atau Threat Explorer; latih pengguna memakai tombol Report |
| SPF dan DKIM pass, tetapi pesan jelas phishing | Domain milik penyerang atau envelope di domain lain | Bandingkan domain `smtp.mailfrom` dan `header.d` dengan `header.from`; nilai alignment [S3][S6] |
| `dmarc=fail` tetapi pesan tetap di Inbox | Kebijakan pengirim `p=none`, tindakan DMARC tidak diterapkan penuh (`action` selain reject), atau allowlist | Cek `action` dan `compauth`; cek allowlist dan mail flow rule [S6][S10] |
| Message trace tidak menemukan pesan yang terlihat di mailbox | Rentang waktu dalam zona waktu salah, atau lebih dari 10 hari per query | Tulis rentang dalam UTC; pecah query per 10 hari [S7] |
| ZAP sudah jalan tetapi pengguna masih bisa membuka pesan | Tindakan phishing di anti-spam policy adalah Move to Junk | Purge manual; ubah tindakan ke karantina lewat proses perubahan [S10] |
| Purge PowerShell gagal dengan pesan parameter `Purge` tidak ditemukan | Akun tidak punya peran Search And Purge di Purview | Tetapkan peran yang benar; Organization Management di Exchange Online tidak cukup [S9] |
| Purge hanya menghapus sebagian pesan di satu mailbox | Batas 10 item per mailbox per tindakan (PowerShell) | Ulangi atau pakai remediation Defender [S9] |
| Action center menunjukkan pesan "not remediable" | Pesan sudah di-hard-delete pengguna, on-premises, atau gagal terkirim | Tidak ada yang perlu ditarik; tetap konfirmasi pengguna [S8] |
| URL halaman phishing tampak bersih saat dicek | Halaman sudah diturunkan, atau cloaking berdasarkan IP pengunjung | Cek dari lokasi berbeda di lingkungan terpisah; hasil bersih bukan bukti aman |
| Klik tidak muncul di proxy maupun Safe Links | Pengguna menyalin URL ke browser di perangkat pribadi | Tanyakan langsung; perlakukan sebagai klik bila ragu |

## 5. Kesalahan umum dan jebakan

- Menganggap SPF pass, DKIM pass, atau gembok di browser sebagai bukti email atau halaman itu sah. Ketiganya bisa dipenuhi domain penyerang sendiri [S1][S2][S3].
- Membaca header `Received` paling bawah sebagai asal pesan. Header itu ditulis server pengirim dan bisa dipalsukan.
- Menganalisis satu pesan sampai tuntas sebelum memetakan kampanye. Salinan lain menunggu diklik selama analisis berjalan.
- Membuka URL phishing dari laptop kantor "sekadar melihat". Penyerang mendapat IP kantor dan tahu salinan penerima mana yang dibuka.
- Mengirim URL berisi alamat email karyawan atau token unik ke layanan scan dengan visibilitas publik [S14].
- Mengunggah lampiran ke layanan reputasi publik padahal mencari hash sudah cukup.
- Menganggap ZAP sudah menyelesaikan pembersihan. Pada default anti-spam policy, phishing hanya dipindah ke Junk [S10].
- Menjalankan purge dengan query yang belum diverifikasi jumlahnya, lalu ikut menghapus email sah.
- Menganggap purge menyelesaikan insiden. Pengguna yang sudah mengirim password tetap harus ditangani sebagai kompromi akun [S13].
- Menunda reset password pengguna yang mengirim kredensial dengan alasan "menunggu jam H", padahal password itu satu-satunya akses penyerang yang diketahui.
- Mempermalukan pengguna yang klik. Pengguna berikutnya akan diam dan SOC kehilangan sensor tercepatnya.

## 6. Catatan terkini

Bagian ini menampung detail versi, standar, dan perilaku produk yang bisa berubah. Berguna saat membaca dokumentasi lain, tetapi tidak mengubah cara menganalisis.

- **DMARC menjadi standar.** RFC 9989 (Mei 2026) menggantikan RFC 7489 dan RFC 9091 dan memindahkan DMARC dari status Informational ke Proposed Standard [S4]. Versi record tetap `v=DMARC1`, tag `pct` dihapus, ada tag `t` untuk mode uji (penerima diminta menerapkan kebijakan satu tingkat lebih rendah), dan domain organisasi ditentukan lewat DNS tree walk, bukan Public Suffix List [S4]. Konsep alignment dan syarat lolos (SPF atau DKIM yang lolos dan aligned) tetap sama [S4]. Materi lama yang menyebut `pct=` masih banyak beredar; header Microsoft juga masih mendokumentasikan nilai `action=pct.quarantine` dan `pct.reject` [S6].
- **Message trace.** `Get-MessageTraceV2` menggantikan `Get-MessageTrace` dan `Get-MessageTraceDetail`. Parameter `PageSize` diganti `ResultSize` dan pagination tidak didukung; data berikutnya diambil dengan `StartingRecipientAddress` dan `EndDate` [S7].
- **eDiscovery klasik pensiun.** Microsoft memensiunkan pengalaman eDiscovery dan Content Search klasik pada 31 Agustus 2025. Panduan search and purge sekarang ada di halaman eDiscovery baru, dengan syarat modul Exchange Online PowerShell 3.9.0 atau lebih baru dan batas 100 item per lokasi bila memakai Microsoft Graph pada kasus dengan fitur premium [S9]. Materi lama yang merujuk Content Search klasik masih banyak beredar.
- **Header `Authentication-Results`** di dokumentasi Microsoft masih merujuk RFC 7001; versi terbaru standarnya adalah RFC 8601 (Mei 2019) [S5][S6].
- **Panduan phishing CISA** terbit Oktober 2023 sebagai dokumen bersama CISA, NSA, FBI, dan MS-ISAC [S13]. Isinya berfokus pada pencegahan; langkah respons insidennya singkat, sehingga detail penanganan akun tetap mengikuti playbook organisasi.

## 7. Cheat sheet

```
URUTAN: asal pesan -> peta kampanye -> payload aman -> blok + purge -> pengguna -> komunikasi

HEADER
  Received: baca dari atas; percaya sampai hop pertama milik M365/organisasimu
  Return-Path (5321.MailFrom, P1) != From (5322.From, P2) -> jelaskan, belum tentu phishing
  Reply-To beda -> pola BEC | Date biasanya UTC (WIB = UTC+7)
  DIR:INB dari internet vs DIR:INT internal | IPV:NLI | SFTY:9.25 first contact

AUTENTIKASI
  SPF  : IP vs record domain MAIL FROM (bukan From) | maks 10 lookup -> permerror
  DKIM : d= bertanggung jawab, isi tidak berubah | d= boleh domain apa saja
  DMARC: SPF atau DKIM pass DAN aligned ke From | p=none/quarantine/reject
  compauth fail 000 (DMARC fail + kebijakan) | 001 (implisit) | 601 (spoof domain sendiri)
  semua pass != aman | lookalike domain tidak ditangani DMARC

KAMPANYE
  ciri: From, MAIL FROM, subjek, IP pengirim, domain URL, hash lampiran
  Get-MessageTraceV2: 90 hari, 10 hari/query, maks 5000, keluaran UTC
  tingkat: menerima | klik (GET, Safe Links) | kirim kredensial (POST) 

TRIAGE AMAN
  URL: jangan klik dari kantor | buang identitas penerima | scan privat/unlisted
  lampiran: hash dulu, jangan unggah sembarangan | detonation di sandbox

PURGE
  ZAP: 48 jam | phishing default -> Junk (bukan hapus) | HC phish & malware -> karantina
  Threat Explorer: soft delete (bisa dipulihkan) | hard delete | Action center 30 hari
  Purview PowerShell: 10 item/mailbox, 50.000 mailbox, verifikasi jumlah dulu
  simpan satu .eml sebagai bukti SEBELUM purge

SETELAH
  kirim kredensial -> reset + revoke sessions SEGERA -> JAB-PB-03 (sign-in, MFA, mailbox)
  blok domain (proxy + sinkhole), IP (firewall), pengirim (Tenant Allow/Block List), dengan log
  kabari pelapor + semua penerima, tanpa link
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "Header email ini menunjukkan `spf=pass` dan `dkim=pass`, jadi pengirimnya sah." Benarkah?

<details><summary>Jawaban</summary>

Tidak. SPF hanya membuktikan IP pengirim diizinkan untuk domain di `MAIL FROM`, dan DKIM hanya membuktikan domain `d=` bertanggung jawab atas pesan dan isinya tidak berubah. Keduanya bisa lolos untuk domain milik penyerang. Yang menghubungkan hasil itu ke domain `From` yang dilihat pengguna adalah DMARC, lewat alignment. Di `INC-2026-020`, SPF dan DKIM lolos untuk `notif-portal.example.net`, sedangkan `From` memakai `jab-support.example.net` tanpa record DMARC, sehingga `dmarc=none` dan `compauth=fail reason=001`. Bahkan DMARC pass pun tidak membuktikan aman, karena DMARC tidak menangani lookalike domain. Lihat bagian 1.2 dan 2.1.

</details>

**2. Skenario keputusan.** Enam laporan masuk untuk email yang sama. Langkah pertama mana yang paling tepat?

- A. Menganalisis satu pesan sampai tuntas, termasuk membongkar halaman phishing, sebelum melakukan hal lain.
- B. Memastikan asal pesan dari header secukupnya, lalu segera memetakan semua penerima dari ciri pesan dan mencari siapa yang klik atau mengirim kredensial.
- C. Langsung menjalankan purge dengan query subjek "Password" supaya cepat.

<details><summary>Jawaban</summary>

B. Phishing datang sebagai kampanye: enam laporan berarti ada salinan lain di mailbox yang belum melapor. Header cukup dibaca untuk memastikan pesan berbahaya dan mendapatkan ciri yang stabil, lalu ciri itu dipakai untuk mencari semua penerima dan tingkat paparan. A keliru karena salinan lain menunggu diklik selama analisis berjalan. C keliru karena query terlalu luas bisa ikut menghapus email sah, dan purge tanpa pemetaan tidak memberi tahu siapa yang sudah klik. Lihat bagian 1.3, 1.4, dan 2.5.

</details>

**3. Pertanyaan jebakan.** "ZAP sudah bertindak atas semua pesan kampanye ini pukul 09:22, jadi tidak ada lagi pengguna yang bisa mengklik link-nya." Benarkah?

<details><summary>Jawaban</summary>

Belum tentu. Untuk verdict phishing (bukan high confidence), tindakan ZAP mengikuti anti-spam policy. Pada default anti-spam policy tindakannya Move to Junk, sehingga pesan masih ada di folder Junk dan bisa dibuka. Di `INC-2026-020`, Hadi membuka pesan dari Junk pukul 09:48 dan hanya terselamatkan karena Safe Links sudah memblok URL itu. ZAP juga hanya mencari email yang dikirim dalam 48 jam terakhir dan bisa dikalahkan allowlist atau mail flow rule. Karena itu purge manual tetap dijalankan. Lihat bagian 1.6.

</details>

**4. Skenario keputusan.** Dimas ingin melihat sendiri halaman phishing. Respons mana yang tepat?

- A. Silakan buka dari laptop kantor, asal tidak mengisi apa-apa.
- B. Kirim URL lengkap ke layanan scan publik supaya hasilnya bisa dibagikan ke tim.
- C. Ambil URL tanpa mengklik, hapus parameter `u=` yang berisi email penerima, lalu buka dari lingkungan analisis terpisah atau lewat scan dengan visibilitas privat.

<details><summary>Jawaban</summary>

C. URL di kampanye ini unik per penerima: parameter `u=` berisi alamat email dalam base64. A keliru karena kunjungan dari IP PT JAB memberi tahu penyerang salinan siapa yang dibuka dan bahwa kampanyenya sedang dianalisis. B keliru karena scan publik membuat URL, termasuk alamat email karyawan di dalamnya, bisa dicari orang lain; riset Positive Security menemukan URL sensitif bocor dengan cara ini. Lihat bagian 1.5.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Lestari Putri, dalam tiga kalimat, kenapa password-nya direset dan ia harus login ulang di semua perangkat, padahal ia merasa "hanya mengisi sekali dan halamannya error".

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Halaman yang kamu isi tadi pagi bukan halaman Microsoft, tetapi halaman tiruan yang dibuat untuk mencatat password, dan 'error' itu biasanya cara mereka membuatmu tidak curiga. Begitu password terkirim, orang lain bisa memakainya dari mana saja, jadi kami menggantinya dan mengeluarkan semua sesi supaya password lama tidak berguna lagi. Kamu tidak salah karena melapor, justru ini membantu kami bergerak cepat; sekarang kami juga sedang mengecek apakah ada login yang mencurigakan ke akunmu."

Kesalahan yang sering muncul:
- Memakai istilah seperti "POST", "credential phishing", atau "revoke sessions" yang tidak dibutuhkan pengguna.
- Tidak menjelaskan kenapa "error" bukan tanda aman.
- Nada menyalahkan, sehingga pengguna enggan melapor di lain waktu.

</details>

**6. Pertanyaan jebakan.** "Soft delete di Threat Explorer selesai dengan status Completed, jadi semua pengguna aman dan insiden bisa ditutup." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Completed berarti tindakan selesai untuk pesan yang bisa ditindak; pesan yang sudah di-hard-delete pengguna tercatat tidak bisa ditindak, dan tidak ada penjelasan apakah pemiliknya sempat klik. Purge juga tidak membatalkan apa yang sudah terjadi: Lestari sudah mengirim password, sehingga akunnya ditangani di `JAB-PB-03` dan severity baru ditinjau setelah pemeriksaan sign-in selesai. Insiden email selesai bila status per pesan terverifikasi, blok terpasang, pengguna yang klik dikonfirmasi, dan semua yang mengirim kredensial sudah diserahkan ke penanganan akun. Lihat bagian 1.6, 1.7, dan 2.5.

</details>

**7. Interview question (English).** "Walk me through how you handle a user-reported credential phishing email."

<details><summary>Sample answer</summary>

"I treat it as a campaign, not a single email. First I pull the original message from the reporting mailbox, not a forwarded copy, and read the headers just enough to confirm where it came from: the first Received hop written by our own mail provider, the envelope sender versus the From address, and the authentication results. I don't stop at SPF or DKIM pass, because attackers pass those with their own domains; I check whether they align with the From domain and whether the From is a lookalike. Then I use stable traits like sender domain, sending IP and URL domain to find every recipient through message trace or Threat Explorer, and I split them into received, clicked, and submitted credentials using Safe Links clicks, proxy logs where a POST shows a form submission, DNS, and a quick call to the user. I analyze the URL from an isolated environment with private scans, and attachments by hash first. Then I block the domain with logging, purge every copy after saving one as evidence, and anyone who submitted credentials goes straight into the account compromise playbook: password reset, session revocation, and a review of sign-ins and MFA changes. Finally I tell the reporters it was real and the recipients what to do, without links."

What makes this answer strong: it starts with scoping the campaign rather than one email, shows a precise understanding of what email authentication does and does not prove, separates exposure levels with specific data sources, handles analysis safely, and connects purge to the account compromise process instead of treating deletion as the end.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | RFC 7208: Sender Policy Framework (SPF) for Authorizing Use of Domains in Email, Version 1 | https://www.rfc-editor.org/rfc/rfc7208.html | primer | April 2014; diakses 2026-10-15 | Tinggi. Identitas MAIL FROM dan HELO, nilai hasil, batas 10 mekanisme yang memicu query DNS |
| S2 | RFC 6376: DomainKeys Identified Mail (DKIM) Signatures | https://www.rfc-editor.org/rfc/rfc6376.html | primer | September 2011; diakses 2026-10-15 | Tinggi. Tag `d=`, `s=`, `h=`, `bh=`, `b=`; kunci di `_domainkey`; domain penanda tangan tidak harus cocok dengan field lain; modifikasi di jalan |
| S3 | RFC 7489: Domain-based Message Authentication, Reporting, and Conformance (DMARC) | https://www.rfc-editor.org/rfc/rfc7489.html | primer | Maret 2015 (Informational, digantikan RFC 9989); diakses 2026-10-15 | Tinggi untuk konsep alignment, syarat lolos, tag kebijakan, dan batas (nama tampilan, lookalike) |
| S4 | RFC 9989: Domain-Based Message Authentication, Reporting, and Conformance (DMARC) | https://www.rfc-editor.org/info/rfc9989 | primer | Mei 2026; diakses 2026-10-15 | Tinggi. Proposed Standard, menggantikan RFC 7489 dan RFC 9091; `v=DMARC1`, penghapusan `pct`, tag `t`, DNS tree walk |
| S5 | RFC 8601: Message Header Field for Indicating Message Authentication Status | https://www.rfc-editor.org/rfc/rfc8601.html | primer | Mei 2019; diakses 2026-10-15 | Tinggi. Header ditambahkan penerima, authserv-id, penghapusan header palsu di perbatasan, tanpa proteksi integritas |
| S6 | Microsoft Learn: Anti-spam message headers in Microsoft 365 | https://learn.microsoft.com/en-us/defender-office-365/message-headers-eop-mdo | primer (dokumentasi vendor) | ms.date 2026-07-27; diakses 2026-10-15 | Tinggi. Field `X-Forefront-Antispam-Report` (CIP, DIR, IPV, SFV, SFTY, PTR), sintaks `Authentication-Results`, nilai `dmarc` dan `action`, kode alasan `compauth` |
| S7 | Microsoft Learn: Get-MessageTraceV2 | https://learn.microsoft.com/en-us/powershell/module/exchangepowershell/get-messagetracev2 | primer (dokumentasi vendor) | diperbarui 2026-02-27; diakses 2026-10-15 | Tinggi. 90 hari, 10 hari per query, ResultSize 1.000 sampai 5.000, keluaran UTC, parameter dan status |
| S8 | Microsoft Learn: Remediate malicious email that was delivered in Office 365 | https://learn.microsoft.com/en-us/defender-office-365/remediate-malicious-email-delivered-office-365 | primer (dokumentasi vendor) | ms.date 2025-09-16; diakses 2026-10-15 | Tinggi. Tindakan remediation, lokasi yang bisa dan tidak bisa ditindak, persetujuan dan peran Search and Purge, Action center 30 hari, batas throttling |
| S9 | Microsoft Learn: Find and delete email messages in eDiscovery | https://learn.microsoft.com/en-us/purview/edisc-search-mailbox-data | primer (dokumentasi vendor) | ms.date 2026-06-19; diakses 2026-10-15 | Tinggi. Cmdlet search and purge, batas 10 dan 100 item, 50.000 mailbox, hold, item tidak terindeks, syarat modul 3.9.0 dan `EnableSearchOnlySession`, pensiun eDiscovery klasik |
| S10 | Microsoft Learn: Zero-hour auto purge in Microsoft Defender for Office 365 | https://learn.microsoft.com/en-us/defender-office-365/zero-hour-auto-purge | primer (dokumentasi vendor) | ms.date 2026-06-01; diakses 2026-10-15 | Tinggi. Jendela 48 jam, tindakan per verdict dan per policy, pengecualian, cara melihat hasil ZAP |
| S11 | Microsoft Learn: Configure user reported message settings in Microsoft Defender for Office 365 | https://learn.microsoft.com/en-us/defender-office-365/submissions-user-reported-messages-custom-mailbox | primer (dokumentasi vendor) | ms.date 2026-09-28; diakses 2026-10-15 | Tinggi. Tujuan laporan dan default-nya, reporting mailbox sebagai SecOps mailbox, alert policy laporan pengguna |
| S12 | Microsoft Learn: UrlClickEvents table in the advanced hunting schema | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-urlclickevents-table | primer (dokumentasi vendor) | ms.date 2026-06-04; diakses 2026-10-15 | Tinggi. Kolom tabel klik Safe Links dan contoh query |
| S13 | CISA, NSA, FBI, MS-ISAC: Phishing Guidance: Stopping the Attack Cycle at Phase One (PDF) | https://www.cisa.gov/sites/default/files/2025-03/Phishing%20Guidance%20-%20Stopping%20the%20Attack%20Cycle%20at%20Phase%20One%20508.pdf | primer | Oktober 2023; diakses 2026-10-15 | Tinggi. Dua jenis phishing, rekomendasi DMARC, denylist ekstensi, enam langkah respons insiden, pelaporan |
| S14 | Positive Security: urlscan.io's SOAR spot, Chatty security tools leaking private data (Fabian Bräunlein) | https://positive.security/blog/urlscan-data-leaks | komunitas (riset independen) | 2022-11-02 (lebih dari 3 tahun); diakses 2026-10-15 | Sedang sampai tinggi. Riset dengan pengujian langsung, diliput beberapa media keamanan; perilaku integrasi tertentu sudah diperbaiki sejak itu |

**Catatan sumber:** klaim bahwa kit phishing memakai daftar blokir IP untuk mengelabui peneliti dan sandbox di bagian 1.5 berasal dari panduan praktisi dan belum dikonfirmasi sumber primer, sehingga ditandai komunitas. Nilai `ActionType` selain `ClickAllowed` (misalnya `ClickBlocked`) tidak dicantumkan sebagai daftar di S12; cek nilai yang muncul di tenant-mu. Pembagian tingkat paparan (menerima, klik, mengirim kredensial), urutan triage URL, dan kriteria selesai insiden email adalah susunan catatan ini dari sumber yang disebut, bukan daftar resmi. Perilaku bahwa pesan internal dari tenant sendiri bertanda `DIR:INT` diambil dari definisi field `DIR` [S6]; cara pesan sah PT JAB dirutekan tergantung konfigurasi mail flow organisasi. Semua isi PT JAB, termasuk domain, IP, waktu, dan jumlah pesan, adalah contoh fiktif.
