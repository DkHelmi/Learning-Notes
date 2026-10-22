---
day: 06
title: 'Metadata TLS: SNI, sertifikat, JA3/JA4 fingerprint, proxy dekripsi, dan keylog di lab'
researched_on: 2026-10-22
versions_checked: 'Wireshark 4.6.9 stabil dan 4.4.19 old stable (field tls.handshake.ja3 sejak 3.6.0, tls.handshake.ja4 dan ja4_r sejak 4.2.0, field tls.ech sejak 4.2.0); TLS 1.3 RFC 8446 dan penggantinya RFC 9846 (Juli 2026); ECH RFC 9849 (2026); SSLKEYLOGFILE RFC 9850 (Juli 2026, Informational); X.509 RFC 5280; JA4 (FoxIO, BSD 3-Clause) dan JA4+ lain (FoxIO License 1.1); repo Salesforce JA3 diarsipkan 2025-05-01; Suricata docs latest (ja3.hash, ja4.hash); Zeek ssl.log docs; Squid SslPeekAndSplice; MITRE ATT&CK T1573.002 v1.3, T1090.004 v1.2, M1020 v1.1; CA/B Forum ballot SC-081v3'
---

# Day 06: Metadata TLS, JA3/JA4, proxy dekripsi, dan keylog di lab

Cakupan: membaca metadata TLS yang tetap terlihat walau isi terenkripsi (versi, SNI, sertifikat, JA3/JA3S/JA4, ukuran dan waktu record), memahami pengaruh proxy dekripsi terhadap apa yang terlihat di sensor egress, serta mendekripsi trafik milik sendiri dengan keylog di lab.

## Ide inti

Enkripsi TLS menutup isi, tetapi tidak menutup percakapan pembukanya. Sebelum kunci sesi disepakati, klien mengirim ClientHello secara polos: versi yang didukung, daftar cipher, daftar ekstensi, dan biasanya nama server tujuan (SNI). Server menjawab dengan ServerHello, dan pada TLS 1.2 juga mengirim sertifikatnya secara polos. Setelah itu yang tersisa hanya record terenkripsi, tetapi ukuran, arah, dan waktunya tetap terlihat. Dari bahan itu analyst jaringan bisa menjawab tiga pertanyaan tanpa membaca isi: ke mana koneksi ini (SNI, sertifikat, IP), siapa yang bicara (fingerprint klien seperti JA3 dan JA4), dan bagaimana polanya (interval, ukuran, volume). Pertanyaan "apa isinya" hanya terjawab bila ada kunci, dan kunci yang sah hanya ada di dua tempat: perangkat yang memang ditugasi membuka TLS (proxy dekripsi dengan kebijakan resmi) atau trafik yang kamu buat sendiri di lab.

Yang sering terlupa adalah bahwa jawaban tiga pertanyaan itu bergantung pada posisi sensor. Di jaringan dengan proxy eksplisit, sensor egress tidak pernah melihat workstation. Ia melihat proxy. Untuk koneksi yang hanya diteruskan proxy, ClientHello yang lewat adalah milik klien asli; untuk koneksi yang didekripsi proxy, ClientHello ke internet dibuat oleh proxy sendiri, sehingga fingerprint-nya milik proxy. Membaca metadata TLS di egress tanpa tahu hal ini menghasilkan kesimpulan yang salah tentang siapa yang bicara.

Kamu sudah mengenal pola ini dari NOC, dari tunnel IPsec. Payload ESP tidak bisa dibaca, tetapi negosiasi IKE terlihat: proposal enkripsi, identitas peer, dan urutan parameter yang sering cukup untuk menebak vendor perangkat di ujung sana, seperti capability di pesan BGP OPEN yang menunjukkan implementasi router tetangga. Ukuran dan waktu paket ESP tetap terlihat di capture, sehingga keepalive yang teratur dan lonjakan volume tetap terbaca. Session border controller (SBC) di jaringan VoIP memberi analogi untuk proxy dekripsi: SBC mengakhiri sesi SIP dari telepon lalu membuat sesi baru ke operator, sehingga operator hanya melihat SBC, bukan telepon. Batas analoginya ada dua. Fingerprint TLS mengenali library dan konfigurasinya, bukan aplikasinya, sehingga banyak program berbagi fingerprint yang sama dan penyerang bisa meniru fingerprint browser. Dan proxy dekripsi hanya berjalan karena workstation memercayai CA internal; aplikasi yang memakai certificate pinning akan menolak, sesuatu yang tidak pernah terjadi pada SBC.

```
                 workstation 10.10.60.x
                        |
                        | CONNECT host:443 (log jkt-proxy01)
                        v
                  jkt-proxy01 10.20.3.60 ----- keputusan per kategori
                   |                 |
          splice (diteruskan)   bump (didekripsi: domain baru / tidak terkategori)
                   |                 |
   ClientHello ASLI workstation   ClientHello BARU buatan proxy
   (JA4 = browser/aplikasi)       (JA4 = proxy; URL dan isi ada di log proxy)
                   |                 |
                   +--------+--------+       server data center tanpa proxy
                            |                (mis. jkt-cirunner02 10.20.45.22)
                            v                         |
             TAP egress Jakarta -> jkt-pcap01 <-------+
                            |
             yang terbaca di pcap: SNI, versi, cipher, JA3/JA4,
             sertifikat (TLS 1.2 saja), ukuran dan waktu record
```

Situasi Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif di Jakarta dengan sekitar 1.200 karyawan. Sejak Senin 2027-05-03, SOC menjalankan Program NSM PT JAB, percobaan Mei sampai Juli 2027 untuk membangun sensor jaringan. Kamu, analyst L2 dengan latar belakang tujuh tahun di NOC, menjadi pelaksananya bersama Bambang Hartono (Manajer NOC) dan Agung Prabowo (Lead Infrastruktur). Sensor yang sudah hidup baru satu: `jkt-pcap01` (`10.20.70.13`), ring buffer pcap yang sejak Selasa 2027-05-04 merekam TAP egress Jakarta dengan target retensi 72 jam. Zeek dan Suricata belum berjalan. Analisis dilakukan dari `jkt-nsm-ws01` (`10.20.70.20`) dengan Wireshark dan tshark, yang punya akses read-only ke `jkt-pcap01`. Trafik web kantor keluar lewat proxy eksplisit `jkt-proxy01` (`10.20.3.60`, port 3128), yang membuka TLS hanya untuk domain baru terdaftar dan yang tidak terkategori; kategori perbankan dan kesehatan sengaja tidak dibuka. Server data center yang punya izin keluar langsung melewati `jkt-fw01` dengan NAT ke `198.51.100.206`.

Selasa 2027-05-11 pukul 08:30, setelah membaca antrean pagi (`SOC-2027-0625` sampai `SOC-2027-0629`), SOC lead Dimas Prasetyo menulis di kanal SOC:

> "Aku buka beberapa file dari jkt-pcap01, isinya hampir semua TLS. Jadi sebenarnya apa yang masih bisa kita lihat dari pcap egress? Bisa tidak kita tahu tujuan tiap koneksi, dan bedanya TLS 1.2 dengan 1.3 apa buat kita? Lalu soal JA3 dan JA4: bulletin vendor kemarin kasih hash JA3, Gilang menemukan cocok di pcap (0627). Itu bisa dipercaya? Kita sebaiknya pakai yang mana, dan ada urusan lisensi tidak? Satu lagi yang bikin aku bingung, di pcap semua kelihatan dari IP proxy, terus bagaimana kita tahu workstation mana? Dan alert firewall 0628 dari server CI itu tolong dilihat dari pcap, kelihatan aneh."

Pukul 08:41 Bambang menambahkan:

> "Dulu di NOC kami decrypt capture pakai private key server. Bisa tidak pcap ini di-decrypt dengan cara yang sama? Kalau tidak bisa, apa yang bisa dibaca dari trafik yang tetap tertutup, dan kapan semua ini berhenti berguna?"

Dua pesan itu memuat tujuh pertanyaan:

1. Apa yang masih terlihat dari koneksi TLS, dan apa bedanya TLS 1.2 dengan 1.3 untuk analyst?
2. Bisakah tujuan tiap koneksi diketahui dari SNI dan sertifikat?
3. Apa JA3 dan JA4, seberapa bisa dipercaya cocokan JA3 dari bulletin vendor, mana yang dipakai, dan bagaimana lisensinya?
4. Kenapa pcap egress hanya menunjukkan IP proxy, bagaimana menemukan workstation-nya, dan apa pengaruh dekripsi proxy terhadap fingerprint?
5. Bisakah pcap didekripsi seperti di NOC dulu?
6. Apa yang bisa dibaca dari trafik yang tetap tertutup, dan di mana batasnya?
7. Bagaimana membedakan koneksi TLS yang jinak dari yang perlu dinaikkan, dan apa yang terjadi dengan server CI di `SOC-2027-0628`?

Pertanyaan 1 dijawab di bagian 1.1 dan 1.2, pertanyaan 2 di bagian 1.3 dan 1.4, pertanyaan 3 di bagian 1.5 dan 1.6, pertanyaan 4 di bagian 1.7, pertanyaan 5 di bagian 1.8, pertanyaan 6 di bagian 1.9, dan pertanyaan 7 di bagian 1.10. Bagian 2 menerapkan semuanya ke pcap egress Selasa pagi, membuka `INC-2027-065`, dan diakhiri jawaban untuk Dimas dan Bambang di bagian 2.10.

Day ini membaca metadata yang memang terlihat oleh siapa pun di jalur, dan mendekripsi hanya trafik lab milik sendiri dengan kunci yang kamu hasilkan sendiri. Tidak ada instruksi menyadap atau memecah enkripsi orang lain. Semua data PT JAB fiktif, IP luar memakai rentang dokumentasi, dan domain memakai akhiran `.example`.

**Kapan relevan:** investigasi trafik terenkripsi dari pcap atau log sensor; identifikasi tujuan koneksi dan kandidat C2 saat isi tertutup; mencocokkan fingerprint klien dengan intel; menilai apa yang bisa dan tidak bisa disimpulkan dari sensor di belakang atau di depan proxy; dekripsi trafik lab sendiri untuk memahami apa yang tersembunyi.
**Kapan bukan jawaban:** saat pertanyaannya tentang isi (file apa yang diunggah, perintah apa yang dikirim) dan tidak ada kunci sah, karena metadata hanya memberi indikator; saat SNI disembunyikan ECH atau trafik berjalan di QUIC tanpa dissector yang tepat (Day 15 dan Day 16); saat penyerang menumpang layanan populer dengan library TLS umum, karena fingerprint dan SNI-nya identik dengan ribuan klien sah; dan saat yang dibutuhkan adalah identitas proses di host, karena itu pekerjaan data endpoint.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (pcap, display filter, capture filter, SPAN/TAP, ring buffer, flow, beacon, DGA, DoH) tidak diulang. Tabel ini memuat istilah yang diperkenalkan Day ini. Kolom kanan memakai padanan dari pekerjaan NOC dan ISP, supaya istilah baru menempel ke hal yang sudah kamu kuasai.

| Istilah | Arti singkat | Padanan di NOC/ISP |
|---|---|---|
| TLS handshake | Pertukaran pesan pembuka untuk menyepakati versi, cipher, dan kunci sesi | Negosiasi IKE sebelum ESP mengalir |
| ClientHello | Pesan pertama klien: versi, cipher, ekstensi, SNI; handshake type 1 | Proposal IKE_SA_INIT dari inisiator |
| ServerHello | Jawaban server: versi dan cipher terpilih; handshake type 2 | Proposal yang dipilih responder |
| Application Data | Record terenkripsi berisi data aplikasi; content type 23 | Paket ESP: isi tertutup, ukuran dan waktu terlihat |
| SNI (Server Name Indication) | Ekstensi ClientHello berisi nama host tujuan | Nama tujuan yang ditulis di header sebelum tunnel terbentuk |
| ALPN | Ekstensi yang menyebut protokol aplikasi di dalam TLS (`h2`, `http/1.1`) | Negosiasi capability yang menyebut protokol di atasnya |
| Sertifikat X.509 | Identitas server yang ditandatangani CA: subject, issuer, masa berlaku, SAN | Sertifikat peer di IKE dengan PKI |
| SAN (subjectAltName) | Daftar nama DNS yang sah untuk sertifikat | Daftar alias yang diizinkan untuk satu peer |
| Self-signed | Sertifikat dengan issuer dan subject yang sama, ditandatangani kunci miliknya sendiri | Peer IKE yang menjamin dirinya sendiri tanpa CA |
| JA3 / JA3S | Hash MD5 dari parameter ClientHello / ServerHello | Mengenali vendor router dari urutan capability BGP OPEN |
| JA4 | Fingerprint ClientHello berformat `a_b_c` yang mengurutkan cipher dan ekstensi | Sama, tetapi urutan capability diabaikan supaya stabil |
| JA4+ | Keluarga fingerprint FoxIO lain (JA4S, JA4X, JA4H, dan lain-lain) | Kumpulan tanda pengenal untuk berbagai protokol manajemen |
| GREASE | Nilai acak yang sengaja disisipkan klien agar server tahan nilai tak dikenal; diabaikan JA3/JA4 | Nilai dummy di field reserved untuk menguji toleransi perangkat |
| Proxy dekripsi (TLS inspection) | Perantara yang membuka TLS dengan CA internal lalu membuat TLS baru ke server | SBC yang mengakhiri SIP dan membuat sesi baru ke operator |
| Splice / bump | Istilah Squid: splice meneruskan TLS apa adanya, bump membukanya | Pass-through vs terminate di SBC |
| Certificate pinning | Aplikasi hanya menerima sertifikat atau kunci tertentu, sehingga menolak proxy dekripsi | Peer yang hanya menerima satu fingerprint sertifikat |
| Keylog file (`SSLKEYLOGFILE`) | File teks berisi secret sesi TLS yang ditulis klien untuk keperluan debug | Export kunci SA IPsec untuk mendekripsi ESP di Wireshark |
| ECH (Encrypted Client Hello) | Ekstensi TLS yang mengenkripsi ClientHello bagian dalam, termasuk SNI | Header tujuan yang ikut dienkripsi; hanya alamat tepi yang terlihat |
| Domain fronting | SNI menyebut satu domain, header HTTP Host menyebut domain lain di CDN yang sama | Label luar menunjuk satu pelanggan, isi diarahkan ke pelanggan lain |

### 1.1 Apa yang terlihat di TLS 1.2 dan TLS 1.3

Pertanyaan pertama Dimas lahir dari kesan bahwa pcap yang "hampir semua TLS" tidak berguna. Kesan itu keliru, tetapi batasnya juga nyata, dan batas itu berbeda antara TLS 1.2 dan 1.3.

Tabel berikut adalah peta dasar yang dipakai sepanjang Day ini. Baca kolom TLS 1.3, karena sebagian besar trafik egress PT JAB sudah memakainya.

| Bagian | TLS 1.2 | TLS 1.3 | Catatan |
|---|---|---|---|
| ClientHello (versi, cipher, ekstensi, SNI) | Terlihat | Terlihat, kecuali bagian dalam bila ECH dipakai | Bahan JA3/JA4 dan SNI |
| ServerHello (versi dan cipher terpilih) | Terlihat | Terlihat | Bahan JA3S |
| Sertifikat server | Terlihat polos | Terenkripsi | Subject, issuer, masa berlaku, SAN |
| Pesan handshake lain setelah ServerHello | Sebagian polos | Terenkripsi | EncryptedExtensions, Certificate, CertificateVerify, Finished |
| Application Data | Terenkripsi | Terenkripsi | Hanya ukuran, arah, dan waktu |

Spesifikasi TLS 1.3 awalnya RFC 8446; sejak Juli 2026 RFC 9846 menggantikannya, sekaligus menggantikan RFC 5246 untuk TLS 1.2 [S21]. Nomor bagian yang dikutip di Day ini mengikuti RFC 8446. Pada TLS 1.3, semua pesan handshake setelah ServerHello dienkripsi [S2]. RFC 8446 menandai EncryptedExtensions, CertificateRequest, Certificate, CertificateVerify, dan Finished sebagai pesan yang dilindungi dengan secret handshake [S2]. Konsekuensinya langsung: pada trafik TLS 1.3, sertifikat server tidak terlihat oleh sensor pasif. Dokumentasi Zeek untuk `ssl.log` menyebut hal yang sama: pada TLS 1.3, sertifikat tidak muncul di log karena tersembunyi dari sistem observasi pasif [S15].

Ada satu detail record TLS 1.3 yang sering menjebak. Setiap record terenkripsi di TLS 1.3 memakai content type luar 23 (application_data) dan field versi record selalu `0x0303`; content type yang sebenarnya baru diketahui setelah dekripsi [S2]. Artinya, filter "record Application Data" pada sesi TLS 1.3 juga menangkap record handshake terenkripsi seperti sertifikat dan Finished. Untuk membaca pola data aplikasi, abaikan beberapa record pertama setiap sesi TLS 1.3 (bagian 2.7).

Meski isi tertutup, metadata handshake memberi banyak: tujuan (SNI, dan sertifikat di 1.2), karakteristik klien (JA3/JA4), dan pola dari ukuran serta waktu record Application Data (beaconing dibahas mendalam di Day 11). Jawaban singkat untuk Dimas: dari pcap egress kita masih tahu ke mana, dengan klien jenis apa, dan dengan pola apa; kita tidak tahu isinya.

### 1.2 Versi TLS: tiga tempat, satu yang jujur

Untuk menjawab "1.2 atau 1.3" di pcap, kamu perlu tahu bahwa versi TLS tertulis di tiga tempat, dan dua di antaranya tidak menunjukkan versi sebenarnya.

Tabel berikut menunjukkan ketiganya. Cari kolom "Nilai di TLS 1.3", karena di situlah jebakannya.

| Tempat | Field Wireshark | Nilai di TLS 1.3 | Yang dipakai untuk |
|---|---|---|---|
| Header record | `tls.record.version` | `0x0303` (atau `0x0301` di record ClientHello pertama) | Tidak untuk menentukan versi |
| Field versi di ClientHello/ServerHello | `tls.handshake.version` | `0x0303` (angka TLS 1.2) | Kompatibilitas lama |
| Ekstensi `supported_versions` | `tls.handshake.extensions.supported_version` | `0x0304` di ServerHello | Versi yang benar-benar dipakai |

RFC 8446 mewajibkan field `legacy_version` di ClientHello bernilai `0x0303` (nomor TLS 1.2), dan versi dinegosiasikan lewat ekstensi `supported_versions`; server yang menerima ekstensi itu wajib hanya memakainya untuk menentukan preferensi klien [S2]. Jadi aturan bacanya:

- Di ClientHello, `supported_versions` adalah daftar versi yang ditawarkan klien. Klien modern menawarkan `0x0304` dan `0x0303` sekaligus.
- Di ServerHello, `supported_versions` berisi satu nilai pilihan server. Bila `0x0304`, sesinya TLS 1.3. Bila ekstensi itu tidak ada di ServerHello, sesinya TLS 1.2 atau lebih lama, dan versinya dibaca dari `tls.handshake.version`.

Versi menentukan apa yang terlihat: sertifikat polos di 1.2 dan tersembunyi di 1.3. Versi lama (TLS 1.0, 1.1) atau cipher lemah juga layak dicatat, walaupun biasanya itu temuan kebersihan konfigurasi, bukan tanda serangan.

Field yang dipakai di Wireshark: `tls.handshake.version`, `tls.record.version`, dan `tls.handshake.extensions.supported_version` tersedia sejak Wireshark 3.0.0 sampai 4.6.9 [S1].

### 1.3 SNI (Server Name Indication)

Pertanyaan kedua Dimas ("bisa tahu tujuan tiap koneksi?") dijawab pertama oleh SNI. Di pcap egress PT JAB, ribuan koneksi berbagi beberapa IP CDN yang sama; tanpa SNI, daftar IP tujuan tidak banyak bercerita.

SNI di ClientHello menyatakan nama host tujuan agar server yang melayani banyak domain tahu sertifikat mana yang dikirim. Di forensik, SNI memperlihatkan tujuan meski satu IP dipakai banyak domain. Field Wireshark-nya `tls.handshake.extensions_server_name` [S1].

Sinyal anomali dari SNI:

- SNI ke domain mencurigakan, baru terdaftar, atau berpola DGA.
- SNI tidak cocok dengan sertifikat. Ini bisa salah konfigurasi, bisa juga domain fronting (lihat di bawah).
- SNI kosong. Klien yang terhubung langsung ke IP tidak mengirim SNI; ini sah untuk sebagian perangkat dan aplikasi, tetapi juga pola alat yang ditulis seadanya.
- SNI tersembunyi oleh ECH.

Domain fronting dicatat ATT&CK sebagai T1090.004: penyerang memanfaatkan routing CDN sehingga SNI menyebut satu domain sementara header HTTP Host menyebut domain lain di CDN yang sama; varian "domainless" mengosongkan SNI [S18]. Detection strategy DET0196 di ATT&CK mencari koneksi HTTPS keluar dengan SNI yang tidak cocok dengan header Host [S18]. Perhatikan konsekuensinya: header Host berada di dalam TLS, jadi ketidakcocokan itu hanya bisa dilihat oleh perangkat yang mendekripsi, yaitu `jkt-proxy01` untuk kategori yang dibuka, bukan oleh pcap egress.

Dengan ECH (Encrypted Client Hello), ClientHello bagian dalam termasuk SNI asli dienkripsi ke kunci publik server [S11]. Yang tampak di ClientHello luar hanya nama publik milik penyedia front-end. ECH sudah menjadi standar sebagai RFC 9849 (2026) [S11], dan adopsinya di browser serta CDN terus bertambah, sehingga forensik SNI makin terbatas. Day 15 membahas apa yang masih tersisa. Seberapa banyak trafik di jaringanmu yang sudah memakai ECH perlu diukur sendiri; Wireshark 4.2.0 ke atas sudah punya field `tls.ech.*` untuk itu [S1].

Untuk PT JAB ada satu kabar baik: di proxy eksplisit, browser tetap menyebut host tujuan di permintaan CONNECT, sehingga log `jkt-proxy01` tetap mencatat tujuan walaupun SNI di jalur luar disembunyikan. Pcap egress dan log proxy saling melengkapi, bukan saling menggantikan.

### 1.4 Sertifikat

Bagian kedua pertanyaan Dimas adalah sertifikat. Pada TLS 1.2 sertifikat server terlihat polos, dan sertifikat itu menceritakan banyak hal tentang siapa yang mengoperasikan server.

Struktur sertifikat X.509 menyusun field dalam urutan tetap: version, serialNumber, signature, issuer, validity, subject, subjectPublicKeyInfo, lalu extensions [S9]. Urutan ini penting saat membaca keluaran tshark, karena field nama (issuer lalu subject) keluar sebagai satu daftar multivalue dengan urutan yang sama. Sertifikat disebut self-issued bila issuer dan subject-nya entitas yang sama, dan self-signed bila tanda tangannya bisa diverifikasi dengan kunci publik di sertifikat itu sendiri [S9].

Sinyal anomali pada sertifikat:

- Self-signed atau issuer tidak dikenal untuk layanan yang seharusnya memakai CA publik.
- Masa berlaku aneh: baru dibuat beberapa jam sebelum koneksi pertama, atau justru jauh lebih panjang dari yang boleh diterbitkan CA publik.
- Subject atau SAN generik (nama default alat, `localhost`, nama host internal) atau tidak cocok dengan SNI.
- Satu sertifikat dipakai banyak domain mencurigakan.

Sinyal "masa berlaku" perlu dikalibrasi ulang di 2027. CA/Browser Forum menyetujui ballot SC-081v3 pada 11 April 2025, yang menurunkan masa berlaku maksimum sertifikat TLS publik secara bertahap dari 398 hari sampai 47 hari antara Maret 2026 dan Maret 2029 [S19]. Jadwal per tahapnya: 200 hari sejak Maret 2026, 100 hari sejak 15 Maret 2027, dan 47 hari sejak 15 Maret 2029 [S20]. Dua akibatnya untuk analyst:

- Sertifikat publik bermasa berlaku 90 hari atau kurang kini normal, jadi "masa berlaku pendek" tidak lagi sinyal.
- Sertifikat yang diterbitkan setelah 15 Maret 2027 dengan masa berlaku jauh di atas 100 hari hampir pasti bukan dari CA publik yang mematuhi aturan itu. Itu sertifikat dari CA privat atau self-signed. Ini inferensi dari aturan CA/B Forum, bukan bukti niat jahat: banyak perangkat dan layanan internal memakai sertifikat self-signed jangka panjang.

Pada TLS 1.3, sertifikat dienkripsi sehingga tidak terlihat tanpa dekripsi [S2]. Pada TLS 1.2 dengan session resumption, sertifikat juga tidak dikirim ulang, sehingga sesi lanjutan tidak membawa sertifikat walaupun versinya 1.2. Di PT JAB, `jkt-proxy01` yang memvalidasi sertifikat server untuk koneksi yang ia buka, jadi untuk kategori yang didekripsi, informasi sertifikat bisa dicari di log proxy (bagian 2.6).

### 1.5 JA3 dan JA3S

Pertanyaan ketiga Dimas dimulai dari bulletin vendor yang hanya memberi hash JA3. Untuk menilai cocokan Gilang (`SOC-2027-0627`), kamu perlu tahu persis apa yang di-hash.

Fingerprint meringkas parameter ClientHello menjadi string pendek yang mengidentifikasi aplikasi atau library TLS klien, bukan isi [S4][S5]. JA3, dibuat di Salesforce pada 2017, mengambil nilai desimal lima field dari ClientHello dan menggabungkannya dengan urutan tetap [S4]:

```
SSLVersion,Cipher,SSLExtension,EllipticCurve,EllipticCurvePointFormat
```

Antar-field dipisah koma, nilai di dalam satu field dipisah tanda hubung, field kosong dibiarkan kosong, lalu seluruh string di-hash MD5 menjadi 32 karakter heksadesimal [S4]. Nilai GREASE diabaikan, supaya klien yang menyisipkan nilai acak itu tetap menghasilkan satu hash [S4]. JA3S memakai cara yang sama untuk ServerHello dengan field `SSLVersion,Cipher,SSLExtension`; karena server cenderung menjawab klien tertentu dengan cara yang sama, pasangan JA3 dan JA3S memberi fingerprint negosiasi yang lebih spesifik daripada JA3 saja [S4]. Repo JA3 memberi contoh pasangan JA3 dan JA3S untuk Trickbot dan Emotet sebagai ilustrasi pemakaian [S4].

Kelemahan JA3 ada di kata "urutan". JA3 memasukkan urutan ekstensi apa adanya. Sejak 20 Januari 2023, Chrome mengacak urutan ekstensi ClientHello di setiap koneksi; Fastly mengamati penurunan tajam fingerprint JA3 Chrome yang tadinya dominan mulai tanggal itu, dan menghitung hampir 15 faktorial kemungkinan urutan, sehingga satu koneksi praktis menghasilkan JA3 yang unik [S12]. Akibatnya, untuk browser berbasis Chromium, JA3 tidak lagi stabil dan tidak berguna untuk mengenali browser itu.

JA3 juga sudah tidak dirawat. Repo Salesforce diarsipkan pemiliknya pada 1 Mei 2025 dan menyatakan proyek itu tidak lagi dirawat aktif; pembuatnya kini merawat JA4 di repo FoxIO [S4]. JA3 tetap banyak muncul di intel, rule lama, dan log alat, jadi kamu tetap perlu membacanya.

Kegunaan forensik keduanya sama: malware tertentu memakai library TLS dan konfigurasi khas, sehingga fingerprint bisa mencocokkan trafik ke keluarga malware atau alat meski isi terenkripsi. Fingerprint bukan bukti pasti. Banyak klien berbagi library (misalnya bahasa pemrograman dengan setelan bawaan OpenSSL), sehingga hash yang sama bisa datang dari skrip internal yang sah. Cocokan bernilai tinggi bila fingerprint-nya langka di jaringanmu dan didukung sinyal lain; cocokan pada fingerprint umum hampir tidak bernilai.

### 1.6 JA4 dan keluarga JA4+

Bagian kedua pertanyaan ketiga Dimas adalah "pakai yang mana". Jawabannya JA4 untuk fingerprint klien, dengan JA3 tetap dibaca untuk intel lama.

Tabel berikut merangkum perbandingan keduanya. Baca baris "Urutan ekstensi", karena itulah yang membuat JA4 tetap berguna setelah Chrome mengacak urutan.

| | JA3 | JA4 |
|---|---|---|
| Asal | Salesforce (2017); repo diarsipkan 2025-05-01 | FoxIO (2023), penerus |
| Bentuk | MD5 32 karakter atas lima field ClientHello | String `a_b_c`: metadata terbaca, lalu dua hash SHA-256 terpotong 12 karakter |
| Urutan ekstensi | Ikut di-hash, sehingga berubah bila diacak | Diurutkan sebelum di-hash, sehingga stabil |
| Varian server | JA3S | JA4S (lisensi berbeda, lihat di bawah) |
| Bisa dibaca sebagian | Tidak; satu hash utuh | Ya; bagian `a` terbaca manusia, bagian bisa dipakai terpisah |
| Lisensi | BSD 3-Clause | JA4 BSD 3-Clause; JA4+ lain FoxIO License 1.1 |
| Dukungan Wireshark | `tls.handshake.ja3`, `ja3_full`, `ja3s`, `ja3s_full` sejak 3.6.0 | `tls.handshake.ja4`, `ja4_r` sejak 4.2.0 |

Spesifikasi JA4 dari FoxIO [S7]:

- **Bagian `a` (10 karakter, terbaca):** karakter 1 transport (`t` TLS di atas TCP, `q` QUIC, `d` DTLS); karakter 2-3 versi TLS tertinggi yang ditawarkan, diambil dari ekstensi `supported_versions` bila ada, bukan dari field versi di header; karakter 4 SNI (`d` bila ekstensi SNI ada, `i` bila tidak ada, biasanya karena tujuan berupa IP); karakter 5-6 jumlah cipher non-GREASE (dua digit, maksimal 99); karakter 7-8 jumlah ekstensi non-GREASE termasuk SNI dan ALPN; karakter 9-10 karakter pertama dan terakhir nilai ALPN pertama (`h2` untuk `h2`, `h1` untuk `http/1.1`, `00` bila tidak ada ALPN).
- **Bagian `b` (12 karakter):** daftar cipher non-GREASE dalam heksadesimal empat digit, diurutkan, digabung koma, di-hash SHA-256, lalu diambil 12 karakter pertama.
- **Bagian `c` (12 karakter):** daftar ekstensi non-GREASE tanpa SNI dan ALPN, diurutkan, lalu ditambah garis bawah dan daftar signature algorithm dalam urutan asli, di-hash SHA-256, diambil 12 karakter pertama. SNI dan ALPN dibuang supaya bagian ini tetap stabil walaupun tujuan atau protokolnya berbeda.
- **`ja4_r`:** bentuk mentah sebelum di-hash, berguna untuk melihat cipher dan ekstensi apa yang sebenarnya ditawarkan. Ada juga `ja4_o` dan `ja4_ro` yang mempertahankan urutan asli.

Contoh yang dipakai spesifikasi adalah `t13d1516h2_8daaf6152771_b186095e22b6`: TCP, TLS 1.3, ada SNI, 15 cipher, 16 ekstensi, ALPN `h2` [S7]. Struktur `a_b_c` memungkinkan pencocokan sebagian. FoxIO memberi contoh pemindai yang memutar cipher: bagian `b` berubah, tetapi `a` dan `c` tetap, sehingga kombinasi `a` dan `c` masih bisa melacaknya [S5].

Dua catatan agar tidak salah membaca bagian `a`:

- Versi di JA4 adalah versi tertinggi yang ditawarkan klien, bukan versi yang akhirnya dipakai. Klien yang menawarkan TLS 1.3 tetap ber-JA4 `t13...` walaupun server memilih TLS 1.2 (bagian 2.4 memperlihatkan kasus ini).
- FoxIO sendiri mengingatkan bahwa JA4 berubah ketika library TLS aplikasi diperbarui [S5]. Fingerprint adalah ciri saat ini, bukan identitas permanen.

Keluarga JA4+ mencakup JA4S (server TLS), JA4H (klien HTTP), JA4L dan JA4LS (latensi), JA4X (sertifikat X.509), JA4SSH, JA4T dan JA4TS (TCP), JA4D (DHCP), JA4N (NTP), dan beberapa pemindai aktif [S5]. Lisensinya terbagi dua [S5]:

- JA4 (fingerprint klien TLS) berlisensi BSD 3-Clause, sama dengan JA3.
- Semua anggota JA4+ lainnya berlisensi FoxIO License 1.1, yang disebut permisif untuk sebagian besar pemakaian, tetapi vendor yang menjual kemampuan JA4+ butuh lisensi OEM.

Untuk SOC PT JAB yang memakai JA4+ di alat internal, lisensi itu biasanya bukan hambatan. Pertanyaannya berubah bila suatu hari PT JAB menjual layanan keamanan terkelola ke pelanggan korporat yang memakai JA4+ sebagai fitur; teks lisensi perlu dibaca ulang oleh Legal saat itu. Ini bukan nasihat hukum, hanya catatan supaya pertanyaan itu tidak terlewat.

Dukungan alat: Wireshark menghitung JA4 dan `ja4_r` secara bawaan sejak 4.2.0 [S1]; anggota JA4+ lain di Wireshark tersedia lewat plugin dari repo FoxIO [S5]. Suricata punya keyword `ja3.hash`, `ja3.string`, `ja3s.hash`, `ja3s.string`, dan `ja4.hash`, dengan opsi `app-layer.protocols.tls.ja3-fingerprints` dan `ja4-fingerprints` yang aktif otomatis bila ada rule yang membutuhkannya [S14]. Zeek mencatat `ja3` dan `ja3s` di `ssl.log` bila script JA3 dijalankan [S15], dan FoxIO menyediakan dukungan JA4+ untuk Zeek [S5]. Day 08 dan Day 09 memasang keduanya di `jkt-zeek01` dan `jkt-ids01`.

### 1.7 Proxy eksplisit dan dekripsi: siapa pemilik ClientHello di egress

Pertanyaan keempat Dimas ("semua kelihatan dari IP proxy") adalah inti Day ini untuk PT JAB. Jawabannya bergantung pada apa yang dilakukan `jkt-proxy01` terhadap tiap koneksi.

Dengan proxy eksplisit, browser tidak membuka TCP ke server. Browser mengirim `CONNECT host:443` ke proxy, lalu proxy yang membuka TCP ke server. Karena itu, di TAP egress semua koneksi web kantor bersumber dari `10.20.3.60`. Leg antara workstation dan proxy berjalan di dalam jaringan kantor dan data center, tidak lewat egress, sehingga tidak ada di `jkt-pcap01`. Satu-satunya jembatan dari koneksi di pcap ke workstation adalah log proxy, dicocokkan lewat waktu, host tujuan, dan port.

Yang terjadi pada ClientHello bergantung pada keputusan proxy. Fitur SslBump di Squid memakai istilah yang jelas untuk ini [S13]:

- **Splice:** koneksi diubah menjadi tunnel TCP tanpa didekode. Bila proxy sempat mengintip (peek) ClientHello untuk membaca SNI, ClientHello itu harus diteruskan apa adanya tanpa modifikasi supaya splice tetap mungkin [S13]. Di egress, ClientHello dan fingerprint-nya milik klien asli, walaupun IP sumbernya proxy.
- **Bump:** proxy membuat TLS sendiri dengan server dan dengan klien memakai sertifikat tiruan yang ditandatangani CA internal [S13]. ClientHello ke server tidak diteruskan; proxy membuat ClientHello tiruan. Dokumentasi Squid menyebut versi, daftar cipher, SNI, dan random diteruskan, sedangkan ekstensi lain hanya kadang diteruskan, dan mengakui bagian dokumentasi itu belum lengkap [S13].

Akibatnya untuk fingerprint di pcap egress:

| Kasus | IP sumber di egress | ClientHello di egress | JA4 di egress | Siapa yang tahu URL dan isi |
|---|---|---|---|---|
| Splice (kategori dikenal, perbankan, kesehatan) | `10.20.3.60` | Milik workstation | Milik browser atau aplikasi | Tidak ada; log proxy hanya host dan port |
| Bump (domain baru, tidak terkategori) | `10.20.3.60` | Buatan proxy | Milik proxy; bagian `b` bisa sama dengan klien bila cipher diteruskan | Log proxy (URL, metode, status, ukuran) |
| Server data center tanpa proxy | IP server, misalnya `10.20.45.22` | Milik aplikasi di server | Milik aplikasi | Tidak ada |

Baca kolom JA4 dengan hati-hati. Cocokan intel JA4 di egress untuk koneksi yang di-bump tidak pernah mengenai malware di workstation, karena fingerprint yang terlihat adalah milik proxy. Sebaliknya, untuk koneksi splice, fingerprint workstation terlihat, tetapi identitas workstation tidak. Perilaku persis ClientHello tiruan bergantung pada versi Squid dan konfigurasinya; ukur sekali di lab sebelum mengandalkan pola "bagian `b` sama" (bagian 3, variasi tantangan).

Ada konsekuensi kedua yang praktis. Bila aplikasi di workstation memakai certificate pinning dan domainnya jatuh ke kategori yang di-bump, aplikasi menolak sertifikat tiruan proxy. Di egress, handshake proxy ke server terlihat berhasil lalu segera ditutup, karena kegagalannya terjadi di leg workstation ke proxy yang tidak lewat sensor. Hanya log proxy yang mencatat penolakan itu (`SOC-2027-0626` di bagian 2.6).

ATT&CK mencatat SSL/TLS inspection sebagai mitigasi M1020, yaitu mendekripsi trafik untuk diperiksa lalu mengenkripsinya kembali ke tujuan, dan memetakannya ke T1573 Encrypted Channel, T1573.002, T1090, dan T1090.004 [S17]. Dekripsi oleh proxy adalah kebijakan infrastruktur, bukan forensik pcap murni, dan punya implikasi privasi. Di PT JAB kebijakannya disetujui manajemen, diumumkan ke karyawan, dan sengaja tidak membuka kategori perbankan dan kesehatan. Perluasan kategori yang dibuka adalah keputusan yang melibatkan DPO (Agus Setiawan) dan Legal (Ratna Sari), bukan keputusan SOC sendiri.

### 1.8 Dekripsi dengan keylog: hanya trafik sendiri

Pertanyaan Bambang ("dulu kami decrypt pakai private key server") berasal dari kebiasaan yang benar di masanya, tetapi tidak lagi berlaku untuk sebagian besar trafik.

Wireshark mengenal tiga cara dekripsi TLS [S3]:

- **Private key RSA server:** hanya berfungsi bila cipher suite tidak memakai (EC)DHE, protokolnya SSLv3 sampai TLS 1.2, kunci cocok dengan sertifikat server, dan sesi tidak di-resume. Cara ini tidak berfungsi untuk TLS 1.3 [S3]. Hampir semua trafik modern memakai ECDHE dengan forward secrecy, sehingga private key server tidak cukup. Untuk PT JAB jawabannya juga lebih sederhana: private key server di internet bukan milik PT JAB.
- **Keylog file:** cara universal yang tetap berfungsi dengan Diffie-Hellman [S3]. Browser dan library menulis secret per sesi ke file yang ditunjuk variabel lingkungan `SSLKEYLOGFILE`, lalu Wireshark membacanya lewat preferensi TLS "(Pre)-Master-Secret log filename" (`tls.keylog_file`) [S3].
- **Pre-shared key (PSK):** untuk sesi yang memakai PSK yang kamu ketahui [S3].

Format keylog kini didokumentasikan sebagai RFC 9850 (Juli 2026, Informational) [S10]. Setiap baris berisi tiga field dipisah spasi: label, client random 32 byte dalam 64 karakter heksadesimal yang mengidentifikasi koneksi, dan secret dalam heksadesimal [S10]. Label untuk TLS 1.2 adalah `CLIENT_RANDOM`; untuk TLS 1.3 antara lain `CLIENT_HANDSHAKE_TRAFFIC_SECRET`, `SERVER_HANDSHAKE_TRAFFIC_SECRET`, `CLIENT_TRAFFIC_SECRET_0`, `SERVER_TRAFFIC_SECRET_0`, dan `EXPORTER_SECRET`; untuk ECH ada `ECH_SECRET` dan `ECH_CONFIG` [S10]. Kolom client random itulah yang membuat Wireshark bisa mencocokkan baris keylog dengan sesi di pcap: nilai yang sama ada di ClientHello.

Aplikasi yang mendukung `SSLKEYLOGFILE` antara lain Firefox, Chrome, curl, dan Edge berbasis Chromium (79 ke atas) lewat NSS, OpenSSL, atau BoringSSL; OpenSSL 3.4 ke atas mendukungnya secara bawaan; Safari dan Edge lama yang memakai SChannel atau SecureTransport tidak [S3]. Keylog bisa disisipkan ke pcapng sebagai Decryption Secrets Block dengan `editcap --inject-secrets`, sehingga pcap dan kuncinya berpindah sebagai satu file [S3].

Batas etis, hukum, dan keamanan:

- RFC 9850 menyatakan format ini hanya untuk sistem di mana TLS melindungi data uji dan tidak boleh dipakai di produksi [S10].
- Siapa pun yang memegang file keylog bisa mendekripsi koneksi yang tercakup, termasuk trafik yang sudah direkam. Karena kuncinya simetris, pemegangnya juga bisa menyuntik atau mengubah data di koneksi aktif; bocornya `ECH_SECRET` membuka ClientHello bagian dalam termasuk SNI [S10].
- Wireshark wiki menyarankan tidak menyetel `SSLKEYLOGFILE` secara global di Windows, karena itu membuat seluruh trafik TLS bisa didekripsi [S3].
- Dekripsi hanya untuk trafik lab milik sendiri dengan kunci yang kamu hasilkan. Mendekripsi trafik orang lain tanpa izin adalah penyadapan; dasar hukumnya di Indonesia dibahas di Day 01 bagian 1.7. Jangan simpan keylog atau kunci nyata di repo; perlakukan pcapng yang berisi DSB seperti kredensial.

Jawaban untuk Bambang: pcap egress tidak bisa didekripsi. Pandangan "terdekripsi" yang sah di PT JAB hanya log `jkt-proxy01` untuk kategori yang dibuka. Keylog dipakai SOC hanya untuk trafik uji yang dibuat sendiri, misalnya saat memvalidasi bahwa sensor merekam handshake utuh (bagian 2.9).

### 1.9 Pola meski terenkripsi, dan batasnya

Pertanyaan keenam ("apa yang bisa dibaca dari yang tetap tertutup") dijawab oleh metadata yang tidak bisa disembunyikan TLS.

Tanpa dekripsi, metadata tetap berguna:

- SNI dan sertifikat (TLS 1.2): tujuan dan identitas server.
- JA3/JA4 dan JA3S: identitas library klien dan cara server menjawab.
- Ukuran dan waktu record Application Data: pola beaconing (Day 11) dan volume keluar (exfiltration, Day 12).
- Arah dan durasi koneksi, serta jumlah koneksi baru per interval.

Forensik TLS modern lebih mengandalkan metadata dan pola daripada isi, karena isi hampir selalu tertutup. Ini mengubah pertanyaan dari "apa isinya" menjadi "ke mana, klien apa, dan pola apa". ATT&CK T1573.002 (Encrypted Channel: Asymmetric Cryptography, versi 1.3) memasukkan C2 yang memakai TLS ke sub-teknik ini, dan analytic di detection strategy DET0543 mencari sesi TLS dengan rantai sertifikat atau handshake yang tidak normal, serta sertifikat yang tidak dikenal atau rusak [S16]. Itu sejalan dengan sinyal di bagian 1.4.

Batas yang harus ditulis di setiap laporan:

- **Padding.** TLS 1.3 mengizinkan padding di dalam record terenkripsi, sehingga pengirim bisa menyembunyikan ukuran trafik dari pengamat [S2]. Ukuran record yang terlihat tidak selalu ukuran data asli. Seberapa sering aplikasi memakai padding perlu dicek per kasus; ukuran tetap berguna untuk pola, bukan untuk menghitung isi.
- **ECH.** SNI hilang dari jalur luar (bagian 1.3, Day 15).
- **QUIC.** HTTP/3 berjalan di atas UDP; JA4 punya awalan `q` untuk ClientHello QUIC [S7], dan Suricata memakai `ja4.hash` juga untuk rule QUIC [S14]. Filter `tls.*` di Wireshark tidak menangkap QUIC dengan cara yang sama; Day 16 membahasnya.
- **Library bersama.** Fingerprint umum tidak membedakan malware dari program sah yang memakai library yang sama (bagian 1.5).
- **Posisi sensor.** Di belakang proxy dekripsi, fingerprint milik proxy (bagian 1.7).

### 1.10 Membedakan dari layanan sah

Pertanyaan terakhir Dimas meminta keputusan: kapan koneksi TLS yang aneh dinaikkan. Prinsipnya sama dengan anomali DNS dan HTTP di Day 05: indikator dikumpulkan, penjelasan jinak dicari secara aktif, dan kesimpulan ditulis terpisah dari indikator.

TLS ke domain tidak dikenal belum tentu jahat: layanan cloud, CDN, API vendor, updater aplikasi, dan DoH semuanya TLS ke banyak domain. Pembedanya:

- Reputasi dan umur SNI/domain, serta sertifikat (issuer, masa berlaku, kecocokan dengan SNI).
- JA3/JA4 yang langka di jaringanmu dan cocok dengan intel spesifik, dibanding fingerprint library umum (browser, curl, bahasa pemrograman).
- Pola waktu: beacon teratur dengan ukuran tetap dibanding trafik manusiawi yang mengikuti jam kerja.
- Prevalence: berapa host lain menghubungi tujuan yang sama.
- Pemilik dan konteks host: apakah sumbernya server yang perilakunya terdokumentasi.

Nyatakan kemungkinan jinak. TLS ke domain baru dengan JA4 langka, sertifikat self-signed, dan beacon teratur jauh lebih mencurigakan daripada salah satu sinyal sendiri. Keputusan menaikkan ke insiden bukan karena satu indikator, tetapi karena kombinasi indikator yang tidak punya penjelasan jinak setelah ditanyakan ke pemilik host. Bagian 2.8 menerapkan ini ke `jkt-cirunner02`.

## 2. Contoh dan langkah praktis: pcap egress Selasa pagi

Semua isi bagian ini fiktif dan merupakan keluaran ilustrasi; angka dihitung ulang supaya konsisten antar subbagian. Perintah dijalankan di `jkt-nsm-ws01` atas salinan pcap dari `jkt-pcap01`. Field dan perilaku tshark mengikuti Wireshark 4.6.9 [S1].

**Asumsi posisi sensor:** TAP egress Jakarta berada di antara core data center dan sisi dalam `jkt-fw01`, sebelum NAT, sehingga pcap memperlihatkan IP internal (`10.20.3.60` untuk proxy, IP server untuk server yang keluar langsung). Trafik broadband pelanggan PT JAB tidak lewat link ini.

**Asumsi log pendukung:** log `jkt-proxy01` di `index=proxy` dengan logformat kustom PT JAB (field `user`, `src`, `method`, `host`, `category`, `tls`, `url`, `status`, `bytes`, `server_tls`, `server_cert_issuer`, `tls_error`); log `jkt-fw01` di `index=firewall`; log resolver di `index=dns`. Nama field mengikuti konfigurasi PT JAB; cek nama field di lingkunganmu.

### 2.1 Menyiapkan pcap satu jam dari `jkt-pcap01`

Langkah pertama menjawab pertanyaan Dimas dengan data yang bisa diulang: satu jam pcap egress dengan rentang waktu absolut, Selasa 2027-05-11 pukul 06:00 sampai 07:00 WIB.

**Tujuan:** menggabungkan file ring buffer satu jam menjadi satu pcap kerja dan memastikan rentangnya benar sebelum dianalisis.

```
mergecap -w /cases/2027-05-11/egress_0600-0700.pcap \
    /mnt/pcap01/egress/egress_20270511T06*.pcap
capinfos -a -e -c -s /cases/2027-05-11/egress_0600-0700.pcap
```

| Bagian | Fungsi |
|---|---|
| `mergecap -w <out>` | Menggabungkan beberapa file pcap menjadi satu, diurutkan menurut timestamp |
| `/mnt/pcap01/egress/egress_20270511T06*.pcap` | File ring buffer `jkt-pcap01` (rotasi per 15 menit) yang dimount read-only di `jkt-nsm-ws01` |
| `capinfos -a -e` | Waktu paket pertama dan terakhir |
| `-c -s` | Jumlah paket dan ukuran file |

Keluaran ilustrasi (diringkas):

```
File name:           /cases/2027-05-11/egress_0600-0700.pcap
Number of packets:   24118552
File size:           20 GB (20.264.118.930 bytes)
First packet time:   2027-05-11 06:00:00.000412
Last packet time:    2027-05-11 06:59:59.998871
```

**Cara membaca hasil:** 20,3 GB dalam satu jam setara rata-rata sekitar 45 Mbps (20,26 GB x 8 / 3.600 detik), sekitar 4,5% dari link internet kantor 1 Gbps. Itu jauh di bawah utilisasi rata-rata harian 20% (35% di jam kerja), wajar untuk pukul 06:00. Cara membaca `capinfos` dibahas di Day 01 bagian 2.5. Waktu pertama dan terakhir menutup jam yang diminta. Kalau waktu pertama ternyata 06:07, ada file yang hilang atau tertimpa; catat sebagai celah, jangan diam-diam dianggap satu jam penuh. Format tampilan `capinfos` bisa berbeda antar versi; yang dicek adalah nilainya.

**Variasi:** untuk satu host, saring dulu dengan capture filter BPF yang cepat sebelum tshark: `tcpdump -r egress_0600-0700.pcap -w cirunner02_0600-0700.pcap host 10.20.45.22`. File hasilnya kecil dan dipakai di bagian 2.4 dan 2.7.

**Kapan gagal:** ring buffer 72 jam sudah menimpa rentang yang diminta (bukti yang tertimpa tidak bisa diambil mundur); jam `jkt-pcap01` tidak sinkron NTP sehingga korelasi dengan log proxy meleset; file terakhir masih ditulis sensor dan terbaca terpotong.

### 2.2 SNI di ClientHello: siapa ke mana

Perintah ini adalah jawaban pertama untuk "bisa tahu tujuan tiap koneksi?" dan sekaligus memperlihatkan kenapa semua terlihat dari IP proxy.

**Tujuan:** mendaftar setiap ClientHello beserta sumber, tujuan, dan SNI-nya.

Display filter untuk menampilkan SNI di Wireshark:

```
tls.handshake.extensions_server_name
```

Versi tshark untuk seluruh pcap:

```
tshark -r egress_0600-0700.pcap -Y "tls.handshake.type==1" \
    -T fields -e ip.src -e ip.dst -e tls.handshake.extensions_server_name
```

| Bagian | Fungsi |
|---|---|
| `-r egress_0600-0700.pcap` | Membaca pcap kerja dari bagian 2.1 |
| `-Y "tls.handshake.type==1"` | Display filter: hanya ClientHello (handshake type 1) |
| `-T fields -e ...` | Keluaran per baris, satu kolom per field |
| `ip.src`, `ip.dst` | Sumber dan tujuan di jalur egress |
| `tls.handshake.extensions_server_name` | SNI; kosong bila klien tidak mengirimnya |

Ringkasan per sumber dengan menambahkan `| cut -f1 | sort | uniq -c | sort -rn`:

```
  15872 10.20.3.60
   1388 10.20.2.25
    412 10.20.45.22
     96 10.20.12.41
```

**Cara membaca hasil:** total 17.768 ClientHello dalam satu jam (15.872 + 1.388 + 412 + 96). Sebanyak 15.872 berasal dari `jkt-proxy01`, yaitu seluruh trafik web kantor; tidak ada satu pun IP workstation. Sumber lain adalah server yang keluar langsung: mail gateway `jkt-mailgw01` (`10.20.2.25`, TLS lewat STARTTLS ke server mail lain), server CI `jkt-cirunner02` (`10.20.45.22`), dan server skrip NOC `jkt-nms-script01` (`10.20.12.41`). Daftar SNI per sumber memperlihatkan tujuan meski satu IP dipakai banyak domain. SNI ke domain baru atau berpola DGA adalah sinyal untuk diperiksa.

Ringkasan SNI untuk `10.20.45.22` (tambahkan `-Y "tls.handshake.type==1 && ip.src==10.20.45.22"` lalu hitung kolom ketiga):

```
    211 pkg.registry.example
     98 mirror.distro.example
     60 sync.cdn-edge.example
     43 api.git-hosting.example
```

Totalnya 412 (211 + 98 + 60 + 43). Tiga tujuan pertama yang dikenal adalah registry paket, mirror distro, dan layanan Git yang memang dipakai pipeline CI. `sync.cdn-edge.example` tidak ada di daftar tujuan yang didokumentasikan untuk server CI, dan muncul tepat 60 kali dalam 60 menit. Itulah yang dibuka lebih lanjut di bagian 2.4 dan 2.7.

**Variasi:** cari ClientHello tanpa SNI dengan `-Y "tls.handshake.type==1 && !tls.handshake.extensions_server_name"`; cari ClientHello yang membawa ECH dengan `-Y "tls.handshake.type==1 && tls.ech.payload"` (detail membaca ECH di Day 15).

**Kapan gagal:** ClientHello terpecah ke beberapa segmen TCP dan reassembly dimatikan; ClientHello besar (misalnya dengan kunci pasca-kuantum) melewati snaplen capture sehingga terpotong; trafik QUIC tidak muncul di filter ini sama sekali.

### 2.3 Versi TLS yang sebenarnya

Langkah ini menjawab bagian "bedanya 1.2 dan 1.3 buat kita": versi menentukan apakah sertifikat bisa dibaca.

**Tujuan:** menghitung berapa sesi yang benar-benar TLS 1.3 dan berapa TLS 1.2, dari ServerHello.

Field yang sering dipakai, beserta jebakannya (bagian 1.2):

```
tls.handshake.version
tls.record.version
tls.handshake.extensions.supported_version
```

```
tshark -r egress_0600-0700.pcap -Y "tls.handshake.type==2" \
    -T fields -e tls.handshake.version -e tls.handshake.extensions.supported_version \
    | sort | uniq -c | sort -rn
```

| Bagian | Fungsi |
|---|---|
| `tls.handshake.type==2` | Hanya ServerHello, karena di sinilah server memilih versi |
| `-e tls.handshake.version` | Field versi lama; `0x0303` untuk TLS 1.2 maupun 1.3 |
| `-e tls.handshake.extensions.supported_version` | Versi pilihan server bila ada; `0x0304` berarti TLS 1.3 |
| `sort \| uniq -c` | Menghitung kombinasi kedua kolom |

Keluaran ilustrasi:

```
  14630 0x0303	0x0304
   2911 0x0303
```

**Cara membaca hasil:** kolom pertama selalu `0x0303`, jadi kolom itu tidak membedakan apa-apa. Kolom kedua yang menentukan: 14.630 sesi TLS 1.3 (sertifikat tidak terlihat) dan 2.911 sesi TLS 1.2 (sertifikat terlihat, kecuali sesi resume). Total ServerHello 17.541, lebih sedikit 227 dari 17.768 ClientHello di bagian 2.2. Selisih itu adalah ClientHello yang tidak dijawab ServerHello dalam rentang ini: server tidak merespons, koneksi di-reset, atau handshake gagal. Satu lagi yang perlu diingat: HelloRetryRequest di TLS 1.3 berbentuk ServerHello juga, sehingga satu koneksi bisa menyumbang dua baris; di jam ini jumlahnya kecil dan tidak mengubah gambaran.

**Variasi:** `-e ip.src -e ip.dst` ditambahkan untuk melihat server mana yang masih memilih TLS 1.2; versi lama (`0x0301`, `0x0302`) atau cipher lemah dicatat sebagai temuan kebersihan konfigurasi.

**Kapan gagal:** memakai `tls.record.version` sebagai versi sesi (selalu `0x0303` atau `0x0301`); memakai `supported_version` dari ClientHello, yang berisi daftar tawaran klien, bukan pilihan server.

### 2.4 Sertifikat TLS 1.2 dari `jkt-cirunner02`

Alert `SOC-2027-0628` berasal dari correlation search firewall "JAB - server DC egress ke tujuan baru" yang berjalan setiap hari pukul 07:50 untuk 24 jam sebelumnya. Isinya: `jkt-cirunner02` (`10.20.45.22`, runner CI milik tim DevOps) membuka sesi ke `203.0.113.170:443` lewat rule `DC-CI-EGRESS-443`, tujuan yang belum pernah terlihat untuk rule itu dalam 30 hari. Satu baris log `jkt-fw01` yang memicunya:

```
2027-05-11T06:00:11+07:00 jkt-fw01 action=allow rule=DC-CI-EGRESS-443 src=10.20.45.22 dest=203.0.113.170 dest_port=443 nat_src=198.51.100.206 app=ssl bytes_out=1874 bytes_in=2236 bytes=4110 duration=1
```

Firewall memberi IP, port, dan byte (1.874 + 2.236 = 4.110), tetapi tidak memberi nama tujuan maupun identitas server. Pcap yang memberikannya, karena server memilih TLS 1.2.

**Tujuan:** membaca sertifikat yang dikirim `203.0.113.170` dan menilai apakah ada sinyal anomali.

Filter dasar di Wireshark:

```
tls.handshake.type == 11
x509sat.PrintableString
```

`tls.handshake.type == 11` menampilkan pesan Certificate; detail subject, issuer, dan validitas dibaca di panel detail paket. Field nama X.509 peka huruf besar dan kecil: yang benar `x509sat.PrintableString` dan `x509sat.UTF8String`, bukan `x509sat.printableString` [S8]. Nama dalam sertifikat bisa disandikan sebagai PrintableString atau UTF8String, jadi periksa keduanya.

Versi tshark atas file hasil saringan bagian 2.1:

```
tshark -r cirunner02_0600-0700.pcap \
    -Y "tls.handshake.type==11 && ip.src==203.0.113.170" \
    -T fields -E occurrence=a -E aggregator=";" \
    -e frame.time -e x509sat.UTF8String -e x509sat.PrintableString \
    -e x509af.utcTime -e x509ce.dNSName \
    | sort -u -k3
```

| Bagian | Fungsi |
|---|---|
| `tls.handshake.type==11 && ip.src==203.0.113.170` | Pesan Certificate yang dikirim server tujuan |
| `-E occurrence=a -E aggregator=";"` | Tampilkan semua nilai field multivalue, dipisah titik koma |
| `x509sat.UTF8String`, `x509sat.PrintableString` | Nilai nama (O, CN, dan lain-lain), berurutan issuer lalu subject sesuai struktur X.509 [S9] |
| `x509af.utcTime` | Waktu notBefore lalu notAfter [S8] |
| `x509ce.dNSName` | Nama DNS di SAN; kosong bila sertifikat tidak punya SAN [S8] |
| `sort -u -k3` | Satu baris per sertifikat unik |

Keluaran ilustrasi (satu sertifikat unik dari 60 sesi):

```
May 11, 2027 06:00:11.183  Edge Sync;edge-node;Edge Sync;edge-node    2027-05-10 00:52:31 (UTC);2028-05-09 00:52:31 (UTC)
```

**Cara membaca hasil:**

- Nilai nama keluar empat: dua pertama milik issuer (`O=Edge Sync`, `CN=edge-node`), dua berikutnya milik subject, dan keduanya identik. Itu sertifikat self-issued, hampir pasti self-signed; verifikasi tanda tangannya di panel detail Wireshark atau di lab.
- Tidak ada SAN, dan CN `edge-node` tidak cocok dengan SNI `sync.cdn-edge.example`.
- Masa berlaku dari 2027-05-10 00:52:31 UTC (Senin 07:52:31 WIB) sampai 2028-05-09 00:52:31 UTC: 365 hari. Sertifikat publik yang diterbitkan setelah 15 Maret 2027 maksimal 100 hari [S20], jadi sertifikat ini bukan dari CA publik. Ini konsisten dengan self-signed, bukan bukti tersendiri.
- Sertifikat dibuat sekitar 28 menit sebelum koneksi pertama ke tujuan ini (bagian 2.7 menunjukkan koneksi pertama Senin 08:20:11 WIB).

Sebagai pembanding, koneksi CI ke `pkg.registry.example` memakai TLS 1.3, sehingga tidak ada pesan Certificate yang bisa dibaca sama sekali. Itu normal, bukan anomali.

**Variasi:** untuk seluruh pcap egress, cari sertifikat yang issuer dan subject-nya sama dengan membandingkan paruh pertama dan kedua daftar nama di skrip kecil; atau, di Wireshark, tambahkan kolom `x509sat.UTF8String` lalu urutkan.

**Kapan gagal:** sesinya TLS 1.3 (tidak ada Certificate polos); sesi TLS 1.2 di-resume sehingga Certificate tidak dikirim; sertifikat besar terpecah ke banyak segmen dan reassembly TCP dimatikan; tampilan `x509af.utcTime` berbeda format antar versi Wireshark (urutannya tetap notBefore lalu notAfter).

### 2.5 JA3/JA4 dan cocokan intel `SOC-2027-0627`

Langkah ini menjawab pertanyaan Dimas tentang bulletin vendor. Senin sore, bulletin intel vendor menyebut hash JA3 `7bdce417f3dc2605bf31580c92cef970` dipakai sebuah loader komersial. Selasa pukul 06:40 Gilang Ramadhan (L1) mencocokkannya ke pcap dan membuka `SOC-2027-0627` karena ada hasil.

**Tujuan:** menghitung fingerprint klien di pcap egress dan menilai cocokan intel.

Field JA3/JA4 di Wireshark 4.6.9 [S1]:

```
tls.handshake.ja3
tls.handshake.ja3_full
tls.handshake.ja3s
tls.handshake.ja4
tls.handshake.ja4_r
```

Stacking JA4 per sumber:

```
tshark -r egress_0600-0700.pcap -Y "tls.handshake.type==1" \
    -T fields -e ip.src -e tls.handshake.ja4 \
    | sort | uniq -c | sort -rn | head -8
```

Keluaran ilustrasi:

```
  11482 10.20.3.60	t13d1516h2_8daaf6152771_b186095e22b6
   2210 10.20.3.60	t13d1715h2_5737b6b2e7b8_cd7eb64ae4fa
   1347 10.20.3.60	t13d1512h2_8daaf6152771_e99876c6e365
   1388 10.20.2.25	t13d291300_67086f404b9b_116341696443
    352 10.20.45.22	t13d3110h2_1de53be1a74d_db7c8dc215ff
     96 10.20.12.41	t13d440600_eede4226c361_5eeaab292395
     60 10.20.45.22	t13d1108h1_ddce9dc3163a_4c86f30764b0
     41 10.20.3.60	t13i1711h1_d84b22b890b6_9f7c9d87483f
```

Hash di keluaran ini fiktif kecuali baris pertama, yang memakai string contoh dari spesifikasi JA4 [S7] untuk mewakili browser berbasis Chromium di kantor.

**Cara membaca hasil:**

- Tiga baris teratas dari proxy adalah tiga kelompok besar. Dua yang pertama adalah ClientHello asli browser yang di-splice (Chromium dan satu browser lain). Baris ketiga, `t13d1512h2_8daaf6152771_e99876c6e365`, punya bagian `b` yang sama dengan Chromium tetapi bagian `c` dan jumlah ekstensi berbeda: pola ClientHello tiruan proxy untuk koneksi Chromium yang di-bump, karena daftar cipher klien diteruskan sedangkan ekstensinya dibuat proxy (bagian 1.7). Dugaan ini dicek di bagian 2.6 dengan log proxy.
- Baris `t13i1711h1_...` dari proxy: tanpa SNI (`i`), 17 cipher, 11 ekstensi, ALPN `http/1.1`. Koneksi ke IP literal yang di-bump (`SOC-2027-0629`, bagian 2.6).
- `jkt-cirunner02` punya dua fingerprint: 352 koneksi pipeline dengan satu JA4, dan 60 koneksi ke `sync.cdn-edge.example` dengan JA4 lain yang tidak muncul di host mana pun.

Cocokan intel JA3:

```
tshark -r egress_0600-0700.pcap \
    -Y 'tls.handshake.ja3 == "7bdce417f3dc2605bf31580c92cef970"' \
    -T fields -e ip.src -e tls.handshake.extensions_server_name -e tls.handshake.ja4 \
    | sort | uniq -c
```

Keluaran ilustrasi:

```
     96 10.20.12.41	api.optics-vendor.example	t13d440600_eede4226c361_5eeaab292395
```

**Cara membaca hasil:** semua 96 cocokan berasal dari satu server, ke satu tujuan, dengan satu JA4. `jkt-nms-script01` milik tim NOC Bambang menjalankan skrip Python yang menarik telemetri optik dari API vendor perangkat setiap beberapa detik per perangkat. JA4-nya menunjukkan 44 cipher, 6 ekstensi, dan tanpa ALPN (`00`): bentuk khas klien yang memakai setelan bawaan library, bukan browser. Hash JA3 di bulletin kemungkinan besar juga berasal dari setelan bawaan library yang sama, yang kebetulan dipakai loader itu. Ini collision, bukan infeksi. Disposisi `SOC-2027-0627`: false positive, dengan dua tindak lanjut: minta vendor intel memberi JA4 dan konteks (SNI, sertifikat, JA3S) bila ada, dan catat bahwa hash JA3 setelan bawaan library tidak layak dijadikan alert sendirian.

Kenapa JA3 tidak membantu untuk browser terlihat dari satu hitungan lagi:

```
tshark -r egress_0600-0700.pcap \
    -Y 'tls.handshake.ja4 == "t13d1516h2_8daaf6152771_b186095e22b6"' \
    -T fields -e tls.handshake.ja3 | sort -u | wc -l
```

Keluaran ilustrasi: `11317`. Dari 11.482 ClientHello dengan satu JA4, ada 11.317 JA3 berbeda, karena urutan ekstensi Chromium diacak per koneksi [S12]. JA4 mengurutkan ekstensi sebelum di-hash, sehingga tetap satu nilai [S7].

**Variasi:** JA3S per tujuan dengan `-Y "tls.handshake.type==2" -e ip.src -e tls.handshake.ja3s`; untuk `203.0.113.170` hasilnya satu nilai, `382a4124d77e192dca6d4ee322f8d96a` (fiktif). Pakai `tls.handshake.ja4_r` untuk melihat daftar cipher dan ekstensi mentah bila dua JA4 hanya berbeda di satu bagian.

**Kapan gagal:** Wireshark lebih lama dari 3.6.0 (tidak ada field JA3) atau 4.2.0 (tidak ada JA4) [S1]; ClientHello tidak ter-reassembly; intel hanya memberi JA3 untuk klien yang mengacak urutan ekstensi; fingerprint yang dicocokkan adalah milik proxy, bukan workstation.

### 2.6 Menyambung pcap egress dengan log `jkt-proxy01`

Langkah ini menjawab pertanyaan keempat Dimas dengan tiga alert proxy pagi itu, dan menguji dugaan di bagian 2.5 bahwa fingerprint `..._e99876c6e365` milik proxy.

**Tujuan:** memetakan koneksi proxy di pcap ke workstation dan keputusan splice atau bump.

Ringkasan keputusan TLS proxy untuk jam yang sama:

```
index=proxy host=jkt-proxy01 method=CONNECT
    earliest="05/11/2027:06:00:00" latest="05/11/2027:07:00:00"
| stats count BY tls
```

| Bagian | Fungsi |
|---|---|
| `index=proxy host=jkt-proxy01 method=CONNECT` | Hanya permintaan CONNECT, yaitu awal setiap sesi HTTPS |
| `earliest=... latest=...` | Rentang absolut yang sama dengan pcap (format `%m/%d/%Y:%H:%M:%S`) |
| `stats count BY tls` | Menghitung keputusan proxy: `spliced`, `decrypted`, `failed` |

Keluaran ilustrasi:

```
tls         count
decrypted   1402
failed       414
spliced    14388
```

**Cara membaca hasil:** total CONNECT 16.204 (14.388 + 1.402 + 414). Pcap mencatat 15.872 ClientHello dari proxy. Selisihnya bisa dijelaskan: 14.388 splice dan 1.402 bump masing-masing menghasilkan satu ClientHello ke server (15.790), dan 82 dari 414 yang gagal sempat mengirim ClientHello sebelum gagal (15.790 + 82 = 15.872). Sisa 332 gagal sebelum TLS ke server dimulai (nama tidak ter-resolve, server tidak menjawab). Angka 1.402 bump cocok dengan 1.347 ClientHello berfingerprint proxy untuk klien Chromium ditambah 41 untuk IP literal dan 14 lainnya dari klien lain di baris "lain-lain" yang tidak ditampilkan. Pencocokan satu per satu antara log proxy dan pcap dilakukan lewat host tujuan dan waktu, dengan toleransi sekitar satu detik.

Tiga alert pagi itu dibaca dengan cara yang sama.

**`SOC-2027-0625` (Senin 2027-05-10 22:14, bump).** Log proxy:

```
2027-05-10T22:14:07+07:00 jkt-proxy01 user=wahyu.saputra src=10.10.60.60 method=CONNECT host=portal.mitra-logistik.example:443 category=Newly-Registered tls=decrypted server_tls=TLSv1.3 server_cert_issuer="CN=Public Issuing CA R7"
2027-05-10T22:14:08+07:00 jkt-proxy01 user=wahyu.saputra src=10.10.60.60 method=GET url=https://portal.mitra-logistik.example/po/2027-05/PO-88412.pdf status=200 bytes=184322 category=Newly-Registered tls=decrypted
```

`JKT-WS-2025` (`10.10.60.60`) milik Wahyu Saputra dari Pengadaan membuka portal mitra logistik yang domainnya baru terdaftar. Karena di-bump, log proxy punya URL dan ukuran file. Pcap egress, yang untuk Senin 22:14 masih berada di dalam retensi 72 jam, hanya menunjukkan ClientHello dari `10.20.3.60` dengan fingerprint proxy dan sesi TLS 1.3 tanpa sertifikat terbaca. Informasi sertifikat (`server_cert_issuer`) ada di log proxy, karena proxy yang memvalidasinya. Pengadaan mengonfirmasi mitra itu baru pindah domain bulan ini. Disposisi: jinak.

**`SOC-2027-0626` (Selasa 01:10, bump gagal).** Log proxy mencatat 340 kegagalan dari `JKT-WS-2027` (`10.10.60.62`, Andika Pratama, DevOps) antara 01:10 dan 06:30:

```
2027-05-11T01:10:22+07:00 jkt-proxy01 user=andika.pratama src=10.10.60.62 method=CONNECT host=updates.devtool.example:443 category=Uncategorized tls=failed tls_error=client_rejected_certificate
```

Di pcap egress, sesi proxy ke `updates.devtool.example` terlihat normal: ClientHello buatan proxy, ServerHello TLS 1.3, beberapa record, lalu ditutup dalam kurang dari satu detik. Kegagalannya terjadi di leg workstation ke proxy: updater alat CLI itu memakai certificate pinning dan menolak sertifikat tiruan proxy (bagian 1.7). Pcap egress tidak akan pernah memperlihatkan penyebab ini. Disposisi: jinak; usulan change request untuk memasukkan `updates.devtool.example` ke daftar splice, diputuskan pemilik proxy.

**`SOC-2027-0629` (Selasa 09:20, IP literal).** Log proxy:

```
2027-05-11T09:20:03+07:00 jkt-proxy01 user=tiara.anggraini src=10.10.60.63 method=CONNECT host=203.0.113.171:443 category=Uncategorized tls=decrypted server_tls=TLSv1.3 server_cert_issuer="CN=VoIP Vendor Device CA"
2027-05-11T09:20:03+07:00 jkt-proxy01 user=tiara.anggraini src=10.10.60.63 method=POST url=https://203.0.113.171/prov/v2/heartbeat status=200 bytes=312 category=Uncategorized tls=decrypted
```

`JKT-WS-2028` (`10.10.60.63`, Tiara Anggraini, Customer Service) menghubungi IP literal tanpa nama domain, sehingga proxy menganggapnya tidak terkategori dan membukanya. Di pcap, ClientHello buatan proxy tidak membawa SNI (JA4 `t13i...`, bagian 2.5). Log proxy memperlihatkan URL `/prov/v2/heartbeat` dan issuer CA perangkat vendor VoIP. Tim IT mengonfirmasi softphone baru yang dipasang di Customer Service sejak Senin memang mengambil konfigurasi dari server provisioning vendor berdasarkan IP. Disposisi: jinak; usulan ke tim IT untuk meminta vendor memakai nama domain, supaya kategori dan reputasinya bisa dinilai.

**Variasi:** untuk koneksi splice, cari pasangan log proxy dengan `index=proxy host=jkt-proxy01 method=CONNECT host="<sni>:443" tls=spliced`, lalu bandingkan waktu dengan ClientHello di pcap.

**Kapan gagal:** jam `jkt-proxy01` dan `jkt-pcap01` tidak sinkron; proxy memakai ulang koneksi ke server untuk beberapa permintaan bump, sehingga satu ClientHello di pcap mewakili banyak permintaan; banyak workstation ke host yang sama dalam detik yang sama, sehingga pencocokan waktu ambigu (pakai port sumber proxy bila logformat mencatatnya).

### 2.7 Pola Application Data tanpa dekripsi

Langkah ini menjawab "apa yang bisa dibaca dari yang tetap tertutup" untuk koneksi `jkt-cirunner02` ke `sync.cdn-edge.example`.

**Tujuan:** mengukur interval koneksi dan ukuran record terenkripsi.

Filter Application Data:

```
tls.record.content_type == 23
```

Content type 23 adalah Application Data (terenkripsi). Di Wireshark, ukuran dan waktunya dilihat lewat Statistics > I/O Graphs atau Conversations, seperti di Day 02 [S6]. Pada sesi TLS 1.3, ingat bahwa record handshake terenkripsi juga bertipe 23 (bagian 1.1); sesi ini TLS 1.2, jadi tipe 23 hanya data aplikasi.

Interval koneksi baru:

```
tshark -r cirunner02_0600-0700.pcap \
    -Y "tls.handshake.type==1 && ip.dst==203.0.113.170" -T fields -e frame.time_epoch \
| awk 'NR>1{d=$1-p; s+=d; n++; if(n==1||d<min)min=d; if(d>max)max=d} {p=$1}
       END{printf "n=%d mean=%.1f min=%.1f max=%.1f\n", n, s/n, min, max}'
```

| Bagian | Fungsi |
|---|---|
| `tls.handshake.type==1 && ip.dst==203.0.113.170` | Setiap koneksi baru ke tujuan itu |
| `frame.time_epoch` | Waktu dalam detik sejak epoch, mudah dihitung selisihnya |
| `awk ...` | Selisih antar koneksi berurutan: jumlah, rata-rata, minimum, maksimum |

Keluaran ilustrasi untuk jam 06:00-07:00:

```
n=59 mean=60.4 min=57.9 max=63.1
```

Ukuran record data aplikasi per arah:

```
tshark -r cirunner02_0600-0700.pcap -Y "tls.record.content_type==23" \
    -T fields -e ip.src -e tls.record.length | sort | uniq -c
```

```
     60 10.20.45.22	117
     60 203.0.113.170	85
```

**Cara membaca hasil:** 60 koneksi dalam satu jam memberi 59 interval, rata-rata 60,4 detik dengan rentang sempit 57,9 sampai 63,1 detik. Setiap koneksi membawa tepat satu record 117 byte dari server CI dan satu record 85 byte dari tujuan, lalu ditutup. Ukuran yang identik di setiap koneksi berarti isi yang dikirim berukuran tetap, seperti check-in, bukan unduhan paket. Pipeline CI yang sah menghasilkan unduhan berukuran bervariasi yang mengikuti jadwal build, bukan detak setiap menit.

Ditarik ke seluruh isi ring buffer, ClientHello pertama ke `203.0.113.170` terjadi Senin 2027-05-10 08:20:11 WIB, dan sampai alert pukul 07:55:00 Selasa tercatat 1.406 koneksi. Rentang itu 84.889 detik (23 jam 34 menit 49 detik), dibagi 1.405 interval, rata-rata 60,4 detik. Log `index=dns` menunjukkan `jkt-cirunner02` pertama kali meminta `sync.cdn-edge.example` ke `jkt-res01` pukul 08:19:58 hari yang sama, dan tidak ada host lain di PT JAB yang pernah memintanya dalam 30 hari retensi.

Ini indikator beaconing, bukan kesimpulan C2. Agent pemantauan, lisensi, dan sinkronisasi yang sah juga check-in teratur. Analisis periodisitas yang lebih lengkap (jitter, skor, dan alat seperti RITA) ada di Day 11.

**Variasi:** volume keluar besar per host dari jumlah `tls.record.length` arah keluar adalah kandidat exfiltration (Day 12); isi tidak perlu dibaca untuk melihat pola.

**Kapan gagal:** satu sesi TLS panjang membawa banyak check-in, sehingga interval harus diukur dari record, bukan dari ClientHello; padding TLS 1.3 menyamarkan ukuran [S2]; jitter besar yang sengaja ditambahkan membuat interval tidak rapi.

### 2.8 Membedakan dari layanan sah dan membuka `INC-2027-065`

Langkah ini menjawab pertanyaan ketujuh Dimas: apakah `jkt-cirunner02` dinaikkan.

**Tujuan:** memeriksa prevalence tujuan dan mengumpulkan indikator dalam satu tabel keputusan.

Filter untuk mencari host lain yang menghubungi domain yang sama:

```
tls.handshake.extensions_server_name contains "cdn-edge"
```

Versi tshark untuk seluruh pcap jam itu dan, bila perlu, file ring buffer lain:

```
tshark -r egress_0600-0700.pcap \
    -Y 'tls.handshake.type==1 && tls.handshake.extensions_server_name contains "cdn-edge"' \
    -T fields -e ip.src | sort | uniq -c
```

Keluaran ilustrasi: `60 10.20.45.22`. Hanya satu host. Pemeriksaan yang sama di log proxy (`index=proxy host="*cdn-edge.example*"`) tidak menghasilkan apa pun, jadi tidak ada workstation yang mencapai domain itu lewat proxy.

Tabel berikut mengumpulkan indikator dan penjelasan jinak yang sudah dicek. Baca kolom kanan, karena keputusan menaikkan bergantung pada apakah penjelasan jinaknya terbantah.

| Indikator | Nilai | Penjelasan jinak yang mungkin | Status |
|---|---|---|---|
| Tujuan baru | `sync.cdn-edge.example`, pertama Senin 08:19:58, prevalence 1 host | Layanan baru yang dipakai pipeline | Tidak ada di daftar tujuan CI; DevOps belum mengenalinya |
| Sertifikat | Self-signed, CN `edge-node` tidak cocok SNI, tanpa SAN, 365 hari, dibuat 28 menit sebelum koneksi pertama | Layanan internal vendor dengan sertifikat sendiri | Tidak ada vendor yang terdaftar |
| Versi | Klien menawarkan TLS 1.3, server memilih TLS 1.2 | Server lama | Bukan sinyal kuat sendirian |
| Fingerprint | JA4 `t13d1108h1_ddce9dc3163a_4c86f30764b0` hanya di host ini, berbeda dari 352 koneksi pipeline | Alat baru yang sah | Belum terjelaskan |
| Pola | 1.406 koneksi, rata-rata 60,4 detik, record 117 dan 85 byte tetap | Agent monitoring | Tidak ada agent terdaftar di server itu |

Pukul 10:05 kamu menghubungi Lutfi Hakim (Lead DevOps). Pukul 11:10 Lutfi melaporkan bahwa di `jkt-cirunner02` ada proses `edge-sync` yang berjalan dengan service account runner sejak Senin 08:20, dan proses itu ditambahkan ke job pipeline `nightly-integration` lewat commit dari akun kontraktor `vendor.dev03` Senin 07:40. Tidak ada tiket perubahan yang menyebutnya. Pukul 11:30 Dimas membuka `INC-2027-065` (akses keluar tidak sah dari server CI, dugaan alat akses jarak jauh) dan menyerahkan scoping ke IR. Apakah `edge-sync` alat kontraktor yang tidak dilaporkan atau akses penyerang lewat akun kontraktor yang dikuasai belum diketahui dari data jaringan; itu pertanyaan IR, dengan data host dan riwayat akun.

Yang diserahkan dari sisi jaringan ke IR:

```
INC-2027-065  Handover data jaringan (Selasa 2027-05-11 11:30)
Host          : jkt-cirunner02 10.20.45.22 (NAT 198.51.100.206)
Tujuan        : sync.cdn-edge.example / 203.0.113.170:443
Rentang       : Senin 2027-05-10 08:20:11 sampai Selasa 07:55:00 WIB, 1.406 koneksi (masih berjalan)
TLS           : klien t13 / server memilih TLS 1.2; JA4 t13d1108h1_ddce9dc3163a_4c86f30764b0
                JA3 76dc4caf91c9aae8ff68249e5f6274fe; JA3S 382a4124d77e192dca6d4ee322f8d96a
Sertifikat    : self-signed, O=Edge Sync CN=edge-node, tanpa SAN,
                2027-05-10 00:52:31 UTC s.d. 2028-05-09 00:52:31 UTC
Pola          : interval rata-rata 60,4 detik; record 117 B keluar, 85 B masuk per koneksi
Bukti         : cirunner02_*.pcap di /cases/2027-05-11/ dengan SHA-256 di catatan kasus;
                ring buffer jkt-pcap01 menimpa data setelah 72 jam -> salin sebelum Kamis pagi
Tidak diketahui: isi record (tidak ada kunci); proses dan pemicu di host (data endpoint)
Usulan        : blokir 203.0.113.170 dan *.cdn-edge.example di jkt-fw01 setelah keputusan IC
```

**Kapan gagal:** menaikkan ke insiden hanya karena satu indikator (misalnya self-signed), padahal banyak layanan internal memakainya; atau sebaliknya, menutup alert karena "hanya check-in kecil" tanpa menanyakan pemilik host.

### 2.9 Dekripsi dengan keylog untuk trafik uji milik SOC

Langkah ini menjawab Bambang secara praktis: di PT JAB keylog tidak dipakai untuk trafik pengguna, tetapi dipakai untuk trafik uji yang dibuat SOC sendiri. Contohnya, sebelum Zeek dihidupkan di Day 08, kamu ingin memastikan `jkt-pcap01` merekam handshake dan record secara utuh untuk koneksi yang isinya kamu ketahui.

**Tujuan:** mendekripsi satu sesi uji milik sendiri di pcap untuk membandingkan apa yang terlihat sebelum dan sesudah dekripsi.

Di klien uji (sesi milik SOC, bukan trafik pengguna), keylog dibuat dengan variabel lingkungan:

```
SSLKEYLOGFILE=/cases/2027-05-11/test/keys.txt \
    curl -sS -o /dev/null https://nsm-test.jab.example/sample.txt
```

Di Wireshark (trafik uji milik sendiri):

```
# Edit > Preferences > Protocols > TLS > (Pre)-Master-Secret log filename
#   arahkan ke /cases/2027-05-11/test/keys.txt
# keylog dibuat oleh klien uji saat env SSLKEYLOGFILE diset
```

Versi tshark dan cara menyimpan pcap beserta kuncinya:

```
tshark -r test_0905.pcap -o tls.keylog_file:/cases/2027-05-11/test/keys.txt \
    -Y "http" -T fields -e http.request.method -e http.request.uri -e http.response.code
editcap --inject-secrets tls,/cases/2027-05-11/test/keys.txt test_0905.pcap test_0905-dsb.pcapng
```

| Bagian | Fungsi |
|---|---|
| `SSLKEYLOGFILE=...` | Klien menulis secret sesi ke file itu (format RFC 9850) [S10] |
| `-o tls.keylog_file:<file>` | Preferensi TLS di tshark, sama dengan menu Preferences [S3] |
| `-Y "http"` | Setelah didekripsi, isi HTTP di dalam TLS bisa difilter seperti HTTP polos |
| `editcap --inject-secrets tls,<file>` | Menyimpan keylog di dalam pcapng sebagai Decryption Secrets Block [S3] |

Keluaran ilustrasi:

```
GET	/sample.txt
	200
```

**Cara membaca hasil:** setelah keylog dimuat, Wireshark mendekripsi Application Data sesi yang kuncinya ada, sehingga header dan body HTTPS terbaca persis seperti HTTP polos. Baris keylog dicocokkan ke sesi lewat client random di ClientHello [S10]; sesi lain di pcap yang sama tetap terenkripsi. Bila sesi uji terbaca utuh, sensor merekam handshake dan record tanpa drop untuk koneksi itu.

**Kapan gagal:** keylog dari sesi yang berbeda (client random tidak cocok); klien tidak mendukung `SSLKEYLOGFILE` (misalnya aplikasi berbasis SChannel) [S3]; reassembly TCP dimatikan [S3]; sesi TLS 1.3 tetapi baris keylog yang ada hanya sebagian label. Setelah uji, `keys.txt` dan pcapng ber-DSB dihapus atau disimpan dengan kontrol akses yang sama dengan bukti kasus, karena siapa pun yang memegangnya bisa membaca sesi itu [S10].

### 2.10 Jawaban untuk Dimas dan Bambang

Ringkasan ini yang kamu kirim Selasa pukul 12:00. Setiap baris merujuk subbagian di atas supaya bisa dibuka bila ditanya.

| Pertanyaan | Jawaban singkat | Dasar |
|---|---|---|
| Apa yang masih terlihat | ClientHello, ServerHello, SNI, fingerprint, ukuran dan waktu record; sertifikat hanya di TLS 1.2 (14.630 sesi 1.3 vs 2.911 sesi 1.2 di jam 06-07) | Bagian 1.1, 1.2, 2.3 |
| Tujuan tiap koneksi | Dari SNI di pcap dan host CONNECT di log proxy; sertifikat untuk sesi 1.2 | Bagian 1.3, 1.4, 2.2, 2.4 |
| JA3, JA4, bulletin vendor | Cocokan JA3 0627 adalah collision dengan skrip NOC; pakai JA4 untuk klien, JA3 hanya untuk intel lama; JA4 BSD 3-Clause, JA4+ lain FoxIO License 1.1 | Bagian 1.5, 1.6, 2.5 |
| IP proxy dan workstation | Workstation hanya ditemukan lewat log `jkt-proxy01`; untuk koneksi yang di-bump, fingerprint di egress milik proxy | Bagian 1.7, 2.6 |
| Dekripsi pcap | Tidak bisa dan tidak boleh untuk trafik pengguna; private key server tidak cukup untuk ECDHE dan TLS 1.3; keylog hanya untuk trafik uji milik SOC | Bagian 1.8, 2.9 |
| Yang tertutup dan batasnya | Pola interval dan ukuran tetap terbaca; ECH, QUIC, padding, dan library bersama adalah batasnya | Bagian 1.9, 2.7 |
| Server CI 0628 | Kombinasi tujuan baru, self-signed, JA4 langka, dan beacon 60 detik tanpa penjelasan jinak; `INC-2027-065` dibuka, scoping ke IR | Bagian 1.10, 2.8 |

**Kapan gagal:** jawaban menyebut "fingerprint cocok, berarti malware" atau "TLS, jadi tidak bisa dilihat". Keduanya salah ke arah yang berlawanan.

## 3. Lab praktik (di VM lab terisolasi)

**Prasyarat:** Wireshark/tshark 4.6.x (minimal 4.2 untuk JA4) di VM analisis; jaringan host-only `192.168.56.0/24` dengan VM klien Linux (`192.168.56.20`), VM web server lab (`192.168.56.30`) dengan sertifikat self-signed buatan sendiri, dan VM sensor atau capture di host (`192.168.56.10`); snapshot bersih sebelum mulai. Pcap lab TLS milik sendiri (plus keylog yang kamu hasilkan di lab) atau pcap publik untuk membaca metadata. Tidak ada trafik atau kunci orang lain; tidak ada pcap kerja; tidak ada data PT JAB.

1. **Siapkan server dan capture.** Di web server lab, buat sertifikat self-signed dengan masa berlaku yang kamu pilih, dan konfigurasikan server untuk menerima TLS 1.2 dan 1.3. Rekam di sensor dengan `dumpcap -i <iface> -f "host 192.168.56.30 and tcp port 443" -w lab06.pcapng`.
2. **SNI.** Dari klien, akses server memakai nama (`https://web.lab.test/`, dengan entri hosts) dan memakai IP. Daftar SNI dari ClientHello (bagian 2.2). Pastikan koneksi berbasis IP tidak membawa SNI, dan catat huruf `i` di JA4-nya.
3. **Sertifikat.** Paksa TLS 1.2 dengan `curl --tlsv1.2 --tls-max 1.2 -k https://web.lab.test/`, lalu periksa subject, issuer, validitas, dan SAN (bagian 2.4). Ulangi dengan TLS 1.3 dan catat bahwa pesan Certificate tidak lagi terbaca.
4. **Versi.** Identifikasi 1.2 vs 1.3 dari ServerHello (bagian 2.3) dan simpulkan apa yang terlihat. Bandingkan nilai `tls.record.version`, `tls.handshake.version`, dan `supported_version` untuk kedua sesi.
5. **JA3/JA4.** Ambil fingerprint (bagian 2.5) dari tiga klien berbeda: curl, skrip Python, dan browser. Buka halaman yang sama sepuluh kali di browser berbasis Chromium, lalu hitung berapa JA3 berbeda dan berapa JA4 berbeda. Catat bahwa fingerprint dari setelan bawaan library dipakai banyak program.
6. **Dekripsi lab.** Dengan keylog lab sendiri (`SSLKEYLOGFILE` di klien), dekripsi dan baca isi (bagian 2.9). Perhatikan apa yang jadi terlihat, lalu simpan versi pcapng ber-DSB dan pastikan file itu tidak masuk repo.
7. **Pola terenkripsi.** Buat beacon jinak buatan sendiri: `while true; do curl -sk https://web.lab.test/ping >/dev/null; sleep 60; done` selama 20 menit. Tanpa dekripsi, ukur interval dan ukuran Application Data (bagian 2.7) dan catat polanya.
8. **Sah vs berbahaya.** Nilai SNI, sertifikat, JA4, dan pola terhadap layanan yang kamu tahu jinak, memakai tabel indikator bagian 2.8. Nyatakan kemungkinan jinak untuk setiap indikator.

**Hasil yang sebaiknya tersimpan:**

- Daftar SNI dari pcap lab, dengan domain atau koneksi tanpa SNI ditandai.
- Satu sertifikat TLS 1.2 yang dibaca lengkap (issuer, subject, validitas, SAN), plus catatan bahwa TLS 1.3 menyembunyikannya.
- Tabel versi dari tiga field untuk sesi 1.2 dan 1.3, dengan field mana yang jujur.
- Tabel JA3/JA4 tiga klien, plus hitungan JA3 berbeda vs JA4 berbeda untuk sepuluh kunjungan browser; keterbatasan library bersama dicatat.
- Bukti dekripsi lab hanya pada trafik sendiri; keylog tidak disimpan di repo.
- Statistik interval dan ukuran record beacon lab, dengan kemungkinan jinak dinyatakan.

**Variasi tantangan:** ambil satu koneksi TLS lab, bandingkan apa yang bisa kamu simpulkan dari metadata saja (SNI, JA3/JA4, pola) dengan apa yang terlihat setelah dekripsi keylog. Tulis dua daftar temuan (sebelum dan sesudah dekripsi) dan jelaskan mana kesimpulan yang hanya bisa didapat dengan kunci, untuk memahami batas forensik tanpa dekripsi. Untuk tantangan tambahan, pasang Squid dengan SslBump di VM terpisah dan CA lab sendiri, arahkan klien lewat proxy eksplisit, lalu bandingkan JA4 di sisi luar proxy untuk koneksi splice dan bump. Catat bagian mana dari JA4 (`a`, `b`, `c`) yang berubah; itulah pola yang perlu dikenali di jaringan dengan proxy dekripsi (bagian 1.7).

## 4. Troubleshooting

Tabel ini memuat masalah yang sering muncul saat membaca metadata TLS dari pcap. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| SNI tidak ada | ECH (terenkripsi), koneksi langsung ke IP, atau ClientHello buatan proxy untuk IP literal | Cek `tls.ech.payload` dan JA4 `i`; catat sebagai tertutup; andalkan JA4, log proxy, dan pola |
| Sertifikat tidak terlihat | TLS 1.3 (terenkripsi) atau sesi TLS 1.2 yang di-resume | Normal; pakai SNI, JA4, atau log proxy bila koneksi di-bump |
| Semua sesi terlihat "TLS 1.2" | Membaca `tls.record.version` atau `tls.handshake.version` | Pakai `tls.handshake.extensions.supported_version` di ServerHello (bagian 2.3) |
| Filter `x509sat.printableString` tidak menghasilkan apa pun | Nama field salah huruf | `x509sat.PrintableString` atau `x509sat.UTF8String` [S8] |
| Dekripsi gagal | Keylog tidak cocok sesi; TLS 1.3 butuh kunci yang tepat | Pastikan keylog dari sesi yang sama (client random cocok); aktifkan reassembly TCP [S3] |
| Private key RSA tidak mendekripsi | Cipher ECDHE atau TLS 1.3 | Normal; hanya keylog yang berfungsi [S3] |
| JA3/JA4 kosong | Wireshark lebih lama dari 3.6.0 (JA3) atau 4.2.0 (JA4); ClientHello tidak ter-reassembly | Perbarui Wireshark; JA4+ lain lewat plugin FoxIO; atau pakai Zeek/Suricata (Day 08-09) |
| JA3 browser berbeda di setiap koneksi | Urutan ekstensi diacak (Chromium sejak Januari 2023) | Pakai JA4 [S12][S7] |
| JA3 cocok browser umum atau setelan bawaan library | Library dipakai banyak klien | Fingerprint umum kurang spesifik; butuh IOC spesifik plus SNI, JA3S, dan konteks |
| Cocokan intel di egress mengenai proxy | Koneksi di-bump; fingerprint milik proxy | Cek keputusan `tls` di log proxy (bagian 2.6) |
| Hitungan ClientHello dan log proxy tidak sama | Koneksi yang gagal, pemakaian ulang koneksi oleh proxy | Rekonsiliasi per kategori seperti di bagian 2.6 |
| Isi tetap tertutup | Tidak punya kunci | Tanpa kunci, hanya metadata; itu batasnya |

## 5. Kesalahan umum dan jebakan

- **Mengira TLS berarti buta total.** Handshake, SNI, fingerprint, dan (di 1.2) sertifikat tetap terlihat; metadata berguna.
- **Mengira sertifikat selalu terlihat.** TLS 1.3 menyembunyikannya [S2]; jangan andalkan di 1.3.
- **Membaca versi dari field yang salah.** `tls.handshake.version` dan `tls.record.version` bernilai `0x0303` di TLS 1.3 [S2]; versi yang dipakai ada di `supported_versions` ServerHello.
- **Mengira versi di JA4 adalah versi sesi.** Bagian `a` JA4 memakai versi tertinggi yang ditawarkan klien [S7]; sesi `t13` bisa berakhir di TLS 1.2.
- **Mengira JA3 cocok berarti bukti pasti.** Library berbagi fingerprint; cocok dengan IOC spesifik yang langka di jaringanmu yang bernilai, bukan cocok dengan library umum (`SOC-2027-0627`).
- **Mencocokkan fingerprint di egress tanpa memperhitungkan proxy.** Untuk koneksi yang di-bump, JA4 di egress milik proxy (bagian 1.7).
- **Menganggap masa berlaku pendek sebagai anomali.** Sejak 15 Maret 2027 sertifikat publik maksimal 100 hari [S20]; yang janggal justru sertifikat baru yang jauh lebih panjang.
- **Menghitung pola dari semua record tipe 23 di sesi TLS 1.3.** Record handshake terenkripsi juga bertipe 23 [S2]; buang beberapa record pertama sesi.
- **Mencari domain fronting di pcap egress.** Header Host ada di dalam TLS; ketidakcocokan SNI dan Host hanya terlihat oleh perangkat yang mendekripsi [S18].
- **Mendekripsi trafik orang lain.** Hanya trafik lab sendiri dengan kunci sendiri; selain itu penyadapan.
- **Menyimpan keylog atau kunci di repo.** Jangan; pemegang keylog bisa membaca sesi yang tercakup, termasuk yang sudah direkam [S10]. Pakai data lab fiktif.
- **Menulis kesimpulan C2 dari pola saja.** Beacon 60 detik adalah indikator; kesimpulan butuh konfirmasi pemilik host dan data endpoint (bagian 2.8).
- `[komunitas, belum terkonfirmasi]` Analyst memakai JA3/JA4 untuk mengenali malware dari trafik terenkripsi karena tiap tool punya pola ClientHello khas; nilainya tergantung kecocokan dengan basis IOC, dan fingerprint umum (browser) kurang membedakan. Cek terhadap basis IOC yang dipakai; FoxIO sendiri menyebut basis data fingerprint ja4db.com masih dikembangkan [S5].

## 6. Catatan terkini

Bagian ini menampung detail versi, tanggal terbit, dan perubahan alat yang berguna saat membuka sumbernya, tetapi tidak mengubah alur kerja di atas.

- Wireshark 4.6.9 adalah rilis stabil per Oktober 2026, dengan 4.4.19 sebagai old stable. Field `tls.handshake.ja3`, `ja3_full`, `ja3s`, dan `ja3s_full` ada sejak 3.6.0; `tls.handshake.ja4` dan `ja4_r` sejak 4.2.0; field ECH `tls.ech.*` sejak 4.2.0, dengan tambahan `tls.ech_accepted` dan `tls.ech_rejected` di 4.6.0 [S1]. Catatan lama "cek dukungan JA3/JA4 di 4.6.9" sudah terjawab: keduanya bawaan.
- Sejak Wireshark 4.2, file kunci yang diekspor hanya memuat secret yang dirujuk paket saat ini [S3].
- JA4 (FoxIO, 2023) adalah penerus JA3 dengan format lebih stabil dan kaya; banyak alat NSM kini mendukung keduanya. Halaman FoxIO mencantumkan Wireshark, Zeek, Arkime, dan Suricata sebagai pendukung JA4+, dengan Suricata ditandai masih dalam pengembangan untuk keluarga JA4+ [S5]. Keyword `ja4.hash` sudah ada di dokumentasi Suricata [S14]; cek versi Suricata-mu di Day 09.
- Repo Salesforce JA3 diarsipkan 1 Mei 2025 dan tidak lagi dirawat [S4].
- Chrome mengacak urutan ekstensi ClientHello sejak 20 Januari 2023; rencananya untuk Chrome 110, tetapi efeknya terlihat juga di 108 dan 109 [S12].
- RFC 9850 (Juli 2026, Informational) mendokumentasikan format `SSLKEYLOGFILE`, mendaftarkan media type `application/sslkeylogfile`, dan membuat registry label keylog [S10].
- TLS 1.3 kini dispesifikasikan RFC 9846 (Juli 2026, Proposed Standard), yang menggantikan RFC 8446 dan juga RFC 5246 (TLS 1.2) [S21]. Dokumen, alat, dan rule lama masih merujuk RFC 8446; mekanisme yang dipakai Day ini (versi lewat `supported_versions`, handshake terenkripsi setelah ServerHello) dikutip dari RFC 8446 [S2], jadi cek nomor bagian padanannya di RFC 9846 bila mengutip untuk laporan formal.
- ECH distandarkan sebagai RFC 9849 (2026, Proposed Standard) [S11]. TLS 1.3 menyembunyikan sertifikat dan ECH mulai menyembunyikan SNI; keduanya mengurangi metadata yang terlihat dan menggeser deteksi ke JA4, pola, dan log perangkat yang mendekripsi.
- CA/Browser Forum ballot SC-081v3 (disetujui 11 April 2025) menurunkan masa berlaku maksimum sertifikat TLS publik: 200 hari sejak Maret 2026, 100 hari sejak 15 Maret 2027, 47 hari sejak 15 Maret 2029 [S19][S20]. Satu penerbit memulai tahap 200 hari pada 11 Maret 2026 [S20]; tanggal acuan ballot ada di dokumen CA/B Forum.
- ATT&CK: T1573.002 versi 1.3 (diubah 11 September 2026) dengan detection strategy DET0543 [S16]; T1090.004 versi 1.2 (diubah 24 Oktober 2025) dengan DET0196 [S18]; M1020 SSL/TLS Inspection versi 1.1 [S17].
- Dekripsi lab lewat `SSLKEYLOGFILE` tetap cara standar menganalisis trafik sendiri; proxy TLS inspection dipakai di korporat dengan implikasi privasi.
- Di Splunk PT JAB, `ssl.log` Zeek masuk ke index `zeek` dengan sourcetype `bro:ssl:json` (Day 08 bagian 1.9).
- Day 08-09 (Zeek/Suricata) menghitung JA3/JA4 dan mencatat SNI serta sertifikat secara otomatis, sehingga perintah tshark di Day ini menjadi alat verifikasi, bukan alat harian.

## 7. Cheat sheet

```
TERLIHAT     ClientHello+SNI (kecuali ECH) | ServerHello | sertifikat (TLS 1.2; 1.3 TERENKRIPSI) | ukuran+waktu App Data
TLS 1.3      semua handshake setelah ServerHello terenkripsi ; record luar selalu type 23, versi 0x0303
VERSI        JANGAN tls.record.version / tls.handshake.version (0x0303)
             PAKAI  tls.handshake.extensions.supported_version di ServerHello (0x0304 = TLS 1.3)
SNI          tls.handshake.extensions_server_name = tujuan ; domain baru/DGA = sinyal ; kosong = IP literal ; ECH sembunyikan SNI
SERT 1.2     tls.handshake.type == 11 ; x509sat.PrintableString / x509sat.UTF8String (issuer lalu subject)
             x509af.utcTime (notBefore;notAfter) ; x509ce.dNSName (SAN)
             self-signed / issuer aneh / CN != SNI / >100 hari terbit setelah 2027-03-15 = sinyal
JA3          MD5(SSLVersion,Cipher,SSLExtension,EllipticCurve,ECPointFormat) ; urutan ekstensi ikut -> Chromium acak
JA3S         MD5(SSLVersion,Cipher,SSLExtension) dari ServerHello ; pasangan JA3+JA3S lebih spesifik
JA4          a_b_c ; a = t/q/d + versi tertinggi DITAWARKAN + d/i + #cipher + #ekstensi + ALPN
             b = sha256[:12] cipher terurut ; c = sha256[:12] ekstensi terurut (tanpa SNI/ALPN) + sigalg
             Wireshark >= 4.2: tls.handshake.ja4, tls.handshake.ja4_r
LISENSI      JA4 = BSD 3-Clause ; JA4S/JA4H/JA4X/JA4T/... = FoxIO License 1.1 (OEM bila dijual)
PROXY        splice = ClientHello klien lewat apa adanya ; bump = ClientHello BUATAN proxy -> JA4 milik proxy
             workstation hanya dari log proxy ; pinning -> gagal di leg klien, tak terlihat di egress
DEKRIPSI LAB SSLKEYLOGFILE -> tls.keylog_file ; editcap --inject-secrets tls,keys.txt in.pcap out.pcapng
             RSA key: tidak untuk ECDHE/TLS 1.3 ; HANYA trafik sendiri ; JANGAN simpan keylog di repo
POLA         tls.record.content_type == 23 ; interval ClientHello + ukuran record = beacon (Day 11) / volume (Day 12)
SAH?         CDN/cloud/DoH = TLS ke banyak domain ; cek reputasi SNI + sertifikat + JA4 langka vs umum + pola + prevalence + pemilik
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "Di ServerHello sesi ini `tls.handshake.version` bernilai `0x0303`, jadi sesinya TLS 1.2 dan sertifikat server pasti bisa dibaca di pcap." Benarkah?

<details><summary>Jawaban</summary>

Tidak. RFC 8446 mewajibkan field versi lama bernilai `0x0303` juga pada TLS 1.3; versi yang benar-benar dipakai ada di ekstensi `supported_versions` ServerHello. Bila ekstensi itu bernilai `0x0304`, sesinya TLS 1.3 dan sertifikat terenkripsi. Bahkan pada TLS 1.2 pun sertifikat tidak dikirim ulang bila sesi di-resume. Lihat bagian 1.2 dan 2.3.

</details>

**2. Skenario keputusan.** Intel vendor memberi satu hash JA3, dan tshark menemukan 96 cocokan di pcap egress, semuanya dari `jkt-nms-script01` ke satu API vendor dengan JA4 tanpa ALPN. Langkah mana yang paling tepat?

- A. Buka insiden dan isolasi `jkt-nms-script01`, karena fingerprint cocok dengan loader.
- B. Periksa siapa pemilik host dan apa yang berjalan di sana, bandingkan SNI, JA4, dan pola dengan perilaku yang terdokumentasi; bila cocok dengan skrip sah, tutup sebagai false positive dan minta intel yang lebih spesifik.
- C. Abaikan semua intel berbasis JA3, karena JA3 sudah diarsipkan.

<details><summary>Jawaban</summary>

B. Hash JA3 dari setelan bawaan library bisa dipakai banyak program, jadi cocokan harus dinilai dengan konteks: prevalence, tujuan, JA4, dan pemilik host. Di PT JAB, cocokan itu adalah skrip Python tim NOC, sebuah collision. A keliru karena memperlakukan indikator sebagai kesimpulan tanpa mencari penjelasan jinak. C keliru karena JA3 tetap ada di intel dan rule lama; yang berubah adalah bobotnya, terutama untuk browser yang mengacak urutan ekstensi. Lihat bagian 1.5 dan 2.5.

</details>

**3. Pertanyaan jebakan.** "Di pcap egress, banyak koneksi dari `10.20.3.60` ber-JA4 `t13d1512h2_8daaf6152771_e99876c6e365`. Karena fingerprint itu tidak cocok dengan browser mana pun yang kita kenal, kemungkinan ada malware di salah satu workstation." Benarkah?

<details><summary>Jawaban</summary>

Tidak. `10.20.3.60` adalah `jkt-proxy01`. Untuk koneksi yang di-bump, proxy membuat ClientHello sendiri ke server, sehingga JA4 di egress milik proxy, bukan workstation. Bagian `b` yang sama dengan Chromium cocok dengan proxy yang meneruskan daftar cipher klien, sedangkan bagian `c` dan jumlah ekstensinya milik proxy. Konfirmasinya ada di log proxy (`tls=decrypted`). Lihat bagian 1.7, 2.5, dan 2.6.

</details>

**4. Skenario keputusan.** Bambang meminta pcap egress satu jam didekripsi untuk melihat isi trafik `jkt-cirunner02`, dengan cara yang dulu dipakai NOC. Jawaban mana yang benar?

- A. Minta private key server `203.0.113.170` lalu muat di Wireshark.
- B. Setel `SSLKEYLOGFILE` di `jkt-cirunner02` mulai sekarang, lalu dekripsi pcap lama.
- C. Pcap ini tidak bisa didekripsi; yang bisa dilakukan adalah membaca metadata dan pola, lalu menyerahkan pertanyaan isi ke IR dengan data host.

<details><summary>Jawaban</summary>

C. Private key server bukan milik PT JAB, dan dekripsi dengan private key RSA tidak berfungsi untuk cipher ECDHE maupun TLS 1.3. Keylog yang disetel sekarang tidak berisi secret sesi lama, dan menyetelnya di server produksi bertentangan dengan RFC 9850 yang menyatakan format itu bukan untuk produksi; di host yang sedang diinvestigasi, perubahan seperti itu juga keputusan IR, bukan analyst jaringan. Lihat bagian 1.8 dan 2.8.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Gilang Ramadhan (L1), dalam tiga kalimat, kenapa pcap egress PT JAB tidak bisa langsung menjawab "workstation mana yang membuka domain ini".

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Workstation kantor tidak keluar sendiri ke internet; browser minta ke `jkt-proxy01` dan proxy yang membuka koneksi, jadi di pcap egress semua koneksi web terlihat dari `10.20.3.60`. Leg dari workstation ke proxy tidak lewat sensor egress, jadi satu-satunya cara menemukan workstation adalah mencocokkan host dan waktu di log proxy. Untuk domain baru atau tidak terkategori, proxy bahkan membuat TLS-nya sendiri, jadi fingerprint di pcap pun milik proxy, bukan workstation."

Kesalahan yang sering muncul:
- Mengira IP sumber di pcap bisa dipetakan ke workstation lewat DHCP, padahal IP sumbernya proxy.
- Lupa bahwa untuk koneksi splice fingerprint-nya tetap milik workstation, hanya identitasnya yang hilang.
- Menyarankan memasang sensor di semua switch akses sebagai jawaban pertama, padahal log proxy sudah menjawabnya.

</details>

**6. Pertanyaan jebakan.** "Sertifikat `203.0.113.170` berlaku 365 hari dan self-signed, jadi sudah pasti server C2." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Self-signed dan masa berlaku panjang hanya menunjukkan sertifikat itu bukan dari CA publik, karena sertifikat publik yang terbit setelah 15 Maret 2027 maksimal 100 hari. Banyak perangkat dan layanan internal sah memakai sertifikat seperti itu. Yang membuat `jkt-cirunner02` dinaikkan adalah kombinasi tujuan baru dengan prevalence satu host, CN yang tidak cocok SNI, JA4 langka, beacon 60 detik dengan ukuran tetap, dan tidak adanya penjelasan dari pemilik host; bahkan setelah itu, `INC-2027-065` dibuka sebagai dugaan dan kesimpulannya diserahkan ke IR. Lihat bagian 1.4, 1.10, dan 2.8.

</details>

**7. Interview question (English).** "Most of the traffic you capture is TLS 1.3. What can you still learn from it without decrypting, and what are the limits?"

<details><summary>Sample answer</summary>

"Quite a lot, as long as I am honest about what it means. The ClientHello is in clear text, so I get the SNI, the offered versions, cipher suites and extensions, which I turn into a JA4 fingerprint, and the ServerHello gives me the negotiated version and a server fingerprint. In TLS 1.3 the certificate is encrypted, so I lean on SNI, JA4 and the timing and size of encrypted records to spot things like a beacon every sixty seconds with fixed-size records to a domain nobody else talks to. I also need to know where the sensor sits: behind an explicit TLS inspection proxy, the egress capture shows the proxy, and for intercepted sessions the fingerprint belongs to the proxy, so I pivot to the proxy logs to find the workstation and the URL. The limits are ECH hiding the real SNI, QUIC needing different tooling, padding hiding sizes, and shared TLS libraries making fingerprints collide, so a JA3 or JA4 match is an indicator I correlate with prevalence, certificates and the asset owner, never a verdict on its own. And I only decrypt traffic I generate myself with a key log in a lab."

What makes this answer strong: it separates what is visible from what it proves, shows awareness of sensor placement and inspection proxies, and treats fingerprints as indicators that need context rather than detections by themselves.

</details>

## 9. Sumber

Tabel ini mencatat sumber untuk verifikasi klaim di Day ini. Kolom kanan menunjukkan seberapa kuat sumber itu dan untuk klaim apa.

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Wireshark display filter reference: Transport Layer Security (tls) | https://www.wireshark.org/docs/dfref/t/tls.html | primer | diakses 2026-10-09 (Day 02), dicek ulang 2026-10-22 | Tinggi. Field filter TLS dan rentang versinya (3.0.0 sampai 4.6.9): JA3 sejak 3.6.0, JA4 dan `ja4_r` sejak 4.2.0, ECH sejak 4.2.0 |
| S2 | RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3 | https://www.rfc-editor.org/rfc/rfc8446 | primer | 2018; diakses 2026-10-09, dicek ulang 2026-10-22 | Tinggi. Pesan yang dienkripsi di 1.3 (bagian 1.2 RFC), `legacy_version` 0x0303 (4.1.2, 4.2.1), record luar type 23 dan 0x0303 (5.2), padding (5.4) |
| S3 | Wireshark wiki: TLS (dekripsi, keylog) | https://wiki.wireshark.org/TLS | primer | diakses 2026-10-09, dicek ulang 2026-10-22 | Tinggi. Tiga metode dekripsi, batas RSA key, aplikasi pendukung `SSLKEYLOGFILE`, `editcap --inject-secrets` |
| S4 | Salesforce JA3 (GitHub) | https://github.com/salesforce/ja3 | primer | diakses 2026-10-09, dicek ulang 2026-10-22 | Tinggi. Definisi JA3/JA3S, penanganan GREASE; repo diarsipkan 2025-05-01 |
| S5 | FoxIO JA4+ (GitHub) | https://github.com/FoxIO-LLC/ja4 | primer | diakses 2026-10-09, dicek ulang 2026-10-22 | Tinggi. Anggota JA4+, pembagian lisensi BSD 3-Clause dan FoxIO License 1.1, dukungan alat |
| S6 | Network-Forensics Day 02-05 (Wireshark, protokol, anomali) | (lokal) | rujukan internal | 2026-10-09 | Metadata dan pola; Statistics dan I/O Graph dibahas di Day 02 |
| S7 | FoxIO: JA4 technical details (JA4.md) | https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4.md | primer | diakses 2026-10-22 | Tinggi. Spesifikasi bagian `a`, `b`, `c`, `ja4_r`, `ja4_o`, contoh fingerprint |
| S8 | Wireshark display filter reference: x509sat, x509ce, x509af | https://www.wireshark.org/docs/dfref/x/x509sat.html ; https://www.wireshark.org/docs/dfref/x/x509ce.html ; https://www.wireshark.org/docs/dfref/x/x509af.html | primer | diakses 2026-10-22 | Tinggi. Nama field `x509sat.PrintableString`, `x509sat.UTF8String`, `x509ce.dNSName`, `x509af.utcTime` |
| S9 | RFC 5280: Internet X.509 PKI Certificate and CRL Profile | https://www.rfc-editor.org/rfc/rfc5280 | primer | 2008; diakses 2026-10-22 | Tinggi. Urutan field TBSCertificate (4.1), definisi self-issued dan self-signed (3.2) |
| S10 | RFC 9850: The SSLKEYLOGFILE Format for TLS | https://www.rfc-editor.org/rfc/rfc9850.html | primer | Juli 2026; diakses 2026-10-22 | Tinggi. Format baris, label TLS 1.2/1.3/ECH, larangan produksi, risiko keamanan |
| S11 | RFC 9849: TLS Encrypted Client Hello | https://www.rfc-editor.org/info/rfc9849 | primer | 2026; diakses 2026-10-22 | Tinggi. ECH mengenkripsi ClientHello dengan kunci publik server; Proposed Standard. Detail dibahas di Day 15 |
| S12 | Fastly: A first look at Chrome's TLS ClientHello permutation in the wild | https://www.fastly.com/blog/a-first-look-at-chromes-tls-clienthello-permutation-in-the-wild | sekunder (blog vendor CDN, data pengamatan) | 2023-02-08; diakses 2026-10-22 | Sedang-tinggi. Tanggal mulai 20 Januari 2023, efek ke JA3, sekitar 15 faktorial permutasi |
| S13 | Squid wiki: SslPeekAndSplice | https://wiki.squid-cache.org/Features/SslPeekAndSplice | primer (dokumentasi proyek) | diakses 2026-10-22 | Sedang-tinggi. Aksi peek, stare, splice, bump; ClientHello diteruskan apa adanya saat splice dan ditiru saat bump. Halaman sendiri menyebut bagian peniruan belum lengkap |
| S14 | Suricata documentation: JA3/JA4 keywords | https://docs.suricata.io/en/latest/rules/ja-keywords.html | primer | diakses 2026-10-22 (versi latest) | Tinggi. Keyword `ja3.hash`, `ja3s.hash`, `ja4.hash`, opsi konfigurasi `ja3-fingerprints` dan `ja4-fingerprints` |
| S15 | Zeek documentation: ssl.log | https://docs.zeek.org/en/master/logs/ssl.html | primer | diakses 2026-10-22 | Tinggi. Field `ssl.log`, `ja3`/`ja3s` lewat script, sertifikat TLS 1.3 tidak terlihat pasif |
| S16 | MITRE ATT&CK: T1573.002 Encrypted Channel: Asymmetric Cryptography | https://attack.mitre.org/techniques/T1573/002/ | primer | versi 1.3, diubah 2026-09-11; diakses 2026-10-22 | Tinggi. TLS termasuk sub-teknik ini; DET0543 mencari handshake dan sertifikat abnormal |
| S17 | MITRE ATT&CK: M1020 SSL/TLS Inspection | https://attack.mitre.org/mitigations/M1020/ | primer | versi 1.1, diubah 2024-12-24; diakses 2026-10-22 | Tinggi. Definisi mitigasi dan teknik yang ditangani |
| S18 | MITRE ATT&CK: T1090.004 Proxy: Domain Fronting | https://attack.mitre.org/techniques/T1090/004/ | primer | versi 1.2, diubah 2025-10-24; diakses 2026-10-22 | Tinggi. SNI vs Host, domainless fronting, DET0196 |
| S19 | CA/Browser Forum: Ballot SC-081v3, Introduce Schedule of Reducing Validity and Data Reuse Periods | https://cabforum.org/2025/04/11/ballot-sc081v3-introduce-schedule-of-reducing-validity-and-data-reuse-periods/ | primer | 2025-04-11; diakses 2026-10-22 | Tinggi untuk titik awal (398 hari), titik akhir (47 hari), dan rentang Maret 2026 sampai Maret 2029; tahap antara ada di redline ballot |
| S20 | SSL.com: SSL Certificate Validity Changes, What You Need to Know | https://www.ssl.com/article/ssl-certificate-validity-changes-what-you-need-to-know/ | sekunder (artikel CA) | 2026-06-02; diakses 2026-10-22 | Sedang-tinggi. Tahap 200 hari, 100 hari (15 Maret 2027), 47 hari (15 Maret 2029) |
| S21 | RFC 9846: The Transport Layer Security (TLS) Protocol Version 1.3 | https://www.rfc-editor.org/info/rfc9846 | primer | Juli 2026; diakses 2026-10-22 | Tinggi. Proposed Standard; menggantikan RFC 8446, RFC 5246, RFC 5077, RFC 6961, RFC 7627, RFC 8422 |

**Catatan sumber:** nama field TLS dan X.509 Wireshark dicocokkan dengan display filter reference yang mencakup sampai 4.6.9 [S1][S8]; format tampilan nilai (misalnya `x509af.utcTime`) bisa berbeda antar versi dan perlu dicek di lab. Bagian yang dienkripsi di TLS 1.3 mengikuti RFC 8446 [S2]. Definisi JA3 (Salesforce) dan JA4 (FoxIO) mengikuti repo resmi masing-masing [S4][S5][S7]; perilaku ClientHello tiruan saat bump mengikuti wiki Squid yang mengakui bagiannya belum lengkap [S13], sehingga pola "bagian `b` JA4 sama dengan klien" perlu diukur di lab dengan versi Squid yang dipakai. Tahap antara jadwal masa berlaku sertifikat (200 dan 100 hari) diambil dari artikel CA [S20] karena halaman ballot CA/B Forum hanya menyebut titik awal dan akhir [S19]. Tingkat adopsi ECH dan ambang pola bergantung lingkungan, perlu dicek. Seluruh isi PT JAB (posisi TAP, host `jkt-cirunner02` dan `jkt-nms-script01`, log proxy dan firewall, hash JA3/JA3S/JA4 selain contoh spesifikasi, angka pcap, alert `SOC-2027-0625` sampai `SOC-2027-0629`, dan `INC-2027-065`) adalah penerapan catatan ini pada organisasi fiktif, bukan hasil eksekusi nyata.
