---
day: 03
title: 'Kontrol jaringan: firewall, NGFW, IDS, IPS, WAF, proxy, VPN, DMZ, segmentasi, dan NAC'
researched_on: 2026-10-21
versions_checked: 'NIST SP 800-94 (Feb 2007; draft Rev. 1 tahun 2012 tidak difinalkan); NIST SP 800-41 Rev. 1 (Sep 2009); NIST SP 800-207 (Agu 2020); NIST SP 800-77 Rev. 1 (Jun 2020); NIST CSRC Glossary (entri diakses 2026-10-21); OWASP CRS 4.30.0 (LTS 4.25.2); Suricata User Guide (cabang latest, diakses 2026-10-21); Zeek docs (cabang master); Wazuh docs (current, 4.14.x); Snort 3; IEEE 802.1X-2020; RFC 3580'
---

# Day 03: Kontrol jaringan (firewall, NGFW, IDS, IPS, WAF, proxy, VPN, DMZ, segmentasi, dan NAC)

Cakupan: alat dan cara mengatur lalu lintas jaringan, yaitu firewall stateless dan stateful, NGFW, IDS, IPS, dan IDPS beserta metode deteksi, jenis berdasarkan lokasi, posisi inline atau out-of-band, dan perilaku saat gagal, lalu WAF, forward dan reverse proxy, VPN, DMZ, segmentasi jaringan, dan NAC, masing-masing dengan pertanyaan "alat ini melihat apa, dan apa yang bisa dilakukannya".

## Ide inti

Setiap kontrol jaringan bisa dipahami lewat tiga pertanyaan. Pertama, seberapa dalam alat itu melihat: hanya label paket (alamat dan port, lapisan 3 dan 4) atau sampai isi percakapan aplikasi (lapisan 7). Kedua, di mana alat itu berdiri: di jalur yang harus dilewati semua lalu lintas, atau di samping jalur sambil menonton salinannya. Ketiga, apa yang dilakukannya setelah melihat sesuatu: mengizinkan atau menolak, memberi peringatan saja, atau menghadang. Firewall, IDS, IPS, WAF, proxy, VPN, DMZ, segmentasi, dan NAC tampak seperti daftar singkatan yang tidak ada habisnya, tetapi semuanya hanya kombinasi berbeda dari tiga jawaban itu.

Karena tiap alat hanya menjawab sebagian, tidak ada satu alat pun yang cukup sendirian. Alat yang hanya membaca label tidak bisa membedakan permintaan web yang wajar dari yang berbahaya ke port yang sama. Alat yang membaca isi tidak bisa melihat ke dalam lalu lintas terenkripsi kecuali ia sendiri yang membuka enkripsinya. Alat yang menghadang bisa salah hadang. Pekerjaan analyst di SOC adalah tahu alat mana melihat apa, supaya bisa membaca alert dengan benar dan tahu ke log mana harus mencari berikutnya.

Bayangkan sebuah gedung kantor. Di gerbang ada penjaga yang mengecek KTP dan alamat tujuan setiap tamu (firewall); ia tidak membuka isi tas. Di lorong dan lobi ada alarm dan CCTV (IDS) yang merekam dan berbunyi bila ada yang mencurigakan, tetapi tidak menangkap siapa pun. Di pintu ruangan penting ada satpam yang berdiri di ambang pintu dan bisa langsung menghadang (IPS). Di loket pelayanan ada petugas yang memeriksa isi formulir sebelum diteruskan ke dalam (WAF). Tamu umum hanya boleh sampai ruang tamu di depan, bukan ke ruang kerja (DMZ), dan gedung dibagi zona dengan pintu sekat (segmentasi). Batas analogi ini: di jaringan, "tamu" datang ribuan per detik, "KTP" (alamat asal) bisa dipalsukan, dan sebagian besar "tas" tersegel enkripsi yang tidak bisa dibuka oleh penjaga mana pun kecuali penjaga yang memang memegang kuncinya.

```
                 INTERNET  (penyerang, pelanggan, vendor)
                     |
               [ jkt-fw01 ]  NGFW + NAT        cek alamat/port, state; fitur IPS ada
                     |                         tapi tidak bisa membaca HTTPS ke portal
     +---------------+-------------------------------+
     |  DMZ  10.20.60.0/24                           |
     |   [ jkt-waf01 ] reverse proxy + WAF           |  membuka TLS, baca isi HTTP (lapisan 7)
     |        |  HTTP polos port 8080                |
     |   [ jkt-portal01 ] portal pelanggan           |
     +--------------------|--------------------------+
                          |  core switch data center
                          |----- SPAN (salinan) -----> [ jkt-ids01 ] Suricata, IDS out-of-band
                          |
     +--------------------+--------------------------+
     | segmen internal: kantor 10.10.0.0/16,         |   [ jkt-proxy01 ] forward proxy web kantor
     | data center 10.20.0.0/16 (server, AD, DB)     |   [ jkt-vpn01 ]   VPN karyawan dari rumah
     | port switch dijaga NAC 802.1X                 |   [ jkt-radius01 ] RADIUS untuk NAC dan VPN
     +-----------------------------------------------+
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan sekitar 1.200 karyawan dan sekitar 400 ribu pelanggan internet rumah. Kamu adalah analyst L1 (lini pertama yang memeriksa setiap peringatan) yang baru bergabung di SOC (Security Operations Center, tim yang memantau dan menangani kejadian keamanan) PT JAB. Rabu 2027-08-04, hari ketiga orientasi, pukul 09:00, mentormu Sari Kusuma (analyst L2) menggambar diagram di atas di papan tulis: perimeter PT JAB dari internet sampai jaringan dalam. Di bawahnya ia menempelkan cetakan alert `SOC-2027-0820` dari dini hari tadi: sensor `jkt-ids01` mencatat tiga permintaan ke portal pelanggan `portal.jab.example` yang berisi pola SQL injection, yaitu upaya menyelipkan perintah database ke dalam isian aplikasi web [S12] (dibahas di Day 15). Sumber aslinya IP luar `192.0.2.101`. Dari log WAF, `192.0.2.101` mengirim 64 permintaan serupa; 61 ditolak WAF, 3 lolos ke portal, dan portal menolak ketiganya dengan pesan kesalahan. Lalu Sari berkata:

> "Kemarin kita belajar membaca label paket. Hari ini kita lihat siapa saja yang membaca label itu, dan siapa yang membaca isinya. Pertanyaanku: kenapa `jkt-fw01` membiarkan permintaan ini masuk, padahal firewall kita sudah NGFW yang punya fitur IPS? Apa bedanya IDS dan IPS, dan kenapa kejadian ini cuma jadi alert, tidak diblok? Bagaimana sensor tahu ini SQL injection, dan kenapa WAF bisa kelewatan tiga? `jkt-ids01` itu NIDS; bedanya apa dengan Wazuh di server Linux? Kenapa sensor kita ditaruh di SPAN, bukan di tengah jalur? Kalau suatu hari kita pasang dia sebagai IPS di tengah jalur lalu dia hang, portal ikut mati atau tidak? WAF itu firewall juga atau bukan, dan kenapa IP penyerang tidak ada di kolom sumber log portal? Kemarin aku bilang ada alat yang boleh membuka HTTPS; itu proxy kantor, kenapa boleh? Kenapa portal ditaruh di DMZ dan tidak bisa langsung ke server AD? Terakhir, karyawan yang kerja dari rumah masuk lewat VPN, sedangkan laptop vendor yang dicolok di ruang rapat tidak dapat jaringan kantor. Itu kerjaan siapa?"

Pesan itu memuat sepuluh pertanyaan:

1. Kenapa `jkt-fw01` membiarkan permintaan SQL injection masuk, padahal ia NGFW dengan fitur IPS?
2. Apa bedanya IDS dan IPS, dan kenapa kejadian ini hanya menjadi alert?
3. Bagaimana sensor mengenali SQL injection, dan kenapa WAF bisa kelewatan?
4. Apa bedanya NIDS seperti `jkt-ids01` dengan HIDS seperti Wazuh?
5. Kenapa sensor dipasang di SPAN, bukan di tengah jalur?
6. Bila sensor dipasang di tengah jalur sebagai IPS lalu mati, apa yang terjadi pada portal?
7. Apa bedanya WAF dengan firewall, dan kenapa IP penyerang tidak muncul di kolom sumber log portal?
8. Kenapa proxy kantor boleh membuka HTTPS?
9. Kenapa portal ditaruh di DMZ dan tidak bisa langsung menghubungi server internal?
10. Siapa yang mengatur akses karyawan dari rumah dan menolak laptop vendor di ruang rapat?

Pertanyaan 1 dijawab di bagian 1.1 dan 1.2, pertanyaan 2 di bagian 1.3, pertanyaan 3 di bagian 1.4 dan 1.8, pertanyaan 4 di bagian 1.5, pertanyaan 5 di bagian 1.6, pertanyaan 6 di bagian 1.7, pertanyaan 7 di bagian 1.8 dan 1.9, pertanyaan 8 di bagian 1.9, pertanyaan 9 di bagian 1.10 dan 1.11, dan pertanyaan 10 di bagian 1.12 dan 1.13. Bagian 2 membaca alert `SOC-2027-0820` secara utuh, membandingkan perilaku IDS dan IPS pada empat kasus, lalu membaca log proxy, NAC, dan VPN.

**Kapan relevan:** setiap kali membaca alert dari firewall, IDS, IPS, WAF, atau proxy; saat memutuskan log mana yang dicari berikutnya; saat menilai kenapa sebuah serangan lolos atau terhenti di lapisan tertentu; dan saat menjawab pertanyaan interview klasik "apa bedanya IDS dan IPS" atau "apa bedanya firewall dan WAF".
**Kapan bukan jawaban:** saat ancamannya sudah berada di dalam perangkat (program jahat yang berjalan di laptop, akun sah yang dicuri) atau tersembunyi di lalu lintas terenkripsi yang tidak dibuka siapa pun. Kontrol jaringan hanya melihat yang lewat jaringan dan yang bisa dibacanya; untuk aktivitas di dalam perangkat dibutuhkan kontrol endpoint dan identitas yang dibahas di Day 06, dan serangan banjir lalu lintas dibahas di Day 04.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day 01 (control, defense in depth, least privilege, zero trust, attack surface) dan Day 02 (paket, header, port, TCP, UDP, model OSI, NAT, HTTP, HTTPS, SNI) tidak diulang di tabel ini; definisinya diulang satu kalimat di subbagian bila dibutuhkan. Tabel ini memuat semua istilah baru Day ini; cari kolom ketiga bila sebuah istilah terasa abstrak.

| Istilah | Arti singkat | Padanan sehari-hari |
|---|---|---|
| Firewall | Perangkat atau program yang mengizinkan atau menolak lalu lintas berdasarkan aturan | Penjaga gerbang yang cek KTP dan alamat tujuan tamu |
| Rule dan ruleset | Satu aturan izinkan/tolak, dan kumpulan aturan itu | Daftar tamu yang boleh masuk dan ke ruangan mana |
| Deny by default | Semua yang tidak diizinkan secara tegas ditolak | "Yang tidak ada di daftar, tidak masuk" |
| Firewall stateless (packet filter) | Memeriksa setiap paket sendiri-sendiri tanpa ingatan | Penjaga tanpa buku tamu |
| Firewall stateful | Mencatat sambungan yang sedang berjalan di state table | Penjaga yang mencatat siapa masuk dan siapa yang sedang ditunggu balasannya |
| NGFW | Firewall stateful yang juga mengenali aplikasi, user, dan biasanya membawa fitur IPS | Penjaga gerbang yang juga boleh membuka tas dan hafal daftar barang terlarang |
| IDS | Sistem yang mendeteksi tanda serangan lalu memberi alert | Alarm dan CCTV |
| IPS | IDS yang juga berusaha menghentikan serangan | Satpam di pintu yang menghadang |
| IDPS | Istilah payung untuk IDS dan IPS | Sistem keamanan gedung secara umum |
| Signature-based | Deteksi dengan mencocokkan pola serangan yang sudah dikenal | Daftar foto buronan di pos satpam |
| Anomaly-based | Deteksi dengan membandingkan aktivitas terhadap profil normal | Satpam yang hafal kebiasaan penghuni gedung |
| Policy-based | Deteksi pelanggaran aturan yang ditetapkan organisasi | Aturan tertulis gedung, misalnya "dilarang membawa kamera ke ruang server" |
| Stateful protocol analysis | Membandingkan urutan dan isi protokol dengan perilaku yang lazim | Petugas yang tahu urutan prosedur: lapor resepsionis dulu, baru naik lift |
| False positive / false negative | Alert untuk aktivitas wajar / serangan yang tidak terdeteksi | Alarm berbunyi karena kucing / maling yang tidak terekam |
| Tuning | Menyesuaikan aturan deteksi supaya lebih akurat | Menyetel sensitivitas alarm supaya tidak berbunyi karena angin |
| NIDS / NIPS | IDS / IPS yang mengamati lalu lintas jaringan | CCTV di lorong / satpam di pintu lorong |
| HIDS / HIPS | IDS / IPS yang berjalan di satu perangkat (host) | Sensor di dalam ruangan atau di brankas |
| WIPS | IPS untuk jaringan nirkabel (Wi-Fi) | Petugas yang mencari pemancar radio liar di gedung |
| Inline | Alat berdiri di jalur; semua lalu lintas harus lewat dia | Satpam yang berdiri di ambang pintu |
| Out-of-band (passive) | Alat menonton salinan lalu lintas dari samping | Petugas di ruang monitor yang menonton salinan rekaman |
| SPAN / TAP | Port switch yang menyalin lalu lintas / alat yang menyadap kabel untuk salinan | Layar CCTV bersama / kamera khusus yang dipasang langsung di pintu |
| Fail-open / fail-closed | Saat alat mati, lalu lintas tetap lewat / lalu lintas terhenti | Pintu darurat yang terbuka saat listrik mati / brankas yang tetap terkunci |
| WAF | Firewall khusus aplikasi web yang membaca isi permintaan HTTP | Petugas yang memeriksa isi formulir sebelum diteruskan ke loket |
| Proxy | Perantara yang membuat sambungan atas nama pihak lain | Perantara atau kurir |
| Forward proxy | Perantara di sisi klien (karyawan) untuk keluar ke internet | Kurir kantor yang membelikan barang untuk karyawan |
| Reverse proxy | Perantara di sisi server yang menerima tamu atas nama server | Resepsionis yang menerima semua tamu atas nama ruangan di dalam |
| TLS inspection | Membuka enkripsi, memeriksa, lalu mengenkripsi ulang | Petugas surat yang boleh membuka amplop lalu menyegel ulang dengan segel kantor |
| VPN | Saluran terenkripsi di atas jaringan publik | Lorong tertutup dari rumah ke kantor yang melewati jalan umum |
| DMZ | Segmen tempat server yang dibuka ke publik, terpisah dari jaringan dalam | Ruang tamu atau loket di depan kantor |
| Segmentasi jaringan | Membagi jaringan menjadi zona dengan aturan di antaranya | Gedung yang dibagi zona dengan pintu sekat kebakaran |
| Lateral movement | Penyerang berpindah dari satu perangkat ke perangkat lain di dalam jaringan | Maling yang sudah masuk lalu berpindah dari ruang ke ruang |
| NAC | Kontrol yang memeriksa perangkat sebelum diberi akses jaringan | Pemeriksaan kartu akses di pintu masuk sebelum dapat meja |
| 802.1X dan RADIUS | Standar autentikasi di port jaringan, dan server yang memutuskan | Pintu berkartu dan kantor keamanan yang memvalidasi kartu |

### 1.1 Firewall: stateless vs stateful

Pertanyaan pertama Sari dimulai dari `jkt-fw01`. Firewall itu mencatat 64 sambungan dari `192.0.2.101` ke `203.0.113.8` port 443, dan semuanya diizinkan. Untuk mengerti kenapa, kamu perlu tahu apa yang sebenarnya diperiksa firewall.

**Apa itu:** firewall adalah perangkat atau program yang mengatur aliran lalu lintas jaringan antara jaringan atau perangkat yang tingkat keamanannya berbeda [S3][S4]. Cara kerjanya memakai ruleset, yaitu daftar aturan yang masing-masing berbunyi kurang lebih "lalu lintas dari sini, ke sana, lewat port ini: izinkan atau tolak" [S3]. Firewall stateless (disebut juga packet filter) memeriksa setiap paket sendiri-sendiri tanpa ingatan tentang paket sebelumnya. Firewall stateful (stateful inspection) mencatat setiap sambungan yang sedang berjalan di sebuah state table dan memeriksa apakah paket baru cocok dengan sambungan yang tercatat [S3].

**Analogi:** penjaga gerbang yang mengecek KTP dan alamat tujuan setiap tamu. Penjaga stateless tidak punya buku tamu: setiap orang yang datang diperiksa dari nol, termasuk orang yang berkata "saya cuma mengantar balasan untuk karyawan di dalam". Penjaga stateful punya buku tamu; ia mencatat "karyawan A baru saja menelepon toko B", sehingga saat kurir dari toko B datang membawa balasan, ia tahu kurir itu memang ditunggu. Batas analoginya: penjaga ini hanya membaca KTP dan alamat, tidak membuka isi tas. KTP (alamat asal) juga bisa dipalsukan.

**Cara kerja:** firewall stateless memutuskan berdasarkan informasi di header: alamat asal, alamat tujuan, protokol (TCP, UDP, ICMP), port asal dan tujuan, serta antarmuka dan arah paket [S3]. Itulah lapisan 3 (alamat) dan lapisan 4 (port) model OSI; model OSI adalah pembagian tujuh lapisan komunikasi jaringan yang dibahas di Day 02 bagian 1.2. Contoh paling umum dari packet filter murni adalah router yang memakai ACL (access control list, daftar aturan izinkan/tolak di router) [S3]. Firewall stateful menambah ingatan. Saat laptop di dalam membuka sambungan keluar yang diizinkan, firewall menulis satu baris di state table berisi alamat dan port kedua sisi serta status sambungan. Paket balasan dari luar baru diizinkan bila cocok dengan baris itu. Paket yang mengaku bagian dari sambungan yang sudah berjalan, padahal tidak ada di tabel, ditolak [S3]. Untuk UDP yang tidak punya sambungan, firewall stateful mencocokkan alamat dan port saja: jawaban DNS dari luar hanya diizinkan bila sebelumnya ada query DNS dari dalam ke alamat itu [S3].

```
State table jkt-fw01 (disederhanakan)
asal                  tujuan               proto  status
10.10.33.15:50412     192.0.2.103:443      tcp    ESTABLISHED   <- laptop JKT-WS-1030 membuka situs dokumentasi
192.0.2.101:41877     203.0.113.8:443      tcp    ESTABLISHED   <- sambungan dari luar ke portal (diizinkan rule IN-PORTAL-HTTPS)
10.10.33.15:53190     10.20.1.10:53        udp    (tunggu jawaban, timeout singkat)

Paket datang: 192.0.2.103:443 -> 10.10.33.15:50412  => cocok baris 1, izinkan
Paket datang: 192.0.2.106:443 -> 10.10.33.15:50999  => tidak ada di tabel, tolak
```

Prinsip yang dianjurkan NIST adalah deny by default: tolak semua lalu lintas masuk dan keluar yang tidak diizinkan secara tegas, karena lebih aman daripada mengizinkan semua yang tidak dilarang [S3]. Firewall juga menyaring arah keluar (egress filtering), misalnya hanya mengizinkan paket keluar yang alamat asalnya memang milik organisasi, supaya perangkat yang terinfeksi tidak bisa memalsukan alamat [S3].

**Contoh di PT JAB:** aturan `IN-PORTAL-HTTPS` di `jkt-fw01` berbunyi "izinkan TCP dari mana saja ke `203.0.113.8` port 443". Pelanggan di seluruh Indonesia harus bisa membuka portal, jadi sumbernya memang "mana saja". Permintaan dari `192.0.2.101` memenuhi aturan itu: alamat tujuan benar, port benar, handshake TCP (tiga langkah pembuka sambungan SYN, SYN-ACK, ACK) lengkap. Dari sudut pandang penjaga gerbang yang membaca KTP dan alamat, tamu ini sah. Isi permintaannya, yang berisi pola SQL injection, berada di lapisan 7 dan terbungkus HTTPS. Di perbatasan jaringan, router PT JAB memakai ACL stateless sederhana untuk membuang paket dari internet yang mengaku beralamat privat seperti `10.x.x.x`, karena alamat itu mustahil datang dari luar.

**Beda dengan NAT:** NAT (penerjemahan alamat privat ke publik, Day 02 bagian 1.11) sering berada di kotak yang sama dengan firewall, tetapi NIST menyebut NAT sebenarnya teknologi routing, bukan teknologi firewall [S3]. NAT menerjemahkan alamat; firewall memutuskan boleh atau tidak.

**Salah paham umum:**
- "Firewall yang mengizinkan sebuah sambungan berarti sambungan itu aman." Firewall hanya menjawab "apakah alamat dan port ini boleh". Permintaan jahat yang memakai alamat dan port yang diizinkan tetap lolos. NIST juga mencatat firewall hanya bekerja efektif pada lalu lintas yang bisa diperiksanya; lalu lintas terenkripsi tidak bisa dibaca isinya [S3].

Kenapa ini penting untuk security: baris `allow` di log firewall bukan bukti bahwa sebuah sambungan wajar. Saat membaca alert, tanyakan dulu "aturan mana yang mengizinkan ini, dan apakah aturan itu memang dimaksudkan untuk sumber dan tujuan ini". Aturan yang terlalu longgar (misalnya port remote desktop yang dibuka ke internet, seperti temuan `SOC-2027-0810` di Day 02) adalah salah satu sumber celah paling umum.

### 1.2 NGFW (next-generation firewall)

Sari menekankan bahwa `jkt-fw01` bukan firewall biasa: ia NGFW dengan fitur IPS. Lalu kenapa fitur IPS itu tidak menghentikan SQL injection ke portal?

**Apa itu:** NGFW adalah firewall stateful yang ditambah kemampuan membaca lapisan aplikasi: mengenali aplikasi apa yang lewat (bukan hanya nomor port), mengenali user di balik alamat IP, membawa fitur IPS terpadu, dan sering bisa membuka enkripsi TLS untuk diperiksa [S9]. Istilahnya dipopulerkan oleh lembaga riset Gartner, dan isinya berbeda-beda antar vendor [S9]. NIST SP 800-41 menyebut kemampuan sejenis sebagai application firewall: firewall stateful yang ditambah stateful protocol analysis, yang oleh sebagian vendor disebut deep packet inspection [S3].

**Analogi:** penjaga gerbang yang selain mengecek KTP juga boleh membuka tas dan hafal daftar barang terlarang. Batasnya: ia hanya bisa membuka tas yang tidak disegel. Amplop tersegel yang ditujukan ke orang lain (lalu lintas HTTPS ke server yang kuncinya dipegang orang lain) tetap tertutup baginya.

**Cara kerja:** NGFW tetap melakukan semua yang dilakukan firewall stateful, lalu menambah pemeriksaan di atasnya. Fitur pengenal aplikasi bisa membedakan, misalnya, aplikasi berbagi file dari browsing biasa walaupun keduanya memakai port 443. Fitur identitas bisa membuat aturan "tim Keuangan boleh ke aplikasi perbankan", bukan hanya "alamat 10.10.33.0/24 boleh". Fitur IPS mencocokkan isi paket dengan pola serangan [S9]. Semua fitur yang membaca isi hanya bekerja bila isinya terbaca: untuk HTTPS, NGFW harus memegang cara membuka enkripsinya (TLS inspection, bagian 1.9). NIST juga mengingatkan bahwa firewall dengan stateful protocol analysis belum tentu setara dengan IDPS penuh, karena IDPS biasanya punya deteksi yang jauh lebih luas [S3].

**Contoh di PT JAB:** `jkt-fw01` menjalankan fitur IPS untuk lalu lintas yang bisa dibacanya, misalnya protokol yang tidak terenkripsi. Untuk HTTPS ke portal, kunci sertifikat `portal.jab.example` dipasang di `jkt-waf01`, bukan di `jkt-fw01`. Bagi `jkt-fw01`, ke-64 sambungan dari `192.0.2.101` hanyalah sambungan TLS yang sah ke port 443; isinya tidak terlihat. Itulah jawaban pertanyaan pertama Sari: firewall-nya bekerja sesuai desain, dan pemeriksaan isi permintaan web memang diserahkan ke WAF.

**Beda dengan IPS:** yang dibedakan adalah fungsi, bukan selalu kotaknya. NIST mencatat sebagian firewall membawa teknologi IPS [S3], dan sebagian sensor IPS inline adalah perangkat gabungan firewall dan IDPS [S1]. Saat orang berkata "firewall kita sudah ada IPS-nya", artinya satu kotak menjalankan dua fungsi: fungsi firewall (izinkan atau tolak berdasarkan aturan) dan fungsi IPS (deteksi lalu hadang berdasarkan pola serangan). Keduanya tetap dipelajari terpisah karena cara berpikir dan cara merawatnya berbeda.

**Salah paham umum:**
- "Punya NGFW berarti tidak perlu WAF atau IDS." NGFW yang tidak membuka TLS ke sebuah server tidak bisa melihat serangan di dalam HTTPS ke server itu, dan fitur IPS-nya biasanya dirancang untuk banyak protokol sekaligus, bukan untuk memahami satu aplikasi web secara mendalam seperti WAF.

Kenapa ini penting untuk security: saat sebuah alert berkata "lolos dari firewall", analyst perlu tahu fitur mana yang aktif dan lalu lintas mana yang benar-benar terbaca. Nama "NGFW" di daftar aset tidak menjamin isi lalu lintas diperiksa.

### 1.3 IDS, IPS, dan IDPS

Pertanyaan kedua Sari: kenapa kejadian ini hanya menjadi alert? Jawabannya ada pada perbedaan IDS dan IPS, istilah yang paling sering ditanyakan di interview.

**Apa itu:** intrusion detection adalah proses mengamati kejadian di sistem atau jaringan dan menganalisisnya untuk mencari tanda kemungkinan insiden, yaitu pelanggaran atau ancaman pelanggaran kebijakan keamanan [S1]. IDS (intrusion detection system) adalah perangkat lunak yang mengotomatiskan proses itu: ia melihat, menilai, mencatat, lalu memberi alert (peringatan) ke petugas. IPS (intrusion prevention system) punya semua kemampuan IDS ditambah upaya menghentikan kejadian yang terdeteksi [S1]. NIST memakai istilah IDPS (intrusion detection and prevention system) untuk menyebut keduanya sekaligus, dan menegaskan istilah itu dipakai demi ringkas, bukan untuk menggantikan IDS dan IPS yang sudah mapan [S1]. Banyak produk IPS bisa dimatikan fitur pencegahannya sehingga bekerja sebagai IDS [S1].

**Analogi:** IDS adalah alarm dan CCTV. Ia merekam, berbunyi, dan memberi tahu petugas, tetapi tidak menangkap siapa pun; yang bertindak adalah manusia yang mendengar alarm. IPS adalah satpam yang berdiri di pintu dan langsung menghadang tamu mencurigakan. Batasnya: sebagian IDS punya fitur respons aktif terbatas (lihat Cara kerja), dan satpam yang tidak dilatih bisa salah hadang tamu sah.

**Cara kerja:** keduanya bekerja dengan langkah yang sama sampai titik keputusan:

```
lalu lintas atau kejadian
        |
   [ amati ]  paket, log, aktivitas host
        |
   [ analisis ]  cocokkan dengan signature, profil normal, atau aturan (bagian 1.4)
        |
   cocok? -- tidak --> lanjut, tidak ada catatan khusus
        |
       ya
        |
   IDS: catat + alert ke SOC ----------------> manusia menilai dan bertindak
   IPS: catat + alert + hadang (drop paket, putus sesi, ubah isi, minta firewall blokir)
```

Cara IPS menghadang bergantung pada posisinya. Sensor inline (berdiri di jalur, bagian 1.6) bisa membuang paket, membatasi bandwidth sebuah protokol, atau membersihkan bagian isi yang berbahaya sebelum diteruskan [S1]. Sensor yang hanya menonton salinan masih bisa mencoba memutus sesi TCP dengan mengirim paket RST (reset) ke kedua ujung, teknik yang disebut session sniping. NIST mencatat teknik ini sering terlambat karena paket serangan sudah sampai lebih dulu, hanya berlaku untuk TCP, dan sudah jarang dipakai [S1]. Sensor di posisi mana pun juga bisa meminta perangkat lain (firewall, router, switch) untuk memblokir alamat tertentu atau memindahkan perangkat yang terinfeksi ke VLAN karantina, atau menjalankan skrip buatan admin [S1]. Di sisi host, Wazuh menyebut fitur sejenis active response: skrip yang dijalankan di endpoint bila alert cocok dengan aturan tertentu, misalnya untuk memblokir akses jaringan dari alamat penyerang, dengan pilihan mencabut tindakannya otomatis setelah waktu tertentu [S19]. Karena itu, kalimat "IDS sepenuhnya pasif" tidak sepenuhnya benar; yang tepat adalah "IDS tidak berdiri di jalur, jadi ia tidak bisa menjamin serangan berhenti sebelum sampai".

Tidak ada IDS atau IPS yang sempurna. NIST mendefinisikan false positive sebagai aktivitas wajar yang salah dikenali sebagai jahat, dan false negative sebagai aktivitas jahat yang gagal dikenali; keduanya tidak mungkin dihapus seluruhnya, dan menurunkan yang satu biasanya menaikkan yang lain [S1]. Menyesuaikan konfigurasi supaya deteksi lebih akurat disebut tuning [S1]. Day 11 membahas keempat kemungkinan hasil alert (true/false positive/negative) lebih dalam.

**Contoh di PT JAB:** `jkt-ids01` menjalankan Suricata, mesin open source yang menyebut dirinya mesin IDS, IPS, dan network security monitoring [S14]. Mesin yang sama bisa dipakai sebagai IDS atau IPS; yang menentukan adalah cara pemasangannya. Di PT JAB ia dipasang sebagai IDS, menerima salinan lalu lintas dari SPAN core switch data center (bagian 1.6). Karena itu, saat tiga permintaan SQL injection lewat, `jkt-ids01` hanya bisa mencatat dan mengirim alert `SOC-2027-0820` ke SIEM (sistem pengumpul log dan alert, Day 10); ia tidak bisa menghentikannya. Yang menghentikan 61 permintaan lain adalah WAF, dan yang membuat tiga sisanya gagal adalah aplikasi portal sendiri.

**Beda dengan firewall:** firewall mengizinkan atau menolak berdasarkan aturan akses yang ditulis lebih dulu ("siapa boleh ke mana"); IDS dan IPS mencari tanda serangan di lalu lintas yang sudah diizinkan ("apakah yang lewat ini berbahaya"). Firewall menjawab pertanyaan izin, IDS/IPS menjawab pertanyaan niat. Tabel lengkapnya ada di bagian 3.1 dan 3.2.

**Salah paham umum:**
- "False positive di IDS murah karena tidak memblokir apa pun." Memang tidak ada trafik yang ikut terblokir, tetapi setiap alert palsu tetap harus diperiksa manusia. Ratusan alert palsu per hari menghabiskan waktu analyst dan membuat alert yang benar tenggelam (alert fatigue, Day 11). NIST sendiri mencatat deteksi yang lebih sensitif membutuhkan sumber daya analisis lebih besar untuk memisahkan alert palsu dari yang benar [S1].
- "IPS bisa dipasang lalu dibiarkan." IPS butuh tuning dan perawatan terus-menerus; IPS yang tidak dirawat bisa memblokir lalu lintas sah (bagian 2.2, kasus aplikasi internal).

Kenapa ini penting untuk security: saat membaca alert, kamu harus tahu apakah alat itu hanya melihat atau juga bertindak. Alert dari IDS berarti "ini terjadi dan mungkin sampai ke tujuan"; alert dari IPS dengan aksi `blocked` berarti "ini dicoba dan dihentikan di titik ini". Keduanya butuh tindak lanjut yang berbeda.

### 1.4 Metode deteksi: signature, anomaly, policy, dan stateful protocol analysis

Pertanyaan ketiga Sari: bagaimana sensor tahu bahwa tiga permintaan itu SQL injection? Jawabannya adalah metode deteksi, dan setiap metode punya titik buta sendiri.

**Apa itu:** NIST SP 800-94 membagi metode deteksi menjadi tiga: signature-based (mencocokkan pola ancaman yang sudah dikenal), anomaly-based (membandingkan aktivitas dengan profil perilaku normal), dan stateful protocol analysis (membandingkan aktivitas dengan profil umum tentang cara sebuah protokol seharusnya dipakai) [S1]. Di banyak materi juga muncul policy-based: deteksi pelanggaran aturan yang ditetapkan organisasi. NIST tidak menjadikannya metode tersendiri, tetapi mencatat bahwa banyak IDPS bisa dikonfigurasi dengan aturan mirip ruleset firewall untuk mengenali lalu lintas yang melanggar kebijakan keamanan atau kebijakan pemakaian [S1]. Kebanyakan produk memakai gabungan beberapa metode (sering disebut hybrid) [S1].

**Analogi:** signature seperti daftar foto buronan di pos satpam: sangat cepat mengenali wajah yang ada di daftar, tetapi buta terhadap wajah baru atau yang menyamar. Anomaly seperti satpam lama yang hafal kebiasaan penghuni ("Pak Budi tidak pernah datang jam dua pagi"). Policy-based seperti aturan tertulis gedung ("dilarang membawa kamera ke ruang server"), yang tidak peduli apakah pelanggarnya berniat jahat. Stateful protocol analysis seperti petugas yang hafal urutan prosedur ("tamu harus lapor resepsionis dulu baru naik lift; tamu yang langsung naik lift itu aneh"). Batasnya: di jaringan, "wajah" serangan bisa diubah sedikit secara otomatis dalam hitungan detik.

**Cara kerja:** tabel berikut merangkum keempatnya; cari kolom "Titik buta" karena itulah yang menjelaskan kenapa sebuah serangan bisa lolos.

| Metode | Cara memutuskan | Kekuatan | Titik buta | Contoh |
|---|---|---|---|---|
| Signature-based | Cocokkan paket atau log dengan daftar pola serangan yang dikenal | Sangat efektif untuk ancaman yang sudah dikenal, sederhana, mudah dijelaskan [S1] | Ancaman baru, varian, dan teknik penyamaran; nama file diubah sedikit pun bisa lolos [S1] | Pola kata kunci SQL di parameter URL |
| Anomaly-based | Bandingkan dengan profil normal yang dibangun selama masa pengamatan (hari sampai minggu) [S1] | Bisa menangkap ancaman yang belum dikenal [S1] | Banyak false positive saat ada aktivitas wajar yang jarang (pemeliharaan bulanan); aktivitas jahat bisa ikut masuk profil; alasan alert sulit dijelaskan [S1] | Laptop yang tiba-tiba mengirim data 50 kali lipat dari biasanya |
| Policy-based | Cocokkan dengan aturan yang ditetapkan organisasi [S1] | Jelas dan mudah diaudit; menangkap pelanggaran walau bukan serangan | Hanya sebaik aturan yang ditulis; tidak menangkap serangan yang tidak melanggar aturan | Telnet ke server produksi, padahal kebijakan mewajibkan SSH |
| Stateful protocol analysis | Bandingkan urutan perintah dan panjang argumen dengan profil protokol yang lazim [S1] | Menangkap urutan perintah yang janggal dan argumen yang tidak wajar | Sangat berat untuk diproses; protokol buatan vendor sering tidak terdokumentasi [S1] | Nama user 1.000 karakter di perintah login, padahal batas wajarnya 20 |

NIST memberi contoh klasik kelemahan signature: signature yang mencari file `freepics.exe` tidak cocok dengan `freepics2.exe` [S1]. Untuk anomaly, profil yang dibangun ulang otomatis (dinamis) juga bisa diakali penyerang yang menaikkan aktivitasnya pelan-pelan sampai dianggap normal [S1].

Istilah zero-day sering muncul di sini: serangan yang memanfaatkan kelemahan yang belum diketahui pembuat perangkat lunak dan belum punya perbaikan (dibahas di Day 17). Karena belum ada polanya, signature tidak bisa menangkapnya; yang punya peluang adalah anomaly-based atau deteksi perilaku di host.

**Contoh di PT JAB:** aturan Suricata yang memicu `SOC-2027-0820` adalah signature: ia mencari pola kata kunci SQL di parameter URL. WAF `jkt-waf01` juga memakai signature, tetapi dari kumpulan aturan yang berbeda. Tiga permintaan yang lolos dari WAF memakai penyamaran (kata kunci SQL disisipi komentar sehingga tidak cocok dengan pola WAF versi yang dipakai), sedangkan aturan Suricata kebetulan menangkap varian itu. Ini contoh kenapa dua lapisan dengan signature berbeda lebih kuat daripada satu. Di sisi lain, Sari menunjukkan alert lain yang memakai metode anomaly: "volume unduhan `JKT-FS01` malam ini lima kali rata-rata 30 hari"; yang ternyata adalah jadwal backup bulanan yang tidak tercakup masa pengamatan, contoh false positive anomaly yang sama persis dengan yang digambarkan NIST.

**Beda dengan "deteksi berbasis perilaku" di endpoint:** di dunia endpoint (EDR, Day 06), "perilaku" biasanya berarti rangkaian aksi program di dalam perangkat. Di IDS jaringan, anomaly berarti penyimpangan dari profil lalu lintas. Konsepnya mirip, bahan yang diamati berbeda.

Kenapa ini penting untuk security: metode deteksi menentukan cara memeriksa alert. Alert signature diperiksa dengan bertanya "apakah isi yang cocok itu memang serangan, dan apakah sampai ke tujuan". Alert anomaly diperiksa dengan bertanya "apa yang berubah, dan apakah ada alasan bisnis". Mengetahui titik buta tiap metode juga menjelaskan kenapa tidak ada satu alat yang cukup.

### 1.5 Jenis berdasarkan lokasi: NIDS, HIDS, NIPS, HIPS, WIPS

Pertanyaan keempat Sari membandingkan `jkt-ids01` dengan Wazuh `jkt-wazuh01`, sistem yang mengawasi server Linux PT JAB yang belum dipasangi EDR. Bedanya ada pada tempat alat itu melihat.

**Apa itu:** IDPS dikelompokkan menurut apa yang diamatinya dan di mana dipasang. NIST SP 800-94 membahas empat kelas: network-based (mengamati lalu lintas jaringan pada segmen tertentu), wireless (mengamati lalu lintas nirkabel dan protokol Wi-Fi itu sendiri), network behavior analysis atau NBA (mengamati pola aliran lalu lintas untuk menemukan banjir lalu lintas, sebagian malware, dan pelanggaran kebijakan), dan host-based (mengamati satu perangkat dan kejadian di dalamnya) [S1]. Singkatan di lapangan menggabungkan lokasi dan fungsi: NIDS dan NIPS untuk jaringan, HIDS dan HIPS untuk host, WIDS dan WIPS untuk nirkabel.

**Analogi:** NIDS seperti CCTV di lorong yang melihat siapa saja yang lewat, tetapi tidak tahu apa yang terjadi di dalam ruangan. HIDS seperti sensor yang dipasang di dalam ruangan dan di pintu brankas: tahu persis laci mana yang dibuka, tetapi hanya di ruangan itu. WIPS seperti petugas yang berkeliling membawa alat pendeteksi pemancar radio liar. Batasnya: di jaringan, satu "ruangan" (server) bisa berbicara dengan ribuan pihak sekaligus, dan lalu lintas terenkripsi di lorong tetap tidak terbaca CCTV.

**Cara kerja:** tabel berikut memetakan jenis, tempat, bahan yang diamati, dan contohnya; perhatikan kolom "Tidak melihat" untuk tahu kapan harus beralih ke sumber lain.

| Jenis | Dipasang di | Mengamati | Tidak melihat | Contoh alat |
|---|---|---|---|---|
| NIDS | Sensor di segmen jaringan, biasanya dari SPAN atau TAP | Paket dan isi protokol yang tidak terenkripsi | Isi lalu lintas terenkripsi; kejadian di dalam host [S1] | Suricata dan Snort dalam mode deteksi [S14][S18] |
| NIPS | Sensor inline di jalur | Sama dengan NIDS, lalu bisa membuang paket | Sama dengan NIDS | Suricata mode IPS, Snort, fitur IPS di NGFW [S15][S18][S9] |
| HIDS | Agen di server atau laptop | Log sistem, perubahan file, proses, konfigurasi [S1] | Lalu lintas ke perangkat lain; host tanpa agen | OSSEC, Wazuh [S20][S19] |
| HIPS | Agen di host yang bisa bertindak | Sama dengan HIDS, lalu memblokir aksi atau alamat | Sama dengan HIDS | Fitur active response di OSSEC atau Wazuh [S20][S19] |
| WIDS / WIPS | Sensor nirkabel di area kantor | Protokol Wi-Fi 802.11: access point liar, perangkat tak dikenal, enkripsi lemah [S1] | Alamat IP dan isi aplikasi; NIST menyebut wireless IDPS tidak memeriksa lapisan di atas protokol nirkabel [S1] | Fitur WIPS di sistem Wi-Fi kantor |
| NBA | Sensor yang membaca ringkasan aliran lalu lintas | Pola volume dan arah aliran [S1] | Isi paket | Fitur analisis aliran di perangkat jaringan |

Beberapa alat sering disebut "IDS" padahal fungsinya lain. Tabel kecil berikut meluruskan tiga yang paling sering tertukar; cari kolom "Lebih tepat disebut".

| Alat | Sering disebut | Lebih tepat disebut | Alasan |
|---|---|---|---|
| Zeek | IDS seperti Snort | Network security monitor (penganalisis lalu lintas pasif) | Zeek menyebut dirinya bukan IDS klasik berbasis signature; keluarannya adalah log aktivitas jaringan seperti log sambungan, HTTP, DNS, dan sertifikat TLS [S17] |
| Tripwire | HIDS | Alat FIM (file integrity monitoring) dan pemantauan konfigurasi | Tripwire Enterprise dipasarkan sebagai pemantauan integritas file dan konfigurasi [S21]; FIM adalah salah satu teknik HIDS, bukan HIDS lengkap [S1] |
| CrowdStrike Falcon | HIPS | EDR (endpoint detection and response) | Vendornya menyebutnya platform EDR dan XDR [S22]; EDR dibahas di Day 06 |

**Contoh di PT JAB:** `jkt-ids01` adalah NIDS. Ia melihat semua lalu lintas yang disalin dari core switch data center, termasuk lalu lintas polos antara `jkt-waf01` dan `jkt-portal01`, tetapi tidak tahu apa yang terjadi di dalam `jkt-portal01`. Wazuh `jkt-wazuh01` menerima kiriman dari agen yang dipasang di server Linux, misalnya server SFTP `jkt-sftp01`; ia tahu berapa kali login SSH gagal di server itu dan file konfigurasi mana yang berubah, tetapi tidak melihat lalu lintas server lain. Untuk server Windows dan laptop, PT JAB memakai EDR Microsoft Defender for Endpoint, yang dibahas di Day 06.

**Beda HIDS dengan antivirus:** antivirus fokus pada file dan program jahat; HIDS lebih luas: log, perubahan file, konfigurasi, dan aktivitas user. Batasnya makin kabur di produk modern, yang menggabungkan keduanya.

Kenapa ini penting untuk security: setiap jenis menutup titik buta jenis lain. NIDS buta terhadap HTTPS yang tidak dibuka; HIDS melihat apa yang terjadi setelah enkripsi dibuka di server. NIST sendiri menyarankan memakai IDPS berbasis host untuk melihat aktivitas di dalam perangkat bila lalu lintas jaringannya terenkripsi [S1]. Saat menelusuri alert, kamu bergerak dari satu jenis ke jenis lain.

### 1.6 Inline vs out-of-band (SPAN dan TAP)

Pertanyaan kelima Sari: kenapa `jkt-ids01` dipasang di SPAN, bukan di tengah jalur? Posisi inilah yang membedakan IDS dari IPS, walaupun mesinnya sama.

**Apa itu:** sensor inline dipasang sehingga lalu lintas yang diamatinya harus melewati sensor itu, seperti lalu lintas yang melewati firewall [S1]. Sensor out-of-band, yang NIST sebut passive, mengamati salinan lalu lintas; tidak ada lalu lintas sungguhan yang melewati sensor [S1]. Salinan itu diambil lewat SPAN port (port di switch yang menerima salinan lalu lintas port lain; NIST menyebutnya spanning port), lewat network TAP (alat yang dipasang langsung di kabel untuk menyalin semua yang lewat), atau lewat IDS load balancer yang menggabungkan dan membagi salinan ke beberapa sensor [S1].

**Analogi:** sensor inline seperti satpam yang berdiri di ambang pintu: semua tamu harus melewatinya, jadi ia bisa menghadang, tetapi bila ia lambat, antrean memanjang, dan bila ia pingsan di ambang pintu, pintu tertutup. Sensor out-of-band seperti petugas di ruang monitor yang menonton salinan rekaman CCTV: tidak mengganggu antrean sama sekali, tetapi hanya bisa menelepon satpam, tidak bisa menghadang sendiri. SPAN seperti layar CCTV bersama di ruang switch: murah karena sudah ada, tetapi saat gedung sangat ramai sebagian gambar bisa hilang. TAP seperti kamera khusus yang dipasang langsung di pintu: gambarnya lengkap, tetapi harus dibeli dan pemasangannya sempat menutup pintu sebentar.

**Cara kerja:**

```
INLINE (IPS)                                   OUT-OF-BAND (IDS)

 internet                                       internet
    |                                              |
 [firewall]                                     [firewall]
    |                                              |
 [ sensor ] <- semua paket lewat sini           [ switch ] ----SPAN/TAP (salinan)----> [ sensor ]
    |          bisa drop, bisa menambah            |                                   hanya bisa alert,
 [server]      latensi, bisa jadi titik gagal   [server]                               RST, atau minta firewall blokir
```

NIST mencatat kelebihan dan kekurangan masing-masing cara mengambil salinan. SPAN murah dan sudah ada di banyak switch, tetapi bisa tidak melihat semua lalu lintas bila switch salah dikonfigurasi atau sedang sangat sibuk, dan banyak switch hanya punya satu SPAN untuk diperebutkan banyak alat [S1]. TAP memberi salinan semua lalu lintas di kabel, tetapi harus dibeli terpisah dan pemasangannya biasanya butuh sedikit waktu henti jaringan [S1]. Untuk sensor inline, NIST mengingatkan risiko lain: saat beban tinggi, sensor yang membuang paket mengganggu availability dan menambah latensi (jeda) [S1]. Kesimpulan NIST sederhana: pasang inline bila memang akan memakai pencegahan, pasang passive bila tidak [S1].

**Contoh di PT JAB:** `jkt-ids01` menerima salinan dari SPAN core switch data center, termasuk segmen DMZ. Tim Infrastruktur (Lead: Agung Prabowo) memilih posisi ini karena tiga alasan. Satu, salah blokir di depan portal pelanggan berdampak langsung ke 400 ribu pelanggan. Dua, aturan Suricata di PT JAB masih dalam tahap tuning. Tiga, `jkt-fw01` sudah menjalankan fitur IPS untuk lalu lintas yang bisa dibacanya, dan WAF sudah menghadang serangan web. Posisi SPAN juga menjelaskan kenapa sensor bisa membaca isi permintaan: ia melihat ruas `jkt-waf01` ke `jkt-portal01`, tempat lalu lintas sudah dibuka enkripsinya oleh WAF dan dikirim sebagai HTTP polos di port 8080. Di ruas luar (internet ke `jkt-waf01`), sensor yang sama hanya melihat sambungan TLS tanpa isi.

**Beda SPAN dengan TAP:** perbandingan lengkapnya ada di bagian 3.4.

**Salah paham umum:**
- "IDS di SPAN melihat semuanya." SPAN bisa kehilangan paket saat switch sibuk, dan NIDS di mana pun tidak bisa membaca isi lalu lintas terenkripsi, termasuk VPN, HTTPS, dan SSH [S1]. Itulah kenapa NIST menyarankan sensor ditempatkan di titik yang lalu lintasnya sudah tidak terenkripsi, misalnya setelah VPN gateway atau setelah perangkat yang membuka TLS [S1].

Kenapa ini penting untuk security: posisi sensor menentukan apa yang bisa kamu simpulkan dari alert-nya. Alert dari sensor out-of-band tidak pernah berarti "sudah dihentikan". Alert dari sensor yang hanya melihat ruas terenkripsi juga tidak akan pernah memuat isi URL. Sebelum menyimpulkan, cari tahu sensor itu duduk di mana.

### 1.7 Fail-open vs fail-closed

Pertanyaan keenam Sari bersifat "seandainya": bila `jkt-ids01` suatu hari dipasang inline sebagai IPS di depan portal, lalu hang, apakah portal ikut mati?

**Apa itu:** fail-open berarti saat alat keamanan gagal, lalu lintas tetap dibiarkan lewat tanpa diperiksa; layanan tetap jalan, perlindungan hilang. Fail-closed berarti saat alat gagal, lalu lintas dihentikan; perlindungan tetap ada, layanan berhenti. Glosarium NIST memakai istilah yang berdekatan: fail secure adalah mode berhenti yang mencegah hilangnya keadaan aman saat terjadi kegagalan, sedangkan fail safe adalah mode berhenti yang mencegah kerusakan pada sumber daya, walaupun bisa berujung pada keamanan yang terkompromi [S8]. Di percakapan sehari-hari jaringan, fail-closed dekat dengan fail secure, dan fail-open dekat dengan fail safe.

**Analogi:** pintu darurat gedung dirancang terbuka otomatis saat listrik mati supaya orang bisa keluar (fail-open, mengutamakan keselamatan dan kelancaran). Pintu brankas dirancang tetap terkunci saat listrik mati (fail-closed, mengutamakan isi brankas). Batasnya: di jaringan, keputusan ini bisa diatur per perangkat bahkan per jenis kejadian, bukan satu pilihan untuk seluruh gedung.

**Cara kerja:** dokumentasi Suricata memberi contoh konkret. Bila Suricata dipasang inline di Linux lewat NFQUEUE (antrean paket yang diserahkan ke Suricata untuk diperiksa), bawaannya paket dibuang bila tidak ada program yang membaca antrean itu; dokumentasi mengingatkan bahwa menghentikan Suricata tanpa membersihkan aturan membuat lalu lintas internet tidak lewat. Itu fail-closed. Opsi `bypass` mengubahnya: paket diterima bila tidak ada program yang membaca, sehingga jaringan tetap jalan, tetapi fungsi blokir hilang. Itu fail-open [S15]. Di dalam mesinnya sendiri, Suricata punya exception policy untuk kondisi seperti memori penuh atau kesalahan parser; dalam mode IPS, bawaan sebagian besar kondisi itu adalah fail close, sedangkan dalam mode IDS kondisi itu diabaikan [S16]. Perangkat IPS komersial sering memakai bypass hardware yang otomatis menyambungkan kabel bila perangkat mati; cek perilaku persisnya di dokumentasi produk yang kamu pakai.

Tabel berikut membantu memilih; cari kolom "Cocok untuk".

| Pilihan | Saat alat gagal | Yang dikorbankan | Cocok untuk |
|---|---|---|---|
| Fail-open | Lalu lintas lewat tanpa diperiksa | Confidentiality dan integrity selama alat mati | Layanan yang ketersediaannya paling penting, dengan lapisan perlindungan lain di belakangnya |
| Fail-closed | Lalu lintas berhenti | Availability | Segmen sangat sensitif yang lebih baik berhenti daripada terbuka tanpa penjagaan |

**Contoh di PT JAB:** saat membahas rencana memindahkan Suricata ke mode inline, Agung Prabowo dan Dimas Prasetyo (SOC lead) menyepakati: untuk jalur ke portal pelanggan, IPS harus fail-open, karena portal punya lapisan lain (WAF, aplikasi yang menolak SQL injection) dan portal mati berarti pelanggan tidak bisa membayar. Untuk jalur ke segmen server pembayaran internal, IPS fail-closed, karena lebih baik transaksi tertunda daripada segmen itu terbuka tanpa penjagaan. Apa pun pilihannya, kegagalan sensor harus memicu alert ke SOC dan NOC.

**Beda dengan high availability:** fail-open dan fail-closed menjawab "apa yang terjadi bila alat ini mati". High availability (dua perangkat, satu cadangan) mencoba supaya alat tidak benar-benar mati. Keduanya sering dipakai bersama.

Kenapa ini penting untuk security: penyerang yang tahu sebuah IPS fail-open punya alasan untuk membuatnya kewalahan. NIST mencatat sensor bisa diserang dengan lalu lintas besar atau lalu lintas yang sengaja memicu banyak alert (blinding) supaya gagal atau supaya alert serangan sesungguhnya tenggelam [S1]. Alert "sensor down" atau "bypass aktif" harus diperlakukan sebagai kejadian keamanan, tidak hanya urusan perawatan.

### 1.8 WAF (web application firewall)

Pertanyaan ketujuh Sari dimulai dari WAF: kenapa namanya firewall, padahal kerjanya berbeda dari `jkt-fw01`, dan kenapa ia bisa kelewatan tiga permintaan?

**Apa itu:** WAF adalah firewall aplikasi untuk aplikasi HTTP: ia menerapkan seperangkat aturan pada percakapan HTTP antara browser dan server web, dan aturannya biasanya menargetkan serangan web umum seperti XSS dan SQL injection [S10]. NIST menyebut WAF sebagai application firewall khusus yang berada di depan server web [S3]. Kumpulan aturan yang paling dikenal untuk WAF open source adalah OWASP CRS (Core Rule Set), aturan deteksi serangan generik untuk ModSecurity dan WAF yang kompatibel, yang mencakup SQL injection, XSS, file inclusion, dan pemindaian bot [S11].

**Analogi:** petugas di loket pelayanan yang memeriksa isi formulir sebelum diteruskan ke petugas di dalam: formulir yang kolom "nama"-nya berisi perintah aneh dikembalikan. Penjaga gerbang (firewall) hanya melihat bahwa tamu datang ke loket yang benar; petugas loket (WAF) membaca isi formulirnya. Batasnya: petugas loket hanya mengurus formulir untuk loket web, dan bisa salah menolak formulir sah yang kebetulan mirip pola berbahaya.

**Cara kerja:** WAF biasanya dipasang sebagai reverse proxy (bagian 1.9) di depan aplikasi [S10]. Browser pelanggan sebenarnya tersambung ke WAF; WAF membuka enkripsi TLS karena sertifikat situs dipasang di WAF, membaca permintaan HTTP lengkap (metode, path, parameter, header, isi form), mencocokkannya dengan aturan, lalu meneruskan yang lolos ke server aplikasi dan menolak yang tidak (biasanya dengan kode `403 Forbidden`). OWASP mengingatkan bahwa menyesuaikan WAF dengan aplikasi butuh usaha besar dan harus dirawat setiap kali aplikasi berubah [S10].

```
browser pelanggan --HTTPS--> [ jkt-waf01 ] --HTTP 8080--> [ jkt-portal01 ]
                             - buka TLS (sertifikat portal ada di sini)
                             - baca: GET /tagihan?id=...
                             - cocokkan aturan: pola SQL injection?
                               ya  -> 403, catat di log WAF
                               tidak -> teruskan, tambah header X-Forwarded-For: <IP asli>
```

**Contoh di PT JAB:** dari 64 permintaan `192.0.2.101`, 61 cocok dengan aturan SQL injection di `jkt-waf01` dan ditolak dengan `403`. Tiga lolos karena memakai penyamaran yang belum dikenali aturan WAF versi terpasang. Ketiganya sampai ke `jkt-portal01`, dan portal menolaknya dengan `400 Bad Request` karena parameter `id` divalidasi sebagai angka dan query database disusun dengan prepared statement (query yang memisahkan perintah SQL dari isian user). OWASP menempatkan prepared statement sebagai pertahanan utama terhadap SQL injection, bukan WAF [S13]. Tindak lanjutnya: tim aplikasi memperbarui aturan WAF supaya mengenali varian itu, dan SOC memastikan tidak ada respons `200` ke `192.0.2.101` di log portal.

**Beda dengan firewall jaringan:** firewall memutuskan berdasarkan alamat dan port (lapisan 3 dan 4) untuk semua jenis lalu lintas; WAF memutuskan berdasarkan isi permintaan HTTP (lapisan 7) dan hanya untuk aplikasi web. Firewall melindungi jaringan; WAF melindungi aplikasi. OWASP juga membedakan WAF dari proxy biasa: proxy umumnya melindungi klien, WAF melindungi server [S10].

**Salah paham umum:**
- "Aplikasi sudah di belakang WAF, jadi tidak perlu diperbaiki." WAF adalah lapisan tambahan yang bisa dilewati dengan varian baru, seperti tiga permintaan di `SOC-2027-0820`. Perbaikan di kode aplikasi (prepared statement, validasi input) tetap pertahanan utama [S13].

Kenapa ini penting untuk security: log WAF adalah sumber terbaik untuk melihat serangan web karena WAF membaca isi yang sudah didekripsi. Saat alert serangan web muncul, pertanyaan pertama analyst adalah "berapa yang diblok WAF, berapa yang lolos, dan apa jawaban server untuk yang lolos".

### 1.9 Proxy: forward vs reverse, dan TLS inspection

Pertanyaan ketujuh Sari punya bagian kedua (kenapa IP penyerang tidak ada di kolom sumber log portal), dan pertanyaan kedelapan menyangkut proxy kantor yang membuka HTTPS. Keduanya dijawab oleh konsep proxy.

**Apa itu:** proxy adalah perantara yang menerima permintaan klien lalu membuat permintaan sendiri ke tujuan atas nama klien itu, sehingga sambungan langsung antara klien dan server terputus [S7]. Forward proxy melayani klien: karyawan di dalam keluar ke internet lewat proxy. Reverse proxy melayani server: tamu dari internet masuk ke proxy, dan proxy yang menghubungi server di belakangnya [S23]. TLS inspection (disebut juga HTTPS inspection atau break and inspect) adalah proses membuka enkripsi lalu lintas, memeriksanya, lalu mengenkripsinya ulang [S25].

**Analogi:** forward proxy seperti kurir kantor yang membelikan barang untuk karyawan: karyawan tidak keluar sendiri, toko hanya melihat kurir kantor. Reverse proxy seperti resepsionis yang menerima semua tamu atas nama ruangan di dalam: tamu tidak pernah tahu nomor ruangan, dan ruangan hanya tahu "tamu ini diantar resepsionis". TLS inspection seperti petugas surat kantor yang, dengan persetujuan karyawan, boleh membuka amplop surat masuk, memeriksa isinya, lalu menyegel ulang dengan segel kantor. Batasnya: karyawan hanya bisa melihat segel kantor, bukan segel asli pengirim, jadi ia harus percaya bahwa petugas surat sudah memeriksa keaslian pengirim dengan benar.

**Cara kerja:** proxy membuat dua sambungan terpisah: klien ke proxy, dan proxy ke tujuan [S3]. Akibatnya, pihak di ujung kedua hanya melihat alamat proxy. Untuk tetap menyampaikan alamat asli, proxy web menambahkan header seperti `X-Forwarded-For` (standar de facto) atau `Forwarded` (standar resmi) berisi alamat klien asli [S23].

Untuk TLS inspection di forward proxy, organisasi memasang sertifikat akar milik proxy di semua laptop kantor, sehingga browser menerima sertifikat yang dibuat proxy untuk situs tujuan. Proxy lalu bertindak sebagai perantara di tengah: satu sambungan TLS ke laptop, satu lagi ke situs aslinya [S24]. CISA mencatat risikonya: laptop hanya bisa memverifikasi sambungannya ke proxy, bukan ke server asli, dan banyak produk tidak memeriksa rantai sertifikat server dengan benar, sehingga justru membuka peluang penyadapan. CISA menganjurkan organisasi memastikan produknya memvalidasi sertifikat dan meneruskan kesalahan ke pengguna [S24]. NSA juga menyarankan inspeksi dilakukan sekali saja di dalam organisasi, bukan berlapis-lapis [S25]. Sertifikat dan rantai kepercayaan dibahas di Day 05.

**Contoh di PT JAB:** dua sisi proxy terlihat di Day ini. Pertama, reverse proxy: `jkt-waf01` menerima sambungan pelanggan, lalu membuat sambungan baru ke `jkt-portal01` dari alamatnya sendiri `10.20.60.10`. Karena itu kolom sumber di log portal selalu `10.20.60.10`, dan IP asli `192.0.2.101` hanya ada di header `X-Forwarded-For`. Itulah jawaban bagian kedua pertanyaan ketujuh. Kedua, forward proxy: semua laptop kantor keluar ke web lewat `jkt-proxy01`. Proxy ini adalah "alat yang memang diizinkan membuka enkripsi" yang disebut di Day 02. Kebijakannya, `jkt-proxy01` hanya membuka TLS untuk situs yang belum terkategori atau baru terdaftar, tempat favorit penyebar malware dan phishing; kategori perbankan dan kesehatan sengaja tidak dibuka demi privasi karyawan. Kebijakan dekripsi itu disetujui manajemen dan diumumkan ke karyawan. Contoh lognya ada di bagian 2.3.

**Beda forward dengan reverse proxy:** forward proxy dipasang dan dikendalikan oleh organisasi pemilik klien; reverse proxy dipasang oleh pemilik server. Perbandingan lengkapnya ada di bagian 3.3.

**Salah paham umum:**
- "IP di kolom sumber log server web selalu IP pengunjung." Bila ada reverse proxy, WAF, load balancer, atau CDN di depan server, kolom sumber berisi alamat perantara. IP asli ada di `X-Forwarded-For`, dan header itu bisa diisi palsu oleh pengirim bila perantara tidak menimpanya; percaya hanya pada nilai yang ditulis perantara milikmu sendiri.

Kenapa ini penting untuk security: proxy menentukan di log mana identitas asli berada. Forward proxy dengan TLS inspection adalah salah satu dari sedikit tempat di jaringan yang bisa melihat URL lengkap lalu lintas HTTPS karyawan, sehingga lognya sangat berharga saat menyelidiki phishing atau unduhan malware. Sebaliknya, proxy itu sendiri menjadi sasaran bernilai tinggi karena memegang lalu lintas yang sudah terbuka.

### 1.10 DMZ

Pertanyaan kesembilan Sari: kenapa portal ditaruh di DMZ dan tidak bisa langsung menghubungi server AD (Active Directory, sistem pusat akun dan login karyawan, Day 07)?

**Apa itu:** DMZ (demilitarized zone) adalah segmen jaringan perimeter di antara jaringan internal dan eksternal, tempat server yang memang harus dijangkau dari luar ditaruh, supaya pihak luar mendapat akses terbatas ke informasi yang boleh dibuka sementara jaringan internal tetap terlindung [S5]. NIST SP 800-41 mendefinisikannya dari sudut pandang firewall: sebuah antarmuka firewall yang mirip antarmuka sisi dalam, tetapi lalu lintas antara DMZ dan jaringan dalam tetap melewati firewall dan bisa dikenai aturan [S3]. Server web dan email publik lazim diletakkan di DMZ [S3].

**Analogi:** ruang tamu atau loket pelayanan di depan kantor. Orang luar boleh masuk sampai ruang itu untuk urusan yang memang dilayani, tetapi pintu dari ruang tamu ke ruang kerja tetap dijaga, dan petugas loket pun tidak bebas masuk ke ruang arsip. Batasnya: bila petugas loket berhasil disuap (server DMZ diambil alih), penyerang sudah berada di dalam gedung, jadi aturan pintu antara ruang tamu dan ruang kerja harus benar-benar ketat.

**Cara kerja:** firewall punya minimal tiga sisi: luar (internet), DMZ, dan dalam. Aturan disusun untuk tiga arah: dari internet ke DMZ hanya layanan publik (misalnya HTTPS ke portal); dari DMZ ke dalam hanya sambungan yang benar-benar dibutuhkan aplikasi (misalnya portal ke database pelanggan di satu port); dari internet langsung ke dalam ditolak.

```
internet --(hanya 443 ke 203.0.113.8)--> [ jkt-fw01 ] --> DMZ: jkt-waf01, jkt-portal01
                                              |
                                              +-- DMZ -> dalam: hanya jkt-portal01 -> DB pelanggan port DB
                                              +-- DMZ -> dalam: AD, file server, laptop kantor = DITOLAK
                                              +-- internet -> dalam = DITOLAK
```

**Contoh di PT JAB:** `jkt-waf01` dan `jkt-portal01` berada di DMZ `10.20.60.0/24`. Portal hanya boleh menghubungi database pelanggan pada satu port, dan tidak boleh menghubungi `JKT-DC01` (domain controller AD) atau file server `JKT-FS01`. Aturan ini lahir dari pengalaman: pada insiden ransomware `INC-2026-017` Oktober 2026, penyerang masuk lewat server aplikasi lama `jkt-dmz-app01`, lalu bergerak ke share Keuangan. Seandainya SQL injection ke portal berhasil sekalipun, penyerang masih harus melewati firewall sekali lagi untuk menyentuh jaringan dalam.

**Beda dengan segmentasi:** DMZ adalah satu bentuk khusus segmentasi, yaitu zona untuk server yang menghadap publik. Segmentasi (bagian 1.11) adalah prinsip umumnya: membagi seluruh jaringan menjadi zona.

**Salah paham umum:**
- "Server di DMZ aman karena berada di zona khusus." DMZ justru zona yang paling sering diserang karena terbuka ke internet. Gunanya adalah membatasi kerusakan bila server di sana jebol, bukan membuat server itu kebal.

Kenapa ini penting untuk security: lalu lintas dari server DMZ ke jaringan dalam yang tidak biasa (misalnya portal mencoba menghubungi domain controller) adalah tanda bahaya yang kuat, karena di desain yang benar lalu lintas itu seharusnya tidak pernah ada.

### 1.11 Segmentasi jaringan

Bagian kedua pertanyaan kesembilan meluas ke seluruh jaringan: kenapa laptop kantor, server data center, dan perangkat jaringan dipisah-pisah?

**Apa itu:** segmentasi jaringan adalah membagi jaringan menjadi beberapa zona dan memasang aturan di antara zona, sehingga perangkat hanya bisa menghubungi zona lain lewat jalur yang diizinkan. Cara klasiknya memakai subnet, VLAN (jaringan lokal virtual yang memisahkan perangkat di switch yang sama), dan firewall internal. Microsegmentation adalah versi yang lebih halus: satu sumber daya atau kelompok kecil sumber daya dilindungi gerbangnya sendiri, misalnya NGFW, perangkat gerbang khusus, atau agen di host [S28]. CISA menyebut microsegmentation komponen penting zero trust yang mengecilkan attack surface dan membatasi lateral movement, yaitu perpindahan penyerang dari satu perangkat ke perangkat lain di dalam jaringan [S29]. Zero trust (Day 01 bagian 1.8) adalah prinsip bahwa tidak ada akses yang dipercaya hanya karena lokasinya di jaringan.

**Analogi:** gedung yang dibagi zona dengan pintu sekat kebakaran. Glosarium NIST bahkan menjelaskan asal nama firewall dari pemisahan jaringan supaya kerusakan tidak menjalar antar subnet, seperti dinding api [S4]. Kebakaran di satu lantai tidak otomatis menghabiskan seluruh gedung. Batasnya: pintu sekat yang selalu diganjal terbuka (aturan "izinkan semua antar zona") tidak berguna, dan di jaringan, ganjalan seperti itu sering tidak terlihat sampai ada yang memeriksa.

**Cara kerja:** NIST SP 800-207 mencatat kelemahan model lama yang hanya menjaga perimeter: begitu penyerang melewati perimeter, lateral movement berikutnya tidak terhalang [S28]. Segmentasi menambah pemeriksaan di dalam. Lalu lintas antar zona di dalam jaringan sering disebut east-west, sedangkan lalu lintas keluar-masuk organisasi disebut north-south. NIST juga mencatat bahwa microsegmentation sebenarnya bisa dibuat dengan firewall stateless sederhana, tetapi biaya administrasi dan sulitnya beradaptasi membuatnya pilihan yang buruk [S28].

**Contoh di PT JAB:** kantor Jakarta (`10.10.0.0/16`), data center (`10.20.0.0/16`), dan kantor Bandung (`10.30.0.0/16`) adalah zona besar. Di dalam data center ada zona lebih kecil: DMZ `10.20.60.0/24`, zona server AD, zona database, dan zona manajemen perangkat jaringan. Laptop kantor tidak bisa langsung membuka RDP ke server; admin harus lewat jump host `JKT-JUMP01` (server perantara khusus admin). Bila sebuah laptop terinfeksi, segmentasi membatasi apa yang bisa dijangkau malware dari laptop itu.

**Beda dengan DMZ:** lihat bagian 1.10. Semua DMZ adalah segmentasi, tetapi tidak semua segmentasi adalah DMZ.

Kenapa ini penting untuk security: alert lateral movement (misalnya satu laptop mencoba login ke puluhan server, atau pemindaian port dari dalam) jauh lebih mudah dibaca bila segmentasinya jelas, karena kamu tahu lalu lintas mana yang seharusnya tidak pernah ada. NIST juga mencatat bahwa deteksi pengintaian lebih berguna di jaringan internal yang terlindung, karena di internet pengintaian terjadi terus-menerus [S1].

### 1.12 VPN

Pertanyaan kesepuluh Sari dimulai dari karyawan yang bekerja dari rumah. Mereka tidak tersambung ke jaringan kantor secara fisik, tetapi bisa membuka aplikasi internal.

**Apa itu:** VPN (virtual private network) adalah jaringan virtual yang dibangun di atas jaringan fisik yang sudah ada, untuk membawa data dengan aman antar jaringan atau antar perangkat [S6]. VPN memakai protokol tambahan untuk mengenkripsi lalu lintas, mengautentikasi user, dan memeriksa keutuhan data; dua pilihan umum adalah IPsec dan SSL/TLS [S3]. NIST membedakan dua arsitektur: gateway-to-gateway (menyambungkan kantor cabang ke kantor pusat lewat internet; user tidak perlu melakukan apa-apa) dan host-to-gateway atau remote access (laptop user menyambung ke VPN gateway organisasi) [S3]. Panduan NIST untuk IPsec VPN adalah SP 800-77 Rev. 1 [S26].

**Analogi:** lorong tertutup dari rumah ke kantor yang melewati jalan umum. Orang di jalan tahu ada lorong, tetapi tidak bisa melihat siapa yang lewat di dalamnya dan apa yang dibawa. Batasnya: lorong tidak memeriksa apakah orang yang masuk dari ujung rumah membawa barang berbahaya. Laptop yang terinfeksi di rumah ikut membawa infeksinya lewat lorong yang sama.

**Cara kerja:** laptop menjalankan aplikasi VPN, mengautentikasi user ke VPN gateway (biasanya lewat RADIUS atau LDAP, yaitu layanan direktori untuk mencari data user dan grup) [S3], lalu membangun terowongan terenkripsi. Laptop mendapat alamat dari rentang internal, dan aturan VPN menentukan user atau grup mana boleh ke sumber daya mana [S3]. NIST mencatat dua konsekuensi bagi kontrol lain: firewall tidak bisa memeriksa lalu lintas VPN yang masih terenkripsi, dan NIDS juga tidak bisa melihat isi VPN, sehingga sensor sebaiknya ditempatkan setelah VPN gateway membuka enkripsi [S3][S1].

**Contoh di PT JAB:** karyawan menyambung ke `jkt-vpn01` (`198.51.100.20`), login dengan akun `@jab.example` ditambah MFA (verifikasi tambahan selain password, Day 06), dan mendapat alamat dari kolam `10.10.33.200` sampai `10.10.33.250`. `jkt-vpn01` memeriksa user ke `jkt-radius01`. Grup NOC boleh ke sistem pemantauan jaringan, grup Keuangan hanya ke aplikasi keuangan. Contoh log login VPN ada di bagian 2.4.

**Beda dengan HTTPS:** HTTPS mengenkripsi satu aplikasi web; VPN mengenkripsi seluruh lalu lintas jaringan laptop ke kantor, untuk aplikasi apa pun. VPN juga beda dengan "VPN gratis" untuk menyembunyikan lokasi; yang itu sebenarnya proxy pihak ketiga yang melihat lalu lintasmu.

**Salah paham umum:**
- "Lalu lintas lewat VPN pasti aman." VPN hanya melindungi perjalanan. CISA dan NSA mencatat server VPN akses jarak jauh adalah pintu masuk ke jaringan terlindung sehingga menjadi sasaran menarik; eksploitasi terhadapnya bisa berujung pada pencurian kredensial, eksekusi kode di perangkat VPN, dan pembajakan sesi [S27].

Kenapa ini penting untuk security: login VPN adalah salah satu log paling penting di SOC, karena akun yang dicuri lalu dipakai login VPN dari luar negeri terlihat seperti karyawan yang bekerja dari rumah. Patch perangkat VPN juga harus diprioritaskan karena perangkat itu menghadap internet.

### 1.13 NAC (network access control) dan 802.1X

Bagian kedua pertanyaan kesepuluh: laptop vendor yang dicolok ke port di ruang rapat tidak mendapat jaringan kantor. Itu kerja NAC.

**Apa itu:** NAC adalah kontrol yang memeriksa perangkat dan user sebelum diberi akses jaringan, berdasarkan kredensial dan hasil pemeriksaan kesehatan perangkat, misalnya antivirus terbaru, patch sistem operasi, dan konfigurasi keamanan; perangkat yang gagal pemeriksaan kesehatan bisa diberi akses terbatas untuk perbaikan [S3]. Standar yang paling umum untuk NAC di port kabel dan Wi-Fi adalah IEEE 802.1X (port-based network access control), yang membatasi pemakaian port LAN hanya untuk perangkat yang terautentikasi dan berwenang [S30].

**Analogi:** pintu masuk kantor dengan kartu akses. Karyawan menempelkan kartu dan masuk ke area kerja; tamu tanpa kartu diarahkan ke ruang tamu dan hanya mendapat Wi-Fi tamu. Petugas bisa juga mengecek apakah karyawan memakai tanda pengenal yang masih berlaku. Batasnya: NAC memeriksa perangkat saat tersambung; perangkat yang lolos lalu terinfeksi kemudian tidak otomatis ketahuan tanpa pemeriksaan ulang.

**Cara kerja:** 802.1X punya tiga peran: supplicant (perangkat yang meminta akses), authenticator (switch atau access point yang meminta bukti), dan authentication server (biasanya server RADIUS yang memeriksa kredensial dan memberi keputusan) [S31]. Authenticator meneruskan pesan autentikasi (EAP) ke server RADIUS, lalu bertindak sesuai jawaban Access-Accept atau Access-Reject [S31]. Server RADIUS juga bisa menyuruh switch menaruh perangkat di VLAN tertentu, misalnya VLAN kantor untuk laptop terdaftar dan VLAN tamu atau karantina untuk yang lain [S31].

```
laptop (supplicant) --EAP--> switch ruang rapat (authenticator) --RADIUS--> jkt-radius01 (authentication server)
                                                                        |
                         Access-Accept + VLAN kantor   <----------------+  laptop domain, sertifikat sah
                         Access-Reject / VLAN tamu     <----------------+  perangkat tidak dikenal
```

**Contoh di PT JAB:** laptop kantor membuktikan dirinya ke `jkt-radius01` dengan sertifikat perangkat dan langsung masuk VLAN kantor. Laptop vendor yang dicolok di ruang rapat tidak punya sertifikat PT JAB, jadi `jkt-radius01` menaruhnya di VLAN tamu yang hanya bisa ke internet. Server RADIUS yang sama dipakai `jkt-vpn01` untuk memeriksa login VPN, sehingga satu tempat memutuskan siapa boleh masuk jaringan, baik dari ruang rapat maupun dari rumah.

**Beda dengan firewall:** firewall memutuskan lalu lintas mana boleh lewat setelah perangkat tersambung; NAC memutuskan apakah perangkat boleh tersambung sama sekali, dan ke zona mana.

Kenapa ini penting untuk security: tanpa NAC, siapa pun yang bisa masuk gedung dan menemukan port kosong mendapat akses yang sama dengan karyawan. Log RADIUS juga membantu investigasi: ia mencatat perangkat mana (MAC address), user mana, port switch mana, dan kapan.

## 2. Contoh nyata

Semua log, alert, dan angka di bagian ini adalah keluaran ilustrasi untuk organisasi fiktif PT JAB, bukan hasil eksekusi nyata. Formatnya disederhanakan; nama field di produk sungguhan bisa berbeda.

### 2.1 Membaca alert `SOC-2027-0820` bersama log WAF

Ini alert yang ditempel Sari di bawah diagram Ide inti. Ringkasan dari SIEM menggabungkan tiga kejadian `jkt-ids01` dalam satu alert.

```
Alert        : SOC-2027-0820  Possible SQL injection to customer portal
Waktu        : 2027-08-04 01:12:40 s.d. 01:19:05 WIB
Sensor       : jkt-ids01 (Suricata, out-of-band dari SPAN core switch DC)
Rule         : sid 9100231 rev 3 "JAB WEB SQL injection pattern in URI parameter"
Klasifikasi  : Web Application Attack, priority 1
Kejadian     : 3
Ruas         : 10.20.60.10:<ephemeral>  ->  10.20.60.21:8080   (jkt-waf01 -> jkt-portal01, HTTP)
HTTP         : GET /tagihan?id=<kata kunci SQL disisipi komentar>  Host: portal.jab.example
X-Forwarded-For : 192.0.2.101
Aksi sensor  : alert (tidak ada blokir; sensor tidak inline)
Respons server  : 400, 400, 400
```

Log WAF untuk sumber yang sama pada rentang waktu itu, diringkas:

```
jkt-waf01  2027-08-04 01:12:31 s.d. 01:19:05  client=192.0.2.101  host=portal.jab.example
  total permintaan            : 64
  ditolak (403, rule SQLi)    : 61
  diteruskan ke jkt-portal01  : 3   (status dari portal: 400, 400, 400)
  user-agent                  : sama untuk ke-64 permintaan (alat otomatis)
```

Tabel berikut membaca kedua catatan itu baris demi baris; kolom terakhir menunjuk subbagian yang menjelaskan istilahnya.

| Yang dibaca | Nilai | Artinya | Bagian |
|---|---|---|---|
| Sensor | `jkt-ids01`, out-of-band | Alat yang melapor hanya bisa melihat dan memberi alert | 1.3, 1.6 |
| Rule | signature `sid 9100231` | Deteksi berbasis pola yang dikenal | 1.4 |
| Ruas | `10.20.60.10` ke `10.20.60.21:8080` | Sensor membaca ruas setelah WAF membuka TLS; karena itu isi URL terlihat | 1.6, 1.8 |
| Sumber di header | `X-Forwarded-For: 192.0.2.101` | IP asli ada di header, bukan di kolom sumber, karena WAF adalah reverse proxy | 1.9 |
| Hitungan WAF | 64 = 61 + 3 | Sebagian besar dihadang WAF; tiga lolos dan sampai ke portal | 1.8 |
| Respons portal | `400` tiga kali | Aplikasi menolak isian; tidak ada data yang keluar | 1.8 |

**Cara membaca:** hitung dulu. 61 ditolak ditambah 3 diteruskan sama dengan 64, dan 3 yang diteruskan cocok dengan 3 kejadian di alert IDS, jadi kedua sumber konsisten. Firewall `jkt-fw01` mencatat 64 sambungan HTTPS yang diizinkan aturan `IN-PORTAL-HTTPS`; ia tidak salah, karena isi permintaan tidak terbaca di lapisan yang ia lihat (bagian 1.1 dan 1.2). WAF menghadang sebagian besar di lapisan 7. IDS menangkap varian yang lolos dari WAF karena memakai signature yang berbeda (bagian 1.4). Aplikasi menjadi lapisan terakhir dan menolak ketiganya.

**Keputusan:** tiga respons `400` dan tidak adanya respons `200` untuk `192.0.2.101` menunjukkan percobaan gagal. Sari menutup alert sebagai serangan nyata yang tidak berhasil (true positive tanpa dampak), meminta tim aplikasi memperbarui aturan WAF untuk varian penyamaran itu, dan menambahkan `192.0.2.101` ke daftar blokir sementara di `jkt-waf01` selama 7 hari. Tidak dibuka insiden karena tidak ada data yang terdampak. Bila salah satu respons portal adalah `200` dengan ukuran jauh lebih besar dari biasanya, kasus ini akan dinaikkan menjadi insiden.

**Variasi yang perlu dikenali:** bila sensor hanya memantau ruas luar (internet ke WAF), alert ini tidak akan pernah muncul karena isi HTTPS tidak terbaca; bila WAF dipasang dalam mode hanya-deteksi, ke-64 permintaan akan sampai ke portal; bila serangan memakai metode `POST`, polanya ada di isi form, bukan di URL, dan hanya alat yang membaca isi (WAF, IDS di ruas polos) yang melihatnya.

### 2.2 Empat kasus: perilaku IDS dibandingkan IPS

Setelah membedah `SOC-2027-0820`, Sari membuka tiga alert lain minggu ini dari `jkt-ids01` dan Wazuh, lalu bertanya, "Bayangkan kalau sensor ini inline dalam mode IPS. Apa yang berbeda?" Rincian keempat kasus:

- **Kasus A, brute force SSH (`SOC-2027-0821`):** Senin 2027-08-02 22:05 sampai 22:25 WIB, `192.0.2.104` mencoba login SSH ke server SFTP mitra `jkt-sftp01` (`198.51.100.41`) sebanyak 1.240 kali dalam 20 menit, rata-rata 62 percobaan per menit, semuanya gagal. `jkt-ids01` memicu aturan ambang batas "lebih dari 30 sambungan SSH baru per menit dari satu sumber". Agen Wazuh di `jkt-sftp01` mencatat kegagalan login yang sama dan menjalankan active response: memblokir `192.0.2.104` di firewall lokal server selama 10 menit, lalu mencabut blokir otomatis.
- **Kasus B, SQL injection (`SOC-2027-0820`):** seperti bagian 2.1.
- **Kasus C, port scan dari dalam (`SOC-2027-0822`):** Selasa 2027-08-03 14:02 sampai 14:09 WIB, laptop `JKT-WS-1034` (`10.10.33.57`) mengirim 2.540 SYN ke 254 alamat di `10.20.1.0/24`, masing-masing ke 10 port (254 kali 10 sama dengan 2.540). Port scan adalah pemeriksaan dari jauh port mana yang terbuka (Day 02 bagian 1.12). Ternyata laptop itu milik peserta magang yang mencoba alat pemindai tanpa izin.
- **Kasus D, false positive aplikasi internal (`SOC-2027-0823`):** setiap malam pukul 02:00 sampai 02:30 WIB, aplikasi laporan lama `jkt-report01` mengirim permintaan HTTP ke `jkt-billing01` dengan teks query SQL di parameter `q`, karena desain aplikasinya memang begitu. Signature yang sama dengan Kasus B (`sid 9100231`) memicu 186 alert per malam.

Tabel berikut membandingkan perilaku alat pada keempat kasus; baca kolom "Pelajaran" untuk inti tiap kasus.

| Kasus | Bila IDS out-of-band (kondisi sekarang) | Bila IPS inline | Pelajaran |
|---|---|---|---|
| A. Brute force SSH | Alert ke SOC; percobaan tetap sampai ke server; Wazuh di host memblokir sementara | Sambungan dari `192.0.2.104` di-drop setelah melewati ambang; percobaan berhenti lebih cepat | Kombinasi NIDS dan HIDS dengan active response sudah cukup efektif; sumber serangan ini mudah dibedakan dari lalu lintas sah |
| B. SQL injection | Alert untuk 3 yang lolos WAF; ketiganya sampai ke portal dan ditolak aplikasi | 3 permintaan di-drop sebelum sampai portal | IPS menambah lapisan, tetapi hanya untuk lalu lintas yang terbaca; tanpa WAF yang membuka TLS, IPS pun buta |
| C. Port scan dari dalam | Alert; scan selesai; analyst menelusuri laptop dan pemiliknya | Paket scan di-drop; scanner melihat semua port "difilter" | Pemblokiran tidak menjawab "kenapa laptop ini memindai"; investigasi tetap dibutuhkan |
| D. False positive aplikasi internal | 186 alert palsu per malam; waktu analyst terbuang dan alert lain bisa tenggelam | Permintaan laporan di-drop; laporan tagihan pagi gagal dibuat, berdampak ke bisnis | IPS yang belum di-tuning bisa memblokir lalu lintas sah; tuning wajib sebelum mode blokir |

**Cara membaca:** di Kasus A dan B, IPS menghentikan serangan lebih awal, tetapi lapisan lain sudah menahan dampaknya. Di Kasus C, blokir otomatis justru menghilangkan sebagian bukti tentang apa yang dicari pemindai. Di Kasus D, IPS akan menimbulkan gangguan nyata. Tindak lanjut Kasus D adalah tuning: membuat pengecualian sempit untuk `sid 9100231` hanya untuk pasangan `jkt-report01` ke `jkt-billing01` di path `/api/report`, bukan mematikan aturannya untuk semua lalu lintas, dan membuka tiket ke tim aplikasi supaya desain query di parameter URL diganti. NIST juga mencatat banyak sensor punya mode belajar atau simulasi yang menahan semua aksi blokir dan hanya mencatat "seandainya diblokir", supaya admin bisa menyetelnya dulu sebelum blokir diaktifkan [S1].

### 2.3 Membaca log forward proxy `jkt-proxy01` dengan dekripsi TLS

Kasus ini menjawab pertanyaan kedelapan Sari dengan log nyata: Rabu pagi, `jkt-proxy01` memicu alert `SOC-2027-0824` untuk laptop `JKT-WS-1031` milik Rina Marlina dari Keuangan.

```
2027-08-04T08:41:12+07:00 jkt-proxy01 user=rina.marlina@jab.example src=10.10.33.24 method=CONNECT host=berkas-tagihan.example:443 dst=192.0.2.108 category=Newly-Registered tls=decrypted
2027-08-04T08:41:13+07:00 jkt-proxy01 user=rina.marlina@jab.example src=10.10.33.24 method=GET url=https://berkas-tagihan.example/dl/Tagihan_Agustus.js status=403 action=block policy=BLOCK-SCRIPT-UNCATEGORIZED bytes=0
2027-08-04T08:52:30+07:00 jkt-proxy01 user=rina.marlina@jab.example src=10.10.33.24 method=CONNECT host=ibanking.bank-contoh.example:443 dst=192.0.2.109 category=Financial-Services tls=not-decrypted bytes_rcvd=184220
```

**Cara membaca:** baris pertama menunjukkan laptop meminta sambungan ke domain yang baru terdaftar; karena kategorinya termasuk yang dibuka, proxy melakukan TLS inspection (bagian 1.9). Baris kedua hanya mungkin ada karena dekripsi itu: proxy melihat URL lengkap, yaitu file berekstensi `.js` (skrip yang bisa dijalankan Windows bila dibuka), lalu memblokirnya sesuai kebijakan. Tanpa dekripsi, log hanya akan memuat nama situs dari SNI dan jumlah byte, seperti yang dijelaskan Day 02 bagian 1.10. Baris ketiga adalah situs perbankan: sengaja tidak dibuka, jadi yang tercatat hanya nama situs dan volume.

**Keputusan:** unduhan diblokir, jadi tidak ada file yang sampai ke laptop. Sari meminta kamu mencari email yang diterima Rina sekitar pukul 08:40 dengan tautan ke `berkas-tagihan.example`, karena pola "tagihan" dengan lampiran skrip adalah pola phishing yang pernah menimpa PT JAB pada `INC-2026-019`. Email phishing dibahas di Day 09.

**Kapan gagal:** bila laptop tidak memakai proxy (misalnya laptop pribadi lewat Wi-Fi tamu), atau bila aplikasi memakai certificate pinning (aplikasi hanya menerima sertifikat asli servernya), dekripsi tidak terjadi dan URL tidak terlihat.

### 2.4 Membaca log NAC dan VPN

Kasus terakhir menjawab pertanyaan kesepuluh Sari. Dua baris pertama dari `jkt-radius01`, dua baris terakhir dari `jkt-vpn01`.

```
2027-08-04T10:05:11+07:00 jkt-radius01 Access-Accept user=host/JKT-WS-1036.corp.jab.example mac=3c:52:82:4d:10:36 nas=sw-jkt-lt5-rapat01 port=Gi1/0/14 method=EAP-TLS vlan=KANTOR-LT5
2027-08-04T10:21:47+07:00 jkt-radius01 Access-Reject user=- mac=a4:83:e7:19:2b:c0 nas=sw-jkt-lt5-rapat01 port=Gi1/0/15 method=MAB reason=unknown-device action=vlan=GUEST

2027-08-04T19:32:05+07:00 jkt-vpn01 login=success user=bambang.hartono@jab.example src=192.0.2.105 mfa=push-approved assigned_ip=10.10.33.211 group=NOC
2027-08-04T19:34:40+07:00 jkt-vpn01 login=fail user=bambang.hartono@jab.example src=192.0.2.107 reason=mfa-denied
```

**Cara membaca:** baris pertama, laptop kantor `JKT-WS-1036` membuktikan dirinya dengan sertifikat (metode EAP-TLS) dan masuk VLAN kantor lantai 5. Baris kedua, perangkat tak dikenal di port sebelahnya tidak punya kredensial 802.1X; switch mencoba mengenalinya dari MAC address saja (MAB, MAC authentication bypass, dipakai untuk perangkat yang tidak mendukung 802.1X seperti printer), tidak ditemukan di daftar, lalu ditaruh di VLAN tamu (bagian 1.13). Itulah laptop vendor di ruang rapat. Baris ketiga, Bambang Hartono (Manajer NOC) login VPN dari rumah, menyetujui MFA, dan mendapat alamat dari kolam VPN. Baris keempat, dua menit kemudian ada percobaan login dengan akun yang sama dari alamat berbeda, dan MFA ditolak oleh Bambang sendiri.

**Keputusan:** baris keempat adalah tanda password Bambang mungkin sudah diketahui orang lain: seseorang memasukkan password yang benar dari `192.0.2.107`, dan hanya MFA yang menghentikannya. Sari meminta kamu menghubungi Bambang lewat telepon untuk konfirmasi, menyarankan reset password, dan mencatat `192.0.2.107` untuk dicek di log lain. Penilaian lebih lanjut soal akun dan MFA dibahas di Day 06.

## 3. Perbandingan istilah yang sering tertukar

### 3.1 IDS vs IPS

Tabel ini menempatkan IDS dan IPS berdampingan pada aspek yang paling sering ditanyakan; cari baris "Bila perangkat mati" dan "Risiko salah blokir" karena di situ keputusan desainnya.

| Aspek | IDS | IPS |
|---|---|---|
| Fungsi | Mendeteksi dan memberi alert [S1] | Mendeteksi, memberi alert, dan berusaha menghentikan [S1] |
| Analogi | Alarm dan CCTV | Satpam di pintu |
| Posisi umum | Out-of-band, menonton salinan dari SPAN atau TAP | Inline, di jalur lalu lintas |
| Dampak ke latensi | Tidak ada, karena tidak di jalur | Ada; beban tinggi bisa menambah jeda atau membuang paket [S1] |
| Bila perangkat mati | Lalu lintas tetap jalan; SOC kehilangan visibilitas | Bergantung desain: fail-open (lalu lintas lewat tanpa diperiksa) atau fail-closed (lalu lintas berhenti) [S15] |
| Respons | Alert; kadang RST, perintah ke firewall, atau skrip [S1] | Drop paket, putus sesi, batasi bandwidth, bersihkan isi, plus semua respons IDS [S1] |
| Akibat false positive | Waktu analyst terbuang, alert fatigue | Lalu lintas sah terblokir, berdampak ke bisnis |
| Akibat false negative | Serangan tidak terlihat | Serangan tidak terlihat dan tidak dihentikan |
| Kebutuhan tuning | Tinggi | Lebih tinggi lagi, karena salahnya langsung terasa user |

### 3.2 Firewall, NGFW, IDS/IPS, dan WAF: apa yang dilihat

Tabel kedua menjawab pertanyaan "alat ini melihat sampai lapisan berapa", yang dijanjikan Day 02 bagian 1.2. Cari baris "Melihat sampai" dan "Buta terhadap".

| Aspek | Firewall stateless | Firewall stateful | NGFW | IDS/IPS jaringan | WAF |
|---|---|---|---|---|---|
| Melihat sampai | Lapisan 3 dan 4 (alamat, port) | Lapisan 3 dan 4 plus status sambungan | Lapisan 3 sampai 7 (aplikasi, user) | Lapisan 3 sampai 7, isi paket yang terbaca | Lapisan 7, khusus HTTP |
| Dasar keputusan | Aturan per paket | Aturan dan state table | Aturan, aplikasi, user, signature IPS | Signature, anomaly, aturan kebijakan | Aturan untuk permintaan web |
| Lalu lintas yang dijaga | Semua | Semua | Semua | Semua yang dilihat sensor | Hanya web ke aplikasi yang dilindungi |
| Buta terhadap | Isi; paket palsu yang mengaku bagian sambungan | Isi permintaan | Isi terenkripsi yang tidak didekripsi | Isi terenkripsi; kejadian di dalam host | Protokol non-web; isi yang dikaburkan dengan cara baru |
| Analogi | Penjaga tanpa buku tamu | Penjaga dengan buku tamu | Penjaga yang juga membuka tas | Alarm dan CCTV / satpam di pintu | Petugas pemeriksa formulir di loket |
| Di PT JAB | ACL router perbatasan | Fungsi dasar `jkt-fw01` | `jkt-fw01` | `jkt-ids01` | `jkt-waf01` |

### 3.3 Forward proxy vs reverse proxy

Tabel ini membedakan dua arah proxy; cari baris "Di log sisi lain terlihat" karena itulah yang paling sering membingungkan saat investigasi.

| Aspek | Forward proxy | Reverse proxy |
|---|---|---|
| Melayani | Klien (karyawan) [S23] | Server (aplikasi) [S23] |
| Dipasang oleh | Organisasi pemilik klien | Organisasi pemilik server |
| Arah lalu lintas | Dari dalam ke internet | Dari internet ke dalam |
| Tujuan keamanan | Saring situs, blokir unduhan, catat URL, TLS inspection | Sembunyikan server, WAF, bagi beban, terminasi TLS |
| Di log sisi lain terlihat | Situs tujuan melihat IP proxy (atau IP NAT kantor) | Server aplikasi melihat IP proxy; IP asli di `X-Forwarded-For` [S23] |
| Analogi | Kurir kantor yang belanja untuk karyawan | Resepsionis yang menerima tamu atas nama ruangan |
| Di PT JAB | `jkt-proxy01` | `jkt-waf01` |

### 3.4 Inline vs out-of-band, SPAN vs TAP

Tabel ini merangkum posisi sensor; cari baris "Risiko" untuk tahu apa yang dikorbankan tiap pilihan.

| Aspek | Inline | Out-of-band lewat SPAN | Out-of-band lewat TAP |
|---|---|---|---|
| Lalu lintas lewat sensor | Ya | Tidak, salinan dari switch [S1] | Tidak, salinan dari kabel [S1] |
| Bisa memblokir | Ya | Tidak secara andal [S1] | Tidak secara andal [S1] |
| Kelengkapan salinan | Melihat semua yang lewat | Bisa kehilangan paket saat switch sibuk atau salah konfigurasi [S1] | Salinan lengkap dari kabel [S1] |
| Biaya dan pemasangan | Perangkat di jalur, perlu rencana gagal | Murah, sudah ada di banyak switch [S1] | Harus dibeli; pemasangan butuh waktu henti singkat [S1] |
| Risiko | Latensi, titik gagal, salah blokir | Titik buta tanpa disadari | Masalah di TAP bisa menambah waktu henti [S1] |

### 3.5 DMZ, segmentasi, VPN, dan NAC

Empat istilah ini sama-sama mengatur "siapa boleh berada di mana", tetapi menjawab pertanyaan yang berbeda; cari kolom "Pertanyaan yang dijawab".

| Istilah | Pertanyaan yang dijawab | Bekerja di | Contoh PT JAB |
|---|---|---|---|
| DMZ | Di mana server publik ditaruh supaya kerusakannya terbatas? | Desain zona di firewall | `jkt-waf01`, `jkt-portal01` di `10.20.60.0/24` |
| Segmentasi | Zona mana boleh bicara dengan zona mana? | Subnet, VLAN, firewall internal, microsegmentation | Laptop tidak bisa langsung RDP ke server |
| VPN | Bagaimana orang atau kantor di luar masuk ke jaringan dengan aman? | Terowongan terenkripsi lewat internet | `jkt-vpn01` untuk karyawan dari rumah |
| NAC | Perangkat mana boleh tersambung, dan ke zona mana? | Port switch dan Wi-Fi, 802.1X dan RADIUS | `jkt-radius01` menaruh laptop vendor di VLAN tamu |

### 3.6 Kapan memakai yang mana

Tabel terakhir menjawab pertanyaan praktis "kebutuhan seperti ini butuh alat apa"; baca kolom "Catatan" karena hampir selalu jawabannya gabungan.

| Kebutuhan | Alat utama | Catatan |
|---|---|---|
| Menutup port dan layanan yang tidak perlu diakses | Firewall (deny by default) | Dasar semua perimeter [S3] |
| Mengenali aplikasi atau user di balik lalu lintas | NGFW | Butuh TLS inspection untuk lalu lintas terenkripsi |
| Melihat serangan tanpa risiko mengganggu layanan | IDS out-of-band | Butuh tim yang membaca alert |
| Menghentikan serangan yang jelas dan sering | IPS inline | Hanya setelah tuning; tentukan fail-open atau fail-closed |
| Melindungi aplikasi web dari serangan lapisan 7 | WAF di depan aplikasi | Tidak menggantikan perbaikan kode [S13] |
| Melihat aktivitas di dalam server | HIDS atau EDR | Menutup titik buta NIDS pada lalu lintas terenkripsi [S1] |
| Mengendalikan dan mencatat web karyawan | Forward proxy | TLS inspection sesuai kebijakan privasi [S24] |
| Membatasi kerusakan bila satu server jebol | DMZ dan segmentasi | Aturan antar zona harus benar-benar ketat |
| Akses aman dari rumah | VPN dengan MFA | Patch perangkat VPN diprioritaskan [S27] |
| Mencegah perangkat asing tersambung | NAC 802.1X | Pemeriksaan ulang tetap dibutuhkan |

Untuk IPS, urutan yang aman adalah sebagai berikut, sesuai saran NIST tentang mode simulasi dan tuning [S1]:

1. Pasang mesin dalam mode IDS (out-of-band atau inline dengan blokir dimatikan).
2. Kumpulkan alert beberapa minggu; pisahkan true positive dari false positive seperti Kasus D di bagian 2.2.
3. Tuning: perbaiki atau persempit aturan yang sering salah, buat pengecualian sesempit mungkin.
4. Aktifkan blokir hanya untuk aturan yang sudah terbukti akurat, mulai dari yang paling jelas (misalnya brute force dari luar).
5. Tetapkan perilaku saat gagal (fail-open atau fail-closed) dan pastikan kegagalan sensor memicu alert.
6. Tinjau ulang aturan secara berkala, karena aplikasi dan lalu lintas berubah [S1].

Pilihan "pakai IPS saja karena tidak ada tim yang memantau 24 jam" sering terdengar. Ada benarnya, karena IPS bisa menghadang tanpa menunggu manusia, tetapi IPS tetap butuh orang yang men-tuning dan merawatnya. IPS yang tidak dirawat akan memblokir lalu lintas sah (Kasus D) atau membiarkan serangan baru lewat karena signature-nya kedaluwarsa.

## 4. Salah paham umum

Butir berikut adalah salah paham yang melintasi beberapa istilah sekaligus. Salah paham yang khusus satu istilah sudah ditulis di subbagiannya.

- **Anggapan:** satu alat yang bagus cukup untuk melindungi jaringan. **Kenyataannya:** setiap alat buta di tempat yang berbeda: firewall buta terhadap isi, NIDS buta terhadap HTTPS yang tidak dibuka, WAF buta terhadap protokol non-web, HIDS hanya melihat host yang dipasangi agen. `SOC-2027-0820` berhenti karena empat lapisan bekerja bersama (bagian 2.1). Itu wujud defense in depth dari Day 01 bagian 1.6.
- **Anggapan:** lalu lintas terenkripsi berarti aman, jadi tidak perlu diperiksa. **Kenyataannya:** serangan juga berjalan di dalam HTTPS dan VPN. Enkripsi melindungi perjalanan, bukan niat pengirim. Isinya hanya bisa diperiksa di titik yang memegang kunci: WAF untuk server sendiri, forward proxy untuk karyawan, atau host itu sendiri (bagian 1.6, 1.8, dan 1.9).
- **Anggapan:** IDS dan IPS adalah dua produk berbeda yang harus dibeli terpisah. **Kenyataannya:** keduanya sering mesin yang sama; yang membedakan adalah posisi (out-of-band atau inline) dan apakah fitur blokir dinyalakan. Suricata bisa menjadi keduanya, dan NGFW sering membawa fungsi IPS (bagian 1.2, 1.3, dan 1.6).
- **Anggapan:** semua alat yang memantau jaringan adalah IDS. **Kenyataannya:** Zeek adalah penganalisis lalu lintas yang menghasilkan log aktivitas, bukan IDS signature; Tripwire adalah alat FIM; CrowdStrike Falcon adalah EDR. Menyebut fungsi dengan tepat penting saat menulis laporan dan saat interview (bagian 1.5).
- **Anggapan:** semua yang ada di dalam perimeter boleh dipercaya. **Kenyataannya:** penyerang yang sudah lolos perimeter bergerak bebas bila jaringan tidak disegmentasi [S28]. Pemindaian dari laptop internal (Kasus C) dan login VPN dengan password curian (bagian 2.4) datang dari "dalam".
- **Anggapan:** blokir otomatis selalu lebih baik daripada alert. **Kenyataannya:** blokir yang salah berdampak langsung ke bisnis, dan blokir yang benar pun tidak menjawab pertanyaan investigasi seperti "kenapa laptop ini memindai". Blokir dan alert saling melengkapi (bagian 2.2).
- **Anggapan:** alamat IP di kolom sumber log selalu pelaku. **Kenyataannya:** NAT (Day 02 bagian 1.11), forward proxy, dan reverse proxy mengganti alamat sumber. Telusuri log perantaranya atau header `X-Forwarded-For` (bagian 1.9).

## 5. Catatan terkini

Bagian ini mencatat status dokumen acuan dan perubahan produk yang memengaruhi cara membaca materi di atas, tanpa mengubah konsepnya.

- **NIST SP 800-94 (Februari 2007)** masih menjadi panduan final NIST untuk IDPS. Draft Rev. 1 yang dirilis untuk komentar publik pada 2012 tidak pernah difinalkan dan sudah dipensiunkan; catatan NIST tertanggal 2022-07-15 menyebut NIST akan mengumumkan bila mulai menyusun panduan IDS/IPS baru [S2]. Konsep dasarnya (metode deteksi, inline vs passive, false positive) tetap berlaku, tetapi contoh produknya sudah tua.
- **NIST SP 800-41 Rev. 1 (September 2009)** masih versi terbaru panduan firewall NIST [S3]. Istilah NGFW belum dipakai di dokumen itu; kemampuan sejenis dibahas sebagai application firewall dan unified threat management (UTM).
- **OWASP CRS:** rilis terbaru 4.30.0, rilis LTS (dukungan jangka panjang) 4.25.2, dan cabang 3.3 sudah end of life [S11]. Bila WAF di lingkunganmu masih memakai CRS 3.x, cek rencana pembaruannya.
- **Suricata:** dokumentasi terkini menjelaskan exception policy yang secara bawaan fail close untuk sebagian besar kondisi dalam mode IPS [S16]. Halaman panduan IPS berpindah alamat antar versi dokumentasi; cek versi Suricata yang terpasang sebelum mengikuti panduan.
- **Snort 3** adalah generasi terkini Snort, yang dikelola Cisco dan menyebut dirinya intrusion prevention system [S18].
- **CISA (29 Juli 2025)** menerbitkan panduan microsegmentation bagian pertama dalam seri Journey to Zero Trust, dengan janji panduan teknis lanjutan [S29].
- **IEEE 802.1X-2020** adalah versi aktif standar NAC berbasis port; corrigendum 802.1X-2020/Cor 1-2026 tercatat sebagai draft yang sudah disetujui [S30].
- **Perangkat VPN** terus menjadi sasaran; CISA dan NSA menerbitkan panduan memilih dan mengeraskan VPN akses jarak jauh pada September 2021 [S27]. Cek peringatan kerentanan terbaru untuk merek VPN yang dipakai organisasimu.

## 6. Cheat sheet

```
FIREWALL          izinkan/tolak berdasarkan aturan; deny by default; lapisan 3-4
  stateless       per paket, tanpa ingatan (ACL router)
  stateful        state table; balasan hanya lolos bila cocok sambungan yang tercatat
NGFW              stateful + aplikasi + user + IPS + TLS decryption; buta pada TLS yang tidak dibuka
IDS               deteksi + alert; out-of-band; tidak menjamin serangan berhenti (alarm/CCTV)
IPS               deteksi + alert + hadang; inline; butuh tuning (satpam di pintu)
IDPS              istilah payung NIST untuk IDS dan IPS
METODE            signature (pola dikenal; buta varian/zero-day)
                  anomaly (profil normal; banyak FP)
                  policy (aturan organisasi)
                  stateful protocol analysis (urutan/argumen protokol; berat)
FP / FN           alert palsu (alert fatigue) / serangan lolos tanpa alert
LOKASI            NIDS/NIPS jaringan | HIDS/HIPS host (OSSEC, Wazuh) | WIPS Wi-Fi | NBA pola aliran
BUKAN IDS         Zeek = network security monitor | Tripwire = FIM | CrowdStrike = EDR
POSISI            inline (di jalur, bisa blokir) | out-of-band (salinan: SPAN murah, TAP lengkap)
GAGAL             fail-open = lalu lintas lewat tanpa cek | fail-closed = lalu lintas berhenti
WAF               lapisan 7 untuk HTTP; reverse proxy; buka TLS; tidak gantikan perbaikan kode
PROXY             forward = untuk klien (jkt-proxy01) | reverse = untuk server (jkt-waf01)
                  IP asli di balik reverse proxy: X-Forwarded-For
TLS INSPECTION    buka, periksa, enkripsi ulang; sertifikat akar proxy di klien; validasi sertifikat server
VPN               terowongan terenkripsi; gateway-to-gateway | host-to-gateway (remote access)
DMZ               zona server publik; DMZ ke dalam tetap lewat firewall
SEGMENTASI        zona + aturan antar zona; microsegmentation; batasi lateral movement
NAC               cek perangkat sebelum tersambung; 802.1X: supplicant, authenticator, RADIUS
URUTAN IPS        IDS dulu -> kumpulkan alert -> tuning -> blokir aturan akurat -> tetapkan fail mode -> tinjau ulang
```

## 7. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "`jkt-fw01` adalah NGFW dengan fitur IPS aktif, jadi semua SQL injection ke portal pasti terdeteksi dan diblok olehnya." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Fitur IPS di NGFW hanya bekerja pada isi yang bisa dibacanya. Lalu lintas ke portal adalah HTTPS, dan sertifikat portal dipasang di `jkt-waf01`, bukan di `jkt-fw01`, sehingga bagi `jkt-fw01` ke-64 sambungan dari `192.0.2.101` hanyalah sambungan TLS sah ke port 443 yang diizinkan aturan `IN-PORTAL-HTTPS`. Pemeriksaan isi permintaan web dilakukan oleh WAF yang membuka TLS. Lihat bagian 1.1, 1.2, dan 2.1.

</details>

**2. Skenario keputusan.** Tim Infrastruktur ingin mengubah `jkt-ids01` menjadi IPS inline di depan portal minggu depan, dengan semua aturan langsung dalam mode blokir. Saran mana yang paling tepat?

- A. Setuju, karena IPS selalu lebih aman daripada IDS.
- B. Jalankan dulu dalam mode deteksi, tuning aturan yang sering salah (misalnya aturan yang memicu 186 alert per malam dari `jkt-report01`), aktifkan blokir bertahap untuk aturan yang terbukti akurat, dan tetapkan perilaku saat gagal.
- C. Tolak, karena IDS dan IPS sama saja sehingga tidak ada gunanya.

<details><summary>Jawaban</summary>

B. IPS yang belum di-tuning bisa memblokir lalu lintas sah; aturan yang sama dengan Kasus D akan menggagalkan laporan tagihan setiap malam. NIST menyarankan mode simulasi untuk menyetel aksi pencegahan sebelum diaktifkan, dan portal juga butuh keputusan fail-open atau fail-closed. A keliru karena "lebih aman" tidak berarti apa-apa bila yang diblokir adalah lalu lintas sah dan sensor menjadi titik gagal baru. C keliru karena IPS memang menambah kemampuan menghadang; yang dipersoalkan hanya cara mengaktifkannya. Lihat bagian 1.3, 1.7, 2.2, dan 3.6.

</details>

**3. Pertanyaan jebakan.** "Kolom sumber di log `jkt-portal01` berisi `10.20.60.10` untuk semua permintaan SQL injection, jadi pelakunya server internal PT JAB." Benarkah?

<details><summary>Jawaban</summary>

Tidak. `10.20.60.10` adalah alamat `jkt-waf01`, yang bekerja sebagai reverse proxy: ia menerima sambungan pelanggan, lalu membuat sambungan baru ke portal dari alamatnya sendiri. Alamat asli pengirim, `192.0.2.101`, dibawa di header `X-Forwarded-For`, dan juga tercatat di log WAF. Lihat bagian 1.9 dan 2.1.

</details>

**4. Skenario keputusan.** PT JAB akan memasang IPS inline di dua tempat: di depan portal pelanggan (yang sudah dilindungi WAF dan aplikasinya memakai prepared statement) dan di depan segmen server pembayaran internal. Pengaturan saat gagal mana yang paling masuk akal?

- A. Keduanya fail-closed, karena keamanan selalu nomor satu.
- B. Portal fail-open, segmen pembayaran fail-closed, dan kegagalan sensor di keduanya memicu alert ke SOC dan NOC.
- C. Keduanya fail-open, dan tidak perlu alert karena lalu lintas tetap jalan.

<details><summary>Jawaban</summary>

B. Portal punya lapisan lain (WAF, aplikasi) dan ketersediaannya sangat penting bagi pelanggan, jadi fail-open masuk akal; segmen pembayaran lebih baik berhenti sebentar daripada terbuka tanpa penjagaan. A keliru karena memutus portal setiap kali sensor bermasalah mengorbankan availability padahal ada lapisan lain. C keliru karena IPS yang diam-diam fail-open tanpa alert bisa dimanfaatkan penyerang yang sengaja membuat sensor kewalahan. Lihat bagian 1.7.

</details>

**5. Jelaskan ulang.** Jelaskan kepada anggota keluargamu yang bukan orang IT, dalam tiga kalimat, apa bedanya firewall, IDS, dan IPS.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Firewall itu seperti penjaga gerbang kantor yang mengecek KTP dan alamat tujuan tamu, tapi tidak membuka isi tasnya. IDS itu seperti alarm dan CCTV: dia merekam dan berbunyi kalau ada yang mencurigakan, tapi tidak menangkap orangnya. IPS itu seperti satpam yang berdiri di pintu dan langsung menghadang orang mencurigakan, tapi kalau satpamnya belum terlatih dia bisa salah menghadang tamu yang baik-baik."

Kesalahan yang sering muncul:
- Menyebut IDS "tidak berguna karena tidak memblokir", padahal tanpa alarm tidak ada yang tahu serangan terjadi.
- Menyebut firewall "memeriksa semua isi", padahal firewall biasa hanya membaca alamat dan port.
- Lupa menyebut batas IPS: bisa salah hadang.

</details>

**6. Pertanyaan jebakan.** "Kita pakai Zeek, jadi kita sudah punya IDS signature seperti Snort. Untuk host, kita punya Tripwire sebagai HIDS lengkap." Benarkah?

<details><summary>Jawaban</summary>

Tidak tepat. Zeek adalah network security monitor yang menghasilkan log aktivitas jaringan (sambungan, HTTP, DNS, TLS), dan dokumentasinya sendiri menyebut Zeek bukan IDS klasik berbasis signature. Tripwire lebih tepat disebut alat FIM (memantau perubahan file dan konfigurasi); FIM adalah salah satu teknik HIDS, sedangkan HIDS seperti OSSEC atau Wazuh juga menganalisis log dan bisa menjalankan active response. Lihat bagian 1.5.

</details>

**7. Interview question (English).** "What is the difference between an IDS and an IPS, and how would you decide where to deploy each in a network?"

<details><summary>Sample answer</summary>

"An IDS monitors traffic or host activity, matches it against signatures, anomaly profiles or policy rules, and raises an alert, but it does not sit in the traffic path, so it cannot guarantee that an attack is stopped. Some IDS tools have limited active response, like sending TCP resets or telling a firewall to block an address. An IPS has the same detection but is deployed inline, so it can drop packets or reset sessions before they reach the target. That power comes with costs: added latency, a new point of failure that must be designed as fail-open or fail-closed, and the risk that a false positive blocks legitimate business traffic. So I would start with detection mode, either out-of-band from a SPAN or TAP or inline with blocking disabled, collect alerts for a few weeks, tune the noisy rules with narrow exceptions, and only then enable blocking for rules that have proven accurate. For placement, I would put sensors where traffic is already decrypted, for example behind the WAF or VPN gateway, because a network sensor cannot inspect TLS it does not terminate. And I would not rely on one layer: firewall rules, a WAF for web apps, host-based monitoring or EDR, and segmentation cover each other's blind spots."

What makes this answer strong: it separates detection logic from deployment position, names concrete IPS actions and the trade-offs (latency, fail mode, false positives), gives a practical rollout sequence that starts in detection mode, and shows awareness that encryption decides where a sensor is useful.

</details>

## 8. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | NIST SP 800-94: Guide to Intrusion Detection and Prevention Systems (IDPS) | https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-94.pdf | primer (publikasi NIST) | Februari 2007; diakses 2026-10-21 | Tinggi. Definisi IDS/IPS/IDPS, metode deteksi, false positive dan tuning, empat kelas IDPS, inline vs passive, SPAN, TAP, IDS load balancer, kemampuan pencegahan, keterbatasan pada lalu lintas terenkripsi, mode simulasi |
| S2 | NIST CSRC: SP 800-94, halaman publikasi | https://csrc.nist.gov/pubs/sp/800/94/final | primer (NIST) | diakses 2026-10-21 | Tinggi. Status final, draft Rev. 1 2012 dipensiunkan, catatan perencanaan 2022-07-15 |
| S3 | NIST SP 800-41 Rev. 1: Guidelines on Firewalls and Firewall Policy | https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-41r1.pdf | primer (publikasi NIST) | September 2009; diakses 2026-10-21 | Tinggi. Packet filtering, stateful inspection dan state table, application firewall, application-proxy gateway, proxy, VPN, NAC, UTM, WAF, keterbatasan pada enkripsi, DMZ, deny by default, NAT sebagai teknologi routing |
| S4 | NIST CSRC Glossary: firewall | https://csrc.nist.gov/glossary/term/firewall | primer (glosarium NIST) | diakses 2026-10-21 | Tinggi. Beberapa definisi; asal nama dari pemisahan jaringan (SP 800-35) |
| S5 | NIST CSRC Glossary: demilitarized zone | https://csrc.nist.gov/glossary/term/demilitarized_zone | primer (glosarium NIST) | diakses 2026-10-21 | Tinggi. Definisi CNSSI 4009-2022 dan SP 800-41 Rev. 1 |
| S6 | NIST CSRC Glossary: virtual private network | https://csrc.nist.gov/glossary/term/virtual_private_network | primer (glosarium NIST) | diakses 2026-10-21 | Tinggi. Definisi SP 800-77 Rev. 1 dan lainnya |
| S7 | NIST CSRC Glossary: proxy | https://csrc.nist.gov/glossary/term/proxy | primer (glosarium NIST) | diakses 2026-10-21 | Tinggi. Definisi SP 800-44, 800-86, 800-113 |
| S8 | NIST CSRC Glossary: fail secure dan fail safe | https://csrc.nist.gov/glossary/term/fail_secure<br>https://csrc.nist.gov/glossary/term/fail_safe | primer (glosarium NIST) | diakses 2026-10-21 | Tinggi. Definisi CNSSI 4009-2022 dari RFC 4949; padanan fail-open/fail-closed adalah penafsiran catatan ini |
| S9 | Cisco: What is a next-generation firewall (NGFW)? | https://www.cisco.com/c/en/us/products/security/firewalls/what-is-a-next-generation-firewall.html | sekunder (vendor) | diakses 2026-10-21 | Sedang. Komponen NGFW dan peran Gartner; definisi vendor, isi produk berbeda antar vendor |
| S10 | OWASP: Web Application Firewall | https://community.owasp.org/Web_Application_Firewall | primer (OWASP) | diakses 2026-10-21 | Tinggi. Definisi WAF, reverse proxy, beda dengan proxy, kebutuhan perawatan |
| S11 | OWASP CRS (Core Rule Set) | https://coreruleset.org/ | primer (proyek OWASP) | diakses 2026-10-21 | Tinggi. Cakupan serangan, versi 4.30.0, LTS 4.25.2, 3.3 end of life |
| S12 | OWASP: SQL Injection | https://community.owasp.org/attacks/SQL_Injection | primer (OWASP) | diakses 2026-10-21 | Tinggi. Definisi dan dampak SQL injection (dipakai untuk konteks; detail di Day 15) |
| S13 | OWASP Cheat Sheet: SQL Injection Prevention | https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html | primer (OWASP) | diakses 2026-10-21 | Tinggi. Prepared statement sebagai pertahanan utama; WAF tidak termasuk pertahanan utama |
| S14 | Suricata User Guide: What is Suricata | https://docs.suricata.io/en/latest/what-is-suricata.html | primer (dokumentasi resmi) | cabang latest; diakses 2026-10-21 | Tinggi. Suricata sebagai mesin IDS, IPS, dan NSM open source dari OISF |
| S15 | Suricata User Guide: Setting up IPS/inline for Linux | https://docs.suricata.io/en/latest/ips/setting-up-ipsinline-for-linux.html | primer (dokumentasi resmi) | cabang latest; diakses 2026-10-21 | Tinggi. NFQUEUE dan AF_PACKET, perilaku bawaan tanpa pembaca antrean, opsi bypass |
| S16 | Suricata User Guide: Exception Policies | https://docs.suricata.io/en/latest/configuration/exception-policies.html | primer (dokumentasi resmi) | cabang latest; diakses 2026-10-21 | Tinggi. Bawaan fail close di mode IPS, diabaikan di mode IDS |
| S17 | Zeek documentation: What Is Zeek? | https://docs.zeek.org/en/master/about/what.html | primer (dokumentasi resmi) | cabang master; diakses 2026-10-21 | Tinggi. Penganalisis lalu lintas pasif, bukan IDS klasik berbasis signature, jenis log |
| S18 | Snort | https://www.snort.org/ | primer (situs proyek) | diakses 2026-10-21 | Tinggi. Snort sebagai IPS open source, dikelola Cisco, Snort 3 |
| S19 | Wazuh documentation: Active Response | https://documentation.wazuh.com/current/user-manual/capabilities/active-response/index.html | primer (dokumentasi resmi) | current (4.14.x); diakses 2026-10-21 | Tinggi. Skrip respons di endpoint, stateless dan stateful, peringatan implementasi yang buruk |
| S20 | OSSEC | https://www.ossec.net/ | primer (situs proyek) | diakses 2026-10-21 | Sedang-tinggi. OSSEC sebagai HIDS dengan analisis log, FIM, active response |
| S21 | Tripwire Enterprise: Integrity and Compliance Monitoring | https://www.tripwire.com/products/tripwire-enterprise | sekunder (halaman produk vendor) | diakses 2026-10-21 | Sedang. Halaman mengembalikan 403 saat riset; deskripsi FIM dan SCM diambil dari judul dan ringkasan halaman di hasil pencarian |
| S22 | CrowdStrike: Falcon Insight XDR data sheet | https://crowdstrike.com/wp-content/uploads/2024/07/crowdstrike-falcon-insight-xdr-data-sheet.pdf | sekunder (dokumen vendor) | Juli 2024; diakses 2026-10-21 | Sedang. Disebut platform EDR dan XDR terpadu |
| S23 | MDN Web Docs: Proxy servers and tunneling | https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/Proxy_servers_and_tunneling | sekunder (dokumentasi Mozilla) | diakses 2026-10-21 | Sedang-tinggi. Forward vs reverse proxy, header `Forwarded` dan `X-Forwarded-For` |
| S24 | CISA Alert TA17-075A: HTTPS Interception Weakens TLS Security | https://www.cisa.gov/news-events/alerts/2017/03/16/https-interception-weakens-tls-security | primer (lembaga pemerintah) | Maret 2017; diakses 2026-10-21 | Tinggi. Cara kerja dan risiko HTTPS inspection, rekomendasi validasi sertifikat |
| S25 | CISA: NSA Releases Cyber Advisory, Managing Risk from Transport Layer Security Inspection | https://www.cisa.gov/news-events/alerts/2019/11/19/nsa-releases-cyber-advisory-managing-risk-transport-layer-security | primer (lembaga pemerintah) | November 2019 (diarsipkan); diakses 2026-10-21 | Tinggi untuk definisi TLSI. Saran inspeksi sekali di dalam organisasi berasal dari ringkasan advisory NSA di hasil pencarian; PDF NSA tidak diperiksa langsung |
| S26 | NIST SP 800-77 Rev. 1: Guide to IPsec VPNs | https://csrc.nist.gov/pubs/sp/800/77/r1/final | primer (publikasi NIST) | Juni 2020; diakses 2026-10-21 | Tinggi. Panduan IPsec dan IKE |
| S27 | CISA: CISA and NSA Release Guidance on Selecting and Hardening VPNs | https://www.cisa.gov/news-events/alerts/2021/09/28/cisa-and-nsa-release-guidance-selecting-and-hardening-vpns | primer (lembaga pemerintah) | 28 September 2021; diakses 2026-10-21 | Tinggi. Server VPN sebagai sasaran dan dampak eksploitasinya |
| S28 | NIST SP 800-207: Zero Trust Architecture | https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-207.pdf | primer (publikasi NIST) | Agustus 2020; diakses 2026-10-21 | Tinggi. Kelemahan model perimeter, lateral movement, ZTA dengan micro-segmentation |
| S29 | CISA: CISA Releases Part One of Zero Trust Microsegmentation Guidance | https://www.cisa.gov/news-events/alerts/2025/07/29/cisa-releases-part-one-zero-trust-microsegmentation-guidance | primer (lembaga pemerintah) | 29 Juli 2025; diakses 2026-10-21 | Tinggi. Microsegmentation sebagai komponen zero trust, membatasi lateral movement |
| S30 | IEEE 802.1X-2020: Port-Based Network Access Control | https://standards.ieee.org/ieee/802.1X/7345/ | primer (halaman standar IEEE) | Februari 2020; diakses 2026-10-21 | Tinggi. Ruang lingkup standar, status aktif, corrigendum 2026 |
| S31 | RFC 3580: IEEE 802.1X RADIUS Usage Guidelines | https://www.rfc-editor.org/rfc/rfc3580.html | primer (IETF, informational) | September 2003; diakses 2026-10-21 | Tinggi. Peran supplicant, authenticator, authentication server; EAP lewat RADIUS; penetapan VLAN |

**Catatan sumber:** padanan fail-open dengan fail safe dan fail-closed dengan fail secure adalah penafsiran catatan ini atas definisi glosarium NIST [S8]; dokumentasi Suricata [S15][S16] memberi contoh konkret perilakunya. Policy-based detection tidak menjadi metode tersendiri di NIST SP 800-94; kemampuan mendeteksi pelanggaran kebijakan disebut sebagai salah satu pemakaian IDPS [S1]. Deskripsi Tripwire [S21] diambil dari ringkasan halaman produk di hasil pencarian karena halamannya menolak akses saat riset; sumber pendukung klasifikasi FIM adalah penjelasan NIST bahwa file integrity checking adalah salah satu teknik HIDS [S1]. Saran NSA agar TLS inspection dilakukan sekali [S25] berasal dari ringkasan advisory, bukan dokumen NSA aslinya. Bypass hardware pada perangkat IPS komersial dan istilah east-west/north-south adalah pengetahuan praktik umum tanpa rujukan tersendiri; cek dokumentasi produkmu. Seluruh alert, log, angka, nama host, dan alamat di bagian 1 dan 2 adalah ilustrasi untuk organisasi fiktif PT JAB, bukan hasil eksekusi nyata.
