---
day: 04
title: 'DDoS dan anti-DDoS: botnet, serangan volumetric, protocol, dan application layer, reflection dan amplification, serta mitigasi dari server sampai ISP'
researched_on: 2026-10-21
versions_checked: 'CISA, FBI, MS-ISAC Understanding and Responding to Distributed Denial-of-Service Attacks versi 2.0 (Maret 2024); CISA TA14-017A UDP-Based Amplification Attacks (revisi terakhir 18 Desember 2019); CISA TA13-088A (revisi 4 Juni 2019); CISA TA14-013A (revisi 6 Oktober 2016); RFC 4987 (Agustus 2007); RFC 2827 / BCP 38 (Mei 2000); RFC 5635 (Agustus 2009); RFC 7999 (Oktober 2016); RFC 8955 (Desember 2020, menggantikan RFC 5575); RFC 4786 / BCP 126 (Desember 2006); NIST SP 800-189 (Desember 2019); NIST CSRC Glossary; MITRE ATT&CK T1498, T1498.002, T1499 (diubah 2025-10-24); Cloudflare DDoS Threat Report H1 2026'
---

# Day 04: DDoS dan anti-DDoS (botnet, tiga jenis serangan, reflection dan amplification, serta mitigasi dari server sampai ISP)

Cakupan: istilah seputar serangan yang membuat layanan tidak bisa dipakai, yaitu DoS dan DDoS, botnet, pembagian serangan volumetric, protocol, dan application layer, SYN flood, UDP flood, HTTP flood, reflection dan amplification, serta cara menahannya dari server sampai ISP: rate limiting, SYN cookies, RTBH, BGP Flowspec, scrubbing center, CDN dan anycast, WAF, dan peran ISP.

## Ide inti

Serangan DDoS tidak mencuri data dan tidak masuk ke dalam sistem. Tujuannya satu: membuat layanan tidak bisa dipakai oleh orang yang berhak, yaitu merusak availability, sifat ketiga dari CIA triad di Day 01. Caranya adalah menghabiskan sumber daya yang paling sempit di jalur menuju layanan itu. Sumber daya itu bisa berupa lebar jalur internet (bandwidth), tabel sambungan di firewall atau server, atau tenaga server aplikasi untuk memproses permintaan. Karena itu setiap serangan DDoS bisa dipahami dengan dua pertanyaan: sumber daya mana yang dihabiskan, dan di titik mana lalu lintas jahat bisa dibuang sebelum sumber daya itu habis.

Jawaban pertanyaan kedua mengikuti satu aturan praktis: makin besar serangannya, makin jauh ke hulu (ke arah internet) pembuangannya harus terjadi. Firewall di depan server tidak bisa menolong bila jalur menuju firewall itu sendiri sudah penuh. Karena itu anti-DDoS bukan satu alat, tetapi rangkaian pertahanan: server dan firewall menahan serangan kecil, WAF menahan serangan ke aplikasi web, ISP dan penyedia hulunya menahan serangan besar, dan jaringan terdistribusi seperti CDN menyebar beban ke banyak lokasi. Analyst yang memahami DDoS bisa menyebut jenis serangannya, menyebut alat yang cocok untuk jenis itu, dan tahu bahwa SOC bukan satu-satunya tim yang bekerja saat serangan berlangsung.

Bayangkan sebuah toko kecil di deretan ruko. Pesaing yang curang membayar ratusan orang suruhan. Sebagian dari mereka memenuhi trotoar dan pintu masuk sehingga pembeli sungguhan tidak bisa mendekat (serangan volumetric). Sebagian lagi mengambil nomor antrean lalu pergi tanpa pernah dilayani, sampai mesin nomor antrean habis (serangan protocol, seperti SYN flood). Sisanya masuk dengan sopan, lalu bertanya harga barang satu per satu di kasir tanpa membeli apa pun, sehingga kasir sibuk melayani mereka (serangan application layer, seperti HTTP flood). Ada juga cara yang lebih licik: penyerang menelepon seratus restoran atas nama tokomu dan memesan paket makan besar untuk diantar ke alamat toko. Teleponnya singkat, tetapi kirimannya besar, dan yang datang adalah kurir restoran sungguhan, bukan penyerang (reflection dan amplification). Batas analoginya: di internet "orang suruhan" adalah puluhan ribu perangkat yang dibajak tanpa pemiliknya tahu, tersebar di seluruh dunia, dan sebagian memakai alamat palsu. Mengusir mereka satu per satu di depan pintu tidak mungkin; pembuangan harus terjadi di jalan raya sebelum mereka sampai ke toko, dan jalan raya itu dikelola ISP. Bagi yang pernah bekerja di NOC (Network Operations Center), serangan volumetric terlihat seperti grafik link pelanggan yang mentok di kapasitas, bedanya isinya sampah yang sengaja dikirim.

```
 Internet (botnet, reflector)
    |  serangan datang dari ribuan alamat
    v
 Upstream / transit (AS64501, AS64502)      <- RTBH, Flowspec, scrubbing center di sini
    |                                          (tempat terbaik untuk serangan sangat besar)
    v
 Border router PT JAB (AS64500)              <- Flowspec, ACL, rate limiting per protokol
    |
    v  link ke data center 10 Gbps           <- titik sempit: penuh bila serangan > 10 Gbps
 jkt-fw01 (firewall stateful)                <- SYN cookies / SYN protection, batas sesi
    |
    v
 jkt-waf01 (WAF)                             <- rate limiting per IP dan per URL, challenge
    |
    v
 jkt-portal01  portal.jab.example  203.0.113.8
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), sebuah ISP (penyedia layanan internet) menengah fiktif dengan sekitar 1.200 karyawan, sekitar 400 ribu pelanggan internet rumah, dan pelanggan korporat yang menyewa dedicated internet (jalur internet khusus dengan kapasitas tetap). NOC PT JAB, tim yang menjaga jaringan tetap berjalan 24 jam, berada satu lantai dengan SOC (Security Operations Center), tim yang memantau dan menangani kejadian keamanan. Portal pelanggan `portal.jab.example` berjalan di server `jkt-portal01` dengan IP publik `203.0.113.8`, di belakang firewall `jkt-fw01` dan WAF `jkt-waf01` di data center Jakarta. Kamu adalah analyst L1 baru di SOC itu.

Kamis 2027-08-05, hari keempat orientasi. Pukul 10:04 muncul alert `SOC-2027-0825`: lonjakan lalu lintas masuk ke `203.0.113.8`. Pukul 10:10 Bambang Hartono, Manajer NOC, menelepon SOC lead Dimas Prasetyo, dan mentormu Sari Kusuma (analyst L2) mengajakmu ke ruang NOC. Selama satu jam berikutnya kamu melihat serangan datang dalam tiga gelombang. Gelombang pertama adalah banjir 42 Gbps dari 38.412 alamat, hampir semuanya paket UDP dari port 53, 123, dan 11211. Setelah NOC menyaring gelombang itu, datang gelombang kedua: jutaan paket SYN per detik ke port 443 yang membuat `jkt-fw01` kehabisan tabel sesi, sehingga portal, situs web, email, dan VPN karyawan ikut terganggu. Gelombang ketiga adalah 46.000 permintaan per detik ke halaman login portal dari 3.800 alamat. Serangan berhenti pukul 11:20. Siang harinya Sari mengirim pesan:

> "Dimas butuh ringkasan untuk laporan `INC-2027-083`, dan aku mau kamu yang menulis draf istilahnya. Jawab dulu ke aku: tadi itu DoS atau DDoS, dan bedanya apa? 38 ribu alamat di gelombang pertama itu siapa, semuanya penyerang? Tiga gelombang tadi menyerang lapisan apa saja, dan kenapa NOC menyebut ukurannya dengan Gbps, Mpps, dan permintaan per detik? Kenapa gelombang pertama datang dari port 53 dan 123, padahal portal tidak pernah bertanya ke server DNS atau NTP di luar sana? Kenapa `jkt-fw01` tumbang di gelombang kedua padahal trafiknya cuma 1,5 Gbps, dan apa yang memulihkannya? Kenapa gelombang ketiga lolos dari scrubbing dan baru tertahan di WAF? Orang Keuangan tanya ke aku kenapa kita tidak blokir saja semua IP penyerang di firewall; jawabanmu apa? Pak Bambang sempat menawarkan blackhole untuk 203.0.113.8 dan Pak Hendra menolak; kenapa, dan apa bedanya blackhole, Flowspec, dan scrubbing? Ada yang usul portal dipindah ke belakang CDN; apa hubungannya dengan anycast? Terakhir, tulis siapa melakukan apa tadi pagi: NOC, SOC, dan upstream, dan apa tanggung jawab kita sebagai ISP."

Pesan itu memuat sepuluh pertanyaan:

1. Serangan tadi DoS atau DDoS, dan apa bedanya?
2. Siapa 38.412 alamat di gelombang pertama, dan apakah semuanya penyerang?
3. Lapisan apa saja yang diserang, dan kenapa ukurannya berbeda (Gbps, Mpps, permintaan per detik)?
4. Kenapa gelombang pertama datang dari port 53, 123, dan 11211?
5. Kenapa `jkt-fw01` tumbang oleh trafik yang hanya 1,5 Gbps, dan apa yang memulihkannya?
6. Kenapa gelombang ketiga lolos dari scrubbing dan baru tertahan di WAF?
7. Kenapa tidak cukup memblokir semua IP penyerang di firewall?
8. Kenapa blackhole ditolak, dan apa beda blackhole, Flowspec, dan scrubbing?
9. Apakah portal perlu CDN, dan apa hubungannya dengan anycast?
10. Siapa melakukan apa, dan apa tanggung jawab PT JAB sebagai ISP?

Pertanyaan 1 dijawab di bagian 1.1, pertanyaan 2 di bagian 1.2 dan 1.5, pertanyaan 3 di bagian 1.3, pertanyaan 4 di bagian 1.4 dan 1.5, pertanyaan 5 di bagian 1.6 dan 1.9, pertanyaan 6 di bagian 1.7, 1.12, dan 1.14, pertanyaan 7 di bagian 1.8, pertanyaan 8 di bagian 1.10, 1.11, dan 1.12, pertanyaan 9 di bagian 1.13, dan pertanyaan 10 di bagian 1.15. Bagian 2 membaca lini waktu insiden, data flow, alert firewall, log WAF, dan dua kasus pelanggan korporat sore harinya.

**Kapan relevan:** saat layanan publik tiba-tiba lambat atau tidak bisa dibuka, saat NOC melaporkan lonjakan trafik, saat menerima laporan abuse bahwa alamat milik organisasimu ikut menyerang pihak lain, saat menyusun rencana ketahanan layanan publik, dan saat menjawab pertanyaan interview "bagaimana melindungi organisasi dari DDoS".
**Kapan bukan jawaban:** saat layanan lambat karena server rusak, aplikasi error, atau lonjakan pengunjung yang sah (misalnya hari jatuh tempo tagihan); memperlakukan lonjakan sah sebagai serangan dan memblokirnya justru merusak availability sendiri. DDoS juga bukan penjelasan untuk data yang bocor atau akun yang diambil alih; itu jenis serangan lain, walaupun bisa terjadi bersamaan.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day 01 (CIA triad, availability, control) dan Day 02 (paket, header, port, TCP, UDP, three-way handshake, spoofing, DNS, ICMP, NAT, model OSI) tidak diulang di tabel ini, tetapi definisinya diulang satu kalimat di subbagian yang memakainya. Tabel ini memuat istilah baru Day ini; cari kolom ketiga bila sebuah istilah terasa abstrak.

| Istilah | Arti singkat | Padanan sehari-hari |
|---|---|---|
| DoS | Serangan yang membuat layanan tidak bisa dipakai pengguna yang berhak | Satu orang iseng yang menghalangi pintu toko |
| DDoS | DoS yang dilakukan dari banyak sumber sekaligus | Ratusan orang suruhan menyerbu toko bersamaan |
| Botnet | Kumpulan perangkat yang dibajak dan dikendalikan dari jauh | Pasukan orang suruhan yang tidak sadar sedang disuruh |
| Bandwidth | Kapasitas jalur, diukur dalam bit per detik (Mbps, Gbps, Tbps) | Lebar jalan menuju toko |
| pps | Packets per second, jumlah paket per detik | Jumlah orang yang lewat pintu per detik, berapa pun ukuran badannya |
| rps | Requests per second, jumlah permintaan aplikasi per detik | Jumlah pertanyaan yang harus dijawab kasir per detik |
| Serangan volumetric | Serangan yang memenuhi bandwidth | Trotoar dan pintu masuk dipenuhi orang |
| Serangan protocol | Serangan yang menghabiskan tabel atau memori perangkat jaringan dan server di lapisan 3 dan 4 | Mesin nomor antrean dihabiskan orang yang langsung pergi |
| Serangan application layer | Serangan yang menghabiskan tenaga aplikasi di lapisan 7 | Kasir sibuk menjawab pertanyaan pembeli palsu |
| UDP flood | Banjir paket UDP ke korban | Brosur dilempar ribuan kali ke pagar sampai halaman penuh |
| SYN flood | Banjir permintaan pembuka sambungan TCP yang tidak pernah diselesaikan | Ribuan telepon "Halo?" yang ditutup sebelum dijawab |
| HTTP flood | Banjir permintaan web yang tampak sah | Pembeli palsu yang bertanya harga tanpa membeli |
| Reflection | Memantulkan serangan lewat server pihak ketiga dengan alamat asal korban | Memesan makanan atas nama tetangga supaya diantar ke rumahnya |
| Amplification | Jawaban server jauh lebih besar daripada permintaannya | Telepon sepuluh detik menghasilkan kiriman satu mobil boks |
| Reflector | Server sah yang dimanfaatkan untuk memantulkan serangan | Restoran yang tertipu pesanan palsu |
| Amplification factor (BAF) | Perbandingan ukuran jawaban dengan ukuran permintaan | Berapa kali lipat kiriman dibanding pesanan |
| Rate limiting | Membatasi jumlah permintaan atau paket per satuan waktu | Satu pembeli maksimal tiga pertanyaan per menit di kasir |
| SYN cookies | Teknik server menjawab SYN tanpa menyimpan catatan sampai handshake selesai | Petugas memberi tiket bersandi alih-alih mencatat nama setiap penelepon |
| BGP | Protokol yang dipakai jaringan besar untuk saling mengumumkan alamat yang bisa dijangkau | Peta jalan bersama yang dipakai semua perusahaan ekspedisi |
| AS | Autonomous System, satu jaringan besar dengan kebijakan routing sendiri, diberi nomor ASN | Satu perusahaan ekspedisi dengan wilayah dan aturannya |
| Upstream / transit | Penyedia yang menghubungkan sebuah jaringan ke seluruh internet | Jalan tol yang menghubungkan kompleks ke kota lain |
| RTBH / blackholing | Membuang semua lalu lintas ke satu alamat di tepi jaringan, dipicu lewat BGP | Menutup jalan menuju rumah korban sama sekali |
| BGP Flowspec | Mengirim aturan penyaring lalu lintas yang rinci lewat BGP ke router hulu | Pesan ke pos polisi di jalan: hentikan mobil boks dari restoran, biarkan yang lain lewat |
| Scrubbing center | Fasilitas yang menyaring lalu lintas serangan lalu meneruskan yang bersih | Pos pemeriksaan besar di pintu tol yang menyaring kendaraan |
| CDN | Jaringan server di banyak lokasi yang melayani pengguna dari lokasi terdekat | Toko yang punya banyak cabang |
| Anycast | Satu alamat IP yang diumumkan dari banyak lokasi sekaligus | Satu nomor telepon layanan yang dijawab cabang terdekat |
| WAF | Penyaring khusus permintaan ke aplikasi web | Petugas yang memeriksa isi formulir sebelum diteruskan ke loket |
| NetFlow / flow | Ringkasan aliran lalu lintas yang dikirim router: siapa ke siapa, port, jumlah paket dan byte | Rekap buku tamu per jam, bukan rekaman CCTV lengkap |
| BCP 38 | Praktik ISP menolak paket dari pelanggan yang alamat asalnya bukan milik pelanggan itu | Kantor pos menolak paket yang label pengirimnya bukan alamat si penyerah paket |

### 1.1 DoS vs DDoS

Pertanyaan pertama Sari terdengar sederhana, tetapi jawabannya menentukan cara bertahan. Serangan dari satu sumber bisa diblokir satu baris aturan; serangan dari 38 ribu sumber tidak.

**Apa itu:** DoS (denial of service) adalah tindakan yang mencegah akses sah ke sebuah sumber daya atau menunda operasi yang waktunya penting [S1]. DDoS (distributed denial of service) adalah teknik DoS yang memakai banyak host untuk menyerang [S2]. Panduan bersama CISA, FBI, dan MS-ISAC menjelaskan bedanya lewat jumlah sumber: DoS memakai satu atau sedikit komputer, sedangkan DDoS memakai banyak sumber, sering berupa botnet, yang mengirim lalu lintas bersamaan [S4]. Keduanya punya tujuan yang sama, yaitu mengganggu availability sistem atau jaringan sasaran [S4].

**Analogi:** DoS seperti satu orang iseng yang berdiri menghalangi pintu toko; satpam cukup memintanya pergi. DDoS seperti ratusan orang suruhan yang datang bersamaan dari segala arah; tidak ada satu orang pun yang bisa ditunjuk sebagai "si penyerang". Batasnya: di internet, satu sumber pun bisa mematikan layanan bila memanfaatkan kelemahan tertentu, misalnya satu permintaan yang membuat aplikasi macet, jadi DoS tidak selalu berarti serangan kecil.

**Cara kerja:** setiap DoS menghabiskan sumber daya yang terbatas. Daftarnya pendek, dan hampir semua serangan bisa dimasukkan ke salah satunya:

1. Bandwidth: jalur penuh, sehingga paket sah ikut terbuang di jalan.
2. Tabel keadaan (state): firewall, load balancer, dan server mencatat setiap sambungan; bila tabel penuh, sambungan baru ditolak.
3. Tenaga proses: CPU, memori, atau jumlah pekerja aplikasi habis untuk melayani permintaan palsu.
4. Kelemahan aplikasi: satu permintaan yang dibuat khusus membuat layanan crash. MITRE ATT&CK, katalog teknik penyerang yang dibahas di Day 14, mencatat ini sebagai Application or System Exploitation (T1499.004) [S17].

CISA menyebut keunggulan utama DDoS dibanding DoS adalah volume lalu lintas yang jauh lebih besar, dan sumber yang tersebar membuat serangan sulit dilacak dan alamatnya sulit diblokir [S4].

**Contoh di PT JAB:** gelombang pertama datang dari 38.412 alamat, gelombang ketiga dari 3.800 alamat. Itu DDoS. Bandingkan dengan kejadian yang akan kamu temui sesekali: skrip milik satu mitra yang salah konfigurasi memanggil halaman laporan portal ratusan kali per detik dari satu IP. Itu DoS, mungkin tanpa niat jahat, dan selesai dengan menghubungi mitranya atau memblokir satu alamat.

**Beda dengan lonjakan sah (flash crowd):** setiap tanggal 20, hari jatuh tempo tagihan, permintaan ke portal naik dari sekitar 600 ke 1.400 per detik. Itu bukan serangan. Pembedanya ada di pola: lonjakan sah datang dari banyak pelanggan dengan perilaku wajar (login, melihat tagihan, membayar), sesuai jadwal yang bisa ditebak, dan banyak yang berhasil menyelesaikan transaksi. Serangan biasanya datang tiba-tiba, pola permintaannya seragam, dan tidak menghasilkan transaksi.

**Salah paham umum:**
- "DDoS tidak berbahaya karena tidak ada data yang dicuri." Gangguan availability bisa menghentikan pembayaran, mengganggu layanan pelanggan, dan merusak reputasi [S4]. MITRE juga mencatat DDoS kadang dipakai sebagai pengalih perhatian atau alat pemerasan [S15], jadi SOC tetap mengawasi aktivitas lain selama serangan berlangsung.

### 1.2 Botnet

Pertanyaan kedua Sari ("38 ribu alamat itu siapa?") punya dua jawaban berbeda untuk gelombang yang berbeda. Gelombang ketiga datang dari botnet. Gelombang pertama datang dari reflector, yang dibahas di bagian 1.5.

**Apa itu:** botnet berasal dari kata "robot" dan "network": penjahat membobol banyak komputer, lalu menyatukan perangkat yang terinfeksi menjadi jaringan "bot" yang bisa dikendalikan dari jauh [S3]. Dalam DDoS, perangkat-perangkat ini dikoordinasikan untuk mengirim lalu lintas atau permintaan ke sasaran secara bersamaan [S4]. Anggota botnet tidak hanya komputer: router rumah, kamera CCTV internet, perangkat IoT (Internet of Things, perangkat sehari-hari yang tersambung ke internet), dan server sewaan yang lemah juga sering menjadi bot.

**Analogi:** pasukan orang suruhan yang tidak sadar sedang disuruh. Pemilik router di rumah tetap memakai internetnya seperti biasa, sementara routernya diam-diam ikut menyerang portal orang lain. Batasnya: orang suruhan sungguhan tahu dirinya dibayar; pemilik perangkat bot biasanya tidak tahu sama sekali, dan bisa menjadi korban sekaligus "pelaku" di log.

**Cara kerja:** penyerang menginfeksi perangkat yang lemah, misalnya router dengan password bawaan atau server yang belum di-patch. Program jahat di perangkat itu menghubungi server pengendali, yang disebut C2 (command and control, dibahas di Day 16), dan menunggu perintah. Saat diperintah, semua bot mengirim lalu lintas ke sasaran yang sama. Karena bot adalah perangkat sungguhan dengan alamat sungguhan, bot bisa menyelesaikan three-way handshake TCP (tiga langkah pembuka sambungan, Day 02 bagian 1.7) dan mengirim permintaan web lengkap. Itu yang membuat botnet cocok untuk serangan application layer. DDoS juga bisa disewa: CISA mencantumkan peringatan FBI tentang layanan "booter" dan "stresser" yang menjual serangan DDoS sebagai jasa [S4].

**Contoh di PT JAB:** gelombang ketiga datang dari 3.800 alamat yang semuanya menyelesaikan handshake dan sesi HTTPS. Itu ciri bot sungguhan, bukan alamat palsu. Dari 3.800 alamat itu, 214 berada di rentang alamat pelanggan internet rumah PT JAB sendiri. Artinya ada router atau perangkat milik pelanggan PT JAB yang menjadi bagian botnet dan ikut menyerang portal perusahaan yang melayani mereka. Ini bukan hal aneh: laporan Cloudflare untuk paruh pertama 2026 menempatkan Indonesia di peringkat ketiga negara sumber serangan DDoS dua kuartal berturut-turut [S19].

**Beda dengan reflector:** bot adalah perangkat yang dibobol dan menjalankan program penyerang. Reflector adalah server sah yang tidak dibobol, hanya salah konfigurasi, dan dimanfaatkan untuk memantulkan jawaban ke korban (bagian 1.5). Keduanya muncul sebagai "alamat penyerang" di log, tetapi tindak lanjutnya berbeda.

**Salah paham umum:**
- "Alamat di log serangan pasti milik penjahat, jadi bisa dilaporkan ke polisi." Hampir semua alamat itu milik korban lain yang perangkatnya dibajak. Yang berguna adalah memberi tahu pemilik jaringannya lewat kontak abuse, seperti yang dilakukan PT JAB untuk 214 pelanggannya sendiri (bagian 1.15).

### 1.3 Volumetric vs protocol vs application layer (L3/L4/L7)

Pertanyaan ketiga Sari menyangkut cara NOC menyebut ukuran tiga gelombang: 42 Gbps, 3,1 Mpps, dan 46.000 permintaan per detik. Tiga satuan itu mencerminkan tiga sumber daya berbeda yang dihabiskan.

**Apa itu:** CISA membagi serangan DoS dan DDoS menjadi tiga jenis teknik [S4]:

1. Volume-based atau volumetric: menghabiskan bandwidth atau sumber daya sasaran dengan lalu lintas yang sangat besar, sampai jaringan jenuh dan permintaan sah tidak tertangani.
2. Protocol-based: memanfaatkan kelemahan protokol jaringan atau implementasinya untuk mengganggu sasaran; biasanya menyasar lapisan 3 (network) dan lapisan 4 (transport) model OSI.
3. Application layer-based: menyasar aplikasi atau layanan tertentu di lapisan 7 (application), menghabiskan tenaga proses aplikasi atau membuatnya macet.

Model OSI adalah model tujuh lapisan untuk menjelaskan komunikasi jaringan (Day 02 bagian 1.2): lapisan 3 berisi alamat IP, lapisan 4 berisi port dan TCP/UDP, lapisan 7 berisi aplikasi seperti HTTP. Itu sebabnya orang menyebut serangan "L3/L4" dan "L7".

**Analogi:** volumetric memenuhi trotoar dan pintu toko, protocol menghabiskan mesin nomor antrean, dan application layer membuat kasir sibuk menjawab pembeli palsu. Batasnya: CISA mengingatkan ketiga jenis ini tidak saling meniadakan, dan penyerang sering menggabungkannya [S4], seperti tiga gelombang pagi tadi.

**Cara kerja:** setiap jenis punya satuan ukur yang cocok, karena sumber daya yang dihabiskan berbeda. Tabel berikut adalah kunci membacanya; cari kolom "Satuan yang dipakai" untuk tahu kenapa NOC menyebut angka yang berbeda-beda.

| Jenis | Lapisan | Sumber daya yang dihabiskan | Satuan yang dipakai | Contoh |
|---|---|---|---|---|
| Volumetric | 3/4 (isi paketnya tidak penting) | Bandwidth jalur | bps (Gbps, Tbps) | UDP flood, reflection dan amplification |
| Protocol | 3/4 | Tabel sesi, memori, CPU perangkat | pps (Mpps) | SYN flood, banjir fragmen paket |
| Application layer | 7 | Pekerja aplikasi, database, CPU server | rps (permintaan per detik) | HTTP flood ke halaman login atau pencarian |

Pembagian satuan di atas adalah kebiasaan di lapangan, bukan aturan baku. MITRE ATT&CK memakai pembagian yang mirip dengan dua teknik: Network Denial of Service (T1498) untuk serangan yang memenuhi jaringan, dan Endpoint Denial of Service (T1499) untuk serangan yang menghabiskan sumber daya sistem tanpa harus memenuhi jaringan [S15][S17].

**Contoh di PT JAB:** gelombang pertama (42 Gbps) adalah volumetric: link 10 Gbps ke data center penuh, dan isi paketnya tidak penting. Gelombang kedua (3,1 juta SYN per detik, hanya sekitar 1,5 Gbps) adalah protocol: yang habis bukan jalur, tetapi tabel sesi `jkt-fw01`. Gelombang ketiga (46.000 permintaan per detik) adalah application layer: jalur dan firewall baik-baik saja, tetapi aplikasi portal yang biasanya melayani sekitar 600 permintaan per detik dan sanggup sampai sekitar 2.500 per detik kewalahan.

**Beda dengan pembagian lapisan alat pertahanan:** jenis serangan menentukan alat yang cocok. Alat yang bekerja di lapisan 3/4 (router, Flowspec, scrubbing biasa) tidak bisa membedakan permintaan login palsu dari yang asli, dan alat lapisan 7 (WAF) tidak berguna bila jalurnya sudah penuh sebelum lalu lintas sampai ke WAF. Perbandingan lengkapnya ada di bagian 3.2 dan 3.3.

### 1.4 UDP flood

Pertanyaan keempat Sari dimulai dari kolom protokol di data flow gelombang pertama: semuanya UDP. Day 02 menjanjikan pembahasan serangan UDP yang memanfaatkan alamat asal palsu, dan janji itu dipenuhi di sini.

**Apa itu:** UDP flood adalah banjir paket UDP yang dikirim ke sasaran untuk memenuhi jalurnya atau menyibukkan perangkatnya. UDP (User Datagram Protocol) adalah protokol yang mengirim data tanpa membuka sambungan dan tanpa tanda terima (Day 02 bagian 1.7). Karena tidak ada handshake, pengirim tidak perlu menerima balasan apa pun, sehingga alamat asal di header paket bisa diisi alamat palsu tanpa mengganggu serangan. Pemalsuan alamat asal ini disebut spoofing (Day 02 bagian 1.1). MITRE mencatat banjir langsung semacam ini sebagai Direct Network Flood (T1498.001) [S15].

**Analogi:** brosur yang dilempar ke pagar ribuan kali per detik sampai halaman rumah penuh dan tukang pos tidak bisa masuk. Pelempar tidak perlu menunggu jawaban, dan label pengirim di brosur bisa ditulis nama siapa saja. Batasnya: brosur di halaman bisa disapu, sedangkan paket yang memenuhi jalur internet sudah menimbulkan kerugian sebelum sampai ke tujuan, karena paket sah ikut terbuang di jalan yang macet.

**Cara kerja:** ada dua bentuk utama.

1. UDP flood langsung: bot mengirim paket UDP sebesar mungkin ke sasaran, sering ke port acak. Bila port yang dituju tidak punya layanan, sasaran membalas dengan ICMP port unreachable (Day 02 bagian 1.8), sehingga sasaran ikut membuang tenaga untuk membalas.
2. UDP flood lewat pihak ketiga: penyerang tidak mengirim ke sasaran, tetapi ke server lain dengan alamat asal palsu berisi alamat sasaran. Jawaban server-server itu yang membanjiri sasaran. Ini reflection, dibahas di bagian 1.5.

Spoofing hanya mungkin bila jaringan asal penyerang tidak memeriksa alamat asal paket yang keluar. Praktik pemeriksaan itu sudah ditetapkan sejak tahun 2000 sebagai BCP 38: penyedia internet hanya meneruskan paket dari pelanggan bila alamat asalnya berada di blok alamat milik pelanggan itu [S9]. Masalahnya, BCP 38 hanya efektif bila diterapkan oleh jaringan tempat penyerang berada, bukan oleh jaringan korban.

**Contoh di PT JAB:** gelombang pertama berisi paket UDP dengan port asal 53, 123, dan 11211 menuju `203.0.113.8`. Portal tidak pernah meminta apa pun ke alamat-alamat itu, jadi semua paket itu adalah jawaban yang tidak pernah ditanyakan. Itu tanda reflection, bukan UDP flood langsung.

**Beda dengan SYN flood:** UDP flood biasanya menyerang bandwidth dengan paket besar; SYN flood menyerang tabel sambungan dengan paket kecil (bagian 1.6). UDP flood tidak meninggalkan status sambungan di log; SYN flood meninggalkan banyak sambungan setengah jadi.

**Salah paham umum:**
- "Blokir saja semua UDP." Banyak layanan sah memakai UDP: DNS, sinkronisasi waktu (NTP), panggilan suara (VoIP), dan web modern lewat HTTP/3 (Day 02 bagian 5). Menyaring UDP harus spesifik ke port asal, tujuan, dan ukuran paket, bukan menutup seluruh protokol.

### 1.5 Reflection dan amplification (DNS, NTP, memcached)

Bagian ini menjawab inti pertanyaan kedua dan keempat Sari. 38.412 alamat di gelombang pertama bukan bot. Hampir semuanya server DNS, server NTP, dan server memcached sungguhan di seluruh dunia, yang menjawab pertanyaan yang tidak pernah diajukan portal.

**Apa itu:** reflection adalah serangan yang memantulkan lalu lintas lewat server pihak ketiga, disebut reflector. Penyerang mengirim permintaan ke reflector dengan alamat asal palsu berisi alamat korban, sehingga reflector mengirim jawabannya ke korban [S16]. Amplification terjadi bila jawaban jauh lebih besar daripada permintaannya, sehingga lalu lintas yang sampai ke korban berlipat ganda [S16]. CISA menyebut gabungan keduanya distributed reflective denial of service (DRDoS), dan menjelaskan bahwa UDP tidak memeriksa alamat asal sehingga alamat korban mudah dipalsukan [S5].

Ukuran pelipatgandaan disebut bandwidth amplification factor (BAF). CISA mendefinisikannya sebagai jumlah byte payload UDP yang dikirim reflector untuk menjawab, dibanding jumlah byte payload UDP permintaannya [S5]. Payload adalah isi paket di luar header (Day 02 bagian 1.1).

**Analogi:** penyerang menelepon seratus restoran atas nama tetanggamu, memesan paket makan keluarga untuk diantar ke rumah tetangga itu. Teleponnya hanya sepuluh detik (permintaan kecil), kirimannya satu mobil boks (jawaban besar). Kurir yang datang adalah kurir restoran sungguhan, bukan penyerang, dan restoran tidak tahu pesanannya palsu. Batasnya: restoran sungguhan biasanya menelepon balik untuk konfirmasi; server UDP yang salah konfigurasi tidak pernah memeriksa, dan di internet ada puluhan ribu "restoran" semacam itu yang bisa dipesan dalam hitungan detik.

**Cara kerja:**

```
 Penyerang / botnet                Reflector (server DNS/NTP/memcached sah)        Korban
 alamat asal dipalsukan                                                            203.0.113.8
 menjadi 203.0.113.8
     |                                     |                                          |
     | -- permintaan kecil (mis. 64 byte) ->|                                          |
     |    "dari: 203.0.113.8"              |                                          |
     |                                     | -- jawaban besar (mis. 3.200 byte) ----> |
     |                                     |    "ke: 203.0.113.8"                     |
     x  penyerang tidak menerima apa pun   x  reflector tidak tahu dirinya dipakai     x  banjir dari ribuan reflector
```

Tidak semua protokol UDP bisa dipakai, hanya yang jawabannya bisa jauh lebih besar dari permintaannya. Tabel berikut berasal dari alert CISA TA14-017A, satu-satunya sumber angka di bagian ini. Cari kolom BAF untuk melihat berapa kali lipat jawaban dibanding permintaan; angka yang berbentuk rentang berarti hasilnya bergantung pada konfigurasi server dan jenis permintaan [S5].

| Protokol | Port UDP umum | BAF menurut CISA | Permintaan yang disalahgunakan |
|---|---|---|---|
| DNS | 53 | 28 sampai 54 | Query ke resolver terbuka, sering jenis ANY (lihat TA13-088A) |
| NTP | 123 | 556,9 | Perintah `monlist` (lihat TA14-013A) |
| memcached | 11211 | 10.000 sampai 51.000 | Permintaan ke server memcached yang terbuka ke internet |
| CharGEN | 19 | 358,8 | Permintaan pembangkit karakter |
| CLDAP | 389 | 56 sampai 70 | Query directory lewat UDP |
| SSDP | 1900 | 30,8 | Permintaan SEARCH |
| SNMPv2 | 161 | 6,3 | Permintaan GetBulk |

Nomor port di kolom kedua adalah port bawaan protokol itu; tabel CISA sendiri tidak mencantumkan port. Daftar CISA lebih panjang (antara lain NetBIOS, QOTD, TFTP, WS-Discovery); tujuh baris di atas dipilih karena paling sering dibahas.

Tiga protokol yang wajib dikenali:

- **DNS:** penyerang mengirim query ke resolver DNS terbuka, yaitu resolver yang mau menjawab siapa saja di internet, dengan alamat asal korban. Query jenis ANY meminta semua informasi tentang sebuah zona dalam satu jawaban, sehingga jawabannya besar [S6]. Resolver DNS adalah server yang mencarikan jawaban DNS untuk perangkat (Day 02 bagian 1.9). Resolver yang dikonfigurasi benar hanya menjawab jaringannya sendiri.
- **NTP:** NTP adalah protokol sinkronisasi jam. Fitur pemantauan `monlist` di server NTP lama mengembalikan daftar hingga 600 alamat terakhir yang menghubunginya; semua versi ntpd sebelum 4.2.7 rentan secara bawaan [S7]. Satu permintaan kecil menghasilkan jawaban berisi ratusan alamat.
- **memcached:** memcached adalah sistem cache data di memori yang biasanya dipakai di dalam data center dan tidak seharusnya terbuka ke internet. Pada 28 Februari 2018, GitHub diserang lewat memcached yang terbuka dengan UDP aktif, dengan puncak 1,35 Tbps dan 126,9 juta paket per detik; GitHub mencatat setiap byte yang dikirim penyerang bisa menghasilkan hingga 51 KB ke sasaran [S18]. GitHub memulihkan layanan dengan mengalihkan routing ke penyedia mitigasi DDoS, dan layanan tidak tersedia penuh sekitar lima menit [S18].

**Menghitung amplification factor:** misalkan satu query DNS berisi payload 64 byte dan jawabannya 3.200 byte. BAF-nya 3.200 dibagi 64, yaitu 50, masih dalam rentang 28 sampai 54 dari CISA. Tetapi BAF hanya menghitung payload. Setiap paket juga membawa header IP dan UDP sebesar 28 byte, sehingga perbandingan lebar jalur yang sebenarnya adalah (3.200 + 28) dibagi (64 + 28), yaitu 3.228 dibagi 92, sekitar 35 kali. Penyerang dengan total jalur 1 Gbps yang memakai query seperti ini menghasilkan sekitar 35 Gbps di korban, asalkan cukup banyak reflector yang mau menjawab. Untuk NTP `monlist` dengan BAF 556,9, permintaan yang sama kecilnya menghasilkan ratusan kali lipat.

**Contoh di PT JAB:** data flow gelombang pertama (bagian 2.2) menunjukkan 21.906 alamat mengirim jawaban DNS dari port 53, 15.377 alamat mengirim jawaban NTP dari port 123, dan 1.129 alamat mengirim jawaban memcached dari port 11211, total 38.412 reflector. Contohnya `192.0.2.110` adalah resolver DNS terbuka milik sebuah kampus, `192.0.2.111` server NTP lama milik sebuah pabrik, dan `192.0.2.112` server memcached milik penyedia hosting. Tidak ada satu pun dari mereka yang berniat menyerang PT JAB.

**Beda reflection dan amplification:** reflection menyembunyikan penyerang dan menyebarkan sumber serangan ke ribuan server sah; amplification melipatgandakan volume. Keduanya biasanya dipakai bersama karena saling menguatkan, tetapi istilahnya berbeda: reflection menjawab "lewat siapa", amplification menjawab "berapa kali lipat".

**Salah paham umum:**
- "Blokir semua reflector." CISA mengingatkan bahwa serangan reflection biasanya datang dari server publik yang sah [S4]. Memblokir 21.906 resolver DNS secara permanen bisa memutus layanan sah, dan daftar reflector berganti di serangan berikutnya. Yang lebih efektif adalah menyaring pola lalu lintasnya (UDP dari port 53 ke alamat yang tidak pernah bertanya) sedekat mungkin dengan hulu.

### 1.6 SYN flood

Pertanyaan kelima Sari adalah yang paling sering membingungkan orang baru: gelombang kedua hanya sekitar 1,5 Gbps, jauh di bawah kapasitas link 10 Gbps, tetapi `jkt-fw01` tumbang.

**Apa itu:** SYN flood adalah serangan yang mengirim sangat banyak segmen SYN, langkah pertama three-way handshake TCP, tanpa pernah menyelesaikan handshake. RFC 4987 menjelaskan tujuannya: menghabiskan antrean sambungan setengah terbuka (half-open) pada sebuah port [S8]. Sambungan half-open adalah sambungan yang sudah menerima SYN dan sudah membalas SYN-ACK, tetapi belum menerima ACK penutup.

**Analogi:** ribuan telepon masuk yang masing-masing berkata "Halo?" lalu diam. Petugas mencatat setiap penelepon di buku antrean sambil menunggu jawaban, dan buku itu penuh sebelum penelepon sungguhan sempat masuk. Batasnya: petugas manusia akan curiga setelah beberapa telepon kosong; perangkat jaringan tanpa perlindungan khusus menunggu setiap penelepon sampai batas waktu habis.

**Cara kerja:** saat menerima SYN, server (atau perangkat stateful di depannya) menyediakan memori untuk mencatat sambungan itu. RFC 4987 menyebut catatan ini TCB (Transmission Control Block) [S8]. Server membalas SYN-ACK dan menunggu ACK. Penyerang tidak pernah mengirim ACK, dan karena alamat asal SYN dipalsukan, SYN-ACK dikirim ke alamat yang tidak pernah meminta sehingga tidak ada jawaban yang membebaskan catatan itu [S8]. Penyerang cukup mengirim SYN lebih cepat daripada server membuang catatan yang kedaluwarsa. Setelah antrean penuh, sambungan sah ikut ditolak.

```
 Normal:   klien --SYN--> server   server --SYN-ACK--> klien   klien --ACK--> server   (catatan dipakai)
 SYN flood: "192.0.2.119" --SYN--> server   server --SYN-ACK--> 192.0.2.119 (tidak pernah minta)
            catatan menunggu ... menunggu ... sampai batas waktu
            x 3,1 juta per detik  ->  tabel penuh, sambungan sah ditolak
```

Firewall stateful, yaitu firewall yang mencatat setiap sambungan supaya bisa mengizinkan jawabannya kembali (dibahas di Day 03), menyimpan catatan yang sama untuk setiap SYN yang diizinkan lewat. RFC 4987 mencatat bahwa memindahkan penanganan handshake ke firewall atau proxy di depan server hanya memindahkan masalahnya ke perangkat tengah itu [S8]. CISA juga mengingatkan bahwa komponen infrastruktur seperti server DNS dan firewall bisa ikut menjadi sasaran DDoS [S4].

**Contoh di PT JAB:** gelombang kedua mengirim sekitar 3,1 juta SYN per detik ke `203.0.113.8:443`, dengan alamat asal acak (lebih dari 2,9 juta alamat berbeda dalam lima menit). Karena aturan firewall mengizinkan HTTPS ke portal, setiap SYN mendapat satu catatan sesi di `jkt-fw01`. Tabel sesi `jkt-fw01` berkapasitas 2.000.000 sesi; dengan 3,1 juta SYN per detik, tabel itu penuh dalam waktu kurang dari satu detik. Akibatnya bukan hanya portal yang terganggu: situs web, email, dan VPN karyawan yang juga lewat `jkt-fw01` tidak bisa membuka sambungan baru. Pemulihannya dibahas di bagian 1.9.

**Beda dengan port scan:** port scan juga mengirim SYN tanpa menyelesaikan handshake (Day 02 bagian 1.12), tetapi tujuannya mengintip pintu mana yang terbuka, ke banyak port dengan jumlah kecil. SYN flood mengirim jutaan SYN ke satu port yang sudah diketahui terbuka, dengan tujuan menghabiskan tabel.

**Salah paham umum:**
- "Trafik kecil berarti bukan DDoS." Ukuran serangan protocol dibaca dari jumlah paket per detik dan dari tabel sesi, bukan dari Gbps. 1,5 Gbps SYN berisi jutaan paket kecil, dan setiap paket meminta satu catatan.

### 1.7 HTTP flood

Pertanyaan keenam Sari: kenapa gelombang ketiga lolos dari scrubbing yang sudah aktif, dan baru tertahan di WAF?

**Apa itu:** HTTP flood adalah banjir permintaan web, misalnya membuka halaman login atau mengirim form, yang masing-masing tampak seperti permintaan sah. Ini serangan application layer: yang dihabiskan adalah tenaga server aplikasi dan database untuk memproses setiap permintaan, bukan jalurnya [S4]. MITRE mencatat pola ini sebagai Application Exhaustion Flood (T1499.003) di bawah Endpoint Denial of Service [S17].

**Analogi:** pembeli palsu yang masuk dengan sopan, antre di kasir, lalu menanyakan harga barang satu per satu tanpa membeli. Satpam di pintu tidak bisa menolak mereka karena penampilannya sama dengan pembeli biasa. Batasnya: pembeli palsu di toko bisa dikenali wajahnya setelah datang berkali-kali; bot HTTP bisa berganti alamat, berganti tanda pengenal browser, dan jumlahnya ribuan.

**Cara kerja:** bot membuka sambungan TCP lengkap (handshake selesai), membuka sesi TLS untuk HTTPS, lalu mengirim permintaan HTTP. Karena handshake harus selesai, alamat asalnya asli, tidak bisa dipalsukan (Day 02 bagian 1.7). Bot memilih halaman yang mahal untuk diproses: login (memeriksa password ke database), pencarian, atau laporan. Satu permintaan login bisa memakan tenaga server berpuluh kali lipat dibanding membuka gambar statis.

Kenapa scrubbing biasa tidak menahan: di lapisan 3 dan 4, paket HTTP flood terlihat sempurna. Handshake lengkap, ukuran wajar, alamat asli, port 443. Isi permintaannya dienkripsi TLS, jadi perangkat yang tidak memegang kunci TLS situs itu tidak bisa membaca path, header, atau isi form. Yang bisa membaca adalah perangkat yang memang membuka enkripsi atas nama situs, seperti WAF atau reverse proxy di depan portal (dibahas di Day 03).

**Contoh di PT JAB:** gelombang ketiga berisi sekitar 46.000 permintaan per detik ke `/login` dari 3.800 alamat, sekitar 12 permintaan per detik per alamat. Normalnya pada jam yang sama sekitar 600 per detik. Scrubbing center hanya memeriksa lapisan 3/4, jadi lalu lintas ini diteruskan sebagai "bersih". Baru `jkt-waf01`, yang membuka TLS atas nama portal, bisa melihat bahwa semua permintaan itu menuju satu path dengan ciri yang seragam (bagian 1.14).

**Beda dengan credential stuffing:** credential stuffing (mencoba pasangan username dan password hasil kebocoran situs lain, seperti alert `SOC-2027-0800` di Day 01) juga mengirim banyak permintaan ke `/login`, tetapi tujuannya masuk ke akun, bukan mematikan layanan. Karena keduanya mirip di log, SOC selalu memeriksa apakah ada login yang berhasil dari alamat penyerang. Pagi tadi jumlahnya nol (bagian 2.4).

**Salah paham umum:**
- "Serangan L7 selalu kecil, jadi tidak berbahaya." HTTP flood bisa sangat kecil dalam Gbps tetapi mematikan aplikasi, karena satuan yang relevan adalah permintaan per detik dibanding kapasitas aplikasi, bukan lebar jalur.

### 1.8 Rate limiting

Pertanyaan ketujuh Sari datang dari orang Keuangan: "Kenapa tidak blokir saja semua IP penyerang di firewall?" Jawabannya ada di bagian ini dan bagian 1.10.

**Apa itu:** rate limiting adalah membatasi jumlah paket, sambungan, atau permintaan per satuan waktu, biasanya per alamat sumber, per tujuan, atau per jenis lalu lintas. Lalu lintas yang melewati batas ditolak, ditunda, atau ditantang. CISA menyarankan rate limiting di beberapa tempat: response rate limiting di server DNS, rate limiting berbasis jaringan dengan QoS (quality of service, pengaturan prioritas lalu lintas di router), dan pembatasan permintaan ke layanan UDP [S5]. Panduan DDoS CISA juga menyarankan batas laju di aturan firewall dan pemakaian rate limiting atau ACL (access control list, daftar aturan izinkan dan tolak di router atau firewall) saat serangan berlangsung [S4]. Response rate limiting (RRL) di DNS meredam laju jawaban server ketika menerima query dalam jumlah besar [S13].

**Analogi:** aturan di kasir: setiap pembeli maksimal tiga pertanyaan per menit; yang lebih dari itu diminta antre ulang. Batasnya: bila pembeli palsunya ribuan dan masing-masing hanya bertanya dua kali per menit, aturan per orang tidak menahan mereka. Sebaliknya, satu keluarga besar yang datang bersama memakai satu "identitas" bisa ikut tertahan padahal sah.

**Cara kerja:** rate limiting membutuhkan tiga keputusan: apa yang dihitung (paket, sambungan, permintaan ke URL tertentu), dikelompokkan berdasarkan apa (per IP sumber, per tujuan, per sesi), dan apa yang dilakukan setelah batas terlewati (tolak, tunda, tantang dengan CAPTCHA). CAPTCHA adalah tantangan yang mudah dijawab manusia tetapi sulit dijawab program, misalnya memilih gambar; CISA menyebutnya cara membedakan manusia dari bot [S4].

Kenapa memblokir IP satu per satu tidak cukup:

1. Pada reflection, alamat sumbernya adalah server sah yang berganti-ganti (bagian 1.5).
2. Pada SYN flood dengan spoofing, alamat sumbernya palsu dan acak; daftar blokir akan berisi jutaan alamat tak bermakna (bagian 1.6).
3. Pada serangan volumetric, aturan blokir di firewall bekerja setelah jalur menuju firewall penuh, jadi sudah terlambat.
4. Pada HTTP flood, alamatnya asli tetapi ribuan, dan bisa berganti; sebagian bahkan pelanggan sendiri yang perangkatnya dibajak (bagian 1.2).

**Contoh di PT JAB:** pukul 11:01 Sari bersama tim aplikasi portal menambahkan aturan di `jkt-waf01`: setiap IP maksimal 20 permintaan ke `/login` per 60 detik. Dengan 3.800 alamat bot, batas itu meloloskan paling banyak 3.800 kali 20 dibagi 60, sekitar 1.267 permintaan per detik, di bawah kapasitas portal sekitar 2.500 per detik. Batas 20 per menit dipilih karena pelanggan sungguhan jarang mencoba login lebih dari beberapa kali per menit, termasuk pelanggan yang berbagi satu IP publik lewat NAT (Day 02 bagian 1.11).

**Beda dengan memblokir:** blokir menolak selamanya berdasarkan identitas (alamat); rate limiting menolak kelebihannya berdasarkan perilaku (laju). Rate limiting tetap memberi jalan kepada pengguna sah yang kebetulan berbagi alamat dengan bot.

**Salah paham umum:**
- "Rate limiting di server cukup untuk semua DDoS." Rate limiting di perangkat sendiri hanya menolong bila lalu lintasnya masih bisa sampai ke perangkat itu. Untuk serangan volumetric yang lebih besar dari jalurmu, rate limiting harus dilakukan di hulu (bagian 1.11).

### 1.9 SYN cookies

Bagian kedua jawaban pertanyaan kelima: apa yang memulihkan `jkt-fw01` di gelombang kedua?

**Apa itu:** SYN cookies adalah teknik yang memungkinkan server menjawab SYN tanpa menyimpan catatan sambungan sampai handshake selesai. Informasi sambungan disandikan ke dalam nomor urut awal (sequence number) di SYN-ACK; bila ACK yang kembali membawa nomor yang cocok, server membangun ulang catatannya saat itu juga [S8]. Sequence number adalah nomor urut yang dipakai TCP untuk menjaga urutan data (Day 02 bagian 1.7).

**Analogi:** alih-alih mencatat nama setiap penelepon di buku antrean, petugas memberi setiap penelepon "kode tiket" yang dibuat dari nama, nomor telepon, dan jam, dengan rumus rahasia. Petugas tidak mencatat apa pun. Hanya penelepon yang menelepon balik dengan kode yang benar yang dilayani. Buku antrean tidak pernah penuh, karena memang tidak ada yang ditulis. Batasnya: kode tiket hanya bisa memuat sedikit informasi, jadi sebagian keterangan tambahan dari penelepon hilang.

**Cara kerja:** RFC 4987 menjelaskan bahwa nilai cookie dibuat dari penghitung waktu, indeks ukuran segmen, dan hash berkunci rahasia atas alamat dan port kedua pihak [S8]. Hash adalah fungsi yang mengubah data menjadi sidik jari pendek (dibahas di Day 05). Karena tidak ada catatan yang disimpan untuk SYN palsu, SYN flood tidak bisa memenuhi tabel. Kekurangannya, menurut RFC 4987: sebagian opsi TCP tidak terbawa, termasuk window scaling yang memengaruhi kinerja, dan karena itu penulisnya menyarankan SYN cookies tidak aktif sebagai bawaan, melainkan dipakai saat dibutuhkan [S8]. RFC yang sama juga mencatat alternatif lain: SYN cache (catatan yang sangat ringkas), serta firewall atau proxy yang menyelesaikan handshake atas nama server, yang sering disebut SYN proxy [S8].

**Contoh di PT JAB:** `jkt-fw01` sebenarnya punya fitur perlindungan SYN (SYN cookies dan SYN proxy), tetapi belum diaktifkan sejak penggantian perangkat. Pukul 10:27 Agung Prabowo, Lead Infrastruktur, mengaktifkannya untuk alamat `203.0.113.8`. Dalam satu menit, sesi half-open turun drastis dan sambungan baru ke portal, web, email, dan VPN pulih pukul 10:28. CPU firewall masih tinggi karena tetap harus menjawab jutaan SYN, dan itu salah satu alasan scrubbing tetap diaktifkan pukul 10:31 (bagian 1.12).

**Beda dengan rate limiting:** rate limiting menolak kelebihan SYN, sehingga sebagian SYN sah ikut tertolak; SYN cookies menjawab semua SYN tanpa mencatat, sehingga klien sah tetap bisa tersambung selama perangkat sanggup menjawab.

**Salah paham umum:**
- "SYN cookies menahan semua DDoS." SYN cookies hanya melindungi tabel sambungan dari SYN flood. Teknik ini tidak membantu bila jalurnya penuh (volumetric) atau bila bot menyelesaikan handshake lalu membanjiri aplikasi (HTTP flood).

### 1.10 RTBH (blackholing)

Pertanyaan kedelapan Sari dimulai dari tawaran Bambang pukul 10:24: "Kita blackhole saja 203.0.113.8, lima menit beres." Hendra Wijaya, Direktur Teknologi, menolak. Untuk memahami kenapa, perlu tahu dulu bagaimana jaringan besar saling bicara.

**Istilah pendukung:** internet terdiri dari puluhan ribu jaringan besar yang disebut AS (Autonomous System), masing-masing punya nomor (ASN) dan kebijakan routing sendiri. PT JAB adalah AS64500, dan terhubung ke internet lewat dua penyedia transit (upstream), AS64501 dan AS64502. AS saling memberi tahu blok alamat (prefix) yang bisa dijangkau lewat dirinya memakai BGP (Border Gateway Protocol). BGP community adalah label tambahan yang ditempel pada pengumuman BGP untuk meminta perlakuan tertentu dari tetangga.

**Apa itu:** RTBH (remotely triggered black hole) adalah teknik membuang semua lalu lintas menuju sebuah alamat di tepi jaringan, dipicu dari jauh lewat BGP. RFC 5635 menjelaskan bentuk dasarnya, destination-based RTBH: setiap router tepi punya rute "buang" yang mengarah ke antarmuka kosong (null atau discard), lalu alamat korban diumumkan lewat BGP dengan tujuan ke rute buang itu, sehingga lalu lintas ke korban dibuang di tepi jaringan dan tidak lagi melintasi jaringan [S10]. RFC 7999 menetapkan community BLACKHOLE bernilai `65535:666` untuk meminta jaringan tetangga membuang lalu lintas ke prefix yang ditandai [S11]. CISA menyarankan RTBH lewat BGP, sebaiknya dikoordinasikan dengan upstream atau ISP [S5].

**Analogi:** menutup jalan menuju rumah korban sama sekali di gerbang tol. Mobil boks kiriman palsu berhenti, tetapi tamu, kurir, dan keluarga korban juga tidak bisa lewat. Batasnya: penutupan jalan sungguhan terlihat oleh semua orang, sedangkan RTBH bekerja diam-diam; pengguna hanya melihat situs tidak bisa dibuka.

**Cara kerja:**

```
 PT JAB (AS64500) mengumumkan ke upstream:
   203.0.113.8/32   community 65535:666 (BLACKHOLE), NO_EXPORT
 Upstream (AS64501, AS64502):
   semua paket ke 203.0.113.8  ->  dibuang di router tepi upstream
 Hasil:
   serangan berhenti memenuhi link PT JAB
   pelanggan sah juga tidak bisa membuka portal
```

RFC 5635 terus terang menyebut kelemahannya: alamat korban menjadi tidak terjangkau sepenuhnya, sehingga serangan justru "selesai" dalam arti tujuan penyerang tercapai, walaupun kerusakan ikutannya terbatas pada alamat itu [S10]. RFC 7999 menyarankan prefix sespesifik mungkin, biasanya `/32` untuk IPv4, supaya alamat tetangga tidak ikut dibuang, dan menyarankan penanda NO_EXPORT supaya pengumuman itu tidak menyebar keluar jaringan penerima [S11]. Penerima juga harus memeriksa bahwa pengirim memang berhak atas prefix itu, karena community BLACKHOLE yang disalahgunakan bisa membuat alamat orang lain tidak terjangkau [S11]. Ada juga source-based RTBH yang membuang lalu lintas dari alamat sumber tertentu dengan bantuan uRPF (pemeriksaan apakah alamat asal paket punya rute yang sah) [S10]; teknik ini tidak berguna bila sumbernya puluhan ribu reflector atau alamat palsu.

**Contoh di PT JAB:** Hendra menolak blackhole untuk `203.0.113.8` karena portal adalah layanan utama pelanggan; mem-blackhole portal sama saja menyelesaikan pekerjaan penyerang. Bulan lalu NOC memakai RTBH dengan tepat: alamat `198.51.100.49`, bekas milik pelanggan korporat yang sudah berhenti berlangganan dan tidak dipakai layanan apa pun, mendadak diserang 18 Gbps. NOC mengumumkan `198.51.100.49/32` dengan community BLACKHOLE ke kedua upstream, dan dalam tiga menit lalu lintas itu dibuang di hulu tanpa ada yang dirugikan.

**Beda dengan Flowspec:** RTBH membuang semua lalu lintas ke alamat korban, apa pun jenisnya. Flowspec membuang atau membatasi hanya lalu lintas yang cocok dengan pola tertentu, misalnya UDP dari port 123 (bagian 1.11).

**Salah paham umum:**
- "Blackhole adalah mitigasi DDoS." RTBH melindungi jaringan dan pelanggan lain dari kerusakan ikutan, tetapi mengorbankan alamat yang diserang. Pakai bila alamat itu tidak penting, atau sebagai langkah terakhir bila serangan mengancam seluruh jaringan.

### 1.11 BGP Flowspec

Lanjutan pertanyaan kedelapan: apa yang dilakukan NOC pukul 10:13, yang membuat gelombang pertama berhenti tanpa mematikan portal?

**Apa itu:** BGP Flowspec (flow specification) adalah cara mengirim aturan penyaring lalu lintas lewat BGP, sehingga router lain, termasuk router milik upstream, bisa menerapkannya. RFC 8955 mendefinisikan aturan itu sebagai sekumpulan kriteria pencocokan yang harus dipenuhi semuanya [S12]. Kriteria yang bisa dipakai: prefix tujuan, prefix sumber, protokol IP, port (sumber, tujuan, atau keduanya), jenis dan kode ICMP, flag TCP, panjang paket, DSCP (penanda prioritas), dan fragmen [S12]. Tindakannya antara lain membatasi laju dalam byte per detik atau paket per detik, mengalihkan ke tabel routing lain, atau menandai ulang prioritas; laju nol berarti semua lalu lintas yang cocok dibuang [S12].

**Analogi:** RTBH menutup jalan menuju rumah korban. Flowspec seperti mengirim pesan ke pos polisi di gerbang tol: "Hentikan mobil boks dari restoran yang menuju rumah nomor 8, biarkan kendaraan lain lewat." Batasnya: polisi di gerbang tol hanya bisa membaca pelat dan jenis kendaraan (header paket), bukan isi muatan; Flowspec tidak bisa melihat isi permintaan web.

**Cara kerja:** NIST SP 800-189 menjelaskan bahwa Flowspec memungkinkan AS hulu menyaring lalu lintas masuk di router tepinya atas permintaan AS hilir, dan menyebutnya penyempurnaan RTBH yang lebih rinci, dinamis, dan efisien [S13]. Supaya tidak disalahgunakan, RFC 8955 menetapkan aturan validasi: aturan dari tetangga BGP hanya diterima bila memuat prefix tujuan dan pengirimnya sama dengan pengumum rute untuk prefix itu [S12]. Akibatnya PT JAB hanya bisa meminta penyaringan untuk alamat miliknya sendiri. Kelemahannya: upstream harus mendukung dan mau menerima Flowspec dari pelanggannya, jumlah aturan dibatasi kapasitas router, aturan hanya melihat header (lapisan 3/4), dan aturan yang terlalu luas bisa membuang lalu lintas sah.

**Contoh di PT JAB:** pukul 10:13 NOC memasang tiga aturan Flowspec di border router PT JAB dan mengirim aturan yang sama ke upstream AS64501, yang menerima Flowspec dari pelanggannya. UDP dari port 123 dan 11211 menuju `203.0.113.8/32` dibuang. UDP dari port 53 menuju alamat yang sama dibatasi 50 Mbps, bukan dibuang, karena NOC belum yakin portal tidak pernah menerima jawaban DNS langsung. Pukul 10:16 link data center kembali normal. Isi aturannya dibaca di bagian 2.2.

**Beda dengan scrubbing:** Flowspec menyaring berdasarkan pola header yang sudah diketahui, di router yang sudah ada, dalam hitungan menit. Scrubbing center memeriksa lalu lintas lebih dalam dengan perangkat khusus dan bisa menangani pola yang berubah-ubah, tetapi lalu lintas harus dialihkan dulu ke sana (bagian 1.12).

### 1.12 Scrubbing center

Lanjutan pertanyaan kedelapan dan bagian pertama pertanyaan keenam: apa yang diaktifkan pukul 10:31, dan kenapa gelombang ketiga tetap lolos?

**Apa itu:** scrubbing center adalah fasilitas berisi perangkat penyaring khusus milik penyedia layanan mitigasi DDoS. Lalu lintas menuju korban dialihkan ke sana, lalu lintas serangan dibuang, dan lalu lintas bersih diteruskan ke korban [S20]. CISA menyarankan organisasi mempertimbangkan penyedia layanan mitigasi DDoS yang punya infrastruktur khusus untuk menyaring lalu lintas jahat sebelum sampai ke jaringan organisasi, dan mengaktifkan layanan mitigasi dari ISP atau pihak ketiga saat serangan terjadi [S4].

**Analogi:** pos pemeriksaan besar di pintu tol. Semua kendaraan menuju kompleks dialihkan lewat pos itu, kendaraan mencurigakan ditahan, sisanya diantar ke kompleks lewat jalur khusus. Batasnya: pos itu hanya memeriksa bentuk dan pelat kendaraan, kecuali pemilik kompleks menitipkan kunci untuk membuka muatan (kunci TLS), dan pengalihan ke pos butuh waktu beberapa menit.

**Cara kerja:** ada dua langkah. Pertama, pengalihan: biasanya lewat BGP, yaitu prefix korban diumumkan lewat penyedia scrubbing sehingga internet mengirim lalu lintas ke sana; untuk layanan web, pengalihan juga bisa lewat perubahan record DNS [S21]. Kedua, pengembalian: lalu lintas bersih dikirim ke jaringan korban lewat terowongan GRE (Generic Routing Encapsulation, cara membungkus paket di dalam paket lain) atau sambungan fisik khusus [S21]. Lalu lintas keluar dari korban tetap lewat jalur biasa [S20].

Ada dua model layanan. Always-on: penyedia scrubbing selalu berada di jalur, sehingga perlindungan langsung aktif tetapi biayanya tinggi. On-demand: penyedia hanya muncul di jalur saat diaktifkan oleh pelanggan yang sedang diserang [S20]. Model on-demand lebih murah tetapi ada jeda pengalihan, dan lalu lintas sebelum pengalihan tetap mengenai korban.

**Contoh di PT JAB:** PT JAB berlangganan scrubbing on-demand dari upstream AS64501. Pukul 10:31 Hendra menyetujui aktivasi, dan pukul 10:38 prefix `203.0.113.0/24` sudah diumumkan lewat penyedia scrubbing. Yang dialihkan adalah seluruh `/24`, bukan hanya `/32` portal, karena prefix yang lebih spesifik dari `/24` biasanya tidak diterima di internet [S11]. Gelombang ketiga pukul 10:52 lolos karena di lapisan 3/4 permintaannya sempurna: handshake lengkap, alamat asli, isi terenkripsi. PT JAB tidak menitipkan kunci TLS portal ke penyedia scrubbing, jadi penyedia tidak bisa membaca permintaan `/login`. Scrubbing dinonaktifkan pukul 16:00 setelah empat jam tanpa gelombang baru.

**Beda dengan CDN:** scrubbing center menyaring lalu lintas lalu meneruskannya ke server asli; CDN melayani pengguna langsung dari cabangnya dan hanya meneruskan sebagian permintaan ke server asli (bagian 1.13).

**Salah paham umum:**
- "Sudah langganan scrubbing, jadi aman dari semua DDoS." Scrubbing L3/L4 tidak membaca isi HTTPS, dan model on-demand punya jeda beberapa menit. Serangan application layer tetap butuh WAF atau layanan yang membuka TLS.

### 1.13 CDN dan anycast

Pertanyaan kesembilan Sari muncul dari usulan dalam rapat evaluasi: pindahkan portal ke belakang CDN.

**Apa itu:** CDN (content delivery network) adalah jaringan server yang tersebar di banyak lokasi geografis, yang menyimpan salinan konten dan melayani pengguna dari lokasi yang dekat. CISA menyebut CDN membantu menahan DDoS dengan menyerap dan menyebarkan lalu lintas ke banyak server dan data center [S4]. Anycast adalah teknik membuat satu alamat layanan tersedia di banyak lokasi terpisah sekaligus, dan sistem routing yang menentukan lokasi mana yang melayani setiap permintaan berdasarkan topologi jaringan dan asal permintaan [S14]. Banyak CDN dan penyedia DNS besar memakai anycast.

**Analogi:** CDN seperti toko yang punya banyak cabang; pembeli datang ke cabang terdekat, dan serbuan orang suruhan di satu kota hanya membebani cabang kota itu. Anycast seperti satu nomor telepon layanan pelanggan yang otomatis dijawab cabang terdekat dari penelepon. Batasnya: barang yang hanya ada di gudang pusat (data pribadi, transaksi login) tetap harus diambil dari pusat, jadi permintaan seperti itu tetap sampai ke server asli.

**Cara kerja:** RFC 4786 menjelaskan dua manfaat anycast terhadap DoS: node anycast bisa menjadi tempat pembuangan lalu lintas serangan yang berasal dari wilayahnya sendiri sehingga node lain tidak terbebani, dan serangan dari sumber yang tersebar dibagi ke semua node, yang lebih mudah ditanggung daripada satu layanan tunggal [S14]. RFC yang sama mencatat anycast bisa membatasi kerusakan serangan dari satu sumber hanya pada satu node [S14]. Di atas itu, CDN modern biasanya juga menjalankan WAF dan rate limiting di setiap cabangnya, sehingga serangan L3/L4 dan L7 sama-sama ditahan sebelum sampai ke server asli.

Ada tiga syarat supaya CDN benar-benar melindungi:

1. Alamat server asli tidak boleh diketahui umum, dan server asli hanya menerima lalu lintas dari CDN; bila tidak, penyerang langsung menyerang alamat aslinya.
2. CDN harus membuka TLS untuk bisa menyaring L7, artinya kunci atau sertifikat situs dikelola pihak ketiga. Ini keputusan risiko dan kepatuhan, terutama untuk portal yang memuat data pribadi pelanggan (pelindungan data pribadi dibahas di Day 18).
3. Halaman dinamis seperti login tetap diteruskan ke server asli, jadi aturan rate limiting di CDN tetap harus diatur.

**Contoh di PT JAB:** portal saat ini tidak memakai CDN. Alamat `203.0.113.8` diumumkan hanya dari data center Jakarta, sehingga semua serangan bertumpuk di satu link 10 Gbps. Usulan di rapat evaluasi: portal ditempatkan di belakang CDN berbasis anycast dengan WAF, server asli hanya menerima lalu lintas dari CDN, dan pengelolaan sertifikat dikaji bersama Nina Kartika (Manajer Risiko dan Kepatuhan TI) dan Agus Setiawan (DPO). Untuk server DNS publik PT JAB, NOC mengusulkan anycast di beberapa POP (point of presence, titik jaringan di kota lain) Bandung, Surabaya, dan Medan.

**Beda dengan load balancing:** load balancing membagi beban ke beberapa server di satu lokasi; CDN dan anycast membagi beban ke banyak lokasi. Load balancer di satu data center tetap tumbang bila jalur ke data center itu penuh.

### 1.14 WAF untuk serangan L7

Bagian terakhir pertanyaan keenam: kenapa `jkt-waf01` yang akhirnya menahan gelombang ketiga?

**Apa itu:** WAF (web application firewall) adalah penyaring khusus yang memeriksa isi permintaan HTTP ke aplikasi web dan bisa menolak, membatasi, atau menantang permintaan itu; pembahasan lengkapnya ada di Day 03. Untuk DDoS, kekuatan WAF ada pada letaknya: WAF di depan portal membuka TLS atas nama portal, sehingga bisa membaca path, header, cookie, dan isi form, hal yang tidak terlihat oleh router, Flowspec, atau scrubbing L3/L4.

**Analogi:** petugas yang memeriksa isi formulir sebelum diteruskan ke loket. Untuk HTTP flood, petugas ini juga menghitung berapa kali setiap orang datang ke loket yang sama dan meminta bukti bahwa ia manusia bila terlalu sering. Batasnya: petugas formulir tidak berguna bila antrean sudah macet di jalan sebelum sampai ke mejanya; WAF hanya bekerja bila lalu lintas masih bisa sampai ke WAF.

**Cara kerja:** WAF menahan HTTP flood dengan beberapa cara yang biasanya digabung:

1. Rate limiting per IP dan per path (bagian 1.8).
2. Challenge: meminta browser menjalankan pemeriksaan kecil atau menjawab CAPTCHA; bot sederhana gagal [S4].
3. Aturan berdasarkan ciri bot: tanda pengenal browser (User-Agent) yang seragam, tidak ada cookie sesi, urutan permintaan yang tidak wajar.
4. Menolak atau membatasi berdasarkan reputasi atau asal alamat, dengan hati-hati karena pelanggan sah bisa ikut tertahan.

**Contoh di PT JAB:** log `jkt-waf01` (bagian 2.4) menunjukkan 95,1% alamat bot memakai string User-Agent yang persis sama dan hampir semua permintaan tidak membawa cookie sesi. Pukul 11:01 dipasang dua aturan: rate limit 20 permintaan ke `/login` per 60 detik per IP, dan challenge untuk permintaan dengan User-Agent bot tanpa cookie sesi. Pukul 11:04 laju permintaan yang diteruskan ke portal turun ke sekitar 640 per detik dan portal kembali normal.

**Beda dengan firewall jaringan:** firewall memutuskan berdasarkan alamat dan port (penjaga gerbang yang cek KTP dan alamat tujuan); WAF memutuskan berdasarkan isi permintaan web. Pada gelombang kedua, SYN flood mengenai `jkt-fw01` sebelum sampai ke WAF, karena WAF berada di belakang firewall dan baru melihat lalu lintas setelah handshake selesai.

**Salah paham umum:**
- "WAF adalah alat anti-DDoS." WAF hanya alat untuk serangan L7 dan hanya sejauh kapasitasnya sendiri. Serangan volumetric dan protocol harus dihentikan sebelum sampai ke WAF.

### 1.15 Peran ISP, NOC, dan SOC

Pertanyaan terakhir Sari: siapa melakukan apa, dan apa tanggung jawab PT JAB sebagai ISP? PT JAB punya posisi unik: ia korban di pagi hari, tetapi juga penyedia jalur bagi ratusan ribu pelanggan, sebagian di antaranya ikut menjadi bot.

**Apa itu:** ISP (internet service provider) adalah penyedia akses internet bagi pelanggannya. Dalam urusan DDoS, ISP punya tiga peran:

1. Pelindung pelanggan: ISP berada di hulu pelanggan, jadi bisa menyaring serangan sebelum memenuhi jalur pelanggan. CISA menyarankan korban menghubungi ISP atau penyedia hosting, memberikan alamat penyerang, dan meminta penyaringan berdasarkan port dan ukuran paket [S4]. MITRE juga menyebut bahwa serangan yang melebihi kapasitas jalur korban biasanya harus dicegat di hulu, oleh ISP, CDN, atau penyedia mitigasi [S15].
2. Warga internet yang baik: menerapkan BCP 38 supaya pelanggannya tidak bisa memalsukan alamat asal [S9], memantau data flow untuk paket palsu dan lonjakan permintaan ke layanan UDP yang rawan, serta menyimpan kontak pelanggan yang selalu terbaru supaya peringatan bisa dikirim cepat [S5]. NIST SP 800-189 juga menyarankan ISP membatasi laju fragmen UDP non-awal di router tepi, karena serangan amplification menghasilkan banyak fragmen semacam itu [S13].
3. Penanganan abuse: menindaklanjuti laporan bahwa alamat pelanggannya ikut menyerang, baik sebagai bot maupun sebagai reflector.

**Analogi:** pengelola jalan tol. Ia bisa menutup gerbang atau memeriksa kendaraan tertentu untuk melindungi satu kompleks, dan ia juga bertanggung jawab memastikan kendaraan yang masuk tol dari wilayahnya tidak memakai pelat palsu. Batasnya: pengelola tol tidak bisa mengatur jalan milik pengelola lain; BCP 38 di jaringan PT JAB tidak menghentikan pemalsuan yang terjadi di jaringan orang lain.

**Cara kerja di PT JAB:** tabel berikut merangkum pembagian tugas pagi tadi; cari kolom "Kenapa tim itu" untuk memahami alasan pembagiannya.

| Tim atau pihak | Yang dikerjakan saat `INC-2027-083` | Kenapa tim itu |
|---|---|---|
| NOC (Bambang Hartono) | Mendeteksi lonjakan di `jkt-flow01`, memasang Flowspec, menghubungi upstream, mengaktifkan pengalihan scrubbing | Memegang router, BGP, kapasitas jalur, dan kontak upstream |
| Infrastruktur (Agung Prabowo) | Mengaktifkan perlindungan SYN di `jkt-fw01` | Mengelola firewall dan server data center |
| SOC (Sari, kamu, Dimas) | Triage alert, menentukan jenis serangan bersama NOC, membaca log WAF, menyusun aturan WAF bersama tim aplikasi, memeriksa login berhasil dari alamat bot, mengumpulkan bukti, membuka dan mencatat insiden | Memegang SIEM, log keamanan, prosedur insiden, dan pengawasan serangan lain yang mungkin menumpang |
| Upstream AS64501 | Menerapkan Flowspec di router tepinya, menjalankan scrubbing on-demand | Berada di hulu PT JAB, punya kapasitas jauh lebih besar |
| Direktur Teknologi (Hendra Wijaya) | Memutuskan menolak RTBH dan menyetujui scrubbing | Keputusan yang mengorbankan layanan atau menambah biaya butuh pemilik risiko |
| Layanan pelanggan dan komunikasi | Mengumumkan gangguan portal ke pelanggan | CISA menekankan komunikasi internal dan eksternal selama serangan [S4] |

SIEM (security information and event management) adalah sistem yang mengumpulkan log dari banyak sumber untuk dianalisis SOC; PT JAB memakai Splunk, dan topik ini dibahas di Day 10. `jkt-flow01` adalah kolektor flow milik NOC yang menerima ringkasan lalu lintas dari router.

**Contoh di PT JAB:** sore harinya peran ISP terlihat dari dua sisi. Pukul 14:35 PT JAB melindungi pelanggan korporat yang diserang dengan Flowspec di border router-nya (`SOC-2027-0828`). Pukul 16:10 PT JAB menerima laporan abuse bahwa server DNS milik pelanggan korporat lain menjadi reflector (`SOC-2027-0829`). Keduanya dibaca di bagian 2.5. Untuk 214 alamat pelanggan rumah yang ikut di gelombang ketiga, tim abuse mengirim pemberitahuan ke pelanggan untuk mengganti password router dan memperbarui firmware.

**Beda NOC dan SOC dalam DDoS:** NOC menjaga jalur tetap bisa dipakai dan memegang alat di lapisan 3/4. SOC memastikan serangan dipahami, dicatat, dan tidak dipakai sebagai pengalih perhatian, serta memegang alat dan log di lapisan 7. Keduanya harus bekerja dari satu ruangan atau satu kanal komunikasi saat serangan berlangsung.

**Salah paham umum:**
- "DDoS urusan NOC, SOC cukup menunggu." SOC tetap dibutuhkan: menentukan apakah ada serangan lain yang menumpang, membaca lalu lintas L7, menyimpan bukti untuk laporan dan penegak hukum [S4], dan menjalankan proses insiden yang dibahas di Day 19.

## 2. Contoh nyata

Semua log, data flow, alert, dan aturan di bagian ini adalah keluaran ilustrasi untuk organisasi fiktif PT JAB, bukan hasil eksekusi nyata. Formatnya disederhanakan; nama field dan sintaks di produk sungguhan bisa berbeda.

### 2.1 Lini waktu `INC-2027-083`

Ini lini waktu yang disusun SOC untuk laporan Dimas. Cari kolom "Lapisan" untuk melihat bagaimana serangan berpindah lapisan setiap kali satu pertahanan berhasil.

| Waktu (WIB) | Kejadian | Lapisan | Tindakan |
|---|---|---|---|
| 10:02 | Gelombang 1 mulai: UDP reflection DNS, NTP, memcached ke `203.0.113.8` | L3/L4 volumetric | |
| 10:04 | `jkt-flow01` memberi alarm ke NOC; alert `SOC-2027-0825` muncul di Splunk | | Triage SOC dimulai |
| 10:06 | Link 10 Gbps ke data center penuh; portal tidak bisa dibuka; link ke AS64501 naik ke 93% | | |
| 10:09 | Puncak: 42 Gbps, 6,3 Mpps, 38.412 sumber | | |
| 10:13 | NOC memasang Flowspec di border dan mengirimnya ke AS64501 | | Flowspec |
| 10:16 | Link data center normal; portal pulih | | |
| 10:20 | Dimas membuka insiden `INC-2027-083` dengan severity SEV-2 | | Proses insiden |
| 10:21 | Gelombang 2 mulai: SYN flood 3,1 juta SYN per detik ke `203.0.113.8:443` | L3/L4 protocol | |
| 10:22 | Tabel sesi `jkt-fw01` penuh; alert `SOC-2027-0826`; portal, web, email, VPN gagal membuka sambungan baru | | |
| 10:24 | Bambang menawarkan RTBH `203.0.113.8/32`; Hendra menolak | | |
| 10:27 | Agung mengaktifkan perlindungan SYN di `jkt-fw01` | | SYN cookies |
| 10:28 | Sambungan baru pulih | | |
| 10:31 | Hendra menyetujui scrubbing on-demand dari AS64501 | | |
| 10:38 | Pengalihan `203.0.113.0/24` ke scrubbing aktif | | Scrubbing |
| 10:52 | Gelombang 3 mulai: HTTP flood ke `/login` dari 3.800 alamat | L7 application | |
| 10:53 | Portal lambat dan banyak error 503; alert `SOC-2027-0827` | | |
| 10:58 | SOC memastikan nol login berhasil dari alamat bot; 214 alamat bot berada di rentang pelanggan PT JAB | | |
| 11:01 | Aturan rate limit dan challenge dipasang di `jkt-waf01` | | WAF |
| 11:04 | Portal normal | | |
| 11:20 | Serangan berhenti | | |
| 16:00 | Scrubbing dinonaktifkan | | |

**Cara membaca:** serangan berlangsung 78 menit (10:02 sampai 11:20). Portal terganggu tiga kali: 10 menit (10:06 sampai 10:16), 6 menit (10:22 sampai 10:28), dan 11 menit (10:53 sampai 11:04), total 27 menit. Setiap gangguan berakhir ketika alat yang cocok untuk lapisan itu dipasang. Pola "ganti cara setelah ditahan" ini biasa disebut serangan multi-vector, dan CISA mencatat penyerang memang menggabungkan teknik [S4]. SEV-2 adalah tingkat keparahan insiden di skala SEV-1 sampai SEV-4 milik PT JAB; artinya dibahas di Day 11.

**Pelajaran untuk persiapan (sebelum serangan berikutnya):** perlindungan SYN di `jkt-fw01` seharusnya sudah aktif; prosedur aktivasi scrubbing butuh persetujuan direktur yang memakan 10 menit; dan portal tanpa CDN membuat semua serangan bertumpuk di satu link. Ketiganya masuk daftar perbaikan, sejalan dengan langkah persiapan CISA seperti rencana respons, layanan mitigasi, perencanaan kapasitas, dan konfigurasi firewall [S4].

### 2.2 Membaca data flow gelombang pertama (`SOC-2027-0825`)

Ini ringkasan yang dibuka Bambang di layar NOC pukul 10:10, dibuat `jkt-flow01` dari data flow border router selama satu menit di puncak serangan.

```
jkt-flow01  window 2027-08-05 10:09:00-10:10:00 WIB  dst=203.0.113.8
proto  src_port  sumber_unik   Gbps    Mpps   rata2_ukuran_paket
udp    53         21.906       26,0    2,60   1.250 byte
udp    123        15.377       14,0    3,50     500 byte
udp    11211       1.129        2,0    0,20   1.250 byte
total             38.412       42,0    6,30     833 byte
normal (Kamis lalu, jam sama): 0,4 Gbps, terutama tcp/443

contoh sumber teratas:
192.0.2.110  udp/53     148 Mbps   (resolver DNS terbuka, kampus)
192.0.2.111  udp/123     92 Mbps   (server NTP lama, pabrik)
192.0.2.112  udp/11211   61 Mbps   (server memcached, penyedia hosting)
```

**Cara membaca:** hitung dulu supaya angkanya konsisten. 26 Gbps sama dengan 3,25 miliar byte per detik; dibagi 1.250 byte per paket, hasilnya 2,6 juta paket per detik. 14 Gbps dibagi 500 byte per paket (1,75 miliar byte per detik dibagi 500) menghasilkan 3,5 juta paket per detik. 2 Gbps dibagi 1.250 byte menghasilkan 0,2 juta. Totalnya 6,3 juta paket per detik, dan 42 Gbps (5,25 miliar byte per detik) dibagi 6,3 juta paket menghasilkan rata-rata sekitar 833 byte per paket. Jumlah sumber 21.906 ditambah 15.377 ditambah 1.129 sama dengan 38.412.

Lalu baca polanya. Port asal adalah 53, 123, dan 11211, yaitu port layanan DNS, NTP, dan memcached; artinya paket-paket ini adalah jawaban dari server, bukan permintaan ke server (bagian 1.5). Ukuran paketnya besar, ciri jawaban yang diperbesar. Portal tidak pernah meminta apa pun ke alamat-alamat itu. Kesimpulan: volumetric, reflection dan amplification, multi-protokol.

**Aturan yang dipasang NOC pukul 10:13:**

```
flowspec  match: dst 203.0.113.8/32, proto udp, src-port 123     action: traffic-rate 0 (buang)
flowspec  match: dst 203.0.113.8/32, proto udp, src-port 11211   action: traffic-rate 0 (buang)
flowspec  match: dst 203.0.113.8/32, proto udp, src-port 53      action: traffic-rate-bytes 6250000 (50 Mbps)
dipasang di: border router AS64500, dan dikirim ke AS64501 lewat sesi BGP Flowspec
```

**Cara membaca aturannya:** setiap baris memuat kriteria pencocokan dan tindakan, sesuai komponen dan tindakan RFC 8955 [S12]. Laju 0 berarti buang. Laju `6250000` dalam byte per detik sama dengan 50 Mbps (6.250.000 kali 8 bit). Lalu lintas sah ke portal (TCP 443) tidak cocok dengan aturan mana pun, jadi tetap lewat. Karena aturan dikirim ke AS64501, sebagian besar serangan dibuang di router upstream sebelum memenuhi link ke PT JAB.

**Variasi yang perlu dikenali:** reflection lewat CLDAP (port asal 389) dan SSDP (1900) terlihat sama di data flow, hanya port asalnya berbeda. Penyerang juga sering mengirim paket yang sudah terpecah menjadi fragmen; fragmen lanjutan tidak membawa header UDP sehingga tidak punya port, dan karena itu NIST menyarankan ISP membatasi laju fragmen UDP non-awal [S13].

**Kapan cara baca ini gagal:** bila serangan datang dari port acak (UDP flood langsung oleh bot), pola "port asal layanan" tidak ada. Penyaringannya beralih ke ukuran paket, port tujuan, atau pengalihan ke scrubbing.

### 2.3 Membaca alert kesehatan firewall gelombang kedua (`SOC-2027-0826`)

Alert ini muncul di Splunk pukul 10:22 dari data kesehatan `jkt-fw01`, dua menit setelah insiden dibuka.

```
Alert   : SOC-2027-0826  jkt-fw01 session table near capacity
Waktu   : 2027-08-05 10:22:10 WIB
Sesi aktif                     : 1.998.442 dari 2.000.000 (99,9%)
Sesi half-open (menunggu ACK)  : 1.951.207 (97,6% dari sesi aktif)
SYN masuk ke 203.0.113.8:443   : 3,1 juta per detik (rata-rata 60 byte per paket)
Volume                         : 1,49 Gbps
CPU data plane                 : 97%
Sumber unik (5 menit terakhir) : 2.904.118, tersebar acak
Sambungan baru ditolak         : portal, www.jab.example, mail.jab.example, jkt-vpn01
```

**Cara membaca:** hitung dulu. 3,1 juta paket kali 60 byte kali 8 bit sama dengan sekitar 1,49 Gbps, jauh di bawah link 10 Gbps; jadi ini bukan serangan bandwidth. 1.951.207 dibagi 1.998.442 sama dengan 97,6%: hampir semua sesi di tabel adalah sambungan setengah jadi, ciri SYN flood (bagian 1.6). 2,9 juta alamat sumber dalam lima menit, tersebar acak, berarti alamat asalnya palsu; tidak ada daftar blokir yang masuk akal. Yang paling penting bagi SOC adalah baris terakhir: dampaknya meluas ke semua layanan di belakang firewall yang sama, termasuk VPN karyawan.

**Keputusan:** memblokir sumber tidak mungkin; mem-blackhole portal ditolak (bagian 1.10). Pilihan yang tepat adalah mengaktifkan perlindungan SYN di firewall (bagian 1.9), lalu memindahkan beban ke hulu dengan scrubbing (bagian 1.12).

### 2.4 Membaca ringkasan log WAF gelombang ketiga (`SOC-2027-0827`)

Ini ringkasan yang dibuat Sari dan kamu dari log `jkt-waf01` di Splunk pukul 10:58, lima menit setelah alert muncul.

```
Ringkasan jkt-waf01  2027-08-05 10:53:00-10:58:00 WIB  host=portal.jab.example
total permintaan          : 13.800.000   (46.000 per detik)
IP sumber unik            : 3.800        (rata-rata 12,1 permintaan per detik per IP)
path                      : GET /login 61%, POST /login 39%
User-Agent identik        : 3.612 IP (95,1%) memakai string yang sama persis
cookie sesi               : tidak ada di 99% permintaan
POST /login berhasil      : 0
IP di rentang pelanggan broadband PT JAB : 214
contoh sumber             : 192.0.2.113, 192.0.2.114 (router rumah di luar negeri)
normal jam ini (Kamis lalu): 600 per detik
```

**Cara membaca:** hitung dulu. Lima menit adalah 300 detik, dan 300 kali 46.000 sama dengan 13.800.000 permintaan. 46.000 dibagi 3.800 sekitar 12,1 permintaan per detik per alamat. 3.612 dibagi 3.800 sama dengan 95,1%. Lalu baca polanya: ribuan alamat asli (handshake dan TLS selesai), satu path saja, User-Agent seragam, tanpa cookie sesi. Itu botnet yang menjalankan HTTP flood (bagian 1.7). Baris `POST /login berhasil : 0` menjawab pertanyaan penting SOC: tidak ada akun yang berhasil dimasuki, jadi ini bukan credential stuffing yang bersembunyi di balik DDoS.

**Aturan yang dipasang pukul 11:01:**

```
DDOS-LOGIN-01  path=/login  per IP  maks 20 permintaan per 60 detik  lebih: tolak (HTTP 429)
DDOS-LOGIN-02  User-Agent = <string bot>  dan  tanpa cookie sesi       tindakan: challenge
```

HTTP 429 adalah kode status "terlalu banyak permintaan". Aturan pertama meloloskan paling banyak 3.800 kali 20 dibagi 60, sekitar 1.267 permintaan per detik dari seluruh bot, di bawah kapasitas portal sekitar 2.500 per detik. Aturan kedua menyaring 95,1% bot yang memakai User-Agent identik, sehingga lalu lintas yang diteruskan turun ke sekitar 640 per detik, dekat dengan normal.

**Kapan cara ini gagal:** bot yang lebih canggih memakai User-Agent acak, membawa cookie, dan menjalankan JavaScript, sehingga aturan kedua tidak menangkapnya; bot yang jumlahnya puluhan ribu dengan laju rendah per alamat lolos dari aturan pertama. Saat itulah CDN dengan kapasitas besar dan pendeteksi bot yang lebih canggih dibutuhkan (bagian 1.13).

### 2.5 Sore hari: PT JAB sebagai ISP (`SOC-2027-0828` dan `SOC-2027-0829`)

Dua kasus sore hari memperlihatkan peran ISP dari dua arah: melindungi pelanggan yang diserang, dan menangani pelanggan yang perangkatnya dipakai menyerang orang lain.

```
Alert   : SOC-2027-0828  Volumetric anomaly to dedicated customer
Waktu   : 2027-08-05 14:35 WIB
Pelanggan : PT Sinar Niaga (fiktif), dedicated internet 1 Gbps, IP 198.51.100.46
Lalu lintas masuk : 6,4 Gbps udp src-port 123 dari 1.812 sumber
                    (contoh 192.0.2.115, 192.0.2.116), rata-rata 468 byte per paket
Link pelanggan    : 100%, layanan pelanggan putus sejak 14:35
Tindakan NOC 14:41: flowspec match dst 198.51.100.46/32, proto udp, src-port 123,
                    packet-length > 200  action: traffic-rate 0
Pulih             : 14:42
```

**Cara membaca:** 6,4 Gbps menuju link 1 Gbps berarti link pelanggan penuh enam kali lipat lebih; pelanggan sendiri tidak bisa berbuat apa-apa di router-nya, karena lalu lintas sudah memenuhi jalur sebelum sampai. PT JAB berada di hulu pelanggan dan punya kapasitas transit jauh lebih besar, jadi 6,4 Gbps itu bisa dibuang di border router PT JAB tanpa mengganggu siapa pun. Aturan Flowspec memakai komponen panjang paket [S12]: jawaban NTP biasa berukuran kecil (sekitar 76 byte termasuk header IP dan UDP), sedangkan jawaban `monlist` jauh lebih besar, sehingga sinkronisasi jam pelanggan tetap berjalan sementara jawaban serangan dibuang. Gangguan pelanggan berlangsung 7 menit (14:35 sampai 14:42).

```
Alert   : SOC-2027-0829  Abuse report: DNS reflection from customer IP
Waktu   : 2027-08-05 16:10 WIB
Sumber laporan : email ke abuse@jab.example dari pemilik jaringan 192.0.2.117
Isi laporan    : "198.51.100.47 mengirim sekitar 380 Mbps jawaban DNS ke 192.0.2.117"
Data flow PT JAB (16:00-16:10):
  masuk  ke 198.51.100.47  udp dst-port 53  dari "192.0.2.117"   9 Mbps   query ANY
  keluar dari 198.51.100.47 udp src-port 53 ke 192.0.2.117      380 Mbps
Pemilik 198.51.100.47 : pelanggan dedicated PT Karya Data (fiktif), server DNS kantor
```

**Cara membaca:** server DNS milik pelanggan PT JAB menerima query ANY yang alamat asalnya dipalsukan menjadi `192.0.2.117`, lalu mengirim jawabannya ke sana. 380 dibagi 9 sekitar 42 kali lipat dalam lebar jalur, dalam kisaran yang wajar untuk DNS amplification (bagian 1.5). Server pelanggan bukan bot dan tidak dibobol; ia resolver terbuka yang menjawab siapa saja, persis pola yang diperingatkan CISA [S6]. Tindakannya: NOC membatasi sementara jawaban DNS keluar dari `198.51.100.47`, tim abuse menghubungi pelanggan supaya membatasi rekursi hanya untuk jaringan kantornya sendiri [S6], lalu membalas pelapor. Query palsu itu datang dari internet, bukan dari jaringan pelanggan PT JAB, jadi BCP 38 di jaringan PT JAB tidak bisa mencegahnya; BCP 38 harus diterapkan di jaringan tempat penyerang berada [S9].

## 3. Perbandingan istilah yang sering tertukar

### 3.1 DoS, DDoS, dan lonjakan sah

Tabel pertama membedakan dua jenis serangan dari lonjakan pengunjung yang sah; cari baris "Ciri di log" karena itulah yang dilihat analyst saat pertama kali menerima alert.

| Aspek | DoS | DDoS | Lonjakan sah (flash crowd) |
|---|---|---|---|
| Jumlah sumber | Satu atau sedikit [S4] | Banyak, sering botnet atau reflector [S4] | Banyak pengguna sungguhan |
| Niat | Mengganggu availability | Mengganggu availability | Memakai layanan |
| Ciri di log | Satu atau beberapa alamat dengan laju sangat tinggi | Ribuan alamat, pola seragam, sering satu port atau path | Banyak alamat, perilaku beragam, ada transaksi berhasil |
| Waktu | Kapan saja | Kapan saja, sering multi-gelombang | Bisa ditebak (jatuh tempo, promo, berita) |
| Penanganan pertama | Blokir atau batasi sumbernya | Identifikasi jenis dan lapisan, libatkan NOC dan upstream | Tambah kapasitas, jangan diblokir |
| Contoh di PT JAB | Skrip mitra yang salah konfigurasi | `INC-2027-083` | Tanggal 20, 1.400 permintaan per detik |

### 3.2 Volumetric, protocol, dan application layer

Tabel kedua membandingkan tiga jenis serangan; cari baris "Alat yang cocok" untuk mengingat pasangan serangan dan pertahanannya.

| Aspek | Volumetric | Protocol | Application layer |
|---|---|---|---|
| Lapisan OSI | 3/4 | 3/4 [S4] | 7 [S4] |
| Yang dihabiskan | Bandwidth | Tabel sesi, memori, CPU perangkat | Pekerja aplikasi, database |
| Satuan | Gbps, Tbps | Mpps | rps |
| Contoh | UDP flood, reflection DNS/NTP/memcached | SYN flood, banjir fragmen | HTTP flood ke `/login` |
| Alamat sumber | Sering palsu atau reflector | Sering palsu | Asli (handshake selesai) |
| Gejala | Link penuh, semua layanan di belakang link lambat | Firewall atau server menolak sambungan baru, padahal link tidak penuh | Link dan firewall normal, aplikasi lambat atau error 503 |
| Alat yang cocok | Upstream: Flowspec, scrubbing, RTBH; CDN dan anycast | SYN cookies, SYN proxy, scrubbing | WAF, rate limiting per path, challenge, CDN dengan WAF |
| Teknik MITRE | T1498 [S15] | T1498 atau T1499 | T1499.003 [S17] |

### 3.3 Alat mitigasi DDoS

Tabel ketiga adalah inti persiapan interview anti-DDoS: setiap alat menangani lapisan tertentu, bekerja di tempat tertentu, dan punya harga sendiri. Cari kolom "Dampak ke lalu lintas sah" karena di situlah keputusan biasanya diperdebatkan.

| Alat | Lapisan | Bekerja di mana | Siapa menjalankan | Dampak ke lalu lintas sah | Kapan dipakai |
|---|---|---|---|---|---|
| Rate limiting | 3/4 dan 7 | Router, firewall, DNS server, WAF | NOC, infrastruktur, SOC | Pengguna yang berbagi IP bisa ikut tertahan | Selalu, dengan ambang yang diuji |
| SYN cookies / SYN proxy | 4 | Server, firewall, load balancer | Infrastruktur | Kecil; sebagian opsi TCP hilang [S8] | SYN flood yang masih muat di jalur |
| RTBH | 3 | Router tepi sendiri atau upstream | NOC dengan upstream | Total: alamat korban tidak terjangkau [S10] | Alamat tidak penting, atau melindungi seluruh jaringan |
| BGP Flowspec | 3/4 | Router tepi sendiri atau upstream | NOC dengan upstream | Kecil bila aturannya spesifik | Pola header jelas (port asal, protokol, ukuran) |
| Scrubbing center | 3/4, bisa 7 bila TLS dibuka | Fasilitas penyedia mitigasi | Penyedia, diaktifkan NOC | Kecil; ada jeda pengalihan pada on-demand | Serangan besar atau berubah-ubah |
| CDN dan anycast | 3/4 dan 7 | Banyak lokasi di seluruh dunia | Penyedia CDN | Kecil; data dan kunci TLS di pihak ketiga | Layanan web publik yang harus selalu tersedia |
| WAF | 7 | Di depan aplikasi web | SOC dan tim aplikasi | Bisa salah tolak pengguna sah | HTTP flood dan serangan aplikasi |

### 3.4 Firewall, IPS, WAF, dan layanan anti-DDoS

Tabel keempat menjawab salah paham yang paling sering: "kita punya firewall, jadi aman dari DDoS". Firewall adalah perangkat yang mengizinkan atau menolak lalu lintas berdasarkan alamat dan port; IPS adalah sistem yang menghadang lalu lintas yang cocok dengan pola serangan; keduanya dibahas lengkap di Day 03. Cari baris "Saat serangan melebihi kapasitas jalur".

| Aspek | Firewall stateful | IPS | WAF | Layanan anti-DDoS (scrubbing, CDN) |
|---|---|---|---|---|
| Fungsi utama | Mengizinkan atau menolak berdasarkan alamat, port, dan status sambungan | Menghadang pola serangan yang dikenali | Menyaring permintaan web | Menyerap dan menyaring volume besar |
| Letak | Di depan jaringan sendiri | Di jalur jaringan sendiri | Di depan aplikasi web | Di hulu, di luar jaringan sendiri |
| Kapasitas | Sebatas perangkat dan jalurnya | Sebatas perangkat | Sebatas perangkat | Sangat besar, tersebar |
| Saat serangan melebihi kapasitas jalur | Tidak menolong, jalur sudah penuh | Tidak menolong | Tidak menolong | Menolong, karena menyaring sebelum jalur |
| Kelemahan khusus DDoS | Tabel sesi bisa habis (bagian 1.6) | Bisa ikut kewalahan memeriksa setiap paket | Hanya L7 | Biaya, jeda pengalihan, data di pihak ketiga |

## 4. Salah paham umum

Butir berikut adalah salah paham yang melintasi beberapa istilah sekaligus. Salah paham yang khusus satu istilah sudah ditulis di subbagiannya.

- **Anggapan:** firewall yang kuat cukup untuk menahan DDoS. **Kenyataannya:** firewall berada di ujung jalur milikmu sendiri. Serangan volumetric memenuhi jalur sebelum sampai ke firewall, dan serangan protocol justru menyasar tabel sesi firewall stateful (bagian 1.6 dan 3.4).
- **Anggapan:** alamat sumber di log DDoS adalah pelakunya. **Kenyataannya:** pada reflection, sumbernya server sah yang dimanfaatkan; pada SYN flood dengan spoofing, sumbernya palsu; pada HTTP flood, sumbernya perangkat korban lain yang dibajak. Pelaku sebenarnya hampir tidak pernah terlihat di log korban (bagian 1.2, 1.5, dan 1.6).
- **Anggapan:** makin besar Gbps, makin berbahaya. **Kenyataannya:** bahaya ditentukan oleh sumber daya mana yang habis. 1,5 Gbps SYN flood menumbangkan firewall, dan HTTP flood yang jauh lebih kecil menumbangkan aplikasi (bagian 1.3).
- **Anggapan:** begitu DDoS selesai, insiden selesai. **Kenyataannya:** SOC memeriksa apakah ada aktivitas lain selama serangan, karena DDoS bisa menjadi pengalih perhatian [S15], lalu menjalankan analisis pasca-insiden, memperbarui rencana respons, dan memperkuat pemantauan sesuai langkah CISA [S4].
- **Anggapan:** ISP hanya perlu melindungi pelanggannya. **Kenyataannya:** ISP juga bertanggung jawab atas lalu lintas yang keluar dari jaringannya: menerapkan BCP 38, menutup reflector milik pelanggan, dan menindaklanjuti perangkat pelanggan yang menjadi bot (bagian 1.15 dan 2.5).
- **Anggapan:** satu alat anti-DDoS menyelesaikan semua jenis serangan. **Kenyataannya:** serangan multi-vector berganti lapisan setiap kali satu pertahanan berhasil. `INC-2027-083` butuh Flowspec, SYN cookies, scrubbing, dan WAF dalam satu jam (bagian 2.1).
- **Anggapan:** amplification factor yang tinggi otomatis berarti serangan besar. **Kenyataannya:** volume akhir juga bergantung pada berapa banyak reflector yang terbuka dan seberapa besar jalur penyerang. Memcached punya BAF sangat tinggi, tetapi jumlah server memcached yang terbuka jauh lebih sedikit dibanding resolver DNS (bagian 1.5 dan 2.2).
- **Anggapan:** DDoS selalu berlangsung berjam-jam, jadi ada waktu untuk menyiapkan respons. **Kenyataannya:** sebagian besar serangan lapisan jaringan berlangsung kurang dari sepuluh menit [S19]. Perlindungan yang baru disiapkan setelah serangan dimulai sering terlambat; itu sebabnya ada model always-on dan mitigasi otomatis (bagian 1.12 dan 5).

## 5. Catatan terkini

Bagian ini mencatat tanggal terbit, revisi dokumen, dan tren serangan yang memengaruhi konteks Day ini, tanpa mengubah konsep di atas.

- **Panduan CISA, FBI, dan MS-ISAC versi 2.0 (21 Maret 2024)** menambahkan pembagian tiga jenis teknik (volumetric, protocol, application), definisi teknis, dan mitigasi per jenis; versi 1.0 terbit Oktober 2022 [S4].
- **Tabel BAF di CISA TA14-017A** terakhir direvisi 18 Desember 2019 (menambahkan WS-Discovery); memcached ditambahkan Februari dan Maret 2018 [S5]. Angka di tabel itu tidak diperbarui sejak 2019, jadi protokol reflection yang ditemukan sesudahnya tidak tercantum. Cek laporan tren terbaru untuk vektor baru.
- **RFC 8955 (Desember 2020)** menggantikan RFC 5575 dan RFC 7674 sebagai spesifikasi Flowspec, dan menambahkan tindakan pembatasan laju dalam paket per detik (traffic-rate-packets) [S12]. Dokumen dan konfigurasi lama masih banyak merujuk RFC 5575.
- **MITRE ATT&CK** terakhir mengubah T1498, T1498.002, dan T1499 pada 24 Oktober 2025 [S15][S16][S17]. MITRE mencatat amplifikasi memcached hingga 51.200 kali, sedikit berbeda dari angka 51.000 di CISA dan GitHub [S16][S5][S18].
- **Cloudflare DDoS Threat Report H1 2026 (11 Agustus 2026)** mencatat 23,2 juta serangan lapisan jaringan dan 29,64 triliun permintaan HTTP DDoS yang dimitigasi pada Januari sampai Juni 2026, 935 serangan di atas 1 Tbps, 90,60% serangan lapisan jaringan selesai dalam kurang dari sepuluh menit, porsi DNS flood naik dari 25,7% ke 40,0% antar kuartal, dan Indonesia di peringkat ketiga negara sumber serangan pada kedua kuartal [S19]. Angka ini hanya dari jaringan satu penyedia, jadi pakai sebagai gambaran tren, bukan ukuran seluruh internet.
- **Riset pengalihan scrubbing (APNIC Blog, 23 April 2026)** memperlihatkan bahwa pengalihan on-demand bisa diamati dari data routing BGP publik, dengan contoh pengalihan yang berlangsung sekitar 8 sampai 22 menit [S20]. Artinya pengaktifan scrubbing on-demand terlihat oleh pihak luar yang memantau routing.

## 6. Cheat sheet

```
DoS          mencegah akses sah / menunda operasi penting; satu atau sedikit sumber
DDoS         DoS dari banyak host; botnet atau reflector; sulit dilacak dan diblokir
BOTNET       perangkat dibajak (PC, router, IoT, server) dikendalikan lewat C2
VOLUMETRIC   habiskan bandwidth; ukur Gbps/Tbps; UDP flood, reflection
PROTOCOL     habiskan tabel sesi/CPU di L3/L4; ukur Mpps; SYN flood, fragmen
APPLICATION  habiskan aplikasi di L7; ukur rps; HTTP flood ke /login, pencarian
UDP FLOOD    banjir UDP; tanpa handshake -> alamat asal mudah dipalsukan
SYN FLOOD    jutaan SYN tanpa ACK -> tabel half-open penuh (RFC 4987)
HTTP FLOOD   permintaan web "sah" dari bot asli; isi terenkripsi TLS
REFLECTION   permintaan dengan alamat asal korban ke server pihak ketiga
AMPLIFICATION jawaban jauh lebih besar dari permintaan
BAF (CISA)   byte payload jawaban / byte payload permintaan
             DNS 28-54 | NTP 556,9 | memcached 10.000-51.000 | CLDAP 56-70 | SSDP 30,8
RATE LIMIT   batasi laju per IP/URL/protokol; tidak menolong bila jalur sudah penuh
SYN COOKIES  state disandikan di sequence number SYN-ACK; tabel tidak pernah penuh
RTBH         buang SEMUA trafik ke alamat korban di tepi/upstream; community 65535:666;
             /32; NO_EXPORT; "menyelesaikan serangan" untuk alamat itu
FLOWSPEC     aturan saring rinci lewat BGP (dst, src, proto, port, panjang paket,
             flag TCP, fragmen); traffic-rate 0 = buang (RFC 8955)
SCRUBBING    alihkan (BGP/DNS) ke penyaring, kembalikan yang bersih (GRE/link);
             always-on vs on-demand; L3/L4 kecuali TLS dibuka
CDN/ANYCAST  satu alamat dari banyak lokasi; serangan tersebar; server asli harus tersembunyi
WAF          L7: rate limit per path, challenge/CAPTCHA, aturan ciri bot
BCP 38       ISP tolak paket pelanggan yang alamat asalnya bukan milik pelanggan
ISP          lindungi pelanggan (hulu), cegah spoofing, tutup reflector, tangani abuse
NOC vs SOC   NOC: jalur, BGP, upstream | SOC: triage, L7, bukti, serangan penumpang

KERANGKA JAWABAN INTERVIEW "BAGAIMANA ANTI-DDoS?"
1. Tujuan: availability; kenali sumber daya yang dihabiskan (bandwidth, state, aplikasi)
2. Sebelum: kenali aset kritis, baseline trafik, kontak darurat ISP, kontrak scrubbing/CDN,
           SYN protection aktif, rate limit WAF, rencana respons dan komunikasi
3. Saat: identifikasi jenis dan lapisan -> pilih alat:
         volumetric -> hulu (Flowspec, scrubbing, RTBH bila terpaksa)
         protocol   -> SYN cookies/proxy, scrubbing
         L7         -> WAF, rate limit, challenge, CDN
         + awasi serangan penumpang, kumpulkan bukti, komunikasi
4. Sesudah: analisis pasca-insiden, perbaiki celah, perbarui rencana, latih ulang
5. Sebut trade-off: RTBH mengorbankan korban; on-demand ada jeda; CDN butuh kunci TLS
```

## 7. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "PT JAB punya NGFW dengan IPS di depan portal, jadi portal sudah terlindungi dari DDoS." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Firewall dan IPS berada di ujung jalur milik PT JAB sendiri. Serangan volumetric 42 Gbps memenuhi link 10 Gbps sebelum lalu lintas sampai ke firewall, sehingga perangkat sebagus apa pun tidak sempat bekerja. Serangan protocol seperti SYN flood justru menyasar tabel sesi firewall stateful, seperti yang membuat `jkt-fw01` tumbang. Perlindungan DDoS butuh alat di hulu (Flowspec, scrubbing, CDN) dan alat khusus per lapisan. Lihat bagian 1.6, 3.4, dan 4.

</details>

**2. Skenario keputusan.** Portal diserang 42 Gbps NTP reflection, dan link ke data center hanya 10 Gbps. Langkah mana yang paling tepat?

- A. Masukkan 15.377 alamat server NTP itu ke daftar blokir `jkt-fw01`.
- B. Minta NOC memasang Flowspec yang membuang UDP dari port 123 ke `203.0.113.8/32`, dan kirim aturan itu ke upstream supaya dibuang sebelum memenuhi link.
- C. Tambah dua server portal lagi di belakang load balancer.

<details><summary>Jawaban</summary>

B. Serangan volumetric harus dibuang di hulu, sebelum titik sempit, dan Flowspec bisa memilih pola yang spesifik (UDP dari port 123 ke satu alamat) tanpa mengorbankan lalu lintas HTTPS ke portal. A keliru karena aturan di `jkt-fw01` bekerja setelah link sudah penuh, dan alamat itu adalah server NTP sah yang berganti setiap serangan. C keliru karena masalahnya ada di jalur, bukan di kapasitas server; server tambahan di data center yang sama tetap di belakang link yang penuh. Lihat bagian 1.5, 1.11, dan 2.2.

</details>

**3. Pertanyaan jebakan.** "Alamat `192.0.2.111` mengirim 92 Mbps ke portal saat gelombang pertama, jadi pemiliknya adalah penyerang dan harus dilaporkan ke polisi." Benarkah?

<details><summary>Jawaban</summary>

Tidak. `192.0.2.111` adalah server NTP lama milik sebuah pabrik yang dipakai sebagai reflector. Penyerang mengirim permintaan `monlist` ke server itu dengan alamat asal palsu `203.0.113.8`, lalu server menjawab ke portal. Pemiliknya korban salah konfigurasi, bukan pelaku. Tindakan yang berguna adalah memberi tahu pemilik jaringannya lewat kontak abuse supaya server itu diperbarui atau `monlist` dimatikan. Lihat bagian 1.2 dan 1.5.

</details>

**4. Skenario keputusan.** Scrubbing L3/L4 sudah aktif, tetapi portal kembali lambat. Log WAF menunjukkan 46.000 permintaan per detik ke `/login` dari 3.800 alamat yang semuanya menyelesaikan handshake. Apa langkah yang paling tepat?

- A. Minta NOC mem-blackhole `203.0.113.8/32` supaya serangan berhenti.
- B. Periksa apakah ada login yang berhasil dari alamat penyerang, lalu pasang rate limiting per IP untuk `/login` dan challenge untuk ciri bot di WAF.
- C. Tunggu, karena scrubbing akan menyaringnya otomatis dalam beberapa menit.

<details><summary>Jawaban</summary>

B. Ini HTTP flood di lapisan 7: alamatnya asli dan isinya terenkripsi, jadi hanya perangkat yang membuka TLS seperti WAF yang bisa membedakannya. Pemeriksaan login berhasil memastikan serangan ini tidak menyembunyikan credential stuffing. A keliru karena blackhole membuat portal tidak terjangkau sama sekali, sama saja menyelesaikan tujuan penyerang. C keliru karena scrubbing L3/L4 melihat permintaan ini sebagai lalu lintas sempurna dan tidak bisa membaca isi HTTPS. Lihat bagian 1.7, 1.12, 1.14, dan 2.4.

</details>

**5. Jelaskan ulang.** Jelaskan kepada anggota keluargamu yang bukan orang IT, dalam tiga kalimat, apa itu DDoS dan apa itu serangan reflection.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "DDoS itu seperti ribuan orang suruhan yang menyerbu sebuah toko bersamaan, sampai pembeli sungguhan tidak bisa masuk; tidak ada yang dicuri, tetapi toko tidak bisa melayani. Orang suruhannya biasanya komputer atau router rumah yang sudah dibajak tanpa pemiliknya sadar. Serangan reflection itu seperti memesan makanan ke seratus restoran atas nama tetangga supaya semuanya diantar ke rumahnya: pesanannya singkat, kirimannya besar, dan yang datang kurir sungguhan, bukan penyerangnya."

Kesalahan yang sering muncul:
- Menyamakan DDoS dengan peretasan atau pencurian data.
- Menyebut alamat di log sebagai pelaku, padahal hampir semuanya perangkat korban lain atau server sah.
- Lupa menjelaskan kenapa reflection memperbesar serangan: jawabannya jauh lebih besar dari permintaannya.

</details>

**6. Pertanyaan jebakan.** "Amplification factor DNS menurut CISA sekitar 50, jadi penyerang dengan jalur 1 Gbps pasti menghasilkan tepat 50 Gbps di korban." Benarkah?

<details><summary>Jawaban</summary>

Tidak tepat. BAF menurut CISA menghitung byte payload saja, tanpa header. Dengan header IP dan UDP sebesar 28 byte, query 64 byte yang dijawab 3.200 byte menghasilkan perbandingan lebar jalur sekitar 3.228 dibagi 92, yaitu sekitar 35 kali, bukan 50. Volume akhir juga bergantung pada jumlah reflector yang mau menjawab dan kapasitas jalur mereka. Lihat bagian 1.5.

</details>

**7. Interview question (English).** "Our company's customer portal is hit by a DDoS attack. How would you defend against it, before, during, and after the attack? Which tools would you use for which type of attack?"

<details><summary>Sample answer</summary>

"I start from the goal of the attack, which is availability, and ask which resource is being exhausted: bandwidth, connection state, or application capacity. That decides where the traffic has to be dropped, because the bigger the attack, the further upstream it must be filtered. Before an attack, I want a baseline of normal traffic, emergency contacts at our upstream providers, a scrubbing or CDN service already contracted, SYN protection enabled on the firewalls, rate limits on expensive pages like login, and an incident and communication plan. During an attack, the network team and the SOC identify the type together. For a volumetric reflection flood, for example DNS or NTP amplification, filtering at our own firewall is too late, so we push BGP Flowspec rules upstream, for instance dropping UDP from source port 123 to the victim address, or divert to a scrubbing center. Remote triggered blackholing is the last resort, because it protects the rest of the network by making the victim address unreachable, which completes the attack for that service. For a SYN flood, SYN cookies or a SYN proxy keep the state table from filling. For an HTTP flood the packets look perfect at layers 3 and 4, so we need a WAF or CDN that terminates TLS, with per-IP rate limiting and bot challenges. Throughout, the SOC checks whether the DDoS is covering something else, like credential stuffing, and collects evidence. Afterwards we run a post-incident review, fix the gaps, such as features that should have been on, and update the plan. As an ISP we also have a duty outward: source address validation per BCP 38, closing open resolvers on customer networks, and notifying customers whose devices are part of a botnet."

What makes this answer strong: it organizes the answer around the resource being exhausted and the before, during, and after phases from government guidance, matches each attack type to the right tool and location, names real mechanisms (Flowspec, RTBH, SYN cookies, scrubbing, WAF) together with their trade-offs, keeps the SOC role visible in an attack often seen as purely a network problem, and adds the ISP responsibility that interviewers at a service provider expect.

</details>

## 8. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | NIST CSRC Glossary: denial of service | https://csrc.nist.gov/glossary/term/denial_of_service | primer (glosarium NIST, dari CNSSI 4009-2022, SP 800-12 Rev. 1, SP 800-82r3) | diakses 2026-10-21 | Tinggi. Definisi DoS |
| S2 | NIST CSRC Glossary: distributed denial of service | https://csrc.nist.gov/glossary/term/distributed_denial_of_service | primer (glosarium NIST, dari NISTIR 7711) | diakses 2026-10-21 | Tinggi. Definisi DDoS |
| S3 | NIST CSRC Glossary: botnet | https://csrc.nist.gov/glossary/term/botnet | primer (glosarium NIST, dari SP 1800-15B/C yang mengutip Kaspersky) | diakses 2026-10-21 | Sedang-tinggi. Definisi botnet; asal definisinya dari vendor |
| S4 | CISA, FBI, MS-ISAC: Understanding and Responding to Distributed Denial-of-Service Attacks | https://www.cisa.gov/sites/default/files/publications/understanding-and-responding-to-ddos-attacks_508c.pdf | primer (panduan pemerintah AS) | versi 2.0, 21 Maret 2024; diakses 2026-10-21 | Tinggi. DoS vs DDoS, tiga jenis teknik, langkah sebelum, saat, dan sesudah serangan, CAPTCHA, CDN, peran ISP |
| S5 | CISA Alert TA14-017A: UDP-Based Amplification Attacks | https://www.cisa.gov/news-events/alerts/2014/01/17/udp-based-amplification-attacks | primer (alert pemerintah AS) | 2014, revisi terakhir 18 Desember 2019; diakses 2026-10-21 | Tinggi. Definisi BAF dan tabel angkanya, RTBH, BCP 38, rate limiting, deteksi oleh ISP |
| S6 | CISA Alert TA13-088A: DNS Amplification Attacks | https://www.cisa.gov/news-events/alerts/2013/03/29/dns-amplification-attacks | primer (alert pemerintah AS) | 29 Maret 2013, revisi 4 Juni 2019; diakses 2026-10-21 | Tinggi. Resolver terbuka, query ANY, pembatasan rekursi, RRL |
| S7 | CISA Alert TA14-013A: NTP Amplification Attacks Using CVE-2013-5211 | https://www.cisa.gov/news-events/alerts/2014/01/13/ntp-amplification-attacks-using-cve-2013-5211 | primer (alert pemerintah AS) | 13 Januari 2014, revisi 6 Oktober 2016; diakses 2026-10-21 | Tinggi. `monlist` 600 alamat, ntpd sebelum 4.2.7 |
| S8 | RFC 4987: TCP SYN Flooding Attacks and Common Mitigations | https://www.rfc-editor.org/rfc/rfc4987.html | primer (IETF, informational) | Agustus 2007; diakses 2026-10-21 | Tinggi. Mekanisme SYN flood, TCB, SYN cookies dan kekurangannya, SYN cache, proxy |
| S9 | RFC 2827 (BCP 38): Network Ingress Filtering | https://www.rfc-editor.org/rfc/rfc2827.html | primer (IETF, BCP 38) | Mei 2000; diakses 2026-10-21 | Tinggi. Penyaringan alamat asal di tepi penyedia |
| S10 | RFC 5635: Remote Triggered Black Hole Filtering with Unicast Reverse Path Forwarding (uRPF) | https://www.rfc-editor.org/rfc/rfc5635.html | primer (IETF, informational) | Agustus 2009; diakses 2026-10-21 | Tinggi. Destination-based dan source-based RTBH, kelemahannya |
| S11 | RFC 7999: BLACKHOLE Community | https://www.rfc-editor.org/rfc/rfc7999.html | primer (IETF, informational) | Oktober 2016; diakses 2026-10-21 | Tinggi. Community `65535:666`, `/32`, NO_EXPORT, prefix lebih spesifik dari `/24` biasanya tidak diterima, risiko penyalahgunaan |
| S12 | RFC 8955: Dissemination of Flow Specification Rules | https://www.rfc-editor.org/rfc/rfc8955.html | primer (standar IETF) | Desember 2020; diakses 2026-10-21 | Tinggi. Komponen pencocokan, tindakan, laju nol, validasi; menggantikan RFC 5575 dan 7674 |
| S13 | NIST SP 800-189: Resilient Interdomain Traffic Exchange: BGP Security and DDoS Mitigation | https://csrc.nist.gov/pubs/sp/800/189/final | primer (publikasi NIST) | Desember 2019; diakses 2026-10-21 | Tinggi. RTBH, Flowspec, RRL, pembatasan fragmen UDP oleh ISP |
| S14 | RFC 4786 (BCP 126): Operation of Anycast Services | https://www.rfc-editor.org/rfc/rfc4786.html | primer (IETF, BCP 126) | Desember 2006; diakses 2026-10-21 | Tinggi. Definisi anycast dan manfaatnya terhadap DoS |
| S15 | MITRE ATT&CK T1498: Network Denial of Service | https://attack.mitre.org/techniques/T1498/ | primer (basis pengetahuan MITRE) | versi 1.2, diubah 2025-10-24; diakses 2026-10-21 | Tinggi. Motif (termasuk pengalih perhatian dan pemerasan), sub-teknik, mitigasi di hulu |
| S16 | MITRE ATT&CK T1498.002: Reflection Amplification | https://attack.mitre.org/techniques/T1498/002/ | primer (basis pengetahuan MITRE) | versi 1.4, diubah 2025-10-24; diakses 2026-10-21 | Tinggi. Reflector, alamat palsu, amplifikasi memcached hingga 51.200 kali |
| S17 | MITRE ATT&CK T1499: Endpoint Denial of Service | https://attack.mitre.org/techniques/T1499/ | primer (basis pengetahuan MITRE) | versi 1.2, diubah 2025-10-24; diakses 2026-10-21 | Tinggi. Beda dengan T1498, sub-teknik T1499.003 dan T1499.004 |
| S18 | GitHub Blog: February 28th DDoS Incident Report | https://github.blog/news-insights/company-news/ddos-incident-report/ | primer (laporan korban) | 1 Maret 2018; diakses 2026-10-21 | Tinggi. 1,35 Tbps, 126,9 Mpps, memcached UDP, hingga 51 KB per byte, pengalihan ke penyedia mitigasi |
| S19 | Cloudflare DDoS Threat Report H1 2026 | https://blog.cloudflare.com/ddos-threat-report-2026-h1/ | sekunder (laporan vendor) | 11 Agustus 2026; diakses 2026-10-21 | Sedang-tinggi. Data satu jaringan penyedia; Indonesia peringkat tiga sumber, durasi serangan, porsi DNS flood |
| S20 | APNIC Blog: Detecting and characterizing DDoS scrubbing from global BGP routing | https://blog.apnic.net/2026/04/23/detecting-and-characterizing-ddos-scrubbing-from-global-bgp-routing/ | sekunder (blog riset) | 23 April 2026; diakses 2026-10-21 | Sedang-tinggi. Definisi scrubbing, always-on vs on-demand, pengalihan lewat BGP |
| S21 | Kaspersky DDoS Protection: Configuring Always-On KDP-IP and On-Demand KDP-IP schemes | https://support.kaspersky.com/KDP/1.0/en-US/205380.htm | sekunder (dokumentasi vendor) | diakses 2026-10-21 | Sedang. Contoh nyata pengalihan lewat BGP atau record DNS dan terowongan GRE ke scrubbing center |

**Catatan sumber:** semua angka amplification factor di bagian 1.5 dan cheat sheet berasal dari CISA TA14-017A [S5]; angka 51.200 dari MITRE [S16] dan 51 KB per byte dari GitHub [S18] disebut terpisah karena sedikit berbeda. Pembagian satuan bps, pps, dan rps per jenis serangan (bagian 1.3) adalah kebiasaan di lapangan, bukan definisi dari sumber primer. Cara kerja pengembalian lalu lintas bersih lewat GRE hanya bersumber dari dokumentasi satu vendor [S21]; sumber riset [S20] tidak membahas mekanisme pengembaliannya. Ukuran paket NTP biasa (sekitar 76 byte termasuk header) adalah fakta dasar protokol yang tidak diberi rujukan tersendiri. Seluruh lini waktu, data flow, alert, log WAF, aturan Flowspec, nama perusahaan pelanggan, dan alamat di bagian 1 dan 2 adalah ilustrasi untuk organisasi fiktif PT JAB, bukan hasil eksekusi nyata.
