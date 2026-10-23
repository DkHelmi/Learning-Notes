---
day: 16
title: 'DNS terenkripsi dan QUIC: DoH, DoT, DoQ, serta apa yang masih terbaca di HTTP/3'
researched_on: 2026-10-23
versions_checked: 'Wireshark 4.6.9 (display filter reference quic dan tls); Zeek 9.0.0 (QUIC::Info dan quic.log, cabang release/9.0); Suricata 8.0.7 (EVE quic, QUIC keywords, parser doh2; CVE-2026-94083 diperbaiki di 8.0.7); RFC 8484, 7858, 9250, 9000, 9001, 9114, 9312, 9369, 9462, 9849; MITRE ATT&CK T1572 v1.1 (diubah 3 September 2026); kebijakan Microsoft Edge DnsOverHttpsMode (Edge 83 ke atas) dan QuicAllowed (Edge 77 ke atas), halaman 20 Mei 2026; Mozilla canary domain use-application-dns.net'
---

# Day 16: DNS terenkripsi dan QUIC

Cakupan: tiga cara DNS disembunyikan dari pengamat jaringan (DoT, DoQ, DoH), apa yang sebenarnya masih bisa dibaca dari trafik QUIC dan HTTP/3 meski terlihat seperti UDP acak, dan cara memakai posisi sensor, proxy, firewall, serta ketiadaan jejak yang seharusnya ada untuk tetap menjawab pertanyaan investigasi.

## Ide inti

Selama ini DNS adalah sumber terbaik untuk mengetahui apa yang hendak dihubungi sebuah host (Day 05), dan SNI di ClientHello adalah pengganti terakhir ketika isi HTTPS tertutup (Day 06). Day ini membahas apa yang terjadi ketika keduanya ikut dibungkus. DNS bisa berjalan di atas TLS (DoT), di atas QUIC (DoQ), atau di dalam HTTPS biasa (DoH); web bisa berjalan di atas QUIC (HTTP/3) yang tampak seperti UDP acak. Gagasan intinya: kebutaan ini tidak merata. DoT dan DoQ memakai port khusus 853 sehingga mudah dikenali; DoH sengaja dirancang supaya tidak bisa dibedakan dari HTTPS; dan paket Initial QUIC, yang membawa ClientHello lengkap dengan SNI dan ALPN, bisa didekripsi oleh pengamat mana pun karena kuncinya diturunkan dari nilai yang terlihat di paket itu sendiri. Analis yang memahami lapisan mana yang menipis tidak berhenti di kata "terenkripsi", tetapi pindah ke hal di sekitarnya: port, tujuan, paket Initial, posisi sensor terhadap proxy dan firewall, dan ketiadaan jejak yang seharusnya ada.

Kamu sudah mengenal pola ini dari NOC. Ketika trafik pelanggan masuk ke tunnel IPsec, kamu kehilangan port dan isi, tetapi masih melihat ujung tunnel, ukuran, dan pertukaran IKE_SA_INIT yang tidak terenkripsi sebelum tunnel naik. Paket Initial QUIC mirip IKE_SA_INIT: tahap awal yang terbaca sebelum isi tertutup. Batas analoginya: Initial QUIC secara teknis terenkripsi, hanya kuncinya bisa diturunkan siapa saja, dan isinya justru lebih kaya daripada IKE_SA_INIT karena membawa nama tujuan (SNI). Untuk DNS terenkripsi, bandingkan trafik manajemen out-of-band di port atau VLAN khusus (mudah di-ACL dan dihitung) dengan trafik manajemen in-band yang menumpang di jalur data pelanggan: DoT dan DoQ seperti yang pertama, DoH seperti yang kedua. ACL berbasis port bekerja untuk DoT dan DoQ; DoH hanya bisa dikenali dari tujuan dan pola.

```
 JKT-WS-2078 10.10.60.163                          jkt-proxy01 10.20.3.60:3128           internet
   |                                                       |
   |-- (1) CONNECT doh.quadresolve.example:443 ----------->|-- TLS ke 203.0.113.190:443 (DoH, isi tertutup)
   |       hop core: http.log CONNECT, sumber = WS          |   hop egress: ssl.log, sumber = proxy
   |
   |-- (2) UDP 443 QUIC Initial ke 203.0.113.191 ---X jkt-fw01 deny
   |       TAP sisi dalam jkt-fw01 tetap melihat paket: quic.log server_name + ALPN, history "I"
   |
   |-- (3) CONNECT 203.0.113.191:443 (alamat IP) ------->|-- TLS ke 203.0.113.191:443
   v
 index=dns (jkt-res01/02) dan dns.log sensor: TIDAK ADA query cfg.edge-relay.example
 => nama tujuan hanya terbaca dari Initial QUIC yang ditolak; resolusinya lewat DoH
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan sekitar 1.200 karyawan, kantor pusat dan data center di Jakarta, dan NOC 24/7 yang satu lantai dengan SOC. Sejak Mei 2027 PT JAB menjalankan "Program NSM PT JAB": Zeek `jkt-zeek01` (`10.20.70.12`) dan Suricata `jkt-ids01` (`10.20.70.11`) menerima trafik dari TAP egress Jakarta di sisi dalam firewall `jkt-fw01` dan dari SPAN core switch data center lewat packet broker `jkt-npb01`; ring buffer pcap `jkt-pcap01` merekam egress. Workstation kantor bertanya DNS ke resolver `jkt-res01` (`10.20.2.53`) dan `jkt-res02` (`10.20.2.54`), keluar ke web hanya lewat proxy eksplisit `jkt-proxy01` (`10.20.3.60:3128`, Squid dengan SslBump), dan koneksi langsung workstation ke internet ditolak firewall. Senin 2027-06-14 tim menyusun peta celah visibilitas akibat ECH (Day 15). Selasa 2027-06-15 muncul empat alert yang semuanya menyentuh DNS terenkripsi atau QUIC: `SOC-2027-0675` (firewall menolak TCP dan UDP 853 dari `JKT-WS-2076`), `SOC-2027-0676` (correlation search baru "DNS diam, koneksi tetap" untuk `JKT-WS-2076`), `SOC-2027-0677` (`quic.log` mencatat Initial QUIC berkala dari `JKT-WS-2078` ke tujuan yang tidak pernah di-resolve), dan `SOC-2027-0678` (lonjakan alur UDP baru ke portal pelanggan `198.51.100.216`). Rabu 2027-06-16 pukul 08:30, SOC lead Dimas Prasetyo menulis kepadamu, dengan Manajer NOC Bambang Hartono di CC:

> "Setelah peta ECH hari Senin, sekarang DNS dan QUIC. Empat alert kemarin semuanya soal ini. Tolong jelaskan dulu DoH, DoT, DoQ itu bedanya apa dan mana yang bisa kita lihat. Kalau ada host yang pakai DoH lewat proxy kita, bagaimana kita tahu tanpa bisa membaca isinya? QUIC katanya terenkripsi penuh; apa yang masih terlihat, dan benarkah kita bisa membaca nama tujuannya walaupun firewall menolaknya? Kenapa alur QUIC kelihatan putus-putus di conn.log dan di flow? Apakah cukup menganggap semua UDP 443 itu QUIC? Pak Bambang tanya dua hal: lonjakan alur UDP ke portal semalam itu serangan atau bukan, dan bisakah RTT pelanggan ke portal diukur dari spin bit. Terakhir, apa sebaiknya kita blokir, dan kapan salah satu alert ini boleh jadi insiden? Rapat jam 14:00."

Pesan itu memuat delapan pertanyaan:

1. Apa beda DoH, DoT, dan DoQ, dan mana yang bisa dikenali dari jaringan?
2. Bagaimana mengenali pemakaian DoH tanpa membaca isinya, terutama di balik proxy eksplisit?
3. Apa yang masih terlihat dari QUIC, dan benarkah SNI terbaca walaupun koneksinya ditolak firewall?
4. Apa yang tidak terlihat dari QUIC, dan kenapa alurnya tampak putus di `conn.log` dan flow?
5. Bagaimana mengenali QUIC, dan apakah UDP 443 cukup sebagai penanda?
6. Lonjakan alur UDP baru ke portal: serangan atau perpindahan koneksi pelanggan?
7. Bisakah RTT diukur dari spin bit, dan seberapa bisa dipercaya?
8. Apa yang sebaiknya diblokir atau diatur, dan kapan sebuah alert boleh menjadi insiden?

Pertanyaan 1 dijawab di bagian 1.1, pertanyaan 2 di bagian 1.2, pertanyaan 3 di bagian 1.3, pertanyaan 4 di bagian 1.4, pertanyaan 5 di bagian 1.5, pertanyaan 6 di bagian 1.6, pertanyaan 7 di bagian 1.7, dan pertanyaan 8 di bagian 1.8 dan 1.9. Bagian 2 berisi artefak hari Rabu: firewall dan Zeek untuk DoT dan DoQ (`SOC-2027-0675`), jejak DoH dan baseline rasio DNS (`SOC-2027-0676`), SNI dan ALPN dari Initial QUIC (`SOC-2027-0677`), perangkaian `JKT-WS-2078` sampai pembukaan `INC-2027-075`, alur QUIC portal (`SOC-2027-0678`), pengukuran RTT, peta visibilitas, dan jawaban untuk Dimas dan Bambang.

**Kapan relevan:** saat sebuah host tiba-tiba hilang dari log resolver padahal tetap aktif; saat SNI atau nama tujuan dibutuhkan dari trafik UDP 443; saat menilai apakah alert "DoH" atau "port 853" berarti pelanggaran kebijakan, alat privasi, atau penyembunyian C2; saat tim jaringan bertanya soal timeout UDP, alur QUIC yang putus, atau RTT pasif; dan saat menyusun peta visibilitas untuk manajemen.
**Kapan bukan jawaban:** saat yang dibutuhkan adalah isi query DoH atau isi stream QUIC, karena tanpa kunci sah keduanya tertutup; saat ECH dipakai di atas QUIC, karena SNI di Initial tidak lagi menunjukkan tujuan sebenarnya (Day 15); saat trafik tidak lewat sensor (antar workstation di switch akses yang sama, laptop di luar kantor, kantor cabang); dan saat yang dibutuhkan adalah proses di host, karena itu pekerjaan data endpoint.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (pcap, SPAN, TAP, ring buffer, `uid`, `conn_state`, `history` di `conn.log`, SNI, ALPN, JA3/JA4, splice, bump, ECH, flow, timeout flow, beacon, prevalence) tidak diulang; definisinya ada di Day 01 sampai 15 [S7]. Tabel ini memuat istilah yang dipakai Day ini; kolom kanan memakai padanan dari pekerjaan NOC dan ISP.

| Istilah | Arti singkat | Padanan di NOC/ISP |
|---|---|---|
| DoT (DNS over TLS) | DNS di dalam TLS di atas TCP port 853 | Manajemen out-of-band di port khusus |
| DoQ (DNS over QUIC) | DNS di atas koneksi QUIC khusus, UDP port 853 | Sama, tetapi lewat transport UDP |
| DoH (DNS over HTTPS) | DNS sebagai pesan HTTP di dalam HTTPS, biasanya port 443 | Manajemen in-band yang menumpang di jalur data pelanggan |
| Resolver terenkripsi | Server DNS yang menerima DoT, DoH, atau DoQ | Resolver ISP yang hanya bisa dijangkau lewat tunnel |
| DDR (Discovery of Designated Resolvers) | Cara klien menemukan versi terenkripsi dari resolver yang sudah dipakainya, lewat query SVCB `_dns.resolver.arpa` | Mengumumkan endpoint layanan lewat DHCP option |
| Canary domain | Nama khusus yang jawabannya dipakai browser untuk memutuskan apakah DoH bawaan dimatikan | Prefiks "penanda" yang dipakai untuk menguji apakah filter aktif |
| QUIC | Transport terenkripsi di atas UDP, versi 1 di RFC 9000 | Transport baru yang membawa sesi seperti TCP plus TLS sekaligus |
| HTTP/3 | HTTP yang berjalan di atas QUIC, ALPN `h3` | Layanan yang sama dengan media transport berbeda |
| Long header dan short header | Dua bentuk header QUIC: long untuk handshake (membawa versi), short untuk data setelah handshake | Header kontrol saat sesi dibangun vs header ringkas di data plane |
| Paket Initial | Paket long header pertama yang membawa ClientHello; kuncinya diturunkan dari konstanta versi dan DCID klien | IKE_SA_INIT yang terbaca sebelum tunnel naik |
| Connection ID (DCID, SCID) | Penanda koneksi QUIC yang dipilih endpoint, terlepas dari alamat dan port | Session ID yang tidak bergantung pada 5-tuple |
| Version Negotiation, Retry | Paket QUIC tak terenkripsi untuk menawar versi dan memvalidasi alamat klien | Pesan kontrol sebelum sesi terbentuk |
| Connection migration | Koneksi QUIC pindah ke alamat atau port baru tanpa handshake ulang | Sesi pelanggan pindah port CGNAT atau BNG tanpa putus |
| NAT rebinding | Alamat atau port klien berubah karena NAT di jalur, bukan karena endpoint | Port PBA CGNAT yang berganti saat mapping kedaluwarsa |
| Idle timeout | Batas diam sebelum state alur dihapus oleh endpoint, firewall, atau NAT | UDP timeout di tabel NAT atau firewall |
| Spin bit | Satu bit di short header yang berganti nilai sekali per RTT | Probe latency pasif di jalur |
| Handshake RTT | RTT yang diukur dari jeda paket handshake QUIC | RTT dari SYN dan SYN-ACK di probe |

### 1.1 Tiga cara DNS disembunyikan

Pertanyaan pertama Dimas menentukan cara membaca dua alert Selasa: `SOC-2027-0675` menyebut port 853, sedangkan `SOC-2027-0676` hanya menyebut "DNS diam". Keduanya bisa berasal dari host yang sama, tetapi meninggalkan jejak yang sangat berbeda.

Tabel ini membandingkan ketiganya dari posisi pengamat jaringan. Cari kolom terakhir: itulah yang menentukan apakah filter port cukup.

| Nama | Dasar | Transport dan port | Terlihat sebagai apa di jaringan |
|---|---|---|---|
| DoT | RFC 7858 | TLS di atas TCP port 853 [S2] | Trafik TLS di port khusus, mudah dikenali |
| DoQ | RFC 9250 | QUIC di atas UDP port 853 [S3] | Trafik QUIC di port khusus, mudah dikenali |
| DoH | RFC 8484 | HTTP di atas TLS, port 443 secara konvensi [S1] | Tidak bisa dibedakan dari HTTPS biasa |

Perbedaan baris ketiga itu bukan kebetulan. RFC 8484 menyatakan tidak memberikan cara untuk mengenali trafik DoH, dan justru menyebut bahwa memakai port 443 serta mencampur DoH dengan trafik HTTPS lain pada koneksi yang sama dapat mencegah perangkat di jalur yang tidak berwenang mengganggunya dan mempersulit analisis trafik [S1]. Sulit dikenali adalah sifat yang memang dirancang. Pesan DoH sendiri adalah pesan DNS biasa dengan media type `application/dns-message`, dikirim lewat GET (query di-encode base64url di parameter `dns`) atau POST [S1]; bentuk ini hanya terlihat oleh pihak yang memegang kunci TLS, misalnya proxy yang mem-bump koneksi.

Dampaknya dinyatakan langsung di dokumennya: sistem penyaringan atau inspeksi yang bergantung pada transport DNS yang tidak diamankan tidak akan berfungsi di lingkungan DoH [S1]. Kalimat ini layak dibawa ke rapat jam 14:00, karena ia datang dari standarnya sendiri, bukan dari pendapat vendor.

Untuk DoT, port 853 ditetapkan sebagai port bawaan, dan RFC 7858 melarang port itu dipakai untuk DNS cleartext [S2]. Untuk DoQ, ada aturan yang berguna bagi pemeriksa: klien dan server DoQ tidak boleh memakai UDP port 53, dan port 853 untuk DoQ direservasi khusus [S3]. Jadi trafik QUIC ke port 853 praktis selalu DoQ, dan TLS ke TCP 853 praktis selalu DoT. ALPN juga membantu: RFC 9462 memakai token `dot` untuk DoT, `h2` untuk DoH, dan `doq` untuk DoQ dalam contoh rekaman penemuannya [S19], sehingga `quic.log` yang mencatat `client_protocol` `doq` di port 853 adalah DoQ.

Ada jalur keempat yang membuat host berpindah ke DNS terenkripsi tanpa konfigurasi manual: DDR. Klien yang sudah memakai resolver tertentu mengirim query SVCB (tipe 64) untuk `_dns.resolver.arpa`; bila resolver menjawab dengan endpoint terenkripsi (ALPN `dot`, `h2`, atau `doq`), klien bisa pindah ke endpoint itu [S19]. Sebelum memakainya secara otomatis, klien wajib memverifikasi bahwa sertifikat resolver terenkripsi memuat alamat IP resolver lama [S19]. Bagi pemeriksa, ini berarti satu hal praktis: query `_dns.resolver.arpa` di log resolver adalah tanda klien mencoba upgrade, dan resolver internal yang tidak menjawabnya membuat klien tetap di DNS polos. `jkt-res01` dan `jkt-res02` tidak mengumumkan endpoint terenkripsi, jadi DDR tidak memindahkan workstation PT JAB ke mana pun; yang perlu diawasi adalah host yang memakai resolver publik secara langsung.

Di PT JAB, `SOC-2027-0675` berisi penolakan firewall untuk TCP 853 dan UDP 853 dari `JKT-WS-2076` ke `203.0.113.190`. Itu definitif: DoT dan DoQ dicoba, dan ditolak. Yang belum terjawab adalah apa yang dilakukan host itu setelah ditolak; bagian 1.2 membahasnya.

### 1.2 Mengenali DoH tanpa membacanya

Pertanyaan kedua Dimas muncul dari `SOC-2027-0676`: jumlah query `JKT-WS-2076` ke resolver internal anjlok, tetapi koneksinya lewat proxy tetap. Setelah DoT dan DoQ ditolak, alat di host itu jatuh ke DoH, yang lolos karena berjalan sebagai HTTPS biasa lewat proxy.

Karena isinya tidak terbaca dan portnya sama dengan HTTPS biasa, pengenalan DoH bersandar pada hal di sekitarnya:

1. **Tujuan.** Daftar penyedia DoH publik yang dikenal, dicocokkan dengan alamat tujuan atau nama host. Ini jalur paling praktis, tetapi daftarnya harus dirawat dan tidak pernah lengkap.
2. **Jalur penemuan.** Sebelum klien memakai DoH, ia biasanya perlu menemukan penyedianya, dan sebagian jalur penemuan itu melewati DNS biasa: nama penyedia di-resolve dulu, atau DDR mengirim query `_dns.resolver.arpa` [S19]. Rekaman HTTPS dan SVCB di DNS juga dibahas di Day 15.
3. **Pola lalu lintas.** Kueri DNS punya bentuk khas: banyak transaksi kecil, berumur pendek, dengan ukuran permintaan dan jawaban dalam rentang sempit. Pola itu berbeda dari trafik web biasa yang punya sedikit permintaan besar.
4. **Ketiadaan DNS polos.** Host yang tiba-tiba berhenti mengirim kueri DNS polos tetapi tetap menghubungi banyak alamat baru hampir pasti memakai resolver terenkripsi. Ketiadaan itu sendiri adalah sinyal.

Poin keempat yang paling sering terlewat dan paling berguna. Bangun baseline jumlah kueri DNS polos per host, lalu cari host yang nilainya turun drastis sementara jumlah koneksi keluarnya tetap. Correlation search di balik `SOC-2027-0676` adalah penerapan langsung poin ini.

Proxy eksplisit mengubah posisi pengamatan, dan untuk DoH perubahannya menguntungkan. Di PT JAB, setiap koneksi HTTPS workstation dimulai dengan `CONNECT host:port` ke `jkt-proxy01`. Klien DoH yang memakai proxy sistem karena itu meninggalkan dua jejak yang tidak tertutup enkripsi: baris `CONNECT doh.quadresolve.example:443` di log proxy dan di `http.log` hop core (sumber masih alamat workstation), lalu query DNS dari proxy untuk nama penyedia itu di `index=dns`. Yang tidak terlihat adalah isi query DoH, karena domain kategori "DNS over HTTPS" di-splice, tidak di-bump. Di hop egress, semua DoH workstation tampak bersumber dari `10.20.3.60` (Day 06 bagian 1.7). Klien DoH yang tidak memakai proxy dan mencoba keluar langsung ke `203.0.113.190:443` ditolak firewall, dan percobaan itu terlihat di TAP sebagai `conn_state` `S0`.

Suricata 8 punya parser DoH di atas HTTP/2 (protokol `doh2`) yang memasukkan query DoH ke logging dan keyword DNS biasa [S14]. Fitur itu bekerja pada trafik HTTP/2 yang sudah cleartext, misalnya hasil dekripsi, bukan pada DoH yang masih di dalam TLS [S14]. Di `jkt-ids01` parser ini praktis tidak pernah melihat DoH, karena sensor hanya menerima trafik terenkripsi. Satu catatan keamanan sensor: parser `doh2` di Suricata sebelum 8.0.7 punya kerentanan type confusion (CVE-2026-94083) yang bisa membuat daemon crash atau berpotensi menjalankan kode bila `app-layer.protocols.doh2` aktif; perbaikannya ada di 8.0.7, dan mitigasi sementaranya mematikan parser itu [S15]. `jkt-ids01` sudah memakai 8.0.7.

ATT&CK mencatat pemakaian DoH oleh penyerang di bawah T1572 Protocol Tunneling: query untuk me-resolve infrastruktur C2 dibungkus di dalam HTTPS terenkripsi [S20]. Label itu dipakai hanya bila ada bukti penyembunyian C2, bukan untuk setiap host yang memakai DoH. `JKT-WS-2076` dan `JKT-WS-2078` sama-sama menghubungi `doh.quadresolve.example`; hanya satu yang berakhir menjadi insiden (bagian 1.9 dan 2.4).

### 1.3 Yang masih terlihat dari QUIC

Pertanyaan ketiga Dimas datang dari `SOC-2027-0677`: `quic.log` di `jkt-zeek01` mencatat nama tujuan `cfg.edge-relay.example` dari `JKT-WS-2078`, padahal firewall menolak setiap paket UDP 443 dari workstation. Jawabannya ada di cara QUIC membangun koneksi, dan di letak TAP yang berada di sisi dalam `jkt-fw01`: paket yang ditolak firewall tetap lewat TAP lebih dulu.

QUIC versi 1 didefinisikan di RFC 9000 [S4], dan HTTP/3 adalah pemetaan HTTP di atas QUIC dengan token ALPN `h3` [S6]. RFC 9312 adalah dokumen informasional yang khusus membahas apa yang bisa dilihat pengamat di jalur pada QUIC versi 1 [S5]. Yang terlihat [S5]:

- **Bit bentuk header**, pembeda long header dan short header, serta **nomor versi** pada long header; paket Version Negotiation memakai nilai versi nol.
- **Connection ID.** Long header membawa Source dan Destination Connection ID; short header hanya Destination Connection ID dengan panjang yang tersirat.
- **Tipe paket, Length, dan Token** pada long header; field Length memungkinkan paket yang digabungkan dipisahkan kembali.
- **Latency spin bit** pada short header, dan **empat flight handshake** yang bisa dikenali: Client Initial, Server Initial, Client Completion, dan Server Completion.
- **Isi paket Initial.** Dienkripsi dengan kunci yang diturunkan dari konstanta per versi dan Destination Connection ID klien, sehingga perangkat mana pun yang tahu konstanta itu bisa mendekripsinya, dan dari situ **SNI serta ALPN** bisa diambil.
- **Ukuran dan port.** Datagram pembawa Initial berisi minimal 1200 byte muatan UDP; nomor port terlihat tetapi tidak andal untuk mengenali aplikasi.
- **Paket Retry dan Version Negotiation** tidak terenkripsi; Retry dilindungi integritasnya.

Baris tentang paket Initial paling sering disalahpahami. RFC 9001 menjelaskan mekanismenya: initial secret dihitung dengan HKDF-Extract dari salt tetap milik versi itu dan Destination Connection ID dari Initial pertama klien, lalu dipecah menjadi kunci "client in" dan "server in" [S8]. Salt untuk QUIC versi 1 tercantum di RFC (`0x38762cf7f55934b34d179ae6a4c80cadccbb7f0a`), dan RFC 9001 sendiri menyatakan bahwa karena kuncinya mudah ditentukan, paket Initial tidak dianggap punya perlindungan kerahasiaan atau integritas [S8]. Banyak orang menganggap QUIC sepenuhnya buram; kenyataannya handshake awalnya bisa dibuka pengamat mana pun [S5], sehingga selama ECH belum dipakai (Day 15), analisis Initial QUIC tidak jauh berbeda dari analisis ClientHello TLS.

Untuk `JKT-WS-2078`, akibatnya konkret. Workstation mengirim Initial ke `203.0.113.191:443`. Paket itu melewati TAP sebelum dibuang `jkt-fw01`. Zeek mendekripsi Initial, membaca ClientHello, dan menulis `server_name` dan `client_protocol` ke `quic.log` [S12], walaupun server tidak pernah membalas. Koneksi yang ditolak tetap membocorkan tujuan yang dimaksud. Di sensor yang berada di sisi luar firewall, paket itu tidak akan pernah terlihat.

Ada dua batas yang menentukan kapan trik ini berhenti bekerja. Pertama, kunci Initial bergantung pada versi: QUIC versi 2 (RFC 9369) memakai nomor versi `0x6b3343cf`, salt yang berbeda, dan pengodean tipe paket long header yang berbeda (Initial `0b01`, 0-RTT `0b10`, Handshake `0b11`, Retry `0b00`), dengan tujuan eksplisit melawan osifikasi [S9]. Alat yang hanya mengenal versi 1 tidak bisa membuka Initial versi 2. Kedua, ECH di atas QUIC menyembunyikan SNI dalam, sehingga yang terbaca hanya nama luar milik penyedia (Day 15).

### 1.4 Yang tidak terlihat dari QUIC

Pertanyaan keempat Dimas ("kenapa alur QUIC kelihatan putus-putus") dijawab oleh daftar ini. Daftar ini juga menentukan apa yang tidak boleh kamu janjikan di rapat [S5]:

- Nomor paket dan bit Key Phase, paket Handshake, serta seluruh muatan 1-RTT termasuk frame ACK.
- Sinyal kehilangan paket, karena informasi acknowledgment ada di muatan terenkripsi; pengukuran kehilangan paket secara pasif karena itu tidak mungkin.
- Akhir koneksi, karena QUIC tidak punya sinyal penutupan yang terlihat sehingga perangkat di jalur bersandar pada idle timeout.
- Paket yang hanya berisi ACK tidak bisa dibedakan secara andal dari paket data, dan parameter transport server tidak terlihat.

Soal timeout, dokumennya memberi angka yang berguna: perangkat disarankan menyimpan state QUIC minimal dua menit, meskipun timeout lebih pendek dipakai untuk trafik UDP lain; endpoint teramati melakukan timeout dalam 30 sampai 60 detik, dan memperpendek timeout NAT tidak dianjurkan [S5]. Angka ini menjelaskan kenapa alur QUIC bisa terlihat "hilang" di log flow yang timeout-nya pendek.

Di PT JAB, ketiga pengamat punya aturan sendiri, dan tidak ada yang melihat "akhir" koneksi QUIC:

- `jkt-flow01` memakai idle timeout 15 detik dan active timeout 300 detik (Day 10). Satu koneksi HTTP/3 yang diam 20 detik lalu aktif lagi menjadi dua record flow.
- Zeek menutup alur UDP dengan timeout inaktivitasnya sendiri, sehingga satu koneksi QUIC yang lama dan berjeda bisa menjadi beberapa baris `conn.log` dengan `uid` berbeda. Nilai timeout UDP di `jkt-zeek01` perlu dicek di konfigurasi sensor sebelum dipakai untuk menghitung durasi.
- `jkt-fw01` memakai UDP idle timeout 30 detik untuk aturan portal (bagian 2.5). Itu di bawah rekomendasi dua menit, dan menjadi penyebab sebagian keluhan pelanggan di `SOC-2027-0678`.

Jadi "putus-putus" di `conn.log` dan flow adalah artefak cara pengamat menutup state, bukan bukti koneksi benar-benar berakhir.

### 1.5 Mengenali QUIC dan jebakannya

Pertanyaan kelima Dimas ("cukupkah menganggap semua UDP 443 itu QUIC?") punya jawaban singkat: tidak, dan sebaliknya juga tidak.

Yang penting diketahui sejak awal: tidak ada metode umum untuk mengenali QUIC, dan trafik UDP yang tidak dikenali bisa saja QUIC [S5]. Tiga heuristik yang sering dipakai dan semuanya bermasalah [S5]:

- **Port 443 bukan indikator yang andal**, karena aplikasi lain seperti SMB di atas QUIC juga memakainya dan HTTP/3 bisa berjalan di port lain.
- **Fixed bit tidak andal**, karena bukan invarian, hanya memberi satu bit informasi, dan bisa diubah ekstensi; **heuristik byte pertama juga tidak dianjurkan** karena arti bitnya bisa berubah di versi mendatang.

Dokumennya juga tidak menganjurkan kontrol akses berbasis versi, karena menerima trafik tanpa memandang versi menghindari kegagalan saat versi berkembang [S5]. QUIC versi 2 adalah contoh nyata alasan itu: nomornya sengaja bukan "2" dan tipe paketnya diacak ulang supaya middlebox tidak menempel pada nilai versi 1 [S9].

Yang lebih kuat daripada heuristik adalah parser yang benar-benar mendekripsi Initial. Di program NSM PT JAB ada tiga:

| Alat | Yang dicatat | Catatan |
|---|---|---|
| Zeek 9.0 `quic.log` | `version`, `client_initial_dcid`, `client_scid`, `server_scid`, `server_name`, `client_protocol`, `history` [S12] | `history` memakai huruf: `I` Initial, `H` Handshake, `Z` 0-RTT, `R` Retry, `C` CONNECTION_CLOSE, `S` Client/Server Hello, `U` versi tidak dikenal, `X` paket dibuang setelah Initial terdekripsi, `O` short header (dicatat secara logaritmik biner); huruf besar dari klien [S12] |
| Suricata 8.0.7 event `quic` | `version`, `sni`, `ua` (untuk versi QUIC pra-standar), `cyu`, `ja3`, `ja4`, `extensions` [S13] | Parser aktif bila `app-layer.protocols.quic.enabled: yes`; keyword `quic.version`, `quic.cyu.hash`, `quic.cyu.string` [S13] |
| Wireshark 4.6.9 | `quic.header_form`, `quic.long.packet_type`, `quic.long.packet_type_v2`, `quic.version`, `quic.dcid`, `quic.scid`, `quic.spin_bit` [S10] | ClientHello dari Initial yang terdekripsi diurai sebagai TLS, sehingga field `tls.handshake.*` dipakai untuk SNI dan ALPN [S11] |

Huruf `U` di `history` Zeek layak diperhatikan: Initial dengan versi yang tidak dikenal tidak bisa didekripsi, sehingga `server_name` kosong. Itu bukan tanda jahat, tetapi tanda alat kehilangan visibilitas.

Untuk identifikasi alur, dua sumbu yang tersedia [S5]. Lima-tuple bekerja selama Connection ID berpanjang nol. Connection ID dirancang supaya perubahan alamat di lapisan bawah tidak membuat paket QUIC salah alamat [S4], dan karena itu bisa menautkan alur ketika alamat endpoint berubah karena NAT rebinding atau migrasi. Penautan itu tidak dijamin: Connection ID bisa berubah di tengah koneksi, dan migrasi yang disengaja juga mengubahnya, sehingga pengamat tidak bisa menautkan alur tersebut [S5].

### 1.6 Connection migration dan akibatnya

Pertanyaan keenam datang dari Bambang. Selasa pukul 20:15, `SOC-2027-0678` berbunyi: dalam 10 menit, `conn.log` hop core mencatat 1.120 alur UDP baru ke portal pelanggan `jkt-dmz-web03` (`10.20.9.70`, publik `198.51.100.216`), padahal baseline jam yang sama sekitar 300. Hampir semuanya berasal dari alamat CGNAT PT JAB sendiri, `198.51.100.210`. Portal itu melayani HTTP/3, dan pelanggan broadband serta seluler PT JAB berpindah jaringan setiap saat.

Migrasi dan NAT rebinding mengubah lima-tuple, sehingga yang teramati menjadi alur yang berbeda dan bisa diperlakukan berbeda oleh jaringan [S5]. Kendali kongesti biasanya di-reset saat jalur berubah, sehingga alur yang bermigrasi bisa berkinerja berbeda [S5]. Di CGNAT `jkt-cgn01`, pelanggan mendapat blok 512 port di `198.51.100.210` (Day 10); bila mapping UDP kedaluwarsa dan dibuat ulang, port berganti di dalam blok yang sama, dan di sisi portal itu tampak seperti klien baru yang langsung mengirim short header tanpa Initial.

Dua hal yang tidak dianjurkan dan layak kamu ketahui saat berdiskusi dengan tim jaringan [S5]: menyembunyikan perubahan alamat lewat penerjemahan alamat di middlebox tidak dianjurkan karena menghalangi endpoint memverifikasi jalur baru dan memudahkan serangan amplifikasi; dan memakai Connection ID untuk penerusan stateful atau multiplexing NAT juga tidak dianjurkan karena perubahan Connection ID bisa diam-diam merusak state dan konektivitas.

Untuk pertahanan DDoS, dokumennya menyatakan migrasi yang disengaja tidak bisa dibedakan dari trafik serangan [S5]. Ini batas yang jujur dan perlu disampaikan apa adanya ke Bambang: "lonjakan alur baru tanpa Initial" sendirian tidak membuktikan serangan maupun membuktikan migrasi. Yang membedakan adalah konteks: sumbernya CGNAT pelanggan sendiri, volume byte per alur sebanding dengan sesi normal, ada keluhan pelanggan yang cocok waktunya, dan lonjakan bertepatan dengan perubahan di jaringan (bagian 2.5).

### 1.7 Spin bit untuk RTT

Pertanyaan ketujuh juga dari Bambang: tim NOC ingin RTT pelanggan ke portal tanpa memasang agent di sisi pelanggan.

Spin bit berubah sekali per RTT ketika kedua endpoint aktif mengirim dan keduanya mengaktifkan spinning, dan pengamat mengukur waktu antar tepi untuk mendapat satu sampel RTT per tepi [S5]. Keterbatasannya [S5]:

- Endpoint mematikan spinning untuk minimal seperdelapan koneksi, dan boleh memakai nilai tetap atau acak.
- Sampel mencakup penundaan transport dan aplikasi, sehingga pengirim yang terbatas aplikasi bisa menggelembungkannya sampai yang terukur adalah periodisitas aplikasi, bukan RTT jaringan.
- Pengurutan ulang paket melintasi tepi spin bisa menghasilkan tepi palsu, dan pengukuran kinerja pasif terbatas pada RTT saja.

Handshake RTT bisa diukur sekali per alur dari jeda antara Client Initial dan Server Initial, serta antara paket Handshake pertama server dan balasan Handshake klien, dan keduanya bisa dijumlahkan [S5]. Ini pengukuran yang paling andal karena tidak bergantung spin bit.

Posisi pengamat menentukan komponen mana yang besar. SPAN core switch DC berada di dekat portal: jeda Client Initial ke Server Initial di titik itu hampir hanya waktu proses server (setengah RTT sisi server yang sangat pendek), sedangkan jeda paket Handshake server ke balasan Handshake klien memuat hampir seluruh perjalanan ke pelanggan. Karena itu kedua komponen dijumlahkan, bukan dipilih salah satu.

### 1.8 Kontrol di sisi organisasi: browser, firewall, resolver

Pertanyaan kedelapan Dimas bagian pertama ("apa sebaiknya kita blokir") lebih sering dijawab dengan kebijakan daripada dengan sensor. Ada empat tuas, dan masing-masing punya batas:

- **Kebijakan browser.** Microsoft Edge punya kebijakan `DnsOverHttpsMode` (Edge 83 ke atas) dengan nilai `off`, `automatic` (DoH dulu, jatuh ke DNS biasa bila gagal), dan `secure` (hanya DoH, gagal bila tidak bisa) [S16]. Untuk perangkat terkelola yang kebijakannya tidak dikonfigurasi, dokumentasinya menyebut query DoH tidak dikirim dan browser bisa memakai resolver sistem [S16]. Kebijakan `QuicAllowed` (Edge 77 ke atas) mengizinkan QUIC bila diaktifkan atau tidak dikonfigurasi, dan memblokirnya bila dinonaktifkan; perubahan butuh restart browser [S17]. Workstation PT JAB memakai Edge (Day 11), jadi kedua kebijakan ini bisa ditetapkan lewat GPO. Batasnya: kebijakan browser tidak mengatur aplikasi lain, termasuk alat privasi atau implant.
- **Canary domain.** Firefox memeriksa `use-application-dns.net` lewat resolver sistem; jawaban selain NOERROR, atau NOERROR tanpa rekaman A/AAAA, dianggap sinyal untuk mematikan DoH [S18]. Pemeriksaan ini hanya berlaku bagi pengguna yang DoH-nya aktif sebagai bawaan, bukan yang menyalakannya sendiri, dan Mozilla menyebutnya langkah sementara [S18]. Resolver internal yang menjawab NXDOMAIN untuk nama itu murah dan tidak merugikan, tetapi bukan kontrol yang bisa diandalkan.
- **Firewall.** Menolak TCP dan UDP 853 keluar dari workstation memutus DoT dan DoQ secara definitif, dan setiap penolakan menjadi log (bagian 2.1). DoH tidak bisa diblokir dengan port; yang bisa dilakukan adalah menolak koneksi langsung ke port 443 (PT JAB sudah begitu) dan mengatur kategori penyedia DoH di proxy.
- **Resolver.** Resolver yang tidak mengumumkan endpoint terenkripsi lewat DDR membuat klien yang patuh tetap di DNS polos [S19]. Bila suatu saat PT JAB ingin DNS internal terenkripsi, pilihan yang tetap menjaga visibilitas adalah DoT atau DoH ke resolver internal sendiri, karena log resolver tetap mencatat query.

Untuk QUIC, firewall PT JAB sudah menolak UDP 443 keluar dari workstation, sehingga aplikasi yang mencoba QUIC jatuh ke TCP lewat proxy. Penolakan itu tetap berguna sebagai sensor: setiap Initial yang ditolak tercatat di `quic.log` dengan SNI-nya (bagian 1.3). Untuk server di data center yang keluar langsung, QUIC tetap terlihat di `quic.log` dan event `quic` Suricata.

### 1.9 Indikator, kesimpulan, dan penjelasan jinak

Bagian kedua pertanyaan kedelapan ("kapan alert ini boleh jadi insiden") dijawab dengan memisahkan indikator dari kesimpulan, seperti di Day 11.

Indikator di Day ini antara lain: penolakan port 853, CONNECT ke penyedia DoH, rasio query DNS yang anjlok, Initial QUIC yang ditolak firewall, `server_name` yang tidak pernah muncul di log DNS mana pun, dan lonjakan alur UDP baru. Semuanya punya penjelasan jinak yang umum:

| Indikator | Penjelasan jinak yang umum | Yang mengubahnya menjadi kandidat |
|---|---|---|
| Penolakan TCP/UDP 853 | Alat privasi DNS, browser dengan DoT/DoQ, perangkat pribadi | Proses tidak dikenal atau tidak bertanda tangan, berbarengan dengan tujuan baru berprevalence rendah |
| CONNECT ke penyedia DoH | Browser atau alat privasi; pengguna yang tidak tahu kebijakan | Klien non-browser, ritme berkala, dan tujuan berikutnya tidak pernah di-resolve lewat resolver internal |
| Rasio DNS anjlok | Host memakai DoH atau resolver lain; host jarang dipakai | Bersamaan dengan tujuan baru yang tidak dikenal |
| Initial QUIC ditolak dari workstation | Aplikasi rapat video atau updater yang mencoba UDP dulu | SNI berprevalence satu, berkala, domain baru |
| Lonjakan alur UDP tanpa Initial | Migrasi atau NAT rebinding pelanggan | Sumber tersebar luas di luar pelanggan sendiri, byte per alur kecil seragam, tanpa sesi sebelumnya |

Di PT JAB, `JKT-WS-2076` dan `JKT-WS-2078` sama-sama menghubungi `doh.quadresolve.example` (`203.0.113.190`). Satu adalah alat privasi milik pengguna yang ditutup sebagai pelanggaran kebijakan; yang lain adalah proses tidak bertanda tangan yang me-resolve tujuan beacon lewat DoH lalu mencoba QUIC dan TCP ke tujuan itu, dan menjadi `INC-2027-075` (bagian 2.4). Tujuan yang sama, kesimpulan berbeda: yang membedakan adalah proses, ritme, prevalence tujuan berikutnya, dan pemilik yang bisa atau tidak bisa menjelaskan.

## 2. Contoh dan langkah praktis: empat alert hari Selasa

Semua keluaran di bagian ini adalah keluaran ilustrasi dari data fiktif PT JAB, bukan hasil eksekusi nyata. Log Zeek di `jkt-zeek01` berformat JSON dan masuk Splunk index `zeek`; sourcetype mengikuti pola `bro:<log>:json` dari TA for Zeek, dan yang belum dipakai di Day sebelumnya (`bro:quic:json`, `bro:dns:json`) divalidasi dulu dengan `| metadata type=sourcetypes index=zeek` sebelum dipakai. Waktu Splunk ditampilkan WIB; `ts` Zeek dan nama file ring `jkt-pcap01` memakai UTC (WIB = UTC + 7). Perintah `zeek-cut` dipakai pada log TSV hasil Zeek offline atas cuplikan pcap di `jkt-nsm-ws01`. Nama field Wireshark mengikuti display filter reference 4.6.9 [S10][S11]; nama field berbeda antar versi Wireshark dan Zeek, jadi cocokkan di lab-mu.

### 2.1 Mengenali DoT dan DoQ: `SOC-2027-0675`

Artefak pertama menjawab pertanyaan 1 untuk host nyata. Selasa pukul 09:52, rule Splunk "port DNS terenkripsi dari workstation" berbunyi untuk `JKT-WS-2076` (`10.10.60.161`, akun `fikri.ananda`, Keuangan).

**Tujuan:** memastikan apa yang dicoba host itu, ke mana, berapa kali, dan apakah ada yang lolos.

Filter Wireshark untuk pcap egress, sama untuk semua versi yang dipakai program:

```
tcp.port == 853
udp.port == 853
```

Keduanya praktis definitif: port 853 direservasi untuk DNS terenkripsi, dan DoQ secara eksplisit dilarang memakai UDP port 53 [S2][S3].

Untuk PT JAB, mulai dari log firewall karena retensinya paling panjang (90 hari), lalu cocokkan dengan sensor:

```
index=firewall src_ip=10.10.60.161 dest_port=853 earliest="06/15/2027:00:00:00" latest="06/16/2027:00:00:00"
| stats count min(_time) AS pertama max(_time) AS terakhir values(action) AS action BY src_ip dest_ip dest_port transport
| convert ctime(pertama) ctime(terakhir)

index=zeek sourcetype=bro:quic:json id.orig_h=10.10.60.161 id.resp_p=853 earliest="06/15/2027:00:00:00" latest="06/16/2027:00:00:00"
| table _time uid id.orig_h id.resp_h id.resp_p version server_name client_protocol history
```

Penjelasan tiap bagian:

- Query pertama memakai field gaya CIM Network Traffic di `index=firewall` (`src_ip`, `dest_ip`, `dest_port`, `transport`, `action`) seperti Day 04; `values(action)` memastikan tidak ada satu pun yang `allow`.
- Query kedua mengambil baris `quic.log` untuk port 853. Field `server_name`, `client_protocol`, dan `history` mengikuti `QUIC::Info` Zeek 9.0 [S12].
- Rentang waktu ditulis absolut supaya hasil bisa diulang besok dengan angka yang sama.

Keluaran ilustrasi:

```
src_ip        dest_ip        dest_port  transport  count  pertama              terakhir             action
10.10.60.161  203.0.113.190  853        tcp        18     06/15/2027 09:47:15  06/15/2027 16:31:43  deny
10.10.60.161  203.0.113.190  853        udp        18     06/15/2027 09:47:12  06/15/2027 16:31:40  deny

_time                uid                 id.orig_h     id.resp_h      id.resp_p  version  server_name              client_protocol  history
06/15/2027 09:47:12  Cq3vL81mTe0Rk2pWa   10.10.60.161  203.0.113.190  853        1        doq.quadresolve.example  doq              I
06/15/2027 10:58:40  CJ7dWn5yUq2Ab8sHe   10.10.60.161  203.0.113.190  853        1        doq.quadresolve.example  doq              I
... (6 baris, terakhir 16:31:40)
```

**Cara membaca hasil:**

- Enam putaran, masing-masing tiga paket UDP 853 lalu tiga SYN TCP 853 sekitar tiga detik kemudian: 6 x 3 = 18 untuk tiap transport. Polanya urutan klien yang mencoba DoQ dulu, lalu DoT, lalu berhenti. Putaran berikutnya muncul setiap kali alat dimulai ulang atau jaringan host berubah.
- `quic.log` hanya punya satu baris per putaran, karena tiga paket Initial yang diulang memakai lima-tuple yang sama dan dihitung satu koneksi. ALPN `doq` dan port 853 menegaskan DoQ (bagian 1.1); `history` `I` saja berarti hanya Initial klien yang terlihat, tanpa balasan server, cocok dengan penolakan firewall.
- SNI `doq.quadresolve.example` terbaca walaupun koneksinya tidak pernah terbentuk (bagian 1.3).
- Pertanyaan berikutnya: ke mana DNS host ini pergi setelah DoQ dan DoT gagal? Itu bagian 2.2.

Yang dicatat per host: apakah ia memakai resolver terenkripsi, ke penyedia mana, dan sejak kapan. Perubahan mendadak pada ketiganya adalah temuan, terutama bila terjadi pada satu host saja di antara banyak host yang seragam. Di PT JAB, 30 hari log firewall tidak memuat penolakan port 853 dari `10.10.60.161` sebelum Selasa 09:47.

**Variasi:** ganti `src_ip=10.10.60.161` dengan `src_ip=10.10.0.0/16` dan `stats dc(src_ip)` untuk melihat berapa workstation yang pernah mencoba DoT atau DoQ dalam 30 hari; untuk server di data center yang keluar langsung, cari `action=allow` di port 853, karena itulah DNS terenkripsi yang benar-benar berhasil.

**Kapan gagal:** organisasi yang memang menerapkan DoT ke resolver internal akan memenuhi filter ini di hampir semua host. Yang kamu cari tetap yang menyimpang dari pola itu. Klien yang langsung memakai DoH tanpa mencoba 853 tidak meninggalkan jejak di sini sama sekali.

### 2.2 Mencari jejak DoH: `SOC-2027-0676`

Artefak kedua menjawab pertanyaan 2. Selasa pukul 14:20, correlation search baru "DNS diam, koneksi tetap" berbunyi untuk host yang sama, `10.10.60.161`.

**Tujuan:** menemukan host yang jumlah query DNS polosnya anjlok dibanding baseline-nya sendiri sementara koneksi web-nya tetap, lalu menemukan ke mana DNS-nya pindah.

Karena tidak ada field yang menandai DoH, kerjakan dengan tiga lapis. Dua perintah Zeek ini dipakai pada log TSV (Zeek offline atau lab):

```
# Zeek: host dengan koneksi ke daftar penyedia DoH yang diketahui
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p \
  | awk '$3 == 443' | grep -F -f daftar-penyedia-doh.txt | sort | uniq -c | sort -rn
```

```
# Zeek: host yang kueri DNS polosnya anjlok tetapi koneksinya tidak
cat dns.log | zeek-cut id.orig_h | sort | uniq -c | sort -rn > dns-per-host.txt
cat conn.log | zeek-cut id.orig_h | sort | uniq -c | sort -rn > conn-per-host.txt
join -1 2 -2 2 <(sort -k2 dns-per-host.txt) <(sort -k2 conn-per-host.txt)
```

Penjelasan tiap bagian:

- Perintah pertama mengambil sumber, tujuan, dan port dari `conn.log`, menyaring port 443, lalu mencocokkan baris dengan daftar alamat penyedia DoH (`grep -F -f` membaca pola teks tetap dari file). Hasilnya jumlah koneksi per pasangan.
- Perintah kedua menghitung query per host di `dns.log` dan koneksi per host di `conn.log`, lalu `join` menggabungkan keduanya pada kolom kedua (alamat host). `join` butuh masukan yang terurut pada kolom gabungan, karena itu `sort -k2`. Keluarannya tiga kolom: alamat, jumlah query DNS, jumlah koneksi.

Cara membacanya: host dengan rasio kueri DNS terhadap jumlah koneksi yang jauh lebih rendah daripada host sejenis adalah kandidat pemakai resolver terenkripsi. Bandingkan dengan baseline, bukan dengan angka mutlak.

Di PT JAB, perintah pertama tidak menemukan apa pun dari workstation, karena workstation tidak membuka koneksi 443 langsung; yang terlihat hanya `10.20.3.60` di hop egress. Versi PT JAB memakai baris `CONNECT` di `http.log` hop core, yang sumbernya masih alamat workstation:

```
zeek-cut id.orig_h method uri < http.log \
  | awk '$2 == "CONNECT" {print $1, $3}' | grep -F -f daftar-penyedia-doh.txt | sort | uniq -c | sort -rn
```

`daftar-penyedia-doh.txt` berisi nama host penyedia, satu per baris (misalnya `doh.quadresolve.example`), bukan alamat IP, karena `uri` untuk `CONNECT` berisi `host:port`.

Keluaran ilustrasi untuk log hari Selasa:

```
    112 10.10.60.163 doh.quadresolve.example:443
     14 10.10.60.161 doh.quadresolve.example:443
```

Correlation search di Splunk menerapkan lapis keempat (ketiadaan DNS polos) dengan baseline 14 hari per host:

```
index=dns sourcetype=isc:bind:query src=10.10.0.0/16 earliest="06/01/2027:00:00:00" latest="06/16/2027:00:00:00"
| bin _time span=1d
| stats count AS dns BY src _time
| append [ search index=proxy method=CONNECT src=10.10.0.0/16 earliest="06/01/2027:00:00:00" latest="06/16/2027:00:00:00"
    | bin _time span=1d | stats count AS conn BY src _time ]
| stats sum(dns) AS dns sum(conn) AS conn BY src _time
| fillnull value=0 dns conn
| eval rasio=if(conn>0, round(dns/conn,3), null())
| eval kemarin=if(_time>=strptime("06/15/2027","%m/%d/%Y"),1,0)
| stats median(eval(if(kemarin=0,dns,null()))) AS dns_baseline median(eval(if(kemarin=0,rasio,null()))) AS rasio_baseline
        max(eval(if(kemarin=1,dns,null()))) AS dns_kemarin max(eval(if(kemarin=1,conn,null()))) AS conn_kemarin
        max(eval(if(kemarin=1,rasio,null()))) AS rasio_kemarin BY src
| where dns_baseline>=200 AND conn_kemarin>=200 AND rasio_kemarin<0.2*rasio_baseline
| table src dns_baseline rasio_baseline dns_kemarin conn_kemarin rasio_kemarin
```

Penjelasan tiap bagian:

- Pencarian utama menghitung query per host per hari di log resolver (`isc:bind:query`, field `src` dan `query` seperti Day 05); subsearch `append` menghitung `CONNECT` per host per hari di log proxy. `stats sum ... BY src _time` menyatukan keduanya menjadi satu baris per host per hari.
- `rasio` adalah query DNS per koneksi web. `kemarin` memisahkan Selasa 15 Juni dari 14 hari baseline (1 sampai 14 Juni).
- `where` memakai tiga syarat: host punya baseline DNS yang berarti (minimal 200 query per hari), masih aktif kemarin (minimal 200 koneksi), dan rasio kemarin kurang dari seperlima baseline-nya sendiri.

Keluaran ilustrasi:

```
src           dns_baseline  rasio_baseline  dns_kemarin  conn_kemarin  rasio_kemarin
10.10.60.161  1840          0.797           41           2260          0.018
```

**Cara membaca hasil:**

- `10.10.60.161` turun dari median 1.840 query per hari ke 41, sementara koneksi lewat proxy tetap 2.260. Rasionya 41 / 2.260 = 0,018, di bawah seperlima dari 0,797 (batasnya 0,159). Itu bentuk "DNS diam, koneksi tetap".
- Keluaran `http.log` di atas menunjukkan ke mana DNS-nya pindah: 14 `CONNECT` ke `doh.quadresolve.example`. Sedikit koneksi untuk ribuan query adalah tanda DoH yang memakai ulang koneksi panjang; satu koneksi HTTP/2 membawa banyak query.
- `10.10.60.163` (`JKT-WS-2078`) tidak muncul di correlation search walaupun membuat 112 `CONNECT` ke penyedia yang sama. Rasionya Selasa 0,74 terhadap baseline 0,78, karena hanya satu proses di host itu yang memakai DoH; DNS sistem tetap ke `jkt-res01`. Pendekatan rasio menangkap DoH di level sistem, bukan DoH satu aplikasi. Pola 112 koneksi pendek yang berkala justru menjadi bahan bagian 2.4.
- Wawancara dengan Fikri dan pemeriksaan MDE menunjukkan alat privasi DNS "QuadResolve Client" yang dipasangnya sendiri Selasa pagi; alat itu mengarahkan DNS sistem ke klien lokal yang mencoba DoQ, DoT, lalu DoH lewat proxy sistem. `SOC-2027-0675` dan `SOC-2027-0676` ditutup sebagai pelanggaran kebijakan perangkat lunak, bukan insiden; tiket ke tim End User Computing untuk menghapus alat itu.

Lapis ketiga adalah pola ukuran dan durasi. Sesi DoH berisi banyak transaksi kecil berumur pendek, sedangkan sesi web biasa berisi lebih sedikit transaksi dengan volume lebih besar. Ini pembeda yang lemah sendirian tetapi menguatkan dua lapis sebelumnya. Di hop egress, 14 sesi `10.20.3.60` ke `203.0.113.190:443` milik Fikri berdurasi panjang dengan ratusan record kecil di dalamnya; itu konsisten dengan DoH, tetapi tanpa log proxy tidak bisa diatribusikan ke workstation mana pun.

**Variasi:** ganti syarat `where` menjadi `rasio_kemarin<0.5*rasio_baseline` untuk melihat penurunan yang lebih lunak, atau jalankan per jam (`span=1h`) untuk menemukan jam mulai. Untuk server data center yang tidak lewat proxy, ganti subsearch proxy dengan `index=zeek sourcetype=bro:conn:json` dan hitung koneksi keluar per `id.orig_h`.

**Kapan gagal:** DoH yang dicampur ke koneksi HTTPS yang juga membawa trafik lain, yang memang disebut sebagai salah satu manfaatnya [S1]. Dalam kasus itu, pola ukuran tidak akan terbaca dan daftar penyedia tidak membantu bila penyedianya juga melayani konten lain. Rasio juga gagal untuk host yang jarang dipakai (baseline kecil), saat hari libur menurunkan keduanya bersamaan, dan saat DoH hanya dipakai satu aplikasi seperti `JKT-WS-2078`.

### 2.3 Mengambil SNI dan ALPN dari QUIC: `SOC-2027-0677`

Artefak ketiga menjawab pertanyaan 3. Selasa pukul 17:40, rule harian atas `quic.log` ("Initial QUIC dari workstation ke SNI berprevalence satu, minimal 20 kali sehari") berbunyi untuk `10.10.60.163`.

**Tujuan:** melihat semua Initial QUIC dari workstation dalam satu hari, siapa ke nama apa, dan memastikan nama itu terbaca dari paket.

Mulai dari ringkasan `quic.log` di Splunk:

```
index=zeek sourcetype=bro:quic:json id.orig_h=10.10.0.0/16 earliest="06/15/2027:00:00:00" latest="06/16/2027:00:00:00"
| stats count dc(id.orig_h) AS host values(history) AS history min(_time) AS pertama max(_time) AS terakhir
        BY server_name client_protocol id.resp_p
| convert ctime(pertama) ctime(terakhir)
| sort host -count
```

Penjelasan tiap bagian: `dc(id.orig_h)` adalah prevalence per nama di antara workstation; `values(history)` menunjukkan apakah ada koneksi yang berhasil (huruf server seperti `i` atau `h` kecil) atau semuanya hanya `I`; `sort host -count` menaruh nama berprevalence rendah dengan jumlah tertinggi di atas.

Keluaran ilustrasi:

```
server_name                client_protocol  id.resp_p  count  host  history  pertama              terakhir
cfg.edge-relay.example     h3               443        112    1     I        06/15/2027 08:01:56  06/15/2027 17:31:49
doq.quadresolve.example    doq              853        6      1     I        06/15/2027 09:47:12  06/15/2027 16:31:40
media-relay.vconf.example  h3               443        96     7     I        06/15/2027 08:31:07  06/15/2027 16:58:12
```

**Cara membaca hasil:**

- Semua 214 baris dari 9 workstation hanya punya `history` `I`: tidak ada satu pun QUIC dari workstation yang berhasil, sesuai aturan firewall. Yang terlihat adalah percobaan, dan percobaan itu sudah membawa nama tujuan.
- `media-relay.vconf.example` dicoba 7 workstation: klien rapat video yang mencoba UDP dulu lalu jatuh ke TCP lewat proxy. Prevalence tujuh dan vendor yang dikenal membuatnya jinak.
- `doq.quadresolve.example` adalah DoQ milik Fikri (bagian 2.1).
- `cfg.edge-relay.example` hanya dari `10.10.60.163`, 112 kali dalam sekitar sembilan setengah jam. Itu kandidat yang diperiksa di bagian 2.4.

Untuk memastikan nama itu memang terbaca dari Initial, dan bukan hasil tebakan alat, buka pcap egress di `jkt-nsm-ws01`. Filter Wireshark untuk ClientHello di dalam Initial QUIC:

```
quic && tls.handshake.type == 1
quic.long.packet_type == 0
```

Keduanya bekerja karena paket Initial bisa didekripsi oleh pengamat memakai kunci yang diturunkan dari konstanta per versi dan Destination Connection ID klien [S5][S8]. Wireshark menguraikan ClientHello hasil dekripsi sebagai TLS, sehingga SNI dan ALPN ada di `tls.handshake.extensions_server_name` dan `tls.handshake.extensions_alpn_str` [S11]. Nama field lama `quic.tls.handshake.extensions_server_name` tidak tercantum di display filter reference 4.6.9 [S10]; bila catatan lama memakainya, ganti. `quic.long.packet_type == 0` adalah Initial untuk versi 1; untuk versi 2 Wireshark memakai field terpisah `quic.long.packet_type_v2`, dengan Initial bernilai 1 [S9][S10].

```
tshark -r /mnt/pcap01/ring/egress-jkt_04396_20270615080000.pcapng \
  -Y 'quic && tls.handshake.type == 1 && ip.src == 10.10.60.163' \
  -T fields -e frame.number -e frame.time_utc -e ip.src -e ip.dst -e udp.dstport \
  -e quic.version -e tls.handshake.extensions_server_name -e tls.handshake.extensions_alpn_str
```

Penjelasan tiap bagian: `-r` membaca satu file ring 15 menit yang dimulai 08:00 UTC (15:00 WIB); `-Y` memilih paket QUIC yang memuat ClientHello dari host kasus; `-T fields` dengan beberapa `-e` mencetak kolom yang disebut.

Keluaran ilustrasi:

```
1187   Jun 15, 2027 08:03:12.418  10.10.60.163  203.0.113.191  443  0x00000001  cfg.edge-relay.example  h3,h3-29
1215   Jun 15, 2027 08:03:13.420  10.10.60.163  203.0.113.191  443  0x00000001  cfg.edge-relay.example  h3,h3-29
1290   Jun 15, 2027 08:03:15.423  10.10.60.163  203.0.113.191  443  0x00000001  cfg.edge-relay.example  h3,h3-29
40211  Jun 15, 2027 08:08:15.077  10.10.60.163  203.0.113.191  443  0x00000001  cfg.edge-relay.example  h3,h3-29
```

**Cara membaca hasil:**

- Tiga frame pertama adalah satu percobaan: Initial yang sama dikirim ulang setelah sekitar 1 dan 2 detik karena tidak ada balasan. Jarak pengulangan bergantung timer klien; cek di lab bila angka ini dipakai.
- Frame 40211 adalah percobaan berikutnya, 302,659 detik setelah frame 1187. Itu ritme sekitar lima menit.
- Versi `0x00000001` adalah QUIC versi 1, sehingga dekripsi Initial berhasil dan SNI terbaca. ALPN menawarkan `h3` dan `h3-29`; `quic.log` Zeek hanya mencatat protokol pertama di `client_protocol` [S12].
- Paket ini tidak pernah sampai ke internet. Yang membuatnya terlihat adalah posisi TAP di sisi dalam firewall.

Bila sebuah baris QUIC tidak punya SNI, ada dua kemungkinan: ECH dipakai (Day 15), atau penguraian gagal. Bedakan dengan memeriksa apakah ekstensi ECH (`tls.handshake.extension.type == 0xfe0d`, codepoint `encrypted_client_hello` di RFC 9849 [S21]) ada di ClientHello-nya, dan apakah versinya dikenal.

**Variasi:** di Suricata, event `quic` di `eve-proto` (disimpan 7 hari di sensor) memuat `sni`, `version`, dan `ja4` untuk Initial yang sama [S13]; JA4 untuk QUIC berawalan `q` (Day 06). Untuk mengekspor semua SNI QUIC dari satu file ring: ganti `-Y` dengan `quic && tls.handshake.type == 1` dan `-e` dengan `ip.src -e tls.handshake.extensions_server_name`, lalu `sort | uniq -c`.

**Kapan gagal:** versi QUIC yang tidak dikenali alatmu, karena kunci Initial diturunkan dari konstanta per versi [S5][S8]. Periksa nomor versi di long header lebih dulu; di Zeek, huruf `U` di `history` menandai versi yang tidak dikenal [S12]. ClientHello yang besar (misalnya dengan kunci pasca-kuantum) bisa terbagi ke beberapa Initial, sehingga file ring yang terpotong di tengah percobaan kehilangan sebagian. Dan ECH di atas QUIC membuat SNI yang terbaca hanya nama luar.

### 2.4 Merangkai `JKT-WS-2078` dan membuka `INC-2027-075`

Artefak keempat menjawab bagian kedua pertanyaan 8 untuk kandidat dari bagian 2.3. `JKT-WS-2078` (`10.10.60.163`) dipakai `laras.wulandari` dari tim Pemasaran. Yang perlu dijawab: dari mana host ini tahu alamat `cfg.edge-relay.example`, apa yang terjadi setelah QUIC ditolak, dan sejak kapan.

**Tujuan:** menyusun satu siklus lengkap dari tiga sumber (proxy, sensor, firewall), lalu memastikan nama tujuan tidak pernah di-resolve lewat resolver internal.

```
index=proxy src=10.10.60.163 earliest="06/14/2027:00:00:00" latest="06/16/2027:12:00:00"
    (host="doh.quadresolve.example" OR host="203.0.113.191")
| stats count min(_time) AS pertama max(_time) AS terakhir values(method) AS method values(url_path) AS url_path
        values(category) AS kategori values(http_user_agent) AS ua BY host
| convert ctime(pertama) ctime(terakhir)

index=dns sourcetype=isc:bind:query earliest="05/17/2027:00:00:00" latest="06/16/2027:12:00:00"
    (query="*edge-relay.example" OR query="*quadresolve.example")
| stats count min(_time) AS pertama BY src query
| convert ctime(pertama)
```

Penjelasan tiap bagian:

- Query pertama mengambil semua baris proxy dari host itu ke penyedia DoH dan ke alamat tujuan QUIC, sejak Senin. Field proxy (`host`, `method`, `url_path`, `category`, `http_user_agent`) mengikuti logformat PT JAB seperti Day 11. Domain kategori "DNS over HTTPS" di-splice, sehingga hanya `CONNECT` yang tercatat; tujuan berupa alamat IP tidak terkategori dan di-bump, sehingga metode dan path di dalam tunnel ikut tercatat (Day 06 bagian 1.7).
- Query kedua mencari kedua nama di log resolver sepanjang retensi 30 hari. Untuk nama yang dipakai sebuah host, ketiadaan di sini sama pentingnya dengan keberadaan.

Keluaran ilustrasi:

```
host                     count  pertama              terakhir             method        url_path  kategori        ua
doh.quadresolve.example  163    06/14/2027 16:23:10  06/16/2027 11:38:02  CONNECT       -         DNS over HTTPS  Go-http-client/1.1
203.0.113.191            326    06/14/2027 16:23:14  06/16/2027 11:38:06  CONNECT POST  /v1/cfg   Uncategorized   Go-http-client/1.1

src         query                    count  pertama
10.20.3.60  doh.quadresolve.example  9      06/14/2027 16:23:10
```

Pemeriksaan yang sama di `index=zeek sourcetype=bro:dns:json` untuk `*edge-relay.example` juga kosong: tidak ada query dari workstation, proxy, atau resolver ke server otoritatif untuk nama itu.

Satu siklus, disusun dari ketiga sumber (WIB):

```
08:01:55.6  index=proxy      CONNECT doh.quadresolve.example:443 dari 10.10.60.163 (splice, isi tertutup)
08:01:56.2  quic.log (TAP)   Initial 10.10.60.163 -> 203.0.113.191:443, SNI cfg.edge-relay.example, ALPN h3, history I
08:01:56.2  index=firewall   deny udp 10.10.60.163 -> 203.0.113.191:443 (3 paket dalam 3 detik)
08:01:59.3  index=proxy      CONNECT 203.0.113.191:443, lalu POST /v1/cfg (bump), status 200
            ... berulang sekitar setiap 5 menit; Senin 17 siklus, Selasa 112, Rabu 34 sampai 11:38
```

**Cara membaca hasil:**

- 163 siklus menghasilkan 163 `CONNECT` ke penyedia DoH dan 326 baris ke `203.0.113.191` (satu `CONNECT` dan satu `POST` per siklus). Firewall mencatat 3 x 163 = 489 penolakan UDP 443 dari host ini.
- Nama `cfg.edge-relay.example` hanya terbaca dari Initial QUIC yang ditolak. Tidak ada satu pun query untuk nama itu di resolver internal dalam 30 hari, dan proxy dipakai dengan alamat IP, bukan nama. Satu-satunya jalur resolusi yang cocok waktunya adalah `CONNECT` ke penyedia DoH 0,6 detik sebelum setiap Initial. Itu pola yang dicatat ATT&CK di T1572: query untuk infrastruktur C2 dibungkus di dalam HTTPS [S20]. Isi query DoH tidak terlihat, jadi pernyataan ini adalah kesimpulan dari urutan waktu, bukan dari isi.
- Senin hanya ada 17 siklus, di bawah ambang rule "minimal 20 kali sehari"; karena itu alert baru muncul Selasa.
- User-Agent `Go-http-client/1.1` bukan Edge, browser armada PT JAB (Day 11).
- Penjelasan jinak yang diuji: alat privasi seperti milik Fikri (tidak cocok, karena DNS sistem host ini tetap normal di bagian 2.2 dan tujuan berikutnya berprevalence satu), updater aplikasi yang memakai DoH bawaan (tidak ada aplikasi terdaftar yang cocok), dan klien rapat video (nama dan vendornya berbeda).

MDE menutup sisi host: koneksi ke `10.20.3.60:3128` dan UDP ke `203.0.113.191:443` berasal dari `netcfgsvc.exe` di `C:\Users\laras.wulandari\AppData\Roaming\NetCfg\`, tidak bertanda tangan, pertama terlihat Senin 2027-06-14 16:22, dan hanya ada di satu perangkat di organisasi. Laras tidak mengenali program itu.

Keputusan Rabu pukul 11:40: `INC-2027-075` dibuka dengan ringkasan "kandidat C2 dari `JKT-WS-2078`: resolusi lewat DoH (T1572), percobaan QUIC langsung yang ditolak, lalu HTTPS lewat proxy ke `203.0.113.191`". Host diisolasi lewat MDE pukul 11:52; `203.0.113.191` dan `cfg.edge-relay.example` diblokir di firewall dan proxy; analisis proses dan cara masuknya diserahkan ke tim IR. `doh.quadresolve.example` tidak diblokir hanya karena insiden ini, karena layanan itu sendiri sah; perubahan kategori DoH di proxy diajukan sebagai keputusan kebijakan (bagian 2.8).

**Variasi:** jadikan pola ini correlation search: `CONNECT` ke kategori "DNS over HTTPS" dari klien non-Edge, diikuti dalam 5 detik oleh `CONNECT` ke alamat IP literal dari host yang sama. Untuk server yang keluar langsung, ganti log proxy dengan `ssl.log` atau `quic.log` dan cari tujuan yang tidak pernah muncul di `dns.log`.

**Kapan gagal:** implant yang memakai DoH lalu langsung TCP lewat proxy tanpa mencoba QUIC tidak meninggalkan SNI di `quic.log`; namanya hanya bisa ditebak dari alamat IP. Implant yang memakai ECH atau domain fronting di atas CDN besar membuat nama yang terbaca adalah nama luar. Dan bila penyedia DoH juga menyajikan konten web biasa, pola "CONNECT ke penyedia DoH" kehilangan ketajamannya.

### 2.5 Mengenali alur QUIC dan batas penautannya: `SOC-2027-0678`

Artefak kelima menjawab pertanyaan 4, 5, dan 6 untuk Bambang. Selasa pukul 20:15, rule "lonjakan alur UDP baru ke DMZ" berbunyi untuk portal pelanggan `jkt-dmz-web03` (`10.20.9.70`, publik `198.51.100.216`, HTTP/3 aktif). Portal berada di DMZ di belakang core switch, sehingga terlihat di SPAN core DC dengan alamat sesudah DNAT (Day 04), tetapi tidak ada di pcap egress.

**Tujuan:** memisahkan alur QUIC baru yang dimulai dengan Initial dari alur yang muncul di tengah jalan, lalu mencari penyebab lonjakan.

Perintah dasar untuk `conn.log` TSV (Zeek offline atau lab):

```
# Zeek: alur UDP yang kandidat QUIC, dikelompokkan per pasangan
cat conn.log | zeek-cut proto id.orig_h id.resp_h id.resp_p duration orig_bytes \
  | awk '$1 == "udp" && $6 > 1200'
```

Ambang 1200 byte dipakai karena datagram yang membawa Initial berisi minimal 1200 byte muatan UDP [S5]. Ini penyempit yang berguna, bukan identifikasi. Perhatikan bahwa `orig_bytes` adalah total muatan dari originator selama alur itu, bukan ukuran satu datagram, sehingga filter ini sebenarnya membuang alur UDP kecil (DNS, NTP, probe) dan menyisakan alur yang cukup besar untuk memuat setidaknya satu Initial.

Versi Splunk untuk data live, dengan pemisahan alur yang dikenali sebagai QUIC:

```
index=zeek sourcetype=bro:conn:json proto=udp id.resp_h=10.20.9.70 id.resp_p=443
    earliest="06/15/2027:20:00:00" latest="06/15/2027:20:20:00"
| eval dengan_initial=if(match(service,"quic"),1,0)
| bin _time span=5m
| stats count AS alur sum(dengan_initial) AS dengan_initial dc(id.orig_h) AS sumber median(orig_bytes) AS med_orig BY _time
```

Penjelasan tiap bagian: field `service` di `conn.log` diisi nama analyzer yang mengenali protokol; analyzer QUIC Zeek hanya mengenali alur yang dimulai dengan Initial (bagian 1.5), sehingga alur yang muncul dengan short header saja memiliki `service` kosong. Nilai persis `service` untuk QUIC perlu dicek di `conn.log` versi Zeek-mu. `median(orig_bytes)` dipakai untuk membandingkan ukuran alur sebelum dan sesudah lonjakan.

Keluaran ilustrasi:

```
_time             alur  dengan_initial  sumber  med_orig
06/15/2027 20:00  148   121             63      18422
06/15/2027 20:05  161   130             66      17950
06/15/2027 20:10  566   164             71      16804
06/15/2027 20:15  554   159             70      17311
```

**Cara membaca hasil:**

- Sepuluh menit sebelum lonjakan ada 148 + 161 = 309 alur; sepuluh menit sesudahnya 566 + 554 = 1.120 alur. Alur yang dimulai dengan Initial hampir tidak berubah (251 menjadi 323); kenaikannya adalah alur tanpa Initial: 1.120 - 323 = 797, atau 71% dari alur sesudah lonjakan.
- Jumlah sumber naik sedikit (66 menjadi 71) dan median byte per alur tetap di kisaran 17 kB. Lonjakan alur yang besar dari sumber yang sama, dengan ukuran sesi normal, bukan bentuk banjir paket kecil.
- Dari 797 alur tanpa Initial, 731 (91,7%) bersumber dari `198.51.100.210`, alamat CGNAT pelanggan PT JAB sendiri (Day 10).

Penyebabnya ada di `index=netops`:

```
index=netops host=jkt-cgn01 earliest="06/15/2027:20:00:00" latest="06/15/2027:20:20:00"
| table _time host _raw
```

Keluaran ilustrasi:

```
06/15/2027 20:08:12  jkt-cgn01  HA: switchover ke unit sekunder dimulai (pemeliharaan terjadwal NOC)
06/15/2027 20:08:30  jkt-cgn01  HA: switchover selesai; sinkronisasi state UDP tidak aktif, mapping UDP dibuat ulang
```

Switchover tanpa sinkronisasi state UDP membuat setiap sesi UDP pelanggan mendapat port baru di blok PBA-nya. Klien QUIC tetap memakai Connection ID yang sama dan melanjutkan dengan short header dari alamat dan port baru; di sisi portal, itu NAT rebinding, dan di `conn.log` itu alur baru tanpa Initial (bagian 1.6).

Yang perlu kamu catat di laporan saat menganalisis alur QUIC:

- Jangan menyimpulkan koneksi berakhir dari ketiadaan paket, karena QUIC tidak punya sinyal penutupan yang terlihat [S5].
- Jangan mengandalkan Connection ID untuk menautkan alur sebelum dan sesudah migrasi, karena migrasi yang disengaja mengubahnya [S5]. Pada NAT rebinding seperti kasus ini, DCID biasanya sama dan penautan sering berhasil; pada migrasi yang disengaja, tidak.
- Dua alur dengan lima-tuple berbeda bisa jadi satu koneksi yang sama; sebaliknya, satu lima-tuple bisa memuat beberapa koneksi bila Connection ID berpanjang nol tidak dipakai [S5].

Keputusan: `SOC-2027-0678` ditutup sebagai jinak terkonfirmasi (rebinding akibat switchover CGNAT). Dua tindak lanjut untuk Bambang dan Agung: jadwal pemeliharaan CGNAT dikirim ke SOC sebelum pelaksanaan, dan UDP idle timeout aturan portal di `jkt-fw01` dinaikkan dari 30 detik ke minimal 120 detik, sesuai rekomendasi menyimpan state QUIC minimal dua menit [S5]. Pemeriksaan ini hanya memakai metadata alur dari alamat CGNAT; tidak ada pemetaan ke pelanggan tertentu lewat RADIUS atau log PBA, karena pertanyaannya tentang pola jaringan, bukan tentang individu (Day 10 bagian 2.9).

**Variasi:** untuk flow `jkt-flow01` di router data center (sampling 1:1, idle timeout 15 detik), hitung record UDP 443 ke `198.51.100.216` per 5 menit dengan nfdump dan bandingkan pola kenaikannya; satu koneksi QUIC yang berjeda lebih dari 15 detik akan menjadi beberapa record bahkan tanpa rebinding (bagian 1.4).

**Kapan gagal:** bila sumber lonjakan tersebar luas di luar pelanggan sendiri, byte per alur kecil dan seragam, dan tidak ada perubahan jaringan yang cocok waktunya, pembeda di atas tidak berlaku dan kasus perlu diperlakukan sebagai kemungkinan serangan; RFC 9312 sendiri menyatakan migrasi yang disengaja tidak bisa dibedakan dari trafik serangan [S5].

### 2.6 Mengukur RTT

Artefak keenam menjawab pertanyaan 7. Bambang ingin RTT pelanggan ke portal tanpa agent. Karena portal tidak ada di pcap egress, tim Agung merekam 10 menit header saja di `jkt-dmz-web03` dengan tiket yang disetujui, lalu file disalin ke `jkt-nsm-ws01`.

**Tujuan:** mengukur handshake RTT dan RTT dari spin bit untuk koneksi yang sama, lalu memutuskan angka mana yang dilaporkan.

```
# di jkt-dmz-web03 (oleh tim Infrastruktur): 10 menit, 128 byte pertama per paket
tcpdump -i ens192 -s 128 -G 600 -W 1 -w /var/tmp/SOC-2027-0678-rtt.pcap 'udp port 443'
```

Penjelasan tiap bagian: `-s 128` menyimpan hanya 128 byte pertama tiap paket, cukup untuk header IP, UDP, dan header QUIC (bentuk header, tipe paket, versi, Connection ID, spin bit), tetapi tidak untuk isi Initial; ini sengaja, karena pertanyaannya tentang waktu, bukan tentang tujuan atau isi trafik pelanggan. `-G 600 -W 1` membuat tcpdump berhenti setelah satu file 600 detik. Wireshark akan menandai paket sebagai terpotong; cek di lab bahwa dissector QUIC tetap mengurai header pada snaplen ini.

Handshake RTT, yang paling andal [S5]:

```
# selisih waktu antara Client Initial dan Server Initial pada alur yang sama
quic.long.packet_type == 0
```

Catat waktu paket Initial dari klien dan dari server, lalu hitung selisihnya. Ulangi untuk pasangan Handshake, lalu jumlahkan kedua komponennya [S5]. Dengan tshark, untuk satu koneksi:

```
tshark -r SOC-2027-0678-rtt.pcap \
  -Y 'udp.port == 40211 && (quic.long.packet_type == 0 || quic.long.packet_type == 2)' \
  -T fields -e frame.time_relative -e ip.src -e quic.long.packet_type -e quic.dcid
```

Penjelasan: di QUIC versi 1, tipe paket long header 0 adalah Initial dan 2 adalah Handshake; `udp.port == 40211` memilih satu koneksi dari alamat CGNAT; `quic.dcid` dicetak untuk memastikan semua baris milik koneksi yang sama [S10].

Keluaran ilustrasi:

```
0.000000  198.51.100.210  0  5f2a9c41d07e83b6
0.000412  10.20.9.70      0  c3e1a7d2
0.000412  10.20.9.70      2  c3e1a7d2
0.038655  198.51.100.210  2  9b44e0a1
```

Cara membaca: komponen pertama (Client Initial ke Server Initial) 0,412 ms, karena pengamat berada di server dan yang terukur hanya waktu proses server. Komponen kedua (Handshake server ke Handshake klien) 38,655 - 0,412 = 38,243 ms, yaitu perjalanan pulang-pergi ke pelanggan. Jumlahnya 38,655 ms, sekitar 39 ms. DCID berbeda antar arah karena setiap endpoint memakai Connection ID yang dipilih lawannya; perubahan DCID klien setelah Initial pertama adalah perilaku normal.

Untuk spin bit, filternya bergantung versi Wireshark; di 4.6.9 field-nya `quic.spin_bit` pada short header (`quic.header_form == 0`) [S10]. Yang penting adalah menafsirkan hasilnya dengan benar. Tulis di laporan bahwa sampelnya mencakup penundaan aplikasi, bahwa sebagian koneksi memang mematikan spinning, dan bahwa pengurutan ulang bisa menghasilkan tepi palsu [S5]. Saring hasilnya, misalnya dengan menolak pencilan atau memakai minimum bergerak [S5].

```
tshark -r SOC-2027-0678-rtt.pcap -Y 'quic.header_form == 0 && ip.src == 198.51.100.210 && udp.srcport == 40211' \
  -T fields -e frame.time_relative -e quic.spin_bit
```

Keluaran ilustrasi (hanya baris saat nilai berganti):

```
1.204118  True
1.242870  False
1.281533  True
4.909761  False
4.948407  True
```

Cara membaca: selisih antar tepi adalah 38,752 ms, 38,663 ms, 3.628,228 ms, dan 38,646 ms. Tiga sampel cocok dengan handshake RTT; sampel 3,6 detik adalah jeda ketika pengguna tidak meminta apa pun, jadi yang terukur adalah periodisitas aplikasi, bukan RTT jaringan. Minimum bergerak atas sampel itu memberi sekitar 38,6 ms. Dari 1.388 koneksi QUIC di file 10 menit itu, 177 (12,8%) tidak pernah mengganti spin bit, sedikit di atas seperdelapan yang memang dimatikan endpoint secara sengaja.

**Variasi:** untuk dashboard NOC, hitung handshake RTT per koneksi untuk seluruh file dan laporkan median dan persentil 90 per prefiks pelanggan, bukan per alamat.

**Kapan gagal:** spin bit mati atau acak di sebagian koneksi; pengurutan ulang membuat tepi palsu; dan bila Retry dipakai, jeda Client Initial ke Server Initial pertama memuat satu RTT tambahan. Handshake RTT hanya ada sekali per koneksi, jadi koneksi panjang tidak memberi sampel baru.

### 2.7 Menyusun peta visibilitas

Artefak ketujuh adalah keluaran akhir Day ini, yang melanjutkan peta celah ECH di Day 15. Tabel umumnya:

| Lapis | Keadaan di jaringanmu | Yang masih bisa dijawab |
|---|---|---|
| DNS polos | sebagian host | Tujuan yang hendak dihubungi |
| DoT atau DoQ | terdeteksi di port 853 | Siapa yang memakai resolver terenkripsi, ke penyedia mana |
| DoH | hanya terdeteksi lewat daftar penyedia dan pola | Perkiraan, bukan kepastian |
| TLS dengan SNI | sebagian besar | Tujuan koneksi |
| TLS dengan ECH | sebagian, bertambah | Hanya penyedia dan alamat |
| QUIC tanpa ECH | SNI dan ALPN dari Initial | Tujuan koneksi |
| QUIC dengan ECH | - | Hanya alamat dan pola |

Untuk rapat jam 14:00, tabel itu diisi dengan keadaan PT JAB per Rabu 2027-06-16. Baca kolom kanan: itulah sumber yang menggantikan lapisan yang hilang.

| Lapis | Keadaan di PT JAB | Sumber pengganti |
|---|---|---|
| DNS polos workstation | Semua workstation ke `jkt-res01`/`02`; 1 host keluar ke DoH (Fikri, sudah ditangani) | Log resolver, `dns.log` |
| DoT dan DoQ dari workstation | Ditolak firewall; 1 host (Fikri) mencoba dalam 30 hari | Log firewall, `quic.log` untuk DoQ |
| DoH dari workstation | Lewat proxy sebagai `CONNECT`, isi tertutup; 2 host Selasa | Log proxy, `http.log` hop core, rasio DNS |
| QUIC dari workstation | Ditolak firewall; percobaan tetap memberi SNI | `quic.log` (TAP sisi dalam firewall) |
| QUIC dari server DC dan ke portal | Terlihat penuh di header; SNI dari Initial | `quic.log`, event `quic` Suricata |
| QUIC dengan versi tidak dikenal | `history` `U`, SNI kosong | Alamat dan pola saja |
| QUIC dengan ECH | Belum teramati di PT JAB, akan bertambah | Alamat dan pola saja |

Tabel ini yang membuat percakapan dengan manajemen menjadi konkret: ia menunjukkan bahwa kebutaan bukan saklar yang hidup atau mati, melainkan lapisan yang menipis satu per satu, dan tiap lapisan punya pengganti yang berbeda biayanya.

### 2.8 Jawaban untuk Dimas dan Bambang

Ringkasan yang dibawa ke rapat jam 14:00, satu baris per pertanyaan; kolom kanan menunjuk bagian yang menjadi dasarnya.

| Pertanyaan | Jawaban singkat | Bagian |
|---|---|---|
| 1. DoH, DoT, DoQ | DoT (TCP 853) dan DoQ (UDP 853) mudah dikenali dari port; DoH sengaja tidak bisa dibedakan dari HTTPS | 1.1, 2.1 |
| 2. DoH di balik proxy | Terlihat sebagai `CONNECT` ke penyedia DoH di log proxy dan `http.log`; rasio DNS per koneksi menangkap DoH level sistem | 1.2, 2.2 |
| 3. Yang terlihat dari QUIC | Header, versi, Connection ID, dan isi Initial termasuk SNI dan ALPN, bahkan untuk percobaan yang ditolak firewall karena TAP di sisi dalam | 1.3, 2.3 |
| 4. Alur putus-putus | QUIC tidak punya sinyal penutupan; flow dan Zeek memotong berdasarkan timeout | 1.4, 2.5 |
| 5. UDP 443 = QUIC? | Tidak andal; pakai parser yang mendekripsi Initial (`quic.log`, Suricata, Wireshark) | 1.5 |
| 6. Lonjakan alur portal | Rebinding akibat switchover `jkt-cgn01` tanpa sinkronisasi state UDP; jinak; naikkan UDP timeout portal ke minimal 120 detik | 1.6, 2.5 |
| 7. RTT dari spin bit | Bisa, setelah pencilan disaring; handshake RTT sekitar 39 ms sebagai pembanding yang lebih andal | 1.7, 2.6 |
| 8. Blokir dan insiden | Pertahankan blok 853 dan UDP 443 dari workstation; tetapkan `DnsOverHttpsMode` `off` lewat GPO; ajukan blok kategori DoH di proxy kecuali daftar pengecualian; `INC-2027-075` dibuka untuk `JKT-WS-2078` | 1.8, 1.9, 2.4 |

## 3. Lab praktik (di VM lab terisolasi)

**Prasyarat:** VM lab dengan Wireshark 4.6.x dan Zeek 9.0 (Day 08) di jaringan host-only `192.168.56.0/24`, semua dengan snapshot; satu VM klien Windows atau Linux yang bisa dikonfigurasi memakai DoH dan DoT; browser yang mendukung HTTP/3; resolver lab (misalnya dnsmasq atau BIND di `192.168.56.53`) untuk baseline DNS polos. Akses internet untuk langkah yang butuh penyedia DoH publik atau situs HTTP/3 lewat NAT VM yang terekam di VM sensor. Tidak ada data PT JAB di lab, dan tidak ada sampel malware atau alat tunneling.

1. Rekam trafik dengan DNS polos, lalu dengan DoT, lalu dengan DoH. Bandingkan ketiganya berdampingan dan tulis apa yang bisa kamu lihat di masing-masing.
2. Buktikan bahwa DoT terdeteksi definitif lewat port 853, lalu buktikan bahwa DoH tidak terdeteksi oleh filter port mana pun.
3. Bangun baseline rasio kueri DNS terhadap jumlah koneksi per host di lab-mu, lalu ubah satu host ke DoH dan buktikan rasionya anjlok. Pakai perintah `join` di bagian 2.2 pada log TSV hasil `zeek -r`.
4. Kumpulkan daftar alamat penyedia DoH publik, lalu ukur berapa banyak host di lab-mu yang terdeteksi lewat daftar itu. Catat kelemahan pendekatan ini.
5. Rekam kunjungan HTTP/3, lalu ekstrak SNI dan ALPN dari paket Initial QUIC dengan filter `quic && tls.handshake.type == 1` dan field `tls.handshake.extensions_server_name`. Buktikan bahwa keduanya terbaca tanpa kunci apa pun. Jalankan Zeek atas pcap yang sama dan bandingkan dengan `quic.log` (`server_name`, `client_protocol`, `history`).
6. Hitung handshake RTT dari pasangan Initial dan pasangan Handshake, lalu bandingkan dengan RTT yang diukur `ping` ke alamat yang sama.
7. Paksa migrasi koneksi, misalnya dengan berpindah antarmuka jaringan di tengah unduhan, lalu amati apa yang terjadi pada lima-tuple dan Connection ID, dan ukur berapa lama alur tetap terlihat setelah aktivitas berhenti.
8. Susun peta visibilitas bagian 2.7 untuk lab-mu dengan angka nyata, lalu gabungkan dengan peta celah dari Day 15 menjadi satu dokumen.

Variasi dan tantangan:

- **Percobaan yang ditolak.** Pasang aturan di VM router lab yang membuang UDP 443 dari klien, rekam di sisi klien router (posisi seperti TAP di sisi dalam firewall), lalu buka situs HTTP/3. Tunjukkan bahwa `quic.log` tetap memuat `server_name` dengan `history` `I`, dan ukur jarak pengulangan Initial yang dikirim klien.
- **Snaplen.** Rekam ulang langkah 6 dengan `-s 128` dan pastikan handshake RTT dan spin bit masih bisa dibaca, sementara SNI tidak.
- **Kebijakan browser.** Di VM Windows dengan Edge, set `DnsOverHttpsMode` ke `off`, `automatic`, lalu `secure`, dan `QuicAllowed` ke nonaktif; catat perubahan di pcap untuk tiap nilai. Ulangi untuk Firefox dengan resolver lab yang menjawab NXDOMAIN untuk `use-application-dns.net`.
- **Versi QUIC.** Bila klien lab mendukung QUIC versi 2, rekam satu koneksi dan periksa `quic.version`, `quic.long.packet_type_v2`, dan apakah Zeek menulis huruf `U` atau berhasil mendekripsi.

**Hasil yang sebaiknya tersimpan:**

- Perbandingan berdampingan trafik DNS polos, DoT, dan DoH.
- Bukti bahwa DoH tidak terdeteksi oleh filter port.
- Baseline rasio kueri DNS terhadap koneksi, sebelum dan sesudah satu host berpindah ke DoH.
- Daftar penyedia DoH yang dipakai beserta catatan kelemahannya.
- SNI dan ALPN yang berhasil diekstrak dari paket Initial QUIC, dan baris `quic.log` yang sama.
- Perbandingan handshake RTT dengan hasil `ping`.
- Catatan hasil percobaan migrasi koneksi.
- Bukti bahwa Initial yang dibuang router tetap memberi SNI di sisi dalam.
- Peta visibilitas gabungan Day 15 dan Day 16 dengan angka lab sendiri.

## 4. Troubleshooting

Tabel ini dipakai saat hasil tidak sesuai harapan; mulai dari kolom gejala.

| Gejala | Kemungkinan penyebab | Cara memeriksa |
|---|---|---|
| Tidak ada trafik di port 853 | Klien memakai DoH, bukan DoT atau DoQ | Periksa konfigurasi resolver klien; pakai pendekatan bagian 2.2 |
| Filter QUIC tidak menghasilkan apa pun | Trafik di port selain 443, atau versi tidak dikenali | Port bukan indikator andal [S5]; periksa nomor versi di long header |
| SNI tidak muncul di QUIC | ECH dipakai, atau penguraian Initial gagal | Periksa keberadaan ekstensi ECH `0xfe0d` (Day 15); periksa versi QUIC |
| Filter `quic.tls.handshake.extensions_server_name` ditolak Wireshark | Field itu tidak ada di 4.6.9 | Pakai `tls.handshake.extensions_server_name` dengan `quic` [S10][S11] |
| `quic.long.packet_type == 0` tidak menangkap Initial | Koneksi memakai QUIC versi 2 | Pakai `quic.long.packet_type_v2 == 1` [S9][S10] |
| `quic.log` kosong padahal ada UDP 443 | Analyzer QUIC tidak mengenali alur (mulai dengan short header, versi tidak dikenal) | Cek `history` `U`; cek `service` di `conn.log`; alur hasil migrasi tidak punya Initial |
| `sourcetype=bro:quic:json` tidak mengembalikan apa pun | Nama sourcetype berbeda di instalasi | `\| metadata type=sourcetypes index=zeek` |
| Alur QUIC terlihat putus di tengah | Tidak ada sinyal penutupan; atau migrasi mengubah lima-tuple [S5] | Jangan simpulkan koneksi berakhir; cari alur baru ke tujuan sama |
| Alur QUIC hilang dari log flow | Idle timeout perangkat terlalu pendek untuk QUIC [S5] | Perpanjang state; rujukan minimal dua menit |
| RTT dari spin bit terlihat aneh | Sampel mencakup penundaan aplikasi, atau ada tepi palsu [S5] | Pakai handshake RTT sebagai pembanding; saring pencilan |
| Dua alur tidak bisa ditautkan | Connection ID berubah saat migrasi [S5] | Nyatakan batasnya; jangan mengarang penautan |
| DoH tidak terdeteksi sama sekali | Dicampur ke koneksi HTTPS yang membawa trafik lain [S1] | Pakai sinyal ketiadaan DNS polos (bagian 2.2) |
| Parser `doh2` Suricata tidak mencatat apa pun | DoH masih di dalam TLS; parser butuh HTTP/2 cleartext [S14] | Jangan berharap event DoH dari sensor egress terenkripsi |
| Correlation search rasio DNS ramai di hari Senin | Baseline memuat akhir pekan atau libur | Pisahkan baseline hari kerja; naikkan syarat minimal koneksi |

## 5. Kesalahan umum dan jebakan

- Menganggap QUIC sepenuhnya buram, padahal paket Initial bisa didekripsi pengamat dan membawa SNI serta ALPN [S5][S8].
- Menganggap koneksi yang ditolak firewall tidak meninggalkan informasi. Dengan TAP di sisi dalam firewall, Initial yang ditolak tetap membawa nama tujuan.
- Memakai port 443 sebagai penanda HTTP/3, padahal aplikasi lain juga memakainya dan HTTP/3 bisa di port lain [S5].
- Memakai fixed bit atau heuristik byte pertama untuk mengenali QUIC, atau menerapkan kontrol akses berbasis versi [S5]; dan menganggap filter tipe paket versi 1 berlaku untuk versi 2 [S9].
- Menyimpulkan koneksi QUIC berakhir karena paketnya berhenti.
- Menautkan alur sebelum dan sesudah migrasi lewat Connection ID tanpa menyebut bahwa penautan itu tidak dijamin [S5].
- Melaporkan kehilangan paket dari pengamatan pasif atas QUIC, yang memang tidak mungkin [S5].
- Mengandalkan daftar penyedia DoH sebagai deteksi yang lengkap, atau menyimpulkan host tidak melakukan resolusi nama hanya karena tidak ada kueri DNS polos.
- Menyamakan "memakai DoH" dengan "C2". `JKT-WS-2076` dan `JKT-WS-2078` memakai penyedia yang sama dengan kesimpulan berbeda; T1572 hanya dipakai bila ada bukti penyembunyian infrastruktur C2 [S20].
- Menganggap pendekatan rasio DNS menangkap semua DoH; DoH satu aplikasi tidak menurunkan rasio host.
- Memperlakukan RTT dari spin bit sebagai RTT jaringan murni [S5], atau memakai komponen pertama handshake RTT saja dari pengamat yang dekat dengan server.
- Menyatakan lonjakan alur UDP baru sebagai DDoS tanpa memeriksa perubahan jaringan, sumber, dan ukuran alur; migrasi yang disengaja tidak bisa dibedakan dari serangan dari pola saja [S5].
- Mengandalkan kebijakan browser untuk memblokir DoH di seluruh host; kebijakan Edge dan canary domain Firefox tidak mengatur aplikasi lain [S16][S18].

## 6. Catatan terkini

Bagian ini menampung detail versi, tanggal terbit, dan perubahan yang perlu dipantau tetapi tidak mengubah langkah di atas.

- RFC 8484 menyatakan sendiri bahwa sistem penyaringan atau inspeksi yang bergantung pada transport DNS yang tidak diamankan tidak akan berfungsi di lingkungan DoH [S1]. Pernyataan itu berasal dari standarnya, sehingga bisa dipakai sebagai dasar diskusi arsitektur tanpa perlu bersandar pada klaim vendor.
- DoQ secara eksplisit melarang pemakaian UDP port 53 dan mereservasi UDP port 853 [S3], sehingga pengenalannya sederhana. Perbedaan tajam antara kemudahan mengenali DoQ dan sulitnya mengenali DoH layak dicatat saat merancang pemantauan.
- RFC 9312 menyebut tidak ada metode umum untuk mengenali QUIC, dan bahwa trafik UDP yang tidak dikenali bisa saja QUIC [S5]. Artinya setiap angka "berapa persen trafik kami QUIC" yang kamu lihat adalah perkiraan, termasuk angka dari produk komersial.
- Rekomendasi menyimpan state QUIC minimal dua menit [S5] sering bertabrakan dengan timeout UDP bawaan perangkat jaringan yang jauh lebih pendek, dan itu penyebab umum log flow yang terpotong. Kemampuan membaca SNI dari paket Initial juga akan hilang begitu ECH dipakai di atas QUIC (Day 15), jadi peta visibilitas di bagian 2.7 perlu diperbarui berkala. ECH distandarkan sebagai RFC 9849 pada Maret 2026, dengan codepoint ekstensi `0xfe0d` [S21].
- QUIC versi 2 (RFC 9369, Mei 2023) memakai nomor versi `0x6b3343cf`, salt baru, dan pengodean tipe paket yang diacak ulang untuk melawan osifikasi [S9]. Wireshark punya field `quic.long.packet_type_v2` sejak 4.0.0 [S10]; cek dukungan versi 2 di parser Zeek dan Suricata versi-mu sebelum mengandalkan SNI dari Initial versi 2.
- Suricata 8 menambah parser DoH di atas HTTP/2 (`doh2`), yang bekerja pada trafik cleartext [S14]. Kerentanan CVE-2026-94083 pada parser ini (type confusion saat upgrade HTTP/1 ke HTTP/2) diperbaiki di Suricata 8.0.7; versi lebih lama perlu mematikan `app-layer.protocols.doh2` [S15].
- Zeek 9.0 mencatat QUIC di `quic.log` dengan field `server_name`, `client_protocol`, dan `history` [S12]; Suricata mencatat event `quic` dengan `sni`, `version`, `cyu`, `ja3`, dan `ja4` [S13].
- Kebijakan Edge `DnsOverHttpsMode` (Edge 83 ke atas) dan `QuicAllowed` (Edge 77 ke atas) didokumentasikan di halaman Microsoft Learn bertanggal 20 Mei 2026 [S16][S17]. Mozilla menyebut canary domain `use-application-dns.net` sebagai langkah sementara sampai ada standar untuk memberi sinyal penyaringan DNS [S18].
- ATT&CK T1572 Protocol Tunneling versi 1.1 (diubah 3 September 2026) memuat contoh DoH untuk me-resolve infrastruktur C2 [S20].

## 7. Cheat sheet

```
DNS TERENKRIPSI
  DoT  RFC 7858  TLS/TCP port 853     -> mudah dikenali (filter port); ALPN dot
  DoQ  RFC 9250  QUIC/UDP port 853    -> mudah dikenali; DILARANG pakai UDP 53; ALPN doq
  DoH  RFC 8484  HTTP/TLS port 443    -> TIDAK ADA cara mengenali (memang dirancang begitu)
       RFC-nya menyatakan: sistem filter/inspeksi yang bergantung DNS tidak aman TIDAK akan berfungsi
  DDR  RFC 9462  query SVCB _dns.resolver.arpa -> klien mencoba upgrade ke resolver terenkripsi

CARI DoH   1 daftar alamat/nama penyedia (tak pernah lengkap)
           2 jalur penemuan: resolve nama penyedia, _dns.resolver.arpa, rekaman HTTPS/SVCB (Day 15)
           3 pola: banyak transaksi KECIL berumur pendek
           4 KETIADAAN kueri DNS polos padahal koneksi keluar tetap banyak  <- paling berguna
           gagal bila DoH dicampur ke koneksi HTTPS yang juga bawa trafik lain
  PT JAB   proxy eksplisit: DoH workstation = CONNECT <penyedia>:443 di index=proxy dan http.log hop core
           rasio dns/conn per host vs baseline 14 hari; < 0.2 x baseline = "DNS diam, koneksi tetap"
           DoH satu aplikasi TIDAK menurunkan rasio host

QUIC TERLIHAT (RFC 9312)
  bit bentuk header | versi (long header; VN = versi 0) | Connection ID (long: src+dst, short: dst saja)
  tipe paket, Length, Token | SPIN BIT (short header) | 4 flight handshake
  >> ISI PAKET INITIAL BISA DIDEKRIPSI pengamat (RFC 9001: HKDF dari salt versi + DCID klien)
     -> SNI dan ALPN TERBACA dari ClientHello di dalam Initial  (hilang kalau ECH dipakai)
     -> Initial yang DITOLAK firewall tetap terbaca bila sensor di sisi dalam firewall
  datagram pembawa Initial minimal 1200 byte muatan UDP
  paket Retry & Version Negotiation tidak terenkripsi
  QUIC v2 (RFC 9369): versi 0x6b3343cf, salt baru, Initial = tipe 0b01

QUIC TIDAK TERLIHAT
  nomor paket, Key Phase | paket Handshake | seluruh muatan 1-RTT termasuk ACK
  sinyal kehilangan paket -> pengukuran loss PASIF TIDAK MUNGKIN
  akhir koneksi (tidak ada sinyal close) -> andalkan idle timeout, simpan state MIN 2 MENIT
  paket ACK-only tak bisa dibedakan dari data; heuristik ukuran tidak andal
  parameter transport server

MENGENALI QUIC   tidak ada metode umum; UDP tak dikenal BISA SAJA QUIC
  port 443 TIDAK andal (SMB over QUIC juga; HTTP/3 bisa di port lain)
  fixed bit TIDAK andal | heuristik byte pertama TIDAK dianjurkan | jangan kontrol akses per versi

ALAT
  Wireshark 4.6.9  quic && tls.handshake.type == 1 ; tls.handshake.extensions_server_name ; tls.handshake.extensions_alpn_str
                   quic.long.packet_type == 0 (Initial v1) ; quic.long.packet_type_v2 == 1 (Initial v2)
                   quic.header_form == 0 (short) ; quic.spin_bit ; quic.version ; quic.dcid ; quic.scid
                   ECH: tls.handshake.extension.type == 0xfe0d
  Zeek 9.0         quic.log: version client_initial_dcid client_scid server_scid server_name client_protocol history
                   history: I init, H handshake, Z 0-RTT, R retry, C close, S hello, U versi asing, X dibuang, O short
                   huruf BESAR = klien ; history "I" saja = tidak ada balasan server
  Suricata 8.0.7   event quic: version sni ua cyu ja3 ja4 extensions ; keyword quic.version quic.cyu.hash quic.cyu.string
                   doh2 hanya untuk HTTP/2 cleartext ; CVE-2026-94083 diperbaiki di 8.0.7

ALUR      5-tuple (bekerja kalau CID panjang nol) | Connection ID (penautan TIDAK DIJAMIN)
MIGRASI   ubah 5-tuple; CID juga berubah -> pengamat TIDAK bisa menautkan; kongesti di-reset
          NAT rebinding (mis. switchover CGNAT): alur baru tanpa Initial, service kosong di conn.log
          jangan sembunyikan perubahan alamat di middlebox; jangan pakai CID untuk NAT stateful
          saat DDoS: migrasi sengaja tak bisa dibedakan dari serangan

RTT       handshake RTT (Client Initial<->Server Initial, + pasangan Handshake) = paling ANDAL
          pengamat dekat server: komponen 1 kecil, komponen 2 = hampir seluruh RTT -> JUMLAHKAN
          spin bit: 1 sampel per tepi; mati di >=1/8 koneksi; termasuk delay APLIKASI;
                    reorder bikin tepi palsu -> saring pencilan / minimum bergerak

KONTROL   Edge DnsOverHttpsMode off|automatic|secure (>=83) ; QuicAllowed (>=77, butuh restart)
          Firefox canary use-application-dns.net -> NXDOMAIN = matikan DoH bawaan (bukan yang diset user)
          firewall: tolak TCP/UDP 853 dan UDP 443 keluar dari workstation (dan jadikan log)
          resolver internal tanpa DDR = klien patuh tetap di DNS polos

INDIKATOR != KESIMPULAN
  853 ditolak / CONNECT penyedia DoH / rasio DNS anjlok / Initial ditolak / alur UDP baru
  -> cek proses (EDR), ritme, prevalence tujuan berikutnya, nama yang tak pernah di-resolve, pemilik
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** Seorang rekan menulis di laporan: "Koneksi ke `203.0.113.191` memakai QUIC dan ditolak firewall, jadi nama tujuannya tidak mungkin diketahui." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Paket Initial QUIC dienkripsi dengan kunci yang diturunkan dari salt tetap milik versi dan Destination Connection ID klien, sehingga pengamat mana pun bisa mendekripsinya dan membaca SNI serta ALPN dari ClientHello. Di PT JAB, TAP berada di sisi dalam `jkt-fw01`, jadi Initial yang kemudian dibuang firewall tetap lewat sensor, dan `quic.log` mencatat `server_name` `cfg.edge-relay.example` dengan `history` `I`. Pengecualiannya: versi QUIC yang tidak dikenal alat dan ECH.

Lihat bagian 1.3 dan 2.3.

</details>

**2. Skenario keputusan.** Log proxy menunjukkan satu workstation membuat `CONNECT` ke penyedia DoH publik. Apa langkah pertamamu?

- A. Buka insiden dan isolasi host, karena DoH adalah teknik penyembunyian C2.
- B. Periksa rasio DNS host itu terhadap baseline-nya, proses yang membuat koneksi, ritmenya, dan tujuan yang dihubungi sesudahnya.
- C. Abaikan, karena DoH adalah layanan sah dan isinya tidak bisa dibaca.

<details><summary>Jawaban</summary>

B. `CONNECT` ke penyedia DoH adalah indikator, bukan kesimpulan. A memperlakukan alat privasi seperti milik Fikri sebagai insiden. C melewatkan kasus seperti `JKT-WS-2078`, yang memakai DoH untuk me-resolve tujuan yang tidak pernah muncul di resolver internal, lalu menghubunginya setiap lima menit dari proses tidak bertanda tangan. Penyedia yang sama, kesimpulan berbeda; pembedanya proses, ritme, prevalence tujuan berikutnya, dan pemilik.

Lihat bagian 1.9, 2.2, dan 2.4.

</details>

**3. Hitung.** Dari pengamat di dekat server, Client Initial terlihat pada 0,000 detik, Server Initial pada 0,001 detik, Handshake server pada 0,001 detik, dan Handshake klien pada 0,052 detik. Tepi spin bit pada koneksi yang sama terlihat di 0,600, 0,653, 0,705, 2,980, dan 3,031 detik. Berapa RTT yang kamu laporkan?

<details><summary>Jawaban</summary>

Handshake RTT = komponen pertama 0,001 detik ditambah komponen kedua 0,052 - 0,001 = 0,051 detik, jadi 52 ms. Sampel spin bit: 53 ms, 52 ms, 2.275 ms, dan 51 ms. Sampel 2.275 ms adalah jeda aplikasi, bukan RTT jaringan, sehingga dibuang; minimum bergerak sekitar 51 sampai 53 ms, cocok dengan handshake RTT. Laporkan sekitar 52 ms dengan handshake RTT sebagai rujukan utama, dan sebut bahwa spin bit mencakup penundaan aplikasi.

Lihat bagian 1.7 dan 2.6.

</details>

**4. Pertanyaan jebakan.** "Tidak ada satu pun query untuk `cfg.edge-relay.example` di `index=dns` selama 30 hari, jadi tidak ada host PT JAB yang menghubungi domain itu." Apa yang salah?

<details><summary>Jawaban</summary>

Ketiadaan query di resolver internal tidak membuktikan ketiadaan koneksi. Host bisa me-resolve lewat DoH (seperti `JKT-WS-2078`), memakai alamat IP langsung, atau menyerahkan resolusi ke proxy eksplisit, yang query-nya tercatat dengan sumber `10.20.3.60`. Di kasus ini, nama itu justru terbaca dari `quic.log`, dan ketiadaannya di log resolver menjadi bagian dari bukti bahwa resolusinya disembunyikan.

Lihat bagian 1.2 dan 2.4.

</details>

**5. Skenario keputusan.** Alur UDP baru ke portal pelanggan melonjak tiga kali lipat dalam lima menit, hampir semuanya tanpa Initial dan dari alamat CGNAT sendiri, dengan ukuran alur normal. Apa yang kamu lakukan?

- A. Blokir `198.51.100.210` di firewall karena sumber lonjakan.
- B. Periksa log perangkat jaringan di jalur (CGNAT, firewall) untuk perubahan yang cocok waktunya, lalu bandingkan sumber dan ukuran alur dengan baseline.
- C. Laporkan sebagai DDoS karena pola alur baru tanpa handshake.

<details><summary>Jawaban</summary>

B. Alur tanpa Initial dari sumber yang sama dengan ukuran normal cocok dengan NAT rebinding atau migrasi; di PT JAB penyebabnya switchover `jkt-cgn01` tanpa sinkronisasi state UDP. A memutus akses portal untuk banyak pelanggan sekaligus, karena satu alamat CGNAT mewakili banyak pelanggan. C mengabaikan bahwa migrasi yang disengaja tidak bisa dibedakan dari serangan dari pola saja; kesimpulan butuh konteks.

Lihat bagian 1.6 dan 2.5.

</details>

**6. Jelaskan ulang.** Jelaskan ke Bambang dalam tiga kalimat kenapa alur QUIC ke portal tampak putus-putus di flow dan di firewall, dan kenapa UDP timeout firewall sebaiknya dinaikkan.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh jawaban: "QUIC tidak punya paket penutup yang terlihat seperti FIN di TCP, jadi router, Zeek, dan firewall hanya bisa menutup alur setelah diam beberapa saat, dan setiap jeda yang lebih panjang dari timeout-nya membuat satu koneksi tercatat sebagai beberapa alur. Firewall portal kita memakai 30 detik, padahal endpoint QUIC biasanya baru timeout setelah 30 sampai 60 detik dan RFC 9312 menyarankan perangkat menyimpan state QUIC minimal dua menit. Kalau timeout firewall lebih pendek, sesi pelanggan yang sedang diam bisa diputus di tengah jalan, jadi kita naikkan ke minimal 120 detik."

Kesalahan yang sering muncul: menyebut alur "putus" sebagai bukti koneksi berakhir; menyarankan memperpendek timeout supaya tabel state lebih kecil, padahal RFC 9312 tidak menganjurkannya; dan mencampur idle timeout flow (15 detik di `jkt-flow01`, hanya mempengaruhi pencatatan) dengan idle timeout firewall (mempengaruhi trafik nyata).

</details>

**7. Interview question (English).** "Our users are moving to DNS over HTTPS and HTTP/3. As a network analyst, what can you still see, and how would you detect DoH in an enterprise network?"

<details><summary>Sample answer</summary>

"I'd separate the three encrypted DNS transports first. DoT and DoQ use port 853, so a simple firewall rule both blocks and logs them; DoH is designed to look like ordinary HTTPS, so I detect it indirectly. Behind an explicit proxy, DoH shows up as CONNECT requests to known resolver hostnames, and I also baseline plain DNS queries per host against outbound connections, because a host that stops querying our resolvers but keeps browsing has moved its DNS somewhere else. For QUIC, the Initial packets can be decrypted by any observer, so Zeek's quic.log or Wireshark still gives me SNI and ALPN, even for attempts our firewall drops if the sensor sits on the inside. What I lose is everything after the handshake, any visible connection close, and loss measurement, and with ECH or an unknown QUIC version I'm down to addresses and patterns. Finally, I treat DoH usage as an indicator: the same resolver can be a privacy tool on one laptop and C2 name resolution on another, so I check the process, the rhythm, and the destinations that follow."

What makes this answer strong: it distinguishes DoT and DoQ from DoH instead of lumping them together, uses the proxy and the absence of plain DNS as practical detection paths, states precisely what QUIC still exposes and what it does not, ties visibility to sensor placement, and keeps the line between indicator and conclusion.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | RFC 8484: DNS Queries over HTTPS (DoH) | https://www.rfc-editor.org/rfc/rfc8484.html | primer | Standards Track, Oktober 2018; dilihat 2026-10-09 | Tinggi. Media type `application/dns-message`, bentuk GET dan POST, pemakaian port 443 secara konvensi, pernyataan bahwa dokumen tidak menyediakan cara mengenali DoH, dan pernyataan bahwa sistem penyaringan yang bergantung transport DNS tidak aman tidak akan berfungsi |
| S2 | RFC 7858: Specification for DNS over Transport Layer Security (DoT) | https://www.rfc-editor.org/rfc/rfc7858.html | primer | dirujuk 2026-10-09 | Tinggi untuk pemakaian port 853 dan larangan memakainya untuk DNS cleartext |
| S3 | RFC 9250: DNS over Dedicated QUIC Connections (DoQ) | https://www.rfc-editor.org/rfc/rfc9250.html | primer | Standards Track, Mei 2022; dilihat 2026-10-09 | Tinggi. Pemakaian UDP port 853, larangan memakai UDP port 53, dan reservasi port |
| S4 | RFC 9000: QUIC: A UDP-Based Multiplexed and Secure Transport | https://www.rfc-editor.org/rfc/rfc9000.html | primer | Standards Track, Mei 2021; dilihat 2026-10-09 | Tinggi. Peran Connection ID, Version Negotiation, dan sifat penautan alur. Dokumen sangat panjang dan hanya dibaca sebagian |
| S5 | RFC 9312: Manageability of the QUIC Transport Protocol | https://www.rfc-editor.org/rfc/rfc9312.html | primer | Informational, September 2022; dilihat 2026-10-09 | Tinggi. Daftar lengkap apa yang terlihat dan tidak terlihat pengamat, dekripsi paket Initial, batas pengenalan QUIC, identifikasi alur, efek migrasi, idle timeout minimal dua menit, dan keterbatasan spin bit |
| S6 | RFC 9114: HTTP/3 | https://www.rfc-editor.org/rfc/rfc9114.html | primer | dirujuk 2026-10-09 | Tinggi untuk posisi HTTP/3 di atas QUIC dan token ALPN `h3` |
| S7 | Network-Forensics Day 04, 05, 06, 08, 10, 11, 15 (lokal) | (lokal) | rujukan internal | 2026-10-09, diperbarui 2026-10-23 | Sensor, proxy eksplisit dan SslBump, resolver, Zeek, flow dan CGNAT, beacon, dan peta celah ECH PT JAB |
| S8 | RFC 9001: Using TLS to Secure QUIC | https://www.rfc-editor.org/rfc/rfc9001.html | primer | Standards Track, Mei 2021; diakses 2026-10-23 | Tinggi. Initial secret dari HKDF-Extract dengan salt versi 1 dan DCID klien, label "client in"/"server in", pernyataan bahwa Initial tidak punya perlindungan kerahasiaan atau integritas. Bagian akhir dokumen tidak dibaca |
| S9 | RFC 9369: QUIC Version 2 | https://www.rfc-editor.org/rfc/rfc9369.html | primer | Standards Track, Mei 2023; diakses 2026-10-23 | Tinggi. Nomor versi `0x6b3343cf`, salt baru, pengodean tipe paket long header, tujuan melawan osifikasi |
| S10 | Wireshark Display Filter Reference: QUIC IETF | https://www.wireshark.org/docs/dfref/q/quic.html | primer | rentang versi sampai 4.6.9; diakses 2026-10-23 | Tinggi. `quic.header_form`, `quic.long.packet_type`, `quic.long.packet_type_v2` (sejak 4.0.0), `quic.version`, `quic.dcid`, `quic.scid`, `quic.spin_bit`; tidak ada field `quic.tls.*` |
| S11 | Wireshark Display Filter Reference: Transport Layer Security | https://www.wireshark.org/docs/dfref/t/tls.html | primer | rentang versi sampai 4.6.9; diakses 2026-10-23 | Tinggi. `tls.handshake.extensions_server_name`, `tls.handshake.extensions_alpn_str`, `tls.handshake.type`, `tls.handshake.extension.type`, field `tls.ech.*` |
| S12 | Zeek docs: base/protocols/quic/main.zeek (QUIC::Info) | https://docs.zeek.org/en/current/scripts/base/protocols/quic/main.zeek.html | primer | cabang release/9.0; diakses 2026-10-23 | Tinggi. Field `quic.log` dan arti huruf `history` |
| S13 | Suricata docs: EVE JSON Format (event `quic`) dan QUIC Keywords | https://docs.suricata.io/en/latest/output/eve/eve-json-format.html ; https://docs.suricata.io/en/latest/rules/quic-keywords.html | primer | dokumentasi latest (9.0.0-dev, berlaku juga untuk 8.0.x); diakses 2026-10-23 | Tinggi. Field `version`, `sni`, `ua`, `cyu`, `ja3`, `ja4`, `extensions`; keyword `quic.version`, `quic.cyu.*`; opsi `app-layer.protocols.quic.enabled` |
| S14 | OISF Redmine Feature #5773: doh: support DNS over HTTPS (DoH) | https://redmine.openinfosecfoundation.org/issues/5773 | primer (pelacak isu proyek) | ditutup Juli 2024, target 8.0.0-beta1; diakses 2026-10-23 | Sedang-tinggi. Parsing DoH (GET dan POST) dari trafik HTTP/2 yang kemungkinan sudah didekripsi; nama protokol `doh2` dan cara aktivasinya dicek di `suricata.yaml` versi-mu |
| S15 | Red Hat Customer Portal: CVE-2026-94083 | https://access.redhat.com/security/cve/CVE-2026-94083 | primer (advisory vendor distribusi) | diakses 2026-10-23 | Tinggi untuk versi terdampak (sebelum 8.0.7), syarat `app-layer.protocols.doh2` aktif, dan mitigasi; halaman tidak memuat tanggal terbit dan skor CVSS |
| S16 | Microsoft Learn: Microsoft Edge policy DnsOverHttpsMode | https://learn.microsoft.com/en-us/deployedge/microsoft-edge-browser-policies/dnsoverhttpsmode | primer | ms.date 2026-05-20; diakses 2026-10-23 | Tinggi. Nilai `off`/`automatic`/`secure`, Edge 83 ke atas, perilaku perangkat terkelola tanpa kebijakan, registry `SOFTWARE\Policies\Microsoft\Edge` |
| S17 | Microsoft Learn: Microsoft Edge policy QuicAllowed | https://learn.microsoft.com/en-us/deployedge/microsoft-edge-browser-policies/quicallowed | primer | ms.date 2026-05-20; diakses 2026-10-23 | Tinggi. Edge 77 ke atas, bawaan diizinkan, butuh restart browser |
| S18 | Mozilla Support: Canary domain - use-application-dns.net | https://support.mozilla.org/en-US/kb/canary-domain-use-application-dnsnet | primer | diakses 2026-10-23 (isi dibaca dari salinan terjemahan halaman yang sama) | Tinggi. Jawaban negatif dan positif, hanya untuk DoH bawaan, langkah sementara |
| S19 | RFC 9462: Discovery of Designated Resolvers | https://www.rfc-editor.org/rfc/rfc9462.html | primer | Standards Track, November 2023; diakses 2026-10-23 | Tinggi. Query SVCB `_dns.resolver.arpa`, ALPN `dot`/`h2`/`doq` di contoh, verifikasi sertifikat memuat IP resolver lama |
| S20 | MITRE ATT&CK T1572 Protocol Tunneling | https://attack.mitre.org/techniques/T1572/ | primer | versi 1.1, diubah 3 September 2026; diakses 2026-10-23 | Tinggi. DoH untuk membungkus query infrastruktur C2 |
| S21 | RFC 9849: TLS Encrypted Client Hello | https://www.rfc-editor.org/rfc/rfc9849.html | primer | Standards Track, Maret 2026; diakses 2026-10-23 | Tinggi untuk codepoint `encrypted_client_hello` `0xfe0d` |

**Catatan sumber:** nama field Wireshark untuk QUIC dan spin bit berubah antar versi; field di Day ini sudah dicocokkan dengan display filter reference 4.6.9 [S10][S11], dan filter lama `quic.tls.handshake.extensions_server_name` diganti karena tidak tercantum di sana. Penguraian ClientHello dari Initial yang terdekripsi sebagai field `tls.*` adalah perilaku dissector yang perlu dicek di versi-mu. Pola pengenalan DoH di bagian 1.2 dan 2.2 adalah pendekatan yang disusun sendiri dari sifat protokol yang dijelaskan RFC 8484, bukan metode yang didokumentasikan di sana; RFC-nya justru menyatakan tidak menyediakan cara pengenalan. Ambang 1200 byte di bagian 2.5 berasal dari ukuran minimum datagram pembawa Initial [S5] dan dipakai sebagai penyempit, bukan sebagai identifikasi. Untuk rincian format header QUIC di luar yang dirangkum di sini, rujuk RFC 9000 dan RFC 9312 langsung. Nilai `service` di `conn.log` untuk alur QUIC, timeout UDP Zeek, pengulangan Initial klien, dan perilaku dissector pada paket terpotong (snaplen 128) belum dicek ke dokumentasi primer dan perlu diuji di lab. Halaman Mozilla [S18] versi bahasa Inggris tidak termuat saat diakses; isinya dibaca dari salinan terjemahan halaman yang sama. Sourcetype `bro:quic:json` dan `bro:dns:json` mengikuti pola TA for Zeek dan perlu divalidasi dengan `| metadata`. Seluruh isi PT JAB (alert, host, akun, nama domain, alamat, angka log, switchover `jkt-cgn01`, timeout firewall, keputusan, dan `INC-2027-075`) adalah penerapan catatan ini pada organisasi fiktif, bukan hasil eksekusi nyata; domain memakai `.example` dan alamat memakai rentang dokumentasi.
