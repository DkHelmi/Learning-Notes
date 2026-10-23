---
day: 10
title: 'Flow analysis: NetFlow/IPFIX, sampling, korelasi dengan conn.log, dan sudut pandang ISP (abuse, CGNAT, permintaan data)'
researched_on: 2026-10-22
versions_checked: 'nfdump 1.7.10 (man page nfdump.1 dan nfcapd.1, rilis terbaru di halaman rilis per 2026-10-22); SiLK 3.24.2 (14 Mei 2026); Zeek 9.0.0 LTS (14 Sep 2026); IANA IPFIX Information Elements registry (diakses 2026-10-22); IPFIX RFC 7011; NetFlow v9 RFC 3954; biflow RFC 5103; RFC 6302 (BCP 162); RFC 6888 (BCP 127); RFC 7422; RFC 6598 (BCP 153); RFC 2142'
---

# Day 10: Flow analysis dan sudut pandang ISP

Cakupan: membaca metadata aliran (NetFlow/IPFIX dan Zeek `conn.log`) untuk forensik skala besar tanpa isi paket, termasuk efek sampling, korelasi flow dengan log sensor, dan sudut pandang ISP saat menangani laporan abuse, CGNAT, dan permintaan data pelanggan.

## Ide inti

Flow adalah satu baris ringkasan per aliran: siapa ke siapa, port berapa, protokol apa, kapan mulai dan selesai, berapa paket dan byte, flag TCP apa saja yang muncul. Tidak ada isi. Karena ringkas, flow bisa dikumpulkan dari seluruh router dan disimpan berbulan-bulan, sesuatu yang mustahil dengan pcap penuh. Untuk forensik, flow menjawab "ke mana, sejak kapan, dan berapa banyak" di skala seluruh jaringan dan dalam rentang waktu panjang; pcap dan log transaksi menjawab "apa isinya" untuk koneksi terpilih yang kebetulan lewat sensor. Analis yang baik tahu tiga batas flow sebelum membacanya: titik ekspor menentukan apa yang terlihat, sampling menentukan seberapa akurat angkanya, dan timeout menentukan bagaimana satu koneksi dipecah menjadi beberapa record.

Bagian ini rumahmu sendiri. Di NOC, flow sudah kamu pakai untuk capacity planning, mencari top talker saat link penuh, dan mengenali DDoS dari banyak sumber ke satu tujuan. Yang berubah di Day ini hanya niatnya: pertanyaan yang sama ("siapa yang paling banyak mengirim ke mana") diajukan untuk investigasi, sehingga setiap angka harus bisa dipertanggungjawabkan, termasuk koreksi sampling dan nama sensor asalnya. Batas analoginya: untuk capacity planning, perkiraan dengan galat beberapa persen sudah cukup dan flow kecil boleh hilang; untuk investigasi, flow kecil yang hilang bisa jadi beacon yang sedang dicari, dan angka volume yang ditulis di laporan insiden harus menyebut rentang galatnya.

Sisi kedua Day ini adalah ISP itu sendiri. PT JAB bukan hanya korban; alamat publiknya dipakai 400 ribu pelanggan broadband di belakang CGNAT, sehingga laporan abuse dan permintaan data dari aparat datang ke PT JAB. Menjawabnya butuh log translasi NAT dengan port dan waktu yang presisi sampai detik, dan butuh disiplin privasi: data pelanggan hanya dibuka sejauh pertanyaannya, oleh orang yang berwenang.

```
            Jakarta                                            Bandung (POP + kantor)
   kantor 10.10.0.0/16                                  kantor 10.30.0.0/16 (Wi-Fi dinas 10.30.50.0/24)
        |                                                        |
   [jkt-fw01] -- TAP egress --> jkt-npb01 --> Zeek/Suricata/pcap  [bdg-fw01]   (tanpa sensor NSM)
        |                                                        |
   [router edge Jakarta] --flow 1:1000--+                  [bdg-rtr01] --flow 1:1000--+
        |                               |                        |                    |
   [jkt-cgn01] CGNAT pelanggan          +--> jkt-flow01 10.20.70.14 (nfcapd/nfdump) <-+
     100.64.0.0/10 -> 198.51.100.210    |        retensi flow 13 bulan
        |                               |
   [router DC] ---------flow 1:1--------+
        |
   core switch DC -- SPAN --> jkt-npb01 --> jkt-zeek01 (conn.log, index zeek)

   Log pendukung: index firewall (jkt-fw01, bdg-fw01), index netops (log blok port jkt-cgn01, RADIUS jkt-bng01)
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan sekitar 1.200 karyawan dan sekitar 400 ribu pelanggan broadband, berkantor pusat dan ber-data center di Jakarta, dengan POP dan kantor regional di Bandung. Sejak Senin 2027-05-03 PT JAB menjalankan "Program NSM PT JAB" (percobaan Mei sampai Juli 2027). Per Jumat 2027-05-21, sensor yang hidup adalah `jkt-pcap01` (pcap egress Jakarta, uji coba sejak 2027-05-04), `jkt-zeek01` (Zeek, produksi sejak Selasa 2027-05-18), dan `jkt-ids01` (Suricata, sejak Rabu 2027-05-19), semuanya hanya melihat egress Jakarta dan core switch data center. Kolektor flow NOC `jkt-flow01` (10.20.70.14) sudah ada jauh sebelum program: IPFIX dan NetFlow v9 dari router edge Jakarta dan `bdg-rtr01` dengan sampling 1:1000, dan dari router data center tanpa sampling (1:1). Kebijakan akses data NSM membatasi pemakaian flow oleh SOC ke prefiks dan alamat korporat PT JAB; trafik pelanggan diurus NOC lewat prosedurnya sendiri.

Dua hal terjadi Kamis 2027-05-20. Pukul 16:38, Microsoft Defender for Endpoint (MDE) membuat alert `SOC-2027-0645` di laptop `JKT-WS-2046` milik staf Penjualan Korporat `rizky.maulana`: proses tanpa tanda tangan `drvupd.exe` di folder profil pengguna membuka koneksi HTTPS langsung ke `203.0.113.178:443`. Laptop itu sedang dinas di kantor Bandung sejak Selasa 2027-05-18 dan memakai Wi-Fi dinas (`10.30.50.46`); di Jakarta alamatnya `10.10.60.101`. Dimas mengisolasi laptop lewat MDE pukul 17:05. Pukul 23:50, `abuse@jab.example` menerima email dari tim abuse sebuah penyedia hosting (`abuse@hosting.example`): server mereka `203.0.113.179` menerima 1.236 percobaan login SSH gagal dari `198.51.100.210`, alamat pool CGNAT pelanggan broadband Jakarta, dengan waktu dalam UTC. NOC membuka tiket abuse `ABU-2027-0512`. Jumat pukul 08:30, Bambang Hartono (Manajer NOC) menulis di kanal SOC-NOC:

> "Pagi. Dua hal, dua-duanya cuma bisa dijawab dari flow. Satu, laptop Rizky di Bandung: Pak Dimas mau tahu sejak kapan, berapa banyak data yang keluar ke 203.0.113.178, dan ada host lain atau tidak. Di Bandung tidak ada Zeek atau pcap, jadi yang ada cuma flow bdg-rtr01 yang 1:1000 dan log bdg-fw01. Seberapa bisa dipercaya angka dari flow sampling? Dua, tiket abuse ABU-2027-0512: pelanggan mana di balik 198.51.100.210, dan bagaimana kita cek tanpa melanggar aturan privasi pelanggan? Bu Ratna titip pertanyaan: kalau polisi minta data untuk IP seperti ini, apa yang kita perlukan dan apa yang boleh kita berikan? Tolong juga bantu anak NOC baca nfdump dengan benar, mereka biasa pakai dashboard saja."

Dimas menambahkan pukul 08:41:

> "Tambahan dari SOC. Tadi pagi alarm top talker NOC menandai 10.10.60.103 kirim sekitar 3 GB ke proxy; sudah kujadikan SOC-2027-0647. Itu di Jakarta, jadi ada di flow router DC dan juga di conn.log Zeek. Pakai kasus itu untuk memastikan cara kita mencocokkan flow dengan Zeek sudah benar, sebelum angka flow Bandung masuk laporan insiden."

Dua pesan itu memuat tujuh pertanyaan:

1. Apa sebenarnya isi satu record flow di `jkt-flow01`, dan kenapa flow bisa menjawab hal yang tidak dilihat sensor NSM?
2. Seberapa bisa dipercaya angka volume dan jumlah koneksi dari flow yang di-sampling 1:1000?
3. Kenapa satu koneksi bisa muncul sebagai beberapa record, dan bagaimana menggabungkannya?
4. Pola apa yang bisa dan tidak bisa dibaca dari flow (top talker, scan, exfiltration, beacon, koneksi panjang)?
5. Bagaimana mencocokkan flow dengan Zeek `conn.log` dan log lain, dan kenapa angkanya tidak pernah persis sama?
6. Pelanggan mana di balik `198.51.100.210` pada waktu laporan, dan bagaimana menangani laporan abuse tanpa melanggar privasi pelanggan?
7. Bila aparat penegak hukum meminta data untuk alamat seperti ini, apa yang diperlukan dan apa yang boleh diberikan?

Pertanyaan 1 dijawab di bagian 1.1 dan 1.2, pertanyaan 2 di bagian 1.3, 2.2, dan 2.3, pertanyaan 3 di bagian 1.4 dan 2.1, pertanyaan 4 di bagian 1.5, 2.4, dan 2.9, pertanyaan 5 di bagian 1.6, 2.5, 2.6, dan 2.7, pertanyaan 6 di bagian 1.7, 2.8, dan 2.9, dan pertanyaan 7 di bagian 1.8. Alat yang dipakai dibahas di bagian 1.9, dan bagian 2.10 berisi jawaban untuk Bambang, Dimas, dan Ratna.

**Kapan relevan:** saat pertanyaannya tentang volume, arah, waktu, dan pasangan komunikasi di skala seluruh jaringan; saat kejadiannya terjadi di segmen atau kantor yang tidak punya sensor NSM; saat rentang waktunya lebih panjang daripada retensi pcap dan log transaksi; dan saat ISP harus menjawab laporan abuse atau permintaan data untuk alamat publik bersama.
**Kapan bukan jawaban:** saat yang dibutuhkan adalah isi (payload, URL, kredensial, nama file); saat koneksi yang dicari kecil dan jarang sementara flow di titik itu di-sampling; saat trafiknya tidak pernah lewat exporter (antar host di satu switch, atau diblok firewall sebelum sampai router); dan saat alamat publik di laporan berada di belakang CGNAT tetapi pelapor tidak menyertakan port sumber dan waktu yang presisi.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (pcap, flow sebagai session data, sampling, SPAN, TAP, blind spot, `uid`, `conn_state`, `history`, Community ID) tidak diulang. Tabel ini hanya memuat istilah yang baru dipakai di Day ini; kolom kanan memakai padanan dari pekerjaan NOC dan ISP.

| Istilah | Arti singkat | Padanan di NOC/ISP |
|---|---|---|
| Exporter | Perangkat yang mengamati paket, membentuk flow, dan mengirim record ke kolektor | Router dengan `ip flow export` atau `flow exporter` |
| Collector | Sistem yang menerima, menyimpan, dan menyediakan record flow untuk dianalisis | Server NetFlow NOC (`jkt-flow01`) |
| 5-tuple | Kunci flow: IP sumber, IP tujuan, port sumber, port tujuan, protokol | Kunci yang sama dengan entri NAT atau ACL |
| Flow record | Satu entri: kunci ditambah metrik (paket, byte, waktu, flag) | Satu baris di tabel `show ip cache flow` |
| Template | Definisi field yang dikirim exporter NetFlow v9 dan IPFIX sebelum data | Template di kolektor yang menentukan cara mendekode data |
| Information Element (IE) | Field IPFIX yang terdaftar di IANA dengan nomor dan definisi tetap | Nama dan OID objek MIB SNMP |
| Uniflow dan biflow | Flow satu arah dan flow dua arah dalam satu record | Counter input dan output interface yang terpisah vs satu ringkasan sesi |
| Active timeout | Batas waktu record untuk flow yang masih aktif; setelah itu record diekspor dan flow lanjut di record baru | Interim-update RADIUS accounting untuk sesi panjang |
| Idle (inactive) timeout | Flow dianggap selesai bila tidak ada paket selama waktu itu | Session timeout di BNG |
| `flowEndReason` | IE yang mencatat kenapa record ditutup (idle, active, end of flow, forced, resources) | Kode terminate cause di RADIUS accounting |
| Sampling 1:N dan koreksinya | Hanya sekitar satu dari N paket yang diukur; counter dikalikan N untuk perkiraan | `sampler` di router edge; grafik yang dikalikan rasio sampling |
| Top talker | Host atau pasangan dengan volume terbesar dalam satu jendela | Top talker di dashboard NetFlow saat link penuh |
| Long-lived flow | Koneksi yang bertahan sangat lama ke satu tujuan | Sesi BGP atau tunnel GRE yang tidak pernah putus |
| CGNAT | NAT di sisi operator: banyak pelanggan berbagi satu alamat IPv4 publik | NAT444 di BNG atau perangkat CGN |
| Shared Address Space | Prefiks `100.64.0.0/10` untuk alamat antara CGN dan CPE pelanggan | Alamat sisi pelanggan di belakang CGN |
| Port block allocation (PBA) | CGNAT memberi satu blok port per pelanggan dan mencatat alokasi blok, bukan setiap koneksi | Log lease DHCP, tetapi untuk rentang port |
| Deterministic NAT | Pemetaan pelanggan ke alamat publik dan rentang port dihitung dari algoritma tetap, sehingga log per koneksi tidak perlu | Pembagian VLAN per port OLT yang bisa dihitung dari nomor port |
| Abuse desk | Fungsi ISP yang menerima dan menindaklanjuti laporan penyalahgunaan dari pihak luar lewat `abuse@` | Helpdesk NOC untuk tiket dari peer atau pelanggan lain |
| Preservation (legal hold) | Menahan log tertentu agar tidak terhapus oleh retensi karena ada permintaan atau perkara | Menyimpan konfigurasi dan log perangkat sebelum RMA |

### 1.1 Flow: definisi, exporter, collector, dan arah

Pertanyaan pertama Bambang terdengar sederhana: apa sebenarnya isi satu record flow yang ia lihat di dashboard setiap hari? Jawabannya menentukan apa yang boleh ditulis di laporan `SOC-2027-0645`.

Flow adalah ringkasan satu aliran trafik yang berbagi kunci yang sama, biasanya 5-tuple (IP sumber, IP tujuan, port sumber, port tujuan, protokol), dalam rentang waktu tertentu di satu titik observasi [S1]. Exporter (router, switch, atau probe) mengamati paket, mengelompokkannya menjadi flow di cache-nya, lalu mengekspor record ke collector. Record memuat metadata, bukan isi. Empat peran dasarnya (exporter, collector, 5-tuple, flow record) sudah ada di tabel bagian 1.0; yang perlu diingat di sini adalah alurnya: router mengamati, cache meringkas, record dikirim, kolektor menyimpan.

Tiga akibat dari definisi itu yang langsung mengenai kasus Bandung:

- **Flow terikat titik observasi.** Record dari `bdg-rtr01` hanya memuat paket yang lewat interface yang diekspor router itu. Laptop `JKT-WS-2046` di Wi-Fi dinas Bandung keluar ke internet lewat `bdg-fw01` lalu `bdg-rtr01`, tidak pernah lewat TAP Jakarta, jadi `jkt-zeek01` dan `jkt-pcap01` tidak punya apa pun tentangnya sejak Selasa. Flow `bdg-rtr01` adalah satu-satunya sumber volume.
- **Flow umumnya searah.** NetFlow v9 dan IPFIX biasa mengekspor uniflow: satu koneksi TCP menghasilkan dua record, satu untuk paket dari laptop ke server dan satu untuk balasannya. IPFIX juga bisa mengekspor biflow, satu record dua arah dengan elemen "reverse" untuk arah balik; arah sumber ditentukan dari siapa yang memulai, dari perimeter (sumber adalah pihak di luar perimeter), atau secara arbitrer di core [S9]. Zeek `conn.log` selalu dua arah per koneksi dengan originator dan responder (Day 08 bagian 1.2). Perbedaan ini sumber salah hitung paling umum saat mencocokkan keduanya (bagian 1.6).
- **Flow tidak tahu tentang aplikasi.** Port 443 berarti "kemungkinan HTTPS", bukan bukti HTTPS. Untuk laptop Rizky, MDE yang memberi nama proses `drvupd.exe`; flow hanya memberi alamat, port, waktu, dan byte.

Kenapa flow bisa menjawab hal yang tidak dilihat sensor NSM: exporter flow sudah tersebar di setiap router edge dan POP karena NOC membutuhkannya untuk operasi, sedangkan sensor NSM baru dipasang di dua titik Jakarta (Day 01 bagian 1.5). Untuk Bandung, Medan, dan POP lain, flow adalah lapisan bukti jaringan yang sudah ada, dengan retensi 13 bulan di `jkt-flow01`.

### 1.2 NetFlow, IPFIX, sFlow, dan field yang benar-benar ada

Bambang menyebut `jkt-flow01` menerima "IPFIX dan NetFlow v9". Untuk investigasi, pertanyaan pentingnya bukan nama protokolnya, tetapi field apa yang dikirim exporter, karena NetFlow v9 dan IPFIX berbasis template: exporter memilih field, dan field yang tidak ada di template tidak pernah ada di kolektor.

Tabel berikut membandingkan protokol flow yang akan kamu temui; cari kolom "Catatan" untuk tahu apakah field bisa dipilih dan apakah datanya di-sampling.

| Protokol | Asal | Catatan |
|---|---|---|
| NetFlow v5 | Cisco | Lama, field tetap, masih ada |
| NetFlow v9 | Cisco (RFC 3954) | Template, fleksibel [S2] |
| IPFIX | IETF (RFC 7011) | Standar terbuka, berbasis template, penerus v9 [S1] |
| sFlow | sampling-based | Sampel paket + counter; beda pendekatan (sampling) |

IPFIX adalah standar modern; NetFlow v9 serupa. sFlow memakai sampling (merekam sebagian paket), cepat tapi tidak lengkap. Untuk forensik, flow lengkap lebih disukai daripada sampled bila tersedia. Di PT JAB, router data center mengekspor tanpa sampling, sedangkan edge Jakarta dan `bdg-rtr01` di-sampling 1:1000; itu fakta konfigurasi, bukan sifat protokol.

Field IPFIX punya nama dan nomor tetap di registry IANA, sehingga dokumentasi kolektor yang berbeda bisa dicocokkan lewat nomor elemennya [S6]. Tabel berikut memuat elemen yang dipakai di Day ini; baca kolom "Yang dijawab" untuk tahu pertanyaan investigasi apa yang bergantung pada elemen itu.

| ID | Information Element | Isi | Yang dijawab |
|---|---|---|---|
| 8, 12 | `sourceIPv4Address`, `destinationIPv4Address` | Alamat sumber dan tujuan | Siapa ke siapa |
| 7, 11 | `sourceTransportPort`, `destinationTransportPort` | Port sumber dan tujuan | Layanan; port sumber untuk CGNAT |
| 4 | `protocolIdentifier` | Nomor protokol IP (6 TCP, 17 UDP) | Jenis transport |
| 1, 2 | `octetDeltaCount`, `packetDeltaCount` | Byte dan paket sejak laporan sebelumnya untuk flow ini; byte dihitung termasuk header IP | Volume |
| 6 | `tcpControlBits` | Gabungan flag TCP dari semua paket yang terhitung | Scan, koneksi gagal |
| 152, 153 | `flowStartMilliseconds`, `flowEndMilliseconds` | Waktu paket pertama dan terakhir | Kapan, berapa lama |
| 136 | `flowEndReason` | Alasan record ditutup | Apakah koneksi benar-benar selesai |
| 10, 14 | `ingressInterface`, `egressInterface` | Interface masuk dan keluar | Arah dan jalur di router |
| 16, 17 | `bgpSourceAsNumber`, `bgpDestinationAsNumber` | AS asal dan tujuan | Peering, upstream, negara/organisasi kasar |
| 5 | `ipClassOfService` | ToS/DSCP | QoS |
| 34, 35 | `samplingInterval`, `samplingAlgorithm` | Rasio dan metode sampling; keduanya kini deprecated, digantikan 305 `samplingPacketInterval` dan 304 `selectorAlgorithm` | Koreksi volume |
| 225, 227 | `postNATSourceIPv4Address`, `postNAPTSourceTransportPort` | Alamat dan port sumber sesudah NAT | Pemetaan pelanggan CGNAT |
| 230 | `natEvent` | Jenis kejadian NAT (misalnya 16 alokasi blok port, 17 pelepasan blok) | Log CGNAT berbasis IPFIX |

Daftar field inti dalam bahasa sehari-hari:

- **5-tuple:** src/dst IP, src/dst port, protokol. Siapa ke siapa, layanan apa.
- **Waktu:** start, end, durasi.
- **Volume:** jumlah paket, jumlah byte (sering per arah).
- **TCP flags:** akumulasi flag (membantu kenali scan/koneksi gagal).
- **Interface/next-hop/AS:** info routing (sudut ISP).
- **ToS/DSCP:** penanda QoS.

Dari field ini, banyak bisa disimpulkan tanpa isi: arah dominan (upload vs download dari byte per arah), koneksi jangka panjang (durasi), scan (banyak flow kecil ke banyak tujuan), volume besar keluar (exfiltration). Pola yang sama sudah dipakai di Day 04 untuk scan dan Day 08 untuk `conn.log` [S5]. Dua hal perlu diingat. Pertama, `tcpControlBits` adalah gabungan (OR) flag semua paket dalam record, sehingga satu record ber-flag `SAPF` tidak memberi tahu urutannya. Kedua, `flowEndReason` hanya ada bila exporter memasukkannya ke template; tanpa field itu, kamu tidak bisa membedakan koneksi yang selesai dari koneksi yang dipotong timeout. Nilainya menurut registry IANA: 1 idle timeout, 2 active timeout, 3 akhir flow terdeteksi (misalnya FIN), 4 forced end (misalnya exporter dimatikan), 5 kehabisan sumber daya [S6].

Cara mengecek field yang benar-benar dikirim router PT JAB: minta Bambang menunjukkan template di kolektor atau konfigurasi `flow record` di router. Jangan menyimpulkan "AS tujuan tidak ada" bila exporter memang tidak mengirim field AS.

### 1.3 Sampling: efek pada volume dan deteksi

Pertanyaan kedua Bambang ("seberapa bisa dipercaya angka dari flow sampling") adalah inti Day ini, karena laporan `SOC-2027-0645` akan memuat angka volume dari `bdg-rtr01` yang di-sampling 1:1000.

Dengan sampling 1:N, exporter hanya mengukur sekitar satu dari N paket. Record yang dihasilkan memuat paket yang terpilih saja. Registry IANA mencatat parameter sampling sebagai elemen tersendiri, termasuk sampling sistematis berbasis hitungan (N paket diambil, lalu sejumlah paket dilewati) [S6]; router berbeda bisa memakai metode berbeda (sistematis, acak n dari N), jadi metode router PT JAB perlu dicek di konfigurasinya.

Kolektor nfdump menangani sampling di sisi penerima: `nfcapd` memakai rasio sampling yang diumumkan exporter dan mengalikan counter paket dan byte di setiap record dengan rasio itu [S8]. Opsi `-s` di `nfcapd` memberi rasio default untuk exporter yang tidak mengirim informasi sampling, dan rasio negatif memaksa nilai itu untuk semua record [S8]. Akibatnya untuk analis:

1. **Angka di keluaran nfdump PT JAB sudah dikoreksi.** Record dari edge yang menunjukkan `1000` paket berarti satu paket tersampel, bukan seribu paket yang terukur. Semua counter yang selalu kelipatan 1.000 adalah tanda record sudah dikalikan. Bila exporter tidak mengumumkan sampling dan `nfcapd` tidak diberi `-s`, angkanya tidak dikoreksi dan terlihat seribu kali lebih kecil; cek salah satunya sebelum menulis angka di laporan.
2. **Volume besar cukup akurat; volume kecil tidak.** Galat relatif perkiraan kira-kira 1 dibagi akar jumlah paket tersampel (asumsi sampling acak, aritmetika peluang, bukan klaim vendor). Upload yang menghasilkan sekitar 1.900 paket tersampel punya galat relatif sekitar 2,3%, atau sekitar plus minus 4,5% pada tingkat keyakinan 95%. Koneksi yang hanya menghasilkan satu paket tersampel tidak punya perkiraan volume yang berarti.
3. **Koneksi kecil hilang.** Peluang koneksi berisi k paket terwakili minimal satu paket adalah 1 - (1 - 1/N)^k. Untuk N = 1000 dan beacon 15 paket, peluangnya sekitar 1,49%. Day 01 bagian 1.4 menghitung hal yang sama untuk beacon 12 paket (sekitar 1,2%), dan Day 04 bagian 1.3 untuk scan satu paket per probe (0,1%).
4. **Flag dan durasi menyesatkan.** Record dari satu paket tersampel punya durasi nol dan flag dari paket itu saja. SYN-only pada record sampled berarti "paket SYN yang kebetulan terpilih", bukan "koneksi tanpa balasan" (Day 04 bagian 2.5 membahas perbedaan ini untuk router DC 1:1). Volumenya juga menggelembung: satu paket 571 byte dari beacon yang total hanya sekitar 2,3 KB tampil sebagai record 1.000 paket dan 571.000 byte setelah dikalikan rasio (bagian 2.1).

Rumus kasarnya untuk laporan: jumlah paket tersampel kali N untuk perkiraan paket, jumlah byte tersampel kali N untuk perkiraan byte, lalu tulis rentang galatnya. Untuk pertanyaan "ada atau tidak koneksi kecil", flow sampled tidak bisa menjawab "tidak ada"; ia hanya bisa menjawab "tidak terlihat".

### 1.4 Satu koneksi, banyak record: timeout dan agregasi

Pertanyaan ketiga muncul saat Bambang pertama kali menarik flow laptop Rizky: satu upload yang menurut MDE berlangsung 47 menit muncul sebagai sepuluh record ke arah server dan sepuluh record ke arah sebaliknya.

Exporter menyimpan flow di cache dan mengekspornya saat salah satu kondisi terpenuhi: tidak ada paket selama idle timeout, flow sudah aktif selama active timeout, ada tanda akhir koneksi seperti FIN atau RST, cache penuh, atau exporter di-reset [S6]. Active timeout ada supaya kolektor mendapat angka untuk koneksi yang sangat panjang tanpa menunggu koneksi selesai. Router edge PT JAB, termasuk `bdg-rtr01`, dan router data center dikonfigurasi dengan active timeout 300 detik dan idle timeout 15 detik (nilai konfigurasi PT JAB; default vendor berbeda-beda, cek di `flow monitor` atau `flow exporter` router-mu). Upload 2.848 detik karena itu terpecah menjadi sembilan record penuh 300 detik dan satu record 148 detik.

Padanannya di ISP adalah interim-update RADIUS accounting: sesi PPPoE yang tersambung seminggu tetap mengirim record berkala, dan untuk menghitung total pemakaian kamu menjumlahkan semua record sesi itu. Batasnya: record flow yang terpecah tidak punya ID sesi bersama seperti `Acct-Session-Id`; yang mengikat mereka hanya 5-tuple dan urutan waktu. Bila port sumber dipakai ulang untuk koneksi baru ke tujuan yang sama, dua koneksi berbeda bisa tergabung tanpa disadari.

Agregasi menggabungkan record kembali. Di nfdump, opsi `-a` mengagregasi per 5-tuple dan `-A` memilih kunci agregasi sendiri; `-b` mengagregasi dua arah dan menampilkan counter masuk dan keluar terpisah [S7]. Agregasi juga dipakai sengaja untuk meringkas, misalnya `-A srcip,dstip,dstport` untuk satu baris per pasangan. Akibatnya, kolom "Flows" di keluaran agregasi berarti jumlah record, bukan jumlah koneksi: sepuluh record upload Rizky adalah satu koneksi.

Kebalikannya juga terjadi: idle timeout pendek memecah koneksi yang diam lebih lama dari 15 detik, misalnya sesi SSH interaktif, menjadi beberapa record, dan beacon yang memakai koneksi persisten bisa terlihat sebagai rangkaian record pendek. Sebelum menyimpulkan "banyak koneksi", cek apakah port sumbernya sama.

### 1.5 Apa yang bisa dan tidak bisa disimpulkan, dan pola forensik di flow

Dimas akan bertanya "jadi apa yang dikirim laptop itu?". Jawaban jujurnya: flow tidak tahu. Bagian ini memisahkan apa yang boleh ditulis dari flow dan apa yang harus diambil dari sumber lain.

Bisa: siapa bicara ke siapa, kapan, berapa lama, berapa data, ke port/layanan apa, arah dominan, pola (periodik, burst). Tidak bisa: isi payload, URL spesifik (kecuali ada ekstensi IPFIX), kredensial, nama file. Flow adalah metadata; untuk isi, naik ke pcap. Prinsip ini sejajar dengan TLS (Day 06): metadata tetap berguna walaupun isi tertutup.

Tabel berikut adalah pola makro yang paling sering dicari di flow; kolom kanan menyebut syarat agar polanya terbaca, karena sampling dan titik ekspor bisa menghapusnya.

| Pola | Tanda di flow | Syarat agar terbaca |
|---|---|---|
| Scan horizontal | Satu src, banyak dst, satu port, flow kecil (sedikit paket/byte) | Di flow sampled, scan harus cukup besar agar sebagian probe tersampel |
| Scan vertikal | Satu src, satu dst, banyak port | Sama; scan kecil ke satu host hampir pasti hilang di 1:1000 |
| DDoS | Banyak src ke satu dst, volume besar | Terbaca baik bahkan dengan sampling |
| Exfiltration | Byte keluar (src ke dst eksternal) jauh lebih besar dari masuk | Butuh dua arah (uniflow keduanya, atau biflow) |
| Beaconing | Flow periodik berukuran mirip ke satu dst (Day 11) | Butuh flow tanpa sampling atau sumber lain per sesi |
| Koneksi jangka panjang | Durasi sangat lama ke satu dst (kemungkinan C2/tunnel) | Gabungkan record yang dipotong active timeout |

Flow mengungkap pola makro ini di seluruh jaringan sekaligus, yang sulit dilihat dari pcap satu segmen. Untuk laptop Rizky, flow bisa menulis: "sekitar 2,75 GB keluar ke `203.0.113.178:443` dalam satu koneksi 47 menit, Kamis 13:05 sampai 13:52 WIB, dengan byte keluar sekitar 55 kali byte masuk". Yang tidak boleh ditulis dari flow: "data pelanggan bocor", "file X diunggah", atau "ini C2". Itu kesimpulan yang butuh MDE, pemeriksaan host, atau pengakuan pemilik data.

Setiap pola punya penjelasan jinak yang harus disingkirkan dulu: top talker bisa backup terjadwal, koneksi panjang bisa VPN atau streaming, scan bisa scanner resmi, dan periodisitas bisa agen update. Bagian 2.5 menunjukkan contohnya: `SOC-2027-0647` ternyata backup yang sah.

### 1.6 Flow, `conn.log`, dan pcap: saling melengkapi dan cara mencocokkan

Pertanyaan kelima datang dari Dimas: sebelum angka flow Bandung masuk laporan insiden, buktikan dulu bahwa cara mencocokkan flow dengan Zeek benar, memakai kasus Jakarta `SOC-2027-0647` yang terlihat di kedua sumber.

Zeek `conn.log` pada dasarnya flow yang diperkaya: satu baris per koneksi, dengan originator dan responder, byte dan paket per arah, durasi, `conn_state`, `history`, dan `uid` yang menautkan ke log protokol lain [S3]. Bila tidak ada NetFlow, `conn.log` memberi data setara dari sensor; bila ada keduanya, angkanya tidak akan pernah persis sama, dan analis harus tahu kenapa. Tabel berikut adalah daftar perbedaan yang harus dicek sebelum menyatakan dua record "sama" atau "berbeda".

| Hal | Flow (NetFlow v9/IPFIX di router) | Zeek `conn.log` |
|---|---|---|
| Arah | Umumnya uniflow, dua record per koneksi | Satu baris, `orig_*` dan `resp_*` |
| Pemecahan | Dipecah active dan idle timeout router | Satu baris per koneksi, ditulis saat koneksi selesai atau timeout Zeek |
| Byte | `octetDeltaCount` termasuk header IP [S6] | `orig_bytes` payload dari sequence number TCP; `orig_ip_bytes` byte level IP dari header total length [S17] |
| Sampling | Bisa di-sampling (edge PT JAB 1:1000) | Tidak di-sampling, tetapi bisa kehilangan paket (`missed_bytes`, capture loss) |
| Waktu | Jam router (NTP), awal dan akhir record | Jam sensor, `ts` awal koneksi dan `duration` |
| Kunci | 5-tuple dan waktu | `uid`, 5-tuple, Community ID |
| Isi protokol | Tidak ada | Tertaut lewat `uid` ke `dns.log`, `http.log`, `ssl.log` |

Aturan korelasi yang dipakai di PT JAB:

1. **Cocokkan 5-tuple dan jendela waktu, bukan ID.** nfdump tidak menghitung Community ID, jadi kunci bersama adalah alamat, port, protokol, dan waktu dengan toleransi beberapa detik untuk selisih jam router dan sensor.
2. **Bandingkan byte level IP dengan byte level IP.** Jumlahkan `octetDeltaCount` semua record satu arah dan bandingkan dengan `orig_ip_bytes`, bukan dengan `orig_bytes`. Selisih antara `orig_ip_bytes` dan `orig_bytes` adalah header IP dan TCP.
3. **Gabungkan record yang dipotong timeout** sebelum membandingkan durasi.
4. **Pastikan titik observasinya sama.** Flow router data center melihat workstation ke proxy, sama seperti SPAN core yang dilihat `jkt-zeek01`. Flow edge melihat proxy atau NAT ke internet, yang di Zeek adalah koneksi lain dengan `uid` lain (Day 08 bagian 1.3 membahas dua hop proxy).

Alur kerja umumnya: flow untuk menemukan koneksi menarik di skala besar (volume anomali, scan, tujuan mencurigakan), lalu `conn.log` untuk menautkan ke log protokol, lalu pcap (bila tersedia untuk periode itu) untuk memeriksa isi. Karena pcap penuh mahal, banyak organisasi menyimpan flow jangka panjang dan pcap hanya untuk periode atau segmen tertentu; perbandingan vendor flow menyebut flow butuh kira-kira seribu kali lebih sedikit ruang daripada paket yang sama, dengan retensi bulanan sampai tahunan dibanding hari sampai minggu untuk pcap [S4]. Di PT JAB, urutan retensinya: flow 13 bulan, log firewall 90 hari, `proxy` dan `dns` 30 hari, pcap egress sekitar 72 jam. Forensik yang baik tahu data mana tersedia dan memilih yang tepat untuk tiap pertanyaan.

### 1.7 Sudut pandang ISP: visibilitas, abuse handling, dan CGNAT

Pertanyaan keenam membawa Day ini ke sisi lain PT JAB: alamat `198.51.100.210` bukan milik satu komputer, tetapi alamat pool CGNAT `jkt-cgn01` yang dipakai bersama pelanggan broadband Jakarta.

Di ISP/NOC, flow dipakai untuk kapasitas, deteksi DDoS, peering/billing (AS, volume), dan troubleshooting. Sudut ini membawa pelajaran untuk forensik:

- **Visibilitas:** di mana exporter dipasang menentukan apa yang terlihat; trafik yang tak lewat exporter tak terekam. Trafik yang diblok `jkt-fw01` juga tidak pernah sampai ke router edge, jadi tidak ada di flow edge.
- **Sampling:** flow sering disampel pada tautan cepat; forensik harus tahu rasio sampling agar tak salah hitung (bagian 1.3).
- **Agregasi:** flow meringkas; detail sub-flow hilang (bagian 1.4).
- **Privasi dan legal:** flow adalah metadata komunikasi; aksesnya diatur hukum dan kebijakan (Day 01 bagian 1.7). Dibahas umum di sini; regulasi lokal perlu dicek dengan Legal.

Pengalaman operasional (membaca top talker, mengenali DDoS) langsung berguna di forensik; yang ditambahkan adalah niat investigatif dan kehati-hatian bukti.

**Abuse desk.** Konvensi internet sejak RFC 2142 adalah mailbox `abuse@` di domain utama organisasi untuk laporan perilaku tidak pantas, berlaku walaupun keluhannya tentang pelanggan di subdomain [S15]. Laporan yang masuk ke `abuse@jab.example` biasanya berisi alamat sumber, waktu, dan cuplikan log korban. Tugas abuse desk: memverifikasi bahwa laporan masuk akal, menemukan pelanggan yang bertanggung jawab atas alamat itu pada waktu itu, memberi tahu pelanggan atau membatasi layanannya sesuai ketentuan layanan, dan membalas pelapor tanpa membuka identitas pelanggan. Abuse desk tidak membaca isi trafik pelanggan; buktinya adalah log pelapor ditambah log milik ISP sendiri.

**CGNAT.** Habisnya pool IPv4 membuat operator berbagi satu alamat publik untuk banyak pelanggan lewat NAT44, NAT64, atau DS-Lite, sehingga alamat publik saja tidak lagi mengidentifikasi pelanggan [S11]. Antara CGN dan CPE, operator memakai Shared Address Space `100.64.0.0/10`, yang tidak boleh dirutekan atau diiklankan ke luar batas operator [S14]. Untuk mengikat satu koneksi ke satu pelanggan, CGN perlu mencatat per pemetaan: protokol, identitas pelanggan, alamat dan port sumber eksternal, dan waktu; RFC 6888 menyebut daftar ini sebagai informasi, bukan kewajiban, dan mencatat volumenya bisa sangat besar [S12]. Ada dua cara mengurangi volume itu:

- **Port block allocation.** CGN memberi tiap pelanggan satu blok port dan mencatat alokasi serta pelepasan blok, bukan setiap koneksi. RFC 6888 menyebut skema di mana banyak pemetaan berbagi satu entri log, dan menjadikan "minimalkan volume log" salah satu persyaratan alokasi port (REQ-14) yang bersaing dengan utilisasi port dan port yang sulit ditebak [S12]. IPFIX punya kode `natEvent` 16 dan 17 untuk alokasi dan pelepasan blok port [S6].
- **Deterministic NAT.** Pelanggan dipetakan ke alamat publik dan rentang port lewat algoritma tetap, sehingga yang perlu dicatat hanya konfigurasi algoritmanya, ditambah blok tambahan dari pool dinamis bila pelanggan kehabisan port [S13]. RFC 7422 memberi gambaran skala: pesan log CGN sekitar 150 byte, rata-rata sekitar 33.000 koneksi per rumah per hari, sehingga log per koneksi mencapai sekitar 150 MB per pelanggan per bulan, atau sekitar 150 TB per bulan untuk satu juta pelanggan [S13].

`jkt-cgn01` memakai port block allocation dengan blok 512 port per pelanggan, dan log alokasinya dikirim ke index `netops` (konfigurasi fiktif PT JAB). Satu baris log menjawab "blok port mana dipegang alamat dalam mana, dari jam berapa sampai jam berapa". Alamat dalam (`100.64.x.x`) lalu dipetakan ke ID pelanggan lewat RADIUS accounting di BNG `jkt-bng01`. Dua langkah ini adalah padanan ISP dari "IP ke hostname" di jaringan korporat.

**Privasi.** RFC 6888 (REQ-12) merekomendasikan CGN tidak mencatat alamat dan port tujuan kecuali ada keperluan administratif, dengan alasan privasi dan volume log [S12]. Logikanya bersandar pada RFC 6302: bila server tujuan mencatat port sumber dan waktu yang presisi, log CGN tanpa tujuan sudah cukup untuk menjawab "siapa"; kata SHOULD di sana memberi ruang untuk kasus server yang tidak mengikuti RFC 6302 [S12]. Prinsip yang sama berlaku untuk flow pelanggan di PT JAB: abuse desk boleh melihat flow pelanggan sejauh perlu memverifikasi laporan (port sumber di blok pelanggan, port tujuan yang dilaporkan, jendela waktu), tidak membuka daftar tujuan lain tanpa alasan, dan SOC hanya menerima ringkasannya.

### 1.8 Permintaan data dari aparat penegak hukum (umum, bukan nasihat hukum)

Pertanyaan ketujuh dari Ratna: bila polisi meminta data pelanggan untuk alamat seperti `198.51.100.210`, apa yang diperlukan dan apa yang boleh diberikan? Bagian ini membahas sisi teknisnya; dasar hukum dan prosedur formalnya milik Legal.

**Apa yang diperlukan agar permintaan bisa dijawab.** RFC 6302 merekomendasikan server yang menghadap internet mencatat, selain alamat sumber: port sumber, timestamp dengan presisi minimal detik dari sumber waktu tepercaya seperti NTP (UTC lebih disukai daripada waktu lokal), serta protokol transport dan port tujuan bila relevan [S11]. Alasannya: di belakang CGNAT, alamat publik saja tidak mengidentifikasi pelanggan, dan port didaur ulang dengan cepat sehingga waktu yang tidak presisi bisa menunjuk pelanggan lain [S11]. Permintaan yang hanya menyebut "IP `198.51.100.210`, tanggal 20 Mei" tidak bisa dijawab dengan satu nama pelanggan; jawaban yang jujur adalah menyebut bahwa alamat itu dipakai bersama dan meminta port sumber serta waktu dengan zona waktunya.

**Apa yang bisa diberikan.** Dari log PT JAB: blok port yang dipegang alamat dalam pada waktu itu (log CGN), ID pelanggan yang memakai alamat dalam itu (RADIUS), lalu identitas pelanggan dari sistem pelanggan. ISP tidak punya isi komunikasi pelanggan karena tidak merekamnya, dan flow pelanggan adalah metadata komunikasi yang penyerahannya butuh dasar hukum tersendiri. Merekam isi komunikasi untuk aparat adalah rezim penyadapan yang berbeda dan tidak dibahas di sini; aturan penyadapan di Indonesia dirangkum di Day 01 bagian 1.7.

**Batas teknis yang harus dinyatakan:**

- Identitas yang ditemukan adalah pemegang kontrak layanan, bukan orang atau perangkat. Di belakang CPE pelanggan ada NAT rumah dan banyak perangkat.
- Jawaban hanya sebaik retensi log. Log CGN yang sudah terhapus oleh retensi tidak bisa dihidupkan lagi; karena itu permintaan resmi atau perkara yang sedang berjalan memicu preservation (legal hold) atas log yang relevan.
- Jam harus dinyatakan dengan zona waktunya. Satu jam selisih (UTC dibaca sebagai WIB atau sebaliknya) bisa menunjuk pelanggan lain, seperti yang terlihat di bagian 2.8.
- Data yang diberikan dibatasi pada pertanyaan: satu alamat, satu port atau rentang port, satu jendela waktu. Menyerahkan daftar semua pelanggan yang memakai satu alamat sepanjang hari bukan jawaban yang proporsional.

Praktik yang disarankan untuk PT JAB: semua permintaan aparat masuk ke Legal (Ratna), bukan ke NOC atau SOC langsung; keaslian permintaan diverifikasi lewat saluran resmi sebelum data apa pun dicari; pencarian dijalankan oleh peran NOC yang ditunjuk dan dicatat; hasilnya diserahkan Legal. Data pelanggan tetap data pribadi di bawah UU PDP (Day 01 bagian 1.7), sehingga DPO Agus perlu tahu prosedurnya.

### 1.9 Alat: nfdump, SiLK, ElastiFlow, dan `conn.log`

Bambang meminta anak NOC diajari nfdump "dengan benar". Tabel ini membandingkan alat yang akan kamu temui di lapangan; PT JAB memakai nfdump, dan alat lain dibahas supaya kamu bisa membaca laporan atau dokumentasi yang memakainya.

| Alat | Bentuk | Yang perlu diingat |
|---|---|---|
| nfdump (`nfcapd` dan `nfdump`) | Kolektor dan pembaca command line; dipakai di `jkt-flow01` | `nfcapd` menulis file per interval (default 300 detik, nama `nfcapd.YYYYMMddhhmm`), mendengarkan default di UDP 9995, opsi `-S` membuat hierarki direktori seperti `%Y/%m/%d`, dan mengalikan counter dengan rasio sampling [S8]. `nfdump` membaca file atau direktori dengan `-r`, memfilter dengan sintaks mirip tcpdump, dan membuat statistik dengan `-s` [S7] |
| SiLK (`rwfilter`, `rwstats`, `rwcut`) | Suite analisis flow dari CERT NetSA | `rwfilter` wajib punya input (pemilihan tanggal, class, type, sensor, atau file) dan minimal satu output (`--pass`, `--fail`); filter seperti `--scidr`, `--dport`, `--flags-all=S/SA` [S10]. `rwstats --fields=sip --values=bytes --count=10` membuat top N; `--values=distinct:dip` menghitung tujuan unik [S10] |
| ElastiFlow | Kolektor flow komersial yang menerima NetFlow, IPFIX, dan sFlow untuk analitik dan dashboard [S16] | Dashboard memudahkan, tetapi untuk laporan tetap cek apakah angka sudah dikoreksi sampling dan dari exporter mana |
| Zeek `conn.log` | Flow yang diperkaya dari sensor (Day 08) | Tanpa sampling, dua arah, tertaut ke log protokol; hanya ada di titik sensor |

Satu hal tentang versi: nfdump 1.7.10 menyebut `-R` (rentang file) dan `-t` (jendela waktu) sebagai sintaks lama; `-r` kini menerima file atau direktori beserta subdirektorinya, dan jendela waktu disarankan lewat filter `first seen` dan `last seen` [S7]. Contoh di Day 04 bagian 2.5 memakai `-R` dan `-t`; keduanya masih bisa dipakai, tetapi contoh di Day ini memakai bentuk baru.

## 2. Contoh dan langkah praktis: Jumat pagi di `jkt-flow01`

Semua keluaran di bagian ini adalah keluaran ilustrasi untuk organisasi fiktif PT JAB, bukan hasil eksekusi nyata. Asumsi lingkungan yang dipakai: `jkt-flow01` menjalankan satu instance `nfcapd` per router dan menyimpan file di `/flow/<router>/` dengan hierarki tanggal (`/flow/bdg-rtr/2027/05/20/`, `/flow/dc-rtr/...`, `/flow/jkt-edge/...`), sama seperti asumsi di Day 04; jam sistem `jkt-flow01` memakai WIB, sedangkan `jkt-zeek01`, `jkt-pcap01`, dan `jkt-nsm-ws01` memakai UTC. NAT kantor Bandung dilakukan di `bdg-rtr01`, dan flow monitor dipasang di interface sisi kantor, sehingga record memuat alamat dalam (`10.30.50.46`), bukan alamat publik Bandung. Wi-Fi dinas Bandung keluar langsung ke internet lewat `bdg-fw01` (kebijakan lama untuk tamu dan staf dinas), sedangkan LAN kantor Bandung memakai `jkt-proxy01` lewat MPLS. Cek path, zona waktu, dan titik ekspor di kolektor-mu sebelum menyalin perintah.

### 2.1 Membaca record flow laptop Rizky dan menggabungkannya

Langkah pertama untuk pertanyaan Dimas ("berapa banyak data yang keluar") adalah melihat record mentah `bdg-rtr01`, karena di situlah terlihat kenapa satu upload muncul sebagai dua puluh baris (pertanyaan 3).

**Tujuan:** menampilkan semua record antara laptop `JKT-WS-2046` (`10.30.50.46`) dan `203.0.113.178` di `bdg-rtr01` sejak Selasa, lalu meringkasnya per koneksi.

**Bentuk paling dasar.** Perintah lama untuk satu file tetap berguna sebagai orientasi:

```bash
nfdump -r flows.nfcapd -o extended
nfdump -r /flow/bdg-rtr/2027/05/20/nfcapd.202705201305 -I
```

`nfdump` membaca file flow yang dikumpulkan `nfcapd`; `-o extended` mencetak satu flow per baris dengan detail tambahan, dan `-I` mencetak statistik ringkas satu file (jumlah flow, paket, byte, waktu pertama dan terakhir) [S7]. Tiap baris satu flow dengan 5-tuple, waktu, paket, byte, flag. Mulai dari gambaran, lalu saring.

**Sintaks untuk kasus ini:**

```bash
nfdump -r /flow/bdg-rtr/2027/05/ -N -o extended \
  'ip 10.30.50.46 and ip 203.0.113.178 and first seen >= 2027-05-18T00:00:00 and last seen <= 2027-05-21T00:00:00'
```

Tabel berikut menjelaskan setiap bagian perintah; perhatikan bahwa `-r` diarahkan ke direktori bulan, sehingga semua subdirektori hari ikut terbaca.

| Bagian | Fungsi |
|---|---|
| `-r /flow/bdg-rtr/2027/05/` | Membaca satu file atau satu direktori beserta subdirektorinya [S7] |
| `-N` | Angka polos tanpa skala (`2745408000`, bukan `2.7 G`), supaya bisa disalin ke laporan dan dijumlahkan [S7] |
| `-o extended` | Satu flow per baris dengan kolom tambahan (flag, ToS, pps, bps, bpp) [S7] |
| `ip 10.30.50.46 and ip 203.0.113.178` | Record yang memuat kedua alamat, di sisi mana pun; jadi dua arah ikut |
| `first seen >= ... and last seen <= ...` | Jendela waktu dengan format ISO 8601; pengganti `-t` yang kini disebut legacy [S7] |

Keluaran ilustrasi (kolom diringkas; 22 record, ditampilkan 6):

```
Date first seen          Duration Proto  Src IP Addr:Port        Dst IP Addr:Port       Flags  Packets       Bytes Flows
2027-05-19 11:47:23.415     0.000 TCP    10.30.50.46:50212   ->  203.0.113.178:443      .AP...    1000      571000     1
2027-05-20 09:20:06.882     0.000 TCP    203.0.113.178:443   ->  10.30.50.46:50890      .AP...    1000     1420000     1
2027-05-20 13:05:12.871   299.402 TCP    10.30.50.46:51544   ->  203.0.113.178:443      .AP...  199000   288152000     1
2027-05-20 13:05:13.390   298.977 TCP    203.0.113.178:443   ->  10.30.50.46:51544      .A....  101000     5252000     1
...
2027-05-20 13:50:11.664   146.853 TCP    10.30.50.46:51544   ->  203.0.113.178:443      .AP...   97000   140456000     1
2027-05-20 13:50:12.020   146.382 TCP    203.0.113.178:443   ->  10.30.50.46:51544      .A....   57000     2964000     1
Summary: total flows: 22, total bytes: 2797319000, total packets: 2858000
```

**Cara membaca hasil:**

- Dua record pertama berdurasi nol dan berisi tepat 1.000 paket: masing-masing satu paket tersampel yang sudah dikalikan rasio. Record pertama adalah satu paket 571 byte dari laptop pada Rabu 11:47, record kedua satu paket 1.420 byte dari server pada Kamis 09:20. Keduanya bagian dari beacon (bagian 2.3), bukan transfer 571 KB dan 1,4 MB.
- Dua puluh record sisanya punya port sumber yang sama (`51544`): satu koneksi yang dipotong active timeout 300 detik menjadi sepuluh record per arah (bagian 1.4). Record terakhir tiap arah lebih pendek (sekitar 147 detik) karena koneksinya selesai.
- Flag hanya `.AP...` dan `.A....`: SYN dan FIN koneksi itu tidak tersampel, jadi dari flow saja kamu tidak tahu kapan koneksi tepatnya dibuka dan ditutup. Template `bdg-rtr01` juga tidak memuat `flowEndReason`, sehingga record terakhir tidak bisa dibedakan antara "koneksi selesai" dan "idle timeout".
- `Date first seen` adalah paket tersampel pertama dalam record, bukan paket pertama koneksi. Awal koneksi yang presisi diambil dari log firewall (bagian 2.2).
- Ringkasan: 22 record, 2.797.319.000 byte (2.745.408.000 + 49.920.000 dari upload, ditambah 571.000 dan 1.420.000 dari dua record beacon).

**Menggabungkan per koneksi.** Untuk laporan, dua puluh record upload harus menjadi satu baris:

```bash
nfdump -r /flow/bdg-rtr/2027/05/ -N -b \
  'ip 10.30.50.46 and ip 203.0.113.178 and first seen >= 2027-05-18T00:00:00 and last seen <= 2027-05-21T00:00:00'
```

`-b` mengagregasi dua arah menjadi satu record per koneksi dan menampilkan counter kedua arah terpisah; ia sudah mencakup `-a` (agregasi per 5-tuple) [S7]. Keluaran ilustrasi (kolom diringkas dan diberi label arah supaya jelas; nama kolom in/out dan arti arahnya perlu dicek di versi-mu):

```
Date first seen          Duration Proto  Src IP Addr:Port       Dst IP Addr:Port    Pkt laptop  Byte laptop  Pkt server Byte server Flows
2027-05-19 11:47:23.415     0.000 TCP    10.30.50.46:50212  <-> 203.0.113.178:443         1000       571000           0           0     1
2027-05-20 09:20:06.882     0.000 TCP    10.30.50.46:50890  <-> 203.0.113.178:443            0            0        1000     1420000     1
2027-05-20 13:05:12.871  2845.646 TCP    10.30.50.46:51544  <-> 203.0.113.178:443      1896000   2745408000      960000    49920000    20
```

**Cara membaca hasil:** satu koneksi upload dengan 1.896 paket tersampel keluar (1.896.000 setelah koreksi) dan 960 paket tersampel masuk. Byte keluar 2.745.408.000, byte masuk 49.920.000, rasio sekitar 55 banding 1: bentuk upload, dengan arah balik hampir hanya ACK (49.920.000 dibagi 960.000 sama dengan 52 byte per paket, ukuran ACK dengan opsi timestamp TCP). Kolom `Flows` 20 berarti dua puluh record, bukan dua puluh koneksi. Durasi 2.845,646 detik adalah jarak paket tersampel pertama dan terakhir, sedikit lebih pendek dari durasi koneksi sebenarnya.

**Variasi:** `-A srcip,dstip,dstport` untuk satu baris per pasangan dan layanan, tanpa memecah per port sumber; `-o csv` untuk mengirim hasil ke spreadsheet atau Splunk; `-B` bila arah klien-server di record kebalikan dari yang kamu harapkan (nfdump menebak arah dari port, dengan ambang 1024) [S7].

**Kapan gagal:** port sumber dipakai ulang untuk koneksi baru ke tujuan yang sama sehingga dua koneksi tergabung; jam router tidak sinkron NTP sehingga `first seen` meleset; path direktori atau `-S` di kolektor berbeda dari asumsi; atau koneksi masih berjalan saat file terakhir ditulis, sehingga record terakhir belum ada.

### 2.2 Koreksi sampling, rentang galat, dan pembanding dari `bdg-fw01`

Bagian ini menjawab inti pertanyaan kedua Bambang: angka 2.745.408.000 byte itu bisa dipercaya sampai seberapa?

**Langkah 1: pastikan angkanya sudah dikoreksi.** Semua counter di bagian 2.1 kelipatan 1.000, tanda bahwa `nfcapd` mengalikan counter dengan rasio sampling yang diumumkan `bdg-rtr01` [S8]. Konfirmasi lewat cara `nfcapd` dijalankan:

```bash
nfcapd -D -w /flow/bdg-rtr -S 1 -t 300 -p 9996
```

| Bagian | Fungsi |
|---|---|
| `-D` | Jalan sebagai daemon di latar belakang [S8] |
| `-w /flow/bdg-rtr` | Direktori tujuan file flow (`-l` adalah alias lama) [S8] |
| `-S 1` | Subdirektori `tahun/bulan/hari` [S8] |
| `-t 300` | Rotasi file tiap 300 detik (default), nama `nfcapd.YYYYMMddhhmm` [S8] |
| `-p 9996` | Port UDP instance ini; default `nfcapd` adalah 9995 [S8] |
| tanpa `-s` | Memakai rasio sampling yang diumumkan exporter; `-s 1000` hanya dipakai bila exporter tidak mengumumkan, dan `-s -1000` memaksa rasio untuk semua record [S8] |

Bila exporter tidak mengumumkan sampling dan `-s` tidak dipasang, counter tidak dikoreksi: record upload akan berisi 199 paket, bukan 199.000. Bila keduanya ada (exporter mengumumkan dan seseorang memasang `-s -1000`), hasilnya tetap 1:1000; yang berbahaya adalah salah rasio, misalnya router diubah ke 1:512 tetapi `nfcapd` memaksa 1000.

**Langkah 2: hitung rentang galat.** Tabel berikut memakai rumus kasar dari bagian 1.3 (galat relatif sekitar 1 dibagi akar jumlah paket tersampel, 95% sekitar 1,96 kali itu). Kolom terakhir adalah angka yang boleh ditulis di laporan.

| Besaran | Tersampel | Perkiraan (x1000) | Galat relatif | Rentang 95% |
|---|---|---|---|---|
| Paket keluar | 1.896 | 1.896.000 | 2,30% | 1.810.680 sampai 1.981.320 |
| Byte keluar | (dari 1.896 paket) | 2.745.408.000 | 2,30% | sekitar 2,62 sampai 2,87 GB |
| Paket masuk | 960 | 960.000 | 3,23% | sekitar 899.000 sampai 1.021.000 |
| Byte masuk | (dari 960 paket) | 49.920.000 | 3,23% | sekitar 46,8 sampai 53,1 MB |

Rentang byte memakai galat relatif yang sama dengan paket karena hampir semua paket keluar berukuran penuh (1.448 byte); untuk trafik dengan ukuran paket bervariasi, galatnya lebih besar. Ini aritmetika peluang dengan asumsi sampling acak per paket, bukan klaim vendor; metode sampling `bdg-rtr01` perlu dicek di konfigurasi `sampler`-nya.

**Langkah 3: cari pembanding tanpa sampling.** `bdg-fw01` mencatat setiap sesi yang diizinkan beserta byte per arah, tanpa sampling.

**Tujuan:** menghitung sesi laptop ke `203.0.113.178` per hari dan byte sebenarnya.

**Asumsi data:** log `bdg-fw01` di `index=firewall` dengan field gaya CIM Network Traffic (`src_ip`, `dest_ip`, `dest_port`, `action`, `bytes_out`, `bytes_in`, `duration`); satu event per sesi, `_time` adalah awal sesi. Cek nama field di parsing firewall-mu.

```
index=firewall host=bdg-fw01 src_ip=10.30.50.46 dest_ip=203.0.113.178 dest_port=443 action=allowed
    earliest="05/18/2027:00:00:00" latest="05/21/2027:00:00:00"
| eval day=strftime(_time,"%F")
| stats count AS sessions sum(bytes_out) AS out sum(bytes_in) AS in max(bytes_out) AS max_out
        min(_time) AS first max(_time) AS last BY day
| eval first=strftime(first,"%T"), last=strftime(last,"%T")
```

| Bagian | Fungsi |
|---|---|
| `host=bdg-fw01 ... action=allowed` | Hanya sesi yang benar-benar keluar dari Bandung |
| `earliest=... latest=...` | Rentang absolut Selasa sampai Kamis, supaya bisa diulang |
| `stats count ... BY day` | Jumlah sesi per hari: angka yang tidak bisa diberikan flow sampled |
| `max(bytes_out)` | Sesi terbesar per hari, untuk menemukan upload |

Keluaran ilustrasi:

```
day         sessions  out         in        max_out     first     last
2027-05-18        19       45220     98990        2380  13:27:04  17:57:09
2027-05-19        40       95200    208400        2380  08:02:11  17:47:15
2027-05-20        37  2739001320  49967772  2738915640  08:05:02  16:50:06
```

**Cara membaca hasil:**

- 96 sesi: 95 beacon (setiap 15 menit selama laptop menyala, masing-masing 2.380 byte keluar dan 5.210 byte masuk) dan satu upload Kamis. Kamis: 36 beacon kali 2.380 sama dengan 85.680, ditambah upload 2.738.915.640, sama dengan 2.739.001.320.
- Sesi upload di log firewall: mulai 13:05:11, durasi 2.848 detik, `bytes_out` 2.738.915.640, `bytes_in` 49.780.212 (dari event mentahnya).
- Perkiraan flow 2.745.408.000 lebih besar 0,24% dari angka firewall; byte masuk lebih besar 0,28%. Keduanya jauh di dalam rentang 95% dari langkah 2. Cara mencocokkan ini sendiri lolos uji: flow sampled yang dikoreksi memberi angka yang benar untuk transfer besar.
- Sesi terakhir 16:50:06, sesudah alert MDE 16:38 dan sebelum isolasi 17:05.

**Variasi:** `| timechart span=15m count` untuk memperlihatkan irama beacon 15 menit; ganti `src_ip` dengan `dest_ip=203.0.113.178` saja untuk mencari host lain (bagian 2.3).

**Kapan gagal:** firewall hanya mencatat awal sesi tanpa byte; sesi sangat panjang dicatat sebagai beberapa event interim; atau firewall cabang tidak mengirim log ke Splunk sama sekali. Dalam kasus itu flow sampled adalah satu-satunya angka volume, dan rentang galatnya wajib ditulis.

### 2.3 Sejak kapan, dan ada host lain atau tidak

Dua sisa pertanyaan Bambang untuk `SOC-2027-0645` ("sejak kapan" dan "ada host lain") adalah pertanyaan tentang ketiadaan, dan flow sampled paling lemah justru di situ.

**Tujuan:** mencari semua sumber yang pernah berkomunikasi dengan `203.0.113.178` sepanjang retensi flow, lalu membandingkannya dengan sumber tanpa sampling.

**Flow, 13 bulan:**

```bash
nfdump -r /flow/bdg-rtr/ -N -s srcip/flows -n 20 'ip 203.0.113.178'
nfdump -r /flow/jkt-edge/ -N -s srcip/flows -n 20 'ip 203.0.113.178'
```

| Bagian | Fungsi |
|---|---|
| `-r /flow/bdg-rtr/` | Seluruh direktori router, sepanjang retensi 13 bulan; berat, jadi jalankan di luar jam sibuk atau per bulan |
| `-s srcip/flows -n 20` | Statistik per alamat sumber, diurutkan jumlah record, 20 teratas [S7] |
| `'ip 203.0.113.178'` | Record dengan alamat itu di sisi mana pun |

Keluaran ilustrasi:

```
bdg-rtr:   Src IP Addr      Flows   Packets       Bytes
           10.30.50.46         11   1897000  2745979000
           203.0.113.178       11    961000    51340000
jkt-edge:  (tidak ada record)
```

**Cara membaca hasil:** hanya laptop Rizky, dan hanya sejak Rabu. Total per sumber cocok dengan bagian 2.1: 11 record dari laptop (10 record upload ditambah satu beacon Rabu) dan 11 record dari server (10 record upload ditambah satu beacon Kamis). Flow tidak melihat beacon Selasa sama sekali dan tidak melihat apa pun dari Jakarta. Kalimat yang benar untuk laporan: "tidak terlihat di flow sampled", bukan "tidak ada".

Hitungannya menjelaskan kenapa. Dengan beacon 15 paket dan sampling 1:1000, peluang satu beacon terwakili sekitar 1,49% (bagian 1.3). Dari 95 beacon laptop Rizky, rata-rata yang terlihat hanya sekitar 1,4, dan peluang tidak ada satu pun yang terlihat sekitar 24%. Dua record beacon yang muncul adalah kebetulan yang wajar, bukan pola.

**Firewall, 90 hari, tanpa sampling:**

```
index=firewall dest_ip=203.0.113.178
    earliest="02/20/2027:00:00:00" latest="05/21/2027:09:45:00"
| stats count AS events values(action) AS action min(_time) AS first max(_time) AS last BY host src_ip
| eval first=strftime(first,"%F %T"), last=strftime(last,"%F %T")
```

| Bagian | Fungsi |
|---|---|
| `dest_ip=203.0.113.178` | Semua firewall, semua sumber |
| `earliest="02/20/2027:00:00:00"` | Awal retensi 90 hari dihitung mundur dari Jumat 2027-05-21 |
| `BY host src_ip` | Memisahkan `jkt-fw01` dan `bdg-fw01`, serta setiap sumber |

Keluaran ilustrasi:

```
host      src_ip        events action   first                last
bdg-fw01  10.30.50.46       96 allowed  2027-05-18 13:27:04  2027-05-20 16:50:06
bdg-fw01  10.30.50.52       41 allowed  2027-05-19 10:31:40  2027-05-20 10:31:52
jkt-fw01  10.10.60.101      31 blocked  2027-05-17 10:12:40  2027-05-17 17:42:44
jkt-fw01  10.10.60.102       7 blocked  2027-05-21 08:12:15  2027-05-21 09:42:20
```

**Cara membaca hasil:**

- **Sejak kapan.** Jejak jaringan paling awal adalah Senin 2027-05-17 10:12:40 WIB: laptop Rizky di Jakarta (`10.10.60.101`) mencoba HTTPS langsung ke `203.0.113.178` dan diblokir `jkt-fw01`, karena workstation Jakarta wajib lewat proxy. 31 percobaan dari 10:12 sampai 17:42, setiap 15 menit. Percobaan yang diblokir tidak pernah sampai router edge, jadi tidak ada di flow edge; `jkt-zeek01` belum hidup hari itu, dan pcap Senin sudah tertimpa ring buffer. Koneksi keluar pertama yang berhasil terjadi Selasa 13:27:04 di Bandung. Kapan file `drvupd.exe` sampai di laptop adalah pertanyaan untuk timeline MDE, bukan untuk jaringan.
- **Host lain.** `10.30.50.52` di Wi-Fi dinas Bandung: 41 sesi, Rabu 10:31 sampai Kamis 10:31. Log DHCP Wi-Fi dinas di `index=netops` memetakan alamat itu ke `JKT-WS-2047` (`dewi.anggraini`, satu tim dengan Rizky dan ikut dinas ke Bandung). Pagi ini laptop itu kembali di Jakarta (`10.10.60.102`) dan percobaannya diblokir `jkt-fw01` sejak 08:12. Alert `SOC-2027-0646` dibuat pukul 09:50, MDE menemukan `drvupd.exe` di laptop itu, dan isolasi dilakukan 09:58. Host ini masuk `INC-2027-069`.
- **Kenapa flow tidak menemukannya.** Peluang 41 beacon `JKT-WS-2047` semuanya lolos dari sampling sekitar 54%: lebih mungkin tidak terlihat daripada terlihat. Itu yang terjadi.

Karena TAP egress Jakarta ada di sisi dalam `jkt-fw01`, percobaan Jumat pagi dari `10.10.60.102` juga terlihat di `conn.log` sebagai SYN tanpa balasan (`conn_state` S0) ke `203.0.113.178:443`, tujuh baris, cocok dengan tujuh event `blocked`. Jakarta punya tiga sumber yang saling menguatkan; Bandung hanya punya firewall dan flow sampled.

**Variasi:** `index=dns` untuk nama yang pernah dijawab dengan `203.0.113.178` (di kasus ini kosong, alamat ditanam langsung di malware, sehingga tidak ada nama untuk dicari di proxy); `nfdump ... 'net 203.0.113.0/24'` untuk tetangga satu prefiks, dengan catatan bahwa satu prefiks hosting bisa memuat ribuan pelanggan yang tidak berhubungan.

**Kapan gagal:** firewall tidak mencatat sesi yang diizinkan (hanya deny); retensi firewall 90 hari sudah lewat sehingga flow sampled satu-satunya sumber jangka panjang; atau malware memakai banyak alamat tujuan, sehingga pencarian per alamat harus diganti dengan pencarian per perilaku (bagian 2.4).

### 2.4 Pola makro di flow `bdg-rtr01`: top talker, scan, arah, dan koneksi panjang

Pertanyaan keempat (pola apa yang bisa dan tidak bisa dibaca) paling mudah dijawab dengan menjalankan empat pertanyaan klasik NOC ke data Kamis `bdg-rtr01`, lalu melihat mana yang memberi jawaban jujur di bawah sampling 1:1000. Bambang memakai bagian ini untuk melatih anak NOC.

**Top talker (volume terbesar).** Bentuk dasarnya:

```bash
nfdump -r flows.nfcapd -s ip/bytes -n 10
nfdump -r /flow/bdg-rtr/2027/05/20/ -N -s ip/bytes -n 10 \
  'first seen >= 2027-05-20T13:00:00 and last seen <= 2027-05-20T14:00:00'
```

| Bagian | Fungsi |
|---|---|
| `-s ip/bytes` | Statistik per alamat IP (sumber dan tujuan dihitung), diurutkan byte [S7] |
| `-n 10` | Sepuluh teratas; default untuk statistik juga 10 [S7] |
| Filter waktu | Satu jam di sekitar upload, supaya pembanding sejam |

Keluaran ilustrasi (lima baris pertama):

```
IP Addr            Flows    Packets        Bytes
10.30.50.46           84    2889000   2836528000
203.0.113.178         20    2856000   2795328000
10.20.3.60          1912    1402000   1188416000
10.30.20.17          131     391000    412300000
10.30.50.38           61     344000    121800000
```

**Cara membaca hasil:** `-s ip` menghitung setiap record dua kali, sekali untuk sumber dan sekali untuk tujuan, jadi kolom `Bytes` tidak boleh dijumlahkan menjadi total trafik. Di ISP, daftar ini adalah daftar kapasitas: `10.20.3.60` adalah `jkt-proxy01` yang melayani LAN kantor Bandung lewat MPLS, dan volumenya wajar. Di forensik, yang menonjol adalah laptop Wi-Fi dinas dan satu alamat luar yang tidak dikenal dengan volume yang setara; volume keluar besar ke tujuan tak biasa adalah kandidat exfiltration, belum kesimpulan. Top talker terbaca baik walaupun di-sampling, karena volumenya besar (bagian 1.3).

**Scan (SYN tanpa ACK).** Bentuk dasarnya dari file lama, lalu versi untuk Wi-Fi dinas:

```bash
nfdump -r flows.nfcapd 'proto tcp and flags S and not flags A' -s dstip
nfdump -r /flow/bdg-rtr/2027/05/20/ -N -s srcip/flows -n 5 \
  'src net 10.30.50.0/24 and proto tcp and flags S and not flags A'
```

| Bagian | Fungsi |
|---|---|
| `flags S and not flags A` | Record yang memuat SYN dan tidak memuat ACK; flag yang tidak disebut diabaikan [S7] |
| `-s dstip` | Tujuan yang paling sering menerima SYN-only; untuk scan horizontal, ganti ke `-s srcip` dan hitung tujuan unik |
| `src net 10.30.50.0/24` | Hanya Wi-Fi dinas Bandung |

Keluaran ilustrasi:

```
Src IP Addr      Flows   Packets   Bytes
10.30.50.38          6      6000  312000
10.30.50.46          5      5000  260000
10.30.50.61          4      4000  208000
10.30.50.12          4      4000  208000
10.30.50.29          3      3000  156000
Summary: total flows: 87 from 41 source addresses
```

**Cara membaca hasil:** 87 record SYN-only tersebar rata di 41 sumber, masing-masing 1.000 paket dan 52.000 byte: satu paket SYN tersampel per record. Ini tanda tangan sampling, bukan scan: setiap koneksi normal punya satu SYN, dan sesekali SYN itulah yang terpilih. Di data tanpa sampling, flow SYN tanpa ACK dari satu sumber ke sangat banyak tujuan (atau port) dengan flow kecil adalah scan horizontal atau vertikal, sejajar Day 04. Di 1:1000, scan 2.000 probe satu paket dari satu laptop rata-rata hanya menghasilkan dua record seperti di atas dan tenggelam. Untuk scan, pakai firewall atau flow router data center 1:1 (Day 04 bagian 2.5).

**Arah dan exfiltration.** Bentuk dasar dari file lama, lalu sehari penuh `bdg-rtr01`:

```bash
nfdump -r flows.nfcapd 'src net 10.0.0.0/8 and not dst net 10.0.0.0/8' -s ip/bytes
nfdump -r /flow/bdg-rtr/2027/05/20/ -N -s ip/bytes -n 5 'src net 10.0.0.0/8 and not dst net 10.0.0.0/8'
```

| Bagian | Fungsi |
|---|---|
| `src net 10.0.0.0/8` | Sumber di jaringan internal PT JAB [S7] |
| `not dst net 10.0.0.0/8` | Tujuan di luar jaringan internal: arah keluar |
| `-s ip/bytes` | Urut byte; karena filter hanya memuat record keluar, byte yang dihitung adalah byte keluar |

Keluaran ilustrasi:

```
IP Addr            Flows    Packets        Bytes
10.30.50.46           95    1918000   2779104000
203.0.113.178         10    1896000   2745408000
10.30.50.38           88    305000     363400000
198.51.100.20         81    301000     361000000
10.30.50.61           58     83000     118000000
```

**Cara membaca hasil:** dalam sehari, 2.779.104.000 byte keluar dari laptop Rizky, 2.745.408.000 di antaranya ke satu alamat (sekitar 98,8%). Byte keluar besar ke satu tujuan eksternal, apalagi tak biasa, adalah kandidat exfiltration (Day 12); flow menunjukkan volume dan arah tanpa isi. Baris `10.30.50.38` ke `198.51.100.20` adalah VPN SSL staf ke `jkt-vpn01` (bagian berikut). Perhatikan yang tidak ada: LAN kantor Bandung keluar lewat `jkt-proxy01`, jadi tujuannya `10.20.3.60` dan tersaring oleh `not dst net 10.0.0.0/8`. Exfiltration dari PC kantor Bandung tidak akan terlihat di query ini; ia muncul di egress Jakarta sebagai trafik proxy.

**Koneksi jangka panjang.** File lama menulis `nfdump -r flows.nfcapd -o long | sort -by-duration` dengan catatan "cek sintaks". Bentuk itu tidak benar: `sort` tidak punya opsi itu, dan nfdump sendiri punya opsi urut `-O` dengan kunci `duration` [S7]. Ada jebakan kedua yang lebih penting:

```bash
nfdump -r /flow/bdg-rtr/2027/05/20/ -N 'net 10.30.50.0/24 and duration > 1800000'
nfdump -r /flow/bdg-rtr/2027/05/20/ -N -b -O duration -n 10 'net 10.30.50.0/24'
```

| Bagian | Fungsi |
|---|---|
| `duration > 1800000` | Record berdurasi lebih dari 30 menit; satuan filter `duration` adalah milidetik [S7] |
| `-b` | Gabungkan record per koneksi dua arah dulu [S7] |
| `-O duration` | Urutkan keluaran menurut durasi [S7] |
| `-n 10` | Batasi sepuluh baris |

Perintah pertama mengembalikan nol record. Itu bukan berarti tidak ada koneksi panjang: active timeout 300 detik memotong setiap record menjadi paling lama 300 detik, dan filter diterapkan pada record sebelum agregasi. Perintah kedua menggabungkan dulu, baru mengurutkan. Arah urutan `-O` dan apakah ia diterapkan setelah agregasi `-b` perlu dicek di versi nfdump-mu; bila tidak, ekspor dengan `-o csv` lalu urutkan kolom durasinya.

Keluaran ilustrasi (dua baris teratas):

```
Date first seen          Duration Proto  Src IP Addr:Port       Dst IP Addr:Port     Flows
2027-05-20 08:31:02.118 25187.304 TCP    10.30.50.38:50833  <-> 198.51.100.20:443      161
2027-05-20 13:05:12.871  2845.646 TCP    10.30.50.46:51544  <-> 203.0.113.178:443       20
```

**Cara membaca hasil:** sekitar tujuh jam dari `10.30.50.38` ke `198.51.100.20`, alamat `jkt-vpn01`: VPN SSL staf yang bekerja dari Wi-Fi dinas, layanan sah berdurasi lama. Jumlah record 161, bukan 168 (25.200 dibagi 300 per arah, dua arah): pada beberapa jendela lima menit tidak ada paket yang tersampel sehingga tidak ada record, dan agregasi menjembatani celah itu. Upload Rizky berada di urutan kedua. Flow berdurasi sangat lama ke satu tujuan bisa C2 persisten atau tunnel; bandingkan dengan layanan sah berdurasi lama (streaming, VPN) lewat tujuan, port, dan pemilik alamat, bukan lewat durasi saja.

**Kapan gagal (keempatnya):** sampling menghapus pola kecil (scan, beacon); exporter tidak ada di jalur (LAN kantor Bandung ke proxy Jakarta, atau trafik yang diblok firewall sebelum router); `-s ip` dijumlahkan sebagai total; atau koneksi panjang yang diam lebih dari idle timeout dipecah menjadi beberapa koneksi dengan port sumber yang sama.

### 2.5 `SOC-2027-0647`: top talker di flow router data center

Sebelum angka Bandung masuk laporan, Dimas meminta cara mencocokkan flow dengan Zeek diuji pada kasus Jakarta yang terlihat di kedua sumber (pertanyaan 5). Alarm top talker NOC Jumat pagi menunjuk `10.10.60.103` (`JKT-WS-2048`, pengguna `ayu.lestari`, tim pemasaran kreatif) dengan sekitar 3 GB ke `jkt-proxy01`.

**Tujuan:** memastikan siapa top talker ke proxy pagi itu dan mengambil angka koneksinya dari router data center, yang mengekspor tanpa sampling.

**Sintaks:**

```bash
nfdump -r /flow/dc-rtr/2027/05/21/ -N -s srcip/bytes -n 3 \
  'dst ip 10.20.3.60 and dst port 3128 and first seen >= 2027-05-21T06:00:00 and last seen <= 2027-05-21T08:30:00'
nfdump -r /flow/dc-rtr/2027/05/21/ -N -b \
  'ip 10.10.60.103 and ip 10.20.3.60 and port 3128 and first seen >= 2027-05-21T07:00:00 and last seen <= 2027-05-21T07:35:00'
```

| Bagian | Fungsi |
|---|---|
| `/flow/dc-rtr/` | Router data center, sampling 1:1, melihat workstation ke proxy |
| `dst ip 10.20.3.60 and dst port 3128` | Hanya arah workstation ke proxy eksplisit |
| `-s srcip/bytes -n 3` | Tiga sumber dengan byte terbanyak [S7] |
| `-b` dengan `ip ... and ip ... and port 3128` | Semua koneksi pasangan itu, digabung dua arah [S7] |

Keluaran ilustrasi, perintah pertama:

```
Src IP Addr        Flows    Packets        Bytes
10.10.60.103          47    2091240   3129018460
10.10.60.104         212     241090    214553120
10.10.60.107         156     112380     96204880
```

Keluaran ilustrasi, perintah kedua (kolom diringkas, label arah ditambahkan):

```
Date first seen          Duration Proto  Src IP Addr:Port        Dst IP Addr:Port   Pkt ws    Byte ws     Pkt proxy Byte proxy Flows
2027-05-21 07:01:58.430     4.112 TCP    10.10.60.103:52617 <-> 10.20.3.60:3128       14       4180          12      9925     2
2027-05-21 07:02:15.108  1794.987 TCP    10.10.60.103:52619 <-> 10.20.3.60:3128  2080501 3120740804     1040262  54100940    12
2027-05-21 07:33:40.006     0.381 TCP    10.10.60.103:52688 <-> 10.20.3.60:3128       11       2210           9      6050     2
```

**Cara membaca hasil:** satu koneksi membawa hampir semua volume: 3.120.740.804 byte level IP dalam 1.794,987 detik, dipecah menjadi 12 record (enam per arah: lima record 300 detik dan satu record sisanya). Karena router data center tidak di-sampling, angka paket dan byte ini adalah hitungan, bukan perkiraan, dan `first seen` adalah paket SYN yang sebenarnya.

**Konteks dari log proxy.** Flow tidak tahu tujuan akhir di balik proxy. Query `index=proxy src=10.10.60.103 method=CONNECT earliest="05/21/2027:07:00:00" latest="05/21/2027:07:35:00"` memberi keluaran ilustrasi:

```
2027-05-21T07:02:15+07:00 jkt-proxy01 user=ayu.lestari src=10.10.60.103 method=CONNECT host=files.backup-resmi.example:443 category=Online-Storage-Sanctioned tls=spliced status=200
```

Ayu dan tim IT mengonfirmasi bahwa setiap Jumat pukul 07:00 arsip desain kampanye mingguan diunggah ke layanan penyimpanan resmi perusahaan. `SOC-2027-0647` ditutup sebagai jinak terkonfirmasi, dan alarm NOC diberi catatan jadwal, bukan dimatikan, karena upload besar ke tujuan lain di jam yang sama tetap harus menyala.

**Kapan gagal:** workstation mengunggah langsung tanpa proxy (aturan seperti `NOC-VENDOR-DIRECT` di Day 02), sehingga tujuan akhirnya ada di flow edge yang di-sampling; atau proxy memakai port lain untuk sebagian klien sehingga filter `dst port 3128` melewatkannya.

### 2.6 `conn.log` sebagai flow

Koneksi yang sama juga lewat SPAN core switch data center, sehingga `jkt-zeek01` mencatatnya. Bila tidak ada NetFlow, `conn.log` memberi data setara dari sensor; di PT JAB keduanya ada, dan bagian ini mengambil sisi Zeek-nya.

**Bentuk dasar (log TSV, misalnya hasil Zeek offline di lab):**

```bash
zeek-cut id.orig_h id.resp_h id.resp_p proto orig_bytes resp_bytes duration conn_state < conn.log
```

`zeek-cut` memilih kolom dari log TSV Zeek. `conn.log` pada dasarnya flow yang diperkaya (Day 08); analisisnya sama: top talker dari byte, scan dari `conn_state`, volume per arah dari `orig_bytes` dan `resp_bytes` [S3]. `orig_bytes` besar berarti arah keluar dari originator besar.

**Bentuk PT JAB (log JSON di Splunk):**

```
index=zeek sourcetype=bro:conn:json id.orig_h=10.10.60.103 id.resp_h=10.20.3.60 id.resp_p=3128
    earliest="05/21/2027:07:00:00" latest="05/21/2027:07:35:00"
| table _time uid id.orig_p duration orig_pkts orig_bytes orig_ip_bytes missed_bytes
        resp_pkts resp_bytes resp_ip_bytes conn_state history community_id
```

| Bagian | Fungsi |
|---|---|
| `sourcetype=bro:conn:json` | Sourcetype `conn.log` dari TA for Zeek (Day 08) |
| `id.orig_h ... id.resp_p=3128` | Pasangan dan port yang sama dengan query flow |
| `earliest/latest` | Ditafsirkan dalam zona waktu pengguna Splunk (WIB), walaupun `ts` mentah dalam UTC |
| `orig_ip_bytes`, `resp_ip_bytes` | Byte level IP dari header total length: pembanding yang setara dengan byte flow [S17] |
| `orig_bytes`, `missed_bytes` | Byte payload dari sequence number, dan byte yang hilang di celah konten [S17] |
| `community_id` | Hash 5-tuple yang sama di Zeek dan Suricata; nfdump tidak menghitungnya |

Keluaran ilustrasi (satu baris yang relevan, dipecah supaya terbaca):

```
_time          2027-05-21 07:02:15.111      (ts mentah 2027-05-21T00:02:15.111Z)
uid            CbV3kR8sQm2wT6yZd
id.orig_p      52619
duration       1794.902
orig_pkts      2080485      orig_bytes 3012554752   orig_ip_bytes 3120716804   missed_bytes 23168
resp_pkts      1040262      resp_bytes 7316         resp_ip_bytes 54100940
conn_state     SF           history ShADadGGFf
```

**Cara membaca hasil:** satu baris untuk seluruh koneksi, tanpa pemecahan timeout dan tanpa sampling. `conn_state` SF berarti koneksi dibuka dan ditutup normal. `history` memuat `GG`: celah konten di arah originator terlihat minimal sepuluh kali (huruf `G` dicatat secara logaritmik, Day 08 bagian 1.4), cocok dengan `missed_bytes` 23.168, yaitu 16 segmen penuh 1.448 byte. `orig_bytes` tetap 3.012.554.752 karena diambil dari sequence number, termasuk byte yang tidak sempat terlihat.

**Variasi:** `| stats sum(orig_ip_bytes) AS out sum(resp_ip_bytes) AS in BY id.orig_h | sort - out` untuk top talker versi Zeek; `conn_state=S0` untuk koneksi tanpa balasan (bagian 2.3).

**Kapan gagal:** koneksi tidak lewat titik sensor (Bandung, atau antar host di switch akses yang sama); `orig_pkts` dan `orig_ip_bytes` kosong bila analyzer ukuran koneksi dimatikan [S17]; atau koneksi sangat panjang dengan jeda diam yang melebihi timeout inaktivitas Zeek, sehingga Zeek menulisnya sebagai lebih dari satu baris.

### 2.7 Mencocokkan flow dan `conn.log`, lalu memutuskan perlu pcap atau tidak

Sekarang dua sumber untuk koneksi yang sama dibandingkan dengan aturan di bagian 1.6. Tabel berikut adalah lembar kerja yang dikirim ke Dimas; baca kolom "Penjelasan" untuk tahu kenapa setiap selisih bukan tanda kesalahan.

| Besaran | Flow DC (`-b`) | Zeek `conn.log` | Selisih | Penjelasan |
|---|---|---|---|---|
| Mulai | 07:02:15.108 WIB | `ts` 00:02:15.111 UTC | 3 ms | Jam router dan jam sensor (keduanya NTP); zona tampilan berbeda |
| Durasi | 1.794,987 detik (12 record digabung) | 1.794,902 detik | 85 ms | `duration` Zeek tidak menghitung paket penutup tanpa payload baru [S17] |
| Paket workstation ke proxy | 2.080.501 | `orig_pkts` 2.080.485 | 16 | 16 paket tidak sampai ke Zeek (drop di SPAN) |
| Byte level IP, arah sama | 3.120.740.804 | `orig_ip_bytes` 3.120.716.804 | 24.000 | 16 paket kali 1.500 byte |
| Byte payload | tidak ada | `orig_bytes` 3.012.554.752 | 108.186.052 terhadap flow | Header IP dan TCP 52 byte kali 2.080.501 paket |
| Arah balik | 1.040.262 paket, 54.100.940 byte | 1.040.262, `resp_ip_bytes` 54.100.940 | 0 | Tidak ada loss di arah ini |
| Kunci | 5-tuple dan waktu | `uid` dan `community_id` | | nfdump tidak mengenal keduanya |

Kesimpulan untuk Dimas: angka cocok sampai tingkat paket setelah tiga hal diselaraskan, yaitu level byte (IP dengan IP), pemecahan record (gabungkan dulu), dan zona waktu. Selisih yang tersisa punya penjelasan yang bisa ditunjuk di field (`missed_bytes`, `history`). Bila flow dibandingkan dengan `orig_bytes`, selisihnya 3,6% dan terlihat seperti kesalahan, padahal itu hanya header. Hitungan header di sini memakai asumsi semua paket membawa 52 byte header; SYN membawa opsi tambahan, jadi di data nyata selisihnya tidak persis kelipatan 52.

**Dari flow ke pcap.** Bentuk umum dari file lama:

```
# setelah menemukan flow menarik, periksa isinya di pcap periode itu (bila tersedia)
# Wireshark: ip.addr == <src> and ip.addr == <dst> and tcp.port == <port>
```

Flow memberi 5-tuple dan waktu koneksi menarik; pcap (bila ada) memperlihatkan isinya. Untuk `SOC-2027-0647`, hop workstation ke proxy tidak ada di `jkt-pcap01` sama sekali, karena pcap fase ini hanya di egress. Hop proxy ke internet ada di ring buffer (masih di dalam jendela sekitar 72 jam), dan bisa diambil dari `jkt-nsm-ws01`:

```bash
tshark -r /mnt/pcap01/ring/egress-jkt_NNNNN_20270521000000.pcapng \
  -Y 'ip.src == 10.20.3.60 && tls.handshake.type == 1 && frame.time >= "2027-05-21T00:02:00Z" && frame.time < "2027-05-21T00:03:00Z"' \
  -T fields -e frame.time_utc -e tls.handshake.extensions_server_name
```

| Bagian | Fungsi |
|---|---|
| `egress-jkt_NNNNN_20270521000000.pcapng` | File ring yang dimulai 00:00:00 UTC (07:00 WIB); ganti `NNNNN` dengan nomor urut di direktori |
| `tls.handshake.type == 1` | ClientHello dari proxy |
| `frame.time >= "...Z"` | Batas waktu dengan zona eksplisit, sintaks dari Day 02 |
| `-e tls.handshake.extensions_server_name` | SNI yang dikirim proxy |

Keluaran ilustrasi: satu ClientHello pada 00:02:15.4 UTC dengan SNI `files.backup-resmi.example`. Pcap menambah SNI dan sertifikat, tetapi isinya TLS yang di-splice proxy, jadi tidak ada isi berkas. Untuk kasus ini flow, `conn.log`, dan log proxy sudah cukup; pcap dipakai bila pertanyaannya menyangkut isi atau bila flow dan log tidak sepakat. Bila pcap tidak tersedia, flow ditambah metadata TLS, DNS, dan Zeek tetap bisa menyimpulkan banyak.

**Kapan gagal:** jendela waktu ring buffer sudah lewat; sumber egress adalah NAT sehingga alamat proxy tidak terlihat (TAP PT JAB ada di sisi dalam firewall, jadi masalah ini tidak terjadi di sini); atau beberapa koneksi proxy ke tujuan yang sama terbuka di detik yang sama, sehingga harus dibedakan dengan ukuran dan durasi dari `conn.log` hop egress.

### 2.8 `ABU-2027-0512`: dari alamat CGNAT ke pelanggan

Pertanyaan keenam pindah ke sisi ISP. Tiket abuse ini milik NOC; SOC (kamu) membantu menyusun langkahnya, dan pencarian dijalankan oleh peran abuse desk NOC yang ditunjuk, karena kebijakan akses data NSM membatasi SOC pada prefiks korporat.

**Isi laporan (cuplikan yang dilampirkan pelapor):**

```
2027-05-20 15:02:11 UTC sshd[22841]: Failed password for invalid user admin from 198.51.100.210 port 41003 ssh2
2027-05-20 15:02:14 UTC sshd[22843]: Failed password for root from 198.51.100.210 port 41017 ssh2
...
2027-05-20 15:49:40 UTC sshd[31206]: Failed password for root from 198.51.100.210 port 41466 ssh2
Total: 1236 failed attempts against 203.0.113.179:22 between 15:02:11 and 15:49:40 UTC
```

**Langkah 1: nilai laporannya.** Tiga hal dicek sebelum mencari pelanggan. Alamat `198.51.100.210` memang milik pool `jkt-cgn01`. Laporan menyertakan port sumber dan waktu dengan zona UTC, persis informasi yang direkomendasikan RFC 6302 [S11]. Pelapor menulis dari `abuse@` domainnya sendiri, dan pola gagal login berulang dari port yang terus berganti masuk akal untuk SSH brute force (Day 04). Konversi waktu: 15:02:11 sampai 15:49:40 UTC sama dengan 22:02:11 sampai 22:49:40 WIB.

**Langkah 2: cari pemegang blok port di log CGN.**

**Asumsi data:** log port block allocation `jkt-cgn01` di `index=netops` dengan field `event` (`pba_alloc`, `pba_release`), `inside_ip`, `outside_ip`, `port_start`, `port_end`; jam perangkat sinkron NTP. Nama sourcetype dan field adalah konfigurasi PT JAB; cek di lingkunganmu.

```
index=netops host=jkt-cgn01 outside_ip=198.51.100.210
    earliest="05/20/2027:00:00:00" latest="05/21/2027:06:00:00"
| where port_start<=41003 AND port_end>=41466
| table _time event inside_ip outside_ip port_start port_end
| sort _time
```

| Bagian | Fungsi |
|---|---|
| `outside_ip=198.51.100.210` | Alamat publik yang dilaporkan |
| `earliest="05/20/2027:00:00:00"` | Jendela lebar: alokasi blok bisa terjadi jauh sebelum kejadian, dan event alokasi itulah yang dicari |
| `where port_start<=41003 AND port_end>=41466` | Blok yang memuat port terkecil dan terbesar di laporan |
| `sort _time` | Urutan alokasi dan pelepasan, supaya pemegang blok di setiap jam terbaca |

Keluaran ilustrasi (waktu WIB):

```
_time                event        inside_ip      outside_ip      port_start  port_end
2027-05-20 14:10:22  pba_alloc    100.64.12.9    198.51.100.210  40960       41471
2027-05-20 15:40:51  pba_release  100.64.12.9    198.51.100.210  40960       41471
2027-05-20 21:47:03  pba_alloc    100.64.37.118  198.51.100.210  40960       41471
2027-05-21 00:12:55  pba_release  100.64.37.118  198.51.100.210  40960       41471
```

**Cara membaca hasil:** blok 40960 sampai 41471 (512 port) dipegang dua pelanggan berbeda pada hari yang sama. Pada 22:02 sampai 22:49 WIB, pemegangnya `100.64.37.118` (dialokasikan 21:47:03, dilepas 00:12:55), dan semua port di laporan (41003 sampai 41466) ada di dalam blok itu. Jarak lebih dari 14 menit ke alokasi dan lebih dari 80 menit ke pelepasan membuat selisih jam kecil antara pelapor dan `jkt-cgn01` tidak mengubah jawaban; bila waktu kejadian dekat batas alokasi, tulis bahwa jawabannya tidak pasti.

Jebakan yang hampir terjadi malam itu: staf NOC jaga pertama kali mengetik 15:02 di time picker Splunk, yang ditafsirkan sebagai WIB, dan mendapat `100.64.12.9`. Pelanggan itu memegang blok yang sama pada 15:02 WIB dan tidak ada hubungannya dengan laporan. Satu kesalahan zona waktu menunjuk orang yang salah, dan bila itu terjadi pada permintaan aparat, akibatnya jauh lebih berat (bagian 1.8).

**Langkah 3: dari alamat dalam ke ID pelanggan.**

```
index=netops host=jkt-bng01 Framed_IP_Address=100.64.37.118
    earliest="05/19/2027:00:00:00" latest="05/21/2027:06:00:00"
| table _time Acct_Status_Type User_Name Acct_Session_Id Framed_IP_Address
```

`Acct-Status-Type`, `User-Name`, `Acct-Session-Id`, dan `Framed-IP-Address` adalah atribut RADIUS accounting; ejaan field di Splunk (garis bawah atau tanda hubung) bergantung pada parsing-mu. Keluaran ilustrasi: `Start` pada Rabu 2027-05-19 06:14:51 dengan `User_Name` `plg-0412987@bb.jab.example`, lalu `Interim-Update` berkala, tanpa `Stop` sampai Jumat pagi. Sesi itu mencakup jendela kejadian, jadi `100.64.37.118` pada 22:02 sampai 22:49 WIB adalah layanan `PLG-0412987`. Nama dan alamat pemegang kontrak dibuka di sistem pelanggan oleh abuse desk; SOC hanya menerima kesimpulan "pelanggan broadband, bukan aset PT JAB".

**Kapan gagal:** pelapor tidak menyertakan port sumber (jawabannya menjadi daftar semua pemegang blok di alamat itu, yang tidak boleh diserahkan begitu saja); pelapor menulis waktu lokal tanpa zona; log CGN untuk tanggal itu sudah terhapus retensi; atau pelanggan memakai IPv6 dan alamat publiknya bukan alamat CGNAT sama sekali.

### 2.9 Memverifikasi laporan dengan flow pelanggan secara proporsional

Abuse desk perlu satu konfirmasi dari sisi PT JAB sebelum menghubungi pelanggan: apakah trafik ke `203.0.113.179:22` dari blok port itu benar-benar ada di jaringan PT JAB. Bagian ini juga menjawab sisi lain pertanyaan keempat: pola brute force tetap terbaca di flow sampled, karena jumlah koneksinya besar.

**Tujuan:** memastikan trafik yang dilaporkan terlihat di flow edge, tanpa membuka tujuan lain pelanggan.

```bash
nfdump -r /flow/jkt-edge/2027/05/20/ -N -A srcip,dstip,dstport \
  'src ip 198.51.100.210 and src port > 40959 and src port < 41472 and dst ip 203.0.113.179 and dst port 22 and first seen >= 2027-05-20T21:50:00 and last seen <= 2027-05-20T23:00:00'
```

| Bagian | Fungsi |
|---|---|
| `/flow/jkt-edge/` | Router edge Jakarta, sesudah `jkt-cgn01`, jadi sumbernya alamat publik; sampling 1:1000 |
| `src port > 40959 and src port < 41472` | Hanya blok port pelanggan itu; perbandingan port memakai `port comp num` [S7] |
| `dst ip 203.0.113.179 and dst port 22` | Hanya tujuan yang dilaporkan; tujuan lain pelanggan tidak ikut terbuka |
| `-A srcip,dstip,dstport` | Satu baris ringkasan untuk pasangan itu [S7] |

Keluaran ilustrasi:

```
Date first seen          Duration Proto  Src IP Addr       Dst IP Addr:Port     Packets   Bytes  Flows
2027-05-20 22:02:40.517  2792.233 TCP    198.51.100.210  ->  203.0.113.179:22     24000  2784000     24
```

**Cara membaca hasil:** 24 paket tersampel dalam 22:02:40 sampai 22:49:12, masing-masing di record berbeda. Tanpa `-A`, ke-24 record itu punya 24 port sumber berbeda: minimal 24 koneksi terpisah, bentuk banyak koneksi pendek, bukan satu sesi interaktif panjang. Angka ini cocok kasar dengan laporan: 1.236 koneksi dengan sekitar 20 paket per koneksi ke arah server menghasilkan sekitar 24.700 paket, dan pada 1:1000 rata-rata sekitar 25 paket tersampel. Asumsi 20 paket per koneksi adalah perkiraan; jumlah nyata bergantung klien SSH dan berapa password dicoba per koneksi. Flow tidak bisa menghitung 1.236 koneksi itu; yang dihitung adalah log pelapor, dan flow hanya menegaskan bahwa trafiknya nyata dan berasal dari blok yang sama.

Batas proporsionalitas yang dipegang abuse desk: query ini tidak diulang dengan `-s dstip` untuk melihat ke mana lagi pelanggan itu terhubung, dan hasilnya tidak dikirim ke SOC kecuali ringkasan satu kalimat. Tujuan lain pelanggan bukan bagian dari laporan (bagian 1.7).

**Tindak lanjut abuse desk.** Pelanggan `PLG-0412987` diberi tahu lewat email dan SMS bahwa perangkat di jaringannya terlihat melakukan percobaan login SSH massal, dengan saran memeriksa perangkat dan CPE; bila berulang, layanan dibatasi sesuai ketentuan layanan. Log CGN dan RADIUS untuk jendela itu ditandai preservation, karena laporan semacam ini kadang berlanjut menjadi permintaan resmi. Balasan ke pelapor (keluaran ilustrasi):

```
Subject: Re: [ABU-2027-0512] SSH brute force from 198.51.100.210

Thank you for your report. 198.51.100.210 is a shared (CGNAT) address. Using the source
ports and UTC timestamps you provided, we identified the subscriber service involved and
have taken action under our terms of service. For privacy reasons we cannot share
subscriber details. Please include source port and UTC time in any future reports.
```

**Kapan gagal:** sampling dan volume kecil (misalnya lima percobaan login) membuat flow kosong, dan "tidak terlihat di flow" lalu ditulis sebagai "laporan palsu"; atau trafik pelanggan keluar lewat POP lain yang tidak mengekspor flow ke `jkt-flow01`.

### 2.10 Satu halaman jawaban untuk Bambang, Dimas, dan Ratna

Jawaban dikirim Jumat pukul 14:00 di kanal SOC-NOC. Tabel berikut adalah ringkasannya; kolom terakhir menunjuk bagian yang berisi buktinya.

| Pertanyaan | Jawaban singkat | Bagian |
|---|---|---|
| 1. Isi record flow | Kunci 5-tuple, waktu paket pertama dan terakhir, paket, byte, gabungan flag, interface, AS; tanpa isi. Field yang tidak ada di template tidak pernah ada di kolektor | 1.1, 1.2 |
| 2. Seberapa bisa dipercaya flow 1:1000 | Volume besar: baik (upload Rizky sekitar 2,75 GB, rentang 95% sekitar 2,62 sampai 2,87 GB; selisih 0,24% dari log `bdg-fw01`). Jumlah koneksi kecil: tidak bisa; 95 beacon hanya terlihat 2 | 1.3, 2.2, 2.3 |
| 3. Satu koneksi banyak record | Active timeout 300 detik; gabungkan dengan `-b` atau `-a`; `Flows` berarti record | 1.4, 2.1 |
| 4. Pola yang terbaca | Top talker, arah, koneksi panjang (setelah digabung), brute force bervolume: ya. Scan kecil dan beacon di 1:1000: tidak | 1.5, 2.4, 2.9 |
| 5. Mencocokkan dengan Zeek | Bandingkan IP dengan IP, gabungkan record, samakan zona waktu; `SOC-2027-0647` cocok sampai 16 paket yang dijelaskan `missed_bytes`. `SOC-2027-0647` jinak (backup terjadwal) | 1.6, 2.5, 2.6, 2.7 |
| 6. Pelanggan di balik `198.51.100.210` | Blok port 40960 sampai 41471 dipegang `100.64.37.118` (layanan `PLG-0412987`) pada 22:02 sampai 22:49 WIB; bukan pemegang blok 15:02 WIB | 1.7, 2.8, 2.9 |
| 7. Permintaan aparat | Lewat Legal; butuh alamat, port sumber, waktu dengan zona; yang bisa diberikan pemegang kontrak layanan, bukan isi; preservation segera | 1.8 |

Untuk `INC-2027-069`, ringkasan jaringan yang masuk laporan: dua laptop (`JKT-WS-2046`, `JKT-WS-2047`); jejak paling awal Senin 2027-05-17 10:12:40 WIB (diblokir di Jakarta); koneksi keluar berhasil hanya dari Wi-Fi dinas Bandung, 96 sesi dari `JKT-WS-2046` dan 41 dari `JKT-WS-2047`; satu upload sekitar 2,74 GB dari `JKT-WS-2046` Kamis 13:05:11 sampai 13:52:39 WIB (angka firewall, dikonfirmasi flow); tidak ada upload besar dari `JKT-WS-2047` (maksimal `bytes_out` per sesi sama dengan ukuran beacon). Isi upload dan cara infeksi diserahkan ke analisis host oleh IR. Rekomendasi jaringan: Wi-Fi dinas cabang ikut aturan egress proxy seperti Jakarta, dan log `bdg-fw01` dijadikan sumber wajib di playbook untuk kantor tanpa sensor.

## 3. Lab praktik (di VM lab terisolasi)

Lab ini memakai jaringan host-only lab (`192.168.56.0/24`) dan pcap publik atau pcap buatan sendiri, bukan data PT JAB. Tujuannya mengulang semua pertanyaan bagian 2 di data yang kamu kendalikan, termasuk efek sampling yang biasanya hanya kamu lihat di router produksi.

**Prasyarat:** VM Linux dengan nfdump (`nfcapd`, `nfdump`, `nfpcapd`), Zeek, dan Wireshark/tshark; satu atau dua pcap lab (trafik web biasa, satu upload besar buatan sendiri, satu scan Nmap ke VM target di host-only); tidak ada data kerja. `nfpcapd` membaca pcap dan menulis file dengan format yang sama dengan `nfcapd`; ia hanya membaca pcap klasik dengan timestamp mikrodetik, bukan pcapng, dan opsi `-e active,inactive` mengatur timeout (default 300,60) [S8].

1. **Siapkan data flow.** Konversi pcapng ke pcap klasik bila perlu (`editcap -F pcap in.pcapng in.pcap`), lalu buat flow: `nfpcapd -r in.pcap -w /lab/flow -e 300,15`. Jalankan juga `zeek -C -r in.pcap` di direktori terpisah untuk `conn.log` dari pcap yang sama.
2. **Orientasi.** Baca flow dan pahami field (5-tuple, byte, durasi, flag) dengan `nfdump -r /lab/flow -o extended` dan `-I` (bagian 2.1).
3. **Top talker.** `-s ip/bytes -n 10` lalu `-s srcip/bytes`; tandai mana operasional dan mana anomali, dan buktikan sendiri bahwa kolom `-s ip` tidak boleh dijumlahkan (bagian 2.4).
4. **Pemecahan record.** Ulang langkah 1 dengan `-e 60,15`, lalu hitung berapa record yang dihasilkan upload besar-mu dan gabungkan dengan `-b` (bagian 1.4 dan 2.1).
5. **Scan.** Kenali scan dari pola SYN ke banyak tujuan (`flags S and not flags A`, bagian 2.4); bandingkan dengan Day 04.
6. **Exfiltration.** Cari byte keluar besar ke luar subnet lab (`src net 192.168.56.0/24 and not dst net 192.168.56.0/24`); tandai kandidat dan hitung rasio byte keluar banding masuk.
7. **Jangka panjang.** Buktikan bahwa `duration > 1800000` pada record mentah kosong bila active timeout 300 detik, lalu temukan koneksi panjang setelah `-b` (bagian 2.4); bedakan C2 dari layanan sah.
8. **Simulasi sampling.** Ambil satu dari setiap 100 paket dengan `tshark -r in.pcap -Y "frame.number % 100 == 0" -w sampled.pcap -F pcap`, buat flow dari `sampled.pcap`, kalikan counter dengan 100 secara manual, lalu bandingkan dengan angka tanpa sampling. Catat galat untuk upload besar dan untuk koneksi kecil. Ini sampling sistematis (setiap paket ke-100), bukan acak; tulis perbedaannya di catatan.
9. **`conn.log` setara flow.** Ulang analisis dengan `zeek-cut` (bagian 2.6) dan cocokkan satu koneksi dengan tabel bagian 2.7: IP dengan IP, gabungkan record, samakan zona waktu.
10. **Pivot.** Pilih satu flow menarik; tulis filter Wireshark untuk memeriksanya di pcap (bagian 2.7), dan nyatakan apa yang tidak bisa dijawab flow saja.

**Hasil yang sebaiknya tersimpan:**

- Field flow inti dibaca dan dipahami maknanya, termasuk arti `Flows` setelah agregasi.
- Top talker dibedakan antara operasional dan anomali.
- Scan dikenali dari pola flow (sejajar Day 04), dan tanda tangan sampling dibedakan dari scan.
- Kandidat exfiltration dikenali dari arah dan volume byte.
- Koneksi jangka panjang dibedakan C2 vs layanan sah, setelah record digabung.
- Tabel galat sampling dari langkah 8: volume besar vs koneksi kecil.
- Satu lembar pencocokan flow dengan `conn.log` dengan penjelasan setiap selisih.
- Batas flow (tanpa isi) dinyatakan; pivot ke pcap direncanakan.

**Variasi tantangan:** dari satu dataset flow, bangun profil satu host internal selama periode: tujuan tersering, volume per arah, port/layanan, dan anomali (scan keluar, volume keluar besar, koneksi panjang). Tulis ringkasan "apa yang bisa disimpulkan dari flow saja" dan "apa yang butuh pcap/log host", untuk melatih memilih sumber data yang tepat. Ini menyiapkan Day 11-12 (beaconing/exfiltration) dan Day 13. Variasi kedua: buat log CGN tiruan sederhana (CSV berisi alokasi blok port dengan waktu UTC) dan latih menjawab "siapa pemegang port 41003 pada 15:02 UTC" sekali dengan waktu yang benar dan sekali dengan waktu yang salah zona, supaya jebakan bagian 2.8 terasa.

## 4. Troubleshooting

Tabel ini memuat gejala yang paling sering muncul saat membaca flow; kolom kanan adalah langkah pertama yang dicek.

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Volume tampak kecil | Sampling aktif dan counter belum dikoreksi | Cek rasio sampling di exporter dan opsi `-s` `nfcapd`; counter yang dikoreksi selalu kelipatan N |
| Volume tampak sangat besar untuk koneksi kecil | Satu paket tersampel dikalikan N | Record berdurasi nol dengan tepat N paket adalah satu paket tersampel |
| Trafik hilang | Tak lewat exporter, atau diblok firewall sebelum router | Visibilitas tergantung lokasi exporter; cek log firewall untuk yang diblok |
| Tak ada isi/URL | Flow = metadata saja | Naik ke pcap, log proxy, atau `http.log`/`ssl.log` untuk isi |
| Durasi terpotong | Flow active timeout | Flow panjang terpecah; gabungkan dengan `-b` atau `-a` sebelum memfilter durasi |
| Filter `duration` tidak mengembalikan apa pun | Filter diterapkan pada record yang dibatasi active timeout | Agregasi dulu, lalu urutkan (bagian 2.4) |
| Scan tak jelas | Flow teragregasi atau di-sampling | Lihat jumlah dst/port unik per src; di data sampled, pakai firewall atau router 1:1 |
| Byte arah membingungkan | Flow searah vs dua arah | Pastikan per-arah; jumlahkan benar; `-b` untuk dua arah |
| Angka flow dan Zeek berbeda sekitar 3 sampai 4% | Membandingkan byte IP flow dengan `orig_bytes` payload | Bandingkan dengan `orig_ip_bytes` |
| Waktu flow dan Zeek berselisih tepat 7 jam | `jkt-flow01` WIB, Zeek UTC | Tulis zona di setiap angka waktu; konversi sebelum mencocokkan |
| Hasil `-r` direktori sangat lambat | Membaca 13 bulan file sekaligus | Persempit direktori per bulan atau hari, lalu tambah filter waktu |
| Field AS atau `flowEndReason` kosong | Tidak ada di template exporter | Cek template di kolektor atau `flow record` router; jangan menyimpulkan nilainya nol |
| Pemegang blok CGNAT tidak ditemukan | Jendela pencarian dimulai setelah alokasi blok | Perlebar jendela ke belakang; yang dicari adalah alokasi terakhir sebelum kejadian |

## 5. Kesalahan umum dan jebakan

- **Mengira flow punya isi.** Flow adalah metadata; untuk payload/URL/kredensial, naik ke pcap atau log aplikasi.
- **Mengabaikan sampling.** Volume dari flow sampled harus dikoreksi rasio; salah hitung bila lupa, dan rentang galatnya harus ditulis di laporan.
- **Menulis "tidak ada" dari flow sampled.** Yang benar "tidak terlihat". Dua laptop di bagian 2.3: satu terlihat lewat kebetulan dua record, satu tidak terlihat sama sekali.
- **Mengira exporter melihat semua.** Visibilitas tergantung lokasi; trafik yang tak lewat tak terekam, termasuk trafik yang diblok firewall sebelum router.
- **Menghitung `Flows` sebagai koneksi.** Setelah active timeout, satu koneksi bisa menjadi puluhan record.
- **Menjumlahkan kolom `-s ip`.** Setiap record dihitung untuk sumber dan tujuan.
- **Membandingkan byte di level berbeda.** Flow menghitung byte IP; `orig_bytes` Zeek adalah payload.
- **Menyamakan durasi lama = jahat.** Streaming/VPN juga lama; bedakan dengan tujuan dan pola.
- **Menyamakan alamat CGNAT dengan satu pelanggan.** Tanpa port sumber dan waktu dengan zona, jawaban yang jujur adalah "alamat dipakai bersama".
- **Salah zona waktu.** Satu jam, atau tujuh jam, menunjuk pelanggan lain (bagian 2.8).
- **Membuka lebih dari yang ditanya.** Abuse handling dan permintaan aparat dibatasi pada alamat, port, dan jendela waktu yang ditanyakan.
- **Mengabaikan privasi/legal.** Flow adalah metadata komunikasi; akses diatur hukum dan kebijakan (Day 01). Dibahas umum; regulasi lokal perlu dicek dengan Legal.
- `[komunitas, belum terkonfirmasi]` Analis dan tim NOC memakai flow untuk menemukan anomali makro (top talker, scan, volume keluar) lalu pivot ke pcap/log untuk bukti isi; pola ini umum di jaringan besar. Field dan opsi alat (nfdump) bisa berbeda antar versi/vendor, perlu dicek.

## 6. Catatan terkini

Bagian ini menampung status versi, standar, dan perubahan yang perlu diingat saat membaca dokumentasi flow per Oktober 2026.

- IPFIX (RFC 7011) adalah standar flow modern berbasis template; NetFlow v9 (RFC 3954) serupa, v5 masih ada di perangkat lama [S1][S2]. Biflow IPFIX didefinisikan di RFC 5103 dengan elemen "reverse" untuk arah balik [S9].
- Di registry IANA, `samplingInterval` (34) dan `samplingAlgorithm` (35) sudah deprecated, digantikan `samplingPacketInterval` (305) dan `selectorAlgorithm` (304). Dokumentasi dan kolektor lama masih memakai nama lama, jadi kenali keduanya [S6].
- nfdump 1.7.10 adalah rilis terbaru di halaman rilis per 2026-10-23; rilis ini memperbaiki masalah agregasi dua arah pada build tertentu di 1.7.9. Di man page, `-R` dan `-t` disebut legacy, dan jendela waktu disarankan lewat filter `first seen` dan `last seen` [S7].
- SiLK 3.24.2 dirilis 14 Mei 2026; dokumentasi `rwfilter` menyebut `--input-pipe` akan dihapus di SiLK 4.0 [S10].
- ElastiFlow kini dipasarkan sebagai kolektor terpadu untuk NetFlow, IPFIX, dan sFlow; repositori lama berbasis Logstash sudah tidak dikembangkan [S16].
- Enkripsi tidak mengurangi nilai flow sebanyak nilai pcap, karena flow memang metadata; ini membuat flow makin relevan saat isi makin tertutup.
- Banyak platform menggabungkan flow, Zeek, dan alert Suricata di SIEM (Day 13) untuk pandangan menyeluruh.
- Day 11 (beaconing) dan Day 12 (exfiltration) memakai flow dan metadata untuk pola yang isinya tak terbaca.
- Dokumen CGNAT yang dipakai di Day ini sudah lama tetapi masih menjadi rujukan: RFC 6302 (BCP 162, Juni 2011), RFC 6888 (BCP 127, April 2013), RFC 6598 (BCP 153, April 2012), dan RFC 7422 (Informational, Desember 2014) [S11][S12][S13][S14].

## 7. Cheat sheet

```
FLOW       ringkasan aliran per 5-tuple (src/dst IP, src/dst port, proto) + waktu + paket/byte + flags ; TANPA isi
PROTO      NetFlow v5 (lama) | v9 RFC3954 (template) | IPFIX RFC7011 (standar) | sFlow (sampling) | biflow RFC5103
ROLE       exporter (router/probe) -> collector (nfcapd) -> analisis (nfdump)
IE         1 octetDeltaCount (termasuk header IP) | 2 packets | 6 tcpControlBits (OR) | 152/153 start/end ms
           136 flowEndReason: 1 idle 2 active 3 end(FIN) 4 forced 5 resources | 305/304 sampling (34/35 deprecated)
           225/227 post-NAT src IP/port | 230 natEvent 16 PBA alloc, 17 PBA release
BISA       siapa->siapa, kapan, berapa lama, berapa byte, port/layanan, arah, pola
TAK BISA   payload, URL spesifik, kredensial, nama file -> naik ke pcap / log aplikasi
POLA       scan: 1 src -> banyak dst/port, flow kecil | DDoS: banyak src -> 1 dst | exfil: byte keluar >> masuk | beacon: periodik | C2: durasi lama
SAMPLING   1:N -> kalikan N ; galat ~ 1/sqrt(n tersampel), 95% ~ 1.96x ; P(koneksi k paket terlihat) = 1-(1-1/N)^k
           N=1000: k=12 -> 1,2% | k=15 -> 1,49% | probe 1 paket -> 0,1% ; "tidak terlihat" != "tidak ada"
TIMEOUT    active 300 s -> 1 koneksi = banyak record ; idle 15 s memecah sesi diam ; Flows = record, bukan koneksi
ISP/NOC    visibilitas (lokasi exporter) | sampling (koreksi rasio) | agregasi (detail hilang) | privasi/legal
ZEEK       conn.log = flow diperkaya (orig_bytes/resp_bytes/duration/conn_state) ; analisis setara
           cocokkan: octetDeltaCount ~ orig_ip_bytes (BUKAN orig_bytes) ; gabung record ; samakan zona waktu
ALUR       flow (temukan anomali skala besar) -> conn.log (tautkan log protokol) -> pcap (periksa isi koneksi terpilih)

nfdump -r DIR -N -o extended 'ip A and ip B and first seen >= YYYY-MM-DDThh:mm:ss and last seen <= ...'
nfdump -r DIR -N -b '...'                      gabung per koneksi dua arah (implies -a)
nfdump -r DIR -A srcip,dstip,dstport '...'     agregasi kunci sendiri
nfdump -r DIR -s ip/bytes -n 10                top talker (kolom tidak boleh dijumlah)
nfdump -r DIR -s srcip/flows 'ip X'            siapa saja yang bicara ke X
nfdump -r DIR 'proto tcp and flags S and not flags A' -s dstip       SYN-only (di data sampled = SYN tersampel)
nfdump -r DIR 'src net 10.0.0.0/8 and not dst net 10.0.0.0/8' -s ip/bytes    arah keluar
nfdump -r DIR -b -O duration -n 10             koneksi panjang (filter duration dalam ms, berlaku per record)
nfcapd -D -w DIR -S 1 -t 300 -p 9995 [-s N | -s -N]   kolektor; -s hanya bila exporter tidak umumkan, negatif = paksa
rwfilter --start-date=... --type=out --scidr=10.0.0.0/8 --dport=443 --pass=stdout | rwstats --fields=sip --values=bytes --count=10

CGNAT      100.64.0.0/10 (RFC 6598) ; butuh: alamat publik + port sumber + waktu (UTC, presisi detik, NTP) (RFC 6302)
           log CGN (blok port, alokasi/pelepasan) -> alamat dalam -> RADIUS -> ID pelanggan
           PBA = log per blok ; deterministic NAT = log konfigurasi algoritma (+ blok dinamis) (RFC 7422)
ABUSE      abuse@domain (RFC 2142) ; verifikasi, cari pemegang, tindak, balas tanpa identitas ; batasi pada pertanyaan
APARAT     lewat Legal ; verifikasi permintaan ; beri pemegang kontrak, bukan isi ; preservation ; zona waktu eksplisit
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** Pencarian 13 bulan di flow edge (sampling 1:1000) untuk sebuah alamat C2 tidak mengembalikan satu record pun dari Jakarta. Bolehkah laporan menulis "tidak ada host Jakarta yang berkomunikasi dengan alamat itu"?

<details><summary>Jawaban</summary>

Tidak. Flow sampled hanya bisa menyatakan "tidak terlihat". Beacon 15 paket punya peluang sekitar 1,49% untuk terwakili, dan 41 beacon sekalipun punya peluang sekitar 54% untuk tidak terlihat sama sekali. Selain itu, percobaan yang diblok `jkt-fw01` tidak pernah sampai ke router edge. Di kasus `INC-2027-069`, jejak Jakarta justru ada di log firewall (diblokir), bukan di flow. Sumber tanpa sampling (firewall, router data center 1:1, `conn.log`) harus dicek sebelum menulis ketiadaan.

Lihat bagian 1.3 dan 2.3.

</details>

**2. Skenario keputusan.** Record flow dari router edge 1:1000 menunjukkan satu baris berdurasi 0,000 detik dengan 1.000 paket dan 571.000 byte dari sebuah laptop ke alamat luar. Apa yang kamu tulis?

- A. Laptop mengirim 571 KB dalam satu burst ke alamat luar.
- B. Satu paket 571 byte dari laptop ke alamat itu tersampel; volume koneksi sebenarnya tidak diketahui dari record ini.
- C. Record rusak dan sebaiknya diabaikan.

<details><summary>Jawaban</summary>

B. Record berdurasi nol dengan tepat N paket adalah satu paket tersampel yang dikalikan rasio. A keliru karena membaca hasil perkalian sebagai pengukuran; beacon yang total keluarnya hanya sekitar 2,3 KB bisa tampil seperti itu. C keliru karena record itu tetap bukti bahwa ada komunikasi ke alamat tersebut pada waktu itu, dan bisa menjadi petunjuk pertama.

Lihat bagian 1.3 dan 2.1.

</details>

**3. Pertanyaan jebakan.** Untuk koneksi yang sama, flow router data center (1:1) mencatat 3.120.740.804 byte, sedangkan `orig_bytes` di `conn.log` 3.012.554.752. Apakah salah satunya rusak?

<details><summary>Jawaban</summary>

Tidak. Flow menghitung byte level IP termasuk header, sedangkan `orig_bytes` adalah byte payload yang diambil dari sequence number TCP. Selisih 108.186.052 byte adalah header 52 byte kali 2.080.501 paket. Pembanding yang setara adalah `orig_ip_bytes` (3.120.716.804), dan selisih 24.000 byte yang tersisa dijelaskan oleh 16 paket yang tidak sampai ke Zeek, terlihat di `missed_bytes` dan huruf `G` di `history`.

Lihat bagian 1.6 dan 2.7.

</details>

**4. Skenario keputusan.** Laporan abuse menyebut "serangan dari `198.51.100.210` pada 20 Mei pukul 15:02" tanpa port sumber dan tanpa zona waktu. Alamat itu adalah alamat pool CGNAT. Apa langkahmu?

- A. Cari pemegang blok port pada 15:02 WIB dan beri tahu pelanggan itu.
- B. Serahkan daftar semua pelanggan yang memakai alamat itu pada 20 Mei kepada pelapor.
- C. Balas bahwa alamat itu dipakai bersama, lalu minta port sumber dan waktu dengan zonanya sebelum mencari pelanggan.

<details><summary>Jawaban</summary>

C. Di belakang CGNAT, alamat publik saja tidak mengidentifikasi pelanggan; dibutuhkan port sumber dan waktu presisi dengan zona. A berisiko menunjuk pelanggan yang salah: di `ABU-2027-0512`, membaca 15:02 UTC sebagai WIB menunjuk `100.64.12.9`, bukan `100.64.37.118`. B membuka data banyak pelanggan yang tidak berhubungan dan tidak proporsional.

Lihat bagian 1.7, 1.8, dan 2.8.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Bambang, dalam tiga kalimat, kenapa angka volume upload laptop Rizky dari flow 1:1000 bisa dipakai di laporan, sedangkan jumlah beaconnya tidak.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh jawaban: "Upload itu menghasilkan sekitar 1.900 paket tersampel, jadi perkiraan volumenya punya galat sekitar 2,3% dan rentang 95% sekitar 2,62 sampai 2,87 GB, dan angka firewall `bdg-fw01` jatuh di dalam rentang itu. Beacon hanya sekitar 15 paket per koneksi, sehingga peluang satu beacon terwakili sekitar 1,5% dan dari 95 beacon hanya dua yang muncul. Jadi flow sampled bagus untuk volume besar, tetapi untuk menghitung koneksi kecil kita pakai log firewall yang mencatat setiap sesi."

Kesalahan yang sering muncul: menulis volume tanpa rentang galat; mengira counter belum dikalikan rasio; atau menyimpulkan beacon baru mulai Rabu karena record beacon pertama di flow muncul Rabu.

</details>

**6. Pertanyaan jebakan.** Filter `nfdump ... 'duration > 1800000'` pada data sehari mengembalikan nol record. Apakah berarti tidak ada koneksi lebih dari 30 menit?

<details><summary>Jawaban</summary>

Tidak. Active timeout 300 detik memotong setiap record menjadi paling lama 300 detik, dan filter diterapkan per record sebelum agregasi. Koneksi panjang harus digabung dulu (`-b` atau `-a`), lalu diurutkan dengan `-O duration`. Di contoh Bandung, VPN tujuh jam dan upload 47 menit baru terlihat setelah digabung.

Lihat bagian 1.4 dan 2.4.

</details>

**7. Interview question (English).** "Our ISP keeps NetFlow from every edge router for a year, sampled at 1 in 1000. A laptop at a branch office with no sensors triggered an EDR alert. How would you use the flow data, and what would you not claim from it?"

<details><summary>Sample answer</summary>

"First I'd confirm how the collector handles sampling, because the counters should already be multiplied by the announced rate; every value being a multiple of 1000 is a quick sign. I'd pull all records between the laptop and the suspect address, merge the records that the active timeout split, and report volume with an error range, which for a multi-gigabyte upload is a few percent. I'd use flow for direction, timing, and size, and I'd cross-check against an unsampled source such as the branch firewall's session logs. What I wouldn't claim is absence: a beacon of a dozen packets is visible only about one time in a hundred at 1:1000, so 'not seen in flow' is not 'didn't happen'. I also wouldn't claim anything about content; for that we need the endpoint data or packet capture."

What makes this answer strong: it starts by checking whether counters are corrected, separates what sampled flow does well (large volumes) from what it cannot do (small connections, absence, content), names an unsampled cross-check, and gives a concrete probability instead of a vague caveat.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | RFC 7011 (IPFIX protocol spec) | https://www.rfc-editor.org/rfc/rfc7011 | primer | diakses 2026-10-09 | Tinggi. Definisi flow/IPFIX, template |
| S2 | RFC 3954 (Cisco NetFlow v9) | https://www.rfc-editor.org/rfc/rfc3954 | primer | diakses 2026-10-09 | Tinggi. NetFlow v9 |
| S3 | Zeek docs: conn.log (flow diperkaya) | https://docs.zeek.org/en/current/logs/index.html | primer | diakses 2026-10-09 (Day 08) | Tinggi. Setara flow |
| S4 | Plixer: packet capture vs flow data | https://www.plixer.com/blog/packet-capture-vs-flow-data/ | sekunder (vendor) | 2026-10-07, dicek ulang 2026-10-23 (tanpa tanggal terbit) | Sedang. Perbandingan umum pcap dan flow: ruang sekitar seribu kali lebih kecil, retensi bulan sampai tahun, sampling menyembunyikan aktivitas kecil; vendor flow, jadi sudut pandangnya berpihak pada flow |
| S5 | Network-Forensics Day 01-09 (lokal) | (lokal) | rujukan internal | 2026-10-09 | Scan, protokol, Zeek, Suricata |
| S6 | IANA: IP Flow Information Export (IPFIX) Entities (Information Elements, flowEndReason, NAT Event Type) | https://www.iana.org/assignments/ipfix/ipfix.xhtml | primer | diakses 2026-10-22, dicek ulang 2026-10-23 | Tinggi. Nomor dan nama IE yang dipakai; `octetDeltaCount` termasuk header IP; 34 dan 35 deprecated (diganti 305 dan 304); nilai `flowEndReason` 1 sampai 5; `natEvent` 16 dan 17 untuk alokasi dan pelepasan blok port |
| S7 | nfdump(1) man page dan halaman rilis nfdump | https://github.com/phaag/nfdump/blob/master/man/nfdump.1 ; https://github.com/phaag/nfdump/releases | primer (dokumentasi proyek) | cabang master; diakses 2026-10-22 dan 2026-10-23 (rilis terbaru 1.7.10) | Tinggi. `-r` file atau direktori, `-R` dan `-t` legacy, `-a`, `-A`, `-b`, `-B`, `-s`, `-n`, `-o`, `-O`, `-N`, `-I`; filter `net`, `port comp`, `flags` (cocok bila salah satu flag ada), `duration` dalam milidetik, `first seen`/`last seen` ISO 8601 |
| S8 | nfcapd(1) dan nfpcapd(1) man page | https://github.com/phaag/nfdump/blob/master/man/nfcapd.1 ; https://github.com/phaag/nfdump/blob/master/man/nfpcapd.1 | primer (dokumentasi proyek) | cabang master; diakses 2026-10-22 dan 2026-10-23 | Tinggi. Port default 9995, rotasi 300 detik, nama `nfcapd.YYYYMMddhhmm`, `-S` level 0 sampai 8, `-s` (positif bila exporter tidak mengumumkan, negatif memaksa), counter dikalikan rasio sampling; `nfpcapd -r` hanya pcap klasik mikrodetik, `-e` default 300,60 |
| S9 | RFC 5103: Bidirectional Flow Export Using IPFIX | https://www.rfc-editor.org/rfc/rfc5103 | primer | Januari 2008; diakses 2026-10-23 | Tinggi. Definisi biflow, IE reverse (PEN 29305), penentuan arah initiator, perimeter, arbitrary |
| S10 | CERT NetSA SiLK: rwfilter, rwstats, halaman unduh | https://tools.netsa.cert.org/silk/rwfilter.html ; https://tools.netsa.cert.org/silk/rwstats.html ; https://tools.netsa.cert.org/silk/download.html | primer (dokumentasi proyek) | diakses 2026-10-23 (SiLK 3.24.2, 14 Mei 2026) | Tinggi. Syarat input dan output `rwfilter`, `--scidr`, `--dport`, `--flags-all=S/SA`; `rwstats --fields --values --count`, `distinct:FIELD` |
| S11 | RFC 6302 (BCP 162): Logging Recommendations for Internet-Facing Servers | https://www.rfc-editor.org/rfc/rfc6302 | primer | Juni 2011; diakses 2026-10-23 | Tinggi. Catat port sumber, waktu UTC presisi detik dari sumber waktu tepercaya, protokol dan port tujuan bila relevan; alasan berbagi alamat dan daur ulang port |
| S12 | RFC 6888 (BCP 127): Common Requirements for Carrier-Grade NATs | https://www.rfc-editor.org/rfc/rfc6888 | primer | April 2013; diakses 2026-10-23 | Tinggi. Informasi log per pemetaan (informatif, bukan wajib); REQ-12 tidak mencatat tujuan; REQ-13 sampai 15 alokasi port yang saling bersaing, REQ-14 minimalkan volume log |
| S13 | RFC 7422: Deterministic Address Mapping to Reduce Logging in Carrier-Grade NAT Deployments | https://www.rfc-editor.org/rfc/rfc7422 | primer (Informational, Independent Submission) | Desember 2014; diakses 2026-10-23 | Tinggi untuk mekanisme; angka volume log (150 byte per pesan, sekitar 33.000 koneksi per rumah per hari, sekitar 150 MB per pelanggan per bulan, sekitar 150 TB per bulan per satu juta pelanggan) berasal dari laporan operator AS saat itu |
| S14 | RFC 6598 (BCP 153): IANA-Reserved IPv4 Prefix for Shared Address Space | https://www.rfc-editor.org/rfc/rfc6598 | primer | April 2012; diakses 2026-10-23 | Tinggi. `100.64.0.0/10` untuk CGN ke CPE; tidak boleh melewati batas operator |
| S15 | RFC 2142: Mailbox Names for Common Services, Roles and Functions | https://www.rfc-editor.org/rfc/rfc2142 | primer | Mei 1997; diakses 2026-10-23 | Tinggi. Mailbox `ABUSE` untuk perilaku publik tidak pantas; wajib di domain utama walaupun keluhan menyangkut host subdomain |
| S16 | ElastiFlow documentation | https://docs.elastiflow.com/docs/ | sekunder (dokumentasi vendor) | diakses 2026-10-23 | Sedang. Kolektor flow yang menerima NetFlow, IPFIX, dan sFlow; halaman utama tidak membahas penanganan sampling |
| S17 | Zeek source: `scripts/base/protocols/conn/main.zeek` (dokumentasi field conn.log) | https://raw.githubusercontent.com/zeek/zeek/master/scripts/base/protocols/conn/main.zeek | primer (kode sumber proyek) | cabang master; diakses 2026-10-22, dicek ulang 2026-10-23 | Tinggi. `orig_bytes` dari sequence number, `orig_ip_bytes` dari header total length (butuh `use_conn_size_analyzer`), `missed_bytes`, `duration` tanpa paket penutup |

**Catatan sumber:** definisi flow dan record IPFIX/NetFlow v9 mengikuti RFC [S1][S2], nomor dan nilai elemen mengikuti registry IANA [S6]. Rumus galat sampling (1 dibagi akar jumlah paket tersampel) dan peluang koneksi kecil terwakili adalah aritmetika peluang dengan asumsi sampling acak per paket, bukan klaim dokumentasi; metode sampling router nyata (sistematis atau acak) perlu dicek di konfigurasi exporter. Opsi nfdump sudah dicek di man page cabang master [S7][S8], tetapi arah urutan `-O`, apakah `-O` berlaku setelah `-b`, dan nama kolom keluaran `-b` perlu dicek di versi yang terpasang. Rasio sampling, timeout router, desain titik ekspor, path kolektor, konfigurasi CGNAT (blok 512 port), dan nama field log CGN dan RADIUS adalah konfigurasi fiktif PT JAB; angka di contoh adalah ilustrasi. Pernyataan bahwa RFC 6888 menyebut daftar informasi log "bukan kewajiban" dan alasan REQ-12 berasal dari pembacaan bagian 4 RFC itu [S12]. Aspek privasi, abuse handling, dan permintaan aparat dibahas umum, bukan nasihat hukum; prosedur dan dasar hukum di Indonesia perlu dicek dengan Legal dan teks resmi. Seluruh isi PT JAB (alert `SOC-2027-0645` sampai `-0647`, `INC-2027-069`, tiket `ABU-2027-0512`, host, akun, pelanggan, dan keluaran perintah) adalah contoh fiktif, bukan hasil eksekusi nyata.
