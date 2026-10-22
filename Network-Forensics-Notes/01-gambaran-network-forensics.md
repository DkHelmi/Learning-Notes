---
day: 01
title: 'Gambaran network forensics: sumber bukti, NSM, posisi sensor, retensi, privasi dan legal'
researched_on: 2026-10-22
versions_checked: 'Wireshark 4.6.9 / 4.4.19 (23 Sep 2026), 5.0.0rc1 rilis pengembangan (21 Okt 2026); dumpcap man page 4.6.9; Zeek 9.0.0 LTS (14 Sep 2026; LTS sebelumnya 8.0.10, 19 Agu 2026); Suricata 8.0.7 (15 Sep 2026; cabang 7.x EOL, rilis terakhir 7.0.17); NIST SP 800-86 (Agu 2006); RFC 7011 IPFIX (Sep 2013); UU 11/2008 ITE sebagaimana diubah terakhir UU 1/2024; KUHP UU 1/2023 (berlaku 2 Jan 2026); UU 27/2022 PDP; PP 33/2026 (berlaku 16 Jan 2027)'
---

# Day 01: Gambaran network forensics (sumber bukti, NSM, posisi sensor, retensi, privasi dan legal)

Cakupan: peta sumber bukti jaringan (pcap, log transaksi, alert, flow, DNS, proxy, firewall), praktik network security monitoring, posisi sensor dan blind spot, retensi pcap dengan ring buffer, serta batas privasi dan hukum saat menangkap trafik di Indonesia.

## Ide inti

Bukti jaringan hanya ada bila ditangkap saat lewat. Endpoint menyimpan jejak di disk dan memori yang bisa diambil belakangan; paket yang tidak direkam oleh sensor sudah hilang begitu sampai di tujuan. Karena itu network forensics bergantung pada keputusan yang diambil jauh sebelum insiden: data apa yang dikumpulkan (isi paket, log transaksi, flow, alert), di titik mana sensor dipasang, berapa lama datanya disimpan, dan siapa yang boleh membukanya. Praktik mengambil keputusan itu secara sengaja, lalu memakai datanya untuk mendeteksi dan menginvestigasi, disebut network security monitoring (NSM). Analisis paket di Wireshark adalah ujung pekerjaannya; pangkalnya adalah peta sumber bukti yang jujur tentang apa yang tidak terlihat.

Pengalaman NOC-mu sudah memuat seluruh pola ini. Saat troubleshooting, kamu memasang `monitor session` SPAN ke laptop Wireshark: isinya lengkap, tetapi hanya untuk port dan rentang waktu yang kamu pilih. CDR di telco mencatat setiap percakapan (siapa, ke siapa, kapan, berapa lama) tanpa merekam suaranya, dan NetFlow yang dipakai untuk capacity planning lebih ringkas lagi. Network forensics memakai ketiga lapisan itu sekaligus. Batas analoginya: di NSM, capture berjalan terus dan disimpan, sehingga volumenya ratusan TB per bulan untuk satu link penuh; log transaksi Zeek mengurai isi protokol (nama domain, URL, sertifikat), bukan hanya siapa dan berapa lama; dan flow yang di-sampling bisa melewatkan koneksi kecil seperti beacon.

```
                         Internet (upstream AS64501, AS64502)
                                       |
                                [router edge] ----- IPFIX/NetFlow v9, sampling 1:1000 ----> jkt-flow01 10.20.70.14
                                       |                                                     (kolektor flow NOC)
                                  [jkt-fw01]  NAT kantor Jakarta 198.51.100.120
                                       |
                        TAP egress Jakarta (sisi dalam firewall) --------------+
                                       |                                        |
       [core switch DC] ------ SPAN (segmen server 10.20.0.0/16) ---------+     |
          |          |                                                    |     |
   server DC    jkt-proxy01, jkt-res01/02                                 v     v
          |                                                     jkt-npb01 10.20.70.10 (packet broker)
   kantor Jakarta 10.10.0.0/16                                     |            |            |
   (switch akses: trafik antar workstation                    jkt-ids01    jkt-zeek01    jkt-pcap01
    di switch yang sama tidak lewat sensor)                   Suricata     Zeek          ring buffer
                                                              .11          .12           .13 (egress saja)
                                                                 \           /
                                                         Splunk index suricata, zeek   <--- jkt-nsm-ws01 .20
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan sekitar 1.200 karyawan dan sekitar 400 ribu pelanggan broadband rumah, berkantor pusat dan ber-data center di Jakarta, dengan NOC 24/7 satu lantai dengan SOC. Bukti jaringan yang dimiliki SOC hari ini hanya log firewall `jkt-fw01`, log proxy `jkt-proxy01` (dekripsi TLS hanya untuk domain baru atau tidak terkategori), log resolver DNS `jkt-res01` dan `jkt-res02`, log VPN, dan flow milik NOC di `jkt-flow01`. Program hunt Februari sampai April 2027 sudah mencatat celah itu: tidak ada Zeek, tidak ada Suricata, tidak ada pcap. Kamis 2027-04-29, alert `SOC-2027-0600` menandai `JKT-WS-2001` (10.10.60.11) yang lewat proxy menghubungi `cdn-sync.example.net` setiap sekitar lima menit; domain itu terkategori "Content Delivery", jadi tidak didekripsi proxy, dan resolver mencatat dua alamat untuknya, `203.0.113.160` dan `203.0.113.161`. Scoping lewat log proxy menemukan pola yang sama di `JKT-WS-2003` (10.10.60.13, alert `SOC-2027-0601`). Kasus itu dibuka sebagai `INC-2027-060` dan ditutup Jumat 2027-04-30 dengan status inkonklusif: proxy hanya mencatat `CONNECT`, host tujuan, dan jumlah byte, sehingga tidak ada yang bisa menjawab apa yang sebenarnya dikirim. Senin 2027-05-03 pukul 09:00, Direktur Teknologi Hendra Wijaya menyetujui "Program NSM PT JAB" sebagai percobaan Mei sampai Juli 2027, dengan sponsor SOC lead Dimas Prasetyo dan pelaksana kamu (analyst L2), Bambang Hartono (Manajer NOC), dan Agung Prabowo (Lead Infrastruktur). Pukul 11:00, Dimas menulis kepadamu:

> "Program NSM resmi jalan, percobaan Mei sampai Juli. Pak Hendra minta jawaban tertulis sebelum rapat Jumat, jadi ini rangkuman pertanyaan dari rapat tadi. Pak Hendra tanya: bukti jaringan apa yang sebenarnya kita punya sekarang, dan kenapa INC-2027-060 berakhir inkonklusif padahal log-nya banyak? Lalu NSM itu apa, apakah cukup beli IDS? Pak Bambang tanya: NOC sudah punya flow dari semua router edge, kenapa masih perlu pcap yang mahal? Pak Agung tanya sensor dipasang di mana, dan bagian jaringan mana yang tetap tidak terlihat. Berapa lama pcap bisa disimpan dengan server yang ada? Pak Agus (DPO) dan Bu Ratna (Legal) minta kejelasan apakah merekam trafik karyawan tidak melanggar aturan penyadapan di UU ITE, dan apa kewajiban kita di UU PDP; Bu Ratna juga minta jaminan kita tidak menyentuh trafik pelanggan broadband. Terakhir, alat apa dan versi berapa, supaya Agung bisa siapkan server."

Pesan itu memuat tujuh pertanyaan:

1. Bukti jaringan apa yang dimiliki PT JAB sekarang, dan kenapa `INC-2027-060` tidak bisa dijawab?
2. Apa itu NSM, dan apakah membeli IDS sudah cukup?
3. Kalau flow NOC sudah ada, kenapa masih perlu pcap?
4. Di mana sensor dipasang, dan apa yang tetap tidak terlihat?
5. Berapa lama pcap bisa disimpan dengan server yang ada?
6. Apakah merekam trafik karyawan sah secara hukum, apa kewajiban PDP-nya, dan bagaimana menjamin trafik pelanggan tidak tersentuh?
7. Alat apa yang dipakai, dan versi berapa?

Pertanyaan 1 dijawab di bagian 1.1 dan 1.2, pertanyaan 2 di bagian 1.3, pertanyaan 3 di bagian 1.4, pertanyaan 4 di bagian 1.5, pertanyaan 5 di bagian 1.6, pertanyaan 6 di bagian 1.7, dan pertanyaan 7 di bagian 1.8. Bagian 2 berisi artefak yang kamu siapkan untuk rapat Jumat: inventaris sumber bukti, rancangan sensor, hitungan disk, perintah capture dan analisis pertama, draf kebijakan akses pcap, dan satu halaman jawaban untuk Dimas.

**Kapan relevan:** saat merancang atau menilai kemampuan investigasi jaringan sebuah organisasi; saat memilih sumber bukti untuk satu pertanyaan investigasi; saat insiden berakhir "inkonklusif" karena bukti jaringan tidak ada; dan saat menjelaskan ke manajemen, NOC, DPO, atau Legal kenapa capture perlu, berapa biayanya, dan apa batasnya.
**Kapan bukan jawaban:** saat buktinya ada di host (proses, file, registry) dan endpoint punya EDR yang lengkap; saat trafiknya terenkripsi end-to-end dan yang dibutuhkan adalah isi, bukan metadata; dan saat pertanyaannya tentang kejadian lampau yang tidak pernah lewat sensor, karena bukti jaringan tidak bisa diambil mundur.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Ini Day pertama topik ini, jadi semua istilah yang dipakai dimuat di sini. Kolom padanan memakai analogi NOC dan ISP yang dipakai di semua Day Network-Forensics.

| Istilah | Arti singkat | Padanan di NOC/ISP |
|---|---|---|
| Network forensics | Mengumpulkan, memeriksa, dan menganalisis data lalu lintas jaringan untuk menjawab pertanyaan investigasi | Troubleshooting gangguan dari data trafik, tetapi hasilnya harus bisa dipertanggungjawabkan sebagai bukti |
| Network security monitoring (NSM) | Pengumpulan, analisis, dan eskalasi indikasi dan peringatan untuk mendeteksi dan merespons intrusi | Program monitoring NOC yang permanen, bukan capture sesaat |
| Full packet capture (pcap) | Salinan utuh paket (header dan payload); Bejtlich menyebutnya full content data | `monitor session` SPAN ke laptop Wireshark, tetapi berjalan terus |
| Session data (flow) | Ringkasan satu percakapan: 5-tuple, waktu, byte, paket | NetFlow/IPFIX untuk capacity planning dan DDoS |
| Transaction data (log Zeek) | Satu baris per transaksi protokol (query DNS, request HTTP, handshake TLS) | CDR telco ditambah ringkasan isi percakapan |
| Alert data (alert Suricata) | Peristiwa yang cocok dengan signature atau aturan | Alarm threshold di NMS |
| Statistical data | Ringkasan statistik trafik atau file capture (jumlah paket, durasi, distribusi protokol) | Grafik MRTG dan counter interface |
| Fidelity | Seberapa banyak detail asli yang dipertahankan sebuah sumber | Resolusi data: counter 5 menit vs capture per paket |
| Sensor | Mesin yang menerima salinan trafik dan menjalankan Zeek, Suricata, atau capture | Probe atau analyzer yang dipasang di link |
| SPAN | Port mirror di switch yang menyalin trafik port atau VLAN lain | `monitor session` di switch |
| TAP | Perangkat pasif yang menyalin sinyal link fisik | Splitter optik pasif |
| Packet broker | Perangkat yang mengumpulkan beberapa SPAN/TAP lalu membagikannya ke beberapa sensor | Patch panel aktif sekaligus aggregation switch khusus monitoring |
| Ring buffer | Kumpulan file capture dengan jumlah tetap; file tertua ditimpa saat batas tercapai | `logging buffered` yang menimpa entri lama |
| Capture filter (BPF) | Filter yang memutuskan paket mana yang disimpan; yang dibuang tidak bisa dipulihkan | ACL pada `monitor session` |
| Display filter | Filter Wireshark yang memutuskan paket mana yang ditampilkan dari yang sudah tersimpan | `show ... \| include` atas output yang sudah ada |
| Snaplen | Batas byte per paket yang disimpan | Capture header saja untuk menghemat buffer |
| Blind spot | Bagian jaringan atau jenis trafik yang tidak terlihat oleh sensor | Link yang tidak di-export NetFlow |
| Sampling | Hanya satu dari N paket yang diperiksa untuk membentuk flow | `sampler` 1:1000 di router edge |
| `uid` | Pengenal unik Zeek untuk satu koneksi, dipakai untuk menghubungkan log yang berbeda | Nomor tiket yang dipakai di semua sistem NOC |
| Checksum offloading | NIC menghitung checksum, sehingga capture di host itu sendiri melihat checksum salah | Counter error palsu karena titik ukur di dalam perangkat |
| Penilaian dampak PDP (DPIA) | Penilaian risiko yang diwajibkan UU PDP untuk pemrosesan berisiko tinggi | Analisis dampak sebelum perubahan besar di jaringan produksi |
| Pejabat PDP (DPO) | Orang yang ditunjuk mengawasi kepatuhan pelindungan data pribadi | Pemilik proses kepatuhan, setara pemegang prosedur permintaan data pelanggan |

### 1.1 Sifat bukti jaringan: kenapa `INC-2027-060` tidak bisa dijawab

Pertanyaan pertama Hendra lahir dari rasa heran: log-nya banyak, kenapa jawabannya tetap "tidak tahu"? Jawabannya ada di sifat bukti jaringan itu sendiri.

Network forensics menjawab tiga jenis pertanyaan:

- Host mana berbicara dengan siapa, kapan, dan berapa banyak?
- Apa isi percakapannya, bila terlihat?
- Apakah polanya cocok dengan C2, exfiltration, atau scanning?

Dibanding forensik endpoint, bukti jaringan punya dua sifat khas:

1. Ia tidak bisa diambil mundur. Jika tidak ditangkap saat lewat, ia hilang. Itu inti NSM: kumpulkan sebelum insiden.
2. Ia sering terenkripsi. TLS membuat isi tidak terlihat, sehingga metadata (siapa, kapan, berapa, sertifikat, SNI) menjadi lebih penting (Day 06).

NIST SP 800-86, panduan integrasi teknik forensik ke incident response, menyebut hal yang sama dari sisi teknis: bila trafik terenkripsi sampai ke host internal, perangkat monitoring di jalurnya hanya melihat karakteristik paling dasar seperti alamat IP sumber dan tujuan, dan data yang tidak muat di storage bisa tertimpa dan hilang [S8]. Panduan itu membagi proses forensik menjadi empat fase, yaitu collection, examination, analysis, dan reporting [S8]; pada `INC-2027-060`, kegagalannya terjadi di fase pertama.

Di `INC-2027-060`, kedua sifat itu bertemu. Tidak ada capture yang berjalan saat `JKT-WS-2001` mengirim data, dan sesi ke `cdn-sync.example.net` terenkripsi tanpa didekripsi proxy. Yang tersisa hanya metadata kasar: host tujuan, waktu, dan jumlah byte.

Network forensics tetap unggul dalam tiga keadaan:

- Endpoint tidak punya agent atau EDR (IoT, OT, perangkat tamu).
- Skala besar: scoping cepat dari metadata ke ribuan host.
- Bukti independen dari host yang mungkin sudah dimanipulasi penyerang.

Ia lemah saat trafik terenkripsi end-to-end, saat trafik tidak lewat titik sensor (lateral di switch yang sama tanpa SPAN), atau saat retensi pcap terlalu pendek.

### 1.2 Spektrum sumber bukti dan prinsip piramida

Hendra juga bertanya bukti apa yang sebenarnya ada. Untuk menjawabnya, setiap sumber perlu dinilai dari tiga sisi: fidelity, biaya simpan, dan retensi. Tabel berikut membandingkan sumber yang umum; cari kolom "Pertanyaan yang dijawab", karena kolom itulah yang menentukan sumber mana dibuka lebih dulu.

| Sumber | Isi | Fidelity | Biaya simpan | Retensi tipikal | Pertanyaan yang dijawab |
|---|---|---|---|---|---|
| Full packet capture (pcap) | Seluruh paket (header dan payload) | Tertinggi | Sangat tinggi | Hari sampai minggu | Apa isi persisnya? File apa yang ditransfer? |
| Log transaksi (Zeek) | Satu baris per koneksi/transaksi per protokol: conn, dns, http, ssl, files, x509, smb, rdp, dll. [S1] | Tinggi (metadata kaya) | Sedang | Minggu sampai bulan | Siapa ke mana, protokol apa, berapa byte, sertifikat apa |
| Alert IDS (Suricata) | Peristiwa yang cocok dengan signature/aturan, plus metadata protokol di eve.json | Selektif | Rendah sampai sedang | Bulan | Apakah ada pola yang dikenal? |
| Flow (NetFlow/IPFIX) | Ringkasan 5-tuple, byte, paket, waktu | Rendah (tanpa payload) | Rendah | Bulan sampai tahun | Volume, pola komunikasi, beaconing kasar, DDoS |
| DNS log (resolver) | Query dan jawaban | Sedang | Rendah | Bulan | Domain apa yang dicari host? DGA, tunneling |
| Proxy / web gateway | URL, user, kategori, user-agent | Sedang (sering dengan TLS inspection) | Sedang | Bulan | Situs apa, oleh siapa |
| Firewall log | Allow/deny per koneksi | Rendah sampai sedang | Rendah | Bulan | Apakah koneksi diizinkan? |

Richard Bejtlich, yang merumuskan definisi NSM, membagi data NSM menjadi tujuh jenis: full content, extracted content (file atau objek yang diekstrak dari trafik), session data, transaction data, statistical data, metadata, dan alert data [S9]. Ia memakai analogi telepon: full content merekam setiap aspek panggilan, session data hanya memberi tahu siapa bicara dan berapa lama, sedangkan transaction data berada di tengah dan memberi inti percakapannya [S9]. Tabel di atas memetakan istilah itu ke alat: pcap adalah full content, flow adalah session data, log Zeek adalah transaction data, dan alert Suricata adalah alert data.

NIST SP 800-86 menilai nilai tiap sumber dengan cara yang sejalan [S8]:

- Data IDS sering menjadi titik awal, tetapi alert-nya harus divalidasi karena IDS menghasilkan false positive.
- Data firewall, router, proxy, dan remote access sendirian bernilai kecil karena mencatat sedikit informasi per event; nilai utamanya untuk korelasi. Translasi alamat (NAT) di perangkat itu penting karena satu alamat yang tampak bisa dipakai ratusan atau ribuan host.
- Packet sniffer mengumpulkan informasi paling banyak, tetapi juga data jinak dalam jumlah sangat besar tanpa petunjuk paket mana yang berbahaya, sehingga paling berguna untuk memperdalam event yang sudah ditandai sumber lain.
- Data flow membantu menjawab apakah sebuah pola komunikasi sudah terjadi di hari atau minggu sebelumnya.

**Prinsip piramida:** semakin ke bawah tabel, semakin murah dan lama disimpan, tetapi semakin sedikit detailnya. Strategi realistis:

- Flow dan log Zeek di seluruh titik penting, dengan retensi panjang.
- pcap di titik kritis, dengan retensi pendek.
- Simpan pcap yang terkait insiden lebih lama.

Pola ini juga yang disarankan materi vendor NSM [S5]. Untuk PT JAB, inventaris sumber yang ada sekarang dan blind spot-nya ditulis di bagian 2.1.

### 1.3 NSM: kumpulkan, deteksi, analisis, eskalasi

Pertanyaan kedua Hendra ("cukup beli IDS?") adalah salah paham yang paling umum tentang NSM.

Bejtlich mendefinisikan NSM sebagai pengumpulan, analisis, dan eskalasi indikasi dan peringatan untuk mendeteksi dan merespons intrusi [S9]. Definisi itu mengandung tiga kata kerja; IDS hanya mengisi sebagian kecil dari kata kerja pertama. Memasang IDS saja belum memenuhi definisi itu, karena NSM menuntut data yang disimpan dan analis yang memakainya. Komponennya:

- Sensor di titik observasi yang tepat: SPAN/TAP di egress, segmen server, atau antar zona.
- Koleksi beberapa jenis data: pcap, Zeek, Suricata, flow.
- Analisis oleh manusia yang memakai data itu untuk menjawab pertanyaan, lalu eskalasi ke pihak yang bertindak (IR, pemilik sistem).

NIST SP 800-86 menambahkan syarat di sisi manusia: alat yang ada punya kemampuan analisis terbatas dan hanya efektif di tangan analis terlatih yang paham prinsip jaringan, protokol umum, dan lingkungan organisasinya sendiri, termasuk arsitektur jaringan, alamat IP aset kritis, dan baseline normal [S8]. Pengalaman NOC-mu adalah separuh syarat itu.

Zeek dan Suricata adalah pasangan klasik:

- Zeek menghasilkan log transaksi yang kaya. Daftar log resminya mencakup conn, dns, http, ssl, x509, files, smb, rdp, quic, ldap, dll., serta weird/notice untuk anomali dan `capture_loss.log` untuk mengukur paket yang hilang di sensor [S1]. Field kunci `conn.log`: `uid`, `id.orig_h`, `id.resp_h`, `duration`, `orig_bytes`, `conn_state`, `history` [S1]. `uid` menghubungkan satu koneksi lintas log. Field `ts` berupa epoch, yang di dokumentasi Zeek dikonversi ke waktu UTC [S12]. Konsep ini dipakai lagi di Day 08 dan Day 11.
- Suricata fokus pada deteksi berbasis aturan dan juga mengeluarkan metadata protokol (Day 09).

Untuk Hendra, kalimatnya: IDS adalah alarm; NSM adalah alarm ditambah rekaman yang bisa diputar ulang dan orang yang tahu cara membacanya. `INC-2027-060` gagal bukan karena tidak ada alarm (alert `SOC-2027-0600` justru muncul), melainkan karena tidak ada rekaman.

### 1.4 Flow vs pcap: jawaban untuk Bambang

Pertanyaan Bambang masuk akal dari kursi NOC. `jkt-flow01` sudah menerima IPFIX dan NetFlow v9 dari router edge (sampling 1:1000) dan dari router data center (1:1, tanpa sampling), dan data itu sudah terbukti berguna untuk capacity planning dan DDoS.

IPFIX (RFC 7011) mendefinisikan flow sebagai kumpulan paket yang melewati satu titik observasi dalam selang waktu tertentu dan berbagi sifat yang sama, misalnya 5-tuple [S10]. Struktur record-nya ditentukan template, sehingga exporter bisa memilih field yang dikirim [S10]. Kolektor IPFIX secara default mendengarkan di port 4739 (SCTP, TCP, UDP) dan 4740 untuk versi TLS/DTLS; SCTP wajib diimplementasikan, sedangkan UDP dan TCP opsional [S10]. Yang tidak ada di definisi itu adalah payload: flow tidak pernah memuat isi percakapan.

Ada tiga alasan flow saja tidak cukup untuk PT JAB:

1. **Tanpa isi.** Flow menjawab "berapa byte ke `203.0.113.160`", tidak pernah "apa isinya". Itu persis pertanyaan yang gagal dijawab di `INC-2027-060`.
2. **Sampling menghilangkan koneksi kecil.** Dengan sampling 1:1000 per paket, satu koneksi beacon berisi sekitar 12 paket hanya punya peluang 1 - 0,999^12, sekitar 1,2%, untuk terwakili minimal satu paket. Beacon tiap lima menit menghasilkan 288 koneksi per hari, jadi rata-rata hanya sekitar 3,4 koneksi per hari yang muncul di flow edge, dan periodisitas lima menitnya tidak bisa direkonstruksi. Hitungan ini adalah aritmetika peluang dengan asumsi 12 paket per koneksi; jumlah paket nyata per koneksi perlu diukur di lab.
3. **Titik observasi setelah proxy dan NAT.** Trafik web workstation keluar lewat `jkt-proxy01`, sehingga flow di router edge melihat proxy atau alamat NAT `198.51.100.120` sebagai sumber, bukan `JKT-WS-2001`. NIST mengingatkan hal yang sama: alamat yang tampak di perangkat NAT bisa dipakai ratusan atau ribuan host [S8].

Sebaliknya, pcap juga tidak cukup sendirian. pcap tanpa flow berarti retensi pendek; flow tanpa pcap berarti tanpa isi. NIST mencatat bahwa data flow berguna untuk melihat apakah sebuah pola komunikasi sudah terjadi di hari atau minggu sebelumnya [S8], dan retensi flow memang jauh lebih panjang daripada pcap. Jawaban untuk Bambang: flow NOC tetap menjadi lapisan retensi panjang, Zeek mengisi lapisan tengah, dan pcap mengisi lapisan isi untuk jendela waktu pendek.

### 1.5 Posisi sensor dan blind spot

Pertanyaan Agung ("dipasang di mana") menentukan apa yang bisa dan tidak bisa dijawab selama tiga bulan percobaan.

Posisi sensor itu krusial. Sensor di egress melihat C2 dan exfiltration ke internet, tetapi tidak melihat lateral movement antar workstation di switch yang sama. Ini mirip dengan pertanyaan "di mana tap NetFlow dipasang" di ISP. Bejtlich mencatat hal serupa untuk wireless: NSM melihat trafik yang keluar dari segmen wireless ke segmen kabel, tetapi aktivitas antar node di segmen yang sama sebagian besar tidak teramati [S9]. NIST menyebut jalur masuk alternatif (koneksi yang tidak lewat gateway utama) dan kegagalan monitoring sebagai masalah teknis pengumpulan, dan menyarankan monitoring berlapis, misalnya firewall jaringan dan firewall host sama-sama mencatat koneksi [S8].

Untuk PT JAB, rancangan fase pertama memakai dua titik:

- **TAP egress Jakarta di sisi dalam `jkt-fw01`.** Di sisi dalam, alamat internal masih terlihat. TAP di sisi luar firewall hanya akan melihat `198.51.100.120` untuk seluruh kantor Jakarta, sehingga tidak bisa membedakan `JKT-WS-2001` dari `JKT-WS-2003`.
- **SPAN di core switch data center** untuk segmen server `10.20.0.0/16`, termasuk trafik workstation ke `jkt-proxy01` dan ke resolver. Titik ini penting untuk trafik yang lewat proxy: di egress, sesi web tampak berasal dari proxy; di core, sesi yang sama tampak dari workstation ke proxy.

Kedua sumber masuk ke packet broker `jkt-npb01`, yang membagikannya ke `jkt-ids01` (Suricata), `jkt-zeek01` (Zeek), dan `jkt-pcap01` (pcap, egress saja). Rancangan lengkapnya ada di bagian 2.2.

Blind spot yang tetap ada dan harus ditulis di setiap laporan:

- Trafik antar workstation di switch akses kantor Jakarta yang sama (lateral movement lewat SMB atau RDP antar workstation).
- Kantor Bandung dan Medan (`10.30.0.0/16`, `10.40.0.0/16`) dan POP lain di fase ini.
- Isi sesi TLS yang tidak didekripsi; yang terlihat hanya metadata.
- Pengguna VPN yang memakai split tunnel, dan workload di AWS dan Azure (index `aws` dan `azure` hanya memuat log cloud, bukan paket).

Satu kalimat yang perlu diingat semua orang di program ini: "tidak ada di pcap" tidak sama dengan "tidak terjadi".

### 1.6 Retensi, biaya simpan, dan ring buffer

Pertanyaan kelima ("berapa lama pcap bisa disimpan") dijawab dengan hitungan, bukan perkiraan.

**Hitungan kasar (dihitung sendiri, bukan dari sumber):** link 1 Gbps yang penuh setara 125 MB/detik, atau sekitar 10,8 TB per hari, atau sekitar 324 TB untuk 30 hari. Link jarang penuh terus-menerus, tetapi angka ini menjelaskan kenapa pcap penuh jarang disimpan lama. Ringkasan sumber vendor menyebut sekitar 316 TB untuk 1 Gbps selama 30 hari [S5]. Selisihnya bukan karena TB vs TiB (dalam TiB hasilnya sekitar 295 TiB), melainkan kemungkinan asumsi pembulatan atau overhead format file. Yang penting adalah orde besarnya: ratusan TB per bulan untuk satu link 1 Gbps yang penuh.

NIST SP 800-86 meminta organisasi memperkirakan pemakaian storage tipikal dan puncak, menentukan berapa jam atau hari data perlu disimpan, lalu memastikan storage-nya cukup; tanpa itu, data aktivitas terbaru bisa tertimpa dan hilang [S8]. Panduan yang sama menyarankan data terkait insiden disimpan jauh lebih lama daripada data lain [S8].

Ring buffer adalah cara menjaga disk tidak penuh: jumlah file tetap, file tertua ditimpa [S11]. Ada dua cara memutar file, dan pilihannya mengubah apa yang dijamin:

- **Berdasarkan waktu** (`-b duration:3600 -b files:24`): jendela waktu tetap sekitar 24 jam, tetapi ukuran disk yang dipakai ikut naik turun dengan trafik. Saat trafik melonjak, disk bisa penuh lebih dulu.
- **Berdasarkan ukuran** (`-b filesize:... -b files:N`): pemakaian disk tetap, tetapi jendela waktunya menyusut saat trafik naik.

Untuk sensor produksi, ring buffer berbasis ukuran lebih aman bagi server, dengan konsekuensi yang harus dipahami Hendra: target "72 jam" adalah target pada trafik rata-rata, bukan jaminan. Bagian 2.3 menghitung angka untuk `jkt-pcap01`, termasuk berapa jam yang tersisa saat link penuh.

Snaplen (`-s`) adalah tuas kedua. Default dumpcap 0, artinya paket disimpan sampai 262144 byte, praktis utuh [S11]. Menyimpan header saja menghemat disk dan sejalan dengan minimisasi data (bagian 1.7), tetapi isi yang tidak disimpan tidak bisa diperiksa belakangan.

### 1.7 Privasi dan legal (umum, bukan nasihat hukum)

Pertanyaan Agus dan Ratna adalah syarat sebelum satu paket pun direkam. Pcap berisi isi komunikasi dan sering data pribadi: email, kredensial plaintext, cookie, isi chat dari protokol tak terenkripsi. NIST SP 800-86 menyebut risiko yang sama: capture bisa memuat password atau isi email secara sengaja maupun tidak, sehingga terbuka bagi staf yang menganalisis atau mengelola sensor; penyimpanan jangka panjang isi seperti itu bisa melanggar kebijakan retensi organisasi [S8]. Bahkan flow pun tidak netral: RFC 7011 mencatat bahwa data flow bisa mengungkap aktivitas jaringan yang sensitif secara privasi, dan kolektor bertanggung jawab melindunginya, termasuk dengan enkripsi atau anonimisasi [S10].

**Larangan intersepsi: UU ITE Pasal 31 dan KUHP baru.**

- UU ITE Pasal 31 (UU 11/2008, sebagaimana telah diubah; perubahan kedua UU 1/2024) melarang intersepsi atau penyadapan tanpa hak atas informasi elektronik di sistem milik orang lain dan atas transmisi yang tidak bersifat publik. Pengecualiannya adalah aparat penegak hukum sesuai prosedur undang-undang [S6].
- Sejak KUHP baru (UU 1/2023) berlaku pada 2 Januari 2026 [S14], Pasal 622 ayat (1) huruf r KUHP mencabut Pasal 31 ayat (1) dan ayat (2) UU ITE [S15]. Larangan yang setara kini ada di KUHP Pasal 258: menyadap, merekam, membelokkan, mengubah, menghambat, atau mencatat transmisi informasi elektronik yang tidak bersifat publik secara melawan hukum, juga menyebarkan hasilnya; ayat (3) menyatakan larangan itu tidak berlaku bagi orang yang melaksanakan ketentuan undang-undang atau tugas jabatan [S16]. Ayat (3) dan (4) Pasal 31 UU ITE, tentang intersepsi untuk penegakan hukum, tidak termasuk yang dicabut [S15].
- Akibat praktisnya: dokumen dan pelatihan lama masih menyebut "Pasal 31 UU ITE", sedangkan rujukan pidana yang berlaku untuk perbuatan sejak 2 Januari 2026 adalah KUHP Pasal 258. Kenali keduanya. UU 1/2026 tentang Penyesuaian Pidana juga mengubah KUHP, dan basis data peraturan yang dirujuk belum memetakan pasal mana yang berubah [S16], jadi cocokkan teks Pasal 258 dan Pasal 622 dengan salinan resmi sebelum mengutipnya.
- Pertanyaan inti untuk Ratna tetap sama di kedua rezim: apa dasar "hak" atau alasan "tidak melawan hukum" bagi PT JAB untuk memonitor jaringannya sendiri (kebijakan penggunaan TI, persetujuan karyawan, kontrak, banner), dan bagaimana menjaga monitoring tidak meluas ke komunikasi yang bukan milik PT JAB.

**UU PDP dan peraturan pelaksananya.**

- UU No. 27/2022 tentang Pelindungan Data Pribadi (PDP) mengatur pemrosesan data pribadi: prinsip, hak subjek data, kewajiban pengendali/prosesor, dan sanksi [S7]. Pcap dan log yang memuat data pribadi adalah bagian dari pemrosesan itu. Implikasinya: tujuan yang jelas, minimisasi, kontrol akses, dan retensi terbatas.
- Pasal 34 mewajibkan penilaian dampak pelindungan data pribadi untuk pemrosesan berpotensi risiko tinggi; daftarnya mencakup pemrosesan berskala besar, pemantauan yang sistematis, dan penggunaan teknologi baru [S17]. Sensor yang merekam trafik seluruh kantor masuk akal diperlakukan sebagai pemantauan sistematis.
- Pasal 53 mewajibkan penunjukan pejabat pelindungan data pribadi bila kegiatan inti pengendali memerlukan pemantauan data pribadi secara teratur dan sistematis dalam skala besar [S18]. PT JAB sudah punya DPO (Agus Setiawan); program NSM perlu masuk ke dalam pengawasannya.
- Peraturan pelaksananya, PP 33/2026, ditetapkan 16 Juli 2026 dan berlaku 16 Januari 2027 menurut dua basis data hukum sekunder [S19][S20]. Ringkasan sekunder menyebut PP itu merinci kapan penilaian dampak wajib, tugas pejabat PDP, dan pemberitahuan kegagalan pelindungan data dalam 3 x 24 jam [S20]. Untuk program yang dimulai Mei 2027, PP ini sudah berlaku; cek pasal spesifiknya di salinan resmi JDIH sebelum dipakai di dokumen PT JAB.

**Praktik dari sumber NSM dan forensik.**

- Bejtlich menulis bahwa legalitas NSM tidak punya jawaban mudah, dan operasi NSM jangan dimulai tanpa nasihat hukum yang memadai [S9]. Untuk melindungi privasi pengguna, ia menyarankan memisahkan tim respons (fokus pada penyerang dan ancaman dari luar) dari tim forensik internal (fokus pada penyalahgunaan oleh pengguna sah) [S9].
- NIST SP 800-86 meminta kebijakan untuk penanganan pengungkapan informasi sensitif yang tidak disengaja, kebijakan monitoring dengan banner peringatan, dan proses permintaan serta persetujuan formal sebelum merekam semua paket milik satu pengguna tertentu [S8].
- NIST juga mencatat bahwa ISP umumnya meminta perintah pengadilan sebelum memberikan informasi tentang aktivitas yang melewati infrastrukturnya [S8], dan Bejtlich mencatat bahwa penyedia layanan menyimpan data NSM-nya sendiri [S9]. PT JAB berada di posisi ISP itu.

**Jaminan untuk Ratna soal trafik pelanggan.** Lingkup Program NSM hanya jaringan korporat PT JAB: egress kantor Jakarta dan segmen server data center. Sensor tidak dipasang di jalur agregasi pelanggan broadband. Ada satu titik yang perlu dikunci tertulis: flow di `jkt-flow01` berasal dari router edge yang juga membawa trafik pelanggan, sehingga pemakaian flow oleh SOC dibatasi ke prefiks dan alamat korporat PT JAB, dan pemakaian di luar itu butuh dasar terpisah yang ditetapkan Legal. Batas ini ditulis di draf kebijakan bagian 2.8.

**Praktik aman untuk catatan ini:**

- Tangkap hanya di lab pribadi, atau pakai pcap publik yang memang disediakan untuk latihan.
- Jangan membawa pcap dari jaringan kerja atau klien ke repo atau laptop pribadi.
- Di pekerjaan, pastikan ada kebijakan tertulis yang mengizinkan monitoring, akses terbatas ke pcap, dan retensi yang ditentukan.
- Pertimbangkan snaplen/header-only atau metadata (Zeek/flow) bila isi paket tidak diperlukan. Ini sejalan dengan prinsip minimisasi data.

### 1.8 Alat yang dipakai dan status versinya

Pertanyaan terakhir Dimas datang dari Agung, yang harus menyiapkan server. Versi menentukan dokumentasi mana yang dibaca dan tutorial mana yang masih berlaku.

- **Wireshark:** 4.6.9 dan 4.4.19 dirilis 23 Sep 2026, dengan banyak perbaikan kerentanan [S2]. Selalu perbarui alat analisis, karena parser protokol adalah permukaan serangan saat membuka pcap dari sumber tidak tepercaya. Untuk `jkt-nsm-ws01`, pakai cabang stabil, bukan rilis kandidat 5.0 (bagian 6).
- **Zeek:** halaman resmi menyebut 9.0.0 sebagai LTS (14 Sep 2026), dengan LTS sebelumnya 8.0.10 (19 Agu 2026). LTS dirawat satu tahun, dengan rilis baru sekitar tiap empat bulan [S3]. Untuk `jkt-zeek01`, LTS adalah pilihan yang wajar karena sensor produksi jarang ingin diganti tiap empat bulan.
- **Suricata:** stabil 8.0.7 (15 Sep 2026). Cabang 7.x sudah End-of-Life, dengan rilis terakhir 7.0.17 [S4]. Abaikan artikel lama yang masih menyebut 7.x sebagai LTS.
- **dumpcap:** mesin capture bawaan distribusi Wireshark; man page yang dirujuk adalah versi 4.6.9 [S11]. dumpcap dipakai untuk capture panjang karena tidak mengurai protokol, sehingga lebih ringan dan lebih kecil permukaan serangannya daripada membuka Wireshark di sensor.

## 2. Contoh dan langkah praktis: persiapan rapat Jumat

Semua isi bagian ini fiktif dan merupakan keluaran ilustrasi. Artefak PT JAB (2.1, 2.2, 2.3, 2.8, 2.9) adalah dokumen kerja; perintah di 2.4 sampai 2.7 dijalankan di VM lab sendiri. Asumsi lab: sensor Linux dengan interface `eth1` terhubung ke port SPAN/host-only; Wireshark/tshark 4.6.x dan Zeek 9.0.x terpasang di VM sensor.

### 2.1 Inventaris sumber bukti PT JAB dan blind spot-nya

Inventaris ini menjawab pertanyaan pertama Hendra dengan memutar ulang `INC-2027-060` terhadap setiap sumber yang ada. Baca kolom "Yang dijawab di INC-2027-060" dan "Yang tidak bisa dijawab"; dua kolom itu adalah alasan program ini ada.

| Sumber | Host / index | Retensi | Yang dijawab di INC-2027-060 | Yang tidak bisa dijawab |
|---|---|---|---|---|
| Proxy | `jkt-proxy01`, index `proxy` | 30 hari | `CONNECT cdn-sync.example.net:443` dari `JKT-WS-2001` dan `JKT-WS-2003`, interval sekitar 5 menit, byte keluar dan masuk per sesi | Isi sesi (domain terkategori, tidak didekripsi); apakah ada sesi lain yang tidak lewat proxy |
| DNS | `jkt-res01`, `jkt-res02`, index `dns` | 30 hari | Query `cdn-sync.example.net` dengan jawaban `203.0.113.160` dan `203.0.113.161`; host mana yang bertanya | Apa yang terjadi setelah resolusi |
| Firewall | `jkt-fw01`, index `firewall` | 90 hari | Proxy ke `203.0.113.160:443` diizinkan; tidak ada koneksi langsung workstation ke IP itu | Workstation mana di balik proxy; isi |
| Flow NOC | `jkt-flow01` | 13 bulan | Volume kasar proxy ke `203.0.113.0/24` per hari | Workstation asal (terlihat sebagai proxy), periodisitas (sampling 1:1000), isi |
| VPN | `jkt-vpn01`, index `vpn` | sesuai index `vpn` | Kedua workstation tidak sedang VPN | Tidak relevan untuk kasus ini |
| EDR | Defender for Endpoint | sesuai lisensi | Proses `SyncHelper.exe` bertanda tangan vendor yang membuka koneksi | Apa yang dikirim proses itu lewat jaringan |
| Zeek, Suricata, pcap | belum ada | - | - | Sertifikat, JA3/JA4, ukuran per request, isi bila didekripsi, alert signature |

Cara membacanya:

- Setiap sumber menjawab sebagian, dan tidak satu pun menjawab "apa yang dikirim". Itu sebabnya status akhir inkonklusif, bukan "aman".
- Kolom flow menunjukkan masalah titik observasi (bagian 1.4): flow edge melihat proxy, bukan workstation.
- Baris terakhir adalah daftar belanja program. Zeek di core switch akan memberi `ssl.log` dan `x509.log` untuk sesi workstation ke proxy dan proxy ke internet; pcap di egress memberi isi untuk 72 jam terakhir.

**Kapan gagal:** inventaris ditulis dari dokumen desain, bukan dari data. Retensi yang tertulis "30 hari" bisa saja kenyataannya 21 hari karena index penuh lebih dulu. Cek setiap angka retensi dengan mencari event tertua di masing-masing index sebelum inventaris dikirim.

### 2.2 Rancangan posisi sensor PT JAB

Rancangan ini menjawab pertanyaan Agung dan diambil dari diagram di Ide inti. Tabel berikut adalah versi yang diserahkan ke Agung; kolom "Masuk produksi" penting karena sebelum tanggal itu, sensor belum bisa dipakai sebagai bukti.

| Host | IP | Fungsi | Sumber trafik | Keluaran | Masuk produksi |
|---|---|---|---|---|---|
| `jkt-npb01` | 10.20.70.10 | Packet broker | TAP egress Jakarta (sisi dalam `jkt-fw01`) dan SPAN core switch DC | Salinan trafik ke tiga sensor | Bersama sensor pertama |
| `jkt-ids01` | 10.20.70.11 | Suricata 8.0.x | Egress dan core DC lewat `jkt-npb01` | `eve.json` ke index `suricata` | Rabu 2027-05-19 |
| `jkt-zeek01` | 10.20.70.12 | Zeek 9.0 LTS | Egress dan core DC lewat `jkt-npb01` | Log transaksi ke index `zeek` | Selasa 2027-05-18 |
| `jkt-pcap01` | 10.20.70.13 | Ring buffer pcap | Egress Jakarta saja | pcapng lokal, target retensi 72 jam | Uji coba sejak Selasa 2027-05-04 |
| `jkt-flow01` | 10.20.70.14 | Kolektor flow NOC (sudah ada) | IPFIX/NetFlow v9 dari router edge (1:1000) dan router DC (1:1) | Flow untuk NOC; SOC hanya prefiks korporat | Sudah berjalan |
| `jkt-nsm-ws01` | 10.20.70.20 | Workstation analisis | Akses ke pcap dan Splunk | Ekstrak pcap per kasus | Bersama `jkt-pcap01` |

Keputusan desain yang perlu disetujui:

- **TAP egress di sisi dalam firewall**, supaya alamat internal terlihat (bagian 1.5).
- **pcap hanya di egress** di fase pertama. Core DC punya volume trafik server ke server yang jauh lebih besar, dan Zeek di titik itu sudah memberi metadata; pcap core DC dievaluasi Juli.
- **Interface capture tanpa alamat IP.** Interface yang menerima TAP/SPAN tidak punya IP; manajemen sensor lewat interface terpisah di `10.20.70.0/24`. Dengan begitu SSH manajemen tidak masuk ke capture dan sensor tidak bisa diserang dari jalur yang dimonitor.

**Kapan gagal:** SPAN di core switch dikonfigurasi untuk VLAN yang salah atau hanya satu arah (rx saja), sehingga Zeek melihat setengah koneksi. Gejalanya `conn_state` dan `history` yang hanya berisi satu sisi untuk sebagian besar koneksi; uji penerimaan di Day 08 bagian 2.9 memeriksanya sebelum sensor dinyatakan produksi.

### 2.3 Perkiraan kebutuhan disk `jkt-pcap01`

Hitungan ini menjawab pertanyaan kelima. Data masukan dari Bambang: link internet korporat Jakarta 1 Gbps (terpisah dari kapasitas transit pelanggan), rata-rata pemakaian 24 jam sekitar 20%, rata-rata jam kerja sekitar 35%. Server yang disiapkan Agung punya 12 disk 1 TB dalam RAID 6.

```
Kapasitas link        1 Gbps = 1.000.000.000 bit/s / 8 = 125 MB/s
Rata-rata 24 jam      20% x 125 MB/s = 25 MB/s
Per hari              25 MB/s x 86.400 s = 2.160.000 MB = 2,16 TB
Target 72 jam         2,16 TB x 3 = 6,48 TB
Cadangan 30%          6,48 TB x 1,3 = 8,424 TB  -> dibulatkan 8,4 TB untuk ring buffer

Disk RAID 6           (12 - 2) x 1 TB = 10 TB usable
Ring buffer           8,4 TB  (sisa sekitar 1,6 TB untuk OS, ekstrak kasus, dan ruang gerak)

Jendela waktu nyata dengan ring buffer 8,4 TB:
  rata-rata 20%       8,4 TB / 25 MB/s     = 336.000 s ~ 93,3 jam
  35% terus-menerus   8,4 TB / 43,75 MB/s  = 192.000 s ~ 53,3 jam
  link penuh 100%     8,4 TB / 125 MB/s    =  67.200 s ~ 18,7 jam
```

Cara membaca hasil:

- Pada rata-rata harian, 8,4 TB memberi sekitar 93 jam, di atas target 72 jam. Cadangan 30% menutup overhead format pcapng dan lonjakan.
- Bila trafik bertahan di level jam kerja sepanjang hari, jendela turun ke sekitar 53 jam. Bila link penuh (misalnya saat serangan volumetrik atau exfiltration besar), jendela turun ke sekitar 18,7 jam. Ini yang perlu diketahui Hendra: pada saat insiden besar, pcap tersimpan paling pendek justru ketika paling dibutuhkan, sehingga ekstrak per kasus harus segera dibuat.
- Log Zeek untuk trafik egress yang sama, dengan asumsi 1-2% dari volume pcap, sekitar 21,6 sampai 43,2 GB per hari. Rasio ini adalah asumsi kasar yang sama dengan variasi tantangan di bagian 3, bukan angka sumber; ukur rasionya di lab dan di minggu pertama `jkt-zeek01`, karena angka ini juga memengaruhi lisensi Splunk.

**Variasi:** ulangi hitungan dengan cadangan 50%, atau dengan link 2 Gbps bila Bambang menambah kapasitas. Rumusnya tetap: jendela (detik) = kapasitas ring buffer (byte) / laju rata-rata (byte per detik).

**Kapan gagal:** utilisasi diambil dari grafik 5 menit yang sudah dirata-rata, sehingga puncak pendek tidak terlihat; atau disk dihitung dalam TB tetapi sistem file melaporkan TiB (8,4 TB setara sekitar 7,64 TiB), sehingga ring buffer berhenti karena disk penuh sebelum jumlah file tercapai.

### 2.4 Menangkap dengan ring buffer (dumpcap)

Perintah ini adalah langkah capture pertama untuk lab, dan variasinya adalah konfigurasi uji coba `jkt-pcap01` yang dimulai Selasa 2027-05-04.

**Tujuan:** menangkap trafik terus-menerus dengan retensi yang bisa diprediksi tanpa memenuhi disk.

```bash
sudo dumpcap -i eth1 -f "not port 22" -b duration:3600 -b files:24 -w /data/pcap/lab.pcapng
```

Tabel berikut menjelaskan tiap bagian perintah.

| Bagian | Arti |
|---|---|
| `-i eth1` | Interface sensor |
| `-f "not port 22"` | Capture filter (sintaks BPF): buang SSH manajemen sensor sendiri agar tidak mengotori data |
| `-b duration:3600` | Ganti file setiap 3600 detik |
| `-b files:24` | Simpan maksimal 24 file (sekitar 24 jam), lalu yang tertua ditimpa. Jumlah file ini menentukan retensi |
| `-w` | Path keluaran; dumpcap menambahkan nomor urut lima digit dan timestamp ke nama file [S11] |

Man page dumpcap menegaskan bahwa setiap `-b` memuat satu kriteria, sehingga beberapa kriteria ditulis dengan mengulang `-b`; `files` membutuhkan `duration`, `interval`, atau `filesize` untuk menentukan kapan file berganti, dan nilainya harus di bawah 100000 [S11].

Keluaran ilustrasi saat capture dihentikan (format baris ringkasan bisa sedikit berbeda antar versi):

```
Capturing on 'eth1'
File: /data/pcap/lab_00001_20261007160000.pcapng
Packets: 182034 Packets dropped: 0
Packets received/dropped on interface 'eth1': 182034/0 (pcap:0/dumpcap:0/flushed:0/ps_ifdrop:0) (100.0%)
```

**Cara membaca hasil:** angka drop di baris terakhir adalah angka yang dicatat di laporan. Drop 0 berarti capture lengkap untuk interface itu; drop di atas nol berarti ada paket yang tidak tersimpan, dan setiap kesimpulan "tidak ada" dari pcap itu harus menyebutnya.

**Variasi untuk `jkt-pcap01` (berbasis ukuran):**

```bash
sudo dumpcap -i ens2f0 -B 1024 -b filesize:1000000 -b files:8400 -w /pcap/egress-jkt.pcapng
```

- `-i ens2f0`: interface yang menerima salinan egress dari `jkt-npb01`, tanpa alamat IP, sehingga capture filter untuk SSH tidak diperlukan.
- `-B 1024`: memperbesar buffer capture; man page menyarankan menaikkan nilai ini bila terjadi drop [S11]. Cek satuannya dengan `dumpcap -h` di versi-mu.
- `-b filesize:1000000`: ganti file setiap 1.000.000 kB, sekitar 1 GB [S11].
- `-b files:8400`: 8400 file sekitar 1 GB, sesuai ring buffer 8,4 TB di bagian 2.3. Man page tidak menegaskan apakah kB di sini 1000 atau 1024 byte [S11]; bila 1024, totalnya sekitar 8,6 TB, jadi sisakan ruang di disk.

**Kenapa ring buffer:** retensi terbatas yang bisa diprediksi tanpa memenuhi disk.
**Kapan gagal:** disk lambat atau link ramai menyebabkan packet drop. Selalu cek statistik drop saat berhenti dan catat di laporan. Capture filter yang terlalu agresif juga membuang paket secara permanen; saat ragu, filter saat display, bukan saat capture.

### 2.5 Ringkasan pcap sebelum analisis (capinfos)

Sebelum membuka file di Wireshark, pastikan file itu memang mencakup waktu yang diselidiki. Bejtlich memasukkan keluaran capinfos ke kategori statistical data [S9].

**Tujuan:** memastikan rentang waktu, jumlah paket, dan ukuran file sebelum analisis.

```bash
capinfos /data/pcap/lab_00001_20261007160000.pcapng
```

Keluaran ilustrasi (dipotong):

```
File type:           Wireshark/... - pcapng
Number of packets:   182 k
File size:           151 MB
Capture duration:    3599.8 seconds
First packet time:   2026-10-07 16:00:00.12
Last packet time:    2026-10-07 16:59:59.95
```

**Cara membaca hasil:** pastikan rentang waktu mencakup kejadian yang diselidiki. Catat juga apakah waktunya UTC atau lokal sebelum menggabungkan dengan log SIEM; PT JAB bekerja dalam WIB (UTC+7). Dari angka ini, rata-rata ukuran per paket sekitar 151 MB / 182 ribu, kira-kira 830 byte, dan laju rata-rata sekitar 335 kbps, wajar untuk lab yang sepi.

**Variasi:** di `jkt-pcap01`, capinfos atas satu file 1 GB memberi rentang waktu file itu; untuk mencari file yang mencakup jam tertentu, cukup baca timestamp di nama file dari dumpcap.

**Kapan gagal:** file masih ditulis dumpcap sehingga ringkasannya belum final, atau file terpotong karena disk penuh.

### 2.6 Dari pcap ke log transaksi (Zeek)

Langkah ini mengubah full content menjadi transaction data, persis yang akan dilakukan `jkt-zeek01` secara live.

**Tujuan:** menghasilkan `conn.log`, `dns.log`, dan log lain dari pcap, lalu mengambil kolom yang dibutuhkan.

```bash
mkdir -p /cases/lab001/zeek && cd /cases/lab001/zeek
zeek -C -r /data/pcap/lab_00001_20261007160000.pcapng
zeek-cut id.orig_h id.resp_h id.resp_p proto service duration orig_bytes resp_bytes < conn.log | head
```

Penjelasan tiap bagian:

- `zeek -r <pcap>`: memproses pcap offline. Log ditulis ke direktori kerja (conn.log, dns.log, dll.).
- `-C`: abaikan error checksum. Ini umum diperlukan pada capture dari host dengan checksum offloading; tanpa `-C`, Zeek bisa mengabaikan paket dengan checksum salah sehingga log tidak lengkap.
- `zeek-cut`: ambil kolom tertentu dari log TSV Zeek.

Keluaran ilustrasi:

```
192.168.56.20  192.168.56.10  1514  tcp  -     3598.2  884213  50211
192.168.56.20  93.184.215.14  443   tcp  ssl   0.41    1820    5102
192.168.56.20  192.168.56.1   53    udp  dns   0.002   41      57
```

**Cara membaca hasil:**

- Baris 1: koneksi panjang ke port 1514/TCP. Port itu adalah port bawaan komunikasi agent Wazuh ke manager-nya: agent membuka satu sesi panjang lalu mengirim event terus-menerus, sehingga durasinya hampir sama dengan panjang capture dan byte dari sisi originator jauh lebih besar. Di lab ini, pola tersebut jinak dan diharapkan.
- Baris 2: HTTPS biasa.
- Baris 3: DNS ke resolver lab.

`orig_bytes` dan `resp_bytes` menghitung byte payload, bukan byte IP; total di level IP ada di `orig_ip_bytes` dan `resp_ip_bytes` [S12]. Kebiasaan inti analisis jaringan adalah mengenali dulu yang normal (agent, update, DNS) sebelum mencari yang aneh.

**Variasi:** hitung koneksi per `service` dengan `zeek-cut service < conn.log | sort | uniq -c | sort -rn`; atau tambahkan `uid` ke daftar kolom lalu cari `uid` yang sama di `ssl.log` untuk melihat nama server dan sertifikat sesi HTTPS di baris 2.

**Kapan gagal:** `-C` lupa dipakai pada capture dari host itu sendiri sehingga banyak koneksi hilang dan `weird.log` penuh entri checksum; atau pcap dari SPAN satu arah sehingga `history` hanya memuat huruf satu sisi.

### 2.7 Display filter Wireshark pertama

Filter berikut adalah yang paling sering dipakai saat pertama membuka pcap kasus. Tabel ini dipakai sebagai daftar awal; detailnya di Day 02.

| Filter | Tujuan |
|---|---|
| `dns` | Semua paket DNS |
| `ip.addr == 192.168.56.20` | Semua trafik satu host (dua arah) |
| `tcp.flags.syn == 1 && tcp.flags.ack == 0` | SYN awal, untuk melihat percobaan koneksi baru |
| `http.request` | Request HTTP plaintext |
| `tls.handshake.type == 1` | TLS ClientHello (lihat SNI di Day 06) |

Capture filter berbeda dari display filter. Capture filter (BPF, bagian 2.4) memutuskan apa yang disimpan. Display filter memutuskan apa yang ditampilkan dari yang sudah tersimpan. Paket yang dibuang capture filter tidak bisa dipulihkan.

**Variasi untuk kasus seperti `INC-2027-060`:** `ip.addr == 203.0.113.160 || ip.addr == 203.0.113.161` menampilkan semua paket ke dua alamat tujuan itu; di pcap egress, sumbernya akan tampak sebagai proxy, sehingga workstation asal harus dicocokkan dari log proxy atau dari Zeek di core.

**Kapan gagal:** filter `ip.addr` dipakai pada trafik IPv6 (gunakan `ipv6.addr`), atau ClientHello yang terpecah ke beberapa segmen TCP sehingga field TLS baru terbaca setelah reassembly.

### 2.8 Draf kebijakan akses pcap

Draf ini menjawab permintaan Agus dan Ratna, dan disusun dari kebutuhan yang disebut NIST SP 800-86 dan UU PDP di bagian 1.7. Tujuannya membuat pcap bisa dipakai saat insiden tanpa menjadikannya alat pengintai karyawan.

```
KEBIJAKAN AKSES DATA NSM PT JAB (DRAF v0.1, 2027-05-05)
Pemilik      : Dimas Prasetyo (SOC lead). Reviewer: Agus Setiawan (DPO), Ratna Sari (Legal)

Lingkup      : Trafik jaringan korporat PT JAB di egress kantor Jakarta dan segmen server data center.
               Trafik pelanggan broadband dan dedicated di luar lingkup. Flow dari jkt-flow01 hanya
               dipakai SOC untuk prefiks dan alamat korporat PT JAB.
Tujuan       : Deteksi dan investigasi insiden keamanan; troubleshooting jaringan atas tiket NOC.
               Bukan untuk menilai kinerja atau perilaku karyawan.
Dasar        : Kebijakan penggunaan TI yang ditandatangani karyawan; banner monitoring di login;
               penilaian dampak PDP sebelum sensor produksi (UU 27/2022 Pasal 34).
Akses pcap   : SOC L2 dan SOC lead, dari jkt-nsm-ws01 saja. NOC atas tiket. Semua akses tercatat.
               Analyst L1 hanya log Zeek dan alert Suricata di Splunk.
Retensi      : Ring buffer jkt-pcap01, target 72 jam pada trafik rata-rata, tertimpa otomatis.
               Ekstrak per kasus disimpan dengan nomor INC dan hash SHA-256, dihapus saat kasus
               ditutup ditambah masa simpan yang ditetapkan Legal.
Persetujuan  : Mengekstrak atau memfilter semua trafik milik satu karyawan tertentu hanya dengan
               permintaan tertulis yang disetujui SOC lead, DPO, dan Legal.
               Dugaan penyalahgunaan oleh karyawan diserahkan ke jalur investigasi internal, bukan SOC.
Pengungkapan : Data sensitif yang terlihat tanpa sengaja (password, isi email) tidak disalin ke
               tiket atau chat; dicatat di kasus sebagai "data sensitif terlihat" dan dilaporkan ke DPO.
Larangan     : Menyalin pcap ke perangkat pribadi atau di luar jaringan analisis.
Tinjauan     : Akhir percobaan (Juli 2027) bersama DPO dan Legal.
```

Cara membaca elemennya:

- **Lingkup** menjawab jaminan yang diminta Ratna, termasuk batas pemakaian flow NOC.
- **Persetujuan** mengikuti saran NIST tentang permintaan dan persetujuan formal sebelum merekam semua paket satu pengguna [S8] dan saran Bejtlich memisahkan respons terhadap penyerang dari investigasi penyalahgunaan internal [S9].
- **Pengungkapan** mengikuti saran NIST tentang kebijakan untuk pengungkapan informasi sensitif yang tidak disengaja [S8].
- **Dasar** dan **Retensi** adalah bagian yang paling mungkin diubah Legal; dasar hukumnya (bagian 1.7) adalah keputusan Ratna, bukan SOC.

**Kapan gagal:** kebijakan ditulis setelah sensor berjalan. Begitu ada pcap yang tersimpan tanpa dasar tertulis, pertanyaan pertama di setiap kasus adalah keabsahan buktinya, bukan isinya.

### 2.9 Satu halaman jawaban untuk Dimas

Ringkasan ini adalah yang kamu kirim ke Dimas Rabu sore untuk rapat Jumat. Setiap baris merujuk subbagian di atas, supaya Dimas bisa membaca alasannya bila ditanya Hendra.

| Pertanyaan | Jawaban singkat | Dasar |
|---|---|---|
| Bukti apa yang ada, kenapa `INC-2027-060` inkonklusif | Firewall, proxy, DNS, VPN, flow NOC, EDR; semuanya metadata, tidak ada yang merekam isi | Bagian 1.1, 1.2, 2.1 |
| NSM itu apa, cukup IDS? | Kumpulkan, analisis, eskalasi; IDS hanya alarm, NSM butuh rekaman dan analis | Bagian 1.3 |
| Flow sudah ada, kenapa pcap | Flow tanpa isi, di-sampling 1:1000 di edge, dan melihat proxy/NAT, bukan workstation | Bagian 1.4 |
| Sensor di mana, apa yang tidak terlihat | TAP egress sisi dalam firewall dan SPAN core DC; blind spot lateral antar workstation, Bandung/Medan, isi TLS, cloud | Bagian 1.5, 2.2 |
| Berapa lama pcap | 8,4 TB ring buffer: sekitar 93 jam rata-rata, sekitar 18,7 jam bila link penuh | Bagian 1.6, 2.3 |
| Legal dan PDP | Larangan intersepsi kini di KUHP Pasal 258 (dulu UU ITE Pasal 31 ayat 1-2); DPIA dan DPO menurut UU PDP; kebijakan akses sebelum produksi; trafik pelanggan di luar lingkup | Bagian 1.7, 2.8 |
| Alat dan versi | Zeek 9.0 LTS, Suricata 8.0.7, Wireshark/dumpcap 4.6.9 | Bagian 1.8 |

**Kapan gagal:** jawaban dikirim dengan janji "setelah sensor jalan, insiden seperti INC-2027-060 pasti terjawab". Isi TLS tetap tidak terlihat tanpa dekripsi; yang dijanjikan adalah metadata yang jauh lebih kaya dan isi untuk trafik yang tidak terenkripsi.

## 3. Lab praktik (di VM lab terisolasi)

**Prasyarat:** VM sensor Linux dengan Wireshark/tshark dan Zeek, VM Windows, Wazuh, dan Splunk di jaringan host-only, semuanya dengan snapshot bersih. Jangan memakai data, nama, atau kejadian dari pekerjaan nyata; PT JAB hanya contoh fiktif.

1. **Peta sensor:** gambar topologi lab (host-only/NAT, VM Windows, Linux, Wazuh, Splunk) dengan gaya diagram di Ide inti. Tandai di mana kamu bisa menangkap (interface host-only di hypervisor atau VM sensor dengan promiscuous) dan apa yang tidak terlihat dari titik itu.
2. **Tabel sumber bukti:** untuk lab-mu, isi tabel bagian 1.2 dengan kolom "ada/tidak" dan "retensi saat ini", lalu buat versi inventaris seperti bagian 2.1 untuk satu kasus rekaan (misalnya VM Windows yang menghubungi satu situs tiap lima menit).
3. **Capture 1 jam:** jalankan bagian 2.4 (ubah `files:` menjadi 2 untuk lab). Selama itu, lakukan aktivitas normal di VM Windows: browsing, update, login.
4. **Ringkas:** `capinfos` (bagian 2.5). Catat jumlah paket, durasi, dan drop.
5. **Zeek:** proses pcap (bagian 2.6). Hitung koneksi per `service`: `zeek-cut service < conn.log | sort | uniq -c | sort -rn`.
6. **Baseline jinak:** identifikasi 5 pola normal (agent Wazuh, Windows Update, DNS, NTP, Splunk forwarder bila ada) beserta host dan port tujuannya.
7. **Privasi:** buka satu stream HTTP plaintext di lab (mis. ke server web lab). Catat data apa yang terlihat. Tulis 3 kalimat tentang kenapa pcap produksi butuh kontrol akses dan retensi.
8. **Korelasi:** cari satu koneksi dari `conn.log` yang juga muncul di log Wazuh/Splunk (mis. agent 1514). Bandingkan timestamp.
9. **Hitung disk:** dari capinfos langkah 4, hitung laju rata-rata lab-mu (byte per detik), lalu pakai rumus bagian 2.3 untuk menghitung jendela waktu bila ring buffer lab diberi 20 GB. Ulangi dengan ring buffer berbasis ukuran (`-b filesize:` dan `-b files:`) dan bandingkan jendela waktunya dengan perkiraanmu.
10. **Kebijakan lab:** tulis versi pendek draf bagian 2.8 untuk lab-mu: siapa yang boleh membuka pcap, berapa lama disimpan, dan apa yang tidak boleh keluar dari VM.

**Hasil yang sebaiknya tersimpan:**

- Diagram sensor dan blind spot.
- pcap 1 jam, ringkasan capinfos, dan catatan drop.
- conn.log yang dihasilkan dan 5 pola normal teridentifikasi.
- Catatan privasi ditulis.
- Hitungan jendela waktu ring buffer lab, perkiraan vs hasil nyata.
- Kebijakan akses pcap versi lab.

**Variasi tantangan:** dengan asumsi link 200 Mbps rata-rata 30% terpakai, hitung kebutuhan disk untuk pcap 7 hari vs log Zeek. Asumsikan log Zeek sekitar 1-2% dari volume pcap, dan tandai asumsi itu, cek dengan mengukur rasio di lab-mu sendiri.

## 4. Troubleshooting

Tabel ini memuat masalah yang sering muncul saat menyiapkan sensor dan capture pertama. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Hanya melihat trafik host sensor sendiri | Bukan port SPAN/promiscuous; virtual switch tidak meneruskan | Aktifkan promiscuous di hypervisor/vSwitch; tangkap di host-only adapter |
| Banyak `weird` checksum di Zeek | Checksum offloading di host capture | Pakai `-C` saat membaca pcap [S1]; atau matikan offloading di sensor |
| Packet drop tinggi | Disk/CPU tidak mengimbangi | Kurangi trafik dengan capture filter; tulis ke disk cepat; naikkan `-B` [S11]; cek statistik drop dan `capture_loss.log` Zeek [S1] |
| Waktu log Zeek berbeda dengan SIEM | UTC vs lokal | Zeek memakai epoch (UTC) [S12]; normalisasi saat korelasi |
| Wireshark crash membuka pcap dari internet | Bug parser | Perbarui ke rilis terbaru (4.6.9) [S2]; buka di VM terisolasi |
| Semua trafik kantor tampak dari satu IP publik | TAP dipasang di sisi luar NAT | Pindahkan TAP ke sisi dalam firewall (bagian 1.5) |
| Semua sesi web tampak dari proxy | Sensor hanya di egress | Tambah SPAN di segmen antara workstation dan proxy; korelasikan dengan log proxy |
| Retensi pcap jauh lebih pendek dari 72 jam | Ring buffer berbasis ukuran dan trafik di atas rata-rata | Hitung ulang jendela dengan laju nyata (bagian 2.3); buat ekstrak kasus lebih awal |
| Ring buffer berhenti sebelum `files:N` tercapai | Disk penuh karena TB vs TiB atau ekstrak kasus di partisi yang sama | Sisakan ruang; pisahkan partisi ring buffer dan ekstrak |
| `conn_state` banyak setengah koneksi | SPAN hanya satu arah atau VLAN salah | Cek konfigurasi SPAN (rx dan tx) di switch |

## 5. Kesalahan umum dan jebakan

- Mengandalkan satu sumber. pcap tanpa flow berarti retensi pendek. Flow tanpa pcap berarti tanpa isi. Kombinasikan.
- Menyamakan NSM dengan membeli IDS. Tanpa data yang disimpan dan analis yang memakainya, IDS hanya alarm (bagian 1.3).
- Capture filter terlalu agresif. Yang dibuang tidak bisa dikembalikan. Saat ragu, filter saat display, bukan saat capture.
- Lupa blind spot sensor. "Tidak ada di pcap" tidak sama dengan "tidak terjadi". Mungkin lewat jalur yang tidak di-tap.
- Memasang TAP di sisi luar NAT, lalu heran kenapa semua workstation tampak sebagai satu alamat.
- Menganggap retensi ring buffer berbasis ukuran sebagai jaminan waktu. Jendelanya menyusut tepat saat trafik melonjak (bagian 2.3).
- Menyimpulkan C2 dari satu indikator. Koneksi periodik bisa berupa agent, update, atau NTP. Bedakan indikator dari kesimpulan. `INC-2027-060` sendiri berakhir inkonklusif, bukan "C2 terkonfirmasi".
- Mengutip "Pasal 31 UU ITE" sebagai satu-satunya dasar larangan intersepsi untuk perbuatan sejak 2 Januari 2026, padahal ayat (1) dan (2) sudah dicabut KUHP dan larangannya pindah ke KUHP Pasal 258 [S15][S16].
- Membawa pcap kerja ke lab/repo. Ini risiko privasi dan legal [S6][S7].
- Memakai flow NOC yang memuat trafik pelanggan untuk investigasi korporat tanpa batas prefiks yang tertulis.
- Klaim dari materi vendor: penghematan biaya "hingga 50%" dan "retensi 10x" dengan memakai metadata Zeek berasal dari materi vendor [S5]. Arahnya masuk akal, tetapi angkanya perlu dicek di lingkunganmu sendiri.

## 6. Catatan terkini

Bagian ini menampung detail versi, tanggal terbit, dan perubahan regulasi yang berguna saat membuka sumbernya, tetapi tidak mengubah alur kerja di atas.

- Wireshark 4.6.9/4.4.19 (23 Sep 2026) berisi banyak perbaikan kerentanan [S2]. Rilis keamanan Wireshark rutin terjadi sepanjang 2026 (Jan, Feb, Apr, Jul, Sep).
- Wireshark 5.0.0rc1 dirilis 21 Okt 2026 sebagai rilis pengembangan [S13]. Perubahan yang relevan untuk sensor dan capture: file capture bisa disimpan dengan kompresi Zstandard, ada opsi `--process-info` untuk mencatat proses pengirim atau penerima paket, interface TCP dumpcap dihapus, build Qt 5 tidak lagi didukung, dan versi Windows minimum menjadi Windows 10 21H2 [S13]. Tetap pakai cabang 4.6 di lab sampai 5.0 stabil.
- Zeek 9.0.0 LTS (14 Sep 2026). Zeek 8.0.x menjadi LTS lama [S3]. Cek perubahan format/field log antara 8.0 dan 9.0 sebelum Day 08.
- Suricata 8.0.7 (15 Sep 2026); 7.x EOL [S4]. Rule dan konfigurasi dari tutorial 7.x mungkin perlu penyesuaian di Day 09.
- UU ITE diubah kedua kalinya dengan UU 1/2024 (berlaku 2 Jan 2024) [S6]. Basis data peraturan yang dirujuk mencatat Pasal 31 pernah diubah UU 19/2016 dan belum memetakan perubahan per pasal oleh UU 1/2024 [S6].
- KUHP baru (UU 1/2023) ditetapkan dan diundangkan 2 Jan 2023 dan berlaku 2 Jan 2026 [S14]. JDIH BPK mencatat KUHP diubah dengan UU 1/2026 tentang Penyesuaian Pidana dan mencabut sebagian pasal UU ITE [S14].
- PP 33/2026 tentang peraturan pelaksanaan UU PDP: ditetapkan dan diundangkan 16 Jul 2026, berlaku 16 Jan 2027, 12 bab dan 225 pasal menurut basis data hukum sekunder [S19].
- NIST SP 800-86 terbit Agustus 2006 [S8]. Contoh alat di dalamnya sudah tua, tetapi pembagian sumber data, fase forensik, dan isu legal pengumpulan trafik masih menjadi rujukan umum.

## 7. Cheat sheet

```
SUMBER    pcap (isi, mahal, pendek) > Zeek (metadata kaya) > Suricata (alert) > flow (murah, lama) ; + DNS, proxy, FW
JENIS     Bejtlich: full content | extracted content | session | transaction | statistical | metadata | alert
STRATEGI  flow+Zeek luas & lama | pcap di titik kritis & pendek | simpan pcap insiden lebih lama
NSM       collection -> analysis -> escalation ; sensor tepat posisi ; tahu BLIND SPOT
POSISI    TAP sisi DALAM NAT/firewall ; SPAN core untuk trafik ke proxy ; switch akses = blind spot
FLOW      tanpa isi ; sampling 1:1000 -> koneksi 12 paket terwakili ~1,2% ; edge melihat proxy/NAT
HITUNG    1 Gbps penuh ~ 125 MB/s ~ 10,8 TB/hari ; jendela (s) = kapasitas ring (B) / laju (B/s)
          PT JAB: 8,4 TB -> ~93 jam (20%) | ~53 jam (35%) | ~18,7 jam (100%)
CAPTURE   dumpcap -i <if> -f "<BPF>" -b duration:3600 -b files:N -w <file>    (capture filter = permanen)
          dumpcap -i <if> -B <buf> -b filesize:<kB> -b files:N -w <file>       (disk tetap, waktu menyusut)
RINGKAS   capinfos <pcap>
ZEEK      zeek -C -r <pcap> ; zeek-cut <cols> < conn.log ; uid = penghubung lintas log ; ts = epoch UTC
DISPLAY   dns | ip.addr==X | tcp.flags.syn==1 && tcp.flags.ack==0 | http.request | tls.handshake.type==1
LEGAL     UU ITE Ps.31 ayat 1-2 dicabut KUHP Ps.622 (berlaku 2 Jan 2026) -> KUHP Ps.258 ;
          UU 27/2022 PDP Ps.34 (DPIA), Ps.53 (DPO) ; PP 33/2026 (berlaku 16 Jan 2027) ; tanya legal
KEBIJAKAN lingkup (tanpa trafik pelanggan) | akses tercatat | retensi | persetujuan per-user | pengungkapan tak sengaja
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "NOC PT JAB sudah menerima flow dari semua router edge, jadi `INC-2027-060` sebenarnya bisa dijawab dari flow tanpa perlu pcap." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Flow tidak pernah memuat isi, padahal pertanyaan yang gagal dijawab adalah apa yang dikirim. Selain itu, flow edge di-sampling 1:1000, sehingga koneksi beacon berisi sekitar 12 paket hanya terwakili sekitar 1,2% dan periodisitasnya tidak bisa direkonstruksi. Titik observasinya juga setelah proxy dan NAT, sehingga yang terlihat adalah proxy atau `198.51.100.120`, bukan `JKT-WS-2001`. Flow tetap berguna sebagai lapisan retensi panjang. Lihat bagian 1.4.

</details>

**2. Skenario keputusan.** Agung menawarkan tiga titik untuk TAP egress Jakarta. Mana yang paling tepat untuk fase pertama?

- A. Di sisi luar `jkt-fw01`, antara firewall dan router edge, karena di situ semua trafik internet pasti lewat.
- B. Di sisi dalam `jkt-fw01`, ditambah SPAN di core switch DC untuk segmen server termasuk proxy dan resolver.
- C. Di switch akses lantai SOC saja, karena di situ analyst bisa langsung memeriksanya.

<details><summary>Jawaban</summary>

B. Di sisi dalam firewall, alamat internal masih terlihat, dan SPAN core menangkap sesi workstation ke proxy yang di egress akan tampak berasal dari proxy. A keliru karena di sisi luar NAT seluruh kantor tampak sebagai `198.51.100.120`, sehingga workstation tidak bisa dibedakan. C keliru karena hanya melihat satu switch akses dan tidak melihat trafik ke internet dari lantai lain. Lihat bagian 1.5 dan 2.2.

</details>

**3. Pertanyaan jebakan.** "Ring buffer `jkt-pcap01` dirancang untuk 72 jam, jadi saat insiden besar kita pasti punya pcap 72 jam terakhir." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Ring buffer berbasis ukuran menjamin pemakaian disk, bukan jendela waktu. Dengan 8,4 TB, jendelanya sekitar 93 jam pada rata-rata 20%, sekitar 53 jam bila trafik bertahan 35%, dan hanya sekitar 18,7 jam bila link 1 Gbps penuh. Insiden besar sering justru menaikkan trafik, jadi ekstrak per kasus harus dibuat secepatnya. Lihat bagian 1.6 dan 2.3.

</details>

**4. Skenario keputusan.** Seorang manajer meminta SOC "merekam semua trafik laptop Andi minggu ini" karena curiga Andi membocorkan dokumen. Langkah mana yang paling tepat?

- A. Langsung buat capture filter untuk IP laptop Andi di `jkt-pcap01`, karena sensor milik PT JAB dan permintaan datang dari manajer.
- B. Tolak capture per orang tanpa permintaan tertulis yang disetujui SOC lead, DPO, dan Legal; arahkan dugaan penyalahgunaan internal ke jalur investigasi internal.
- C. Tolak sepenuhnya, karena pcap tidak boleh dipakai untuk apa pun yang menyangkut karyawan.

<details><summary>Jawaban</summary>

B. NIST SP 800-86 meminta permintaan dan persetujuan formal sebelum merekam semua paket satu pengguna, dan Bejtlich menyarankan memisahkan respons terhadap penyerang dari investigasi penyalahgunaan oleh pengguna sah. Draf kebijakan PT JAB menuliskan keduanya. A keliru karena tidak ada dasar tertulis, dan pemantauan terarah seperti itu menyentuh larangan intersepsi serta kewajiban PDP. C keliru karena investigasi internal bisa sah bila melalui persetujuan dan dasar hukum yang benar. Lihat bagian 1.7 dan 2.8.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Bambang Hartono (Manajer NOC), dalam tiga kalimat, kenapa Program NSM memakai flow, Zeek, dan pcap sekaligus.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Flow dari `jkt-flow01` tetap jadi lapisan paling murah dengan retensi paling panjang, cocok untuk melihat apakah sebuah pola sudah terjadi berminggu-minggu, tetapi tidak punya isi dan di edge di-sampling 1:1000. Zeek seperti CDR yang juga mencatat inti percakapannya: nama domain, sertifikat, URL, dan jumlah byte per transaksi, dengan retensi minggu sampai bulan. pcap merekam seluruh isi, tetapi karena 1 Gbps penuh setara sekitar 10,8 TB per hari, kita hanya menyimpannya sekitar 72 jam di egress, cukup untuk memperdalam kasus yang sudah ditandai dua lapisan lain."

Kesalahan yang sering muncul:
- Menyebut flow tidak berguna, padahal ia lapisan retensi panjang.
- Lupa menyebut sampling dan titik observasi setelah proxy/NAT.
- Menjanjikan pcap berbulan-bulan tanpa hitungan disk.

</details>

**6. Pertanyaan jebakan.** "Dasar hukum larangan penyadapan yang harus dikutip di kebijakan NSM PT JAB 2027 adalah Pasal 31 ayat (1) dan (2) UU ITE." Benarkah?

<details><summary>Jawaban</summary>

Tidak sepenuhnya. Sejak KUHP baru berlaku 2 Januari 2026, Pasal 622 ayat (1) huruf r KUHP mencabut Pasal 31 ayat (1) dan (2) UU ITE, dan larangan setara kini ada di KUHP Pasal 258. Ayat (3) dan (4) Pasal 31 UU ITE tentang intersepsi penegakan hukum tidak dicabut. Dokumen lama masih menyebut Pasal 31, jadi keduanya perlu dikenali, dan teks resminya dicocokkan Legal, termasuk kemungkinan perubahan oleh UU 1/2026. Lihat bagian 1.7.

</details>

**7. Interview question (English).** "Our company has no network sensors today. How would you start a network security monitoring capability, and what would you tell management about its limits?"

<details><summary>Sample answer</summary>

"I would start from the investigation questions we failed to answer, not from a product. I map what evidence we already have, such as firewall, proxy, DNS and flow, and write down what each source cannot answer. Then I place sensors where they add the most: a TAP on the inside of the internet firewall so internal addresses are still visible, and a SPAN on the core segment where clients talk to the proxy and resolvers. I layer the data: flow for long retention, Zeek transaction logs for rich metadata over weeks, and full packet capture in a size-based ring buffer for a few days, sized from measured utilisation. Before anything records, I agree a written access and retention policy with legal and the privacy officer, including a formal approval step for any capture targeting one person. To management I state the limits plainly: encrypted content stays opaque without decryption, east-west traffic on the same access switch is a blind spot, and the pcap window shrinks exactly when traffic spikes during a big incident."

What makes this answer strong: it starts from evidence gaps, explains sensor placement with the NAT and proxy reasons, sizes retention with arithmetic, puts legal and privacy before deployment, and states blind spots instead of overselling.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Zeek documentation: Logs (index) | https://docs.zeek.org/en/current/logs/index.html | primer | diakses 2026-10-07, dicek ulang 2026-10-22 | Tinggi. Daftar log (termasuk `capture_loss.log`, weird, notice) dan field conn.log |
| S2 | Wireshark news: 4.6.9 dan 4.4.19 | https://www.wireshark.org/news/20260923.html | primer | 2026-09-23; diakses 2026-10-10, dicek ulang 2026-10-22 | Tinggi untuk nomor versi dan tanggal rilis |
| S3 | Zeek: Get Zeek | https://zeek.org/get-zeek/ | primer | diakses 2026-10-07, dicek ulang 2026-10-22 | Tinggi. LTS 9.0.0, LTS sebelumnya 8.0.10, kebijakan LTS |
| S4 | Suricata: Download | https://suricata.io/download/ | primer | diakses 2026-10-07, dicek ulang 2026-10-22 | Tinggi. 8.0.7 stabil, 7.x EOL dengan rilis terakhir 7.0.17 |
| S5 | Plixer: packet capture vs flow data (blog vendor; materi serupa dari Corelight dan Network Computing) | https://www.plixer.com/blog/packet-capture-vs-flow-data/ | sekunder (vendor) | 2026-10-07 | Rendah sampai sedang. Klaim penghematan bersifat pemasaran; situs bisa menolak akses otomatis |
| S6 | Pasal.id: UU 11/2008 Pasal 31 | https://pasal.id/peraturan/uu/uu-no-11-tahun-2008/pasal-31 | primer (basis data peraturan) | diakses 2026-10-07, dicek ulang 2026-10-22 | Sedang sampai tinggi. Menampilkan naskah asli; mencatat perubahan oleh UU 19/2016 dan status "perlu diperiksa" karena pencabutan sebagian; tanggal berlaku UU 1/2024 dicocokkan ke salinan resmi |
| S7 | JDIH BPK: UU No. 27 Tahun 2022 | https://peraturan.bpk.go.id/Details/229798 | primer | 2026-10-07 | Tinggi untuk keberadaan dan ruang lingkup undang-undang |
| S8 | NIST SP 800-86: Guide to Integrating Forensic Techniques into Incident Response (Kent, Chevalier, Grance, Dang) | https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-86.pdf | primer | 2006-08; diakses 2026-10-22 | Tinggi untuk fase forensik, sumber data trafik (NIST 6.2), isu legal dan teknis pengumpulan (NIST 6.3), nilai tiap sumber (NIST 6.4.2.1). Dokumen lama; contoh alat sudah usang |
| S9 | Richard Bejtlich: The Practice of Network Security Monitoring, Bab 1 (sampel penerbit No Starch) | https://nostarch.com/download/samples/PNSM_Ch01.pdf | primer (buku penulis definisi NSM) | 2013; diakses 2026-10-22 | Tinggi untuk definisi NSM, tujuh jenis data NSM, dan catatan legal/privasi. Pembahasan hukum berfokus ke Amerika Serikat dan Uni Eropa |
| S10 | RFC 7011: Specification of the IPFIX Protocol for the Exchange of Flow Information | https://www.rfc-editor.org/rfc/rfc7011 | primer | 2013-09; diakses 2026-10-22 | Tinggi. Definisi flow, template, port 4739/4740, SCTP wajib, pertimbangan privasi data flow |
| S11 | Wireshark: dumpcap manual page | https://www.wireshark.org/docs/man-pages/dumpcap.html | primer | versi 4.6.9; diakses 2026-10-22 | Tinggi. Opsi `-b` (duration, files, filesize, interval), nama file ring buffer, `-s`, `-B`. Satuan kB tidak didefinisikan tegas |
| S12 | Zeek documentation: Connection log (conn.log) | https://docs.zeek.org/en/current/logs/conn.html | primer | diakses 2026-10-22 | Tinggi. Field conn.log; `ts` epoch dikonversi ke UTC; beda `orig_bytes` dan `orig_ip_bytes` dari contoh di halaman |
| S13 | Wireshark news: 5.0.0rc1 Development Release | https://www.wireshark.org/news/20261021.html | primer | 2026-10-21; diakses 2026-10-22 | Tinggi untuk status rilis kandidat dan daftar perubahan |
| S14 | JDIH BPK: UU No. 1 Tahun 2023 tentang KUHP | https://peraturan.bpk.go.id/Details/234935/uu-no-1-tahun-2023 | primer | diakses 2026-10-22 | Tinggi. Penetapan dan pengundangan 2 Jan 2023, berlaku 2 Jan 2026, diubah UU 1/2026, mencabut sebagian pasal UU ITE |
| S15 | Pasal.id: UU 1/2023 (KUHP) Pasal 622 | https://pasal.id/peraturan/uu/uu-no-1-tahun-2023/pasal-622 | primer (basis data peraturan) | diakses 2026-10-22 | Sedang sampai tinggi. Ayat (1) huruf r mencabut antara lain Pasal 31 ayat (1) dan (2) UU ITE; naskah asli, perubahan oleh UU 1/2026 belum dipetakan |
| S16 | Pasal.id: UU 1/2023 (KUHP) Pasal 258 | https://pasal.id/peraturan/uu/uu-no-1-tahun-2023/pasal-258 | primer (basis data peraturan) | diakses 2026-10-22 | Sedang sampai tinggi. Larangan penyadapan transmisi nonpublik dan pengecualian tugas jabatan; perubahan oleh UU 1/2026 belum dipetakan |
| S17 | Pasal.id: UU 27/2022 (PDP) Pasal 34 | https://pasal.id/peraturan/uu/uu-no-27-tahun-2022/pasal-34 | primer (basis data peraturan) | diakses 2026-10-22 | Sedang sampai tinggi. Daftar pemrosesan berisiko tinggi yang wajib penilaian dampak |
| S18 | Pasal.id: UU 27/2022 (PDP) Pasal 53 | https://pasal.id/peraturan/uu/uu-no-27-tahun-2022/pasal-53 | primer (basis data peraturan) | diakses 2026-10-22 | Sedang sampai tinggi. Kewajiban menunjuk pejabat PDP |
| S19 | Meridian Hukum: PP No. 33 Tahun 2026 | https://meridianhukum.com/peraturan/pp-no-33-tahun-2026 | sekunder (basis data hukum swasta) | diakses 2026-10-22 | Sedang. Judul, tanggal penetapan, pengundangan, berlaku, jumlah bab dan pasal |
| S20 | Veritask: pengaturan teknis PDP lewat PP 33/2026 | https://veritask.ai/id/artikel/pengaturan-teknis-pelindungan-data-pribadi-dan-kewajiban-pengendali-serta-prosesor-akhirnya-terbit-lewat-pp-33-2026 | sekunder (artikel hukum) | diakses 2026-10-22 | Sedang. Ringkasan isi PP: penilaian dampak, pejabat PDP, pemberitahuan kegagalan 3 x 24 jam |

**Catatan sumber:** definisi NSM di bagian 1.3 mengikuti Bejtlich [S9], bukan definisi resmi Zeek. Angka penghematan biaya metadata dibanding pcap (bagian 5) berasal dari materi vendor dan perlu diukur di lingkungan sendiri. Hitungan volume, disk, dan peluang sampling di bagian 1.4, 1.6, dan 2.3 adalah aritmetika sendiri dengan asumsi yang ditulis, bukan angka dari sumber; rasio log Zeek 1-2% dari volume pcap adalah asumsi yang perlu diukur. Uraian UU ITE, KUHP, dan UU PDP adalah gambaran umum, bukan analisis hukum: pemetaan pencabutan Pasal 31 UU ITE ke KUHP diambil dari basis data peraturan [S15][S16] yang belum memetakan perubahan oleh UU 1/2026, dan keterangan PP 33/2026 hanya dari dua sumber sekunder [S19][S20] karena salinan resminya belum diperiksa; cocokkan semuanya dengan teks resmi di JDIH sebelum dipakai di dokumen formal. Status lembaga pengawas PDP tidak dibahas dan perlu dicek terpisah. Seluruh isi PT JAB (alert, insiden, host, angka utilisasi, retensi, kebijakan) adalah penerapan catatan ini pada organisasi fiktif, bukan hasil eksekusi nyata.
