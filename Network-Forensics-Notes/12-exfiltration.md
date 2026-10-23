---
day: 12
title: 'Exfiltration: mengenali pencurian data dari arah dan volume, saluran tersembunyi, dan staging'
researched_on: 2026-10-23
versions_checked: 'MITRE ATT&CK v20.0 (13 Okt 2026): TA0010, T1048 v1.6 (3 Sep 2026, DET0131), T1048.003 v2.2 (3 Sep 2026, DET0149), T1567 v1.5 (12 Mei 2026, DET0548), T1567.002 v1.3 (12 Mei 2026, DET0570), T1041 v2.4 (11 Sep 2026, DET0348), T1030 v1.2 (16 Sep 2026, DET0213), T1700 v1.0 (baru di v20, 9 Okt 2026); Zeek 9.0.0 LTS (conn.log/files.log; files.log memakai uid dan id sejak Zeek 5.1; skrip conn/main.zeek, init-bare.zeek, ICMP.cc cabang master dibaca 2026-10-22); TA for Zeek 1.0.11 (sourcetype bro:<log>:json); Wireshark 4.6.9; nfdump 1.7.10 (7 Sep 2026); RFC 9846 (TLS 1.3, Juli 2026); RFC 1035; Splunk Research DNS Query Length With High Standard Deviation v16 (13 Mei 2026); Microsoft 365 URLs and IP address ranges (14 Agu 2026); Microsoft Entra tenant restrictions v2 (20 Mar 2026); Squid logformat (kode >st, <st, format native squid); rujukan Day 01-11'
---

# Day 12: Exfiltration dari arah, volume, saluran, dan staging

Cakupan: mengenali exfiltration dari arah, volume, tujuan, dan saluran trafik (unggahan ke layanan web, DNS tunneling, protokol tak biasa), mengukur berapa yang keluar dan seberapa yakin, membedakannya dari backup atau sinkronisasi yang sah, dan menyambungkannya ke staging di host.

Day ini membahas exfiltration dari sisi deteksi dan forensik. Tidak ada instruksi melakukan exfiltration; teknik dirujuk ke katalog MITRE ATT&CK, bukan ditulis sebagai prosedur. Data PT JAB fiktif, lab memakai jaringan host-only pribadi, dan IOC di-defang di laporan.

## Ide inti

Exfiltration adalah pemindahan data keluar jaringan ke kendali penyerang, dan di jaringan ia hampir selalu terlihat sebagai satu bentuk: arah trafik terbalik dari kebiasaan host itu. Workstation dan server biasanya lebih banyak menerima daripada mengirim; host yang tiba-tiba mengirim ratusan megabyte ke tujuan yang belum pernah ia hubungi, atau mengirim ribuan query DNS unik ke satu domain, sedang mengeluarkan sesuatu. Karena isi hampir selalu terenkripsi, pekerjaan Day ini adalah mengukur bentuk itu dengan angka yang bisa dipertanggungjawabkan (byte per arah, per pasangan host dan tujuan, per jendela waktu), menemukan titik sensor yang masih tahu siapa host aslinya, lalu menulis dengan jujur apa yang terbukti dari jaringan (berapa, ke mana, kapan, lewat apa) dan apa yang hanya bisa dijawab host (data apa).

Bentuk yang sama juga dimiliki unggahan yang sah: sinkronisasi OneDrive, backup ke cloud, pengiriman file ke mitra. Rasio arah tidak tahu tujuan, akun, jadwal, atau izin. Jadi setiap kandidat exfiltration diputus oleh konteks: tujuan milik siapa (tenant perusahaan atau akun pribadi), sejak kapan dihubungi, berapa host lain melakukan hal yang sama, proses apa yang mengirim, dan apakah ada perubahan yang tercatat. Volume besar sendiri bukan bukti, dan volume kecil bukan jaminan aman.

Polanya sudah kamu kenal dari NOC. Profil trafik pelanggan broadband hampir selalu asimetris: downstream jauh lebih besar dari upstream. Pelanggan rumahan yang upstream-nya tiba-tiba penuh berjam-jam di tengah malam adalah anomali yang biasa kamu lihat di grafik utilisasi dan di NetFlow: bisa CPE yang jadi bagian botnet, bisa juga pelanggan yang baru memasang kamera CCTV ke cloud. Rasio upstream ke downstream adalah padanan rasio `orig_bytes` ke `resp_bytes` di Day ini. Batas analoginya ada tiga. Di ISP kamu melihat satu pelanggan sebagai satu alamat, sedangkan di kantor proxy dan resolver mewakili ratusan klien sehingga atribusi butuh hop sebelum perantara. Grafik utilisasi tidak tahu tujuan, padahal tujuan adalah separuh keputusan. Dan penyerang, tidak seperti CCTV, sengaja memecah pengiriman atau menumpang layanan populer supaya grafiknya terlihat normal.

```
 JKT-WS-2057 10.10.60.127                                   internet
   |  (1) CONNECT up.simpanfile.example:443  ----------------------------------------+
   |      hop core: Zeek conn+http (CONNECT host), orig_bytes ~ unggahan            |
   v                                                                                 |
 jkt-proxy01 10.20.3.60:3128  -- splice, log proxy: CONNECT host, bytes ke klien     |
   |      hop egress: Zeek conn+ssl (SNI), sumber 10.20.3.60                         v
   |------------------------------- TAP egress (sisi dalam jkt-fw01) ---> 203.0.113.182 (layanan
   |                                                                       penyimpanan cloud)
   |  (2) DNS TXT <data>.<data>.<data>.<seq>.x.kirimdata.example
   v      hop core: Zeek dns (klien asli)       hop egress: Zeek dns (sumber resolver)
 jkt-res01 10.20.2.53  ------------------- TAP egress ---------------> 203.0.113.183:53
   |                                                                    (authoritative milik
   |  (3) SYN langsung ke 203.0.113.183:443 -> jkt-fw01 RST             penyerang)
   v      Zeek egress: REJ, orig_bytes 0 ; firewall: deny
 flow: router DC 1:1 (WS ke proxy/resolver) ; router edge 1:1000 (sesudah NAT 198.51.100.120)
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan sekitar 1.200 karyawan, kantor pusat dan data center di Jakarta, dan NOC 24/7 yang satu lantai dengan SOC. Sejak Senin 2027-05-03, PT JAB menjalankan "Program NSM PT JAB" sebagai percobaan Mei sampai Juli 2027. Per pekan ini, `jkt-zeek01` (`10.20.70.12`, produksi sejak Selasa 2027-05-18) dan `jkt-ids01` (`10.20.70.11`, sejak Rabu 2027-05-19) membaca SPAN core switch data center dan TAP egress Jakarta lewat packet broker `jkt-npb01`; `jkt-pcap01` (`10.20.70.13`) menyimpan pcap egress dengan target 72 jam; kolektor flow NOC `jkt-flow01` (`10.20.70.14`) menerima flow router edge (sampling 1:1000) dan router data center (1:1). Workstation kantor keluar ke web hanya lewat proxy eksplisit `jkt-proxy01` (`10.20.3.60:3128`, Squid dengan SslBump yang hanya mendekripsi domain baru atau tidak terkategori) dan me-resolve nama lewat `jkt-res01` (`10.20.2.53`) dan `jkt-res02` (`10.20.2.54`); keluar langsung ke internet ditolak `jkt-fw01` dengan reset. Sepekan setelah Zeek hidup, SOC menambahkan tiga saved search exfiltration di atas index `zeek`.

Malam Selasa 2027-05-25 sampai Rabu dini hari, lima alert masuk antrean shift malam Dwi Cahyono (L1), dengan Rudi Hartanto (L2) sebagai on-call: unggahan besar dari `JKT-WS-2057` ke layanan penyimpanan cloud pribadi lewat proxy (`SOC-2027-0655`, 21:15), ratusan SYN dari host yang sama langsung ke `203.0.113.183:443` yang ditolak firewall (`SOC-2027-0656`, 22:58), unggahan besar dari `JKT-WS-2055` ke OneDrive (`SOC-2027-0657`, 23:15), query DNS TXT panjang dari `JKT-WS-2057` (`SOC-2027-0658`, 01:20), dan unggahan FTP dari `jkt-recon01` ke mitra (`SOC-2027-0659`, 01:45). Pukul 01:48 Rudi membuka `INC-2027-071`, dan `JKT-WS-2057` diisolasi lewat Microsoft Defender for Endpoint pukul 02:11:47. Rabu 2027-05-26 pukul 08:30, Dimas Prasetyo (SOC lead) menulis kepadamu:

> "Pagi. INC-2027-071 sudah di tangan Yoga untuk sisi host, tapi jam 13 aku harus lapor ke Pak Hendra dan Bu Nina, dan pertanyaan mereka pasti satu: ada data yang keluar atau tidak, berapa banyak, ke mana, dan seberapa yakin kita. Tolong pakai data jaringan. Sebelum mulai: sebenarnya sumber kita yang mana yang bisa menjawab itu, kan semua lewat proxy? Dari 2057, berapa yang keluar ke penyimpanan cloud itu, kapan, dan apakah blokir proxy jam 21:34 benar menghentikannya? Lalu 2055 juga mengunggah gigabyte ke OneDrive, rasionya sama-sama miring; kenapa yang satu insiden dan yang satu bukan? DNS 2057 tengah malam itu benar membawa data, dan kalau iya berapa? Ada juga SYN langsung ke 443 dan FTP dari jkt-recon01; ada yang keluar lewat jalur itu? Semua HTTPS, jadi seberapa yakin kita soal isinya, dan apa yang sama sekali tidak bisa kita lihat? Tolong petakan juga ke ATT&CK untuk laporan, dan bilang apa yang perlu aku teruskan ke Pak Agus sebagai DPO. Terakhir, kiriman 2,1 MB dari 2052 hari Jumat di INC-2027-070 masih menggantung; Yoga minta angka yang bisa dipegang."

Pesan itu memuat delapan pertanyaan:

1. Sumber mana yang bisa menjawab "ada data keluar", dan di titik mana host aslinya masih terlihat walaupun semua lewat proxy?
2. Berapa yang keluar dari `JKT-WS-2057` lewat `jkt-proxy01`, ke mana, kapan, dan apakah blokir pukul 21:34 menghentikannya?
3. Kenapa unggahan OneDrive `JKT-WS-2055` tidak dianggap exfiltration, padahal rasionya sama miring?
4. Apakah DNS dari `JKT-WS-2057` benar membawa data, dan berapa banyak?
5. Apakah ada data yang keluar lewat SYN langsung ke `203.0.113.183:443` atau lewat FTP `jkt-recon01`?
6. Bila isi terenkripsi, seberapa yakin kita, dan apa yang sama sekali tidak terlihat?
7. Teknik ATT&CK apa yang dipakai di laporan, dan apa yang perlu diteruskan ke DPO?
8. Apa yang bisa dikatakan jaringan tentang kiriman 2.118.004 byte dari `JKT-WS-2052` Jumat 2027-05-21 pukul 15:13:40 WIB (`INC-2027-070`, Day 11)?

Pertanyaan 1 dijawab di bagian 1.1 dan 1.2, pertanyaan 2 di bagian 1.3, 2.1, 2.2, dan 2.3, pertanyaan 3 di bagian 1.6 dan 2.4, pertanyaan 4 di bagian 1.4 dan 2.5, pertanyaan 5 di bagian 1.5 dan 2.6, pertanyaan 6 di bagian 1.7 dan 1.8, pertanyaan 7 di bagian 1.9, 1.10, dan 2.8, dan pertanyaan 8 di bagian 1.8 dan 2.7.

**Kapan relevan:** saat menilai dampak intrusi ("apa yang keluar"), saat alert volume keluar, DNS panjang, atau protokol tak biasa masuk antrean, saat legal atau DPO bertanya berapa dan sejak kapan, dan saat merancang saved search exfiltration di atas Zeek, flow, atau proxy.
**Kapan bukan jawaban:** saat pertanyaannya "dokumen apa persisnya yang dicuri" (itu dijawab bukti host dan log aplikasi, jaringan hanya memberi volume dan tujuan); saat host bekerja dari luar kantor lewat VPN split tunnel atau jaringan rumah, karena trafiknya tidak lewat sensor PT JAB; dan saat exfiltration berjalan sangat pelan dan tersebar sehingga tidak ada satu jendela pun yang menonjol, karena ambang volume lalu harus diganti agregasi jangka panjang dan korelasi host.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (pcap, SPAN, TAP, packet broker, ring buffer, `uid`, `conn_state`, `history`, SNI, JA3/JA4, splice dan bump, DNS tunneling, entropi, NetFlow/IPFIX, sampling) tidak diulang; definisinya ada di Day 01 sampai 11 [S5]. Tabel ini hanya memuat istilah yang dipakai Day ini; kolom padanan memakai pengalaman NOC dan ISP.

| Istilah | Arti singkat | Padanan di NOC/ISP |
|---|---|---|
| Exfiltration | Pemindahan data keluar jaringan ke kendali penyerang (ATT&CK TA0010) | Upstream pelanggan yang penuh berjam-jam di luar profilnya |
| `orig_bytes` / `resp_bytes` | Byte payload yang dikirim pihak pemulai / pihak yang dihubungi dalam satu koneksi Zeek | Counter upstream / downstream per sesi |
| Rasio arah | `orig_bytes` dibagi `resp_bytes` per koneksi atau per pasangan host dan tujuan | Rasio upstream ke downstream pelanggan |
| PCR (producer-consumer ratio) | (kirim dikurangi terima) dibagi (kirim ditambah terima); dari -1 (murni menerima) sampai 1 (murni mengirim) | Profil asimetri link yang dinormalisasi, terlepas dari besar bandwidth |
| Hop core / hop egress | Leg workstation ke proxy atau resolver (terlihat di SPAN core) / leg perantara ke internet (terlihat di TAP egress) | Sisi akses vs sisi upstream satu sesi yang melewati CGNAT |
| Staging | Mengumpulkan dan memaketkan data di satu tempat sebelum dikirim (T1074) | Menumpuk trafik di buffer sebelum burst dikirim |
| Pecahan berukuran tetap | Data dipotong menjadi bagian sama besar supaya tiap transfer di bawah ambang (T1030) | Fragmentasi ke ukuran MTU yang sama |
| Low and slow | Pengiriman sedikit-sedikit tersebar waktu supaya tidak ada lonjakan | Trafik yang selalu di bawah ambang alarm utilisasi |
| Layanan web sah sebagai saluran | Mengunggah ke penyimpanan cloud, repositori kode, atau webhook yang memang diizinkan (T1567) | Penyerang memakai jalur transit yang sudah di-whitelist ACL |
| Protokol alternatif | Mengirim data lewat protokol selain kanal C2, misalnya DNS, FTP, SMTP (T1048) | Data disisipkan ke kanal yang tidak dimaksudkan untuk muatan, seperti signaling |
| Tenant | Instance organisasi di layanan SaaS; OneDrive milik PT JAB berbeda tenant dari OneDrive pribadi | Pelanggan berbeda di platform yang sama, dibedakan VRF atau ID pelanggan |
| Overhead TLS record | Byte tambahan per record terenkripsi (header, tipe konten, tag AEAD) di atas data asli | Overhead enkapsulasi MPLS/GRE yang menambah byte di atas payload |

### 1.1 Sinyal jaringan exfiltration

Pertanyaan pertama Dimas ("ada data yang keluar atau tidak") hanya bisa dijawab bila kamu tahu sinyal apa yang dicari. Alert `SOC-2027-0655` menyalakan dua sinyal sekaligus: volume keluar besar dan tujuan yang belum pernah dihubungi host itu.

Tabel berikut adalah sinyal yang dipakai sepanjang Day ini; kolom kanan menunjukkan kenapa satu sinyal saja tidak pernah cukup.

| Sinyal | Penjelasan | Penjelasan jinak yang harus disingkirkan |
|---|---|---|
| Volume keluar besar | Byte outbound jauh di atas baseline host | Backup, sinkronisasi, unggahan video, transfer ke mitra |
| Rasio arah terbalik | Normalnya download lebih besar dari upload; exfil membalik (upload besar) | Semua unggahan sah juga miring ke arah kirim |
| Tujuan tak biasa | Ke IP, domain, atau cloud yang bukan pola normal host | Layanan baru yang sah, vendor baru, rapat dengan mitra baru |
| Waktu tak biasa | Transfer besar di luar jam kerja | Backup terjadwal malam, sinkronisasi awal yang dibiarkan semalam |
| Saluran menyatu | Lewat HTTPS, DNS, atau cloud agar tampak sah | Memang begitulah hampir semua trafik sah sekarang |
| Mengikuti C2 | Exfil setelah beaconing atau perintah (Day 11) | Agent sah juga punya ritme tetap |
| Keseragaman mesin | Pecahan sama besar, laju sangat rata, tanpa jeda manusiawi | Aplikasi sinkronisasi juga memotong file dan membatasi laju |

Sinyal utama adalah arah dan volume: host yang tiba-tiba mengirim banyak data keluar ke tujuan tak biasa. Flow (Day 10) dan `conn.log` Zeek sangat cocok untuk ini karena menyimpan byte per arah [S2][S3]. ATT&CK v20 menuliskan analitik deteksi exfiltration lewat kanal C2 dengan bahasa yang sama: volume keluar yang tidak cocok dengan kebiasaan proses, rasio byte yang abnormal, dan tujuan yang langka, terutama setelah akses ke data sensitif [S9]. Kalimat terakhir itu penting: ATT&CK sendiri memasangkan sinyal jaringan dengan sinyal host (akses file, kompresi), bukan berdiri sendiri.

Jawaban untuk bagian pertama pertanyaan Dimas: "data keluar" di jaringan berarti byte yang terukur meninggalkan PT JAB ke tujuan tertentu dalam jendela waktu tertentu. Itu bisa dibuktikan. "Data X keluar" adalah kesimpulan berbeda yang butuh bukti host (bagian 1.10).

### 1.2 Di mana sinyal terlihat di PT JAB: hop core, hop egress, dan perantara

Bagian kedua pertanyaan pertama Dimas ("kan semua lewat proxy?") adalah persoalan titik pandang. Di TAP egress, unggahan `JKT-WS-2057` tidak terlihat berasal dari `10.10.60.127`; sumbernya `10.20.3.60`, alamat proxy, bersama ratusan workstation lain.

Satu unggahan lewat proxy eksplisit adalah dua koneksi TCP dengan `uid` berbeda (Day 08 bagian 1.3). Tiap koneksi terlihat di titik sensor yang berbeda, dan masing-masing tahu hal yang berbeda. Tabel berikut adalah peta yang dipakai setiap kali kamu menjawab "siapa mengirim berapa ke mana"; cari kolom yang memuat ketiga unsur itu sekaligus.

| Sumber | Tahu host asli? | Tahu tujuan? | Tahu byte keluar? | Catatan |
|---|---|---|---|---|
| Zeek hop core (SPAN core DC: workstation ke `jkt-proxy01:3128`) | Ya (`id.orig_h`) | Ya, dari `CONNECT host` di `http.log` (teks polos ke proxy) | Ya (`orig_bytes`, termasuk header CONNECT) | Titik terbaik untuk aturan per host-tujuan |
| Zeek hop egress (TAP egress: proxy ke internet) | Tidak (sumber `10.20.3.60`) | Ya (`id.resp_h`, SNI di `ssl.log`) | Ya | Konfirmasi IP tujuan dan SNI |
| Log proxy `index=proxy` | Ya (`src`, `user`) | Ya (`CONNECT host:port`; URL hanya bila di-bump) | Format native Squid hanya mencatat byte yang dikirim ke klien [S15] | Unggahan nyaris tidak terlihat dari kolom `bytes` |
| Zeek `dns.log` hop core (workstation ke resolver) | Ya | Nama yang ditanyakan | Panjang nama dan jumlah query, bukan byte koneksi | DNS tunneling terlihat di sini |
| Log resolver `index=dns` | Ya (`src`) | Nama (`query`, `query_type`) | Tidak | Tanpa kode jawaban (Day 05) |
| Flow router data center (1:1) | Ya | Hanya proxy atau resolver sebagai tujuan | Ya, per arah sebagai flow terpisah | Bukti independen dari Zeek |
| Flow router edge (1:1000) | Tidak (sesudah NAT `198.51.100.120`) | Ya (IP) | Perkiraan dari sampel | Retensi 13 bulan; cocok untuk low and slow |
| pcap `jkt-pcap01` | Tidak | Ya | Ya | 72 jam; isi tetap terenkripsi |

Konsekuensinya: aturan "volume keluar per host dan tujuan" di PT JAB dijalankan di hop core, dengan tujuan diambil dari baris `CONNECT` di `http.log` yang berbagi `uid` dengan koneksinya. Hop egress dipakai untuk memastikan IP tujuan, SNI, dan bahwa byte yang sama memang meninggalkan gedung. Proxy log dipakai untuk akun pengguna dan untuk membuktikan blokir. Bentuk persis pencatatan `CONNECT` di `http.log` dan apakah `ssl.log` juga muncul di hop core untuk sesi yang di-splice perlu dicek sekali di versi Zeek dan Squid-mu, seperti dicatat di Day 08.

Ada dua jalur yang tidak terlihat sama sekali dari data ini: laptop yang bekerja dari luar kantor dengan VPN split tunnel, dan trafik antar workstation di switch akses yang sama (Day 01 bagian 1.5). Untuk `INC-2027-071`, keduanya tidak relevan karena `JKT-WS-2057` adalah PC meja di lantai Sales; tetap tulis kalimat itu di laporan.

### 1.3 Mengukur arah dan volume: `orig_bytes`, rasio, dan PCR

Pertanyaan kedua Dimas meminta angka. Alert `SOC-2027-0655` menyebut "538 MB keluar dalam 15 menit", dan sebelum angka itu masuk laporan direksi kamu harus tahu persis apa yang dihitung.

Flow dan Zeek `conn.log` menyimpan byte per arah. Di Zeek, `orig_bytes` adalah byte payload yang dikirim originator dan `resp_bytes` byte payload yang dikirim responder [S2][S11]. Untuk TCP, angka itu diambil dari sequence number dan bisa tidak akurat pada koneksi besar [S11]; `orig_ip_bytes` (byte di level IP, termasuk header) hanya terisi bila analyzer ukuran koneksi aktif [S11]. Untuk host internal sebagai originator ke tujuan eksternal:

- `orig_bytes` besar berarti banyak data dikirim keluar (kandidat exfil).
- Bandingkan dengan baseline host: lonjakan outbound ke tujuan baru mencolok.
- Jumlahkan per tujuan dan per periode untuk melihat total yang keluar.

Ini mengubah "ada trafik" menjadi "X GB keluar ke tujuan Y dalam periode Z", ukuran dampak yang konkret.

Dua ukuran turunan membantu membandingkan host yang besar dan kecil. Rasio arah (`orig_bytes` dibagi `resp_bytes`) mudah dibaca tetapi meledak ke angka ratusan ribu bila balasan nyaris nol. PCR (producer-consumer ratio) menormalkannya ke rentang -1 sampai 1: (byte kirim dikurangi byte terima) dibagi (byte kirim ditambah byte terima), dihitung dari byte aplikasi, bukan header [S21]. PCR diperkenalkan Carter Bullard dan John Gerth di FloCon 2014; nilai 0 berarti seimbang, negatif berarti lebih banyak menerima, positif berarti lebih banyak mengirim [S20]. Tabel patokan berikut berasal dari catatan praktisi, jadi baca sebagai gambaran bentuk, bukan ambang:

| PCR | Peran host | Contoh |
|---|---|---|
| 1,0 | Murni mengirim | Unggahan FTP, beacon satu arah |
| 0,4 | Sekitar 70:30 mengirim | Mengirim email |
| 0,0 | Seimbang | NTP |
| -0,5 | Sekitar 1:3 menerima | Browsing web |
| -1,0 | Murni menerima | Unduhan HTTP |

Patokan tabel di atas berasal dari repositori praktisi [S21] yang meringkas presentasi FloCon 2014, bukan dari presentasinya sendiri; berkas presentasi di situs QoSient tidak bisa dibuka saat Day ini ditulis karena sertifikat situsnya kedaluwarsa. Perlakukan angkanya sebagai ilustrasi bentuk, dan cocokkan dengan presentasi asli bila bisa diakses.

Dua batas PCR yang langsung relevan untuk PT JAB. Pertama, PCR tidak membedakan tujuan atau izin: unggahan OneDrive `JKT-WS-2055` menghasilkan PCR 0,94 dan unggahan `JKT-WS-2057` 0,9994 (bagian 2.2), dua-duanya "murni mengirim". Kedua, PCR per koneksi bisa tertipu. Tim engineering Salesforce mencatat bahwa exfil yang dipecah ke ratusan koneksi TLS kecil menghasilkan PCR sekitar -0,33 per koneksi, karena handshake dan sertifikat dari server lebih besar daripada pecahan data yang dikirim [S20]. Solusinya sama dengan yang mereka pakai: agregasikan per sumber, tujuan, dan port tujuan sebelum menghitung, bukan per koneksi [S20].

Jawaban untuk sebagian pertanyaan kedua Dimas: angka yang masuk laporan adalah jumlah `orig_bytes` hop core per pasangan host dan tujuan, dikoreksi dengan overhead TLS (bagian 1.8) dan dicocokkan dengan hop egress serta flow router data center (bagian 2.1 dan 2.2).

### 1.4 DNS sebagai saluran exfiltration

Alert `SOC-2027-0658` pukul 01:20 menyebut ribuan query TXT dari `JKT-WS-2057` dengan subdomain panjang ke `kirimdata.example`. Pertanyaan keempat Dimas adalah apakah itu benar membawa data.

DNS tunneling menyandikan data di dalam nama yang ditanyakan (dan balasan di record jawaban); ATT&CK menyebut DNS secara eksplisit sebagai protokol tak terenkripsi yang bisa dipakai T1048.003, termasuk data yang disandikan di subdomain [S7]. Resolver internal tidak perlu dikompromikan: query untuk nama unik tidak pernah ada di cache, sehingga setiap query diteruskan sampai ke authoritative server milik penyerang (Day 05 bagian 1.2). Batas protokol menentukan bentuknya: RFC 1035 membatasi satu label maksimal 63 oktet, satu nama maksimal 255 oktet, dan pesan UDP klasik 512 oktet [S14]. Akibatnya tunnel yang mengejar kapasitas mengisi beberapa label sampai mendekati 63 karakter, dan mengirim sangat banyak query.

Untuk exfiltration, yang diukur adalah empat hal berikut, dengan nilai `INC-2027-071` sebagai contoh (dihitung di bagian 2.5):

| Ukuran | Kenapa | Nilai `JKT-WS-2057` | Nilai wajar workstation PT JAB |
|---|---|---|---|
| Subdomain unik per domain induk per jam | Data yang berbeda menghasilkan nama yang berbeda | 32.400 | Puluhan |
| Panjang subdomain (rata-rata dan maksimum) | Label diisi mendekati batas 63 | rata-rata 179, maksimum 200 | rata-rata di bawah 20 |
| Entropi label | Base32 acak mendekati log2(32) = 5 bit per karakter | 4,53 sampai 4,72 untuk label 63 karakter | 2 sampai 3,5 untuk nama bermakna |
| Porsi TXT dan volume | TXT memberi ruang balasan, volume menunjukkan kanal data | 98,75% TXT dari host itu | Di bawah 1% |

Entropi Shannon menghitung keacakan dari frekuensi tiap karakter; untuk alfabet base32 (32 simbol), batas atasnya log2(32) = 5 bit per karakter, dan label 63 karakter acak rata-rata sekitar 4,59 karena tidak semua simbol muncul merata pada sampel sependek itu (dihitung dari 20.000 label acak; rentang 4,19 sampai 4,90). Day 05 bagian 1.7 sudah menunjukkan jebakannya: label pendek dan ID base32 yang sah juga berentropi tinggi. Karena itu entropi hanya penyaring; keputusan diambil dari kombinasi panjang, jumlah unik, sedikitnya klien, dan domain induk yang baru.

Satu ukuran praktis lain adalah perkiraan byte data. Base32 membawa 5 bit per karakter, jadi 8 karakter membawa 5 byte. Label data sepanjang 168 karakter per query membawa 168 x 5 / 8 = 105 byte. Dikalikan jumlah subdomain unik, kamu mendapat perkiraan isi yang keluar, terlepas dari isi aslinya. Perkiraan ini meleset bila penyandiannya bukan base32 (hex membawa 4 bit per karakter, base64 6 bit), bila ada kompresi sebelum disandikan, atau bila sebagian label adalah nomor urut, bukan data. Tulis sebagai perkiraan dengan asumsi penyandian.

Splunk Research menerbitkan analitik "DNS Query Length With High Standard Deviation" yang memetakan pola ini ke T1048.003: hitung panjang query, lalu ambil yang lebih panjang dari rata-rata ditambah dua kali simpangan baku, dan ringkas per sumber [S19]. Analitik itu membuang record PTR, SOA, dan SRV, dan mengakui bahwa nama panjang yang sah memang ada [S19]. Day 05 bagian 2.1 sudah menunjukkan contoh nama panjang yang sah di PT JAB (reverse lookup IPv6 dan lisensi GIS).

### 1.5 Protokol tak biasa dan saluran lain

Pertanyaan kelima Dimas menyangkut dua alert yang bentuknya berbeda: SYN langsung dari `JKT-WS-2057` ke `203.0.113.183:443` (`SOC-2027-0656`) dan unggahan FTP malam dari `jkt-recon01` (`SOC-2027-0659`). Keduanya adalah "protokol atau jalur selain web lewat proxy".

Tabel berikut merangkum saluran exfiltration dari sisi deteksi; kolom tengah adalah apa yang terlihat di data PT JAB.

| Saluran | Pola terlihat | Catatan deteksi |
|---|---|---|
| HTTPS | POST/PUT besar ke endpoint/cloud; TLS metadata | Isi terenkripsi; pakai volume + SNI/JA3 |
| DNS tunneling | Volume query tinggi, nama panjang (Day 05) | Data tersandi di query |
| Cloud storage | Upload ke penyedia cloud (sah maupun jahat) | Bedakan akun sah vs tujuan asing |
| Email/webmail | Lampiran keluar | Konteks dan volume |
| Protokol tak lazim | Transfer di port/proto aneh | Konteks port |
| Saluran tersembunyi | ICMP, field tak terpakai, timing | Jarang; volume rendah, sulit |

Fokus deteksi adalah pola makro (ke mana, berapa, kapan, arah), bukan mereplikasi teknik.

ATT&CK T1048 (v1.6) mencakup FTP, SMTP, HTTP/S, DNS, dan SMB sebagai contoh protokol alternatif, dan membaginya menjadi tiga sub-teknik menurut enkripsi: simetris, asimetris, dan tidak terenkripsi [S4]. Sub-teknik tidak terenkripsi (T1048.003) juga mencatat cara menyembunyikan data di protokol polos dengan penyandian seperti base64 atau di header dan field protokol [S7]. Satu analitiknya dekat dengan dunia NOC: transfer konfigurasi, tabel routing, atau log lewat TFTP, FTP, atau HTTP ke alamat yang tidak tepercaya, misalnya lewat perintah administratif semacam `copy run ftp:` [S7]. Di ISP, backup konfigurasi router ke server FTP internal adalah hal rutin; yang menjadi sinyal adalah tujuan di luar daftar server manajemen.

Di PT JAB, dua sifat jaringan menentukan cara membaca saluran ini:

- **Workstation tidak bisa keluar langsung.** `jkt-fw01` menolak koneksi langsung workstation ke internet dengan reset (Day 03). Sensor egress berada di sisi dalam firewall, sehingga Zeek melihat SYN dari workstation dan RST dari firewall. Di `conn.log`, pola itu menjadi `conn_state` REJ dengan `orig_bytes` 0: percobaan saluran alternatif yang gagal, bukan data yang keluar. Pengecualian yang diketahui adalah lima workstation NOC `10.10.60.20` sampai `.24` lewat aturan lama `NOC-VENDOR-DIRECT` (Day 02).
- **Zeek mengenali protokol dari isi, bukan port.** Dynamic protocol detection membuat SSH di port 443 tercatat dengan `service` `ssh`, dan FTP tercatat di `ftp.log` dengan perintah `STOR` serta file yang diunggah di `files.log` dengan `is_orig` `T` (Day 08 bagian 1.5). Ketidakcocokan antara `service` dan port adalah sinyal; port sendiri tidak.

ICMP perlu satu catatan karena sering disebut sebagai saluran tersembunyi. Zeek memperlakukan ICMP dan UDP dengan semantik flow [S11]. Di kode analyzer ICMP, kunci koneksinya memakai tipe ICMP sebagai "port" originator dan tipe pasangannya sebagai "port" responder [S11], sehingga echo request tampil dengan `id.orig_p` 8 dan `id.resp_p` 0 (echo reply). Dengan begitu `orig_bytes` dan `resp_bytes` per pasangan alamat bisa dijumlahkan seperti TCP; ping biasa menghasilkan byte simetris dan kecil, sedangkan ICMP yang membawa data menghasilkan payload besar dan sering asimetris. Arti persis `orig_bytes` untuk ICMP (payload ICMP saja atau termasuk header) perlu dicek dengan ping berukuran diketahui di lab (bagian 3).

Jawaban awal untuk pertanyaan kelima Dimas: SYN yang ditolak firewall tidak membawa data, karena tidak ada satu byte payload pun yang bisa dikirim sebelum handshake selesai; yang dibuktikan alert itu adalah niat dan proses yang mencoba, bukan kebocoran. FTP dari `jkt-recon01` sebaliknya pasti membawa data, karena `STOR` adalah unggahan; pertanyaannya bukan "ada yang keluar" tetapi "apakah yang keluar memang boleh keluar". Keduanya dibuktikan di bagian 2.6.

### 1.6 Membedakan exfiltration dari unggahan sah

Pertanyaan ketiga Dimas paling sering muncul di rapat: `JKT-WS-2055` mengunggah 6,4 GB ke OneDrive sepanjang malam (`SOC-2027-0657`), lima kali lebih banyak daripada `JKT-WS-2057`, dengan PCR yang sama-sama mendekati 1. Kenapa yang kecil insiden dan yang besar bukan?

Karena ukuran dan rasio adalah sifat trafik, sedangkan exfiltration adalah sifat izin. Banyak unggahan sah yang besar:

| Upload sah | Pola | Yang membuktikan sah |
|---|---|---|
| Backup ke cloud | Upload besar terjadwal ke penyedia dikenal | Jadwal job, akun layanan, tujuan di kontrak |
| Sync (Drive, OneDrive, Dropbox) | Upload berkala ke cloud akun perusahaan | Tenant perusahaan, proses klien sync resmi |
| Software/log shipping | Kirim log/telemetry ke vendor | Agent terdaftar di inventaris, prevalence tinggi |
| Transfer bisnis sah | Kirim data ke mitra | Perjanjian, tiket permintaan, akun yang disepakati |
| Migrasi data | Upload sekali jalan bervolume sangat besar | Change ticket dengan jadwal dan daftar host |

Pembedaan memakai lima pertanyaan, dan semuanya bisa dijawab dari data yang dimiliki PT JAB:

1. **Tujuan milik siapa.** Penyedia yang sama bisa berarti dua hal. OneDrive for Business tinggal di bawah `*.sharepoint.com` dengan nama host per tenant (`<tenant>-my.sharepoint.com`), sedangkan OneDrive pribadi memakai domain konsumen seperti `onedrive.live.com` [S16]. SNI tenant PT JAB (`ptjab-my.sharepoint.com`, nama tenant fiktif) adalah bukti kuat; SNI ke domain konsumen membuka pertanyaan akun pribadi. Hati-hati dengan domain campuran: daftar endpoint Microsoft 365 menempatkan `storage.live.com` di kelompok OneDrive for Business untuk fungsi dukungan dan API [S16], jadi kemunculannya sendiri belum berarti akun pribadi.
2. **Sejak kapan dihubungi.** First seen tujuan untuk host itu dan untuk seluruh PT JAB. `up.simpanfile.example` tidak pernah muncul di log proxy 30 hari sebelum Selasa; tenant OneDrive PT JAB dihubungi ratusan host setiap hari.
3. **Berapa host lain melakukan hal yang sama.** Prevalence (Day 11 bagian 1.7). Satu host mengunggah ke tujuan langka adalah pola yang berbeda dari 24 host satu departemen mengunggah ke tenant yang sama pada malam yang sama.
4. **Proses apa yang mengirim.** Jaringan hanya memberi petunjuk (JA4 klien bila di-splice, User-Agent bila di-bump); kepastian datang dari EDR: `OneDrive.exe` bertanda tangan Microsoft berbeda dari executable tanpa tanda tangan di `C:\ProgramData`.
5. **Apakah ada perubahan yang tercatat.** Change ticket, permintaan mitra, atau jadwal backup. Bila ada, cocokkan host, jam, dan volumenya; tiket yang menyebut "migrasi Legal gelombang 3, Selasa malam" tidak menjelaskan unggahan dari lantai Sales.

Kontrol pencegahan juga perlu dikenal karena memengaruhi apa yang mungkin terjadi. Tenant restrictions v2 di Microsoft Entra membatasi akun eksternal (termasuk akun Microsoft pribadi) yang boleh dipakai dari jaringan dan perangkat organisasi [S17]. Lewat proxy, kebijakan itu hanya berlaku di authentication plane (proxy menyisipkan header `sec-Restrict-Tenant-Access-Policy`, sehingga perlu inspeksi TLS ke endpoint login); perlindungan data plane butuh sinyal dari sisi klien, misalnya lewat Group Policy Windows [S17]. Dokumentasinya juga menyebut batas: pemblokiran akses anonim ke OneDrive konsumen belum didukung, dan solusi sementaranya adalah memblokir `onedrive.live.com` di proxy [S17]. Apakah PT JAB sudah menerapkannya perlu dicek ke tim Agung; untuk analisis Day ini cukup dicatat bahwa tanpa kontrol itu, unggahan ke akun pribadi di penyedia yang sama secara teknis mungkin.

Jawaban untuk pertanyaan ketiga Dimas, yang dibuktikan di bagian 2.4: `JKT-WS-2055` lolos kelima pertanyaan, `JKT-WS-2057` gagal di semuanya. Volume besar sendiri bukan bukti, dan volume kecil bukan jaminan aman.

### 1.7 Low and slow, pecahan berukuran tetap, dan evasion

Pertanyaan keenam Dimas ("apa yang sama sekali tidak bisa kita lihat") separuhnya dijawab di sini. Alert `SOC-2027-0655` menyala karena `JKT-WS-2057` mengirim 538 MB dalam 15 menit. Penyerang yang lebih sabar tidak akan menyalakannya.

Penyerang canggih menghindari deteksi volume dengan exfiltration pelan: sedikit data tiap kali, tersebar waktu, agar tak ada lonjakan. Ini sulit dari volume sesaat; deteksi butuh agregasi jangka panjang (total keluar ke satu tujuan selama berminggu) dan baseline. Teknik lain: memecah data, mengenkripsi atau mengompres agar ukuran tak jelas, memakai banyak tujuan. Deteksi jadi probabilistik dan bergantung korelasi, bukan satu ambang.

Hitungan sederhana menunjukkan kenapa ambang tidak cukup. Ambang saved search PT JAB adalah 500 MB per host dan tujuan per 15 menit. Arsip 1,45 GB yang dibuat di `JKT-WS-2057` (bagian 2.8) bisa dikirim di bawah ambang itu dengan sekitar 483 MB per 15 menit selama 45 menit, atau dengan 20 MB per jam dalam tiga hari, yang di grafik utilisasi link 1 Gbps tidak lebih dari garis datar. Ambang yang lebih rendah langsung menabrak unggahan sah (bagian 1.6). Karena itu PT JAB membutuhkan dua lapis: ambang per jendela pendek untuk yang tergesa-gesa, dan agregasi harian atau mingguan per host dan tujuan (dengan flow 13 bulan sebagai baseline) untuk yang sabar.

Tiga bentuk evasion yang perlu dikenali di data:

- **Pecahan berukuran tetap (T1030).** Data dipotong menjadi bagian sama besar, sering satu pecahan per koneksi. ATT&CK menuliskan analitik untuk pola ini sebagai koneksi keluar dengan muatan berukuran seragam pada interval yang teratur [S8]. Di `INC-2027-071`, 78 koneksi berturut-turut membawa `orig_bytes` yang selisihnya hanya 34 byte (bagian 2.3): keseragaman seperti itu adalah tanda mesin, bukan orang.
- **Banyak koneksi kecil.** Tim engineering Salesforce mencatat bahwa exfiltration yang dipecah ke banyak koneksi paralel bisa lolos dari ambang per koneksi dan dari PCR; deteksi mereka menjumlahkan byte dari koneksi yang berbagi alamat sumber, alamat tujuan, dan port tujuan tetapi berbeda port sumber [S20]. Penjumlahan per pasangan host dan tujuan di bagian 2.1 mengikuti logika yang sama.
- **Banyak tujuan atau layanan populer.** Membagi kiriman ke beberapa akun penyimpanan, atau ke layanan yang dipakai semua orang, membuat setiap tujuan terlihat kecil atau wajar. Agregasi per host (semua tujuan) melengkapi agregasi per pasangan.

Yang tidak terlihat sama sekali dari sensor PT JAB: trafik laptop di luar kantor, host di switch akses yang sama (Day 01 bagian 1.5), kantor cabang yang tidak lewat TAP Jakarta, dan data yang keluar lewat media fisik atau layar. Untuk `JKT-WS-2057`, PC meja yang tidak pernah dibawa keluar, hanya butir terakhir yang tetap terbuka.

### 1.8 Isi terenkripsi: dari byte TLS ke byte data, dan batas keyakinan

Sisa pertanyaan keenam Dimas ("seberapa yakin kita soal isinya") dan pertanyaan kedelapan (kiriman 2,1 MB `JKT-WS-2052`) bergantung pada satu keterampilan: mengubah byte yang terukur di jaringan menjadi perkiraan byte data, dan menulis batasnya.

`orig_bytes` di Zeek adalah byte payload TCP [S11], bukan byte file. Di dalamnya ada beberapa lapis tambahan:

| Lapis | Ukuran kira-kira | Asal angka |
|---|---|---|
| Permintaan `CONNECT` ke proxy (hanya hop core) | 150 sampai 300 byte | Teks HTTP polos ke proxy |
| Handshake TLS dari klien (ClientHello, Finished) | 500 sampai 2.000 byte | Tergantung ekstensi dan sertifikat klien |
| Header HTTP di dalam TLS | Ratusan byte sampai beberapa KB | Header permintaan, boundary multipart |
| Overhead per record TLS 1.3 | 22 byte per record berisi penuh: header 5 byte, tipe konten 1 byte, tag AEAD 16 byte | RFC 9846 bagian 5.1 dan 5.2 [S13] |

RFC 9846 membatasi isi satu record pada 2^14 (16.384) byte dan menyebut record terenkripsi tidak boleh melebihi 2^14 + 256 byte [S13]; header record 5 byte dan tipe konten di dalam ciphertext 1 byte [S13]. Tag 16 byte berlaku untuk cipher AEAD yang umum (AES-GCM dan ChaCha20-Poly1305); padding opsional bisa menambah. Untuk unggahan besar, overhead itu sekitar 0,13% (22 dari 16.384), cukup kecil sehingga byte TLS adalah perkiraan yang baik untuk byte data, dan cukup teratur sehingga bisa dikurangkan.

Contoh hitung untuk satu pecahan `JKT-WS-2057`: bila datanya 16 MiB (16.777.216 byte), dibutuhkan 16.777.216 / 16.384 = 1.024 record, dengan overhead 1.024 x 22 = 22.528 byte. Ditambah sekitar 2.150 byte untuk `CONNECT`, handshake, dan header HTTP, hasilnya sekitar 16.801.900 byte, sama dengan `orig_bytes` yang tercatat (bagian 2.3). Hitungan balik seperti ini yang membuat angka di laporan bisa dipertahankan: "sekitar 1,31 GB data aplikasi keluar", bukan "1,31 GB file pelanggan".

Tingkat keyakinan untuk setiap klaim sebaiknya ditulis eksplisit:

| Klaim | Dari mana | Keyakinan |
|---|---|---|
| Ada data keluar dari host X ke tujuan Y pada jam Z | Zeek hop core dan hop egress, flow router DC, log proxy | Tinggi bila dua sumber independen cocok |
| Jumlahnya sekitar N byte | Penjumlahan `orig_bytes`, dikoreksi overhead | Tinggi untuk orde besar; meleset beberapa persen bila ada retransmisi atau koneksi besar [S11] |
| Datanya berasal dari arsip A | Waktu dan ukuran cocok dengan jejak host | Sedang; butuh EDR atau forensik disk |
| Isinya dokumen D | Hanya bila arsip ditemukan, atau trafik polos, atau dekripsi | Tidak bisa dari metadata saja |

Yang sama sekali tidak terlihat dari TLS adalah isi, nama file, dan apakah data dikompres atau dienkripsi sebelum dikirim. Kompresi membuat byte di jaringan lebih kecil dari data aslinya: 1,45 GB arsip bisa berasal dari 2 GB dokumen. Laporan harus menyebut angka yang diukur (byte keluar) dan, terpisah, perkiraan data asli bila ada bukti host.

### 1.9 Peta ATT&CK untuk exfiltration

Pertanyaan ketujuh Dimas meminta label untuk laporan. ATT&CK mengelompokkan teknik ini di taktik Exfiltration (TA0010) [S1]. Yang paling relevan untuk analis jaringan [S4]:

| Teknik | Inti | Yang terlihat di jaringan |
|---|---|---|
| T1041 Exfiltration Over C2 Channel | Data dikirim lewat saluran C2 yang sudah ada | Koneksi ke tujuan beacon yang tiba-tiba membawa `orig_bytes` jauh lebih besar dari check-in biasa |
| T1048 Exfiltration Over Alternative Protocol | Data dikirim lewat protokol lain dari C2 (FTP, DNS, SMTP, HTTP polos, protokol terenkripsi lain) | Protokol atau tujuan yang tidak dipakai host itu sebelumnya |
| T1048.003 Exfiltration Over Unencrypted Non-C2 Protocol | Data dikirim lewat protokol polos, sering disandikan (base64, subdomain DNS) | Nama DNS panjang dan unik, FTP `STOR` ke tujuan tak dikenal |
| T1567 Exfiltration Over Web Service | Data diunggah ke layanan web sah, misalnya penyimpanan cloud (T1567.002) | SNI ke penyedia cloud terkenal dengan upload besar; sulit dibedakan dari pemakaian sah |
| T1029 Scheduled Transfer | Pengiriman dijadwalkan pada jam tertentu | Upload berulang pada jam yang sama, sering di luar jam kerja |
| T1030 Data Transfer Size Limits | Data dipecah ke pecahan berukuran tetap | Banyak koneksi dengan `orig_bytes` hampir sama, misalnya tiap 16 MiB |
| T1020 Automated Exfiltration | Pengiriman otomatis tanpa operator | Pola mesin: ritme tetap, tanpa jeda manusiawi |
| T1700 AI-Enabled Exfiltration | Agent AI perusahaan diarahkan (misalnya lewat prompt injection) untuk memindahkan data dengan alat yang sudah diizinkan | Trafik yang tampak seperti pemakaian sah agent; nyaris tidak bisa dibedakan dari jaringan saja |

Dua teknik di tahap sebelumnya juga perlu dikenali karena jejaknya di host: T1074 Data Staged (data dikumpulkan di satu folder) dan T1560 Archive Collected Data (data diarsip atau dikompres sebelum dikirim). Bila data diambil dari file share, T1039 Data from Network Shared Drive melengkapi rantainya, dan bagian ini justru terlihat di SPAN core (bagian 1.10).

Analitik deteksi ATT&CK v20 untuk teknik-teknik ini memakai bahasa yang dekat dengan Day ini. Untuk T1041, analitiknya menandai volume keluar yang tidak cocok dengan kebiasaan proses dan rasio byte yang abnormal ke tujuan langka, setelah akses ke data [S9]. Untuk T1567.002, unggahan HTTPS `POST` atau `PUT` ke domain penyimpanan cloud, terutama setelah pembacaan file sensitif atau kompresi, dengan alat seperti rclone dan curl disebut namanya [S6]. Untuk T1048.003, penyandian data di subdomain DNS dan transfer konfigurasi perangkat jaringan lewat FTP atau TFTP [S7]. T1700 adalah teknik baru di v20, versi 1.0, yang menggambarkan agent AI perusahaan dipakai memindahkan data keluar lewat alat yang sudah ia punya [S10]; PT JAB belum memakai agent seperti itu, tetapi teknik ini mengingatkan bahwa "alat yang diizinkan" bisa menjadi saluran.

Cara memberi label yang jujur: label didukung data jaringan (misalnya T1567.002 bila unggahan besar ke layanan penyimpanan terukur), label dugaan menunggu host (misalnya T1560.001 sampai arsip dan alatnya ditemukan), dan percobaan yang gagal disebut sebagai percobaan, bukan teknik yang berhasil.

### 1.10 Staging, rantai intrusi, dan dari sinyal ke dampak

Bagian terakhir pertanyaan ketujuh Dimas ("apa yang perlu diteruskan ke DPO") hanya bisa dijawab bila sinyal jaringan disambungkan ke data yang diambil.

Exfiltration sering didahului staging: penyerang mengumpulkan dan memaketkan data (arsip, kompres) sebelum mengirim. Di jaringan, staging mungkin tak terlihat (lokal di host), tetapi jejaknya ada di endpoint: berkas arsip besar yang baru dibuat (`.zip`, `.7z`, `.rar`) di folder sementara, proses pengarsip yang dijalankan dengan banyak berkas sebagai argumen, atau akses baca massal ke file share dalam waktu singkat. Bila staging terjadi di file server lewat SMB, sebagian jejaknya terlihat di jaringan sebagai banyak operasi baca dari satu klien (Day 19). Di PT JAB, file server ada di data center, sehingga pembacaan dari workstation lewat core switch terlihat di SPAN core sebagai `resp_bytes` besar dari port 445; lateral movement antar workstation di switch akses yang sama tetap tidak terlihat. Menghubungkan sinyal jaringan (transfer keluar) dengan jejak host (staging) memperkuat kesimpulan dan menunjukkan apa yang diambil. Urutan khas: akses awal, C2 (Day 11), pengumpulan/staging, exfiltration.

```
 akses awal --> C2 (Day 11) --> pengumpulan --> staging --> exfiltration

 bukti jaringan per tahap:
   akses awal    sedikit, tergantung vektor
   C2            beacon, ukuran check-in seragam (Day 11)
   pengumpulan   SMB baca: resp_bytes besar dari port 445 (SPAN core)
   staging       tidak ada; lokal di host (EDR, forensik disk)
   exfiltration  orig_bytes, nama DNS, FTP STOR (hop core + hop egress)
```

Pertanyaan kunci exfiltration adalah "apa dan berapa banyak yang keluar". Untuk menjawab:

- Ukur total volume keluar per tujuan dan periode (dampak kuantitatif).
- Bila polos atau bisa didekripsi lab, identifikasi jenis data (`files.log`, Export Objects); bila terenkripsi, simpulkan dari volume dan konteks host.
- Korelasi dengan staging host untuk tahu data apa.
- Nyatakan keyakinan dan batas: metadata memberi volume/tujuan; isi butuh pcap polos atau bukti host.

Pisahkan "data keluar dalam jumlah besar ke tujuan mencurigakan" (sinyal) dari "data sensitif X dicuri" (kesimpulan yang butuh identifikasi isi/host).

Yang diteruskan ke DPO bukan kesimpulan teknis, tetapi bahan keputusan. Agus Setiawan sebagai DPO dan Legal (Day 01 bagian 1.7) yang memutuskan apakah suatu kejadian adalah kegagalan pelindungan data pribadi yang wajib diberitahukan. Bahan dari jaringan adalah: kapan pertama dan terakhir data keluar, berapa byte, ke mana (domain, IP, negara bila diketahui), lewat saluran apa, apakah sudah dihentikan dan sejak kapan, dan dari share atau folder mana data kemungkinan berasal beserta jenis data pribadi yang biasa ada di sana menurut pemilik datanya. Tulis juga apa yang belum diketahui. Waktu menjadi penting: bila kewajiban pemberitahuan berlaku, hitungannya berjalan sejak organisasi mengetahui, jadi laporan yang menunggu kepastian isi sampai berhari-hari bisa merugikan.

## 2. Contoh dan langkah praktis: mengukur `INC-2027-071` dari data sensor

Semua keluaran di bagian ini adalah keluaran ilustrasi untuk organisasi fiktif PT JAB, bukan hasil eksekusi nyata. Asumsi lingkungan: log Zeek JSON di Splunk index `zeek` (sourcetype `bro:conn:json` dan `bro:http:json` terkonfirmasi; `bro:dns:json`, `bro:files:json`, dan `bro:ftp:json` mengikuti pola yang sama dan perlu divalidasi dengan `| metadata type=sourcetypes index=zeek`), arsip Zeek di `/opt/zeek/logs/<tanggal UTC>/` yang disalin ke folder kasus `/cases/INC-2027-071/zeek/` di `jkt-nsm-ws01` (UTC), flow di `jkt-flow01` dengan jam WIB (`/flow/dc-rtr/` dan `/flow/jkt-edge/`, sudah dikoreksi sampling), log proxy di `index=proxy`, log resolver di `index=dns`, dan log `jkt-fw01` di `index=firewall`. Splunk menampilkan waktu dalam WIB. Perintah lama dari catatan versi sebelumnya dipertahankan dan ditempatkan di samping versi untuk data PT JAB.

### 2.1 Volume keluar per host dan tujuan di hop core

**Tujuan:** mengubah alert `SOC-2027-0655` menjadi angka per host dan tujuan yang bisa dipertanggungjawabkan, dan melihat apakah ada pasangan lain yang menonjol malam itu.

Perintah dari catatan lama, untuk `conn.log` TSV satu sensor tanpa proxy:

```
zeek-cut id.orig_h id.resp_h id.resp_p orig_bytes resp_bytes < conn.log | grep <host internal>
```

- `zeek-cut` mengambil kolom dari log TSV; `grep` menyaring baris yang memuat host internal.
- Jumlahkan `orig_bytes` per `id.resp_h` untuk host internal.
- Cara membaca: tujuan dengan `orig_bytes` total besar berarti banyak data dikirim host ke sana. Bandingkan baseline; lonjakan ke tujuan baru adalah kandidat exfil.

Keluaran ilustrasi (agregasi) dari catatan lama, untuk jaringan tanpa proxy:

```
dst               total_orig_bytes
203.0.113.50      5,200,000,000   <- 5.2 GB keluar (anomali)
cloud-corp.example 80,000,000     <- backup sah dikenal
```

Di PT JAB, perintah itu menghasilkan jawaban yang salah tanpa pesan galat: di hop core, `id.resp_h` setiap koneksi web workstation adalah `10.20.3.60` (proxy), dan di hop egress, `id.orig_h` adalah proxy. Tujuan diambil dari baris `CONNECT` di `http.log` yang berbagi `uid` dengan koneksinya (Day 08 bagian 1.3). Ini saved search yang menyalakan `SOC-2027-0655`:

```
index=zeek earliest=-15m@m latest=@m
    ((sourcetype=bro:http:json method=CONNECT)
     OR (sourcetype=bro:conn:json "id.resp_h"="10.20.3.60" "id.resp_p"=3128))
| stats values(uri) AS tujuan sum(orig_bytes) AS kirim sum(resp_bytes) AS terima
        values(id.orig_h) AS src BY uid
| where isnotnull(tujuan) AND kirim>0
| stats sum(kirim) AS kirim sum(terima) AS terima count AS koneksi BY src tujuan
| eval pcr=round((kirim-terima)/(kirim+terima),4)
| where kirim > 500000000
```

Penjelasan tiap bagian:

- Baris pencarian mengambil dua jenis event: baris `CONNECT` (yang membawa nama tujuan di `uri`) dan baris `conn.log` workstation ke proxy (yang membawa byte). Keduanya punya `uid` yang sama untuk satu tunnel.
- `stats ... BY uid` pertama menyatukan keduanya per tunnel. `sum(orig_bytes)` aman karena baris `http.log` tidak punya field itu.
- `where isnotnull(tujuan)` membuang koneksi ke proxy yang bukan `CONNECT` (misalnya HTTP polos lewat proxy, yang punya `host` dan `uri` berbeda) dan tunnel yang baris `CONNECT`-nya jatuh di luar jendela.
- `stats ... BY src tujuan` kedua menjumlahkan semua tunnel per pasangan; ini yang menangkap pecahan dan koneksi paralel (bagian 1.7).
- `pcr` dihitung dari byte payload, sesuai definisi (bagian 1.3). Ambang 500 MB per 15 menit adalah pilihan program; ia sengaja tinggi supaya tidak menabrak sinkronisasi harian.

Keluaran ilustrasi saat alert menyala (jendela Selasa 21:00:00 sampai 21:14:59 WIB):

```
src            tujuan                        kirim        terima   koneksi  pcr
10.10.60.127   up.simpanfile.example:443     537660680    166693   32       0.9994
```

Untuk laporan, jendelanya diperlebar ke seluruh malam (Selasa 18:00 sampai Rabu 03:00) dan ambangnya diturunkan ke 50 MB supaya pasangan lain ikut terlihat:

```
src            tujuan                         kirim        terima      koneksi  pcr
10.10.60.125   ptjab-my.sharepoint.com:443    6412880512   198336511   1284     0.9400
10.10.60.127   up.simpanfile.example:443      1310547961   406298      78       0.9994
10.10.60.126   ptjab-my.sharepoint.com:443    388120455    41870233    211      0.8052
```

**Cara membaca hasil:** tiga pasangan melewati 50 MB malam itu. `10.10.60.127` (`JKT-WS-2057`) mengirim 1.310.547.961 byte, sekitar 1,31 GB, ke satu tujuan dalam 78 tunnel. `10.10.60.125` (`JKT-WS-2055`) dan `10.10.60.126` (`JKT-WS-2056`) mengirim ke tenant OneDrive PT JAB; yang pertama menyalakan `SOC-2027-0657` karena 15 menit pertamanya melewati 500 MB, yang kedua tidak pernah melewati ambang. Angka "538 MB dalam 15 menit" di alert adalah 537.660.680 byte payload TCP di hop core, termasuk header `CONNECT`, handshake, dan overhead TLS; byte data aplikasi sedikit lebih kecil (bagian 1.8). Ambang yang dipakai bersifat per jendela, jadi `JKT-WS-2057` memicu alert hanya sekali walaupun dua jendela berturut-turut melewati ambang (21:00 dan 21:15; jendela 21:30 hanya 168 MB) (`SOC-2027-0655` di-throttle per pasangan selama 60 menit).

**Variasi:** di `jkt-nsm-ws01`, versi `jq` untuk arsip JSON menggabungkan dua log per `uid`:

```
cd /cases/INC-2027-071/zeek/2027-05-25
jq -r 'select(.method=="CONNECT") | [.uid, ."id.orig_h", .uri] | @tsv' http.*.log | sort > connect.tsv
jq -r 'select(."id.resp_h"=="10.20.3.60" and ."id.resp_p"==3128)
       | [.uid, .orig_bytes // 0, .resp_bytes // 0] | @tsv' conn.*.log | sort > tunnel.tsv
join -t $'\t' connect.tsv tunnel.tsv \
  | awk -F'\t' '{k=$2" "$3; o[k]+=$4; r[k]+=$5; n[k]++}
                END{for(k in o) printf "%s %d %d %d\n", k, o[k], r[k], n[k]}' | sort -k3,3nr | head
```

Folder tanggal memakai UTC, jadi malam Selasa 18:00 sampai Rabu 03:00 WIB berada di folder 2027-05-25 (11:00 sampai 20:00 UTC); untuk jendela lain, periksa batas tanggal UTC lebih dulu. `// 0` mengganti field yang tidak ada (koneksi tanpa payload) dengan nol supaya penjumlahan tidak gagal.

**Kapan gagal:** bila sensor kehilangan paket, `orig_bytes` dari sequence number bisa melebihi byte yang benar-benar lewat; periksa `missed_bytes` dan notice capture loss (Day 08). Koneksi yang masih terbuka belum ditulis ke `conn.log`, sehingga unggahan panjang baru muncul setelah selesai. Dan pola ini hanya menangkap workstation di Jakarta yang lewat SPAN core; unggahan langsung dari server yang punya NAT sendiri harus dicari di hop egress dengan `id.orig_h` server itu.

### 2.2 Rasio arah, PCR, dan flow sebagai bukti kedua

**Tujuan:** memastikan angka Zeek dengan sumber yang independen, dan melihat apakah `JKT-WS-2057` pernah melakukan hal serupa sebelum sensor Zeek hidup.

Perintah dari catatan lama:

```
nfdump -r flows.nfcapd 'src net 10.0.0.0/8 and not dst net 10.0.0.0/8' -s ip/bytes
```

- `-r` membaca file flow; filter memilih flow dari alamat internal ke tujuan di luar `10.0.0.0/8`; `-s ip/bytes` membuat statistik alamat diurut menurut byte. Cek sintaks di versi nfdump-mu [S12].
- Cara membaca: normalnya host mengunduh lebih banyak dari mengunggah; rasio terbalik (upload jauh lebih besar dari download) ke satu tujuan adalah sinyal exfil. Flow jangka panjang menangkap low and slow.

Di PT JAB, filter "tujuan di luar `10.0.0.0/8`" tidak menemukan apa-apa untuk workstation, karena tujuannya proxy. Flow router data center (1:1) dibaca per arah antara workstation dan proxy, lalu flow edge (1:1000) untuk sisi internet:

```
# arah kirim: workstation ke proxy, malam Selasa (jam WIB)
nfdump -r /flow/dc-rtr/2027/05/25/ -t 2027/05/25.21:00:00-2027/05/25.21:40:00 -N \
  -A srcip,dstip 'src ip 10.10.60.127 and dst ip 10.20.3.60 and dst port 3128'
# arah terima: proxy ke workstation
nfdump -r /flow/dc-rtr/2027/05/25/ -t 2027/05/25.21:00:00-2027/05/25.21:40:00 -N \
  -A srcip,dstip 'src ip 10.20.3.60 and src port 3128 and dst ip 10.10.60.127'
# sisi internet: NAT proxy ke tujuan, sudah dikoreksi sampling
nfdump -r /flow/jkt-edge/2027/05/25/ -t 2027/05/25.21:00:00-2027/05/25.21:40:00 -N \
  -A srcip,dstip 'src ip 198.51.100.120 and dst ip 203.0.113.182'
```

- `-r` dengan direktori membaca semua file di dalamnya (Day 10); `-t` membatasi ke jendela waktu, dalam jam WIB karena `jkt-flow01` memakai WIB.
- `-A srcip,dstip` mengagregasi semua record yang alamat sumber dan tujuannya sama, jadi timeout aktif 300 detik dan port sumber yang berganti tidak memecah hasil.
- `-N` menampilkan angka penuh tanpa satuan K/M/G, supaya bisa dibandingkan dengan Zeek.

Keluaran ilustrasi (kolom dipersingkat):

```
Date first seen          Duration  Src IP Addr     Dst IP Addr     Packets    Bytes
2027-05-25 21:02:14.031  1918.886  10.10.60.127    10.20.3.60      905112     1357613785
2027-05-25 21:02:14.032  1918.884  10.20.3.60      10.10.60.127    453180     23971658
2027-05-25 21:02:14.290  1918.511  198.51.100.120  203.0.113.182   911000     1366416000
```

**Cara membaca hasil:** router data center mencatat 1.357.613.785 byte level IP dari `JKT-WS-2057` ke proxy dalam 1.918 detik. Selisihnya dengan Zeek (1.310.547.961 byte payload) adalah 47.065.824 byte, yaitu 905.112 paket x 52 byte header IP dan TCP (dengan opsi timestamp): dua sumber independen cocok setelah header dihitung. Arah sebaliknya hanya 23,97 MB, hampir semuanya paket ACK. PCR yang dihitung dari byte flow menjadi 0,9653, lebih rendah dari PCR Zeek 0,9994, karena header ACK ikut terhitung; ini alasan definisi PCR memakai byte aplikasi [S21]. Flow edge sesudah koreksi menunjukkan 1,366 GB dari NAT proxy `198.51.100.120` ke `203.0.113.182`, selisih 0,65% dari angka router data center, jauh di dalam rentang galat sampling 1:1000 untuk sekitar 900 paket tersampel (Day 10 bagian 2.2). Laju rata-ratanya 5,46 Mbps, sangat rata selama setengah jam: unggahan yang dibatasi lajunya oleh alat, bukan oleh link.

Pertanyaan kedua flow adalah riwayat. Flow router data center disimpan 13 bulan, sehingga baseline `JKT-WS-2057` bisa dibangun jauh sebelum Zeek hidup:

```
nfdump -r /flow/dc-rtr/2027/ -N -A srcip,dstip \
  -t 2027/02/01.00:00:00-2027/05/25.20:59:59 'src ip 10.10.60.127 and dst ip 10.20.3.60'
```

Hasil ilustrasi: total kirim ke proxy 1,62 GB selama hampir empat bulan, atau rata-rata sekitar 14 MB per hari, dengan hari tertinggi 61 MB. Malam Selasa, host yang sama mengirim 1,36 GB dalam 32 menit, hampir sama dengan total empat bulan sebelumnya. Rasio seperti ini lebih meyakinkan untuk laporan direksi daripada ambang absolut.

**Variasi:** untuk mencari host lain yang mengunggah ke tujuan yang sama sebelum alert ada, jalankan agregasi flow edge per tujuan (`dst ip 203.0.113.182`) untuk 30 hari terakhir. Di PT JAB, flow edge untuk web hanya menunjukkan NAT proxy, sehingga jawabannya "ada atau tidak ada", bukan "host mana"; host diambil dari log proxy (bagian 2.3).

**Kapan gagal:** flow edge tersampel bisa melewatkan unggahan kecil sepenuhnya (Day 10 bagian 2.2). Router yang mengekspor dua kali untuk satu koneksi (ingress dan egress) menggandakan angka bila tidak difilter per interface. Dan flow tidak membawa nama domain; tanpa Zeek atau log proxy, `203.0.113.182` hanya alamat.

### 2.3 Waktu, pecahan seragam, dan apakah blokir proxy menghentikannya

**Tujuan:** menyusun urutan waktu unggahan `JKT-WS-2057`, menguji pola pecahan berukuran tetap, dan membuktikan apa yang terjadi setelah `up.simpanfile.example` diblokir di `jkt-proxy01` pukul 21:34:10.

Perintah dari catatan lama:

```
zeek-cut ts id.orig_h id.resp_h orig_bytes < conn.log | grep <dst>
```

- Cara membaca: transfer besar di luar jam kerja atau pada jam tak biasa untuk host itu memperkuat kecurigaan; korelasikan dengan baseline aktivitas host.

Untuk PT JAB, `<dst>` di hop core adalah proxy, jadi daftar tunnel diambil per `uid` yang sudah tergabung di bagian 2.1, lalu dibandingkan dengan log proxy:

```
index=zeek sourcetype=bro:conn:json "id.orig_h"="10.10.60.127" "id.resp_h"="10.20.3.60"
    earliest="05/25/2027:20:00:00" latest="05/25/2027:23:59:59"
| table _time uid orig_bytes resp_bytes duration conn_state
| sort 0 _time

index=proxy src=10.10.60.127 host="*simpanfile.example*"
    earliest="05/25/2027:20:00:00" latest="05/25/2027:23:59:59"
| table _time method host status action bytes category
```

Keluaran ilustrasi (sebagian baris):

```
_time                    uid                 orig_bytes  resp_bytes  duration  conn_state
2027-05-25 21:02:14.000  C7mQ2b1xYk3aVt9Fe1  16801909    5202        24.36     SF
2027-05-25 21:02:38.630  CuX4p0a8Kd2LmW7nB3  16801888    5209        24.10     SF
...
2027-05-25 21:33:24.050  Cq8Hn3ZsV0eRt6Yw42  16801914    5204        24.12     SF
2027-05-25 21:33:48.710  CbT1oZ5mW9qPa2Xc87  16801891    5195        24.18     SF
2027-05-25 21:34:15.204  Cv2Ld7Qe1Rn8Ks3Ua5  287         3951        0.01      SF
2027-05-25 21:34:45.611  CzP0w6Ta4Xm2Hb9Ln1  287         3951        0.01      SF
2027-05-25 21:35:45.917  Ck5Fr8Ny3Qd1Ve7Js0  287         3951        0.01      SF

_time                 method   host                       status  action   bytes  category
2027-05-25 21:02:14   CONNECT  up.simpanfile.example:443  200     TUNNEL   5163   Online Storage
...                   (78 baris CONNECT 200 sampai 21:33:48)
2027-05-25 21:34:15   CONNECT  up.simpanfile.example:443  403     DENIED   3912   Online Storage
2027-05-25 21:34:45   CONNECT  up.simpanfile.example:443  403     DENIED   3912   Online Storage
2027-05-25 21:35:45   CONNECT  up.simpanfile.example:443  403     DENIED   3912   Online Storage
```

**Cara membaca hasil:**

- **Pecahan seragam.** Ke-78 tunnel membawa `orig_bytes` antara 16.801.880 dan 16.801.914 byte, selisih maksimum 34 byte, dan setiap tunnel dimulai 24,5 sampai 24,7 detik setelah yang sebelumnya (median 24,62 detik, CV 0,002). Hitungan di bagian 1.8 menunjukkan isi tiap tunnel adalah 16 MiB data ditambah overhead: alat memotong data menjadi pecahan 16 MiB dan mengirim satu pecahan per koneksi, dengan laju yang dibatasi. Ini pola T1030 yang dijelaskan ATT&CK [S8], dan juga pola mesin T1020.
- **Total.** 78 pecahan x 16.777.216 byte = 1.308.622.848 byte data aplikasi, sekitar 1,31 GB, dikirim antara 21:02:14 dan 21:34:12 WIB.
- **Blokir.** Kategori "Online Storage" termasuk kategori yang di-splice, jadi proxy tidak melihat URL atau method di dalam tunnel. Kolom `bytes` di log proxy adalah byte yang dikirim proxy ke klien (format native Squid mencatat `%<st`, ukuran balasan [S15]), sehingga 78 unggahan 16 MB tercatat sebagai sekitar 5 KB masing-masing. Inilah alasan alert dibuat di Zeek, bukan di proxy. Aturan blokir dipasang 21:34:10. Tunnel ke-78 sudah berjalan sejak 21:33:48 dan selesai 21:34:12, dua detik setelah blokir: blokir proxy berlaku untuk `CONNECT` baru, bukan tunnel yang sudah terbuka. Setelah itu tiga `CONNECT` ditolak dengan 403 (21:34:15, 21:34:45, 21:35:45), masing-masing 287 byte keluar (hanya header `CONNECT`), lalu tidak ada lagi.
- **Apakah blokir menghentikannya.** Untuk saluran itu, ya: setelah 21:34:12 tidak ada satu byte pun ke `up.simpanfile.example` dari host mana pun, di hop core, log proxy, maupun flow edge ke `203.0.113.182`. Untuk penyerangnya, tidak: 67 menit kemudian host yang sama mencoba jalur langsung (bagian 2.6), dan tengah malam beralih ke DNS (bagian 2.5).

**Variasi:** bila pecahan dikirim paralel, urutkan tunnel menurut waktu mulai dan hitung jumlah tunnel yang tumpang tindih; laju per tunnel turun tetapi total per pasangan tetap. Untuk pecahan dengan ukuran yang diacak, gunakan histogram `orig_bytes` dibulatkan ke 1 MB; ukuran acak dalam rentang sempit tetap menonjol dibanding unggahan manusia yang ukurannya mengikuti ukuran file.

**Kapan gagal:** ukuran file asli yang kebetulan seragam (misalnya segmen video dari kamera) menghasilkan pola yang sama; prosesnya yang memutuskan. Bila alat memakai satu koneksi panjang untuk semua pecahan, keseragaman tidak terlihat di `conn.log`, hanya di pcap sebagai jeda antar ledakan record.

### 2.4 Membedakan unggahan OneDrive `JKT-WS-2055` dari exfiltration

**Tujuan:** menjawab pertanyaan ketiga Dimas dengan bukti, bukan dengan rasa: kenapa 6,4 GB ke OneDrive dari `JKT-WS-2055` (`10.10.60.125`, pengguna `lestari.wulandari`, Legal) ditutup sebagai jinak, sedangkan 1,31 GB dari `JKT-WS-2057` menjadi insiden.

Filter dari catatan lama, untuk pcap egress di Wireshark:

```
tls.handshake.extensions_server_name contains "<penyedia-cloud-perusahaan>"
```

- Cocokkan tujuan dengan penyedia dan akun cloud perusahaan yang dikenal dan jadwal backup; periksa reputasi tujuan asing.
- Cara membaca: upload ke akun cloud perusahaan yang terjadwal kemungkinan sah; upload ke penyimpanan pribadi atau asing tanpa otorisasi mencurigakan. Konteks akun, jadwal, dan reputasi memutuskan.

Untuk PT JAB, kategori Microsoft 365 di-splice, jadi SNI di pcap egress adalah milik klien asli dan filter itu bisa dipakai di pcap `jkt-pcap01` malam Selasa (masih dalam 72 jam). Versi yang lebih berguna mencari tenant SharePoint lain selain milik PT JAB, karena unggahan ke tenant organisasi lain adalah jalur exfiltration yang terlihat sah:

```
tls.handshake.extensions_server_name contains "sharepoint.com" && !(tls.handshake.extensions_server_name contains "ptjab")
```

Untuk skala seluruh kantor, prevalence tenant diambil dari `CONNECT` di hop core:

```
index=zeek sourcetype=bro:http:json method=CONNECT uri="*sharepoint.com:443"
    earliest="05/25/2027:18:00:00" latest="05/26/2027:06:00:00"
| rex field=uri "^(?<sp_host>[^:]+)"
| stats dc(id.orig_h) AS jumlah_host count AS tunnel BY sp_host
| sort - jumlah_host
```

Keluaran ilustrasi:

```
sp_host                          jumlah_host  tunnel
ptjab-my.sharepoint.com          412          29318
ptjab.sharepoint.com             388          11207
mitrakonsultan-my.sharepoint.com 2            14
```

Lalu kelima pertanyaan bagian 1.6 dijawab untuk kedua host:

| Pertanyaan | `JKT-WS-2055` ke OneDrive | `JKT-WS-2057` ke `up.simpanfile.example` |
|---|---|---|
| Tujuan milik siapa | Tenant PT JAB (`ptjab-my.sharepoint.com`), dikelola IT | Layanan penyimpanan konsumen, akun tidak diketahui |
| Sejak kapan dihubungi | Setiap hari kerja sejak OneDrive dipakai; host ini sejak migrasi gelombang 1 | Tidak pernah dalam 30 hari log proxy, dari host mana pun |
| Prevalence | 412 host ke tenant yang sama; 23 dari 24 host gelombang 3 mengunggah malam itu | Satu host |
| Proses (MDE) | `OneDrive.exe` bertanda tangan Microsoft | Executable tanpa tanda tangan di `C:\ProgramData\SysCache\` |
| Perubahan tercatat | `CHG-2027-0418`: migrasi home folder Legal gelombang 3, Selasa 22:00 sampai Rabu 06:00, 24 host termasuk `JKT-WS-2055` dan `JKT-WS-2056` | Tidak ada |
| Bentuk trafik | 1.284 tunnel berukuran beragam, PCR 0,94 (ada unduhan metadata dan delta) | 78 tunnel identik 16 MiB, PCR 0,9994, laju rata |

**Cara membaca hasil:** `SOC-2027-0657` ditutup Dwi pukul 23:40 sebagai jinak dengan tautan ke `CHG-2027-0418`, setelah volume per host di gelombang 3 dicocokkan dengan perkiraan ukuran home folder dari tim IT (selisih di bawah 10%). Baris ketiga di keluaran prevalence adalah temuan sampingan: dua host Legal membuka tenant konsultan hukum mitra. Itu kolaborasi yang lazim, tetapi tenant luar adalah tempat yang sah secara teknis untuk mengeluarkan data; volumenya kecil (14 tunnel) dan dicatat untuk ditinjau pemilik proses, bukan insiden. Apakah tenant restrictions v2 sudah diterapkan di PT JAB (bagian 1.6) menentukan apakah akun pribadi di Microsoft bisa dipakai dari kantor; cek ke tim Agung.

**Variasi:** untuk penyedia lain (Google Drive, Dropbox, Box), pola nama host per tenant berbeda dan tidak selalu membawa nama organisasi di SNI; pembeda akun lalu bergantung pada log proxy yang di-bump, CASB, atau log audit penyedia cloud.

**Kapan gagal:** change ticket yang terlalu umum ("migrasi OneDrive bulan Mei, semua departemen") tidak bisa membedakan unggahan sah dari penyalahgunaan di tenant yang sama, misalnya karyawan yang menyalin data departemen lain ke OneDrive-nya sebelum resign. Kasus seperti itu bukan pertanyaan jaringan lagi; log audit Microsoft 365 (siapa mengunggah file apa ke mana) adalah sumber yang tepat.

### 2.5 DNS `JKT-WS-2057`: apakah membawa data, dan berapa

**Tujuan:** menjawab pertanyaan keempat Dimas: apakah ribuan query TXT ke `kirimdata.example` (`SOC-2027-0658`) membawa data, dan berapa perkiraannya.

Field Wireshark dari catatan lama:

```
dns.qry.name
```

- Volume query sangat tinggi dengan nama panjang atau tersandi ke satu domain induk adalah tanda DNS tunneling untuk exfil (Day 05).
- Cara membaca: data keluar lewat DNS tampak sebagai banyak query besar, bukan transfer biasa; ukur volume kumulatif query ke domain itu.

Di pcap egress PT JAB, query itu bersumber resolver `10.20.2.53`, bukan workstation. Host asli ada di `dns.log` hop core. Saved search yang menyalakan alert berjalan setiap 30 menit (menit 20 dan 50) atas jendela 60 menit:

```
index=zeek sourcetype=bro:dns:json "id.orig_h"="10.10.60.127"
    earliest="05/26/2027:00:00:00" latest="05/26/2027:02:12:00"
| eval parent=replace(query, "^.*\.([^.]+\.[^.]+)$", "\1")
| eval sub=replace(query, "\.?[^.]+\.[^.]+$", "")
| eval sublen=len(sub)
| stats count dc(query) AS unik avg(sublen) AS rata max(sublen) AS maks
        values(qtype_name) AS tipe min(_time) AS awal max(_time) AS akhir BY parent
| eval rata=round(rata,0) | convert ctime(awal) ctime(akhir)
| sort - unik
```

Penjelasan tiap bagian:

- `parent` mengambil dua label terakhir sebagai domain induk. Untuk sufiks dua tingkat seperti `co.id`, cara ini memotong salah; untuk analisis serius pakai daftar public suffix (misalnya lewat URL Toolbox di Splunk).
- `sub` adalah semua label di depan domain induk; `sublen` panjangnya termasuk titik.
- `dc(query)` adalah jumlah nama unik; selisihnya dengan `count` adalah query yang diulang (retry atau cache miss biasa).

Keluaran ilustrasi:

```
parent              count  unik   rata  maks  tipe       awal                 akhir
kirimdata.example   43561  43012  179   200   TXT        05/26/2027 00:52:07  05/26/2027 02:11:46
microsoft.com       214    61     14    38    A AAAA     05/26/2027 00:00:41  05/26/2027 02:09:12
windows.com         188    23     11    27    A AAAA     05/26/2027 00:01:13  05/26/2027 02:10:55
...
```

Satu baris contoh dari `dns.log` (dipersingkat, label data dipotong):

```
query: hn4ga2lr...(63)...m5xq.b7k2c...(63)...a6p.q3d...(42)...zj.004817.x.kirimdata.example
qtype_name: TXT   rcode_name: NOERROR   answers: ["ok4817"]
```

Perkiraan isi dihitung dari struktur nama:

```
cd /cases/INC-2027-071/zeek/2027-05-25
jq -r 'select(."id.orig_h"=="10.10.60.127" and (.query|endswith(".kirimdata.example"))) | .query' dns.*.log \
  | sort -u > kirimdata_unik.txt
wc -l < kirimdata_unik.txt                                   # jumlah nama unik
cut -d. -f1-3 kirimdata_unik.txt | tr -d . | grep -c '[^a-z2-7]'   # karakter di luar alfabet base32
cut -d. -f4 kirimdata_unik.txt | sort -n | sed -n '1p;$p'          # nomor urut pertama dan terakhir
cut -d. -f1-3 kirimdata_unik.txt | tr -d . | awk '{s+=length($0)} END{print s/NR}'   # rata-rata karakter data
```

Penjelasan dan hasil ilustrasi:

- Jendela 00:52 sampai 02:12 WIB Rabu adalah 17:52 sampai 19:12 UTC Selasa, jadi berada di folder 2027-05-25.
- `wc -l` memberi 43.012 nama unik.
- Tiga label pertama adalah data; tidak ada karakter di luar `a-z` dan `2-7` (hasil `grep -c` 0), cocok dengan base32 huruf kecil.
- Label keempat adalah nomor urut enam digit dari `000001` sampai `043012`, tanpa celah: setiap pecahan yang dikirim tercatat, dan transfer dimulai dari awal pada 00:52:07, bukan lanjutan.
- Rata-rata 168 karakter data per query.

**Cara membaca hasil:** ya, DNS ini membawa data. Bentuknya cocok dengan tunneling di setiap ukuran bagian 1.4: 43.012 nama unik dalam 79 menit (9 per detik, atau 32.400 per jam), subdomain rata-rata 179 dan maksimum 200 karakter (tiga label data 63 karakter ditambah nomor urut dan label `x`), entropi label 4,53 sampai 4,72, dan 98,75% query host itu bertipe TXT (43.561 dari 44.112). Perkiraan data yang keluar: 43.012 x 168 x 5 / 8 = 4.516.260 byte, sekitar 4,5 MB, dengan asumsi base32 tanpa kompresi tambahan. Bila ternyata hex, angkanya 3,6 MB; bila base64, 5,4 MB; alfabet yang teramati membuat base32 paling mungkin. Balasan TXT hanya token pendek seperti `ok4817` (pengakuan per pecahan), jadi arah datanya keluar. Transfer berhenti pada 02:11:46, satu detik sebelum isolasi; nomor urut terakhir tidak menandai akhir file, sehingga transfer kemungkinan terputus, bukan selesai.

Hop egress dan resolver memberi konfirmasi: `dns.log` egress mencatat 43.561 query dari `10.20.2.53` ke `203.0.113.183:53` (authoritative `x.kirimdata.example`) dalam jendela yang sama, dan `index=dns` mencatat 43.561 query `src=10.10.60.127` untuk domain itu. Tidak ada host lain yang menanyakan `kirimdata.example` dalam 30 hari retensi resolver.

**Variasi:** analitik Splunk Research "DNS Query Length With High Standard Deviation" memakai data model `Network_Resolution`, membuang PTR, SOA, dan SRV, lalu menyaring query yang lebih panjang dari rata-rata ditambah dua kali simpangan baku dan meringkasnya per sumber [S19]. Bila index `dns` PT JAB sudah dipetakan ke CIM, analitik itu bisa dipakai sebagai pembanding saved search program; di sumber resolver PT JAB, `src` adalah klien asli.

**Kapan gagal:** tunnel yang memakai label pendek dan laju rendah (beberapa query per menit) tidak melewati ambang jumlah unik per jam; agregasi harian per domain induk dengan "jumlah nama unik dari sedikit klien" lebih tahan. DNS terenkripsi (DoH atau DoT) langsung ke internet menghilangkan nama dari `dns.log` sama sekali (Day 16); di PT JAB, workstation tidak bisa keluar langsung, sehingga DoH hanya mungkin lewat proxy dan terlihat sebagai `CONNECT` ke penyedia DoH.

### 2.6 Saluran lain: SYN langsung ke `203.0.113.183:443` dan FTP `jkt-recon01`

**Tujuan:** menjawab pertanyaan kelima Dimas: apakah ada data yang keluar lewat percobaan langsung `JKT-WS-2057` (`SOC-2027-0656`) atau lewat FTP malam `jkt-recon01` (`SOC-2027-0659`).

Untuk percobaan langsung, `conn.log` hop egress dan log firewall dibandingkan:

```
index=zeek sourcetype=bro:conn:json "id.orig_h"="10.10.60.127" ("id.resp_h"="203.0.113.182" OR "id.resp_h"="203.0.113.183")
    earliest="05/25/2027:18:00:00" latest="05/26/2027:03:00:00"
| stats count sum(orig_bytes) AS kirim sum(resp_bytes) AS terima values(conn_state) AS state
        values(history) AS hist min(_time) AS awal max(_time) AS akhir BY id.resp_h id.resp_p
| convert ctime(awal) ctime(akhir)

index=firewall src=10.10.60.127 dest IN (203.0.113.182, 203.0.113.183)
    earliest="05/25/2027:18:00:00" latest="05/26/2027:03:00:00"
| stats count BY dest dest_port action
```

Keluaran ilustrasi:

```
id.resp_h       id.resp_p  count  kirim  terima  state  hist  awal                 akhir
203.0.113.183   443        776    0      0       REJ    Sr    05/25/2027 22:41:12  05/25/2027 23:19:58

dest            dest_port  action  count
203.0.113.183   443        deny    776
```

**Cara membaca hasil:** 776 percobaan, semuanya `REJ` dengan `history` `Sr` (SYN dari workstation, RST dari firewall), `orig_bytes` dan `resp_bytes` nol, dan jumlah yang sama persis di log firewall. Karena sensor berada di sisi dalam firewall, Zeek melihat setiap SYN; tidak ada SYN-ACK dari luar, sehingga tidak ada handshake dan tidak ada payload. Jawaban: tidak ada data yang keluar lewat jalur ini. Yang dibuktikan: alat di `JKT-WS-2057` mencoba kembali ke infrastruktur yang sama (`203.0.113.183` juga authoritative DNS untuk `kirimdata.example`) lewat jalur lain setelah proxy diblokir, setiap sekitar 3 detik selama 39 menit. Seperti pelajaran Day 11, "ditolak firewall" adalah bukti niat dan fallback, bukan alasan menutup alert.

Untuk FTP, file yang diunggah terlihat langsung karena protokolnya polos. Perintah dari catatan lama:

```
# Zeek files.log: file yang terlihat di koneksi, beserta arah pengirimnya
zeek-cut uid id.orig_h id.resp_h is_orig mime_type total_bytes md5 < files.log
```

- Sejak Zeek 5.1, `files.log` tidak lagi memuat `tx_hosts` dan `rx_hosts` secara bawaan; keduanya diganti `uid` dan `id` milik koneksinya [S2]. Arah ditentukan dari `is_orig`: `T` berarti file dikirim oleh originator koneksi.
- Cara membaca: baris dengan `id.orig_h` internal, `id.resp_h` eksternal, dan `is_orig` bernilai `T` adalah file yang diunggah keluar; `mime_type` dan ukuran menunjukkan jenis dan besar. Hash untuk korelasi. Bila terenkripsi, `files.log` tak memperlihatkan isi; andalkan volume dan host.
- Tutorial lama yang masih memakai `tx_hosts`/`rx_hosts` akan menghasilkan kolom kosong di Zeek modern.

Versi Splunk yang menjadi saved search ketiga program ("file keluar lewat protokol polos, minimal 25 MB per host per jam"), ditambah `ftp.log` untuk nama file dan akun:

```
index=zeek sourcetype=bro:files:json "id.orig_h"="10.20.15.41" is_orig=true
    earliest="05/26/2027:01:00:00" latest="05/26/2027:02:00:00"
| stats count sum(total_bytes) AS total values(source) AS sumber values(mime_type) AS mime BY id.resp_h

index=zeek sourcetype=bro:ftp:json "id.orig_h"="10.20.15.41" command=STOR
    earliest="05/26/2027:01:00:00" latest="05/26/2027:02:00:00"
| table _time user command arg file_size reply_code
```

Keluaran ilustrasi:

```
id.resp_h       count  total     sumber    mime
203.0.113.165   8      34094286  FTP_DATA  text/plain

_time                user      command  arg                                     file_size  reply_code
05/26/2027 01:30:04  recon_jab STOR     ftp://203.0.113.165/./rekon_20270518.csv 4350240    226
05/26/2027 01:30:19  recon_jab STOR     ftp://203.0.113.165/./rekon_20270519.csv 4164102    226
...
05/26/2027 01:31:51  recon_jab STOR     ftp://203.0.113.165/./rekon_20270525.csv 4213770    226
```

**Cara membaca hasil:** `jkt-recon01` (`10.20.15.41`) mengunggah delapan file rekonsiliasi (`rekon_20270518.csv` sampai `rekon_20270525.csv`, total 34.094.286 byte) ke `ftp.mitrabayar.example` (`203.0.113.165`) dengan akun `recon_jab`, lewat NAT `198.51.100.203`. Ini job yang sama yang dipelajari di Day 03 (satu file sekitar 4,2 MB setiap malam); malam ini delapan file karena tim Keuangan meminta pengiriman ulang data 18 sampai 24 Mei setelah mitra memulihkan sistemnya (tiket Keuangan, dikonfirmasi pukul 08:50 Rabu). Data memang keluar, dan memang boleh keluar ke tujuan itu: disposisi jinak. Tetapi FTP polos berarti data rekonsiliasi pembayaran dan kredensial `recon_jab` melintasi internet tanpa enkripsi, seperti temuan Day 03, kini untuk delapan hari data sekaligus. Itu temuan risiko yang perlu diteruskan ke DPO (bagian 2.8), bukan insiden exfiltration.

**Variasi:** untuk HTTP polos, filter `http.request.method == "POST" or http.request.method == "PUT"` di Wireshark (bagian 2.7) dan `files.log` dengan `source` `HTTP` dan `is_orig` `T` memberi bentuk yang sama. Untuk SMTP keluar langsung dari server, lampiran juga muncul di `files.log` dengan `source` `SMTP`.

**Kapan gagal:** FTP dengan TLS (FTPS) atau SFTP menyembunyikan nama file dan isi; yang tersisa hanya volume per koneksi. Mode aktif FTP membuat koneksi data dimulai dari server mitra, sehingga `id.orig_h` adalah alamat luar dan file unggahan tercatat dengan `is_orig` `F`; arah harus dibaca dari perintah `STOR` di `ftp.log`, bukan dari asumsi.

### 2.7 Kiriman 2.118.004 byte dari `JKT-WS-2052` (pertanyaan terbuka Day 11)

**Tujuan:** menjawab sejauh mungkin pertanyaan kedelapan: apa yang bisa dikatakan jaringan tentang satu tunnel `JKT-WS-2052` (`10.10.60.112`) ke `assets.northwind-cdn.example` Jumat 2027-05-21 pukul 15:13:40 WIB yang membawa 2.118.004 byte dari host, di tengah 93 check-in yang masing-masing hanya sekitar 1.540 byte (Day 11 bagian 2.4).

Filter Wireshark dari catatan lama untuk unggahan HTTP:

```
http.request.method == "POST" or http.request.method == "PUT"
```

- Untuk HTTP polos: POST/PUT besar ke endpoint tak biasa.
- Untuk HTTPS: tak terlihat isi; pakai volume Application Data (Day 06) dan SNI tujuan.
- Cara membaca: unggahan besar ke tujuan asing, apalagi di luar jam kerja, adalah kandidat. SNI/JA3 dan reputasi tujuan membantu menilai.

Untuk kasus ini filter itu tidak menolong, karena dua alasan. Pertama, pcap egress Jumat 15:13 sudah tertimpa ring buffer `jkt-pcap01` (target 72 jam, jadi tertimpa sekitar Senin sore), dan folder kasus `INC-2027-070` hanya menyimpan pcap Jumat 10:30 sampai 11:00. Kedua, domain itu di-bump proxy, sehingga proxy memang melihat `POST /api/v3/assets`; tetapi ke-96 check-in juga `POST` ke path yang sama (Day 11 bagian 2.8), dan kolom `bytes` proxy adalah ukuran balasan (`%<st`) [S15]. Log proxy tidak membedakan kiriman besar dari check-in. Yang tersisa adalah `conn.log` di arsip Zeek dan jejak host:

```
# hop core: tunnel CONNECT 10.10.60.112 ke proxy sekitar 15:13:40 WIB (08:13:40 UTC)
cd /opt/zeek/logs/2027-05-21
zcat conn.08*.log.gz | jq -r 'select(."id.orig_h"=="10.10.60.112" and ."id.resp_h"=="10.20.3.60")
       | [.ts, .uid, .orig_bytes, .resp_bytes, .duration] | @tsv' | sort -n | awk '$3>100000'
# hop egress: koneksi proxy ke alamat tujuan pada detik yang sama
zcat conn.08*.log.gz | jq -r 'select(."id.orig_h"=="10.20.3.60"
       and (."id.resp_h"=="203.0.113.180" or ."id.resp_h"=="203.0.113.181") and .orig_bytes > 100000)
       | [.ts, .uid, ."id.resp_h", .orig_bytes, .resp_bytes, .duration] | @tsv'
```

Keluaran ilustrasi:

```
1810887220.418  CpL3kQ8vX2nZ5aWe71  2118004  4231  3.92
1810887220.437  Cn7Rt2Wd5Yb9Mk1Qa6  203.0.113.181  2117951  4886  3.88
```

Perhitungan ukuran data, dengan cara bagian 1.8:

| Langkah | Angka |
|---|---|
| `orig_bytes` tunnel hop core | 2.118.004 |
| Dikurangi median check-in (CONNECT, handshake, POST kecil) | 2.118.004 - 1.540 = 2.116.464 |
| Record TLS tambahan untuk isi itu | 2.116.464 / 16.384 = 129,2, dibulatkan 130 record |
| Overhead record (130 x 22 byte) | 2.860 |
| Perkiraan isi permintaan HTTP tambahan (header dan body) | 2.116.464 - 2.860 = 2.113.604 byte |

Temuan sementara Yoga dari MDE di `JKT-WS-2052` (Selasa 2027-05-25): proses `nwassets.exe` membuat file `C:\Users\rina.oktaviani\AppData\Local\Temp\nw_7f3a.tmp` berukuran 2.112.486 byte pada 15:13:31 WIB dan menghapusnya pada 15:13:52.

**Cara membaca hasil:** kiriman itu satu tunnel berdurasi 3,92 detik. Di hop egress, proxy membuka koneksi baru ke `203.0.113.181` 19 milidetik kemudian dengan `orig_bytes` 2.117.951, jadi byte itu benar meninggalkan gedung ke infrastruktur kandidat C2 yang sama; selisih 53 byte adalah perbedaan TLS antara sisi klien dan sisi proxy, karena sesi di-bump. Perkiraan isi permintaan 2.113.604 byte, lebih besar 1.118 byte dari file sementara yang dibuat implant sembilan detik sebelumnya; selisih seukuran header HTTP dan pembungkus multipart. Kecocokan waktu dan ukuran ini adalah bukti korelasi yang kuat, bukan bukti isi.

Jawaban yang bisa dipegang untuk `INC-2027-070`:

- Sekitar 2,11 MB data aplikasi keluar dari `JKT-WS-2052` ke `assets.northwind-cdn.example` (`203.0.113.181`) satu kali, Jumat 2027-05-21 15:13:40 WIB, lewat kanal C2 yang sama dengan check-in. Label ATT&CK: T1041, didukung data jaringan dan waktu jejak host.
- Selama jendela sensor (Kamis 13:57 sampai isolasi Senin 10:55), tidak ada kiriman lain dari host itu di atas ukuran check-in, tidak ada query DNS berpola tunneling, dan ke-288 SYN ke `203.0.113.181:8443` tidak membawa payload. Total yang terlihat keluar adalah kiriman 2,1 MB itu ditambah sekitar 96 x 1,5 KB check-in.
- Isinya belum diketahui. File sementara sudah dihapus; pemulihan dari image disk sedang dicoba tim IR. Ukuran 2,1 MB cocok untuk satu arsip dokumen kecil atau hasil pengumpulan data sistem; kedua kemungkinan tetap terbuka.
- Batasnya: kiriman sebelum Kamis 13:57 tidak ada karena domain itu belum pernah dihubungi (Day 11), dan aktivitas di luar titik pandang sensor tidak tercakup.

**Variasi:** bila pcap masih tersedia untuk koneksi seperti ini, panjang record Application Data dari klien bisa dihitung langsung (`tls.record.length` per frame untuk arah klien ke server; nama field ada di referensi display filter Wireshark [S18]), sehingga overhead tidak perlu diperkirakan.

**Kapan gagal:** perhitungan mengasumsikan TLS 1.3 dengan tag 16 byte dan record penuh; implementasi yang memecah data ke record kecil atau menambah padding membuat overhead lebih besar. Bila check-in itu sendiri bervariasi lebar, median bukan pengurang yang baik; gunakan rentang dan tulis hasilnya sebagai rentang.

### 2.8 Staging, timeline, label ATT&CK, dan bahan untuk DPO

**Tujuan:** menyambungkan unggahan ke data yang diambil (pertanyaan 7 Dimas), menyusun timeline `INC-2027-071`, dan menulis ringkasan yang dibawa ke rapat 13:00.

Staging terjadi di host, tetapi pengumpulan dari file server lewat SMB melewati core switch:

```
index=zeek sourcetype=bro:conn:json "id.orig_h"="10.10.60.127" "id.resp_p"=445
    earliest="05/25/2027:00:00:00" latest="05/25/2027:23:59:59"
| table _time id.resp_h orig_bytes resp_bytes duration
| sort 0 _time
```

Keluaran ilustrasi:

```
_time                    id.resp_h    orig_bytes  resp_bytes   duration
2027-05-25 08:12:40.118  10.20.8.22   1204551     38604112     33621.7
2027-05-25 19:48:03.442  10.20.8.22   9812334     2071436812   2928.4
```

**Cara membaca hasil:** `10.20.8.22` adalah `jkt-fs02`, file server Penjualan. Sesi siang adalah pemakaian biasa (38,6 MB sepanjang hari kerja; median harian host ini ke `jkt-fs02` selama delapan hari Zeek hidup 46 MB, dan maksimum harian dalam 90 hari flow router data center 310 MB). Sesi kedua dimulai 19:48:03, dua jam setelah pengguna pulang, dan menarik 2.071.436.812 byte, sekitar 2,07 GB, dalam 49 menit. `smb_files.log` (SMB di `jkt-fs02` tidak memakai enkripsi) menunjukkan sebagian besar pembacaan dari folder `Kontrak` dan `Pipeline` di share `SALES$`. Itu pola T1039 Data from Network Shared Drive yang terlihat dari jaringan. Kemungkinan jinak yang diuji: indeksasi pencarian Windows atau sinkronisasi offline files juga membaca banyak; tetapi keduanya tidak diikuti unggahan 1,31 GB ke penyimpanan konsumen 25 menit kemudian.

Temuan sementara Yoga dari MDE (Rabu 07:40): `7za.exe` di `C:\ProgramData\SysCache\` membuat `p.7z` antara 20:37:10 dan 20:58:44, berukuran akhir 1.447.034.880 byte; executable tanpa tanda tangan `svch.exe` di folder yang sama membuka tunnel ke proxy; sesi `teguh.santoso` (Account Manager, Penjualan Enterprise) aktif sejak 08:05, sementara kartu akses menunjukkan Teguh keluar gedung pukul 17:40. Cara masuk awal belum diketahui.

Dibandingkan dengan jaringan: 1.308.622.848 byte yang terunggah adalah 90,4% dari arsip itu; 138.412.032 byte (9,6%) tidak sempat keluar lewat web sebelum blokir. DNS membawa sekitar 4,5 MB setelahnya; apakah itu sisa arsip (yang akan butuh lebih dari 40 jam pada laju itu) atau file lain, hanya host yang bisa menjawab.

Timeline `INC-2027-071` (WIB):

| Waktu | Kejadian | Bukti |
|---|---|---|
| Selasa 19:48:03 sampai 20:36:51 | `JKT-WS-2057` membaca sekitar 2,07 GB dari `jkt-fs02` lewat SMB | Zeek hop core `conn.log`, `smb_files.log` |
| 20:37:10 sampai 20:58:44 | Arsip `p.7z` 1,45 GB dibuat | MDE (Yoga) |
| 21:02:14 | Tunnel pertama ke `up.simpanfile.example` | Zeek hop core, log proxy |
| 21:15 | `SOC-2027-0655` menyala (538 MB dalam 15 menit) | Splunk |
| 21:34:10 | `*.simpanfile.example` diblokir di `jkt-proxy01` oleh Rudi | Change log proxy |
| 21:34:12 | Tunnel ke-78 selesai; total 1,31 GB | Zeek, flow router DC dan edge |
| 21:34:15 sampai 21:35:45 | Tiga `CONNECT` ditolak 403 | Log proxy |
| 22:41:12 sampai 23:19:58 | 776 SYN ke `203.0.113.183:443`, semua ditolak; `SOC-2027-0656` pukul 22:58 | Zeek hop egress, firewall |
| 23:15 | `SOC-2027-0657` (`JKT-WS-2055`, OneDrive), ditutup 23:40 sebagai jinak (`CHG-2027-0418`) | Bagian 2.4 |
| Rabu 00:52:07 | DNS TXT ke `kirimdata.example` dimulai | Zeek hop core `dns.log`, `index=dns` |
| 01:20 | `SOC-2027-0658` menyala | Splunk |
| 01:30:04 sampai 01:31:51 | FTP `jkt-recon01` ke mitra; `SOC-2027-0659` pukul 01:45, jinak dengan temuan risiko | Bagian 2.6 |
| 01:48 | Rudi membuka `INC-2027-071` | Tiket |
| 02:11:46 | Query DNS terakhir; 43.012 nama unik, sekitar 4,5 MB | Bagian 2.5 |
| 02:11:47 | `JKT-WS-2057` diisolasi lewat MDE | MDE |
| 02:20 | `kirimdata.example` diblokir di `jkt-res01`/`jkt-res02`; `203.0.113.182` dan `.183` diblokir di `jkt-fw01` | Change log |

Label ATT&CK untuk laporan:

| Teknik | Status | Dasar |
|---|---|---|
| T1039 Data from Network Shared Drive | Didukung data jaringan | 2,07 GB SMB dari `jkt-fs02` di luar jam kerja |
| T1074.001 Local Data Staging, T1560.001 Archive via Utility | Didukung host, menunggu konfirmasi IR | `p.7z` dan `7za.exe` di MDE |
| T1567.002 Exfiltration to Cloud Storage | Didukung data jaringan | 1,31 GB ke layanan penyimpanan konsumen |
| T1030 Data Transfer Size Limits | Didukung data jaringan | 78 pecahan 16 MiB, selisih maksimum 34 byte |
| T1048.003 Exfiltration Over Unencrypted Non-C2 Protocol | Didukung data jaringan | DNS TXT base32, sekitar 4,5 MB |
| Percobaan koneksi langsung ke `203.0.113.183:443` | Percobaan gagal, tanpa data | 776 `REJ` |
| T1041 Exfiltration Over C2 Channel (`INC-2027-070`) | Didukung data jaringan dan waktu jejak host | Bagian 2.7 |

Ringkasan yang dibawa Dimas:

```
INC-2027-071  Ringkasan exfiltration dari data jaringan (Rabu 2027-05-26 12:00 WIB)
Host          : JKT-WS-2057 (10.10.60.127), sesi teguh.santoso (Penjualan Enterprise)
Sumber data   : jkt-fs02 (10.20.8.22) share SALES$, folder Kontrak dan Pipeline; ~2,07 GB dibaca 19:48-20:37
Keluar (web)  : up.simpanfile.example (203.0.113.182), 21:02:14-21:34:12, 78 pecahan x 16 MiB
                = 1.308.622.848 byte data (Zeek hop core; cocok dengan flow DC dan edge)
Keluar (DNS)  : x.kirimdata.example (NS 203.0.113.183), 00:52:07-02:11:46, 43.012 query unik
                = ~4,5 MB bila base32 (3,6-5,4 MB tergantung penyandian)
Tidak keluar  : 776 SYN langsung ke 203.0.113.183:443 (semua ditolak, 0 byte)
Dihentikan    : web 21:34:10 (proxy; satu tunnel berjalan selesai 21:34:12), DNS 02:11:47 (isolasi)
Keyakinan     : tinggi untuk waktu, tujuan, dan volume; isi = arsip p.7z menurut korelasi ukuran
                dan waktu (MDE), belum dibuktikan dengan membuka arsip
Belum diketahui: cara masuk awal, isi persis arsip, isi DNS, akun di simpanfile, host lain di luar sensor
Data          : /cases/INC-2027-071/ (log Zeek + sha256, ekspor flow, log proxy/DNS/firewall, pcap 20:45-02:15)
```

Bahan yang diteruskan ke Agus Setiawan (DPO), disusun sebagai fakta, bukan kesimpulan hukum:

- Data yang kemungkinan keluar berasal dari folder `Kontrak` dan `Pipeline` share Penjualan. Menurut pemilik datanya (Kepala Penjualan Enterprise), folder itu memuat kontrak pelanggan korporat dengan nama, jabatan, email, dan nomor telepon PIC pelanggan, serta nilai kontrak. Daftar file persis menunggu IR.
- Jumlah dan waktu: sekitar 1,31 GB ke layanan penyimpanan konsumen pada Selasa 21:02 sampai 21:34, dan sekitar 4,5 MB lewat DNS pada Rabu 00:52 sampai 02:12; keduanya sudah dihentikan.
- Tujuan: layanan penyimpanan cloud pihak ketiga dengan akun yang tidak diketahui; permintaan penghapusan atau preservasi ke penyedia perlu diputuskan bersama Legal.
- Temuan terpisah (bukan insiden): delapan hari data rekonsiliasi pembayaran dikirim ke mitra lewat FTP tanpa enkripsi malam ini (bagian 2.6), mengulang temuan Day 03.
- Untuk `INC-2027-070`: sekitar 2,1 MB dari laptop Pengadaan keluar ke infrastruktur kandidat C2 pada Jumat 21 Mei; isinya belum diketahui.

Ringkasan jawaban untuk delapan pertanyaan Dimas:

| Pertanyaan | Jawaban singkat | Bagian |
|---|---|---|
| Sumber mana, dan di mana host asli terlihat | Zeek hop core (`CONNECT` + `conn.log`) untuk host dan tujuan; hop egress, flow, dan proxy untuk konfirmasi | 1.1, 1.2, 2.1 |
| Berapa dari 2057, kapan, apakah blokir menghentikan | 1,31 GB, 21:02:14 sampai 21:34:12; blokir menghentikan saluran web (tunnel yang sedang jalan tetap selesai), bukan penyerangnya | 1.3, 2.1, 2.2, 2.3 |
| Kenapa OneDrive 2055 bukan insiden | Tenant PT JAB, 412 host, `OneDrive.exe`, `CHG-2027-0418`; 2057 gagal di kelima pertanyaan | 1.6, 2.4 |
| DNS membawa data? | Ya, sekitar 4,5 MB (base32, 43.012 pecahan bernomor urut) | 1.4, 2.5 |
| SYN langsung dan FTP | SYN: 0 byte, percobaan fallback; FTP: 34 MB keluar sah ke mitra, tetapi polos | 1.5, 2.6 |
| Isi terenkripsi, seberapa yakin | Waktu, tujuan, dan volume tinggi; isi hanya lewat korelasi dengan arsip di host | 1.7, 1.8 |
| ATT&CK dan DPO | Tabel label di atas; bahan DPO berupa fakta jumlah, waktu, tujuan, dan jenis data menurut pemilik | 1.9, 1.10, 2.8 |
| Kiriman 2,1 MB 2052 | 2,11 MB data sekali ke kanal C2 (T1041), cocok dengan file sementara implant; isi belum diketahui | 1.8, 2.7 |

**Kapan gagal:** bila file server memakai enkripsi SMB 3, `smb_files.log` tidak memuat nama file dan hanya volume per sesi yang tersisa; asal data lalu bergantung pada audit akses file di server. Bila workstation menyalin dari file server di cabang yang tidak lewat core Jakarta, langkah pengumpulan tidak terlihat sama sekali.

## 3. Lab praktik (di VM lab terisolasi)

**Prasyarat:** Wireshark 4.6.x dan/atau Zeek (log `conn.log`, `files.log`, `dns.log`), atau flow lab atau publik; dataset berisi transfer keluar (unggahan uji dan unggahan sah); alat flow dibaca sebagai teks; tidak ada data kerja. Jaringan host-only `192.168.56.0/24`: VM klien `192.168.56.10`, VM server `192.168.56.20` (web server dengan endpoint unggah dan server FTP lab), VM proxy Squid `192.168.56.30:3128`, dan VM sensor Zeek yang melihat kedua segmen.

Trafik uji cukup dibuat dengan alat biasa dan file acak yang tidak berisi data apa pun, misalnya `head -c 50M /dev/urandom > uji.bin` lalu mengunggahnya ke server lab dengan `curl -T uji.bin http://192.168.56.20/upload/` dan, untuk versi lewat proxy, `curl -x http://192.168.56.30:3128 -k -T uji.bin https://192.168.56.20/upload/`. Sebagai pembanding sah, unduh file yang sama dari server lab. Tidak ada alat exfiltration yang perlu dipasang atau ditulis.

1. **Volume keluar.** Agregasi `orig_bytes` per tujuan untuk host internal (bagian 2.1); tandai lonjakan. Untuk unggahan lewat proxy, gabungkan `CONNECT` dan `conn.log` per `uid`.
2. **Arah.** Nilai rasio upload vs download dan PCR ke tujuan kandidat, sekali dari byte Zeek dan sekali dari flow atau `orig_ip_bytes` (bagian 2.2). Catat selisihnya dan jelaskan dari header.
3. **Saluran.** Tentukan saluran (HTTPS, DNS, cloud, FTP) dan baca metadata relevan (bagian 2.5 dan 2.6). Untuk DNS, kirim beberapa query TXT berlabel acak panjang dengan `dig` ke zona lab yang dilayani VM server, lalu ukur jumlah unik, panjang, dan entropi seperti bagian 2.5.
4. **Data.** Bila polos (HTTP atau FTP lab), identifikasi jenis dan ukuran via `files.log` dengan `is_orig` (bagian 2.6); bila terenkripsi, hitung perkiraan byte data dari `orig_bytes` dengan overhead TLS (bagian 1.8) dan bandingkan dengan ukuran file uji yang kamu ketahui.
5. **Waktu dan pecahan.** Periksa waktu transfer terhadap baseline host (bagian 2.3). Unggah file uji yang dipotong sama besar (`split -b 5M uji.bin bagian_`) satu per satu, lalu lihat keseragaman `orig_bytes` di `conn.log`.
6. **Sah vs jahat.** Bandingkan tujuan dengan penyedia/akun perusahaan dan reputasi (bagian 2.4); nyatakan kemungkinan jinak.
7. **Dampak dan cerita.** Ukur total keluar; hubungkan ke C2/staging (bagian 1.10 dan 2.8); nyatakan keyakinan dan batas.
8. **ICMP.** Kirim `ping -c 5 -s 1000 192.168.56.20` dari VM klien dan baca baris ICMP di `conn.log`: catat `id.orig_p`, `id.resp_p`, `orig_bytes`, dan `orig_ip_bytes`, lalu tentukan apakah `orig_bytes` berisi payload ICMP saja (bagian 1.5).

**Hasil yang sebaiknya tersimpan:**

- Volume keluar per tujuan diagregasi dan lonjakan ditandai, termasuk versi lewat proxy.
- Rasio arah dan PCR dinilai terhadap baseline, dengan catatan perbedaan byte payload dan byte IP.
- Saluran exfiltration dikenali dari metadata.
- Jenis dan ukuran data diidentifikasi bila polos; perkiraan dari overhead TLS dibandingkan dengan ukuran file uji bila terenkripsi.
- Pola pecahan berukuran tetap terlihat di `conn.log`.
- Exfiltration dibedakan dari upload/backup/sync sah dengan tujuan, akun, jadwal, dan reputasi.
- Arti `orig_bytes` untuk ICMP di versi Zeek-mu tercatat.
- Dampak (total keluar) diukur dan dihubungkan ke tahap lain; keyakinan dinyatakan; IOC di-defang.

**Variasi tantangan:** diberi satu pcap/flow intrusi, bangun cerita akhir: akses awal, C2/beaconing (Day 11), lalu exfiltration, dengan total volume keluar, tujuan, dan saluran. Tulis write-up dampak: perkiraan data yang keluar (dari volume/host), tingkat keyakinan, dan apa yang hanya bisa dipastikan dengan bukti host atau pcap polos. Tantangan kedua: tulis saved search volume per host dan tujuan (bagian 2.1) di Splunk lab, lalu cari ambang terendah yang tidak menyala untuk unduhan dan sinkronisasi biasa di lab-mu. Ini menyiapkan Day 13-14 (metode kerja dan capstone).

## 4. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Volume besar tapi sah | Backup/sync terjadwal, migrasi | Cek tujuan/tenant perusahaan, change ticket, prevalence, proses (bagian 2.4) |
| Exfil tak terlihat | Low and slow | Agregasi jangka panjang + baseline; flow 13 bulan (bagian 1.7) |
| Isi tak terbaca | Terenkripsi | Pakai volume/arah/tujuan; isi butuh host/pcap polos (bagian 1.8) |
| DNS volume tinggi | Tunneling atau layanan berisik | Periksa panjang/entropi nama, jumlah unik, alfabet, nomor urut (Day 05, bagian 2.5) |
| Arah membingungkan | Flow searah vs dua arah | Pastikan byte per arah dihitung benar; flow memisahkan arah menjadi dua record |
| Tujuan cloud ambigu | Cloud dipakai sah dan jahat | Bedakan akun/tenant dan reputasi; nama host per tenant di SNI (bagian 1.6) |
| Semua unggahan web bersumber proxy | Proxy eksplisit | Gabungkan `CONNECT` di `http.log` hop core dengan `conn.log` per `uid` (bagian 2.1) |
| Log proxy menunjukkan unggahan 16 MB sebagai 5 KB | Kolom `bytes` adalah ukuran balasan (`%<st`) | Tambahkan `%>st` ke logformat bila perlu ukuran permintaan [S15]; sementara pakai Zeek |
| Angka Zeek dan flow berbeda beberapa persen | Payload vs byte IP, sampling | Hitung header per paket; untuk flow edge, rentang galat sampling (bagian 2.2) |
| `orig_bytes` jauh lebih besar dari flow | Capture loss atau koneksi sangat besar | Periksa `missed_bytes` dan notice capture loss; bandingkan `orig_ip_bytes` [S11] |
| Unggahan berjalan setelah blokir | Blokir hanya untuk `CONNECT` baru | Periksa tunnel yang sudah terbuka; putuskan dengan isolasi host bila perlu (bagian 2.3) |
| `files.log` kosong untuk FTP | FTPS/SFTP atau mode aktif dibaca terbalik | Cek `ftp.log` dan `is_orig`; FTP terenkripsi hanya memberi volume (bagian 2.6) |
| Jendela Splunk tidak cocok dengan folder arsip | Arsip Zeek per tanggal UTC, Splunk WIB | Konversi jam sebelum memilih folder (bagian 2.1 dan 2.5) |

## 5. Kesalahan umum dan jebakan

- **Mengira volume besar = exfil.** Backup/sync sah juga besar; tujuan, akun, jadwal, reputasi memutuskan. Di PT JAB, unggahan terbesar malam itu justru migrasi OneDrive yang sah.
- **Hanya melihat volume sesaat.** Low and slow butuh agregasi jangka panjang dan baseline.
- **Mengira terenkripsi berarti buntu.** Volume, arah, tujuan, dan waktu tetap memberi banyak; isi dari host/pcap polos.
- **Menyimpulkan data apa tanpa bukti.** Volume/tujuan = sinyal; jenis data butuh files.log polos atau korelasi host.
- **Mengabaikan staging/tahap lain.** Menghubungkan ke C2 dan staging host memperkuat cerita dan menunjukkan apa yang diambil.
- **Mengukur di hop egress saja.** Di balik proxy semua workstation menjadi satu alamat; angka per host harus dari hop core.
- **Membaca kolom `bytes` proxy sebagai unggahan.** Format native Squid mencatat ukuran balasan ke klien [S15]; unggahan nyaris tidak terlihat di sana.
- **Menulis byte TLS sebagai ukuran file.** Byte terukur termasuk handshake, header, dan overhead record; laporkan sebagai byte data aplikasi, lalu perkiraan ukuran file dengan asumsinya (bagian 1.8).
- **Menganggap blokir sudah menghentikan exfiltration.** Blokir menghentikan satu saluran; tunnel yang sedang jalan selesai, dan penyerang mencoba jalur lain.
- **Menghitung SYN yang ditolak sebagai data keluar.** Tanpa handshake tidak ada payload; yang dibuktikan adalah niat dan fallback.
- **Menunggu isi pasti sebelum melapor ke DPO.** Fakta jumlah, waktu, dan tujuan sudah bisa diteruskan; kesimpulan hukum di tangan DPO dan Legal.
- Pola kerja yang umum di komunitas analis adalah menandai exfiltration lewat volume keluar anomali dan rasio arah terbalik ke tujuan tak biasa, lalu membedakannya dari backup/sync sah via akun, jadwal, dan reputasi, dan mengukur dampak dari total byte; low and slow ditangkap dengan agregasi jangka panjang. Pendekatan ini belum dikonfirmasi satu sumber primer sebagai metode baku; ambang bergantung baseline lingkungan, jadi ukur di lingkunganmu.

## 6. Catatan terkini

Bagian ini menampung status versi dan perubahan yang perlu diingat saat membaca materi exfiltration per Oktober 2026.

- ATT&CK v20.0 menambah T1700 AI-Enabled Exfiltration (versi 1.0, diubah 9 Oktober 2026): agent AI perusahaan diarahkan untuk memindahkan data lewat alat yang sudah diizinkan [S10]. Analitik deteksi di v20 diberi ID strategi (misalnya DET0348 untuk T1041, DET0149 untuk T1048.003, DET0570 untuk T1567.002, DET0213 untuk T1030) [S6][S7][S8][S9].
- Exfiltration makin lewat layanan cloud dan HTTPS sah (penyimpanan, API populer) agar menyatu; deteksi bergeser ke tujuan/akun dan volume, bukan port/proto.
- Microsoft Entra tenant restrictions v2: lewat proxy hanya melindungi authentication plane; data plane butuh sinyal dari klien Windows, dan pemblokiran akses anonim ke OneDrive konsumen belum didukung (dokumen diperbarui 20 Maret 2026) [S17].
- Daftar endpoint Microsoft 365 diperbarui berkala (terakhir 14 Agustus 2026 saat Day ini ditulis); domain `*.cloud.microsoft` mulai menggantikan sebagian domain lama, jadi daftar allowlist dan kategori proxy perlu ikut diperbarui [S16].
- TLS 1.3 kini RFC 9846 (Juli 2026, menggantikan RFC 8446); batas record 2^14 byte dan ekspansi AEAD maksimal 255 byte tidak berubah untuk keperluan perhitungan bagian 1.8 [S13].
- DNS tunneling tetap dipakai untuk exfil tersembunyi; deteksi berbasis volume dan entropi (Day 05). Analitik Splunk Research untuk panjang query DNS berada di versi 16 (13 Mei 2026) [S19].
- Low and slow dan enkripsi membuat deteksi bergantung baseline jangka panjang (flow, Day 10) dan korelasi multi-sinyal.
- Day 13 (metode kerja dan integrasi SIEM) dan Day 14 (capstone) menyatukan semua sinyal ini; jenis data yang keluar tetap perlu dikonfirmasi dari host.

## 7. Cheat sheet

```
EXFIL      data keluar ke kendali penyerang ; sinyal utama = ARAH (upload besar) + VOLUME (di atas baseline) + tujuan tak biasa
SALURAN    HTTPS (POST/PUT besar, metadata) | DNS tunneling (query banyak/panjang) | cloud storage | email | port aneh | covert (ICMP/timing)
UKUR       Zeek orig_bytes per dst (host internal) | flow byte per arah ; jumlahkan per tujuan+periode = total keluar
PROXY      hop core: CONNECT (http.log uri) + conn.log, gabung per uid ; hop egress = sumber proxy, cek IP+SNI
           log proxy native Squid: bytes = %<st (balasan) -> unggahan nyaris tak terlihat ; tambah %>st
ARAH       normal: download > upload ; exfil: upload >> download ke 1 dst
PCR        (kirim - terima) / (kirim + terima) ; -1 konsumen .. +1 produsen ; pakai byte aplikasi, agregasi per src+dst+dport
LOW&SLOW   sedikit tiap kali, tersebar waktu -> agregasi JANGKA PANJANG + baseline, bukan ambang sesaat
PECAHAN    orig_bytes nyaris sama + interval rata = T1030/T1020 (mesin)
TLS        byte data ~ byte TLS - (CONNECT+handshake+header) - 22 B per record 16 KiB (TLS 1.3, tag 16 B)
DNS        unik/jam, panjang sub (maks label 63, nama 255), entropi, % TXT ; data ~ unik x karakter x 5/8 (base32)
FTP/HTTP   files.log (uid, id.orig_h internal, id.resp_h eksternal, is_orig=T, mime_type, bytes, hash) bila polos ; terenkripsi = volume+host saja
SYN REJ    orig_bytes 0 = tidak ada data ; bukti niat dan fallback, bukan alasan tutup
SAH?       backup/sync/log shipping/transfer bisnis ke penyedia+akun perusahaan terjadwal = sah ; penyimpanan asing di luar jam = curiga
           tenant di SNI, first seen, prevalence, proses (EDR), change ticket
STAGING    sering didahului kumpul+arsip di host (T1074, T1560) ; SMB baca dari file server DC terlihat di SPAN core (T1039)
DAMPAK     ukur total byte keluar + jenis data (host/files.log) ; sinyal != "data X dicuri" (butuh identifikasi)
DPO        fakta: kapan, berapa, ke mana, saluran, sudah dihentikan?, jenis data menurut pemilik ; keputusan hukum di DPO+Legal
TEKNIK     kerangka via ATT&CK taktik Exfiltration ; JANGAN tulis prosedur
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** Alert menunjukkan satu workstation mengirim 6,4 GB ke `*.sharepoint.com` dengan PCR 0,94 dalam satu malam. Bolehkah tiket ditulis "kemungkinan besar exfiltration karena volume dan rasio sangat tinggi"?

<details><summary>Jawaban</summary>

Tidak. Volume dan PCR adalah sifat trafik, bukan sifat izin; unggahan sah juga besar dan miring ke arah kirim. Yang memutuskan: tenant di SNI (milik organisasi atau bukan), first seen, prevalence, proses yang mengirim, dan perubahan yang tercatat. Di PT JAB, kasus `JKT-WS-2055` adalah migrasi OneDrive dengan change ticket, 412 host ke tenant yang sama, dan `OneDrive.exe` bertanda tangan.

Lihat bagian 1.6 dan 2.4.

</details>

**2. Hitung.** Sebuah tunnel TLS 1.3 tercatat dengan `orig_bytes` 8.411.250, sedangkan check-in biasa ke tujuan yang sama sekitar 1.250 byte. Perkirakan isi permintaan HTTP tambahan, dengan record penuh dan tag 16 byte.

<details><summary>Jawaban</summary>

Selisih dengan check-in: 8.411.250 - 1.250 = 8.410.000 byte. Jumlah record: 8.410.000 / 16.384 = 513,3, dibulatkan 514 record. Overhead: 514 x 22 = 11.308 byte. Perkiraan isi: 8.410.000 - 11.308 = 8.398.692 byte, sekitar 8,4 MB termasuk header HTTP. Tulis sebagai byte data aplikasi, bukan ukuran file, dan sebut asumsinya (TLS 1.3, AEAD dengan tag 16 byte, tanpa padding).

Lihat bagian 1.8 dan 2.7.

</details>

**3. Skenario keputusan.** Pukul 21:34:10 kamu memblokir domain penyimpanan di proxy. Pukul 21:34:12 Zeek mencatat tunnel 16,8 MB dari host yang sama ke domain itu. Apa artinya?

- A. Blokir gagal; aturan proxy salah tulis.
- B. Tunnel itu sudah terbuka sebelum blokir; blokir proxy berlaku untuk `CONNECT` baru, sehingga tunnel yang sedang berjalan selesai.
- C. Zeek salah mencatat waktu.

<details><summary>Jawaban</summary>

B. `conn.log` ditulis saat koneksi selesai, dan `ts` adalah waktu mulai. Tunnel yang dimulai 21:33:48 sudah lewat pemeriksaan kebijakan sebelum aturan baru berlaku. `CONNECT` sesudahnya ditolak 403. Bila tunnel yang sedang berjalan harus diputus seketika, langkahnya isolasi host atau memutus sesi, bukan aturan URL.

Lihat bagian 2.3.

</details>

**4. Hitung.** Dalam satu jam, `dns.log` hop core mencatat 21.600 nama unik di bawah satu domain induk, dengan rata-rata 120 karakter data per nama dan alfabet `a-z2-7`. Berapa perkiraan data yang keluar, dan apa asumsinya?

<details><summary>Jawaban</summary>

Base32 membawa 5 bit per karakter: 120 x 5 / 8 = 75 byte per nama. 21.600 x 75 = 1.620.000 byte, sekitar 1,6 MB per jam. Asumsinya: label data memakai base32 (didukung alfabet yang teramati), tidak ada kompresi tambahan, dan nomor urut atau label tetap sudah dikeluarkan dari hitungan karakter. Bila hex, hasilnya 1,3 MB; bila base64, 1,9 MB.

Lihat bagian 1.4 dan 2.5.

</details>

**5. Pertanyaan jebakan.** Firewall mencatat 776 percobaan dari workstation ke `203.0.113.183:443`, semuanya ditolak. Rekan menulis "776 percobaan exfiltration ditolak, tidak berdampak, tutup". Apa yang kurang tepat?

<details><summary>Jawaban</summary>

Dua hal. Pertama, "percobaan exfiltration" adalah tafsiran: yang terbukti hanya percobaan koneksi; tanpa handshake tidak ada payload (`REJ`, `orig_bytes` 0). Kedua, "tidak berdampak, tutup" mengabaikan arti percobaan itu: ada proses di host yang mencoba jalur lain ke infrastruktur yang sama. Di `INC-2027-071`, alamat itu juga authoritative DNS untuk kanal tunneling yang dimulai satu setengah jam kemudian.

Lihat bagian 2.6.

</details>

**6. Skenario keputusan.** Dimas harus melapor ke DPO pukul 13:00. Isi arsip yang terunggah belum bisa dibuka tim IR. Mana yang tepat?

- A. Tunda laporan ke DPO sampai isi arsip pasti.
- B. Laporkan fakta yang sudah terukur (kapan, berapa, ke mana, saluran, sudah dihentikan atau belum), asal data yang kemungkinan dan jenis data di sana menurut pemiliknya, serta apa yang belum diketahui.
- C. Laporkan bahwa data pribadi pelanggan sudah pasti bocor supaya aman.

<details><summary>Jawaban</summary>

B. Keputusan apakah ini kegagalan pelindungan data pribadi yang wajib diberitahukan ada di DPO dan Legal, dan mereka butuh fakta sedini mungkin. A membuang waktu yang bisa penting bila ada tenggat pemberitahuan. C mengklaim isi yang belum dibuktikan.

Lihat bagian 1.10 dan 2.8.

</details>

**7. Interview question (English).** "An executive asks you: 'Did data leave our network, how much, and how sure are you?' All the traffic was HTTPS through a web proxy. How do you answer?"

<details><summary>Sample answer</summary>

"I'd separate what the network can prove from what it can't. Behind an explicit proxy, the egress view only shows the proxy, so I'd measure on the inside leg: join the CONNECT requests to their connection records to get bytes per workstation and destination, then confirm the same volume leaving the building with egress logs and flow data from a different device. That gives me who, where, when, and how much with high confidence. I'd subtract TLS overhead and handshake bytes so I report application data, not a file size. What the network can't tell me is what the data was. For that I'd correlate timing and size with endpoint evidence, like an archive created minutes before the upload, and I'd say clearly that this is correlation until the archive is recovered. I'd also rule out the benign explanations, sanctioned sync, backups, migrations, using tenant, prevalence, process, and change records. And I'd state the blind spots: hosts outside the sensor's view and anything slower than our thresholds."

What makes this answer strong: it addresses the proxy blind spot directly, uses two independent sources for the volume, distinguishes measured bytes from file size and network facts from content claims, tests benign explanations, and names the limits instead of overstating certainty.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | MITRE ATT&CK: Exfiltration (taktik TA0010) | https://attack.mitre.org/tactics/TA0010/ | primer | diakses 2026-10-09, dicek ulang 2026-10-22 | Tinggi. Kerangka teknik exfil; ATT&CK v20.0 |
| S2 | Zeek docs: conn.log/files.log; Zeek NEWS (catatan rilis 5.1 tentang penggantian `tx_hosts`/`rx_hosts`) | https://docs.zeek.org/en/current/logs/index.html | primer | diakses 2026-10-10 | Tinggi. Byte per arah, field `files.log` termasuk `is_orig`; catatan rilis ada di berkas NEWS repo zeek/zeek |
| S3 | RFC 7011 (IPFIX, byte per arah) | https://www.rfc-editor.org/rfc/rfc7011 | primer | diakses 2026-10-09 (Day 10) | Tinggi. Flow |
| S4 | MITRE ATT&CK T1048 Exfiltration Over Alternative Protocol (dan T1041, T1567, T1029, T1030, T1020, T1074, T1560) | https://attack.mitre.org/techniques/T1048/ | primer | diakses 2026-10-10, dicek ulang 2026-10-22 | Tinggi. Definisi teknik di tabel bagian 1.9; T1048 versi 1.6 (diubah 3 September 2026) |
| S5 | Network-Forensics Day 01-11 (DNS, TLS, Zeek, Suricata, flow, beaconing) | (lokal) | rujukan internal | 2026-10-09, diperbarui 2026-10-23 | Metadata, pola, dan insiden PT JAB sebelumnya |
| S6 | MITRE ATT&CK T1567.002 Exfiltration Over Web Service: Exfiltration to Cloud Storage | https://attack.mitre.org/techniques/T1567/002/ | primer | diakses 2026-10-22, dicek ulang 2026-10-23 | Tinggi. Versi 1.3, diubah 12 Mei 2026; strategi deteksi DET0570; analitik menyebut unggahan POST/PUT ke penyimpanan cloud setelah akses file atau kompresi, dan alat seperti rclone |
| S7 | MITRE ATT&CK T1048.003 Exfiltration Over Unencrypted Non-C2 Protocol | https://attack.mitre.org/techniques/T1048/003/ | primer | diakses 2026-10-22, dicek ulang 2026-10-23 | Tinggi. Versi 2.2, diubah 3 September 2026; DET0149; penyandian base64, data di subdomain DNS, transfer konfigurasi lewat FTP/TFTP |
| S8 | MITRE ATT&CK T1030 Data Transfer Size Limits | https://attack.mitre.org/techniques/T1030/ | primer | diakses 2026-10-22, dicek ulang 2026-10-23 | Tinggi. Versi 1.2, diubah 16 September 2026; DET0213; muatan berukuran seragam pada interval teratur |
| S9 | MITRE ATT&CK T1041 Exfiltration Over C2 Channel | https://attack.mitre.org/techniques/T1041/ | primer | diakses 2026-10-22, dicek ulang 2026-10-23 | Tinggi. Versi 2.4, diubah 11 September 2026; DET0348; volume keluar tidak cocok dengan kebiasaan proses, rasio byte abnormal, tujuan langka |
| S10 | MITRE ATT&CK T1700 AI-Enabled Exfiltration | https://attack.mitre.org/techniques/T1700/ | primer | diakses 2026-10-23 | Tinggi. Teknik baru, versi 1.0, diubah 9 Oktober 2026 |
| S11 | Zeek source: `scripts/base/protocols/conn/main.zeek`, `init-bare.zeek`, analyzer ICMP (cabang master) | https://github.com/zeek/zeek/blob/master/scripts/base/protocols/conn/main.zeek | primer (kode sumber) | diakses 2026-10-22, dicek ulang 2026-10-23 | Tinggi. Komentar field `orig_bytes` (dari sequence number, bisa tidak akurat pada koneksi besar), `orig_ip_bytes`, `missed_bytes`; semantik flow ICMP dan UDP; kode bisa berubah antar rilis |
| S12 | phaag/nfdump (repo resmi, README dan man page) | https://github.com/phaag/nfdump | primer (repo resmi alat) | diakses 2026-10-22 (Day 10) | Tinggi. Opsi `-r`, `-t`, `-A`, `-s`, `-N`; versi 1.7.10 (7 September 2026) |
| S13 | RFC 9846: The Transport Layer Security (TLS) Protocol Version 1.3 | https://www.rfc-editor.org/rfc/rfc9846 | primer | terbit Juli 2026, diakses 2026-10-23 | Tinggi. Bagian 5.1 dan 5.2: isi record maksimal 2^14 byte, header 5 byte, tipe konten di dalam ciphertext, ekspansi AEAD maksimal 255 byte |
| S14 | RFC 1035: Domain Names, Implementation and Specification | https://www.rfc-editor.org/rfc/rfc1035 | primer | diakses 2026-10-22 | Tinggi. Batas label 63 oktet, nama 255 oktet, pesan UDP 512 oktet |
| S15 | Squid configuration directive `logformat` | https://www.squid-cache.org/Doc/config/logformat/ | primer (dokumentasi resmi) | diakses 2026-10-22, dicek ulang 2026-10-23 | Tinggi. `%>st` ukuran permintaan dari klien, `%<st` ukuran balasan ke klien; format native `squid` memakai `%<st` |
| S16 | Microsoft Learn: Microsoft 365 URLs and IP address ranges | https://learn.microsoft.com/en-us/microsoft-365/enterprise/urls-and-ip-address-ranges | primer | diperbarui 2026-08-14, diakses 2026-10-23 | Tinggi. `*.sharepoint.com` untuk SharePoint Online dan OneDrive for Business; `storage.live.com` di kelompok OneDrive for Business |
| S17 | Microsoft Learn: Configure tenant restrictions v2 (Microsoft Entra External ID) | https://learn.microsoft.com/en-us/entra/external-id/tenant-restrictions-v2 | primer | diperbarui 2026-03-20, diakses 2026-10-23 | Tinggi. Authentication plane vs data plane, header `sec-Restrict-Tenant-Access-Policy`, batas proxy, OneDrive konsumen |
| S18 | Wireshark Display Filter Reference | https://www.wireshark.org/docs/dfref/ | primer | diakses 2026-10-23 | Tinggi. Field `http.request.method`, `dns.qry.name`, `tls.handshake.extensions_server_name`, `tls.record.length`; Wireshark 4.6.9 |
| S19 | Splunk Research: DNS Query Length With High Standard Deviation | https://research.splunk.com/network/1a67f15a-f4ff-4170-84e9-08cf6f75d6f5/ | primer (konten deteksi vendor) | versi 16, diperbarui 2026-05-13, diakses 2026-10-23 | Tinggi untuk logika analitik; memetakan ke T1048.003; membuang PTR, SOA, SRV |
| S20 | Salesforce Engineering: Detecting Multithreaded Exfiltration in Zeek | https://engineering.salesforce.com/detecting-multithreaded-exfiltration-in-zeek-e8a244885896/ | sekunder (blog engineering vendor) | tanggal 9 Februari, tahun tidak tertulis di halaman; diakses 2026-10-23 | Sedang-tinggi. PCR per koneksi -0,334 untuk exfil multithread; agregasi per sumber, tujuan, dan port tujuan; ambang dapat dikonfigurasi |
| S21 | w8mej/ThreatPlays: analyze_producer_consumer_ratio | https://github.com/w8mej/ThreatPlays/blob/master/analyze_producer_consumer_ratio.md | komunitas | diakses 2026-10-23 | Sedang. Rumus PCR dari byte aplikasi dan tabel patokan peran host; meringkas presentasi FloCon 2014 Bullard dan Gerth |

**Catatan sumber:** sinyal exfiltration (arah, volume, tujuan) adalah pengetahuan NSM/hunting mapan; ambang spesifik bergantung baseline lingkungan dan perlu dicek. Teknik exfil dirujuk ke ATT&CK, bukan ditulis sebagai prosedur; versi dan ID strategi deteksi mengikuti ATT&CK v20.0 per tanggal riset [S1][S4][S6][S7][S8][S9][S10]. Pembedaan dari backup/sync sah bergantung akun, jadwal, dan reputasi lingkungan; pola nama host OneDrive dan perilaku tenant restrictions mengikuti dokumentasi Microsoft per tanggal di tabel [S16][S17]. Perhitungan overhead TLS adalah aritmetika dari batas record RFC 9846 [S13] dengan asumsi tag AEAD 16 byte; padding opsional dan implementasi yang memecah record membuat overhead lebih besar. Perkiraan byte data DNS mengasumsikan base32 dan tidak ada kompresi. Patokan PCR berasal dari ringkasan praktisi [S21] karena presentasi FloCon 2014 tidak bisa dibuka saat riset; perilaku PCR pada koneksi paralel berasal dari blog engineering Salesforce [S20], bukan pengujian di PT JAB. Bentuk pencatatan `CONNECT` di `http.log` dan logformat proxy PT JAB adalah asumsi yang perlu dicek di versi Zeek dan Squid yang dipakai.
