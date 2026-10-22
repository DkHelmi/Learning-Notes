---
day: 07
title: 'Review minggu 1: sumber bukti, Wireshark, protokol, scan dan brute force, anomali DNS/HTTP, dan metadata TLS'
researched_on: 2026-10-22
versions_checked: 'Merangkum Day 01-06; Wireshark 4.6.9 stabil dan 4.4.19 old stable, 5.0.0rc1 rilis pengembangan (halaman unduhan, dicek 2026-10-22); Zeek 9.0.0 LTS (14 Sep 2026), LTS sebelumnya 8.0.10; RFC 9846 TLS 1.3 (Jul 2026, menggantikan RFC 8446 dan RFC 5246); RFC 9849 ECH (Mar 2026); MITRE ATT&CK v20.0: T1071.004 DNS versi 1.4 (diubah 3 Sep 2026), DET0400'
---

# Day 07: Review minggu 1 (sumber bukti, Wireshark, protokol, scan, DNS/HTTP, dan TLS)

Cakupan: ringkasan Day 01-06, peta konsep satu alur analisis pcap, lima insiden minggu pertama Program NSM PT JAB dan blind spot yang tersisa, tabel gejala ke protokol dan field ke jinak atau mencurigakan, glosarium, lalu lab gabungan atas lima alert Rabu pagi, latihan di lab pribadi, dan skenario dengan pembahasan.

## Ide inti

Day 01-06 bukan enam alat terpisah, tetapi satu cara kerja. Setiap analisis jaringan dimulai dari pertanyaan (siapa, ke mana, kapan, apa), lalu memilih sumber yang benar-benar melihat kejadian itu dari titik pandangnya, membaca bentuk percakapan protokolnya, mencocokkannya dengan tiga keluarga pola (akses: scan dan brute force; protokol polos: DNS dan HTTP; terenkripsi: TLS), dan selalu berakhir di penyaring yang sama: sinyal, penjelasan jinak, dan korroborasi, ditulis bersama batasnya (posisi sensor, retensi, enkripsi). Cara kerja itu sudah kokoh bila kamu bisa mengambil tiket apa pun dari minggu ini dan menjelaskan, tanpa membuka catatan, sumber mana yang melihatnya, apa yang tidak terlihat dari sana, dan apa yang membuatnya jinak atau perlu dinaikkan. Menghafal filter tidak cukup; yang diuji di pekerjaan dan di interview adalah alurnya.

Minggu depan sifat pekerjaannya berubah. `jkt-zeek01` hidup Selasa 2027-05-18 dan `jkt-ids01` Rabu 2027-05-19, sehingga sebagian besar pembacaan manual minggu ini (siapa bicara dengan siapa, SNI, sertifikat, fingerprint, nama file) akan muncul sebagai log dan alert. Kebiasaan yang terbentuk minggu ini menentukan apakah log itu dibaca dengan benar: Zeek tetap hanya melihat apa yang lewat sensornya, dan alert Suricata tetap sinyal, bukan kesimpulan.

Analoginya laporan gangguan bulanan NOC. Setelah sebulan tiket, NOC tidak cukup menulis "ada 40 gangguan"; laporan yang berguna menyebut gangguan mana yang terdeteksi monitoring dan mana yang dilaporkan pelanggan lebih dulu, akar masalahnya, dan link mana yang ternyata tidak di-export NetFlow sehingga gangguannya baru diketahui dari telepon pelanggan. Review ini melakukan hal yang sama untuk minggu pertama Program NSM. Batas analoginya: gangguan link tidak berusaha bersembunyi, dan laporan NOC menjelaskan kejadian yang sudah diketahui. Laporan NSM juga harus menyebut apa yang sama sekali tidak bisa dilihat, karena penyerang yang memilih jalur tanpa sensor tidak akan pernah muncul sebagai tiket. Seperti `logging buffered` yang sudah menimpa entri lama, ring buffer pcap juga tidak bisa diputar mundur.

```
 pertanyaan (siapa, ke mana, kapan, apa)
        |
        v
 sumber + titik pandang (Day 01)   pcap egress | log proxy/DNS/firewall | flow | EDR
        |                           "tidak ada di pcap" != "tidak terjadi"
        v
 alat (Day 02)   pcap kasus + hash -> Statistics -> display filter -> Follow Stream -> Export Objects -> tshark
        |
        v
 bentuk percakapan (Day 03)   mekanis (capture, jaringan, firewall)?  atau dipakai untuk hal tak normal?
        |
        v
 tiga keluarga pola   akses (Day 04) | DNS/HTTP (Day 05) | TLS (Day 06)
        |
        v
 sinyal + penjelasan jinak + korroborasi (host, log lain, pemilik)
        |
        v
 jinak terkonfirmasi | eskalasi (INC) | data tidak cukup   + batas tertulis
```

Situasi Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan sekitar 1.200 karyawan, kantor pusat dan data center di Jakarta, serta NOC 24/7 yang satu lantai dengan SOC. Senin 2027-05-03, Direktur Teknologi Hendra Wijaya menyetujui Program NSM PT JAB sebagai percobaan Mei sampai Juli 2027, dengan SOC lead Dimas Prasetyo sebagai sponsor dan kamu (analyst L2 dengan latar tujuh tahun di NOC), Bambang Hartono (Manajer NOC), dan Agung Prabowo (Lead Infrastruktur) sebagai pelaksana. Sensor yang hidup minggu ini baru satu: `jkt-pcap01` (`10.20.70.13`), ring buffer pcap uji coba sejak Selasa 2027-05-04 di TAP egress Jakarta, sisi dalam firewall `jkt-fw01`, dengan target retensi 72 jam. Analisis dikerjakan di `jkt-nsm-ws01` (`10.20.70.20`). Selain itu SOC punya log firewall, proxy `jkt-proxy01`, resolver `jkt-res01` dan `jkt-res02`, VPN, Microsoft Defender for Endpoint (MDE), dan flow NOC di `jkt-flow01`. Rabu 2027-05-12 pukul 08:05, Dimas menulis:

> "Minggu pertama selesai. Jumat aku ketemu Pak Hendra, dan Selasa depan Zeek hidup, Rabu Suricata. Tolong siapkan satu halaman: apa yang sebenarnya sudah kelihatan dari pcap uji coba, lima insiden minggu ini (061 sampai 065) ketemunya dari mana dan pcap menambah apa, dan blind spot apa yang masih tersisa, termasuk yang tidak akan beres walaupun Zeek dan Suricata sudah jalan. Aku tidak mau menjanjikan yang tidak bisa."

Pukul 08:20 Sari Kusuma (analyst L2) menambahkan di kanal yang sama:

> "Aku mau pakai antrean pagi ini sebagai latihan gabungan buat Gilang dan Dwi sebelum Zeek datang. Ada lima: scan ke IP publik kita (0630), TXT panjang dari satu laptop (0631), NXDOMAIN banyak dari laptop yang baru balik WFH (0632), alert MDE di laptop yang sama dengan 0631 (0633), dan MDE di laptop yang sedang VPN dari rumah (0634). Tolong kerjakan bareng mereka dengan alur minggu ini, dan siapkan tabel gejala yang bisa mereka pegang: gejala apa, lihat field apa, kapan jinak, kapan mencurigakan. Sama daftar istilahnya, Dwi masih sering tertukar capture filter dan display filter."

Dua pesan itu memuat tujuh pertanyaan:

1. Apa inti Day 01-06 yang harus dikuasai sebelum Zeek dan Suricata hidup?
2. Bagaimana semua itu tersambung menjadi satu alur kerja?
3. Apa yang sudah terlihat dari pcap uji coba, dan dari mana lima insiden minggu ini ditemukan?
4. Blind spot apa yang tersisa, dan mana yang tidak akan ditutup Zeek dan Suricata?
5. Bagaimana L1 menilai sebuah gejala: field apa, kapan jinak, kapan mencurigakan?
6. Istilah apa yang wajib dipahami?
7. Bagaimana lima alert Rabu pagi dikerjakan dengan alur minggu ini?

Pertanyaan 1 dijawab di bagian 1.1 sampai 1.6, pertanyaan 2 di bagian 1.7, pertanyaan 3 di bagian 1.8, pertanyaan 4 di bagian 1.9, pertanyaan 5 di bagian 1.10, pertanyaan 6 di bagian 1.11, dan pertanyaan 7 di lab gabungan (Bagian A sampai F). Bagian 1.12 adalah satu halaman yang dikirim ke Dimas.

**Kapan relevan:** sebelum masuk Zeek, Suricata, dan flow (Day 08 dan seterusnya), saat melatih L1 membaca pcap, saat menyiapkan laporan berkala ke manajemen tentang apa yang terlihat dan tidak terlihat, dan sebelum interview yang meminta kamu menceritakan satu analisis pcap dari awal sampai keputusan.
**Kapan bukan jawaban:** review ini tidak menambah konsep baru di luar Day 01-06; bila ada yang terasa baru, kembali ke Day asalnya. Review ini juga tidak membahas Zeek, Suricata, beaconing, atau exfiltration secara mendalam; itu Day 08 sampai Day 12.

## 1. Ringkasan, peta konsep, dan glosarium

Ringkasan per Day di bawah ditulis cukup lengkap untuk dibaca tanpa membuka Day asalnya, tetapi detail perintah, angka, dan sumbernya tetap ada di Day asal. Ringkasan mewarisi sumber dan tingkat keyakinan Day asalnya [S1].

### 1.1 Day 01: sumber bukti, NSM, posisi sensor, retensi, privasi dan legal

Pertanyaan Hendra di Day 01 ("log-nya banyak, kenapa `INC-2027-060` inkonklusif?") adalah titik awal semua yang terjadi minggu ini.

- Bukti jaringan hanya ada bila ditangkap saat lewat; ia tidak bisa diambil mundur, dan sering terenkripsi sehingga metadata menjadi penting. `INC-2027-060` (beacon `JKT-WS-2001` lewat proxy ke `cdn-sync.example.net`, akhir April) gagal di fase collection: tidak ada sumber yang merekam isi.
- Bukti tersusun dalam piramida. Paling atas pcap penuh: isi lengkap, paling mahal, retensi hari sampai minggu. Di bawahnya log transaksi Zeek (satu baris per koneksi atau transaksi, retensi minggu sampai bulan), alert IDS, flow NetFlow/IPFIX (ringkasan 5-tuple dan byte, retensi bulan sampai tahun), lalu log DNS, proxy, dan firewall. Strategi realistis: flow dan Zeek di semua titik penting dengan retensi panjang, pcap di titik kritis dengan retensi pendek, dan pcap insiden disimpan lebih lama.
- Angka yang perlu diingat: link 1 Gbps yang penuh menghasilkan 125 MB per detik, sekitar 10,8 TB per hari dan sekitar 324 TB per 30 hari. Angka ini menjelaskan kenapa pcap penuh jarang disimpan lama. Untuk `jkt-pcap01` (ring buffer 8,4 TB), jendelanya sekitar 93 jam pada utilisasi rata-rata 20%, sekitar 53 jam pada 35%, dan sekitar 18,7 jam bila link penuh.
- NSM adalah praktik sengaja mengumpulkan data jaringan supaya deteksi dan investigasi bisa dilakukan: sensor di posisi yang tepat, beberapa jenis data, dan analis yang memakainya. IDS hanya alarm; NSM adalah alarm ditambah rekaman dan orang yang bisa membacanya.
- Flow tidak cukup sendirian: tanpa isi, di-sampling 1:1000 di edge (koneksi 12 paket hanya terwakili sekitar 1,2%), dan titik observasinya setelah proxy dan NAT.
- Posisi sensor menentukan blind spot. Sensor di egress melihat C2 dan exfiltration, tetapi tidak melihat lateral movement antar workstation di switch yang sama. PT JAB memasang TAP egress di sisi dalam `jkt-fw01` (alamat internal masih terlihat) dan SPAN di core switch data center untuk segmen server.
- Dari sisi hukum, minggu ini memakai dua rujukan yang perlu dikenali bersama. UU ITE Pasal 31 melarang intersepsi tanpa hak, dan materi lama masih mengutipnya. Sejak KUHP baru berlaku 2 Januari 2026, Pasal 622 KUHP mencabut Pasal 31 ayat (1) dan (2) UU ITE, dan larangan penyadapan kini ada di KUHP Pasal 258 (Day 01 bagian 1.7). UU 27/2022 tentang PDP mengatur pemrosesan data pribadi, termasuk yang terekam di pcap.
- Praktik aman: tangkap hanya di lab atau pakai pcap publik, jangan membawa pcap kerja ke laptop pribadi, dan pastikan ada kebijakan tertulis untuk monitoring di tempat kerja. Draf kebijakan akses pcap PT JAB (Day 01 bagian 2.8) menetapkan lingkup tanpa trafik pelanggan, akses tercatat, dan persetujuan SOC lead, DPO, dan Legal untuk mengambil semua trafik satu karyawan. Untuk pertanyaan hukum yang spesifik, tanya tim legal.

### 1.2 Day 02: Wireshark esensial

Day 02 menjawab tiket pertama `jkt-pcap01`: Bambang melihat `198.51.100.202` (NAT aturan lama `NOC-VENDOR-DIRECT`) menarik sekitar 1,4 GB dari `203.0.113.162:8080`.

- Pcap egress berisi byte buatan pihak luar, termasuk penyerang, dan setiap byte diurai dissector. Karena itu: Wireshark versi stabil terbaru (4.6.9) sebagai user biasa, hak capture hanya untuk `dumpcap`, resolusi nama jaringan mati (`tshark -n`), potong dulu lalu buka, kerja di salinan dengan SHA-256, dan file hasil Export Objects diperlakukan sebagai sampel.
- Pcap menyimpan waktu dalam UTC; Wireshark menampilkan waktu lokal mesin pembaca. `jkt-pcap01` dan `jkt-nsm-ws01` diset UTC, Splunk dan dashboard flow NOC menampilkan WIB (UTC+7). Literal waktu di display filter tanpa "Z" dibaca sebagai waktu lokal mesin. Setiap jam di laporan diberi "Z" atau "WIB".
- Capture filter (sintaks BPF: `host`, `port`, `net`) memutuskan apa yang disimpan, dan paket yang dibuangnya hilang permanen. Display filter (sintaks Wireshark: `ip.addr`, `tcp.port`, `http.request`) hanya menyembunyikan tampilan. Untuk forensik, tangkap luas dan persempit dengan display filter. Usul Agung menyimpan port 80 dan 443 saja ditolak karena kasus pertama sendiri ada di port 8080.
- Operator yang menjebak: `ip.addr != X` berarti "semua tidak sama", jadi negasi paling jelas ditulis `!(ip.addr == X)`; `contains` tidak bisa dipakai pada field angka atau alamat; `matches` memakai PCRE2 dan tidak peka huruf secara default.
- Alur membuka pcap yang belum dikenal: Statistics > Protocol Hierarchy (isinya apa), Conversations (siapa ke siapa dan berapa banyak), Endpoints, lalu pivot ke sesi menarik dengan display filter dan Follow Stream [S2]. IO Graph memperlihatkan pola waktu, misalnya trafik teratur yang mengarah ke beacon atau lonjakan upload. Export Objects memulihkan file dari protokol polos (HTTP, SMB, FTP), yang lalu di-hash; cek dulu Expert Information untuk segmen yang hilang. Expert Information memperlihatkan anomali jaringan (retransmission, reset), bukan ancaman. tshark mengekstrak field ke tabel untuk stacking dan otomasi: `tshark -r f.pcap -Y "<filter>" -T fields -e <field>`.
- Profil tim `JAB-NSM` menyimpan kolom, coloring, dan tombol filter supaya analisis bisa diulang; profil hanya diimpor dari repo tim di Wireshark 4.6.9 atau lebih baru.
- Hasilnya: unduhan besar adalah firmware OLT (jinak, tetapi kredensial mirror vendor terkirim plaintext), dan pcap menemukan hal yang tidak ditanyakan siapa pun: `JKT-WS-2007` mengunduh `/a.hta` dari `203.0.113.163` lalu TLS tiap sekitar 60 detik ke `static-update.example.net`. Dengan alert MDE `SOC-2027-0607` tentang `mshta.exe`, itu menjadi `INC-2027-061`.

### 1.3 Day 03: protokol dari sudut forensik

Day 03 memilah lima item di antrean Sari dengan satu pertanyaan: penyimpangan ini mekanis atau dipakai untuk hal yang tidak normal?

- TCP memberi cerita koneksi lewat flag: SYN, SYN-ACK, ACK membuka koneksi; RST memutus paksa; FIN menutup normal. `tcp.stream` mengelompokkan satu koneksi, dan `tcp.completeness` merangkum tahap yang terlihat (33 berarti SYN dan RST saja, koneksi ditolak). UDP tidak punya handshake, jadi "koneksi" disimpulkan dari pasangan alamat dan waktu.
- RST bisa dibuat firewall atas nama tujuan. Di `SOC-2027-0611`, RST datang 1 ms setelah SYN dengan TTL 64, padahal paket asli dari `203.0.113.164` tiba dengan TTL 49 setelah 38 ms: `jkt-fw01` yang menolak, server tujuan tidak pernah menerima SYN.
- Retransmission hampir selalu masalah jaringan, sedangkan celah urutan yang kemudian di-ACK tanpa pengiriman ulang (ACKed unseen) adalah kehilangan di alat capture. Di `SOC-2027-0610`, 98,5% celah seperti itu, sehingga tindak lanjutnya tiket kapasitas `jkt-pcap01`, bukan gangguan link dan bukan insiden.
- Titik pandang sensor: di pcap egress, sumber HTTP adalah proxy `jkt-proxy01` (`10.20.3.60`) dan sumber DNS adalah resolver (`10.20.2.53`, `10.20.2.54`). Klien asli dicari di `index=proxy` dan `index=dns` lewat waktu dan tujuan. Jumlah query di pcap egress biasanya lebih kecil dari log resolver karena cache.
- HTTP polos memperlihatkan method, host, URI, User-Agent, status, dan isi. DNS memperlihatkan nama yang dicari (`dns.qry.name`), tipe record (A, AAAA, TXT, CNAME), dan kode jawaban (NXDOMAIN = nama tidak ada). SMB memperlihatkan share yang diakses (`smb2.tree`) dan nama berkas (`smb2.filename`); akses `C$` atau `ADMIN$` dari workstation ke workstation adalah kandidat lateral movement. FTP mengirim perintah dan kredensial polos (USER, PASS, RETR untuk unduh, STOR untuk unggah). Kredensial yang terlihat dicatat keberadaannya, bukan nilainya.
- HTTPS masih memberi SNI, versi terpilih, ALPN, cipher, dan alert; versi asli TLS 1.3 dibaca dari `supported_version` di ServerHello, bukan dari field legacy 0x0303.
- Kebiasaan yang dibawa: mulai dari pertanyaan, lalu pilih protokol dan field yang menjawabnya. Domain dari DNS, HTTP Host, atau SNI; file dari HTTP, SMB, atau FTP; scan dari pola SYN; lateral movement dari SMB (dengan sensor yang tepat).
- Hasilnya: TXT banyak dari mail gateway adalah pemeriksaan SPF (jinak), FTP malam `jkt-recon01` adalah job terjadwal dengan kredensial plaintext (jinak, temuan risiko), dan dua kanal dari `JKT-WS-2011` (SYN ke port 4444 tiap 60 detik yang ditolak, lalu POST tiap 300 detik lewat proxy ke tujuan yang sama) menjadi `INC-2027-062` setelah EDR menemukan proses tanpa tanda tangan.

### 1.4 Day 04: pemindaian dan brute force

Day 04 membaca satu malam yang ramai: scan dan brute force ke server FTP lama, sweep dari dua sumber, dan spray VPN.

- Tipe scan dikenali dari respons target. SYN scan: SYN keluar, SYN-ACK berarti terbuka, RST berarti tertutup, lalu scanner mengirim RST tanpa menyelesaikan handshake. Connect scan menyelesaikan handshake. FIN/NULL/Xmas memakai kombinasi flag tidak lazim. UDP scan bergantung pada ICMP port unreachable untuk port tertutup. ACK scan memetakan aturan firewall.
- Vertikal berarti satu sumber ke banyak port di satu host (penyerang fokus pada satu target); horizontal berarti satu port di banyak host (penyerang mencari layanan tertentu, misalnya SMB 445). Nilai investigasinya ada pada dampak: port mana yang menjawab SYN-ACK, dan apakah scan diikuti koneksi ke port itu.
- Tiga sensor memberi tiga angka yang sama-sama benar: firewall melihat semua probe, pcap di sisi dalam hanya melihat probe yang diizinkan dan sesudah DNAT, flow edge 1:1000 hampir buta terhadap probe satu paket. Hitung port unik, bukan paket.
- Brute force mencoba banyak kata sandi untuk satu akun; password spray mencoba sedikit kata sandi untuk banyak akun. Di protokol polos, kegagalan terlihat (FTP 530, HTTP 401, SMB `STATUS_LOGON_FAILURE`). Di SSH hanya pola koneksi yang terlihat: banyak sesi pendek ke port 22, lalu satu sesi panjang yang mungkin berarti login berhasil; kesimpulannya dari log autentikasi. Scanner kerentanan internal dan health check menghasilkan pola serupa, jadi sumber dan jadwal selalu diperiksa.
- Rule yang hanya menghitung kegagalan menyesatkan: shift malam mencatat "gagal semua", padahal pcap menunjukkan `230 Login successful` untuk `mitra.instalasi` setelah 2.310 kegagalan, lalu dua unduhan. Itu `INC-2027-063`. Spray VPN terdistribusi (37 sumber, 206 akun) lolos rule per IP; dua kegagalan `mfa-denied` berarti password dua akun sudah benar.
- Sweep `203.0.113.167` adalah scanner riset (jinak), dan sweep port 445 dari `JKT-WS-2017` adalah skrip inventaris tanpa tiket perubahan (pelanggaran kebijakan, bukan insiden). Bentuk sama, konteks berbeda.

### 1.5 Day 05: anomali DNS dan HTTP

Day 05 memilah lima tiket DNS dan HTTP, dan menegaskan bahwa sumber yang melihat isi belum tentu melihat klien.

- DNS tunneling menyelundupkan data di label subdomain: nama panjang dengan karakter acak, banyak query TXT atau NULL, dan volume tinggi ke satu domain induk. Format tetap yang dipakai banyak klien satu tim (lisensi GIS di `SOC-2027-0622`) adalah layanan, bukan tunnel.
- DGA menghasilkan banyak nama acak, sehingga terlihat sebagai rentetan NXDOMAIN sampai satu nama terdaftar menjawab. Nama terstruktur dan bermakna (inventaris switch lama di `SOC-2027-0621`) adalah konfigurasi usang, bukan DGA. NXDOMAIN di-cache resolver selama TTL negatif dari SOA, sehingga egress bisa melihat lebih sedikit ulangan daripada log.
- Fast flux memetakan satu domain ke banyak IP yang berganti cepat dengan TTL rendah. CDN juga memakai banyak IP dan TTL rendah, tetapi IP-nya berada di rentang milik penyedia yang dikenal. TTL rendah dengan satu IP bukan fast flux.
- Anomali HTTP: User-Agent kosong atau khas tool, URI acak atau dengan parameter base64 panjang, Host berupa IP langsung, POST berulang ke endpoint yang sama, dan unduhan executable tanpa navigasi sebelumnya. User-Agent bisa dipalsukan ke dua arah.
- Magic byte menentukan tipe berkas sebenarnya (`MZ` untuk PE Windows), bukan ekstensi atau Content-Type; kolom Content Type di Export Objects pun hanya header. Entropi dan panjang hanya penyaring awal, karena token, hash, dan nama CDN juga terlihat acak.
- Konteks yang menentukan: pemilik, prevalence, first-seen, proses, dan sinyal kedua yang independen. Log resolver PT JAB hanya mencatat query (tanpa kode jawaban), log proxy mencatat URL tanpa isi, dan pcap egress mencatat rcode dan isi tanpa tahu kliennya.
- Hasilnya: tiga tiket jinak, dan dua tiket (`tagihan-mei-2027.pdf` yang ternyata PE, dan NXDOMAIN acak per jam yang ternyata `JKT-WS-2021` tanpa MDE) menjadi `INC-2027-064`. Unduhan hari Kamis sudah tertimpa di ring buffer; log proxy 30 hari yang menyelamatkan timeline.

### 1.6 Day 06: metadata TLS, JA3/JA4, proxy dekripsi, keylog

Day 06 menjawab "apa yang masih bisa dilihat bila hampir semuanya TLS".

- Isi TLS tertutup, tetapi ClientHello (termasuk SNI, kecuali bila ECH dipakai), ServerHello, ukuran, dan waktu record tetap terlihat. Di TLS 1.2 sertifikat server terlihat polos (subject, issuer, masa berlaku, SAN); di TLS 1.3 sertifikat ikut dienkripsi karena semua pesan handshake setelah ServerHello dienkripsi [S5]. Sinyal sertifikat: self-signed untuk layanan yang seharusnya publik, masa berlaku sangat pendek atau baru dibuat, dan nama yang tidak cocok dengan SNI.
- JA3 adalah hash MD5 atas parameter Client Hello; JA4 adalah penerusnya dengan format string terstruktur yang lebih tahan perubahan urutan ekstensi. Keduanya mengenali library atau aplikasi klien, bukan isi; banyak aplikasi berbagi fingerprint yang sama, jadi kecocokan adalah sinyal, bukan bukti. Cocokan JA3 dari bulletin vendor di `SOC-2027-0627` ternyata collision dengan skrip NOC.
- Proxy eksplisit mengubah apa yang terlihat. Koneksi yang di-splice membawa ClientHello asli klien; koneksi yang di-bump (domain baru dan tidak terkategori) membawa ClientHello buatan proxy, sehingga fingerprint di egress milik proxy. Workstation hanya ditemukan lewat log `jkt-proxy01`.
- Dekripsi dengan `SSLKEYLOGFILE` hanya untuk trafik lab sendiri atau trafik uji milik SOC. Private key server tidak cukup untuk ECDHE dan TLS 1.3. Di korporat, isi TLS biasanya hanya tersedia lewat proxy inspeksi yang merupakan keputusan kebijakan, bukan teknik forensik.
- Hasilnya: `jkt-cirunner02` menghubungi `203.0.113.170` tiap rata-rata 60,4 detik dengan sertifikat self-signed dan JA4 yang hanya ada di host itu. Setelah DevOps menemukan proses `edge-sync` tanpa tiket perubahan, `INC-2027-065` dibuka dan diserahkan ke IR.

### 1.7 Peta konsep Minggu 1

Peta berikut menggabungkan enam Day dalam satu gambar. Pakai sebagai satu-satunya bantuan saat lab gabungan dan saat menjelaskan alur ke L1.

```
                  PERTANYAAN INVESTIGASI
                 (siapa, ke mana, kapan, apa)
                            |
          +-----------------+------------------+
          |                                    |
   SUMBER BUKTI (Day 01)               ALAT (Day 02)
   pcap > Zeek > alert > flow          capture vs display filter
   posisi sensor = blind spot          Statistics -> filter -> Follow Stream
   retensi ring buffer                 waktu UTC vs WIB, pcap kasus + hash
          |                                    |
          +-----------------+------------------+
                            |
                 PROTOKOL DAN FIELD (Day 03)
                 TCP flags | HTTP | DNS | SMB | FTP | TLS awal
                 mekanis (capture/jaringan/firewall) vs dipakai tak normal
                 titik pandang: proxy, resolver, NAT
                            |
        +-------------------+--------------------+
        |                   |                    |
   POLA AKSES (Day 04)  POLA PROTOKOL (Day 05)  POLA TERENKRIPSI (Day 06)
   scan V/H, brute,     tunneling, DGA, flux,   SNI, sertifikat, JA3/JA4,
   spray, dampak        UA, magic byte          splice/bump, ukuran + waktu
        |                   |                    |
        +-------------------+--------------------+
                            |
             SINYAL + KONTEKS + PENJELASAN JINAK
         (pemilik, prevalence, first-seen, host/EDR, log lain)
                            |
              TIMELINE, IOC (defang), KEYAKINAN, BATAS
```

Peta ini dibaca dari atas: pertanyaan menentukan sumber dan alat, protokol memberi field, tiga keluarga pola memberi sinyal, dan semua sinyal melewati penyaring yang sama (konteks dan penjelasan jinak) sebelum menjadi temuan. Baris terbawah selalu memuat batas: dari titik mana bukti diambil, rentang waktu apa yang masih tersimpan, dan apa yang tertutup enkripsi.

### 1.8 Lima insiden dan apa yang ditambahkan pcap uji coba

Pertanyaan Dimas yang ketiga adalah inti bahan rapat Jumat: apakah pcap uji coba sudah membuktikan nilainya, atau insiden itu sebenarnya akan ditemukan juga tanpa pcap? Tabel berikut menjawabnya per insiden. Baca kolom "Yang hanya ada di pcap" dan "Yang tidak bisa dijawab pcap"; dua kolom itu adalah alasan program ini ada dan batasnya.

| Insiden | Host | Pemicu awal | Yang hanya ada di pcap | Yang tidak bisa dijawab pcap | Day |
|---|---|---|---|---|---|
| `INC-2027-061` | `JKT-WS-2007` (`10.10.60.22`) | Laporan flow Bambang tentang hal lain (unduhan firmware) | Request `/a.hta` dari IP mentah, isi file dan hash, 32 Client Hello tiap sekitar 60 detik; host berada di aturan tanpa proxy, jadi tidak ada log proxy | Apakah `mshta.exe` berjalan (dijawab MDE `SOC-2027-0607`) | Day 02 |
| `INC-2027-062` | `JKT-WS-2011` (`10.10.60.31`) | Rule firewall dan rule proxy | RST dibuat firewall (koneksi 4444 tidak pernah tersambung), isi POST, satu tujuan untuk dua kanal | Proses pembuat koneksi (dijawab EDR) | Day 03 |
| `INC-2027-063` | `jkt-dmz-ftp01` (`10.20.9.45`) | Rule port scan dan rule login FTP gagal | `230` setelah 2.310 kali `530`, dua `RETR` dengan `150` dan `226`, `STOR` ditolak; tanpa pcap, catatan "gagal semua" akan bertahan | Login SSH dan VPN (dijawab log `sshd` dan `index=vpn`); isi file sebagai data pelanggan (dikonfirmasi pemilik data) | Day 04 |
| `INC-2027-064` | `JKT-WS-2021` (`10.10.60.51`), `JKT-WS-2023` (`10.10.60.53`) | Alert MDE dan ringkasan harian pcap (Gilang) | Kode NXDOMAIN (tidak ada di log resolver), magic byte `MZ` di file berlabel PDF | Klien asli (dijawab `index=dns` dan `index=proxy`); unduhan Kamis yang sudah tertimpa ring buffer | Day 05 |
| `INC-2027-065` | `jkt-cirunner02` (`10.20.45.22`) | Correlation search firewall "server DC egress ke tujuan baru" | Sertifikat self-signed, JA4 langka, ukuran record tetap, interval 60,4 detik | Isi record (tanpa kunci); proses `edge-sync` dan asal commit (dijawab DevOps dan IR) | Day 06 |

Ringkasan antrean minggu ini: 23 alert dan tiket (`SOC-2027-0605` sampai `0607` dan `0610` sampai `0629`) dipilah menjadi lima insiden, satu temuan kapasitas sensor (`0610`), satu pelanggaran kebijakan (`0619`), satu false positive intel (`0627`), dan sisanya jinak, beberapa dengan temuan risiko (kredensial plaintext di `0605`, `0614`, dan `0623`).

Pola yang muncul berulang:

- **Pcap jarang menjadi pemicu, tetapi sering menjadi pembeda.** Hanya `0624` yang lahir dari ringkasan pcap. Di insiden lain, pcap mengubah sinyal lemah menjadi cerita yang bisa dibuktikan, atau membantah catatan yang keliru (`INC-2027-063`).
- **Pcap tidak pernah memberi nama proses.** Setiap insiden butuh telemetri host atau pemilik sistem untuk menjadi kesimpulan.
- **Atribusi selalu lewat log.** Di balik proxy dan resolver, workstation tidak ada di paket egress.
- **Retensi nyata lebih pendek dari target saat dibutuhkan.** Senin pagi paket tertua di ring buffer adalah Kamis 20:10, sekitar 84 jam; unduhan Kamis 15:31 di `INC-2027-064` sudah hilang.

### 1.9 Blind spot yang tersisa, dan mana yang ditutup Zeek dan Suricata

Pertanyaan keempat Dimas ("jangan sampai aku menjanjikan yang tidak bisa") dijawab dengan tabel ini. Kolom paling kanan adalah yang paling sering disalahpahami: sensor baru minggu depan memakai sumber trafik yang sama dengan `jkt-pcap01` ditambah SPAN core DC, jadi tidak menambah titik pandang di luar dua titik itu.

| Blind spot | Contoh minggu ini | Ditutup Zeek/Suricata minggu depan? |
|---|---|---|
| Klien di balik proxy dan resolver pada pcap egress | Semua HTTP dan DNS di pcap tampak dari `10.20.3.60` dan `10.20.2.53`/`.54` (Day 03, 05) | Sebagian: SPAN core DC melihat sesi workstation ke proxy dan ke resolver, sehingga Zeek bisa merangkai kedua hop |
| Lateral movement antar workstation di switch akses yang sama | Pcap egress nol SMB (Day 03 bagian 2.7); sweep `JKT-WS-2017` hanya terlihat di flow router DC (Day 04) | Tidak; trafik workstation ke workstation tidak lewat TAP egress maupun SPAN core |
| Isi TLS yang tidak di-bump proxy | `INC-2027-060`, `INC-2027-065` | Tidak; Zeek dan Suricata membaca metadata TLS yang sama, lebih cepat dan otomatis |
| Login VPN | `jkt-vpn01` tersambung sejajar firewall (Day 04) | Tidak; pakai `index=vpn` |
| Laptop VPN split tunnel, AWS dan Azure | Disebut di Day 01 bagian 1.5 | Tidak |
| Kantor Bandung dan Medan | Disebut di Day 01 bagian 1.5 | Tidak di fase ini |
| Retensi pendek | Unduhan Kamis di `INC-2027-064` tertimpa | Sebagian: log Zeek disimpan jauh lebih lama daripada pcap, tetapi isi file tetap hanya selama ring buffer |
| Paket hilang di sensor | `SOC-2027-0610` (ACKed unseen saat puncak) | Diukur, bukan ditutup: Zeek mencatat `capture_loss.log`; kapasitas tetap urusan Agung |
| Koneksi kecil di flow edge | Sampling 1:1000 (Day 01 bagian 1.4) | Tidak mengubah flow; Zeek mencatat setiap koneksi di titiknya |

Satu kalimat yang perlu diulang di setiap laporan: "tidak ada di pcap" berarti "tidak sampai ke sensor" atau "sudah tertimpa", bukan "tidak terjadi".

### 1.10 Tabel gejala ke protokol, field, dan penilaian

Pertanyaan kelima Sari adalah lembar pegangan L1. Isi dulu kolom "Jinak bila" dan "Mencurigakan bila" tanpa membuka tabel ini, lalu bandingkan. Tabel pertama adalah gejala umum di pcap; tabel kedua memakai tiket minggu ini sebagai contoh nyata.

| Gejala di pcap | Protokol/field | Filter (Wireshark) | Jinak bila | Mencurigakan bila |
|---|---|---|---|---|
| Banyak SYN ke banyak port satu host | TCP flags | `tcp.flags.syn==1 and tcp.flags.ack==0` | Scanner internal terjadwal | Sumber eksternal tak dikenal |
| Satu port ke banyak host | TCP flags | `... and tcp.dstport==445` | Discovery/monitoring sah | Sweep cari layanan rentan |
| FTP 530 berulang | FTP response | `ftp.response.code==530` | Salah ketik pengguna | Brute force (banyak cepat) |
| Banyak koneksi pendek ke port 22 | TCP | `tcp.port==22` | Health check | Brute force SSH (pola) |
| Query DNS panjang/acak ke 1 domain induk | DNS | `dns.qry.name`, type 16 | CDN/layanan dinamis | Tunneling (volume + entropi) |
| Banyak NXDOMAIN nama acak | DNS rcode | `dns.flags.rcode==3` | Search domain salah konfigurasi | DGA (acak + teratur) |
| 1 domain ke banyak IP, TTL rendah | DNS | `dns.a`, `dns.resp.ttl` | CDN sah (rentang dikenal) | Fast flux (domain mencurigakan) |
| UA kosong/khas tool | HTTP | `http.user_agent` | Updater/tool internal sah | C2 (dengan pola lain) |
| GET .jpg tapi isi MZ | HTTP magic byte | Export Objects | (jarang jinak) | Payload disamarkan |
| SNI ke domain baru | TLS | `tls.handshake.extensions_server_name` | Layanan cloud baru sah | C2 (dengan JA3/pola) |
| Sertifikat tak terlihat | TLS versi | `tls.handshake.version` | TLS 1.3 normal | (bukan sinyal sendiri) |
| App Data ukuran/interval tetap | TLS pola | `tls.record.content_type==23` | Keep-alive sah | Beaconing (teratur) |

Prinsip berulang: hampir setiap sinyal punya penjelasan jinak; yang membedakan adalah kombinasi sinyal, konteks sumber, reputasi, dan pola waktu. Satu sinyal jarang cukup untuk kesimpulan.

Tabel kedua menunjukkan bahwa kolom "jinak bila" bukan teori: sebagian besar tiket minggu ini memang jinak, dan pembedanya hampir selalu konteks, bukan bentuk paket.

| Gejala yang terlihat | Field atau sumber | Jinak di minggu ini | Mencurigakan di minggu ini | Day |
|---|---|---|---|---|
| Ribuan retransmission dan "previous segment not captured" | `tcp.analysis.lost_segment`, `tcp.analysis.ack_lost_segment` | `0610`: celah di-ACK, drop di sensor | Tidak ada | Day 03 |
| SYN selalu dibalas RST | TTL dan jeda RST, `tcp.completeness == 33` | Port tertutup di server | `0611`: RST dari firewall, percobaan tiap 60 detik | Day 03 |
| POST berulang | `http.request.method`, interval, UA | `0623`: skrip NOC, pemilik jelas | `0613`: satu klien, UA generik, 300 detik | Day 03, 05 |
| TXT banyak | `dns.qry.type == 16`, domain induk, panjang | `0612`: SPF mail gateway; `0622`: lisensi GIS format tetap | Bagian D lab gabungan | Day 03, 05 |
| Banyak login gagal | FTP `530`, `index=vpn` | Salah ketik satu akun | `0616`: `230` setelah `530`; `0618`: `mfa-denied` | Day 04 |
| Sweep satu port | Firewall, flow DC | `0617`: scanner riset; `0619`: skrip inventaris (pelanggaran kebijakan) | Sweep dari host tanpa pemilik yang bisa menjelaskan | Day 04 |
| File berlabel dokumen | `http.file_data[0:2] == 4d:5a` | Tidak ada | `0620`: PDF yang ternyata PE | Day 05 |
| Cocokan JA3 dari intel | `tls.handshake.ja3`, JA4, SNI | `0627`: setelan bawaan library skrip NOC | Fingerprint langka plus tujuan baru | Day 06 |
| Bump gagal, IP literal | Log proxy `tls=failed`, JA4 `t13i...` | `0626` pinning, `0629` softphone | Tidak ada | Day 06 |
| Self-signed, CN tidak cocok SNI | `x509sat.*`, `x509ce.dNSName` | Antarmuka BMC internal | `0628`: tujuan baru, satu host, beacon | Day 06 |

### 1.11 Glosarium Minggu 1

Definisi di bawah ditulis dengan kata sendiri untuk keperluan belajar. Kolom terakhir adalah pasangan yang paling sering membuat L1 (dan jawaban interview) keliru.

| Istilah | Penjelasan singkat | Sering tertukar dengan |
|---|---|---|
| NSM (Network Security Monitoring) | Pengumpulan data jaringan yang disengaja untuk deteksi dan investigasi | Membeli IDS |
| pcap vs flow | pcap menyimpan paket penuh (isi); flow menyimpan ringkasan koneksi (tanpa isi) | Log Zeek (di tengah keduanya) |
| Blind spot | Trafik yang tidak melewati titik sensor, sehingga tidak ada di bukti | "Tidak terjadi" |
| Titik pandang sensor | Apa yang terlihat dari posisi sensor (sebelum atau sesudah NAT, proxy, resolver) | Klien asli |
| Ring buffer | Kumpulan file capture berjumlah tetap; file tertua ditimpa | Arsip bukti |
| Pcap kasus | Cuplikan pcap untuk host dan rentang yang relevan, bernomor kasus dan ber-hash | File ring buffer asli |
| Capture filter vs display filter | Capture filter (BPF) menyaring saat merekam dan membuang permanen; display filter menyaring tampilan dengan sintaks Wireshark | Satu sama lain (sintaksnya juga berbeda) |
| Follow Stream | Merangkai satu koneksi TCP/UDP menjadi aliran yang bisa dibaca | Export Objects |
| Three-way handshake | SYN, SYN-ACK, ACK untuk membuka koneksi TCP | Teardown (FIN atau RST) |
| ACKed unseen | Penerima meng-ACK segmen yang tidak pernah tertangkap sensor: kehilangan di alat capture | Retransmission (kehilangan di jaringan) |
| SYN scan | Scan half-open; SYN tanpa menyelesaikan handshake | Connect scan |
| Vertikal vs horizontal | Scan banyak port satu host vs satu port banyak host | Brute force vs spray |
| Password spray | Sedikit kata sandi dicoba pada banyak akun | Brute force (banyak kata sandi, satu akun) |
| DNAT | Firewall menerjemahkan alamat tujuan publik ke alamat internal | NAT sumber kantor |
| DNS tunneling | Menyandikan data di query/response DNS untuk C2 atau exfiltration | Layanan sah yang memakai subdomain panjang |
| DGA | Algoritma penghasil banyak nama domain untuk C2 yang sulit diblokir | Search suffix salah konfigurasi |
| Negative caching | Resolver menyimpan jawaban NXDOMAIN selama TTL negatif dari SOA | Query yang hilang |
| Fast flux | Satu domain ke banyak IP berganti cepat, TTL rendah | CDN |
| Magic byte | Byte awal berkas penentu tipe sebenarnya (misalnya `MZ` untuk PE) | Content-Type atau ekstensi |
| LOLBin | Program bawaan sistem operasi yang disalahgunakan untuk mengunduh atau menjalankan kode | Malware yang dibawa penyerang |
| Prevalence dan first-seen | Jumlah host yang melakukan hal sama, dan kapan pertama kali terlihat | Reputasi dari feed |
| SNI | Nama host tujuan di Client Hello TLS, terlihat kecuali ECH | Header HTTP Host |
| ECH | Encrypted Client Hello, mengenkripsi SNI asli | Domain fronting |
| JA3/JA4 | Fingerprint parameter Client Hello untuk mengenali klien | Identitas aplikasi atau malware tertentu |
| Splice vs bump | Proxy meneruskan TLS apa adanya vs membukanya dengan CA internal | Fingerprint klien vs fingerprint proxy |
| SSLKEYLOGFILE | Berkas kunci sesi untuk dekripsi TLS lab sendiri di Wireshark | Private key server |
| Application Data (content_type 23) | Rekaman TLS terenkripsi; ukuran dan waktu tetap terlihat | Isi yang bisa dibaca |
| Defang | Menulis IOC agar tidak bisa diklik atau dieksekusi, misalnya `203.0.113[.]50` dan `hxxp://` | Menyamarkan bukti |

### 1.12 Satu halaman untuk Dimas

Tabel berikut adalah yang kamu kirim ke Dimas Rabu pukul 16:00, setelah lab gabungan selesai. Setiap baris merujuk bagian di atas supaya Dimas bisa membaca alasannya bila Hendra bertanya.

| Pertanyaan | Jawaban singkat | Dasar |
|---|---|---|
| Apa yang terlihat dari pcap uji coba | Isi HTTP, FTP, dan DNS polos, kode jawaban DNS, file dan hash, metadata TLS (SNI, sertifikat TLS 1.2, fingerprint, ukuran dan waktu), dan bukti bahwa sebuah koneksi tidak pernah tersambung | Bagian 1.2 sampai 1.6 |
| Lima insiden ditemukan dari mana | Pemicu dari firewall, proxy, MDE, flow NOC, dan satu dari ringkasan pcap; pcap menjadi pembeda di kelimanya, dan di `INC-2027-063` membantah catatan "gagal semua" | Bagian 1.8 |
| Hasil minggu ini | 23 alert dan tiket, 5 insiden, 1 temuan kapasitas sensor, 1 pelanggaran kebijakan, 1 false positive intel, 3 temuan kredensial plaintext; pagi ini satu insiden lagi dari latihan (`INC-2027-066`) | Bagian 1.8, lab gabungan |
| Blind spot | Lateral antar workstation, isi TLS, login VPN, split tunnel dan cloud, Bandung dan Medan, retensi pendek | Bagian 1.9 |
| Yang ditutup Zeek dan Suricata | Atribusi workstation di balik proxy dan resolver (lewat SPAN core), metadata otomatis, retensi metadata lebih panjang, pengukuran paket hilang | Bagian 1.9 |
| Yang tidak ditutup | Semua blind spot di atas selain atribusi; Zeek dan Suricata tidak menambah titik pandang | Bagian 1.9 |
| Kesiapan L1 | Tabel gejala dan glosarium; latihan gabungan pagi ini | Bagian 1.10, 1.11, lab gabungan |

Satu kalimat untuk Hendra: pcap uji coba sudah ikut menentukan kelima insiden minggu ini, tetapi semua kesimpulan masih bergantung pada log dan telemetri host, dan Zeek serta Suricata minggu depan mempercepat pembacaan di dua titik yang sama, bukan menambah titik baru.

## 2-4. Lab gabungan dan troubleshooting

Lab gabungan ini menjawab pertanyaan ketujuh dengan lima alert Rabu 2027-05-12 pagi, dikerjakan bersama Gilang Ramadhan dan Dwi Cahyono (L1) dari pukul 08:30 sampai 15:30. Semua isi Bagian A sampai F fiktif dan merupakan keluaran ilustrasi; perintah ditulis untuk Wireshark/tshark 4.6.9 di `jkt-nsm-ws01` dan query untuk Splunk PT JAB yang menampilkan WIB. Bagian G adalah latihan di VM lab pribadimu, dan Bagian H berisi skenario dengan pembahasan.

Peta lima alert dan Day yang dilatih. Kolom terakhir adalah keputusan akhir, supaya terlihat bahwa satu antrean berisi semua jenis hasil.

| Alert | Waktu (WIB) | Sumber alert | Ringkasan | Day yang dilatih | Bagian | Keputusan |
|---|---|---|---|---|---|---|
| `SOC-2027-0630` | 06:41 | Rule port scan firewall | `203.0.113.173` ke `198.51.100.207` | Day 01, 04 | B | Jinak tanpa dampak |
| `SOC-2027-0631` | 07:05 | Rule "TXT subdomain lebih dari 30 karakter dari klien baru" | `JKT-WS-2033` (`10.10.60.73`) | Day 03, 05 | D | Eskalasi `INC-2027-066` |
| `SOC-2027-0632` | 07:15 | Rule "lebih dari 500 query per jam ke satu domain induk" | `JKT-WS-2030` (`10.10.60.70`) | Day 05 | C | Jinak, tiket IT |
| `SOC-2027-0633` | 07:58 | MDE, severity sedang | `JKT-WS-2033`, `powershell.exe` dengan query DNS beruntun | Day 02, 06 | E | Digabung ke `INC-2027-066` |
| `SOC-2027-0634` | 08:52 | MDE, severity rendah | `JKT-WS-2034`, laptop VPN dari rumah | Day 01 | F | Data jaringan tidak cukup |

### Bagian A: pcap kasus Rabu pagi (Day 01, 02)

Langkah pertama memastikan bukti tersimpan sebelum ring buffer menimpanya, dengan rentang yang benar. Jendela kerja 06:30:00 sampai 08:00:00 WIB Rabu 2027-05-12 adalah 2027-05-11T23:30:00Z sampai 2027-05-12T01:00:00Z: tanggal UTC-nya masih Selasa untuk 30 menit pertama.

**Tujuan:** satu pcap kasus berisi trafik DNS resolver, HTTP dan TLS proxy, dan trafik ke dua IP luar yang disebut alert, dengan hash dan rentang terverifikasi.

```bash
mkdir -p /cases/SOC-2027-0630/carve
for f in $(cat /cases/SOC-2027-0630/files.txt); do
  tcpdump -r "$f" -w "/cases/SOC-2027-0630/carve/$(basename "$f")" \
    '(port 53 and (host 10.20.2.53 or host 10.20.2.54)) or host 10.20.3.60 or host 203.0.113.172 or host 203.0.113.173 or host 198.51.100.207'
done
mergecap -w /cases/SOC-2027-0630/latihan-0630-0634_2330Z-0100Z.pcapng /cases/SOC-2027-0630/carve/*.pcapng
capinfos -M -c -u -S -H /cases/SOC-2027-0630/latihan-0630-0634_2330Z-0100Z.pcapng
```

| Bagian | Fungsi |
|---|---|
| `files.txt` | Daftar file ring buffer yang mencakup jendela, dipilih dari timestamp nama file seperti Day 02 bagian 2.1 dan dicek dengan `capinfos -a` |
| `tcpdump -r ... -w ... '<BPF>'` | Memotong tanpa mengurai protokol, lebih ringan daripada `tshark -Y` untuk file besar |
| `port 53 and (host 10.20.2.53 or host 10.20.2.54)` | DNS kedua resolver; klien asli tidak ada di sini (Day 03 bagian 1.4) |
| `host 10.20.3.60` | Semua trafik proxy, HTTP polos dan TLS |
| `host 203.0.113.172 ...` | Dua IP luar dari alert dan IP publik target scan, untuk memastikan tidak ada jalur lain |
| `mergecap -w` | Menggabungkan cuplikan menurut waktu paket |
| `capinfos -M -c -u -S -H` | Jumlah paket, durasi, epoch awal dan akhir, hash SHA-256 |

Keluaran ilustrasi (diringkas):

```
Number of packets:    3812406
Capture duration:     5399.902117 seconds
Earliest packet time: 1810078200.041833
Latest packet time:   1810083599.943950
SHA256:               <64 karakter heksadesimal, dicatat di tiket>
```

**Cara membaca hasil:** epoch `1810078200` adalah 2027-05-11 23:30:00 UTC (06:30:00 WIB) dan `1810083599` adalah 2027-05-12 00:59:59 UTC (07:59:59 WIB); konversi dengan `date -u -d @<epoch>`. Durasi 5.399,9 detik sesuai jendela 90 menit. Pcap kasus ini yang dipakai di Bagian B sampai F, dan hash-nya dicatat sebelum siapa pun membukanya di GUI.

**Kapan gagal:** file ring dipilih dengan tanggal WIB ("20270512063000") padahal nama file memakai jam UTC, sehingga 30 menit pertama hilang; atau pemotongan ditunda sampai sore dan sebagian file sudah tertimpa pada jam sibuk (Day 01 bagian 2.3).

### Bagian B: scan ke alamat publik yang tidak dipakai (`SOC-2027-0630`, Day 04)

Alert ini melatih pelajaran Day 04 bagian 1.3: tiga sensor, tiga angka. `198.51.100.207` adalah alamat di blok publik PT JAB yang belum dipakai layanan apa pun; `jkt-fw01` menolak semua trafik ke sana dan tidak ada DNAT.

**Tujuan:** mengukur lebar scan, apa yang dijawab, dan apakah ada dampak.

```
index=firewall src_ip=203.0.113.173 earliest="05/12/2027:06:00:00" latest="05/12/2027:08:00:00"
| stats count dc(dest_port) AS port_unik dc(dest_ip) AS tujuan_unik values(action) AS aksi min(_time) AS awal max(_time) AS akhir BY dest_ip
| convert ctime(awal) ctime(akhir)
```

Keluaran ilustrasi:

```
dest_ip          count  port_unik  tujuan_unik  aksi     awal                 akhir
198.51.100.207   2000   1000       1            blocked  05/12/2027 06:38:10  05/12/2027 06:38:52
```

Pembanding dari pcap kasus dan flow:

```bash
tshark -n -r latihan-0630-0634_2330Z-0100Z.pcapng -Y 'ip.addr == 203.0.113.173 || ip.addr == 198.51.100.207' | wc -l
```

Keluaran ilustrasi: `0`. Flow edge di `jkt-flow01` untuk sumber yang sama mencatat 2 record.

**Cara membaca hasil:**

- 2.000 event untuk 1.000 port unik: setiap probe dikirim dua kali, pola yang sama dengan Day 04 bagian 2.2. Hitung port, bukan event.
- Pcap nol paket karena tidak ada DNAT, sehingga probe dibuang firewall sebelum sampai ke TAP di sisi dalam. Flow edge 1:1000 atas 2.000 paket memberi harapan sekitar 2 paket tersampel, sesuai yang terlihat. Ketiga angka benar untuk titiknya.
- Dampak (Day 04 bagian 1.7): tidak ada port yang menjawab, tidak ada host hidup di alamat itu, dan dalam 24 jam firewall tidak mencatat `203.0.113.173` ke alamat PT JAB lain. Sumber ini tidak ada di daftar scanner riset yang dicek, jadi labelnya bukan "scanner riset", melainkan "scan eksternal tanpa dampak".
- Disposisi: ditutup jinak tanpa dampak. Memblokir sumber adalah keputusan kebijakan, bukan tindakan wajib.

**Kapan gagal:** Gilang menulis "tidak ada di pcap, berarti false positive". Firewall melihat semuanya; yang benar adalah "tidak sampai ke sensor".

### Bagian C: NXDOMAIN dari laptop yang baru kembali (`SOC-2027-0632`, Day 05)

Alert ini adalah versi nyata skenario lama di catatan minggu ini: nama bermakna dengan akhiran domain rumah.

**Tujuan:** membedakan search suffix yang salah konfigurasi dari DGA.

```
index=dns src=10.10.60.70 earliest="05/12/2027:06:30:00" latest="05/12/2027:07:30:00"
| rex field=query "^(?<sub>.+)\.(?<parent>[^.]+\.[^.]+)$"
| stats count dc(query) AS nama_unik values(query) AS contoh BY parent
| sort - count
```

Keluaran ilustrasi (diringkas):

```
parent             count  nama_unik  contoh
isp-home.example   1230   41         fileserver.corp.local.isp-home.example
                                     printer-lt3.corp.local.isp-home.example
                                     intranet.corp.local.isp-home.example ...
jab.example         118   23         ...
```

**Cara membaca hasil:**

- 41 nama unik, masing-masing ditanya sekitar 30 kali dalam satu jam (41 x 30 = 1.230), semuanya terstruktur dan bermakna (`fileserver`, `printer-lt3`, `intranet`) dengan akhiran `corp.local.isp-home.example`. DGA menghasilkan nama acak tanpa pola kata (Day 05 bagian 1.3).
- Di pcap kasus, resolver hanya mengirim 302 query ke luar untuk nama-nama itu, karena jawaban NXDOMAIN membawa SOA dengan TTL negatif 900 detik. Batas atasnya 41 nama x 4 jendela 15 menit x 2 resolver = 328; selisih ke angka log adalah negative caching, bukan query yang hilang.
- Laptop `JKT-WS-2030` milik staf yang dua minggu bekerja dari rumah; suffix pencarian dari router rumahnya masih tersimpan di konfigurasi adapter. Disposisi: jinak, tiket ke IT untuk membersihkan suffix.

**Kapan gagal:** Dwi mencari kode NXDOMAIN di `index=dns`. Log resolver PT JAB hanya mencatat query, tanpa kode jawaban (Day 05 bagian 1.1); rcode dibaca dari pcap.

### Bagian D: TXT panjang ke satu domain baru (`SOC-2027-0631`, Day 03 dan 05)

Alert ini adalah inti latihan. Rule yang sama pernah memicu `SOC-2027-0622` (lisensi GIS, jinak), jadi Gilang hampir menutupnya dengan alasan yang sama.

**Tujuan:** menentukan apakah TXT ini pola layanan atau pola tunneling, siapa kliennya, dan berapa besar volumenya.

Langkah 1, bentuk nama di pcap (sisi resolver ke authoritative):

```bash
tshark -n -r latihan-0630-0634_2330Z-0100Z.pcapng \
  -Y 'dns.flags.response == 0 && dns.qry.type == 16 && dns.qry.name contains "cdn-metrik"' \
  -T fields -e ip.src -e ip.dst -e dns.qry.name \
  | awk '{split($3,a,"."); n++; s+=length(a[1]); if(length(a[1])>mx)mx=length(a[1]); if(mn==""||length(a[1])<mn)mn=length(a[1]); src[$1]++; dst[$2]++}
         END{print "query", n, "label1 min/avg/max", mn, s/n, mx; for(k in src) print "src", k, src[k]; for(k in dst) print "dst", k, dst[k]}'
```

| Bagian | Fungsi |
|---|---|
| `dns.flags.response == 0 && dns.qry.type == 16` | Query TXT saja |
| `dns.qry.name contains "cdn-metrik"` | Domain induk dari alert |
| `split($3,a,".")` dan `length(a[1])` | Panjang label pertama, tempat data biasanya disisipkan |
| `src[$1]`, `dst[$2]` | Resolver mana yang bertanya, dan ke server mana |

Keluaran ilustrasi:

```
query 1840 label1 min/avg/max 48 52.0 60
src 10.20.2.53 951
src 10.20.2.54 889
dst 203.0.113.172 1840
```

Langkah 2, atribusi dan konteks dari log resolver:

```
index=dns query="*.cdn-metrik.example" earliest="05/12/2027:00:00:00" latest="05/12/2027:08:00:00"
| stats count dc(query) AS nama_unik min(_time) AS awal max(_time) AS akhir BY src query_type
| convert ctime(awal) ctime(akhir)
```

Keluaran ilustrasi:

```
src          query_type  count  nama_unik  awal                 akhir
10.10.60.73  TXT         1840   1840       05/12/2027 07:01:05  05/12/2027 07:52:10
```

Pencarian 30 hari ke belakang untuk `cdn-metrik.example` di `index=dns` dan `index=proxy` tidak menghasilkan apa pun sebelum 07:01:05 pagi ini.

**Cara membaca hasil:**

- Bentuknya kebalikan dari lisensi GIS di `SOC-2027-0622`: panjang label bervariasi 48 sampai 60 karakter (bukan format tetap), setiap nama unik (1.840 dari 1.840), satu klien, domain yang first-seen pagi ini, dan prevalence satu host. Itu pola tunneling yang dijelaskan Day 05 bagian 1.2, dan ATT&CK mencatat C2 lewat DNS memang menaruh perintah dan hasilnya di dalam query dan record seperti TXT [S6].
- Jumlah di pcap egress sama persis dengan log resolver (1.840). Ini kebalikan dari `SOC-2027-0612` di Day 03 bagian 2.4: nama yang selalu unik tidak pernah bisa dijawab dari cache, jadi setiap query diteruskan ke authoritative server `203.0.113.172`. Angka yang sama di dua sumber adalah sinyal tersendiri.
- Perkiraan volume, dengan asumsi label berisi base32 (setiap karakter membawa 5 bit): 52 karakter x 5 / 8 = 32,5 byte per query, sehingga 1.840 query membawa sekitar 59.800 byte (sekitar 58,4 KiB) keluar. Jawaban TXT di pcap rata-rata 200 byte, sekitar 368.000 byte (sekitar 359 KiB) masuk. Angka ini indikator ukuran, bukan bukti isi; penyandiannya belum diketahui.
- Durasi 07:01:05 sampai 07:52:10 adalah 3.065 detik, rata-rata satu query tiap sekitar 1,7 detik. Manusia tidak mengetik 1.840 nama unik secepat itu.
- Penjelasan jinak yang perlu digugurkan: produk keamanan yang memakai DNS untuk lookup reputasi (seharusnya ke domain vendor yang dikenal dan dipakai banyak host), dan lisensi atau telemetri aplikasi (format tetap, banyak klien). Keduanya tidak cocok.

**Kapan gagal:**

- Gilang memfilter pcap dengan `frame.time >= "2027-05-12T07:01:00Z"` dan mendapat nol paket. 07:01 WIB adalah 00:01Z; filter yang benar `frame.time >= "2027-05-12T00:01:00Z"` atau `"2027-05-12T07:01:00+07:00"` (Day 02 bagian 1.3).
- Rule ditutup karena "sama dengan GIS minggu lalu". Allowlist per domain dan per klien (Day 05) yang membuat GIS jinak; domain ini tidak ada di allowlist mana pun.

### Bagian E: dari mana pemicunya, dan `INC-2027-066` (Day 02, 06)

Alert MDE `SOC-2027-0633` pukul 07:58 memberi korroborasi dari host: `powershell.exe` di `JKT-WS-2033` (pengguna `bayu.firmansyah`, Marketing) dijalankan dari pintasan di folder Downloads pukul 06:58:31, mengunduh berkas dari `paste-cdn.example`, lalu melakukan query DNS beruntun. Langkah jaringan di bagian ini mencari jejak unduhan itu dan menyusun timeline.

Log proxy untuk klien yang sama:

```
index=proxy src=10.10.60.73 earliest="05/12/2027:06:50:00" latest="05/12/2027:07:10:00"
| table _time user method host category tls bytes
```

Keluaran ilustrasi:

```
_time                user             method   host                    category      tls      bytes
05/12/2027 06:58:40  bayu.firmansyah  CONNECT  paste-cdn.example:443   File-Sharing  spliced  10112
```

Karena kategori File-Sharing di-splice, ClientHello di pcap egress adalah milik klien asli, bukan proxy (Day 06 bagian 1.7):

```bash
tshark -n -r latihan-0630-0634_2330Z-0100Z.pcapng \
  -Y 'tls.handshake.type == 1 && tls.handshake.extensions_server_name == "paste-cdn.example"' \
  -T fields -e frame.time_utc -e ip.src -e tls.handshake.ja4
```

Keluaran ilustrasi:

```
2027-05-11T23:58:40.212Z  10.20.3.60  t12d...(fiktif, dipotong)
```

**Cara membaca hasil:**

- Waktu 23:58:40Z di pcap adalah 06:58:40 WIB di log proxy: satu kejadian di dua sumber, sekaligus pemeriksaan jam sensor (Day 02 bagian 1.3).
- Bagian a JA4 dimulai `t12`: klien menawarkan TLS 1.2 sebagai versi tertinggi, berbeda dengan `t13d1516h2_...` milik Edge armada PT JAB (Day 06 bagian 1.6). Di 30 hari log proxy, `paste-cdn.example` dikunjungi 14 klien lain, semuanya lewat browser. Domainnya populer dan bukan IOC; yang menjadi sinyal adalah klien non-browser yang memakainya beberapa detik setelah pintasan dibuka.
- Isi unduhan tidak terlihat (splice, TLS); 10.112 byte di log proxy adalah volume seluruh sesi. Nama dan isi berkas datang dari MDE.

Pukul 08:15 Dimas menyatakan `INC-2027-066` (dugaan DNS tunneling dari `JKT-WS-2033` setelah eksekusi skrip yang diunduh), dan pukul 08:20 host diisolasi lewat MDE. Timeline berikut memisahkan bukti dari kesimpulan, seperti format Day 04 bagian 2.11.

| Waktu (WIB) | Kejadian | Sumber | Bukti atau kesimpulan |
|---|---|---|---|
| 06:58:31 | `powershell.exe` dijalankan dari pintasan di Downloads | MDE (`SOC-2027-0633`) | Bukti host |
| 06:58:40 | CONNECT `paste-cdn.example:443`, splice, 10.112 byte | Log proxy, pcap egress (ClientHello `t12`) | Bukti; isi tidak diketahui |
| 07:01:05 | Query TXT pertama ke `*.cdn-metrik.example` | `index=dns`, pcap egress | Bukti |
| 07:01:05 sampai 07:52:10 | 1.840 query TXT unik, label 48 sampai 60 karakter, ke NS `203.0.113.172` | `index=dns`, pcap egress | Bukti |
| 07:05 | `SOC-2027-0631` terpicu | Splunk | |
| 07:52:10 | Query terakhir; alasan berhenti tidak diketahui dari jaringan | `index=dns` | Bukti |
| 08:15 | `INC-2027-066` dinyatakan | SOC | Kesimpulan: dugaan tunneling, sekitar 58 KiB keluar (perkiraan) |
| 08:20 | Isolasi `JKT-WS-2033` | MDE | |

Yang diserahkan ke IR:

```
INC-2027-066  Handover data jaringan (Rabu 2027-05-12 09:30)
Host          : JKT-WS-2033 10.10.60.73 (bayu.firmansyah), MDE aktif, diisolasi 08:20 WIB
Domain        : cdn-metrik[.]example (first-seen 07:01:05, prevalence 1 host); NS 203.0.113[.]172
Pola          : 1.840 query TXT unik 07:01:05-07:52:10 WIB; label1 48-60 karakter (rata-rata 52)
Volume        : perkiraan 59.800 byte keluar (asumsi base32), 368.000 byte TXT masuk
Unduhan       : paste-cdn[.]example via proxy (splice) 06:58:40 WIB, 10.112 byte; isi dari MDE
Bukti         : latihan-0630-0634_2330Z-0100Z.pcapng (SHA-256 di tiket), stream DNS 203.0.113.172
                disalin ke penyimpanan kasus sebelum tertimpa ring buffer
Tidak diketahui: isi data yang dikeluarkan; isi skrip; apakah host lain menerima pintasan yang sama
Usulan        : sinkhole *.cdn-metrik.example di jkt-res01/02 ke jkt-sink01; blok 203.0.113.172
                untuk trafik DNS resolver setelah keputusan IC; cek email gateway untuk pintasan
```

**Kapan gagal:** handover menulis "data pelanggan bocor 58 KiB". Yang ada adalah perkiraan volume dari panjang label dengan asumsi penyandian; isi dan jenis datanya pertanyaan IR dengan data host.

### Bagian F: laptop VPN, write-up, dan IOC (`SOC-2027-0634`, Day 01)

Alert MDE `SOC-2027-0634` pukul 08:52 menyebut `JKT-WS-2034` membuka domain berkategori berisiko rendah. Dwi diminta "cek di pcap".

| Sumber | Hasil | Arti |
|---|---|---|
| `index=vpn` | Sesi `JKT-WS-2034` aktif sejak 07:30 dari rumah, profil split tunnel | Trafik internet laptop keluar lewat ISP rumah, bukan lewat PT JAB |
| `index=proxy`, `index=dns` | Nol event untuk domain itu | Proxy dan resolver PT JAB tidak dipakai |
| Pcap egress | Nol paket | Tidak lewat TAP |

Disposisi dari sisi jaringan: data tidak cukup, dan ini dicatat sebagai blind spot (Day 01 bagian 1.5), bukan sebagai "aman". Keputusan diambil dari MDE: browser membuka iklan, tanpa unduhan atau proses baru; ditutup jinak berdasarkan telemetri host.

Write-up satu halaman untuk Sari, format yang dipakai L1 mulai minggu depan:

```
LATIHAN GABUNGAN 2027-05-12 (pcap kasus SHA-256 di tiket SOC-2027-0630)
Rentang     : 06:30-08:00 WIB (2027-05-11T23:30Z - 2027-05-12T01:00Z), TAP egress sisi dalam jkt-fw01
Tidak dilihat: lateral antar workstation; laptop VPN split tunnel; isi TLS; Bandung/Medan
0630  scan 1.000 port ke 198.51.100.207 (tak terpakai)     firewall/pcap/flow   jinak tanpa dampak
0632  1.230 query 41 nama bermakna, suffix rumah            dns log/pcap         jinak, tiket IT
0631  1.840 TXT unik ke domain first-seen, 1 klien          dns log/pcap         eskalasi INC-2027-066
0633  powershell dari pintasan, unduh paste-cdn, query DNS  MDE/proxy/pcap       digabung INC-2027-066
0634  laptop VPN split tunnel                               vpn log; pcap nol    data jaringan tidak cukup
IOC (defang): cdn-metrik[.]example (tinggi), 203.0.113[.]172 (tinggi untuk aktivitas ini; cek shared hosting)
Bukan IOC  : paste-cdn[.]example (layanan populer; sinyalnya klien non-browser, bukan domain)
```

**Hasil yang sebaiknya tersimpan:**

- Pcap kasus dengan hash, daftar file sumber, dan rentang UTC serta WIB.
- Hitungan scan dari tiga sensor dan kalimat dampaknya.
- Pemisahan search suffix dari DGA dengan angka log dan pcap, termasuk batas atas negative caching.
- Ukuran label, prevalence, first-seen, dan perkiraan volume untuk `0631`, dengan asumsi tertulis.
- Timeline `INC-2027-066` dengan kolom bukti atau kesimpulan, dan handover ke IR.
- Satu catatan blind spot untuk `0634`.
- Write-up satu halaman dan daftar IOC ter-defang dengan keyakinan.

### Bagian G: lab gabungan pribadi di VM lab terisolasi

Bagian ini dikerjakan di lab pribadimu, bukan di data PT JAB.

**Prasyarat:** Wireshark 4.6.x; satu pcap lab atau publik yang mengandung beberapa fenomena (misalnya scan lalu infeksi dengan unduhan payload dan koneksi terenkripsi berkala); tidak ada pcap kerja. Bila membuat sendiri, pakai jaringan host-only `192.168.56.0/24` dengan snapshot di semua VM.

Kerjakan satu pcap end-to-end memakai Day 01-06:

1. **Bukti (Day 01).** Jalankan `capinfos`: catat rentang waktu, jumlah paket, dan apakah zona waktunya UTC. Tulis satu kalimat tentang posisi capture dan apa yang mungkin tidak terlihat.
2. **Orientasi (Day 02).** Statistics > Protocol Hierarchy dan Conversations. Catat tiga protokol dominan dan lima pasangan dengan volume terbesar.
3. **Scan (Day 04).** Ada reconnaissance di awal? Tentukan tipe, arah (vertikal/horizontal), target, dan port yang menjawab SYN-ACK.
4. **Protokol (Day 03).** Baca koneksi kunci: HTTP, DNS, SMB, FTP yang relevan; ikuti stream bila polos.
5. **Anomali (Day 05).** Ada tunneling, DGA, User-Agent aneh, atau unduhan payload? Ukur jumlah query, NXDOMAIN, dan cek magic byte.
6. **TLS (Day 06).** Untuk koneksi terenkripsi, baca SNI, sertifikat (bila TLS 1.2), JA3/JA4, dan pola Application Data di IO Graph.
7. **Sintesis.** Susun timeline: apa lebih dulu, apa akibatnya. Pisahkan bukti dari kesimpulan.
8. **IOC.** Daftar IOC yang di-defang (IP, domain, hash) dengan keyakinan tiap item.
9. **Resolver lab.** Bila VM lab punya resolver sendiri, kirim 200 query TXT dengan label acak ke zona lab yang tidak ada, lalu 200 query untuk 10 nama tetap. Bandingkan jumlah query klien dengan jumlah query yang keluar dari resolver untuk kedua kelompok, seperti Bagian C dan D.

Variasi: ulangi langkah 3-6 hanya dengan tshark, tanpa GUI, dan simpan perintahnya sebagai skrip kecil. Bandingkan apa yang lebih cepat dan apa yang terlewat.

**Hasil yang sebaiknya tersimpan:**

- Ringkasan capinfos dan catatan posisi capture.
- Peta protokol dan percakapan dari orientasi.
- Temuan scan dengan tipe, target, dan port terbuka (bila ada).
- Anomali DNS/HTTP yang terukur, termasuk hash payload bila ada.
- Metadata TLS untuk koneksi terenkripsi yang relevan.
- Perbandingan jumlah query klien dan query keluar resolver untuk nama unik dan nama berulang.
- Timeline dan daftar IOC ter-defang dengan keyakinan.
- Write-up satu halaman: ringkasan, timeline, temuan per tahap, IOC, dan batas analisis.
- Rencana perbaikan: tandai Day yang langkahnya paling sulit diulang di lab gabungan, lalu ulang bagian Konsep inti, Contoh, dan Lab Day itu. Catat tiga hal: konsep yang masih kabur (misalnya beda JA3 dan JA4, atau kapan NXDOMAIN jinak), filter yang belum hafal, dan satu pcap latihan tambahan yang akan dikerjakan sebelum Day 08.

### Bagian H: latihan skenario dengan pembahasan

Jawab dulu tiap skenario dalam dua sampai tiga kalimat, lalu buka pembahasannya.

**Skenario A.** Dalam 40 detik, `10.0.0.99` mengirim SYN ke port 1-1024 di `10.0.0.20`. Port 22 dan 80 menjawab SYN-ACK, sisanya RST. Setelah itu tidak ada trafik lain dari `10.0.0.99`.

<details><summary>Pembahasan</summary>

Ini SYN scan vertikal yang menemukan dua port terbuka. Karena tidak ada koneksi lanjutan, tidak ada bukti eksploitasi di capture ini. Pertanyaan berikutnya: apakah `10.0.0.99` scanner kerentanan yang terdaftar dan terjadwal? Bila bukan, cek apakah host itu atau host lain menghubungi port 22/80 di `10.0.0.20` pada periode berikutnya, dan catat bahwa capture yang berakhir bukan berarti aktivitas berakhir.

</details>

**Skenario B.** Workstation `10.0.0.15` membuat 2.300 query TXT dalam satu jam ke subdomain berbeda di bawah `cdn-sync[.]example`, dengan label 50-60 karakter heksadesimal. Jawaban berupa TXT 200-an byte.

<details><summary>Pembahasan</summary>

Kombinasi volume tinggi ke satu domain induk, label panjang tersandi, tipe TXT, dan jawaban besar adalah pola DNS tunneling yang kuat. Penjelasan jinak yang perlu disingkirkan: produk keamanan yang memakai DNS untuk lookup reputasi juga membuat query panjang, tetapi ke domain vendor yang dikenal. Langkah lanjut: hitung total byte di label query (perkiraan data keluar), cek umur dan reputasi domain, dan cari proses di host yang membuat query. Bagian D lab gabungan adalah versi lengkap langkah ini.

</details>

**Skenario C.** Ada koneksi TLS 1.3 berkala dari `10.0.0.8` ke `203.0.113[.]50` setiap sekitar 60 detik, SNI `upd-check[.]example`, ukuran Application Data hampir sama tiap kali. Sertifikat tidak terlihat.

<details><summary>Pembahasan</summary>

Sertifikat yang tidak terlihat adalah sifat normal TLS 1.3, bukan sinyal. Sinyalnya adalah keteraturan waktu dan ukuran ke domain yang tidak dikenal. Bandingkan JA3/JA4 dengan fingerprint browser dan aplikasi yang biasa di host itu; cek apakah domain itu baru terdaftar; cari kejadian sebelum koneksi pertama (unduhan, email). Kesimpulan yang jujur: "kandidat beacon, keyakinan sedang", sampai ada konfirmasi dari host.

</details>

**Skenario D.** Request `GET /images/logo.jpg` ke `198.51.100[.]7` dengan User-Agent milik komponen Windows, respons `Content-Type: image/jpeg`, tetapi Export Objects menunjukkan berkas diawali `MZ`.

<details><summary>Pembahasan</summary>

Magic byte mengalahkan ekstensi dan header. Ini executable yang disamarkan sebagai gambar, dan penjelasan jinaknya sangat jarang. Simpan hash dan metadata, jangan simpan atau buka berkasnya di luar VM analisis. Tandai waktu unduhan sebagai titik awal timeline kandidat infeksi, lalu cari koneksi baru dari host yang sama setelah waktu itu.

</details>

**Skenario E.** Ratusan NXDOMAIN untuk nama seperti `fileserver.corp.local.isp-home[.]example` dari laptop yang baru kembali dari kerja jarak jauh.

<details><summary>Pembahasan</summary>

Nama yang terstruktur dan bermakna dengan akhiran domain rumah atau ISP adalah ciri search suffix yang salah konfigurasi, bukan DGA. DGA menghasilkan nama acak tanpa pola kata. Ini contoh kenapa kolom "jinak bila" di tabel bagian 1.10 harus diisi sebelum menyimpulkan, dan Bagian C lab gabungan adalah kasus nyatanya di PT JAB.

</details>

**Skenario F.** Pcap egress jam 09:00 tidak memuat satu pun koneksi dari laptop yang dilaporkan EDR menghubungi domain berbahaya pukul 09:05.

<details><summary>Pembahasan</summary>

Sebelum menulis apa pun, cek tiga hal: apakah laptop itu sedang VPN split tunnel atau di luar kantor (Bagian F), apakah koneksinya lewat proxy sehingga di pcap tampak dari `10.20.3.60`, dan apakah rentang pcap ditulis dengan zona waktu yang benar (09:05 WIB adalah 02:05Z). Bila ketiganya bersih dan tetap nol, tulis "tidak terlihat dari titik egress", bukan "tidak terjadi".

</details>

### Troubleshooting ringkas

Tabel ini menggabungkan masalah yang paling sering muncul di Day 01-06 dan di lab gabungan. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Tidak tahu harus mulai dari mana di pcap besar | Langsung membaca daftar paket | Mulai dari Protocol Hierarchy dan Conversations (bagian 1.2) |
| Display filter merah (tidak valid) | Sintaks BPF dipakai di kolom display filter | Ganti `host x` dengan `ip.addr == x` |
| HTTP tidak muncul padahal ada trafik web | Trafiknya HTTPS | Baca metadata TLS (bagian 1.6) |
| Export Objects kosong | Protokol terenkripsi atau stream tidak lengkap | Cek Expert Info untuk segmen hilang; TLS butuh keylog lab |
| Waktu timeline tidak cocok dengan log lain | Zona waktu tampilan berbeda | Set View > Time Display Format ke UTC dan catat di laporan |
| Filter waktu menghasilkan nol paket | Jam WIB ditulis dengan akhiran "Z" | Kurangi 7 jam, atau tulis offset `+07:00` (Bagian D) |
| Terlalu banyak kandidat anomali | Tidak ada baseline | Kumpulkan pola normal lab dulu (Day 01 lab) |
| Semua HTTP dari proxy, semua DNS dari resolver | Titik pandang sensor egress | Atribusi lewat `index=proxy` dan `index=dns` (bagian 1.3) |
| Jumlah query di pcap lebih kecil dari log | Cache dan negative caching resolver | Bandingkan jeda ulangan dengan TTL (Bagian C); nama unik tidak ter-cache (Bagian D) |
| Kode NXDOMAIN tidak ada di Splunk | Log resolver hanya query | Baca rcode dari pcap (Bagian C) |
| Scan besar di firewall, nol di pcap | Probe dibuang sebelum TAP, tanpa DNAT | Ambil lebar scan dari firewall (Bagian B) |
| Kejadian lama tidak ada di ring buffer | Sudah tertimpa | Cek paket tertua dengan capinfos; pakai log dengan retensi lebih panjang |
| Banyak previous segment not captured | Paket hilang di sensor | Bandingkan dengan ACKed unseen dan statistik drop (bagian 1.3) |
| Fingerprint di egress tidak cocok dengan klien | Koneksi di-bump, ClientHello milik proxy | Cek kolom `tls` di log proxy (bagian 1.6) |
| Laptop tidak terlihat di sumber jaringan mana pun | VPN split tunnel atau di luar kantor | Cek `index=vpn`; catat sebagai blind spot (Bagian F) |

## 5. Kesalahan umum dan jebakan

- **Melompat ke kesimpulan dari satu sinyal.** Tabel bagian 1.10 ada karena hampir setiap sinyal punya penjelasan jinak.
- **Mengira "tidak ada di pcap" berarti "tidak terjadi".** Selalu sebut posisi sensor dan rentang waktu capture.
- **Menjanjikan bahwa Zeek dan Suricata menutup semua blind spot.** Keduanya membaca titik yang sama; lateral antar workstation, VPN, dan isi TLS tetap tidak terlihat (bagian 1.9).
- **Memakai capture filter ketat saat menangkap bukti.** Yang dibuang tidak bisa dipulihkan.
- **Mengira sertifikat yang hilang di TLS 1.3 sebagai anomali.** Itu perilaku normal protokol.
- **Mencari klien di pcap egress.** Di balik proxy dan resolver, klien hanya ada di log.
- **Menutup alert karena mirip kasus jinak minggu lalu.** `SOC-2027-0631` memakai rule yang sama dengan lisensi GIS, tetapi bentuknya berlawanan.
- **Menjadikan domain populer sebagai IOC.** Di `INC-2027-066`, `paste-cdn.example` dipakai banyak klien sah; sinyalnya ada di klien dan waktunya.
- **Menulis perkiraan volume sebagai fakta isi.** Volume dari panjang label bergantung asumsi penyandian.
- **Menulis jam tanpa zona, atau filter WIB dengan "Z".** Pcap UTC, Splunk dan NOC WIB.
- **Menyimpan kredensial atau payload di catatan.** Catat keberadaan dan hash, bukan nilai atau berkasnya.
- **Lupa men-defang IOC.** IOC yang bisa diklik di dokumen bersama adalah risiko.
- **Mengutip UU ITE Pasal 31 ayat (1) dan (2) sebagai dasar yang masih berlaku.** Sejak 2 Januari 2026 larangannya ada di KUHP Pasal 258 (Day 01 bagian 1.7).

## 6. Catatan terkini

Bagian ini menampung status versi dan tren yang memengaruhi cara membaca Day 01-06, tetapi tidak mengubah alur kerja di atas.

- Tren utama Minggu 1: enkripsi (TLS 1.3, DoH, ECH yang kini distandarkan sebagai RFC 9849 [S4]) terus mengurangi isi yang terlihat, menggeser forensik ke metadata, fingerprint, dan pola. Day 15 dan 16 membahas batas barunya.
- TLS 1.3 kini diterbitkan sebagai RFC 9846 (Juli 2026), menggantikan RFC 8446 dan juga RFC 5246 (TLS 1.2) [S5]. Pernyataan bahwa semua pesan handshake setelah ServerHello dienkripsi tetap sama, jadi pembacaan sertifikat di pcap tetap terbatas pada TLS 1.2.
- Wireshark 4.6.9 adalah rilis stabil yang dipakai di Minggu 1, dengan 4.4.19 sebagai old stable dan 5.0.0rc1 sebagai rilis pengembangan [S7]; nama field display filter, terutama TLS, bisa berubah antar versi [S3].
- Zeek 9.0.0 LTS (14 September 2026), dengan LTS sebelumnya 8.0.10, adalah versi yang disiapkan untuk `jkt-zeek01` [S8]. Versi Suricata untuk `jkt-ids01` dicatat di Day 01 dan dicek ulang di Day 09.
- ATT&CK v20: T1071.004 (Application Layer Protocol: DNS) versi 1.4, terakhir diubah 3 September 2026, dengan detection strategy DET0400 untuk DNS tunneling [S6].
- Minggu 2 memperkenalkan Zeek dan Suricata yang mengotomasi banyak pembacaan manual Minggu 1 (log koneksi, SNI, fingerprint, alert), lalu pola lanjut (beaconing, exfiltration) dan metode kerja.

## 7. Cheat sheet

```
BUKTI      pcap (isi, mahal) > Zeek > alert > flow (murah, lama) ; posisi sensor = blind spot ; 1 Gbps penuh ~ 10,8 TB/hari
           jkt-pcap01 8,4 TB: ~93 jam (20%) | ~53 jam (35%) | ~18,7 jam (penuh) ; "tidak ada di pcap" != "tidak terjadi"
ALUR       capinfos -> Protocol Hierarchy -> Conversations -> display filter -> Follow Stream -> Export Objects -> hash
WAKTU      pcap UTC | Splunk/NOC WIB = UTC+7 | frame.time >= "...Z" atau "...+07:00" | epoch untuk skrip
FILTER     capture (BPF, permanen) vs display (aman) ; ip.addr== | tcp.stream eq N | dns.flags.rcode==3 | http.request
           negasi: !(ip.addr == X)
TCP        RST dari firewall: jeda ~1 ms, TTL beda ; ACKed unseen = capture loss ; completeness 33 = ditolak
TITIK      egress: HTTP = proxy 10.20.3.60, DNS = resolver .53/.54 -> klien dari index=proxy / index=dns
SCAN       SYN tanpa ACK ; SYN-ACK = terbuka ; RST = tertutup ; vertikal (port) vs horizontal (host) ; ukur dampak
           firewall = semua probe | pcap sisi dalam = diizinkan, sesudah DNAT | flow edge 1:1000 = hampir buta
BRUTE      FTP 530 | HTTP 401 | SMB LOGON_FAILURE | SSH: banyak sesi pendek ke 22, lalu satu sesi panjang
           cari 230 SETELAH 530 ; spray = dc(user) lintas sumber ; mfa-denied = password benar
DNS        tunneling: label panjang + TXT + volume ke 1 induk ; DGA: NXDOMAIN acak ; flux: banyak IP TTL rendah
           nama unik: pcap = log (tanpa cache) ; nama berulang: pcap < log (negative cache) ; log resolver tanpa rcode
           volume label (asumsi base32) = karakter x 5 / 8 byte per query
HTTP       UA aneh | Host = IP | URI acak | magic byte MZ mengalahkan ekstensi/Content-Type
TLS        SNI (kecuali ECH) | sertifikat (1.2 saja) | JA3/JA4 = klien, bukan isi | ukuran+waktu App Data
           splice = ClientHello klien | bump = ClientHello proxy ; JA4 a: t12/t13 = versi tertinggi ditawarkan
JUJUR      sinyal + konteks (pemilik, prevalence, first-seen, host) + penjelasan jinak -> temuan
           bukti vs kesimpulan ; IOC defang ; domain populer bukan IOC ; nyatakan batas dan blind spot
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "Mulai minggu depan Zeek dan Suricata hidup, jadi lateral movement SMB antar workstation di kantor Jakarta sudah bisa kita lihat." Benarkah?

<details><summary>Jawaban</summary>

Tidak. `jkt-zeek01` dan `jkt-ids01` memakai sumber trafik yang sama dengan `jkt-pcap01` (TAP egress) ditambah SPAN core switch data center. Trafik workstation ke workstation di switch akses yang sama tidak melewati keduanya. Yang membaik adalah atribusi workstation di balik proxy dan resolver, karena SPAN core melihat sesi workstation ke proxy dan ke resolver. Lihat bagian 1.9.

</details>

**2. Skenario keputusan.** Firewall mencatat 2.000 event deny dari `203.0.113.173` ke 1.000 port di `198.51.100.207`, alamat publik yang tidak dipakai. Pcap egress nol paket, flow edge dua record. Apa kesimpulan yang tepat?

- A. False positive, karena pcap tidak melihat apa pun.
- B. Scan eksternal tanpa dampak: lebar scan dari firewall, nol di pcap karena probe dibuang sebelum TAP dan tidak ada DNAT, tidak ada port yang menjawab.
- C. Insiden, karena flow edge juga melihatnya sehingga trafiknya pasti besar.

<details><summary>Jawaban</summary>

B. Ketiga angka benar untuk titiknya: firewall melihat semua probe, pcap di sisi dalam hanya probe yang diizinkan, dan flow edge 1:1000 atas 2.000 paket memang memberi sekitar dua sampel. A keliru karena "tidak ada di pcap" berarti tidak sampai ke sensor, bukan tidak terjadi. C keliru karena dua record flow adalah hasil sampling, bukan tanda volume besar, dan dampak diukur dari port yang menjawab. Lihat bagian 1.4 dan Bagian B.

</details>

**3. Pertanyaan jebakan.** "Jumlah query DNS di pcap egress selalu lebih kecil daripada di log resolver, karena resolver menjawab sebagian dari cache." Benarkah?

<details><summary>Jawaban</summary>

Tidak selalu. Untuk nama yang berulang, cache dan negative caching memang membuat angka egress lebih kecil (Bagian C: 1.230 di log, 302 di pcap). Untuk nama yang selalu unik, cache tidak pernah bisa menjawab, sehingga setiap query diteruskan dan angkanya sama (Bagian D: 1.840 di kedua sumber). Angka yang sama untuk nama unik ke satu domain induk justru sinyal pola tunneling. Lihat bagian 1.3, Bagian C, dan Bagian D.

</details>

**4. Skenario keputusan.** Log proxy mencatat `JKT-WS-2033` membuka `paste-cdn.example:443` dengan `category=File-Sharing tls=spliced`. Di pcap egress, ClientHello ke SNI itu berasal dari `10.20.3.60` dengan JA4 berawalan `t12`. Fingerprint siapa yang kamu lihat?

- A. Fingerprint proxy, karena IP sumbernya proxy.
- B. Fingerprint klien asli di workstation, karena koneksi yang di-splice meneruskan ClientHello klien apa adanya.
- C. Tidak bisa diketahui tanpa dekripsi.

<details><summary>Jawaban</summary>

B. Pada splice, proxy hanya meneruskan, sehingga ClientHello di egress adalah milik klien walaupun IP sumbernya proxy; pada bump, proxy membuat ClientHello sendiri. A keliru karena IP sumber dan pemilik ClientHello adalah dua hal berbeda di proxy eksplisit. C keliru karena ClientHello selalu polos; yang butuh dekripsi adalah isi. Lihat bagian 1.6 dan Bagian E.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Hendra Wijaya (Direktur Teknologi), dalam tiga kalimat, apa yang sudah dibuktikan pcap uji coba minggu ini dan apa batasnya.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Dalam satu minggu, pcap egress ikut menentukan kelima insiden: ia menemukan unduhan berbahaya yang tidak ditanyakan siapa pun, membuktikan koneksi yang ditolak firewall tidak pernah tersambung, dan membantah catatan bahwa brute force FTP gagal semua. Tetapi pcap tidak pernah memberi nama proses atau workstation di balik proxy, jadi setiap kesimpulan tetap butuh EDR dan log proxy serta DNS, dan isinya hanya bertahan sekitar tiga sampai empat hari. Zeek dan Suricata minggu depan mempercepat pembacaan di titik yang sama, tetapi tidak membuat kita melihat trafik antar workstation, laptop VPN, atau isi HTTPS."

Kesalahan yang sering muncul:
- Menyebut jumlah alert tanpa menyebut apa yang hanya bisa dilihat dari pcap.
- Menjanjikan Zeek dan Suricata menutup semua blind spot.
- Lupa menyebut retensi yang menyusut saat trafik naik.

</details>

**6. Pertanyaan jebakan.** Gilang memotong pcap untuk kejadian Rabu 2027-05-12 pukul 06:30 sampai 08:00 WIB dengan `frame.time >= "2027-05-12T06:30:00Z" && frame.time < "2027-05-12T08:00:00Z"` dan mendapat pcap yang isinya tidak cocok dengan alert. Apa yang salah?

<details><summary>Jawaban</summary>

Jam WIB ditulis dengan akhiran "Z", sehingga filter mengambil 06:30 sampai 08:00 UTC, yaitu 13:30 sampai 15:00 WIB. Rentang yang benar adalah `2027-05-11T23:30:00Z` sampai `2027-05-12T01:00:00Z`, atau jam WIB dengan offset `+07:00`. Perhatikan bahwa 30 menit pertama masih bertanggal Selasa dalam UTC. Lihat bagian 1.2 dan Bagian A.

</details>

**7. Interview question (English).** "Your only packet sensor sits on the internet egress, behind an explicit proxy and internal DNS resolvers. You get an alert for long TXT queries. Walk me through your triage."

<details><summary>Sample answer</summary>

"First I remember what the sensor can and cannot see: in the packet capture every DNS query comes from the resolvers, so the client is only in the resolver logs. I carve a case pcap for the window with the timezone written explicitly and hash it. From the pcap I measure the shape: label length spread, how many names are unique, record type, response sizes, and which authoritative server receives them. From the resolver logs I attribute the client and check prevalence and first-seen for the parent domain. A fixed format used by many hosts of one team usually means a licensing or telemetry service; variable long labels, every name unique, one client and a domain first seen today point to tunnelling, and with unique names the egress count matches the log count because the cache cannot answer. I estimate volume with the encoding assumption written down, then ask the EDR which process made the queries. Only with host corroboration do I escalate it as an incident, and in the handover I separate evidence, estimates, and unknowns."

What makes this answer strong: it starts from sensor vantage point, combines packets and logs for different questions, tests benign explanations with prevalence and format, states assumptions behind the volume estimate, and does not call it tunnelling until the host confirms it.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Network-Forensics Day 01-06 (lokal) | (lokal) | rujukan internal | 2026-10-10, dicek ulang 2026-10-22 | Materi yang direview; masing-masing Day punya sumber primer sendiri |
| S2 | Wireshark User's Guide | https://www.wireshark.org/docs/wsug_html_chunked/ | primer | diakses 2026-10-09 | Tinggi. Statistics, Follow Stream, Export Objects, format waktu |
| S3 | Wireshark display filter reference | https://www.wireshark.org/docs/dfref/ | primer | diakses 2026-10-09 | Tinggi. Nama field di tabel bagian 1.10; cek per versi |
| S4 | RFC 9849: TLS Encrypted Client Hello | https://www.rfc-editor.org/rfc/rfc9849.html | primer | Maret 2026; diakses 2026-10-09 | Tinggi. Status ECH sebagai standar |
| S5 | RFC 9846: The Transport Layer Security (TLS) Protocol Version 1.3 | https://www.rfc-editor.org/rfc/rfc9846.html | primer | Juli 2026; diakses 2026-10-22 | Tinggi. Menggantikan RFC 8446 dan 5246; pesan handshake setelah ServerHello dienkripsi |
| S6 | MITRE ATT&CK T1071.004 Application Layer Protocol: DNS | https://attack.mitre.org/techniques/T1071/004/ | primer | v20.0, versi teknik 1.4 (diubah 2026-09-03); diakses 2026-10-22 | Tinggi. C2 lewat query dan record DNS seperti TXT; DET0400 |
| S7 | Wireshark: Download | https://www.wireshark.org/download.html | primer | diakses 2026-10-22 | Tinggi untuk nomor versi stabil, old stable, dan rilis pengembangan; halaman tidak memuat tanggal rilis |
| S8 | Zeek: Get Zeek | https://zeek.org/get-zeek/ | primer | diakses 2026-10-22 | Tinggi. 9.0.0 LTS (14 Sep 2026), LTS sebelumnya 8.0.10 |

**Catatan sumber:** Day review ini tidak menambah klaim teknis baru di luar Day 01-06 kecuali status versi di bagian 6; ringkasan di bagian 1.1 sampai 1.6 mewarisi sumber dan tingkat keyakinan Day asalnya, termasuk catatan legal Day 01 yang perlu dicocokkan dengan teks resmi di JDIH. Skenario di Bagian H fiktif, dan angka di dalamnya dibuat untuk latihan, bukan dari capture nyata. Seluruh isi PT JAB di bagian 1.8, 1.9, 1.12, dan lab gabungan (alert `SOC-2027-0630` sampai `0634`, `INC-2027-066`, host, domain, dan angka) adalah penerapan catatan ini pada organisasi fiktif dan keluaran ilustrasi, bukan hasil eksekusi nyata; perkiraan volume di Bagian D adalah aritmetika dengan asumsi penyandian base32 yang ditulis.
