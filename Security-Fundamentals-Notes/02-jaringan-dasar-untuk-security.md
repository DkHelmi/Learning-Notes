---
day: 02
title: 'Jaringan dasar untuk security: paket, IP, port, TCP/UDP, DNS, HTTP(S), NAT, dan port scan'
researched_on: 2026-10-20
versions_checked: 'RFC 9293 (TCP, Agustus 2022); RFC 768 (UDP); RFC 791 (IPv4); RFC 8200 (IPv6); RFC 4291 (arsitektur alamat IPv6); RFC 1918 (alamat privat); RFC 5737 dan RFC 3849 (alamat dokumentasi); RFC 4632 (CIDR); RFC 826 (ARP); RFC 792 (ICMP); RFC 1034 dan RFC 1035 (DNS); RFC 3596 (AAAA); RFC 1122 (lapisan TCP/IP); RFC 3022 (NAT); RFC 6335 (rentang port); RFC 9110 (HTTP semantics); RFC 9114 (HTTP/3); RFC 8484 (DNS over HTTPS); RFC 8744 (SNI); IANA Service Name and Port Number Registry (pembaruan 2026-10-15); NIST CSRC Glossary; MITRE ATT&CK T1046, T1557.002, T1071.004, T1133'
---

# Day 02: Jaringan dasar untuk security (paket, IP, port, TCP/UDP, DNS, HTTP(S), NAT, dan port scan)

Cakupan: istilah jaringan yang muncul di hampir setiap log dan alert security, yaitu paket dan header, protokol, model OSI dan TCP/IP, IP address dan subnet, MAC address dan ARP, port, TCP dan UDP, ICMP, DNS, HTTP dan HTTPS, NAT, serta port scan, masing-masing dengan alasan kenapa istilah itu penting untuk security.

## Ide inti

Setiap komunikasi di jaringan dipecah menjadi paket, dan setiap paket membawa label berisi alamat asal, alamat tujuan, nomor layanan yang dituju, dan aturan main yang dipakai. Hampir semua alat security, dari firewall sampai sistem pengumpul log di SOC, bekerja dengan membaca label itu, bukan dengan memahami isi percakapan. Karena itu, bila kamu bisa membaca label sebuah paket (siapa bicara ke siapa, lewat pintu mana, dengan aturan apa), kamu sudah bisa membaca sebagian besar log jaringan. Sisanya adalah memahami bagian yang membuat label itu menipu: alamat yang diterjemahkan, nama yang diubah menjadi angka, dan nomor pintu yang hanya kebiasaan.

Bayangkan jaringan sebagai layanan kurir. Isi kiriman dimasukkan ke paket, dan paket diberi label pengiriman. Label menulis alamat rumah pengirim dan penerima (IP address), nomor ruangan atau loket yang dituju di gedung penerima (port), dan jenis layanan kirimnya: surat tercatat yang harus ditandatangani penerima (TCP) atau brosur yang cukup dilempar ke pagar (UDP). Sebelum mengirim, kamu mencari alamat penerima di buku telepon atau kontak HP (DNS). Di kantor, semua kiriman keluar lewat resepsionis yang memakai satu nomor telepon untuk semua karyawan (NAT), dan di gerbang ada penjaga yang mengecek KTP dan alamat tujuan (firewall). Batas analoginya: label paket di jaringan bisa dipalsukan pengirimnya, dan penjaga gerbang biasa hanya membaca label, tidak membuka isi tas.

```
 Laptop kamu (10.10.4.27)
   |
   | 1. "docs.vendorapp.example itu IP berapa?"   --- DNS, UDP 53 --->  jkt-res01 (resolver)
   | 2. "192.0.2.80"                               <------------------
   |
   | 3. buka sambungan TCP ke 192.0.2.80 port 443 (three-way handshake)
   v
 jkt-fw01 (firewall + NAT)
   - cek aturan: boleh keluar ke port 443?            -> allow
   - ganti alamat asal 10.10.4.27 jadi 198.51.100.120  (NAT)
   - tulis satu baris log
   |
   v
 Internet ---> server 192.0.2.80:443
   |
   4. data HTTPS terenkripsi bolak-balik
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), sebuah ISP menengah fiktif dengan sekitar 1.200 karyawan dan sekitar 400 ribu pelanggan internet rumah. Jaringan internal PT JAB memakai alamat `10.10.0.0/16` untuk kantor Jakarta, `10.20.0.0/16` untuk data center, dan `10.30.0.0/16` untuk kantor Bandung. Sebagian besar server yang dibuka ke internet memakai rentang publik `198.51.100.0/24`, dan semua laptop kantor Jakarta keluar ke internet dengan satu alamat, `198.51.100.120`. Kamu adalah analyst L1 (lini pertama yang memeriksa setiap peringatan) yang baru bergabung di SOC (Security Operations Center, tim yang memantau dan menangani kejadian keamanan) PT JAB. Selasa 2027-08-03, hari kedua orientasi, pukul 09:00, mentormu Sari Kusuma (analyst L2) membuka dua hal di layar. Pertama, satu baris log dari firewall perimeter Jakarta `jkt-fw01`, yaitu sambungan laptopmu sendiri `JKT-WS-0815` pagi tadi. Kedua, alert (peringatan otomatis dari sistem pemantauan) `SOC-2027-0810` dari dini hari: IP luar `192.0.2.45` mengetuk banyak port di rentang IP publik PT JAB. Lalu Sari berkata:

> "Dua hal ini kelihatan beda, tapi bahannya sama. Coba jelaskan ke aku: satu baris log ini sebenarnya mencatat apa? Laptopmu alamatnya 10.10.4.27, kenapa di kolom lain muncul 198.51.100.120? Kenapa log ini tidak menyebut MAC address laptopmu? Angka 443 dan 52814 itu apa, dan kenapa aku langsung khawatir lihat 3389 di alert? Kolomnya bilang proto=tcp, bedanya apa dengan udp, dan apa maksud 'SYN tanpa ACK' di alert? Scanner itu juga mengirim ping dan tidak dibalas, artinya servernya mati? Kenapa ada query DNS dari laptopmu sedetik sebelum sambungan ini? Firewall tahu kamu buka situs apa, tapi tahu juga halaman apa yang kamu baca? Terakhir, port scan begini muncul hampir tiap hari. Kenapa yang ini aku angkat?"

Pesan itu memuat sembilan pertanyaan:

1. Apa yang sebenarnya tercatat dalam satu baris log, dan dari mana firewall mendapat informasinya?
2. Kenapa alamat laptop `10.10.4.27` tercatat sebagai `198.51.100.120` di kolom lain?
3. Kenapa log firewall tidak menyebut MAC address laptop?
4. Apa arti angka 443 dan 52814, dan kenapa port 3389 membuat khawatir?
5. Apa bedanya TCP dan UDP, dan apa maksud "SYN tanpa ACK"?
6. Bila ping tidak dibalas, apakah servernya mati?
7. Kenapa ada query DNS sebelum sambungan?
8. Firewall tahu situs yang dibuka, tetapi apakah tahu halaman yang dibaca?
9. Apa itu port scan, dan kenapa scan yang satu ini diangkat?

Pertanyaan 1 dijawab di bagian 1.1 dan 1.2, pertanyaan 2 di bagian 1.3, 1.4, dan 1.11, pertanyaan 3 di bagian 1.5, pertanyaan 4 di bagian 1.6, pertanyaan 5 di bagian 1.7, pertanyaan 6 di bagian 1.8, pertanyaan 7 di bagian 1.9, pertanyaan 8 di bagian 1.10, dan pertanyaan 9 di bagian 1.12. Bagian 2 membaca log, alert, jawaban DNS, dan perbandingan HTTP dengan HTTPS secara utuh.

**Kapan relevan:** setiap kali membaca log firewall, log DNS, log web, atau alert yang memuat IP, port, dan protokol; saat menilai apakah sebuah layanan terbuka ke internet; dan saat menjawab pertanyaan interview "apa yang terjadi saat seseorang membuka sebuah situs".
**Kapan bukan jawaban:** saat pertanyaannya tentang isi file, proses di dalam komputer, atau siapa orang di balik akun; label paket hanya memberi tahu alamat dan pintu, dan untuk itu dibutuhkan log endpoint dan identitas yang dibahas di Day lain.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day 01 (CIA triad, risk, control, attack surface) tidak diulang di sini. Tabel ini memuat semua istilah jaringan yang dipakai Day ini; cari kolom ketiga bila sebuah istilah terasa abstrak.

| Istilah | Arti singkat | Padanan sehari-hari |
|---|---|---|
| Paket | Satuan kecil data yang dikirim lewat jaringan | Paket kurir |
| Header | Bagian awal paket berisi alamat dan informasi kendali | Label pengiriman di paket |
| Protokol | Aturan baku cara dua pihak berkomunikasi | Tata cara mengisi formulir pengiriman yang sama di semua kantor |
| Model OSI | Model konsep tujuh lapisan untuk menjelaskan komunikasi jaringan | Tahapan pengiriman: isi, kemas, label, truk, jalan |
| Model TCP/IP | Model empat lapisan yang benar-benar dipakai internet | Versi ringkas tahapan yang sama |
| IP address | Alamat sebuah perangkat di jaringan | Alamat rumah lengkap |
| IP publik / IP privat | Alamat yang berlaku di internet / alamat yang hanya berlaku di jaringan internal | Alamat jalan resmi / nomor ruangan di dalam gedung |
| IPv4 / IPv6 | Versi alamat 32 bit / versi alamat 128 bit | Format alamat lama dan format alamat baru yang jauh lebih panjang |
| Subnet dan CIDR | Satu blok alamat yang berurutan, ditulis dengan garis miring (`/24`) | Satu kompleks perumahan dengan rentang nomor rumah |
| MAC address | Alamat perangkat keras kartu jaringan, hanya berarti di jaringan lokal | Nomor rangka kendaraan |
| ARP | Protokol untuk mencari MAC address dari sebuah IP di jaringan lokal | Bertanya ke seluruh lorong, "Siapa yang menempati kamar 27?" |
| Port | Nomor yang menunjuk layanan tertentu di sebuah perangkat | Nomor loket atau nomor ruangan di gedung |
| Port ephemeral | Port sementara yang dipilih perangkat untuk sisi pengirim | Nomor antrean yang diambil tamu dan dibuang setelah urusan selesai |
| TCP | Protokol yang membuka sambungan dan memastikan data sampai berurutan | Surat tercatat dengan tanda terima |
| UDP | Protokol yang mengirim tanpa sambungan dan tanpa jaminan sampai | Brosur yang dilempar ke pagar |
| Three-way handshake | Tiga langkah pembuka sambungan TCP: SYN, SYN-ACK, ACK | Percakapan telepon: "Halo?", "Halo, dengar?", "Dengar, mulai." |
| ICMP | Protokol pesan kendali dan laporan kesalahan, dipakai `ping` | Surat pemberitahuan kantor pos "alamat tidak ditemukan" |
| DNS | Sistem yang menerjemahkan nama domain menjadi IP address | Buku telepon atau kontak HP |
| Resolver | Server yang mencarikan jawaban DNS untuk perangkat | Operator informasi yang mencarikan nomor telepon |
| DNS record | Satu baris data DNS, misalnya A, AAAA, MX, TXT, CNAME, PTR | Satu entri di buku telepon |
| HTTP / HTTPS | Protokol web tanpa enkripsi / protokol web di atas TLS yang terenkripsi | Kartu pos / surat dalam amplop tersegel |
| SNI | Nama situs yang dikirim browser di awal sambungan HTTPS | Nama penerima yang tetap tertulis di luar amplop |
| NAT | Penerjemahan alamat privat menjadi alamat publik di batas jaringan | Resepsionis yang memakai satu nomor telepon untuk semua karyawan |
| Port scan | Memeriksa dari jauh port mana yang terbuka di sebuah perangkat | Orang yang mengetuk setiap pintu di gedung untuk melihat mana yang dibuka |
| Firewall | Perangkat yang memeriksa alamat dan port lalu mengizinkan atau menolak lalu lintas | Penjaga gerbang yang cek KTP dan alamat tujuan |

### 1.1 Paket, header, dan protokol

Pertanyaan pertama Sari ("satu baris log ini mencatat apa?") hanya bisa dijawab bila kamu tahu apa yang dilihat firewall. Firewall adalah perangkat yang memeriksa alamat dan port setiap lalu lintas lalu mengizinkan atau menolaknya; pembahasan lengkapnya ada di Day 03. Yang dilihat firewall adalah paket.

**Apa itu:** paket adalah satuan kecil data yang dikirim lewat jaringan. Sebuah file atau halaman web tidak dikirim utuh, tetapi dipecah menjadi banyak paket. Setiap paket terdiri dari header (bagian awal berisi informasi pengiriman) dan payload (isi yang dibawa). Protokol adalah aturan baku yang menentukan bentuk header, urutan pesan, dan apa yang harus dilakukan kedua pihak, supaya perangkat buatan pabrik mana pun bisa saling mengerti.

**Analogi:** paket kurir dan labelnya. Label menulis alamat pengirim, alamat penerima, dan jenis layanan; isi kardus tidak perlu dibuka untuk mengirimkannya. Protokol adalah formulir pengiriman baku yang dipakai semua kantor kurir. Batasnya: label paket jaringan diisi sendiri oleh pengirim, jadi alamat asal bisa dipalsukan (spoofing), dan tidak ada petugas yang mengecek KTP pengirim saat paket diserahkan.

**Cara kerja:** paket dibungkus berlapis, dan setiap lapisan menambah header-nya sendiri. Header IP berisi antara lain alamat asal, alamat tujuan, nomor protokol di dalamnya, dan Time to Live (TTL), angka yang dikurangi setiap kali paket melewati router (perangkat yang meneruskan paket antar jaringan) supaya paket yang tersesat tidak berputar selamanya [S3]. Header TCP berisi port asal, port tujuan, nomor urut, dan flag kendali seperti SYN, ACK, FIN, dan RST [S1]. Header UDP hanya punya empat field: port asal, port tujuan, panjang, dan checksum (angka untuk memeriksa kerusakan data) [S2].

```
+------------------+----------------+-----------------+----------------------+
| Ethernet header  | IP header      | TCP header      | payload (isi)        |
| MAC asal/tujuan  | IP asal/tujuan | port asal/tujuan| mis. permintaan web  |
|                  | TTL, protokol  | flag SYN/ACK/.. |                      |
+------------------+----------------+-----------------+----------------------+
  lokal saja         dari ujung ke ujung                 dilihat aplikasi
```

**Contoh di PT JAB:** baris log `jkt-fw01` yang dibuka Sari berisi tanggal, aksi `allow`, `proto=tcp`, IP asal dan tujuan, port asal dan tujuan, serta jumlah byte. Hampir semuanya diambil dari header IP dan TCP. Firewall tidak perlu membaca isi halaman untuk menulis baris itu.

**Beda dengan isi (payload):** header menjawab "dari siapa, ke mana, lewat pintu apa"; payload menjawab "apa yang dibicarakan". Log firewall biasa hampir seluruhnya berasal dari header. Untuk tahu isi, dibutuhkan alat lain atau log aplikasi.

Kenapa ini penting untuk security: karena alamat asal bisa dipalsukan, satu IP di log belum tentu pelaku sebenarnya, terutama untuk lalu lintas tanpa sambungan seperti UDP. Pada sambungan TCP yang sudah selesai handshake (bagian 1.7), pemalsuan jauh lebih sulit karena pengirim harus menerima balasan.

### 1.2 Model OSI vs model TCP/IP

Sari menyebut bahwa firewall "melihat lapisan 3 dan 4". Angka lapisan itu berasal dari model OSI, cara baku orang security dan jaringan menyebut letak sebuah masalah atau alat.

**Apa itu:** model OSI (Open Systems Interconnection) adalah model konsep yang membagi komunikasi jaringan menjadi tujuh lapisan, dari kabel sampai aplikasi. Model TCP/IP adalah model yang benar-benar dipakai internet, dengan empat lapisan: Application, Transport, Internet, dan Link [S17]. OSI dipakai sebagai bahasa bersama untuk belajar dan menjelaskan; TCP/IP adalah yang berjalan di perangkat [S18].

**Analogi:** tahapan pengiriman kurir. Ada yang menulis isi surat, yang mengemas, yang menempel label alamat, yang memuat ke truk, dan jalan raya tempat truk lewat. Setiap tahap hanya peduli pada tugasnya sendiri. Batasnya: di dunia nyata satu perangkat sering bekerja di beberapa lapisan sekaligus, jadi pembagian lapisan adalah alat bantu berpikir, bukan sekat yang kaku.

**Cara kerja:** tabel berikut memetakan tujuh lapisan OSI ke empat lapisan TCP/IP. Cari kolom "Contoh" untuk mengingat protokol mana yang tinggal di lapisan mana; angka di kolom pertama adalah yang dimaksud orang saat menyebut "serangan layer 7" atau "firewall layer 3/4".

| No | Lapisan OSI | Tugasnya | Contoh | Lapisan TCP/IP |
|---|---|---|---|---|
| 7 | Application | Antarmuka ke aplikasi | HTTP, DNS, SMTP, FTP | Application |
| 6 | Presentation | Format, enkripsi, kompresi data | Pengubahan format data | Application |
| 5 | Session | Membuka, menjaga, menutup sesi | RPC, NetBIOS | Application |
| 4 | Transport | Pengiriman dari ujung ke ujung, port | TCP, UDP | Transport |
| 3 | Network | Alamat logis dan routing | IP, ICMP | Internet |
| 2 | Data Link | Pengiriman di satu jaringan lokal | Ethernet, Wi-Fi, MAC address | Link |
| 1 | Physical | Sinyal di media | Kabel, fiber, gelombang radio | Link |

Pemetaan lapisan 5 sampai 7 OSI ke satu lapisan Application di TCP/IP disebut langsung di RFC 1122 untuk lapisan 6 dan 7, dan dijelaskan di sumber sekunder untuk ketiganya [S17][S18]. Lapisan Link kadang disebut Network Access [S18].

**Contoh di PT JAB:** firewall `jkt-fw01` memutuskan berdasarkan IP (lapisan 3) dan port (lapisan 4). Alert serangan web yang memuat path URL berada di lapisan 7. Saat Sari berkata "itu masalah layer 2", maksudnya masalah di jaringan lokal, misalnya kabel, switch (perangkat yang menyambungkan banyak perangkat di satu jaringan lokal), atau MAC address.

**Beda dengan model TCP/IP:** OSI punya tujuh lapisan dan tidak terikat protokol tertentu; TCP/IP punya empat lapisan dan dibangun di sekitar protokol yang memang dipakai [S18]. Di percakapan sehari-hari orang mencampur keduanya: nama protokol dari TCP/IP, nomor lapisan dari OSI.

Kenapa ini penting untuk security: setiap alat pertahanan bekerja di lapisan tertentu. Alat yang hanya melihat lapisan 3 dan 4 tidak bisa membedakan permintaan web yang wajar dan yang berbahaya ke port yang sama. Pertanyaan "alat ini melihat sampai lapisan berapa?" akan sering muncul di Day 03 dan Day 04.

### 1.3 IP address: publik vs privat, IPv4 vs IPv6

Pertanyaan kedua Sari dimulai dari dua angka: `10.10.4.27` milik laptopmu dan `198.51.100.120` di kolom lain. Keduanya IP address, tetapi jenisnya berbeda.

**Apa itu:** IP address adalah alamat sebuah perangkat di jaringan, dipakai router untuk mengantar paket ke tujuan. IPv4 memakai alamat 32 bit yang ditulis sebagai empat angka 0 sampai 255 dipisah titik, misalnya `10.10.4.27` [S3]. IP publik berlaku di seluruh internet dan harus unik. IP privat hanya berlaku di dalam jaringan sebuah organisasi; tiga blok privat IPv4 ditetapkan RFC 1918: `10.0.0.0/8`, `172.16.0.0/12`, dan `192.168.0.0/16` [S6].

**Analogi:** alamat rumah lengkap. IP publik seperti alamat jalan resmi yang bisa dituju kurir dari kota mana pun. IP privat seperti nomor ruangan di dalam gedung kantor: "ruang 27" ada di banyak gedung, dan hanya bermakna setelah kamu berada di dalam gedung itu. Batasnya: alamat rumah jarang berubah, sedangkan IP bisa berubah, misalnya karena DHCP (layanan yang membagikan IP otomatis saat perangkat tersambung), dan satu IP publik bisa dipakai bersama banyak perangkat (bagian 1.11).

**Cara kerja:** router di internet tidak meneruskan paket ke alamat privat, jadi alamat privat yang sama bisa dipakai ulang di ribuan organisasi [S6]. Supaya perangkat berIP privat bisa ke internet, alamatnya diterjemahkan ke IP publik di batas jaringan (NAT, bagian 1.11).

IPv4 hanya punya 2^32, sekitar 4,29 miliar alamat (tepatnya 4.294.967.296), dan jumlah itu tidak cukup untuk semua perangkat di dunia. IPv6 memakai alamat 128 bit [S4], ditulis sebagai delapan kelompok heksadesimal dipisah titik dua; deretan kelompok nol boleh disingkat `::` satu kali dalam satu alamat [S5]. Contoh: `2001:db8:64:1::10`. Alamat `::1` adalah loopback (perangkat bicara ke dirinya sendiri), dan alamat yang diawali `fe80:` hanya berlaku di satu jaringan lokal [S5]. Header IPv6 mengganti nama TTL menjadi Hop Limit dengan fungsi yang sama [S4].

**Contoh di PT JAB:** `10.10.4.27` ada di blok privat `10.0.0.0/8`, jadi hanya bermakna di dalam PT JAB. `198.51.100.120` adalah alamat publik kantor Jakarta yang terlihat oleh internet. `192.0.2.45`, sumber port scan, juga alamat publik. Di catatan ini semua alamat publik memakai rentang khusus dokumentasi `192.0.2.0/24`, `198.51.100.0/24`, dan `203.0.113.0/24` [S7] serta `2001:db8::/32` untuk IPv6 [S8], supaya tidak menunjuk organisasi sungguhan.

**Beda dengan MAC address:** IP adalah alamat logis yang bisa diganti dan dipakai dari ujung ke ujung; MAC address melekat pada kartu jaringan dan hanya berarti di jaringan lokal (bagian 1.5).

**Salah paham umum:**
- "IP privat berarti perangkatnya aman dari internet." Perangkat privat tetap bisa membuka sambungan keluar, dan malware (program jahat) di laptop memanfaatkan jalan keluar itu. Yang tidak bisa dilakukan pihak luar adalah langsung memulai sambungan ke alamat privat tanpa aturan khusus di batas jaringan.

Kenapa ini penting untuk security: jenis IP menentukan pertanyaan berikutnya. IP privat di log berarti kamu mencari perangkatnya di inventaris internal. IP publik berarti kamu mencari pemiliknya di luar, atau mengecek reputasinya. Alert yang memuat IPv6 juga harus diperlakukan sama seriusnya; IPv6 bukan "jaringan lain" yang boleh diabaikan.

### 1.4 Subnet dan notasi CIDR

Alamat `10.10.4.27` ada di dalam `10.10.0.0/16`, blok kantor Jakarta. Garis miring dan angka 16 itu adalah cara menulis subnet.

**Apa itu:** subnet adalah satu blok alamat IP yang berurutan dan diperlakukan sebagai satu kelompok. CIDR (Classless Inter-Domain Routing) adalah notasi untuk menulis blok itu: alamat awal, garis miring, lalu jumlah bit di depan yang menjadi bagian jaringan [S9]. Sisa bitnya dipakai untuk membedakan perangkat di dalam blok.

**Analogi:** satu kompleks perumahan. Nama kompleks (bagian jaringan) sama untuk semua rumah di dalamnya, dan nomor rumah (bagian host) membedakan tiap rumah. Angka setelah garis miring menentukan seberapa panjang nama kompleks; makin panjang namanya, makin sedikit nomor rumah yang tersisa. Batasnya: batas kompleks di jaringan bisa dipindah dengan mengubah satu angka, sesuatu yang tidak bisa dilakukan pada kompleks sungguhan.

**Cara kerja:** sebuah prefix sepanjang n bit mencakup 2^(32 - n) alamat [S9]. Makin kecil angka di belakang garis miring, makin besar bloknya. Dua alamat di setiap blok biasanya tidak dipakai untuk perangkat: alamat pertama (alamat jaringan) dan alamat terakhir (alamat broadcast). Tabel berikut menunjukkan ukuran blok yang paling sering muncul; cari kolom "Bisa dipakai perangkat" saat menghitung.

| CIDR | Subnet mask | Jumlah alamat | Bisa dipakai perangkat | Contoh di PT JAB |
|---|---|---|---|---|
| `/32` | 255.255.255.255 | 1 | 1 (satu alamat tunggal) | `198.51.100.120` saja |
| `/24` | 255.255.255.0 | 256 | 254 | `10.10.4.0/24`, satu lantai kantor |
| `/16` | 255.255.0.0 | 65.536 | 65.534 | `10.10.0.0/16`, seluruh kantor Jakarta |
| `/8` | 255.0.0.0 | 16.777.216 | 16.777.214 | `10.0.0.0/8`, seluruh blok privat 10 |

CIDR menggantikan pembagian lama Class A, B, dan C, yang ukurannya kaku [S9]. Istilah "kelas C" masih sering terdengar untuk maksud `/24`.

**Contoh di PT JAB:** `10.10.4.27` ada di `10.10.4.0/24` (alamat `10.10.4.1` sampai `10.10.4.254` untuk perangkat) dan sekaligus di `10.10.0.0/16`. Dari angka itu saja kamu tahu laptopmu ada di kantor Jakarta, bukan di data center (`10.20.0.0/16`) atau Bandung (`10.30.0.0/16`).

**Beda dengan subnet mask:** CIDR `/24` dan subnet mask `255.255.255.0` adalah dua cara menulis hal yang sama. CIDR lebih ringkas dan lebih umum di aturan firewall dan dokumentasi modern.

Kenapa ini penting untuk security: aturan firewall, allowlist, dan blocklist ditulis dalam CIDR. Salah ketik satu angka mengubah cakupan secara drastis: aturan yang dimaksudkan untuk `198.51.100.0/24` (256 alamat) tetapi tertulis `/8` mencakup lebih dari 16 juta alamat.

### 1.5 MAC address dan ARP

Pertanyaan ketiga Sari: kenapa log firewall tidak menyebut MAC address laptopmu? Jawabannya ada pada jangkauan MAC address.

**Apa itu:** MAC address adalah alamat perangkat keras kartu jaringan, 48 bit, biasanya ditulis sebagai enam pasang heksadesimal seperti `3c:52:82:1a:7e:04`. Alamat ini dipakai untuk mengantar paket di dalam satu jaringan lokal (lapisan 2). ARP (Address Resolution Protocol) adalah protokol untuk mencari MAC address dari sebuah IP di jaringan lokal [S10].

**Analogi:** MAC address seperti nomor rangka kendaraan, melekat pada perangkatnya. ARP seperti bertanya ke seluruh lorong, "Siapa yang menempati kamar 27?", lalu penghuni kamar 27 menjawab langsung ke penanya. Batasnya: nomor rangka sulit diganti, sedangkan MAC address bisa diubah lewat perangkat lunak, jadi tidak bisa dijadikan bukti identitas yang kuat.

**Cara kerja:** saat laptop mau mengirim paket ke IP lain di jaringan lokal (atau ke router sebagai pintu keluar), laptop butuh MAC tujuan. Bila belum tahu, laptop menyiarkan permintaan ARP ke semua perangkat di jaringan lokal; perangkat yang punya IP itu membalas langsung dengan MAC-nya, dan laptop menyimpan pasangan itu di tabel ARP [S10]. Setiap kali paket melewati router, header lapisan 2 diganti dengan MAC router berikutnya, sehingga MAC laptopmu tidak pernah sampai ke internet.

```
 Laptop 10.10.4.27                         Jaringan lokal 10.10.4.0/24
   "Siapa punya 10.10.4.1? Beri tahu 10.10.4.27"  ==> siaran ke semua
   <== "10.10.4.1 ada di 00:1a:2b:3c:4d:5e"         (jawaban langsung dari router)
   laptop simpan: 10.10.4.1 = 00:1a:2b:3c:4d:5e
```

**Contoh di PT JAB:** `jkt-fw01` berada beberapa lompatan router dari laptopmu, jadi yang dilihatnya adalah MAC router terakhir, bukan MAC laptop. Itu sebabnya log firewall tidak mencatat MAC. MAC laptop baru terlihat di perangkat jaringan lokal, misalnya switch lantai atau server DHCP, yang mencatat "IP 10.10.4.27 diberikan ke MAC `3c:52:82:1a:7e:04` pukul 07:52".

**Beda dengan IP address:** IP dipakai dari ujung ke ujung dan bisa berganti; MAC hanya berlaku di satu jaringan lokal dan diganti di setiap lompatan router.

Kenapa ini penting untuk security: ARP tidak punya autentikasi; perangkat menerima jawaban ARP tanpa memeriksa siapa pengirimnya [S10][S27]. Penyerang yang sudah berada di jaringan lokal bisa mengirim jawaban ARP palsu ("10.10.4.1 ada di MAC saya"), sehingga lalu lintas korban lewat perangkatnya dulu. Teknik ini disebut ARP spoofing atau ARP cache poisoning, dan dipakai untuk menyadap atau mengubah data [S27]. Data log yang mengaitkan IP dan MAC (DHCP, switch) juga menjadi bahan penting saat mencari perangkat mana yang memakai sebuah IP pada jam tertentu.

### 1.6 Port dan port umum

Pertanyaan keempat Sari menyangkut dua angka di log (`443` dan `52814`) dan satu angka di alert (`3389`).

**Apa itu:** port adalah nomor 0 sampai 65535 yang menunjuk layanan tertentu di sebuah perangkat. Satu perangkat dengan satu IP bisa menjalankan banyak layanan sekaligus, dan port yang membedakan paket untuk layanan web dari paket untuk layanan email. IANA (lembaga yang mencatat nomor-nomor baku internet) membagi port menjadi tiga rentang: System atau Well Known 0 sampai 1023, User atau Registered 1024 sampai 49151, dan Dynamic atau Private 49152 sampai 65535 [S15][S16]. Port di rentang Dynamic juga disebut port ephemeral dan tidak pernah didaftarkan untuk layanan tertentu [S16].

**Analogi:** IP adalah alamat gedung; port adalah nomor loket atau nomor ruangan di gedung itu. Loket 443 melayani web aman, loket 25 menerima surat. Tamu yang datang juga mengambil nomor antrean sementara (port ephemeral) supaya jawaban kembali ke orang yang tepat. Batasnya: nomor loket hanya kebiasaan. Layanan apa pun bisa dipasang di loket mana pun bila dikonfigurasi begitu.

**Cara kerja:** sambungan selalu punya dua port. Sisi server memakai port tetap yang sudah dikenal (443), sisi klien memakai port ephemeral yang dipilih acak oleh sistem operasi (52814). Pasangan IP asal, port asal, IP tujuan, port tujuan, dan protokol membedakan satu sambungan dari yang lain, sehingga laptop yang membuka sepuluh tab ke situs yang sama tetap tidak bingung.

Tabel berikut adalah port yang paling sering muncul di log dan alert. Cari kolom terakhir: itulah alasan port tersebut sering diperhatikan SOC.

| Port | Protokol transport | Layanan (nama IANA) | Kenapa diperhatikan security |
|---|---|---|---|
| 20, 21 | TCP | FTP data dan kendali (`ftp-data`, `ftp`) | Transfer file tanpa enkripsi; password terbaca di jaringan |
| 22 | TCP | SSH (`ssh`) | Akses jarak jauh ke server; sasaran tebak password |
| 23 | TCP | Telnet (`telnet`) | Akses jarak jauh tanpa enkripsi; tidak layak dibuka |
| 25 | TCP | SMTP (`smtp`) | Pengiriman email antar server; disalahgunakan untuk spam |
| 53 | UDP dan TCP | DNS (`domain`) | Hampir selalu diizinkan; bisa dipakai sebagai saluran rahasia (bagian 1.9) |
| 80 | TCP | HTTP (`http`) | Web tanpa enkripsi; isi terbaca |
| 110, 143 | TCP | POP3 (`pop3`), IMAP (`imap`) | Mengambil email dari server; versi tanpa enkripsi membuka password |
| 443 | TCP, juga UDP | HTTPS (`https`) | Sebagian besar lalu lintas web; isi terenkripsi |
| 445 | TCP | SMB, berbagi file Windows (`microsoft-ds`) | Jalur penyebaran program jahat (ransomware, worm); tidak boleh terbuka ke internet |
| 1433 | TCP | Microsoft SQL Server (`ms-sql-s`) | Database; tidak boleh terbuka ke internet |
| 3306 | TCP | MySQL (`mysql`) | Database; tidak boleh terbuka ke internet |
| 3389 | TCP, juga UDP | RDP, remote desktop Windows (`ms-wbt-server`) | Pintu masuk favorit penyerang bila terbuka ke internet |
| 49152 sampai 65535 | TCP dan UDP | Ephemeral, tidak didaftarkan | Port sisi klien; normal muncul sebagai port asal |

Nama layanan di kolom ketiga adalah nama resmi di registry IANA [S15]. Registry mencatat sebagian besar nomor ini untuk TCP dan UDP sekaligus; kolom kedua menulis protokol yang lazim dipakai.

**Contoh di PT JAB:** di log, `dpt=443` berarti laptopmu menuju layanan web aman di server tujuan, dan `spt=52814` adalah nomor antrean sementara milik laptopmu, yang masuk rentang ephemeral 49152 sampai 65535. Di alert `SOC-2027-0810`, server `198.51.100.35` menjawab di port 3389. Artinya ada layanan remote desktop Windows yang bisa dijangkau dari internet.

**Beda dengan protokol:** port menunjuk layanan di sebuah perangkat; protokol (TCP, UDP, HTTP) adalah aturan bicaranya. Port 53 dipakai DNS di atas UDP maupun TCP [S13].

**Salah paham umum:**
- "Lalu lintas di port 443 pasti HTTPS yang sah." RFC 6335 sendiri mengingatkan bahwa nomor port tidak menjamin layanan di baliknya, dan lalu lintas di port terdaftar tidak membuktikan lalu lintas itu sah [S16]. Penyerang sengaja memakai port 443 karena hampir selalu diizinkan keluar.

Kenapa ini penting untuk security: setiap port yang terbuka ke internet adalah pintu yang bisa dicoba orang lain, bagian dari attack surface (lihat Day 01). RDP yang terbuka ke internet tercatat dipakai berbagai kelompok penyerang sebagai akses awal [S29]. Port 445, 1433, dan 3306 adalah layanan internal yang tidak punya alasan diakses langsung dari internet.

### 1.7 TCP vs UDP dan three-way handshake

Kolom `proto=tcp` di log dan frasa "SYN tanpa ACK" di alert adalah pertanyaan kelima Sari.

**Apa itu:** TCP (Transmission Control Protocol) dan UDP (User Datagram Protocol) adalah dua protokol lapisan transport. TCP membuka sambungan lebih dulu, memberi nomor urut pada data, meminta tanda terima, dan mengirim ulang data yang hilang, sehingga data sampai lengkap dan berurutan [S1]. UDP langsung mengirim tanpa sambungan; RFC 768 menyebut pengiriman dan perlindungan dari duplikasi tidak dijamin [S2]. Three-way handshake adalah tiga langkah TCP untuk membuka sambungan: SYN, SYN-ACK, ACK [S1].

**Analogi:** TCP seperti surat tercatat dengan tanda terima: pengirim tahu suratnya sampai, dan surat yang hilang dikirim ulang. UDP seperti brosur yang dilempar ke pagar: cepat dan murah, tetapi pengirim tidak tahu apakah brosur dibaca. Handshake seperti membuka telepon: "Halo?", "Halo, kamu dengar saya?", "Dengar, ayo mulai." Batasnya: UDP bukan berarti tidak bisa diandalkan sama sekali. Aplikasi di atas UDP bisa menambah pemeriksaan sendiri, dan DNS serta HTTP/3 berjalan di atas UDP dengan baik.

**Cara kerja:** klien mengirim segmen dengan flag SYN dan nomor urut awal. Server membalas dengan SYN miliknya sekaligus ACK atas nomor urut klien. Klien membalas ACK atas nomor urut server. Setelah itu data mengalir. Sambungan ditutup dengan FIN (selesai baik-baik) atau dihentikan dengan RST (reset) [S1].

```
 Laptop 10.10.4.27:52814                       Server 192.0.2.80:443
        |                                              |
        | ---- SYN      (seq=x) ---------------------> |  1. "Halo?"
        | <--- SYN-ACK  (seq=y, ack=x+1) ------------- |  2. "Halo, kamu dengar saya?"
        | ---- ACK      (ack=y+1) -------------------> |  3. "Dengar, ayo mulai."
        | ==== data (HTTPS) ========================== |
        | ---- FIN  (selesai) atau RST (putus) ------> |
```

Delapan flag kendali TCP menurut RFC 9293 adalah CWR, ECE, URG, ACK, PSH, RST, SYN, dan FIN [S1]. Untuk pekerjaan SOC sehari-hari, empat yang paling sering dibaca adalah SYN, ACK, FIN, dan RST. Bila SYN datang ke port yang tidak punya layanan, perangkat membalas RST [S1].

**Contoh di PT JAB:** sambungan laptopmu ke `192.0.2.80:443` memakai TCP dan handshake-nya selesai, karena ada data yang terkirim (kolom byte di log). Di alert `SOC-2027-0810`, scanner mengirim SYN, menerima SYN-ACK dari port yang terbuka, tetapi tidak pernah mengirim ACK penutup; ia langsung mengirim RST. Itulah arti "SYN tanpa ACK": handshake sengaja dibiarkan setengah jadi karena scanner hanya ingin tahu pintunya terbuka atau tidak.

**Beda dengan UDP:** UDP tidak punya handshake, jadi tidak ada SYN, ACK, atau status sambungan. Firewall dan log tetap mencatat alamat dan port-nya, tetapi tidak ada tanda "sambungan berhasil" seperti pada TCP. Perbandingan lengkapnya ada di bagian 3.

Kenapa ini penting untuk security: pola flag menceritakan niat. Banyak SYN tanpa handshake lengkap ke banyak port adalah ciri port scan (bagian 1.12). Handshake yang selesai berarti kedua pihak benar-benar terhubung, sehingga alamat asalnya jauh lebih bisa dipercaya daripada paket UDP tunggal.

### 1.8 ICMP

Pertanyaan keenam Sari berasal dari baris "ICMP echo: 254, semua ditolak" di alert. Scanner mengirim ping ke 254 alamat dan tidak ada satu pun yang dibalas.

**Apa itu:** ICMP (Internet Control Message Protocol) adalah protokol untuk pesan kendali dan laporan kesalahan pengiriman, misalnya "tujuan tidak bisa dijangkau". ICMP adalah bagian tak terpisahkan dari IP dan wajib ada di setiap perangkat IP [S11]. Perintah `ping` memakai ICMP Echo (type 8) dan Echo Reply (type 0) [S11].

**Analogi:** surat pemberitahuan kantor pos, misalnya "alamat tidak ditemukan" atau "paket kedaluwarsa di jalan". `ping` seperti mengirim kartu "Kamu di rumah?" dan menunggu kartu balasan. Batasnya: rumah yang tidak membalas kartu belum tentu kosong; penghuninya mungkin memang tidak membalas kartu dari orang asing.

**Cara kerja:** tabel berikut memuat pesan ICMP yang paling sering muncul di log; cari kolom "Artinya bagi analyst".

| Type (code) | Nama | Artinya bagi analyst |
|---|---|---|
| 8 | Echo (permintaan `ping`) | Seseorang menanyakan "apakah alamat ini hidup?" |
| 0 | Echo Reply | Alamat itu hidup dan mau membalas ping |
| 3 (code 3) | Destination Unreachable, port unreachable | Port UDP yang dituju tidak punya layanan |
| 3 (kode lain) | Destination Unreachable | Jaringan, host, atau protokol tidak bisa dijangkau |
| 11 | Time Exceeded | TTL paket habis di jalan; dipakai juga oleh `traceroute` |

Semua nomor type dan code di atas berasal dari RFC 792 [S11]. `traceroute` memanfaatkan TTL yang sengaja dibuat kecil sehingga setiap router di jalan membalas Time Exceeded dan memperlihatkan dirinya.

**Contoh di PT JAB:** `jkt-fw01` diatur untuk menolak ICMP Echo dari internet. Karena itu 254 ping dari `192.0.2.45` tidak dibalas, padahal empat server di rentang itu hidup dan salah satunya bahkan membuka port 3389. Scanner yang hanya mengandalkan ping akan menyimpulkan semua alamat mati; scanner ini tetap melanjutkan dengan SYN, dan berhasil menemukan layanan.

**Beda dengan TCP dan UDP:** ICMP tidak memakai port. Pesannya dibedakan dengan type dan code, bukan nomor layanan.

Kenapa ini penting untuk security: ping tidak dibalas tidak membuktikan perangkat mati, karena ICMP sering diblokir. Sebaliknya, deretan ICMP Echo ke banyak alamat berurutan (ping sweep) adalah tanda awal pengintaian. Jawaban ICMP port unreachable juga membantu penyerang memetakan port UDP yang tertutup.

### 1.9 DNS

Pertanyaan ketujuh Sari: sedetik sebelum baris log firewall, resolver `jkt-res01` mencatat laptopmu bertanya "`docs.vendorapp.example` itu IP berapa?". Sambungan ke `192.0.2.80` baru terjadi setelah jawaban datang.

**Apa itu:** DNS (Domain Name System) adalah sistem yang menerjemahkan nama domain yang mudah diingat manusia menjadi data yang dibutuhkan perangkat, terutama IP address. DNS punya tiga komponen: ruang nama dan record, name server yang menyimpan data, dan resolver yang mencarikan jawaban untuk perangkat [S12]. DNS memakai port 53 di atas UDP maupun TCP [S13].

**Analogi:** buku telepon atau kontak HP. Kamu mengingat nama "Sari", HP yang menyimpan nomornya. Resolver seperti operator informasi yang mencarikan nomor bila kontak itu belum ada di HP-mu, lalu mengingatnya untuk sementara. Batasnya: jawaban DNS bisa dipalsukan bila tidak divalidasi, dan satu nama bisa punya banyak nomor yang berganti-ganti.

**Cara kerja:** laptop punya stub resolver sederhana yang hanya tahu alamat resolver kantor [S12]. Resolver (`jkt-res01`) melakukan pencarian rekursif: menanyakan ke name server lain sampai mendapat jawaban akhir, lalu mengembalikannya ke laptop [S12]. Setiap jawaban punya TTL dalam detik, batas berapa lama jawaban boleh disimpan di cache [S12]. TTL di DNS adalah batas waktu cache, berbeda dengan TTL di header IP yang menghitung lompatan router.

Jenis record yang paling sering ditemui dirangkum di tabel berikut; cari kolom "Contoh pemakaian" untuk mengingat kapan record itu muncul dalam investigasi.

| Record | Isi | Contoh pemakaian |
|---|---|---|
| A | IPv4 address sebuah nama [S13] | `www.jab.example` ke `198.51.100.10` |
| AAAA | IPv6 address sebuah nama [S14] | `www.jab.example` ke `2001:db8:64:1::10` |
| CNAME | Nama alias yang menunjuk nama lain [S13] | `portal.jab.example` adalah alias `www.jab.example` |
| MX | Server penerima email untuk sebuah domain, dengan angka prioritas (lebih kecil lebih diutamakan) [S13] | Email ke `@jab.example` dikirim ke `mail.jab.example` |
| TXT | Teks bebas [S13] | Kebijakan email (SPF, Day 09) dan verifikasi kepemilikan domain |
| PTR | Nama untuk sebuah IP, kebalikan dari A [S13] | `198.51.100.10` dinamai `www.jab.example` |

**Contoh di PT JAB:** log resolver mencatat `client=10.10.4.27 query=docs.vendorapp.example type=A answer=192.0.2.80`. Urutan "query DNS lalu sambungan" ini normal: browser tidak bisa menghubungi nama, ia butuh angka. Bila suatu hari kamu melihat sambungan ke IP tanpa query DNS sebelumnya, itu juga petunjuk: program bisa saja membawa IP tujuan yang sudah ditanam di dalamnya.

**Beda dengan IP address:** domain adalah nama, IP adalah alamat. Satu domain bisa menunjuk ke banyak IP, dan satu IP (misalnya server hosting bersama) bisa melayani banyak domain.

Kenapa ini penting untuk security: DNS hampir selalu diizinkan, bahkan di jaringan yang ketat, sehingga penyerang memakainya sebagai saluran komunikasi tersembunyi. Perintah dan data diselipkan di dalam pertanyaan dan jawaban DNS, teknik yang disebut DNS tunneling [S28]. Tandanya di log biasanya berupa banyak query ke subdomain panjang yang tampak acak di bawah satu domain. Log resolver juga menjadi salah satu sumber paling berharga di SOC, karena hampir setiap aktivitas jaringan diawali query DNS.

### 1.10 HTTP vs HTTPS

Pertanyaan kedelapan Sari: firewall tahu laptopmu menuju `docs.vendorapp.example`, tetapi apakah tahu halaman mana yang kamu baca? Jawabannya bergantung pada HTTP atau HTTPS.

**Apa itu:** HTTP (Hypertext Transfer Protocol) adalah protokol yang dipakai browser dan server web untuk bertukar halaman, file, dan data. HTTPS adalah HTTP yang dikirim di dalam sambungan TLS (Transport Layer Security), lapisan enkripsi yang dibahas di Day 05 [S21]. Port bawaan HTTP adalah TCP 80, dan port bawaan HTTPS adalah TCP 443 [S20]. Untuk alamat `https`, klien wajib memastikan permintaannya diamankan sebelum dikirim dan wajib memeriksa identitas server dari sertifikatnya, semacam kartu identitas digital server yang juga dibahas di Day 05 [S20].

**Analogi:** HTTP seperti kartu pos: siapa pun yang memegangnya di jalan bisa membaca tulisannya. HTTPS seperti surat dalam amplop tersegel: isinya tertutup, tetapi nama dan alamat penerima tetap tertulis di luar amplop. Batasnya: amplop tersegel hanya menjamin isi tidak dibaca dan tidak diubah di jalan. Amplop itu tidak menjamin pengirim atau penerimanya orang baik.

**Cara kerja:** permintaan HTTP berisi metode (`GET` untuk mengambil, `POST` untuk mengirim data), path halaman, header seperti `Host` dan `User-Agent`, lalu server membalas dengan kode status (`200` berhasil, `404` tidak ditemukan) dan isi halaman [S20]. Pada HTTPS, semua itu dienkripsi. Yang tetap terlihat oleh firewall di jalan adalah IP dan port tujuan, jumlah byte, waktu, dan biasanya nama situs, karena browser menyebut nama situs di pesan pembuka TLS (SNI) yang masih terkirim tanpa enkripsi [S22].

**Contoh di PT JAB:** sambungan laptopmu memakai port 443, jadi `jkt-fw01` hanya tahu kamu menuju `docs.vendorapp.example` dan mengunduh sekitar 52 KB. Path halaman, isi dokumen, dan password yang mungkin kamu ketik tidak terlihat. Seandainya situs itu memakai HTTP di port 80, path lengkap, parameter, dan isi form terbaca oleh siapa pun yang berada di jalur yang sama.

**Beda dengan "situs aman":** HTTPS melindungi perjalanan data, bukan menilai pemilik situs. Situs phishing (situs palsu yang meniru situs asli untuk mencuri data) pun bisa memakai HTTPS dengan sertifikat yang sah.

Kenapa ini penting untuk security: perpindahan web ke HTTPS membuat penyerang di jalur tidak bisa menyadap isi, tetapi juga membuat alat security di jaringan tidak bisa melihat isi. Analyst harus tahu apa yang masih bisa dibaca (IP, port, SNI, volume, waktu) dan apa yang hanya bisa didapat dari log server atau endpoint. Layanan internal yang masih memakai HTTP, Telnet, atau FTP mengirim password dalam bentuk yang bisa dibaca, dan menjadi sasaran empuk penyadapan seperti ARP spoofing (bagian 1.5).

### 1.11 NAT

Bagian ini menjawab inti pertanyaan kedua Sari: kenapa `10.10.4.27` menjadi `198.51.100.120`?

**Apa itu:** NAT (Network Address Translation) adalah penerjemahan alamat IP di batas jaringan, biasanya dari alamat privat ke alamat publik. Bentuk yang paling umum, NAPT (Network Address Port Translation), menerjemahkan pasangan IP privat dan port menjadi satu IP publik dengan port yang berbeda-beda, sehingga banyak perangkat bisa berbagi satu alamat publik sekaligus [S19].

**Analogi:** resepsionis kantor yang memakai satu nomor telepon untuk semua karyawan. Dari luar, setiap telepon keluar terlihat datang dari nomor kantor. Resepsionis mencatat siapa menelepon siapa, sehingga saat ada telepon balik, ia tahu harus menyambungkan ke meja mana. Batasnya: dari luar semua terlihat dari satu alamat, dan tanpa catatan resepsionis tidak ada yang bisa tahu karyawan mana yang menelepon.

**Cara kerja:** saat paket dari `10.10.4.27:52814` keluar, `jkt-fw01` mengganti alamat asal menjadi `198.51.100.120` dan port asal menjadi port yang belum terpakai, misalnya `61027`, lalu mencatat pasangan itu di tabel NAT. Saat balasan datang ke `198.51.100.120:61027`, firewall melihat tabel dan meneruskannya ke `10.10.4.27:52814`.

```
 Jaringan dalam (privat)             jkt-fw01 (NAT)                    Internet
 10.10.4.27:52814  ------------>  asal diganti  ------------------>  192.0.2.80:443
                                  198.51.100.120:61027
 10.10.7.91:50233  ------------>  198.51.100.120:61028  ---------->  192.0.2.80:443

 Tabel NAT di jkt-fw01 (disederhanakan):
 alamat dalam        alamat luar             tujuan
 10.10.4.27:52814    198.51.100.120:61027    192.0.2.80:443
 10.10.7.91:50233    198.51.100.120:61028    192.0.2.80:443
```

Sambungan dari luar ke dalam tidak bisa dibuat tanpa aturan khusus yang memetakan alamat publik ke perangkat tertentu [S19]. Server yang memang dibuka ke internet, seperti `198.51.100.35`, punya pemetaan semacam itu.

**Contoh di PT JAB:** ratusan laptop kantor Jakarta keluar ke internet dari `198.51.100.120`. Di log server tujuan, kamu dan rekan sebelahmu terlihat sebagai alamat yang sama. Di log `jkt-fw01`, kolom `nat_src` dan `nat_spt` menyimpan pasangan publik itu, sedangkan `src` dan `spt` menyimpan alamat asli.

**Beda dengan firewall:** NAT menerjemahkan alamat; firewall memutuskan boleh atau tidak. Keduanya sering berada di perangkat yang sama, tetapi fungsinya berbeda. RFC 3022 menyebut NAT bisa dipandang memberi privasi, tetapi tidak menyebutnya mekanisme keamanan, dan justru mencatat bahwa NAT menyulitkan penelusuran penyalahgunaan [S19].

**Salah paham umum:**
- "Kalau ada laporan abuse untuk `198.51.100.120`, pelakunya satu orang di kantor Jakarta yang bisa langsung ditunjuk." Alamat itu dipakai bersama semua laptop kantor Jakarta. Untuk menemukan perangkatnya, kamu butuh log NAT dengan IP publik, port publik, dan waktu yang tepat, lalu log DHCP untuk tahu laptop mana yang memakai IP privat itu saat itu.

Kenapa ini penting untuk security: NAT membuat satu IP di log menunjuk banyak user. Tanpa log NAT yang disimpan cukup lama dan jam yang sinkron antar perangkat, laporan "IP kalian menyerang kami pukul 10:05" tidak bisa ditelusuri sampai ke laptop yang benar.

### 1.12 Port scan

Pertanyaan terakhir Sari: port scan muncul hampir setiap hari, jadi kenapa `SOC-2027-0810` diangkat?

**Apa itu:** port scan adalah memakai program untuk memeriksa dari jauh port mana yang terbuka di sebuah sistem [S25]. Hasilnya memperlihatkan layanan apa yang menerima sambungan, dan layanan mana yang mungkin bisa diserang. MITRE ATT&CK, katalog teknik penyerang yang dibahas di Day 14, mencatat kegiatan ini sebagai Network Service Discovery (T1046) [S26].

**Analogi:** orang yang berjalan menyusuri gedung dan mengetuk setiap pintu, mencatat pintu mana yang dibuka dari dalam. Mengetuk belum masuk, tetapi daftar pintu yang terbuka adalah bahan untuk langkah berikutnya. Batasnya: di internet pengetukan ini terjadi terus-menerus oleh banyak pihak, termasuk peneliti dan layanan pemindai yang tidak berniat jahat, sehingga ketukan saja jarang cukup untuk disebut serangan.

**Cara kerja:** cara yang paling umum adalah SYN scan. Scanner mengirim SYN ke setiap pasangan IP dan port, lalu membaca balasannya. Tabel berikut adalah kunci membaca hasilnya; cari kolom "Kesimpulan scanner".

| Balasan atas SYN | Kesimpulan scanner | Dasar |
|---|---|---|
| SYN-ACK | Port terbuka, ada layanan yang menunggu | Langkah 2 handshake (bagian 1.7) [S1] |
| RST | Port tertutup, perangkat hidup tetapi tidak ada layanan | Perangkat membalas RST bila tidak ada sambungan yang cocok [S1] |
| Tidak ada balasan | Difilter, biasanya oleh firewall yang membuang paket diam-diam | Penolakan tanpa balasan |

Setelah menerima SYN-ACK, scanner langsung mengirim RST tanpa menyelesaikan handshake, sehingga di log terlihat banyak SYN tanpa ACK penutup. Untuk UDP, port tertutup biasanya dijawab ICMP port unreachable (bagian 1.8).

```
 port terbuka :  scanner --SYN-->  server   server --SYN-ACK-->  scanner   scanner --RST--> server
 port tertutup:  scanner --SYN-->  server   server --RST------>  scanner
 difilter     :  scanner --SYN-->  jkt-fw01 (dibuang, tanpa balasan)
```

**Contoh di PT JAB:** `192.0.2.45` mengirim 5.080 SYN ke 254 alamat di `198.51.100.0/24`, masing-masing ke 20 port (254 kali 20 sama dengan 5.080). Lima SYN diizinkan ke layanan yang memang dibuka (web, email, DNS), dan satu SYN lagi ke `198.51.100.35:3389` juga lolos dan dibalas SYN-ACK. Server itu adalah `jkt-dmz-test01`, server uji coba aplikasi vendor yang port RDP-nya dibuka sementara bulan lalu dan lupa ditutup. Scan-nya sendiri rutin; yang membuat Sari mengangkat alert ini adalah layanan yang tidak seharusnya terlihat dari internet. Rincian lengkapnya ada di bagian 2.2.

**Beda dengan serangan:** port scan adalah pengintaian. Belum ada login, belum ada exploit. Yang membuat sebuah scan penting adalah apa yang ditemukannya dan apa yang terjadi sesudahnya, misalnya percobaan login berulang ke port yang ditemukan terbuka.

Kenapa ini penting untuk security: scanner penyerang dan scanner milik sendiri melihat hal yang sama. Alert port scan dari luar memberi tahu bahwa ada yang memetakan attack surface PT JAB, dan hasil scan itu bisa dipakai SOC untuk memeriksa apakah ada pintu yang terbuka tanpa sengaja. Banyak SOC menurunkan prioritas alert scan biasa dan menaikkannya bila scan menemukan layanan sensitif atau diikuti aktivitas lain dari IP yang sama.

## 2. Contoh nyata

Semua log, alert, dan jawaban di bagian ini adalah keluaran ilustrasi untuk organisasi fiktif PT JAB, bukan hasil eksekusi nyata. Formatnya disederhanakan; nama field di produk sungguhan bisa berbeda.

### 2.1 Membaca satu baris log firewall

Ini baris yang dibuka Sari di awal Ide inti: sambungan laptopmu `JKT-WS-0815` pagi tadi, diawali query DNS sedetik sebelumnya.

```
2027-08-03T08:14:21.402+07:00 jkt-res01 client=10.10.4.27 query=docs.vendorapp.example type=A rcode=NOERROR answer=192.0.2.80 ttl=300

2027-08-03T08:14:22+07:00 jkt-fw01 action=allow rule=OUT-WEB proto=tcp src=10.10.4.27 spt=52814 dst=192.0.2.80 dpt=443 nat_src=198.51.100.120 nat_spt=61027 bytes_sent=1840 bytes_rcvd=52310 duration=12
```

Tabel berikut membaca baris firewall kolom demi kolom; kolom ketiga menunjuk subbagian yang menjelaskan istilahnya.

| Kolom | Nilai | Artinya | Bagian |
|---|---|---|---|
| waktu | `2027-08-03T08:14:22+07:00` | Waktu sambungan dibuka, zona WIB (UTC+7) | |
| perangkat | `jkt-fw01` | Firewall perimeter Jakarta yang menulis log | 1.1 |
| `action` | `allow` | Sambungan diizinkan | 1.1 |
| `rule` | `OUT-WEB` | Nama aturan yang cocok, di sini aturan web keluar | 1.1 |
| `proto` | `tcp` | Protokol transport | 1.7 |
| `src`, `spt` | `10.10.4.27`, `52814` | IP privat laptop dan port ephemeral-nya | 1.3, 1.6 |
| `dst`, `dpt` | `192.0.2.80`, `443` | IP publik server tujuan dan port HTTPS | 1.3, 1.6 |
| `nat_src`, `nat_spt` | `198.51.100.120`, `61027` | Alamat dan port setelah NAT, yang dilihat server tujuan | 1.11 |
| `bytes_sent`, `bytes_rcvd` | `1840`, `52310` | Laptop mengirim sekitar 1,8 KB dan menerima sekitar 52 KB | 1.10 |
| `duration` | `12` | Sambungan berlangsung 12 detik | |

**Cara membaca:** laptop privat Jakarta membuka sambungan TCP ke layanan HTTPS di internet, diizinkan aturan web keluar, keluar dengan alamat NAT kantor, dan mengunduh jauh lebih banyak daripada yang diunggah, pola wajar untuk membaca halaman. Baris DNS di atasnya menjelaskan dari mana laptop tahu alamat `192.0.2.80`: dari jawaban `jkt-res01` sedetik sebelumnya, dengan TTL 300 detik (5 menit).

**Yang tidak ada di baris ini:** MAC address laptop (bagian 1.5), path halaman dan isinya (bagian 1.10), dan nama user. Untuk tahu siapa yang memakai laptop, dibutuhkan log lain seperti log login atau log DHCP.

### 2.2 Membaca alert port scan `SOC-2027-0810`

Ini alert kedua yang dibuka Sari. Ringkasannya dibuat dari log `jkt-fw01` antara pukul 02:12 dan 02:17 dini hari.

```
Alert        : SOC-2027-0810  Possible external port scan
Waktu        : 2027-08-03 02:12:50 s.d. 02:17:05 WIB
Sumber       : 192.0.2.45
Tujuan       : 198.51.100.1 - 198.51.100.254 (254 alamat)
Tahap 1 ICMP : 254 Echo request (type 8), semua ditolak, 0 Echo Reply
Tahap 2 TCP  : 5.080 SYN = 254 alamat x 20 port
               (termasuk 21, 22, 23, 25, 53, 80, 443, 445, 1433, 3306, 3389)
Diizinkan    : 6     Ditolak (dibuang tanpa balasan): 5.074
SYN-ACK dari target  : 6
  198.51.100.10:80, 198.51.100.10:443   (www.jab.example)
  198.51.100.11:25, 198.51.100.11:443   (mail.jab.example)
  198.51.100.12:53                      (ns1.jab.example)
  198.51.100.35:3389                    (jkt-dmz-test01)  <-- tidak ada di daftar layanan publik
ACK penutup dari sumber : 0   (sumber mengirim RST setelah setiap SYN-ACK)
```

**Cara membaca:** hitung dulu. 254 alamat kali 20 port sama dengan 5.080 SYN, dan 6 diizinkan ditambah 5.074 ditolak juga sama dengan 5.080, jadi angka alert konsisten. Tahap 1 adalah ping sweep yang gagal karena ICMP dari internet diblokir; tidak dibalas bukan berarti mati (bagian 1.8). Tahap 2 adalah SYN scan: tidak ada satu pun handshake yang diselesaikan, ciri scanner yang hanya mengintip (bagian 1.7 dan 1.12). Lima dari enam port yang terbuka cocok dengan daftar layanan publik PT JAB. Yang keenam, RDP di `198.51.100.35`, tidak.

**Keputusan:** scan dari luar tidak bisa dicegah dan tidak perlu dikejar ke sumbernya. Yang ditindaklanjuti adalah temuannya: Sari meminta tim infrastruktur (Agung Prabowo) menutup aturan yang membuka port 3389 ke `jkt-dmz-test01`, lalu meminta kamu memeriksa apakah ada percobaan login ke server itu sejak port dibuka. Bila ditemukan login yang berhasil dari luar, kasus ini naik dari alert menjadi insiden.

**Variasi yang perlu dikenali:** scan yang lambat (satu SYN per beberapa menit) sering lolos ambang alert; scan dari banyak IP sumber terlihat seperti banyak kejadian kecil; scan ke satu port di banyak alamat (misalnya 3389 saja) biasanya mencari satu jenis layanan untuk diserang massal.

### 2.3 Membaca jawaban DNS untuk `jab.example`

Saat orientasi, Sari juga menunjukkan isi DNS publik domain PT JAB, supaya kamu tahu jawaban normal sebelum melihat yang aneh.

```
www.jab.example.               3600  IN  A      198.51.100.10
www.jab.example.               3600  IN  AAAA   2001:db8:64:1::10
portal.jab.example.            3600  IN  CNAME  www.jab.example.
jab.example.                   3600  IN  MX     10 mail.jab.example.
mail.jab.example.              3600  IN  A      198.51.100.11
jab.example.                   3600  IN  TXT    "v=spf1 ip4:198.51.100.11 -all"
10.100.51.198.in-addr.arpa.    3600  IN  PTR    www.jab.example.
```

**Cara membaca:** setiap baris berisi nama, TTL (3600 detik atau 1 jam boleh disimpan di cache), kelas `IN` (internet), jenis record, dan isinya.

- `A` dan `AAAA`: situs `www.jab.example` bisa dijangkau lewat IPv4 `198.51.100.10` maupun IPv6 `2001:db8:64:1::10`. Alert yang menyebut salah satu alamat itu menunjuk server yang sama.
- `CNAME`: `portal.jab.example` hanyalah nama lain untuk `www.jab.example`; resolver mengikuti alias itu sampai menemukan record `A`.
- `MX`: email untuk `@jab.example` dikirim ke `mail.jab.example` dengan prioritas 10. Bila ada dua MX, yang angkanya lebih kecil dicoba lebih dulu [S13].
- `TXT`: teks bebas. Isi di sini adalah kebijakan SPF yang menyatakan server pengirim email sah untuk domain ini; artinya dibahas di Day 09.
- `PTR`: kebalikan `A`. Nama record ditulis dengan urutan angka IP dibalik di bawah `in-addr.arpa`, jadi `198.51.100.10` menjadi `10.100.51.198.in-addr.arpa`. Di alert, nama PTR membantu memberi petunjuk siapa pemilik sebuah IP, tetapi pemilik IP bebas mengisinya, jadi jangan dijadikan bukti.

**Contoh yang tidak normal:** bila log resolver mencatat ratusan query dari satu laptop ke nama seperti `q7x2k9a1m3.c4b8.data-sync.example`, dengan subdomain berbeda setiap kali, itu pola yang perlu dieskalasi: kemungkinan data diselipkan di nama subdomain (bagian 1.9).

### 2.4 HTTP vs HTTPS: apa yang terlihat di log

Untuk menjawab pertanyaan kedelapan Sari, bandingkan dua kunjungan ke server yang sama, sekali lewat HTTP dan sekali lewat HTTPS, seperti yang tercatat oleh perangkat yang hanya berada di jalur jaringan.

```
# Kunjungan lewat HTTP (port 80): permintaan terbaca utuh
src=10.10.4.27 dst=192.0.2.80 dpt=80 proto=tcp
  GET /katalog/harga?produk=router-x HTTP/1.1
  Host: promo.vendorapp.example
  User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)
  Status: 200   Bytes: 18244

# Kunjungan lewat HTTPS (port 443): hanya label yang terbaca
src=10.10.4.27 dst=192.0.2.80 dpt=443 proto=tcp
  sni=docs.vendorapp.example   bytes_sent=1840   bytes_rcvd=52310
  (metode, path, header, isi, dan status: terenkripsi)
```

**Cara membaca:** pada HTTP, siapa pun di jalur yang sama bisa membaca path, parameter, jenis browser, dan isi halaman, termasuk password bila dikirim lewat form. Pada HTTPS, yang terbaca hanyalah IP, port, nama situs dari SNI, volume, dan waktu (bagian 1.10). Untuk tahu halaman apa yang dibuka lewat HTTPS, analyst mencarinya di log server web, di log endpoint, atau di perangkat yang memang diizinkan membuka enkripsi, yang dibahas di Day 03.

## 3. Perbandingan istilah yang sering tertukar

Tabel pertama membandingkan TCP dan UDP; cari baris "Ciri di log" karena itulah yang paling sering dipakai saat membaca alert.

| Aspek | TCP | UDP |
|---|---|---|
| Sambungan | Dibuka dulu dengan three-way handshake | Tanpa sambungan, langsung kirim |
| Jaminan sampai | Ada tanda terima dan kirim ulang | Tidak dijamin [S2] |
| Urutan data | Dijaga dengan nomor urut | Tidak dijaga |
| Header | Besar, banyak field dan flag | Kecil, empat field [S2] |
| Contoh pemakaian | Web (HTTP/1.1, HTTP/2), SSH, SMTP, RDP | DNS, HTTP/3, streaming, VoIP |
| Ciri di log | Ada flag SYN/ACK/FIN/RST, status sambungan, durasi | Hanya alamat, port, dan volume |
| Pemalsuan alamat asal | Sulit setelah handshake selesai | Lebih mudah karena tidak ada balasan yang harus diterima |

Tabel kedua membedakan tiga "alamat" yang sering tertukar; cari kolom "Berlaku di" untuk tahu di log mana masing-masing muncul.

| Aspek | IP address | MAC address | Port |
|---|---|---|---|
| Menunjuk | Perangkat (antarmuka jaringan) | Kartu jaringan | Layanan di perangkat |
| Lapisan OSI | 3 (Network) | 2 (Data Link) | 4 (Transport) |
| Berlaku di | Dari ujung ke ujung, lintas jaringan | Satu jaringan lokal saja | Di dalam satu perangkat |
| Contoh | `10.10.4.27`, `198.51.100.120` | `3c:52:82:1a:7e:04` | `443`, `52814` |
| Analogi | Alamat rumah | Nomor rangka kendaraan | Nomor loket atau ruangan |
| Bisa berubah | Ya (DHCP, NAT) | Bisa dipalsukan lewat perangkat lunak | Port klien berganti tiap sambungan |
| Muncul di log | Firewall, DNS, web, hampir semua | Switch, DHCP, Wi-Fi | Firewall, IDS, log sambungan |

Tabel ketiga membandingkan HTTP dan HTTPS dari sudut pandang analyst; cari baris "Terlihat oleh perangkat di jalur".

| Aspek | HTTP | HTTPS |
|---|---|---|
| Port bawaan | TCP 80 [S20] | TCP 443 [S20] |
| Enkripsi | Tidak ada | TLS |
| Terlihat oleh perangkat di jalur | Semua: path, header, isi, password | IP, port, SNI, volume, waktu |
| Melindungi dari | Tidak ada | Penyadapan dan perubahan isi di jalan |
| Tidak melindungi dari | Apa pun | Situs palsu, malware yang diunduh lewat HTTPS, server yang jahat |

Tabel keempat membandingkan IP publik dan IP privat; cari baris "Langkah investigasi" karena di situ bedanya terasa di pekerjaan.

| Aspek | IP publik | IP privat |
|---|---|---|
| Berlaku di | Seluruh internet | Di dalam satu organisasi |
| Rentang IPv4 | Semua di luar rentang khusus | `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` [S6] |
| Bisa dihubungi dari internet | Ya, bila tidak diblokir | Tidak langsung, perlu NAT atau aturan khusus |
| Unik | Ya, di seluruh dunia | Hanya di dalam organisasi; dipakai ulang di mana-mana |
| Contoh di PT JAB | `198.51.100.120`, `192.0.2.45` | `10.10.4.27`, `10.20.x.x` |
| Langkah investigasi | Cari pemilik dan reputasi di luar | Cari perangkat di inventaris, DHCP, dan log NAT internal |

Model OSI dan TCP/IP sudah dibandingkan di tabel bagian 1.2.

## 4. Salah paham umum

Butir berikut adalah salah paham yang melintasi beberapa istilah sekaligus. Salah paham yang khusus satu istilah sudah ditulis di subbagiannya.

- **Anggapan:** situs yang memakai HTTPS (ikon gembok) adalah situs aman. **Kenyataannya:** HTTPS hanya menjamin sambungan terenkripsi dan bahwa server memegang sertifikat untuk nama itu. Situs phishing dan situs penyebar malware juga bisa memakai HTTPS (bagian 1.10).
- **Anggapan:** bila ping tidak dibalas dan port yang dicoba tertutup, perangkatnya mati atau tidak ada. **Kenyataannya:** firewall sering membuang ICMP dan SYN tanpa balasan. Di `SOC-2027-0810`, semua ping gagal, tetapi empat server hidup dan satu membuka RDP (bagian 1.8 dan 2.2).
- **Anggapan:** satu IP di log selalu menunjuk satu orang atau satu perangkat. **Kenyataannya:** NAT membuat ribuan perangkat terlihat dari satu IP, DHCP membuat satu IP berpindah pemilik dari hari ke hari, dan alamat asal bisa dipalsukan untuk lalu lintas tanpa handshake (bagian 1.1, 1.3, dan 1.11).
- **Anggapan:** nomor port memberi tahu aplikasi apa yang berjalan. **Kenyataannya:** port hanya kebiasaan. SSH bisa dipasang di 443, dan malware memakai 443 atau 53 justru karena port itu hampir selalu diizinkan [S16].
- **Anggapan:** UDP tidak penting untuk security karena "tidak bisa diandalkan". **Kenyataannya:** DNS, HTTP/3, dan banyak layanan penting berjalan di atas UDP, dan banyak serangan memanfaatkan UDP karena alamat asalnya mudah dipalsukan (Day 04 membahas serangan semacam ini).
- **Anggapan:** port scan berarti sistem sudah diretas. **Kenyataannya:** port scan adalah pengintaian. Yang menentukan tingkat bahaya adalah layanan apa yang ditemukan dan apakah ada aktivitas lanjutan (bagian 1.12).
- **Anggapan:** IPv6 belum dipakai, jadi alert yang memuat IPv6 bisa diabaikan. **Kenyataannya:** sebagian besar perangkat modern sudah mendukung IPv6, dan pengukuran Google mencatat lebih dari separuh akses ke layanannya sudah memakai IPv6 pada Maret 2026 [S30]. Aturan firewall yang hanya ditulis untuk IPv4 bisa meninggalkan pintu terbuka di IPv6.
- **Anggapan:** alamat privat dan NAT membuat jaringan internal tidak bisa diserang dari luar. **Kenyataannya:** penyerang jarang masuk langsung ke alamat privat. Mereka masuk lewat layanan yang dibuka ke internet atau lewat laptop yang membuka sambungan keluar, misalnya setelah user membuka lampiran berbahaya (bagian 1.3 dan 1.11).

## 5. Catatan terkini

Bagian ini mencatat perubahan standar dan tren yang memengaruhi apa yang terlihat di log, tanpa mengubah konsep di atas.

- **RFC 9293 (Agustus 2022)** menggantikan RFC 793 sebagai spesifikasi TCP. Isinya merangkum perbaikan yang terkumpul sejak 1981; konsep handshake dan flag tidak berubah [S1]. Dokumen lama yang masih merujuk RFC 793 tetap benar untuk konsep dasar.
- **HTTP/3 (RFC 9114, Juni 2022)** berjalan di atas QUIC, yang memakai UDP, bukan TCP [S23]. Akibatnya lalu lintas web tidak lagi hanya TCP 443; di praktik HTTP/3 biasanya memakai UDP 443, walaupun RFC 9114 mengizinkan port UDP mana pun [S23]. Registry IANA mencatat `https` di 443 untuk TCP dan UDP [S15]. Aturan firewall dan pemantauan yang hanya memperhatikan TCP 443 melewatkan sebagian lalu lintas web.
- **RFC 9110 (Juni 2022)** menyatukan definisi makna HTTP (metode, status, header) untuk semua versi HTTP [S20].
- **DNS over HTTPS (DoH, RFC 8484, Oktober 2018)** mengirim query DNS di dalam HTTPS. RFC itu sendiri menyebut sistem penyaringan atau inspeksi yang mengandalkan DNS tanpa enkripsi tidak akan berfungsi [S24]. Bagi SOC, browser atau malware yang memakai DoH ke penyedia luar melewati resolver internal, sehingga query-nya tidak tercatat di log `jkt-res01`. Cek kebijakan browser dan resolver di organisasimu untuk tahu apakah DoH ke luar diizinkan.
- **SNI masih terkirim tanpa enkripsi** pada sambungan TLS biasa [S22], sehingga nama situs tujuan masih bisa dicatat firewall. RFC 8744 (Juli 2020) membahas kebutuhan untuk mengenkripsi SNI; bila mekanisme itu dipakai luas, nama situs di log jaringan juga akan hilang. Cek dukungan browser dan perangkat di lingkunganmu.
- **IPv6:** Internet Society Pulse (21 April 2026) melaporkan akses IPv6 ke layanan Google pertama kali melewati 50%, yaitu 50,10% pada 28 Maret 2026 [S30]. Angka ini hanya mengukur akses ke Google dan sangat bervariasi antar negara, jadi cek data negara dan jaringanmu sendiri.

## 6. Cheat sheet

```
PAKET      header (label: alamat, port, flag) + payload (isi); alamat asal bisa dipalsukan
PROTOKOL   aturan baku cara bicara (IP, TCP, UDP, ICMP, DNS, HTTP)
OSI        7 App | 6 Presentation | 5 Session | 4 Transport | 3 Network | 2 Data Link | 1 Physical
TCP/IP     Application (OSI 5-7) | Transport | Internet | Link (OSI 1-2)
IPv4       32 bit, 4 angka 0-255 (10.10.4.27); total 4.294.967.296 alamat
IPv6       128 bit, heksadesimal dengan titik dua (2001:db8:64:1::10); "::" sekali per alamat
PRIVAT     10.0.0.0/8 | 172.16.0.0/12 | 192.168.0.0/16 (RFC 1918)
DOKUMENTASI 192.0.2.0/24 | 198.51.100.0/24 | 203.0.113.0/24 | 2001:db8::/32
CIDR       /n -> 2^(32-n) alamat; /24 = 256 (254 host) | /16 = 65.536 (65.534 host)
MAC        48 bit, lapisan 2, hanya di jaringan lokal; tidak sampai ke log firewall perimeter
ARP        IP -> MAC di jaringan lokal; tanpa autentikasi -> ARP spoofing
PORT       0-1023 well known | 1024-49151 registered | 49152-65535 ephemeral
TCP        sambungan + urutan + kirim ulang; handshake SYN -> SYN-ACK -> ACK; tutup FIN/RST
UDP        tanpa sambungan, tanpa jaminan; 4 field header; dipakai DNS, HTTP/3
ICMP       tanpa port; 8 echo | 0 echo reply | 3 unreachable (code 3 = port) | 11 time exceeded
DNS        nama -> IP; resolver rekursif; UDP/TCP 53; TTL = batas cache
RECORD     A (IPv4) | AAAA (IPv6) | CNAME (alias) | MX (server email) | TXT (teks) | PTR (IP -> nama)
HTTP       TCP 80, tanpa enkripsi, isi terbaca
HTTPS      TCP 443 (HTTP/3: UDP), TLS; terlihat: IP, port, SNI, volume, waktu
NAT        privat -> publik; banyak perangkat satu IP; telusuri dengan log NAT + DHCP + waktu tepat
PORT SCAN  SYN-ACK = terbuka | RST = tertutup | tanpa balasan = difilter; SYN tanpa ACK penutup
FIREWALL   penjaga gerbang: cek alamat dan port, allow atau deny (Day 03)

PORT UMUM
20/21 FTP     22 SSH        23 Telnet      25 SMTP       53 DNS
80 HTTP       110 POP3      143 IMAP       443 HTTPS     445 SMB
1433 MSSQL    3306 MySQL    3389 RDP       49152-65535 ephemeral
Jangan terbuka ke internet: 23, 445, 1433, 3306, 3389
```

## 7. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "Firewall menolak semua ping dari internet ke rentang `198.51.100.0/24`, jadi server di rentang itu tidak terlihat dari internet." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Memblokir ping hanya menyembunyikan jawaban ICMP Echo. Scanner yang mengirim SYN ke port tertentu tetap mendapat SYN-ACK dari layanan yang diizinkan firewall. Di `SOC-2027-0810`, semua 254 ping gagal, tetapi enam port tetap menjawab, termasuk RDP di `198.51.100.35`. Lihat bagian 1.8 dan 2.2.

</details>

**2. Skenario keputusan.** Sebuah organisasi luar mengirim email: "IP `198.51.100.120` milik kalian mencoba login ke server kami 40 kali pukul 10:05:33 WIB tadi." Langkah pertama mana yang paling tepat?

- A. Blokir `198.51.100.120` di firewall supaya serangan berhenti.
- B. Minta detail waktu dan port asal dari pelapor, lalu cari di log NAT `jkt-fw01` pasangan alamat publik, port publik, dan waktu itu untuk menemukan IP privat, kemudian cocokkan dengan log DHCP untuk menemukan laptopnya.
- C. Balas bahwa IP itu milik server web PT JAB, jadi pasti salah lapor.

<details><summary>Jawaban</summary>

B. `198.51.100.120` adalah alamat NAT yang dipakai bersama semua laptop kantor Jakarta, jadi pelakunya hanya bisa ditemukan lewat log NAT dengan waktu dan port yang tepat, lalu log DHCP. A keliru karena memblokir alamat itu memutus internet seluruh kantor Jakarta tanpa menemukan sumbernya. C keliru karena alamat itu bukan server web (`www.jab.example` ada di `198.51.100.10`) dan menutup laporan tanpa memeriksa. Lihat bagian 1.11.

</details>

**3. Pertanyaan jebakan.** "Laptop `JKT-WS-0815` hanya membuat sambungan ke port 443, dan semua situs yang dibukanya memakai HTTPS. Jadi laptop itu bersih." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Nomor port hanya kebiasaan, dan penyerang sengaja memakai 443 karena hampir selalu diizinkan keluar. HTTPS juga hanya menjamin sambungannya terenkripsi, bukan bahwa situs atau server tujuannya baik; malware bisa diunduh dan dikendalikan lewat HTTPS. Untuk menilai, analyst melihat tujuan (IP, SNI), volume, waktu, dan log endpoint. Lihat bagian 1.6, 1.10, dan 4.

</details>

**4. Skenario keputusan.** Log `jkt-res01` menunjukkan satu laptop mengirim sekitar 3.000 query DNS per jam ke nama seperti `a91k3x7q2m.data-sync.example`, dengan subdomain berbeda di setiap query. Apa langkah yang paling tepat?

- A. Abaikan, karena DNS adalah lalu lintas normal dan selalu diizinkan.
- B. Perlakukan sebagai kemungkinan DNS dipakai sebagai saluran tersembunyi, catat laptop, domain, dan rentang waktunya, lalu eskalasi ke L2.
- C. Matikan `jkt-res01` supaya query berhenti.

<details><summary>Jawaban</summary>

B. Banyak query ke subdomain panjang yang tampak acak di bawah satu domain adalah pola DNS tunneling, cara menyelipkan perintah atau data di dalam DNS. A keliru justru karena DNS selalu diizinkan, penyerang memakainya. C keliru karena mematikan resolver memutus akses nama untuk semua perangkat tanpa menyelesaikan masalah di laptop itu. Lihat bagian 1.9 dan 2.3.

</details>

**5. Jelaskan ulang.** Jelaskan kepada anggota keluargamu yang bukan orang IT, dalam tiga kalimat, apa itu IP address, port, dan DNS.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "IP address itu seperti alamat rumah untuk komputer atau HP, supaya data di internet tahu harus diantar ke mana. Port itu seperti nomor loket di gedung tujuan, karena satu komputer bisa melayani banyak hal sekaligus, misalnya web di loket 443 dan email di loket 25. DNS itu seperti kontak di HP: kamu cukup ingat nama situsnya, lalu DNS mencarikan alamat angkanya."

Kesalahan yang sering muncul:
- Memakai istilah teknis lain untuk menjelaskan (misalnya "port adalah endpoint di lapisan transport"), sehingga pendengar tetap bingung.
- Menyamakan IP dengan identitas orang, padahal satu IP bisa dipakai banyak orang lewat NAT.
- Lupa menyebut kenapa DNS dibutuhkan: manusia mengingat nama, perangkat butuh angka.

</details>

**6. Pertanyaan jebakan.** "Subnet `10.10.4.0/24` cukup untuk 256 laptop, dan `10.10.0.0/16` cukup untuk 65.536 perangkat." Benarkah?

<details><summary>Jawaban</summary>

Tidak tepat. Blok `/24` memang berisi 256 alamat, tetapi alamat pertama (alamat jaringan) dan terakhir (broadcast) biasanya tidak dipakai perangkat, jadi yang bisa dipakai 254. Dengan cara yang sama, `/16` berisi 65.536 alamat dan 65.534 yang bisa dipakai perangkat. Rumusnya 2^(32 - n) alamat, dikurangi dua untuk perangkat. Lihat bagian 1.4.

</details>

**7. Interview question (English).** "Walk me through what happens on the network when a user types a website address into the browser and presses Enter. What can a security team see along the way?"

<details><summary>Sample answer</summary>

"First the laptop needs an IP address for the name, so it sends a DNS query, usually over UDP port 53, to the internal resolver, which resolves it recursively and returns an A or AAAA record. That query is already a useful log: the resolver records which internal host asked for which domain. Next the browser opens a TCP connection to the server on port 443 with the three-way handshake, SYN, SYN-ACK, ACK, from a random ephemeral source port. At the perimeter the firewall checks the rule, applies NAT so the private source address becomes the company's public address, and logs source, destination, ports, NAT mapping and bytes. Then TLS is negotiated and HTTP runs inside it, so on the network we can still see IPs, ports, the SNI server name, timing and volume, but not the URL path or content. For that we need server logs or endpoint telemetry. One caveat: with HTTP/3 the connection runs over QUIC on UDP instead of TCP, and if the browser uses DNS over HTTPS, the lookup may never reach our resolver logs."

What makes this answer strong: it follows the real order of events (DNS, handshake, firewall and NAT, TLS, HTTP), names the log produced at each step, states clearly what encryption hides from network monitoring, and shows awareness of current changes (HTTP/3 and DoH) that affect visibility.

</details>

## 8. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | RFC 9293: Transmission Control Protocol (TCP) | https://www.rfc-editor.org/rfc/rfc9293.html | primer (standar IETF, STD 7) | Agustus 2022; diakses 2026-10-20 | Tinggi. Handshake, delapan flag, RST untuk segmen tanpa sambungan; menggantikan RFC 793 |
| S2 | RFC 768: User Datagram Protocol | https://www.rfc-editor.org/rfc/rfc768.html | primer (standar IETF) | 28 Agustus 1980; diakses 2026-10-20 | Tinggi. Empat field header, pengiriman tidak dijamin |
| S3 | RFC 791: Internet Protocol | https://www.rfc-editor.org/rfc/rfc791.html | primer (standar IETF) | September 1981; diakses 2026-10-20 | Tinggi. Alamat 32 bit, field header, fungsi TTL |
| S4 | RFC 8200: Internet Protocol, Version 6 (IPv6) Specification | https://www.rfc-editor.org/rfc/rfc8200.html | primer (standar IETF, STD 86) | Juli 2017; diakses 2026-10-20 | Tinggi. Alamat 128 bit, Hop Limit |
| S5 | RFC 4291: IP Version 6 Addressing Architecture | https://www.rfc-editor.org/rfc/rfc4291.html | primer (standar IETF) | Februari 2006; diakses 2026-10-20 | Tinggi. Penulisan alamat, `::`, loopback, link-local |
| S6 | RFC 1918: Address Allocation for Private Internets | https://www.rfc-editor.org/rfc/rfc1918.html | primer (BCP 5) | Februari 1996; diakses 2026-10-20 | Tinggi. Tiga blok alamat privat |
| S7 | RFC 5737: IPv4 Address Blocks Reserved for Documentation | https://www.rfc-editor.org/rfc/rfc5737.html | primer (IETF) | Januari 2010; diakses 2026-10-20 | Tinggi. TEST-NET-1, -2, -3 |
| S8 | RFC 3849: IPv6 Address Prefix Reserved for Documentation | https://www.rfc-editor.org/rfc/rfc3849.html | primer (IETF) | Juli 2004; diakses 2026-10-20 | Tinggi. `2001:db8::/32` |
| S9 | RFC 4632: Classless Inter-domain Routing (CIDR) | https://www.rfc-editor.org/rfc/rfc4632.html | primer (BCP 122) | Agustus 2006; diakses 2026-10-20 | Tinggi. Notasi prefix, 2^(32-n) alamat, menggantikan kelas A/B/C |
| S10 | RFC 826: An Ethernet Address Resolution Protocol | https://www.rfc-editor.org/rfc/rfc826.html | primer (standar IETF) | November 1982; diakses 2026-10-20 | Tinggi. Request siaran, reply langsung, alamat 48 bit, tanpa autentikasi |
| S11 | RFC 792: Internet Control Message Protocol | https://www.rfc-editor.org/rfc/rfc792.html | primer (standar IETF) | September 1981; diakses 2026-10-20 | Tinggi. Nomor type dan code |
| S12 | RFC 1034: Domain Names, Concepts and Facilities | https://www.rfc-editor.org/rfc/rfc1034.html | primer (standar IETF) | November 1987; diakses 2026-10-20 | Tinggi. Komponen DNS, rekursif, stub resolver, TTL |
| S13 | RFC 1035: Domain Names, Implementation and Specification | https://www.rfc-editor.org/rfc/rfc1035.html | primer (standar IETF) | November 1987; diakses 2026-10-20 | Tinggi. Jenis record A, CNAME, PTR, MX, TXT; port 53 UDP dan TCP; prioritas MX |
| S14 | RFC 3596: DNS Extensions to Support IP Version 6 | https://www.rfc-editor.org/rfc/rfc3596.html | primer (standar IETF) | Oktober 2003; diakses 2026-10-20 | Tinggi. Record AAAA |
| S15 | IANA: Service Name and Transport Protocol Port Number Registry | https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml | primer (registry resmi) | pembaruan 2026-10-15; diakses 2026-10-20 | Tinggi. Rentang port dan nama layanan untuk semua port di tabel bagian 1.6 |
| S16 | RFC 6335: IANA Procedures for the Management of the Service Name and Transport Protocol Port Number Registry | https://www.rfc-editor.org/rfc/rfc6335.html | primer (BCP 165) | Agustus 2011; diakses 2026-10-20 | Tinggi. Rentang ephemeral; port tidak menjamin layanan |
| S17 | RFC 1122: Requirements for Internet Hosts, Communication Layers | https://www.rfc-editor.org/rfc/rfc1122.html | primer (standar IETF) | Oktober 1989; diakses 2026-10-20 | Tinggi. Empat lapisan TCP/IP dan perbandingan dengan OSI |
| S18 | Imperva Learning Center: What is OSI Model | https://www.imperva.com/learn/application-security/osi-model/ | sekunder (vendor) | diakses 2026-10-20 | Sedang. Tujuh lapisan OSI dan pemetaan ke TCP/IP |
| S19 | RFC 3022: Traditional IP Network Address Translator (Traditional NAT) | https://www.rfc-editor.org/rfc/rfc3022.html | primer (IETF, informational) | Januari 2001; diakses 2026-10-20 | Tinggi. Basic NAT, NAPT, catatan privasi dan penelusuran |
| S20 | RFC 9110: HTTP Semantics | https://www.rfc-editor.org/rfc/rfc9110.html | primer (standar IETF, STD 97) | Juni 2022; diakses 2026-10-20 | Tinggi. Skema http dan https, port 80 dan 443, kewajiban klien https |
| S21 | MDN Web Docs: HTTPS (glossary) | https://developer.mozilla.org/en-US/docs/Glossary/HTTPS | sekunder (dokumentasi Mozilla) | diakses 2026-10-20 | Sedang-tinggi. HTTPS sebagai HTTP terenkripsi TLS |
| S22 | RFC 8744: Issues and Requirements for Server Name Identification (SNI) Encryption in TLS | https://www.rfc-editor.org/rfc/rfc8744.html | primer (IETF, informational) | Juli 2020; diakses 2026-10-20 | Tinggi. SNI terkirim tanpa enkripsi di ClientHello |
| S23 | RFC 9114: HTTP/3 | https://www.rfc-editor.org/rfc/rfc9114.html | primer (standar IETF) | Juni 2022; diakses 2026-10-20 | Tinggi. HTTP/3 di atas QUIC dan UDP; port UDP bebas |
| S24 | RFC 8484: DNS Queries over HTTPS (DoH) | https://www.rfc-editor.org/rfc/rfc8484.html | primer (standar IETF) | Oktober 2018; diakses 2026-10-20 | Tinggi. Dampak ke sistem penyaringan dan inspeksi DNS |
| S25 | NIST CSRC Glossary: port scanning | https://csrc.nist.gov/glossary/term/port_scanning | primer (glosarium NIST, dari SP 800-82r3) | diakses 2026-10-20 | Tinggi. Definisi port scan |
| S26 | MITRE ATT&CK T1046: Network Service Discovery | https://attack.mitre.org/techniques/T1046/ | primer (basis pengetahuan MITRE) | versi 3.2, diubah 2026-05-12; diakses 2026-10-20 | Tinggi |
| S27 | MITRE ATT&CK T1557.002: ARP Cache Poisoning | https://attack.mitre.org/techniques/T1557/002/ | primer (basis pengetahuan MITRE) | versi 1.1, diubah 2025-10-24; diakses 2026-10-20 | Tinggi. ARP tanpa autentikasi, tujuan penyerang |
| S28 | MITRE ATT&CK T1071.004: Application Layer Protocol: DNS | https://attack.mitre.org/techniques/T1071/004/ | primer (basis pengetahuan MITRE) | versi 1.4, diubah 2026-09-03; diakses 2026-10-20 | Tinggi. DNS sebagai saluran C2, DNS tunneling |
| S29 | MITRE ATT&CK T1133: External Remote Services | https://attack.mitre.org/techniques/T1133/ | primer (basis pengetahuan MITRE) | versi 2.5, diubah 2026-05-12; diakses 2026-10-20 | Tinggi. Contoh prosedur kelompok penyerang memakai RDP yang terbuka ke internet |
| S30 | Internet Society Pulse: 18 years later, IPv6 reaches majority | https://pulse.internetsociety.org/en/blog/18-years-later-ipv6-reaches-majority/ | sekunder (blog Internet Society, data Google) | 2026-04-21; diakses 2026-10-20 | Sedang-tinggi. 50,10% pada 28 Maret 2026, hanya akses ke Google |

**Catatan sumber:** daftar tujuh lapisan OSI diambil dari sumber sekunder [S18]; standar OSI sendiri (ISO/IEC 7498-1) tidak diperiksa, sedangkan pemetaannya ke TCP/IP dikuatkan sebagian oleh RFC 1122 [S17]. Klaim bahwa HTTP/3 di praktiknya biasanya memakai UDP 443 didukung registry IANA [S15] tetapi RFC 9114 sendiri mengizinkan port UDP mana pun [S23]; cek di lingkunganmu. Fakta stabil yang tidak diberi rujukan tersendiri, seperti dua alamat cadangan per subnet (alamat jaringan dan broadcast), perubahan header lapisan 2 di setiap router, cara kerja `traceroute`, dan port tertutup UDP yang dijawab ICMP port unreachable, adalah pengetahuan dasar jaringan yang konsisten dengan RFC di atas. Angka IPv6 [S30] berasal dari pengukuran akses ke Google, bukan seluruh internet. Seluruh log, alert, record DNS, nama host, dan alamat di bagian 1 dan 2 adalah ilustrasi untuk organisasi fiktif PT JAB, bukan hasil eksekusi nyata.
