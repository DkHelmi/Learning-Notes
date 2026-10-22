---
day: 05
title: 'Anomali DNS dan HTTP: tunneling, DGA, fast flux, User-Agent mencurigakan, dan pola unduhan payload'
researched_on: 2026-10-22
versions_checked: 'Wireshark 4.6.9 (stabil; 4.4.19 old stable), display filter reference dns dan http untuk 4.6.9, tshark man page; Zeek 9.0.0 LTS (14 Sep 2026), dokumentasi master dns.log, http.log, files.log; MITRE ATT&CK v20: T1071.004 v1.4, T1568.001 v1.1, T1568.002 v1.2, T1071.001 v1.5, T1105 v2.6; RFC 1035; RFC 2308; RFC 9110; CISA AA25-093A Fast Flux (3 Apr 2025); kebijakan Microsoft Edge IntranetRedirectBehavior (Edge 88 ke atas, halaman diperbarui Juni 2026); Microsoft PE Format (Sep 2026)'
---

# Day 05: Anomali DNS dan HTTP (tunneling, DGA, fast flux, User-Agent, dan unduhan payload)

Cakupan: mengenali penyalahgunaan DNS dan HTTP (tunneling, DGA, fast flux, User-Agent aneh, POST berkala, unduhan payload) dari pcap, log resolver, dan log proxy, mengatribusikannya ke host yang benar, lalu memisahkannya dari layanan sah yang polanya mirip.

Catatan ruang lingkup: Day ini membahas penyalahgunaan DNS dan HTTP dari sisi forensik dan defensif. Tidak ada instruksi membangun tunnel, DGA, atau malware; semua dari sudut mendeteksi dan menafsirkan trafik. Data PT JAB fiktif, lab memakai trafik buatan sendiri, dan IOC di-defang saat dibagikan.

## Ide inti

DNS dan HTTP hampir selalu diizinkan keluar, sehingga penyerang memakainya untuk mengunduh payload, menghubungi C2, dan mengeluarkan data. Penyalahgunaan itu meninggalkan bentuk yang bisa diukur: bentuk nama (panjang, keacakan, tipe record), bentuk jawaban (NXDOMAIN, TTL, jumlah IP), bentuk header HTTP (User-Agent, Referer, Content-Type yang tidak cocok dengan isi), dan ritme (permintaan yang kembali dengan interval mirip). Masalahnya, setiap bentuk itu juga dihasilkan layanan sah: CDN memakai TTL rendah dan banyak IP, produk keamanan menyelipkan hash di subdomain, skrip otomasi memakai User-Agent non-browser dan POST berkala. Karena itu pekerjaan Day ini ada dua: mengukur bentuknya dengan angka, lalu menimbang konteks (siapa pemilik host, berapa host lain yang melakukan hal sama, sejak kapan tujuan itu terlihat, proses apa yang memanggilnya) sebelum memberi label jinak, perlu eskalasi, atau data tidak cukup.

Ada satu kesulitan yang khas jaringan kantor: sumber yang melihat isi belum tentu melihat siapa kliennya. Di jaringan dengan resolver internal dan proxy eksplisit, pcap di egress hanya melihat resolver dan proxy sebagai pengirim; log resolver tahu klien tetapi tidak tahu jawabannya; log proxy tahu klien dan URL tetapi tidak menyimpan isi file. Satu temuan biasanya baru utuh setelah dua atau tiga sumber dicocokkan lewat waktu dan nama.

Polanya sudah kamu kenal dari resolver pelanggan ISP. Lonjakan NXDOMAIN dari satu CPE biasanya berarti CPE itu kena bot atau salah konfigurasi, dan kamu membedakannya dari bentuk nama yang diminta: nama acak yang berganti tiap hari berbeda dengan nama perangkat lama yang terus dicari. User-Agent mirip `sysDescr` SNMP atau banner yang dilaporkan perangkat tentang dirinya sendiri: berguna, tetapi siapa pun bisa mengubahnya. Content-Type yang tidak cocok dengan isi file mirip deskripsi interface yang tertulis "uplink POP Bandung" padahal LLDP menunjukkan perangkat lain di ujungnya: yang benar adalah apa yang terlihat di kabel, bukan label. Batas analoginya: di resolver ISP satu CPE adalah satu rumah dan alamatnya terlihat langsung, sedangkan di kantor resolver dan proxy mewakili ratusan klien sehingga atribusi butuh log tambahan; dan penyerang, tidak seperti CPE rusak, sengaja meniru bentuk layanan sah.

```
 workstation (10.10.60.x)
   |                         \
   | query DNS                \ HTTP/HTTPS lewat proxy eksplisit
   v                           v
 resolver jkt-res01/02        proxy jkt-proxy01 (10.20.3.60:3128)
 index=dns: klien, nama,      index=proxy: klien, user, URL, metode,
 tipe; TANPA kode jawaban     status, Content-Type, UA, ukuran; TANPA isi
   |                           |
   | query rekursif            | koneksi ke server tujuan
   v                           v
 ======================== egress Jakarta (TAP) ========================
 jkt-pcap01 (uji coba sejak 2027-05-04, ring buffer target 72 jam)
 melihat: rcode, TTL, jawaban A/TXT, header dan isi HTTP polos
 TIDAK melihat: workstation mana yang bertanya (sumber = 10.20.2.53/.54
 untuk resolver, 10.20.3.60 untuk proxy; TAP di sisi dalam jkt-fw01)
   |
   v
 cocokkan waktu + nama/URL  ->  host  ->  konteks (pemilik, prevalence,
 first-seen, proses)  ->  label: jinak | eskalasi | data tidak cukup
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan sekitar 1.200 karyawan, kantor pusat dan data center di Jakarta, serta NOC 24/7 yang satu lantai dengan SOC. Kamu analyst L2 SOC dengan latar belakang tujuh tahun di NOC. Sejak Senin 2027-05-03, PT JAB menjalankan Program NSM (network security monitoring) sebagai percobaan Mei sampai Juli 2027. Sensor Zeek dan Suricata belum hidup (dijadwalkan 18 dan 19 Mei), jadi bukti jaringan minggu ini terbatas pada log resolver (`index=dns`), log proxy (`index=proxy`), firewall, flow NOC, dan ring buffer pcap `jkt-pcap01` (`10.20.70.13`) yang uji coba di egress Jakarta sejak Selasa 2027-05-04 dengan retensi target 72 jam. Analisis pcap dikerjakan di workstation `jkt-nsm-ws01` (`10.20.70.20`) yang punya akses read-only ke `jkt-pcap01`. TAP egress terpasang di sisi dalam firewall `jkt-fw01`, sebelum NAT, sehingga alamat internal resolver `jkt-res01` (`10.20.2.53`) dan `jkt-res02` (`10.20.2.54`) serta proxy `jkt-proxy01` (`10.20.3.60`) masih terlihat; setelah firewall, resolver keluar lewat alamat NAT `198.51.100.205` dan proxy lewat NAT kantor Jakarta `198.51.100.120`. Senin 2027-05-10 pukul 08:20, Sari Kusuma (analyst L2) menulis kepadamu:

> "Pagi. Di antrean ada lima tiket dari Jumat sampai Minggu, semuanya soal DNS dan HTTP: SOC-2027-0620 sampai 0624. Dwi sudah menempelkan cuplikan log, tapi dia bingung karena semuanya kelihatan aneh. Ada MDE yang mengkarantina file dari domain baru, ada workstation NOC dengan ribuan nama yang katanya NXDOMAIN, ada query TXT dengan subdomain panjang, ada skrip dengan User-Agent aneh yang POST tiap lima menit, dan semalam Gilang membuat tiket dari ringkasan pcap: ratusan NXDOMAIN untuk nama acak, tapi kliennya tidak ketahuan. Tolong pisahkan mana yang jinak dan mana yang harus dieskalasi ke Dimas sebelum stand-up jam 11. Satu lagi: pcap egress kita baru 72 jam, sebenarnya ini perlu pcap atau cukup log resolver dan proxy? Kalau ada yang dieskalasi, IOC apa yang aman dikirim ke Bambang untuk diblokir NOC?"

Pesan itu memuat tujuh pertanyaan:

1. Sumber mana yang melihat apa (log resolver, log proxy, pcap egress), dan apakah pcap egress yang retensinya sekitar 72 jam dibutuhkan?
2. Apakah TXT dengan subdomain panjang dari laptop baru berarti DNS tunneling?
3. Apakah "ribuan NXDOMAIN" dari workstation NOC berarti DGA, dan dari mana nama acak di ringkasan pcap berasal?
4. Apakah domain dengan TTL rendah yang muncul di kasus ini fast flux?
5. Apakah User-Agent aneh dan POST tiap lima menit berarti C2?
6. File apa yang dikarantina MDE, dan siapa lagi yang mengunduhnya?
7. Mana yang jinak, mana yang dieskalasi, dan IOC apa yang aman dikirim ke NOC?

Pertanyaan 1 dijawab di bagian 1.1, pertanyaan 2 di bagian 1.2, 2.1, dan 2.2, pertanyaan 3 di bagian 1.3 dan 2.3, pertanyaan 4 di bagian 1.4 dan 2.4, pertanyaan 5 di bagian 1.5 dan 2.5, pertanyaan 6 di bagian 1.6 dan 2.6, dan pertanyaan 7 di bagian 1.7, 1.8, 2.7, dan 2.8.

**Kapan relevan:** investigasi C2, exfiltration, dan infeksi malware yang menumpang DNS atau HTTP; triage alert berbasis DNS dan proxy; scoping setelah EDR menemukan satu host, untuk mencari host lain yang tidak terlindungi EDR; dan saat NOC atau pemilik sistem bertanya apakah sebuah pola DNS atau HTTP wajar.
**Kapan bukan jawaban:** saat DNS sudah pindah ke DoH atau DoT dan HTTP ke TLS tanpa inspeksi, karena isi nama dan header tidak lagi terlihat dan analisis bergeser ke metadata TLS (Day 06) dan DNS terenkripsi (Day 16); saat pola yang sama dipakai ratusan host untuk layanan sah yang populer, karena tanpa data endpoint atau isi trafik pola jaringannya tidak bisa dibedakan; dan saat satu sinyal (entropi, User-Agent, TTL) dipakai sendirian sebagai vonis.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (display filter, capture filter, tshark, Follow Stream, Export Objects, handshake TCP, dasar header HTTP dan record DNS) tidak diulang. Tabel ini memuat istilah yang baru dipakai Day ini; kolom kanan memakai padanan dari pekerjaan NOC dan ISP.

| Istilah | Arti singkat | Padanan di NOC/ISP |
|---|---|---|
| Label | Satu bagian nama DNS di antara titik; maksimal 63 oktet | Satu segmen di hostname perangkat |
| Domain induk | Domain terdaftar di atas subdomain (di Day ini, dua label terakhir) | Prefiks agregat di atas banyak /32 |
| DNS tunneling | Membawa data atau perintah di dalam nama query dan jawaban DNS | Data pelanggan yang diselipkan di kanal signaling |
| NXDOMAIN | Kode jawaban 3 (Name Error): nama tidak ada | Panggilan ke nomor yang tidak terdaftar |
| Negative caching | Resolver menyimpan jawaban "tidak ada" selama TTL dari SOA zona | Cache route yang di-blackhole sementara |
| DGA | Domain Generation Algorithm: malware menghitung daftar domain C2 dari seed atau tanggal | Daftar nomor cadangan yang dihitung dari tanggal |
| Fast flux | Satu domain dipetakan ke banyak IP yang berganti cepat dengan TTL rendah | Anycast liar yang anggotanya berganti tiap beberapa menit |
| TTL | Detik sebuah record boleh disimpan di cache | Hold timer pada informasi route |
| Entropi (Shannon) | Ukuran seberapa merata karakter dalam string; dipakai sebagai ukuran keacakan | Ukuran sebaran trafik di banyak port |
| User-Agent | Header yang dilaporkan klien tentang dirinya sendiri | `sysDescr` SNMP atau banner perangkat |
| Referer | Header yang menyebut halaman asal permintaan | Asal panggilan yang diteruskan |
| Magic byte | Beberapa byte awal file yang menandai format sebenarnya (`MZ` untuk executable Windows) | LLDP yang menunjukkan perangkat sebenarnya di ujung port |
| MIME sniffing | Klien menebak tipe isi dari datanya, bukan dari header | Menebak jenis perangkat dari perilakunya |
| Query log resolver | Log yang mencatat setiap pertanyaan klien ke resolver | Log permintaan di resolver pelanggan ISP |
| Atribusi klien | Menentukan workstation asal di balik resolver atau proxy | Mencari pelanggan di balik CGNAT |
| Prevalence | Jumlah host berbeda yang melakukan hal yang sama | Berapa pelanggan yang memakai layanan yang sama |
| First-seen | Waktu pertama kali sebuah domain atau IP terlihat di data | Waktu prefiks pertama kali muncul di tabel BGP |
| Sinkhole | Resolver mengembalikan alamat milik sendiri untuk domain berbahaya | Blackhole route ke null0 yang tetap mencatat siapa yang datang |
| Defang | Menulis IOC agar tidak bisa diklik (`contoh[.]example`) | Menulis nomor uji agar tidak terpanggil tidak sengaja |

### 1.1 Di mana DNS dan HTTP terlihat di PT JAB

Pertanyaan pertama Sari sebenarnya pertanyaan tentang posisi sensor. Lima tiket di antreannya berasal dari tiga sumber berbeda, dan setiap sumber menjawab sebagian saja.

Ada tiga titik pengamatan DNS dan HTTP di PT JAB minggu ini:

- **Log resolver (`index=dns`).** Resolver `jkt-res01` dan `jkt-res02` mengirim query log BIND ke Splunk dengan retensi 30 hari. Isinya: waktu, IP klien, nama, dan tipe record. Kanal log yang dikirim hanya query log, sehingga kode jawaban (NOERROR, NXDOMAIN) dan isi jawaban tidak ada. "Ribuan NXDOMAIN" yang disebut Dwi tidak mungkin dibaca dari sumber ini; yang terbaca hanyalah ribuan nama yang ditanyakan. Untuk mendapat jawaban, resolver perlu kanal log tambahan (response logging atau dnstap) atau penangkapan pasif; cek opsi yang tersedia di dokumentasi BIND versi resolver-mu.
- **Log proxy (`index=proxy`).** Trafik web workstation lewat proxy eksplisit `jkt-proxy01` (`10.20.3.60:3128`), juga retensi 30 hari. Isinya: klien, user, URL, metode, status, ukuran balasan, Content-Type dari header balasan, User-Agent, dan Referer. Proxy mendekripsi TLS hanya untuk domain baru atau tidak terkategori; untuk HTTPS lain yang tercatat hanya `CONNECT host:port`. Isi file tidak disimpan.
- **pcap egress (`jkt-pcap01`).** TAP di egress Jakarta memberi paket lengkap: rcode, TTL, semua jawaban, header dan isi HTTP polos. Tetapi di titik itu, query DNS sudah berasal dari resolver (`10.20.2.53` dan `10.20.2.54`) dan HTTP sudah berasal dari proxy (`10.20.3.60`), karena workstation bertanya ke keduanya, bukan ke internet langsung. Workstation mana yang bertanya tidak terlihat; titik pandang ini dibahas di Day 03 bagian 1.4. Hanya koneksi langsung workstation ke internet, yang biasanya ditolak firewall, yang terlihat dengan alamat aslinya karena TAP berada sebelum NAT. Retensinya juga terbatas: ring buffer berbasis ukuran, sehingga jendela waktunya mengikuti volume trafik (Day 01 bagian 1.6). Senin pagi, paket tertua bertanggal Kamis 2027-05-06 20:10, sekitar 84 jam sebelumnya. Seperti `logging buffered` di router, yang sudah tertimpa tidak bisa diambil mundur.

Tabel berikut merangkum siapa melihat apa; baca kolom "Tidak melihat", karena itulah yang menentukan sumber kedua yang harus dicocokkan.

| Sumber | Melihat | Tidak melihat | Retensi |
|---|---|---|---|
| `index=dns` (query log) | Klien, nama, tipe record, waktu | rcode, jawaban (IP, TTL, isi TXT) | 30 hari |
| `index=proxy` | Klien, user, URL, metode, status, ukuran, Content-Type header, UA, Referer | Isi file, magic byte; isi HTTPS yang tidak didekripsi | 30 hari |
| pcap `jkt-pcap01` | rcode, TTL, jawaban, header dan isi HTTP polos | Workstation asal (hanya resolver dan proxy) | Target 72 jam; minggu ini sekitar 84 jam |
| MDE di endpoint | Proses, file, hash, koneksi per proses | Workstation tanpa MDE | 30 hari |

Jawaban untuk pertanyaan Sari: pcap tidak menggantikan log, dan log tidak menggantikan pcap. Log resolver dan proxy menjawab "siapa", pcap menjawab "apa jawabannya" dan "apa isinya". Dua kebutuhan nyata di tiket minggu ini hanya bisa dijawab pcap: kode NXDOMAIN dan TTL (tidak ada di query log), dan isi file yang diunduh (tidak ada di log proxy). Sebaliknya, ringkasan pcap yang dibuat Gilang tidak bisa menunjuk host karena semua query tampak berasal dari dua resolver. Dan apa pun sebelum Kamis malam hanya tersisa di log.

### 1.2 DNS tunneling

Tiket `SOC-2027-0622` menyebut query TXT dengan subdomain panjang dari laptop baru `JKT-WS-2022`. Sebelum menilai, pahami dulu seperti apa tunneling yang sebenarnya.

Tunneling menyandikan data di dalam query dan response DNS untuk C2 atau exfiltration; ATT&CK mencatat pemakaian DNS sebagai saluran C2 sebagai T1071.004 [S3]. Mekanismenya sederhana: malware menaruh data di subdomain dari domain milik penyerang, query itu diteruskan oleh hierarki resolver sampai ke authoritative server milik penyerang, dan server itu mencatat atau membalas [S16]. Resolver internal tidak perlu dikompromikan; resolver justru menjadi pengantar yang patuh. Sinyalnya:

| Sinyal | Penjelasan |
|---|---|
| Query panjang/aneh | Label subdomain panjang berisi data tersandi (base32/base64/hex) |
| Entropi tinggi | Nama domain acak, bukan kata bermakna |
| Tipe record tak lazim | Banyak TXT, NULL, CNAME untuk membawa payload |
| Volume tinggi ke satu domain | Banyak query ke subdomain berbeda di satu domain induk |
| Response besar | TXT berisi data balasan |

Contoh pola (defang): `data-tersandi.tunnel[.]example[.]com` dengan subdomain berubah tiap query. Volume query ke satu domain induk jauh di atas normal adalah sinyal kuat.

Batas protokol menentukan bentuk tunneling. RFC 1035 membatasi satu label maksimal 63 oktet dan satu nama maksimal 255 oktet, dan pesan UDP klasik maksimal 512 oktet [S2]. Akibatnya, tunnel yang ingin cepat cenderung mengisi label sampai mendekati 63 karakter, memakai beberapa label sekaligus, dan mengirim sangat banyak query. Data tersandi juga membuat panjang subdomain bervariasi dari query ke query, karena isi yang dibawa berbeda-beda. Nilai tipe record yang sering muncul: A bernilai 1, CNAME 5, NULL 10, dan TXT 16 [S2].

ATT&CK v20 mencatat TXT sebagai tipe yang paling sering dipakai contoh prosedur di T1071.004, tetapi juga A, AAAA, dan OPT [S3]. Analitik deteksinya menyoroti subdomain panjang, pola tersandi, frekuensi atau volume tinggi, dan query dari proses non-browser seperti PowerShell, `rundll32`, atau `python.exe` [S3]. Jadi tunneling tidak harus TXT; query A biasa dengan subdomain tersandi juga bisa membawa data.

Penelitian Unit 42 (Mei 2024) menunjukkan tunneling juga dipakai untuk hal selain C2 dan exfil: melacak siapa yang membuka email phishing dengan menaruh hash alamat email di subdomain, dan memindai infrastruktur korban untuk mencari open resolver [S16]. Untuk analyst, artinya subdomain tersandi ke domain asing bisa berarti pelacakan atau pemindaian, bukan hanya pencurian data, dan tetap layak dicatat.

Dari sisi bentuk, yang membedakan tunneling dari pemakaian DNS yang sah dan intensif ada di empat ukuran: panjang subdomain yang bervariasi dan mendekati batas, jumlah subdomain unik per satuan waktu yang sangat besar, sedikit klien (biasanya satu), dan domain induk yang tidak dikenal atau baru. Bagian 2.1 dan 2.2 menerapkannya ke `JKT-WS-2022`.

### 1.3 DGA dan NXDOMAIN

Dua tiket menyentuh NXDOMAIN: `SOC-2027-0621` (workstation NOC dengan ribuan nama) dan `SOC-2027-0624` (ringkasan pcap Gilang dengan ratusan NXDOMAIN untuk nama acak). Keduanya terlihat mirip di permukaan, padahal penyebabnya sangat berbeda.

Malware memakai DGA untuk menghasilkan banyak nama domain, lalu mencoba resolusi sampai satu hidup (C2). Penyerang cukup mendaftarkan satu dari ribuan nama itu pada hari tertentu, sehingga memblokir satu domain tidak memutus C2 (ATT&CK T1568.002) [S3]. ATT&CK v20 menyebut beberapa gaya DGA: huruf acak, gabungan kata dari daftar kata, nama baru per periode waktu (per jam, harian, bulanan), dan seed tambahan yang kadang berupa tanggal [S3]. Sinyal:

- Banyak query ke domain yang namanya acak (entropi tinggi, bukan kata).
- Banyak response NXDOMAIN (domain tidak ada) karena kebanyakan domain DGA belum didaftarkan.
- Pola waktu teratur (malware mencoba daftar domain berkala).

Membedakan dari typo atau CDN: DGA menghasilkan banyak NXDOMAIN berturut dengan nama acak; CDN punya nama terstruktur dan resolusi berhasil.

Tiga hal teknis menentukan apa yang benar-benar terlihat di data PT JAB:

- **NXDOMAIN adalah rcode 3.** RFC 1035 menyebutnya Name Error, dan kode ini hanya bermakna dari authoritative server [S2]. RFC 2308 memakai istilah NXDOMAIN untuk kode yang sama [S6].
- **NXDOMAIN di-cache.** Authoritative server menyertakan record SOA zona di authority section jawaban negatif, dan TTL negatifnya adalah nilai terkecil antara field MINIMUM SOA dan TTL record SOA itu sendiri [S6]. RFC 2308 menyarankan resolver membatasi lama cache negatif, dengan satu sampai tiga jam sebagai nilai default yang masuk akal [S6]. Akibatnya untuk pcap egress: bila malware mengulang nama yang sama sebelum cache negatif habis, resolver menjawab dari cache dan query itu tidak pernah melewati egress. Jumlah NXDOMAIN di pcap egress bisa jauh lebih kecil daripada jumlah query klien.
- **Tidak semua NXDOMAIN acak berasal dari malware.** Browser berbasis Chromium menjalankan pemeriksaan intranet redirect: tiga lookup untuk hostname satu label acak sepanjang 7 sampai 15 huruf a-z, saat browser mulai dan setiap kali IP atau konfigurasi DNS perangkat berubah [S9]. Tujuannya mendeteksi jaringan yang membajak jawaban NXDOMAIN. Pengukuran Verisign di satu root server pada 13 Mei 2020 memperkirakan sekitar 45,8% trafik root berasal dari probe ini [S9]. Sebagian probe sampai ke resolver dengan suffix pencarian ditempelkan oleh resolver stub atau aplikasi [S9]. Di Microsoft Edge, perilaku ini diatur kebijakan `IntranetRedirectBehavior` (nilai 1 mematikan pemeriksaan dan infobar), dan pada Edge 88 pemeriksaan ini aktif secara default dengan rencana dimatikan secara default di rilis mendatang [S10]. Cek status default di versi browser-mu sebelum menyimpulkan.

Bentuk nama membedakan ketiganya. Tabel berikut adalah pegangan saat melihat daftar NXDOMAIN; baca kolom "Bentuk nama" dan "Ritme" bersamaan, karena satu kolom saja tidak cukup.

| Sumber NXDOMAIN | Bentuk nama | Ritme | Klien |
|---|---|---|---|
| DGA | Label acak di domain terdaftar (dua label atau lebih), daftar berganti per hari atau periode | Teratur (per jam, per hari), nama sama diulang dalam satu periode | Satu atau sedikit host yang terinfeksi |
| Probe Chromium | Satu label, 7 sampai 15 huruf a-z, kadang ditambah suffix pencarian | Saat browser mulai atau jaringan berubah, tiga sekaligus | Hampir semua workstation |
| Inventaris atau konfigurasi usang | Nama terstruktur dan bermakna (`bdg-sw-acc-07`), sering ditambah suffix pencarian | Mengikuti jadwal job atau aplikasi | Satu server atau workstation operasional |
| Salah ketik pengguna | Mirip kata nyata | Acak, jarang | Banyak, masing-masing sekali dua kali |

Satu catatan tentang suffix pencarian: bila sebuah nama gagal di-resolve, DNS client bisa mencoba lagi dengan suffix domain organisasi ditambahkan (`<nama>.corp.jab.example`). Kapan suffix ditambahkan untuk nama yang sudah bertitik bergantung pada setelan DNS client, jadi cek setelan GPO-mu. Efeknya: satu nama yang tidak ada bisa menghasilkan dua sampai empat query (A dan AAAA, dengan dan tanpa suffix). Bagian 2.3 menerapkan semua ini ke `JKT-WS-2020` dan ke ringkasan Gilang.

### 1.4 Fast flux dan TTL rendah

Saat menelusuri tiket MDE, Dwi mencatat bahwa domain asal file punya TTL 60 detik, lalu bertanya apakah itu fast flux. TTL rendah memang salah satu sinyal, tetapi bukan satu-satunya.

Fast flux memetakan satu domain ke banyak IP yang berganti cepat (TTL rendah) untuk ketahanan C2/phishing (ATT&CK T1568.001) [S3]. Sinyal:

- Satu domain resolve ke banyak IP berbeda dalam waktu singkat.
- TTL sangat rendah (detik hingga menit).
- IP tersebar di banyak jaringan/negara.

Dua varian yang perlu dikenali [S3][S8]:

- **Single flux:** alamat di record A satu domain terus ditambah dan dibuang. ATT&CK menyebut rata-rata tiap alamat terdaftar sekitar lima menit [S3].
- **Double flux:** selain alamat, name server zona juga berganti; advisory gabungan CISA, NSA, FBI, dan mitra (AA25-093A, 3 April 2025) mencatat pola ini terlihat pada record NS dan CNAME [S8].

Advisory yang sama memberi angka yang berguna sebagai pembanding: domain fast flux bisa berputar melalui puluhan sampai ratusan IP per hari, dan alamatnya bisa berganti kira-kira tiap 3 sampai 5 menit [S8]. Sinyal lain yang disebut: keragaman IP yang tinggi di jawaban, data geolokasi IP yang tidak konsisten, dan flow yang menunjukkan komunikasi ke banyak IP berbeda dalam waktu singkat [S8].

Membedakan dari CDN sah: CDN juga pakai banyak IP dan TTL rendah, tetapi IP dalam rentang milik CDN yang dikenal dan nama domain sah. Fast flux jahat memakai domain mencurigakan dengan IP di jaringan residensial/beragam. Advisory itu sendiri mengakui bahwa CDN, load balancer, dan hosting dinamis bisa terlihat seperti single flux, dan saran utamanya adalah memasukkan layanan CDN yang diharapkan ke allowlist [S8].

Karena PT JAB adalah ISP, advisory ini punya sisi kedua: ISP dan penyedia protective DNS diminta membangun deteksi dan pemblokiran fast flux, mempertimbangkan sinkhole, membagikan indikator lebih awal karena aktivitas domain seperti ini terjadi dalam beberapa hari setelah dipakai pertama kali, dan memberi tahu pelanggan bila aktivitas jahat terkonfirmasi [S8]. Itu relevan untuk Bambang di bagian 2.8.

Kesimpulan untuk pertanyaan Dwi: TTL 60 detik dengan satu IP bukan fast flux. Itu tanda bahwa pemilik domain ingin bisa memindahkan alamat dengan cepat, yang dilakukan banyak layanan sah maupun penyerang. Fast flux butuh rotasi banyak IP; bagian 2.4 mengukurnya.

### 1.5 Anomali HTTP: User-Agent, Referer, dan ritme

Tiket `SOC-2027-0623` berasal dari rule proxy yang menandai User-Agent non-browser dengan interval teratur di `JKT-WS-2024`. Sebelum melihat datanya, pahami apa yang bisa dan tidak bisa dikatakan sebuah header.

| Sinyal | Penjelasan |
|---|---|
| User-Agent aneh | UA kosong, tidak lazim, atau khas tool (bukan browser normal) |
| URI mencurigakan | Path acak, parameter base64 panjang, ekstensi executable |
| MIME tidak cocok | Content-Type text tapi isi executable (MZ header) |
| Host header aneh | IP langsung sebagai host, atau domain mencurigakan |
| Metode/pola C2 | POST berulang ke endpoint sama dengan body tersandi |
| Tanpa Referer wajar | Unduhan executable tanpa navigasi web normal |

User-Agent bukan bukti pasti (bisa dipalsukan), tetapi UA yang khas tool C2 atau kosong pada trafik yang seharusnya browser adalah sinyal.

RFC 9110 menjelaskan kenapa header ini lemah sebagai bukti. User agent sebaiknya mengirim User-Agent di setiap request kecuali dikonfigurasi untuk tidak mengirimnya, dan RFC itu mendorong implementasi untuk tidak memakai token produk implementasi lain demi mengklaim kompatibilitas [S7]. Kata kuncinya "mendorong": tidak ada yang mencegah program memakai string browser apa pun. Akibat praktisnya dua arah. Skrip jujur seperti `python-requests` atau `curl` mudah tertangkap rule UA, sementara malware yang menulis string browser lama lolos dari rule yang sama. Yang lebih kuat daripada UA itu sendiri adalah ketidakcocokan: UA yang menyebut sistem operasi atau browser yang tidak ada di host itu, atau UA berbeda dari host yang sama untuk tujuan yang berbeda.

Referer juga harus dibaca dengan aturan RFC. Bila URI target datang dari sumber yang tidak punya URI sendiri, seperti ketikan di address bar atau bookmark, user agent wajib menghilangkan Referer atau mengirim `about:blank` [S7]. Referer juga tidak dikirim ke request HTTP polos bila halaman asalnya diakses lewat protokol aman [S7]. Jadi unduhan tanpa Referer bisa berarti tidak ada navigasi (skrip atau malware), tetapi juga bisa berarti pengguna mengklik tautan di aplikasi email desktop atau pindah dari halaman HTTPS. "Tanpa Referer" adalah sinyal kecil yang harus ditemani sinyal lain.

ATT&CK mencatat C2 lewat protokol web sebagai T1071.001: perintah dan hasil diselipkan di header, cookie, atau body, supaya menyatu dengan trafik yang ada [S17]. Contoh prosedur yang tercantum memakai cookie, header kustom, dan body POST, termasuk malware yang berkomunikasi berkala lewat HTTP POST [S17]. Ritme POST yang teratur karenanya sinyal yang layak, dengan catatan yang sama seperti UA: agent monitoring, telemetry, dan skrip otomasi juga POST berkala. Pengukuran ritme yang lebih lengkap (interval, jitter, skor beacon) dibahas di Day 11; di Day ini cukup median, minimum, dan maksimum jarak antar-request.

### 1.6 Pola unduhan payload dan magic byte

Tiket `SOC-2027-0620` adalah alert MDE: file `tagihan-mei-2027.pdf` di `JKT-WS-2023` dikarantina sebagai malware beberapa detik setelah diunduh. Pertanyaan jaringan yang mengikutinya: file apa yang sebenarnya lewat, dari mana, dan siapa lagi yang mengunduhnya.

Unduhan malware lewat HTTP meninggalkan jejak:

- GET ke file executable (.exe, .dll, .ps1, .hta) atau arsip.
- Response dengan magic byte MZ (PE) meski Content-Type menyatakan lain.
- Host berupa IP langsung atau domain baru/mencurigakan.
- Tidak ada konteks navigasi (unduhan tiba-tiba tanpa klik halaman).

ATT&CK menamai pemindahan alat atau file dari sistem luar ke lingkungan yang dikompromikan sebagai Ingress Tool Transfer (T1105), yang bisa lewat kanal C2 atau protokol lain seperti FTP [S17].

Export Objects (Day 02 bagian 1.8) memperlihatkan file yang ditransfer [S5]; magic byte menentukan tipe sebenarnya, bukan ekstensi atau Content-Type. Jangan jalankan atau simpan payload di repo; catat hash dan metadata.

Kenapa magic byte lebih bisa dipercaya daripada label:

- **Content-Type adalah klaim pengirim.** RFC 9110 menjelaskan bahwa klien kadang memeriksa isi dan mengabaikan tipe yang dinyatakan (MIME sniffing), dan praktik itu bisa membawa kesimpulan keliru serta risiko keamanan [S7]. Bagi analyst, header yang sama bisa dipakai penyerang untuk menyamarkan executable sebagai PDF atau gambar.
- **Kolom Content Type di Export Objects berasal dari header.** Panduan Wireshark menyebut kolom itu sebagai tipe konten objek, di samping hostname pengirim, ukuran, dan nama file [S13]. Itu klaim server, bukan hasil pemeriksaan isi. Tipe sebenarnya baru terlihat dari byte awal file.
- **Executable Windows punya penanda tetap.** File PE diawali stub MS-DOS; header DOS itu dimulai dengan string ASCII `MZ` (heksadesimal `4D 5A`) [S15]. Di offset `0x3c` stub ada offset ke signature PE, yaitu `PE` diikuti dua byte nol, dan stub default linker mencetak pesan "This program cannot be run in DOS mode" [S14]. Tiga penanda itu (`MZ` di awal, offset di `0x3c`, `PE\0\0`) cukup untuk mengenali executable Windows di aliran HTTP.

Zeek mengenali tipe file dari isinya. Contoh di dokumentasi Zeek memperlihatkan `http.log` dengan `resp_mime_types` bernilai `application/x-dosexec` dan `files.log` dengan tipe yang sama untuk file yang diekstrak, ditautkan lewat `resp_fuids` dan `fuid` [S11]. Zeek baru hidup di PT JAB tanggal 18 Mei (Day 08), tetapi versi offline-nya sudah bisa dijalankan di `jkt-nsm-ws01` terhadap cuplikan pcap (bagian 2.6).

Satu aturan bukti: file yang diekspor dari pcap adalah barang bukti berbahaya. Simpan di direktori kasus yang hanya bisa dibaca, catat hash SHA-256 dan ukurannya, dan jangan pernah menjalankannya atau menaruhnya di repo catatan.

### 1.7 Entropi dan panjang sebagai sinyal

Rule yang memicu `SOC-2027-0621` dan ringkasan Gilang di `SOC-2027-0624` sama-sama memakai ukuran keacakan nama. Sebelum mempercayainya, pahami batasnya.

Banyak anomali DNS/HTTP ditandai keacakan: nama domain DGA, subdomain tunneling, parameter URI tersandi. Entropi tinggi (karakter acak merata) dan panjang tak lazim menandakan data tersandi, bukan nama/teks manusiawi. Ini heuristik, bukan bukti; layanan sah (CDN, hash, token) juga pakai string acak. Pakai sebagai penyaring awal, lalu timbang konteks.

Entropi Shannon untuk string dihitung dari frekuensi tiap karakter: makin merata, makin tinggi nilainya, dengan batas atas log2 dari jumlah karakter berbeda yang mungkin. Untuk string pendek, batas atas itu juga dibatasi panjang string sendiri: string 13 karakter paling banyak punya 13 karakter berbeda, jadi entropinya tidak bisa melebihi log2(13), sekitar 3,7. Akibatnya entropi pada label pendek sering menipu. Tabel berikut dihitung dari label yang muncul di Day ini; baca baris kedua dan ketiga bersama.

| Label | Panjang | Entropi (bit per karakter) | Asal |
|---|---|---|---|
| `ixlzwxuqaoyhubfd` | 16 | 3,75 | Nama DGA (bagian 2.3) |
| `fjkgrvugfwgmj` | 13 | 3,03 | Nama DGA (bagian 2.3) |
| `bdg-sw-acc-07` | 13 | 3,18 | Nama switch lama, jinak (bagian 2.3) |
| `mfrggzdfmztwq2lknnwg23tpobyxe43u` | 32 | 4,35 | ID perangkat base32 lisensi GIS, jinak (bagian 2.1) |
| `tagihan-mei-2027` | 16 | 3,50 | Nama file umpan (bagian 2.6) |
| `login` | 5 | 2,32 | Kata biasa |

Dua pelajaran dari tabel itu. Pertama, nama switch yang jinak (3,18) punya entropi lebih tinggi daripada satu nama DGA (3,03), jadi ambang entropi tunggal untuk label sependek ini akan salah ke dua arah. Kedua, label dengan entropi tertinggi di tabel (4,35) justru jinak: ID perangkat yang disandikan base32. Entropi berguna sebagai penyaring untuk label panjang dan dalam jumlah banyak, lalu harus ditemani bentuk (apakah ada kata, tanda hubung, angka berpola), ritme, prevalence, dan umur domain.

Panjang punya jebakan serupa. Nama DNS terpanjang di pcap egress PT JAB biasanya bukan tunneling, melainkan nama reverse lookup IPv6 di bawah `ip6.arpa`: 32 nibble alamat yang masing-masing diikuti titik, ditambah `ip6.arpa`, sehingga panjangnya 72 karakter untuk setiap alamat IPv6 (bagian 2.1).

### 1.8 Membedakan dari layanan sah dan menulis keputusan

Permintaan terakhir Sari adalah keputusan: mana yang jinak, mana yang dieskalasi. Keputusan itu harus bisa dipertanggungjawabkan di stand-up, jadi bentuknya perlu baku.

Banyak anomali mirip layanan sah:

- DoH (DNS over HTTPS) terlihat seperti HTTPS ke penyedia DNS; bukan tunneling jahat.
- CDN pakai banyak IP, TTL rendah, subdomain banyak; mirip fast flux/tunneling.
- Updater dan telemetry pakai UA khas tool dan POST berkala; mirip C2.
- Antivirus/EDR cloud lookup membuat banyak query domain.

Karena itu, setiap anomali yang dikenali harus ditimbang terhadap layanan sah yang diketahui di lingkungan. Nyatakan kemungkinan jinak dan korelasikan dengan reputasi domain/IP serta konteks host (Day 01-04).

Lima pertanyaan konteks dipakai untuk setiap tiket di Day ini. Tabel berikut adalah urutan pengecekannya; kolom kanan menunjukkan sumber PT JAB yang menjawab.

| Pertanyaan konteks | Kenapa penting | Sumber di PT JAB |
|---|---|---|
| Siapa pemilik host dan apa fungsinya? | Workstation NOC, laptop GIS, dan PC Keuangan punya pola normal berbeda | Inventaris aset, tim pemilik |
| Berapa host lain melakukan hal yang sama (prevalence)? | Pola di ratusan host biasanya layanan; di satu host perlu dijelaskan | `index=dns`, `index=proxy` dengan `dc(src)` |
| Sejak kapan tujuan terlihat (first-seen) dan berapa umurnya? | Domain yang baru muncul minggu ini lebih berisiko | `min(_time)` 30 hari di log, data registrasi domain |
| Proses apa yang memanggil? | Browser, agent bertanda tangan vendor, atau biner di folder profil pengguna | MDE (bila ada), konfirmasi pemilik |
| Apakah ada sinyal kedua yang independen? | Satu sinyal adalah indikator, dua sinyal independen mulai menjadi cerita | Gabungan DNS, proxy, pcap, endpoint |

Label yang dipakai: jinak terkonfirmasi (dengan siapa yang mengonfirmasi), perlu eskalasi (diserahkan ke IR dengan nomor insiden), dan data tidak cukup (dengan apa yang kurang). Bedakan indikator dari kesimpulan dalam setiap kalimat: "nama acak dengan ritme per jam" adalah indikator, "host terinfeksi malware dengan DGA" adalah kesimpulan yang butuh bukti tambahan dari host.

Untuk IOC yang dibagikan: tulis dalam bentuk defang (`berkas-tagihan[.]example`, `203.0.113[.]169`) supaya tidak terklik di chat atau tiket, sebut tingkat keyakinannya, dan sebut risiko efek samping pemblokiran (misalnya IP yang dipakai bersama banyak domain sah).

## 2. Contoh dan langkah praktis: lima tiket hari Senin

Semua isi bagian ini fiktif dan merupakan keluaran ilustrasi, bukan hasil eksekusi. Asumsi data PT JAB: `index=dns sourcetype=isc:bind:query` dengan field `src`, `query`, `query_type`; `index=proxy sourcetype=squid:access` dengan field `src`, `user`, `http_method`, `url`, `uri_path`, `dest`, `status`, `bytes`, `http_content_type`, `http_user_agent`, `http_referrer`. Nama sourcetype dan field bergantung add-on dan logformat, jadi cocokkan dengan lingkunganmu sebelum menjalankan. Perintah tshark ditulis untuk Wireshark 4.6.x di `jkt-nsm-ws01`. IOC di-defang di teks dan laporan, tetapi ditulis utuh di dalam perintah supaya perintahnya bisa dijalankan.

Lima tiket di antrean Sari, diurutkan menurut waktu alert. Tabel ini adalah peta bagian 2; kolom terakhir menunjuk subbagian yang membahasnya.

| Alert | Waktu | Sumber alert | Host | Ringkasan | Dibahas di |
|---|---|---|---|---|---|
| `SOC-2027-0620` | Jumat 2027-05-07 09:13 | MDE | `JKT-WS-2023` (`10.10.60.53`, `yusuf.pranata`, Keuangan) | `tagihan-mei-2027.pdf` dari `berkas-tagihan.example` dikarantina | 2.4, 2.6 |
| `SOC-2027-0621` | Jumat 2027-05-07 10:15 | Rule Splunk "klien dengan lebih dari 1.000 nama unik per jam" | `JKT-WS-2020` (`10.10.60.50`, PC NOC) | 2.412 nama unik dalam satu jam | 2.3 |
| `SOC-2027-0622` | Jumat 2027-05-07 16:02 | Rule Splunk "TXT dengan subdomain lebih dari 30 karakter dari klien baru" | `JKT-WS-2022` (`10.10.60.52`, laptop GIS) | TXT ke `lic.gisdesk.example`, subdomain 47 karakter | 2.1, 2.2 |
| `SOC-2027-0623` | Sabtu 2027-05-08 14:30 | Rule Splunk "UA non-browser dengan interval teratur" | `JKT-WS-2024` (`10.10.60.54`, PC NOC) | `python-requests/2.32.3` POST tiap 300 detik | 2.5 |
| `SOC-2027-0624` | Minggu 2027-05-09 20:05 | Ringkasan harian pcap egress (uji coba), dibuat Gilang | Tidak diketahui | 1.176 NXDOMAIN hari Sabtu untuk 49 nama acak | 2.3, 2.5 |

Sebelum mulai, cuplikan pcap egress disiapkan sekali di `jkt-nsm-ws01`. Ring buffer `jkt-pcap01` di-mount read-only di `/mnt/pcap01`, dan file kerja ditulis ke direktori kasus. Perintah ini memisahkan DNS milik resolver dan HTTP polos milik proxy dari setiap file ring:

```
mkdir -p /cases/2027-05-10-dnshttp
for f in /mnt/pcap01/ring/egress-jkt_*.pcapng; do
  b=$(basename "$f" .pcapng)
  tcpdump -r "$f" -w "/cases/2027-05-10-dnshttp/dns_$b.pcap"  'port 53 and (host 10.20.2.53 or host 10.20.2.54)'
  tcpdump -r "$f" -w "/cases/2027-05-10-dnshttp/http_$b.pcap" 'host 10.20.3.60 and tcp port 80'
done
mergecap -w /cases/2027-05-10-dnshttp/egress-dns.pcap  /cases/2027-05-10-dnshttp/dns_egress-jkt_*.pcap
mergecap -w /cases/2027-05-10-dnshttp/egress-http.pcap /cases/2027-05-10-dnshttp/http_egress-jkt_*.pcap
sha256sum /cases/2027-05-10-dnshttp/egress-*.pcap > /cases/2027-05-10-dnshttp/HASHES.txt
```

- `tcpdump -r ... -w ... '<filter>'` membaca file ring dan menulis ulang hanya paket yang cocok dengan filter BPF; ini jauh lebih ringan daripada membuka ring berukuran besar di Wireshark.
- `port 53 and (host 10.20.2.53 or host 10.20.2.54)` mengambil DNS kedua resolver; `host 10.20.3.60 and tcp port 80` mengambil HTTP polos dari proxy ke server tujuan. HTTPS tidak diambil karena isinya tidak terbaca di egress. Karena TAP berada sebelum NAT, alamat internal ini yang dipakai, bukan alamat NAT.
- `mergecap -w` menggabungkan cuplikan menurut waktu paket.
- `sha256sum` mencatat hash file kerja supaya analisis bisa dibuktikan berasal dari cuplikan yang sama.

**Kapan gagal:** file ring sedang ditulis saat dibaca (lewati file terbaru, atau tunggu rotasi berikutnya); resolver atau proxy punya lebih dari satu alamat; TAP kelak dipindah ke sisi luar firewall sehingga filter harus memakai alamat NAT; atau sebagian query resolver memakai TCP port 53 untuk jawaban besar, yang tetap terambil karena filter `port 53` tidak membatasi protokol transport.

### 2.1 Query DNS panjang/aneh (tunneling)

Bagian ini menjawab pertanyaan kedua Sari lewat tiket `SOC-2027-0622`. Langkah pertama adalah melihat nama-nama terpanjang di pcap egress, supaya kamu tahu seperti apa "panjang" yang normal di PT JAB sebelum menilai satu domain.

```
dns.qry.name
dns.qry.type == 16
```

- `dns.qry.type == 16` adalah TXT (sering dipakai tunneling). Filter query untuk melihat nama.
- Dengan tshark, ambil dan ukur panjang nama:

```
tshark -r capture.pcap -Y "dns" -T fields -e dns.qry.name | awk '{ print length, $0 }' | sort -rn | head
```

- Cara membaca: nama panjang dengan subdomain acak ke satu domain induk, berulang, menandakan tunneling. Bandingkan dengan query normal (pendek, nama bermakna).

**Tujuan:** mengetahui nama terpanjang yang lewat egress dan memeriksa apakah nama dari `JKT-WS-2022` menonjol.

**Sintaks yang dipakai di PT JAB:**

```
tshark -r /cases/2027-05-10-dnshttp/egress-dns.pcap \
  -Y "dns.flags.response == 0" -T fields -e dns.qry.name \
  | sort -u | awk '{ print length, $0 }' | sort -rn | head -5
```

| Bagian | Fungsi |
|---|---|
| `-Y "dns.flags.response == 0"` | Hanya query; tanpa ini setiap nama muncul dua kali (query dan response) |
| `-T fields -e dns.qry.name` | Keluarkan satu kolom, nama yang ditanyakan [S1] |
| `sort -u` | Buang nama yang sama sebelum mengukur, supaya daftar teratas tidak penuh duplikat |
| `awk '{ print length, $0 }'` | Tambahkan panjang karakter di depan setiap nama |
| `sort -rn \| head -5` | Urutkan dari terpanjang, ambil lima |

Keluaran ilustrasi:

```
72 4.3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa
72 c.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa
63 mfrggzdfmztwq2lknnwg23tpobyxe43u.1809679800.lic.gisdesk.example
63 mfrggzdfmztwq2lknnwg23tpobyxe43u.1809680400.lic.gisdesk.example
63 nbswy3dpeb3w64tmmqqgc3dpnfxgo2lq.1809680400.lic.gisdesk.example
```

**Cara membaca hasil:**

- Dua baris teratas adalah reverse lookup IPv6, selalu 72 karakter. Panjang tetapi jinak, karena strukturnya ditentukan alamat, bukan data.
- Tiga baris berikutnya adalah nama lisensi GIS. Panjang seluruh nama 63 karakter, subdomain di kiri `gisdesk.example` 47 karakter, dengan label terpanjang 32 karakter (jauh di bawah batas 63 per label [S2]). Strukturnya tetap: satu label 32 karakter base32, satu label angka 10 digit, lalu `lic`. Angka 10 digit itu cocok dengan Unix time: `1809679800` adalah Jumat 2027-05-07 15:50 WIB dan `1809680400` sepuluh menit kemudian.
- Baris kelima punya label base32 yang berbeda, artinya ada perangkat lain yang mengirim pola sama. Prevalence dicek di bagian 2.2.

**Variasi:** ukur label terpanjang, bukan nama penuh, karena tunneling mengisi label: `awk -F. '{ m=0; for (i=1;i<=NF;i++) if (length($i)>m) m=length($i); print m, $0 }'`. Atau gunakan field Wireshark `dns.qry.name.len` dan `dns.count.labels` langsung di filter, misalnya `dns.qry.name.len > 50 && dns.flags.response == 0` [S1].

**Kapan gagal:** pcap egress tidak memuat nama di zona internal (`corp.jab.example`) karena resolver menjawabnya sendiri; nama yang dijawab dari cache resolver juga tidak lewat egress; dan bila program memakai DoH, nama tidak pernah terlihat di DNS polos (Day 16).

### 2.2 Volume query ke satu domain induk

Panjang saja tidak cukup; bagian 1.2 menyebut volume, keragaman panjang, dan jumlah klien. Data itu ada di `index=dns`, yang juga tahu kliennya.

```
dns.qry.name contains "tunnel-domain.example.com"
```

- Hitung query per domain induk; volume tinggi ke satu induk dengan subdomain berbeda = sinyal tunneling.
- Cara membaca: ratusan/ribuan query ke `*.satu-domain` dalam waktu singkat jauh di atas normal; itu saluran data, bukan resolusi biasa.

**Tujuan:** untuk setiap domain induk yang menerima TXT dengan subdomain panjang, hitung volume, subdomain unik, sebaran panjang, dan jumlah klien.

**Sintaks:**

```
index=dns sourcetype=isc:bind:query query_type=TXT
    earliest="05/07/2027:00:00:00" latest="05/10/2027:08:00:00"
| eval q=lower(rtrim(query, "."))
| rex field=q "^(?<sub>.+)\.(?<parent>[^.]+\.[^.]+)$"
| eval sub_len=len(sub)
| stats count AS queries dc(sub) AS unique_sub min(sub_len) AS min_len
        avg(sub_len) AS avg_len max(sub_len) AS max_len dc(src) AS clients
        values(src) AS src_list BY parent
| where max_len > 30
| eval avg_len=round(avg_len, 1)
| sort - queries
```

| Bagian | Fungsi |
|---|---|
| `query_type=TXT` | Hanya TXT, sesuai rule yang memicu tiket |
| `rtrim(query, ".")` dan `lower(...)` | Buang titik akhir dan samakan huruf, supaya nama yang sama tidak terhitung dua kali |
| `rex ... (?<parent>[^.]+\.[^.]+)$` | Domain induk = dua label terakhir; sisanya `sub` |
| `min_len`, `avg_len`, `max_len` | Sebaran panjang: data tersandi bervariasi, ID berformat tetap tidak |
| `dc(src)` dan `values(src)` | Prevalence: satu klien atau banyak |
| `where max_len > 30` | Sama dengan ambang rule |

Keluaran ilustrasi:

```
parent           queries  unique_sub  min_len  avg_len  max_len  clients  src_list
gisdesk.example      344         344       47     47.0       47        7  10.10.60.52 10.10.61.71 10.10.61.72 10.10.61.73 10.10.61.74 10.10.61.75 10.10.61.76
```

**Cara membaca hasil:** hanya satu domain induk yang lolos. Enam klien di `10.10.61.71` sampai `.76` adalah workstation tim GIS yang sudah ada di allowlist rule sejak 2026; masing-masing bertanya tiap 600 detik selama jam kerja Jumat 08:00 sampai 17:00, yaitu 55 query per host, total 330. `JKT-WS-2022` menambah 14 query dari 15:50 sampai 18:00 sebelum laptop dibawa pulang, sehingga totalnya 344. Panjang minimum, rata-rata, dan maksimum sama persis (47): format tetap, bukan data yang mengalir. Setiap query unik karena label waktu berganti, bukan karena isi yang disandikan. Tabel berikut membandingkannya dengan profil tunneling dari bagian 1.2.

| Ukuran | `gisdesk.example` | Profil tunneling |
|---|---|---|
| Sebaran panjang subdomain | Tetap 47 | Bervariasi, mendekati batas label |
| Volume per klien | 6 query per jam | Ratusan sampai ribuan per jam |
| Klien | 7, satu tim, sama fungsi | Biasanya satu |
| Domain induk | Vendor perangkat lunak yang dibeli tim GIS, terlihat sejak 2026 | Baru atau tidak dikenal |
| Jawaban TXT (dari pcap) | Sekitar 90 byte token lisensi, sama ukurannya tiap kali | Besar dan bervariasi bila membawa data balik |

Konfirmasi konteks: tim IT memasang perangkat lunak GIS di laptop baru `JKT-WS-2022` Jumat siang sesuai tiket pengadaan, dan dokumentasi vendor menyebut pemeriksaan lisensi lewat TXT. Label: jinak terkonfirmasi. Tindakan: tambahkan pasangan `gisdesk.example` dan `10.10.60.52` ke allowlist rule. Allowlist berbasis pasangan domain dan klien, bukan domain saja, supaya host lain yang tiba-tiba memakai domain yang sama tetap memicu rule.

**Variasi:** jalankan query yang sama tanpa `query_type=TXT` untuk mencari tunneling lewat record A, karena ATT&CK mencatat A dan AAAA juga dipakai [S3]. Untuk pcap, jumlah query per domain induk bisa dihitung dengan `tshark ... -e dns.qry.name | awk -F. '{ print $(NF-1)"."$NF }' | sort | uniq -c | sort -rn | head`.

**Kapan gagal:** domain induk memakai akhiran dua label seperti `co.id`, sehingga `parent` terpotong di tempat yang salah dan semua domain `.co.id` menjadi satu; tunneling yang menyebar ke banyak domain induk sehingga masing-masing di bawah ambang; dan query yang datang dari proxy atau server lain yang bertanya atas nama banyak klien, karena `dc(src)` lalu tidak lagi mewakili jumlah pengguna.

### 2.3 DGA dan NXDOMAIN

Bagian ini menangani dua tiket sekaligus, `SOC-2027-0621` dan `SOC-2027-0624`, karena keduanya bertumpu pada NXDOMAIN dan keduanya menjawab pertanyaan ketiga Sari.

```
dns.flags.rcode == 3
```

- rcode 3 = NXDOMAIN. Banyak NXDOMAIN ke nama acak dari satu host = kandidat DGA.
- Dengan tshark, hitung NXDOMAIN per host dan periksa nama (acak vs terstruktur).
- Cara membaca: burst NXDOMAIN dengan nama acak teratur = malware mencoba daftar domain DGA. Typo biasa jarang dan namanya mirip kata.

#### Langkah 1: bentuk nama dari `JKT-WS-2020`

**Tujuan:** melihat nama apa yang ditanyakan `JKT-WS-2020` pada jam alert, karena query log tidak punya rcode dan pcap egress tidak memuat zona internal.

```
index=dns sourcetype=isc:bind:query src=10.10.60.50
    earliest="05/07/2027:10:00:00" latest="05/07/2027:11:00:00"
| eval suffix=case(like(query, "%.pop.jab.example.corp.jab.example"), "pop+corp",
                   like(query, "%.pop.jab.example"), "pop",
                   true(), "lain")
| stats count AS queries dc(query) AS names min(_time) AS first max(_time) AS last
        BY suffix query_type
| convert ctime(first) ctime(last)
```

| Bagian | Fungsi |
|---|---|
| `like(query, "%.pop.jab.example.corp.jab.example")` | Nama yang sudah ditempeli suffix `corp.jab.example`; diperiksa lebih dulu karena juga cocok dengan pola kedua bila urutannya terbalik |
| `case(..., true(), "lain")` | Semua nama lain masuk satu kelompok |
| `BY suffix query_type` | Pisahkan A dan AAAA |
| `convert ctime(...)` | Ubah epoch ke waktu terbaca |

Keluaran ilustrasi:

```
suffix    query_type   queries  names  first                last
pop       A               1206   1206  05/07/2027 10:00:03  05/07/2027 10:13:41
pop       AAAA            1206   1206  05/07/2027 10:00:03  05/07/2027 10:13:41
pop+corp  A               1206   1206  05/07/2027 10:00:03  05/07/2027 10:13:42
pop+corp  AAAA            1206   1206  05/07/2027 10:00:03  05/07/2027 10:13:42
```

**Cara membaca hasil:** total 4.824 query untuk 2.412 nama unik: 1.206 hostname, masing-masing dalam dua bentuk (tanpa dan dengan suffix), masing-masing ditanya A dan AAAA. Kelompok "lain" kosong, jadi tidak ada nama lain dalam jam itu. Contoh nama: `bdg-sw-acc-07.pop.jab.example`, terstruktur dan bermakna. Semua berakhir di zona internal, sehingga tidak pernah lewat egress; itulah kenapa ringkasan pcap Gilang tidak memuatnya.

Konteks: Bambang mengonfirmasi bahwa `JKT-WS-2020` menjalankan job inventaris POP tiap Jumat pukul 10:00 dari file CSV lama. Nama switch POP Bandung diganti pada migrasi November 2026, dan IPAM menunjukkan nol dari 1.206 nama itu masih ada. Rasio dua nama per hostname juga cocok dengan suffix pencarian dari bagian 1.3. Label: jinak terkonfirmasi (salah konfigurasi). Tindakan: tiket ke NOC untuk memperbarui CSV; rule tidak perlu diubah, karena job yang sama dengan daftar baru tidak akan melampaui 1.000 nama unik yang gagal.

Klaim "ribuan NXDOMAIN" di catatan Dwi tidak bisa dibuktikan dari data yang ada: query log tidak memuat rcode, dan zona internal tidak lewat egress. Yang bisa ditulis: nama-nama itu tidak ada di IPAM, sehingga hampir pasti dijawab NXDOMAIN. Itu kalimat yang jujur; "terbukti NXDOMAIN" tidak.

#### Langkah 2: nama acak di ringkasan Gilang

**Tujuan:** menghitung NXDOMAIN untuk nama berbentuk acak di pcap egress, lengkap dengan jumlah, panjang label, dan waktu pertama dan terakhir.

```
tshark -r /cases/2027-05-10-dnshttp/egress-dns.pcap \
  -Y "dns.flags.response == 1 && dns.flags.rcode == 3" \
  -T fields -e frame.time_epoch -e dns.qry.name \
| gawk '$2 ~ /^[a-z]{12,16}\.[a-z]+$/ {
          c[$2]++; if (!($2 in f)) f[$2]=$1; l[$2]=$1 }
        END { for (n in c) { split(n, p, ".");
              print c[n], length(p[1]), strftime("%a %H:%M", f[n]), strftime("%a %H:%M", l[n]), n } }' \
| sort -k1,1nr
```

| Bagian | Fungsi |
|---|---|
| `dns.flags.response == 1 && dns.flags.rcode == 3` | Hanya jawaban NXDOMAIN [S1][S2] |
| `-e frame.time_epoch -e dns.qry.name` | Waktu (epoch) dan nama |
| `$2 ~ /^[a-z]{12,16}\.[a-z]+$/` | Hanya nama dua label dengan label pertama 12 sampai 16 huruf. Pola ini sengaja dibuat dari bentuk nama di ringkasan Gilang, bukan pola DGA umum |
| `c[$2]++`, `f[$2]`, `l[$2]` | Jumlah, waktu pertama, waktu terakhir per nama |
| `strftime(...)` | Fungsi gawk untuk memformat epoch; tidak ada di awk biasa |
| `sort -k1,1nr` | Urutkan menurut jumlah, terbesar di atas |

Keluaran ilustrasi (dipangkas dari 248 baris):

```
24 13 Fri 00:40 Fri 23:40 fjkgrvugfwgmj.example
24 12 Fri 00:40 Fri 23:40 lnfeickjtsat.test
24 12 Sat 00:40 Sat 23:40 xlmarznlmsao.example
24 12 Sat 00:40 Sat 23:40 wftgdyholqlq.test
24 16 Sun 00:40 Sun 23:40 tlekiwrcjvkjfzcu.test
24 13 Sun 00:40 Sun 23:40 xwjpfxbctrmbh.example
8 13 Mon 00:40 Mon 07:40 uzndfnlebnjeo.example
8 16 Mon 00:40 Mon 07:40 fqopwxkpijpmedmr.test
4 16 Thu 20:40 Thu 23:40 ixlzwxuqaoyhubfd.example
4 14 Thu 20:40 Thu 23:40 phmrdshaxgnify.test
2 14 Sat 10:02 Sat 10:03 kantorpusatjab.example
```

Nama di catatan ini memakai akhiran `.example` dan `.test` sebagai pengganti TLD nyata.

**Cara membaca hasil:**

- 245 baris punya pola yang sama: 49 nama per hari, setiap nama diulang tepat pada menit ke-40 setiap jam, dan daftarnya berganti saat tengah malam. Jumlah per nama mengikuti jumlah jam dalam jendela pcap: Kamis 4 (20:40 sampai 23:40, karena paket tertua 20:10), Jumat, Sabtu, dan Minggu masing-masing 24, Senin 8 (00:40 sampai 07:40). Totalnya 49 nama kali 84 percobaan, yaitu 4.116 NXDOMAIN.
- Jumlah yang identik antar-nama pada hari yang sama adalah tanda jadwal, bukan pengguna. Salah ketik tidak pernah muncul tepat 24 kali.
- Pengulangan per jam terlihat di egress karena negative cache resolver sudah habis sebelum jam berikutnya. SOA di authority section jawaban NXDOMAIN untuk nama-nama ini membawa TTL 900 detik, jadi setiap percobaan per jam kembali ke authoritative server [S6].
- Tiga baris sisanya, seperti `kantorpusatjab.example`, muncul satu atau dua kali dan mirip kata: salah ketik pengguna.

**Langkah lanjutan, jawaban yang berhasil.** DGA menunggu satu nama yang hidup. Filter berikut mencari jawaban NOERROR untuk nama berbentuk sama:

```
tshark -r /cases/2027-05-10-dnshttp/egress-dns.pcap \
  -Y 'dns.flags.response == 1 && dns.flags.rcode == 0 && dns.qry.name matches "^[a-z]{12,16}[.](example|test)$"' \
  -T fields -e dns.qry.name -e dns.a -e dns.resp.ttl | sort | uniq -c
```

`matches` memakai ekspresi reguler; titik ditulis sebagai kelas karakter `[.]` supaya tidak perlu escape berlapis di shell dan di string filter.

Keluaran ilustrasi:

```
     24 cjljpwkfppwfbi.example	203.0.113.168	300
      4 fyzcettoeeaagyg.test	203.0.113.168	300
     24 yodsxyzljbncgk.test	203.0.113.168	300
     24 liounebubzpkgexs.example	203.0.113.168	300
      8 upkfcpiqzrqlc.test	203.0.113.168	300
```

Satu nama per hari hidup, semuanya menunjuk `203.0.113.168` dengan TTL 300 detik. Per jam: 49 NXDOMAIN dan satu NOERROR, sehingga satu percobaan berisi 50 nama. Jumlah 84 jawaban NOERROR cocok dengan 84 percobaan di jendela pcap.

#### Langkah 3: atribusi ke workstation lewat `index=dns`

pcap tidak tahu siapa yang bertanya; query log tahu. Daftar 250 nama dari langkah 2 (245 NXDOMAIN dan 5 nama hidup) disimpan sebagai lookup `soc2027_0624_dga_names.csv` dengan satu kolom `query`.

```
index=dns sourcetype=isc:bind:query
    earliest="05/06/2027:00:00:00" latest="05/10/2027:08:00:00"
    [| inputlookup soc2027_0624_dga_names.csv | fields query]
| stats count AS queries dc(query) AS names min(_time) AS first max(_time) AS last BY src
| convert ctime(first) ctime(last)
```

Subsearch di dalam kurung siku mengubah isi lookup menjadi kondisi `query=... OR query=...`, sehingga hanya event dengan nama itu yang diambil. Untuk 250 nama ini aman; untuk daftar ribuan nama, batas subsearch bisa memotong daftar tanpa peringatan yang jelas, jadi gunakan `lookup` setelah pencarian.

Keluaran ilustrasi:

```
src           queries  names  first                last
10.10.60.51      4450    250  05/06/2027 15:40:02  05/10/2027 07:40:03
10.20.3.60         89      5  05/06/2027 15:41:01  05/10/2027 07:41:02
```

**Cara membaca hasil:**

- `10.10.60.51` adalah `JKT-WS-2021`, workstation Keuangan milik `meila.rahayu`, salah satu workstation yang belum terpasang MDE. 4.450 query untuk 250 nama: 50 nama per percobaan kali 89 percobaan per jam dari Kamis 15:40 sampai Senin 07:40 (9 pada Kamis, masing-masing 24 pada Jumat, Sabtu, dan Minggu, 8 pada Senin). Log resolver tidak dibatasi jendela pcap, sehingga lima percobaan pertama hari Kamis (15:40 sampai 19:40) yang sudah tertimpa di pcap tetap ada di sini. Lima hari kali 50 nama memberi 250 nama.
- `10.20.3.60` adalah `jkt-proxy01`. Proxy hanya menanyakan lima nama yang hidup, satu menit setelah workstation, 89 kali. Artinya workstation memeriksa nama sendiri lewat resolver, lalu menghubungi nama yang hidup lewat proxy. Pada proxy eksplisit, browser biasanya menyerahkan resolusi nama ke proxy; program yang me-resolve sendiri lalu tetap lewat proxy adalah perilaku non-browser.

Pivot berikutnya adalah scoping: adakah klien lain yang menanyakan nama berbentuk sama, termasuk nama yang tidak ada di daftar dan hari sebelum Kamis? Pencarian memakai bentuk nama, bukan daftar, untuk semua klien sejak awal bulan:

```
index=dns sourcetype=isc:bind:query
    earliest="05/01/2027:00:00:00" latest="05/10/2027:08:00:00"
| regex query="^[a-z]{12,16}\.(example|test)$"
| stats count AS queries dc(query) AS names min(_time) AS first max(_time) AS last BY src
| convert ctime(first) ctime(last)
| sort - queries
```

Keluaran ilustrasi:

```
src          queries  names  first                last
10.10.60.51     4450    250  05/06/2027 15:40:02  05/10/2027 07:40:03
10.20.3.60        89      5  05/06/2027 15:41:01  05/10/2027 07:41:02
10.10.60.56        2      1  05/08/2027 10:02:11  05/08/2027 10:02:12
```

Hanya satu workstation punya bentuk itu, dan tidak ada aktivitas sebelum Kamis 15:40. Baris `10.10.60.56` adalah salah ketik `kantorpusatjab.example` yang juga terlihat di langkah 2. Perintah `regex` di SPL menyaring event dengan ekspresi reguler pada field; pola yang sama dengan langkah 2 dipakai supaya hasil pcap dan log bisa dibandingkan.

Label: perlu eskalasi. Indikatornya nama acak dengan daftar harian, ritme per jam, satu klien, resolusi oleh program non-browser, dan satu IP tujuan untuk semua nama yang hidup. Kesimpulan "host terinfeksi" masih butuh bukti dari host, tetapi bagian 2.5 dan 2.6 menambah dua sinyal independen.

**Variasi:** di lingkungan dengan Zeek (Day 08), `dns.log` memuat `rcode_name`, `answers`, dan `TTLs` per transaksi dan bisa ditautkan ke `conn.log` lewat `uid` [S11], sehingga NXDOMAIN per klien bisa dihitung langsung bila sensor berada di depan resolver.

**Kapan gagal:** resolver menjawab dari negative cache sehingga egress tidak melihat ulangan (bila malware mengulang lebih cepat dari TTL negatif, jumlah di pcap jauh lebih kecil dari jumlah di log); DGA berbasis daftar kata menghasilkan nama yang terlihat bermakna dan lolos regex huruf acak; klien memakai resolver luar atau DoH sehingga query tidak ada di `index=dns`; dan pola `[a-z]{12,16}` dibuat dari data, jadi DGA lain dengan panjang atau alfabet berbeda butuh pola sendiri.

### 2.4 Fast flux

Pertanyaan keempat Sari, "apakah TTL rendah berarti fast flux", dijawab dengan menghitung jumlah IP berbeda per nama dan TTL terendahnya di pcap egress.

```
dns.a
dns.resp.ttl
```

- Untuk satu nama, lihat berapa IP (`dns.a`) berbeda dan TTL-nya. Banyak IP + TTL rendah = kandidat fast flux.
- Cara membaca: satu domain resolve ke banyak IP tersebar dengan TTL detik = fast flux; bandingkan dengan domain sah (IP stabil atau rentang CDN dikenal).

**Tujuan:** daftar nama dengan TTL 60 detik atau kurang, beserta jumlah IP berbeda yang pernah dijawab selama jendela pcap (sekitar 84 jam).

**Sintaks:**

```
tshark -r /cases/2027-05-10-dnshttp/egress-dns.pcap \
  -Y "dns.flags.response == 1 && dns.a" \
  -T fields -E separator=/t -E aggregator=, \
  -e dns.qry.name -e dns.a -e dns.resp.ttl \
| awk -F'\t' '{ n=split($2, ip, ","); split($3, t, ",");
               for (i=1; i<=n; i++) { k=$1 SUBSEP ip[i]; if (!(k in seen)) { seen[k]=1; cnt[$1]++ } }
               if (!($1 in mint) || t[1]+0 < mint[$1]) mint[$1]=t[1]+0 }
             END { for (d in cnt) if (mint[d] <= 60) print cnt[d], mint[d], d }' \
| sort -rn | head
```

| Bagian | Fungsi |
|---|---|
| `-Y "dns.flags.response == 1 && dns.a"` | Hanya jawaban yang memuat record A [S1] |
| `-E separator=/t -E aggregator=,` | Kolom dipisah tab; nilai ganda dalam satu kolom (beberapa A, beberapa TTL) dipisah koma [S12] |
| `split($2, ip, ",")` | Pecah daftar IP dalam satu jawaban |
| `seen[k]`, `cnt[$1]++` | Hitung IP berbeda per nama selama jendela pcap |
| `t[1]+0 < mint[$1]` | Simpan TTL terkecil; `+0` memaksa perbandingan angka |
| `mint[d] <= 60` | Hanya nama dengan TTL 60 detik atau kurang |

Keluaran ilustrasi:

```
37 20 edge.vidconf.example
12 30 img.cdn-statik.example
4 60 api.pembayaran-mitra.example
1 60 berkas-tagihan.example
```

**Cara membaca hasil:**

- `edge.vidconf.example`: 37 IP dengan TTL 20 detik. Bentuknya seperti fast flux, tetapi semua alamat berada di dua prefiks milik penyedia layanan video conference yang sama, dan log proxy menunjukkan domain ini dipakai 612 klien setiap hari kerja sejak 2026. Ini CDN; masuk allowlist sesuai saran advisory [S8].
- `img.cdn-statik.example` dan `api.pembayaran-mitra.example`: pola serupa dalam skala lebih kecil, juga prefiks milik satu penyedia, juga ratusan klien.
- `berkas-tagihan.example`: TTL 60 tetapi hanya satu IP (`203.0.113.169`) selama jendela pcap. Bukan fast flux. TTL rendah pada domain yang baru muncul berarti pemiliknya siap memindahkan alamat dengan cepat, dan itu sinyal kecil yang ditambahkan ke tiket `SOC-2027-0620`, bukan kesimpulan.
- Nama-nama DGA dari bagian 2.3 tidak muncul karena TTL-nya 300 detik.

Kesimpulan: tidak ada fast flux di pcap egress Kamis 20:10 sampai Senin 08:00. Itu ditulis apa adanya, dengan cakupannya: hanya trafik DNS resolver kantor Jakarta yang lewat egress, hanya record A, dan hanya sekitar 84 jam.

**Variasi:** tambahkan `-e dns.aaaa` untuk IPv6; hitung keragaman jaringan dengan memotong IP ke /24 (`split(ip[i], o, "."); k=$1 SUBSEP o[1]"."o[2]"."o[3]`) sebelum dihitung, karena IP dari satu /24 lebih mungkin satu penyedia daripada IP yang tersebar di banyak /24.

**Kapan gagal:** `dns.resp.ttl` memuat TTL semua record jawaban, termasuk CNAME, sehingga `t[1]` bisa berupa TTL CNAME, bukan TTL record A; jawaban dari cache resolver tidak lewat egress, sehingga rotasi yang terjadi selama cache masih berlaku tidak terlihat; dan double flux yang memutar name server butuh analisis record NS, yang tidak tercakup filter ini [S8].

### 2.5 User-Agent dan header HTTP

Bagian ini menjawab pertanyaan kelima Sari lewat tiket `SOC-2027-0623`, lalu memakai pola yang sama untuk memeriksa `JKT-WS-2021` dari bagian 2.3.

```
http.user_agent
http.request.method == "POST"
```

- Ambil daftar UA unik; cari yang kosong, khas tool, atau tidak lazim.

```
tshark -r capture.pcap -Y "http.request" -T fields -e http.host -e http.user_agent -e http.request.uri
```

- Cara membaca: UA kosong atau khas tool pada trafik yang seharusnya browser, atau POST berulang ke satu endpoint dengan body tersandi, adalah sinyal C2. UA bisa dipalsukan, jadi timbang dengan konteks.

#### Langkah 1: ritme POST di log proxy

**Tujuan:** untuk setiap pasangan klien dan path yang menerima POST berulang, hitung jumlah, median, minimum, dan maksimum jarak antar-request, beserta User-Agent dan jumlah host tujuan.

```
index=proxy sourcetype=squid:access http_method=POST
    earliest="05/06/2027:00:00:00" latest="05/10/2027:08:00:00"
| sort 0 src uri_path _time
| streamstats current=f last(_time) AS prev BY src uri_path
| eval gap=_time-prev
| stats count AS posts median(gap) AS med_gap min(gap) AS min_gap max(gap) AS max_gap
        values(http_user_agent) AS ua dc(dest) AS dests BY src uri_path
| where posts >= 24 AND (max_gap - min_gap) <= 120
| sort - posts
```

| Bagian | Fungsi |
|---|---|
| `sort 0 src uri_path _time` | Urutkan semua event (tanpa batas 10.000) per klien dan path, menurut waktu |
| `streamstats current=f last(_time) AS prev BY src uri_path` | Waktu request sebelumnya dari klien dan path yang sama |
| `eval gap=_time-prev` | Jarak antar-request dalam detik |
| `median`, `min`, `max` | Ritme dan seberapa rapat jitter-nya |
| `dc(dest)` | Berapa nama host tujuan dipakai untuk path yang sama |
| `where posts >= 24 AND (max_gap - min_gap) <= 120` | Minimal 24 POST dengan rentang jarak paling lebar dua menit |

Keluaran ilustrasi (dipangkas dari 7 baris; lima lainnya agent monitoring dan sinkronisasi kalender yang sudah dikenal):

```
src          uri_path   ua                                                   posts  med_gap  min_gap  max_gap  dests
10.10.60.54  /v1/push   python-requests/2.32.3                                 553      300      299      301      1
10.10.60.51  /api/sync  Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1)      89     3601     3572     3628      5
```

**Cara membaca hasil:**

- **`10.10.60.54` (`JKT-WS-2024`).** 553 POST ke `ingest.netstatus.example/v1/push` sejak Sabtu 10:00 sampai Senin 08:00: 46 jam, 552 jarak masing-masing 300 detik, dengan selisih paling banyak satu detik. UA `python-requests` jujur menyebut dirinya skrip. Rule menangkapnya karena UA non-browser.
- **`10.10.60.51` (`JKT-WS-2021`).** 89 POST ke `/api/sync`, satu per jam dengan jitter sekitar 30 detik ke dua arah, ke lima nama host berbeda yang semuanya nama DGA yang hidup dari bagian 2.3. UA menyebut Internet Explorer 7 di Windows NT 6.1. Request Edge dari host yang sama di log proxy memakai token `Windows NT 10.0`, jadi UA ini tidak cocok dengan host-nya. Rule UA tidak menangkapnya karena string itu terlihat seperti browser.

Dua baris dengan ritme sama memperoleh label berbeda karena konteksnya. Tabel berikut menaruh keduanya berdampingan; baca baris terakhir.

| Konteks | `JKT-WS-2024` | `JKT-WS-2021` |
|---|---|---|
| Pemilik dan fungsi | PC NOC, skrip status link yang dipasang engineer on-call Sabtu pagi | PC Keuangan |
| UA | Non-browser, jujur | Browser lama, tidak cocok dengan host |
| Tujuan | Satu domain vendor status page yang dikontrak NOC, terlihat sejak 2025 | Lima nama acak, satu per hari, satu IP |
| Prevalence | Skrip sama di `jkt-noc-mon01` sejak 2025 | Satu host |
| Sinyal kedua | Tidak ada | DGA (2.3) dan unduhan payload (2.6) |
| Label | Jinak terkonfirmasi oleh Bambang | Perlu eskalasi |

Satu catatan untuk `JKT-WS-2024`: endpoint vendor itu memakai HTTP polos, dan pcap egress memperlihatkan header `Authorization` berisi token API di setiap request. Catat keberadaannya, bukan nilainya, dan minta NOC beralih ke HTTPS dan mengganti token. Itu temuan kebersihan, bukan insiden.

#### Langkah 2: isi POST di pcap egress

**Tujuan:** memastikan POST `JKT-WS-2021` di pcap dan membaca header yang tidak dicatat proxy.

```
tshark -r /cases/2027-05-10-dnshttp/egress-http.pcap \
  -Y 'ip.dst == 203.0.113.168 && http.request.method == "POST"' \
  -T fields -e frame.time -e http.host -e http.user_agent -e http.content_type \
  -e http.content_length -e http.referer | head -3
```

Keluaran ilustrasi:

```
May  8, 2027 00:41:07.512 WIB  yodsxyzljbncgk.test  Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1)  application/octet-stream  420
May  8, 2027 01:40:41.088 WIB  yodsxyzljbncgk.test  Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1)  application/octet-stream  412
May  8, 2027 02:41:22.930 WIB  yodsxyzljbncgk.test  Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.1)  application/octet-stream  428
```

**Cara membaca hasil:** 84 POST di jendela pcap, satu per jam, body 412 sampai 428 byte bertipe `application/octet-stream`, kolom Referer kosong, dan balasan selalu 64 byte. Follow HTTP Stream memperlihatkan body berupa teks mirip base64. Isinya tidak didekode dan tidak disimpan di catatan; untuk keperluan IR cukup ukurannya, waktunya, dan hash pcap cuplikannya. Ukuran yang kecil dan stabil konsisten dengan check-in, bukan pengiriman data dalam jumlah besar, tetapi itu tetap indikator; exfiltration dibahas di Day 12.

**Variasi:** `tshark -r ... -q -z http_req,tree` memberi ringkasan request per host server, dan `-z http,tree` memberi distribusi metode dan status [S12]; berguna untuk melihat sekilas apakah ada host yang hanya menerima POST.

**Kapan gagal:** C2 memakai HTTPS ke domain yang tidak didekripsi proxy, sehingga UA dan path tidak terlihat dan hanya `CONNECT` yang tercatat (Day 06); jitter dibuat lebar (misalnya 50%) sehingga `max_gap - min_gap` melampaui ambang; path berubah tiap request sehingga pengelompokan per `uri_path` memecah satu beacon menjadi banyak baris; dan proxy mencatat waktu dalam detik penuh sehingga jitter kecil tidak terlihat.

### 2.6 Unduhan payload dan MIME

Bagian ini menjawab pertanyaan keenam Sari: file apa yang dikarantina MDE di `JKT-WS-2023`, dan siapa lagi yang menerimanya.

```
http.response.code == 200 and http.content_type
http.request.uri contains ".exe"
```

- Cari GET ke executable/arsip, dan response yang Content-Type-nya tak cocok isi.
- Export Objects (File > Export Objects > HTTP) memperlihatkan file; magic byte MZ = PE meski ekstensi/Content-Type lain.
- Cara membaca: unduhan executable dari IP langsung/domain baru tanpa konteks navigasi = kandidat payload. Catat hash dan metadata; jangan simpan/jalankan payload.

#### Langkah 1: siapa saja yang mengunduh, dari log proxy

**Tujuan:** semua request ke domain asal file selama retensi proxy, dan kapan domain itu pertama kali terlihat.

```
index=proxy sourcetype=squid:access dest="berkas-tagihan.example"
    earliest="04/10/2027:00:00:00" latest="05/10/2027:08:00:00"
| table _time src user http_method url status bytes http_content_type http_user_agent http_referrer
| sort _time
```

Keluaran ilustrasi:

```
_time                src          user           http_method  url                                                  status  bytes   http_content_type  http_user_agent                       http_referrer
2027-05-06 15:31:08  10.10.60.51  meila.rahayu   GET          http://berkas-tagihan.example/dl/tagihan-mei-2027.pdf  200     287744  application/pdf    Mozilla/5.0 (Windows NT 10.0; ...) Edg/...  -
2027-05-07 09:12:05  10.10.60.53  yusuf.pranata  GET          http://berkas-tagihan.example/dl/tagihan-mei-2027.pdf  200     287744  application/pdf    Mozilla/5.0 (Windows NT 10.0; ...) Edg/...  -
```

**Cara membaca hasil:**

- Hanya dua request selama 30 hari, keduanya ke URL yang sama, dari dua workstation Keuangan, dengan ukuran balasan sama persis. First-seen domain ini Kamis 15:31; data registrasi domain menunjukkan didaftarkan Rabu 2027-05-05.
- UA adalah Edge dan Referer kosong. Keduanya wajar untuk pengguna yang mengklik tautan dari aplikasi email desktop (bagian 1.5), jadi unduhan ini sendiri tidak terlihat aneh dari sisi header. Yang aneh ada di tempat lain: domain berumur satu hari, TTL 60 (bagian 2.4), dan isi file.
- Request pertama dari `JKT-WS-2021` terjadi sembilan menit sebelum percobaan DGA pertama (15:40, bagian 2.3). Itu korelasi waktu, bukan bukti eksekusi; host tanpa MDE tidak punya catatan proses di SOC.
- Unduhan Kamis tidak ada di pcap (sudah tertimpa). Unduhan Jumat 09:12 ada.

#### Langkah 2: isi file di pcap egress

**Tujuan:** membuktikan tipe file dari byte awalnya dan menghitung hash dari salinan yang lewat jaringan.

Filter Wireshark untuk menemukan respons yang membawa executable meski Content-Type-nya lain:

```
ip.addr == 203.0.113.169 && http.response.code == 200 && http.file_data[0:2] == 4d:5a
```

| Bagian | Fungsi |
|---|---|
| `ip.addr == 203.0.113.169` | Hanya percakapan proxy dengan server asal file |
| `http.response.code == 200` | Hanya respons berhasil [S1] |
| `http.file_data[0:2] == 4d:5a` | Dua byte pertama body adalah `MZ` [S1][S15]. `http.file_data` adalah body setelah reassembly dan dekompresi, jadi slice ini membaca byte file, bukan byte paket |

Variasi yang lebih toleran: `http.file_data contains "This program cannot be run in DOS mode"`, string stub default yang dicantumkan spesifikasi PE [S14]. Stub bisa diganti saat linking, jadi tidak adanya string ini tidak membuktikan file bukan PE.

Keluaran ilustrasi: satu frame cocok, Jumat 2027-05-07 09:12:05, `Content-Type: application/pdf`, `Content-Length: 287744`. Di panel bytes, body diawali `4D 5A`, dan di offset `0x3c` terdapat nilai yang menunjuk ke `50 45 00 00` (`PE\0\0`).

Lalu `File > Export Objects > HTTP` dengan Text Filter `tagihan`. Daftar objek memperlihatkan Hostname `berkas-tagihan.example`, Content Type `application/pdf`, Size 287 kB, Filename `tagihan-mei-2027.pdf` [S13]. Kolom Content Type itu datang dari header server, jadi tetap "PDF" walaupun isinya PE. Simpan objek ke `/cases/2027-05-10-dnshttp/evidence/` (bukan ke repo, bukan ke folder yang disinkronkan), lalu:

```
sha256sum /cases/2027-05-10-dnshttp/evidence/tagihan-mei-2027.pdf
file /cases/2027-05-10-dnshttp/evidence/tagihan-mei-2027.pdf
```

Keluaran ilustrasi:

```
a91a44e0d296377c887cab467c0bcdb42f875925c7d5a669798043eaabe9514d  /cases/2027-05-10-dnshttp/evidence/tagihan-mei-2027.pdf
/cases/2027-05-10-dnshttp/evidence/tagihan-mei-2027.pdf: PE32+ executable (GUI) x86-64, for MS Windows
```

**Cara membaca hasil:** hash SHA-256 sama dengan hash file yang dikarantina MDE di `JKT-WS-2023`. Nama berakhiran `.pdf`, header menyatakan PDF, isinya executable Windows. Tiga lapis label berbohong; hanya byte file yang tidak.

#### Langkah 3: konfirmasi dengan Zeek offline (opsional)

Zeek belum berjalan sebagai sensor, tetapi `jkt-nsm-ws01` punya Zeek untuk analisis offline. Menjalankannya pada cuplikan pcap memberi kolom yang dibutuhkan tanpa klik:

```
cd /cases/2027-05-10-dnshttp/zeek && zeek -C -r ../egress-http.pcap
zeek-cut ts host uri user_agent resp_mime_types resp_fuids < http.log | grep berkas-tagihan
zeek-cut fuid mime_type seen_bytes total_bytes < files.log | grep x-dosexec
```

- `-r` membaca pcap; `-C` mengabaikan checksum yang salah, yang sering terjadi pada paket hasil offload kartu jaringan.
- `zeek-cut` memilih kolom dari log berformat TSV.
- `resp_mime_types` di `http.log` dan `mime_type` di `files.log` berasal dari isi, sehingga memperlihatkan `application/x-dosexec` walaupun header menyebut PDF [S11]. Pemakaian Zeek lebih lengkap ada di Day 08.

**Variasi:** cari semua respons PE dari tujuan yang belum pernah terlihat, bukan hanya domain ini: `http.file_data[0:2] == 4d:5a && !(http.host contains "windowsupdate")` lalu tinjau host-nya satu per satu. Pengecualian berbasis nama seperti itu hanya contoh; gunakan daftar updater yang dikenal di lingkunganmu.

**Kapan gagal:** unduhan lewat HTTPS yang tidak didekripsi proxy, sehingga isi tidak ada di pcap egress (Day 06); file dikirim dalam arsip terenkripsi atau terkompresi tambahan sehingga byte awalnya bukan `MZ`; transfer terpotong karena paket hilang di SPAN atau TAP, sehingga Export Objects menyimpan file tidak utuh dan hash-nya berbeda; dan ring buffer sudah menimpa transfer, seperti unduhan Kamis.

### 2.7 Membedakan dari layanan sah

Bagian ini menyatukan lima tiket menjadi keputusan, menjawab pertanyaan ketujuh Sari sebelum stand-up.

```
# periksa domain/IP terhadap reputasi dan daftar layanan dikenal
dns.qry.name contains "<domain>"
```

- Bandingkan domain/IP anomali dengan daftar CDN, DoH provider, updater yang dikenal.
- Cara membaca: trafik ke penyedia DoH atau CDN sah bukan tunneling/fast flux jahat; nama dan rentang IP yang dikenal membedakannya. Reputasi domain/IP (threat intel) membantu, tapi string acak sendiri bukan bukti.

**Tujuan:** satu query prevalence dan first-seen untuk semua tujuan yang muncul di tiket, supaya pertanyaan konteks di bagian 1.8 dijawab dengan angka yang sama.

```
index=proxy sourcetype=squid:access
    earliest="04/10/2027:00:00:00" latest="05/10/2027:08:00:00"
    (dest="berkas-tagihan.example" OR dest="ingest.netstatus.example" OR dest="edge.vidconf.example"
     OR dest="cjljpwkfppwfbi.example" OR dest="yodsxyzljbncgk.test"
     OR dest="liounebubzpkgexs.example" OR dest="upkfcpiqzrqlc.test")
| stats dc(src) AS clients count AS requests min(_time) AS first_seen BY dest
| convert ctime(first_seen)
| sort clients
```

Keluaran ilustrasi:

```
dest                      clients  requests  first_seen
berkas-tagihan.example          2         2  05/06/2027 15:31:08
cjljpwkfppwfbi.example          1         24  05/07/2027 00:41:01
liounebubzpkgexs.example        1         24  05/09/2027 00:41:02
upkfcpiqzrqlc.test              1          8  05/10/2027 00:41:02
yodsxyzljbncgk.test             1         24  05/08/2027 00:41:07
ingest.netstatus.example        2       1108  04/10/2027 00:00:41
edge.vidconf.example          612    2914406  04/10/2027 00:00:03
```

**Cara membaca hasil:** tujuan yang berbahaya punya prevalence satu atau dua dan first-seen minggu ini; tujuan jinak punya prevalence tinggi atau riwayat sejak awal retensi. `ingest.netstatus.example` punya dua klien: `JKT-WS-2024` dan `jkt-noc-mon01`, dan first-seen-nya sama dengan awal rentang pencarian, artinya sudah ada sebelum retensi dimulai. Nama DGA hari Kamis (`fyzcettoeeaagyg.test`) tidak dimasukkan ke daftar ini, tetapi ada di log dengan 9 request.

Keputusan lima tiket. Tabel ini adalah isi yang dibawa ke stand-up; kolom "Dasar" menunjuk bukti, kolom "Label" adalah kesimpulan.

| Alert | Host | Indikator | Dasar | Label |
|---|---|---|---|---|
| `SOC-2027-0620` | `JKT-WS-2023` | File PE berlabel PDF dari domain berumur satu hari, TTL 60 | Proxy, pcap, hash cocok MDE (2.4, 2.6) | Perlu eskalasi: file berbahaya terunduh; MDE mengkarantina sebelum eksekusi, tidak ada query DGA dari host ini |
| `SOC-2027-0621` | `JKT-WS-2020` | 2.412 nama unik dalam satu jam | Nama terstruktur, zona internal, IPAM, job terjadwal (2.3) | Jinak terkonfirmasi (Bambang): inventaris usang |
| `SOC-2027-0622` | `JKT-WS-2022` | TXT subdomain 47 karakter | Format tetap, 7 klien satu tim, vendor dikenal (2.1, 2.2) | Jinak terkonfirmasi (tim IT): lisensi GIS |
| `SOC-2027-0623` | `JKT-WS-2024` | UA `python-requests`, POST tiap 300 detik | Pemilik, vendor kontrak, prevalence (2.5) | Jinak terkonfirmasi (Bambang), dengan temuan token di HTTP polos |
| `SOC-2027-0624` | `JKT-WS-2021` | NXDOMAIN nama acak per jam, POST tiap jam dengan UA tidak cocok, unduhan file sama | Pcap, log resolver, log proxy (2.3, 2.5, 2.6) | Perlu eskalasi: kemungkinan besar terinfeksi, host tanpa MDE |

**Kapan gagal:** daftar "layanan dikenal" tidak dirawat, sehingga CDN baru dicurigai setiap minggu atau, lebih buruk, domain berbahaya yang menumpang layanan populer dianggap jinak karena prevalence-nya tinggi; dan reputasi domain dari feed dipakai sebagai vonis, padahal domain yang baru didaftarkan biasanya belum punya reputasi apa pun.

### 2.8 Laporan ke Sari, eskalasi, dan IOC untuk NOC

Bagian ini adalah keluaran akhir Day: catatan untuk Sari, eskalasi ke Dimas, dan daftar IOC untuk Bambang. Pukul 10:40, Dimas menyatakan `INC-2027-064` dengan cakupan awal `JKT-WS-2021` dan `JKT-WS-2023`.

```
INC-2027-064  dinyatakan Senin 2027-05-10 10:40 (Dimas Prasetyo)
Ringkasan     : File executable berlabel PDF diunduh dua workstation Keuangan dari domain
                baru. Satu host (JKT-WS-2021, tanpa MDE) menunjukkan DGA dan POST berkala
                sejak Kamis 15:40; satu host (JKT-WS-2023) dikarantina MDE sebelum eksekusi.
Timeline      : Rab 05-05      berkas-tagihan.example didaftarkan (data registrasi)
                Kam 05-06 15:31 JKT-WS-2021 GET /dl/tagihan-mei-2027.pdf (proxy)
                Kam 05-06 15:40 percobaan DGA pertama dari 10.10.60.51 (index=dns)
                Kam 05-06 15:41 POST pertama /api/sync ke nama DGA yang hidup (proxy)
                Kam 05-06 20:10 paket tertua yang masih ada di ring buffer jkt-pcap01
                Jum 05-07 09:12 JKT-WS-2023 GET URL yang sama; MDE karantina 09:12:31
                Sen 05-10 07:41 POST terakhir yang tercatat sebelum laporan
Bukti jaringan: egress-dns.pcap, egress-http.pcap (SHA-256 di HASHES.txt);
                tagihan-mei-2027.pdf SHA-256 a91a44e0d296377c887cab467c0bcdb42f875925c7d5a669798043eaabe9514d
Indikator vs kesimpulan:
                Indikator: DGA 250 nama/5 hari, 1 IP tujuan; POST per jam UA tidak cocok; PE berlabel PDF
                Belum terbukti: eksekusi file di JKT-WS-2021, isi POST, data yang mungkin keluar
Di luar cakupan: trafik sebelum Kam 20:10 di pcap; HTTPS yang tidak didekripsi; host di luar
                kantor (VPN split tunnel); query DoH
Tindak lanjut : IR: triage host JKT-WS-2021 (tanpa MDE); cek email gateway untuk penerima
                tautan lain; cek apakah ada klien lain yang POST ke 203.0.113.168 lewat jalur
                selain proxy (firewall, flow NOC)
```

**Daftar IOC untuk NOC (defang).** Tingkat keyakinan dan risiko pemblokiran ditulis per baris, supaya Bambang bisa memilih tindakan.

| IOC | Jenis | Keyakinan | Tindakan yang disarankan | Risiko efek samping |
|---|---|---|---|---|
| `berkas-tagihan[.]example` | Domain unduhan | Tinggi (hash cocok MDE) | Sinkhole di `jkt-res01`/`jkt-res02` ke `jkt-sink01` (`10.20.99.99`), blok di proxy | Rendah |
| `203.0.113[.]169` | IP unduhan | Sedang | Blok di `jkt-fw01` setelah dicek apakah IP dipakai bersama domain lain | Sedang bila shared hosting |
| `203.0.113[.]168` | IP C2 | Tinggi untuk aktivitas ini | Blok di `jkt-fw01` dan proxy; pantau sinkhole untuk host lain | Sedang bila shared hosting |
| Lima nama DGA yang hidup (`cjljpwkfppwfbi[.]example`, `yodsxyzljbncgk[.]test`, `liounebubzpkgexs[.]example`, `upkfcpiqzrqlc[.]test`, `fyzcettoeeaagyg[.]test`) | Domain C2 | Tinggi, tetapi berumur satu hari | Sinkhole; jangan berharap ini menghentikan DGA | Rendah |
| SHA-256 `a91a44e0...9514d` | Hash file | Tinggi | Custom indicator di MDE (block and remediate) | Rendah |

Dua catatan untuk Bambang. Pertama, memblokir nama DGA hanya menutup nama yang sudah lewat; nama besok belum diketahui, sehingga blok IP dan sinkhole yang mencatat siapa yang datang lebih berguna. ATT&CK juga mencatat bahwa mendaftarkan atau memblokir semua kemungkinan domain DGA tidak praktis, dan menyebut sinkhole lokal sebagai cara murah mengurangi risiko [S3]. Kedua, sebagai ISP, PT JAB juga melayani resolver pelanggan; advisory fast flux 2025 mendorong ISP membagikan indikator lebih awal dan memberi tahu pelanggan bila aktivitas jahat terkonfirmasi [S8]. Apakah resolver pelanggan ikut diperiksa adalah keputusan NOC, Legal, dan DPO karena menyangkut data pelanggan (Day 01 bagian 1.7), bukan langkah otomatis dari tiket ini.

**Balasan untuk Sari (10:55).**

> "Lima tiket sudah dipilah. Jinak tiga: 0621 job inventaris NOC dengan nama switch lama (minta NOC perbarui CSV), 0622 lisensi GIS di laptop baru (sudah masuk allowlist per host), 0623 skrip status NOC (jinak, tapi token API lewat HTTP polos, minta diganti). Eskalasi dua dan sudah jadi INC-2027-064: 0620 file PE berlabel PDF dari domain baru, dan 0624 ternyata JKT-WS-2021 yang mengunduh file yang sama Kamis lalu dan sejak itu DGA tiap jam plus POST ke 203.0.113.168. Pcap memang dibutuhkan: rcode NXDOMAIN dan isi file tidak ada di log resolver maupun proxy. Tapi pcap tidak tahu kliennya, jadi atribusi tetap dari index=dns dan index=proxy. Unduhan Kamis sudah tertimpa di ring buffer; untungnya log proxy menyimpan 30 hari. IOC untuk Bambang sudah di tiket, defang, dengan catatan risiko blok IP."

**Kapan gagal:** laporan menulis "terinfeksi" sebagai fakta padahal belum ada bukti dari host; IOC dikirim tanpa defang lalu terklik di chat; atau baris "di luar cakupan" dihapus sehingga pembaca mengira semua jalur keluar sudah diperiksa.

## 3. Lab praktik (di VM lab terisolasi)

**Prasyarat:** Wireshark 4.6.x; pcap lab/publik berisi anomali DNS/HTTP (mis. sampel latihan DNS tunneling atau unduhan malware; cek lisensi); tidak ada pcap kerja. Untuk membuat trafik sendiri: jaringan host-only `192.168.56.0/24` dengan VM Linux sebagai sensor dan server lab (`192.168.56.53`, menjalankan resolver lab seperti dnsmasq atau BIND untuk zona `lab.test`, dan `python3 -m http.server`), VM Windows dengan Edge atau Chrome, semua dengan snapshot. Rekam di VM sensor dengan `tshark -i <interface-host-only> -w lab05.pcap` selama latihan. Semua trafik di bawah dibuat sendiri dan jinak; tidak ada tool tunneling atau sampel malware yang dipakai.

1. **DNS tunneling.** Cari query panjang/TXT ke satu domain induk (bagian 2.1-2.2). Ukur volume dan panjang; bandingkan normal. Untuk membuat pembanding sendiri, dari VM Linux kirim 200 query TXT dengan label acak 48 karakter ke zona lab yang tidak ada: `for i in $(seq 1 200); do dig +short "$(head -c 30 /dev/urandom | base32 | tr -d '=' | tr 'A-Z' 'a-z').lab.test" TXT @192.168.56.53; done`. 30 byte acak menjadi tepat 48 karakter base32 tanpa padding. Lalu kirim 50 query dengan format tetap seperti bagian 2.2 (satu ID tetap 32 karakter ditambah label waktu). Bandingkan `min_len`, `avg_len`, dan `max_len` keduanya.
2. **DGA.** Hitung NXDOMAIN per host dan periksa nama (bagian 2.3). Tentukan apakah acak dan teratur. Buat dua kelompok nama yang tidak ada: 50 nama acak 12 sampai 16 huruf diulang tiga kali dengan jeda 5 menit, dan 50 nama terstruktur (`lab-sw-01.lab.test` sampai `lab-sw-50.lab.test`). Jalankan perintah tshark dan gawk bagian 2.3; pastikan jumlah per nama sama dengan jumlah ulangan untuk kelompok acak. Lalu set TTL negatif zona lab (field MINIMUM SOA) ke 600 detik dan ulangi dengan jeda 2 menit: hitung berapa ulangan yang tidak sampai ke server upstream karena negative cache.
3. **Probe browser.** Tutup semua jendela browser di VM Windows, rekam, lalu buka browser dan ubah alamat IP VM sekali. Cari query satu label 7 sampai 15 huruf dengan `dns.count.labels == 1 && dns.flags.response == 0`. Catat berapa query muncul per peristiwa, apakah suffix ditambahkan, dan apakah kebijakan `IntranetRedirectBehavior` (bila diset ke 1 lewat registry lab) menghilangkannya.
4. **Fast flux.** Bila ada, periksa satu domain dengan banyak IP dan TTL rendah (bagian 2.4). Di zona lab, buat `flux.lab.test` dengan 10 record A di `192.168.56.0/24` dan TTL 5 detik, lalu `flap.lab.test` dengan satu record A dan TTL 60. Query keduanya tiap 10 detik selama 10 menit dan jalankan perintah bagian 2.4. Tuliskan kenapa yang pertama hanya menyerupai fast flux di lab (semua IP satu /24 milik sendiri).
5. **HTTP UA/header.** Daftar UA unik; tandai yang aneh (bagian 2.5). Periksa POST berulang. Kirim POST tiap 30 detik selama 15 menit dengan dua UA berbeda: `curl -s -A "lab-agent/1.0" -d "status=ok" http://192.168.56.53:8000/push` dan versi dengan UA browser lama. `http.server` membalas 501 untuk POST; itu tidak masalah karena yang diamati adalah request. Hitung median, minimum, dan maksimum jarak dengan tshark (`-e frame.time_epoch`) dan awk.
6. **Payload.** Cari unduhan executable; periksa magic byte via Export Objects (bagian 2.6). Catat hash, jangan simpan payload. Untuk latihan tanpa malware: salin satu executable bawaan Windows yang tidak berbahaya ke server lab, ganti namanya menjadi `laporan.pdf`, lalu unduh dari VM Windows lewat browser. Terapkan filter `http.file_data[0:2] == 4d:5a`, Export Objects, `sha256sum`, dan bandingkan dengan hash file asli. Perhatikan kolom Content Type yang mengikuti tebakan `http.server` dari ekstensi.
7. **Sah vs berbahaya.** Nilai domain/IP terhadap layanan dikenal dan reputasi (bagian 2.7). Nyatakan kemungkinan jinak.
8. **Rangkum.** Tulis 3-5 baris: anomali apa, sinyalnya, dan apakah berbahaya atau butuh konteks lebih. Lalu isi tabel keputusan seperti bagian 2.7 untuk trafik lab-mu dan satu catatan laporan seperti bagian 2.8 (tanpa nama atau data nyata).

**Hasil yang sebaiknya tersimpan:**

- Sinyal tunneling (panjang, volume, tipe record) dikenali dan diukur, termasuk perbandingan sebaran panjang data acak dan ID berformat tetap.
- DGA dibedakan dari typo/CDN lewat NXDOMAIN + keacakan, beserta catatan berapa ulangan yang hilang karena negative cache.
- Jumlah dan bentuk probe browser per peristiwa, dan pengaruh kebijakan browser terhadapnya.
- Fast flux dibedakan dari CDN sah lewat IP/nama.
- UA/header HTTP mencurigakan ditandai, dengan catatan UA bisa palsu; ritme POST diukur dengan angka.
- Payload dikenali lewat magic byte, bukan ekstensi; hash dicatat, payload tidak disimpan.
- Anomali ditimbang terhadap layanan sah; kemungkinan jinak dinyatakan.
- Satu tabel keputusan dan satu catatan laporan dengan baris "di luar cakupan".

**Variasi tantangan:** dalam satu pcap infeksi, susun urutan: unduhan payload (HTTP) lalu C2 (DNS/HTTP), dan tentukan domain/IP mana yang jadi IOC. Tulis daftar IOC yang di-defang (domain, IP, hash) dan nyatakan di mana bukti kuat dan di mana masih kandidat yang perlu korelasi threat intel. Untuk pcap publik dari situs latihan analisis infeksi, ikuti metode yang sama tanpa menyalin jawaban penulisnya: tulis dulu temuanmu, baru bandingkan [S4].

## 4. Troubleshooting

Tabel ini memuat masalah yang sering muncul saat menganalisis anomali DNS dan HTTP. Cari gejalanya di kolom kiri; baris yang ditandai PT JAB berasal dari kasus Day ini.

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Query panjang tapi sah | DoH, CDN, layanan dengan subdomain dinamis | Cek domain induk dan reputasi |
| Banyak NXDOMAIN tapi bukan DGA | Salah konfigurasi, search domain | Periksa keacakan nama dan keteraturan |
| Fast flux mirip CDN | CDN sah pakai banyak IP | Cek rentang IP dan nama domain dikenal |
| UA aneh tapi sah | Updater, tool internal sah | Korelasi dengan aplikasi dikenal |
| Payload tak terlihat | Terenkripsi (HTTPS) | DNS/HTTP polos tak cukup; lihat Day 06 TLS |
| Export Objects kosong | Transfer terpotong/terenkripsi | Perlu capture lengkap dan polos |
| `reply_code` kosong di semua event (PT JAB) | Resolver hanya mengirim query log | Hitung rcode dari pcap atau tambah kanal log jawaban; jangan tulis "terbukti NXDOMAIN" dari query log (bagian 1.1) |
| Semua DNS di pcap berasal dari dua resolver dan semua HTTP dari proxy (PT JAB) | Sensor di egress melihat resolver atau proxy, bukan klien (Day 03 bagian 1.4) | Atribusi lewat `index=dns` atau `index=proxy` dengan waktu dan nama (bagian 2.3) |
| Jumlah NXDOMAIN di pcap jauh lebih kecil dari jumlah query di log | Negative cache di resolver [S6] | Bandingkan jeda ulangan dengan TTL SOA di authority section |
| Kejadian yang dicari tidak ada di pcap (PT JAB) | Ring buffer sudah menimpanya | Cek paket tertua (`capinfos` pada file ring tertua); pakai log yang retensinya lebih panjang |
| Kolom Content Type di Export Objects menyebut PDF untuk file PE | Kolom itu dari header server [S13] | Periksa byte awal (`http.file_data[0:2] == 4d:5a`) |
| `http.file_data` kosong atau tidak diawali `MZ` | Reassembly atau dekompresi dimatikan di preferensi HTTP/TCP, atau file dibungkus arsip | Aktifkan reassembly dan dekompresi body; periksa magic byte arsip |
| `parent` salah untuk domain `.co.id` | Regex dua label terakhir | Pakai daftar public suffix atau tambahkan kasus khusus |
| Rule UA tidak menangkap beacon (PT JAB) | Malware memakai string browser | Ukur ritme dan cocokkan UA dengan inventaris OS host (bagian 2.5) |
| `strftime` tidak dikenal | Memakai `awk` atau `mawk`, bukan `gawk` | Jalankan dengan `gawk`, atau cetak epoch lalu konversi di tempat lain |

## 5. Kesalahan umum dan jebakan

- **Mengira semua query panjang = tunneling.** DoH dan CDN juga panjang; cek domain induk dan volume. Nama terpanjang di egress sering reverse lookup IPv6 (72 karakter).
- **Mengira UA aneh = bukti.** UA bisa dipalsukan; sinyal, bukan bukti. Sebaliknya, UA yang terlihat normal juga tidak membuktikan apa-apa: beacon `JKT-WS-2021` lolos rule UA karena memakai string browser [S7].
- **Percaya ekstensi/Content-Type** untuk tipe file; pakai magic byte. Kolom Content Type di Export Objects juga hanya header [S13].
- **Menyimpan atau menjalankan payload.** Catat hash dan metadata; jangan simpan di repo.
- **Tidak menyatakan kemungkinan jinak.** Banyak anomali mirip layanan sah; timbang konteks dan reputasi.
- **Menulis "terbukti NXDOMAIN" dari query log.** Query log hanya memuat pertanyaan; tulis apa yang benar-benar terbukti dan dari sumber apa.
- **Mencari klien di pcap egress.** Di balik resolver dan proxy, klien tidak ada di paket; atribusi selalu lewat log.
- **Memakai entropi sebagai ambang tunggal pada label pendek.** Nama switch jinak bisa lebih tinggi entropinya daripada nama DGA (bagian 1.7).
- **Menyimpulkan fast flux dari TTL rendah saja.** Satu IP dengan TTL 60 bukan fast flux; hitung jumlah IP dan sebarannya [S8].
- **Menganggap "tanpa Referer" selalu mencurigakan.** Klik dari aplikasi email desktop atau perpindahan dari HTTPS ke HTTP juga menghilangkan Referer [S7].
- **Allowlist per domain saja.** Host lain yang tiba-tiba memakai domain yang sama ikut lolos; pakai pasangan domain dan klien.
- **Memblokir IP tanpa mengecek pemakaian bersama.** IP C2 di shared hosting bisa membawa ratusan domain sah.
- `[komunitas, belum terkonfirmasi]` Analis menandai DNS tunneling lewat kombinasi panjang query, entropi, tipe TXT/NULL, dan volume ke satu domain induk; DGA lewat burst NXDOMAIN bernama acak. Heuristik ini umum di NSM; ambang pastinya bergantung baseline lingkungan, perlu dicek.

## 6. Catatan terkini

Bagian ini menampung perubahan sumber, versi, dan tren yang berguna saat membuka dokumen aslinya, tetapi tidak mengubah langkah di atas.

- DoH/DoT makin umum, memindahkan DNS ke HTTPS sehingga query tak lagi terlihat polos; deteksi bergeser ke metadata TLS (Day 06) dan endpoint DoH yang dikenal. DoH, DoT, dan DoQ dibahas di Day 16.
- DGA dan fast flux tetap dipakai; deteksi berbasis entropi dan NXDOMAIN masih relevan.
- Banyak C2 kini meniru trafik sah (domain fronting, CDN) sehingga pembedaan makin bergantung reputasi dan konteks.
- **ATT&CK v20:** T1071.004 versi 1.4 (diubah 3 September 2026), T1568.001 versi 1.1 (24 Oktober 2025), T1568.002 versi 1.2 (12 Mei 2026), T1071.001 versi 1.5 dan T1105 versi 2.6 (keduanya 11 September 2026) [S3][S17]. Halaman teknik kini memuat detection strategy dan analitik bernomor (misalnya DET0419 untuk DGA dan DET0485 untuk fast flux).
- **Advisory fast flux (3 April 2025):** advisory gabungan NSA, CISA, FBI, ASD's ACSC, CCCS, dan NCSC-NZ menyebut fast flux sebagai celah pertahanan di banyak jaringan dan memberi peran khusus untuk ISP dan penyedia protective DNS [S8].
- **Probe Chromium:** pengukuran 2020 menempatkan probe intranet redirect sekitar separuh trafik root [S9]. Dokumentasi kebijakan Edge (diperbarui 2026) masih menulis bahwa pemeriksaan aktif secara default sejak M88 dengan rencana dimatikan di rilis mendatang [S10]; cek status di versi browser yang dipakai.
- **Unit 42 (Mei 2024):** tunneling dipakai juga untuk melacak pembukaan email dan memindai open resolver, bukan hanya C2 dan exfil [S16].
- **Versi alat:** Wireshark 4.6.9 stabil dan 4.4.19 old stable; referensi field `dns` dan `http` yang dipakai di Day ini berlaku sampai 4.6.9 [S1]. Zeek 9.0.0 LTS (14 September 2026), dengan 8.0.10 sebagai LTS sebelumnya [S11].
- Day 06 masuk ke TLS metadata; Day 11-12 ke beaconing dan exfiltration.

## 7. Cheat sheet

```
DNS TUNNEL   query panjang/acak + TXT (type 16)/NULL + volume tinggi ke 1 domain induk | response TXT besar
             label <= 63, nama <= 255 (RFC 1035) ; tunneling: panjang BERVARIASI dekat batas, 1 klien, domain baru
             format tetap (min=avg=max), banyak klien satu tim = layanan (lisensi, reputasi)
DGA          banyak NXDOMAIN (rcode 3) nama ACAK + teratur ; CDN/typo = nama terstruktur, resolve
             jumlah identik per nama per hari = jadwal ; 1 nama hidup per periode ; 1 IP tujuan
NXDOMAIN     di-cache: TTL = min(SOA MINIMUM, TTL SOA) ; egress bisa melihat lebih sedikit dari log
             probe Chromium: 1 label, 7-15 huruf a-z, 3 sekaligus saat start/ganti jaringan
FAST FLUX    1 domain -> banyak IP, TTL rendah, tersebar ; CDN sah = rentang IP dikenal, nama sah
             TTL rendah + 1 IP != fast flux ; fast flux: puluhan-ratusan IP/hari, ganti ~3-5 menit
HTTP UA      kosong/khas tool pada trafik browser = sinyal (bisa dipalsukan)
             UA browser lama yang tidak cocok dengan OS host = sinyal lebih kuat
HTTP C2      POST berulang ke 1 endpoint, body tersandi ; ukur med/min/max gap
REFERER      kosong wajar untuk klik dari aplikasi email, bookmark, HTTPS -> HTTP
PAYLOAD      GET .exe/.dll/.ps1 | magic byte MZ (PE) != Content-Type/ekstensi | IP langsung/domain baru, tanpa navigasi
             http.file_data[0:2] == 4d:5a ; PE\0\0 di offset dari 0x3c ; Export Objects "Content Type" = header
ATRIBUSI     pcap egress = resolver/proxy sebagai sumber -> klien dari index=dns / index=proxy (waktu + nama/URL)
SAH?         DoH, CDN, updater, EDR cloud = mirip anomali ; cek nama/rentang IP dikenal + reputasi
KONTEKS      pemilik | prevalence dc(src) | first-seen | proses | sinyal kedua independen
ATURAN       entropi/panjang = heuristik, bukan bukti ; catat hash, JANGAN simpan payload ; IOC di-defang

tshark  -Y "dns.flags.response == 0" -T fields -e dns.qry.name | sort -u | awk '{print length, $0}' | sort -rn
tshark  -Y "dns.flags.response == 1 && dns.flags.rcode == 3" -T fields -e frame.time_epoch -e dns.qry.name
tshark  -Y "dns.flags.response == 1 && dns.a" -T fields -E aggregator=, -e dns.qry.name -e dns.a -e dns.resp.ttl
tshark  -q -z dns,tree | -z http,tree | -z http_req,tree
SPL     ... | rex field=q "^(?<sub>.+)\.(?<parent>[^.]+\.[^.]+)$" | stats ... dc(src) BY parent
SPL     ... | streamstats current=f last(_time) AS prev BY src uri_path | eval gap=_time-prev
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "Dwi menulis bahwa `JKT-WS-2020` menghasilkan ribuan NXDOMAIN. Karena datanya dari `index=dns`, klaim itu sudah terbukti." Benarkah?

<details><summary>Jawaban</summary>

Tidak. `index=dns` di PT JAB berisi query log resolver yang hanya memuat pertanyaan: klien, nama, dan tipe record, tanpa kode jawaban. Nama-nama itu juga berada di zona internal sehingga tidak lewat pcap egress. Yang bisa ditulis jujur: 2.412 nama unik ditanyakan, dan tidak satu pun ada di IPAM sehingga hampir pasti dijawab NXDOMAIN. Lihat bagian 1.1 dan 2.3.

</details>

**2. Skenario keputusan.** Ringkasan pcap egress menunjukkan 1.176 NXDOMAIN dalam sehari untuk 49 nama acak, semuanya dalam percakapan dengan `10.20.2.53` dan `10.20.2.54`. Langkah pertama yang paling tepat?

- A. Blok `10.20.2.53` dan `10.20.2.54` di firewall karena keduanya sumber query mencurigakan.
- B. Simpan daftar nama sebagai lookup, lalu cari di `index=dns` klien mana yang menanyakan nama-nama itu.
- C. Tutup tiket karena NXDOMAIN berarti domainnya tidak ada, jadi tidak ada koneksi yang berhasil.

<details><summary>Jawaban</summary>

B. Di egress, semua query DNS kantor berasal dari resolver, karena workstation bertanya ke resolver dan resolver yang bertanya ke internet; klien hanya bisa ditemukan lewat query log resolver dengan mencocokkan nama dan waktu. A keliru karena kedua alamat itu adalah resolver PT JAB sendiri; memblokirnya memutus DNS seluruh kantor. C keliru karena DGA memang menghasilkan banyak NXDOMAIN sambil menunggu satu nama yang hidup; di kasus ini satu nama per hari menjawab `203.0.113.168`. Lihat bagian 1.1 dan 2.3.

</details>

**3. Pertanyaan jebakan.** "`berkas-tagihan.example` punya TTL 60 detik, jadi domain itu memakai fast flux." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Fast flux membutuhkan rotasi banyak IP; advisory 2025 menyebut puluhan sampai ratusan IP per hari dengan pergantian kira-kira tiap 3 sampai 5 menit. Domain ini hanya menjawab satu IP (`203.0.113.169`) selama sekitar 84 jam jendela pcap. TTL rendah pada domain baru adalah sinyal kecil bahwa pemiliknya siap memindahkan alamat, bukan fast flux. Sebaliknya, `edge.vidconf.example` dengan 37 IP dan TTL 20 adalah CDN. Lihat bagian 1.4 dan 2.4.

</details>

**4. Skenario keputusan.** Dua host POST berkala lewat proxy: `JKT-WS-2024` dengan UA `python-requests/2.32.3` tiap 300 detik ke satu domain vendor, dan `JKT-WS-2021` dengan UA Internet Explorer 7 tiap sekitar 3.600 detik ke lima nama berbeda. Rule UA hanya memicu untuk `JKT-WS-2024`. Apa yang kamu lakukan?

- A. Eskalasi `JKT-WS-2024` karena rule memicu, dan abaikan `JKT-WS-2021` karena UA-nya browser.
- B. Nilai keduanya dengan konteks: pemilik, tujuan, prevalence, dan sinyal kedua; `JKT-WS-2024` jinak setelah dikonfirmasi pemilik, `JKT-WS-2021` dieskalasi karena UA tidak cocok dengan host, tujuan berganti tiap hari, dan ada DGA serta unduhan PE.
- C. Eskalasi keduanya karena POST berkala adalah tanda C2.

<details><summary>Jawaban</summary>

B. Ritme yang sama memperoleh label berbeda karena konteksnya. A keliru karena rule UA hanya menangkap program yang jujur menyebut dirinya; UA bisa ditulis apa saja. C keliru karena skrip otomasi dan agent monitoring juga POST berkala; mengeskalasi semua POST berkala membuat IR tenggelam dalam false positive. Lihat bagian 1.5 dan 2.5.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Dwi Cahyono (L1), dalam tiga kalimat, kenapa kolom Content Type di Export Objects tidak cukup untuk menyatakan file itu PDF.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Kolom Content Type di Export Objects hanya menyalin header yang dikirim server, jadi server penyerang bisa menulis `application/pdf` untuk file apa pun. Tipe sebenarnya dilihat dari byte awal file: executable Windows selalu diawali `MZ`, dan di kasus 0620 file `tagihan-mei-2027.pdf` diawali `MZ` dengan signature `PE` di dalamnya. Jadi setiap unduhan yang mencurigakan dicek dengan filter `http.file_data[0:2] == 4d:5a` atau perintah `file` pada salinan yang diekspor, lalu dicatat hash-nya tanpa pernah dibuka."

Kesalahan yang sering muncul:
- Mengandalkan ekstensi nama file, yang sama mudahnya dipalsukan.
- Membuka file untuk "memastikan", padahal itu menjalankan barang bukti berbahaya.
- Lupa bahwa `http.file_data` membaca body setelah reassembly dan dekompresi, bukan byte paket mentah.

</details>

**6. Pertanyaan jebakan.** "Label `mfrggzdfmztwq2lknnwg23tpobyxe43u` punya entropi 4,35, lebih tinggi dari semua nama DGA di kasus ini, jadi ini tanda tunneling paling kuat." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Itu ID perangkat base32 dari pemeriksaan lisensi GIS: panjang subdomainnya tetap 47 karakter di setiap query, dipakai tujuh workstation satu tim, enam query per jam per host, ke vendor yang dikenal sejak 2026. Entropi tinggi hanya berarti karakternya merata; data acak, hash, token, dan ID tersandi sama-sama tinggi. Tunneling dibedakan dari panjang yang bervariasi mendekati batas label, volume sangat tinggi, satu klien, dan domain baru. Lihat bagian 1.7 dan 2.2.

</details>

**7. Interview question (English).** "You see a workstation generating hundreds of NXDOMAIN responses for random-looking domains. Walk me through how you would investigate it."

<details><summary>Sample answer</summary>

"First I check where I am seeing it, because that decides what I can attribute. If it comes from a sensor at the egress, the source is usually our recursive resolver, so I take the list of names and timestamps and find the client in the resolver query logs. Then I look at the shape: random labels on registered domains, a list that changes every day, and identical retry counts per name point to a DGA; a single label of seven to fifteen letters points to the Chromium intranet redirect probe; structured names like old switch hostnames with our search suffix point to a stale inventory job. I also account for negative caching, because the resolver answers repeats from cache, so egress counts can be lower than the client's real query count. For a DGA candidate, I look for the one name that resolves and what the host does next: if the same host then talks to that IP through the proxy with a user agent that does not match its OS, and the proxy shows it downloaded a PE disguised as a PDF the day before, I escalate with timeline, defanged IOCs and clear scope, and I state that infection on the host still needs endpoint evidence."

What makes this answer strong: it starts with sensor placement and attribution instead of jumping to a verdict, names concrete benign look-alikes, handles caching effects on counts, and separates indicators from the conclusion while still making a decisive escalation call.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Wireshark display filter reference (dns, http) | https://www.wireshark.org/docs/dfref/ | primer | diakses 2026-10-09 (Day 02); halaman `d/dns.html` dan `h/http.html` dicek ulang 2026-10-22 | Tinggi. Field filter. Referensi berlaku untuk Wireshark 1.0.0 sampai 4.6.9: `dns.qry.name`, `dns.qry.name.len`, `dns.count.labels`, `dns.qry.type`, `dns.flags.rcode`, `dns.flags.response`, `dns.resp.ttl`, `dns.a`, `dns.txt`, `http.user_agent`, `http.content_type`, `http.referer`, `http.file_data` (sejak 2.2.0), `http.response.code` |
| S2 | RFC 1035 (DNS, tipe record, rcode) | https://www.rfc-editor.org/rfc/rfc1035 | primer | diakses 2026-10-09 (Day 03); dicek ulang 2026-10-22 | Tinggi. Batas label 63 dan nama 255 oktet, UDP 512 oktet (2.3.4); rcode 0-5 (4.1.1); tipe A 1, CNAME 5, NULL 10, TXT 16 (3.2.2) |
| S3 | MITRE ATT&CK T1071.004 (Application Layer Protocol: DNS), T1568.002 (Domain Generation Algorithms), T1568.001 (Fast Flux DNS) | https://attack.mitre.org/techniques/T1071/004/ | primer | diakses 2026-10-10; dicek ulang 2026-10-22 (ATT&CK v20) | Tinggi. Definisi teknik; halaman T1568 di https://attack.mitre.org/techniques/T1568/002/ dan https://attack.mitre.org/techniques/T1568/001/. Versi: T1071.004 v1.4, T1568.002 v1.2, T1568.001 v1.1 |
| S4 | malware-traffic-analysis.net (metode analisis infeksi) | https://www.malware-traffic-analysis.net/ | sekunder | diakses 2026-10-09 (Day 02) | Sedang-tinggi. Metode, bukan hasil palsu |
| S5 | Network-Forensics Day 02-04 (Wireshark, protokol, scan) | (lokal) | rujukan internal | 2026-10-09 | Filter dan protokol |
| S6 | RFC 2308: Negative Caching of DNS Queries (DNS NCACHE) | https://www.rfc-editor.org/rfc/rfc2308 | primer | Maret 1998; diakses 2026-10-22 | Tinggi. Definisi NXDOMAIN dan NODATA, SOA di authority section, TTL negatif dari nilai terkecil MINIMUM SOA dan TTL SOA, saran batas satu sampai tiga jam |
| S7 | RFC 9110: HTTP Semantics | https://www.rfc-editor.org/rfc/rfc9110 | primer | Juni 2022 (STD 97); diakses 2026-10-22 | Tinggi. Content-Type dan MIME sniffing (8.3), Referer (10.1.3), User-Agent (10.1.5) |
| S8 | CISA, NSA, FBI, dan mitra: Fast Flux: A National Security Threat (AA25-093A) | https://www.cisa.gov/news-events/cybersecurity-advisories/aa25-093a | primer (advisory pemerintah) | 2025-04-03; diakses 2026-10-22 | Tinggi. Single dan double flux, sinyal deteksi, puluhan sampai ratusan IP per hari, pergantian sekitar 3-5 menit, kemiripan dengan CDN, rekomendasi untuk ISP dan protective DNS |
| S9 | APNIC Blog (Matthew Thomas, Verisign): Chromium's impact on root DNS traffic | https://blog.apnic.net/2020/08/21/chromiums-impact-on-root-dns-traffic | sekunder (blog peneliti operator root) | 2020-08-21; diakses 2026-10-22 | Sedang-tinggi. Perilaku probe intranet redirect dan pengukuran 13 Mei 2020 di satu root server. Data lebih dari 24 bulan; perilaku browser saat ini perlu dicek |
| S10 | Microsoft Learn: Microsoft Edge policy IntranetRedirectBehavior | https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies/intranetredirectbehavior | primer (dokumentasi vendor) | halaman diperbarui 2026-06-15; diakses 2026-10-22 | Tinggi untuk Edge. Edge 88 ke atas, nilai 0-3, default aktif sejak M88 dengan rencana dimatikan |
| S11 | Zeek documentation: dns.log, http.log, files.log; Get Zeek | https://docs.zeek.org/en/master/logs/dns.html | primer | dokumentasi master; diakses 2026-10-22 | Tinggi. Field `rcode_name`, `answers`, `TTLs`, `resp_mime_types`, `resp_fuids`, `mime_type` `application/x-dosexec`; halaman lain di https://docs.zeek.org/en/master/logs/http.html dan https://docs.zeek.org/en/master/logs/files.html; versi dari https://zeek.org/get-zeek/ (9.0.0 LTS, 14 Sep 2026) |
| S12 | tshark man page | https://www.wireshark.org/docs/man-pages/tshark.html | primer | diakses 2026-10-22 | Tinggi. `-T fields`, `-E separator`, `-E aggregator`, `-q`, `-z dns,tree`, `-z http,tree`, `-z http_req,tree` |
| S13 | Wireshark User's Guide: Export Objects | https://www.wireshark.org/docs/wsug_html_chunked/ChIOExportSection.html | primer | diakses 2026-10-22 | Tinggi. Kolom Packet, Hostname, Content Type, Size, Filename; Text Filter |
| S14 | Microsoft Learn: PE Format | https://learn.microsoft.com/en-us/windows/win32/debug/pe-format | primer | halaman diperbarui 2026-09-10; diakses 2026-10-22 | Tinggi. Stub MS-DOS, offset `0x3c`, signature `PE\0\0`, pesan stub default |
| S15 | Wikipedia: DOS MZ executable | https://en.wikipedia.org/wiki/DOS_MZ_executable | sekunder | diakses 2026-10-22 | Sedang. Magic `MZ` (`4D 5A`) di awal header DOS; dikonfirmasi silang dengan PE Format [S14] yang menyebut stub MS-DOS di depan setiap image |
| S16 | Unit 42 (Palo Alto Networks): Leveraging DNS Tunneling for Tracking and Scanning | https://unit42.paloaltonetworks.com/three-dns-tunneling-campaigns/ | sekunder (riset vendor) | 2024-05-13; diakses 2026-10-22 | Sedang-tinggi. Mekanisme subdomain ke authoritative server penyerang, tipe record yang dipakai, kampanye pelacakan dan pemindaian |
| S17 | MITRE ATT&CK T1071.001 (Application Layer Protocol: Web Protocols) dan T1105 (Ingress Tool Transfer) | https://attack.mitre.org/techniques/T1071/001/ | primer | diakses 2026-10-22 (ATT&CK v20) | Tinggi. T1071.001 v1.5 dan T1105 v2.6, keduanya diubah 11 September 2026; halaman T1105 di https://attack.mitre.org/techniques/T1105/ |

**Catatan sumber:** definisi teknik DNS sebagai saluran C2, DGA, dan fast flux mengikuti ATT&CK [S3]; daftar sinyal di tabel bagian 1.2 adalah pengetahuan NSM mapan, bukan kutipan satu sumber. Ambang pasti (panjang query, jumlah NXDOMAIN, TTL) bergantung baseline lingkungan dan perlu dicek. Nama filter Wireshark (`dns.qry.type`, `dns.flags.rcode`, `http.user_agent`) bisa beda antar versi, cek di 4.6.9; field yang dipakai Day ini sudah dicocokkan dengan referensi 4.6.9 [S1]. malware-traffic-analysis dipakai sebagai contoh metode, bukan sumber hasil. Pembedaan dari DoH/CDN/updater bergantung konteks lingkungan. Data probe Chromium [S9] berasal dari 2020; dokumentasi Edge [S10] masih menyebut rencana mematikan pemeriksaan secara default tanpa tanggal, jadi status default di Chrome dan Edge versi terbaru perlu dicek di catatan rilis browser. Halaman Zeek [S11] tidak menjelaskan mekanisme penentuan `mime_type`; klaim bahwa nilainya berasal dari isi file didasarkan pada contoh di halaman itu yang mengenali isi sebagai `application/x-dosexec`. Pernyataan bahwa query log BIND tidak memuat kode jawaban dan opsi kanal log tambahan di resolver perlu dicek di dokumentasi BIND versi resolver-mu. Perilaku penambahan suffix pencarian untuk nama bertitik bergantung setelan DNS client Windows dan belum dicek ke dokumentasi primer. Seluruh isi PT JAB (lima alert, host, user, angka query, hash, nama domain, keputusan, dan `INC-2027-064`) adalah penerapan catatan ini pada organisasi fiktif, bukan hasil eksekusi nyata.
