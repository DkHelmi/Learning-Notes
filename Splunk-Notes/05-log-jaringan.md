---
day: 05
title: 'Log jaringan di Splunk: firewall, proxy/web, DNS, dan VPN'
researched_on: 2026-10-14
versions_checked: 'Splunk Enterprise 10.6 (versi platform tertinggi yang tercantum di halaman kompatibilitas Splunkbase add-on yang dibuka); Splunk Add-on for Palo Alto Networks 4.0.0 (Splunkbase, rilis 14 Agu 2026, CIM 8.x dan 6.x); Palo Alto Networks Add-on for Splunk 8.1.3 (arsip, 24 Mei 2024); Splunk Common Information Model 8.7.0 (Splunkbase, 2 Sep 2026) dengan halaman data model Network Traffic, Web, Network Resolution (DNS), dan Authentication versi 8.7; Splunk Add-on for Squid Proxy 2.1.0 (arsip, 1 Des 2023); Splunk Add-on for ISC BIND 2.0.0 (arsip, 14 Nov 2020); Fortinet FortiGate Add-On for Splunk 1.6.10 (9 Jun 2026); ES 8.7.0'
---

# Day 05: Log jaringan di Splunk (firewall, proxy/web, DNS, dan VPN)

Cakupan: cara empat sumber log jaringan masuk ke Splunk (add-on, sourcetype, pemetaan ke data model CIM) dan cara membaca masing-masing saat triage, termasuk apa yang tidak bisa dijawab tiap sumber, ditambah sudut pandang khusus sebuah ISP yang juga menyimpan log resolver dan trafik pelanggan.

## Ide inti

Empat sumber log jaringan menjawab empat pertanyaan berbeda tentang satu kejadian yang sama. Firewall menjawab "alamat mana menghubungi alamat mana, lewat port apa, diizinkan atau ditolak, dan berapa besar datanya". Proxy atau URL filtering menjawab "halaman apa yang dibuka, oleh user mana, dengan hasil apa". DNS menjawab "nama apa yang dicari sebelum koneksi itu terjadi". VPN menjawab "identitas siapa yang sedang memegang alamat internal itu". Nilai terbesarnya muncul saat empat sumber itu disambungkan dengan dua kunci sederhana, alamat IP dan waktu, dan saat kamu tahu batas masing-masing: firewall tidak melihat isi, proxy hanya melihat nama host saat trafik HTTPS, DNS dari sudut resolver tidak selalu menyebut klien aslinya, dan pemetaan IP ke orang basi dalam hitungan menit.

Kamu sudah mengerjakan pola ini di NOC saat merekonstruksi satu panggilan dari beberapa sumber. CDR di softswitch memberi tahu nomor asal, nomor tujuan, durasi, dan kode penyebab putus, tetapi tidak isi percakapan: itu posisi log firewall. Log aplikasi di server memberi detail isi transaksi: itu posisi log proxy. Lookup nomor sebelum call setup adalah DNS. Dan accounting RADIUS yang memetakan sesi ke pelanggan adalah log VPN. Satu hal lagi yang khas ISP: sebagian log di Splunk-mu bukan tentang karyawan, tetapi tentang pelanggan. Volumenya jauh lebih besar, isinya lebih sensitif, dan kewenangan untuk bertindak atas isinya berbeda.

```
Satu kejadian, empat jejak

  klien 10.10.14.12
    |-- tanya nama       -> resolver        -> index=dns      -> CIM Network Resolution (DNS)
    |-- buka URL         -> proxy / URL flt -> index=proxy    -> CIM Web
    |-- buka koneksi     -> firewall        -> index=firewall -> CIM Network Traffic
    '-- sesi remote      -> VPN gateway     -> index=vpn      -> CIM Authentication

  kunci penyambung : src / dest + rentang waktu
  yang hilang      : isi payload (firewall), path URL saat HTTPS (proxy),
                     klien asli (DNS di belakang resolver), pemilik IP setelah pool dipakai ulang (VPN)
```

Situasi yang dipakai sepanjang Day ini: pukul 09.00, NOC lead PT Jaringan Anak Bangsa (PT JAB, ISP menengah fiktif) menulis di channel bersama SOC dan membuka tiket SOC-2026-0231:

> "Tiga hal pagi ini. Satu, query di resolver pelanggan `jkt-dns01` naik tiga kali lipat sejak jam 03.00 dan NOC curiga ada yang salah di sisi kami. Dua, pelanggan korporat menelepon, katanya IP kantor mereka `198.51.100.77` diblokir perangkat kami. Tiga, dari sisi SOC ada alert proxy 'akses ke domain yang belum pernah terlihat' untuk JKT-WS-0412 jam 03.14. Ini satu kejadian atau tiga kejadian terpisah?"

Pesan itu memuat lima pertanyaan:

1. Empat sumber ini masuk lewat add-on dan sourcetype apa, dan nama field mana yang aman dipakai lintas sumber?
2. Apa yang sebenarnya dicatat log firewall, dan bagaimana membuktikan sebuah IP pelanggan benar ditolak dan oleh aturan mana?
3. Apa yang masih terlihat di log proxy ketika hampir semua trafik HTTPS?
4. Lonjakan query dan NXDOMAIN di resolver pelanggan itu masalah operasional atau sinyal keamanan, dan kenapa sudut pandang resolver berbeda dari sudut pandang klien?
5. Bagaimana memetakan alamat VPN ke orang, dan kapan pemetaan itu salah?

Pertanyaan 1 dijawab di bagian 1.1, pertanyaan 2 di bagian 1.2, pertanyaan 3 di bagian 1.3, pertanyaan 4 di bagian 1.4 dan 1.5, dan pertanyaan 5 di bagian 1.6. Bagian 1.7 membahas cara menyambung empat sumber, dan bagian 2 menjalankan semuanya sebagai search.

**Kapan relevan:** triage alert jaringan (koneksi ke destination buruk, lonjakan trafik keluar, domain baru, DNS gagal massal), investigasi lateral movement dan exfiltration, menjawab pertanyaan pelanggan atau NOC yang butuh bukti dari log, dan hunting berbasis metadata jaringan.
**Kapan bukan jawaban:** saat pertanyaannya tentang apa yang terjadi di dalam host (proses apa yang membuka koneksi, file apa yang ditulis), karena itu wilayah log endpoint di Day 03 dan Day 04; saat trafik tidak melewati perangkat yang mengirim log (koneksi antar VM di satu host, trafik yang lewat jalur lain); dan saat satu-satunya bukti yang dibutuhkan adalah isi payload, yang tidak ada di sumber mana pun di Day ini.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dasar Splunk dari Day 01 dan 02 (index, sourcetype, source, host, `stats`, `eval`) tidak diulang. Tabel ini memuat istilah jaringan dan CIM yang dipakai di Day ini; kolom padanan memakai hal yang sudah kamu kerjakan di NOC dan SOC. Baca kolom arti sekali, lalu kembali ke sini saat sebuah nama field terasa asing.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| Traffic log (session log) firewall | Satu baris per sesi atau koneksi beserta keputusan perangkat | CDR atau flow record: siapa menghubungi siapa, berapa besar |
| `action` di Network Traffic | Hasil keputusan perangkat, dengan nilai baku `allowed`, `blocked`, `teardown` | Kolom status panggilan: tersambung, ditolak, diakhiri |
| `rule` | Nama aturan yang menentukan keputusan itu | Nama ACL atau policy di router |
| `app` | Identifikasi aplikasi layer 7 oleh perangkat, bukan sekadar nomor port | Hasil klasifikasi DPI di perangkat |
| Proxy access log | Satu baris per request HTTP yang lewat proxy | Access log server web |
| `CONNECT` | Request pembuka tunnel TLS lewat proxy; setelah itu hanya host dan port yang terlihat | Panggilan terenkripsi: metadata ada, isi tidak |
| URL filtering dan `category` | Kategori domain atau URL menurut vendor | Kategori layanan di policy QoS |
| Resolver | Server DNS yang menjawab pertanyaan klien dan meneruskannya ke luar | Server lookup terpusat |
| `query` dan `record_type` | Nama yang ditanyakan dan jenis record yang diminta (A, AAAA, TXT) | Nomor yang dicari dan jenis pencariannya |
| `reply_code` dan NXDOMAIN | Kode hasil jawaban DNS; NXDOMAIN berarti nama tidak ada | Kode penyebab reject pada lookup |
| Entropi subdomain | Ukuran keacakan label di depan domain | Mengenali deretan karakter yang dibangkitkan mesin |
| VPN gateway | Perangkat yang menerima sesi VPN dan memberi alamat internal | NAS atau BRAS yang memberi IP ke sesi pelanggan |
| IP tunnel (assigned IP) | Alamat internal yang diberikan ke satu sesi VPN | IP yang di-assign RADIUS ke sesi pelanggan |
| NAT dan CGNAT | Penerjemahan alamat; banyak klien berbagi satu alamat publik | Satu IP publik dipakai ratusan pelanggan |
| Sampling | Hanya sebagian event disimpan agar volume terkendali | Sampling NetFlow 1:1000 di router |
| Data model CIM | Skema field standar lintas vendor; di Day ini: Network Traffic, Web, Network Resolution (DNS), Authentication | Normalisasi format log di SIEM mana pun |

### 1.1 Empat sumber, satu bahasa: add-on, sourcetype, dan CIM

Pertanyaan NOC lead menyentuh empat sumber sekaligus, jadi langkah pertama bukan menulis search, tetapi memastikan keempatnya masuk lewat jalur yang jelas dan field-nya dinormalisasi.

Pola jalurnya sama untuk semua sumber jaringan: perangkat mengirim syslog atau menulis file, Splunk menerima dan memberi sourcetype, lalu add-on vendor melakukan dua hal, yaitu mengekstrak field mentah dan memetakan field itu ke nama CIM. Bagian kedua inilah yang membuat satu search bisa menanyakan hal yang sama ke beberapa vendor. Kalau add-on tidak terpasang di search head, field hasil ekstraksi search-time tidak muncul walaupun data sudah masuk.

PT JAB memakai firewall Palo Alto Networks karena add-on-nya umum dan sekarang didukung langsung oleh Splunk. Add-on itu, Splunk Add-on for Palo Alto Networks 4.0.0, memecah log firewall menjadi sourcetype per jenis log dan mendokumentasikan pemetaan CIM tiap sourcetype [S1][S2]. Yang relevan untuk Day ini:

| Sourcetype | Isi | Data model CIM menurut dokumentasi add-on |
|---|---|---|
| `pan:traffic` | Traffic log: sesi yang diizinkan atau ditolak | Network Traffic [S1] |
| `pan:threat` | Threat log, termasuk URL filtering | Intrusion Detection dan Web [S1] |
| `pan:globalprotect` | Login dan sesi VPN GlobalProtect | Authentication [S1] |
| `pan:system`, `pan:config` | Event sistem dan perubahan konfigurasi perangkat | Authentication dan Change, Change [S1] |
| `pan:dns:cloud` | Log DNS Security dari layanan cloud vendor | Network Resolution [S1] |

Dua catatan praktis dari jalur ini. Pertama, add-on ini menggantikan Palo Alto Networks Add-on for Splunk versi 8.1.3 yang kini berstatus arsip dan tidak lagi mendapat pembaruan [S3]. Kalau instance-mu masih memakai add-on lama, nama sourcetype bisa sama tetapi pemetaan CIM dan daftar field bisa berbeda, sehingga search yang mengandalkan data model perlu diuji ulang. Kedua, [komunitas, belum terkonfirmasi] praktisi di forum menyebut data harus masuk dengan sourcetype pembuka (`pan:log`) supaya transforms add-on memecahnya ke `pan:traffic`, `pan:threat`, dan seterusnya, dan add-on harus ada di indexer atau heavy forwarder untuk itu. Yang belum pasti adalah apakah nama sourcetype pembuka itu masih sama di versi 4.0.0; cek halaman konfigurasi firewall di dokumentasi add-on versi-mu sebelum menyalin stanza input.

Vendor lain tetap memungkinkan. Fortinet FortiGate Add-On for Splunk 1.6.10, misalnya, dirilis Juni 2026 dan mencantumkan dukungan CIM 4.x, 5.x, dan 6.x [S15]. Yang penting bukan vendornya, tetapi tiga hal yang harus kamu ketahui untuk setiap sumber: sourcetype-nya, data model CIM yang diisi, dan versi add-on yang terpasang.

Untuk tiga sumber lain di PT JAB:

- Proxy web karyawan memakai Squid. Add-on resminya, Splunk Add-on for Squid Proxy 2.1.0, berstatus arsip di Splunkbase dan mencantumkan dukungan CIM 5.x [S9]. Halaman add-on di dokumentasi Splunk menyebut datanya diambil dengan file monitoring pada access log Squid dan add-on menyediakan knowledge yang CIM-compatible [S10]. Nama sourcetype yang dipakai di Day ini, `squid:access`, berasal dari halaman sourcetype add-on yang tidak dapat dibuka saat riset, jadi cocokkan dengan dokumentasi add-on versi-mu atau dengan `props.conf` add-on itu sendiri.
- Resolver memakai BIND. Splunk Add-on for ISC BIND 2.0.0 juga berstatus arsip, rilis November 2020, dengan dukungan CIM 4.x [S11]. Untuk ISP ini berarti satu keputusan nyata: menerima bahwa add-on tidak lagi dirawat, atau menormalisasi sendiri lewat props dan transforms (Day 28). Lantern mencatat bahwa data resolusi nama di Splunk bisa datang dari banyak jalur berbeda, antara lain Splunk App for Stream, add-on ISC BIND, add-on Sysmon, dan berbagai add-on vendor DNS [S14]. Artinya, pertanyaan "DNS kami masuk lewat apa" harus dijawab per lingkungan, bukan diasumsikan.
- VPN karyawan memakai GlobalProtect pada firewall yang sama, sehingga datanya masuk sebagai `pan:globalprotect` dan dipetakan ke Authentication [S1].

Bahasa bersamanya adalah CIM. Versi terbaru CIM add-on di Splunkbase saat riset adalah 8.7.0, rilis 2 September 2026 [S8]. Empat data model yang dipakai Day ini dan field intinya:

| Data model | Tag dataset | Field yang paling sering dipakai |
|---|---|---|
| Network Traffic (`All_Traffic`) | `network`, `communicate` | `action` (`allowed`, `blocked`, `teardown`), `src`, `dest`, `src_port`, `dest_port`, `transport` (`tcp`, `udp`, `icmp`), `bytes`, `bytes_in`, `bytes_out`, `app`, `rule`, `direction`, `user`, `vendor_product` [S4] |
| Web | `web` (anak: `proxy`, `storage`) | `action`, `url`, `uri_path`, `site`, `http_method`, `http_user_agent`, `http_referrer`, `status`, `src`, `dest`, `user`, `category`, `bytes_in`, `bytes_out` [S5] |
| Network Resolution (`DNS`) | `network`, `resolution`, `dns` | `query`, `query_type`, `record_type`, `answer`, `reply_code`, `reply_code_id`, `message_type` (`Query`, `Response`), `src`, `dest`, `transport` [S6] |
| Authentication | `authentication` (anak antara lain `privileged`, `cleartext`/`insecure`) | `action` (`success`, `failure`, `pending`, `error`), `app`, `src`, `dest`, `user`, `user_agent`, `signature`, `reason_id`, `duration` [S7] |

Tiga nilai yang sering salah ingat. `action` di Network Traffic bernilai `allowed` dan `blocked`, bukan `allow` dan `deny`, walaupun data mentah vendor memakai kata lain dan sebagian konten resmi menyaring kedua bentuk sekaligus [S4][S12]. `reply_code` di DNS punya nilai baku bergaya kalimat (`No Error`, `Format Error`, `Server Failure`, `Non-Existent Domain`) sekaligus menerima bentuk singkat yang dipakai vendor (`NoError`, `FormErr`, `ServFail`, `NXDomain`), dan ada pasangan numeriknya `reply_code_id` dengan 0 sampai 3 untuk empat kode itu [S6]. Dan `action` di Authentication bernilai `success` atau `failure`, bukan `allowed`. Jalankan `stats count BY action` sekali untuk setiap sourcetype baru sebelum menulis kondisi apa pun.

### 1.2 Firewall: metadata koneksi, keputusan, dan aturan

Pertanyaan pelanggan korporat PT JAB sederhana tetapi harus dijawab dengan bukti: apakah benar `198.51.100.77` ditolak, oleh perangkat mana, dan oleh aturan apa.

Traffic log firewall adalah catatan per sesi, bukan per paket. Satu baris biasanya memuat alamat dan port asal, alamat dan port tujuan, protokol, aplikasi yang dikenali perangkat, nama aturan yang memutuskan, hasil keputusan, dan jumlah byte dua arah. Di CIM, semua itu ada sebagai `src`, `dest`, `src_port`, `dest_port`, `transport`, `app`, `rule`, `action`, `bytes_in`, `bytes_out`, dan `bytes` yang merupakan jumlah keduanya [S4]. Itu sudah cukup untuk menjawab banyak pertanyaan triage tanpa menyentuh satu pun payload.

Yang perlu dipahami sebelum menyimpulkan apa pun dari log firewall:

- **Arah dan sudut pandang.** Field `direction` bernilai `inbound` atau `outbound` menurut perangkat yang mencatat [S4]. Perangkat perimeter data center melihat trafik yang sama dengan arah berbeda dari firewall kantor. Tanpa memeriksa `host` atau `vendor_product` perangkat pencatat, "inbound" bisa menyesatkan.
- **NAT membuat alamat berganda.** Log firewall sering memuat alamat sebelum dan sesudah translasi. Nama field pasca-NAT bergantung vendor, dan CIM tidak selalu mengisinya. Untuk ISP dengan CGNAT, satu alamat publik bisa mewakili ratusan pelanggan pada waktu yang sama, sehingga pertanyaan "siapa di balik IP ini" butuh log translasi, bukan log sesi.
- **Deny bisa berarti banyak hal.** Satu pelanggan yang mencoba port yang memang tertutup akan menghasilkan deny yang wajar. Yang menarik adalah pola: satu sumber mencoba banyak port tujuan (scan), atau satu sumber ditolak aturan tertentu secara berulang pada jam yang sama (konfigurasi salah di sisi pelanggan).
- **Log yang dipangkas.** Di lingkungan besar, logging untuk sebagian aturan dimatikan demi volume, dan sesi yang sangat pendek bisa hilang karena agregasi perangkat. "Tidak ada di log" tidak sama dengan "tidak terjadi". Periksa dulu apakah aturan yang relevan memang menulis log.

Untuk arah keluar, pola yang paling berguna adalah membandingkan trafik internal ke tujuan di luar untuk port yang seharusnya tidak pernah keluar. Konten resmi Splunk memakai pola ini untuk SMB: menyaring `action` yang mengizinkan, port tujuan 139 atau 445 atau `app="smb"`, mensyaratkan sumber berada di blok alamat privat, dan menolak tujuan yang juga privat, lalu menambahkan `iplocation` pada tujuan [S12]. Daftar blok privat di sana datang dari sebuah macro Enterprise Security (`non_public_ip_blocks`) yang mencakup rentang RFC 1918 ditambah rentang lain seperti `100.64.0.0/10` dan `127.0.0.0/8` [S12].

**Tanpa ES:** macro `non_public_ip_blocks` dan lookup aset ikut terpasang bersama Enterprise Security. Di Splunk Enterprise biasa, ganti macro itu dengan `cidrmatch()` di dalam `where`, atau dengan lookup CSV berisi daftar blok milikmu sendiri, dan ganti pencarian konteks aset dengan lookup inventaris NOC. Hasilnya sama; yang hilang hanya kemudahan memakainya ulang di banyak detection.

### 1.3 Proxy dan URL filtering: apa yang masih terlihat saat trafik HTTPS

Alert "domain yang belum pernah terlihat" untuk JKT-WS-0412 berasal dari log proxy. Supaya tidak salah menyimpulkan, kamu perlu tahu apa yang proxy masih lihat dan apa yang tidak.

Proxy mencatat satu baris per request. Untuk HTTP biasa, isinya lengkap: method, URL penuh termasuk path, status code, user agent, referrer, jumlah byte, dan user bila proxy melakukan autentikasi. Semua itu punya nama CIM di data model Web [S5]. Untuk HTTPS lewat proxy, yang terjadi berbeda: klien mengirim request `CONNECT host:443`, proxy membuka tunnel, dan setelah itu hanya metadata yang tercatat. Artinya kamu masih mendapat nama host, port, waktu, jumlah byte, dan identitas user, tetapi tidak path, tidak parameter query, dan biasanya tidak status code aplikasi. Jebakan praktisnya: bila search-mu menyaring `uri_path` atau mengandalkan `status` untuk menilai keberhasilan, hasilnya akan terlihat kosong untuk hampir semua trafik modern, padahal trafiknya ada.

Kalau proxy melakukan TLS inspection, path kembali terlihat. Itu keputusan kebijakan, bukan teknis semata, dan konsekuensinya langsung terasa di Splunk: URL penuh berarti token, parameter sesi, dan kadang data pribadi masuk ke index, sehingga index itu perlu pembatasan akses (Day 44).

Sumber kedua untuk pertanyaan web adalah URL filtering di firewall. Di Palo Alto, log itu masuk ke `pan:threat`, yang dipetakan ke Intrusion Detection sekaligus Web [S1]. Jadi satu lingkungan bisa punya dua sumber "web" dengan cakupan berbeda: proxy hanya melihat trafik yang memang lewat proxy, sedangkan firewall melihat trafik yang lewat perimeter termasuk host yang tidak memakai proxy. Field `category` di data model Web adalah kategori trafik yang diberikan, misalnya, oleh proxy [S5]. Kategori berguna untuk triage cepat, tetapi kategori "uncategorized" atau "newly registered domain" lebih sering menandai domain baru daripada domain jahat; perlakukan sebagai petunjuk, bukan putusan.

Satu hal yang membuat log proxy sangat berharga: field `user`. Firewall biasanya hanya tahu alamat IP, sedangkan proxy yang terintegrasi dengan direktori tahu nama akun. Itu jalan terpendek dari "host ini" ke "orang ini", dan karena itu juga jalan terpendek untuk salah menuduh orang bila satu workstation dipakai bergantian atau satu akun dipakai layanan otomatis.

### 1.4 DNS: pertanyaan, jenis record, dan kode jawaban

Lonjakan di `jkt-dns01` adalah pertanyaan DNS murni. Untuk menjawabnya kamu perlu tiga hal: apa yang ditanyakan, jenis record apa, dan jawabannya apa.

Data model Network Resolution memisahkan pertanyaan dan jawaban lewat `message_type` dengan nilai baku `Query` dan `Response`; `query` berisi nama yang perlu diselesaikan dan hanya berlaku untuk pesan bertipe Query, sedangkan `answer` berisi alamat hasil resolusi [S6]. `record_type` dan `query_type` berisi jenis record atau opcode menurut daftar IANA, misalnya A, AAAA, MX, TXT, PTR, dan bila `query_type` tidak terisi maka `record_type` yang dipakai [S6]. Pola yang perlu dikenali saat triage:

- **Volume dan keunikan.** Satu klien yang menanyakan ribuan nama unik dalam sejam adalah pola yang sama sekali berbeda dari satu klien yang menanyakan satu nama ribuan kali. Yang pertama mengarah ke pembangkitan nama otomatis atau tunneling, yang kedua ke beacon atau aplikasi yang tidak menghormati TTL.
- **Jenis record yang tak lazim.** TXT dan NULL dalam volume besar dari satu klien adalah sinyal klasik tunneling karena keduanya bisa membawa banyak data. Konten resmi Splunk memetakan jenis analisis ini ke teknik ATT&CK T1071.004, yaitu penggunaan DNS sebagai saluran command and control [S13].
- **Kegagalan massal.** Detection "Excessive DNS Failures" milik Splunk menghitung response DNS yang kode jawabannya bukan sukses, mengabaikan `No Error`, `NoError`, dan `unknown`, membuang query yang berakhiran `*.arpa` dan yang tidak mengandung titik, mengeluarkan domain yang ada di lookup domain korporat dan lookup domain populer, lalu menyalakan alert bila satu sumber melewati 50 kejadian [S13]. Halaman itu menandai detection-nya experimental dan menyebut trafik yang sah bisa memicunya [S13].
- **Subdomain acak dan panjang.** Lantern memberi pola hunting untuk tunneling lewat subdomain yang dibangkitkan mesin: pecah query menjadi domain dan subdomain, hitung entropi Shannon subdomain, hitung panjangnya, lalu kelompokkan per domain induk dan ambil domain dengan rata-rata entropi di atas 3, rata-rata panjang subdomain di atas 20 karakter, dan standar deviasi panjang di bawah 2 [S16]. Contohnya dibangun di atas data Zeek dengan `sourcetype=bro_dns` dan membutuhkan app URL Toolbox untuk macro `ut_parse` dan `ut_shannon`, tetapi artikelnya menyatakan sumber DNS lain bisa menggantikan [S16]. Standar deviasi yang kecil adalah bagian yang paling mudah dilewatkan: alat tunneling menghasilkan label dengan panjang yang nyaris seragam, sedangkan subdomain CDN yang juga terlihat acak panjangnya bervariasi.

Satu catatan akurasi yang penting untuk PT JAB: query log BIND mencatat pertanyaan, bukan jawaban. Jadi untuk `isc:bind:query`, field `reply_code` dan `answer` bisa kosong, dan analisis NXDOMAIN tidak bisa dijalankan di sourcetype itu. Untuk mendapatkan kode jawaban kamu butuh kanal log lain dari resolver, dnstap, atau penangkapan pasif seperti Splunk App for Stream atau Zeek [S14]. Periksa dulu dengan `stats count BY message_type reply_code` sebelum menulis detection yang bergantung pada `reply_code`.

### 1.5 Sudut pandang resolver dan skala ISP

Lonjakan di resolver pelanggan bukan hanya soal angka. Ia mengubah arti setiap field yang kamu lihat.

Di jaringan karyawan, `src` di log DNS adalah workstation. Di resolver pelanggan, `src` adalah perangkat pelanggan atau, lebih sering, alamat sesudah NAT, sedangkan resolver yang meneruskan query ke dunia luar akan muncul sebagai `src` di log hulu. Konsekuensinya: satu query jahat dari satu perangkat pelanggan bisa terlihat sebagai query dari resolver-mu di log pihak lain, dan sebaliknya, agregasi per `src` di resolver bisa menyatukan banyak pelanggan menjadi satu baris.

Tiga hal yang khas pada posisi ISP dan jarang dibahas di materi SIEM umum:

1. **Volume menentukan desain, bukan sebaliknya.** Resolver pelanggan menghasilkan event beberapa urutan besaran lebih banyak daripada seluruh log karyawan. Karena itu PT JAB melakukan sampling pada index `dns` untuk trafik pelanggan. Sampling mengubah cara membaca angka: hitungan absolut tidak lagi berarti, tetapi rasio dan peringkat masih berarti. Setiap search yang memakai ambang absolut, termasuk ambang 50 di detection "Excessive DNS Failures" [S13], harus disesuaikan dengan rasio sampling.
2. **Lonjakan bisa berasal dari sisi kamu.** Resolver yang terbuka ke internet dipakai pihak lain untuk amplification, dan satu perubahan konfigurasi di POP bisa mengalihkan trafik pelanggan ke resolver lain. Sebelum menyimpulkan serangan, bandingkan lonjakan dengan jumlah sumber unik: sedikit sumber dengan volume raksasa mengarah ke penyalahgunaan atau kesalahan konfigurasi, sedangkan banyak sumber dengan kenaikan merata mengarah ke perubahan routing atau kegagalan resolver lain.
3. **Isinya data pelanggan.** Query DNS pelanggan adalah catatan perilaku orang. Akses ke index itu, retensi, dan apa yang boleh ditulis di tiket mengikuti aturan yang lebih ketat daripada log karyawan, dan keputusan menindak pelanggan bukan kewenangan SOC. Sisi teknisnya ada di Day 44; yang perlu diingat di sini adalah bahwa hasil search ini sering tidak boleh disalin apa adanya ke tiket.

### 1.6 VPN: dari alamat ke identitas

Pertanyaan "siapa yang memegang 10.10.250.x jam 03.14" adalah pertanyaan paling sering diajukan dan paling sering dijawab keliru.

Log VPN punya dua bagian yang perlu dibedakan. Bagian autentikasi menjawab siapa yang login, dari alamat publik mana, berhasil atau gagal, dan dengan metode apa; di CIM ini masuk ke Authentication dengan `action` bernilai `success` atau `failure`, `user`, `src`, `app`, dan `reason_id` untuk alasan kegagalan [S7]. Bagian sesi menjawab alamat internal apa yang diberikan ke sesi itu dan sampai kapan. Nama field untuk alamat internal itu bergantung vendor dan CIM tidak menetapkan field baku untuknya, jadi periksa dengan `| fieldsummary` di instance-mu sebelum menulis search yang memetakan alamat ke user.

Empat alasan pemetaan alamat ke orang bisa salah:

- **Pool dipakai ulang.** Setelah sesi berakhir, alamat yang sama bisa diberikan ke orang lain beberapa menit kemudian. Pemetaan harus selalu dibatasi rentang waktu sesi, bukan hanya alamatnya.
- **Satu orang, beberapa sesi.** Laptop dan ponsel bisa punya sesi bersamaan dengan dua alamat berbeda.
- **Akun bersama.** Akun vendor atau akun uji dipakai beberapa orang. Alamat memetakan ke akun, bukan ke manusia.
- **Reconnect.** Koneksi yang putus dan tersambung lagi menghasilkan sesi baru, kadang dengan alamat baru, dalam satu pekerjaan yang sama.

Lokasi geografis dari alamat publik adalah petunjuk tambahan yang murah: `iplocation` menambahkan negara dan kota dari basis data bawaan Splunk. Dua batasnya perlu dikatakan terus terang. Alamat privat tidak mendapat lokasi, dan alamat dari operator seluler, VPN komersial, atau cloud sering dipetakan ke lokasi yang jauh dari pemakainya. Day 07 memakai lokasi login VPN sebagai salah satu bahan triage, dan perlakuannya di sana juga sebagai petunjuk, bukan bukti.

### 1.7 Menyambung empat sumber dan batas kepercayaannya

Kembali ke pertanyaan terakhir NOC lead: satu kejadian atau tiga. Yang menjawabnya adalah urutan waktu, bukan masing-masing sumber.

Urutan yang wajar untuk aktivitas keluar dari satu host adalah DNS lebih dulu, lalu koneksi di firewall, lalu request di proxy bila trafiknya web. Kalau ada koneksi ke alamat luar tanpa query DNS sebelumnya, ada tiga penjelasan yang semuanya menarik: alamat ditulis langsung di konfigurasi atau malware, nama sudah ada di cache klien dari jam sebelumnya, atau klien memakai resolver lain (DNS over HTTPS ke penyedia publik, misalnya), yang berarti jejak DNS-mu memang tidak lengkap.

Tiga kunci penyambung dan batasnya:

| Kunci | Dipakai untuk | Batas yang harus diingat |
|---|---|---|
| Alamat IP | Menyambung DNS, firewall, proxy, dan VPN untuk satu host | Berubah karena DHCP, NAT, dan pool VPN; selalu batasi rentang waktu |
| Waktu | Menyusun urutan kejadian | Perangkat jaringan sering berbeda zona waktu atau tidak sinkron NTP; selisih beberapa detik bisa membalik urutan |
| Nama akun | Menyambung aktivitas web ke orang | Hanya ada di proxy dan VPN, tidak di firewall dan DNS; satu akun bisa bukan satu orang |

Karena itu kesimpulan yang ditulis di tiket sebaiknya menyebut kuncinya: "host 10.10.14.12, pukul 03.14 sampai 03.21 WIB, dipetakan ke JKT-WS-0412 lewat log DHCP dan ke akun andi.pratama lewat log proxy". Kalimat itu bisa diperiksa orang lain; "Andi mengunduh file dari domain jahat" tidak.

## 2. Contoh SPL dan langkah praktis

Semua keluaran di bagian ini adalah keluaran ilustrasi, bukan hasil eksekusi. Asumsi PT JAB: index `firewall` (`sourcetype=pan:traffic`, `pan:threat`, `pan:globalprotect` dari Splunk Add-on for Palo Alto Networks 4.0.0), index `proxy` (`sourcetype=squid:access`), index `dns` (`sourcetype=isc:bind:query` untuk resolver, dengan sampling untuk trafik pelanggan), index `vpn` (`sourcetype=pan:globalprotect`), CIM add-on terpasang, Splunk Enterprise 10.6, dijalankan di app Search & Reporting tanpa ES. Jaringan internal `10.10.0.0/16` (kantor Jakarta), `10.20.0.0/16` (data center), `10.30.0.0/16` (Bandung), pool VPN karyawan `10.10.250.0/24`.

### 2.1 Inventaris: apa yang benar-benar masuk, dan apakah CIM terisi

Sebelum menjawab tiga pertanyaan NOC lead, pastikan dulu empat sumber itu ada dan field CIM-nya terisi.

**Tujuan:** melihat sourcetype per index jaringan beserta volumenya.

```
| tstats count where index IN (firewall, proxy, dns, vpn) earliest=-24h by index sourcetype
| sort index - count
```

- `tstats ... by index sourcetype`: `index` dan `sourcetype` adalah field indexed, jadi hitungan ini dibaca dari tsidx dan jauh lebih murah daripada menelusuri event (Day 25).
- `IN (...)` dipakai di klausa `where` milik `tstats`, bentuk yang sama dengan command `search`.

Keluaran ilustrasi:

```
index      sourcetype          count
dns        isc:bind:query      418209331
firewall   pan:traffic         64028115
firewall   pan:threat          1902004
firewall   pan:globalprotect   28431
proxy      squid:access        9120773
vpn        pan:globalprotect   28431
```

**Cara membaca hasil:** dua baris `pan:globalprotect` dengan jumlah identik menandakan data VPN masuk ke dua index sekaligus, biasanya karena satu input lama belum dimatikan saat index baru dibuat. Itu membuat setiap hitungan login VPN berpotensi dua kali lipat dan harus dibereskan di sisi input (Day 28), bukan ditambal di search.

**Variasi (apakah data model terisi):**

```
| tstats count from datamodel=Network_Traffic where nodename=All_Traffic earliest=-24h by sourcetype
```

Kalau hasilnya kosong padahal `index=firewall` penuh, masalahnya ada di tag dan field CIM, bukan di data (Day 23). Pada data model yang belum diakselerasi, `tstats` tetap jalan tetapi jauh lebih lambat karena harus menjalankan pencarian data model-nya (Day 26).

**Kapan gagal:** `tstats` tidak bisa menghitung berdasarkan field hasil ekstraksi search-time seperti `action` atau `query`; untuk itu pakai `stats` biasa.

### 2.2 Membuktikan IP pelanggan ditolak, dan oleh aturan apa

Ini jawaban langsung untuk telepon pelanggan korporat.

**Tujuan:** melihat semua sesi yang melibatkan `198.51.100.77` pagi ini beserta keputusan dan nama aturannya.

```
index=firewall sourcetype=pan:traffic (src="198.51.100.77" OR dest="198.51.100.77")
    earliest="10/14/2026:00:00:00" latest="10/14/2026:09:30:00"
| stats count values(action) AS aksi values(rule) AS aturan dc(dest_port) AS port_tujuan_unik
        min(_time) AS mulai max(_time) AS selesai BY host src dest app transport
| eval mulai=strftime(mulai, "%F %T"), selesai=strftime(selesai, "%F %T")
| sort - count
```

| Bagian | Penjelasan |
|---|---|
| `(src=... OR dest=...)` | Tanda kurung wajib, supaya `OR` tidak menelan filter `sourcetype` |
| `earliest`/`latest` absolut | Rentang dikunci di sekitar keluhan, jadi hasilnya bisa diulang besok dan dilampirkan ke tiket |
| `BY host ...` | `host` adalah perangkat yang mencatat, jadi terlihat firewall mana yang memutuskan |
| `dc(dest_port)` | Banyak port tujuan unik dari satu sumber mengarah ke scan, bukan ke satu layanan |

Keluaran ilustrasi:

```
host        src             dest          app     transport  count  aksi     aturan                port_tujuan_unik  mulai                selesai
jkt-fw01    198.51.100.77   10.20.8.21    ssh     tcp        38     blocked  deny-mgmt-from-wan    1                 2026-10-14 07:02:11  2026-10-14 09:11:40
jkt-fw01    198.51.100.77   10.20.8.40    web-browsing tcp   214    allowed  allow-cust-portal     2                 2026-10-14 07:00:03  2026-10-14 09:28:55
```

**Cara membaca hasil:** pelanggan tidak diblokir seluruhnya. Trafik ke portal pelanggan tetap diizinkan; yang ditolak adalah 38 percobaan SSH ke alamat manajemen oleh aturan `deny-mgmt-from-wan`. Jawaban untuk pelanggan jelas dan bisa diperiksa: layanan normal jalan, akses ke jaringan manajemen memang ditolak kebijakan. Yang perlu ditanyakan balik adalah kenapa perangkat mereka mencoba SSH ke alamat itu 38 kali.
**Variasi (scan):** hilangkan filter alamat dan cari sumber dengan banyak port tujuan unik:

```
index=firewall sourcetype=pan:traffic action=blocked earliest=-6h
| stats dc(dest_port) AS port_unik dc(dest) AS tujuan_unik count BY src
| where port_unik >= 20
| sort - port_unik
```

**Kapan gagal:** aturan yang logging-nya dimatikan tidak menghasilkan baris apa pun, sehingga "tidak ada deny" bisa berarti "tidak dicatat". Alamat pasca-NAT juga bisa membuat `src` berbeda dari alamat yang dilihat pelanggan; cek field alamat pra-NAT dan pasca-NAT di add-on versi-mu.

### 2.3 Trafik keluar ke port yang seharusnya tidak keluar

Pola ini dipakai untuk menemukan sesi dari dalam ke luar yang tidak punya alasan bisnis, dan menjadi dasar beberapa detection resmi [S12].

**Tujuan:** menemukan host internal yang berhasil membuka koneksi SMB atau RDP ke alamat di luar.

```
index=firewall sourcetype=pan:traffic action=allowed dest_port IN (139, 445, 3389) earliest=-24h
| where (cidrmatch("10.0.0.0/8", src) OR cidrmatch("172.16.0.0/12", src) OR cidrmatch("192.168.0.0/16", src))
        AND NOT (cidrmatch("10.0.0.0/8", dest) OR cidrmatch("172.16.0.0/12", dest)
                 OR cidrmatch("192.168.0.0/16", dest) OR cidrmatch("127.0.0.0/8", dest)
                 OR cidrmatch("100.64.0.0/10", dest))
| stats count sum(bytes_out) AS byte_keluar values(dest_port) AS port values(app) AS aplikasi
        min(_time) AS mulai max(_time) AS selesai BY src dest
| iplocation dest
| eval mulai=strftime(mulai, "%F %T"), selesai=strftime(selesai, "%F %T")
| sort - byte_keluar
```

- `dest_port IN (139, 445, 3389)`: `IN` di command `search`, difilter di awal pipeline supaya murah.
- `cidrmatch("10.0.0.0/8", src)`: argumen pertama adalah blok, argumen kedua alamat yang diuji. Daftar blok di `NOT (...)` mengikuti daftar blok non-publik yang dipakai konten resmi, termasuk `100.64.0.0/10` dan `127.0.0.0/8` [S12].
- `sum(bytes_out)`: byte yang keluar dari perangkat pencatat; untuk pertanyaan exfiltration inilah angka yang dilihat, bukan `bytes` total [S4].
- `iplocation dest`: negara dan kota tujuan, untuk prioritas awal.

Keluaran ilustrasi:

```
src           dest             count  byte_keluar  port  aplikasi  mulai                selesai              Country
10.10.14.12   203.0.113.90     7      18422119     445   smb       2026-10-14 03:21:08  2026-10-14 03:44:52  Netherlands
```

**Cara membaca hasil:** satu workstation kantor mengirim sekitar 18,4 MB keluar lewat port 445 selama 24 menit. SMB keluar ke internet tidak punya alasan bisnis di PT JAB, dan konten resmi Splunk memperlakukannya sebagai sinyal pengambilan kredensial atau pergerakan lateral, dengan catatan bahwa trafik sah bisa muncul bila blok internal belum terdefinisi dengan benar [S12]. Host ini sama dengan host di alert proxy, jadi dua dari tiga laporan NOC lead mulai menyatu.
**Variasi:** ganti daftar port dengan `app!="web-browsing" AND dest_port NOT IN (80, 443)` untuk mencari protokol tak lazim secara umum, lalu urutkan menurut `byte_keluar`.
**Kapan gagal:** host yang trafiknya tidak lewat perangkat pencatat tidak akan muncul. Blok alamat internal yang dipakai tetapi tidak ada di daftar `cidrmatch` akan muncul sebagai "tujuan eksternal" dan membuat hasil penuh false positive; simpan daftar blok internal sebagai lookup supaya satu tempat saja yang perlu diperbarui.

### 2.4 Proxy: domain yang baru muncul untuk satu host

Ini memeriksa isi alert proxy jam 03.14 tanpa mempercayai judul alert.

**Tujuan:** menemukan tujuan web yang baru pertama kali diakses oleh JKT-WS-0412 dalam 24 jam terakhir, dibandingkan dengan 30 hari ke belakang.

```
index=proxy sourcetype=squid:access src=10.10.14.12 earliest=-30d latest=now
| stats count earliest(_time) AS pertama_kali latest(_time) AS terakhir
        values(http_method) AS metode values(status) AS status values(http_user_agent) AS user_agent
        sum(bytes_in) AS byte_masuk sum(bytes_out) AS byte_keluar BY dest
| where pertama_kali >= relative_time(now(), "-24h")
| eval pertama_kali=strftime(pertama_kali, "%F %T"), terakhir=strftime(terakhir, "%F %T")
| sort - byte_keluar
```

- `earliest(_time)` di `stats`: waktu kemunculan paling awal per tujuan dalam 30 hari. Dipadukan dengan `where`, inilah definisi "baru": tujuan yang kemunculan pertamanya ada di dalam 24 jam terakhir.
- `relative_time(now(), "-24h")`: batas waktu dalam bentuk epoch, supaya bisa dibandingkan dengan hasil `earliest(_time)`.
- `values(http_user_agent)`: user agent yang tidak lazim sering lebih informatif daripada nama domainnya.

Keluaran ilustrasi:

```
dest                  count  pertama_kali         terakhir             metode   status  user_agent              byte_masuk  byte_keluar
sync-node7.example.net  46   2026-10-14 03:14:22  2026-10-14 03:46:05  CONNECT  200     python-requests/2.32.3  184922      9120443
```

**Cara membaca hasil:** tujuan baru, method `CONNECT` (jadi trafiknya HTTPS dan path tidak terlihat), user agent pustaka HTTP Python bukan browser, dan byte keluar jauh lebih besar daripada byte masuk. Kombinasi arah byte dan user agent itu yang membuat baris ini layak dieskalasi, bukan fakta "domainnya baru". Perhatikan juga bahwa karena trafiknya `CONNECT`, mencari `uri_path` di sini tidak akan menghasilkan apa pun (bagian 1.3).
**Variasi (dari sisi user, bukan host):** ganti `src=10.10.14.12` dengan `user=andi.pratama` untuk melihat apakah akun yang sama memakai pola ini dari host lain.
**Kapan gagal:** host yang belum pernah terlihat sama sekali dalam 30 hari akan membuat semua tujuannya terlihat baru. Untuk host baru, bandingkan dengan baseline kelompok (departemen atau jenis host), bukan dengan dirinya sendiri. Rentang 30 hari di index proxy besar bisa berat; untuk pemakaian rutin, simpan daftar tujuan yang sudah dikenal sebagai summary atau lookup (Day 40).

### 2.5 DNS: kegagalan jawaban per sumber di resolver

Ini bagian pertama dari pertanyaan NOC lead tentang `jkt-dns01`.

**Tujuan:** menemukan sumber dengan kegagalan resolusi paling banyak dalam enam jam terakhir, memakai data model supaya tidak bergantung pada satu vendor.

```
| tstats count from datamodel=Network_Resolution
    where nodename=DNS DNS.reply_code!="No Error" DNS.reply_code!="NoError" DNS.reply_code!="unknown"
          DNS.query="*.*" NOT DNS.query="*.arpa" earliest=-6h
    by DNS.src DNS.reply_code
| rename DNS.* AS *
| stats sum(count) AS gagal values(reply_code) AS kode BY src
| where gagal > 50
| sort - gagal
```

- Pola filter ini mengikuti detection "Excessive DNS Failures": buang kode sukses dalam dua ejaan dan nilai `unknown`, buang query `*.arpa` (reverse lookup) dan query tanpa titik, lalu bandingkan dengan ambang [S13].
- `DNS.query="*.*"`: mensyaratkan ada titik di nama, cara murah membuang nama host tunggal yang bukan FQDN.
- `where gagal > 50`: ambang bawaan detection itu, yang memang dimaksudkan untuk disesuaikan [S13]. Di index yang disampling, ambang ini harus dikalikan rasio sampling (bagian 1.5).

Keluaran ilustrasi:

```
src             gagal   kode
100.96.14.203   114820  NXDomain
100.96.22.17    2140    NXDomain ServFail
10.10.14.12     318     NXDomain
```

**Cara membaca hasil:** dua baris pertama berasal dari rentang alamat pelanggan di belakang CGNAT, jadi satu baris bisa mewakili banyak perangkat sekaligus. Angka 114.820 kegagalan dari satu alamat dalam enam jam, hampir semuanya NXDOMAIN, adalah pola pembangkitan nama otomatis, bukan orang yang salah mengetik. Baris ketiga kecil tetapi penting: host yang sama dengan bagian 2.3 dan 2.4.
**Variasi (tanpa data model):** bila data model belum terisi, jalankan langsung di index, dengan catatan nama field bergantung sourcetype:

```
index=dns earliest=-6h message_type=Response
| stats count count(eval(in(reply_code, "NXDomain", "Non-Existent Domain"))) AS nxdomain dc(query) AS nama_unik BY src
| eval rasio_nx=round(nxdomain / count * 100, 1)
| where count > 1000 AND rasio_nx > 60
| sort - nxdomain
```

Di sini `in()` dipakai di dalam ekspresi `eval` untuk mencakup dua ejaan kode CIM sekaligus [S6], dan rasio dipakai sebagai pengganti ambang absolut supaya tahan terhadap sampling.
**Kapan gagal:** pada query log BIND yang hanya mencatat pertanyaan, `message_type` dan `reply_code` tidak terisi, sehingga kedua search di atas mengembalikan nol baris walaupun datanya ada (bagian 1.4). Periksa dulu dengan `index=dns | stats count BY message_type reply_code`, lalu pakai jalur sumber lain untuk kode jawaban.

### 2.6 DNS: subdomain panjang dan acak

Lonjakan NXDOMAIN dari satu sumber menuntun ke pertanyaan berikutnya: nama yang ditanyakan itu bentuknya seperti apa.

**Tujuan:** menemukan domain induk yang subdomainnya acak, panjang, dan panjangnya seragam, pola khas tunneling [S16].

```
index=dns sourcetype=isc:bind:query earliest="10/14/2026:03:00:00" latest="10/14/2026:09:00:00"
| `ut_parse(query)`
| `ut_shannon(ut_subdomain)`
| eval sublen=len(ut_subdomain)
| stats count dc(src) AS sumber_unik avg(ut_shannon) AS entropi_rata
        avg(sublen) AS panjang_rata stdev(sublen) AS stdev_panjang
        values(ut_subdomain) AS contoh_subdomain BY ut_domain
| where entropi_rata > 3 AND panjang_rata > 20 AND stdev_panjang < 2
| eval entropi_rata=round(entropi_rata, 2), panjang_rata=round(panjang_rata, 1),
       stdev_panjang=round(stdev_panjang, 2),
       contoh_subdomain=mvindex(contoh_subdomain, 0, 2)
| sort - count
```

| Bagian | Penjelasan |
|---|---|
| `ut_parse(query)` | Macro URL Toolbox: memecah nama menjadi `ut_domain` dan `ut_subdomain` [S16] |
| `ut_shannon(ut_subdomain)` | Macro URL Toolbox: entropi Shannon subdomain [S16] |
| `len(ut_subdomain)` | Panjang subdomain dalam karakter |
| `stdev(sublen)` | Keseragaman panjang; alat tunneling menghasilkan label yang nyaris sama panjang |
| `where entropi_rata > 3 AND panjang_rata > 20 AND stdev_panjang < 2` | Tiga ambang awal dari Lantern, dimaksudkan untuk disetel per lingkungan [S16] |
| `mvindex(contoh_subdomain, 0, 2)` | Ambil tiga contoh saja; `values()` pada data DNS bisa mengembalikan ribuan nilai |

Keluaran ilustrasi:

```
ut_domain          count   sumber_unik  entropi_rata  panjang_rata  stdev_panjang  contoh_subdomain
cdnmetrics.test    114203  1            4.21          31.4          0.84           k7qv2m... 9fp1xd... b3ne8r...
```

**Cara membaca hasil:** satu domain induk, satu sumber, 114.203 query dalam enam jam, subdomain acak dengan panjang rata-rata 31 karakter dan sebaran sangat kecil. Itu bentuk yang cocok dengan tunneling, dan jumlahnya cocok dengan baris NXDOMAIN terbesar di bagian 2.5. Untuk tiket, yang dilampirkan adalah domain induk, jumlah, rentang waktu, dan tiga contoh subdomain, bukan seluruh daftar query pelanggan.
**Variasi:** bila URL Toolbox tidak terpasang, hitung panjang label pertama dengan `eval label1=mvindex(split(query, "."), 0) | eval sublen=len(label1)` lalu pakai ambang panjang dan jumlah nama unik per domain saja. Entropi hilang, tetapi pola "banyak nama unik, label panjang, satu domain induk" masih tertangkap.
**Kapan gagal:** domain CDN dan layanan telemetri sah juga menghasilkan subdomain yang terlihat acak; yang membedakan biasanya `stdev_panjang` dan jumlah sumber unik, karena layanan sah dipakai banyak klien. Nama yang dipotong atau diubah oleh sampling juga merusak perhitungan entropi.

### 2.7 VPN dan kronologi gabungan

Langkah terakhir: siapa pemilik sesi pada waktu itu, lalu susun satu urutan dari empat sumber.

**Tujuan pertama:** memetakan alamat VPN ke akun pada rentang waktu tertentu.

```
index=vpn sourcetype=pan:globalprotect action=success
    earliest="10/14/2026:00:00:00" latest="10/14/2026:09:30:00"
| stats min(_time) AS mulai max(_time) AS terakhir_terlihat values(user) AS akun values(src) AS ip_publik
        BY private_ip
| eval mulai=strftime(mulai, "%F %T"), terakhir_terlihat=strftime(terakhir_terlihat, "%F %T")
| sort mulai
```

- `action=success`: nilai CIM Authentication untuk login berhasil [S7].
- `private_ip`: nama field untuk alamat tunnel pada log GlobalProtect. CIM tidak menetapkan field baku untuk alamat yang dialokasikan, jadi nama ini wajib dicek di instance-mu dengan `| fieldsummary` sebelum dipakai (bagian 1.6).
- `values(user) BY private_ip`: bila satu alamat menghasilkan lebih dari satu akun dalam rentang itu, pool sudah dipakai ulang dan pemetaan tidak boleh dipakai tanpa memperhatikan waktu.

Keluaran ilustrasi:

```
private_ip     akun                        ip_publik        mulai                terakhir_terlihat
10.10.250.17   andi.pratama                198.51.100.23    2026-10-14 02:58:44  2026-10-14 04:02:10
10.10.250.17   andi.pratama rina.wulandari  198.51.100.23 198.51.100.140  2026-10-14 02:58:44  2026-10-14 08:40:31
```

**Cara membaca hasil:** baris kedua adalah contoh jebakan pool: alamat yang sama dipegang dua akun dalam rentang sembilan jam. Untuk menentukan pemilik pada 03.14, rentang search harus dipersempit ke sekitar waktu itu, atau sesi dipisahkan dengan event logout bila vendor mencatatnya.

**Tujuan kedua:** menyusun satu kronologi untuk host 10.10.14.12 dari tiga sumber sekaligus.

```
| multisearch
    [search index=dns sourcetype=isc:bind:query src=10.10.14.12
        earliest="10/14/2026:03:00:00" latest="10/14/2026:04:00:00"
     | eval sumber="dns", rincian=query]
    [search index=proxy sourcetype=squid:access src=10.10.14.12
        earliest="10/14/2026:03:00:00" latest="10/14/2026:04:00:00"
     | eval sumber="proxy", rincian=http_method." ".dest." status=".status]
    [search index=firewall sourcetype=pan:traffic src=10.10.14.12
        earliest="10/14/2026:03:00:00" latest="10/14/2026:04:00:00"
     | eval sumber="firewall", rincian=action." ".dest.":".dest_port." ".app]
| sort _time
| table _time sumber rincian
```

- `multisearch` menjalankan beberapa search sekaligus dan menggabungkan event-nya; setiap subsearch hanya boleh memuat command streaming, dan `eval` memenuhi syarat itu.
- Setiap cabang membuat kolom `sumber` dan `rincian` dengan nama sama, sehingga satu tabel bisa dibaca berurutan.

Keluaran ilustrasi:

```
_time                sumber    rincian
2026-10-14 03:14:19  dns       sync-node7.example.net
2026-10-14 03:14:20  firewall  allowed 203.0.113.90:443 ssl
2026-10-14 03:14:22  proxy     CONNECT sync-node7.example.net status=200
2026-10-14 03:21:08  firewall  allowed 203.0.113.90:445 smb
```

**Cara membaca hasil:** urutannya wajar (nama dicari dulu, lalu koneksi, lalu request), sehingga tiga laporan NOC lead bukan tiga kejadian terpisah untuk host ini. Yang paling penting adalah baris terakhir: setelah jalur web, host yang sama membuka SMB ke alamat yang sama. Selisih satu detik antara DNS dan firewall tidak bisa dipakai untuk memastikan urutan sebab akibat, karena jam perangkat bisa berbeda beberapa detik (bagian 1.7).
**Kapan gagal:** `multisearch` menolak subsearch yang memuat command transforming seperti `stats`; untuk itu pakai `append` atau `union`. Satu index yang jauh lebih besar dari yang lain juga akan mendominasi hasil, jadi persempit rentang waktu sebelum menambah cabang.

**Ringkasan untuk tiket SOC-2026-0231:** tiga laporan pagi ini adalah dua kejadian. Pertama, keluhan pelanggan bukan pemblokiran layanan: trafik ke portal tetap diizinkan dan yang ditolak adalah 38 percobaan SSH ke jaringan manajemen oleh aturan `deny-mgmt-from-wan`; balas ke NOC dengan bukti bagian 2.2 dan tanyakan asal percobaan itu. Kedua, lonjakan resolver dan alert proxy berhubungan dengan satu host: JKT-WS-0412 (10.10.14.12) menanyakan subdomain acak ke `cdnmetrics.test`, membuka `CONNECT` ke tujuan baru dengan user agent pustaka Python, lalu mengirim sekitar 18,4 MB keluar lewat port 445. Eskalasikan ke L2 dengan kronologi bagian 2.7, dan catat terpisah bahwa dua alamat pelanggan di belakang CGNAT menghasilkan volume NXDOMAIN yang sangat besar, yang penanganannya di jalur abuse pelanggan, bukan di SOC.

## 3. Lab praktik (di VM lab terisolasi)

Lab memakai dua sumber: dataset BOTS (statis, jadi rentang waktunya absolut) dan VM lab terisolasi milikmu dengan resolver dan proxy sendiri. Semua perintah dijalankan di VM lab bersnapshot, bukan di mesin kerja atau perangkat produksi.

1. **Tentukan rentang waktu dataset.** Jalankan `| tstats min(_time) AS awal max(_time) AS akhir where index=botsv1 | eval awal=strftime(awal, "%F %T"), akhir=strftime(akhir, "%F %T")`, lalu ulangi untuk index BOTS lain yang kamu punya. Catat hasilnya dan pakai sebagai `earliest`/`latest` absolut di semua langkah berikut. Jangan memakai rentang relatif pada dataset statis.
2. **Inventaris sumber jaringan.** Jalankan `| metadata type=sourcetypes index=botsv1 | table sourcetype totalCount firstTime lastTime`, lalu tandai mana yang berisi data jaringan (firewall, proxy atau web, DNS, VPN). Tulis padanannya ke empat sumber di Day ini; beberapa dataset memakai penangkapan pasif, bukan log perangkat, sehingga nama field-nya berbeda.
3. **Periksa pemetaan CIM.** Untuk setiap sourcetype jaringan yang kamu temukan, jalankan `| tstats count from datamodel=Network_Traffic where nodename=All_Traffic by sourcetype` dan ulangi untuk `Web` dan `Network_Resolution`. Catat sourcetype mana yang masuk data model dan mana yang tidak. Untuk yang tidak masuk, jalankan `| fieldsummary maxvals=5` pada beberapa event dan catat field apa yang hilang.
4. **Keputusan firewall.** Jalankan `stats count BY action` pada sourcetype firewall dataset itu. Bandingkan nilai mentahnya dengan nilai baku CIM (`allowed`, `blocked`, `teardown`). Tulis satu baris pemetaan nilai mentah ke nilai CIM untuk sourcetype itu.
5. **Kegagalan DNS.** Jalankan versi bagian 2.5 pada dataset dengan rentang absolut dari langkah 1. Bila `reply_code` kosong, catat sourcetype mana yang membawa response dan mana yang hanya membawa query.
6. **Hunting subdomain.** Pasang URL Toolbox di instance lab, lalu jalankan versi bagian 2.6. Catat domain yang lolos ambang Lantern, lalu naikkan dan turunkan satu ambang (misalnya panjang 20 menjadi 15 dan 25) dan catat berapa banyak hasil yang muncul atau hilang. Tujuannya merasakan sensitivitas ambang, bukan menemukan satu jawaban benar.
7. **Bangun sumber sendiri.** Di VM lab, jalankan satu resolver (BIND atau unbound) dan satu proxy (Squid), arahkan satu VM klien ke keduanya, lalu buat trafik: beberapa kunjungan HTTPS, satu unduhan besar, sepuluh query ke nama yang tidak ada, dan sepuluh query ke subdomain panjang di domain lab-mu sendiri. Pasang input file monitor ke access log dan query log dengan index dan sourcetype milikmu.
8. **Bandingkan dengan dan tanpa add-on.** Lihat field yang terekstrak sebelum dan sesudah add-on dipasang di search head. Catat field CIM yang terisi, yang kosong, dan yang namanya berbeda dari dokumentasi.
9. **Satu kronologi.** Dengan data lab sendiri, jalankan versi `multisearch` bagian 2.7 untuk satu klien. Pastikan urutan DNS, firewall, dan proxy terbaca wajar. Bila urutannya kacau, periksa zona waktu dan sinkronisasi jam di VM.

**Hasil yang sebaiknya tersimpan:**

- Rentang waktu absolut tiap dataset BOTS yang kamu punya.
- Tabel sourcetype jaringan di dataset itu beserta data model CIM yang terisi dan yang tidak.
- Pemetaan nilai `action` mentah ke nilai CIM untuk firewall dataset dan firewall lab-mu.
- Catatan sourcetype DNS mana yang membawa `reply_code` dan mana yang hanya membawa query.
- Hasil tiga ambang berbeda pada hunting subdomain, dengan jumlah domain yang lolos.
- Daftar field CIM yang kosong di sumber lab sendiri, sebagai bahan latihan normalisasi (Day 28).
- Satu tangkapan kronologi `multisearch` dari data lab yang urutannya sudah benar.

**Variasi tantangan:** jadikan versi rasio di bagian 2.5 sebuah report terjadwal (Day 09) yang berjalan setiap jam di satu index saja, lalu tulis satu paragraf tentang kenapa ambang rasio lebih tahan terhadap sampling daripada ambang absolut, dan apa yang akan rusak bila rasio sampling diubah tanpa memberi tahu SOC.

## 4. Troubleshooting

Tabel ini untuk saat search tidak mengembalikan yang kamu harapkan; mulai dari kolom gejala.

| Gejala | Kemungkinan penyebab | Cara memeriksa atau memperbaiki |
|---|---|---|
| `index=firewall` penuh tetapi `tstats` dari Network_Traffic kosong | Tag dan field CIM belum terisi, atau add-on tidak ada di search head | Jalankan `stats count BY action src dest` di index itu; bila field kosong, pasang add-on di search head (Day 23) |
| Satu sourcetype pecah menjadi beberapa nama tak dikenal | Add-on memecah log per jenis lewat transforms di indexer atau heavy forwarder | Cek konfigurasi input dan letak add-on; untuk Palo Alto, cek halaman konfigurasi firewall di dokumentasi add-on versi-mu [S1] |
| `action=allowed` tidak cocok tetapi data ada | Nilai mentah vendor belum dinormalisasi (`allow`, `permit`, kode angka) | `stats count BY action`; pakai nilai yang benar-benar ada, atau perbaiki pemetaan CIM [S4] |
| Semua `uri_path` kosong di log proxy | Trafik HTTPS lewat `CONNECT`, path tidak terlihat | Pakai `dest`, `http_method`, dan arah byte; jangan menyaring berdasarkan path (bagian 1.3) |
| `reply_code` kosong di semua event DNS | Sourcetype hanya memuat query, bukan response | `stats count BY message_type reply_code`; tambahkan sumber yang memuat response [S14] |
| Hitungan login VPN dua kali lipat | Satu input dikirim ke dua index | Bandingkan `count BY index sourcetype` seperti bagian 2.1; matikan input ganda (Day 28) |
| Pemetaan alamat VPN ke akun menghasilkan dua akun | Pool alamat dipakai ulang dalam rentang search | Persempit rentang ke sekitar waktu kejadian; pakai event logout bila ada (bagian 1.6) |
| `iplocation` tidak mengisi negara | Alamat privat atau tidak ada di basis data | Wajar untuk alamat internal; untuk alamat publik, perlakukan kosong sebagai tidak diketahui |
| `multisearch` gagal dengan keluhan command | Ada command transforming di subsearch | Pindahkan `stats` ke setelah `multisearch`, atau pakai `append` |
| Hitungan di index DNS pelanggan terasa terlalu kecil | Sampling di sisi ingest | Konfirmasi rasio sampling, lalu ubah ambang absolut menjadi rasio (bagian 1.5) |

## 5. Kesalahan umum dan jebakan

- Menganggap `action` di semua data model memakai nilai yang sama. Network Traffic memakai `allowed` dan `blocked`, Authentication memakai `success` dan `failure` [S4][S7].
- Menyimpulkan "tidak ada koneksi" dari log firewall tanpa memeriksa apakah aturan yang relevan memang menulis log.
- Membaca `direction` tanpa melihat perangkat pencatatnya. Arah selalu relatif terhadap perangkat itu [S4].
- Memperlakukan satu alamat publik sebagai satu pelanggan di lingkungan CGNAT. Satu alamat bisa mewakili ratusan perangkat pada waktu yang sama.
- Mencari path URL di trafik HTTPS lewat proxy. Yang ada hanya host dan port setelah `CONNECT` (bagian 1.3).
- Menilai domain hanya dari kategori URL filtering. Kategori kosong atau "newly registered" menandai domain baru, bukan domain jahat [S5].
- Menjalankan analisis NXDOMAIN pada sourcetype yang hanya memuat query. Hasil nol baris di situ bukan bukti tidak ada kegagalan (bagian 1.4).
- Memakai ambang absolut dari konten publik di index yang disampling. Ambang 50 pada detection "Excessive DNS Failures" ditulis untuk data penuh dan memang dimaksudkan untuk disesuaikan [S13].
- Menyimpulkan tunneling hanya dari entropi tinggi. Tanpa memeriksa keseragaman panjang dan jumlah sumber unik, domain CDN akan ikut tertangkap [S16].
- Memetakan alamat VPN ke orang tanpa membatasi waktu. Pool dipakai ulang, dan satu akun bisa dipakai lebih dari satu orang (bagian 1.6).
- Menyalin hasil search yang memuat query atau alamat pelanggan ke tiket apa adanya. Yang masuk tiket adalah agregat dan beberapa contoh, dengan akses index yang terbatas (Day 44).
- Menyandarkan search pada nama field vendor dari contoh di internet. Nama field bergantung versi add-on; konfirmasi dengan `| fieldsummary` di instance-mu.

## 6. Catatan terkini

Bagian ini menampung versi dan tanggal sumber. Tidak ada yang mengubah search di atas, kecuali bila add-on di instance-mu versinya berbeda.

- Splunk Add-on for Palo Alto Networks versi 4.0.0 di Splunkbase dirilis 14 Agustus 2026, mencantumkan dukungan platform 9.3 sampai 10.6 dan CIM 8.x serta 6.x, dengan dokumentasi di situs GitHub Pages Splunk [S2]. Halaman source types di dokumentasi itu mencatat 25 sourcetype beserta data model CIM-nya [S1].
- Palo Alto Networks Add-on for Splunk versi 8.1.3, add-on lama yang dirawat vendor, terakhir dirilis 24 Mei 2024, kini berstatus arsip, dan halaman Splunkbase-nya menyatakan add-on itu sudah tidak digunakan lagi [S3]. Pemetaan CIM dan nama field bisa berbeda dari add-on yang didukung Splunk, jadi jangan mencampur contoh dari dua era.
- Versi CIM add-on terbaru di Splunkbase saat riset adalah 8.7.0, rilis 2 September 2026 [S8]. Catatan ini sebelumnya memakai CIM 6.4 sebagai versi acuan, dan beda itu nyata: add-on yang satu mencantumkan dukungan CIM 8.x dan 6.x [S2], yang lain masih 4.x atau 5.x [S9][S11]. Sebelum mengandalkan sebuah field, cek matriks kompatibilitas add-on terhadap versi CIM yang terpasang.
- Splunk Add-on for Squid Proxy versi 2.1.0 (1 Desember 2023) dan Splunk Add-on for ISC BIND versi 2.0.0 (14 November 2020) keduanya berstatus arsip di Splunkbase, dengan dukungan CIM 5.x dan 4.x [S9][S11]. Untuk sumber open source seperti ini, rencanakan normalisasi sendiri atau jalur pengumpulan lain (Day 28).
- Fortinet FortiGate Add-On for Splunk versi 1.6.10 dirilis 9 Juni 2026 dan mencantumkan dukungan platform 9.0 sampai 10.6 serta CIM 4.x, 5.x, dan 6.x [S15]. Disebut di sini hanya sebagai pembanding bahwa vendor firewall lain punya jalur serupa.
- Halaman data model CIM yang dipakai Day ini (Network Traffic, Web, Network Resolution, Authentication) dibaca pada dokumentasi CIM versi 8.7 [S4][S5][S6][S7]. Pada Network Resolution, nilai baku `reply_code` bergaya kalimat dan nilai singkat gaya vendor keduanya diterima, dengan `reply_code_id` 0 sampai 3 sebagai pasangan numeriknya [S6].
- Detection "Excessive DNS Failures" di research.splunk.com ditandai experimental dan uji otomatisnya tercatat gagal, jadi perlakukan ambang dan logikanya sebagai titik awal [S13]. Artikel Lantern tentang tunneling lewat subdomain acak juga menyebut bahwa langkah terakhir contohnya merujuk field yang tidak dibuat oleh `stats` sebelumnya, sehingga query itu perlu disesuaikan sebelum menghasilkan hasil [S16].

## 7. Cheat sheet

```
SUMBER -> DATA MODEL
firewall traffic  pan:traffic        -> Network Traffic   (network, communicate)
firewall threat   pan:threat         -> Intrusion Detection + Web
proxy             squid:access       -> Web               (web; anak: proxy)
DNS               isc:bind:query     -> Network Resolution (network, resolution, dns)
VPN               pan:globalprotect  -> Authentication    (authentication)

FIELD KUNCI
Network Traffic  action=allowed|blocked|teardown  src dest src_port dest_port
                 transport=tcp|udp|icmp  bytes bytes_in bytes_out  app rule direction
Web              url uri_path site http_method http_user_agent status category
                 src dest user bytes_in bytes_out
DNS              query query_type record_type answer message_type=Query|Response
                 reply_code (No Error|NXDomain|...)  reply_code_id 0..3  src dest
Authentication   action=success|failure|pending|error  user src dest app reason_id

POLA CEPAT
inventaris     | tstats count where index IN (firewall,proxy,dns,vpn) by index sourcetype
nilai action   stats count BY action            (lakukan sebelum menulis kondisi)
keluar tak lazim  action=allowed dest_port IN (139,445,3389)
                  | where cidrmatch("10.0.0.0/8",src) AND NOT cidrmatch("10.0.0.0/8",dest)
tujuan baru    stats earliest(_time) AS p BY dest | where p >= relative_time(now(),"-24h")
DNS gagal      reply_code!="No Error" reply_code!="NoError"  -> stats BY src
subdomain      ut_parse(query) -> ut_shannon(ut_subdomain) -> len()
               entropi>3  panjang>20  stdev<2        (URL Toolbox, ambang disetel sendiri)
kronologi      | multisearch [search ... | eval sumber="dns"] [...]   (subsearch streaming saja)

JEBAKAN
HTTPS lewat proxy -> hanya CONNECT host:port, tidak ada uri_path
query log BIND    -> tidak ada reply_code/answer
CGNAT             -> satu IP publik = banyak pelanggan
pool VPN          -> IP yang sama berganti pemilik; selalu batasi waktu
index disampling  -> pakai rasio, bukan ambang absolut
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** Analyst menjalankan analisis NXDOMAIN di `sourcetype=isc:bind:query` dan mendapat nol baris. Ia menyimpulkan resolver pelanggan sehat. Benarkah?

<details><summary>Jawaban</summary>

Tidak. Query log BIND mencatat pertanyaan, bukan jawaban, sehingga `reply_code` dan `answer` bisa kosong dan filter apa pun pada kode jawaban akan mengembalikan nol baris walaupun kegagalan resolusi terjadi dalam jumlah besar. Periksa dulu dengan `stats count BY message_type reply_code`; untuk mendapatkan kode jawaban, butuh kanal log resolver lain, dnstap, atau penangkapan pasif. Tanpa kode jawaban, pakai volume dan jumlah nama unik per sumber sebagai pengganti. Lihat bagian 1.4 dan 2.5.

</details>

**2. Skenario keputusan.** Pelanggan korporat melapor IP kantornya diblokir. Langkah pertama yang paling tepat?

- A. Jawab bahwa firewall tidak memblokir pelanggan, karena aturan default mengizinkan trafik portal.
- B. Cari semua sesi yang melibatkan alamat itu pada rentang waktu keluhan, kelompokkan per perangkat pencatat, tujuan, aplikasi, dan nama aturan, lalu lihat apa yang diizinkan dan apa yang ditolak.
- C. Minta tim jaringan mematikan aturan deny yang mencurigakan supaya keluhan selesai.

<details><summary>Jawaban</summary>

B. Pertanyaan pelanggan hanya bisa dijawab dengan bukti per sesi, dan hampir selalu jawabannya bukan "diblokir" atau "tidak diblokir" tetapi "layanan ini jalan, akses itu ditolak oleh aturan ini". Mengelompokkan sampai tingkat `rule` membuat jawabannya bisa diperiksa orang lain dan sering memunculkan pertanyaan balik yang lebih penting, misalnya kenapa perangkat pelanggan mencoba SSH ke jaringan manajemen. A adalah tebakan tanpa data. C mengubah kebijakan untuk menutup keluhan, dan justru menghapus kontrol yang bekerja sebagaimana mestinya. Lihat bagian 1.2 dan 2.2.

</details>

**3. Pertanyaan jebakan.** "Log proxy tidak berguna lagi karena semua trafik sudah HTTPS." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Yang hilang pada trafik HTTPS lewat proxy adalah path dan parameter URL, karena setelah request `CONNECT` yang tercatat tinggal metadata. Yang tetap ada justru sering cukup untuk triage: nama host tujuan, port, waktu, jumlah byte masuk dan keluar, user agent, dan yang paling bernilai, nama akun yang melakukan request. Kombinasi user agent tak lazim dengan byte keluar yang jauh lebih besar daripada byte masuk bisa cukup untuk eskalasi tanpa melihat path sama sekali. Lihat bagian 1.3 dan 2.4.

</details>

**4. Skenario keputusan.** Detection publik untuk kegagalan DNS memakai ambang lebih dari 50 kejadian per sumber. Index DNS pelanggan di PT JAB disampling. Apa yang kamu lakukan sebelum memakainya?

- A. Pakai apa adanya, karena ambang itu berasal dari konten resmi.
- B. Turunkan ambang menjadi 10 supaya lebih sensitif.
- C. Ubah logikanya menjadi rasio terhadap total query per sumber, dan sesuaikan ambang absolut dengan rasio sampling.

<details><summary>Jawaban</summary>

C. Ambang absolut mengasumsikan semua event tersimpan. Pada index yang disampling, hitungan apa pun hanya sebagian dari kenyataan, sehingga ambang 50 bisa berarti ribuan kejadian nyata, dan satu perubahan rasio sampling akan mengubah perilaku detection tanpa ada yang mengubah SPL-nya. Rasio terhadap total per sumber tahan terhadap perubahan itu. A keliru karena halaman detection-nya sendiri menandai ambang itu untuk disesuaikan dan menandai detection-nya experimental. B hanya menebak arah tanpa memperbaiki sebabnya. Lihat bagian 1.5 dan 2.5.

</details>

**5. Jelaskan ulang.** Jelaskan kepada analyst L1 baru, dalam tiga kalimat, kenapa pemetaan alamat VPN ke nama orang harus selalu disertai rentang waktu.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Alamat di pool VPN dipinjamkan per sesi, jadi setelah seseorang disconnect, alamat yang sama bisa diberikan ke orang lain beberapa menit kemudian. Kalau kita mencari pemilik 10.10.250.17 untuk rentang sembilan jam, kita bisa mendapat dua akun sekaligus dan tidak tahu mana yang memegangnya pada jam kejadian. Karena itu pemetaan selalu dibatasi ke sekitar waktu kejadian dan, kalau vendor mencatat logout, dipisahkan per sesi, lalu ditulis di tiket sebagai 'alamat ini dipetakan ke akun itu pada rentang jam tersebut'."

Kesalahan yang sering muncul:
- Menyebut alamat VPN seolah milik tetap satu orang, seperti nomor meja.
- Lupa bahwa satu orang bisa punya dua sesi sekaligus (laptop dan ponsel) dengan dua alamat.
- Menyimpulkan identitas dari alamat saja padahal akun bersama (vendor, akun uji) dipakai beberapa orang.

</details>

**6. Pertanyaan jebakan.** "Ada koneksi ke alamat luar di log firewall tetapi tidak ada query DNS sebelumnya, berarti log DNS kita rusak." Benarkah?

<details><summary>Jawaban</summary>

Belum tentu, dan tiga penjelasan lain justru lebih menarik. Alamat tujuan bisa ditulis langsung di konfigurasi aplikasi atau di malware sehingga tidak perlu resolusi nama; nama bisa sudah ada di cache klien dari jam sebelumnya sehingga query-nya terjadi di luar rentang search; atau klien memakai resolver lain, misalnya DNS over HTTPS ke penyedia publik, sehingga pertanyaannya memang tidak pernah lewat resolver-mu. Yang terakhir itu temuan tersendiri, karena berarti visibilitas DNS untuk host itu tidak lengkap. Lihat bagian 1.7.

</details>

**7. Interview question (English).** "You have firewall, proxy, DNS and VPN logs in Splunk. Walk me through how you would investigate a host suspected of exfiltrating data."

<details><summary>Sample answer</summary>

"I'd start by checking what data I actually have for that host and whether the CIM fields are populated, because a quick inventory by index and sourcetype often shows gaps or duplicated inputs before I waste time on a search. Then I'd use the firewall traffic log to establish the shape of the outbound activity: destinations, ports, applications, and bytes out rather than total bytes, keeping the source inside our internal ranges and excluding internal destinations with cidrmatch. Next I'd use the proxy log for the web part, and I'd expect only CONNECT host and port for HTTPS, so I'd lean on user agent, byte direction, and the account name instead of the URL path. On the DNS side I'd look at the names that host asked for just before the connections, checking volume, unique names, record types, failure codes if that source carries responses, and subdomain length and entropy for tunneling patterns. If the host came in over VPN I'd map the tunnel address to an account within the exact time window, because the pool gets reused. Finally I'd put all of it in one timeline, state the keys I used to join it, and be explicit about what the data cannot tell me: no payload, no URL path, and possibly incomplete DNS if the client resolves names somewhere else."

What makes this answer strong: it validates the data before trusting it, uses the right field for the question (bytes out, not total), names the specific blind spots of each source, handles the VPN-to-identity mapping correctly, and ends with what the evidence cannot prove.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Splunk Add-on for Palo Alto Networks: Source types (CIM mapping) | https://splunk.github.io/splunk-add-on-for-palo-alto-networks/Cimmapping/ | primer (Splunk) | add-on 4.0.0; diakses 2026-10-14 | Tinggi. Daftar 25 sourcetype dan data model CIM tiap sourcetype |
| S2 | Splunkbase: Splunk Add-on for Palo Alto Networks | https://splunkbase.splunk.com/app/7523 | primer | versi 4.0.0, 2026-08-14; diakses 2026-10-14 | Tinggi untuk versi, kompatibilitas platform, dan CIM |
| S3 | Splunkbase: Palo Alto Networks Add-on for Splunk (arsip) | https://splunkbase.splunk.com/app/2757 | primer | versi 8.1.3, 2024-05-24; diakses 2026-10-14 | Tinggi. Status arsip dan tidak didukung |
| S4 | Splunk CIM 8.7: Network Traffic | https://help.splunk.com/en/data-management/common-information-model/8.7/data-models/network-traffic | primer | CIM 8.7; diakses 2026-10-14 | Tinggi. Nilai baku `action`, field byte, `rule`, `direction`, tag dataset |
| S5 | Splunk CIM 8.7: Web | https://help.splunk.com/en/data-management/common-information-model/8.7/data-models/web | primer | CIM 8.7; diakses 2026-10-14 | Tinggi. Field URL, user agent, status, `category`, tag dataset |
| S6 | Splunk CIM 8.7: Network Resolution (DNS) | https://help.splunk.com/en/data-management/common-information-model/8.7/data-models/network-resolution-dns | primer | CIM 8.7; diakses 2026-10-14 | Tinggi. `message_type`, `reply_code` dan `reply_code_id`, `record_type`, tag dataset |
| S7 | Splunk CIM 8.7: Authentication | https://help.splunk.com/en/data-management/common-information-model/8.7/data-models/authentication | primer | CIM 8.7; diakses 2026-10-14 | Tinggi. Nilai baku `action`, `reason_id`, tag dataset dan anaknya |
| S8 | Splunkbase: Splunk Common Information Model (CIM) | https://splunkbase.splunk.com/app/1621 | primer | versi 8.7.0, 2026-09-02; diakses 2026-10-14 | Tinggi untuk versi CIM terbaru |
| S9 | Splunkbase: Splunk Add-on for Squid Proxy (arsip) | https://splunkbase.splunk.com/app/2965 | primer | versi 2.1.0, 2023-12-01; diakses 2026-10-14 | Tinggi untuk versi, status arsip, dan CIM 5.x |
| S10 | Splunk Supported Add-ons: Squid Proxy | https://help.splunk.com/en/supported-add-ons/splunk-supported-add-ons/squid-proxy | primer | diakses 2026-10-14 | Sedang. Menyebut pengumpulan lewat file monitoring pada access log dan knowledge CIM-compatible, tanpa nama sourcetype |
| S11 | Splunkbase: Splunk Add-on for ISC BIND (arsip) | https://splunkbase.splunk.com/app/2876 | primer | versi 2.0.0, 2020-11-14; diakses 2026-10-14 | Tinggi untuk versi, status arsip, dan CIM 4.x |
| S12 | Splunk Security Content: Detect Outbound SMB Traffic | https://research.splunk.com/network/1bed7774-304a-4e8f-9d72-d80e45ff492b | primer (Splunk) | diakses 2026-10-14 | Tinggi. Pola trafik keluar, daftar blok non-publik, catatan false positive |
| S13 | Splunk Security Content: Excessive DNS Failures | https://research.splunk.com/network/104658f4-afdc-499e-9719-17243f9826f1 | primer (Splunk) | diakses 2026-10-14 | Sedang-tinggi. Ditandai experimental; ambang dan filter kode jawaban |
| S14 | Splunk Lantern: Network resolution data | https://lantern.splunk.com/Data_Types/Network_resolution_data | primer (Splunk) | diakses 2026-10-14 | Sedang-tinggi. Daftar jalur pengumpulan data DNS |
| S15 | Splunkbase: Fortinet FortiGate Add-On for Splunk | https://splunkbase.splunk.com/app/2846 | primer (vendor) | versi 1.6.10, 2026-06-09; diakses 2026-10-14 | Tinggi untuk versi dan kompatibilitas CIM |
| S16 | Splunk Lantern: DNS tunneling through randomized subdomains | https://lantern.splunk.com/Security/Use_Cases/Threat_Hunting/Monitoring_a_network_for_DNS_exfiltration/DNS_tunneling_through_randomized_subdomains | primer (Splunk) | diakses 2026-10-14 | Sedang-tinggi. Ambang entropi dan panjang subdomain, kebutuhan URL Toolbox, catatan query perlu disesuaikan |

**Catatan sumber:** nama sourcetype `squid:access` dan `isc:bind:query` tidak dapat dikonfirmasi langsung karena halaman source types kedua add-on di dokumentasi Splunk tidak dapat dibuka saat riset; yang terkonfirmasi adalah keberadaan, versi, dan status arsip kedua add-on [S9][S10][S11]. Cocokkan nama sourcetype dengan dokumentasi add-on versi-mu atau dengan `props.conf` add-on itu sendiri sebelum menulis search produksi. Nama field untuk alamat tunnel VPN (`private_ip` di contoh bagian 2.7) berasal dari penamaan log GlobalProtect dan bukan field CIM; nama persisnya perlu dicek di instance-mu. Kebutuhan sourcetype pembuka supaya add-on Palo Alto memecah log per jenis berasal dari forum praktisi dan ditandai sebagai klaim komunitas di bagian 1.1; versi 4.0.0 belum dikonfirmasi memakai mekanisme yang sama. Nilai dan pola di seluruh keluaran ilustrasi adalah data fiktif PT JAB, bukan hasil eksekusi.
