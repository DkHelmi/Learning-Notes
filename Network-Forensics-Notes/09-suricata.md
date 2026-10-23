---
day: 09
title: 'Suricata: rule, alert, eve.json, community_id ke Zeek, ruleset dan tuning, IDS vs IPS, serta onboarding ke Splunk'
researched_on: 2026-10-22
versions_checked: 'Suricata 8.0.7 (15 Sep 2026, rilis keamanan dengan 67 kerentanan diperbaiki; cabang 7.x EOL dengan rilis terakhir 7.0.17, LibHTP diarsipkan); dokumentasi Suricata 8.0.7 (rules intro, meta keywords, thresholding, JA3/JA4 keywords, eve-json-output, suricata.yaml) dan dokumentasi latest (eve-json-format, global thresholds, suricata-update, IPS/inline, upgrade notes 7.0 ke 8.0 dan 8.x ke 9.0 yang belum dirilis); suricata-update docs (readthedocs latest); Community ID spec v1 (Corelight); sidallocation.org; ET FAQ (ET Open BSD, ETPRO per sensor); Splunkbase CCX Add-on for Suricata 1.0.1 (app 6994, 8 Agu 2025) dan SuriZeek 1.5.8 (app 9818, 10 Okt 2026); rujukan Day 01-08'
---

# Day 09: Suricata, dari rule dan alert ke triage yang bisa dipertanggungjawabkan

Cakupan: cara Suricata mencocokkan trafik dengan rule dan menulis alert serta event protokol ke `eve.json`, cara membaca rule dan alert untuk triage, cara menyambung alert ke log Zeek lewat `community_id`, cara merawat ruleset (ET Open, ET Pro, `suricata-update`) dan menekan bising dengan threshold, suppress, dan disable, beda mode IDS dan IPS, perubahan penting Suricata 8.x, serta pilihan sourcetype dan volume saat `eve.json` masuk Splunk.

## Ide inti

Suricata membaca trafik yang sama dengan Zeek, tetapi pertanyaannya berbeda. Zeek bertanya "apa yang terjadi" dan menulis catatan untuk setiap transaksi. Suricata bertanya "apakah ada yang cocok dengan rule" dan menulis alert setiap kali sebuah rule cocok. Alert adalah klaim sebuah rule tentang satu paket atau satu transaksi, bukan kesimpulan tentang sebuah insiden. Rule yang memeriksa SNI hanya membuktikan bahwa nama itu diminta di ClientHello; rule yang memeriksa URI hanya membuktikan bahwa string itu dikirim, bukan bahwa server memprosesnya. Karena itu triage alert selalu punya bentuk yang sama: baca apa yang diklaim rule, cek apakah konteks koneksinya cocok dengan klaim itu, lalu putuskan apakah ini sinyal, bising yang perlu dituning, atau masalah sensor.

Konteks itu datang dari tiga lapis. Di dalam satu alert, objek protokol (`http`, `tls`, `dns`) dan `flow_id` menunjukkan koneksi mana yang memicu. Di dalam `eve.json`, event `flow`, `dns`, `http`, `tls`, `fileinfo`, dan `anomaly` dengan `flow_id` yang sama melengkapinya. Di luar Suricata, `community_id` menyambung alert ke `conn.log` Zeek, dan dari sana ke `uid`, log proxy, dan pcap. Hari pertama sensor IDS hampir selalu ramai, dan sebagian besar keramaiannya bukan serangan: kebiasaan jaringan sendiri yang kebetulan cocok dengan rule, latar belakang internet, dan gejala sensor yang kehilangan paket. Pekerjaan minggu pertama adalah memisahkan ketiganya, menuliskan setiap tuning dengan alasan dan tanggal tinjau, dan memastikan sedikit alert yang benar-benar penting tidak tenggelam.

Kamu sudah mengenal bentuk ini dari NOC: alarm threshold di NMS. Alarm "CPU di atas 90%" atau "interface flapping" berbunyi karena aturan terpenuhi, bukan karena ada yang rusak; hari pertama NMS baru dipasang, ratusan alarm muncul dari perangkat yang memang begitu sejak lama, dan pekerjaan pertamamu adalah menyetel threshold, membuat maintenance window, dan memastikan alarm link down di uplink utama tidak tenggelam. Batas analoginya ada dua. Pertama, alarm NMS berasal dari counter perangkat sendiri yang jujur, sedangkan rule Suricata hanya mengenal pola yang sudah ditulis orang: diam bukan berarti aman, dan penyerang bisa sengaja menghindari pola. Kedua, alarm NMS jarang perlu dibuktikan isinya, sedangkan setiap alert Suricata perlu dicek terhadap konteks koneksinya sebelum menjadi temuan.

```
 kantor JKT ---(core switch DC, SPAN)---+                  +--- TAP egress JKT (sisi dalam jkt-fw01, sebelum NAT)
                                        v                  v
                                   jkt-npb01 10.20.70.10 (agregasi + dedup)
                                   /                 |                \
               jkt-ids01 10.20.70.11       jkt-zeek01 10.20.70.12    jkt-pcap01 10.20.70.13 (egress saja)
               Suricata 8.0.7, IDS pasif   Zeek 9.0 LTS
                    |                           |
   eve-alert.json (alert, anomaly, stats)       /opt/zeek/logs/current/*.log (JSON)
   eve-proto.json (flow, dns, http, tls, files: tetap di sensor 7 hari)
                    |                           |
          index=suricata sourcetype=suricata    index=zeek sourcetype=bro:<log>:json
                    \__________ community_id (hash 5-tuple, seed 0) __________/
                                        |
                          index=proxy (siapa di balik 10.20.3.60), pcap egress 72 jam
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan sekitar 1.200 karyawan, kantor pusat dan data center di Jakarta, dan NOC 24/7 yang satu lantai dengan SOC. Sejak Senin 2027-05-03, PT JAB menjalankan "Program NSM PT JAB" sebagai percobaan Mei sampai Juli 2027: TAP egress Jakarta di sisi dalam firewall `jkt-fw01` dan SPAN core switch data center masuk ke packet broker `jkt-npb01`, lalu dibagikan ke sensor. Workstation kantor keluar ke web lewat proxy eksplisit `jkt-proxy01` (`10.20.3.60:3128`, Squid dengan dekripsi untuk domain baru atau tidak terkategori) dan me-resolve nama lewat resolver `jkt-res01` (`10.20.2.53`). Kemarin, Selasa 2027-05-18, `jkt-zeek01` masuk produksi dengan Community ID aktif. Rabu 2027-05-19 pukul 08:00 WIB, tim Agung Prabowo (Lead Infrastruktur) menyatakan `jkt-ids01` (Suricata 8.0.7, ruleset ET Open ditambah rule lokal PT JAB) produksi, dan alert-nya mulai masuk Splunk index `suricata`. Sampai pukul 16:00, index itu menerima 1.374 alert dari 61 signature. Di antaranya: 640 alert SNMP dari server monitoring (`SOC-2027-0640`), 118 alert user agent Nmap dari `203.0.113.177` ke portal pelanggan (`SOC-2027-0641`), alert rule lokal C2 yang menunjuk proxy dan resolver, bukan workstation (`SOC-2027-0642`, menjadi `INC-2027-068`), ratusan alert `SURICATA STREAM` bersamaan dengan drop kernel di sensor (`SOC-2027-0643`), dan enam percobaan path traversal ke portal yang tercatat `allowed` (`SOC-2027-0644`). Pukul 16:45, SOC lead Dimas Prasetyo menulis kepadamu:

> "Suricata hari pertama: 1.374 alert, Gilang dan Dwi kewalahan. Besok pagi aku lapor ke Pak Hendra, tolong bantu. Pertama, kita sudah punya Zeek sejak kemarin, kenapa masih perlu Suricata? Kedua, Gilang tidak paham cara membaca alert dan rule-nya; sid, rev, classtype itu apa? Ketiga, alert C2 tadi pagi menunjuk 10.20.3.60 dan 10.20.2.53, padahal itu proxy dan resolver kita sendiri; jadi workstation mana, dan di eve.json sebenarnya ada apa saja? Keempat, bagaimana menyambung alert ini ke log Zeek kemarin? Kelima, dari 1.374 alert ini mana yang layak dieskalasi? Keenam, alert SNMP 640 biji itu bisa dimatikan saja? Ruleset gratis cukup atau kita perlu beli ET Pro? Ketujuh, Pak Hendra pasti tanya: kenapa percobaan eksploit ke portal tidak diblokir, padahal alat ini katanya IPS? Terakhir, sourcetype apa di Splunk, berapa GB per hari, dan alert STREAM ratusan itu tanda sensornya sakit?"

Pesan itu memuat delapan pertanyaan:

1. Apa beda Suricata dengan Zeek, dan kenapa perlu keduanya?
2. Bagaimana membaca satu alert dan rule di baliknya (sid, rev, classtype)?
3. Kenapa alert C2 menunjuk proxy dan resolver, dan apa saja isi `eve.json`?
4. Bagaimana menyambung alert Suricata ke log Zeek?
5. Dari 1.374 alert, mana yang layak dieskalasi?
6. Bolehkah alert yang berisik dimatikan, dan cukupkah ET Open atau perlu ET Pro?
7. Kenapa percobaan eksploit tidak diblokir; perlukah IPS?
8. Sourcetype apa di Splunk, berapa volumenya, dan apakah sensor sehat?

Pertanyaan 1 dijawab di bagian 1.1, pertanyaan 2 di bagian 1.2 dan 1.3, pertanyaan 3 di bagian 1.4, pertanyaan 4 di bagian 1.5, pertanyaan 5 di bagian 1.6, pertanyaan 6 di bagian 1.7 dan 1.8, pertanyaan 7 di bagian 1.9, dan pertanyaan 8 di bagian 1.10. Bagian 1.11 menjelaskan batas deteksi signature dan perubahan Suricata 8.x yang memengaruhi semuanya. Bagian 2 berisi artefak hari pertama `jkt-ids01`: perintah offline di `jkt-nsm-ws01`, pembacaan alert dan rule, korelasi `flow_id` dan `community_id` untuk `INC-2027-068`, triage lima alert, tuning, onboarding Splunk, kesehatan sensor, dan satu halaman jawaban untuk Dimas.

**Kapan relevan:** saat butuh alert awal untuk pola yang sudah dikenal (C2 yang diketahui, eksploit, pemindaian, pelanggaran kebijakan) di trafik yang terlalu besar untuk dibaca manusia; saat ingin menerapkan IOC jaringan (domain, SNI, JA3/JA4, URI) sebagai rule yang langsung jalan di sensor; dan saat triage alert jaringan di SIEM.
**Kapan bukan jawaban:** saat pertanyaannya "apa saja yang dilakukan host ini seminggu" (pakai log Zeek dan flow); saat ancamannya belum punya rule atau sengaja menghindari pola; saat isi koneksi terenkripsi dan rule butuh payload; dan saat sensor sedang kehilangan paket, karena tidak adanya alert lalu tidak berarti apa-apa.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (pcap, SPAN, TAP, packet broker, SNI, JA3/JA4, `uid`, `conn_state`, capture loss, sourcetype, Community ID sebagai konsep) tidak diulang. Tabel ini hanya memuat istilah yang dipakai Day ini; kolom padanan memakai pengalaman NOC dan ISP.

| Istilah | Arti singkat | Padanan di NOC/ISP |
|---|---|---|
| Suricata | Engine IDS/IPS dan NSM yang mencocokkan trafik dengan rule dan menulis alert serta event protokol | NMS dengan aturan alarm, ditambah probe yang mengurai protokol |
| Rule (signature) | Satu baris teks: action, header, dan options yang mendefinisikan pola yang dicari | Satu aturan alarm di NMS (kondisi, ambang, pesan) |
| Action | Apa yang dilakukan saat rule cocok: `alert`, `pass`, `drop`, `reject` | Severity dan tindakan otomatis alarm |
| Header | Protokol, alamat, port, dan arah yang diperiksa rule | Lingkup alarm: perangkat dan interface mana |
| Options | Isi rule di dalam kurung: `msg`, `content`, `flow`, sticky buffer, `classtype`, `sid`, `rev` | Kondisi detail alarm dan teks pesannya |
| Sticky buffer | Keyword yang menentukan bagian protokol mana yang diperiksa `content` sesudahnya (`tls.sni`, `http.uri`, `dns.query`) | Memilih OID tertentu, bukan seluruh MIB |
| `sid`, `rev`, `gid` | ID unik rule, nomor revisinya, dan grup rule | ID aturan alarm dan versi template-nya |
| `classtype` | Kategori rule yang membawa prioritas bawaan dan menjadi `severity` di alert | Kelas alarm critical, major, minor |
| Ruleset | Kumpulan rule dari satu sumber (ET Open, ET Pro, rule lokal) | Paket template alarm dari vendor NMS |
| ET Open / ET Pro | Ruleset Emerging Threats gratis (BSD) dan berbayar per sensor | Template komunitas vs template berlangganan dari vendor |
| `suricata-update` | Alat resmi untuk mengunduh, menggabungkan, dan memodifikasi ruleset | Sistem distribusi konfigurasi yang menimpa template sambil menjaga pengecualian lokal |
| Threshold, suppress, disable | Membatasi frekuensi alert, menghilangkan alert untuk kombinasi tertentu, mematikan rule | Dampening, pengecualian per perangkat, mematikan aturan alarm |
| `eve.json` | Output JSON Suricata: satu event per baris dengan `event_type` | Syslog terstruktur dari NMS dan probe sekaligus |
| `event_type` | Jenis event di `eve.json`: `alert`, `flow`, `dns`, `http`, `tls`, `fileinfo`, `anomaly`, `stats`, dan lainnya | Facility syslog |
| `flow_id` | ID satu flow di dalam satu instance Suricata, menghubungkan event dari flow yang sama | Session ID di satu probe |
| `community_id` | Hash standar 5-tuple yang sama di Suricata, Zeek, Wireshark, dan alat lain | Kunci flow bersama dua kolektor berbeda |
| Engine event | Rule bawaan Suricata untuk keganjilan decoder, stream, dan app-layer (`SURICATA ...`) | Alarm internal perangkat: CRC error, out-of-order |
| IDS / IPS | Mode pasif yang hanya mengamati salinan trafik / mode inline yang bisa membuang paket | Port mirror ke analyzer / perangkat in-path seperti firewall |
| `HOME_NET` | Variabel alamat yang dianggap jaringan sendiri dan dipakai di header rule | Daftar prefiks pelanggan sendiri di kolektor flow |

### 1.1 Suricata dan Zeek: deteksi dan catatan

Pertanyaan pertama Dimas wajar: kemarin Zeek sudah menghasilkan lebih dari dua puluh log, dan hari ini ada sensor lain yang membaca trafik yang sama.

Zeek mencatat kejadian; Suricata menambahkan deteksi berbasis rule [S1]. Suricata mencocokkan trafik dengan ribuan signature dan menaikkan alert saat pola known-bad muncul (eksploit, C2 malware, pemindaian, pelanggaran kebijakan). Suricata juga bisa menjadi IPS yang memblokir, dan menghasilkan log protokol yang kaya di `eve.json`, mirip Zeek. Di SOC, alert Suricata menjadi titik awal yang lalu diinvestigasi dengan Zeek, log proxy, dan Wireshark. Tabel berikut meringkas perbedaannya; baris terakhir adalah cara paling cepat mengingatnya.

| | Suricata | Zeek |
|---|---|---|
| Fokus | Deteksi berbasis rule (alert) | Pencatatan kejadian (log) |
| Output | Alert dan `eve.json` (log kaya) | Log per protokol |
| Mode | IDS (deteksi) atau IPS (blokir) | Observasi (tidak memblokir) |
| Kekuatan | Mengenali known-bad dengan cepat | Konteks dan korelasi luas |
| Penghubung antar event | `flow_id` di satu instance | `uid` di satu sensor |
| Analogi | Rule deteksi untuk paket | Telemetry terstruktur |

Keduanya memahami protokol dan bisa menghasilkan log; Suricata menonjol pada deteksi signature, Zeek pada analitik dan konteks. Banyak lingkungan memakai keduanya. Rule Suricata juga contoh detection-as-code: logika deteksi disimpan sebagai teks yang punya ID dan nomor revisi, dan bisa direview serta diuji seperti kode, persis cara tim deteksi mengelola rule untuk log (misalnya rule berformat Sigma, standar terbuka untuk menulis deteksi log yang bisa dikonversi ke bahasa query SIEM mana pun).

Jawaban untuk Dimas: Zeek adalah buku catatan, Suricata adalah alarm. Alarm tanpa buku catatan membuat analis tidak bisa membuktikan apa pun; buku catatan tanpa alarm membuat analis harus mencari sendiri setiap pagi. Di PT JAB, alert Suricata masuk antrean triage, lalu dibuktikan atau dibantah dengan log Zeek, log proxy, dan pcap.

### 1.2 Anatomi rule

Pertanyaan kedua Dimas datang dari Gilang (L1) yang membuka alert `SOC-2027-0642` dan melihat `sid 1000101`, `rev 1`, `classtype trojan-activity`, tanpa tahu apa artinya.

Rule Suricata punya tiga bagian: action, header, dan options [S2][S12].

```
action  header                                    options
alert   tcp $HOME_NET any -> $EXTERNAL_NET 443    (msg:"..."; flow:...; content:"..."; sid:...; rev:...;)
```

- **Action:** apa yang dilakukan saat cocok. Dokumentasi Suricata mendaftarkan `alert` (buat alert), `pass` (hentikan pemeriksaan paket itu), `drop` (buang paket dan buat alert), `reject` (kirim RST atau ICMP unreachable ke pengirim), serta `rejectsrc`, `rejectdst`, dan `rejectboth`; di mode IPS, setiap reject juga membuang paket [S12]. `drop` dan `reject` adalah action IPS (bagian 1.9).
- **Header:** protokol, sumber, port, arah, tujuan, port. Variabel `$HOME_NET` dan `$EXTERNAL_NET` diisi di konfigurasi. Arah `->` hanya mencocokkan paket ke arah itu, `<>` mencocokkan dua arah (Suricata menggandakan rule-nya), dan `=>` mengikuti arah `->` tetapi boleh mencocokkan transaksi dua arah; tidak ada arah `<-` [S12]. Protokol di header bisa protokol lapisan bawah (`tcp`, `udp`) atau protokol aplikasi (`http`, `tls`, `dns`), yang membuat rule hanya cocok bila parser mengenali protokol itu.
- **Options:** di dalam kurung, dipisah titik koma. Urutan options bermakna; mengubah urutannya mengubah arti rule [S12].

Dokumentasi Suricata memberi contoh rule berikut [S12]: rule ini memberi alert untuk request GET dari jaringan sendiri ke luar yang URI-nya memuat kata "rule".

```
alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"HTTP GET Request Containing Rule in URI"; flow:established,to_server; http.method; content:"GET"; http.uri; content:"rule"; fast_pattern; classtype:bad-unknown; sid:123; rev:1;)
```

Option yang paling sering kamu temui saat membaca rule ET Open dan rule lokal [S2][S13]:

| Option | Arti saat triage |
|---|---|
| `msg` | Teks yang muncul sebagai `alert.signature`. Konvensinya: awalan huruf besar yang menunjukkan kelas (`ET MALWARE`, `ET SCAN`, `GPL SNMP`, `JAB LOCAL`) |
| `flow:established,to_server` | Rule hanya cocok pada koneksi yang sudah terbentuk, arah klien ke server. Alert dari rule ini tidak mungkin dipicu SYN scan |
| `content:"..."` | String atau byte yang harus ada. Huruf besar/kecil berpengaruh kecuali ada `nocase` |
| Sticky buffer (`http.uri`, `http.user_agent`, `dns.query`, `tls.sni`, `ja3.hash`, `ja4.hash`) | Menentukan bagian protokol mana yang dicocokkan `content` sesudahnya. Rule dengan `tls.sni` hanya melihat SNI, bukan isi terenkripsi |
| `pcre:"/.../"` | Pola regex, biasanya pelengkap `content` |
| `classtype` | Kategori (misalnya `trojan-activity`, `attempted-recon`) yang didefinisikan di `classification.config` dengan nama panjang dan prioritas; prioritas itu menentukan `severity` alert, dan nama panjangnya muncul sebagai `alert.category` |
| `priority` | Angka 1 sampai 255 (1 tertinggi; yang umum dipakai 1 sampai 4) yang menimpa prioritas dari `classtype` [S13] |
| `threshold` / `detection_filter` | Rule baru memicu setelah sejumlah kejadian dalam rentang waktu, umum di rule scan dan brute force (bagian 1.8) |
| `reference`, `metadata` | Rujukan (CVE, URL) dan atribut seperti tanggal dibuat (`created_at`, `updated_at`), `signature_severity`, dan target. Metadata membantu menilai umur dan keyakinan rule; pasangan key-value metadata bisa ikut tercatat di alert `eve.json` [S13] |
| `target` | Menyatakan sisi mana yang menjadi target (`src_ip` atau `dest_ip`), sehingga alert memuat informasi source dan target [S13] |
| `sid`, `rev`, `gid` | Identitas, revisi, dan grup. `gid` bawaan 1; alert ditulis sebagai `[gid:sid:rev]`, misalnya `[1:123:1]` [S13] |

Membaca option ini memberi pertanyaan triage yang tepat. Bila rule memakai `tls.sni; content:"x.example"`, satu-satunya yang dibuktikan alert adalah klien meminta nama itu di ClientHello; isi koneksi tidak pernah diperiksa. Bila rule memakai `content` tanpa sticky buffer pada `alert udp`, rule itu mencocokkan byte mentah paket dan alert-nya tidak membawa objek protokol (bagian 1.11).

Jawaban untuk Gilang: `sid 1000101` adalah ID rule (rentang 1000000 sampai 1999999 dicadangkan untuk rule lokal, bagian 1.3), `rev 1` berarti rule itu belum pernah direvisi, dan `classtype trojan-activity` adalah kategori "A Network Trojan was detected" yang di `classification.config` bawaan berprioritas 1, sehingga alert-nya ber-`severity` 1 [S13].

### 1.3 Membaca rule, bukan menulis serangan; menilai umur dan asal rule

Gilang lalu bertanya hal yang lebih berguna: "rule ini dari siapa, dan bisa dipercaya atau tidak?"

Day ini membaca rule untuk memahami deteksi, bukan membuat payload. Saat sebuah rule menyebut pola serangan (misalnya string eksploit di URI), itu dibaca sebagai "inilah yang dideteksi", bukan resep. Untuk memahami teknik serangan yang dideteksi, rujuk katalog resmi (MITRE ATT&CK, dan untuk uji terkendali gunakan nama atau ID test di katalog seperti Atomic Red Team) alih-alih menuliskan payload. Fokusnya selalu sisi deteksi dan triage.

Asal rule terbaca dari `sid`. Dokumentasi Suricata menyebut ada rentang `sid` yang dicadangkan dan dicatat di sidallocation.org, `sid` harus unik di dalam satu `gid`, dan karena `suricata-update` hanya melihat `sid`, sebaiknya pakai `sid` yang benar-benar unik [S13]. Tabel berikut adalah rentang yang paling sering kamu lihat di alert PT JAB, menurut sidallocation.org [S17]; cari rentang `sid` alert-mu di kolom kiri.

| Rentang `sid` | Pemilik |
|---|---|
| 1000000 sampai 1999999 | Lokal: rule buatan sendiri |
| 2000000 sampai 2103999 | Emerging Threats (ET Open) |
| 2200000 sampai 2299999 | OISF: engine event Suricata (`SURICATA ...`) |
| 2400000 sampai 2609999 | ET Open |
| 2800000 sampai 2899999 | ET Pro |
| 2700000 sampai 2799999, 100000000 sampai 199999999 | Emerging Threats (rentang tambahan) |
| 3000000 ke atas (selain rentang ET di atas) | Ruleset pihak lain, misalnya Corelight 3000000 sampai 3099999, Stamus Networks 3100000 sampai 3199999, abuse.ch 80000000 ke atas |

Rule ET Open sering disebut memakai rentang 2000000 sampai 2999999. Itu benar sebagai rentang besar milik Emerging Threats, tetapi tabel alokasi memisahkannya: engine event OISF ada di 22xxxxx dan ET Pro di 28xxxxx [S17]. Alert dengan `sid` 28xxxxx di sensor yang hanya memuat ET Open berarti ada sumber rule yang tidak kamu ketahui.

Umur rule terbaca dari `metadata` (`created_at`, `updated_at`) dan `rev`. Rule yang dibuat bertahun-tahun lalu untuk kampanye yang sudah mati lebih mungkin cocok dengan trafik sah yang kebetulan mirip. Rule lokal PT JAB diberi metadata sumber intel dan tanggal, supaya analis tahu dari mana IOC-nya dan kapan harus ditinjau.

### 1.4 `eve.json`: satu file, banyak `event_type`

Pertanyaan ketiga Dimas berasal dari alert `SOC-2027-0642`: rule lokal C2 untuk domain `telemetry-upd.example` memicu dua alert DNS dari `10.20.3.60` dan `10.20.2.53`, dan delapan alert TLS dari `10.20.3.60` ke `203.0.113.176:443`. Tidak satu pun menyebut workstation.

Suricata punya dua output yang sering dibaca:

- **fast.log:** satu baris per alert, ringkas (waktu, `[gid:sid:rev]`, msg, classification, prioritas, protokol, IP dan port). Cepat dibaca, tanpa konteks.
- **eve.json:** JSON kaya, satu event per baris, banyak tipe event, mirip log Zeek ditambah alert. Ini sumber utama untuk analisis dan SIEM [S3].

Setiap event `eve.json` punya field umum: `timestamp` (presisi mikrodetik, dengan offset zona waktu), `flow_id`, `event_type`, 5-tuple (`src_ip`, `src_port`, `dest_ip`, `dest_port`, `proto`), dan `app_proto` untuk event lapisan aplikasi [S7]. Saat memproses pcap, `pcap_cnt` dan `pcap_filename` ikut tercatat [S7]. Tabel berikut adalah tipe event yang dipakai PT JAB; kolom kanan adalah pertanyaan yang dijawab masing-masing [S3][S7].

| `event_type` | Isi utama | Pertanyaan yang dijawab |
|---|---|---|
| `alert` | `alert.action`, `gid`, `signature_id`, `rev`, `signature`, `category`, `severity`, `metadata`, ditambah objek protokol bila rule memakai keyword app-layer | Rule apa yang cocok, pada paket dan koneksi mana |
| `flow` | `pkts_toserver`, `pkts_toclient`, `bytes_toserver`, `bytes_toclient`, `start`, `end`, `age`, `state`, `reason`, `alerted` | Berapa besar dan berapa lama koneksi itu, dan bagaimana berakhir |
| `dns` | Query dan jawaban (format versi 3 bawaan di Suricata 8.0) | Nama apa ditanyakan, dijawab apa |
| `http` | `hostname`, `url`, `http_user_agent`, `http_content_type`; mode extended menambah `http_method`, `status`, `length`, `protocol`, `http_refer` | URL, user agent, status |
| `tls` | `sni`, `version`; mode extended menambah `subject`, `issuerdn`, `serial`, `fingerprint`, `notbefore`, `notafter`; `ja3`/`ja3s` dan `ja4` bila diaktifkan | Ke server bernama apa sesi terenkripsi itu |
| `fileinfo` | `filename`, `magic` (butuh libmagic), `md5`/`sha1`/`sha256`, `size`, `state`, `stored`, `gaps` | File apa yang berpindah, utuh atau tidak |
| `anomaly` | `type` (`decode`, `stream`, `applayer`), `event`, `layer` | Keganjilan protokol yang ditemui decoder, stream, atau parser |
| `stats` | Counter engine (capture, decoder, flow, app-layer) per interval | Apakah sensor sehat pada jam itu |

Beberapa detail field menentukan cara membaca:

- **`alert.action`** bernilai `allowed` atau `blocked`. Nilai `blocked` muncul bila rule `drop` di mode IPS, atau `reject`, bekerja [S7]. Di sensor pasif PT JAB, setiap alert `allowed` (bagian 1.9).
- **`severity`** 1 adalah tertinggi dan berasal dari prioritas `classtype` (atau `priority`) rule.
- **Hash file:** MD5 dan SHA1 hanya ditulis bila file tertutup tanpa celah dan hashing tidak dimatikan; SHA256 ditulis bila tersedia; `gaps` menandai bagian file yang hilang [S7]. File dengan `gaps` true dan hash kosong biasanya akibat paket hilang, bukan penyerang yang cerdik.
- **Event `flow`** adalah record dua arah; event `netflow` (bawaannya dikomentari) adalah record satu arah, sehingga jumlahnya sekitar dua kali `flow` [S3]. Counter `flow` ikut menghitung trafik yang di-bypass [S7].
- **Arah di event alert.** `src_ip` dan `dest_ip` di tingkat atas alert mengikuti paket yang memicu rule. Contoh di dokumentasi menunjukkan objek `flow` di dalam alert memuat alamat yang terbalik dari tingkat atas [S7], artinya arah paket dan arah flow bisa berbeda. Rule yang cocok pada respons server menghasilkan alert dengan `src_ip` server. Baca keduanya sebelum menulis "host X menyerang host Y".
- **`flow_id`** menghubungkan alert, `fileinfo`, `http`, `anomaly`, dan `flow` dari sesi yang sama [S7], mirip `uid` Zeek. Nilainya hanya berlaku di instance Suricata yang membuatnya.

Kembali ke `SOC-2027-0642`. Alert menunjuk proxy dan resolver karena itulah yang terlihat di titik sensor: workstation bertanya nama ke `jkt-res01`, dan proxy yang me-resolve nama tujuan web lalu membuka koneksi ke internet. Hop egress (proxy ke `203.0.113.176`) lewat TAP egress; query proxy ke resolver dan koneksi workstation ke proxy lewat SPAN core. `eve.json` mencatat ketiga hop itu sebagai flow terpisah dengan `flow_id` terpisah. Rule TLS SNI hanya cocok di hop egress, karena di hop core workstation membuka tunnel `CONNECT` ke proxy. Apakah Suricata 8 mengurai TLS di dalam tunnel `CONNECT` dan bisa memicu rule SNI yang sama di hop core perlu dicek di lab; di `jkt-ids01` hari pertama tidak ada alert dengan sumber workstation, sehingga workstation dicari lewat event `http` `CONNECT` di hop core, log Zeek, dan log proxy (bagian 2.7).

Satu konsekuensi lain dari proxy PT JAB: `jkt-proxy01` mendekripsi domain baru atau tidak terkategori, sehingga ClientHello di egress untuk koneksi yang didekripsi adalah buatan proxy. JA3/JA4 di event `tls` hop egress lalu milik proxy, bukan milik malware di workstation (Day 06 bagian 1.7). Rule berbasis SNI tetap bekerja karena proxy meneruskan nama tujuan di SNI-nya.

### 1.5 `community_id`: jembatan ke Zeek

Pertanyaan keempat Dimas: kemarin Sari merangkai `INC-2027-067` dengan `uid` Zeek; hari ini alert datang dari alat lain yang tidak mengenal `uid`.

`flow_id` Suricata dan `uid` Zeek adalah ID internal masing-masing alat. Penghubung lintas alat adalah Community ID: string standar yang dihitung dari 5-tuple dan sama di semua alat yang mendukungnya [S16]. Spesifikasinya [S16]:

- Masukan hash: seed 2 byte (bawaan 0), alamat sumber dan tujuan, protokol 1 byte diikuti 1 byte padding nol, lalu port sumber dan tujuan, semuanya dalam network byte order.
- Kedua ujung diurutkan sehingga pasangan IP:port yang lebih kecil ada di depan. Karena itu arah tidak berpengaruh: koneksi dari A ke B dan balasannya dari B ke A menghasilkan ID yang sama.
- Hash SHA-1 (20 byte), di-encode base64, diberi awalan versi `1:`. Contoh bentuknya di spesifikasi: `1:hO+sN4H+MG5MY/8hIrXPqc4ZQz0=`.
- ICMP memakai type dan code sebagai pengganti port; protokol IP lain hanya memakai alamat dan protokol.
- Spesifikasi menyebut tabrakan hash mungkin terjadi tetapi tidak fatal, karena waktu dan ID asli alat bisa membedakannya; ID dengan seed berbeda tidak boleh dibandingkan; enkapsulasi bertingkat, VLAN, dan MPLS tidak dicakup.
- Pendukung yang tercantum antara lain Zeek, Suricata (sejak 4.1), Wireshark (sejak 3.3.1), Arkime, dan Elastic.

Di Suricata, Community ID diaktifkan per instance `eve-log` dengan `community-id: true` (bawaannya `false`) dan `community-id-seed` 0 sampai 65535 (bawaan 0); dokumentasi menekankan bahwa seed harus sama di semua sensor dan alat [S3]. Di Zeek, Community ID bawaan sejak 6.0 lewat skrip `community-id-logging`, yang sudah aktif di `jkt-zeek01` sejak produksi (Day 08 bagian 1.7).

Ada tiga batas yang perlu diingat di PT JAB:

- **NAT dan proxy memutus ID.** Community ID dihitung dari 5-tuple yang dilihat sensor. Hop workstation ke proxy dan hop proxy ke internet adalah dua koneksi berbeda dengan ID berbeda, persis seperti dua `uid` berbeda di Zeek. Karena TAP egress di sisi dalam `jkt-fw01` (sebelum NAT), Suricata, Zeek, dan pcap egress melihat 5-tuple yang sama; log firewall sesudah NAT tidak.
- **Seed harus sama.** `jkt-ids01` dan `jkt-zeek01` memakai seed 0. Mengubah seed di satu alat saja membuat semua join gagal tanpa pesan error.
- **Satu ID bisa berulang.** Port sumber dipakai ulang setelah beberapa waktu; join yang benar memakai `community_id` ditambah jendela waktu.

Jawaban untuk Dimas: alert Suricata disambung ke `conn.log` Zeek lewat `community_id` yang sama, lalu dari `conn.log` ke log Zeek lain lewat `uid`, seperti kemarin. Hop yang tidak berbagi 5-tuple (workstation ke proxy) tetap disambung lewat waktu, host, dan log proxy.

### 1.6 Triage alert: benar, false positive, atau sensor

Pertanyaan kelima adalah inti hari ini: 1.374 alert, dua analis L1, dan satu pertanyaan "mana yang dieskalasi".

Alert bukan kesimpulan; ia titik awal triage. Langkahnya:

1. Baca `signature`, `category`, dan rule-nya: apa yang diklaim, dan dari bagian protokol mana (bagian 1.2).
2. Lihat konteks (IP, port, `flow`, `http`/`dns`/`tls` di `eve.json`): cocok dengan klaim?
3. Korelasikan dengan Zeek, log proxy, dan Wireshark: apakah trafik sungguh seperti yang dituduh rule?
4. Nilai sumber dan tujuan serta reputasinya: aset internal yang dikenal atau tujuan eksternal yang mencurigakan? Apakah targetnya benar-benar menjalankan perangkat lunak yang diserang?
5. Putuskan: benar (eskalasi), false positive atau benar tetapi tidak relevan (tuning), masalah sensor (perbaiki sensor), atau butuh data lebih.

Banyak alert adalah false positive (rule luas, trafik sah mirip pola). Keterampilan inti adalah memisahkan sinyal dari bising, persis prinsip minggu pertama program: alert adalah sinyal, konteks yang menentukan.

Ada satu pembedaan yang menghemat waktu: false positive (rule salah mengenali trafik) berbeda dengan benar tetapi tidak relevan (rule benar, tetapi di lingkunganmu kejadian itu diketahui dan diterima). Alert SNMP community `public` dari server monitoring sendiri adalah contoh yang kedua: rule-nya benar, kejadiannya nyata, dan tetap menyimpan risiko yang perlu tiket ke NOC, tetapi bukan insiden. Keduanya dituning dengan cara yang berbeda (bagian 1.8).

Kategori ketiga sering terlupa: alert yang lahir dari sensor. Engine event `SURICATA STREAM ...` dalam jumlah besar, terutama bila bersamaan dengan drop kernel di counter `stats`, biasanya berarti sensor tidak melihat semua paket atau melihat trafik satu arah, bukan berarti ada serangan (bagian 1.10).

Tabel berikut adalah urutan prioritas yang dipakai PT JAB untuk hari-hari pertama; cari baris yang cocok dengan alert-mu dari atas.

| Ciri alert | Perlakuan awal |
|---|---|
| Rule lokal dari intel atau `ET MALWARE` ke tujuan eksternal, dari aset internal | Eskalasi segera; cari host asal di balik proxy atau resolver |
| Rule serangan web ke aset publik PT JAB | Cek respons server (status, ukuran) dan apakah aset memakai perangkat lunak itu |
| `ET SCAN` dari internet | Catat, batasi dengan threshold; eskalasi hanya bila diikuti koneksi berhasil |
| `ET POLICY` dan `ET INFO` dari aset internal yang dikenal | Kandidat tuning setelah dicek pemilik aset |
| `SURICATA STREAM`, `SURICATA DECODE` dalam jumlah besar | Cek kesehatan sensor dulu, bukan host |

Jawaban untuk Dimas: dari 1.374 alert hari pertama, yang dieskalasi hanya 10 alert rule lokal C2 (`INC-2027-068`); 6 alert path traversal ke portal diperiksa dan ditutup sebagai percobaan yang gagal; sisanya bising yang dituning atau gejala sensor (bagian 2.9).

### 1.7 Ruleset: ET Open, ET Pro, rule lokal, dan `suricata-update`

Pertanyaan keenam Dimas berisi dua hal; bagian ini menjawab yang kedua: cukupkah ruleset gratis.

Suricata dijalankan dengan ruleset. ET Open (Emerging Threats) adalah ruleset gratis yang umum; ada juga ET Pro dan rule komersial atau internal. Ruleset diperbarui berkala karena ancaman berubah. Deteksi signature hanya sebaik ruleset: rule usang melewatkan ancaman baru, rule terlalu luas menghasilkan false positive.

Perbedaan ET Open dan ET Pro menurut FAQ Emerging Threats [S18]:

- **ET Open:** gratis dengan lisensi BSD, boleh dipakai sesukamu. Isinya signature kontribusi komunitas dan signature yang ditulis ET/Proofpoint dari riset komunitas.
- **ET Pro:** signature yang lahir dari riset Proofpoint sendiri (detonasi malware, jaringan sensor global, integrasi dengan produk lain). Lisensinya per instance sensor Snort atau Suricata; lisensi standar adalah lisensi enterprise untuk melindungi aset organisasi sendiri, dan memasukkan ET Pro ke produk atau layanan yang dijual ke pihak lain butuh lisensi OEM [S18].

Butir terakhir penting untuk PT JAB sebagai ISP. Bila suatu hari Suricata dengan ET Pro dipakai untuk layanan keamanan yang dijual ke pelanggan korporat, lisensi standar tidak cukup. Untuk percobaan ini, ET Pro hanya relevan bila dipakai di `jkt-ids01` untuk melindungi PT JAB sendiri. Harga dan syarat terkini perlu dicek ke Proofpoint atau reseller; FAQ yang dipakai di sini bertanggal 2022.

Rule lokal melengkapi keduanya. Rule `JAB LOCAL` dibuat dari intel yang relevan untuk PT JAB (IOC dari ISAC, temuan insiden sebelumnya), diberi `sid` di rentang lokal, dan disimpan di repositori konfigurasi seperti kode.

`suricata-update` adalah alat resmi untuk mengelola rule dan ikut terpasang sejak Suricata 4.1 [S11]. Secara bawaan ia mengunduh ET Open, menggabungkan semua rule menjadi satu berkas `/var/lib/suricata/rules/suricata.rules`, dan Suricata harus dikonfigurasi dengan `default-rule-path: /var/lib/suricata/rules` dan `rule-files: - suricata.rules` [S11][S14]. Sumber lain dikelola dengan `update-sources`, `list-sources`, `enable-source`, `disable-source` (konfigurasi tetap tersimpan), dan `remove-source` (konfigurasi dihapus, sehingga sumber berbayar seperti `et/pro` meminta kode akses lagi saat diaktifkan ulang) [S11].

Perubahan lokal ditulis di berkas kebijakan, bukan di `suricata.rules`, supaya tidak hilang saat ruleset diperbarui besok. Urutan penerapannya disable, enable, drop, lalu modify [S11]:

| Berkas (lokasi umum) | Fungsi | Contoh baris |
|---|---|---|
| `/etc/suricata/disable.conf` | Mematikan rule | `2019401`, `group:emerging-info.rules`, `re:heartbleed` |
| `/etc/suricata/enable.conf` | Menyalakan rule yang bawaannya mati | Format sama dengan disable |
| `/etc/suricata/drop.conf` | Mengubah rule yang cocok menjadi `drop` (hanya bermakna di IPS) | `1:2019401`, `re:heartbleed` |
| `/etc/suricata/modify.conf` | Mengubah isi rule dengan pola `<sid> "<dari>" "<ke>"` | `2019401 "seconds \d+" "seconds 3600"` |

Setiap baris disable dan enable bisa berupa `sid`, `group:<file>.rules`, atau `re:<string>`; `#` memulai komentar [S11]. Opsi yang dipakai di sensor produksi: `--local` untuk menambah berkas rule lokal, `--reload-command` untuk memuat ulang rule hanya bila berkas keluaran berubah, `--no-reload`, `--test-command` untuk menguji rule sebelum reload, dan `--no-test` untuk melewati pengujian [S11]. Konfigurasi `suricata-update` sendiri ada di `/etc/suricata/update.yaml` [S11].

Jawaban untuk Dimas: ET Open cukup untuk percobaan tiga bulan, ditambah rule lokal dari intel. Keputusan ET Pro dibuat di akhir Juli dari data: berapa alert benar yang datang dari ET Open dan rule lokal, dan apakah ada insiden yang terlewat karena tidak ada rule. Bila kelak ada layanan keamanan untuk pelanggan, lisensinya dibahas terpisah.

### 1.8 Tuning: threshold, suppress, disable

Bagian pertama pertanyaan keenam: "640 alert SNMP, matikan saja?" Jawabannya hampir selalu "jangan matikan rule-nya dulu".

Ada tiga alat dengan efek berbeda, dari yang paling sempit ke yang paling luas:

- **Suppress** menghilangkan alert untuk kombinasi rule dan alamat tertentu; rule tetap aktif untuk sumber lain. Sintaksnya `suppress gen_id <gid>, sig_id <sid>, track <by_src|by_dst|by_either>, ip <ip|subnet|variabel>`; `by_either` cocok bila sumber atau tujuan cocok, dan kolom `ip` menerima satu alamat, CIDR, variabel seperti `$HOME_NET`, atau daftar dalam kurung siku [S9]. Rule yang disupresi tetap menjalankan aksi lainnya, misalnya tetap men-set flowbit [S9], sehingga rule lain yang bergantung padanya tidak rusak.
- **Threshold** membatasi frekuensi alert tanpa menyembunyikan kejadiannya. Di `threshold.config`, sintaksnya `threshold gen_id <gid>, sig_id <sid>, type <threshold|limit|both>, track <...>, count <N>, seconds <T>`; pilihan track adalah `by_src`, `by_dst`, `by_rule`, `by_both`, dan `by_flow` [S9]. Ada juga `rate_filter`, yang mengubah action rule (`alert`, `drop`, `pass`, `reject`) untuk sementara setelah ambang tercapai [S9].
- **Disable** mematikan rule sepenuhnya lewat `disable.conf` (bagian 1.7). Tidak ada yang tercatat lagi, untuk siapa pun.

Arti tipe threshold, menurut dokumentasi keyword `threshold` di rule [S10]:

| Tipe | Perilaku | Contoh |
|---|---|---|
| `threshold` | Alert pada kejadian ke-N dalam T detik, lalu hitungan diulang | 10 email masuk dari server yang sama dalam 60 detik |
| `limit` | Maksimal N alert per T detik | 1 alert per host per 180 detik |
| `both` | Alert setelah N kejadian, lalu dibatasi | 1 alert per 6 menit setelah minimal 5 kejadian |
| `backoff` | Alert pada kejadian 1, 10, 100, 1000 (count 1, multiplier 10); hanya untuk `track by_flow` | Engine event stream yang berulang di satu flow |

`detection_filter` berbeda dari `threshold` tipe `threshold`: setelah ambang tercapai, ia memberi alert pada setiap kejadian berikutnya, bukan sekali per ambang [S10].

Interaksi `threshold.config` dengan rule: rule yang sudah punya `threshold` atau `detection_filter` tetap bisa terkena threshold global; suppress bisa digabung tanpa pengecualian; tetapi threshold global untuk satu signature menggantikan threshold milik rule itu sendiri [S9]. Dokumentasi juga menyebut menimpa semua gid atau sid sekaligus (`gen_id 0` atau `sig_id 0`) tidak didukung untuk threshold, walaupun contoh suppress dengan `sig_id 0` tercantum di halaman yang sama [S9]. Untuk aman, tulis setiap baris per `sid`. Lokasi bawaan berkasnya `/etc/suricata/threshold.config`, diatur lewat `threshold-file` di `suricata.yaml` [S14].

Contoh baris yang dipakai di catatan lama tetap berlaku:

```
# jangan beri alert sid 2027000 bila sumbernya scanner internal yang diketahui
suppress gen_id 1, sig_id 2027000, track by_src, ip 10.0.0.5
# batasi alert sid 2001219 maksimal 1 per 60 detik per sumber
threshold gen_id 1, sig_id 2001219, type limit, track by_src, count 1, seconds 60
```

`suppress` menghilangkan alert untuk kombinasi tertentu tetapi rule tetap aktif untuk sumber lain; `threshold type limit` mengurangi banjir alert tanpa menyembunyikan kejadiannya.

Aturan tuning PT JAB lahir dari pengalaman NOC dengan alarm yang di-dampening lalu dilupakan:

1. Pilih alat paling sempit yang menyelesaikan masalah: suppress per sumber sebelum threshold, threshold sebelum disable.
2. Setiap baris tuning punya komentar: nomor alert pemicu, alasan, pemilik, dan tanggal tinjau. Suppress yang dilupakan adalah titik buta permanen.
3. Tuning tidak menghapus risiko yang ditemukan rule. Bila rule menemukan konfigurasi lemah (SNMP `public`), buka tiket untuk pemiliknya.
4. Perubahan tuning masuk repositori konfigurasi dan change log, lalu diuji dengan `suricata -T` sebelum reload.

Jawaban untuk Dimas: alert SNMP tidak dimatikan. Rule-nya disupresi hanya untuk sumber `jkt-mon01`, dengan tanggal tinjau, dan NOC mendapat tiket untuk mengganti community `public` di 20 perangkat. Rule yang sama tetap aktif untuk host lain, karena SNMP `public` dari workstation adalah sinyal yang menarik (bagian 2.10).

### 1.9 IDS vs IPS: sensor pasif PT JAB

Pertanyaan ketujuh hampir pasti datang dari Hendra: enam alert path traversal ke portal pelanggan tercatat `allowed`, dan "Suricata katanya IPS".

Suricata bisa berjalan dalam dua mode:

- **IDS (pasif).** Sensor menerima salinan trafik dari SPAN, TAP, atau packet broker. Paket asli sudah sampai ke tujuan sebelum Suricata selesai memeriksa salinannya. Sensor tidak bisa membuang apa pun; ia hanya mencatat.
- **IPS (inline).** Trafik benar-benar lewat Suricata. Dokumentasi Suricata menjelaskan dua cara di Linux [S15]. Mode NFQ memakai antrean Netfilter (`iptables -I FORWARD -j NFQUEUE`, Suricata dijalankan dengan opsi `-q`); secara bawaan paket di antrean dibuang bila tidak ada program yang mendengarkan, kecuali opsi `bypass` diaktifkan. Mode AF_PACKET IPS memasangkan dua interface khusus dengan `copy-iface`, dan `copy-mode: ips` membuat keyword drop dihormati, sedangkan `copy-mode: tap` hanya menjembatani tanpa membuang apa pun; kedua interface butuh MTU sama dan `cluster-id` berbeda, dan `stream.inline` di-set `auto` atau `yes` [S15].

Di mode IDS, rule `drop` tidak bisa membuang paket; alert dari rule itu tetap tercatat dengan `action` `allowed`, karena nilai `blocked` hanya muncul saat drop di mode IPS atau reject bekerja [S7]. Perilaku persis rule `drop` dan `reject` di mode pasif perlu dicek di lab (bagian 3).

Kenapa PT JAB memilih IDS untuk percobaan:

- **Ketersediaan.** IPS di egress Jakarta berarti seluruh trafik kantor lewat satu server baru. Bila Suricata hang atau kelebihan beban, pilihan desainnya fail-open (trafik lewat tanpa diperiksa) atau fail-closed (kantor putus). Untuk percobaan tiga bulan, risiko itu tidak sepadan.
- **False positive memblokir orang.** Hari pertama membuktikan sebagian besar alert adalah bising. Di mode IPS, rule `drop` yang salah memutus layanan sah.
- **Posisi sensor.** `jkt-ids01` membaca SPAN core dan TAP egress lewat `jkt-npb01` (Day 01 bagian 2.2). Interface capture tidak punya IP dan tidak mengirim apa pun ke jalur yang dimonitor.

Blokir di PT JAB dilakukan oleh perangkat yang memang in-path, berdasarkan keputusan analis: `jkt-fw01` untuk alamat, `jkt-proxy01` untuk domain dan URL. IPS dievaluasi di akhir program untuk segmen terbatas, dimulai dari rule dengan false positive mendekati nol.

Jawaban untuk Hendra: Suricata di PT JAB dipasang sebagai IDS pasif, jadi ia mencatat dan tidak memblokir. Percobaan path traversal itu tetap tidak berhasil, karena portal menjawab 400 dan 404 tanpa isi berkas (bagian 2.9), dan alamat penyerang diblokir di firewall 14 menit setelah alert. Memblokir otomatis adalah keputusan terpisah yang butuh data false positive dulu.

### 1.10 Suricata ke Splunk: sourcetype, event yang dikirim, volume, dan kesehatan sensor

Pertanyaan terakhir Dimas menentukan apakah query di Day ini dan Day berikutnya bisa dijalankan.

**Add-on.** Berbeda dengan Zeek, tidak ada add-on Suricata yang dirawat Splunk atau vendor Suricata yang tercantum aktif saat dicek. Yang ditemukan di Splunkbase:

- "CCX Add-on for Suricata" (app 6994), versi 1.0.1 tertanggal 8 Agustus 2025, dirawat developer (CyberCX), kompatibel dengan Splunk 9.1 sampai 10.6 dan CIM 5.x dan 6.x. Halamannya menyebut satu bundel field extraction untuk log EVE JSON yang masuk lewat syslog, dengan dukungan data model Alerts, Network Resolution, Network Session, Network Traffic, Web, Intrusion Detection, dan Certificates; nama sourcetype tidak dicantumkan [S21].
- "SuriZeek" (app 9818), versi 1.5.8 tertanggal 10 Oktober 2026, dirawat developer, yang menghubungkan alert Suricata dengan log Zeek dari koneksi yang sama berdasarkan IP, port, dan protokol [S22]. Ini app dashboard, bukan parser CIM.

**Sourcetype.** Karena tidak ada add-on resmi yang menetapkan nama, PT JAB menetapkan sendiri: satu sourcetype `suricata` untuk semua event dari `eve.json`, dibedakan dengan field `event_type`. Satu sourcetype dipilih karena `eve.json` adalah satu berkas berisi banyak tipe event; memecahnya per tipe di Splunk butuh transform saat indexing, dan `event_type` sudah memberi pemisah yang sama di search time. Parsing ditulis di app lokal (bagian 2.11); add-on CIM dievaluasi di index staging sebelum dipasang, dengan memeriksa sourcetype yang diharapkan di `props.conf`-nya.

**Event yang dikirim.** `jkt-zeek01` sudah mengirim metadata koneksi, DNS, HTTP, TLS, dan file ke index `zeek` (Day 08 bagian 1.9). Mengirim `flow`, `dns`, `http`, `tls`, dan `fileinfo` Suricata ke Splunk berarti membayar lisensi dua kali untuk informasi yang hampir sama. Karena itu `jkt-ids01` menulis dua instance `eve-log` (bagian 2.11), sesuatu yang didukung dokumentasi, masing-masing dengan nama berkas dan daftar `types` sendiri [S3]:

| Berkas | Isi | Tujuan |
|---|---|---|
| `eve-alert.json` | `alert` (dengan metadata app-layer dan flow), `anomaly`, `stats` | Splunk index `suricata`, sourcetype `suricata` |
| `eve-proto.json` | `flow`, `dns`, `http`, `tls`, `files` | Tetap di sensor, dirotasi per jam, disimpan 7 hari untuk pivot `flow_id` |

`community-id: true` ditulis di kedua instance, karena opsinya per instance [S3].

**Volume.** Hari pertama, 08:00 sampai 16:00 WIB, `eve-alert.json` sekitar 0,159 GB, atau sekitar 0,265 GB per hari dengan asumsi delapan jam kerja membawa 60% trafik harian (asumsi yang sama dengan Day 08). Bila `eve-proto.json` ikut dikirim, tambahannya sekitar 14,0 GB per delapan jam, sekitar 23,3 GB per hari, lebih besar daripada seluruh index `zeek`. Rinciannya di bagian 2.11.

**Kesehatan sensor.** Event `stats` memuat counter capture per interval. Yang dipantau PT JAB adalah `capture.kernel_packets` dan `capture.kernel_drops`: selisih keduanya antar dua snapshot memberi persentase drop pada jendela itu (bagian 2.12). Ini padanan `capture_loss.log` di Zeek. Ratusan alert `SURICATA STREAM` pada hari pertama muncul di jam yang sama dengan drop 1,90% pukul 09:00 sampai 09:30 WIB; setelah jumlah thread dan ukuran ring AF_PACKET dinaikkan pukul 12:30, drop turun ke 0,02% dan alert stream ikut turun. Itu jawaban untuk "sensornya sakit": ya, pagi hari, dan sudah diperbaiki, dengan jendela yang harus ditulis di laporan.

Jawaban untuk Dimas: index `suricata`, sourcetype `suricata`, hanya alert, anomaly, dan stats yang dikirim (sekitar 0,27 GB per hari), event protokol tetap di sensor tujuh hari, dan kesehatan sensor dipantau dari `stats`.

### 1.11 Batas deteksi signature dan perubahan Suricata 8.x yang memengaruhi keputusan

Semua jawaban di atas berlaku dengan batas yang sama; bagian ini mengumpulkannya.

Batas deteksi signature:

- Hanya mendeteksi yang ada rule-nya (known); zero-day dan teknik baru lolos sampai rule dibuat.
- Trafik terenkripsi membatasi inspeksi isi; banyak rule TLS bergantung pada metadata (SNI, JA3/JA4), bukan payload. Di Suricata 8.0, `app-layer.protocols.tls.encryption-handling` bawaannya `track-only`: sesi TLS tetap dilacak dan keyword `tls.*` tetap bekerja, tetapi inspeksi `content` mentah dimatikan; `bypass` menghentikan semua pemeriksaan sesi itu, dan `full` memeriksa seperti biasa [S14].
- Penyerang bisa mengubah pola untuk menghindari signature (evasion).
- JA3/JA4 di egress PT JAB untuk koneksi yang didekripsi proxy adalah milik proxy (bagian 1.4), sehingga rule `ja3.hash` atau `ja4.hash` dari intel hanya bermakna untuk koneksi yang tidak didekripsi atau untuk host yang keluar tanpa proxy.
- Karena itu Suricata dipadu dengan Zeek (konteks dan anomali) dan analitik perilaku; signature saja tidak cukup.

JA3 dan JA4 terintegrasi di Suricata lewat `app-layer.protocols.tls.ja3-fingerprints` dan `ja4-fingerprints`; bila tidak di-set eksplisit `no`, dukungannya otomatis aktif ketika ada rule yang membutuhkannya [S6]. Keyword yang tersedia: `ja3.hash`, `ja3.string`, `ja3s.hash`, dan `ja4.hash`; nama lama seperti `ja3_hash` masih bekerja, dan rule bisa memakai `requires: feature ja3;` atau `requires: feature ja4;` supaya dilewati di build tanpa dukungan itu [S6]. Contoh rule `ja4.hash` di dokumentasi memakai `alert quic` [S6]. Di `jkt-ids01`, kedua opsi di-set `yes` supaya field `ja3` dan `ja4` selalu ada di event `tls`, bukan hanya saat ada rule.

Perubahan Suricata 8.0 yang mengubah cara membaca alert dan menulis query [S8]:

- **Metadata app-layer di alert** kini hanya ditulis untuk rule yang memakai keyword app-layer. Alert dari rule `alert udp` dengan `content` mentah (seperti rule SNMP) tidak membawa objek protokol, sehingga konteksnya dicari lewat `flow_id` atau `community_id`. Opsi `detect.guess-applayer-tx` bisa memaksa tebakan, tetapi tidak ada yang ditulis bila ada lebih dari satu transaksi aktif [S8].
- **DNS di `eve.json`** memakai format versi 3 secara bawaan, yang menyatukan event `dns` dengan objek `dns` di alert; format versi 2 (gaya Suricata 7) masih bisa dipilih, tetapi dokumentasi menyebut akan dihapus di Suricata 9 [S7][S8]. Query Splunk yang disalin dari panduan Suricata 7 untuk field DNS perlu dicek ulang.
- **Inspeksi saat request atau respons selesai** untuk protokol selain FTP dan HTTP, sehingga sebagian match `content` yang dulu terjadi lebih awal tidak lagi terjadi; sebaliknya rule stream dan payload bisa menghasilkan lebih banyak alert karena reassembly memicu lebih awal [S8]. Jumlah alert dari Suricata 7 tidak bisa dipakai sebagai baseline.
- **Output yang dihentikan:** `tls-log`, output `syslog` terpisah (syslog lewat EVE tidak terpengaruh), dan nilai `default` untuk `encryption-handling` (pakai `track-only`) dijadwalkan dihapus di 9.0; `http-log` dihapus di 9.0 [S8]. Pakai `eve-log`.
- **`ja3.hash` dan `ja3s.hash`** menolak `content` yang bukan heksadesimal, karena tidak mungkin cocok [S8].

Satu hal lagi yang mengubah keputusan operasional: Suricata 8.0.7 (15 September 2026) adalah rilis keamanan yang memperbaiki 67 kerentanan, jumlah laporan kerentanan terbanyak yang pernah diterima proyek itu, Suricata 7 sudah EOL dengan 7.0.17 sebagai rilis terakhir, dan proyek LibHTP (pustaka parser HTTP Suricata) sudah EOL dengan repositori yang diarsipkan [S4][S19]. Sensor IDS mengurai trafik yang dikirim pihak mana pun, termasuk penyerang; parser yang rentan adalah permukaan serangan. PT JAB menetapkan 8.0.7 sebagai versi minimum `jkt-ids01` dan memasukkan Suricata ke daftar patch prioritas.

## 2. Contoh dan langkah praktis: hari pertama `jkt-ids01`

Semua isi bagian ini fiktif dan merupakan keluaran ilustrasi. Log PT JAB memakai alamat dokumentasi sebagai pengganti alamat publik. IOC di-defang di laporan; di query dan rule ditulis apa adanya karena hanya ada di sensor dan Splunk. Perintah offline dijalankan di `jkt-nsm-ws01` (`10.20.70.20`) terhadap ekstrak pcap dari `jkt-pcap01`; untuk latihan, pakai lab pribadi (bagian 3). `jkt-ids01` dan `jkt-nsm-ws01` memakai zona waktu UTC, sehingga `timestamp` di `eve.json` ber-offset `+0000`; Splunk menampilkan WIB (UTC+7) untuk akun SOC. Nama dan `sid` rule ET di contoh ini dipakai sebagai ilustrasi; cocokkan dengan `suricata.rules` di sensor-mu sebelum menyalinnya ke tiket.

Konfigurasi `jkt-ids01` yang dipakai sepanjang bagian ini: Suricata 8.0.7 dalam runmode `workers` dengan AF_PACKET pada satu port 10G dari `jkt-npb01` (interface `ens1f0`, tanpa IP); `HOME_NET` berisi `10.0.0.0/8` dan blok publik PT JAB; `EXTERNAL_NET` di-set `any`, bukan bawaan `!$HOME_NET`, karena separuh trafik yang dilihat sensor adalah trafik internal di core DC dan PT JAB ingin rule tetap memeriksa trafik itu; ruleset ET Open lewat `suricata-update` ditambah `/etc/suricata/rules/jab-local.rules`; `community-id: true` dengan seed 0. Pilihan `EXTERNAL_NET: any` ikut menjelaskan sebagian keramaian hari pertama, karena rule yang ditulis untuk "luar ke dalam" kini juga cocok pada trafik dalam ke dalam.

### 2.1 Menjalankan Suricata pada pcap (offline)

Langkah ini dipakai Sari untuk memutar ulang pcap egress `INC-2027-068` di `jkt-nsm-ws01` dengan ruleset yang sama dengan sensor, sekaligus contoh perintah dasar untuk lab.

**Tujuan:** menghasilkan `fast.log` dan `eve.json` dari pcap di direktori kasus yang bersih, lalu memastikan rule dan konfigurasinya valid.

```
suricata -r capture.pcap -l ./out

# PT JAB: uji konfigurasi dan rule dulu, lalu putar ulang ekstrak egress 09:10-09:50 WIB (02:10-02:50 UTC)
suricata -T -c /etc/suricata/suricata.yaml -v
mkdir -p /cases/INC-2027-068/suricata-offline
suricata -c /etc/suricata/suricata.yaml -k none \
  -S /cases/INC-2027-068/rules/suricata.rules -s /cases/INC-2027-068/rules/jab-local.rules \
  -r /cases/INC-2027-068/egress_20270519_0210-0250.pcapng \
  -l /cases/INC-2027-068/suricata-offline/
```

Penjelasan tiap bagian:

- `-r` membaca pcap offline; `-l` menentukan direktori output (`eve.json`, `fast.log`, `stats.log`, `suricata.log`), menimpa `default-log-dir` di YAML [S23]. Ruleset harus terpasang di konfigurasi atau diberikan lewat opsi.
- `-T` menguji konfigurasi dan memuat semua rule tanpa memproses trafik; `-v` menaikkan verbositas sehingga rule yang gagal dimuat terlihat [S23]. Uji ini dijalankan sebelum setiap reload di sensor (bagian 1.8).
- `-k none` mematikan pemeriksaan checksum [S23]. Pcap dari host dengan offloading sering berisi checksum salah; tanpa opsi ini sebagian sesi bisa diabaikan engine, padanan `-C` di Zeek.
- `-S` memuat satu berkas rule secara eksklusif dan mengabaikan rule di YAML; `-s` memuat berkas tambahan bersama rule di YAML [S23]. Di sini keduanya dipakai supaya rule yang diputar ulang adalah salinan rule sensor pada hari kejadian, yang disimpan di folder kasus. Ruleset yang diperbarui besok bisa memberi hasil berbeda.
- Bila `-r` diberi direktori, Suricata memproses semua file di dalamnya berurutan menurut waktu modifikasi dan mempertahankan state flow antar file [S23]. Ini berguna untuk beberapa file ring buffer `jkt-pcap01` yang berurutan.

Keluaran ilustrasi (daftar file di direktori kasus PT JAB):

```
eve.json  fast.log  stats.log  suricata.log
```

**Cara membaca hasil:** hasil utama ada di `out/eve.json` dan `out/fast.log`. Mulai dari `fast.log` untuk gambaran cepat, lalu `eve.json` untuk konteks. `suricata.log` memuat jumlah rule yang dimuat dan rule yang gagal; baca baris itu sebelum menyimpulkan "tidak ada alert". Pcap ini hanya memuat egress, jadi hop workstation ke proxy (SPAN core) tidak ada di hasil offline; untuk hop itu yang dipakai adalah `eve-proto.json` di sensor dan log Zeek (bagian 2.7).

**Variasi:** `--runmode single` untuk pcap kecil supaya urutan event mudah dibaca; `--set` untuk menimpa satu nilai konfigurasi tanpa mengubah YAML, misalnya mengaktifkan `community-id` di salinan konfigurasi lab [S23].

**Kapan gagal:** rule tidak dimuat (salah path atau error sintaks) sehingga keluaran tanpa alert terlihat seperti trafik bersih; `HOME_NET` di konfigurasi lab berbeda dari sensor sehingga rule berheader `$HOME_NET` tidak cocok; pcap tidak memuat awal koneksi sehingga keyword `flow:established` tidak terpenuhi; dan alamat jaringan lab tidak masuk `HOME_NET`.

### 2.2 Membaca `fast.log`

Langkah ini memberi gambaran cepat sebelum membuka JSON, dan biasanya dipakai L1 pada jam pertama.

**Tujuan:** melihat alert apa saja, seberapa penting, dan antara alamat mana.

```
cat out/fast.log

# PT JAB, di sensor: alert rule lokal hari ini
grep -F '[1:10001' /var/log/suricata/fast.log | head
```

- `cat` membaca seluruh berkas; `grep -F '[1:10001'` mencari teks persis `[gid:sid` untuk rule lokal 1000101 sampai 1000109 tanpa regex.

Keluaran ilustrasi (satu baris format umum, lalu dua baris PT JAB):

```
10/09/2026-10:15:02 [**] [1:2027000:1] ET MALWARE Observed Suspicious TLS SNI [**] [Classification: ...] [Priority: 1] {TCP} 10.0.0.8:49722 -> 203.0.113.50:443

05/19/2027-02:12:40.915388  [**] [1:1000102:1] JAB LOCAL C2 DNS query telemetry-upd.example (ISAC 2027-05-17) [**] [Classification: A Network Trojan was detected] [Priority: 1] {UDP} 10.20.3.60:48213 -> 10.20.2.53:53
05/19/2027-02:12:41.004812  [**] [1:1000101:1] JAB LOCAL C2 SNI telemetry-upd.example (ISAC 2027-05-17) [**] [Classification: A Network Trojan was detected] [Priority: 1] {TCP} 10.20.3.60:41822 -> 203.0.113.176:443
```

**Cara membaca hasil:** satu baris berisi waktu, `[gid:sid:rev]`, `msg`, classification, prioritas, protokol, dan 4-tuple. Prioritas 1 paling penting. Catat `sid` untuk menelusuri rule dan sejarahnya. Dua baris PT JAB sudah menjawab sebagian pertanyaan ketiga Dimas: sumbernya proxy (`10.20.3.60`), bukan workstation, dan alert DNS mendahului alert TLS 89 milidetik, cocok dengan urutan proxy me-resolve nama lalu membuka koneksi. Waktu `02:12` UTC adalah 09:12 WIB.

**Variasi:** `tail -f /var/log/suricata/fast.log` di lab untuk melihat alert muncul saat trafik uji dibangkitkan.

**Kapan gagal:** `fast.log` tidak membawa objek protokol, `flow_id`, atau `community_id`, sehingga tidak bisa dipakai untuk korelasi; dan di sensor produksi PT JAB `fast.log` dimatikan setelah minggu pertama karena semua isinya ada di `eve-alert.json`.

### 2.3 Membaca alert di `eve.json`

Langkah ini adalah inti pembacaan alert `SOC-2027-0642`: satu event, semua field yang dibutuhkan triage.

**Tujuan:** menampilkan event alert lengkap dengan konteksnya.

```
cat out/eve.json | jq 'select(.event_type=="alert")'

# PT JAB: hanya alert rule lokal, field yang dibutuhkan triage
jq -c 'select(.event_type=="alert" and .alert.signature_id>=1000000 and .alert.signature_id<2000000)
       | {timestamp, flow_id, community_id, src_ip, src_port, dest_ip, dest_port, app_proto,
          action: .alert.action, sid: .alert.signature_id, sig: .alert.signature, sev: .alert.severity,
          sni: .tls.sni, rrname: .dns.queries[0].rrname}' /var/log/suricata/eve-alert.json
```

Penjelasan tiap bagian:

- `select(.event_type=="alert")` menyaring event alert dari semua tipe event di berkas.
- Rentang `signature_id` 1000000 sampai 1999999 adalah rule lokal (bagian 1.3).
- Objek `{...}` membentuk ringkasan satu baris; `-c` membuat keluaran ringkas.
- `.dns.queries[0].rrname` mengikuti format DNS versi 3 di alert (bagian 1.11). Nama objek di versi ini perlu dicek di event contoh dari sensor-mu; di format versi 2 nama field-nya berbeda.

Contoh satu event alert TLS lengkap dari `jkt-ids01` (diringkas; field `metadata` dan `flow` dipendekkan):

```
{"timestamp":"2027-05-19T02:12:41.004812+0000","flow_id":1489203365718842,"in_iface":"ens1f0",
 "event_type":"alert","src_ip":"10.20.3.60","src_port":41822,"dest_ip":"203.0.113.176","dest_port":443,
 "proto":"TCP","community_id":"1:q3Xv8nT2bLw0YfK5rJc9sPm1HdE=",
 "alert":{"action":"allowed","gid":1,"signature_id":1000101,"rev":1,
          "signature":"JAB LOCAL C2 SNI telemetry-upd.example (ISAC 2027-05-17)",
          "category":"A Network Trojan was detected","severity":1,
          "metadata":{"created_at":["2027_05_18"],"source":["isac_bulletin_2027_05_17"]}},
 "app_proto":"tls","tls":{"sni":"telemetry-upd.example","version":"TLS 1.3",
          "ja3":{"hash":"(milik proxy)"},"ja4":"(milik proxy)"},
 "flow":{"pkts_toserver":3,"pkts_toclient":1,"bytes_toserver":657,"bytes_toclient":74,
         "start":"2027-05-19T02:12:40.998121+0000","src_ip":"10.20.3.60","dest_ip":"203.0.113.176"}}
```

**Cara membaca hasil:**

- `action` `allowed` berarti Suricata berjalan sebagai IDS dan koneksi tidak diblokir; di mode IPS dengan rule `drop` nilainya `blocked` [S7].
- `severity` 1 adalah tertinggi dan berasal dari `classtype` rule (`trojan-activity`).
- `flow_id` dipakai mencari event `flow`, `tls`, dan `fileinfo` dari koneksi yang sama (bagian 2.6); `community_id` dipakai menyambung ke Zeek (bagian 2.8).
- Objek `tls.sni` menunjukkan bahwa yang cocok adalah nama di ClientHello, sesuai option rule-nya. Isi koneksi tidak pernah diperiksa rule ini.
- `tls.ja3` dan `tls.ja4` ditulis karena opsi fingerprint di-set `yes`, tetapi karena domain baru ini di-bump proxy, ClientHello di egress adalah buatan `jkt-proxy01`; fingerprint itu sama dengan ribuan koneksi lain dari proxy dan tidak berguna untuk membedakan malware (bagian 1.4).
- `metadata` dari rule ikut tercatat di alert [S13], sehingga analis langsung tahu sumber IOC dan tanggal rule dibuat.
- `flow` di dalam alert menunjukkan 3 paket ke server (SYN, ACK, ClientHello) dan 1 paket ke klien (SYN-ACK) saat alert ditulis: alert muncul pada ClientHello, jauh sebelum sesi selesai. Arah `flow` di sini sama dengan arah alert karena paket pemicunya dikirim klien; pada rule yang cocok di respons server, keduanya terbalik (bagian 1.4).

**Variasi:** `jq 'select(.event_type=="alert") | .alert.metadata'` untuk melihat metadata rule saja; berguna saat menilai umur rule ET (bagian 1.3).

**Kapan gagal:** berkas `eve.json` yang dirotasi saat dibaca membuat `jq` berhenti di baris terpotong; objek protokol tidak ada untuk rule tanpa keyword app-layer (bagian 1.11), sehingga `.tls.sni` bernilai `null` walaupun sesinya TLS.

### 2.4 Menghitung dan memprioritaskan alert

Langkah ini menjawab "1.374 alert, mulai dari mana" dengan angka, bukan perasaan.

**Tujuan:** mengelompokkan alert per signature dan per kelompok, lalu memilih urutan triage.

```
cat out/eve.json | jq -r 'select(.event_type=="alert") | .alert.signature' | sort | uniq -c | sort -rn
```

Di PT JAB alert sudah ada di Splunk, jadi hitungannya dibuat di sana:

```
index=suricata sourcetype=suricata event_type=alert earliest="05/19/2027:08:00:00" latest="05/19/2027:16:00:00"
| eval kelompok=case(
    'alert.signature_id'>=1000000 AND 'alert.signature_id'<2000000, "rule lokal",
    like('alert.signature', "SURICATA %"), "engine event",
    like('alert.signature', "GPL SNMP%"), "GPL SNMP",
    like('alert.signature', "ET SCAN%"), "ET SCAN",
    like('alert.signature', "ET WEB_SERVER%"), "ET WEB_SERVER",
    true(), "lainnya")
| stats count AS alert dc(alert.signature_id) AS signature dc(src_ip) AS sumber BY kelompok
| sort - alert
```

| Bagian | Fungsi |
|---|---|
| `earliest`/`latest` absolut | Jendela hari pertama 08:00 sampai 16:00 WIB; bisa diulang dengan hasil sama |
| `event_type=alert` | Hanya alert; `anomaly` dan `stats` ikut di index yang sama (bagian 2.11) |
| `'alert.signature_id'` | Field bertitik dari JSON ditulis dengan kutip tunggal di `eval` |
| `case(...)` | Kelompok kasar menurut rentang `sid` dan awalan `msg` |
| `stats ... BY kelompok` | Jumlah alert, jumlah signature, dan jumlah sumber per kelompok |

Keluaran ilustrasi:

```
kelompok        alert  signature  sumber
GPL SNMP          640          1       1
engine event      412          5      38
lainnya           188         51      44
ET SCAN           118          1       1
rule lokal         10          2       2
ET WEB_SERVER       6          1       1
```

**Cara membaca hasil:** total 1.374 alert dari 61 signature. Alert tersering ada di atas, tetapi volume bukan prioritas. Kelompok terbesar, GPL SNMP, datang dari satu sumber saja: pola kebiasaan internal, bukan serangan. Engine event dari 38 sumber berbeda pada jam yang sama menunjuk ke sensor, bukan ke 38 host (bagian 2.12). Kelompok terkecil, rule lokal dengan 10 alert dari 2 sumber, justru yang paling penting karena rule-nya dibuat dari intel yang relevan untuk PT JAB. Urutan triage mengikuti tabel prioritas bagian 1.6: rule lokal dulu, lalu serangan web ke aset publik, lalu pemindaian, lalu kesehatan sensor dan bising.

**Variasi:** ganti `BY kelompok` dengan `BY alert.signature_id alert.signature` dan tambahkan `| head 10` untuk daftar per signature; tambahkan `values(src_ip)` untuk kelompok dengan sumber sedikit.

**Kapan gagal:** volume tinggi satu signature bisa berarti serangan nyata atau rule berisik; prioritas dan konteks yang membedakan, bukan angkanya. Field `alert.signature_id` tidak ter-extract bila sourcetype tidak di-parse sebagai JSON (bagian 2.11).

### 2.5 Membaca rule di balik alert

Langkah ini menjawab pertanyaan Gilang dengan membuka rule-nya langsung, bukan hanya `msg`.

**Tujuan:** menemukan rule dari `sid` lalu membaca action, header, dan options untuk memahami apa yang memicunya.

```
# contoh rule (dibaca, bukan ditulis untuk menyerang):
alert dns $HOME_NET any -> any any (msg:"ET ... suspicious DNS query"; dns.query; content:"..."; sid:2000001; rev:2;)

# PT JAB: cari rule dari sid di ruleset gabungan dan rule lokal
grep -h 'sid:1000101;' /var/lib/suricata/rules/suricata.rules /etc/suricata/rules/jab-local.rules
grep -h 'sid:1000102;' /var/lib/suricata/rules/suricata.rules /etc/suricata/rules/jab-local.rules
```

Pembacaan contoh umum: header `dns` dari `$HOME_NET` ke mana saja, option `dns.query` dengan `content` (pola nama domain), lalu `sid` dan `rev` (identitas dan versi). Ini memberi tahu apa yang memicu alert, sehingga kamu bisa menilai apakah trafik yang terlihat benar cocok.

Keluaran ilustrasi (dua rule lokal yang ditulis Sari Selasa malam dari buletin ISAC, dipotong per baris supaya mudah dibaca; di berkas aslinya satu rule satu baris):

```
alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"JAB LOCAL C2 SNI telemetry-upd.example (ISAC 2027-05-17)";
  flow:established,to_server; tls.sni; content:"telemetry-upd.example"; nocase; endswith;
  classtype:trojan-activity; sid:1000101; rev:1;
  metadata:created_at 2027_05_18, source isac_bulletin_2027_05_17, review_at 2027_08_18;)
alert dns $HOME_NET any -> any any (msg:"JAB LOCAL C2 DNS query telemetry-upd.example (ISAC 2027-05-17)";
  dns.query; content:"telemetry-upd.example"; nocase; endswith;
  classtype:trojan-activity; sid:1000102; rev:1;
  metadata:created_at 2027_05_18, source isac_bulletin_2027_05_17, review_at 2027_08_18;)
```

**Cara membaca hasil:**

- `alert tls $HOME_NET any -> $EXTERNAL_NET any`: protokol aplikasi `tls`, jadi rule hanya cocok bila parser mengenali TLS, di port mana pun. Sumber harus di `HOME_NET`. Itu sebabnya alert TLS bersumber proxy: dari sudut sensor egress, proxy-lah klien TLS ke internet.
- `flow:established,to_server`: hanya pada sesi yang sudah terbentuk, arah klien ke server. SYN scan tidak bisa memicunya.
- `tls.sni; content:...; nocase; endswith;`: yang dicocokkan hanya SNI, tidak peka huruf besar/kecil, dan harus berakhir dengan nama itu, sehingga subdomain seperti `a.telemetry-upd.example` juga cocok. Isi sesi tidak diperiksa.
- Rule DNS memakai `dns.query` tanpa batas arah ke `$EXTERNAL_NET`, sehingga cocok pada query proxy ke resolver internal dan pada query resolver ke internet. Itu sebabnya ada dua alert DNS dari dua sumber berbeda untuk satu kali resolve.
- `metadata` memuat sumber IOC dan tanggal tinjau. Tiga bulan setelah dibuat, rule ini ditinjau: masih relevan atau dimatikan.

**Variasi:** untuk rule ET, baca juga `reference` (CVE atau URL) dan `metadata` `signature_severity` serta `updated_at`; untuk engine event, cari `sid` di berkas rule bawaan Suricata (misalnya `stream-events.rules`, `decoder-events.rules`; lokasinya cek di `suricata.yaml` versi-mu).

**Kapan gagal:** `grep` pada `suricata.rules` tidak menemukan `sid` karena rule datang dari berkas lain (rule lokal yang dimuat terpisah, atau rule engine event); rule sudah direvisi sejak alert ditulis, sehingga isi rule berbeda dengan yang memicu alert. Bandingkan `rev` di alert dengan `rev` di berkas.

### 2.6 Korelasi alert ke konteks lewat `flow_id`

Langkah ini mengumpulkan semua yang diketahui Suricata tentang satu koneksi `SOC-2027-0642` sebelum keluar ke alat lain.

**Tujuan:** dari `flow_id` alert, ambil event `flow`, `tls`, `http`, dan `fileinfo` pada aliran yang sama.

```
# ambil flow_id/4-tuple dari alert, lalu cari event lain di eve.json atau log Zeek
cat out/eve.json | jq 'select(.flow_id==<id>)'

# PT JAB, di jkt-ids01: event protokol ada di eve-proto.json (7 hari), alert di eve-alert.json
jq -c 'select(.flow_id==1489203365718842) | {timestamp, event_type, app_proto, tls, flow}' \
  /var/log/suricata/eve-alert.json /var/log/suricata/eve-proto.json
```

Penjelasan: `flow_id` menghubungkan alert ke event `http`, `dns`, `tls`, dan `fileinfo` pada aliran yang sama, mirip `uid` Zeek [S7]. Di PT JAB event alert dan event protokol ada di dua berkas berbeda (bagian 1.10), jadi keduanya diberikan ke `jq`. Karena keduanya ditulis instance Suricata yang sama, `flow_id` tetap cocok lintas berkas.

Keluaran ilustrasi (diringkas):

```
{"timestamp":"2027-05-19T02:12:41.004812+0000","event_type":"alert","app_proto":"tls", ... }
{"timestamp":"2027-05-19T02:12:41.211530+0000","event_type":"tls","app_proto":"tls",
 "tls":{"sni":"telemetry-upd.example","version":"TLS 1.3"}}
{"timestamp":"2027-05-19T02:12:43.882104+0000","event_type":"flow","app_proto":"tls",
 "flow":{"pkts_toserver":14,"pkts_toclient":12,"bytes_toserver":2846,"bytes_toclient":6215,
         "start":"2027-05-19T02:12:40.998121+0000","end":"2027-05-19T02:12:41.876402+0000",
         "age":1,"state":"closed","reason":"timeout","alerted":true}}
```

**Cara membaca hasil:** satu `flow_id`, tiga event: alert saat ClientHello, event `tls` setelah handshake, dan event `flow` yang ditulis saat flow dikeluarkan dari tabel. Koneksi ini pendek (sekitar 0,88 detik dari `start` ke `end`) dan kecil (2.846 byte ke server, 6.215 byte ke klien), dan ditutup normal (`state` `closed`; `reason` `timeout` berarti flow dikeluarkan dari tabel setelah timeout, bukan dipaksa). Delapan koneksi yang sama setiap sekitar 300 detik dengan ukuran mirip adalah pola beacon (Day 11), tetapi pola itu indikator, bukan kesimpulan: aplikasi telemetri sah juga begitu. Yang membuatnya kasus adalah intel ISAC ditambah domain baru dan tidak terkategori. Tidak ada event `fileinfo`, karena isi TLS tidak terlihat oleh Suricata.

**Variasi:** di lab tanpa pemisahan berkas, `jq 'select(.flow_id==<id>)' eve.json` sudah cukup; tambahkan `| .event_type` untuk melihat urutan tipe event saja.

**Kapan gagal:** `flow_id` dari dua instance Suricata atau dua sensor tidak bisa dibandingkan; `eve-proto.json` untuk hari itu sudah dirotasi dan dihapus (retensi 7 hari); atau event `flow` belum ditulis karena flow masih aktif di tabel.

### 2.7 Mencari workstation di balik proxy: `INC-2027-068`

Langkah ini adalah jawaban lengkap pertanyaan ketiga Dimas: alert menunjuk proxy dan resolver, padahal yang dicari adalah workstation.

**Tujuan:** menemukan host asal koneksi ke `telemetry-upd.example` lewat hop core (workstation ke proxy), lalu mengonfirmasinya dengan Zeek dan log proxy.

```
# di jkt-ids01: event http di hop core (workstation ke proxy port 3128)
jq -c 'select(.event_type=="http" and .dest_ip=="10.20.3.60" and .dest_port==3128
              and ((.http.hostname // "") | endswith("telemetry-upd.example")))
       | {timestamp, flow_id, src_ip, src_port, method: .http.http_method,
          hostname: .http.hostname, url: .http.url, status: .http.status}' \
  /var/log/suricata/eve-proto.json
```

Penjelasan tiap bagian:

- `event_type=="http"` dan `dest_ip`/`dest_port` proxy: hanya request yang dikirim ke proxy, yaitu hop core yang dilihat SPAN core.
- `(.http.hostname // "")` mengganti `null` dengan string kosong supaya `endswith` tidak error pada event tanpa hostname.
- `http_method` dan `status` hanya ditulis bila logging HTTP diatur `extended: yes` (bagian 1.4); instance `eve-proto.json` PT JAB memakainya.

Keluaran ilustrasi (diringkas; sembilan baris, lima di tengah dihilangkan):

```
{"timestamp":"2027-05-19T02:12:40.912447+0000","flow_id":702144309182736,"src_ip":"10.10.60.92","src_port":52114,"method":"CONNECT","hostname":"telemetry-upd.example","url":"telemetry-upd.example:443","status":200}
{"timestamp":"2027-05-19T02:17:42.905113+0000","flow_id":702147730415529,"src_ip":"10.10.60.92","src_port":52187,"method":"CONNECT","hostname":"telemetry-upd.example","url":"telemetry-upd.example:443","status":200}
...
{"timestamp":"2027-05-19T02:47:43.921870+0000","flow_id":702165902873301,"src_ip":"10.10.60.92","src_port":52603,"method":"CONNECT","hostname":"telemetry-upd.example","url":"telemetry-upd.example:443","status":200}
{"timestamp":"2027-05-19T02:52:44.118930+0000","flow_id":702168814025716,"src_ip":"10.10.60.92","src_port":52671,"method":"CONNECT","hostname":"telemetry-upd.example","url":"telemetry-upd.example:443","status":403}
```

**Cara membaca hasil:** satu sumber, `10.10.60.92` (`JKT-WS-2042`), sembilan request `CONNECT` ke domain yang sama. Delapan pertama dijawab 200 oleh proxy dan masing-masing diikuti, sekitar 90 milidetik kemudian, oleh koneksi TLS proxy ke `203.0.113.176` yang memicu alert `sid 1000101`. Yang kesembilan, 09:52:44 WIB, dijawab 403 karena domain sudah diblokir di proxy pukul 09:48; tidak ada koneksi egress yang menyertainya, sehingga tidak ada alert TLS kesembilan. Bentuk `hostname` dan `url` untuk request `CONNECT` di event `http` Suricata 8 perlu dicek di lab (bagian 3); bila Suricata tidak mencatat `CONNECT` sebagai event `http` di versi-mu, langkah berikut tetap menemukan host yang sama.

Konfirmasi dari Zeek (hop core, `http.log`) dan log proxy, dalam satu jendela yang sama:

```
index=zeek sourcetype=bro:http:json method=CONNECT uri="telemetry-upd.example*"
    earliest="05/19/2027:09:00:00" latest="05/19/2027:10:00:00"
| stats count min(_time) AS pertama max(_time) AS terakhir values(status_code) AS status BY id.orig_h
| convert ctime(pertama) ctime(terakhir)

index=proxy host="telemetry-upd.example" earliest="05/19/2027:09:00:00" latest="05/19/2027:10:00:00"
| stats count values(method) AS method values(url) AS url values(status) AS status values(category) AS kategori BY src user
```

Keluaran ilustrasi:

```
id.orig_h     count  pertama              terakhir             status
10.10.60.92   9      05/19/2027 09:12:40  05/19/2027 09:52:44  200 403

src          user        count  method        url                                                status  kategori
10.10.60.92  (kosong)    17     CONNECT POST  telemetry-upd.example:443 https://telemetry-upd.example/api/v2/ping  200 403  Uncategorized
```

**Cara membaca hasil:** Zeek melihat sembilan `CONNECT` yang sama dari `10.10.60.92`, sehingga Suricata dan Zeek saling menguatkan untuk hop core. Log proxy memberi yang tidak bisa dilihat sensor mana pun: karena domain ini baru dan tidak terkategori, proxy men-decrypt sesinya, sehingga log proxy memuat delapan `POST` ke `/api/v2/ping` di dalam delapan tunnel, ditambah sembilan baris `CONNECT` (17 baris). Kolom `user` kosong karena proxy PT JAB tidak meminta autentikasi untuk workstation; identitas pengguna diambil dari Microsoft Defender for Endpoint (MDE). Nama field proxy mengikuti logformat PT JAB.

Timeline yang ditulis di `INC-2027-068` (WIB):

| Waktu | Kejadian | Bukti |
|---|---|---|
| 09:12:40.912 | `JKT-WS-2042` mengirim `CONNECT telemetry-upd.example:443` ke proxy | `eve-proto.json` event `http`; Zeek `http.log` hop core; `index=proxy` |
| 09:12:40.915 | Proxy me-resolve nama ke `jkt-res01` (alert `sid 1000102`) | `eve-alert.json`, sumber `10.20.3.60` |
| 09:12:40.917 | `jkt-res01` meneruskan query ke authoritative server di internet (alert `sid 1000102`) | `eve-alert.json`, sumber `10.20.2.53` |
| 09:12:41.004 | Proxy membuka TLS ke `203.0.113.176:443`, SNI cocok (alert `sid 1000101`) | `eve-alert.json`; Zeek `conn.log` dan `ssl.log` hop egress |
| 09:17 sampai 09:47 | Tujuh koneksi lagi, jeda 297 sampai 304 detik; tidak ada query DNS baru karena TTL 3600 detik masih berlaku di proxy | `eve-alert.json` (7 alert TLS) |
| 09:13 | Correlation search Splunk atas rule `JAB LOCAL` membuat `SOC-2027-0642`; Gilang mengambilnya 09:20 dan meneruskan ke L2 09:31 | Splunk |
| 09:38 | Host asal ditemukan: `10.10.60.92` (`JKT-WS-2042`) | Bagian ini |
| 09:41 | Dimas membuka `INC-2027-068` | Tiket |
| 09:48 dan 09:49 | Domain diblokir di `jkt-proxy01`; `203.0.113.176` diblokir di `jkt-fw01` | Change log |
| 09:52:44 | Percobaan kesembilan dijawab 403 oleh proxy | `eve-proto.json`, Zeek, `index=proxy` |
| 09:53 | MDE mengisolasi `JKT-WS-2042`; penanganan host diserahkan ke tim IR | MDE |

Indikator bukan kesimpulan. Yang terbukti dari jaringan: satu workstation menghubungi domain yang ada di buletin ISAC, delapan kali dengan jeda sekitar 300 detik dan ukuran mirip, lewat proxy. Yang tidak terbukti dari jaringan: proses apa yang membuat koneksi, apakah ada data yang keluar di dalam `POST` itu, dan sejak kapan host terinfeksi. Sebelum 08:00 Rabu tidak ada data Suricata; Zeek sejak Selasa 08:00 dan log proxy 30 hari dipakai untuk mencari koneksi lebih awal ke domain atau alamat yang sama.

**Variasi:** cari host lain yang menghubungi `203.0.113.176` tanpa nama domain (misalnya IP mentah lewat `CONNECT 203.0.113.176:443`) dengan mengganti filter `hostname` menjadi `.http.url | startswith("203.0.113.176")`.

**Kapan gagal:** workstation yang keluar tanpa proxy (aturan firewall lama seperti `NOC-VENDOR-DIRECT` di Day 02) tidak punya hop `CONNECT`, sehingga sumber egress-nya langsung alamat workstation; workstation di switch akses yang sama tetap tidak terlihat sensor bila berkomunikasi satu sama lain; dan `eve-proto.json` hanya disimpan 7 hari, sehingga untuk kasus yang ditemukan terlambat, Zeek dan log proxy menjadi sumber utama.

### 2.8 Menyambung ke Zeek lewat `community_id`, lalu ke paket

Langkah ini menjawab pertanyaan keempat Dimas dengan satu search.

**Tujuan:** menggabungkan alert Suricata dan baris `conn.log` Zeek untuk koneksi yang sama, lalu membuka paketnya di Wireshark bila perlu.

```
(index=suricata sourcetype=suricata event_type=alert alert.signature_id=1000101)
 OR (index=zeek sourcetype=bro:conn:json id.resp_h=203.0.113.176)
 earliest="05/19/2027:09:00:00" latest="05/19/2027:10:00:00"
| stats min(_time) AS pertama values(sourcetype) AS sumber values(alert.signature_id) AS sid
        values(uid) AS uid values(conn_state) AS conn_state values(resp_bytes) AS resp_bytes BY community_id
| convert ctime(pertama)
| sort pertama
```

| Bagian | Fungsi |
|---|---|
| Dua kondisi dengan `OR` | Alert rule lokal dari Suricata dan semua koneksi Zeek ke alamat yang sama |
| Jendela waktu absolut | Satu jam; membatasi tabrakan `community_id` karena port sumber dipakai ulang (bagian 1.5) |
| `stats ... BY community_id` | Menggabungkan event dari dua alat tanpa `join`; satu baris per koneksi |
| `values(sourcetype)` | Baris yang memuat kedua sourcetype berarti kedua alat melihat koneksi itu |

Keluaran ilustrasi (diringkas; delapan baris, enam di tengah dihilangkan):

```
community_id                     pertama              sumber                    sid      uid                conn_state  resp_bytes
1:q3Xv8nT2bLw0YfK5rJc9sPm1HdE=   05/19/2027 09:12:40  bro:conn:json suricata    1000101  CJk8sV3mQw7nR2tLp  SF          5431
1:Zr4Kp0wE7yLb2Nf6TqHs1Vx9JcA=   05/19/2027 09:17:43  bro:conn:json suricata    1000101  CPv2dW9hLs4kT7bNe  SF          5398
...
1:Mf8Lq2Ys5Dk1Wv7Pb3Rt0Hn6XeG=   05/19/2027 09:47:44  bro:conn:json suricata    1000101  CzX6gH1qRm8vB3nKs  SF          5460
```

**Cara membaca hasil:** delapan koneksi, masing-masing punya satu alert Suricata dan satu baris `conn.log` dengan `community_id` yang sama. Dari `uid` Zeek, pivot berlanjut ke `ssl.log` dan `x509.log` seperti di Day 08. Tidak ada baris yang hanya berisi `bro:conn:json`, artinya tidak ada koneksi lain ke `203.0.113.176` dalam jam itu tanpa alert, dan tidak ada baris yang hanya berisi `suricata`, artinya Zeek melihat semua koneksi yang dilihat Suricata. `pertama` lebih awal sekitar 6 milidetik dari alert karena `_time` baris Zeek adalah awal koneksi, sedangkan alert ditulis saat ClientHello.

Angka byte dari dua alat tidak sama, dan itu wajar. `resp_bytes` Zeek adalah byte payload dari sisi server (Day 08), sedangkan `bytes_toclient` Suricata (6.215 untuk koneksi pertama, bagian 2.6) dihitung dari paket utuh. Cara Suricata menghitung byte perlu dicek di dokumentasi atau lab versi-mu; jangan membandingkan angka byte lintas alat untuk menyimpulkan ada data yang hilang.

**Menyelam ke paket.** Alert memberi tahu koneksi mana; Wireshark memperlihatkan paketnya untuk konfirmasi akhir. Pcap egress `jkt-pcap01` masih tersedia (retensi target 72 jam):

```
# buka pcap di Wireshark, filter ke 4-tuple dari alert
ip.addr == 10.0.0.8 and ip.addr == 203.0.113.50 and tcp.port == 443

# PT JAB: koneksi pertama INC-2027-068
ip.addr == 10.20.3.60 and ip.addr == 203.0.113.176 and tcp.port == 41822
```

Ini menutup lingkaran Suricata (deteksi) ke Zeek (konteks) ke Wireshark (bukti paket). Wireshark sejak 3.3.1 juga bisa menghitung Community ID [S16]; cara mengaktifkannya dan nama field filternya cek di Preferences Wireshark versi-mu.

**Variasi:** ganti kondisi Zeek menjadi `sourcetype=bro:ssl:json` untuk langsung mendapat `server_name` dan fingerprint per `community_id`; nama sourcetype selain `bro:conn:json`, `bro:http:json`, dan `bro:ssl:json` perlu divalidasi dengan `| metadata type=sourcetypes index=zeek` sebelum dipakai di search tersimpan.

**Kapan gagal:** seed `community-id` di salah satu alat tidak 0; salah satu alat belum mengaktifkan Community ID (field kosong, baris tidak tergabung); jendela waktu terlalu lebar sehingga dua koneksi berbeda dengan 5-tuple sama tergabung; dan koneksi workstation ke proxy tidak pernah punya `community_id` yang sama dengan koneksi proxy ke internet, karena itu dua koneksi berbeda (bagian 1.5).

### 2.9 Triage lima alert hari pertama

Langkah ini adalah jawaban pertanyaan kelima Dimas dalam bentuk keputusan per tiket. Urutannya mengikuti tabel prioritas bagian 1.6.

**Tujuan:** untuk setiap tiket, menulis klaim rule, bukti yang menguatkan atau membantah, label, dan tindakan.

Tabel berikut adalah ringkasan yang dikirim ke Dimas; cari kolom "Label" untuk melihat bahwa hanya satu tiket menjadi insiden.

| Tiket | Alert | Klaim rule | Bukti utama | Label | Tindakan |
|---|---|---|---|---|---|
| `SOC-2027-0642` | 10 (2 DNS, 8 TLS) | Klien meminta domain C2 dari buletin ISAC | `CONNECT` dari `JKT-WS-2042`, delapan koneksi berjeda sekitar 300 detik, `POST` di log proxy (bagian 2.7) | Benar, dieskalasi | `INC-2027-068`; blokir domain dan IP; isolasi MDE; IR |
| `SOC-2027-0644` | 6 | Percobaan path traversal ke server web | Respons 404 dan 400 berukuran kecil, tanpa 200 | Benar, percobaan gagal | Blokir sumber di `jkt-fw01` pukul 13:38; tutup |
| `SOC-2027-0641` | 118 | User agent Nmap Scripting Engine | 118 request HTTP port 80 dari satu sumber dalam tujuh menit, tanpa sesi lanjutan | Benar, pemindaian tanpa dampak | Threshold per sumber; tutup |
| `SOC-2027-0643` | 412 (5 signature) | Keganjilan stream TCP | Drop kernel 1,90% di jam yang sama, 38 sumber berbeda | Masalah sensor | Perbaikan kapasitas pukul 12:30; jendela ditulis di laporan (bagian 2.12) |
| `SOC-2027-0640` | 640 | SNMP community `public` | Satu sumber `jkt-mon01`, 20 perangkat, tiap 15 menit | Benar tetapi tidak relevan, dengan risiko | Suppress per sumber; tiket NOC ganti community (bagian 2.10) |

Sisanya, 188 alert dari 51 signature (kelompok "lainnya" di bagian 2.4), dibaca Dwi sebagai satu daftar: kebanyakan `ET POLICY` dan `ET INFO` dari server internal yang dikenal. Tidak ada yang ditiketkan sendiri; kandidat tuning dikumpulkan dan ditanyakan ke pemilik aset sebelum ada yang diubah.

**Alert path traversal dan Nmap (`SOC-2027-0644`, `SOC-2027-0641`).** Kedua tiket berasal dari sumber yang sama, `203.0.113.177`, ke portal pelanggan `jkt-dmz-portal01` (`10.20.9.60`, alamat publik `198.51.100.209`). Sensor melihat alamat internal karena DMZ ada di belakang core switch dan DNAT sudah terjadi di firewall (Day 04). Klaim rule path traversal hanya "URI berisi urutan `../` ke berkas sistem"; apakah server memberikan berkas itu dijawab oleh respons, yang tidak ada di alert. Respons dicari di `http.log` Zeek:

```
index=zeek sourcetype=bro:http:json id.orig_h=203.0.113.177 earliest="05/19/2027:13:15:00" latest="05/19/2027:13:35:00"
| stats count BY id.resp_h id.resp_p status_code
| sort - count

index=zeek sourcetype=bro:http:json id.orig_h=203.0.113.177 uri="*..*" earliest="05/19/2027:13:15:00" latest="05/19/2027:13:35:00"
| table _time uid uri status_code response_body_len
```

Keluaran ilustrasi:

```
id.resp_h   id.resp_p  status_code  count
10.20.9.60  80         404          93
10.20.9.60  80         200          14
10.20.9.60  80         301           9
10.20.9.60  80         400           2

_time                uid                uri                                       status_code  response_body_len
05/19/2027 13:24:11  CbN3wQ7rT1yLk5vHs  /../../../../etc/passwd                   400          157
05/19/2027 13:24:12  CbN3wQ7rT1yLk5vHs  /..%2f..%2f..%2f..%2fetc%2fpasswd         404          153
05/19/2027 13:24:14  CbN3wQ7rT1yLk5vHs  /%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd   400          157
05/19/2027 13:24:15  CqL8mZ2xV6nB4tRd    /help/..%2f..%2f..%2fetc%2fpasswd         404          153
05/19/2027 13:24:17  CqL8mZ2xV6nB4tRd    /static/..%2f..%2f..%2f..%2fetc%2fpasswd  404          153
05/19/2027 13:24:19  CqL8mZ2xV6nB4tRd    /index.php?page=../../../../etc/passwd    404          153
```

**Cara membaca hasil:** 118 request HTTP ke port 80 (93 + 14 + 9 + 2), sama dengan jumlah alert user agent Nmap; enam request path traversal termasuk di dalamnya, karena skrip Nmap juga mengirim request itu dengan user agent yang sama, sehingga satu request bisa memicu dua rule. Tidak ada respons 200 untuk keenam request traversal, dan ukuran respons 153 sampai 157 byte adalah halaman error, bukan isi `/etc/passwd`. Respons 200 yang 14 itu adalah halaman bantuan lama di port 80 yang memang publik. Request ke port 443 hanya terlihat sebagai sesi TLS di `conn.log` dan `ssl.log`; user agent dan URI-nya tidak terlihat oleh Suricata maupun Zeek, sehingga "118 alert" adalah batas bawah dari apa yang dikirim pemindai. `index=firewall` menunjukkan sumber yang sama hanya ke `198.51.100.209` port 80 dan 443 antara 13:20:05 dan 13:26:40, dan tidak ada koneksi setelahnya. Label: pemindaian dan percobaan nyata, tidak berhasil. Port 80 portal yang masih melayani halaman lama dicatat sebagai temuan terpisah untuk pemilik portal.

**Alert SNMP (`SOC-2027-0640`).**

```
index=suricata sourcetype=suricata event_type=alert alert.signature="GPL SNMP public access udp"
    earliest="05/19/2027:08:00:00" latest="05/19/2027:16:00:00"
| stats count dc(dest_ip) AS perangkat min(_time) AS pertama max(_time) AS terakhir BY src_ip
| convert ctime(pertama) ctime(terakhir)
```

Keluaran ilustrasi:

```
src_ip       count  perangkat  pertama              terakhir
10.20.4.30   640    20         05/19/2027 08:00:12  05/19/2027 15:45:09
```

**Cara membaca hasil:** satu sumber, `jkt-mon01`, ke 20 perangkat. Dari 08:00 sampai 15:45 ada 32 siklus polling tiap 15 menit, dan 32 dikali 20 sama dengan 640. Rule-nya benar: SNMPv2c mengirim community string sebagai teks polos, dan `public` adalah community bawaan yang mudah ditebak. Rule ini memakai `content` mentah pada `alert udp`, sehingga alert-nya tidak membawa objek protokol (bagian 1.11). Bambang mengonfirmasi bahwa 20 perangkat itu switch dan PDU lama yang belum dimigrasi ke SNMPv3. Label: benar tetapi tidak relevan sebagai insiden, dengan risiko yang tetap harus diperbaiki.

**Engine event stream (`SOC-2027-0643`).** 412 alert dari lima signature `SURICATA STREAM ...` (misalnya paket di luar window dan ACK tidak valid), 371 di antaranya antara 08:30 dan 10:00, dari 38 sumber yang tidak punya hubungan satu sama lain. Pola "banyak sumber, satu jam, jenis keganjilan TCP" menunjuk ke sensor yang kehilangan paket, bukan ke 38 host yang menyerang. Pembuktiannya dari counter `stats` (bagian 2.12).

**Variasi:** untuk alert serangan web ke aset sendiri, selalu tambahkan dua pertanyaan: apakah aset itu menjalankan perangkat lunak yang diserang (tanya pemilik aset, lihat banner di `http.log`), dan apakah ada respons sukses dengan ukuran yang tidak wajar.

**Kapan gagal:** respons server tidak terlihat karena portal hanya melayani HTTPS; Zeek kehilangan paket pada jam itu sehingga `http.log` tidak lengkap; atau pemindai memakai user agent biasa, sehingga rule user agent diam walaupun pemindaian tetap terjadi.

### 2.10 Tuning hari pertama: threshold, suppress, dan tidak ada disable

Langkah ini adalah jawaban pertanyaan keenam Dimas dalam bentuk berkas konfigurasi.

**Tujuan:** menekan bising yang sudah dilabeli tanpa membuat titik buta, dengan jejak yang bisa ditinjau.

```
# /etc/suricata/threshold.config di jkt-ids01 (disimpan di repositori konfigurasi jab-nsm)

# SOC-2027-0640 | 2027-05-19 | pemilik: SOC (Dimas) | tinjau: 2027-06-19
# jkt-mon01 polling SNMPv2c community public ke 20 perangkat lama; tiket NOC untuk migrasi ke SNMPv3
suppress gen_id 1, sig_id 2101411, track by_src, ip 10.20.4.30

# SOC-2027-0641 | 2027-05-19 | pemilik: SOC (Dimas) | tinjau: 2027-06-19
# User agent Nmap dari internet: satu alert per sumber per 10 menit cukup untuk tahu ada pemindaian
threshold gen_id 1, sig_id 2009358, type limit, track by_src, count 1, seconds 600
```

Penjelasan tiap bagian:

- Baris komentar memuat nomor tiket pemicu, tanggal, pemilik, alasan, dan tanggal tinjau (aturan tuning PT JAB, bagian 1.8).
- `suppress ... track by_src, ip 10.20.4.30`: alert SNMP dari `jkt-mon01` hilang; dari sumber lain tetap muncul [S9]. Rule-nya tetap berjalan, jadi bila suatu hari workstation mengirim SNMP `public`, alert tetap ada.
- `threshold ... type limit, track by_src, count 1, seconds 600`: maksimal satu alert per sumber per 600 detik [S9][S10]. Kejadiannya tetap tercatat, hanya jumlah alert-nya yang dibatasi. Rule path traversal tidak diubah.
- `sid` 2101411 dan 2009358 adalah `sid` rule SNMP dan Nmap di contoh ini; ambil `sid` yang benar dari `alert.signature_id` di Splunk, bukan dari catatan, karena ruleset bisa berubah.

Lalu uji dan muat ulang:

```
suricata -T -c /etc/suricata/suricata.yaml -v
suricata-update --reload-command "suricatasc -c ruleset-reload-nonblocking"
```

- `suricata -T` memastikan berkas threshold dan rule bisa dimuat sebelum sensor menerimanya.
- `suricata-update` dengan `--reload-command` memuat ulang rule hanya bila berkas keluaran berubah; `ruleset-reload-nonblocking` memuat ulang tanpa menghentikan pemeriksaan trafik [S11]. Apakah reload rule juga memuat ulang `threshold.config` perlu dicek di dokumentasi versi-mu; bila ragu, restart terjadwal di luar jam sibuk.

Keluaran ilustrasi (validasi hari berikutnya, Kamis 2027-05-20 08:00 sampai 16:00):

```
index=suricata sourcetype=suricata event_type=alert alert.signature_id IN (2101411, 2009358)
    earliest="05/20/2027:08:00:00" latest="05/20/2027:16:00:00"
| stats count BY alert.signature_id src_ip

(tidak ada hasil)
```

**Cara membaca hasil:** tidak ada alert `2101411` dari `10.20.4.30`, yang merupakan tujuan suppress. Kamis tidak ada pemindai dengan user agent Nmap, jadi efek threshold belum terlihat di produksi; perilakunya diuji di lab (bagian 3). Hasil kosong juga bisa berarti sensor atau forwarder mati, jadi pastikan alert lain dan event `stats` hari itu tetap masuk sebelum menyimpulkan tuning bekerja. Tuning berhasil bila alert yang dilabeli bising hilang atau berkurang, dan alert yang sama dari sumber lain masih bisa muncul. Uji yang kedua: di lab, kirim SNMP `public` dari host lain dan pastikan alert-nya tetap muncul (bagian 3).

**Kenapa tidak ada disable.** Di minggu pertama, belum ada rule yang dimatikan lewat `disable.conf`. Mematikan rule berarti tidak ada yang tercatat untuk siapa pun (bagian 1.8), dan data satu hari belum cukup untuk tahu rule mana yang tidak pernah berguna. Kandidat disable dikumpulkan sampai akhir Mei dari kelompok "lainnya", dengan bukti jumlah alert, sumber, dan label.

**Variasi:** untuk alert `ET POLICY` dari satu server repositori internal yang sah, `suppress ... track by_src, ip <server>` lebih sempit daripada disable; untuk rule yang terlalu luas di seluruh jaringan, `modify.conf` bisa mengubah satu bagian rule, tetapi perubahan isi rule ET membuat rule berbeda dari yang dirawat Emerging Threats dan perlu dicatat sebagai rule turunan.

**Kapan gagal:** suppress ditulis dengan `track by_dst` padahal maksudnya sumber, sehingga yang hilang adalah alert untuk perangkat tujuan dari siapa pun; baris tanpa komentar yang tidak pernah ditinjau; dan `sid` yang ditulis dari ingatan sehingga rule lain yang tersupresi.

### 2.11 Onboarding Splunk: dua `eve-log`, `inputs.conf`, `props.conf`, validasi, dan volume

Langkah ini adalah jawaban pertanyaan terakhir Dimas dalam bentuk konfigurasi dan angka.

**Tujuan:** mengirim hanya alert, anomaly, dan stats ke index `suricata` dengan sourcetype `suricata`, menyimpan event protokol di sensor, lalu memastikan parsing dan volumenya benar.

```
# /etc/suricata/suricata.yaml di jkt-ids01 (cuplikan bagian outputs)
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve-alert.json
      community-id: true
      community-id-seed: 0
      types:
        - alert:
            metadata: yes
        - anomaly:
            enabled: yes
        - stats:
            totals: yes
            threads: no
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve-proto-%Y%m%d-%H.json
      rotate-interval: hour
      community-id: true
      community-id-seed: 0
      types:
        - flow
        - dns
        - http:
            extended: yes
        - tls:
            extended: yes
        - files
```

| Bagian | Fungsi |
|---|---|
| Dua `eve-log` dengan `filename` dan `types` sendiri | Didukung dokumentasi; satu berkas untuk SIEM, satu untuk pivot di sensor [S3] |
| `community-id: true`, `community-id-seed: 0` | Opsi per instance, jadi ditulis di keduanya; seed sama dengan `jkt-zeek01` [S3] |
| `alert` dengan `metadata: yes` | Alert membawa metadata app-layer, flow, dan metadata rule [S3] |
| `anomaly`, `stats` | Keganjilan protokol dan counter kesehatan sensor ikut ke Splunk |
| `stats` `totals: yes`, `threads: no` | Satu event total per interval, bukan satu per thread, supaya event tetap kecil [S3] |
| `filename` dengan pola waktu dan `rotate-interval: hour` | Berkas protokol berganti tiap jam; berkas yang lebih tua dari 7 hari dihapus oleh tugas terjadwal di sensor [S3] |
| `http` dan `tls` `extended: yes` | Menambah `http_method`, `status`, field sertifikat (bagian 1.4) |

Satu catatan dari dokumentasi: event `drop` hanya boleh ada di satu instance `eve-log` [S3]. Di sensor IDS ini tidak relevan, tetapi akan relevan bila kelak ada segmen IPS.

Forwarder dan parsing:

```
# /opt/splunkforwarder/etc/apps/jab_suricata_inputs/local/inputs.conf di jkt-ids01
[monitor:///var/log/suricata/eve-alert.json]
index = suricata
sourcetype = suricata

# etc/apps/jab_suricata/local/props.conf di indexer dan search head
[suricata]
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)
TIME_PREFIX = "timestamp":"
TIME_FORMAT = %Y-%m-%dT%H:%M:%S.%6N%z
MAX_TIMESTAMP_LOOKAHEAD = 32
TRUNCATE = 200000
KV_MODE = json
```

| Bagian | Fungsi |
|---|---|
| `sourcetype = suricata` | Satu sourcetype untuk semua event dari `eve-alert.json`; dibedakan dengan `event_type` (bagian 1.10) |
| `SHOULD_LINEMERGE`, `LINE_BREAKER` | Satu baris JSON satu event |
| `TIME_PREFIX`, `TIME_FORMAT` | `_time` diambil dari field `timestamp` Suricata (mikrodetik dan offset), bukan waktu baca forwarder |
| `MAX_TIMESTAMP_LOOKAHEAD = 32` | Nilai `timestamp` panjangnya 31 karakter (`2027-05-19T02:12:41.004812+0000`) |
| `TRUNCATE = 200000` | Event `stats` jauh lebih panjang daripada batas bawaan Splunk; tanpa ini event terpotong dan JSON-nya rusak. Ukur panjang event `stats` di sensor-mu lalu sesuaikan |
| `KV_MODE = json` | Field diekstrak saat search; nama bertitik seperti `alert.signature` |

Validasi di index staging sebelum produksi, lalu di produksi:

```
| metadata type=sourcetypes index=suricata
| table sourcetype totalCount lastTime

index=suricata sourcetype=suricata earliest="05/19/2027:08:00:00" latest="05/19/2027:16:00:00"
| stats count BY event_type

index=suricata sourcetype=suricata event_type=alert | head 1
| table _time timestamp alert.signature_id alert.signature src_ip dest_ip community_id
```

Keluaran ilustrasi (search kedua):

```
event_type  count
alert       1374
anomaly     120500
stats       3600
```

**Cara membaca hasil:** `| metadata` harus menampilkan hanya `suricata`; sourcetype lain di index ini berarti ada input yang salah konfigurasi. Jumlah per `event_type` memastikan ketiga tipe masuk. `_time` dan `timestamp` pada event contoh harus menunjukkan saat yang sama (Splunk menampilkan WIB, `timestamp` UTC). Bila add-on CIM pihak ketiga kelak dipasang, sourcetype yang diharapkan add-on itu dicek dulu di `props.conf`-nya, karena halaman Splunkbase-nya tidak mencantumkan nama sourcetype [S21].

Volume hari pertama, 08:00 sampai 16:00 WIB, dari metrik lisensi per sourcetype ditambah hitungan event per tipe. Tabel ini dipakai untuk menjawab "berapa GB per hari"; perhatikan bahwa `stats`, bukan alert, yang paling besar.

| `event_type` | Event | Rata-rata byte/event | Volume |
|---|---|---|---|
| `alert` | 1.374 | 2.000 | 2,748 MB |
| `anomaly` | 120.500 | 400 | 48,200 MB |
| `stats` | 3.600 | 30.000 | 108,000 MB |
| Total `eve-alert.json` | 125.474 | | 158,948 MB (sekitar 0,159 GB) |

Proyeksi harian dengan asumsi yang sama dengan Day 08 (delapan jam kerja membawa 60% trafik harian): 0,159 dibagi 0,6 sama dengan sekitar 0,265 GB per hari. Event `stats` ditulis tiap 8 detik (28.800 detik dibagi 8 sama dengan 3.600 event) dan memakan 68% volume. Menaikkan interval `stats` ke 60 detik menurunkannya ke 480 event atau 14,4 MB per delapan jam, sehingga total menjadi sekitar 65,3 MB per delapan jam (sekitar 0,109 GB per hari); keputusan itu ditunda sampai resolusi 60 detik terbukti cukup untuk mengukur drop.

Bila `eve-proto.json` ikut dikirim, perkiraannya dari ukuran berkas di sensor pada jendela yang sama:

| `event_type` | Event | Rata-rata byte/event | Volume |
|---|---|---|---|
| `flow` | 14.300.000 | 550 | 7,865 GB |
| `dns` | 6.100.000 | 450 | 2,745 GB |
| `tls` | 3.400.000 | 600 | 2,040 GB |
| `http` | 1.250.000 | 900 | 1,125 GB |
| `fileinfo` | 410.000 | 550 | 0,226 GB |
| Total `eve-proto.json` | 25.460.000 | | 14,0 GB |

14,0 GB per delapan jam setara sekitar 23,3 GB per hari, lebih besar daripada seluruh index `zeek` (11,256 GB per delapan jam, sekitar 18,8 GB per hari, Day 08) untuk informasi yang sebagian besar sama. Itu alasan event protokol Suricata tetap di sensor.

**Variasi:** bila suatu hari event protokol Suricata dibutuhkan di Splunk untuk satu kasus, kirim satu jam berkas `eve-proto` yang relevan ke index kasus dengan `oneshot`, bukan mengubah input permanen.

**Kapan gagal:** `TRUNCATE` bawaan memotong event `stats`; `_time` diambil dari waktu indexing karena `TIME_PREFIX` tidak cocok (misalnya `json` `preserve-order` dimatikan sehingga `timestamp` tidak lagi di awal); `KV_MODE = json` digabung dengan `INDEXED_EXTRACTIONS = json` sehingga setiap field muncul dua kali; dan rotasi `eve-alert.json` oleh logrotate tanpa sinyal ke Suricata membuat berkas berhenti ditulis.

### 2.12 Kesehatan sensor dari `stats`: `SOC-2027-0643`

Langkah ini membuktikan bahwa ratusan alert stream pagi hari adalah gejala sensor, dan mengukur jendela yang harus ditulis di laporan.

**Tujuan:** menghitung persentase drop per 30 menit dari counter capture, lalu mencocokkannya dengan waktu alert stream dan perubahan konfigurasi.

```
# di sensor: counter capture dari event stats
jq -c 'select(.event_type=="stats")
       | {timestamp, pkts: .stats.capture.kernel_packets, drops: .stats.capture.kernel_drops,
          gap: .stats.tcp.reassembly_gap}' /var/log/suricata/eve-alert.json | head -3

# di Splunk: drop per 30 menit
index=suricata sourcetype=suricata event_type=stats earliest="05/19/2027:08:00:00" latest="05/19/2027:16:00:00"
| bin _time span=30m
| stats min(stats.capture.kernel_packets) AS p0 max(stats.capture.kernel_packets) AS p1
        min(stats.capture.kernel_drops) AS d0 max(stats.capture.kernel_drops) AS d1
        min(stats.uptime) AS up0 max(stats.uptime) AS up1 BY _time
| eval packets=p1-p0, drops=d1-d0, drop_pct=round(drops/packets*100,2)
| eval restart=if(up1-up0 < 1700 OR up1-up0 > 1900, "ya", "tidak")
| table _time packets drops drop_pct restart
```

Penjelasan tiap bagian:

- `capture.kernel_packets` dan `capture.kernel_drops` adalah counter capture; di AF_PACKET yang kedua menghitung paket yang dibuang sebelum sampai ke Suricata [S20]. Keduanya kumulatif sejak Suricata mulai, jadi yang dibaca adalah selisih antar snapshot.
- `bin _time span=30m` dan pasangan `min`/`max` mengambil selisih counter dalam setiap jendela 30 menit.
- `drop_pct` = drop dibagi paket dikali 100. Dokumentasi tidak menuliskan rumus; apakah `kernel_packets` di AF_PACKET sudah termasuk paket yang di-drop perlu dicek di lab. Pada angka drop di bawah beberapa persen, perbedaannya kecil.
- `stats.uptime` dipakai mendeteksi restart: dalam jendela 30 menit tanpa restart, selisih uptime pertama dan terakhir sekitar 1.790 detik; restart membuat uptime kembali ke nol, sehingga selisihnya jauh lebih kecil atau jauh lebih besar. Counter capture juga kembali ke nol, jadi selisih `min`/`max` dalam jendela itu tidak bermakna.
- `tcp.reassembly_gap` menghitung celah data di stream TCP; dokumentasi menyebut nilai idealnya 0, dan bahwa checksum salah atau memori stream yang habis juga bisa menaikkannya, bukan hanya paket hilang [S20].

Keluaran ilustrasi (search Splunk):

```
_time             packets      drops       drop_pct  restart
05/19/2027 08:00  412000000     1236000    0.30      tidak
05/19/2027 08:30  498000000     5976000    1.20      tidak
05/19/2027 09:00  540000000    10260000    1.90      tidak
05/19/2027 09:30  531000000     7965000    1.50      tidak
05/19/2027 10:00  505000000     3030000    0.60      tidak
05/19/2027 10:30  497000000     2485000    0.50      tidak
05/19/2027 11:00  480000000     1920000    0.40      tidak
05/19/2027 11:30  455000000     1365000    0.30      tidak
05/19/2027 12:00  447000000     1341000    0.30      tidak
05/19/2027 12:30  (diabaikan)  (diabaikan)  -        ya
05/19/2027 13:00  486000000       97200    0.02      tidak
05/19/2027 13:30  492000000       49200    0.01      tidak
...
```

**Cara membaca hasil:** drop naik dari 0,30% ke puncak 1,90% antara 09:00 dan 09:30, saat trafik pagi paling tinggi (540 juta paket dalam 30 menit, sekitar 300 ribu paket per detik), lalu turun perlahan. Dari 412 alert stream, 371 jatuh di jendela 08:30 sampai 10:00 ketika drop di atas 1%. Pukul 12:31 Agung menaikkan jumlah thread AF_PACKET dari 8 menjadi 16 dan memperbesar ring per thread, lalu me-restart Suricata (sekitar dua menit buta, 12:31 sampai 12:33). Setelahnya drop 0,01% sampai 0,02%. Nama dan satuan opsi `threads` dan `ring-size` di bagian `af-packet` perlu dicek di `suricata.yaml` versi-mu.

Yang ditulis di tiket dan laporan harian: "08:30 sampai 10:00 WIB, `jkt-ids01` kehilangan 1,2% sampai 1,9% paket; alert stream di jendela itu adalah gejala sensor; tidak adanya alert lain di jendela itu tidak membuktikan tidak ada kejadian. 12:31 sampai 12:33 WIB sensor di-restart." `SOC-2027-0643` ditutup sebagai masalah sensor dengan perbaikan.

Drop di Suricata hanya mengukur paket yang sampai ke interface sensor. Paket yang dibuang `jkt-npb01` atau port SPAN di core switch tidak terlihat di counter ini; untuk itu baca counter port di packet broker dan switch, dan counter NIC sensor dengan `ethtool -S` [S20]. Ini padanan `capture_loss.log` di Zeek: Zeek memperkirakan dari celah ACK, Suricata menghitung dari kernel (Day 08).

Saved search `JAB-IDS-HEALTH-01` (tiap 15 menit) dibuat dari search di atas dengan `span=15m` dan `where drop_pct > 1 OR isnull(packets)`; baris dengan `packets` kosong berarti event `stats` tidak masuk sama sekali, gejala sensor atau forwarder mati.

**Variasi:** opsi `deltas: yes` di bagian `stats` `eve-log` menambahkan nilai selisih per interval sehingga `min`/`max` tidak perlu [S3]; nama field selisihnya cek di event contoh. Tambahkan `stats.tcp.reassembly_gap` ke tabel untuk melihat apakah celah stream ikut turun setelah perbaikan.

**Kapan gagal:** restart di tengah jendela membuat selisih negatif atau terlalu kecil bila tidak dideteksi; event `stats` terpotong `TRUNCATE` sehingga field `capture` tidak terbaca; dan counter `capture` tidak ada di mode capture tertentu (misalnya membaca pcap offline).

### 2.13 Satu halaman jawaban untuk Dimas

Ringkasan ini dikirim pukul 18:10 untuk laporan pagi Dimas ke Hendra. Setiap baris merujuk subbagian, supaya Dimas bisa membaca alasannya bila ditanya.

| Pertanyaan | Jawaban singkat | Dasar |
|---|---|---|
| Kenapa perlu Suricata bila sudah ada Zeek | Zeek buku catatan, Suricata alarm; alarm dibuktikan dengan catatan, dan keduanya disambung `community_id` | Bagian 1.1, 1.5 |
| Membaca alert dan rule | `[gid:sid:rev]`, `classtype` menentukan `severity`; `sid` 1000000 sampai 1999999 rule lokal; baca sticky buffer untuk tahu apa yang sebenarnya dibuktikan | Bagian 1.2, 1.3, 2.5 |
| Kenapa alert menunjuk proxy dan resolver | Itu titik pandang sensor egress; workstation `JKT-WS-2042` ditemukan lewat `CONNECT` di hop core, Zeek, dan log proxy | Bagian 1.4, 2.7 |
| Menyambung ke Zeek | `community_id` sama, seed 0 di kedua sensor; hop proxy tetap disambung lewat waktu dan host | Bagian 1.5, 2.8 |
| Mana yang dieskalasi | Hanya 10 alert rule lokal (`INC-2027-068`); 6 percobaan path traversal gagal; sisanya bising atau gejala sensor | Bagian 1.6, 2.9 |
| SNMP dimatikan? ET Pro? | Tidak dimatikan; suppress untuk `jkt-mon01` saja dan tiket NOC; ET Open cukup untuk percobaan, ET Pro diputuskan akhir Juli dari data | Bagian 1.7, 1.8, 2.10 |
| Kenapa tidak diblokir | Sensor IDS pasif; blokir di firewall dan proxy oleh analis; IPS dievaluasi di akhir program | Bagian 1.9 |
| Sourcetype, volume, sensor sehat | `index=suricata sourcetype=suricata`; alert, anomaly, dan stats saja, sekitar 0,27 GB per hari; drop 1,2% sampai 1,9% pukul 08:30 sampai 10:00, sudah diperbaiki | Bagian 1.10, 2.11, 2.12 |

**Kapan gagal:** jawaban dikirim tanpa menyebut jendela buta hari pertama (sebelum 08:00, drop 08:30 sampai 10:00, restart 12:31 sampai 12:33), atau tanpa menyebut bahwa lateral movement antar workstation di switch akses yang sama tetap tidak terlihat Suricata maupun Zeek. Tanpa itu, pembaca akan menganggap sensor melihat seluruh jaringan sepanjang hari.

## 3. Lab praktik (di VM lab terisolasi)

**Prasyarat:** Suricata 8.0.x di VM sensor Linux lab (dengan snapshot) dengan ruleset ET Open lewat `suricata-update`, atau `eve.json` dan `fast.log` contoh; pcap lab atau pcap publik dari sumber tepercaya; Zeek dengan Community ID dan Wireshark untuk korelasi; `jq`; Splunk lab bila ingin mengerjakan langkah 10; jaringan host-only `192.168.56.0/24` dengan `HOME_NET` diatur ke rentang itu. Jangan memakai pcap kerja; PT JAB hanya contoh fiktif.

1. **Jalankan (teks).** `suricata -T -c /etc/suricata/suricata.yaml -v`, lalu `suricata -r capture.pcap -l ./out` (bagian 2.1); identifikasi output dan baca jumlah rule yang dimuat di `suricata.log`.
2. **fast.log.** Baca gambaran cepat alert dan prioritas (bagian 2.2).
3. **eve.json.** Baca alert kaya dengan konteks (bagian 2.3); hitung dan prioritaskan (bagian 2.4).
4. **Rule.** Ambil satu `sid`; cari rule-nya dengan `grep` dan baca anatominya (bagian 2.5) untuk memahami pemicunya. Catat sticky buffer apa yang dipakai dan apa yang tidak dibuktikan alert-nya.
5. **Triage.** Untuk 2 sampai 3 alert teratas, lakukan triage (bagian 1.6): benar, false positive, benar tetapi tidak relevan, atau masalah sensor, dengan alasan.
6. **Korelasi.** Pakai `flow_id` (bagian 2.6), `community_id` ke `conn.log` Zeek (bagian 2.8), dan Wireshark untuk konfirmasi. Proses pcap yang sama dengan Zeek yang memuat `community-id-logging`, lalu cocokkan `community_id` untuk satu koneksi; ulangi dengan seed berbeda di salah satu alat dan catat bahwa join gagal tanpa pesan error.
7. **Rule lokal dari IOC lab.** Di VM klien lab, buat query DNS dan koneksi HTTPS ke nama milik lab sendiri (misalnya domain `*.test` di resolver lab). Tulis dua rule lokal dengan `sid` di rentang 1000000 sampai 1999999 untuk `dns.query` dan `tls.sni` nama itu, uji dengan `suricata -T`, putar ulang capture, dan pastikan setiap rule memicu sesuai klaimnya.
8. **Tuning.** Tambahkan satu baris `suppress ... track by_src` untuk satu sumber lab dan satu baris `threshold ... type limit` untuk rule yang berulang (bagian 2.10). Putar ulang capture; pastikan alert dari sumber yang disupresi hilang dan alert dari sumber lain tetap ada. Bandingkan jumlah alert sebelum dan sesudah threshold.
9. **suricata-update.** Jalankan `suricata-update` di VM, tambahkan satu entri `disable.conf` (`sid`, `group:`, atau `re:`), jalankan ulang, dan pastikan rule itu hilang dari `suricata.rules` sedangkan entri tetap ada setelah update berikutnya.
10. **Splunk.** Kirim `eve.json` lab ke index lab dengan sourcetype `suricata` dan `props.conf` bagian 2.11, lalu jalankan `| stats count BY event_type` dan satu search `community_id`. Catat apakah event `stats` terpotong dengan `TRUNCATE` bawaan.
11. **Kesehatan sensor.** Jalankan Suricata live di VM sensor selama minimal 30 menit sambil membangkitkan trafik, lalu hitung drop dari dua event `stats` (bagian 2.12). Ulangi dengan ring AF_PACKET yang sengaja kecil dan trafik lebih tinggi untuk melihat drop dan alert `SURICATA STREAM` naik bersama.
12. **Mode dan `CONNECT`.** Tambahkan VM Squid sebagai proxy eksplisit untuk VM klien, lalu catat apakah Suricata 8 mencatat request `CONNECT` sebagai event `http` dan bagaimana `hostname` dan `url` ditulis (bagian 2.7). Bila sempat, jalankan rule `drop` di mode IDS dan catat nilai `alert.action` yang muncul (bagian 1.9).
13. **Rangkum.** Tulis mana alert yang nyata, mana false positive atau tidak relevan, mana gejala sensor, dan rekomendasi tuning singkat.

**Hasil yang sebaiknya tersimpan:**

- Output Suricata (`fast.log`, `eve.json`, `suricata.log`) dikenali dan dibaca.
- Anatomi rule (action, header, options) dibaca untuk memahami pemicu, termasuk apa yang tidak dibuktikan rule.
- Alert dihitung dan diprioritaskan; volume berisik dikenali.
- Triage memisahkan benar, false positive, tidak relevan, dan masalah sensor dengan konteks.
- `flow_id`, `community_id`, dan 4-tuple dipakai untuk korelasi ke Zeek dan Wireshark, termasuk bukti bahwa seed berbeda mematahkan join.
- Dua rule lokal yang memicu sesuai klaim, dengan `sid` lokal dan metadata.
- Baris suppress dan threshold beserta bukti sebelum dan sesudah, dan entri `disable.conf` yang bertahan setelah update.
- Satu perhitungan drop dari event `stats`, dan catatan perilaku `CONNECT` serta `drop` di mode IDS.
- Rangkuman memuat rekomendasi tuning, tidak berhenti di daftar alert.

**Variasi tantangan:** untuk satu alert malware C2 di pcap infeksi, buktikan atau bantah dengan konteks: cocokkan SNI/JA3 (`eve.json` `tls`) dan domain (`dns`) dengan IOC, lalu tulis mini-laporan triage (klaim rule, bukti pendukung, keyakinan, tindakan). Nyatakan kapan kamu akan menyetujui eskalasi dan kapan menandai tuning; bila tuning, tulis baris `suppress` atau entri `disable.conf` yang kamu usulkan beserta alasannya. Ini menyiapkan Day 13 (integrasi SIEM).

## 4. Troubleshooting

Tabel ini memuat masalah yang muncul saat menjalankan Suricata offline, di sensor, dan di Splunk. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Tidak ada alert | Ruleset tak terpasang/trafik tak cocok | Pastikan rule dimuat (`suricata -T -v`, jumlah rule di `suricata.log`); cek `fast.log` |
| Terlalu banyak alert | Rule luas/berisik, atau `EXTERNAL_NET` `any` | Prioritaskan, tuning, korelasi konteks (bagian 2.4, 2.10) |
| Alert tanpa konteks | Hanya `fast.log` dibaca | Pakai `eve.json` untuk flow/http/dns/tls |
| Alert tanpa objek protokol di Suricata 8 | Rule tidak memakai keyword app-layer | Pivot lewat `flow_id` atau `community_id`; `detect.guess-applayer-tx` hanya bila paham batasnya (bagian 1.11) [S8] |
| Rule TLS tak memicu | Isi terenkripsi | Banyak rule TLS pakai metadata (SNI/JA3); `encryption-handling` `track-only` mematikan inspeksi `content` mentah (bagian 1.11) |
| `flow_id` tak cocok | Salah event/aliran, atau beda instance | Pastikan `flow_id` sama dan dari instance yang sama; cek `event_type` |
| `community_id` tidak tergabung dengan Zeek | Seed berbeda, Community ID mati di salah satu alat, atau hop proxy dibandingkan dengan hop egress | Cek `community-id-seed` dan skrip Zeek; bandingkan hop yang sama (bagian 1.5) |
| Versi rule berbeda | Ruleset usang/baru | Jalankan ulang `suricata-update`; bandingkan `rev` rule di alert |
| Rule `ja3.hash`/`ja4.hash` tak pernah memicu | Fingerprint dimatikan di konfigurasi, atau ClientHello milik proxy | Cek `ja3-fingerprints`/`ja4-fingerprints` di `suricata.yaml`; cek apakah koneksi di-bump proxy (bagian 1.4) |
| Rule lokal ditolak saat load | Error sintaks, `sid` bentrok, atau keyword versi lama | `suricata -T -v`; `sid` unik di rentang lokal; nama keyword baru (`ja3.hash`, bukan `ja3_hash` untuk rule baru) |
| Banyak alert `SURICATA STREAM` atau `DECODE` di jam sibuk | Drop di sensor atau SPAN satu arah | Hitung drop dari `stats` (bagian 2.12); cek counter port broker dan `ethtool -S` |
| Suppress tidak bekerja | `track` salah arah, `sid` salah, atau threshold belum dimuat ulang | Cek baris dan `alert.signature_id`; uji di lab; restart terjadwal bila reload tidak memuat `threshold.config` |
| Field `alert.signature` tidak ada di Splunk | Sourcetype tidak di-parse sebagai JSON | `KV_MODE = json` di search head; cek `\| metadata` dan satu event contoh |
| Event `stats` rusak di Splunk | `TRUNCATE` bawaan memotong event panjang | Naikkan `TRUNCATE` (bagian 2.11) |
| Field DNS di query lama kosong | Format DNS versi 3 di Suricata 8 | Sesuaikan nama field dengan event contoh; versi 2 masih bisa dipilih tetapi akan dihapus di 9 [S7][S8] |
| Alert dari rule `drop` tetap `allowed` | Sensor IDS pasif | Normal; `blocked` hanya di IPS atau reject (bagian 1.9) |

## 5. Kesalahan umum dan jebakan

- **Menganggap alert = kepastian.** Alert adalah sinyal; triage dan konteks menentukan benar/false positive.
- **Hanya membaca fast.log.** eve.json memberi konteks yang diperlukan untuk triage.
- **Membaca `msg` tanpa membaca rule.** `msg` adalah judul yang ditulis pembuat rule; yang dibuktikan alert ditentukan header dan sticky buffer (bagian 1.2).
- **Menyimpulkan "host X menyerang host Y" dari `src_ip` alert.** Arah alert mengikuti paket pemicu, bukan pembuka koneksi (bagian 1.4).
- **Mencari workstation di alert egress padahal ada proxy eksplisit.** Sumber egress adalah proxy dan resolver; workstation dicari di hop core, Zeek, dan log proxy (bagian 2.7).
- **Memakai JA3/JA4 egress sebagai fingerprint malware di balik proxy dekripsi.** ClientHello-nya milik proxy (bagian 1.4).
- **Suppress tanpa catatan.** Setiap suppress dan rule yang dimatikan perlu alasan, pemilik, dan tanggal tinjau.
- **Mematikan rule untuk menghilangkan bising dari satu sumber.** Suppress per sumber lebih sempit; disable membuat titik buta untuk semua host (bagian 1.8).
- **Menganggap tuning menutup risikonya.** SNMP `public` tetap risiko walaupun alert-nya disupresi; tiketnya ke pemilik aset.
- **Mengira Suricata menggantikan Zeek.** Suricata deteksi, Zeek konteks; dipakai bersama.
- **Mengabaikan pemeliharaan ruleset.** Rule usang melewatkan ancaman; rule luas membuat bising.
- **Membaca rule sebagai resep serangan.** Baca sebagai "apa yang dideteksi"; teknik serangan dirujuk ke katalog resmi (bagian 1.3).
- **Membaca "tidak ada alert" sebagai "tidak ada kejadian".** Tanpa rule yang cocok, saat sensor drop, atau saat sensor di-restart, diam tidak membuktikan apa pun (bagian 2.12).
- **Menyebut alert IDS "diblokir".** Di sensor pasif, `action` selalu `allowed`; blokir adalah tindakan terpisah di firewall atau proxy (bagian 1.9).
- **Membandingkan jumlah alert Suricata 7 dan 8 sebagai tren.** Waktu inspeksi dan logging berubah di 8.0 (bagian 1.11).
- **Mengirim semua event `eve.json` ke SIEM tanpa menghitung.** Event protokol Suricata bisa lebih besar daripada seluruh log Zeek untuk informasi yang hampir sama (bagian 2.11).
- `[komunitas, belum terkonfirmasi]` Banyak SOC memakai Suricata (ET Open) untuk alert awal dan Zeek untuk konteks, lalu triage di SIEM; pola ini umum. Nama field eve.json dan opsi `suricata-update` bisa berbeda antar versi, cek terhadap versi 8.0 yang dipakai.

## 6. Catatan terkini

Bagian ini menampung detail versi, perubahan perilaku Suricata, alat pengelola rule, dan add-on Splunk yang relevan saat membaca dokumentasi atau tutorial lain.

- Suricata 8.0.7 (15 Sep 2026) adalah rilis stabil; cabang 7.x sudah EOL dengan rilis terakhir 7.0.17 [S4]. Pengumumannya menyebut 8.0.7 sebagai rilis keamanan dengan 67 laporan kerentanan, terbanyak sejauh ini, yang dikaitkan proyek dengan naiknya analisis berbantuan AI; nomor CVE masih "Pending" saat diumumkan, dan tiket privat dibuka dua minggu setelah rilis [S19]. eve.json tetap format output utama untuk SIEM. Tutorial berbasis 7.x mungkin memakai nama keyword lama (misalnya `ja3_hash`, kini `ja3.hash`).
- Perubahan 7.0 ke 8.0 yang paling sering membuat query dan triage keliru: metadata app-layer hanya untuk rule dengan keyword app-layer, format DNS baru, inspeksi saat request atau respons selesai, dan output lama yang dijadwalkan dihapus (bagian 1.11) [S8].
- Dokumentasi `latest` sudah memuat catatan upgrade 8.x ke 9.0 untuk rilis yang belum keluar: `http-log` dihapus, `stream.reassembly.depth` bawaan menjadi 1 MiB bila tidak di-set, `pgsql` tidak lagi aktif secara bawaan, nama hook state SSH dan TLS berubah sehingga rule dengan nama lama gagal dimuat, dan beberapa nama counter app-layer berganti dari tanda hubung ke garis bawah [S8]. Saat membaca dokumentasi, pastikan versinya (`latest` atau `suricata-8.0.7`) sama dengan sensor.
- JA3 dan JA4 terintegrasi di Suricata; dukungannya aktif bila diset di konfigurasi (`app-layer.protocols.tls.ja3-fingerprints` / `ja4-fingerprints`) atau otomatis bila ada rule yang membutuhkannya, kecuali dimatikan eksplisit [S6].
- ET Open tetap ruleset gratis yang umum; pemeliharaan lewat `suricata-update` dengan `disable.conf`/`enable.conf`/`modify.conf`. `suricata-update` versi dokumentasi terbaru adalah 1.3.8 [S11]. FAQ Emerging Threats tentang lisensi ET Pro bertanggal 2022; syarat lisensi terkini perlu dicek ke Proofpoint [S18].
- Splunkbase belum punya add-on Suricata yang dirawat Splunk atau OISF; yang tersedia dirawat developer, yaitu CCX Add-on for Suricata 1.0.1 (8 Agu 2025) dan SuriZeek 1.5.8 (10 Okt 2026) [S21][S22]. Halaman SuriZeek menyebut sourcetype `zeek_json` untuk log Zeek, berbeda dari pola `bro:<log>:json` PT JAB, sehingga app itu perlu disesuaikan sebelum dipakai [S22].
- Dengan trafik makin terenkripsi, deteksi bergeser ke rule berbasis metadata TLS (SNI, JA3/JA4) dan korelasi dengan Zeek, bukan inspeksi payload. Konfigurasi sensor, alert, dan angka PT JAB di Day ini dibangun di atas Day 01 sampai 08 [S5].
- Day 10 (flow) dan Day 11-12 (beaconing/exfiltration) menambah sudut perilaku; Day 13 mengintegrasikan alert ke Splunk.

## 7. Cheat sheet

```
PERAN      Suricata = deteksi rule (alert, IDS/IPS) ; Zeek = log kejadian (konteks) ; dipakai bersama
RULE       action header options -> alert tcp $HOME_NET any -> $EXTERNAL_NET 443 (msg; content; flow; sid; rev;)
ACTION     alert (catat) | drop/reject (IPS) | pass ; reject* di IPS juga drop
ARAH       -> satu arah | <> dua arah (rule digandakan) | => arah + transaksi dua arah ; tidak ada <-
OPTIONS    urutan bermakna ; sticky buffer (tls.sni, http.uri, dns.query, ja3.hash, ja4.hash) = bagian yg dicocokkan
SID        1000000-1999999 lokal | 2000000-2103999, 2400000-2609999 ET Open | 2200000-2299999 engine event | 2800000-2899999 ET Pro
CLASSTYPE  classification.config -> priority -> alert.severity (1 tertinggi) ; priority keyword menimpa
OUTPUT     fast.log (ringkas 1 baris/alert) | eve.json (JSON kaya: alert/flow/dns/http/tls/fileinfo/anomaly/stats) = utama SIEM
ALERT eve  alert.action(allowed|blocked) signature signature_id(sid) rev category severity metadata + objek app-layer
           Suricata 8: objek app-layer hanya bila rule pakai keyword app-layer ; src/dest = arah paket pemicu
flow_id    perekat alert ke event di aliran yang sama (mirip UID Zeek) ; hanya dalam 1 instance
COMMUNITY  community-id: true ; seed 0 di semua alat ; SHA1 base64 "1:..." ; arah tak berpengaruh ; NAT/proxy = ID beda
TRIAGE     baca klaim -> cek konteks -> korelasi Zeek/Wireshark -> nilai reputasi -> benar / FP / tidak relevan / sensor / butuh data
TUNING     suppress (per sid+ip) < threshold (limit/threshold/both/backoff) < disable ; komentar: tiket, alasan, pemilik, tinjau
           threshold.config: suppress gen_id 1, sig_id N, track by_src, ip X
                             threshold gen_id 1, sig_id N, type limit, track by_src, count 1, seconds 60
RULESET    ET Open (gratis, BSD) | ET Pro (per sensor; OEM bila dijual) ; suricata-update -> /var/lib/suricata/rules/suricata.rules
           disable -> enable -> drop -> modify ; --local, --reload-command, --test-command ; suricata -T sebelum reload
OFFLINE    suricata -c yaml -k none -S rules -r pcap -l outdir ; -r <dir> = file berurutan, state flow dijaga
JQ         jq 'select(.event_type=="alert")' eve.json ; ... | .alert.signature | sort | uniq -c | sort -rn
SPLUNK     index=suricata sourcetype=suricata (PT JAB) ; event_type=alert|anomaly|stats ; KV_MODE=json ; TRUNCATE besar
           | metadata type=sourcetypes index=suricata
SEHAT      stats.capture.kernel_packets / kernel_drops (kumulatif, selisih antar snapshot) ; tcp.reassembly_gap ; uptime = restart
IDS/IPS    IDS pasif: action selalu allowed ; IPS: NFQ (-q) atau AF_PACKET copy-mode ips ; fail-open vs fail-closed
BATAS      hanya known (ada rule) ; terenkripsi -> metadata (SNI/JA3) ; evasion mungkin ; padukan Zeek+perilaku
BACA RULE  pahami APA yang dideteksi ; teknik serangan -> katalog resmi, bukan resep
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "Alert rule lokal C2 `SOC-2027-0642` bersumber `10.20.3.60` dan `10.20.2.53`. Berarti proxy dan resolver yang terinfeksi, dan keduanya harus diisolasi." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Itu titik pandang sensor: workstation PT JAB keluar ke web lewat proxy eksplisit, sehingga yang me-resolve nama dan membuka koneksi ke internet adalah proxy, dan resolver meneruskan query ke internet. Alert TLS hanya cocok di hop egress (proxy ke `203.0.113.176`), sedangkan workstation hanya membuka tunnel `CONNECT` ke proxy. Host asal, `JKT-WS-2042` (`10.10.60.92`), ditemukan lewat event `http` `CONNECT` di hop core, `http.log` Zeek, dan log proxy. Lihat bagian 1.4 dan 2.7.

</details>

**2. Skenario keputusan.** 640 alert `GPL SNMP public access udp` hari pertama berasal dari `jkt-mon01` ke 20 perangkat, tiap 15 menit. Langkah mana yang paling tepat?

- A. Matikan rule lewat `disable.conf`, karena semua alert-nya dari server monitoring sendiri.
- B. Suppress rule itu hanya untuk sumber `10.20.4.30` dengan komentar tiket, alasan, pemilik, dan tanggal tinjau, lalu buka tiket NOC untuk mengganti community `public`.
- C. Pasang `threshold type limit, track by_rule, count 1, seconds 3600` supaya hanya ada satu alert per jam untuk seluruh jaringan.

<details><summary>Jawaban</summary>

B. Suppress per sumber menghilangkan bising dari satu sumber yang sudah dikenal, tetapi rule tetap aktif untuk host lain, sehingga SNMP `public` dari workstation tetap memicu alert; tiket NOC menangani risiko yang ditemukan rule. A keliru karena disable membuat titik buta untuk semua host. C keliru karena `by_rule` menggabungkan semua sumber, sehingga alert dari host baru yang menarik bisa tertelan oleh polling `jkt-mon01` di jam yang sama. Lihat bagian 1.8 dan 2.10.

</details>

**3. Pertanyaan jebakan.** "Rule `JAB LOCAL C2 SNI` memicu delapan kali. Rule itu memeriksa `tls.sni`, jadi delapan alert ini membuktikan ada data yang dikirim ke server C2." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Sticky buffer `tls.sni` membuat rule hanya mencocokkan nama di ClientHello; satu-satunya yang dibuktikan alert adalah klien meminta nama itu. Isi sesi terenkripsi tidak pernah diperiksa, dan di Suricata 8 `encryption-handling` bawaan `track-only` memang mematikan inspeksi `content` mentah pada sesi terenkripsi. Bukti `POST` datang dari log proxy, karena proxy men-decrypt domain baru; isi `POST` itu sendiri tetap perlu dinilai terpisah. Lihat bagian 1.2, 1.11, dan 2.7.

</details>

**4. Skenario keputusan.** Setelah membaca enam alert path traversal yang `allowed`, Hendra meminta `jkt-ids01` langsung dijadikan IPS di egress Jakarta minggu ini. Jawaban mana yang paling tepat?

- A. Setuju: cukup ubah action rule menjadi `drop` lewat `drop.conf`, dan sensor akan mulai memblokir.
- B. Belum: sensor saat ini pasif (SPAN dan TAP lewat packet broker) sehingga tidak bisa memblokir apa pun; IPS butuh jalur inline (NFQ atau AF_PACKET `copy-mode: ips`), keputusan fail-open atau fail-closed, dan data false positive. Percobaan hari ini gagal (404 dan 400) dan sumbernya sudah diblokir di firewall.
- C. Tidak perlu IPS karena IDS sudah memblokir; nilai `allowed` di alert hanya label default.

<details><summary>Jawaban</summary>

B. Di sensor yang membaca salinan trafik, paket asli sudah sampai sebelum Suricata selesai memeriksa, jadi rule `drop` tidak bisa membuang apa pun dan alert-nya tetap `allowed`. IPS butuh trafik benar-benar lewat Suricata, dengan risiko ketersediaan dan risiko memblokir layanan sah karena false positive; hari pertama menunjukkan sebagian besar alert adalah bising. A keliru karena `drop.conf` hanya bermakna di mode IPS. C keliru karena `allowed` berarti tidak diblokir; `blocked` hanya muncul saat drop di IPS atau reject bekerja. Lihat bagian 1.9 dan 2.9.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Bambang Hartono (Manajer NOC), dalam tiga kalimat, kenapa 412 alert `SURICATA STREAM` pagi ini tidak dianggap serangan dan apa yang membuktikannya.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Alert `SURICATA STREAM` adalah alarm internal engine untuk keganjilan TCP, mirip counter out-of-order dan CRC error di interface, bukan rule untuk serangan tertentu. Sebagian besar muncul antara 08:30 dan 10:00 dari 38 host yang tidak berhubungan, persis saat counter `stats` sensor menunjukkan 1,2% sampai 1,9% paket dibuang kernel di puncak trafik, jadi yang rusak adalah pandangan sensor, bukan sesi host-host itu. Setelah thread dan ring AF_PACKET dinaikkan pukul 12:31 drop turun ke 0,02% dan alert stream ikut turun, dan jendela pagi itu kami tulis sebagai jendela buta di laporan."

Kesalahan yang sering muncul:
- Menganggap 38 sumber berarti 38 host bermasalah, padahal satu sensor yang drop membuat semua sesi di jam itu tampak ganjil.
- Menyebut alert stream sebagai ukuran drop; ukurannya counter `capture.kernel_drops` dibanding `kernel_packets`.
- Lupa bahwa drop di packet broker atau SPAN tidak terlihat di counter sensor.

</details>

**6. Pertanyaan jebakan.** "`community_id` alert TLS egress `INC-2027-068` tidak ditemukan di baris `conn.log` koneksi `JKT-WS-2042` ke `10.20.3.60:3128`. Berarti Community ID di salah satu sensor salah konfigurasi." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Community ID dihitung dari 5-tuple yang dilihat sensor. Koneksi workstation ke proxy dan koneksi proxy ke internet adalah dua koneksi berbeda dengan 5-tuple berbeda, sehingga ID-nya pasti berbeda, sama seperti dua `uid` berbeda di Zeek. Yang harus cocok adalah alert egress dengan baris `conn.log` hop egress, dan itu cocok untuk delapan koneksi; hop core disambung lewat waktu, host, dan log proxy. Salah konfigurasi (misalnya seed berbeda) baru dicurigai bila koneksi yang sama pun tidak tergabung. Lihat bagian 1.5 dan 2.8.

</details>

**7. Interview question (English).** "You get a Suricata alert for a known C2 domain from your IDS. Walk me through your triage."

<details><summary>Sample answer</summary>

"First I read the rule, not just the message: which protocol, which direction, which buffer it inspects. If it matches on TLS SNI, the alert only proves that a client asked for that name in the ClientHello, nothing about the payload. Then I look at the alert in eve.json, including the action, which on a passive sensor is always allowed, and I pivot on flow_id to the flow, TLS and file events from the same session to see size, duration and how it ended. I check where the sensor sits: behind an explicit proxy, the source on the egress side is the proxy, so I find the real host on the client-to-proxy hop, in Zeek's http.log, and in the proxy logs. I join Suricata to Zeek with the community ID, using the same seed on both sensors and a tight time window, and if needed I pull the packets from the ring buffer. Before I write anything about absence, I check the sensor's stats for packet drops in that window. Finally I separate indicators, such as periodic connections to an intel-listed domain, from conclusions about compromise, which need endpoint evidence."

What makes this answer strong: it reads what the rule actually proves, uses flow_id and community ID correctly, accounts for the proxy vantage point, validates sensor health before claiming absence, and separates network indicators from host conclusions.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Suricata documentation (overview) | https://docs.suricata.io/ | primer | diakses 2026-10-09 | Tinggi. Konsep dan output |
| S2 | Suricata docs: Rules (anatomi, options) | https://docs.suricata.io/en/latest/rules/ | primer | diakses 2026-10-09 | Tinggi. Struktur rule |
| S3 | Suricata docs: Eve JSON output | https://docs.suricata.io/en/latest/output/eve/eve-json-output.html | primer | diakses 2026-10-09, dicek ulang 2026-10-23 | Tinggi. Beberapa instance `eve-log`, `community-id` dan seed (bawaan false dan 0), `flow` dua arah vs `netflow` satu arah, `types`, opsi alert `metadata`, `extended` TLS dan HTTP, opsi `stats` (`totals`, `threads`, `deltas`), rotasi, `drop` hanya di satu instance |
| S4 | Suricata: Download/rilis | https://suricata.io/download/ | primer | diakses 2026-10-07 (Day 01) | Tinggi. 8.0.7 stabil (15 Sep 2026), 7.x EOL |
| S5 | Network-Forensics Day 01-08 (lokal) | (lokal) | rujukan internal | 2026-10-09, diperbarui 2026-10-23 | Sensor, proxy, Zeek, dan asumsi volume PT JAB |
| S6 | Suricata docs: JA3/JA4 Keywords | https://docs.suricata.io/en/latest/rules/ja-keywords.html | primer | diakses 2026-10-10, dicek ulang 2026-10-23 | Tinggi. `ja3.hash`, `ja3.string`, `ja3s.*`, `ja4.hash`, nama lama, `requires: feature`, aktif otomatis kecuali di-set `no`; contoh `ja4.hash` memakai `alert quic` |
| S7 | Suricata docs: EVE JSON Format | https://docs.suricata.io/en/latest/output/eve/eve-json-format.html | primer | diakses 2026-10-23 | Tinggi. Field umum, `alert.action` allowed/blocked, contoh alert dengan `flow` terbalik, hash `fileinfo` dan `gaps`, field `flow`, `anomaly.type`, DNS versi 3 bawaan di 8.0 |
| S8 | Suricata docs: Upgrading (7.0 ke 8.0, 8.x ke 9.0) | https://docs.suricata.io/en/latest/upgrade.html | primer | diakses 2026-10-23 | Tinggi. Metadata app-layer di alert, `detect.guess-applayer-tx`, waktu inspeksi, output yang dihentikan, `ja3.hash` hanya heksadesimal; catatan 9.0 untuk rilis yang belum keluar |
| S9 | Suricata docs: Global-Thresholds (`threshold.config`) | https://docs.suricata.io/en/latest/configuration/global-thresholds.html | primer | diakses 2026-10-23 | Tinggi. Sintaks suppress, threshold, `rate_filter`, pilihan track, suppress tetap men-set flowbit, interaksi dengan threshold rule, `gen_id 0`/`sig_id 0` tidak didukung untuk threshold |
| S10 | Suricata 8.0.7 docs: Thresholding Keywords | https://docs.suricata.io/en/suricata-8.0.7/rules/thresholding.html | primer | diakses 2026-10-23 | Tinggi. Tipe `threshold`, `limit`, `both`, `backoff` (hanya `by_flow`), beda `detection_filter` |
| S11 | suricata-update docs (Update, Quick Start) dan Suricata docs: Rule Management with Suricata-Update | https://suricata-update.readthedocs.io/en/latest/update.html ; https://suricata-update.readthedocs.io/en/latest/quickstart.html ; https://docs.suricata.io/en/latest/rule-management/suricata-update.html | primer | diakses 2026-10-23 | Tinggi. Versi dokumentasi 1.3.8, ikut Suricata sejak 4.1, keluaran `/var/lib/suricata/rules/suricata.rules`, format dan urutan disable/enable/drop/modify, opsi `--local`, `--reload-command`, `--test-command`, `update.yaml`, `disable-source` vs `remove-source` |
| S12 | Suricata docs: Rules Format (intro) | https://docs.suricata.io/en/latest/rules/intro.html | primer | diakses 2026-10-23 | Tinggi. Action termasuk `rejectsrc`/`rejectdst`/`rejectboth`, arah `->`, `<>`, `=>`, tidak ada `<-`, urutan options bermakna, contoh rule HTTP GET |
| S13 | Suricata 8.0.7 docs: Meta Keywords; berkas `etc/classification.config` di repo OISF | https://docs.suricata.io/en/suricata-8.0.7/rules/meta.html ; https://raw.githubusercontent.com/OISF/suricata/master/etc/classification.config | primer | diakses 2026-10-23 | Tinggi. `msg`, `sid` unik per `gid` dan sidallocation.org, `rev`, `gid` dan format `[1:123:1]`, `classtype`, `priority` 1 sampai 255, `metadata` di alert, `target`; `trojan-activity` prioritas 1 |
| S14 | Suricata 8.0.7 docs: suricata.yaml | https://docs.suricata.io/en/suricata-8.0.7/configuration/suricata-yaml.html | primer | diakses 2026-10-23 | Tinggi. `encryption-handling` (`track-only` bawaan, `bypass`, `full`), `detect.guess-applayer-tx`, `threshold-file`, `default-rule-path`, `rule-files` |
| S15 | Suricata docs: Setting up IPS/inline for Linux | https://docs.suricata.io/en/latest/ips/setting-up-ipsinline-for-linux.html | primer | diakses 2026-10-23 | Tinggi. NFQ (`NFQUEUE`, `-q`, opsi `bypass`), AF_PACKET `copy-iface`, `copy-mode` ips/tap, MTU sama, `cluster-id` berbeda, `stream.inline` |
| S16 | Corelight: Community ID Flow Hashing specification | https://github.com/corelight/community-id-spec | primer (spesifikasi) | diakses 2026-10-23 | Tinggi. Masukan hash, urutan endpoint, SHA1 base64 dengan awalan `1:`, ICMP, cakupan, seed, tabrakan, daftar pendukung (Suricata 4.1+, Wireshark 3.3.1+) |
| S17 | SID Allocation (sidallocation.org) | https://sidallocation.org/ | sekunder (registri komunitas) | diakses 2026-10-23 | Sedang-tinggi. Rentang lokal, ET Open, ET Pro, engine event OISF, ruleset pihak lain |
| S18 | Emerging Threats Community: Frequently Asked Questions | https://community.emergingthreats.net/t/frequently-asked-questions/56 | primer (vendor) | 26 Sep 2022; diakses 2026-10-23 | Sedang-tinggi. ET Open BSD, sumber ET Pro, lisensi per sensor, enterprise vs OEM; tanggal 2022 |
| S19 | oss-security: "Suricata 8.0.7 released with 67 vulnerabilities fixed" (dan balasan) | https://www.openwall.com/lists/oss-security/2026/09/19/1 ; https://www.openwall.com/lists/oss-security/2026/09/19/3 | sekunder (milis yang mengutip pengumuman resmi) | 18-19 Sep 2026; diakses 2026-10-23 | Sedang-tinggi. 67 laporan kerentanan, CVE "Pending", Suricata 7 EOL setelah 7.0.17, LibHTP diarsipkan |
| S20 | Suricata docs: Statistics | https://docs.suricata.io/en/latest/performance/statistics.html | primer | diakses 2026-10-23 | Tinggi. `capture.kernel_packets`, `capture.kernel_drops` (arti di AF_PACKET), `tcp.reassembly_gap` dan penyebab lain, `ethtool -S`, interval `stats.log` 8 detik |
| S21 | Splunkbase: CCX Add-on for Suricata (app 6994) | https://splunkbase.splunk.com/app/6994 | primer (halaman add-on) | versi 1.0.1, 2025-08-08; diakses 2026-10-23 | Sedang. Dirawat developer; EVE JSON lewat syslog; data model CIM; Splunk 9.1 sampai 10.6; tidak mencantumkan sourcetype |
| S22 | Splunkbase: SuriZeek, Suricata and Zeek Correlation App (app 9818) | https://splunkbase.splunk.com/app/9818 | primer (halaman app) | versi 1.5.8, 2026-10-10; diakses 2026-10-23 | Sedang. Dirawat developer; korelasi alert Suricata ke log Zeek lewat IP, port, protokol; app dashboard; Zeek sourcetype `zeek_json` |
| S23 | Suricata docs: Command Line Options | https://docs.suricata.io/en/latest/command-line-options.html | primer | diakses 2026-10-23 | Tinggi. `-r` (termasuk direktori), `-l`, `-S`, `-s`, `-k`, `-T`, `-c`, `--set`, `-v`, `--runmode` |

**Catatan sumber:** anatomi rule, keyword, dan output mengikuti dokumentasi Suricata [S1][S2][S3][S6][S7][S12][S13]; sebagian halaman dibaca dari cabang `latest`, yang sudah memuat catatan Suricata 9.0, sehingga detail yang bergantung versi perlu dicocokkan dengan dokumentasi `suricata-8.0.7`. Dua halaman resmi berbeda soal versi DNS bawaan (halaman format menyebut versi 3 bawaan di 8.0, halaman output `latest` menyebut versi 2); Day ini memakai versi 3 untuk 8.0 dan menyarankan cek event contoh. Lokasi berkas `suricata.rules`, `disable.conf`, dan `threshold.config` adalah lokasi instalasi umum dan bisa berbeda per distribusi; cek di `suricata.yaml` lab-mu. Rentang `sid` adalah konvensi registri sidallocation.org, bukan aturan Suricata. Angka 67 kerentanan diambil dari milis yang mengutip pengumuman proyek, bukan dari halaman suricata.io langsung [S19]. Nama dan `sid` rule ET (SNMP `2101411`, Nmap `2009358`, path traversal, engine event `SURICATA STREAM`) dipakai sebagai ilustrasi dan harus dicocokkan dengan ruleset yang terpasang. Hal yang perlu dicek di lab: pencatatan `CONNECT` sebagai event `http`, perilaku rule `drop` dan `reject` di mode IDS, cara Suricata menghitung byte flow, apakah `kernel_packets` AF_PACKET termasuk paket yang di-drop, nama field `deltas` di event `stats`, apakah reload rule memuat ulang `threshold.config`, dan nama opsi `threads`/`ring-size` di bagian `af-packet`. Sourcetype `suricata` adalah ketetapan PT JAB, bukan nama dari add-on; validasi dengan `| metadata type=sourcetypes index=suricata`. Rule dibaca untuk memahami deteksi, bukan untuk menulis serangan. Seluruh isi PT JAB (alert `SOC-2027-0640` sampai `-0644`, `INC-2027-068`, host, alamat, `community_id`, angka volume dan drop) adalah penerapan catatan ini pada organisasi fiktif, bukan hasil eksekusi nyata.
