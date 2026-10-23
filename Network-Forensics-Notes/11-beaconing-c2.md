---
day: 11
title: 'Beaconing dan C2: mengukur periodisitas, jitter, ukuran, dan long connection dari metadata, skor RITA, dan memisahkan indikator dari kesimpulan'
researched_on: 2026-10-22
versions_checked: 'RITA v5.1.2 (7 Mei 2026; README, default_config.hjson, docs/Configuration.md, kode analysis/beacons.go, config/config.go, database/tables.go cabang main dibaca 2026-10-22); Zeek 9.0.0 LTS (conn.log, http.log, ssl.log); Wireshark 4.6.9; MITRE ATT&CK v20.0: TA0011, T1071.001 v1.5, T1573 v1.2, T1571 v1.3; TA for Zeek 1.0.11 (sourcetype bro:http:json di Splunk Research); Microsoft Learn: Windows Time service tools and settings (diperbarui 2026-02-16), DeviceNetworkEvents (diperbarui 2026-06-26)'
---

# Day 11: Beaconing dan C2 dari metadata trafik

Cakupan: mengenali beaconing dan saluran command-and-control dari metadata trafik (interval, jitter, ukuran, durasi, tujuan), memakai statistik sederhana dan skor beacon RITA 5 untuk memeringkat kandidat, mengatribusi beacon di balik proxy eksplisit, dan memisahkan indikator beaconing dari kesimpulan C2 dengan penjelasan jinak yang selalu disebut.

## Ide inti

Implant yang sudah tertanam di sebuah host perlu saluran kendali: ia menghubungi server command-and-control (C2) untuk menanyakan perintah dan mengirim hasil. Karena implant tidak tahu kapan operatornya punya perintah, ia bertanya berulang kali dengan jadwal, dan jadwal itu meninggalkan pola di jaringan: koneksi ke tujuan yang sama, dengan jarak waktu yang teratur, ukuran yang mirip, dan durasi yang pendek. Pola ini disebut beaconing. Karena isi saluran hampir selalu terenkripsi, deteksi bersandar pada pola itu, bukan pada isi. Masalahnya, perangkat lunak sah juga berperilaku sama persis: antivirus, Windows Update, agent sinkronisasi, skrip telemetri, dan sinkronisasi waktu semuanya menelepon pulang dengan jadwal. Jadi pekerjaan inti Day ini ada dua: mengukur keteraturan dengan benar walaupun penyerang menambah jitter, lalu membuang penjelasan jinak satu per satu sampai yang tersisa layak disebut kandidat C2. Beaconing adalah indikator; C2 adalah kesimpulan yang butuh tujuan, prevalence, konteks proses di host, dan pemilik yang tidak bisa menjelaskannya.

Kamu sudah mengenal pola ini dari NOC. Polling SNMP dari NMS ke ribuan perangkat berjalan dengan interval tetap, ukuran paket yang hampir sama, dan tujuan yang sama setiap kali; kalau kamu melihat polling SNMP dari sumber yang tidak terdaftar di NMS, kamu curiga bukan karena polanya, tetapi karena sumbernya tidak dikenal. Di sini sama: keteraturan hanya mengangkat sebuah pasangan host ke daftar periksa, dan pertanyaan berikutnya selalu "siapa yang memasang poller ini?". Batas analoginya ada dua. Pertama, poller jahat sengaja menambahkan jitter supaya intervalnya tidak serapi NMS, jadi ukuran keteraturan harus toleran terhadap variasi. Kedua, di NOC kamu punya daftar poller resmi; di jaringan kantor, daftar agent sah harus dibangun sendiri dari data (baseline dan prevalence), karena tidak ada satu tim yang memegangnya.

```
  JKT-WS-2052 10.10.60.112                       jkt-proxy01 10.20.3.60:3128              internet
  (implant, tiap ~600 s +-25%)                   (proxy eksplisit, splice)
        |                                                 |
        |-- SYN 203.0.113.181:8443 --X jkt-fw01 deny      |                     (T1571, conn_state S0)
        |      (21 detik kemudian)                        |
        |-- CONNECT assets.northwind-cdn.example:443 ---->|-- TLS ke 203.0.113.180 atau .181:443 -->
        |   hop core (SPAN core DC):                      |   hop egress (TAP sisi dalam jkt-fw01):
        |   http.log method=CONNECT, sumber = WS          |   conn/ssl.log, sumber = 10.20.3.60, SNI
        v                                                 v
  jkt-zeek01 10.20.70.12 --> Splunk index=zeek (bro:conn:json, bro:http:json, bro:ssl:json)
        |
        +--> log harian disalin ke jkt-nsm-ws01 --> rita import / rita view --> kandidat
             kandidat --> prevalence + pemilik + proses (MDE) --> jinak | kandidat C2 | INC-2027-070
```

Situasi yang dipakai sepanjang Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan sekitar 1.200 karyawan, kantor pusat dan data center di Jakarta, dan NOC 24/7 yang satu lantai dengan SOC. Sejak Mei 2027 PT JAB menjalankan "Program NSM PT JAB": sensor Zeek `jkt-zeek01` (`10.20.70.12`) menerima trafik dari TAP egress Jakarta di sisi dalam firewall `jkt-fw01` dan dari SPAN core switch data center lewat packet broker `jkt-npb01`, dan log-nya masuk Splunk index `zeek` sejak Selasa 2027-05-18 pukul 08:00. Workstation kantor keluar ke web hanya lewat proxy eksplisit `jkt-proxy01` (`10.20.3.60:3128`, Squid dengan SslBump: domain baru atau tidak terkategori di-bump, kategori yang dikenal di-splice). Hunt beaconing pertama dijanjikan ke Direktur Teknologi Hendra Wijaya setelah satu minggu data terkumpul. Senin 2027-05-24 pukul 08:15, analyst L2 Sari Kusuma menyalin log Zeek enam hari (Selasa 08:00 sampai Senin 08:00) ke workstation analisis `jkt-nsm-ws01` dan menjalankan RITA. Hasilnya 1.962 pasangan dengan skor beacon minimal 70, dan baris paling atas adalah `JAB DocSync`, aplikasi sinkronisasi dokumen milik PT JAB sendiri, dengan skor 99. Pukul 09:00, SOC lead Dimas Prasetyo menulis kepadamu:

> "Hunt beacon pertama dari data Zeek sudah jalan, hasilnya hampir dua ribu baris dan paling atas malah DocSync kita sendiri. Rapat dengan Pak Hendra dan Pak Bambang jam 15:00, tolong siapkan jawaban. Beacon itu persisnya apa, dan kenapa dianggap tanda C2? Penyerang katanya menambah jitter; bagaimana mengukur keteraturan yang benar? Skor RITA itu dihitung dari apa, dan skor 99 artinya pasti C2? Hampir semua tujuan web kelihatan dari IP proxy; workstation mana sebenarnya? Bagaimana memisahkan Defender, Windows Update, DocSync, dan skrip NOC dari yang jahat? Sari juga lihat satu koneksi 26 jam dan ratusan SYN ke port 8443 yang ditolak firewall, itu apa? Terakhir, kapan kita boleh menyebut sesuatu C2 dan membuka insiden, dan label ATT&CK apa yang ditulis di laporan?"

Pesan itu memuat tujuh pertanyaan:

1. Apa itu beaconing, dan kenapa dianggap tanda C2?
2. Bagaimana mengukur keteraturan bila penyerang menambah jitter?
3. Dari apa skor RITA dihitung, dan apakah skor tinggi berarti C2?
4. Kalau semua tujuan web terlihat dari IP proxy, workstation mana sumbernya?
5. Bagaimana memisahkan agent sah (Defender, Windows Update, `JAB DocSync`, skrip NOC) dari yang jahat?
6. Apa arti koneksi 26 jam dan SYN berulang ke port 8443?
7. Kapan sebuah kandidat boleh disebut C2, dan label ATT&CK apa yang dipakai?

Pertanyaan 1 dijawab di bagian 1.1, pertanyaan 2 di bagian 1.2 dan 1.3, pertanyaan 3 di bagian 1.4, pertanyaan 4 di bagian 1.5, pertanyaan 5 di bagian 1.6 dan 1.7, pertanyaan 6 di bagian 1.8, dan pertanyaan 7 di bagian 1.9 dan 1.10. Bagian 2 berisi artefak hunt hari Senin: persiapan data dan cek insiden yang sudah diketahui, pengukuran interval dan ukuran, RITA dan stacking hasilnya, query Splunk, atribusi lewat proxy, long connection dan port tidak lazim, triage kandidat, pembukaan `INC-2027-070`, dan jawaban untuk Dimas.

**Kapan relevan:** saat hunting C2 di log Zeek, flow, atau proxy; saat menilai apakah host yang sudah diduga terkompromi masih menelepon pulang; saat memvalidasi bahwa containment sebuah insiden berhasil (beacon berhenti); dan saat merancang rule deteksi terjadwal untuk pola periodik di SIEM.
**Kapan bukan jawaban:** saat C2 tidak periodik (sesi interaktif, satu tunnel panjang, atau jeda acak yang lebar); saat beacon jarang sekali (beberapa kali sehari) dan jendela data pendek; saat trafik tidak lewat sensor (lateral di switch akses yang sama, laptop di luar kantor, split tunnel VPN); dan saat yang dibutuhkan adalah kesimpulan tentang proses atau isi, karena metadata jaringan hanya memberi indikator.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (pcap, SPAN, TAP, packet broker, `uid`, `conn_state`, `history`, SNI, JA3/JA4, splice, bump, DGA, flow, sampling) tidak diulang; definisinya ada di Day 01 sampai 10 [S5]. Tabel ini memuat istilah yang dipakai Day ini; kolom kanan memakai padanan dari pekerjaan NOC dan ISP.

| Istilah | Arti singkat | Padanan di NOC/ISP |
|---|---|---|
| Command and control (C2) | Saluran yang dipakai penyerang untuk mengendalikan host yang sudah dikuasai: mengirim perintah, menerima hasil | Jalur manajemen out-of-band, tetapi dipasang orang yang tidak berhak |
| Implant | Program penyerang di host yang menjalankan perintah dari C2 | Agent manajemen yang tidak terdaftar di inventaris |
| Beaconing | Koneksi berulang dari host ke tujuan yang sama dengan jarak waktu teratur | Polling SNMP terjadwal dari NMS |
| Check-in | Satu kali implant menghubungi C2 untuk menanyakan perintah | Satu siklus poll |
| Sleep | Interval dasar antar-check-in yang diatur operator | Polling interval di NMS |
| Jitter | Variasi acak yang ditambahkan ke sleep, biasanya dalam persen | Polling yang sengaja diacak supaya tidak serentak |
| Interval (delta) | Selisih waktu antara dua koneksi berurutan dari pasangan yang sama | Selisih timestamp dua baris log poll |
| Coefficient of variation (CV) | Deviasi standar interval dibagi rata-ratanya; makin kecil, makin teratur | Jitter relatif pada pengukuran latency |
| Median absolute deviation (MAD) | Median dari selisih mutlak setiap nilai terhadap median; tahan terhadap outlier | Ukuran sebaran yang tidak terganggu satu spike |
| Bowley skewness | Ukuran kemencengan dari kuartil: (Q1 + Q3 - 2 x median) / (Q3 - Q1) | Melihat apakah distribusi latency condong ke satu sisi |
| Skor beacon | Angka 0 sampai 1 (ditampilkan 0 sampai 100) dari RITA tentang seberapa mirip sebuah pasangan dengan beacon | Health score gabungan beberapa KPI |
| Prevalence | Proporsi host internal yang berkomunikasi dengan sebuah tujuan | Berapa banyak pelanggan yang memakai satu layanan |
| First seen | Kapan sebuah tujuan pertama kali terlihat di data | Tanggal sebuah prefiks pertama muncul di tabel routing |
| Long connection | Satu koneksi yang berlangsung sangat lama (jam sampai hari) | Sesi BGP atau tunnel yang tidak pernah turun |
| Non-standard port | Protokol dipakai di port yang tidak lazim untuknya | Layanan di port tidak standar yang lolos ACL berbasis port |
| Indikator | Pengamatan yang menaikkan kecurigaan, bukan bukti | Alarm threshold |
| Kesimpulan | Pernyataan tentang apa yang terjadi, didukung beberapa sumber | Root cause yang sudah dikonfirmasi |

### 1.1 Apa itu beaconing, dan kenapa ia tanda C2

Pertanyaan pertama Dimas tampak sederhana, tetapi jawabannya menentukan cara membaca 1.962 baris RITA: beacon adalah bentuk perilaku, bukan jenis malware.

Beaconing adalah koneksi berulang dari host ke tujuan dengan keteraturan tertentu. Implant C2 melakukan check-in pada interval yang diatur operator (misalnya setiap 60 detik atau setiap 10 menit) untuk menanyakan perintah. Bila tidak ada perintah, server membalas kosong dan implant tidur lagi. Sinyal utamanya ada empat:

- **Periodisitas:** interval antar-koneksi konsisten.
- **Tujuan tetap:** ke IP atau domain yang sama berulang kali.
- **Ukuran mirip:** check-in kosong berukuran serupa, karena isi yang dikirim kecil dan tetap.
- **Durasi pendek:** setiap koneksi singkat, kecuali saat ada perintah atau transfer.

Kenapa C2 hampir selalu beacon? Karena arah koneksi. Firewall kantor mengizinkan koneksi keluar dan menolak koneksi masuk, sehingga server C2 tidak bisa menghubungi implant; implant yang harus keluar. Dan karena implant tidak tahu kapan ada perintah, ia harus bertanya berulang. Hasilnya adalah pola periodik yang bisa dilihat tanpa membaca isi.

Saluran yang ditumpangi beacon bisa bermacam-macam, dan setiap saluran meninggalkan jejak berbeda. Tabel ini membantu memilih log mana yang dibuka untuk saluran tertentu; cari kolom "Yang terlihat".

| Saluran | Yang terlihat | Catatan deteksi |
|---|---|---|
| HTTP/S | POST/GET berkala ke endpoint sama; SNI dan JA3/JA4 tetap | Isi terenkripsi; pakai metadata dan pola |
| DNS | Query berkala, kadang tunneling dengan subdomain tersandi (Day 05) | Volume dan keteraturan per domain induk |
| TLS langsung | Koneksi berkala; fingerprint klien khas | Metadata TLS (Day 06) |
| Protokol lain | Koneksi berkala ke port tak lazim | Konteks port dan protokol |

Fokus deteksi adalah pola (kapan, seberapa sering, ke mana, berapa besar), bukan membangun atau menganalisis payload C2.

Di PT JAB, 1.962 baris itu adalah 1.962 pasangan sumber dan tujuan yang perilakunya mirip beacon. Hampir semuanya adalah perangkat lunak sah yang memang menelepon pulang. Beacon menjawab "pasangan mana yang teratur", bukan "pasangan mana yang jahat".

### 1.2 Jitter, sleep panjang, dan evasion

Pertanyaan kedua Dimas muncul karena Sari membaca bahwa penyerang menambah jitter. Itu benar, dan itulah alasan pengukuran harus statistik.

Penyerang tahu periodisitas sempurna mudah dideteksi, jadi ia menambah jitter: variasi acak pada interval, biasanya ditulis sebagai persen dari sleep (misalnya 60 detik plus minus 20%, sehingga interval jatuh antara 48 dan 72 detik). Deteksi modern memperhitungkan jitter: yang dicari adalah keteraturan statistik meski ada variasi, bukan interval persis.

Teknik evasion lain yang perlu dikenal:

- **Sleep panjang.** Beacon beberapa kali sehari menghasilkan terlalu sedikit sampel; alat seperti RITA bahkan tidak menganalisis pasangan dengan koneksi di bawah ambang tertentu (bagian 1.4).
- **Meniru trafik sah.** Domain fronting, CDN, dan layanan cloud populer membuat tujuan tampak wajar dan berprevalence tinggi.
- **Mengubah ukuran.** Padding acak membuat ukuran tidak lagi seragam.
- **Rotasi tujuan.** Beberapa IP atau domain dipakai bergantian, sehingga keteraturan per IP hilang walaupun keteraturan per host tetap ada (bagian 2.4).
- **Satu sesi panjang.** Alih-alih banyak koneksi pendek, implant mempertahankan satu koneksi yang hidup berjam-jam; tidak ada interval yang bisa diukur, tetapi ada long connection (bagian 1.8).

Akibatnya, deteksi beaconing bersifat probabilistik, bukan pasti. Jitter yang cukup besar, sampel yang cukup sedikit, atau tujuan yang cukup umum bisa membuat beacon lolos dari ambang apa pun. Sebuah studi workshop September 2026 bahkan mengukur trafik agent berbasis Model Context Protocol dengan jeda antar-request berdistribusi lognormal, dan dalam lab penulisnya skor beacon RITA untuk trafik itu tetap 0,0 walaupun jitter ditambahkan [S14]. Pola yang tidak teratur tidak berarti tidak ada C2.

### 1.3 Mengukur periodisitas: interval, median, CV, dan MAD

Untuk menjawab pertanyaan kedua dengan angka, kamu butuh cara mengukur keteraturan yang tidak rusak oleh jitter atau satu jeda malam.

Langkahnya selalu sama:

1. Kumpulkan timestamp koneksi untuk satu pasangan sumber dan tujuan.
2. Urutkan, lalu hitung interval (delta) antar-koneksi berurutan.
3. Nilai sebaran interval: delta yang terkelompok rapat berarti periodik, yang menyebar berarti tidak.
4. Dengan jitter, delta berpusat di satu nilai dengan sebaran terbatas.

Ada tiga ukuran sebaran yang dipakai di Day ini, masing-masing dengan kelebihannya:

| Ukuran | Rumus | Kuat untuk | Lemah untuk |
|---|---|---|---|
| CV | deviasi standar / rata-rata | Mudah dihitung di SPL, `awk`, atau spreadsheet | Satu jeda panjang (PC tidur, jaringan putus) langsung menaikkan deviasi standar |
| MAD relatif | MAD / median | Tahan outlier; satu jeda malam hampir tidak berpengaruh | Tidak tersedia langsung di semua alat |
| Bowley skewness | (Q1 + Q3 - 2 x median) / (Q3 - Q1) | Menangkap distribusi yang condong, misalnya interval yang kadang dobel karena check-in terlewat | Tidak bermakna bila Q3 - Q1 sangat kecil |

Seberapa besar jitter memengaruhi angka-angka itu bisa dihitung. Bila jitter tersebar merata sampai plus minus j dari interval dasar, deviasi standarnya sekitar j dibagi akar 3 (sekitar 1,732), dan MAD-nya sekitar j dibagi 2. Jadi:

- Jitter plus minus 20%: CV sekitar 0,115, MAD relatif sekitar 0,10.
- Jitter plus minus 25%: CV sekitar 0,144, MAD relatif sekitar 0,125.
- Jitter plus minus 35%: CV sekitar 0,202, MAD relatif sekitar 0,175.

Beacon `JKT-WS-2052` di bagian 2.3 memakai interval dasar sekitar 600 detik dengan jitter sekitar plus minus 25%. Hasil terukurnya CV 0,149 dan MAD relatif 0,134, sedikit di atas teori karena dihitung dari sampel, bukan distribusi ideal.

Satu jeda panjang merusak CV. Laptop yang tidur semalam menghasilkan satu interval 15 jam di antara ratusan interval 10 menit, dan deviasi standarnya melonjak. Karena itu query di bagian 2.7 membuang interval yang lebih panjang dari tiga kali median sebelum menghitung CV, lalu mencatat berapa jeda yang dibuang. Ambang yang dipakai program PT JAB adalah CV maksimal 0,2 setelah jeda dibuang, minimal 24 koneksi, dan median interval antara 30 detik dan 4 jam. Ambang 0,2 memberi margin di atas jitter plus minus 25% yang umum, dan baru dilewati sekitar jitter plus minus 35%. Ambang ini titik awal; ukur ulang di lingkunganmu.

Pertukarannya jelas. Ambang yang lebih longgar menangkap beacon berjitter besar tetapi menambah false positive dari polling sah; ambang yang ketat sebaliknya. Pembedanya bukan ambang, tetapi konteks (bagian 1.6 dan 1.7).

### 1.4 Skor beacon RITA 5

Pertanyaan ketiga Dimas paling sering salah dipahami: skor 99 untuk `JAB DocSync` adalah skor keteraturan, bukan skor kejahatan.

RITA (Real Intelligence Threat Analytics) dari Active Countermeasures adalah alat open source yang membaca log Zeek (TSV atau JSON) dan mencari beaconing, long connection, DNS tunneling, serta kecocokan dengan feed threat intel [S4]. Rilis terbarunya v5.1.2 (7 Mei 2026) [S6]. RITA menghitung skor beacon per pasangan sumber dan tujuan. Di RITA 5.x, skor itu adalah rata-rata berbobot dari empat subskor dengan bobot bawaan masing-masing 0,25 [S4]:

- **timestamp:** seberapa teratur delta antar-koneksi.
- **data size:** seberapa seragam ukuran data tiap koneksi.
- **duration:** seberapa konsisten pasangan itu muncul sepanjang rentang data.
- **histogram:** bentuk sebaran jumlah koneksi per bin waktu, untuk menangkap pola yang rata atau bertingkat.

Kode analisis RITA menjelaskan cara tiap subskor dihitung [S7]. Ringkasannya penting karena menjelaskan kenapa agent sah bisa mendapat skor hampir sempurna:

| Subskor | Cara hitung | Akibat praktis |
|---|---|---|
| timestamp | Rata-rata dua angka: 1 dikurangi nilai mutlak Bowley skewness interval, dan (median - MAD) / median | Jitter merata menurunkan skor sedikit (MAD naik), tetapi distribusi simetris tetap dihargai |
| data size | Rumus yang sama atas ukuran data per koneksi | Yang dinilai keseragaman, bukan kecilnya ukuran |
| duration | Nilai terbesar dari coverage (rentang pertama sampai terakhir pasangan dibanding rentang dataset) dan consistency (deret bin terisi terpanjang dibanding 12 bin ideal) | Pasangan yang hanya aktif beberapa bin tidak mendapat subskor duration sama sekali |
| histogram | Nilai terbesar dari 1 dikurangi CV jumlah koneksi per bin (24 bin sepanjang rentang data), dan kecocokan bimodal (dua kelompok frekuensi terbesar dibanding jumlah bin terisi) | Pola "sibuk jam kerja, sepi malam" tetap bisa mendapat skor tinggi lewat kecocokan bimodal |

Skor akhir adalah jumlah keempat subskor dikali bobotnya, dibulatkan ke tiga desimal; tampilan RITA menulisnya sebagai angka 0 sampai 100 [S7].

Beberapa ambang bawaan yang mengubah hasil hunt [S4][S8]:

- Pasangan dengan kurang dari empat koneksi unik tidak dianalisis sama sekali (`unique_connection_threshold` bawaan 4; konfigurasinya menyebut nilai ini bisa dinaikkan bila tidak peduli beacon lambat).
- Subskor duration baru dihitung bila jumlah bin terisi lebih dari `duration_min_hours_seen` (bawaan 6), dan consistency penuh dicapai pada `duration_consistency_ideal_hours_seen` (bawaan 12, setengah hari).
- Ambang kategori beacon di `default_config.hjson`: skor di bawah 50 berada di bawah ambang dasar, 50 sampai 69 rendah, 70 sampai 89 sedang, dan 90 ke atas tinggi [S4][S8]. Nilai bawaan di kode `config.go` untuk ambang rendah tertulis 75, bukan 70 [S8]; yang berlaku adalah file konfigurasi yang terpasang, jadi cek `/etc/rita/config.hjson` di lab-mu.

Setelah skor beacon, RITA menyesuaikan tingkat keparahan dengan modifier dari perilaku lain [S8]. Nilai bawaannya:

| Modifier | Kondisi | Perubahan |
|---|---|---|
| Prevalence naik | Tujuan dihubungi maksimal 2% host internal | +0,15 |
| Prevalence turun | Tujuan dihubungi minimal 50% host internal | -0,15 |
| First seen naik | Tujuan pertama kali terlihat maksimal 7 hari lalu | +0,15 |
| First seen turun | Tujuan pertama kali terlihat minimal 30 hari lalu | -0,15 |
| Rare signature | Fingerprint klien jarang | +0,15 |
| Missing host header | Request HTTP tanpa header Host | +0,1 |
| Threat intel | Cocok dengan feed dan data minimal sekitar 25 MB | +0,15 |
| MIME type mismatch | Tipe isi tidak cocok dengan yang diklaim | +0,15 |

Komentar di kode konfigurasi RITA menyebut kategori "critical" hanya bisa dicapai bila modifier mendorong skor melewati kategori tinggi, dan dokumentasi konfigurasinya menyebut kategori impact tidak bisa diatur ke critical secara langsung [S8].

Dua akibat untuk PT JAB. Pertama, `JAB DocSync` mendapat skor beacon 99 karena memang poller yang sangat rapi (interval 900 detik, ukuran tetap). Sensor melihat 1.412 host internal; DocSync dipakai 149 host (sekitar 10,6%), belum mencapai 50%, sehingga tidak mendapat pengurangan prevalence, sedangkan Defender (812 host, sekitar 57,5%) dan Windows Update (790 host, sekitar 55,9%) mendapatkannya. Skor tinggi bukan vonis. Kedua, sensor `jkt-zeek01` baru berumur enam hari, sehingga hampir setiap tujuan tampak "first seen kurang dari 7 hari". Modifier first seen menaikkan semua pasangan secara merata dan tidak membedakan apa pun sampai data mencapai 30 hari. Cara RITA menghitung first seen (dari data di dataset itu saja atau dari riwayat lain) perlu dicek di versi-mu.

### 1.5 Proxy eksplisit: siapa sumber beacon

Pertanyaan keempat Dimas lahir dari daftar RITA: dua baris teratas untuk alamat `203.0.113.180` dan `203.0.113.181` bersumber dari `10.20.3.60`, yaitu proxy, bukan workstation.

Dengan proxy eksplisit, workstation tidak membuka TCP ke server tujuan. Ia mengirim `CONNECT host:443` ke proxy, dan proxy yang membuka TCP ke internet. Satu check-in beacon menjadi dua koneksi dengan `uid` berbeda di `jkt-zeek01`:

- **Hop core** (dilihat SPAN core switch data center): workstation ke `10.20.3.60:3128`. Di `conn.log` tujuannya selalu proxy, jadi tidak membedakan tujuan akhir. Di `http.log`, baris dengan `method` `CONNECT` mencatat `host` tujuan akhir yang diminta workstation.
- **Hop egress** (dilihat TAP sisi dalam `jkt-fw01`): `10.20.3.60` ke IP tujuan di port 443. `conn.log` mencatat IP dan byte, dan untuk koneksi yang di-splice, `ssl.log` mencatat SNI dan fingerprint milik klien asli (Day 06).

Akibatnya, analisis beacon per IP di egress menggabungkan semua workstation yang memakai proxy ke satu sumber. Analisis yang bermakna untuk workstation harus memakai pasangan workstation dan nama tujuan dari `CONNECT` di hop core. RITA 5 mengenali pola ini: kode basis datanya memperlakukan request `CONNECT` di `http.log` sebagai koneksi proxy, mencatat alamat proxy-nya, dan menambahkannya ke analisis karena record `conn.log` pasangannya tersaring [S9]. Hasilnya, RITA bisa menampilkan pasangan workstation ke nama domain (FQDN), selain pasangan proxy ke IP. Perilaku persisnya di tampilan `view` perlu dicek dengan beacon uji di lab (bagian 3).

Query DNS untuk domain itu juga tidak berasal dari workstation. Yang me-resolve nama tujuan adalah proxy, sehingga `dns.log` memuat query dari `10.20.3.60`, dan cache proxy membuat tidak setiap check-in menghasilkan query baru (Day 08).

Ada satu jalur yang tidak melewati proxy dan justru membuka identitas workstation di egress: percobaan koneksi langsung. Karena TAP terpasang di sisi dalam firewall, SYN dari workstation ke internet tetap terlihat walaupun firewall menolaknya (bagian 1.8).

### 1.6 Trafik periodik sah dan penjelasan jinak

Pertanyaan kelima Dimas adalah tantangan utama hunt beaconing: banyak trafik sah yang periodik.

Tabel berikut adalah daftar penjelasan jinak yang harus dibuang dulu sebelum sebuah kandidat naik; cari kolom "Cara membedakan".

| Sumber sah | Pola mirip beacon | Cara membedakan |
|---|---|---|
| Update checker (Windows Update, aplikasi) | Cek berkala ke vendor | Tujuan vendor yang dikenal, prevalence tinggi, proses bertanda tangan vendor |
| Agent keamanan (EDR, antivirus) | Telemetri dan cek kebijakan berkala | Ratusan host, tujuan sama, terdaftar di inventaris |
| NTP dan sinkronisasi waktu | Poll berkala UDP 123 | Port dan protokol, tujuan server waktu, interval yang membesar bertahap |
| Telemetry/analytics | Kirim data berkala | Pemilik aplikasi bisa menjelaskan, ada di dokumentasi vendor |
| Keep-alive/heartbeat | Koneksi hidup berkala | Bagian dari aplikasi yang sedang dipakai |
| Sync (email, cloud, dokumen) | Poll berkala | Aplikasi resmi, prevalence sesuai jumlah pengguna |

Sinkronisasi waktu Windows adalah contoh yang baik tentang kenapa interval sah tidak selalu tetap. Komputer anggota domain menyinkronkan waktu lewat hierarki domain, sedangkan domain controller yang memegang peran PDC emulator di root forest yang menyinkronkan ke sumber waktu luar [S12]. Interval poll diatur dalam satuan log basis 2 detik: bawaan `MinPollInterval` 6 (64 detik) dan `MaxPollInterval` 10 (1.024 detik) untuk domain controller, serta 10 dan 15 untuk anggota domain dan komputer standalone [S12]. Komputer standalone memakai `time.windows.com` dengan flag SpecialInterval dan `SpecialPollInterval` bawaan 604.800 detik (satu minggu) [S12]. Akibatnya untuk hunt: NTP dari domain controller ke luar terlihat periodik tetapi intervalnya bisa berubah antara 64 dan 1.024 detik, dan NTP dari workstation anggota domain mestinya tidak keluar ke internet sama sekali. Workstation yang poll ke server NTP internet adalah temuan konfigurasi, bukan C2.

Pembeda utama untuk semua baris di tabel itu adalah:

- **Tujuan dan reputasi:** vendor dikenal atau domain baru tanpa riwayat.
- **Prevalence:** dipakai ratusan host atau hanya satu (bagian 1.7).
- **Fingerprint klien:** JA3/JA4 library umum atau milik browser, atau fingerprint yang hanya ada di satu host (Day 06).
- **Proses di host:** proses bertanda tangan vendor di lokasi instalasi standar, atau binary tanpa tanda tangan di folder pengguna.
- **Pemilik:** ada orang yang bisa menjelaskan kenapa host itu menelepon ke sana.

Beacon ke domain baru dengan fingerprint langka dan tanpa konteks proses sah jauh lebih mencurigakan daripada poll ke vendor dikenal. Kemungkinan jinak selalu dinyatakan, termasuk untuk kandidat yang akhirnya dinaikkan.

### 1.7 Baseline dan prevalence

Pertanyaan kelima juga punya sisi kedua: bagaimana memisahkan secara massal, karena 1.962 baris tidak mungkin dibuka satu per satu.

Tanpa baseline, sulit tahu apa yang anomali: banyak host memang berbicara periodik ke layanan sah. Baseline (apa yang normal untuk host dan jaringan ini) membuat beacon mencurigakan menonjol. Di threat hunting, membandingkan dengan baseline lalu memeriksa outlier adalah cara kerja utama: pasangan sumber dan tujuan yang jarang muncul di seluruh jaringan lebih layak diperiksa daripada yang dipakai ratusan host. Flow jangka panjang (Day 10) dan log Zeek membantu membangun baseline.

Prevalence adalah alat paling murah untuk ini. Hitung, untuk setiap tujuan, berapa host internal yang menghubunginya. Di hunt hari Senin:

- `wdcp.mde-cloud.example.net` (Defender) muncul di 812 pasangan, `delivery.wu-cdn.example.net` (Windows Update) di 790, dan `docsync-update.jab.example` (`JAB DocSync`) di 149. Ketiganya layanan yang memang dipasang di banyak host.
- Tujuan dengan satu atau dua sumber saja tinggal enam (bagian 2.6).

Prevalence punya dua jebakan. Pertama, penyerang yang menumpang layanan populer (CDN, penyimpanan cloud) mewarisi prevalence tinggi layanan itu, sehingga filter "maksimal 2 sumber" sengaja membuangnya; filter ini dipakai untuk memeringkat, dan tujuan berprevalence tinggi ditinjau terpisah dengan cara lain (misalnya fingerprint langka di tujuan umum). Kedua, prevalence dihitung dari host yang terlihat sensor. Host di kantor Bandung dan Medan, laptop di luar kantor, dan segmen yang tidak lewat SPAN tidak ikut dihitung (Day 01).

Baseline juga berlaku untuk insiden yang sudah ditutup. Hunt pertama adalah kesempatan memastikan bahwa beacon dari insiden sebelumnya benar-benar berhenti: `INC-2027-061` (`JKT-WS-2007` ke `static-update.example.net` di `203.0.113.163`, Day 02) dan `INC-2027-065` (`jkt-cirunner02` ke `sync.cdn-edge.example` di `203.0.113.170`, Day 06). Ketiadaan beacon itu di data `jkt-zeek01` adalah bukti containment untuk jendela sensor saja, bukan untuk masa sebelum 18 Mei (bagian 2.1).

### 1.8 Long connection dan port tidak lazim

Pertanyaan keenam Dimas menyangkut dua indikator yang melengkapi beaconing: koneksi yang tidak pernah putus, dan koneksi yang memakai port yang salah.

**Long connection.** C2 tidak harus banyak koneksi pendek. Implant bisa mempertahankan satu koneksi yang hidup berjam-jam dan menerima perintah lewat koneksi itu. Tidak ada interval yang bisa diukur, jadi analisis beacon tidak menangkapnya; yang menangkapnya adalah durasi. RITA menilai long connection dengan ambang durasi bawaan 1 jam (dasar), 4 jam (rendah), 8 jam (sedang), dan 12 jam (tinggi) [S4][S8]. Penjelasan jinak untuk long connection juga banyak: VPN, sesi remote support, websocket notifikasi aplikasi, streaming, dan replikasi data. Satu catatan teknis: `conn.log` baru ditulis saat koneksi selesai (Day 08), sehingga koneksi yang masih hidup belum muncul di log biasa; di balik proxy eksplisit, satu tunnel `CONNECT` yang panjang hanya terlihat sebagai satu baris di setiap hop.

**Non-standard port.** ATT&CK mencatat penyerang yang memakai pasangan protokol dan port yang tidak lazim, dengan contoh HTTPS di port 8088 alih-alih 443, sebagai T1571 Non-Standard Port [S11]. Tujuannya menghindari filter berbasis port atau membuat analisis lebih sulit. Analitik deteksinya di ATT&CK v20 menyebut proses yang membuat koneksi keluar di port tidak lazim atau dengan protokol yang tidak cocok dengan port-nya [S11]. Di PT JAB, workstation tidak diizinkan keluar langsung ke internet, jadi koneksi langsung ke port 8443 ditolak `jkt-fw01`. Penolakan itu tetap informatif: karena TAP egress berada di sisi dalam firewall, setiap percobaan tercatat di `conn.log` sebagai `conn_state` `S0` (SYN tanpa balasan) dengan alamat asli workstation. Implant yang mencoba jalur langsung dulu lalu jatuh ke proxy meninggalkan dua jejak dengan ritme yang sama, dan jejak yang ditolak justru yang membuka identitas host.

### 1.9 Saluran C2 dan label ATT&CK

Pertanyaan ketujuh Dimas punya dua bagian; bagian pertama adalah label yang ditulis di laporan.

ATT&CK mengelompokkan teknik C2 di taktik Command and Control (TA0011) [S1]. Teknik yang paling sering kamu temui dari sisi jaringan, beserta apa yang terlihat di telemetri, ada di tabel berikut [S3][S10][S11]; cari kolom kanan untuk tahu bukti jaringan apa yang mendukung tiap label.

| Teknik | Inti | Yang terlihat di jaringan |
|---|---|---|
| T1071.001 Web Protocols | C2 menumpang HTTP/HTTPS (dan WebSocket) supaya menyatu dengan trafik yang ada | Request berkala ke host/URI yang sama; di TLS hanya SNI, JA3/JA4, ukuran, waktu |
| T1071.004 DNS | C2 lewat query/response DNS | Query berkala atau subdomain tersandi ke satu domain induk (Day 05) |
| T1573 Encrypted Channel | Penyerang mengenkripsi C2 dengan algoritma sendiri, bukan hanya mengandalkan perlindungan bawaan protokol | Isi tidak terbaca; pola koneksi dan fingerprint klien tetap ada |
| T1568 Dynamic Resolution | Alamat C2 berubah (DGA, fast flux) | Banyak NXDOMAIN, TTL rendah, IP berganti (Day 05) |
| T1571 Non-Standard Port | Protokol di port tak lazim | HTTP/TLS di port selain 80/443, atau protokol tak dikenal |
| T1090 Proxy | C2 diteruskan lewat perantara yang dikendalikan penyerang | Tujuan tampak sah (CDN, layanan cloud); asal sebenarnya tersembunyi |

Versi teknik yang dicek di ATT&CK v20.0: T1071.001 versi 1.5 (diubah 11 September 2026), T1573 versi 1.2 dengan sub-teknik T1573.001 Symmetric Cryptography dan T1573.002 Asymmetric Cryptography, dan T1571 versi 1.3 (keduanya diubah 3 September 2026) [S3][S10][S11].

Tiga catatan penerapan untuk `INC-2027-070`:

- **T1071.001** didukung langsung oleh data jaringan: beacon memakai HTTPS lewat `CONNECT` ke port 443.
- **T1573** perlu hati-hati. Deskripsi ATT&CK menekankan enkripsi yang ditambahkan penyerang di luar perlindungan bawaan protokol [S10]. Dari data jaringan, yang bisa dibuktikan hanya TLS. Banyak laporan memberi label T1573 untuk C2 lewat HTTPS; di laporan PT JAB, label itu ditulis sebagai dugaan sampai analisis host menunjukkan cara implant mengenkripsi isinya.
- **T1571** didukung oleh percobaan ke port 8443 (bagian 2.10). Proxy perusahaan yang dipakai implant bukan T1090, karena T1090 adalah perantara yang dikendalikan penyerang.

Tabel ini cukup untuk memberi label teknik di laporan. Prosedur spesifik tiap keluarga malware tidak perlu dipahami untuk mendeteksi polanya.

### 1.10 Dari indikator ke kesimpulan

Bagian kedua pertanyaan ketujuh: kapan boleh menyebut C2 dan membuka insiden.

Beaconing adalah sinyal kuat tetapi bukan bukti C2 sendiri. Untuk menyimpulkan:

- Konfirmasi tujuan mencurigakan (reputasi, umur domain, IOC, prevalence).
- Korelasi dengan host: proses mana yang membuat koneksi itu. Di Windows, Sysmon Event ID 3 (network connection) mencatat nama image proses beserta IP dan port tujuan, sehingga beacon ke IP tertentu bisa dipasangkan dengan proses tertentu (Day 13 membahas korelasinya di SIEM). Di PT JAB yang memakai Microsoft Defender for Endpoint, tabel advanced hunting `DeviceNetworkEvents` memberi hal yang sama: `RemoteIP`, `RemotePort`, `RemoteUrl`, `InitiatingProcessFileName`, `InitiatingProcessFolderPath`, `InitiatingProcessSHA1`, dan akun yang menjalankan proses [S13].
- Cari bukti pendukung: unduhan payload sebelumnya (Day 05), alert Suricata (Day 09), percobaan ke port tidak lazim, atau host lain yang menghubungi tujuan yang sama.
- Nyatakan keyakinan dan batas: metadata saja, atau sudah dikonfirmasi host.

Pisahkan tiga tingkat pernyataan berikut di laporan:

| Tingkat | Contoh kalimat | Butuh |
|---|---|---|
| Indikator | "Ada pola beaconing dari `JKT-WS-2052` ke `assets.northwind-cdn.example`" | Data jaringan saja |
| Kandidat C2 | "Pola itu tidak punya penjelasan jinak: tujuan baru, satu host, tanpa pemilik, disertai percobaan port 8443" | Data jaringan, prevalence, dan konfirmasi bahwa pemilik tidak bisa menjelaskan |
| Kesimpulan C2 | "Host terkompromi; proses X tanpa tanda tangan membuat koneksi itu" | Data host (EDR) dan analisis IR |

Insiden dibuka di tingkat kandidat C2, karena menunggu kesimpulan berarti membiarkan saluran tetap terbuka. Laporan jaringan berhenti di kandidat; kesimpulan ditulis IR setelah data host diperiksa.

## 2. Contoh dan langkah praktis: hunt beacon pertama dari data `jkt-zeek01`

Semua artefak di bagian ini berasal dari hunt Senin 2027-05-24: log Zeek enam hari dari `jkt-zeek01` (Selasa 2027-05-18 08:00 sampai Senin 2027-05-24 08:00 WIB, 144 jam), index `zeek` dan `proxy` di Splunk, log `jkt-fw01` di index `firewall`, dan pcap ring buffer `jkt-pcap01` yang masih menyimpan sekitar 72 jam terakhir. Perintah ditulis sebagai teks, keluaran berlabel ilustrasi, dan alamat serta domain memakai rentang dokumentasi. Waktu di Splunk ditampilkan dalam WIB; `ts` di log Zeek dan waktu di pcap tersimpan dalam UTC, sehingga 14:03:17 WIB tertulis 07:03:17 UTC.

### 2.1 Menyiapkan data dan memeriksa beacon dari insiden yang sudah diketahui

Sebelum mencari beacon baru, Sari memastikan dua hal: datanya lengkap, dan beacon dari insiden sebelumnya tidak muncul lagi (bagian 1.7).

**Tujuan:** menyalin log enam hari ke `jkt-nsm-ws01` tanpa mengubah aslinya, lalu memeriksa tujuan dari `INC-2027-061`, `INC-2027-065`, dan `INC-2027-068`.

```
# di jkt-nsm-ws01: salin log arsip Zeek (JSON, rotasi per jam) ke folder kasus
mkdir -p /cases/HUNT-2027-05-24/zeek
rsync -a --include='*/' --include='conn.*' --include='http.*' --include='ssl.*' \
      --include='dns.*' --exclude='*' \
      zeekro@10.20.70.12:/opt/zeek/logs/2027-05-1[89]/ \
      zeekro@10.20.70.12:/opt/zeek/logs/2027-05-2[0-4]/ \
      /cases/HUNT-2027-05-24/zeek/
sha256sum /cases/HUNT-2027-05-24/zeek/*/* > /cases/HUNT-2027-05-24/zeek.sha256
```

Penjelasan tiap bagian:

- `/opt/zeek/logs/<tanggal>/` adalah folder arsip harian bawaan zeekctl; log yang sedang ditulis ada di `/opt/zeek/logs/current/` (Day 08). Folder harian diberi nama menurut tanggal UTC, jadi Selasa 08:00 WIB berada di folder `2027-05-18` mulai pukul 01:00 UTC.
- Pola `--include` hanya mengambil empat log yang dibutuhkan hunt beacon: `conn`, `http` (untuk `CONNECT`), `ssl` (SNI), dan `dns`.
- Akun `zeekro` adalah akun baca saja; hash SHA-256 dicatat supaya hasil hunt bisa diulang dari data yang sama.

Cek insiden lama di Splunk, untuk jendela yang sama:

```
index=zeek sourcetype=bro:conn:json earliest="05/18/2027:08:00:00" latest="05/24/2027:08:00:00"
    (id.resp_h="203.0.113.163" OR id.resp_h="203.0.113.170" OR id.resp_h="203.0.113.176")
| stats count min(_time) AS pertama max(_time) AS terakhir values(id.orig_h) AS sumber BY id.resp_h
| convert ctime(pertama) ctime(terakhir)

index=zeek sourcetype=bro:http:json method=CONNECT earliest="05/18/2027:08:00:00" latest="05/24/2027:08:00:00"
    (uri="static-update.example.net*" OR uri="sync.cdn-edge.example*" OR uri="telemetry-upd.example*")
| stats count min(_time) AS pertama max(_time) AS terakhir BY id.orig_h uri
| convert ctime(pertama) ctime(terakhir)
```

Keluaran ilustrasi:

```
id.resp_h       count  pertama              terakhir             sumber
203.0.113.176   8      05/19/2027 09:12:41  05/19/2027 09:47:43  10.20.3.60

id.orig_h     uri                        count  pertama              terakhir
10.10.60.92   telemetry-upd.example:443  9      05/19/2027 09:12:40  05/19/2027 09:52:44
```

**Cara membaca hasil:** `203.0.113.163` (`INC-2027-061`) dan `203.0.113.170` (`INC-2027-065`) tidak muncul sama sekali selama 144 jam. `JKT-WS-2007` berada di aturan `NOC-VENDOR-DIRECT` dan keluar tanpa proxy, sehingga beacon yang masih hidup akan terlihat dengan alamat aslinya di hop egress; ketiadaannya adalah bukti containment untuk jendela sensor. Untuk `INC-2027-068`, hanya delapan koneksi Rabu pagi yang sudah tercatat di Day 09 bagian 2.7 dan permintaan kesembilan yang ditolak proxy; tidak ada koneksi sebelum 09:12:40 atau sesudah isolasi. Di RITA nanti, pasangan `10.10.60.92` ke `telemetry-upd.example` mendapat skor rendah walaupun intervalnya sekitar 300 detik: hanya aktif 40 menit, sehingga subskor duration nol dan histogram buruk (bagian 1.4). Itu contoh nyata bahwa beacon pendek yang cepat diblokir tidak akan muncul di daftar skor tinggi.

**Variasi:** ganti daftar IP dengan IOC dari buletin ISAC terbaru; atau pakai `index=firewall` untuk melihat apakah beacon lama mencoba keluar dan ditolak (blokir di firewall tidak menghapus jejak percobaan).

**Kapan gagal:** bila ada jam yang hilang di arsip (sensor restart, disk penuh), interval di sekitar jam itu menjadi jeda palsu. Cek `capture_loss.log` dan jumlah file per hari (24 file per log) sebelum menghitung apa pun.

### 2.2 Mengumpulkan koneksi ke satu tujuan

Setelah RITA (bagian 2.5) menunjuk `JKT-WS-2052`, langkah pertama adalah daftar timestamp mentah, karena semua ukuran keteraturan dihitung dari situ (bagian 1.3).

**Tujuan:** mengambil setiap koneksi dari satu sumber ke satu tujuan, dari Zeek dan dari pcap.

```
# Zeek http.log hop core: setiap CONNECT dari 10.10.60.112, urut waktu
cat /cases/HUNT-2027-05-24/zeek/*/http.*.log \
  | jq -r 'select(.method=="CONNECT" and ."id.orig_h"=="10.10.60.112") | [.ts, .uri, .status_code] | @tsv' \
  | sort -n > /cases/HUNT-2027-05-24/ws2052_connect.tsv
```

Untuk log Zeek dalam format TSV, perintah dari catatan lama tetap berlaku:

```
zeek-cut ts id.orig_h id.resp_h id.resp_p < conn.log | grep <dst> | sort -n
```

- `zeek-cut` memilih kolom dari log TSV; untuk log JSON pakai `jq` seperti di atas.
- `grep <dst>` menyaring tujuan; untuk tujuan di balik proxy, sumbernya `10.20.3.60` dan tujuan IP-nya `203.0.113.180` atau `.181`, jadi yang dipakai adalah `http.log` hop core.

Keluaran ilustrasi (`ws2052_connect.tsv`, tujuh baris pertama dari 96):

```
1810796597.412  assets.northwind-cdn.example:443  200
1810797182.630  assets.northwind-cdn.example:443  200
1810797851.218  assets.northwind-cdn.example:443  200
1810798359.904  assets.northwind-cdn.example:443  200
1810799061.077  assets.northwind-cdn.example:443  200
1810799628.551  assets.northwind-cdn.example:443  200
1810800211.336  assets.northwind-cdn.example:443  200
```

Di pcap egress, filter Wireshark dari catatan lama dipakai untuk percobaan langsung yang ditolak firewall (bagian 2.10):

```
tcp.flags.syn == 1 and tcp.flags.ack == 0 and ip.dst == 203.0.113.181
```

- Filter SYN ke satu tujuan memberi daftar awal koneksi dan waktunya. Catatan lama memakai alamat contoh `93.184.216.34`; ganti dengan tujuan kasusmu.
- Cara membaca: catat timestamp tiap koneksi ke tujuan itu; ini bahan mengukur periodisitas.

**Cara membaca hasil:** baris pertama, 1810796597 (Kamis 2027-05-20 14:03:17 WIB), adalah `CONNECT` pertama `JKT-WS-2052` ke domain itu di seluruh jendela. Jarak baris berurutan 585, 669, 508, 702, 567, dan 583 detik: tidak ada dua yang sama, tetapi semuanya di sekitar 10 menit.

**Kapan gagal:** filter `ip.dst` di pcap egress untuk koneksi yang lewat proxy hanya menemukan proxy sebagai sumber; tanpa hop core, workstation tidak terlihat. Pcap juga hanya menyimpan sekitar 72 jam, jadi untuk Kamis siang yang tersisa hanya log Zeek.

### 2.3 Mengukur interval dan sebaran

**Tujuan:** menghitung delta, membuang jeda panjang, lalu menghitung median, CV, MAD relatif, dan Bowley skewness untuk `JKT-WS-2052`.

```
cut -f1 /cases/HUNT-2027-05-24/ws2052_connect.tsv \
  | awk 'NR>1 {printf "%.0f\n", $1-prev} {prev=$1}' > ws2052_delta.txt
sort -n ws2052_delta.txt | awk '
  {d[NR]=$1} END {
    n=NR; med=(n%2)?d[(n+1)/2]:(d[n/2]+d[n/2+1])/2
    k=0; for(i=1;i<=n;i++) if(d[i]<=3*med){k++; v[k]=d[i]; s+=d[i]; ss+=d[i]*d[i]}
    m=s/k; sd=sqrt((ss-k*m*m)/(k-1))
    printf "interval=%d dibuang=%d dipakai=%d median=%.0f mean=%.1f sd=%.1f cv=%.3f\n", n, n-k, k, med, m, sd, sd/m
  }'
```

Penjelasan tiap bagian:

- `awk 'NR>1 {...} {prev=$1}'` menghitung selisih setiap baris dengan baris sebelumnya, dibulatkan ke detik.
- `sort -n` mengurutkan delta supaya median bisa diambil dari posisi tengah.
- `d[i]<=3*med` membuang jeda yang lebih dari tiga kali median (PC tidur, akhir pekan), sesuai aturan program di bagian 1.3, lalu menghitung rata-rata dan deviasi standar sampel dari sisanya.
- MAD dan kuartil tidak dihitung di skrip ini supaya tetap pendek; `datamash` (`datamash median 1 mad 1 q1 1 q3 1`) atau spreadsheet memberikannya dari file yang sama. Opsi `mad` di `datamash` versi tertentu sudah dikalikan konstanta skala, jadi cek manual versi-mu.

Keluaran ilustrasi:

```
interval=95 dibuang=2 dipakai=93 median=598 mean=601.3 sd=89.6 cv=0.149
median=598 mad=80 q1=523 q3=677 min=452 max=748
```

Keluaran ilustrasi untuk perbandingan (catatan lama, dua pola):

```
delta(s): 60, 58, 61, 59, 62, 60  -> periodik ~60s (jitter kecil)
delta(s): 5, 320, 17, 1200, 44     -> tidak periodik
```

**Cara membaca hasil:**

- 96 koneksi menghasilkan 95 interval. Dua yang dibuang adalah jeda Kamis malam ke Jumat pagi (PC tidur) dan jeda Jumat sore ke Senin pagi; keduanya dicatat, bukan dihilangkan dari laporan.
- CV 0,149 (89,6 / 601,3) dan MAD relatif 0,134 (80 / 598) cocok dengan jitter sekitar plus minus 25% (bagian 1.3). Interval terpendek 452 dan terpanjang 748 detik, yaitu sekitar 600 plus minus 25%.
- Bowley skewness (523 + 677 - 2 x 598) / (677 - 523) = 4 / 154 = 0,026: hampir simetris, ciri jitter acak merata, bukan check-in yang kadang terlewat.
- Pada pola lama di atas, deret pertama periodik sekitar 60 detik dengan jitter kecil; deret kedua menyebar dan bukan beacon.

**Variasi:** hitung ulang per hari. Bila interval Jumat dan Kamis sama, konfigurasi implant tidak berubah; bila berubah, operator mungkin mengubah sleep (bisa berarti sesi interaktif).

**Kapan gagal:** median dari terlalu sedikit sampel tidak stabil (di bawah sekitar 24 interval, bagian 1.3); delta yang dibulatkan ke detik tidak cukup untuk beacon di bawah sekitar 10 detik.

### 2.4 Konsistensi ukuran dan rotasi tujuan

**Tujuan:** memeriksa apakah ukuran tiap check-in seragam, dan apakah beacon berpindah antara beberapa IP.

```
zeek-cut id.resp_h orig_bytes resp_bytes < conn.log | grep <dst>
```

Perintah dari catatan lama itu untuk log TSV. Untuk log JSON PT JAB, ukuran tunnel hop core diambil dari `conn.log` dengan `uid` yang sama dengan baris `CONNECT`, dan alamat tujuan akhir dari hop egress:

```
# hop core: ukuran setiap tunnel CONNECT 10.10.60.112 ke proxy
jq -r 'select(."id.orig_h"=="10.10.60.112" and ."id.resp_h"=="10.20.3.60" and ."id.resp_p"==3128)
       | [.ts, .orig_bytes, .resp_bytes, .duration] | @tsv' /cases/HUNT-2027-05-24/zeek/*/conn.*.log \
  | sort -n | awk '{print int($2/100)*100, int($3/100)*100}' | sort | uniq -c | sort -rn | head

# hop egress: IP tujuan yang dipakai proxy untuk domain itu
jq -r 'select(.server_name=="assets.northwind-cdn.example") | ."id.resp_h"' \
   /cases/HUNT-2027-05-24/zeek/*/ssl.*.log | sort | uniq -c
```

Keluaran ilustrasi:

```
     93 1500 4200
      1 2118000 4200
      1 1500 184300
      1 1500 0

     49 203.0.113.180
     47 203.0.113.181
```

**Cara membaca hasil:** 93 dari 96 check-in jatuh di bucket yang sama; nilai persisnya `orig_bytes` 1.517 sampai 1.561 dan `resp_bytes` 4.212 sampai 4.260, selisih kurang dari 50 byte di setiap arah: check-in kosong. Tiga yang berbeda justru yang paling penting: satu respons 184.330 byte (Jumat 10:42:18 WIB) (sesuatu diunduh ke host, mungkin perintah atau modul), satu kiriman 2.118.004 byte dari host (Jumat 15:13:40 WIB) (data keluar; pertanyaannya diteruskan ke Day 12), dan satu koneksi Senin 07:59:41 tanpa respons karena terpotong batas jendela data. Variasi ukuran bisa aktivitas C2, bukan hanya check-in. Di hop egress, 96 koneksi tersebar ke dua IP, 49 dan 47: resolusi DNS di proxy berganti antara dua alamat, sehingga analisis per IP hanya melihat setengah beacon dengan interval yang tidak rapi (bagian 1.2). Analisis per nama domain atau per workstation menyatukannya kembali.

**Kapan gagal:** beacon dengan padding acak membuat ukuran tidak seragam; di sini subskor data size RITA turun, tetapi interval tetap teratur. Sebaliknya, banyak agent sah juga berukuran seragam, jadi keseragaman ukuran tidak membedakan jinak dan jahat.

### 2.5 RITA: impor, tampilan, dan ekspor

**Tujuan:** memeringkat semua pasangan dalam 144 jam data dengan skor beacon RITA, lalu mengekspor hasilnya untuk di-stack.

```
# RITA 5.x: impor log Zeek ke dataset, lalu tampilkan hasil
rita import --database=jab_hunt_20270524 --logs=/cases/HUNT-2027-05-24/zeek
rita view jab_hunt_20270524
# di kotak pencarian TUI, contoh filter:
#   beacon:>=70 sort:beacon-desc
# keluaran CSV untuk dilampirkan ke laporan
rita view --stdout jab_hunt_20270524 > /cases/HUNT-2027-05-24/rita_beacon.csv
```

Penjelasan tiap bagian:

- `import` membaca direktori log Zeek (TSV atau JSON) dan membuat dataset; `view` membuka tampilan terminal dengan kolom severity, sumber, tujuan, skor beacon, dan durasi [S4].
- Untuk dataset yang terus bertambah dari sensor, RITA memakai flag `--rolling`; untuk log lama yang diimpor sekali seperti hunt ini, jangan pakai flag itu karena hasilnya bisa salah [S4].
- `beacon:>=70 sort:beacon-desc` adalah sintaks pencarian di TUI; `--stdout` mengeluarkan hasil sebagai CSV. Susunan kolom CSV persisnya cek di versi-mu dengan `head -1`.
- Konfigurasi yang dipakai adalah `/etc/rita/config.hjson` bawaan, dengan ambang beacon 50/70/90 dan minimal empat koneksi unik (bagian 1.4). Untuk hunt di PT JAB, `10.20.3.60` tidak dikecualikan, supaya pasangan proxy ke IP tetap muncul sebagai pembanding.

Keluaran ilustrasi (kolom diringkas; 10 dari 1.962 baris dengan skor minimal 70):

```
Severity  Source         Destination                     Beacon  Duration
critical  10.10.60.37    docsync-update.jab.example        99     144h
high      10.10.61.204   wdcp.mde-cloud.example.net        98     144h
high      10.10.62.18    delivery.wu-cdn.example.net       97     71h
critical  10.20.12.41    api.optic-vendor.example          97     144h
critical  10.10.60.110   license.cadtool.example           96     52h
critical  10.10.60.111   ping.remote-support.example       92     49h
critical  10.10.60.113   app.pmo-tracker.example           88     47h
critical  10.10.60.112   assets.northwind-cdn.example      81     17h
critical  10.20.3.60     203.0.113.180                     74     17h
critical  10.20.2.25     feeds.spamfilter-vendor.example   71     144h
```

Contoh dari catatan lama tetap berguna sebagai pengingat (alamat lab):

```
Severity  Source       Destination              Beacon  Duration
high      10.0.0.8     cdn-upd[.]example        93      23h41m
medium    10.0.0.15    time.windows[.]com       78      24h00m
low       10.0.0.22    api.vendor[.]example     55      6h12m
```

**Cara membaca hasil:**

- Kolom Severity belum berguna di sensor berumur enam hari. Modifier first seen (+0,15) mengenai hampir semua tujuan, sehingga `JAB DocSync` (skor 99) dan semua pasangan berprevalence rendah (+0,15 lagi) terdorong ke critical. Hanya Defender dan Windows Update yang tertahan di high, karena dihubungi lebih dari separuh host dan mendapat pengurangan prevalence (bagian 1.4). Untuk hunt ini, urutan kerja diambil dari prevalence (bagian 2.6), bukan dari Severity.
- `JKT-WS-2052` (`10.10.60.112`) hanya di urutan kedelapan dengan skor 81: interval berjitter dan tiga koneksi berukuran lain menurunkan subskor timestamp dan data size. Beacon jahat tidak harus paling rapi.
- `10.20.3.60` ke `203.0.113.180` adalah hop egress dari beacon yang sama (bagian 2.4). Skor per IP lebih rendah karena hanya setengah check-in yang ke alamat itu.
- Pada contoh lama, baris pertama paling layak diperiksa, tetapi baris kedua menunjukkan kenapa skor bukan vonis: sinkronisasi waktu Windows juga teratur dan muncul sepanjang hari. Triage tetap dengan reputasi tujuan, JA3/JA4, dan proses di host.

**Variasi:** jalankan ulang dengan `unique_connection_threshold` lebih tinggi untuk membuang beacon lambat, atau lebih rendah di lab untuk melihat bagaimana beacon berumur pendek seperti `INC-2027-068` diperlakukan. Flow (Day 10) memberi data yang sama di skala jaringan bila Zeek tidak terpasang di semua titik.

**Kapan gagal:** beacon dengan sleep sangat panjang (kurang dari empat koneksi di jendela data), beacon yang memakai domain CDN bersama, atau tujuan yang berganti setiap beberapa jam. Pola lognormal dari agent otomatis juga bisa mendapat skor nol [S14].

### 2.6 Stacking hasil RITA dengan prevalence

1.962 baris tidak dibuka satu per satu. Sari memeringkatnya dengan prevalence (bagian 1.7).

**Tujuan:** menghitung, untuk setiap tujuan dengan skor minimal 70, berapa sumber internal yang menghubunginya, lalu menyisakan tujuan dengan satu atau dua sumber.

```
head -1 /cases/HUNT-2027-05-24/rita_beacon.csv
# misal kolom: severity,source,destination,beacon,...  (cek urutannya dulu)
awk -F, 'NR>1 && $4>=70 && $2!="10.20.3.60" {n[$3]++} END {for (d in n) print n[d], d}' \
    /cases/HUNT-2027-05-24/rita_beacon.csv | sort -rn > prevalence.txt
head -3 prevalence.txt; awk '$1<=2' prevalence.txt; wc -l < prevalence.txt
```

Penjelasan tiap bagian:

- `$4>=70` memakai kolom skor beacon; `$2!="10.20.3.60"` membuang baris proxy ke IP, karena di hop egress setiap tujuan web hanya punya satu sumber (proxy) dan prevalence-nya selalu satu. Baris proxy ditinjau terpisah untuk tujuan yang lolos.
- `n[$3]++` menghitung jumlah sumber per tujuan; `awk '$1<=2'` menyisakan tujuan dengan satu atau dua sumber.

Keluaran ilustrasi:

```
812 wdcp.mde-cloud.example.net
790 delivery.wu-cdn.example.net
149 docsync-update.jab.example
1 assets.northwind-cdn.example
1 license.cadtool.example
2 app.pmo-tracker.example
1 api.optic-vendor.example
1 ping.remote-support.example
1 feeds.spamfilter-vendor.example
64
```

**Cara membaca hasil:** tiga tujuan teratas menyumbang 1.751 dari 1.962 baris (812 + 790 + 149). Setelah baris proxy dibuang, ada 64 tujuan, dan hanya enam yang dihubungi satu atau dua sumber. Enam itu masuk triage (bagian 2.11). Tujuan berprevalence tinggi tidak otomatis bersih: untuk itu ada pemeriksaan fingerprint langka di tujuan umum (bagian 1.7).

**Kapan gagal:** host di kantor cabang dan laptop di luar kantor tidak terlihat sensor, sehingga prevalence-nya kurang. Kolom CSV yang salah dipilih membuat seluruh hasil salah tanpa pesan error; selalu cocokkan dua baris dengan tampilan `view`.

### 2.7 Query Splunk untuk beacon workstation di balik proxy

Hunt dengan RITA dijalankan manual. Supaya pola ini dipantau setiap hari, Sari menulis query yang sama logikanya di Splunk, memakai `CONNECT` di hop core.

**Tujuan:** menghitung median interval, CV setelah jeda dibuang, dan prevalence untuk setiap pasangan workstation dan domain tujuan.

```
index=zeek sourcetype=bro:http:json method=CONNECT earliest="05/18/2027:08:00:00" latest="05/24/2027:08:00:00"
| eval tujuan=mvindex(split(uri,":"),0)
| sort 0 id.orig_h tujuan _time
| streamstats current=f last(_time) AS prev BY id.orig_h tujuan
| eval delta=_time-prev
| where isnotnull(delta)
| eventstats median(delta) AS med BY id.orig_h tujuan
| eval jeda=if(delta>3*med,1,0), d_ok=if(jeda=0,delta,null())
| stats count AS n_interval sum(jeda) AS jeda_dibuang median(delta) AS median_s
        avg(d_ok) AS rata stdev(d_ok) AS sd BY id.orig_h tujuan
| eval cv=round(sd/rata,3)
| eventstats dc(id.orig_h) AS prevalence BY tujuan
| where n_interval>=24 AND cv<=0.2 AND median_s>=30 AND median_s<=14400
| sort prevalence cv
| table id.orig_h tujuan n_interval jeda_dibuang median_s cv prevalence
```

Penjelasan tiap bagian:

- `uri` untuk `CONNECT` berisi `host:port`; `split` dan `mvindex` mengambil nama domainnya. Sourcetype `bro:http:json` mengikuti TA for Zeek 1.0.11 [S15]; nama field `method`, `uri`, dan `status_code` mengikuti `http.log` Zeek [S2].
- `sort 0 ... _time` mengurutkan dari yang paling lama, karena `streamstats` membaca event sesuai urutan; tanpa itu delta menjadi negatif.
- `streamstats current=f last(_time)` mengambil waktu event sebelumnya untuk pasangan yang sama.
- `eventstats median(delta)` menambahkan median ke setiap event supaya jeda lebih dari tiga kali median bisa ditandai, lalu `d_ok` hanya berisi interval yang dipakai.
- `eventstats dc(id.orig_h) BY tujuan` dihitung sebelum `where`, sehingga prevalence mencakup semua workstation yang menghubungi domain itu, bukan hanya yang lolos filter keteraturan.
- `where` memakai ambang program: minimal 24 interval, CV maksimal 0,2, median antara 30 detik dan 4 jam (bagian 1.3).

Keluaran ilustrasi (8 dari 1.207 baris):

```
id.orig_h      tujuan                         n_interval  jeda_dibuang  median_s  cv     prevalence
10.10.60.112   assets.northwind-cdn.example   95          2             598       0.149  1
10.10.60.110   license.cadtool.example        51          3             3600      0.004  1
10.10.60.111   ping.remote-support.example    2944        4             60        0.011  1
10.10.60.113   app.pmo-tracker.example        139         3             900       0.021  2
10.10.60.114   app.pmo-tracker.example        128         3             900       0.023  2
10.10.60.37    docsync-update.jab.example     569         1             900       0.002  149
10.10.61.204   wdcp.mde-cloud.example.net     1714        0             300       0.087  812
10.10.62.18    delivery.wu-cdn.example.net    94          2             2700      0.162  790
```

**Cara membaca hasil:**

- Hasil query (1.207 pasangan) lebih sedikit daripada RITA karena hanya memuat workstation di balik proxy dan memakai ambang yang lebih ketat. `jkt-nms-script01` dan `jkt-mailgw01` tidak muncul karena keluar langsung tanpa proxy, dan median `api.optic-vendor.example` di bawah 30 detik.
- `JKT-WS-2052` menonjol bukan karena CV-nya (justru yang paling tinggi di daftar ini), tetapi karena prevalence satu dan domain yang belum dikenal. Beacon sah sering jauh lebih rapi daripada implant berjitter.
- `ping.remote-support.example` dengan 2.944 interval berjarak 60 detik: alat remote support yang aktif terus. Jinak atau tidak, ia perlu pemilik (bagian 2.11).

**Variasi:** ubah ke correlation search harian dengan `earliest=-24h`, `n_interval>=24`, dan `prevalence<=2`, lalu kecualikan pasangan yang sudah diverifikasi lewat lookup `beacon_allowlist.csv` (sumber, tujuan, pemilik, tanggal tinjau ulang). Untuk server yang keluar langsung, ganti sumber datanya menjadi `bro:ssl:json` dengan `server_name` sebagai tujuan.

**Kapan gagal:** `streamstats` dan `eventstats` pada jutaan event bisa lambat dan terkena batas memori; jalankan per hari lalu gabungkan, atau pakai summary index. CV tidak menangkap beacon berjitter besar atau beacon lambat; query ini pelengkap RITA, bukan pengganti.

### 2.8 Atribusi lewat proxy, log proxy, dan proses di host

Baris RITA `10.20.3.60` ke `203.0.113.180` dan `.181` menjawab "ke mana", tetapi bukan "siapa" (bagian 1.5). Langkah ini menyambungkan hop egress ke workstation, lalu ke proses.

**Tujuan:** memastikan bahwa koneksi proxy ke `203.0.113.180`/`.181` milik `JKT-WS-2052`, membaca apa yang dilihat proxy di dalam tunnel, dan meminta data proses dari Microsoft Defender for Endpoint (MDE).

```
index=zeek sourcetype=bro:http:json method=CONNECT uri="*northwind-cdn.example*"
    earliest="05/18/2027:08:00:00" latest="05/24/2027:08:00:00"
| stats count dc(uri) AS n_uri values(uri) AS uri min(_time) AS pertama max(_time) AS terakhir BY id.orig_h
| convert ctime(pertama) ctime(terakhir)

index=proxy host="*northwind-cdn.example" earliest="05/01/2027:00:00:00" latest="05/24/2027:08:00:00"
| stats count min(_time) AS pertama values(method) AS method values(category) AS kategori
        values(http_user_agent) AS ua BY src host url_path
| convert ctime(pertama)
```

Penjelasan tiap bagian:

- Query pertama mencari semua workstation yang pernah meminta domain induk itu, bukan hanya `assets.`, supaya subdomain lain ikut terlihat.
- Query kedua memakai log `jkt-proxy01` (retensi 30 hari) sejak awal bulan, karena log proxy lebih tua daripada sensor Zeek. Domain yang tidak terkategori di-bump, sehingga proxy mencatat method dan path di dalam tunnel (Day 06). Nama field proxy mengikuti logformat PT JAB.

Keluaran ilustrasi:

```
id.orig_h     count  n_uri  uri                                                                   pertama              terakhir
10.10.60.112  97     2      assets.northwind-cdn.example:443 share.northwind-cdn.example:443   05/20/2027 13:57:39  05/24/2027 07:59:41

src           host                          url_path                   count  pertama              method  kategori       ua
10.10.60.112  share.northwind-cdn.example   /d/Penawaran_Harga_Q3.zip  1      05/20/2027 13:57:40  GET     Uncategorized  Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... Edg/...
10.10.60.112  assets.northwind-cdn.example  /api/v3/assets             96     05/20/2027 14:03:17  POST    Uncategorized  Mozilla/5.0 (Windows NT 10.0; Win64; x64) ... Chrome/...
```

**Cara membaca hasil:** satu workstation saja, `10.10.60.112` (`JKT-WS-2052`). Urutannya: Kamis 13:57:40 WIB, browser Edge mengunduh file zip dari subdomain `share.`; enam menit kemudian mulai `POST` berkala ke `assets.` dengan User-Agent yang mengaku Chrome. Workstation PT JAB memakai Edge, dan tidak ada riwayat Chrome dari host ini sebelum Kamis. Tidak ada log proxy untuk domain ini sebelum 13:57:39, sehingga dalam 30 hari retensi proxy, inilah awalnya. Unduhan sebelum beacon adalah bukti pendukung yang dicari (bagian 1.10), tetapi isi zip dan apa yang dijalankan adalah pertanyaan host.

Data proses dari MDE (KQL, advanced hunting; `Timestamp` dalam UTC):

```
DeviceNetworkEvents
| where Timestamp between (datetime(2027-05-20 06:50:00) .. datetime(2027-05-24 01:00:00))
| where DeviceName startswith "jkt-ws-2052"
| where (RemoteIP == "10.20.3.60" and RemotePort == 3128) or RemotePort == 8443
| summarize n=count(), pertama=min(Timestamp), terakhir=max(Timestamp)
    by InitiatingProcessFileName, InitiatingProcessFolderPath, InitiatingProcessSHA1,
       InitiatingProcessAccountName, RemoteIP, RemotePort, ActionType
| order by n desc
```

- `DeviceNetworkEvents` memuat koneksi per proses beserta `RemoteIP`, `RemotePort`, `RemoteUrl`, nama, folder, dan hash proses, serta akun yang menjalankannya [S13].
- Koneksi lewat proxy tercatat ke `10.20.3.60:3128`, bukan ke tujuan akhir; apakah `RemoteUrl` berisi nama domain untuk koneksi lewat proxy perlu dicek di tenant-mu. Karena itu filternya memakai proxy dan port 8443, lalu dibandingkan waktunya dengan baris `CONNECT`.

Keluaran ilustrasi (diringkas):

```
InitiatingProcessFileName  InitiatingProcessFolderPath                                   RemoteIP       RemotePort  n
msedge.exe                 C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe  10.20.3.60     3128        4127
nwassets.exe               C:\Users\rina.oktaviani\AppData\Roaming\NorthwindAssets\...   10.20.3.60     3128        96
nwassets.exe               C:\Users\rina.oktaviani\AppData\Roaming\NorthwindAssets\...   203.0.113.181  8443        96
```

**Cara membaca hasil:** proses yang sama, `nwassets.exe` di folder profil pengguna `rina.oktaviani` (staf Pengadaan), membuat 96 koneksi ke proxy dan 96 percobaan ke `203.0.113.181:8443`, dengan jumlah yang sama persis dengan baris `CONNECT` dan `S0` di Zeek. Ini korelasi host yang dibutuhkan untuk menaikkan pasangan ini dari indikator ke kandidat C2. Tanda tangan, asal file, dan perilaku proses diperiksa IR, bukan disimpulkan dari data jaringan. MDE tidak membuat alert untuk proses ini selama empat hari; itu catatan untuk IR, bukan bukti bahwa proses itu jinak.

**Kapan gagal:** host tanpa MDE (seperti `JKT-WS-2021` di Day 05) tidak punya data proses; pakai Sysmon Event ID 3 bila terpasang, atau minta triage host. Host di luar kantor tidak lewat sensor, sehingga data MDE bisa memuat koneksi yang tidak ada di Zeek.

### 2.9 Pola TLS dan DNS beacon, dan pembanding dengan agent sah

**Tujuan:** melihat beacon yang sama dari pcap egress (SNI, fingerprint, ukuran record) dan dari `dns.log`, lalu membandingkannya dengan agent sah.

```
mergecap -w /cases/HUNT-2027-05-24/egress_20270521_1030-1100.pcapng \
  /mnt/pcap01/ring/egress-jkt_*_20270521033000.pcapng /mnt/pcap01/ring/egress-jkt_*_20270521034500.pcapng
tshark -r /cases/HUNT-2027-05-24/egress_20270521_1030-1100.pcapng \
  -Y 'tls.handshake.type == 1 and tls.handshake.extensions_server_name contains "northwind-cdn"' \
  -T fields -e frame.time -e ip.src -e ip.dst -e tls.handshake.extensions_server_name -e tls.handshake.ja4
```

Filter Wireshark dari catatan lama untuk pola TLS tanpa isi:

```
tls.handshake.extensions_server_name
tls.record.content_type == 23
```

- Untuk beacon HTTPS, lihat SNI tetap dan interval koneksi; ukuran Application Data (Day 06).
- Cara membaca: koneksi TLS berkala ke SNI sama dengan JA3 tetap dan App Data kecil seragam adalah kandidat beacon C2 terenkripsi. Isi tidak perlu dibaca.

Keluaran ilustrasi (`tshark`, tiga baris; ring file 03:30 dan 03:45 UTC, yaitu 10:30 sampai 11:00 WIB):

```
May 21, 2027 03:32:09.118 UTC  10.20.3.60  203.0.113.181  assets.northwind-cdn.example  t13d1512h2_8daaf6152771_e99876c6e365
May 21, 2027 03:42:18.204 UTC  10.20.3.60  203.0.113.180  assets.northwind-cdn.example  t13d1512h2_8daaf6152771_e99876c6e365
May 21, 2027 03:51:47.660 UTC  10.20.3.60  203.0.113.181  assets.northwind-cdn.example  t13d1512h2_8daaf6152771_e99876c6e365
```

**Cara membaca hasil:** sumber egress adalah proxy, dan JA4-nya sama dengan JA4 yang dibuat `jkt-proxy01` untuk koneksi Chromium yang di-bump (Day 06 bagian 2.5), karena domain tidak terkategori di-bump dan ClientHello di egress dibuat proxy. Fingerprint di sini tidak membedakan implant dari browser. Interval dan SNI tetap terlihat; isi tidak. Check-in 03:42:18 UTC (10:42:18 WIB) adalah koneksi dengan respons 184.330 byte di bagian 2.4: di pcap, record Application Data dari server jauh lebih banyak daripada check-in lain, tanpa perlu dekripsi.

DNS dari sisi resolver, filter Wireshark dari catatan lama:

```
dns.qry.name contains "c2-domain.example.com"
```

Untuk kasus ini, di `dns.log`:

```
index=zeek sourcetype=bro:dns:json query="*.northwind-cdn.example"
    earliest="05/18/2027:08:00:00" latest="05/24/2027:08:00:00"
| stats count values(answers) AS jawaban values(TTLs) AS ttl BY id.orig_h query
```

Keluaran ilustrasi:

```
id.orig_h   query                          count  jawaban                       ttl
10.20.3.60  assets.northwind-cdn.example   96     203.0.113.180 203.0.113.181   300.0
10.20.3.60  share.northwind-cdn.example    1      203.0.113.180                 300.0
```

**Cara membaca hasil:** semua query berasal dari proxy, bukan workstation (bagian 1.5). TTL 300 detik lebih pendek dari interval sekitar 600 detik, jadi hampir setiap check-in memicu query baru, dan jawabannya berganti antara dua alamat. Query berkala ke domain sama adalah beacon DNS dalam arti luas; bila subdomain acak dan volume tinggi, bisa tunneling sekaligus (Day 05). Sourcetype `bro:dns:json` belum divalidasi di PT JAB; cek dengan `| metadata type=sourcetypes index=zeek` (Day 08).

Pembanding dengan agent sah, filter Wireshark dari catatan lama:

```
tls.handshake.extensions_server_name contains "<vendor-dikenal>"
```

- Cocokkan tujuan beacon dengan daftar vendor/layanan sah dan reputasi; periksa JA3 (library umum vs tool).
- Cara membaca: beacon ke vendor update dikenal dengan JA3 browser biasa kemungkinan sah; beacon ke domain baru dengan JA3 tool dan tanpa konteks proses sah mencurigakan. Konteks dan reputasi memutuskan.

| Ciri | `JAB DocSync` | `assets.northwind-cdn.example` |
|---|---|---|
| Interval dan CV | 900 detik, CV 0,002 | 598 detik, CV 0,149 |
| Prevalence | 149 workstation | 1 workstation |
| First seen | sejak sensor hidup (dan 30 hari di log proxy) | Kamis 2027-05-20 13:57:39 |
| Kategori proxy | Internal application, di-splice | Uncategorized, di-bump |
| Proses (MDE) | `DocSync.exe` di `C:\Program Files\` | `nwassets.exe` di `AppData\Roaming` |
| Pemilik | Tim aplikasi internal | Tidak ada |

**Kapan gagal:** dengan ECH, SNI di ClientHello luar tidak lagi menunjukkan tujuan sebenarnya (Day 15). Dengan DNS over HTTPS dari host, `dns.log` resolver internal tidak memuat query itu (Day 16).

### 2.10 Long connection 26 jam dan SYN berulang ke port 8443

Pertanyaan keenam Dimas berasal dari dua hal yang Sari lihat di luar RITA beacon: alert `SOC-2027-0651` hari Minggu dan alert `SOC-2027-0650` hari Jumat yang sudah ditutup.

**Tujuan:** membaca kedua indikator dari `conn.log` dan firewall, lalu memutuskan mana yang jinak (bagian 1.8).

```
index=zeek sourcetype=bro:conn:json duration>43200
    earliest="05/18/2027:08:00:00" latest="05/24/2027:08:00:00"
| eval jam=round(duration/3600,1)
| table _time uid id.orig_h id.resp_h id.resp_p service jam orig_bytes resp_bytes conn_state

index=zeek sourcetype=bro:conn:json id.resp_p=8443 conn_state=S0
    earliest="05/18/2027:08:00:00" latest="05/24/2027:08:00:00"
| stats count min(_time) AS pertama max(_time) AS terakhir values(history) AS history
        sum(orig_pkts) AS syn BY id.orig_h id.resp_h
| convert ctime(pertama) ctime(terakhir)
```

Penjelasan tiap bagian:

- `duration>43200` sama dengan ambang long connection kategori tinggi RITA, 12 jam (bagian 1.8). `_time` di baris `conn.log` adalah awal koneksi, walaupun baris itu baru ditulis saat koneksi selesai (Day 08).
- `conn_state=S0` berarti SYN terlihat tanpa balasan apa pun (Day 08 bagian 1.4) [S2]; `orig_pkts` dijumlahkan untuk menghitung SYN termasuk retransmisi.

Keluaran ilustrasi:

```
_time                uid                 id.orig_h    id.resp_h   id.resp_p  service  jam   orig_bytes  resp_bytes  conn_state
05/22/2027 07:48:02  CkQ3vN2xT9pLm4Wd8a  10.20.12.42  10.20.3.60  3128       http     26.2  3912044     611820381   SF

id.orig_h     id.resp_h      count  pertama              terakhir             history  syn
10.10.60.112  203.0.113.181  96     05/20/2027 14:02:56  05/24/2027 07:59:20  S        288
```

**Cara membaca hasil:**

- Long connection: `jkt-noc-mon01` (`10.20.12.42`) membuka satu tunnel `CONNECT` lewat proxy Sabtu 07:48:02 WIB yang hidup 26 jam 14 menit (94.440 detik), sekitar 612 MB dari luar dan 3,9 MB ke luar. Baris `http.log` dengan `uid` yang sama menunjukkan `CONNECT stream.optic-vendor.example:443`. Tim NOC Bambang Hartono mengonfirmasi: dashboard telemetri optik vendor memakai websocket yang hanya dibuka ulang saat token habis. Disposisi `SOC-2027-0651`: jinak, dicatat di allowlist dengan pemilik dan tanggal tinjau ulang. Karena tunnel lewat proxy, hop egress juga hanya punya satu baris panjang, dari proxy.
- Port 8443: 96 percobaan dari `10.10.60.112` ke `203.0.113.181:8443`, masing-masing tiga SYN (288 total), `history` `S`, tidak ada balasan karena `jkt-fw01` menolak. Jumlahnya sama dengan 96 `CONNECT`. Setiap percobaan terjadi sekitar 21 detik sebelum `CONNECT` berikutnya (14:02:56 lalu 14:03:17). Pola ini cocok dengan implant yang mencoba jalur langsung dulu, menunggu batas waktu connect TCP, lalu jatuh ke proxy. Jeda 21 detik sesuai dengan SYN awal dan dua retransmisi di Windows (3, 6, lalu 12 detik), tetapi angka itu bisa diubah lewat registry dan perlu dicek di host.

Firewall mencatat penolakan yang sama:

```
index=firewall action=deny src=10.10.60.112 dest=203.0.113.181 dest_port=8443
| bin _time span=1d | stats count BY _time rule
```

Keluaran ilustrasi:

```
_time       rule              count
2027-05-20  DEFAULT-DENY-OUT  87
2027-05-21  DEFAULT-DENY-OUT  195
2027-05-24  DEFAULT-DENY-OUT  6
```

**Cara membaca hasil:** 87 + 195 + 6 = 288 baris, satu per paket SYN; 29, 65, dan 2 percobaan per hari dikali tiga. Alert `SOC-2027-0650` dibuat Jumat 18:05 oleh correlation search "workstation keluar langsung ditolak, lebih dari 50 per hari" dan ditutup L1 dengan catatan "diblokir firewall, tidak berdampak". Penolakan memang menghentikan jalur itu, tetapi tidak menghentikan implant yang punya jalur kedua. Pertanyaan yang benar untuk alert seperti ini adalah "proses apa yang mencoba, dan apakah ia berhasil lewat jalan lain". `SOC-2027-0650` dibuka ulang dan digabung ke `INC-2027-070`.

**Variasi:** cari percobaan langsung lain dari workstation dengan `conn_state=S0 id.orig_h="10.10.*"` dan port bukan 80/443, lalu bandingkan waktunya dengan `CONNECT` dari host yang sama.

**Kapan gagal:** bila TAP berada di sisi luar firewall, percobaan yang ditolak tidak pernah terlihat sensor, dan hanya log firewall yang tersisa. Long connection yang masih hidup saat jendela ditutup belum ada di `conn.log`; RITA 5 menganalisis koneksi terbuka secara terpisah, dan detailnya perlu dicek di versi-mu.

### 2.11 Triage kandidat dan pembukaan `INC-2027-070`

**Tujuan:** memutuskan untuk enam tujuan berprevalence rendah (bagian 2.6), ditambah dua alert di bagian 2.10, mana yang jinak, mana yang perlu tindak lanjut non-insiden, dan mana yang menjadi insiden.

| Kandidat | Bukti jaringan | Penjelasan jinak yang diuji | Hasil | Tindak lanjut |
|---|---|---|---|---|
| `JKT-WS-2052` (`10.10.60.112`) ke `assets.northwind-cdn.example` | 96 check-in, median 598 detik, CV 0,149; first seen Kamis; satu host; percobaan 8443; unduhan zip sebelumnya | Agent aplikasi baru? Tidak ada di inventaris, tidak ada pemilik, proses di `AppData` | Kandidat C2 | `SOC-2027-0652`, `INC-2027-070` |
| `JKT-WS-2050` (`10.10.60.110`) ke `license.cadtool.example` | Tepat 3.600 detik, CV 0,004, jeda malam | Lisensi software desain jaringan FTTH; terdaftar di inventaris, tim engineering mengonfirmasi | Jinak | `SOC-2027-0653` ditutup; allowlist |
| `JKT-WS-2051` (`10.10.60.111`) ke `ping.remote-support.example` | 60 detik terus-menerus, 2.944 interval | Alat remote support yang dipasang teknisi vendor printer dua minggu lalu dan tidak dicopot | Jinak, tetapi tidak disetujui | Tiket IT untuk mencopot; alat remote access tanpa izin tetap risiko |
| `JKT-WS-2053` dan `JKT-WS-2054` ke `app.pmo-tracker.example` | 900 detik, dua host tim PMO | Uji coba aplikasi SaaS manajemen proyek | Jinak | Didaftarkan ke daftar aplikasi SaaS untuk ditinjau |
| `jkt-nms-script01` (`10.20.12.41`) ke `api.optic-vendor.example` | Interval beberapa detik, satu host, JA4 library (Day 06) | Skrip telemetri NOC | Jinak | Allowlist |
| `jkt-mailgw01` (`10.20.2.25`) ke `feeds.spamfilter-vendor.example` | 300 detik, sepanjang 144 jam | Update signature antispam | Jinak | Allowlist |
| `jkt-noc-mon01` long connection 26 jam | Satu tunnel 94.440 detik | Websocket dashboard vendor | Jinak | `SOC-2027-0651` ditutup |
| `SOC-2027-0650` SYN 8443 | 288 SYN ditolak | Tidak ada; "diblokir" bukan penjelasan | Bagian dari kandidat C2 | Digabung ke `INC-2027-070` |

Timeline `INC-2027-070` (Senin 2027-05-24, WIB):

| Waktu | Kejadian | Bukti |
|---|---|---|
| 08:15 | Sari menyalin log Zeek enam hari dan menjalankan RITA | Bagian 2.1, 2.5 |
| 09:35 | Temuan hunt dicatat sebagai `SOC-2027-0652` | Splunk |
| 09:58 | `CONNECT` dan log proxy mengikat beacon ke `10.10.60.112` (`JKT-WS-2052`) | Bagian 2.8 |
| 10:20 | MDE menunjukkan `nwassets.exe` di profil `rina.oktaviani` sebagai pembuat koneksi | Bagian 2.8 |
| 10:35 | Atasan Rina dan helpdesk IT memastikan tidak ada aplikasi "Northwind Assets" yang disetujui | Konfirmasi pemilik |
| 10:48 | Dimas membuka `INC-2027-070`; `SOC-2027-0650` dan `SOC-2027-0652` ditautkan | Tiket |
| 10:52 dan 10:53 | `*.northwind-cdn.example` diblokir di `jkt-proxy01`; `203.0.113.180` dan `.181` diblokir di `jkt-fw01` | Change log |
| 10:55 | MDE mengisolasi `JKT-WS-2052`; host diserahkan ke tim IR | MDE |
| 13:00 | Correlation search baru (bagian 2.7) berjalan pertama kali: hanya `JKT-WS-2052` dan pasangan yang sudah di-allowlist; temuan dicatat sebagai `SOC-2027-0654` dan ditutup sebagai duplikat | Splunk |

Ringkasan jaringan yang masuk tiket:

```
INC-2027-070  Handover data jaringan (Senin 2027-05-24 11:10 WIB)
Host          : JKT-WS-2052 (10.10.60.112), pengguna rina.oktaviani (Pengadaan)
Tujuan        : assets.northwind-cdn.example, share.northwind-cdn.example
                (203.0.113.180, 203.0.113.181; 203.0.113.181:8443 ditolak)
Jendela       : Kamis 2027-05-20 13:57:40 s.d. Senin 2027-05-24 07:59:41 WIB
Pola          : 96 check-in HTTPS lewat proxy, median 598 s, CV 0,149, MAD relatif 0,134
                96 percobaan TCP 8443 langsung (288 SYN), ~21 s sebelum tiap CONNECT
Anomali ukuran: 1 respons 184.330 B (Jumat 10:42:18), 1 kiriman 2.118.004 B (Jumat 15:13:40)
ATT&CK        : T1071.001 (didukung data jaringan); T1571 (percobaan 8443);
                T1573 dugaan, menunggu analisis host
Tingkat       : kandidat C2; kesimpulan menunggu IR
Belum diketahui: isi zip, cara eksekusi, isi kiriman 2,1 MB, host lain di luar sensor
Data          : /cases/HUNT-2027-05-24/ (log Zeek + sha256, CSV RITA, pcap Jumat 10:30-11:00)
```

**Cara membaca hasil:** enam dari tujuh pasangan berprevalence rendah punya pemilik yang bisa menjelaskan; satu tidak. Dua dari yang jinak tetap menghasilkan tindak lanjut (alat remote support dan SaaS tanpa registrasi): hunt beacon sering menemukan masalah tata kelola, bukan hanya serangan. Kiriman 2,1 MB hari Jumat ditandai untuk analisis exfiltration (Day 12).

**Kapan gagal:** bila pemilik tidak bisa dihubungi atau inventaris aplikasi tidak ada, langkah "pemilik tidak bisa menjelaskan" tertunda. Jangan menunggu bila ada tanda lain yang kuat (unduhan sebelum beacon, percobaan port tidak lazim, proses di folder pengguna); buka insiden di tingkat kandidat dan tulis apa yang belum dikonfirmasi.

### 2.12 Satu halaman jawaban untuk Dimas

| Pertanyaan | Jawaban singkat | Bagian |
|---|---|---|
| Beacon itu apa, kenapa tanda C2 | Koneksi berulang ke tujuan sama dengan interval teratur; C2 harus keluar dan bertanya berulang karena tidak bisa dihubungi dari luar | 1.1 |
| Jitter, cara mengukur | Ukur sebaran interval (CV setelah jeda dibuang, MAD relatif), bukan mencari interval persis; ambang program CV 0,2 | 1.2, 1.3, 2.3 |
| Skor RITA, skor 99 | Rata-rata empat subskor keteraturan; skor 99 `JAB DocSync` berarti sangat rapi, bukan jahat | 1.4, 2.5 |
| Siapa di balik proxy | `CONNECT` di `http.log` hop core dan log proxy; untuk kasus ini `JKT-WS-2052` | 1.5, 2.8 |
| Memisahkan yang sah | Prevalence, first seen, kategori proxy, proses di MDE, dan pemilik; 1.962 baris menjadi enam tujuan, lalu satu kandidat | 1.6, 1.7, 2.6, 2.11 |
| Koneksi 26 jam dan SYN 8443 | 26 jam: websocket dashboard NOC, jinak; SYN 8443: implant mencoba jalur langsung sebelum proxy, bagian dari kandidat | 1.8, 2.10 |
| Kapan C2, label ATT&CK | Insiden dibuka di tingkat kandidat (`INC-2027-070`); kesimpulan menunggu IR; T1071.001, T1571, T1573 sebagai dugaan | 1.9, 1.10, 2.11 |

Untuk rapat 15:00 dengan Pak Hendra dan Pak Bambang: hunt pertama menemukan satu kandidat C2 yang tidak terdeteksi alert mana pun selama empat hari (alert firewall ada, tetapi ditutup), memastikan beacon dari tiga insiden sebelumnya tidak muncul lagi di jendela sensor, dan menghasilkan satu correlation search harian serta allowlist berpemilik. Batasnya disebut juga: host di luar sensor, laptop di luar kantor, dan beacon yang lebih jarang dari beberapa kali sehari tidak tertangkap cara ini.

## 3. Lab praktik (di VM lab terisolasi)

**Prasyarat:** Wireshark 4.6.x dan/atau Zeek (log `conn.log`); pcap atau flow lab atau publik berisi trafik periodik (beacon simulasi dan trafik sah); RITA dibaca sebagai teks atau dipasang di VM lab; tidak ada data kerja. Jaringan host-only `192.168.56.0/24`: VM klien `192.168.56.10`, VM server web `192.168.56.20`, VM proxy Squid `192.168.56.30:3128`, dan VM sensor Zeek yang melihat kedua segmen.

Untuk trafik periodik buatan sendiri, cukup permintaan HTTP biasa dengan jeda acak dari VM klien, misalnya `while true; do curl -s -o /dev/null http://192.168.56.20/ping; sleep $((45 + RANDOM % 31)); done` (interval 45 sampai 75 detik). Ini trafik uji yang jinak, bukan implant; tidak ada kode C2 yang perlu ditulis atau diunduh.

1. **Kumpulkan.** Pilih satu tujuan berulang; kumpulkan timestamp koneksi (bagian 2.2).
2. **Periodisitas.** Hitung delta antar-koneksi; nilai keteraturan dan jitter dengan median, CV setelah jeda dibuang, dan MAD relatif (bagian 2.3). Bandingkan hasilnya dengan perkiraan teori untuk jitter plus minus 25% (bagian 1.3).
3. **Ukuran.** Periksa konsistensi ukuran check-in (bagian 2.4).
4. **Saluran.** Tentukan saluran (HTTP/S, DNS, TLS) dan baca metadata yang relevan (bagian 2.9).
5. **Skala.** Pakai RITA atau flow untuk memeringkat kandidat beacon (bagian 2.5), lalu stack hasilnya dengan prevalence (bagian 2.6).
6. **Proxy.** Ulangi langkah 1 sampai 5 dengan `curl -x http://192.168.56.30:3128 https://...` dari VM klien. Catat bagaimana `http.log` mencatat `CONNECT` dan apakah RITA menampilkan pasangan klien ke nama domain, pasangan proxy ke IP, atau keduanya (bagian 1.5 dan 2.8).
7. **Sah vs jahat.** Bandingkan tujuan dengan vendor dikenal dan reputasi; periksa JA3/JA4 (bagian 2.9). Nyatakan kemungkinan jinak.
8. **Sintesis.** Nilai keyakinan: sinyal beaconing atau kesimpulan C2; rencanakan korelasi host (bagian 1.10).

**Hasil yang sebaiknya tersimpan:**

- Timestamp koneksi ke satu tujuan dikumpulkan dan delta dihitung.
- Periodisitas dan jitter dinilai secara statistik, tidak hanya mencari interval persis; CV dan MAD relatif tercatat beserta jumlah jeda yang dibuang.
- Konsistensi ukuran check-in diperiksa.
- Saluran C2 dikenali dari metadata, bukan isi.
- Catatan perilaku RITA terhadap `CONNECT` di versi yang dipakai.
- Beacon jahat dibedakan dari trafik periodik sah dengan reputasi, JA3/JA4, dan konteks.
- Keyakinan dinyatakan; korelasi host direncanakan; IOC di-defang.

**Variasi tantangan:** diberi dua tujuan periodik (satu sah, satu beacon simulasi), tulis analisis komparatif: delta, jitter, ukuran, tujuan dan reputasi, JA3/JA4, dan konteks, lalu simpulkan mana yang mencurigakan dan mengapa, serta apa yang masih perlu dikonfirmasi di host. Tantangan kedua: naikkan jitter di skrip uji sampai CV melewati 0,2 dan catat pada titik mana skor RITA turun di bawah 70. Ini menyiapkan Day 13 (korelasi SIEM).

## 4. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Delta tampak acak | Jitter tinggi atau bukan beacon | Lihat distribusi; cari pusat meski ada sebaran; pakai MAD relatif, bukan hanya CV |
| CV besar padahal deret tampak rapi | Satu atau dua jeda panjang (PC tidur, akhir pekan) | Buang interval lebih dari tiga kali median dan catat jumlahnya (bagian 2.3) |
| Terlalu banyak kandidat | Banyak trafik periodik sah | Stack dengan prevalence, saring dengan reputasi/JA3/konteks (bagian 2.6) |
| Semua tujuan web bersumber satu IP | Proxy eksplisit | Pakai `CONNECT` di `http.log` hop core dan log proxy (bagian 2.8) |
| Beacon jarang terlewat | Sleep panjang; kurang dari empat koneksi | Perlu jendela waktu panjang (flow jangka panjang, log proxy 30 hari) |
| Ukuran bervariasi | Ada perintah/transfer | Variasi bisa aktivitas C2, bukan hanya check-in (bagian 2.4) |
| TLS tak terbaca | Terenkripsi | Pakai metadata (SNI, JA3/JA4) dan pola, bukan isi |
| JA4 sama dengan browser | Koneksi di-bump; ClientHello dibuat proxy | Fingerprint klien asli tidak ada di egress untuk sesi yang di-bump (Day 06) |
| Skor RITA tinggi tapi sah | Layanan periodik sah | Skor adalah prioritas; triage dengan konteks dan pemilik |
| Skor RITA berbeda antar dua instalasi | Konfigurasi berbeda (ambang 70 vs 75, modifier) | Bandingkan `/etc/rita/config.hjson` kedua instalasi (bagian 1.4) |
| Long connection tidak muncul | Koneksi belum selesai saat log dibaca | Cek analisis koneksi terbuka di RITA atau tunggu rotasi; `conn.log` ditulis saat koneksi selesai |
| `streamstats` lambat atau terpotong | Jumlah event besar | Jalankan per hari, pakai summary index |

## 5. Kesalahan umum dan jebakan

- **Mengira hanya interval persis yang beacon.** Jitter membuat beacon tidak persis; cari keteraturan statistik.
- **Mengira semua trafik periodik adalah C2.** Update, NTP, telemetri, lisensi, dan sinkronisasi juga periodik; reputasi, prevalence, dan pemilik yang memutuskan.
- **Membaca skor RITA sebagai skor kejahatan.** Skor 99 `JAB DocSync` adalah keteraturan; yang menentukan prioritas adalah konteks dan modifier.
- **Menyimpulkan C2 dari pola saja.** Beaconing adalah sinyal; konfirmasi butuh reputasi tujuan dan korelasi host.
- **Menghitung beacon per IP di belakang proxy.** Semua workstation menjadi satu sumber dan setiap tujuan berprevalence satu; pakai hop core.
- **Menutup alert karena "diblokir firewall".** Blokir menghentikan satu jalur; implant bisa punya jalur lain (bagian 2.10).
- **Menganggap ketiadaan beacon sebagai bersih.** Ketiadaan hanya berlaku untuk jendela dan titik pandang sensor; beacon jarang, pendek, atau berpola tidak teratur lolos.
- **Mengabaikan baseline.** Tanpa tahu normal, sulit menilai anomali; modifier first seen RITA tidak berguna sebelum data mencapai 30 hari.
- **Memberi label T1573 hanya karena ada TLS.** Tulis sebagai dugaan sampai analisis host menunjukkan enkripsi tambahan (bagian 1.9).
- **Mencoba membangun atau menganalisis payload C2.** Fokus deteksi pola; teknik C2 dirujuk ke ATT&CK dan nama atau ID test di katalog uji seperti Atomic Red Team, bukan ditulis.
- Pola kerja yang umum di hunting C2 adalah mendeteksi beaconing lewat keteraturan delta waktu (dengan toleransi jitter), konsistensi ukuran, dan jumlah koneksi ke tujuan tetap, lalu triage dengan reputasi dan konteks host; alat seperti RITA mengotomasi skor ini. Ini praktik komunitas yang belum dikonfirmasi satu sumber primer; ambang dan skor bergantung alat dan baseline, jadi ukur di lingkunganmu.

## 6. Catatan terkini

Bagian ini menampung status versi dan perubahan yang perlu diingat saat membaca materi beaconing per Oktober 2026.

- RITA v5.1.2 (7 Mei 2026) adalah rilis terbaru [S6]. RITA 5.x mengganti antarmuka lama berbasis subcommand per temuan (`show-beacons` dan sejenisnya di 4.x) dengan `import` dan `view`; tutorial lama masih memakai perintah 4.x [S4].
- Ambang kategori beacon di `default_config.hjson` (50/70/90) dan nilai bawaan di `config.go` (ambang rendah 75) berbeda; yang berlaku adalah file konfigurasi terpasang [S4][S8].
- ATT&CK v20.0: T1071.001 versi 1.5 (diubah 11 September 2026), T1573 versi 1.2, dan T1571 versi 1.3 (diubah 3 September 2026) [S3][S10][S11].
- C2 modern memakai jitter, sleep panjang, dan peniruan trafik sah (domain fronting, CDN, layanan cloud populer) untuk menghindari deteksi periodisitas sederhana; deteksi bergeser ke statistik dan korelasi multi-sinyal.
- Trafik agent AI berbasis Model Context Protocol mulai diteliti sebagai pola yang tidak cocok dengan heuristik beacon: makalah workshop IEEE ICNP NIPA 2026 melaporkan skor beacon RITA 0,0 untuk profil uji di lab penulisnya [S14]. Hasil itu terbatas pada testbed satu penulis dan perlu dicek ulang di lingkunganmu.
- Dengan isi hampir selalu terenkripsi, deteksi beaconing bersandar pada metadata (waktu, ukuran, SNI, JA3/JA4) dan baseline, bukan payload. ECH dan DNS terenkripsi mengurangi metadata itu (Day 15 dan 16).
- Alat seperti RITA (Active Countermeasures) dan modul beacon di SIEM mengotomasi pencarian beacon dari log Zeek dan flow.
- Day 12 (exfiltration) dan Day 13 (integrasi SIEM) melanjutkan.

## 7. Cheat sheet

```
BEACON     koneksi berulang + interval teratur + tujuan tetap + ukuran mirip kecil + durasi pendek
JITTER     variasi acak interval (mis. 60s +-20%) untuk evasion -> cari keteraturan STATISTIK, bukan persis
UKUR       kumpulkan ts koneksi ke 1 dst -> delta -> buang jeda > 3x median -> CV, MAD/median, Bowley
           jitter merata +-j: CV ~ j/1,732 ; MAD rel ~ j/2 ; ambang PT JAB CV <= 0,2, n >= 24, median 30 s-4 jam
SALURAN    HTTP/S (POST/GET berkala, SNI/JA3 tetap) | DNS (query berkala/tunneling) | TLS (JA3 khas) | port tak lazim
PROXY      egress: sumber = proxy, JA4 bump = milik proxy ; workstation dari http.log method=CONNECT + log proxy
TOOL       RITA 5.x: import --database=X --logs=DIR ; view X ; beacon:>=70 ; view --stdout X > x.csv
           skor = 0,25 x (timestamp + datasize + duration + histogram) ; min 4 koneksi unik
           ambang hjson: <50 di bawah dasar, 50 rendah, 70 sedang, 90 tinggi ; modifier prevalence/first seen +-0,15
LONGCONN   RITA 1/4/8/12 jam ; conn.log ditulis saat koneksi selesai
PORT       S0 berulang ke port tak lazim (TAP di dalam firewall) = jejak T1571 + identitas host asli
SAH?       update/NTP/telemetry/keep-alive/sync/lisensi periodik juga ; bedakan via prevalence+first seen+proses+pemilik
BASELINE   tanpa normal, anomali tak jelas ; bangun dari flow/Zeek jangka panjang
SINYAL!=C2 indikator -> kandidat C2 (buka insiden) -> kesimpulan C2 (butuh host/IR)
TEKNIK     T1071.001 | T1571 | T1573 (dugaan bila hanya TLS) | T1090 = perantara milik penyerang ; JANGAN tulis payload
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** Sebuah pasangan mendapat skor beacon RITA 99. Bolehkah laporan hunt menulis "kemungkinan besar C2"?

<details><summary>Jawaban</summary>

Tidak. Skor beacon mengukur keteraturan dari empat subskor (timestamp, data size, duration, histogram), bukan niat. Agent sah seperti `JAB DocSync` sering lebih rapi daripada implant berjitter; di hunt PT JAB, DocSync mendapat 99 sementara beacon yang benar mencurigakan hanya 81. Skor adalah prioritas pemeriksaan; kandidat C2 butuh prevalence, first seen, proses, dan pemilik yang tidak bisa menjelaskan.

Lihat bagian 1.4 dan 2.5.

</details>

**2. Hitung.** Interval sebuah pasangan setelah jeda dibuang punya rata-rata 300 detik dan deviasi standar 66 detik. Dengan ambang program PT JAB, apakah pasangan ini lolos, dan kira-kira berapa jitter-nya bila jitter tersebar merata?

<details><summary>Jawaban</summary>

CV = 66 / 300 = 0,22, di atas ambang 0,2, jadi tidak lolos query Splunk. Untuk jitter merata plus minus j, CV sekitar j / 1,732, sehingga j sekitar 0,22 x 1,732 = 0,38, atau plus minus 38%. Pasangan ini masih bisa muncul di RITA, karena subskor timestamp memakai MAD dan Bowley skewness, bukan CV. Itulah alasan query CV adalah pelengkap, bukan pengganti.

Lihat bagian 1.3, 1.4, dan 2.7.

</details>

**3. Skenario keputusan.** Di daftar RITA, sepuluh baris teratas bersumber `10.20.3.60`. Apa langkah pertamamu?

- A. Isolasi `10.20.3.60` karena menghubungi banyak tujuan secara periodik.
- B. Cari baris `CONNECT` di `http.log` hop core dan log proxy untuk tujuan itu, untuk menemukan workstation di baliknya.
- C. Abaikan semua baris dari proxy karena proxy memang sibuk.

<details><summary>Jawaban</summary>

B. `10.20.3.60` adalah proxy eksplisit; setiap koneksi web workstation keluar dengan alamat itu. A memutus seluruh akses web kantor tanpa menyentuh host yang sebenarnya. C membuang beacon yang nyata, karena tujuan seperti `203.0.113.180` hanya terlihat sebagai baris proxy di hop egress.

Lihat bagian 1.5 dan 2.8.

</details>

**4. Pertanyaan jebakan.** Alert "workstation keluar langsung ditolak, lebih dari 50 per hari" ditutup L1 dengan alasan "diblokir firewall, tidak berdampak". Apa yang salah?

<details><summary>Jawaban</summary>

Blokir menghentikan satu jalur, bukan proses yang mencoba. Di `INC-2027-070`, 96 percobaan ke `203.0.113.181:8443` ditolak, tetapi implant yang sama berhasil keluar lewat proxy 21 detik setelah setiap percobaan. Pertanyaan untuk alert seperti ini adalah proses apa yang mencoba dan apakah ia berhasil lewat jalan lain.

Lihat bagian 2.10.

</details>

**5. Skenario keputusan.** Hunt menemukan satu workstation menghubungi `ping.remote-support.example` setiap 60 detik selama dua minggu. Pemiliknya menjelaskan alat itu dipasang teknisi vendor printer dan lupa dicopot. Disposisi mana yang tepat?

- A. Kandidat C2; buka insiden.
- B. Jinak; tutup tanpa tindak lanjut.
- C. Jinak secara asal-usul, tetapi alat remote access tanpa izin; tiket IT untuk mencopot dan catat sebagai temuan tata kelola.

<details><summary>Jawaban</summary>

C. Ada pemilik yang bisa menjelaskan, jadi pola itu bukan kandidat C2 (A keliru). Namun alat remote access yang tidak disetujui tetap membuka akses dari luar, sehingga menutup tanpa tindak lanjut (B) meninggalkan risiko. Hunt beacon sering menemukan masalah tata kelola seperti ini.

Lihat bagian 1.6 dan 2.11.

</details>

**6. Pertanyaan jebakan.** Hunt enam hari di `jkt-zeek01` tidak menemukan koneksi ke `203.0.113.170`. Bolehkah laporan menulis "beacon `INC-2027-065` sudah berhenti total"?

<details><summary>Jawaban</summary>

Hanya dengan batas. Ketiadaan itu berlaku untuk jendela 18 sampai 24 Mei dan untuk trafik yang lewat titik pandang sensor (TAP egress Jakarta dan SPAN core data center). Ia tidak menjangkau masa sebelum sensor hidup, host di kantor cabang, laptop di luar kantor, atau beacon yang pindah ke alamat lain. Kalimat yang tepat: "tidak ada koneksi ke alamat itu yang terlihat sensor antara Selasa 08:00 dan Senin 08:00".

Lihat bagian 1.7 dan 2.1.

</details>

**7. Interview question (English).** "You run a beacon-hunting tool over a week of Zeek logs and get two thousand results. Walk me through how you get from that list to an incident, and what you would and would not claim."

<details><summary>Sample answer</summary>

"First I'd check the data itself: that the week is complete, and whether a web proxy sits in the path, because then the egress view collapses every workstation into one source and I need the CONNECT records on the inside hop. Then I'd stack the results by destination prevalence. Destinations used by hundreds of hosts are almost always update, security, or sync agents, so I'd review them separately for rare fingerprints rather than one by one. The handful of destinations with one or two sources get triage: first seen, domain age, proxy category, the process behind the connection from EDR, and above all an owner who can explain it. If nobody can explain a new, single-host destination, especially with supporting signs like a download just before the first check-in or failed attempts on an odd port, I'd open an incident at the candidate level and hand it to IR. What I would not claim from network data alone is that the host is compromised or what the channel carried; the score measures regularity, not intent, and absence of beacons only covers what the sensor sees."

What makes this answer strong: it starts with data quality and the proxy blind spot, reduces volume with prevalence instead of reading rows, names concrete triage signals including ownership, and separates indicator, candidate, and conclusion explicitly.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | MITRE ATT&CK: Command and Control (taktik TA0011) | https://attack.mitre.org/tactics/TA0011/ | primer | diakses 2026-10-09, dicek ulang 2026-10-22 | Tinggi. Kerangka teknik C2 |
| S2 | Zeek docs: Logs (conn.log, http.log; ts, bytes, duration, conn_state) | https://docs.zeek.org/en/current/logs/index.html | primer | diakses 2026-10-09 (Day 08), dicek ulang 2026-10-22 | Tinggi. Data pengukuran dan nama field |
| S3 | MITRE ATT&CK T1071 Application Layer Protocol (dan sub-teknik T1071.001 Web Protocols, https://attack.mitre.org/techniques/T1071/001/; teknik terkait di TA0011: T1568, T1090) | https://attack.mitre.org/techniques/T1071/ | primer | diakses 2026-10-10, dicek ulang 2026-10-22 | Tinggi. Definisi teknik C2 di tabel bagian 1.9; T1071.001 versi 1.5, diubah 11 September 2026 |
| S4 | activecm/rita: README dan default_config.hjson (RITA 5.x) | https://github.com/activecm/rita | primer (repo resmi alat) | diakses 2026-10-10, dicek ulang 2026-10-23 | Tinggi. Perintah `import`/`view`, flag `--rolling`, sintaks pencarian, empat subskor beacon berbobot 0,25, minimal 4 koneksi unik, ambang 50/70/90, ambang long connection 1/4/8/12 jam, nilai modifier |
| S5 | Network-Forensics Day 01-10 (lokal) | (lokal) | rujukan internal | 2026-10-09, diperbarui 2026-10-23 | Sensor, proxy, Zeek, Suricata, flow, TLS, dan insiden PT JAB sebelumnya |
| S6 | activecm/rita: rilis v5.1.2 | https://github.com/activecm/rita/releases/tag/v5.1.2 | primer (halaman rilis resmi) | rilis 7 Mei 2026, diakses 2026-10-23 | Tinggi. Versi terbaru per tanggal riset |
| S7 | activecm/rita: `analysis/beacons.go` (cabang main) | https://github.com/activecm/rita/blob/main/analysis/beacons.go | primer (kode sumber) | diakses 2026-10-22 | Tinggi untuk cara hitung subskor; kode bisa berubah di rilis berikutnya |
| S8 | activecm/rita: `config/config.go` dan `docs/Configuration.md` (cabang main) | https://github.com/activecm/rita/blob/main/config/config.go | primer (kode sumber dan dokumentasi repo) | diakses 2026-10-22, dicek ulang 2026-10-23 | Tinggi. Nilai bawaan di kode (ambang rendah 75), ambang duration 6 dan 12, komentar tentang kategori critical; dokumentasi di https://github.com/activecm/rita/blob/main/docs/Configuration.md |
| S9 | activecm/rita: `database/tables.go` (cabang main) | https://github.com/activecm/rita/blob/main/database/tables.go | primer (kode sumber) | diakses 2026-10-22, dicek ulang 2026-10-23 | Sedang-tinggi. Request `CONNECT` di `http.log` ditambahkan sebagai koneksi proxy; kolom alamat proxy; perilaku di `view` perlu diuji di lab |
| S10 | MITRE ATT&CK T1573 Encrypted Channel | https://attack.mitre.org/techniques/T1573/ | primer | diakses 2026-10-22, dicek ulang 2026-10-23 | Tinggi. Versi 1.2, diubah 3 September 2026; sub-teknik .001 dan .002 |
| S11 | MITRE ATT&CK T1571 Non-Standard Port | https://attack.mitre.org/techniques/T1571/ | primer | diakses 2026-10-22 | Tinggi. Versi 1.3, diubah 3 September 2026; contoh HTTPS di port 8088; analitik deteksi |
| S12 | Microsoft Learn: Windows Time Service Tools and Settings | https://learn.microsoft.com/en-us/windows-server/networking/windows-time-service/windows-time-service-tools-and-settings | primer | diperbarui 2026-02-16, diakses 2026-10-23 | Tinggi. Hierarki domain, PDC emulator, `MinPollInterval`/`MaxPollInterval`, `SpecialPollInterval` |
| S13 | Microsoft Learn: DeviceNetworkEvents table in the advanced hunting schema | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table | primer | diperbarui 2026-06-26, diakses 2026-10-23 | Tinggi. Kolom `RemoteIP`, `RemotePort`, `RemoteUrl`, `InitiatingProcess*` |
| S14 | Sohail, "When Agents Look Like Beacons: NIDS Evasion by Model Context Protocol Traffic" (IEEE ICNP Workshop NIPA 2026), arXiv:2609.19091 | https://arxiv.org/abs/2609.19091 | sekunder (makalah workshop, satu penulis) | terbit 2026-09-16, diakses 2026-10-23 | Sedang. Skor beacon RITA 0,0 untuk trafik MCP dengan jeda lognormal; terbatas pada testbed penulis |
| S15 | Splunk Research: Data Source Bro http | https://research.splunk.com/sources/c5d9612b-0ffd-44d3-8247-3cf3486ec5e2/ | primer | diakses 2026-10-22, dicek ulang 2026-10-23 | Tinggi untuk sourcetype `bro:http:json` dan TA for Zeek 1.0.11; tidak memuat daftar field |

**Catatan sumber:** metode pengukuran beaconing (delta, jitter, konsistensi ukuran) adalah pengetahuan NSM dan hunting yang mapan. Perkiraan CV dan MAD untuk jitter merata adalah aritmetika distribusi seragam, bukan klaim dokumentasi alat. Bobot, ambang, dan modifier RITA mengikuti konfigurasi bawaan 5.x di repo resmi [S4][S8] dan cara hitung di kode [S7]; nilai di kode dan di `default_config.hjson` berbeda untuk ambang rendah, dan keduanya bisa diubah per instalasi, jadi cek `/etc/rita/config.hjson` di lab-mu. Perlakuan RITA terhadap `CONNECT` dibaca dari kode basis data [S9], bukan dari dokumentasi pengguna, sehingga tampilan persisnya perlu diuji. Jeda 21 detik sebelum `CONNECT` dijelaskan dengan perilaku retransmisi SYN bawaan Windows yang tidak dikutip dari sumber di tabel ini; cek di host. Ambang CV 0,2 dan aturan tiga kali median adalah ketetapan program PT JAB yang fiktif; ambang baseline di lingkunganmu perlu diukur sendiri. Teknik C2 dirujuk ke ATT&CK, bukan ditulis sebagai payload. Pembedaan dari trafik sah bergantung reputasi dan konteks lingkungan. Semua host, domain, alamat, dan angka PT JAB fiktif; domain memakai `.example` dan alamat memakai rentang dokumentasi.
