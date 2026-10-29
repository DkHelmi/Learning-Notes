---
day: 14
title: 'Capstone network forensics: satu insiden PT JAB dari pcap sampai laporan dengan metode kerja v1.0, template write-up pcap, dan template integrasi Zeek ke Splunk'
researched_on: 2026-10-29
versions_checked: 'Wireshark 4.6.9 stabil, 4.4.19 old stable, 5.0.0rc1 rilis pengembangan (halaman unduhan, dicek 2026-10-29); Zeek 9.0.1 LTS (26 Okt 2026), LTS sebelumnya 8.0.11 (dalam cerita jkt-zeek01 masih 9.0.0); Suricata 8.0.7 (15 Sep 2026), cabang 7.0.x EOL; TA for Zeek 1.0.11 (Splunkbase 5466, 21 Agu 2025, dirawat Corelight; Splunk 9.3, 9.4, 10.0 sampai 10.7; CIM 6.x); Splunk CIM 6.2 data model Network Traffic (All_Traffic, tag network dan communicate); Zeek SMB::logged_file_actions bawaan tanpa SMB::FILE_READ; MITRE ATT&CK v20: T1105 v2.6 (11 Sep 2026), T1567.002 v1.3 (12 Mei 2026), T1071.001, T1573, T1039, T1560, T1030, T1048.002; rujukan Day 01-13'
---

# Day 14: Capstone network forensics dari pcap sampai laporan

Cakupan: satu insiden PT JAB dikerjakan utuh dengan metode kerja v1.0 (pertanyaan dan bukti, orientasi, pembatasan, protokol, pola, korelasi, write-up), lalu dibakukan menjadi template write-up pcap dan template integrasi Zeek ke Splunk, ditambah kasus tertulis untuk latihan di lab pribadi dan rubrik penilaian diri.

Day penutup ini tidak menambah materi serangan baru. Semua entitas, IP, domain, hash, dan angka fiktif; IOC di-defang di laporan; teknik serangan hanya diberi label ATT&CK untuk tahap yang didukung bukti.

## Ide inti

Capstone tidak menguji apakah kamu bisa menemukan penyerang. Ia menguji apakah Day 01 sampai 13 sudah menyatu menjadi satu kemampuan: menerima insiden yang berantakan, menulis pertanyaannya, mengamankan bukti sebelum ring buffer menimpanya, membaca data dari titik pandang yang benar, mengukur pola dengan angka yang bisa dihitung ulang, menyambung jaringan dengan host, lalu menulis laporan yang memisahkan bukti dari kesimpulan dan jujur tentang apa yang tidak terlihat. Insiden nyata hampir selalu punya tahap yang buta (pemicu di host, isi TLS, lalu lintas antar workstation), dan laporan yang baik justru terlihat dari cara ia menulis kebutaan itu. Dua produk lahir dari capstone dan dipakai ulang sesudahnya: template write-up pcap untuk setiap insiden jaringan, dan template integrasi Zeek ke Splunk untuk setiap sensor atau sumber log baru.

Capstone juga memperlihatkan hal yang tidak terlihat di latihan satu Day: alert yang benar bisa tetap terlambat. Bila tiga alert rendah dan sedang di host yang sama diperiksa terpisah oleh shift berbeda, organisasi baru tahu ketika data sudah keluar. Bagian laporan yang paling berguna untuk manajemen sering bukan timeline serangan, tetapi timeline deteksi.

Analoginya uji terima (acceptance test) link baru di NOC sebelum diserahkan ke pelanggan: semua komponen yang sudah diuji satu per satu (optik, routing, QoS, monitoring) diuji bersama dengan trafik nyata, dan hasilnya ditulis dalam satu berita acara yang bisa diperiksa orang lain. Write-up adalah RFO (reason for outage) untuk insiden keamanan, dan template integrasi adalah checklist onboarding perangkat ke NMS: community SNMP, polling, template grafik, threshold, dan uji alarm. Batas analoginya: uji terima memakai trafik uji yang bisa diulang, sedangkan capstone ini memakai insiden nyata yang tidak bisa diputar ulang; dan RFO menulis akar masalah sebagai kepastian, sedangkan write-up keamanan menulis tingkat keyakinan per kesimpulan dan batasnya.

```
 Rabu 2027-06-02 (WIB)                                   Kamis 2027-06-03 (WIB)
 16:47 unduhan PE    16:48 kanal tiap ~60 s    22:41 baca SMB     00:20 unggah 31 pecahan    01:31 isolasi
   |                   |                         |                  |                          |
   v                   v                         v                  v                          v
 http.log/files.log  http.log CONNECT          smb_*.log          http.log CONNECT + conn    MDE
 (hop core + egress) ssl.log/x509 (egress)     conn resp_bytes    flow DC + edge             |
   |                   |                         |                  |                          v
 SOC-0665 (ditutup)  SOC-0667 (antrean pagi)   (tanpa alert)      SOC-0669 00:45           INC-2027-073
 SOC-0666 (MDE rendah)                         SOC-0668 scanner (FP)
        \___________________ metode v1.0: 0 bukti | 1 orientasi | 2 batasi | 3 protokol | 4 pola | 5 korelasi | 6 write-up
                                                   |
                                                   v
                     write-up final + template write-up + template integrasi Zeek ke Splunk + satu halaman untuk Hendra
```

Situasi Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan sekitar 1.200 karyawan, kantor pusat dan data center di Jakarta, serta NOC 24/7 yang satu lantai dengan SOC. Sejak Senin 2027-05-03 PT JAB menjalankan "Program NSM PT JAB" sebagai percobaan Mei sampai Juli 2027. Per pekan ini, `jkt-zeek01` (`10.20.70.12`, Zeek 9.0.0, produksi sejak 2027-05-18) dan `jkt-ids01` (`10.20.70.11`, Suricata 8.0.7, sejak 2027-05-19) membaca SPAN core switch data center (hop core) dan TAP egress Jakarta di sisi dalam `jkt-fw01` (hop egress) lewat packet broker `jkt-npb01`; `jkt-pcap01` (`10.20.70.13`) menyimpan pcap egress dengan ring buffer yang di bulan Juni menjangkau sekitar 81 sampai 86 jam; `jkt-flow01` (`10.20.70.14`) menerima flow router data center (1:1) dan router edge (1:1000). Workstation keluar ke web lewat proxy eksplisit `jkt-proxy01` (`10.20.3.60:3128`, Squid: domain baru atau tidak terkategori di-bump, kategori dikenal di-splice). Log Zeek masuk Splunk di index `zeek` (sourcetype `bro:<log>:json`), alert Suricata di index `suricata`. Analisis dikerjakan di `jkt-nsm-ws01` (`10.20.70.20`) dengan metode kerja v1.0 yang dibakukan Senin 2027-05-31 (Day 13).

Rabu malam, shift malam Dwi Cahyono (L1) dengan Rudi Hartanto (L2) sebagai on-call menerima alert volume keluar `SOC-2027-0669` pukul 00:45. Rudi membuka `INC-2027-073` pukul 01:25 dan `JKT-WS-2066` diisolasi lewat Microsoft Defender for Endpoint (MDE) pukul 01:31:12. Kamis 2027-06-03 pukul 07:30, Dimas Prasetyo (SOC lead) menulis kepadamu:

> "Latihan jam 15 dengan Pak Hendra kita pakai INC-2027-073 yang dibuka Rudi semalam, bukan kasus lama. Kasus nyata, metode v1.0, dari pcap sampai laporan. Pak Hendra pasti tanya: apa yang terjadi dan sejak kapan, apa yang keluar dan seberapa yakin kita, kenapa baru ketahuan jam satu pagi padahal alert pertamanya sore, ada host lain atau tidak, dan apa yang harus diperbaiki. Bu Nina dan Pak Agus ikut karena yang dibaca share Keuangan. Pakai format write-up final, satu template untuk semua insiden jaringan mulai sekarang, dan jangan tulis C2 sebelum Yoga bilang."

Pukul 07:50, Sari Kusuma (analyst L2) menambahkan:

> "Pak Hendra juga minta integrasi Zeek ke Splunk dibakukan sebelum fase Juli, supaya sensor berikutnya tidak mengulang masalah index constraint minggu lalu. Aku butuh satu template integrasi yang bisa dicentang, termasuk daftar search mana yang menyala dan mana yang diam semalam, dan kenapa."

Dua pesan itu memuat tujuh pertanyaan:

1. Apa yang terjadi pada `JKT-WS-2066`, dalam urutan apa, dan sejak kapan?
2. Apa yang keluar, berapa, ke mana, dan seberapa yakin?
3. Kenapa baru ketahuan pukul 00:45 padahal alert pertama menyala 16:47?
4. Adakah host lain yang terdampak, dan apa yang tidak bisa dilihat?
5. Seperti apa write-up final, dan template apa yang dipakai tim mulai sekarang?
6. Seperti apa template integrasi Zeek ke Splunk, dan search mana yang menyala atau diam semalam?
7. Apa yang dibawa ke Hendra, Nina, dan Agus dalam satu halaman?

Pertanyaan 1 dijawab di bagian 1.2 dan Bagian B sampai F, pertanyaan 2 di bagian 1.3 dan Bagian F dan I, pertanyaan 3 di bagian 1.6 dan Bagian G, pertanyaan 4 di Bagian H, pertanyaan 5 di bagian 1.4 dan Bagian J dan K, pertanyaan 6 di bagian 1.5 dan Bagian L, dan pertanyaan 7 di Bagian M. Bagian A adalah langkah 0, bagian 1.1 memetakan Day 01 sampai 13 ke metode, dan Bagian N adalah kasus tertulis untuk lab pribadi.

**Kapan relevan:** saat menutup insiden jaringan dari pcap sampai laporan untuk IR, manajemen, dan DPO; saat menyiapkan template write-up atau onboarding log baru ke SIEM; saat menilai kenapa deteksi yang benar terlambat; dan sebelum interview tentang investigasi jaringan end-to-end.
**Kapan bukan jawaban:** capstone tidak menggantikan pengetahuan protokol dan pola di Day 03 sampai 12; bila satu langkah macet, kembali ke Day asalnya. Capstone juga tidak menjawab pertanyaan host (proses, persistence, isi berkas): itu bagian IR. Topik Day 15 sampai 19 (ECH, DNS terenkripsi, cloud, capture skala besar, lateral movement) juga di luar capstone ini.

## 1. Ringkasan, peta konsep, dan glosarium

Bagian ini merangkai Day 01 sampai 13 menjadi alat kerja capstone. Detail perintah, angka, dan sumbernya tetap ada di Day asal; ringkasan di sini mewarisi sumber dan tingkat keyakinan Day asalnya [S5].

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (pcap kasus, hop core dan hop egress, `uid`, `community_id`, splice dan bump, beacon, CV, PCR, prevalence, metode kerja, kriteria berhenti, tingkat keyakinan, CIM, index constraint, `summariesonly`) tidak diulang; definisinya ada di Day 01 sampai 13 dan diringkas di glosarium bagian 1.7. Tabel ini hanya memuat istilah yang baru dipakai Day ini.

| Istilah | Arti singkat | Padanan di NOC/ISP |
|---|---|---|
| Capstone | Satu insiden yang dikerjakan penuh dengan semua alat dan metode, sampai laporan dan perbaikan | Uji terima end-to-end link baru sebelum serah terima |
| Write-up final | Laporan insiden jaringan dengan template baku tim, siap dibaca IR, manajemen, dan DPO | RFO gangguan besar yang dipresentasikan ke direksi |
| Template integrasi | Checklist berlapis untuk membawa satu sumber log ke SIEM sampai search di atasnya terbukti menyala | Checklist onboarding perangkat ke NMS sampai alarm uji terbukti muncul |
| Timeline deteksi | Daftar kapan setiap alert menyala, siapa yang memegangnya, dan apa keputusannya, terpisah dari timeline serangan | Kronologi tiket: kapan alarm muncul, kapan di-acknowledge, kapan dieskalasi |
| Dwell time deteksi | Selisih antara alert pertama yang benar dan saat insiden dibuka | Waktu dari alarm pertama sampai tiket gangguan dinaikkan |
| Korelasi per host | Menggabungkan alert dari sumber berbeda (Suricata, saved search, MDE) per host dalam satu jendela, sehingga beberapa sinyal lemah menjadi satu prioritas | Korelasi alarm per node: lima alarm minor di satu router dalam satu jam dinaikkan jadi satu major |
| Rubrik penilaian diri | Daftar aspek berskor untuk menilai write-up sendiri atau milik rekan sebelum dikirim | Checklist acceptance test sebelum berita acara ditandatangani |
| Kasus tertulis | Artefak fiktif yang sudah disiapkan untuk latihan metode di luar pekerjaan | Soal troubleshooting di lab pelatihan NOC |

### 1.1 Peta Day 01-13 ke metode kerja v1.0

Dimas meminta "kasus nyata, metode v1.0", jadi capstone memakai tujuh langkah Day 13 bagian 1.2 tanpa mengubahnya. Tabel berikut adalah peta yang dipegang sepanjang hari: setiap langkah, Day yang menyediakan alatnya, dan kebiasaan yang diuji. Baca kolom terakhir sebagai daftar kesalahan yang paling mungkin terjadi pada kasus ini.

| Langkah v1.0 | Day asal | Yang dipakai di capstone | Kebiasaan yang diuji |
|---|---|---|---|
| 0 Pertanyaan dan bukti | Day 01, 02, 13 | Potong pcap egress dari ring, salin arsip Zeek per tanggal UTC, hash | Jendela ditulis dalam WIB dan UTC; bukti diamankan sebelum analisis panjang |
| 1 Orientasi | Day 02, 08 | `capinfos`, Conversations, hitungan per sourcetype | Tiga sampai lima kalimat isi data, termasuk capture loss |
| 2 Pembatasan | Day 03, 12, 13 | Hop core untuk workstation, hop egress untuk IP dan SNI | Tidak mencari workstation di pcap egress |
| 3 Protokol | Day 03, 05, 06, 08 | `http.log`, `files.log`, `ssl.log`, `x509.log`, `smb_mapping.log`, `smb_files.log` | Magic byte dan `mime_type`, bukan ekstensi; splice atau bump menentukan pemilik ClientHello |
| 4 Pola | Day 04, 10, 11, 12 | Interval dan CV kanal, volume per `uid`, pecahan seragam, baseline flow 13 bulan | Angka pola dihitung, dibandingkan baseline, penjelasan jinak diuji |
| 5 Korelasi | Day 09, 10, 11, 13 | `community_id`, flow DC dan edge, log proxy, MDE, prevalence | Label tinggi hanya dengan dua sumber independen atau korroborasi host |
| 6 Write-up | Day 07, 12, 13 | Template bagian 1.4, timeline WIB, IOC lima kolom, batas, pertanyaan terbuka | Ringkasan ditulis terakhir; "C2" menunggu IR |

### 1.2 Rantai intrusi dari sudut jaringan

Pertanyaan pertama Dimas meminta urutan, dan rantai intrusi punya tahap yang terlihat dan tidak terlihat dari sensor. Tabel berikut dipakai untuk menulis bagian "Temuan per tahap": kolom kedua adalah sumber jaringan PT JAB yang bisa membuktikan tahap itu, kolom ketiga apa yang harus datang dari host.

| Tahap | Bukti jaringan di PT JAB | Butuh host (MDE, IR) | Label ATT&CK bila didukung |
|---|---|---|---|
| Pemicu (email, lampiran, skrip) | Hampir tidak ada; proxy hanya mencatat unduhan sesudahnya | Proses induk, berkas yang dibuka | Tidak dilabeli dari jaringan |
| Masuknya alat | `http.log` dan `files.log` kedua hop, log proxy, pcap egress (isi utuh bila HTTP polos) | Proses yang mengunduh, tempat berkas ditulis | T1105 Ingress Tool Transfer [S1][S9] |
| Kanal berkala | `CONNECT` di hop core, `ssl.log` dan `x509.log` di hop egress, log proxy | Proses yang membuat koneksi, fungsi berkas | T1071.001 dan T1573 setelah fungsi dikonfirmasi [S1] |
| Pengumpulan dari share | `smb_mapping.log`, `smb_files.log`, `conn.log` ke port 445 di hop core | Proses yang membaca | T1039 Data from Network Shared Drive [S1] |
| Pemaketan | Tidak terlihat (lokal di host) | Berkas arsip dan ukurannya | T1560 (dugaan sampai host mengonfirmasi) |
| Pengiriman | `CONNECT` dan `conn.log` per `uid` di hop core, `conn.log` dan `ssl.log` hop egress, flow DC dan edge | Proses yang mengirim | T1030, T1567.002 bila ke layanan penyimpanan [S8] |

Prinsipnya sama dengan Day 12 bagian 1.9: label diberikan untuk tahap yang didukung data, label dugaan ditulis sebagai dugaan, dan tahap tanpa bukti tidak dilabeli hanya supaya rantainya terlihat lengkap. Untuk "masuknya alat", ATT&CK v20 (T1105 versi 2.6) menyebut utilitas bawaan Windows seperti `certutil` sebagai cara mengunduh alat ke host korban [S9], dan proyek LOLBAS mencatat bahwa unduhan `certutil` membawa User-Agent `Microsoft-CryptoAPI/10.0` atau `CertUtil URL Agent` [S10]. User-Agent itu juga dipakai Windows untuk urusan sertifikat yang sah, jadi ia sinyal, bukan bukti. T1567.002 menekankan bahwa trafik ke layanan penyimpanan yang biasa dipakai mudah berbaur [S8]; karena itu baseline dan prevalence wajib ada.

### 1.3 Bukti, kesimpulan, dan keyakinan di kasus berlapis

Pertanyaan kedua Dimas ("seberapa yakin") punya jawaban berbeda untuk setiap tahap, dan satu label untuk seluruh laporan menyesatkan. Aturan Day 13 bagian 1.5 berlaku per kalimat kesimpulan: rendah untuk satu sinyal jaringan, sedang untuk beberapa sinyal jaringan independen dengan penjelasan jinak utama sudah diuji, tinggi untuk sinyal jaringan ditambah korroborasi host atau pemilik, atau angka yang cocok dari dua sumber independen.

Di kasus berlapis, keyakinan tiap tahap bergerak sepanjang hari, dan write-up harus menunjukkan kapan dan karena apa label naik. Pola yang muncul di capstone ini:

- **Volume keluar** bisa langsung tinggi dari jaringan saja, karena Zeek hop core, flow router data center, dan flow edge adalah sumber independen (Day 12 bagian 2.2). Yang tetap tidak diketahui adalah isinya.
- **Kanal berkala** naik dari "kandidat beacon, sedang" menjadi "kanal dari proses yang memuat berkas unduhan, tinggi" setelah MDE menunjukkan proses dan jumlah koneksi yang sama. Kata "C2" baru dipakai setelah IR menyatakan fungsi berkas (Day 13 bagian 2.8).
- **Jenis data yang keluar** tetap paling rendah keyakinannya. Urutan (baca share, arsip dibuat, unggah) dan kecocokan ukuran adalah bukti tidak langsung; nama folder share adalah bukti bahwa folder itu dibuka, bukan bahwa isinya yang terkirim.

Dua kesalahan berlawanan sering muncul: menurunkan semua label ke tahap terlemah ("tidak tahu apa-apa karena terenkripsi") atau menaikkannya ke tahap terkuat ("1,6 GB data Keuangan bocor"). Label di kolom terpisah dari kalimat bukti mencegah keduanya.

### 1.4 Template write-up pcap: kenapa setiap bagian ada

Pertanyaan kelima Dimas meminta satu template untuk semua insiden jaringan. Template final memakai urutan dan nama bagian kerangka Day 13 bagian 1.6, ditambah dua hal yang muncul di capstone: timeline deteksi dan label keyakinan per kesimpulan. Tabel berikut menjelaskan fungsi tiap bagian dan kesalahan yang dicegahnya; template kosongnya ada di Bagian K dan contoh terisinya di Bagian J.

| Bagian | Fungsi | Kesalahan yang dicegah |
|---|---|---|
| Kepala (nomor, analis, versi, status label) | Identitas dokumen dan versi, karena write-up diperbarui saat IR menemukan fakta baru | Dua versi beredar tanpa tanda mana yang terbaru |
| Ringkasan | Satu paragraf: apa, sejak kapan, dampak, keyakinan, apa yang belum diketahui; ditulis terakhir | Kesimpulan mendahului bukti |
| Timeline (WIB, sumber per baris) | Urutan kejadian; UTC di kolom terpisah untuk baris dari pcap | Campuran zona waktu, baris tanpa sumber |
| Timeline deteksi | Kapan alert menyala, siapa memegang, keputusannya | Perbaikan proses hilang di balik cerita serangan |
| Temuan per tahap | Bukti per tahap dan label ATT&CK yang didukung | Label untuk tahap tanpa bukti |
| IOC (lima kolom) | Nilai ter-defang, tipe, ditemukan di, keyakinan, pemakaian | Layanan bersama diblokir sebagai IOC; fingerprint proxy dianggap fingerprint klien |
| Data dan metode | Sumber, rentang, hash, titik sensor, alat, selisih jam antar sumber | Analisis tidak bisa diulang |
| Batas | Apa yang tidak akan pernah terlihat dari data ini | Diam dianggap bersih |
| Pertanyaan terbuka | Apa yang belum dikerjakan dan oleh siapa | Pekerjaan lanjutan tidak punya pemilik |
| Rekomendasi | Tindakan berurutan, ada pemilik dan tenggat | Saran umum yang tidak bisa dijalankan |

Fase reporting NIST SP 800-86 meminta laporan menyebut tindakan yang dilakukan, alasan memilih alat, tindakan lanjutan, dan rekomendasi perbaikan (Day 13 bagian 1.6). Template PT JAB memenuhinya lewat bagian data dan metode, pertanyaan terbuka, dan rekomendasi. Bagian "siapa pelakunya" sengaja tidak ada, sesuai alasan yang sama di Day 13 bagian 1.2.

### 1.5 Template integrasi Zeek ke Splunk: lapisan yang harus lolos

Pertanyaan keenam datang dari Sari, dan jawabannya adalah lapisan. Data dari sensor baru dipercaya bila setiap lapisan di bawah ini lolos, dari bawah ke atas, dan pemeriksaannya tertulis. Tabel berikut adalah kerangka template di Bagian L; kolom "Gagal diam-diam bila" adalah alasan template ini ada.

| Lapisan | Isi | Bukti lolos | Gagal diam-diam bila |
|---|---|---|---|
| 1 Sumber | Log Zeek JSON, daftar log yang dikirim, zona waktu sensor UTC | Daftar log dan alasan log yang tidak dikirim | Log penting tidak pernah dikirim (misalnya `smb_files`) |
| 2 Input | `inputs.conf` satu stanza per log, `index`, sourcetype eksplisit (Day 08 bagian 2.11) | `\| metadata type=sourcetypes index=zeek` | Salah ketik sourcetype membuat satu log tidak ter-parse |
| 3 TA | TA for Zeek 1.0.11 di indexer dan search head [S3] | Field CIM ada di event mentah | TA hanya di forwarder, field CIM kosong |
| 4 Waktu | `_time` sama dengan `ts`; tampilan WIB | Satu event dicocokkan dengan pcap | Timeline bergeser tujuh jam |
| 5 CIM | Tag `network` dan `communicate` untuk `All_Traffic` [S13], pemetaan field | Tabel tag per sourcetype | Event tidak masuk data model |
| 6 Index constraint | Index `zeek` di macro data model (Day 13 bagian 2.9) | `\| tstats summariesonly=false count ... where index=zeek` lebih dari nol | Correlation search CIM nol tanpa galat |
| 7 Acceleration | Summary dibangun, `summariesonly` dipahami | `summariesonly=true` memberi angka sama untuk jendela baru | Replay jendela lama menghasilkan nol |
| 8 Kesehatan | `JAB-ZEEK-HEALTH-01`, `capture_loss`, volume harian | Alert uji saat forwarder dihentikan | Jeda log dianggap malam yang sepi |
| 9 Use case per titik pandang | Search hop core untuk workstation, CIM untuk server dengan NAT sendiri | Replay insiden lama menyala | Search benar secara sintaks, buta karena titik pandang |
| 10 Operasional | Pemilik, severity, routing antrean, tanggal tinjau | Tabel pemilik per search | Alert benar menunggu di antrean yang salah |

Lapisan 1 sampai 8 sudah dibahas di Day 08 bagian 1.9 dan 2.11 dan Day 13 bagian 1.7 sampai 2.9. Lapisan 9 dan 10 adalah pelajaran capstone: search yang menyala tetap tidak berguna bila titik pandangnya salah atau antreannya menahan alert sampai pagi (bagian 1.6). CIM menyamakan nama field, bukan titik pandang: definisi `bytes_out` di CIM 6.2 adalah byte yang dikirim perangkat atau antarmuka [S13], sehingga untuk sensor pasif arahnya tetap dibaca bersama `src` dan `dest`.

### 1.6 Alert yang benar tetapi terlambat: antrean dan korelasi per host

Pertanyaan ketiga Dimas adalah pertanyaan yang paling tidak nyaman, dan jawabannya bukan "sensor gagal". Di kasus ini, sensor dan saved search menyala lima kali sebelum insiden dibuka. Masalahnya ada di cara alert diperiksa:

- **Satu alert, satu keputusan.** Setiap alert diperiksa sendiri. Alert rendah yang ditutup dengan alasan masuk akal ("User-Agent CryptoAPI biasanya pengambilan CRL") tidak pernah bertemu alert sedang di host yang sama satu jam kemudian.
- **Routing berdasarkan severity.** Alert sedang setelah jam kerja menunggu antrean pagi; hanya alert tinggi yang membangunkan on-call. Rangkaian sinyal sedang di malam hari tidak pernah mencapai manusia.
- **Diam dianggap bersih.** Tidak ada rule untuk baca massal dari share di luar jam kerja, sehingga tahap pengumpulan tidak menyalakan apa pun. Tanpa alert bukan bukti tidak terjadi.

Padanannya di NOC adalah korelasi alarm per node: lima alarm minor di satu router dalam satu jam tidak diperlakukan sebagai lima tiket, tetapi dinaikkan menjadi satu major. Untuk SOC, bentuknya adalah search yang menghitung alert dari semua sumber per host dalam satu jendela dan menaikkan prioritas bila jumlah sumber berbeda melewati ambang. Batasnya: korelasi per host butuh nama host yang seragam di semua sumber, padahal Suricata di hop egress melihat proxy dan MDE memakai nama perangkat (Day 09 bagian 2.7). Normalisasi entitas adalah pekerjaan integrasi (lapisan 9 dan 10 di bagian 1.5).

### 1.7 Glosarium Day 08-13

Glosarium Minggu 1 ada di Day 07 bagian 1.11. Tabel ini melengkapinya dengan istilah Minggu 2 yang dipakai di capstone; cari istilah yang masih terasa samar dan baca ulang Day asalnya.

| Istilah | Arti di catatan ini | Day |
|---|---|---|
| `uid` | ID satu koneksi yang sama di semua log Zeek; jembatan `conn.log`, `http.log`, `ssl.log`, `files.log` | 08 |
| `is_orig` | Arah berkas: `false` berarti berkas mengalir dari pihak yang dihubungi ke pemulai | 08 |
| Suppress | Menghilangkan alert untuk rule dan alamat tertentu; rule tetap aktif untuk sumber lain | 09 |
| Hop core, hop egress | SPAN core switch DC (workstation terlihat) dan TAP egress (web bersumber proxy) | 08, 12 |
| Beacon, CV, prevalence | Koneksi berkala, ukuran keteraturan interval, jumlah host ke tujuan yang sama | 11 |
| Ambang beacon program | Minimal 24 interval, CV maksimal 0,2, median 30 detik sampai 4 jam | 11 |
| PCR | Producer-consumer ratio, arah dominan byte dari -1 sampai 1 | 12 |
| Pecahan seragam | Banyak koneksi dengan byte keluar hampir sama (T1030) | 12 |
| Saved search exfil hop core | Volume per host dan tujuan lebih dari 500 MB per 15 menit, dari `CONNECT` dan `conn.log` per `uid` | 12 |
| Metode kerja v1.0 | Langkah 0 sampai 6 dengan tiga kriteria berhenti | 13 |

### 1.8 Peta konsep capstone

Peta ini menyambung pertanyaan Dimas dan Sari dengan langkah dan keluaran hari Kamis; baca dari atas ke bawah sebagai satu hari kerja.

```
 07:30 pertanyaan Dimas + Sari
   |
   v
 0 bukti (Rudi 01:40 + kamu 08:10)  pcap egress 09:30Z-18:40Z, arsip Zeek 2027-06-02, log proxy/firewall, SHA256SUMS
   |
   v
 1 orientasi   capinfos | Conversations | stats count BY sourcetype | capture_loss
   |
   v
 2 batasi      hop core: 10.10.60.146 ; hop egress: 203.0.113.186/.187/.198/.199 ; proxy: user + URL
   |
   v
 3 protokol    unduhan (http/files) | kanal (CONNECT, ssl, x509) | share (smb_mapping, smb_files) | unggah (CONNECT+conn)
   |
   v
 4 pola        interval 60,2 s CV 0,048 | 1,87 GB baca | 31 pecahan ~52,5 MB | baseline flow 13 bulan
   |
   v
 5 korelasi    flow DC + edge | MDE proses + berkas | proxy 30 hari | firewall | timeline deteksi
   |
   v
 6 write-up    template final (Bagian K) | IOC lima kolom | batas | terbuka | rekomendasi
   |
   +--> template integrasi Zeek ke Splunk (Bagian L)  +--> satu halaman 15:00 (Bagian M)
```

## 2-4. Capstone `INC-2027-073` dan troubleshooting

Bagian A sampai M adalah jalur kerja PT JAB, Kamis 2027-06-03 pukul 08:10 sampai 15:45, dikerjakan bersamamu oleh Sari dan Gilang Ramadhan (L1), dengan Yoga Pratama memegang sisi host untuk IR. Semua isi Bagian A sampai M fiktif dan merupakan keluaran ilustrasi; perintah ditulis untuk `jkt-nsm-ws01` (tshark 4.6.9, `jq`, nfdump) dan query untuk Splunk PT JAB yang menampilkan WIB. Bagian N adalah kasus tertulis dan rekonstruksi di VM lab pribadimu.

Tabel berikut adalah peta lima alert yang menjadi bahan hari itu. Kolom "Keputusan saat itu" dan "Keputusan setelah capstone" sengaja berdampingan, karena selisih keduanya adalah jawaban pertanyaan ketiga Dimas.

| Alert | Waktu (WIB) | Sumber | Ringkasan | Keputusan saat itu | Keputusan setelah capstone | Bagian |
|---|---|---|---|---|---|---|
| `SOC-2027-0665` | Rabu 16:47:10 | Suricata `jkt-ids01`, rule lokal sid 1000131 | Unduhan PE berekstensi gambar, dua event (hop egress dan hop core) | Ditutup 17:10 oleh L1 shift sore: "User-Agent CryptoAPI, pengambilan CRL" | Benar positif, digabung ke `INC-2027-073` | C, G |
| `SOC-2027-0666` | Rabu 16:47:31 | MDE, severity rendah | `certutil.exe` mengunduh berkas di `JKT-WS-2066` | Menunggu antrean pagi (rendah) | Benar positif, digabung | C, H |
| `SOC-2027-0667` | Rabu 18:02 | Saved search beacon program (Day 11) | `10.10.60.146` ke `cdn.kirana-stat.example`, 73 interval | Menunggu antrean pagi (sedang setelah jam kerja) | Benar positif, digabung | D, G |
| `SOC-2027-0668` | Rabu 22:05 | Suricata, rule lokal sid 1000140 | 412 alert sweep port 445 dari `10.20.10.61` | Belum disentuh | Benar tetapi tidak relevan; suppress dengan tanggal tinjau | G |
| `SOC-2027-0669` | Kamis 00:45:40 | Saved search exfil hop core (Day 12) | `10.10.60.146` ke `drop.berkasku.example`, 525 MB dalam 15 menit | Dwi menelepon Rudi 00:51; `INC-2027-073` 01:25 | Benar positif, pemicu insiden | F, G |

### Bagian A: langkah 0, pertanyaan dan bukti

Rudi sudah menjalankan langkah 0 pukul 01:40, sebelum isolasi selesai dicatat, tetapi hanya untuk dua IP unggahan. Pagi ini kamu mengulangnya untuk semua tujuan yang muncul, karena langkah 0 boleh diulang setiap kali pertanyaan bertambah (Day 13 bagian 2.1).

**Tujuan:** menulis pertanyaan sebelum membuka data, menetapkan jendela dalam dua zona, dan mengamankan pcap egress serta log sebelum ring buffer menimpanya.

Pertanyaan yang ditulis di tiket pukul 08:12:

```
Q1 Apa yang diunduh JKT-WS-2066 (10.10.60.146) dari 203.0.113.186, dan apakah dijalankan?
Q2 Apa pola koneksi ke cdn.kirana-stat.example, sejak kapan, dan proses apa pembuatnya?
Q3 Apa yang dibaca host ini dari file server, kapan, dan berapa?
Q4 Berapa byte yang keluar ke drop.berkasku.example, kapan, dan apa hubungannya dengan Q3?
Q5 Host lain mana yang menghubungi keempat IP luar, kedua domain, atau membaca share yang sama di luar jam kerja?
Jendela: Rabu 2027-06-02 16:30:00 WIB sampai Kamis 2027-06-03 01:40:00 WIB = 2027-06-02 09:30:00Z sampai 18:40:00Z
         (seluruh jendela berada di tanggal UTC yang sama: satu folder arsip Zeek)
```

Pemotongan pcap kasus mengikuti pola Day 02 bagian 2.1 dan Day 13 bagian 2.1:

```bash
mkdir -p /cases/INC-2027-073/{carve,zeek,export,splunk}
for f in $(cat /cases/INC-2027-073/files.txt); do
  tcpdump -r "$f" -w "/cases/INC-2027-073/carve/$(basename "$f")" \
    'host 203.0.113.186 or host 203.0.113.187 or host 203.0.113.198 or host 203.0.113.199'
done
mergecap -w /cases/INC-2027-073/inc073_0930Z-1840Z.pcapng /cases/INC-2027-073/carve/*.pcapng
capinfos -M -c -u -a -e -S -H /cases/INC-2027-073/inc073_0930Z-1840Z.pcapng
for l in conn http files ssl x509 dns smb_mapping smb_files capture_loss; do
  rsync -a jkt-zeek01:/opt/zeek/logs/2027-06-02/ --include="$l.09*" --include="$l.1[0-8]*" \
    --exclude='*' /cases/INC-2027-073/zeek/
done
sha256sum /cases/INC-2027-073/inc073_*.pcapng /cases/INC-2027-073/zeek/* /cases/INC-2027-073/splunk/* \
  > /cases/INC-2027-073/SHA256SUMS
```

| Bagian | Fungsi |
|---|---|
| `files.txt` | File ring di `/mnt/pcap01/ring/` yang mencakup 09:30Z sampai 18:40Z, dipilih dari jam UTC di nama file ditambah satu file sebelumnya, dicek dengan `capinfos -a -e` |
| BPF empat `host` | Semua IP luar yang sudah diketahui; DNS tidak ikut karena nama di-resolve proxy dan resolver, dan `dns.log` hop core sudah memuatnya |
| `rsync ... /opt/zeek/logs/2027-06-02/` | Arsip Zeek per tanggal UTC; jam 09 sampai 18 UTC |
| `splunk/` | Ekspor CSV `index=proxy` dan `index=firewall` untuk jendela yang sama, supaya bukti tidak bergantung pada retensi 30 dan 90 hari |
| `sha256sum ... > SHA256SUMS` | Hash dicatat sebelum siapa pun membuka file; pcap Rudi semalam punya baris hash sendiri dan tidak ditimpa |

Keluaran ilustrasi `capinfos` (diringkas):

```
Number of packets:    1673416
Capture duration:     29791.904000 seconds
Earliest packet time: 1811929629.418000
Latest packet time:   1811959421.322000
SHA256:               <64 karakter heksadesimal, dicatat di tiket>
```

**Cara membaca hasil:** epoch `1811929629` adalah 2027-06-02 09:47:09 UTC (16:47:09 WIB): paket pertama adalah koneksi proxy ke `203.0.113.186`, sesuai unduhan. Paket terakhir 18:03:41 UTC (01:03:41 WIB) adalah tunnel kanal terakhir yang sempat keluar sebelum blokir proxy 01:04:30; percobaan sesudahnya ditolak proxy dan tidak pernah sampai egress. Ring buffer bulan Juni menjangkau 81 sampai 86 jam, jadi pcap Rabu sore masih aman sampai Sabtu pagi, tetapi tidak ada alasan menunggu.

**Kapan gagal:** file ring dipilih dengan jam WIB; pcap Rudi dianggap cukup padahal hanya memuat dua IP unggahan; atau hash dihitung setelah analisis dimulai.

### Bagian B: langkah 1, orientasi

**Tujuan:** menulis tiga sampai lima kalimat tentang isi data sebelum membaca satu paket pun, di kedua hop.

Perintah orientasi dari catatan lama, untuk sensor yang melihat host langsung tanpa proxy:

```
zeek-cut id.orig_h id.resp_h id.resp_p service orig_bytes resp_bytes < conn.log \
  | awk '$1=="10.10.5.23" && $5!="-" {out[$2]+=$5} END {for (d in out) print out[d], d}' \
  | sort -rn | head
```

- Tujuan: daftar tujuan dari satu host diurutkan menurut byte keluar.
- Cara membaca: tujuan yang tidak ada di baseline langsung menjadi fokus; volume besar di luar jam kerja dibanding baseline kecil adalah anomali yang tidak butuh statistik.

Di PT JAB perintah itu, bila dijalankan di hop core untuk `10.10.60.146`, menaruh `10.20.3.60` (proxy) di puncak dengan sekitar 1,6 GB, karena semua web workstation ke proxy. Tujuan sebenarnya ada di baris `CONNECT` (Day 12 bagian 2.1). Orientasi dilakukan di dua tempat. Di pcap egress, Statistics > Conversations (tab IPv4, diurutkan Bytes) memperlihatkan empat pasangan: `10.20.3.60` dengan `203.0.113.198` (16 percakapan TCP 443, sekitar 811 MB dari proxy ke luar), dengan `203.0.113.199` (15 percakapan, sekitar 788 MB), dengan `203.0.113.187` (495 percakapan pendek), dan dengan `203.0.113.186` (1 percakapan TCP 80, sekitar 212 KB ke arah proxy). Di Splunk, untuk hop core:

```
index=zeek ("id.orig_h"="10.10.60.146" OR "id.resp_h"="10.10.60.146")
    earliest="06/02/2027:16:30:00" latest="06/03/2027:01:40:00"
| stats count BY sourcetype
```

Keluaran ilustrasi:

```
sourcetype              count
bro:conn:json           9884
bro:dns:json            2316
bro:http:json           1211
bro:smb_files:json      2117
bro:smb_mapping:json    3
bro:ssl:json            37
bro:files:json          4
```

**Cara membaca hasil:** dalam sembilan jam lebih, `10.10.60.146` membuat 1.211 transaksi HTTP ke proxy (termasuk `CONNECT`), 2.117 baris berkas SMB, dan 4 berkas polos. Nama `bro:smb_files:json` dan `bro:smb_mapping:json` mengikuti pola sourcetype PT JAB dan sudah divalidasi dengan `| metadata` (Day 08 bagian 1.9). Kalimat orientasi yang ditulis Gilang: "Pcap egress memuat satu unduhan HTTP polos dari `203.0.113.186`, 495 sesi TLS pendek ke `203.0.113.187`, dan 31 sesi TLS besar ke `203.0.113.198` dan `.199`, semuanya bersumber proxy. Log Zeek hop core memuat `10.10.60.146` dengan aktivitas web, SMB ke file server, dan DNS ke resolver sepanjang jendela. `capture_loss` di `jkt-zeek01` maksimal 0,02% pada jam-jam itu, dan tidak ada jeda `JAB-ZEEK-HEALTH-01`." Tanpa kalimat terakhir, celah data bisa terbaca sebagai "tidak ada aktivitas" (Day 08 bagian 2.10).

**Kapan gagal:** orientasi hanya di pcap egress, lalu host ditulis tidak terlihat.

### Bagian C: langkah 2 dan 3, pintu masuk

**Tujuan:** menjawab Q1 dari dua hop dan memeriksa ulang keputusan `SOC-2027-0665`.

```
index=zeek sourcetype=bro:http:json uri="*scan_0602.png"
    earliest="06/02/2027:16:30:00" latest="06/02/2027:17:00:00"
| table _time uid id.orig_h id.resp_h method host uri user_agent status_code resp_mime_types
| sort 0 _time
```

Keluaran ilustrasi:

```
_time                    uid                 id.orig_h     id.resp_h      method  host           uri                                      user_agent                status_code  resp_mime_types
2027-06-02 16:47:09.412  CfV7nQ2kLw8sYb3Td   10.10.60.146  10.20.3.60     GET     203.0.113.186  http://203.0.113.186/files/scan_0602.png  Microsoft-CryptoAPI/10.0  200          application/x-dosexec
2027-06-02 16:47:09.418  Cq1Rz8mT0vXe5Ua2H   10.20.3.60    203.0.113.186  GET     203.0.113.186  /files/scan_0602.png                     Microsoft-CryptoAPI/10.0  200          application/x-dosexec
```

Pasangannya di `files.log`, yang sejak Zeek 5.1 memuat `uid` dan arah dibaca dari `is_orig` [S2]:

```
_time                    uid                 id.orig_h     id.resp_h      is_orig  mime_type              seen_bytes  total_bytes  sha256
2027-06-02 16:47:09.455  Cq1Rz8mT0vXe5Ua2H   10.20.3.60    203.0.113.186  false    application/x-dosexec  211456      211456       9a4e...71c2
2027-06-02 16:47:09.471  CfV7nQ2kLw8sYb3Td   10.10.60.146  10.20.3.60     false    application/x-dosexec  211456      211456       9a4e...71c2
```

**Cara membaca hasil:** tiga hal tidak cocok dalam satu baris, sama seperti di kasus tertulis Bagian N: nama berkas berekstensi `.png`, `mime_type` hasil inspeksi isi `application/x-dosexec` (PE Windows), dan Host berupa IP langsung. User-Agent `Microsoft-CryptoAPI/10.0` adalah User-Agent komponen Windows, bukan browser; komponen ini memang dipakai mengambil sertifikat dan daftar pencabutan, tetapi juga muncul saat `certutil` dipakai mengunduh berkas [S10]. CRL atau sertifikat tidak pernah berupa executable, jadi alasan penutupan `SOC-2027-0665` ("pengambilan CRL") gugur begitu kolom `resp_mime_types` dibaca. Satu berkas terlihat sekali per hop dengan `uid` berbeda dan hash identik (Day 08 bagian 1.3), dan `seen_bytes` sama dengan `total_bytes` berarti berkas terlihat utuh. Di ATT&CK, mengunduh alat ke host korban adalah T1105 Ingress Tool Transfer [S1][S9].

Yang tidak bisa dijawab jaringan: bagaimana unduhan dipicu (email, tautan, makro, skrip). Itu ditulis sebagai pertanyaan untuk host (Bagian H), bukan ditebak.

**Variasi:** di pcap egress, `http.request.uri contains "scan_0602"` menemukan permintaan proxy, dan Export Objects > HTTP memulihkan berkas di VM analisis; hash-nya dicocokkan dengan `files.log`, dan berkasnya diperlakukan sebagai sampel (Day 02). `http.file_data[0:2] == 4d:5a` memastikan magic byte `MZ` (Day 05 bagian 1.6).

**Kapan gagal:** keputusan triage diambil dari User-Agent saja; atau hash diambil dari berkas hasil Export Objects yang segmennya hilang, sehingga tidak cocok dengan hash `files.log`.

### Bagian D: langkah 3 dan 4, kanal berkala

**Tujuan:** mengukur pola `CONNECT` ke `cdn.kirana-stat.example` dengan ambang program, membaca apa yang terlihat di hop egress, dan memastikan pemilik ClientHello.

Pengukuran interval memakai cara Day 11 bagian 1.3 dan Day 13 bagian 2.4:

```
index=zeek sourcetype=bro:http:json method=CONNECT "id.orig_h"="10.10.60.146" uri="cdn.kirana-stat.example:443"
    earliest="06/02/2027:16:30:00" latest="06/03/2027:01:40:00"
| sort 0 _time
| streamstats current=f last(_time) AS prev
| eval delta=_time-prev
| stats count AS n_connect count(eval(status_code=200)) AS n_ok median(delta) AS med
        avg(delta) AS rata stdev(delta) AS sd min(_time) AS pertama max(_time) AS terakhir
| eval cv=round(sd/rata,3)
| convert ctime(pertama) ctime(terakhir)
```

Keluaran ilustrasi:

```
n_connect  n_ok  med   rata   sd    cv     pertama                     terakhir
522        495   60.2  60.20  2.89  0.048  06/02/2027 16:48:01.207     06/03/2027 01:30:45.407
```

**Cara membaca hasil:** 522 `CONNECT` memberi 521 interval dengan median 60,2 detik dan CV 0,048, jauh di bawah ambang program 0,2. Yang berstatus 200 hanya 495; 27 sisanya berstatus 403 karena Rudi memblokir domain di proxy pukul 01:04:30, dan proses di host tetap mencoba tiap sekitar 60 detik sampai isolasi 01:31:12. Percobaan yang ditolak itu berguna: ia membuktikan perilaku berasal dari proses yang terus berjalan, bukan dari tab browser yang terbuka. Koneksi pertama muncul 51,8 detik setelah unduhan (16:47:09,412 ke 16:48:01,207). Pada 18:02, saved search beacon sudah melihat 73 interval, cukup untuk menyalakan `SOC-2027-0667`.

Ukuran per tunnel diambil dengan penggabungan `CONNECT` dan `conn.log` per `uid` (Day 12 bagian 2.1), sekaligus mencari tunnel yang balasannya besar:

```
index=zeek earliest="06/02/2027:16:30:00" latest="06/03/2027:01:40:00"
    ((sourcetype=bro:http:json method=CONNECT "id.orig_h"="10.10.60.146" uri="cdn.kirana-stat.example:443")
     OR (sourcetype=bro:conn:json "id.orig_h"="10.10.60.146" "id.resp_h"="10.20.3.60" "id.resp_p"=3128))
| stats values(uri) AS tujuan min(_time) AS mulai sum(orig_bytes) AS kirim sum(resp_bytes) AS terima BY uid
| where isnotnull(tujuan) AND terima > 10000
| convert ctime(mulai)
| sort 0 mulai
```

Keluaran ilustrasi:

```
uid                 mulai                       kirim  terima
CkA3s9Vb2Yq7nE1Lr   06/02/2027 17:02:13.104     1183   18204
CuT5m0Wd8Rx2pH6Kc   06/02/2027 19:40:25.611     1171   22716
Cz9Lq4Ne1Fs7bJ3Ga   06/02/2027 22:38:50.930     1196   41380
Cr2Hx6Pk9Tw0mV5Dy   06/02/2027 23:12:04.287     1164   19932
Cb8Vn1Yt5Qe3kS7Jm   06/03/2027 00:18:05.455     1189   37668
Cd4Gw7Ra2Ux9fM0Pq   06/03/2027 00:59:40.018     1177   24090
```

**Cara membaca hasil:** tunnel biasa mengirim 1.140 sampai 1.212 byte (median 1.176) dan menerima 1.890 sampai 2.050 byte; enam tunnel menerima 18 sampai 41 KB. Respons yang lebih besar dari check-in biasa bisa berarti server mengirim perintah atau modul. Dua di antaranya jatuh tepat sebelum tahap berikutnya: 22:38:50, dua menit sebelum sesi SMB dimulai (Bagian E), dan 00:18:05, dua menit sebelum unggahan pertama (Bagian F). Itu kesimpulan berkeyakinan sedang, bukan bukti isi. Kanal ini hanya mengirim sekitar 0,58 MB (495 kali 1.176 byte).

Di hop egress, koneksi proxy ke `203.0.113.187` tercatat di `ssl.log` dengan `version` TLSv12 dan `server_name` `cdn.kirana-stat.example`, dan `x509.log` memuat sertifikatnya:

```
certificate.subject       CN=cdn.kirana-stat.example
certificate.issuer        CN=cdn.kirana-stat.example
certificate.not_valid_before  2027-05-31T00:00:00Z
certificate.not_valid_after   2027-06-30T00:00:00Z
```

Sertifikat self-signed, diterbitkan dua hari sebelum unduhan, berlaku 30 hari. Sertifikat terlihat karena sesi ini TLS 1.2 (Day 06 bagian 1.1). Log proxy menjawab kenapa SNI dan sertifikat asli terlihat di egress: `category=Technology tls=spliced`. Domain berumur 97 hari itu sudah diberi kategori oleh vendor, sehingga proxy meneruskan TLS apa adanya; pada koneksi splice, ClientHello di egress adalah milik klien asli (Day 06 bagian 1.7).

Karena di-splice, fingerprint klien bisa dihitung dari pcap egress. Zeek di `jkt-zeek01` belum memuat paket fingerprint (Day 08), jadi tshark yang dipakai:

```
tshark -r /cases/INC-2027-073/inc073_0930Z-1840Z.pcapng -Y 'tls.handshake.type == 1' \
  -T fields -e ip.dst -e tls.handshake.extensions_server_name -e tls.handshake.ja3 -e tls.handshake.ja4 \
  | sort | uniq -c
```

Keluaran ilustrasi (hash dipersingkat, lengkap di tiket):

```
    495 203.0.113.187  cdn.kirana-stat.example  7c41...e9a0  t13d1210h1_...
     16 203.0.113.198  drop.berkasku.example    7c41...e9a0  t13d1210h1_...
     15 203.0.113.199  drop.berkasku.example    7c41...e9a0  t13d1210h1_...
```

**Cara membaca hasil:** satu klien yang sama membuka kanal dan mengunggah. Bagian `a` JA4 (`t13`, `h1`) berarti klien menawarkan TLS 1.3 dan hanya `http/1.1` di ALPN; server kanal memilih TLS 1.2, server unggahan TLS 1.3. Fingerprint ini bukan milik Edge armada PT JAB, yang menawarkan `h2`. Keyakinan untuk JA3 dan JA4 sebagai indikator tetap sedang: fingerprint bisa dibagi aplikasi lain yang memakai pustaka TLS yang sama (Day 06 bagian 1.6).

**Kapan gagal:** interval dihitung di hop egress, tempat koneksi proxy dari banyak workstation ke tujuan yang sama bercampur; JA4 di egress dianggap milik klien padahal koneksinya di-bump; atau kata "C2" ditulis di tiket sebelum ada korroborasi host.

### Bagian E: langkah 3 dan 4, baca massal dari file server

**Tujuan:** menjawab Q3 dari hop core: share apa, berkas apa, berapa byte, dan apakah itu tidak biasa untuk host ini.

Trafik workstation ke file server data center melewati core switch, sehingga terlihat di SPAN core. `smb_mapping.log` menunjukkan share yang dipetakan pukul 22:41:07 [S7]: `\\JKT-FS01\KEUANGAN$` di `jkt-fs01` (`10.20.8.21`), file server Keuangan yang, seperti `jkt-fs02`, tidak memakai enkripsi SMB. Rincian berkasnya dari `smb_files.log`:

```
index=zeek sourcetype=bro:smb_files:json "id.orig_h"="10.10.60.146" "id.resp_h"="10.20.8.21"
    earliest="06/02/2027:22:30:00" latest="06/02/2027:23:30:00"
| eval folder=mvindex(split(name,"\\"),0)
| stats count AS baris dc(name) AS berkas min(_time) AS mulai max(_time) AS selesai BY action folder
| convert ctime(mulai) ctime(selesai)
```

Keluaran ilustrasi:

```
action          folder            baris  berkas  mulai                selesai
SMB::FILE_OPEN  Laporan-Bulanan   641    313     06/02/2027 22:41:09  06/02/2027 23:06:51
SMB::FILE_OPEN  Pajak             812    401     06/02/2027 22:41:12  06/02/2027 23:06:55
SMB::FILE_OPEN  Treasury          664    318     06/02/2027 22:41:10  06/02/2027 23:06:40
```

**Cara membaca hasil:** 2.117 baris `SMB::FILE_OPEN` untuk 1.032 berkas berbeda di tiga folder dalam 25 menit 48 detik, di luar jam kerja. Hanya `FILE_OPEN` yang muncul karena PT JAB memakai setelan bawaan Zeek: set `SMB::logged_file_actions` bawaannya hanya memuat `FILE_OPEN`, `FILE_DELETE`, `FILE_RENAME`, `PRINT_OPEN`, dan `PRINT_CLOSE`, walaupun enum aksinya juga mengenal `FILE_READ`, `FILE_WRITE`, dan aksi pipe [S6]. Membuka berkas belum membuktikan membaca isinya. Volume baca diambil dari `conn.log`:

```
index=zeek sourcetype=bro:conn:json "id.orig_h"="10.10.60.146" "id.resp_h"="10.20.8.21" "id.resp_p"=445
    earliest="06/02/2027:22:30:00" latest="06/02/2027:23:30:00"
| stats count sum(orig_bytes) AS kirim sum(resp_bytes) AS terima min(_time) AS mulai max(_time) AS selesai
```

Keluaran ilustrasi: 3 koneksi, `orig_bytes` 21.906.114, `resp_bytes` 1.874.913.280 (sekitar 1,87 GB atau 1,75 GiB), 22:41:07 sampai 23:06:55. Jumlah kolom `size` untuk 1.032 berkas unik adalah 1.838.402.519 byte. `size` di `smb_files.log` adalah ukuran total berkas [S6], bukan byte yang dipindahkan, sehingga selisih 36.510.761 byte (1,95%) adalah overhead SMB2 dan metadata, dan angka resmi volume baca adalah `resp_bytes`. Kecocokan keduanya menguatkan bahwa berkas yang dibuka memang dibaca habis. Di ATT&CK, mengumpulkan data dari share jaringan adalah T1039 Data from Network Shared Drive [S1].

Baseline diambil dari flow router data center yang disimpan 13 bulan (Day 10 bagian 2.2, Day 12 bagian 2.2):

```
nfdump -r /flow/dc-rtr/ -t 2026/05/04.00:00:00-2027/06/02.16:00:00 -N -A srcip,dstip \
  'src ip 10.20.8.21 and src port 445 and dst ip 10.10.60.146'
```

Perintah yang sama dijalankan per hari dengan skrip kecil, lalu diringkas: pada hari kerja, `jkt-fs01` mengirim median 52 MB per hari ke `10.10.60.146`, maksimum 288 MB pada hari tutup buku Maret, dan di atas pukul 19:00 tidak pernah lebih dari 5 MB. Malam Rabu, 1,87 GB dalam 26 menit adalah 36 kali median harian. Penjelasan jinak yang diuji: indeksasi Windows Search atau Offline Files juga membaca banyak berkas, dan jadwal pemindai `jkt-vscan01` jatuh di malam yang sama (Bagian G). Indeksasi dan Offline Files tidak memetakan share secara baru pada pukul 22:41 dan tidak diikuti unggahan; pemindai menyapu server dari alamatnya sendiri, bukan dari workstation. Keputusan tetap menunggu proses di host (Bagian H).

**Variasi:** bila pertanyaan berikutnya membutuhkan bukti baca per berkas, `redef SMB::logged_file_actions += { SMB::FILE_READ };` di `local.zeek` membuat `smb_files.log` mencatat aksi baca, dengan harga volume log yang jauh lebih besar; keputusan itu dicatat di template integrasi (Bagian L).

**Kapan gagal:** `size` dijumlahkan sebagai volume; ketiadaan `FILE_READ` dibaca sebagai "tidak ada yang dibaca"; atau SMB di server tujuan memakai enkripsi, sehingga nama berkas tidak terlihat sama sekali (SMB terenkripsi dan lateral movement dibahas di Day 19).

### Bagian F: langkah 4 dan 5, unggahan ke layanan berbagi berkas

**Tujuan:** menjawab Q4 dengan angka yang bisa dipertanggungjawabkan dari dua sumber independen.

Saved search exfil hop core (Day 12 bagian 2.1) yang menyalakan `SOC-2027-0669`, jendela Kamis 00:30:00 sampai 00:44:59:

```
src            tujuan                       kirim        terima   koneksi  pcr
10.10.60.146   drop.berkasku.example:443    525017743    69418    10       0.9997
```

Tunnel ke-11 di jendela itu (mulai 00:44:12) belum selesai saat search berjalan, sehingga belum ada di `conn.log`; Zeek menulis baris koneksi saat koneksi berakhir (Day 12 bagian 2.1). Untuk laporan, jendela diperlebar ke seluruh malam dan rincian per `uid` diambil dengan query yang sama seperti di Bagian D, dengan `uri="drop.berkasku.example:443"` dan tanpa filter `terima`. Keluaran ilustrasi (diringkas):

```
uid                 mulai                     kirim       terima
CmQ1v7Xe3Tb9Rk2Ws   06/03/2027 00:20:12.044   52501770    6938
CjW4k0Lp8Yd2Hc6Nf   06/03/2027 00:21:32.051   52501930    6944
CeR7t2Ga5Mz1Uq9Bx   06/03/2027 00:22:52.047   52501726    6941
... (25 baris lagi, kirim 52501697 sampai 52501934)
CsN3b8Qy6Vk0Ej4Lh   06/03/2027 00:57:32.049   52501719    6940
CwZ6d1Ht9Pr5Ka3Fm   06/03/2027 00:58:52.052   52502707    6947
CaY0f4Jm2Ws8Gn7Tc   06/03/2027 01:00:12.046   23627251    6921
total 31 tunnel                               1598681611  215202
```

**Cara membaca hasil:** 31 tunnel berangkat tepat tiap 80 detik dari 00:20:12 sampai 01:00:12, dan tunnel terakhir selesai 01:00:46. Tiga puluh tunnel membawa `kirim` yang hampir sama, 52.501.697 sampai 52.502.707 byte (selisih maksimal 1.010 byte), dan tunnel terakhir sekitar 23,6 MB. Itu bentuk pecahan berukuran tetap, T1030 Data Transfer Size Limits (Day 12 bagian 1.7). Di hop core, ukuran tunnel tidak identik persis seperti di jaringan tanpa proxy (kasus tertulis Bagian N), karena setiap tunnel juga membawa baris `CONNECT`, handshake TLS, dan header HTTP yang sedikit berbeda.

Hitungan kasar ukuran pecahan: TLS 1.3 membungkus data dalam record maksimal 16.384 byte dengan overhead 22 byte per record, jadi 52.501.812 byte dibagi 1,00134 menjadi sekitar 52.431.409 byte, dan setelah dikurangi sekitar 2,6 KB handshake dan header tinggal sekitar 52.428.800 byte, yaitu tepat 50 MiB. Tiga puluh pecahan 50 MiB ditambah satu pecahan 22,5 MiB adalah 1.596.456.960 byte. Angka ini dicocokkan dengan host di Bagian H.

Sumber kedua adalah flow, dengan pola Day 12 bagian 2.2:

```
nfdump -r /flow/dc-rtr/2027/06/03/ -t 2027/06/03.00:20:00-2027/06/03.01:01:00 -N \
  -A srcip,dstip 'src ip 10.10.60.146 and dst ip 10.20.3.60 and dst port 3128'
nfdump -r /flow/jkt-edge/2027/06/03/ -t 2027/06/03.00:20:00-2027/06/03.01:01:00 -N \
  -A srcip,dstip 'src ip 198.51.100.120 and (dst ip 203.0.113.198 or dst ip 203.0.113.199)'
```

Keluaran ilustrasi (kolom dipersingkat):

```
Date first seen          Duration  Src IP Addr     Dst IP Addr     Packets   Bytes
2027-06-03 00:20:12.039  2434.511  10.10.60.146    10.20.3.60      1104322   1656180214
2027-06-03 00:20:12.300  2434.024  198.51.100.120  203.0.113.198   590000    862000000
2027-06-03 00:21:32.311  2353.902  198.51.100.120  203.0.113.199   514000    800400000
```

**Cara membaca hasil:** router data center mencatat 1.656.180.214 byte level IP dari `10.10.60.146` ke proxy. Byte payload unggahan di Zeek (1.598.681.611) ditambah 1.104.274 paket kali 52 byte header IP dan TCP sama dengan 1.656.103.859; sisanya 76.355 byte adalah tunnel kanal dan sedikit trafik Edge di jendela yang sama. Flow edge sesudah koreksi sampling 1:1000 berjumlah 1.662.400.000 byte ke dua alamat, selisih 0,38% dari angka router data center, di dalam rentang galat sampling untuk sekitar 1.100 paket tersampel (Day 10 bagian 2.2). Dua sumber independen cocok, sehingga volume keluar berkeyakinan tinggi dari jaringan saja. Laju per tunnel sekitar 5,6 Mbps dan sangat rata: alat yang mengatur lajunya, bukan link 1 Gbps yang penuh.

Tujuan dibaca dari log proxy: `drop.berkasku.example`, `category=Online-Storage tls=spliced`, di-resolve proxy ke `203.0.113.198` dan `203.0.113.199` secara bergantian (16 dan 15 tunnel). Itu layanan berbagi berkas publik fiktif, sehingga labelnya T1567.002 Exfiltration to Cloud Storage [S8]. Baseline flow 13 bulan untuk unggahan host ini ke proxy: rata-rata 41 MB per hari kerja, maksimum 196 MB, dan malam hari rata-rata 2 MB. Malam Kamis, 1,6 GB dalam 41 menit.

**Kapan gagal:** volume diambil dari kolom `bytes` proxy, yang untuk tunnel splice hanya ukuran balasan ke klien (Day 12); angka hop core dan flow edge dibandingkan tanpa menghitung header dan koreksi sampling; atau dua IP tujuan diperlakukan sebagai dua tujuan berbeda, padahal satu nama layanan.

### Bagian G: triage alert dan timeline deteksi

**Tujuan:** menjawab pertanyaan ketiga Dimas dengan fakta: alert mana yang menyala, kapan, siapa yang memegangnya, dan apa yang dipelajari.

Perintah triage dari catatan lama, untuk `eve.json` tunggal:

```
cat eve.json | jq -r 'select(.event_type=="alert") | [.alert.signature_id, .alert.signature, .src_ip] | @tsv' \
  | sort | uniq -c | sort -rn
```

Di `jkt-ids01`, alert ada di `eve-alert.json` (Day 09 bagian 1.10), jadi perintahnya dijalankan pada berkas itu dengan jendela waktu yang sama. Keluaran ilustrasi:

```
    412  1000140  JAB-LOCAL SCAN SYN ke banyak host port 445   10.20.10.61
      1  1000131  JAB-LOCAL HTTP PE dengan ekstensi gambar     203.0.113.186
      1  1000131  JAB-LOCAL HTTP PE dengan ekstensi gambar     10.20.3.60
```

**Cara membaca hasil:**

- Sid 1000140 (412 kali) adalah volume terbesar, tetapi sumbernya `jkt-vscan01` (`10.20.10.61`), pemindai resmi tim Agung yang menyapu data center sebulan sekali (Day 04 bagian 1.6), dan malam itu jadwal bulanannya, 22:00 sampai 22:31. Itu benar secara teknis dan tidak relevan untuk kasus ini. Usulan tuning: `suppress gen_id 1, sig_id 1000140, track by_src, ip 10.20.10.61` dengan komentar nomor alert, pemilik, dan tanggal tinjau (Day 09 bagian 1.8); `track by_src` menekan alert hanya bila sumbernya cocok dengan alamat itu [S4][S11], sehingga sweep yang sama dari workstation tetap menyala.
- Sid 1000131 hanya dua event (satu per hop), tetapi persis mengonfirmasi Bagian C. Jumlah alert bukan ukuran pentingnya.
- Tidak ada alert untuk baca massal SMB dan untuk unggahan TLS ke layanan penyimpanan. Itu bukan bukti bersih; ruleset tidak punya rule untuk keduanya, dan saved search exfil hanya menyala karena ambang 500 MB per 15 menit terlewati. Unggahan yang sama dengan laju setengahnya tidak akan pernah menyalakannya (Day 12 bagian 1.7).

Timeline deteksi dipisahkan dari timeline serangan karena pembacanya berbeda. Tabel ini adalah bahan utama untuk jawaban "kenapa baru ketahuan jam satu".

| Waktu (WIB) | Alert atau kejadian | Dipegang | Keputusan | Yang seharusnya terjadi |
|---|---|---|---|---|
| Rabu 16:47:10 | `SOC-2027-0665` Suricata | L1 shift sore, 17:10 | Ditutup: "CryptoAPI, pengambilan CRL" | `resp_mime_types` dibaca; PE bukan CRL |
| Rabu 16:47:31 | `SOC-2027-0666` MDE rendah | Antrean pagi | Tidak disentuh | Digabung dengan `0665` karena host dan menit yang sama |
| Rabu 18:02 | `SOC-2027-0667` beacon | Antrean pagi | Tidak disentuh (sedang, setelah jam kerja) | Tiga sinyal di satu host dalam 75 menit dinaikkan |
| Rabu 22:05 | `SOC-2027-0668` scanner | Antrean | Tidak disentuh | Disupresi per sumber sejak awal |
| Rabu 22:41 sampai 23:07 | Baca 1,87 GB dari `jkt-fs01` | Tidak ada alert | | Rule baca massal share di luar jam kerja |
| Kamis 00:45:40 | `SOC-2027-0669` exfil | Dwi, lalu Rudi 00:51 | Eskalasi | Sudah benar |
| Kamis 01:04:30 | Blokir dua domain di proxy | Rudi | Unggahan sudah selesai 01:00:46 | |
| Kamis 01:25 | `INC-2027-073` dibuka | Rudi, setuju Dimas lewat telepon | | |
| Kamis 01:31:12 | `JKT-WS-2066` diisolasi MDE | Rudi | | |

**Cara membaca hasil:** dwell time deteksi dari alert benar pertama sampai insiden dibuka adalah 8 jam 37 menit 50 detik. Dari lima alert, empat benar positif dan satu benar tetapi tidak relevan; tidak ada sensor yang gagal. Yang gagal adalah triage yang membaca satu field (User-Agent), routing yang menahan alert sedang sampai pagi, dan ketiadaan korelasi per host (bagian 1.6). Bila tiga alert pertama dibaca bersama pukul 18:02, isolasi bisa terjadi sebelum share dibaca.

Usulan search korelasi per host, ditulis sebagai titik awal (nama field notable dan lookup aset dicek di Enterprise Security PT JAB sebelum dipakai):

```
index=notable earliest=-6h
| eval entitas=coalesce(dest_nt_host, src_nt_host, dest, src)
| stats dc(source) AS jumlah_sumber values(source) AS search min(_time) AS pertama max(_time) AS terakhir BY entitas
| where jumlah_sumber >= 2
```

`dc(source)` menghitung berapa search atau rule berbeda yang menyala untuk entitas yang sama dalam enam jam; dua atau lebih menaikkan prioritas ke on-call, berapa pun severity masing-masing. Kapan gagal: alert Suricata dari hop egress memuat proxy, bukan workstation, sehingga entitasnya harus diambil dari event hop core atau dari log proxy lebih dulu (Day 09 bagian 2.7).

### Bagian H: langkah 5, korelasi host dan scoping

**Tujuan:** menjawab bagian "proses apa" dari Q1, Q2, dan Q4 dengan MDE, lalu Q5 dengan log proxy, firewall, dan Zeek.

Pola korelasi dari catatan lama memakai Sysmon Event ID 3; di PT JAB, telemetri host utama adalah MDE, dengan pola Day 11 bagian 2.8 dan Day 13 bagian 2.7 (`Timestamp` UTC):

```
DeviceNetworkEvents
| where Timestamp between (datetime(2027-06-02 09:30:00) .. datetime(2027-06-02 18:40:00))
| where DeviceName startswith "jkt-ws-2066"
| where RemoteIP == "10.20.3.60" and RemotePort == 3128
| summarize n=count(), pertama=min(Timestamp), terakhir=max(Timestamp)
    by InitiatingProcessFileName, InitiatingProcessFolderPath
| order by n desc
```

Keluaran ilustrasi (diringkas):

```
InitiatingProcessFileName  InitiatingProcessFolderPath                                   n     pertama              terakhir
msedge.exe                 C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe  641   2027-06-02 09:30:04  2027-06-02 10:58:12
ksync.exe                  C:\Users\yohana.siregar\AppData\Roaming\KiranaSync\ksync.exe   553   2027-06-02 09:48:01  2027-06-02 18:30:45
certutil.exe               C:\Windows\System32\certutil.exe                              1     2027-06-02 09:47:09  2027-06-02 09:47:09
```

**Cara membaca hasil:** `certutil.exe` membuat satu koneksi ke proxy pada 16:47:09 WIB, detik yang sama dengan unduhan di Zeek. `ksync.exe` membuat 553 koneksi: 522 ke kanal ditambah 31 unggahan, persis jumlah `CONNECT` di Zeek untuk kedua tujuan. Jumlah dan waktu yang sama dari dua sumber independen menaikkan "kandidat beacon" dan "unggahan besar" menjadi "kanal dan unggahan dari satu proses yang lahir dari berkas unduhan", keyakinan tinggi. Edge berhenti pukul 17:58 WIB: pengguna pulang dan meninggalkan workstation menyala.

Yoga menarik tiga fakta host lain dari MDE dan menuliskannya untuk tiket: rantai proses `wscript.exe` yang menjalankan berkas `.js` dari folder unduhan pukul 16:46:52, lalu `certutil.exe` dengan URL `203.0.113.186` pukul 16:47:08, lalu `ksync.exe` pukul 16:47:58; `ksync.exe` membuka berkas di `\\JKT-FS01\KEUANGAN$` mulai 22:41:09; dan `ksync.exe` menulis berkas `kx0602.dat` berukuran 1.596.456.960 byte di folder sementara pukul 23:58:12. Ukuran itu sama persis dengan hitungan 30 kali 50 MiB ditambah 22,5 MiB dari Bagian F. Pemaketan (T1560) kini didukung host; apakah arsip itu terenkripsi dan isinya apa adalah pertanyaan IR. Tim email melaporkan pesan bertema "rekap pajak Mei" dengan lampiran arsip ke 9 alamat Keuangan pukul 16:31; itu ditulis sebagai informasi dari tim email.

Pukul 13:40, Yoga menyatakan dari analisis berkas bahwa `ksync.exe` adalah alat akses jarak jauh yang mengambil perintah dari server lewat kanal itu. Baru sejak itu label C2 (T1071.001 dan T1573) dipakai di write-up, dengan sumber IR.

Scoping memakai log proxy 30 hari, `index=firewall` 30 hari, dan Zeek hop core sejak 2027-05-18:

```
index=proxy (host="203.0.113.186" OR host="*kirana-stat.example*" OR host="*berkasku.example*")
    earliest="05/04/2027:00:00:00" latest="06/03/2027:08:30:00"
| stats count min(_time) AS pertama max(_time) AS terakhir sum(bytes) AS bytes_ke_klien BY src user host
| convert ctime(pertama) ctime(terakhir)
```

Keluaran ilustrasi:

```
src            user              host                        count  pertama              terakhir             bytes_ke_klien
10.10.60.146   yohana.siregar    203.0.113.186               1      06/02/2027 16:47:09  06/02/2027 16:47:09  211843
10.10.60.146   yohana.siregar    cdn.kirana-stat.example:443 522    06/02/2027 16:48:01  06/03/2027 01:30:45  1001842
10.10.60.146   yohana.siregar    drop.berkasku.example:443   31     06/03/2027 00:20:12  06/03/2027 01:00:12  215202
10.10.63.57    rendy.kusnadi     drop.berkasku.example:443   4      05/12/2027 10:14:40  05/27/2027 15:02:19  8114560
10.10.62.131   sinta.marpaung    drop.berkasku.example:443   2      05/19/2027 13:47:05  05/19/2027 13:48:11  3212644
```

**Cara membaca hasil:** tidak ada host lain yang menghubungi `203.0.113.186` atau domain kanal. `drop.berkasku.example` dipakai dua pengguna lain di jam kerja, tanpa unggahan besar di Zeek hop core; ia layanan bersama, bukan IOC jahat. `index=firewall` 30 hari untuk keempat IP luar hanya memuat `10.20.3.60` (`allowed`), jadi tidak ada percobaan langsung dari workstation. Zeek hop core sejak 2027-05-18 tidak memuat host lain yang membaca lebih dari 500 MB dari `jkt-fs01` di luar jam kerja. MDE untuk 8 penerima email lain tidak mencatat eksekusi lampiran.

**Kapan gagal:** scoping hanya di hop egress, sehingga semua host tampak sebagai proxy; atau "tidak ada host lain" ditulis tanpa batasnya. Workstation ke workstation di switch akses tidak lewat sensor (Day 07 bagian 1.9), dan laptop yang membuka email di luar kantor tidak lewat proxy maupun sensor; keduanya masuk bagian batas.

### Bagian I: langkah 5 dan 6, timeline, label ATT&CK, dan IOC

**Tujuan:** menyusun tiga tabel inti write-up sebelum ringkasan ditulis.

Timeline serangan memakai WIB, dengan UTC di kolom terpisah untuk baris yang berasal dari pcap (Day 13 bagian 1.5). Kolom terakhir memisahkan bukti dari kesimpulan.

| Waktu (WIB) | UTC (pcap) | Kejadian | Sumber | Bukti atau kesimpulan |
|---|---|---|---|---|
| Rabu 16:31 | | Email "rekap pajak Mei" dengan lampiran arsip ke 9 alamat Keuangan | Tim email | Informasi pihak lain |
| 16:46:52 | | `wscript.exe` menjalankan berkas `.js` dari folder unduhan `JKT-WS-2066` | MDE | Bukti host |
| 16:47:09.412 | 09:47:09.418 | `certutil.exe` mengunduh `scan_0602.png` (PE, 211.456 byte) dari `203.0.113.186` lewat proxy | Zeek `http.log`, `files.log` kedua hop, log proxy, pcap egress, MDE | Bukti |
| 16:47:58 | | `ksync.exe` mulai berjalan dari profil pengguna | MDE | Bukti host |
| 16:48:01 sampai Kamis 01:03:40 | 09:48:01 sampai 18:03:41 | 495 tunnel ke `cdn.kirana-stat.example` (`203.0.113.187`) tiap median 60,2 detik, CV 0,048, sertifikat self-signed | Zeek hop core dan egress, log proxy, pcap egress, MDE | Bukti; "C2" kesimpulan IR 13:40 |
| 22:38:50 | 15:38:50 | Tunnel kanal dengan balasan 41.380 byte | Zeek hop core | Bukti; "perintah" kesimpulan sedang |
| 22:41:07 sampai 23:06:55 | | Membuka 1.032 berkas di `\\JKT-FS01\KEUANGAN$`, menerima 1.874.913.280 byte | Zeek `smb_mapping.log`, `smb_files.log`, `conn.log` hop core, MDE | Bukti; "pengumpulan" kesimpulan |
| 23:58:12 | | `kx0602.dat` 1.596.456.960 byte ditulis di folder sementara | MDE | Bukti host; "arsip data share" kesimpulan |
| Kamis 00:18:05 | 17:18:05 | Tunnel kanal dengan balasan 37.668 byte | Zeek hop core | Bukti; "perintah" kesimpulan sedang |
| 00:20:12 sampai 01:00:46 | 17:20:12 sampai 18:00:46 | 31 tunnel ke `drop.berkasku.example` (`203.0.113.198`, `.199`), total `orig_bytes` 1.598.681.611 | Zeek hop core dan egress, flow DC dan edge, log proxy, MDE | Bukti; "exfiltration" kesimpulan tinggi |
| 01:04:30 | | Kedua domain diblokir di proxy; 27 percobaan kanal berikutnya berstatus 403 | Change log proxy, Zeek hop core | Bukti |
| 01:31:12 | | `JKT-WS-2066` diisolasi | MDE | Bukti |
| 01:40 | | Keempat IP luar diblokir di `jkt-fw01` | Change log firewall | Bukti |

Label ATT&CK hanya untuk tahap yang didukung data, dengan sumber dukungannya. Tabel ini menjadi bagian "Temuan per tahap".

| Tahap | Teknik | Didukung oleh | Status |
|---|---|---|---|
| Masuknya alat | T1105 Ingress Tool Transfer | Zeek kedua hop, pcap egress, MDE | Didukung jaringan dan host |
| Kanal | T1071.001 Web Protocols, T1573 Encrypted Channel | Zeek, log proxy, MDE, analisis berkas IR | Didukung; label C2 dari IR |
| Pengumpulan | T1039 Data from Network Shared Drive | Zeek hop core, MDE | Didukung jaringan dan host |
| Pemaketan | T1560 Archive Collected Data | MDE (berkas dan ukurannya) | Didukung host; alat pemaket belum diketahui |
| Pengiriman | T1030 Data Transfer Size Limits, T1567.002 Exfiltration to Cloud Storage | Zeek, flow DC dan edge, log proxy, MDE | Didukung jaringan dan host |
| Pemicu | Tidak dilabeli | Tim email, MDE | Menunggu IR |

IOC ditulis dengan lima kolom (Day 13 bagian 1.5). Perhatikan kolom pemakaian: layanan bersama tidak masuk daftar blokir IOC, dan fingerprint TLS hanya untuk hunting.

| Nilai (defang) | Tipe | Ditemukan di | Keyakinan sebagai indikator jahat | Pemakaian |
|---|---|---|---|---|
| `hxxp://203.0.113[.]186/files/scan_0602.png` | URL | `http.log` kedua hop, log proxy | Tinggi | Blokir di proxy, hunting |
| `203.0.113[.]186` | IP | `conn.log` hop egress, firewall | Tinggi | Blokir di firewall |
| `cdn.kirana-stat[.]example`, `203.0.113[.]187` | Domain, IP | `http.log` `CONNECT`, `ssl.log`, `x509.log`, log proxy | Tinggi | Blokir, hunting 90 hari di `index=zeek` |
| SHA-256 `9a4e...71c2` (lengkap di tiket) | Hash | `files.log` kedua hop, MDE | Tinggi | Diteruskan ke IR dan MDE |
| `drop.berkasku[.]example`, `203.0.113[.]198`, `203.0.113[.]199` | Domain, IP | `http.log` `CONNECT`, `ssl.log`, log proxy, flow edge | Rendah sebagai indikator jahat (layanan bersama yang dipakai pengguna lain) | Kebijakan kategori proxy dan hunting unggahan, bukan blokir IOC |
| JA3 `7c41...e9a0`, JA4 `t13d1210h1_...` | Fingerprint TLS klien (splice) | pcap egress (tshark) | Sedang | Hunting saja |
| Sertifikat self-signed `CN=cdn.kirana-stat.example` | Sertifikat | `x509.log` hop egress | Sedang | Hunting sertifikat yang sama di IP lain |

**Cara membaca hasil:** keyakinan per baris IOC bukan keyakinan bahwa insiden terjadi. Domain berbagi berkas berkeyakinan rendah sebagai indikator jahat walaupun kesimpulan exfiltration berkeyakinan tinggi, karena memblokirnya sebagai IOC akan menyentuh pemakaian sah dan memberi rasa aman palsu terhadap layanan lain yang sejenis.

### Bagian J: langkah 6, write-up final `INC-2027-073`

**Tujuan:** menulis temuan dengan template final (Bagian K), ringkasan ditulis terakhir, versi dinaikkan saat IR menambah fakta.

Write-up dikirim ke Dimas, Yoga, dan Sari pukul 14:30 sebagai versi 1.1 (versi 1.0 pukul 12:00 belum memuat label C2 dan berkas arsip).

```
# Write-up Investigasi Jaringan: INC-2027-073, unggahan data share Keuangan dari JKT-WS-2066
Analis: <analyst L2 NSM>   Versi: 1.1 (Kamis 2027-06-03 14:30 WIB)   Status: insiden aktif, host diisolasi
Pertanyaan: Q1-Q5 di tiket (08:12)

## Ringkasan
JKT-WS-2066 (10.10.60.146, Akuntansi Pajak) menjalankan skrip dari lampiran email pada Rabu 2027-06-02 16:46,
yang mengunduh executable berkedok gambar dari 203.0.113[.]186 dan menjalankannya. Program itu membuka kanal
TLS tiap ~60 detik ke cdn.kirana-stat[.]example; IR menyatakan pukul 13:40 bahwa kanal itu adalah C2.
Pukul 22:41-23:07 host membaca 1,87 GB dari \\JKT-FS01\KEUANGAN$ (folder Pajak, Treasury, Laporan-Bulanan),
dan Kamis 00:20-01:01 mengunggah 1,60 GB dalam 31 pecahan ke layanan berbagi berkas drop.berkasku[.]example.
Keyakinan: tinggi untuk unduhan, eksekusi, kanal, pembacaan share, dan volume keluar (Zeek + flow + proxy + MDE);
sedang bahwa yang terkirim adalah arsip dari berkas share (ukuran cocok persis, isi belum diperiksa); rendah
untuk berkas mana persisnya yang terkirim. Alert pertama yang benar menyala 16:47:10; insiden dibuka 01:25.

## Timeline (WIB; UTC di kolom terpisah untuk baris pcap)
| Waktu | UTC | Kejadian | Sumber | Bukti / kesimpulan |
(13 baris, Bagian I)

## Timeline deteksi
| Waktu | Alert | Dipegang | Keputusan | Pelajaran |
(9 baris, Bagian G); dwell time deteksi 8 jam 37 menit

## Temuan per tahap
- Masuknya alat [T1105]: GET http://203.0.113[.]186/files/scan_0602.png, UA Microsoft-CryptoAPI/10.0,
  mime application/x-dosexec, 211.456 byte, sha256 9a4e...71c2; certutil.exe di host (MDE).
- Kanal [T1071.001, T1573]: 522 CONNECT (495 sukses, 27 ditolak setelah blokir), median 60,2 s, CV 0,048,
  sertifikat self-signed 2027-05-31 s.d. 2027-06-30; 6 balasan 18-41 KB, dua di antaranya 2 menit sebelum
  tahap berikutnya (kesimpulan sedang: perintah).
- Pengumpulan [T1039]: 1.032 berkas dibuka, resp_bytes 1.874.913.280 dari jkt-fs01 dalam 25 menit 48 detik;
  36x median harian host ini (flow DC 13 bulan).
- Pemaketan [T1560]: kx0602.dat 1.596.456.960 byte (MDE), sama dengan 30 x 50 MiB + 22,5 MiB.
- Pengiriman [T1030, T1567.002]: 31 tunnel tiap 80 s, orig_bytes total 1.598.681.611 (Zeek hop core);
  1.656.180.214 byte IP di flow DC dan 1.662.400.000 di flow edge setelah koreksi (selisih 0,38%).

## IOC
(7 baris lima kolom, Bagian I)

## Data dan metode
- pcap egress inc073_0930Z-1840Z.pcapng (1.673.416 paket, SHA-256 di tiket) dan pcap Rudi 01:40 (hash terpisah)
- arsip Zeek /opt/zeek/logs/2027-06-02/ jam 09-18 UTC (conn, http, files, ssl, x509, dns, smb_mapping, smb_files,
  capture_loss); capture loss maksimal 0,02%; tidak ada jeda JAB-ZEEK-HEALTH-01
- index=proxy dan index=firewall 30 hari (ekspor CSV di folder kasus); flow jkt-flow01 dc-rtr (1:1) dan
  jkt-edge (1:1000) 13 bulan; eve-alert.json jkt-ids01; MDE DeviceNetworkEvents, DeviceProcessEvents, DeviceFileEvents
- alat: tshark 4.6.9, jq, nfdump, Splunk; selisih jam MDE dan Zeek < 1 detik (diukur pada unduhan 16:47:09)

## Batas
- Isi kanal dan isi unggahan tertutup TLS (splice: proxy tidak mendekripsi).
- smb_files.log mencatat FILE_OPEN, bukan FILE_READ (setelan bawaan Zeek); daftar berkas yang dibaca adalah daftar
  yang dibuka; volume dari conn.log.
- Trafik workstation ke workstation di switch akses tidak lewat sensor; laptop di luar kantor tidak terlihat.
- Pemicu (cara skrip dijalankan) hanya terlihat di host.

## Pertanyaan terbuka
- Isi dan enkripsi kx0602.dat, dan apakah berkas itu masih ada (IR, Yoga)
- Daftar berkas share yang memuat data pribadi (pemilik data Keuangan bersama DPO)
- Apakah kredensial dari JKT-WS-2066 dipakai di tempat lain (IR)
- Kenapa SOC-2027-0665 ditutup dengan alasan CRL (SOC lead, review triage)

## Rekomendasi (urut prioritas, pemilik, tenggat)
1. Reimage JKT-WS-2066 setelah IR selesai; reset kredensial pengguna (IR, Agung; Jumat)
2. Bahan keputusan pemberitahuan ke DPO dan Legal: jendela 00:20-01:01, volume, tujuan, folder share (Agus, Ratna; hari ini)
3. Hunting 90 hari di index=zeek untuk kedua domain, sertifikat, dan hash; MDE untuk 8 penerima email lain (SOC; Jumat)
4. Search korelasi per host dan routing: dua sumber alert berbeda di satu host dalam 6 jam ke on-call (Sari; 2027-06-10)
5. Saved search baca massal share Keuangan di luar jam kerja dari smb_files.log dan conn.log (Sari; 2027-06-10)
6. Triage rule lokal 1000131: wajib baca resp_mime_types; tutup "CRL" hanya bila mime sertifikat atau CRL (Dimas; segera)
7. Suppress sid 1000140 untuk jkt-vscan01, tinjau 2027-09-03 (Sari; segera)
8. Kebijakan proxy kategori Online-Storage untuk divisi Keuangan: tinjau splice vs bump dan unggahan (Agung, Nina; Juli)
```

**Cara membaca hasil:** setiap kalimat ringkasan bisa ditunjuk ke baris timeline atau temuan, dan setiap label keyakinan punya dasar. Kata "C2" muncul karena IR sudah menyatakannya, dengan jam pernyataannya. Volume ditulis dengan tiga angka dari tiga sumber, sehingga pertanyaan "yakin 1,6 GB?" bisa dijawab dengan selisih 0,38%, bukan dengan "kira-kira". Rekomendasi 2 tidak menyatakan wajib atau tidak wajib lapor: itu keputusan DPO dan Legal (Day 01 bagian 1.7, Day 12 bagian 1.10); jaringan memberi bahan keputusannya.

**Kapan gagal:** ringkasan menyebut "data Keuangan bocor 1,87 GB", mencampur angka baca share dengan angka unggahan; atau bagian timeline deteksi dihapus karena "membuat tim terlihat buruk", padahal di situlah rekomendasi 4 sampai 7 berasal.

### Bagian K: template write-up pcap dan rubrik penilaian diri

Template ini menjadi format tim mulai Kamis 2027-06-03 untuk setiap insiden jaringan, besar atau kecil; bagian yang tidak relevan diisi "tidak ada" dengan alasan, bukan dihapus. Urutan dan nama bagiannya sama dengan kerangka Day 13 bagian 1.6, ditambah kepala dokumen dan timeline deteksi (bagian 1.4).

```
# Write-up Investigasi Jaringan: <nomor INC>, <judul kasus satu baris>
Analis: <nama>   Versi: <n.n> (<tanggal jam WIB>)   Status: <aktif / ditutup>
Pertanyaan: <Q1..Qn, ditulis di tiket sebelum membuka data>

## Ringkasan  (ditulis TERAKHIR)
<Satu paragraf: apa yang terjadi, host/aset/akun, sejak kapan, apa yang keluar, keyakinan per kesimpulan,
 apa yang belum diketahui. Label C2 hanya bila IR sudah menyatakan fungsi, dengan jamnya.>

## Timeline (WIB; UTC di kolom terpisah untuk baris pcap)
| Waktu | UTC | Kejadian | Sumber (log, field, uid) | Bukti / kesimpulan |

## Timeline deteksi
| Waktu | Alert | Dipegang | Keputusan | Pelajaran |
Dwell time deteksi: <alert benar pertama sampai INC dibuka>

## Temuan per tahap  (ATT&CK hanya untuk tahap yang didukung; sebut sumber dukungannya)

## IOC
| Nilai (defang) | Tipe | Ditemukan di | Keyakinan sebagai indikator jahat | Pemakaian |

## Data dan metode
<sumber + rentang + hash ; titik sensor (hop core / egress / flow) ; capture loss dan jeda log ;
 alat dan versi ; selisih jam antar sumber>

## Batas  (apa yang TIDAK AKAN terlihat dari data ini)

## Pertanyaan terbuka  (apa yang BELUM dikerjakan, dan oleh siapa)

## Rekomendasi  (urut prioritas, bisa dijalankan, pemilik, tenggat)
```

Template generik catatan lama (kepala dengan "Keyakinan keseluruhan", lalu ringkasan, lingkup dan data, timeline, temuan per tahap, IOC empat kolom, batas analisis, rekomendasi) adalah bagian inti template di atas; bentuk terisinya ada di contoh jawaban kasus tertulis Bagian N, dan perbedaannya dengan template PT JAB dibahas di sana.

Rubrik berikut menilai write-up-mu sendiri atau milik rekan dengan skala 0 sampai 2 per baris. Total 16 ke atas dari 20 berarti siap dipakai di kasus nyata. Cari baris bernilai di bawah 2; itulah Day yang perlu dibaca ulang.

| Aspek | 0 | 1 | 2 |
|---|---|---|---|
| Pertanyaan | Tidak ditulis | Ditulis setelah analisis | Ditulis di awal dan dijawab satu per satu |
| Bukti per klaim | Klaim tanpa sumber | Sebagian klaim bersumber | Setiap klaim punya log dan UID/waktu |
| Bukti vs kesimpulan | Tercampur | Dipisah sebagian | Dipisah tegas di timeline dan temuan |
| Angka | Tidak ada atau salah hitung | Ada tetapi tanpa satuan atau cara hitung | Benar, bersatuan, bisa dihitung ulang |
| Baseline | Tidak dipakai | Disebut tanpa angka | Dibandingkan dengan angka |
| False positive | Tidak ditriage | Diabaikan tanpa alasan | Ditriage, alasan dan usulan tuning ditulis |
| ATT&CK | Tidak ada atau berlebihan | Ada tetapi termasuk tahap tanpa bukti | Hanya tahap yang didukung bukti |
| IOC | Tidak di-defang | Di-defang tanpa keyakinan | Di-defang, berkonteks, berkeyakinan |
| Batas | Tidak disebut | Disebut umum | Spesifik, termasuk apa yang perlu dari host |
| Rekomendasi | Tidak ada | Umum ("tingkatkan keamanan") | Spesifik, berurutan, bisa dijalankan |

Untuk write-up PT JAB, dua pemeriksaan tambahan tanpa skor dilakukan sebelum dikirim: apakah titik sensor setiap angka disebut (hop core, egress, atau flow), dan apakah timeline deteksi ada.

### Bagian L: template integrasi Zeek ke Splunk dan status search semalam

**Tujuan:** menjawab Sari dengan checklist yang bisa dicentang untuk sensor atau sumber log berikutnya, dan dengan daftar search yang menyala atau diam beserta alasannya.

Template integrasi berikut mengikuti sepuluh lapisan bagian 1.5. Isian di kanan adalah status `jkt-zeek01` per Kamis 2027-06-03; untuk sensor baru, kolom itu dikosongkan.

```
# Template integrasi Zeek ke Splunk: <sensor>, <tanggal>, pemilik <nama>
 1 SUMBER      log dikirim : conn dns http ssl x509 files notice weird capture_loss smb_* (dce_rpc, kerberos, ntlm)
               format      : JSON ; zona sensor UTC ; arsip /opt/zeek/logs/<tanggal UTC>/
               keputusan   : smb_files bawaan (FILE_OPEN, tanpa FILE_READ) ; alasan: volume ; tinjau Juli
 2 INPUT       inputs.conf satu stanza per log ; index=zeek ; sourcetype=bro:<log>:json eksplisit
               validasi    : | metadata type=sourcetypes index=zeek (semua sourcetype muncul, lastTime segar)
 3 TA          TA for Zeek 1.0.11 (Splunkbase 5466) di indexer + search head ; dicek ulang tiap pembaruan TA/Zeek
               validasi    : index=zeek sourcetype=bro:conn:json | head 1 | table src_ip dest_ip bytes_out conn_state_meaning
 4 WAKTU       _time == ts ; tampilan WIB ; satu event dicocokkan dengan pcap (selisih < 1 s)
 5 CIM         tag network+communicate (All_Traffic) ; pemetaan id.orig_h=src id.resp_h=dest orig_bytes=bytes_out
               resp_bytes=bytes_in ; dns -> Network_Resolution ; http -> Web
 6 CONSTRAINT  macro cim_Network_Traffic_indexes, cim_Network_Resolution_indexes, cim_Web_indexes memuat zeek
               validasi    : | tstats summariesonly=false count from datamodel=Network_Traffic.All_Traffic where index=zeek
 7 ACCEL       diatur ES ; summariesonly=true diuji pada jendela baru ; replay jendela lama pakai false
 8 KESEHATAN   JAB-ZEEK-HEALTH-01 (jeda conn.log > 300 s) ; capture_loss ; volume harian (~18,8 GB) ; deploy = jendela buta
 9 USE CASE    workstation  : saved search hop core per uid (CONNECT + conn) untuk beacon dan volume
               server NAT   : correlation search CIM bytes_out/dest
               share        : baca massal di luar jam kerja (smb_files + conn ke 445)        <- baru, dari INC-2027-073
               korelasi     : alert per host dari >= 2 sumber dalam 6 jam                    <- baru, dari INC-2027-073
               uji          : replay insiden lama (INC-2027-071, -072, -073) harus menyala
10 OPERASIONAL pemilik per search ; severity ; routing (on-call vs antrean pagi) ; tanggal tinjau ; retensi 90 hari
```

Template generik dari catatan lama, untuk lab atau organisasi lain, tetap disimpan karena memuat tiga pencarian dasar:

```
# Pipeline Zeek ke Splunk
1. Sumber log   : <path log Zeek>, format JSON (LogAscii::use_json=T) atau TSV
2. Input        : universal forwarder, [monitor://<path>] dengan index = zeek
3. TA           : TA for Zeek (Splunkbase 5466) di forwarder bila diminta, indexer, dan search head
4. CIM          : Network_Traffic  id.orig_h=src  id.resp_h=dest  id.resp_p=dest_port
                                   orig_bytes=bytes_out  resp_bytes=bytes_in  proto=transport
                  Network_Resolution (dns.log), Web (http.log)   (cek hasil di field sidebar)
5. Validasi     : index=zeek earliest=-15m | stats count by sourcetype
                  zona waktu event = UTC ; jumlah event per jam masuk akal
6. Pencarian    :
   upload besar : index=zeek sourcetype=<conn> | stats sum(bytes_out) as out by src dest | where out > 500000000
   tujuan baru  : bandingkan dest 24 jam terakhir dengan dest 30 hari sebelumnya
   beacon       : streamstats current=f last(_time) as prev by src dest | eval delta=_time-prev
                  | stats count avg(delta) stdev(delta) by src dest | where count > 50 AND stdev(delta) < 0.1*avg(delta)
7. Korelasi     : stats by host_ip atas Zeek + Sysmon EventCode=3 (proses pembuat koneksi)
8. Operasional  : saved search terjadwal, dashboard top talker, pemilik dan tanggal tinjau tiap rule
```

Pencarian beacon di template generik menghitung delta antar-koneksi per pasangan dengan `streamstats`, lalu memilih pasangan yang punya lebih dari 50 koneksi dan simpangan baku delta kurang dari 10 persen rata-ratanya. Ambang itu titik awal dan perlu diukur dengan baseline. Sebelum `streamstats`, urutkan event menurut waktu naik (`| sort 0 _time`), karena hasil pencarian Splunk bawaannya terurut terbaru lebih dulu dan delta akan bernilai negatif bila urutannya terbalik. Di PT JAB, ketiga pencarian generik itu buta untuk workstation bila dijalankan di hop core tanpa `CONNECT`, karena `dest` selalu proxy; versi PT JAB-nya adalah Day 11 bagian 2.7 dan Day 12 bagian 2.1.

Status search semalam, yang diminta Sari. Tabel ini dibaca per baris: "diam" bukan otomatis masalah, selama alasannya benar.

| Search atau rule | Hasil semalam | Kenapa | Tindakan |
|---|---|---|---|
| Rule lokal Suricata 1000131 | Menyala 16:47:10 | Benar | Triage diperbaiki (rekomendasi 6) |
| Beacon hop core (Day 11) | Menyala 18:02 | Benar, 73 interval | Routing: korelasi per host |
| Exfil hop core per `uid` (Day 12) | Menyala 00:45:40 | 525 MB dalam 15 menit | Tetap; catat bahwa laju setengahnya lolos |
| File polos minimal 25 MB per jam (Day 12) | Diam | Unggahan memakai TLS, bukan protokol polos | Benar diam |
| Correlation search CIM volume (Day 13) | Diam | Hanya untuk server dengan NAT sendiri; `dest` workstation adalah proxy | Benar diam |
| `JAB-ZEEK-HEALTH-01` | Diam | Tidak ada jeda log | Benar diam; dicek manual di Bagian B |
| Rule lokal 1000140 | 412 alert | `jkt-vscan01` terjadwal | Suppress per sumber |
| Baca massal share | Tidak ada | Belum pernah dibuat | Dibuat (rekomendasi 5) |

**Cara membaca hasil:** dari delapan baris, hanya satu yang benar-benar celah deteksi (baca massal share) dan satu yang celah proses (routing). Pipeline Zeek ke Splunk sendiri lolos semua lapisan; pelajaran index constraint minggu lalu (Day 13 bagian 2.9) sudah tertutup oleh lapisan 6.

**Kapan gagal:** template dicentang dari dokumentasi, bukan dari hasil query.

### Bagian M: satu halaman untuk Hendra, Nina, dan Agus

Satu halaman berikut dipresentasikan pukul 15:00. Setiap baris merujuk bagian supaya Dimas bisa membaca alasannya bila ditanya.

| Pertanyaan | Jawaban singkat | Bagian |
|---|---|---|
| Apa yang terjadi, sejak kapan | Skrip dari lampiran email menjalankan alat akses jarak jauh di `JKT-WS-2066` Rabu 16:47; kanal tiap 60 detik sampai diisolasi Kamis 01:31 | C, D, H, J |
| Apa yang keluar, seberapa yakin | 1,60 GB ke layanan berbagi berkas, 00:20 sampai 01:01; volume yakin tinggi (tiga sumber cocok); isinya kemungkinan arsip dari share Keuangan yang dibaca 22:41 sampai 23:07 (sedang); berkas persisnya belum diketahui | E, F, I |
| Kenapa baru ketahuan 00:45 | Sensor menyala lima kali sejak 16:47; satu alert ditutup dengan alasan keliru, dua menunggu antrean pagi; tidak ada korelasi per host | G |
| Host lain | Tidak ada yang terlihat; dengan batas: antar workstation dan laptop di luar kantor tidak lewat sensor | H |
| Data pribadi | Bahan untuk DPO dan Legal: jendela, volume, tujuan, folder share; keputusan pemberitahuan di tangan Agus dan Ratna | J |
| Apa yang diperbaiki | Korelasi per host dan routing, rule baca massal share, aturan triage rule PE, suppress pemindai; tidak ada pembelian | J, L |

Dua pertanyaan Hendra di sesi itu dicatat jawabannya. "Kenapa NSM tidak memblokir?" `jkt-ids01` dan `jkt-zeek01` adalah sensor pasif dari SPAN dan TAP (Day 09 bagian 1.9); yang bisa memblokir adalah proxy dan firewall, dan keduanya memblokir sekitar 20 menit setelah alert tinggi dilihat manusia. "Apakah perlu ET Pro atau alat baru?" Tidak dari kasus ini: alert yang dibutuhkan sudah ada, yang kurang adalah cara membacanya; keputusan ET Pro tetap akhir Juli dari data (Day 09 bagian 1.7).

Satu kalimat untuk Hendra: bagian paling mahal dari kasus ini bukan sensor yang buta, tetapi alert benar yang dibaca terpisah.

### Bagian N: kasus tertulis `WS-FIN-07` dan rekonstruksi di lab pribadi

Bagian ini dikerjakan di VM lab terisolasi milikmu, bukan dengan data PT JAB. Kasus tertulis berikut adalah kasus latihan dari catatan lama dengan organisasi fiktif lain, PT Contoh, yang sengaja memakai jaringan tanpa proxy: sensor Zeek dan Suricata di egress kantor pusat melihat workstation langsung, ditambah sensor kedua di segmen server yang melihat trafik ke file server. Membandingkannya dengan `INC-2027-073` melatih hal yang paling sering salah di PT JAB: titik pandang.

**Latar.** Flow dari router inti disimpan 90 hari. Senin pagi, 21 September 2026, NOC melaporkan link internet kantor pusat sempat penuh pada Minggu dini hari, padahal kantor libur. Grafik flow menunjukkan sumbernya satu workstation di bagian keuangan, `10.10.5.23` (hostname fiktif `WS-FIN-07`). Kamu menerima pcap egress dan segmen server untuk Sabtu 19 September 00:00 sampai Senin 21 September 00:00 UTC (48 jam), log Zeek (conn, dns, http, ssl, x509, files, smb_files) dari sensor yang sama, `eve.json` Suricata untuk periode yang sama, dan ringkasan flow 30 hari sebelumnya untuk `10.10.5.23` sebagai baseline. Semua waktu di artefak dalam UTC; WIB adalah UTC+7.

**Pertanyaan investigasi.** (1) Apakah `10.10.5.23` terkompromi, dan bila ya, bagaimana dan kapan? (2) Apakah ada saluran C2: pola, tujuan, sejak kapan? (3) Apakah ada exfiltration: volume, tujuan, waktu, dan data apa bila bisa ditentukan? (4) Apa IOC-nya, seberapa yakin, dan apa rekomendasinya?

Artefak A sampai G disajikan apa adanya; baca semuanya sebelum membuka contoh jawaban.

```
# Artefak A: baseline flow 30 hari
host 10.10.5.23 (WS-FIN-07), 2026-08-19 s.d. 2026-09-18
rata-rata byte keluar per hari kerja   : 85 MB
maksimum byte keluar satu hari         : 240 MB
rata-rata byte keluar akhir pekan      : 3 MB   (laptop biasanya mati)
tujuan eksternal teratas               : layanan update OS, layanan email cloud, portal bank (rentang IP dikenal)
pernah ke 198.51.100.7 / 203.0.113.50 / 192.0.2.80 : tidak

# Artefak B: http.log (zeek-cut ts uid id.orig_h id.resp_h method host uri user_agent status_code resp_mime_types)
1789780360.412  CHt1a9  10.10.5.23  198.51.100.7  GET  198.51.100.7  /files/scan_0919.png  Microsoft-CryptoAPI/10.0  200  application/x-dosexec
# files.log (zeek-cut ts uid id.orig_h id.resp_h is_orig source mime_type filename total_bytes sha256)
1789780360.655  CHt1a9  10.10.5.23  198.51.100.7  F  HTTP  application/x-dosexec  scan_0919.png  184320  4b1d...9e07
# Timestamp 1789780360 adalah 2026-09-19 01:12:40 UTC.

# Artefak C: dns.log (ts id.orig_h query qtype_name rcode_name answers TTLs)
1789780398.020  10.10.5.23  upd-check.example  A  NOERROR  203.0.113.50  300.0
# ssl.log (ts uid id.orig_h id.resp_h version server_name established ja3), paket JA3 dimuat
1789780400.118  CA77k2  10.10.5.23  203.0.113.50  TLSv12  upd-check.example  T  a1f3...c0d2
1789780460.904  CQ02mf  10.10.5.23  203.0.113.50  TLSv12  upd-check.example  T  a1f3...c0d2
... (berulang)
# x509.log (certificate.subject certificate.issuer certificate.not_valid_before certificate.not_valid_after)
CN=upd-check.example  CN=upd-check.example  2026-09-17T00:00:00Z  2026-10-17T00:00:00Z

# Artefak D: ringkasan conn.log ke 203.0.113.50
koneksi dari 10.10.5.23 ke 203.0.113.50:443, 2026-09-19 01:13:20 s.d. 2026-09-20 23:59:41
jumlah koneksi           : 2.794
delta 10 koneksi pertama : 57 63 59 61 66 55 60 62 58 60   (detik)
orig_bytes per koneksi   : 590-640
resp_bytes per koneksi   : 1.050-1.180, kecuali 6 koneksi dengan resp_bytes 18.000-41.000
conn_state               : SF untuk semua koneksi

# Artefak E: smb_files.log dari sensor segmen server (ts id.orig_h id.resp_h action path name size, diringkas)
2026-09-20T01:30:05Z  10.10.5.23  10.10.2.10  SMB::FILE_OPEN  \\FS01\Finance  2026\Q3\ledger_Q3.xlsx      4194304
2026-09-20T01:30:06Z  10.10.5.23  10.10.2.10  SMB::FILE_READ  \\FS01\Finance  2026\Q3\ledger_Q3.xlsx      4194304
... 1.912 operasi FILE_READ ke 1.204 berkas berbeda di \\FS01\Finance s.d. 01:52:40
total byte dibaca (resp_bytes conn.log ke 10.10.2.10:445, 01:30-01:53) : 2,31 GB

# Artefak F: conn.log (ts id.orig_h id.resp_h id.resp_p duration orig_bytes resp_bytes conn_state)
1789870210.0  10.10.5.23  192.0.2.80  443  61.2  52430112  4810  SF
1789870288.4  10.10.5.23  192.0.2.80  443  59.8  52430112  4807  SF
... 37 koneksi, 2026-09-20 02:10:10 s.d. 02:58:03, orig_bytes identik 52430112
# ssl.log
server_name files-drop.example  version TLSv13  ja3 a1f3...c0d2
# Timestamp 1789870210 adalah 2026-09-20 02:10:10 UTC.

# Artefak G: alert Suricata (diringkas dari eve.json)
signature                                                    sid      count  src          dest
LOCAL TLS self-signed certificate to rare domain             9000101  1      203.0.113.50 10.10.5.23
LOCAL HTTP PE download with image extension                  9000117  1      198.51.100.7 10.10.5.23
LOCAL SCAN multiple SYN to many hosts on 445                 9000204  412    10.10.1.5    10.10.0.0/16
# 10.10.1.5 = server vulnerability scanner tim infrastruktur, terjadwal setiap Sabtu 02:00 UTC.
```

Dua catatan membaca artefak yang tidak berlaku sama di PT JAB. Pertama, baris `SMB::FILE_READ` di artefak E hanya muncul bila sensor PT Contoh menambahkan aksi itu ke `SMB::logged_file_actions`, karena setelan bawaan Zeek tidak mencatatnya [S6]; `size` tetap ukuran berkas, bukan byte yang dipindahkan, sehingga volume diambil dari `resp_bytes`. Kedua, `orig_bytes` yang identik persis di artefak F mungkin karena sensor melihat koneksi langsung; di balik proxy, ukuran tunnel hanya hampir sama (Bagian F).

<details><summary>Contoh jawaban kasus tertulis (buka setelah write-up-mu selesai)</summary>

Poin baca utama: unduhan PE berkedok gambar dari IP langsung dengan User-Agent CryptoAPI (T1105); DNS `upd-check[.]example` 38 detik setelah unduhan dan koneksi TLS pertama 2 detik setelah DNS; rata-rata sepuluh delta pertama 60,1 detik dengan rentang 55 sampai 66, jitter kurang dari 10 persen, request stabil 590 sampai 640 byte, sertifikat self-signed yang diterbitkan dua hari sebelum unduhan dan berlaku 30 hari (T1071.001, T1573); enam respons 18 sampai 41 KB kemungkinan perintah atau modul; 1.204 berkas dibaca dari share keuangan dalam 22 menit pada Minggu 01:30 UTC (08:30 WIB, hari libur), 2,31 GB menurut `resp_bytes` (T1039); 37 kali 52.430.112 byte sama dengan 1.939.914.144 byte, sekitar 1,94 GB (1,81 GiB), dalam pecahan identik sekitar 50 MiB ke tujuan non-C2 lewat TLS 1.3 (T1030, T1048.002), dengan JA3 yang sama dengan klien C2; 1,94 GB keluar dibanding 2,31 GB dibaca cocok dengan pola baca, kompres, kirim, tetapi itu interpretasi; alert 9000204 terbanyak tetapi pemindai terjadwal, usulan `suppress gen_id 1, sig_id 9000204, track by_src, ip 10.10.1.5` dengan tanggal tinjau; tidak ada alert untuk exfiltration, dan itu bukan bukti bersih. Perintah timeline lama: `zeek-cut ts uid id.orig_h id.resp_h id.resp_p service orig_bytes < conn.log | awk '$3=="10.10.5.23"' | sort -n > timeline_ws-fin-07.tsv`, lalu pilih baris titik balik (unduhan, koneksi C2 pertama, respons besar, SMB pertama, upload pertama dan terakhir), masing-masing dengan sumber log dan UID-nya.

```
# Write-up Investigasi Jaringan: exfiltration data keuangan dari WS-FIN-07
Analis: <nama>    Tanggal: 2026-09-21    Keyakinan keseluruhan: tinggi untuk C2 dan volume keluar; sedang untuk jenis data

## Ringkasan
Workstation 10.10.5.23 (WS-FIN-07) mengunduh executable yang disamarkan sebagai gambar pada
2026-09-19 01:12:40 UTC, lalu berkomunikasi teratur (sekitar 60 detik) ke 203.0.113[.]50
(upd-check[.]example) selama sisa akhir pekan. Pada 2026-09-20 01:30-01:52 UTC host ini membaca
1.204 berkas (2,31 GB) dari \\FS01\Finance, dan pada 02:10-02:58 UTC mengirim 1,94 GB dalam
37 pecahan identik ke 192.0.2[.]80 (files-drop[.]example). Jaringan membuktikan volume, tujuan,
dan urutan; jenis data yang keluar belum dapat dipastikan karena isinya terenkripsi.

## Lingkup dan data
- Pertanyaan: kompromi, C2, exfiltration, IOC
- Data: pcap dan log Zeek egress + segmen server 2026-09-19 00:00 s.d. 2026-09-21 00:00 UTC;
  eve.json Suricata; baseline flow 30 hari
- Batas visibilitas: isi TLS tertutup; tidak ada sensor antar workstation; tidak ada data host

## Timeline (UTC)
| Waktu | Kejadian | Sumber | Bukti / kesimpulan |
|---|---|---|---|
| 09-19 01:12:40 | Unduhan PE "scan_0919.png" dari 198.51.100[.]7 | http.log, files.log (CHt1a9) | Bukti |
| 09-19 01:13:18 | Query A upd-check[.]example ke 203.0.113[.]50 | dns.log | Bukti |
| 09-19 01:13:20 | Koneksi TLS pertama ke 203.0.113[.]50, sertifikat self-signed | ssl.log, x509.log | Bukti |
| 09-19 s.d. 09-20 | 2.794 koneksi, delta sekitar 60 s | conn.log | Bukti; "C2" adalah kesimpulan |
| 09-20 01:30-01:52 | 1.204 berkas dibaca dari \\FS01\Finance, 2,31 GB | smb_files.log, conn.log | Bukti; "staging" adalah kesimpulan |
| 09-20 02:10-02:58 | 37 upload x 52.430.112 byte ke 192.0.2[.]80 | conn.log, ssl.log | Bukti; "exfiltration" adalah kesimpulan |

## Temuan per tahap (ATT&CK)
- Masuknya alat: unduhan PE disamarkan [T1105]. Pemicu unduhan tidak terlihat di jaringan.
- C2: beacon TLS teratur ke domain dan sertifikat baru [T1071.001, T1573].
- Pengumpulan: baca massal dari share keuangan pada hari libur [T1039].
- Exfiltration: pecahan 50 MiB lewat TLS ke tujuan non-C2 [T1030, T1048.002].

## IOC (ter-defang)
| Tipe | Nilai | Konteks | Keyakinan |
|---|---|---|---|
| IP | 198.51.100[.]7 | sumber unduhan PE | tinggi |
| IP | 203.0.113[.]50 | server C2 | tinggi |
| domain | upd-check[.]example | SNI dan DNS C2 | tinggi |
| IP | 192.0.2[.]80 | tujuan exfiltration | tinggi |
| domain | files-drop[.]example | SNI exfiltration | tinggi |
| sha256 | 4b1d...9e07 | berkas yang diunduh | tinggi |
| JA3 | a1f3...c0d2 | klien C2 dan exfil | sedang (bisa dipakai aplikasi lain) |

## Batas analisis
- Jenis data yang keluar disimpulkan dari urutan dan volume, bukan dari isi.
- Cara unduhan dipicu tidak diketahui.
- Aktivitas host lain ke tujuan yang sama belum diperiksa di luar periode capture.

## Rekomendasi
1. Isolasi WS-FIN-07 dan ambil image memori serta disk sebelum dimatikan.
2. Blokir kelima IOC jaringan di proxy dan firewall; cari host lain yang menghubunginya (flow 90 hari).
3. Minta tim endpoint memastikan proses pembuat koneksi, cara eksekusi, dan isi arsip bila tersisa.
4. Laporkan ke pemilik data keuangan dan tim legal untuk penilaian kewajiban pemberitahuan.
5. Deteksi baru: upload TLS di atas 500 MB ke tujuan yang belum pernah dilihat dalam 30 hari.
6. Tuning: suppress alert 9000204 untuk scanner 10.10.1.5 dengan tanggal tinjau.
```

Hal yang membuat contoh ini layak dicontoh: ringkasan bisa dibaca manajemen dalam satu menit, setiap baris timeline punya sumber, kata "C2" dan "exfiltration" diberi label kesimpulan, keyakinan JA3 lebih rendah daripada IP, dan rekomendasi nomor 1 menjaga bukti host sebelum hilang. Yang kurang dibanding template PT JAB: zona waktu satu (UTC) untuk laporan yang dibaca orang WIB, tanpa timeline deteksi, dan label "C2" dipakai tanpa korroborasi host, hal yang di PT JAB menunggu IR.

</details>

**Prasyarat:** kasus tertulis di atas, data lab sepadan, atau pcap publik dengan cerita serupa (cek lisensinya, Day 13 bagian 1.9); Wireshark 4.6.x, Zeek, Suricata 8.0.x, Splunk lab opsional; jaringan host-only `192.168.56.0/24`; tanpa data kerja.

1. **Kerjakan tanpa contoh.** Jangan buka contoh jawaban. Dari artefak A sampai G, jawab keempat pertanyaan dengan metode v1.0 dan isi template Bagian K.
2. **Hitung ulang angka.** Rata-rata delta, total byte exfiltration, rasio terhadap baseline. Tulis cara hitungnya.
3. **Bandingkan.** Buka contoh jawaban dan nilai hasilmu dengan rubrik Bagian K. Catat baris yang nilainya di bawah 2.
4. **Bangun ulang di lab.** Buat versi kecil skenario di lab sendiri: unduhan berkas dari web server lab, koneksi berkala dengan skrip `curl` dalam loop ke server lab, salinan berkas dari share lab, dan upload ke server lab. Proses capture-nya dengan Zeek dan Suricata. Pastikan log yang kamu hasilkan memperlihatkan pola yang sama dengan artefak. Tambahkan varian kedua dengan proxy Squid lab di antara klien dan internet lab, lalu ulangi pengukuran di dua titik (klien ke proxy dan proxy ke luar) seperti hop core dan hop egress PT JAB.
5. **SMB.** Jalankan Zeek sekali dengan setelan bawaan dan sekali dengan `redef SMB::logged_file_actions += { SMB::FILE_READ };`; catat selisih jumlah baris `smb_files.log` dan bandingkan jumlah `size` dengan `resp_bytes`.
6. **Splunk.** Isi template integrasi Bagian L untuk lab-mu, kirim log Zeek ke index lab, jalankan ketiga pencarian template generik dan versi per `uid` untuk varian proxy. Catat pencarian mana yang menemukan pola dan mana yang perlu ambang baru.
7. **Red team of one.** Tulis setengah halaman: di mana kesimpulanmu paling lemah, data apa yang akan mengubahnya, dan bias apa yang mungkin memengaruhi (misalnya confirmation bias terhadap hipotesis C2).

**Hasil yang sebaiknya tersimpan:**

- Write-up kasus tertulis hasil kerjamu sendiri, sebelum dan sesudah dibandingkan dengan contoh.
- Lembar hitung angka (delta, total byte, rasio baseline).
- Skor rubrik dan daftar aspek yang perlu diperbaiki.
- Log Zeek dan `eve.json` dari rekonstruksi lab, dengan dan tanpa proxy, plus catatan perbedaannya dengan artefak.
- Perbandingan `smb_files.log` bawaan dan dengan `FILE_READ`.
- Template integrasi yang terisi dan hasil pencarian Splunk.
- Catatan red team of one.

Rencana lanjut setelah capstone: catat Day yang paling lemah menurut rubrik, kerjakan tiga pcap publik yang menyasar kelemahan itu dengan aturan Day 13 bagian 2.10, dan bawa alur ini ke Splunk lab secara nyata.

### Troubleshooting ringkas

Tabel ini menggabungkan masalah yang paling sering muncul saat capstone dan saat mengerjakan kasus tertulis. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Timeline tidak urut atau bertabrakan | Campuran UTC dan WIB | Satu zona per tabel, UTC di kolom terpisah (Bagian I) |
| Tidak menemukan hash di `files.log` | Zeek dijalankan tanpa `local` | Jalankan ulang dengan `local` (Day 08) |
| Delta beacon negatif di Splunk | Event terurut terbaru dulu | `sort 0 _time` sebelum `streamstats` |
| JA3/JA4 kosong di `ssl.log` | Paket fingerprint tidak dimuat di Zeek | Pakai `tls.handshake.ja3` dan `tls.handshake.ja4` dari tshark, atau `tls.ja3` dari `eve.json` bila diaktifkan |
| JA4 egress tidak cocok dengan klien | Koneksi di-bump, ClientHello milik proxy | Cek `tls=` di log proxy (Day 06 bagian 1.7) |
| Byte SMB tidak cocok dengan `smb_files` | `size` adalah ukuran berkas, bukan byte yang ditransfer | Pakai `resp_bytes` `conn.log` untuk volume |
| Tidak ada `SMB::FILE_READ` | Setelan bawaan `SMB::logged_file_actions` | Baca volume dari `conn.log`; tambahkan aksi bila perlu (Bagian E) |
| Workstation tidak ada di pcap egress | Proxy di antara host dan sensor | Hop core dan log proxy (Bagian C) |
| Volume dari proxy jauh lebih kecil | Kolom `bytes` adalah ukuran balasan ke klien | `orig_bytes` per `uid` di hop core (Bagian F) |
| Flow dan Zeek berselisih beberapa persen | Header IP dan TCP, sampling edge | Tambahkan 52 byte per paket; koreksi sampling (Bagian F) |
| Saved search exfil tidak menangkap tunnel terakhir | Baris `conn.log` ditulis saat koneksi selesai | Perlebar jendela untuk laporan (Bagian F) |
| Alert benar menunggu sampai pagi | Routing per severity, tanpa korelasi per host | Search korelasi per host (Bagian G) |

## 5. Kesalahan umum dan jebakan

- **Memaksa cerita rapi.** Kasus nyata ambigu; tulis ketidakpastian per tahap, jangan mengisi celah dengan tebakan.
- **Satu label keyakinan untuk seluruh laporan.** Volume bisa tinggi sementara jenis data tetap rendah (bagian 1.3).
- **Menilai alert dari jumlahnya.** Alert terbanyak di kedua kasus justru pemindai terjadwal.
- **Menutup alert dari satu field.** User-Agent CryptoAPI tidak menjelaskan executable; baca `resp_mime_types`.
- **Melewati baseline.** Tanpa flow 13 bulan, 1,87 GB hanya angka; dengan baseline, ia 36 kali median harian.
- **Mencampur angka baca share dan angka unggahan.** 1,87 GB dibaca, 1,60 GB keluar; keduanya fakta berbeda.
- **Menjumlahkan `size` di `smb_files.log` sebagai volume, atau membaca ketiadaan `FILE_READ` sebagai tidak ada baca.**
- **Menyebut keluarga malware atau "C2" sebelum IR.** Tidak ada bukti jaringan untuk keluarga; label C2 menunggu fungsi berkas.
- **Memblokir layanan bersama sebagai IOC.** Layanan berbagi berkas diatur lewat kebijakan kategori.
- **Menghapus timeline deteksi dari laporan.** Perbaikan proses justru lahir dari sana.
- **Berhenti di jaringan.** Konfirmasi proses, berkas, dan isi butuh host; tulis sebagai pertanyaan terbuka yang spesifik.

## 6. Catatan terkini

Bagian ini menampung status versi dan perubahan per 2026-10-29 yang perlu diingat saat memakai template di atas.

- Zeek 9.0.1 LTS dan 8.0.11 terbit 26 Oktober 2026 [S14]; dalam cerita, `jkt-zeek01` masih 9.0.0, dan setiap pembaruan Zeek atau TA diperlakukan sebagai perubahan yang mewajibkan validasi lapisan 2 sampai 6 template integrasi. Suricata 8.0.7 masih stabil dan cabang 7.0.x EOL [S15]; Wireshark 4.6.9 stabil, 4.4.19 old stable, 5.0.0rc1 rilis pengembangan [S12].
- TA for Zeek (Splunkbase 5466) masih 1.0.11 (21 Agustus 2025), dirawat Corelight, kompatibel Splunk 9.3, 9.4, dan 10.0 sampai 10.7, CIM 6.x [S3].
- ATT&CK v20: T1105 versi 2.6 (11 September 2026) menyebut `certutil` di deskripsi dan contoh prosedur [S9]; T1567.002 versi 1.3 (12 Mei 2026) dengan detection strategy DET0570 [S8].
- Setelan bawaan `SMB::logged_file_actions` di referensi skrip Zeek saat ini tidak memuat `FILE_READ` [S6]; cek ulang di versi yang terpasang sebelum menyimpulkan dari `smb_files.log`.
- Day 15 sampai 19 memperluas capstone ke ECH dan JA4+, DNS terenkripsi dan QUIC, log jaringan cloud, capture skala besar, serta SMB dan Kerberos.

## 7. Cheat sheet

```
KASUS      Q tertulis + jendela WIB/UTC -> 0 bukti (pcap ring + arsip Zeek tanggal UTC + ekspor proxy/fw, sha256)
           -> 1 orientasi (egress + hop core + capture_loss) -> 2 batasi (hop core = workstation) -> 3 protokol
           -> 4 pola (angka + baseline) -> 5 korelasi (flow, proxy, MDE, scoping) -> 6 write-up
MASUK      http.log + files.log kedua hop : ekstensi vs mime_type, Host = IP, UA CryptoAPI ; T1105
KANAL      CONNECT hop core : n, median, CV, status 403 setelah blokir ; ssl/x509 egress bila splice ; T1071.001/T1573 setelah IR
SHARE      smb_mapping + smb_files (bawaan FILE_OPEN saja) ; volume = resp_bytes conn.log :445 ; size = ukuran berkas ; T1039
KIRIM      CONNECT + conn per uid ; pecahan hampir sama di balik proxy ; flow DC (+52 B/paket) + edge (x1000) ; T1030, T1567.002
ALERT      triage per sid, bukan jumlah ; suppress by_src + tanggal tinjau ; tanpa alert != bersih ; korelasi per host
YAKIN      per kesimpulan: volume tinggi (3 sumber) | isi rendah-sedang | C2 dari IR
WRITE-UP   kepala+versi | ringkasan (TERAKHIR) | timeline WIB(+UTC) | timeline deteksi | temuan+ATT&CK | IOC 5 kolom
           | data+metode | batas | terbuka | rekomendasi (pemilik, tenggat)
INTEGRASI  1 sumber 2 input 3 TA 4 waktu 5 CIM 6 constraint 7 accel 8 kesehatan 9 use case per titik pandang 10 routing
RUBRIK     10 aspek x 0-2 ; >= 16 siap dipakai ; + titik sensor per angka + timeline deteksi
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "Alert pertama menyala pukul 16:47 dan insiden baru dibuka pukul 01:25, jadi sensor NSM gagal." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Sensor dan saved search menyala lima kali, empat di antaranya benar positif. Yang gagal adalah triage yang membaca satu field, routing yang menahan alert sedang sampai pagi, dan ketiadaan korelasi per host. Satu celah deteksi nyata adalah tidak adanya rule baca massal share.

Lihat bagian 1.6.

</details>

**2. Skenario keputusan.** `smb_files.log` hanya memuat `SMB::FILE_OPEN` untuk 1.032 berkas. Apa yang ditulis di write-up tentang volume baca?

- A. Tidak ada bukti pembacaan, karena tidak ada `FILE_READ`.
- B. Jumlah kolom `size` 1.838.402.519 byte sebagai volume baca.
- C. `resp_bytes` `conn.log` ke port 445, 1.874.913.280 byte, dengan catatan bahwa daftar berkas adalah daftar yang dibuka.

<details><summary>Jawaban</summary>

C. A keliru karena setelan bawaan Zeek memang tidak mencatat `FILE_READ`. B keliru karena `size` adalah ukuran total berkas, bukan byte yang dipindahkan; kecocokannya dengan `resp_bytes` hanya penguat.

Lihat Bagian E.

</details>

**3. Pertanyaan jebakan.** Ringkasan rekan berbunyi: "1,87 GB data Keuangan bocor ke berkasku." Apa yang salah?

<details><summary>Jawaban</summary>

1,87 GB adalah volume yang dibaca dari share; yang keluar 1,60 GB. Bahwa isi unggahan adalah arsip berkas share baru berkeyakinan sedang (ukuran cocok dengan berkas di host, isi belum diperiksa), dan berkas mana yang terkirim masih rendah. Label keyakinan ditulis per kesimpulan.

Lihat bagian 1.3 dan Bagian J.

</details>

**4. Skenario keputusan.** Dimas ingin memasukkan `drop.berkasku.example` ke daftar blokir IOC dengan keyakinan tinggi. Mana yang tepat?

- A. Setuju, karena domain itu tujuan exfiltration.
- B. Catat sebagai layanan bersama berkeyakinan rendah sebagai indikator jahat, atur lewat kebijakan kategori proxy dan hunting unggahan.
- C. Abaikan domain itu dan blokir IP-nya saja.

<details><summary>Jawaban</summary>

B. Dua pengguna lain memakainya secara sah, sehingga blokir IOC menyentuh pemakaian sah dan memberi rasa aman palsu terhadap layanan sejenis. C keliru karena layanan itu memakai lebih dari satu alamat dan alamatnya bisa berganti.

Lihat Bagian H dan I.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Bu Nina, dalam tiga kalimat, kenapa angka 1,60 GB bisa dipercaya walaupun isinya terenkripsi.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Angka itu dihitung dari sensor di core switch dan dicocokkan dengan dua catatan lalu lintas router yang dikumpulkan terpisah, dan selisihnya hanya 0,38 persen setelah header dan sampling dihitung. Ukurannya juga sama persis dengan berkas 1,6 GB yang ditemukan di komputer itu. Yang belum kami ketahui adalah isi berkas itu, dan itu sedang diperiksa tim IR."

Kesalahan yang sering muncul:
- Menyebut angka baca share (1,87 GB) sebagai angka yang keluar.
- Menyatakan isi data padahal hanya volume yang terbukti.

</details>

**6. Pertanyaan jebakan.** "Pipeline Zeek ke Splunk lolos semua lapisan, jadi correlation search CIM volume pasti menangkap unggahan workstation." Benarkah?

<details><summary>Jawaban</summary>

Tidak. CIM menyamakan nama field, bukan titik pandang. Di hop core, `dest` setiap tunnel workstation adalah proxy, sehingga search CIM PT JAB sengaja hanya untuk server dengan NAT sendiri; workstation memakai saved search hop core per `uid`.

Lihat bagian 1.5 dan Bagian L.

</details>

**7. Interview question (English).** "Tell me about an end-to-end network investigation you led, and what you would change afterwards."

<details><summary>Sample answer</summary>

"In a lab exercise modelled on an ISP SOC, a finance workstation behind an explicit proxy downloaded a Windows executable disguised as an image, started a 60-second TLS channel, read 1.87 GB from a finance share after hours, and then pushed 1.6 GB to a file-sharing service in 31 near-identical chunks. I wrote the questions first, preserved and hashed the evidence, and worked from the core sensor because the egress view only shows the proxy. I measured the channel interval and variation, took volume per connection from Zeek and cross-checked it against two flow sources, and only called the channel C2 after the endpoint team confirmed the binary's function. The report had a timeline with one time zone, defanged indicators with a confidence and usage column, explicit limits, and a separate detection timeline. That timeline showed the sensors had alerted eight hours earlier, so the fixes were per-host alert correlation, routing, and a rule for bulk share reads, not new tools."

What makes this answer strong: it shows vantage-point awareness, numbers validated by independent sources, discipline about labels, and honest process lessons instead of blaming tools.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | MITRE ATT&CK: T1105, T1071.001, T1573, T1039, T1030, T1048.002 | https://attack.mitre.org/ | primer | diakses 2026-10-10 | Tinggi. Label teknik; halaman teknik di https://attack.mitre.org/techniques/T1039/ dan https://attack.mitre.org/techniques/T1048/002/ |
| S2 | Zeek docs: Logs (conn, dns, http, ssl, files, smb) | https://docs.zeek.org/en/current/logs/index.html | primer | diakses 2026-10-09 | Tinggi. Field artefak, `files.log` dengan `uid` dan `is_orig` |
| S3 | Splunkbase: TA for Zeek (app 5466) | https://splunkbase.splunk.com/app/5466 | primer | diakses 2026-10-10, dicek ulang 2026-10-29 | Tinggi. 1.0.11 (21 Agustus 2025), Corelight, Splunk 9.3 sampai 10.7, CIM 6.x; nama sourcetype dicek di instalasi |
| S4 | Suricata docs: Eve JSON output dan thresholding | https://docs.suricata.io/en/latest/output/eve/eve-json-output.html | primer | diakses 2026-10-09 | Tinggi. Field alert dan sintaks suppress |
| S5 | Network-Forensics Day 01-13 (lokal) | (lokal) | rujukan internal | 2026-10-10, diperbarui 2026-10-29 | Alat, pola, sensor, metode v1.0, dan insiden PT JAB sebelumnya |
| S6 | Zeek script reference: base/protocols/smb/main.zeek | https://docs.zeek.org/en/current/scripts/base/protocols/smb/main.zeek.html | primer | diakses 2026-10-29 | Tinggi. Enum `SMB::Action` (termasuk `FILE_READ`), `SMB::logged_file_actions` bawaan tanpa `FILE_READ`, `size` = ukuran total berkas |
| S7 | Zeek docs: SMB logs | https://docs.zeek.org/en/current/logs/smb.html | primer | diakses 2026-10-29 | Tinggi. Contoh `smb_mapping.log` dan `smb_files.log`; arah transfer dibaca dari log lain |
| S8 | MITRE ATT&CK: T1567.002 Exfiltration to Cloud Storage | https://attack.mitre.org/techniques/T1567/002/ | primer | diakses 2026-10-29 | Tinggi. Versi 1.3, 12 Mei 2026, DET0570 |
| S9 | MITRE ATT&CK: T1105 Ingress Tool Transfer | https://attack.mitre.org/techniques/T1105/ | primer | diakses 2026-10-29 | Tinggi. Versi 2.6, 11 September 2026; `certutil` di deskripsi dan contoh prosedur |
| S10 | LOLBAS Project: Certutil | https://lolbas-project.github.io/lolbas/Binaries/Certutil/ | sekunder (proyek komunitas terkurasi) | diakses 2026-10-29 | Sedang-tinggi. Fungsi unduh `certutil` (T1105) dan User-Agent `Microsoft-CryptoAPI/10.0` atau `CertUtil URL Agent` |
| S11 | Suricata docs: Global thresholds (suppress) | https://docs.suricata.io/en/latest/configuration/global-thresholds.html | primer | diakses 2026-10-29 | Tinggi. Sintaks `suppress` dengan `track by_src`, `by_dst`, `by_either` |
| S12 | Wireshark: Download | https://www.wireshark.org/download.html | primer | diakses 2026-10-29 | Tinggi. 4.6.9 stabil, 4.4.19 old stable, 5.0.0rc1 |
| S13 | Splunk Help: CIM 6.2 data model Network Traffic | https://help.splunk.com/en/data-management/common-information-model/6.2/data-models/network-traffic | primer | diakses 2026-10-29 | Tinggi. Dataset `All_Traffic`, tag `network` dan `communicate`, definisi `bytes_in`, `bytes_out`, `src`, `dest` |
| S14 | Zeek: Get Zeek | https://zeek.org/get-zeek/ | primer | diakses 2026-10-29 | Tinggi. 9.0.1 LTS dan 8.0.11, 26 Oktober 2026 |
| S15 | Suricata: Download | https://suricata.io/download/ | primer | diakses 2026-10-29 | Tinggi. 8.0.7 (15 September 2026); 7.0.17 terakhir, 7.0.x EOL |

**Catatan sumber:** skenario `INC-2027-073`, kasus tertulis `WS-FIN-07`, hash, sid, dan angka di Day ini fiktif dan disusun agar konsisten satu sama lain; angka turunan dihitung dari artefak itu (misalnya rata-rata delta 60,1 detik, 37 kali 52.430.112 = 1.939.914.144 byte, 30 kali 50 MiB ditambah 22,5 MiB = 1.596.456.960 byte, selisih flow 0,38%). Overhead TLS 22 byte per record dan header 52 byte per paket adalah hitungan kasar untuk TLS 1.3 dengan AEAD dan TCP dengan opsi timestamp. Pemetaan field CIM mengikuti pola umum TA dan dicek di field sidebar setelah TA terpasang; nama sourcetype `bro:smb_files:json` dan `bro:smb_mapping:json` mengikuti pola PT JAB dan divalidasi dengan `| metadata`. Search korelasi per host di Bagian G adalah usulan; nama field notable (`dest_nt_host`, `src_nt_host`, `source`) perlu dicek di versi Enterprise Security yang terpasang. Pencatatan `CONNECT` dan TLS di balik proxy perlu dicek di versi Zeek dan proxy-mu (Day 08). Halaman docs.zeek.org untuk log SMB tidak menampilkan contoh `SMB::FILE_READ`; keberadaan aksi itu dan setelan bawaannya diambil dari referensi skrip [S6].
