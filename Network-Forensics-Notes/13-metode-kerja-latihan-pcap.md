---
day: 13
title: 'Metode kerja analisis pcap dan log jaringan: alur dari pertanyaan sampai write-up, dataset latihan publik, dan integrasi Zeek ke Splunk dengan CIM'
researched_on: 2026-10-29
versions_checked: 'Wireshark 4.6.9 stabil, 4.4.19 old stable, 5.0.0rc1 rilis pengembangan (halaman unduhan, dicek 2026-10-29); Zeek 9.0.1 LTS (26 Okt 2026), LTS sebelumnya 8.0.11; Suricata 8.0.7 (15 Sep 2026), cabang 7.0.x EOL; TA for Zeek 1.0.11 (Splunkbase 5466, 21 Agu 2025, dirawat Corelight; Splunk 9.3, 9.4, 10.0 sampai 10.7; CIM 6.x); Splunk CIM 6.2 data model Network Traffic (dataset All_Traffic, tag network dan communicate); perintah tstats (argumen summariesonly, bawaan false); NIST SP 800-86 (Agustus 2006); rujukan Day 01-12'
---

# Day 13: Metode kerja analisis pcap, latihan, dan integrasi ke Splunk

Cakupan: alur kerja yang bisa diulang untuk menganalisis pcap dan log jaringan apa pun (pertanyaan, pengamanan bukti, orientasi, pembatasan, pendalaman protokol, pola, korelasi, write-up), cara menulis IOC, timeline, dan keyakinan, cara berlatih dengan dataset publik secara aman, dan cara membawa log Zeek dan Suricata ke Splunk dengan pemetaan CIM yang benar-benar bekerja.

Day ini menyusun metode kerja dari sisi forensik dan defensif. Dataset publik dirujuk untuk metode, bukan untuk menyalin hasilnya; lisensi dan ketentuan tiap sumber dicek sendiri sebelum dipakai. Data PT JAB fiktif, lab memakai jaringan host-only pribadi, dan IOC di-defang di laporan.

## Ide inti

Day 01 sampai 12 memberi alat dan pola: Wireshark, protokol, scan, DNS dan HTTP, TLS, Zeek, Suricata, flow, beaconing, exfiltration. Day ini mengikat semuanya menjadi satu metode kerja yang sama untuk setiap kasus: mulai dari pertanyaan yang ditulis, amankan bukti sebelum ring buffer menimpanya, orientasi dulu sebelum membaca paket, persempit ke data yang menjawab pertanyaan, dalami protokol dan pola yang relevan, korelasikan dengan sumber lain dan host, lalu tulis temuan yang memisahkan bukti dari kesimpulan. Metode ini tidak membuat analisis lebih pintar; ia membuat analisis bisa diulang, diperiksa orang lain, dan dihentikan pada saat yang tepat. Dua analis dengan metode yang sama boleh berbeda kesimpulan, tetapi harus bisa menunjuk langkah mana yang membuat mereka berbeda.

Logika yang sama berlaku di setiap skala: pcap 50 MB di Wireshark, log Zeek satu hari di `jq`, dan jutaan event di Splunk; yang berubah hanya alat di tiap langkah. Di Splunk ada satu lapisan tambahan: normalisasi CIM membuat satu pencarian bisa membaca Zeek, firewall, dan proxy sekaligus, tetapi hanya bila data benar-benar masuk data model, dan CIM menyamakan nama field, bukan titik pandang sensor.

Analoginya alur troubleshooting baku di NOC: verifikasi gejala, tentukan segmen, kumpulkan `show` dan log sebelum ada yang di-reset, periksa per layer, uji hipotesis, lalu tulis RFO (reason for outage) dengan kronologi, akar masalah, dampak, dan tindakan. Write-up jaringan adalah RFO untuk insiden keamanan, dan CIM adalah padanan IF-MIB: NMS bisa membaca `ifHCInOctets` dari router vendor mana pun karena namanya standar, tetapi "in" tetap berarti masuk dari sudut antarmuka yang ditanya. Batas analoginya ada tiga. Gangguan link tidak bersembunyi, sedangkan penyerang menyesuaikan diri dengan apa yang kamu pantau. RFO menulis akar masalah sebagai kepastian, sedangkan write-up keamanan menulis tingkat keyakinan dan apa yang tidak terlihat. Dan bukti jaringan hilang lebih cepat daripada log router, sehingga langkah mengamankan bukti ada di depan, bukan di tengah.

```
 pertanyaan tertulis + jendela waktu (WIB dan UTC)
        |
        v
 0 amankan bukti     pcap kasus dari ring + log Zeek/Suricata + ekspor log lain, semua ber-hash
        |
        v
 1 orientasi         capinfos | Protocol Hierarchy | Conversations | jumlah per sourcetype
        |
        v
 2 pembatasan        host, waktu, protokol yang menjawab pertanyaan ; titik pandang (hop core / egress)
        |
        v
 3 pendalaman        HTTP | DNS | TLS | SMB | FTP (Day 03-06, 08)
        |
        v
 4 pola              scan | anomali DNS/HTTP | beacon | exfil (Day 04, 05, 11, 12)
        |
        v
 5 korelasi          uid, community_id, waktu, hash ; proxy/DNS/firewall/flow ; host (MDE) ; scoping
        |
        v
 6 write-up          ringkasan | timeline | temuan | IOC (defang) | batas | rekomendasi
        |
        +--> berhenti bila: jinak terkonfirmasi | eskalasi (INC) | data tidak cukup, ditulis dengan batasnya
```

Situasi Day ini terjadi di PT Jaringan Anak Bangsa (PT JAB), ISP menengah fiktif dengan sekitar 1.200 karyawan, kantor pusat dan data center di Jakarta, serta NOC 24/7 yang satu lantai dengan SOC. Sejak Senin 2027-05-03 PT JAB menjalankan "Program NSM PT JAB" sebagai percobaan Mei sampai Juli 2027. Per pekan ini, `jkt-zeek01` (`10.20.70.12`, produksi sejak Selasa 2027-05-18) dan `jkt-ids01` (`10.20.70.11`, Suricata, sejak Rabu 2027-05-19) membaca SPAN core switch data center dan TAP egress Jakarta lewat packet broker `jkt-npb01`; `jkt-pcap01` (`10.20.70.13`) menyimpan pcap egress dengan target 72 jam; kolektor flow NOC `jkt-flow01` (`10.20.70.14`) menerima flow router edge (sampling 1:1000) dan router data center (1:1). Log Zeek masuk Splunk di index `zeek` (sourcetype `bro:<log>:json`), alert Suricata di index `suricata`. Workstation keluar ke web lewat proxy eksplisit `jkt-proxy01` (`10.20.3.60:3128`) dan me-resolve nama lewat `jkt-res01` dan `jkt-res02`. Analisis dikerjakan di `jkt-nsm-ws01` (`10.20.70.20`).

Dua minggu setelah Zeek hidup, antrean sudah menghasilkan enam insiden jaringan (`INC-2027-066` sampai `071`). Senin 2027-05-31 pukul 07:30 WIB, Dimas Prasetyo (SOC lead) menulis kepadamu:

> "Aku baca ulang write-up enam insiden terakhir. Isinya bagus, tapi formatnya beda-beda: dua laporan mencampur jam UTC dan WIB tanpa keterangan, satu menulis 'C2' di ringkasan sebelum host mengonfirmasi, dan cuma satu yang punya bagian batas. Kamis kita latihan satu kasus penuh dari pcap sampai laporan di depan Pak Hendra. Sebelum itu tolong tulis metode kerja baku tim: langkahnya apa, kapan boleh berhenti, sumber mana untuk pertanyaan apa, format IOC dan timeline, dan kerangka write-up. Uji langsung di antrean pagi ini bareng Gilang, biar ketahuan bagian mana yang tidak jalan."

Pukul 07:45, Sari Kusuma (analyst L2) menambahkan di kanal yang sama:

> "Dua titipan. Pertama, correlation search 'upload besar ke tujuan baru' yang kutulis Kamis di atas data model Network_Traffic tidak pernah menyala. Waktu kuputar ulang di jendela INC-2027-071 hasilnya nol, padahal raw search ke index zeek jalan. Kedua, aku mau Gilang dan Dwi latihan pakai pcap publik di sela antrean. Dari mana yang aman, dan aturannya apa?"

Dua pesan itu memuat tujuh pertanyaan:

1. Apa yang membuat write-up enam insiden tidak seragam, dan apa yang harus dibakukan?
2. Langkah apa yang dipakai ulang, dalam urutan apa, dan kapan analisis boleh berhenti?
3. Bagaimana memilih sumber dan alat dari pertanyaan, bukan sebaliknya, dan bagaimana menyesuaikan metode bila yang ada hanya flow atau log?
4. Bagaimana IOC, timeline, dan tingkat keyakinan ditulis supaya bukti terpisah dari kesimpulan?
5. Kerangka write-up apa yang dipakai tim?
6. Kenapa correlation search berbasis data model tidak menyala padahal raw search jalan?
7. Pcap publik mana yang sah untuk latihan L1, dan apa aturan amannya?

Pertanyaan 1 dijawab di bagian 1.1, pertanyaan 2 di bagian 1.2 dan 2.1 sampai 2.4, pertanyaan 3 di bagian 1.3 dan 1.4, pertanyaan 4 di bagian 1.5 dan 2.5 sampai 2.7, pertanyaan 5 di bagian 1.6 dan 2.8, pertanyaan 6 di bagian 1.7, 1.8, dan 2.9, dan pertanyaan 7 di bagian 1.9 dan 2.10. Bagian 1.10 memperlihatkan alur yang sama pada kasus lab kecil, dan bagian 2.11 adalah metode kerja v1.0 yang dikirim ke Dimas.

**Kapan relevan:** setiap kali menerima pcap, log Zeek, atau alert jaringan yang belum dikenal; saat melatih L1 membaca kasus dari awal sampai keputusan; saat menulis laporan untuk IR, manajemen, atau DPO; saat membangun pipeline log jaringan ke SIEM dan correlation search di atas CIM; dan sebelum interview yang meminta kamu menceritakan satu analisis jaringan secara runtut.
**Kapan bukan jawaban:** metode ini tidak menggantikan pengetahuan protokol dan pola di Day 03 sampai 12; bila langkah 3 atau 4 macet, kembali ke Day asalnya. Metode juga tidak mengubah apa yang terlihat: blind spot sensor, retensi, dan enkripsi tetap batas yang sama, dan langkah yang rapi atas data yang tidak ada tetap menghasilkan "data tidak cukup". Untuk pertanyaan "proses apa" dan "data apa", jawabannya ada di host, bukan di jaringan.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dari Day sebelumnya (pcap kasus, display filter, Follow Stream, Export Objects, `uid`, `community_id`, hop core dan hop egress, beacon, PCR, sourcetype, prevalence, first-seen, defang) tidak diulang; definisinya ada di Day 01 sampai 12 [S17]. Tabel ini hanya memuat istilah yang dipakai Day ini; kolom padanan memakai pengalaman NOC dan ISP.

| Istilah | Arti singkat | Padanan di NOC/ISP |
|---|---|---|
| Metode kerja | Urutan langkah baku yang dipakai ulang untuk setiap kasus, dengan keluaran tertulis per langkah | Alur troubleshooting baku tiket gangguan |
| Pertanyaan investigasi | Kalimat yang ditulis sebelum membuka data: siapa, ke mana, kapan, apa, dan seberapa yakin harus dijawab | Gejala yang diverifikasi di tiket sebelum mulai `show` |
| Event of interest | Kejadian yang memicu analisis: alert, laporan pengguna, atau temuan saat review (istilah NIST SP 800-86) | Alarm NMS atau telepon pelanggan yang membuka tiket |
| Orientasi | Ringkasan isi data sebelum membaca detail: komposisi protokol, pihak, volume, rentang waktu | Melihat grafik utilisasi dan tabel interface sebelum masuk satu port |
| Pembatasan | Mempersempit data ke host, waktu, dan protokol yang menjawab pertanyaan | Isolasi segmen: link mana, router mana, jam berapa |
| Kriteria berhenti | Tiga keadaan yang mengakhiri analisis: jinak terkonfirmasi, eskalasi, atau data tidak cukup | Tiket ditutup, dinaikkan ke vendor, atau ditutup "tidak dapat direproduksi" |
| Fidelity sumber | Seberapa dekat sebuah sumber dengan kejadian asli; sumber asli lebih dipercaya daripada data yang sudah dinormalisasi atau ditafsirkan | Counter interface langsung vs angka di dashboard yang sudah diagregasi |
| Bukti vs kesimpulan | Bukti adalah fakta yang bisa ditunjuk di data; kesimpulan adalah tafsiran atas bukti | Counter error naik vs "kabel rusak" |
| Tingkat keyakinan | Label rendah, sedang, atau tinggi untuk setiap kesimpulan, dengan dasar yang ditulis | "Dugaan" vs "terkonfirmasi" di RFO |
| Write-up | Dokumen temuan: ringkasan, timeline, temuan, IOC, batas, rekomendasi | RFO (reason for outage) |
| CIM (Common Information Model) | Skema nama field bersama di Splunk supaya sumber berbeda bisa dicari dengan satu pencarian | IF-MIB: nama counter standar lintas vendor |
| Data model | Definisi dataset CIM (misalnya Network_Traffic, dataset `All_Traffic`) yang memilih event lewat tag dan menyediakan field | Template grafik NMS yang membaca OID tertentu dari semua perangkat |
| Data model acceleration | Summary data model yang dibangun di latar belakang supaya `tstats` cepat | Polling yang disimpan sebagai RRD |
| Index constraint | Daftar index yang dibaca sebuah data model, diatur di halaman CIM Setup dan disimpan sebagai macro `cim_<datamodel>_indexes` | Daftar perangkat yang dimasukkan ke grup polling |
| `summariesonly` | Argumen `tstats`; bila `true`, hanya membaca summary acceleration dan melewatkan data yang belum diringkas | Grafik yang hanya membaca RRD, bukan counter mentah terbaru |
| Correlation search | Pencarian terjadwal di Splunk ES yang membuat finding atau notable bila kondisinya terpenuhi | Rule korelasi alarm di NMS |
| Dataset latihan publik | Pcap atau log yang dirilis publik untuk belajar; sebagian berisi malware asli | Lab GNS3 atau EVE-NG dan konfigurasi contoh vendor |

### 1.1 Kenapa perlu metode kerja: enam write-up, satu pola masalah

Pertanyaan pertama Dimas lahir dari membaca ulang enam write-up. Tidak ada yang salah fakta; yang berbeda urutan berpikir dan apa yang ditulis. Dua laporan mencampur jam pcap (UTC) dan jam Splunk (WIB) di satu tabel, sehingga pembaca mengira ada jeda tujuh jam antara unduhan dan koneksi pertama. Satu laporan menulis "C2" di kalimat pertama saat yang ada baru pola interval. Hanya satu yang menyebut apa yang tidak terlihat dari sensor.

Pola masalahnya sama dengan tiket gangguan yang dikerjakan tanpa alur baku: setiap engineer benar menurut caranya sendiri, tetapi shift berikutnya tidak bisa meneruskan, dan RFO tidak bisa dibandingkan antarbulan. Yang perlu dibakukan bukan isi kesimpulan, melainkan lima hal: urutan langkah (bagian 1.2), cara memilih sumber dari pertanyaan (bagian 1.3), format IOC dan timeline dengan zona waktu dan sumber per baris (bagian 1.5), label keyakinan (bagian 1.5), dan kerangka write-up dengan bagian batas yang wajib (bagian 1.6).

NIST SP 800-86 merumuskan proses forensik digital dalam empat fase: collection (mengidentifikasi, memberi label, mencatat, dan mengambil data sambil menjaga integritasnya), examination (memproses data dengan cara otomatis dan manual lalu mengekstrak yang relevan), analysis (menurunkan informasi yang menjawab pertanyaan yang memicu pengumpulan), dan reporting (melaporkan hasil, termasuk tindakan yang dipakai, alasan memilih alat, tindakan lanjutan, dan rekomendasi perbaikan) [S7]. Dokumen itu juga menyarankan organisasi menyusun panduan dan prosedur yang membuat tindakan konsisten, efektif, dan akurat, dan meninjaunya berkala [S7]. Metode kerja PT JAB di bagian 1.2 adalah penjabaran empat fase itu untuk data jaringan: langkah 0 adalah collection, langkah 1 sampai 4 examination, langkah 5 analysis, dan langkah 6 reporting.

Metode baku bukan formulir yang diisi penuh untuk setiap alert: alert jinak boleh berhenti di langkah 1 atau 2 bila kriteria berhentinya tercatat (bagian 1.2).

### 1.2 Alur kerja: tujuh langkah dan kriteria berhenti

Pertanyaan kedua Dimas ("langkahnya apa, kapan boleh berhenti") dijawab dengan alur ini. Alur konsisten mencegah tersesat di detail. Inti alurnya enam langkah dari catatan lama, ditambah langkah 0 di depan:

1. **Orientasi (Day 02).** Protocol Hierarchy, Conversations, Endpoints. Gambaran: protokol, pihak, volume.
2. **Pembatasan.** Tentukan pertanyaan dan cakupan (host mana, periode mana, apa yang dicari).
3. **Pendalaman per protokol (Day 03-06).** Baca koneksi kunci: HTTP, DNS, TLS, SMB; ikuti stream polos.
4. **Deteksi pola (Day 04-05, 11-12).** Scan, anomali, beaconing, exfiltration.
5. **Korelasi.** Hubungkan sinyal lintas protokol, host, dan waktu; pakai Zeek UID, flow, alert Suricata.
6. **Penulisan.** Timeline, IOC, temuan, batas. Pisahkan bukti dari kesimpulan.

Alur ini berlaku untuk pcap kecil (Wireshark) maupun besar (Zeek, flow, SIEM); skalanya berbeda, logikanya sama.

Langkah 0 ditambahkan karena pelajaran Minggu 1: unduhan Kamis di `INC-2027-064` sudah tertimpa ring buffer ketika dicari hari Senin (Day 07 bagian 1.8). Langkah 0 berisi tiga hal: tulis pertanyaan dan jendela waktu dalam WIB dan UTC, potong pcap kasus dari ring buffer dan catat hash-nya (Day 02 bagian 2.1), lalu salin log Zeek, Suricata, proxy, DNS, dan firewall untuk jendela yang sama ke folder kasus. Pertanyaan ditulis sebelum membuka data, dan pembatasan di langkah 2 adalah turunan pertanyaan itu.

Tabel berikut adalah versi kerja alur itu. Kolom "Keluaran tertulis" adalah yang membuat langkah bisa diperiksa orang lain; kolom terakhir menunjukkan di mana analisis boleh berhenti.

| Langkah | Isi | Alat utama di PT JAB | Keluaran tertulis | Boleh berhenti bila |
|---|---|---|---|---|
| 0 Pertanyaan dan bukti | Pertanyaan, jendela WIB/UTC, potong pcap, salin log | `tcpdump -r`, `mergecap`, `capinfos`, salin arsip Zeek | Folder kasus, hash, daftar sumber dan rentangnya | Belum boleh |
| 1 Orientasi | Komposisi protokol, pihak, volume, rentang waktu | Statistics Wireshark, `capinfos`, hitungan per sourcetype | Tiga sampai lima kalimat "isi data ini" | Data tidak mencakup kejadian (di luar retensi atau di luar titik sensor): "data tidak cukup" |
| 2 Pembatasan | Host, waktu, protokol; hop mana yang memuat host asli | Display filter, `index=zeek` per `uid`, log proxy | Daftar koneksi kunci | Pemicu terbukti mekanis atau jinak dengan pemilik yang jelas: "jinak terkonfirmasi" |
| 3 Pendalaman | Isi protokol koneksi kunci | Follow Stream, `http.log`, `dns.log`, `ssl.log`, `files.log` | Fakta per koneksi (method, URI, SNI, mime, hash) | Isi menjelaskan perilaku sah |
| 4 Pola | Scan, DNS/HTTP, beacon, exfil | Day 04, 05, 11, 12 | Angka pola (interval, CV, volume, PCR) | Pola sesuai baseline atau allowlist yang tercatat |
| 5 Korelasi | Sumber lain, host, scoping | Proxy, DNS, firewall, flow, MDE, prevalence | Timeline gabungan, daftar host terdampak | Eskalasi: sinyal jaringan ditambah korroborasi host |
| 6 Write-up | Ringkasan, timeline, temuan, IOC, batas, rekomendasi | Template bagian 1.6 | Dokumen kasus | Selesai |

NIST SP 800-86 memecah examination dan analysis data jaringan dalam urutan yang mirip: mengenali event of interest, memeriksa sumber data (biasanya mulai dari beberapa sumber utama seperti konsol IDS atau SIEM), menarik kesimpulan, dan identifikasi penyerang [S7]. Untuk butir terakhir, dokumen itu mengingatkan bahwa identitas penyerang biasanya bukan prioritas utama dan mahal dikejar; fokusnya dampak negatif kejadian bagi organisasi [S7]. Itu sebabnya write-up PT JAB tidak punya bagian "siapa pelakunya", tetapi punya bagian dampak dan batas.

Kriteria berhenti ditulis eksplisit karena dua kesalahan yang berlawanan sama-sama mahal: berhenti terlalu cepat dengan "tidak ada di pcap" padahal data tidak pernah sampai ke sensor (Day 07 bagian 1.9), atau terus membaca paket setelah pertanyaan terjawab. Tiga keluaran yang sah adalah jinak terkonfirmasi (dengan pemilik atau perubahan yang tercatat), eskalasi (sinyal jaringan ditambah korroborasi host), dan data tidak cukup (dengan sumber yang tidak ada dan alasannya). Keluaran ketiga bukan kegagalan; ia temuan tentang blind spot.

### 1.3 Pertanyaan memandu, bukan alat

Pertanyaan ketiga Dimas ("sumber mana untuk pertanyaan apa") adalah inti metode. Investigasi dipandu pertanyaan ("apakah host ini terkompromi", "apa yang keluar", "dari mana masuknya"), bukan alat. Alat melayani pertanyaan: Wireshark untuk detail, Zeek untuk korelasi, flow untuk volume, Suricata untuk alert. Mulai dari pertanyaan menjaga fokus dan menentukan data serta alat yang tepat. Tanpa pertanyaan, mudah tenggelam membaca paket tanpa arah.

Di PT JAB pertanyaan juga menentukan titik sensor, karena tidak semua sumber melihat host asli. Tabel berikut adalah peta yang dipakai di langkah 2; cari baris pertanyaanmu, lalu baca kolom "Sumber pertama" dan "Jebakan titik pandang". Peta lengkap per hop untuk volume ada di Day 12 bagian 1.2.

| Pertanyaan | Sumber pertama | Sumber penguat | Jebakan titik pandang |
|---|---|---|---|
| Workstation mana yang menghubungi tujuan X? | Zeek hop core (`http.log` `CONNECT`, `conn.log` ke `10.20.3.60:3128`), log proxy | Flow router DC (1:1) | Di hop egress dan pcap egress, semua web bersumber proxy `10.20.3.60` |
| Nama apa yang ditanyakan workstation? | `index=dns`, Zeek `dns.log` hop core | Pcap egress (rcode dari resolver ke luar) | Di egress sumber DNS adalah resolver; log resolver tanpa kode jawaban (Day 05) |
| Apa isi unduhan HTTP polos? | Zeek `files.log` (mime, hash), pcap egress (isi) | Log proxy (URL, status) | File yang di-bump hanya terlihat polos di proxy, bukan di kabel |
| Apakah koneksi teratur (beacon)? | Zeek `conn.log` dan `http.log` per pasangan (Day 11) | Log proxy, flow DC | Sampling 1:1000 di flow edge hampir buta terhadap koneksi kecil (Day 10) |
| Berapa byte yang keluar? | Zeek hop core per `uid` (Day 12 bagian 2.1) | Flow DC dan edge, hop egress | Kolom `bytes` proxy adalah ukuran balasan, bukan unggahan (Day 12) |
| Proses apa yang membuat koneksi? | MDE `DeviceNetworkEvents` (Day 11 bagian 2.8) | Triage host | Jaringan tidak pernah memberi nama proses |
| Apakah alert Suricata benar? | `eve.json` alert dan `flow_id` (Day 09) | Zeek lewat `community_id`, pcap | Alert dari hop egress memuat proxy, bukan workstation (Day 09 bagian 2.7) |

NIST SP 800-86 memberi dua prinsip yang memperkuat tabel ini [S7]. Pertama, sumber asli lebih dipercaya daripada data yang sudah dinormalisasi, dan data tafsiran seperti alert IDS dan SIEM harus divalidasi karena setiap alat punya false positive dan false negative. Kedua, sumber sekunder dibutuhkan bila sumber utama tidak memuat aktivitas, misalnya serangan antar host di segmen internal yang tidak dipantau; di PT JAB itulah lateral movement antar workstation di switch akses, yang tetap blind spot (Day 07 bagian 1.9). Prinsip pertama juga berlaku untuk field CIM di Splunk (bagian 1.8).

### 1.4 Menyesuaikan metode dengan data yang tersedia

Bagian kedua pertanyaan ketiga Dimas menyangkut kasus yang datanya tidak lengkap. Metode tidak berubah, tetapi apa yang bisa dijawab berubah. Tabel berikut dipakai di langkah 1 untuk menulis sejak awal pertanyaan mana yang mungkin terjawab; lihat kolom "Tidak bisa dijawab" sebelum menjanjikan apa pun.

| Data yang ada | Langkah yang paling kuat | Bisa dijawab | Tidak bisa dijawab |
|---|---|---|---|
| Pcap penuh (egress, 72 jam) | 3 dan 4 | Isi protokol polos, file dan hash, metadata TLS, bentuk TCP | Host di balik proxy, proses, isi TLS, kejadian di luar retensi |
| Log Zeek (90 hari di Splunk) | 2, 4, 5 | Siapa ke mana kapan berapa, DNS, SNI, hash file polos, rantai `uid` | Isi lengkap, byte di luar yang dicatat, segmen tanpa sensor |
| Alert Suricata | 1 dan 2 (sebagai event of interest) | Cocokan signature dan konteks flow | Apa pun yang tidak punya signature |
| Flow NOC (13 bulan) | 4 untuk volume dan waktu panjang | Volume per arah, pasangan alamat, sejak kapan | Isi, nama domain, koneksi kecil di edge karena sampling |
| Log proxy, DNS, firewall (30 sampai 90 hari) | 2 dan 5 | Atribusi workstation dan akun, URL bila di-bump, keputusan blokir | Isi yang di-splice, byte unggahan dari kolom `bytes` |

Kasus nyata sering bergeser dari pcap ke log Zeek ke flow seiring retensi habis; metodenya tetap, yang berubah kolom batas di write-up. NIST SP 800-86 menyebut data jaringan hampir tidak pernah lengkap, sehingga analisis harus metodis dan kesimpulan disusun dari data yang ada ditambah asumsi tentang data yang hilang, yang didasarkan pada pengetahuan teknis [S7]. Di write-up, asumsi itu ditulis eksplisit, misalnya "jeda 10:00 sampai 10:15 tidak ada di pcap karena file ring itu sudah tertimpa; diasumsikan pola beacon tetap, berdasarkan `conn.log` yang utuh untuk jam itu".

### 1.5 IOC, timeline, bukti vs kesimpulan, dan tingkat keyakinan

Pertanyaan keempat Dimas menyentuh masalah paling sering di enam write-up: jam tanpa zona dan kesimpulan yang ditulis sebagai fakta.

- **IOC:** kumpulkan indikator (IP, domain, hash, URI, JA3) dengan konteks (di mana ditemukan, keyakinan). Defang sebelum ditulis (misalnya `93.184.216[.]34`, `hxxp://`).
- **Timeline:** urutkan kejadian dengan timestamp (dari pcap atau `ts` Zeek), tandai sumber tiap entri. Timeline mengubah temuan terpisah menjadi cerita.
- **Bukti vs kesimpulan:** tandai jelas mana fakta dari data ("host A mengirim 5 GB ke IP B") dan mana interpretasi ("kemungkinan exfiltration"). Ini menjaga kejujuran analitis.

Tiga aturan tambahan dibakukan untuk PT JAB:

1. **Satu zona waktu per tabel, ditulis di judul kolom.** Pcap dan arsip Zeek di sensor memakai UTC, Splunk dan NOC menampilkan WIB (Day 02 bagian 1.3). Timeline write-up memakai WIB, dengan UTC di kolom terpisah bila baris itu berasal dari pcap. Detik dipertahankan; pembulatan ke menit menyembunyikan urutan unduhan dan koneksi pertama.
2. **Setiap IOC punya lima kolom:** nilai ter-defang, tipe, tempat ditemukan (log dan field), keyakinan sebagai indikator jahat, dan catatan pemakaian (blokir, hunting saja, jangan diblokir karena layanan bersama). Domain layanan bersama (penyimpanan cloud, CDN) bukan IOC blokir (Day 07 bagian 1.10), dan fingerprint TLS di egress setelah bump adalah milik proxy (Day 06 bagian 1.7).
3. **Keyakinan memakai tiga label dengan dasar tertulis.** Rendah: satu sinyal jaringan, penjelasan jinak belum disingkirkan. Sedang: beberapa sinyal jaringan independen yang konsisten, penjelasan jinak utama sudah diuji, belum ada konfirmasi host. Tinggi: sinyal jaringan ditambah korroborasi host atau pemilik sistem, atau angka yang cocok dari dua sumber independen (misalnya volume dari Zeek dan flow). Label ditempel ke kalimat kesimpulan, bukan ke laporan secara keseluruhan.

Contoh yang membedakan bukti dan kesimpulan dalam satu baris timeline: "07:43:05 WIB, `10.10.60.133` membuka `CONNECT update.raksasoft.example:443` lewat proxy (Zeek hop core `http.log`)" adalah bukti. "Kandidat C2, keyakinan sedang (interval 120 detik, CV 0,06, domain tidak terkategori, satu host)" adalah kesimpulan, dan ia ditulis di kolom terpisah. Kasus ini dibedah di bagian 2.4 sampai 2.7.

### 1.6 Menulis temuan jaringan

Pertanyaan kelima Dimas meminta satu kerangka. Write-up yang baik (cek struktur sesuai kebijakan organisasi):

- **Ringkasan:** satu paragraf: apa yang terjadi, dampak, keyakinan.
- **Timeline:** kronologi dengan sumber.
- **Temuan:** per tahap (akses, C2, exfil), dengan bukti.
- **IOC:** daftar ter-defang dengan konteks.
- **Batas:** apa yang tak bisa disimpulkan (isi terenkripsi, visibilitas, data hilang).
- **Rekomendasi:** tindakan (blokir IOC, isolasi host, tuning deteksi).

Tujuannya agar pembaca (IR, manajemen) bisa bertindak: jelas, jujur tentang keyakinan, dan memisahkan fakta dari interpretasi.

PT JAB menambahkan dua bagian kecil yang diambil dari fase reporting NIST SP 800-86, yaitu tindakan yang dipakai dan alasan memilih alat, serta tindakan lanjutan yang perlu dilakukan [S7]:

- **Data dan metode:** sumber yang dipakai beserta rentang dan hash-nya, titik sensor, dan alat (misalnya "Zeek hop core 07:30 sampai 09:30 WIB, pcap egress dengan SHA-256 di tiket, log proxy 30 hari"). Pembaca harus bisa mengulang analisis dari bagian ini.
- **Pertanyaan terbuka:** apa yang masih perlu dijawab dan oleh siapa (host, pemilik data, Legal). Bagian ini berbeda dari batas: batas adalah apa yang tidak akan pernah terlihat dari data ini, pertanyaan terbuka adalah apa yang belum dikerjakan.

Ringkasan ditulis paling akhir, setelah timeline dan temuan selesai, supaya kalimat pertamanya tidak mendahului bukti. Kesalahan "C2 di kalimat pertama" di salah satu write-up lama terjadi karena ringkasan ditulis di awal, saat dugaan masih segar. Template lengkap untuk kasus besar disusun di Day 14; bagian 2.8 memperlihatkan versi ringkasnya pada `INC-2027-072`.

### 1.7 Integrasi Zeek ke Splunk

Pertanyaan keenam Sari ("raw search jalan, data model nol") hanya bisa dijawab bila pipeline-nya jelas. Zeek menghasilkan log terstruktur yang cocok untuk SIEM. Pipeline umum:

1. Zeek menulis log, sebaiknya JSON (`LogAscii::use_json=T`, Day 08) supaya nama field ikut di setiap event.
2. Universal forwarder di sensor memantau direktori log Zeek dan mengirimnya ke indexer, ke index khusus (misalnya `zeek`).
3. Technology Add-on (TA) mem-parse event, memberi sourcetype per jenis log, dan memetakan field ke Common Information Model (CIM).
4. Pencarian SPL atas log (conn, dns, http, ssl, files) untuk analisis skala besar: top talker, beaconing, exfiltration, korelasi dengan sumber lain.

TA yang dipakai adalah "TA for Zeek" (Splunkbase app 5466), yang mem-parse Zeek format JSON maupun TSV dan mengisi data model CIM [S5]. TA ini dulu dirawat Splunk dengan nama "Splunk Add-on for Zeek aka Bro" (app 1617) dan kini dirawat Corelight; halaman app lama menyatakan penggantian itu. Per 2026-10-29 versinya masih 1.0.11 (21 Agustus 2025), kompatibel dengan Splunk 9.3, 9.4, dan 10.0 sampai 10.7, serta CIM 6.x [S5]. Sourcetype berawalan `bro:` tetap dipakai walaupun nama alatnya sudah Zeek.

Keputusan PT JAB sudah dibuat di Day 08: JSON, index `zeek`, sourcetype eksplisit `bro:<log>:json` di `inputs.conf`, dan validasi di index staging (Day 08 bagian 1.9 dan 2.11). Yang terkonfirmasi sumber hanya `bro:conn:json`, `bro:http:json`, dan `bro:ssl:json`; nama lain mengikuti pola yang sama dan dicek ulang dengan `| metadata type=sourcetypes index=zeek` setiap kali TA diperbarui. Alert Suricata masuk index `suricata` dengan satu sourcetype `suricata` untuk semua event (Day 09 bagian 1.10).

Keuntungannya: pertanyaan yang di Day 08 dijawab dengan `zeek-cut` kini dijawab dengan SPL di jutaan event, ditambah korelasi dengan log endpoint, proxy, dan autentikasi. Harganya: `_time` ditampilkan dalam zona pengguna sehingga timeline harus disatukan zonanya (bagian 1.5), dan pencarian berbasis data model membaca lapisan tambahan yang bisa gagal tanpa pesan galat (bagian 1.8).

### 1.8 CIM dan normalisasi

CIM adalah skema field bersama milik Splunk [S6]. Setiap sumber log dipetakan ke nama field yang sama sehingga satu pencarian atau dashboard bisa membaca firewall, Zeek, dan proxy sekaligus. Untuk log koneksi, data model yang relevan adalah Network_Traffic. Dokumentasi CIM 6.2 menyebut dataset induknya `All_Traffic`, yang memilih event bertag `network` dan `communicate` [S8]. Field utamanya dipetakan dari `conn.log` sebagai berikut; tabel ini dipakai saat menulis correlation search dan saat mencocokkan angka CIM dengan field asli.

| Field Zeek (conn.log) | Field CIM Network_Traffic | Catatan |
|---|---|---|
| `id.orig_h` | `src` (atau `src_ip`) | Pemrakarsa koneksi |
| `id.resp_h` | `dest` (atau `dest_ip`) | Penerima koneksi |
| `id.resp_p` | `dest_port` | Angka, bukan nama layanan |
| `proto` | `transport` | tcp/udp/icmp, huruf kecil |
| `service` | `app` | Protokol aplikasi yang dikenali |
| `orig_bytes` | `bytes_out` | Byte dari originator |
| `resp_bytes` | `bytes_in` | Byte dari responder |
| `duration` | `duration` | Detik |

Log DNS dipetakan ke data model Network_Resolution (`query`, `answer`, `reply_code`), HTTP ke Web (`url`, `http_user_agent`, `status`), dan file ke data model yang memuat hash. Pemetaan di tabel adalah pola umum; cek hasil sebenarnya di field sidebar Splunk setelah TA terpasang. Dokumentasi CIM mendefinisikan `bytes_in` dan `bytes_out` dari sudut "perangkat atau antarmuka" yang menerima dan mengirim [S8], definisi yang jelas untuk firewall tetapi ambigu untuk sensor pasif. TA for Zeek memetakan dari sudut originator, sehingga untuk koneksi dari internet ke server PT JAB, `bytes_out` adalah byte dari pihak luar. Seperti `ifInOctets` yang selalu dibaca dari sisi antarmuka yang ditanya, arah CIM harus dibaca bersama `src` dan `dest`.

Normalisasi penting karena correlation search dan rule deteksi ditulis terhadap nama CIM, bukan nama vendor. Rule "upload besar ke tujuan baru" yang ditulis dengan `bytes_out` dan `dest` bekerja untuk Zeek, firewall, dan flow cloud tanpa diubah. Jebakannya: bila TA tidak terpasang di search head, event tetap terindeks tetapi field CIM tidak ada, sehingga pencarian berbasis data model mengembalikan nol tanpa pesan galat.

Ada tiga jebakan lain yang sama-sama diam:

- **Index constraint.** Secara bawaan setiap data model mencari di semua index; halaman CIM Setup memungkinkan membatasi index per data model, dan index baru harus ditambahkan ke daftar itu ketika masuk lingkungan [S9]. Batasan itu tersimpan di macro yang menjadi bagian constraint data model, misalnya `cim_Network_Traffic_indexes` [S10]. Index `zeek` yang dibuat setelah daftar disusun tidak ikut dibaca.
- **Acceleration dan `summariesonly`.** Data model CIM tidak di-accelerate secara bawaan, tetapi Enterprise Security bisa memaksakannya lewat modular input, dan perubahan di halaman CIM Setup lalu tidak bertahan [S9]. `tstats` dengan `summariesonly=true` hanya membaca summary acceleration (bawaannya `false`) [S11], jadi correlation search seperti itu nol untuk index yang belum punya summary.
- **Titik pandang.** CIM menyamakan nama, bukan posisi sensor. Di hop core, `dest` setiap koneksi web workstation adalah `10.20.3.60` (proxy), sehingga rule "tujuan baru" di atas `All_Traffic` tidak pernah melihat tujuan sebenarnya; nama tujuan ada di `http.log` baris `CONNECT` (Day 12 bagian 2.1).

Prinsip fidelity dari bagian 1.3 berlaku di sini: angka yang masuk write-up diambil atau dicocokkan dengan field asli Zeek (`orig_bytes`, `id.resp_h`), sedangkan field CIM dipakai untuk pencarian lintas sumber dan correlation search.

### 1.9 Dataset latihan publik

Pertanyaan ketujuh Sari menyangkut latihan. Berlatih butuh data sah. Sumber umum di bawah dipilih karena dipakai luas; cek lisensi dan ketentuan tiap situs sebelum memakai [S3][S4][S12][S13]:

| Sumber | Isi | Catatan |
|---|---|---|
| malware-traffic-analysis.net | Pcap infeksi dengan latihan | Populer untuk latihan; situs menyatakan pemakaian atas risiko sendiri, banyak arsip berisi sampel malware, dan sebagian pcap bisa ditandai antivirus [S12]; ikuti metode, jangan jalankan malware |
| Wireshark SampleCaptures | Pcap contoh beragam protokol | Untuk belajar protokol; halaman tidak menyatakan satu lisensi untuk semua file, sebagian file berisi trafik malware atau exploit dan sebagian memuat material sensitif seperti kunci sesi [S13] |
| Netresec publik pcap | Daftar pcap publik | Kurasi tautan per kategori (forensik jaringan, ICS, latihan CDX, malware, CTF); bagian malware memperingatkan bahwa arsip berkata sandi berisi malware asli, dan ketentuan pakai mengikuti tiap sumber [S4] |
| CTF/range (misalnya CyberDefenders, Blue Team Labs) | Tantangan DFIR jaringan | Latihan terstruktur |

Aturan: unduh hanya ke VM lab terisolasi, jangan jalankan sampel malware, jangan simpan pcap kerja atau klien di repo, defang IOC di catatan. Banyak pcap di situs latihan dibungkus arsip berkata sandi justru karena berisi malware aktif; ekstrak hanya di VM analisis, dan jangan buka berkas hasil Export Objects di luar VM itu.

Untuk L1 PT JAB, aturan tambahannya ada di bagian 2.10: VM latihan terpisah, pertanyaan tertulis untuk setiap pcap latihan, template write-up yang sama dengan kasus nyata, dan pembahasan resmi dibaca setelah write-up selesai. Day ini tidak menyebut nama file atau isi pcap publik tertentu; pilih sendiri dan catat sumbernya.

### 1.10 Contoh alur pada kasus kecil

Sebelum masuk ke data PT JAB, alur yang sama pada kasus lab yang kecil. Kasus fiktif: helpdesk melaporkan laptop `10.0.0.8` lambat sejak kemarin sore. Kamu diberi pcap 2 jam dari port SPAN lantai itu.

1. **Pertanyaan.** "Apakah 10.0.0.8 terinfeksi, dan bila ya, sejak kapan dan berkomunikasi dengan siapa?" Pertanyaan ini langsung membatasi data ke satu host.
2. **Orientasi.** Protocol Hierarchy: 70 persen TLS, 20 persen SMB, sisanya DNS dan HTTP. Conversations: tujuan eksternal terbesar dari 10.0.0.8 adalah layanan update OS dan satu IP `203.0.113[.]50` dengan 118 koneksi.
3. **Pembatasan.** Filter `ip.addr == 10.0.0.8 and (dns or http or tls)`. Satu request HTTP polos ke `198.51.100[.]7` mengunduh `update.png` yang magic byte-nya `MZ` (Day 05); 40 detik kemudian koneksi pertama ke `203.0.113[.]50` muncul.
4. **Deteksi pola.** Delta koneksi ke `203.0.113[.]50` berkisar 55-65 detik selama 2 jam, ukuran request hampir sama (Day 11). SNI `upd-check[.]example`, domain yang tidak ada di baseline.
5. **Korelasi.** UID di Zeek mengikat unduhan ke hash di files.log; alert Suricata untuk SNI yang sama ikut muncul (Day 09).
6. **Penulisan.** Ringkasan: "10.0.0.8 kemungkinan besar terinfeksi sejak 14:02:11 WIB melalui unduhan PE yang disamarkan, lalu beacon tiap sekitar 60 detik ke 203.0.113[.]50. Keyakinan sedang-tinggi; belum dikonfirmasi di host."

Perhatikan apa yang tidak ditulis: tidak ada nama keluarga malware, karena pcap tidak membuktikannya; tidak ada klaim exfiltration, karena `orig_bytes` ke tujuan itu kecil dan stabil. Dua kalimat batas itu sama pentingnya dengan temuan. Perhatikan juga bedanya dengan PT JAB: di lab ini sensor melihat laptop langsung tanpa proxy, sehingga langkah 2 cukup satu display filter. Di PT JAB, langkah yang sama butuh dua hop dan log proxy (bagian 2.3).

## 2. Contoh dan langkah praktis: menguji metode pada antrean Senin pagi

Semua artefak di bagian ini fiktif dan merupakan keluaran ilustrasi: perintah ditulis untuk `jkt-nsm-ws01` (tshark 4.6.9, `jq`, Zeek offline) dan query untuk Splunk PT JAB yang menampilkan WIB. Pagi itu antrean berisi lima alert. Tabel berikut adalah peta yang dipakai sepanjang bagian 2; kolom terakhir menunjukkan langkah metode yang paling banyak dilatih.

| Alert | Waktu (WIB) | Sumber | Ringkasan | Bagian | Langkah yang dilatih |
|---|---|---|---|---|---|
| `SOC-2027-0660` | 07:41 | Suricata `jkt-ids01`, rule unduhan PE lewat HTTP | Dua event: hop egress (`10.20.3.60` dan `203.0.113.184`) dan hop core (`10.20.3.60` dan `10.10.60.133`) | 2.1 sampai 2.6 | 0 sampai 4 |
| `SOC-2027-0662` | 07:44 | MDE, severity sedang | `JKT-WS-2063` (`10.10.60.133`): `rundll32.exe` memuat file berekstensi `.dat` dari folder Downloads | 2.7 | 5 |
| `SOC-2027-0663` | 07:52 | MDE, severity rendah, remediasi otomatis | `JKT-WS-2061` (`10.10.60.131`): file dikarantina saat ditulis | 2.7 | 5 (scoping) |
| `SOC-2027-0661` | 09:02 | Saved search beacon program (Day 11) | `JKT-WS-2063` ke `update.raksasoft.example` lewat proxy, 24 interval atau lebih | 2.7 | 5 |
| `SOC-2027-0664` | 10:20 | MDE, severity sedang | `JKT-WS-2060` (`10.10.60.130`, workstation Gilang): sampel malware di folder ekstraksi arsip latihan | 2.10 | Aturan latihan |

Kamu mengerjakan `SOC-2027-0660` bersama Gilang Ramadhan (L1) mulai 08:20, dengan metode bagian 1.2 di layar.

### 2.1 Langkah 0: pertanyaan, jendela waktu, dan bukti (`SOC-2027-0660`)

**Tujuan:** menulis pertanyaan sebelum membuka data, menetapkan jendela dalam dua zona waktu, dan mengamankan pcap serta log sebelum ring buffer menimpanya.

Pertanyaan yang ditulis Gilang di tiket pukul 08:22, setelah dikoreksi sekali:

```
Q1 Workstation mana yang menerima file dari 203.0.113.184, dan file apa?
Q2 Apakah file itu dijalankan, dan apa yang dilakukan host sesudahnya di jaringan?
Q3 Host lain mana yang menghubungi 203.0.113.184 atau tujuan yang muncul dari Q2?
Jendela: Senin 2027-05-31 07:30:00 sampai 08:25:00 WIB = 00:30:00Z sampai 01:25:00Z (tanggal UTC sama)
```

Versi pertama Gilang berbunyi "analisis alert Suricata". Itu bukan pertanyaan: tidak ada yang bisa dijawab ya atau tidak, dan tidak menentukan data apa yang dipotong.

Pemotongan pcap kasus mengikuti pola Day 02 bagian 2.1 dan Day 07:

```bash
mkdir -p /cases/SOC-2027-0660/{carve,zeek,export}
for f in $(cat /cases/SOC-2027-0660/files.txt); do
  tcpdump -r "$f" -w "/cases/SOC-2027-0660/carve/$(basename "$f")" \
    'host 203.0.113.184 or host 203.0.113.185 or (port 53 and (host 10.20.2.53 or host 10.20.2.54))'
done
mergecap -w /cases/SOC-2027-0660/soc0660_0030Z-0125Z.pcapng /cases/SOC-2027-0660/carve/*.pcapng
capinfos -M -c -u -S -H /cases/SOC-2027-0660/soc0660_0030Z-0125Z.pcapng
rsync -a jkt-zeek01:/opt/zeek/logs/2027-05-31/ --include='conn.0[01]*' --include='http.0[01]*' \
  --include='dns.0[01]*' --include='files.0[01]*' --include='ssl.0[01]*' --exclude='*' /cases/SOC-2027-0660/zeek/
sha256sum /cases/SOC-2027-0660/soc0660_*.pcapng /cases/SOC-2027-0660/zeek/* > /cases/SOC-2027-0660/SHA256SUMS
```

| Bagian | Fungsi |
|---|---|
| `files.txt` | File ring di `/mnt/pcap01/ring/` yang mencakup jendela, dipilih dari jam UTC di nama file dan dicek dengan `capinfos -a` |
| BPF `host 203.0.113.184 or host 203.0.113.185` | Tujuan dari alert ditambah tujuan yang baru muncul (langkah 0 boleh diulang saat pertanyaan bertambah) |
| `port 53 and (host 10.20.2.53 or host 10.20.2.54)` | DNS kedua resolver ke luar; klien asli tidak ada di sini |
| `rsync ... /opt/zeek/logs/2027-05-31/` | Arsip Zeek per tanggal UTC; jam 00 dan 01 UTC mencakup jendela |
| `sha256sum ... > SHA256SUMS` | Hash dicatat sebelum siapa pun membuka file |

Keluaran ilustrasi `capinfos` (diringkas):

```
Number of packets:    214388
Capture duration:     3299.612408 seconds
Earliest packet time: 1811723400.018233
Latest packet time:   1811726699.630641
SHA256:               <64 karakter heksadesimal, dicatat di tiket>
```

**Cara membaca hasil:** epoch `1811723400` adalah 2027-05-31 00:30:00 UTC (07:30:00 WIB), sesuai awal jendela; durasi 3.299,6 detik sesuai 55 menit. Sebagian besar paket adalah DNS resolver, bukan trafik ke dua IP luar; itu wajar karena filter DNS sengaja luas.

**Variasi:** bila kasus naik menjadi insiden, jendela diperpanjang dan dipotong lagi dengan pola yang sama; hasilnya digabung dengan `mergecap` dan hash baru dicatat di baris terpisah, bukan menimpa hash lama.

**Kapan gagal:** file ring atau folder arsip Zeek dipilih dengan jam WIB padahal keduanya memakai UTC (Day 12 bagian 2.1); atau pemotongan ditunda dan file Senin pagi baru dicari Kamis.

### 2.2 Langkah 1: orientasi

**Tujuan:** menulis tiga sampai lima kalimat tentang isi data sebelum membaca satu paket pun.

Perintah orientasi dari catatan lama berlaku untuk pcap apa pun:

```
# Wireshark: Statistics > Protocol Hierarchy, Conversations, Endpoints
# Zeek untuk pcap besar:
zeek -r capture.pcap
```

- Cara membaca: hierarchy memberi komposisi protokol; conversations memberi pihak dan volume. Ini menentukan ke mana mendalami [S1].

Di pcap kasus, Conversations (tab IPv4, diurutkan Bytes) memperlihatkan dua pasangan non-DNS: `10.20.3.60` dengan `203.0.113.184` (1 percakapan TCP port 80, sekitar 1,33 MB dari luar ke proxy) dan `10.20.3.60` dengan `203.0.113.185` (21 percakapan TCP port 443, masing-masing beberapa kilobyte). Karena pcap egress tidak memuat workstation, orientasi untuk hop core dilakukan di Splunk:

```
index=zeek ("id.orig_h"="10.10.60.133" OR "id.resp_h"="10.10.60.133")
    earliest="05/31/2027:07:30:00" latest="05/31/2027:08:25:00"
| stats count BY sourcetype
```

Keluaran ilustrasi:

```
sourcetype       count
bro:conn:json    1904
bro:dns:json     612
bro:http:json    23
bro:files:json   3
```

**Cara membaca hasil:** dalam 55 menit, `10.10.60.133` membuat 1.904 koneksi di SPAN core, 612 query DNS, 23 transaksi HTTP ke proxy, dan 3 file polos. Kalimat orientasi yang ditulis Gilang: "Pcap egress memuat satu unduhan HTTP polos dari `203.0.113.184` dan 21 sesi TLS pendek ke `203.0.113.185`, semuanya bersumber proxy. Log Zeek hop core memuat `10.10.60.133` dengan 23 transaksi HTTP lewat proxy. Data mencakup seluruh jendela; tidak ada catatan capture loss di jam ini." Kalimat terakhir dicek dengan `bro:capture_loss:json` (Day 08 bagian 2.10).

**Kapan gagal:** orientasi dilewati dan analis langsung membuka stream pertama yang menarik.

### 2.3 Langkah 2: membatasi ke yang menjawab pertanyaan

**Tujuan:** memilih koneksi kunci untuk Q1 dan Q2, di hop yang memuat host asli.

Display filter dari catatan lama untuk sensor yang melihat host langsung:

```
ip.addr == <host> and (dns or http or tls)
```

- Setelah orientasi, saring ke host atau protokol yang relevan dengan pertanyaan.
- Cara membaca: fokus pada koneksi yang menjawab pertanyaan, bukan semua paket.

Di pcap egress PT JAB, `<host>` diganti tujuan, bukan workstation: `ip.addr == 203.0.113.184 or ip.addr == 203.0.113.185`. Workstation dicari di hop core:

```
index=zeek sourcetype=bro:http:json "id.orig_h"="10.10.60.133"
    earliest="05/31/2027:07:30:00" latest="05/31/2027:08:25:00"
| table _time uid method host uri status_code resp_mime_types
| sort 0 _time
```

Keluaran ilustrasi (diringkas):

```
_time                    uid                 method   host                      uri                                              status_code  resp_mime_types
2027-05-31 07:38:12.402  CkQ3vR2b8xYtT1aH9   GET      berkas-faktur.example     http://berkas-faktur.example/f/faktur-0531.dat  200          application/x-dosexec
2027-05-31 07:43:05.117  C9wLm41ZqH7eXk2Ra   CONNECT  update.raksasoft.example  update.raksasoft.example:443                     200
2027-05-31 07:45:05.604  CaP0u8nY3sVd6Ji1e   CONNECT  update.raksasoft.example  update.raksasoft.example:443                     200
... (19 baris CONNECT lagi ke tujuan yang sama)
2027-05-31 08:01:26.885  CmX5e0Tq2WbLr8Yu4   GET      portal.jab.example        /absensi                                         200          text/html
```

**Cara membaca hasil:** Q1 terjawab di baris pertama: `10.10.60.133` meminta `faktur-0531.dat` lewat proxy dengan URI absolut (ciri permintaan ke proxy eksplisit), dan Zeek mengenali isi balasannya sebagai executable Windows. Lima menit kemudian dimulai rangkaian `CONNECT` ke tujuan yang tidak disebut alert. Baris `portal.jab.example` (absensi internal) tidak menjawab pertanyaan apa pun, jadi tidak didalami. Tujuan baru `update.raksasoft.example` ditambahkan ke Q3 dan ke BPF langkah 0.

**Variasi:** di pcap egress, `http.request.uri contains "faktur-0531"` menemukan permintaan proxy ke `203.0.113.184` dengan selisih milidetik dari hop core; itulah jembatan waktu antara dua hop.

**Kapan gagal:** filter workstation dijalankan di pcap egress dan hasilnya nol; analis lalu menulis "host tidak menghubungi tujuan itu". Yang benar: host tidak pernah terlihat di titik itu.

### 2.4 Langkah 3 dan 4: pendalaman protokol dan pola

**Tujuan:** memastikan isi unduhan dari dua hop, lalu mengukur pola rangkaian `CONNECT` dengan ambang program.

Pendalaman unduhan memakai `files.log`, yang sejak Zeek 5.1 memuat `uid` dan `id` sehingga arah dibaca dari `is_orig` [S2] (Day 08 bagian 1.5):

```
index=zeek sourcetype=bro:files:json mime_type="application/x-dosexec"
    earliest="05/31/2027:07:30:00" latest="05/31/2027:08:25:00"
| table _time uid id.orig_h id.resp_h is_orig mime_type seen_bytes total_bytes sha256
```

Keluaran ilustrasi:

```
_time                    uid                 id.orig_h     id.resp_h      is_orig  mime_type              seen_bytes  total_bytes  sha256
2027-05-31 07:38:12.430  Cr8JtE6yUo3Wn0Pq5   10.20.3.60    203.0.113.184  false    application/x-dosexec  1284608     1284608      6c1f...e9b4
2027-05-31 07:38:12.512  CkQ3vR2b8xYtT1aH9   10.10.60.133  10.20.3.60     false    application/x-dosexec  1284608     1284608      6c1f...e9b4
```

**Cara membaca hasil:** satu file terlihat sekali per hop, dengan `uid` berbeda dan hash identik (Day 08 bagian 1.3). `is_orig=false` berarti file mengalir dari pihak yang dihubungi ke pemulai, dan `seen_bytes` sama dengan `total_bytes` berarti file terlihat utuh. Di pcap egress, file yang sama bisa dipulihkan dengan Export Objects > HTTP di VM analisis, dicek dengan `http.file_data[0:2] == 4d:5a`, dan di-hash untuk dicocokkan; berkasnya diperlakukan sebagai sampel (Day 02). Ekstensi `.dat` tidak berarti apa-apa; magic byte yang menentukan (Day 05 bagian 1.6).

Pola rangkaian `CONNECT` diukur dengan cara Day 11 bagian 1.3:

```
index=zeek sourcetype=bro:http:json method=CONNECT "id.orig_h"="10.10.60.133" uri="update.raksasoft.example:443"
    earliest="05/31/2027:07:30:00" latest="05/31/2027:08:25:00"
| sort 0 _time
| streamstats current=f last(_time) AS prev
| eval delta=_time-prev
| stats count AS n_conn median(delta) AS med avg(delta) AS rata stdev(delta) AS sd
| eval cv=round(sd/rata,3)
```

Keluaran ilustrasi:

```
n_conn  med    rata   sd    cv
21      120.4  120.5  7.23  0.060
```

**Cara membaca hasil:** 21 koneksi memberi 20 interval dengan median 120,4 detik dan CV 0,060, jauh di bawah ambang program 0,2. Jumlah interval masih di bawah minimal 24 milik saved search beacon (Day 11), sehingga alert beacon belum menyala pada 08:25; pada laju ini ambang 24 interval tercapai sekitar 08:31, dan saved search yang berjalan tiap jam membuat `SOC-2027-0661` pada 09:02. `orig_bytes` per tunnel berkisar 1.902 sampai 1.968 byte (median 1.931). Log proxy menunjukkan domain tidak terkategori, sehingga tunnel di-bump dan proxy mencatat `POST https://update.raksasoft.example/v2/poll` dengan status 200 di setiap tunnel. Ini kandidat beacon, belum kesimpulan C2: penjelasan jinak (agent pembaruan perangkat lunak) diuji di langkah 5 lewat prevalence dan proses.

**Kapan gagal:** interval dihitung dari hop egress, di mana koneksi proxy dari banyak workstation ke tujuan yang sama bercampur; atau CV dihitung dari jumlah interval yang terlalu sedikit, sehingga keteraturan kebetulan terlihat seperti mesin.

### 2.5 Langkah 5a: ekstraksi IOC

**Tujuan:** mengumpulkan kandidat IOC dari log, lalu menulisnya dengan konteks dan keyakinan (bagian 1.5).

Perintah dari catatan lama, untuk log Zeek TSV:

```
zeek-cut id.resp_h < conn.log | sort | uniq -c | sort -rn | head
zeek-cut query < dns.log | sort -u
zeek-cut server_name < ssl.log | sort -u
zeek-cut md5 sha256 mime_type < files.log
```

- Cara membaca: kumpulkan tujuan, domain, SNI, dan hash sebagai kandidat IOC; defang saat menulis.

Arsip `jkt-zeek01` berformat JSON dan terkompresi, sehingga padanannya memakai `zcat -f` dan `jq`, dijalankan di folder kasus:

```bash
cd /cases/SOC-2027-0660/zeek
zcat -f dns.*  | jq -r 'select(.query != null) | .query' | sort | uniq -c | sort -rn | grep -E 'faktur|raksasoft'
zcat -f files.* | jq -r 'select(.mime_type == "application/x-dosexec") | [.sha256, .md5, .mime_type, .total_bytes] | @tsv' | sort -u
zcat -f http.*  | jq -r 'select(.host != null) | [.host, .uri] | @tsv' | grep -E 'faktur|raksasoft' | sort | uniq -c
```

| Bagian | Fungsi |
|---|---|
| `zcat -f` | Membaca file `.gz` dan file biasa dengan perintah yang sama |
| `select(.query != null)` | Membuang baris DNS tanpa nama (misalnya respons tanpa query) |
| `select(.mime_type == "application/x-dosexec")` | Hanya executable Windows; hash diambil dari `files.log`, bukan dari file yang diekspor ulang |
| `[.host, .uri] \| @tsv` lalu `uniq -c` | Daftar URI unik per host beserta jumlahnya |

Keluaran ilustrasi (diringkas):

```
     11 update.raksasoft.example
      2 berkas-faktur.example
6c1f...e9b4   3b9d...a07e   application/x-dosexec   1284608
      4 berkas-faktur.example   http://berkas-faktur.example/f/faktur-0531.dat
     21 update.raksasoft.example   update.raksasoft.example:443
```

**Cara membaca hasil:** query DNS di arsip ini berasal dari proxy dan resolver (proxy yang me-resolve nama, Day 08), sehingga angka 11 dan 2 adalah jumlah query proxy, bukan jumlah klien atau koneksi; dengan TTL 300 detik, proxy bertanya ulang sekitar tiap lima menit, bukan tiap tunnel. URI unduhan muncul empat kali: dua permintaan (satu dari `10.10.60.133` dan satu lagi pukul 07:51:30 yang ditelusuri di bagian 2.7), masing-masing tercatat di hop core dan hop egress. Daftar IOC yang ditulis ke tiket:

| Nilai (defang) | Tipe | Ditemukan di | Keyakinan sebagai indikator jahat | Pemakaian |
|---|---|---|---|---|
| `hxxp://berkas-faktur[.]example/f/faktur-0531.dat` | URL | `http.log` hop core dan egress, log proxy | Tinggi (memuat PE yang dijalankan, bagian 2.7) | Blokir di proxy, hunting |
| `berkas-faktur[.]example`, `203.0.113[.]184` | Domain, IP | `dns.log`, `conn.log` hop egress | Tinggi | Blokir di proxy dan firewall |
| `update.raksasoft[.]example`, `203.0.113[.]185` | Domain, IP | `http.log` `CONNECT`, `dns.log`, `conn.log` hop egress | Tinggi setelah korroborasi host | Blokir, hunting 90 hari di `index=zeek` |
| SHA-256 `6c1f...e9b4` (lengkap di tiket) | Hash | `files.log` kedua hop | Tinggi | Diteruskan ke IR dan MDE |
| URI `/v2/poll` metode `POST` | Pola URI | Log proxy (bump) | Sedang (generik) | Hunting saja, bukan blokir |

Fingerprint TLS di egress tidak dimasukkan: tunnel di-bump, sehingga ClientHello ke `203.0.113.185` milik `jkt-proxy01` (Day 06 bagian 1.7).

**Kapan gagal:** IOC ditulis tanpa defang di tiket yang dirender sebagai tautan; hash diambil dari file yang diekspor ulang dari pcap yang segmennya hilang, sehingga tidak cocok dengan hash asli; atau domain layanan bersama (CDN, penyimpanan cloud) dimasukkan ke daftar blokir.

### 2.6 Langkah 5b: timeline dari beberapa sumber

**Tujuan:** menyusun kejadian berurutan dengan satu zona waktu dan sumber per baris.

Perintah dari catatan lama, untuk `conn.log` TSV:

```
zeek-cut ts uid id.orig_h id.resp_h id.resp_p service < conn.log | sort -n
```

- Cara membaca: urutkan koneksi berdasarkan `ts`; pakai UID untuk pivot ke detail. Susun entri timeline dengan timestamp dan sumber.

Padanan JSON, dengan `ts` epoch diubah ke WIB di kolom pertama:

```bash
zcat -f conn.* | jq -r 'select(."id.orig_h"=="10.10.60.133" or ."id.resp_h"=="203.0.113.184" or ."id.resp_h"=="203.0.113.185")
    | [.ts, .uid, ."id.orig_h", ."id.resp_h", ."id.resp_p", (.service // "-")] | @tsv' \
  | sort -n \
  | while IFS=$'\t' read -r ts rest; do printf '%s\t%s\n' "$(TZ=Asia/Jakarta date -d "@${ts%.*}" '+%F %T')" "$rest"; done \
  | head
```

`select(...)` mengambil koneksi workstation di hop core dan koneksi proxy ke dua IP luar di hop egress, `(.service // "-")` mengisi `-` bila layanan tidak dikenali, dan `TZ=Asia/Jakarta date -d "@${ts%.*}"` mengubah epoch (tanpa pecahan detik) menjadi jam WIB.

Keluaran ilustrasi (diringkas):

```
2027-05-31 07:38:12   CkQ3vR2b8xYtT1aH9   10.10.60.133   10.20.3.60      3128   http
2027-05-31 07:38:12   Cr8JtE6yUo3Wn0Pq5   10.20.3.60     203.0.113.184   80     http
2027-05-31 07:43:05   C9wLm41ZqH7eXk2Ra   10.10.60.133   10.20.3.60      3128   http
2027-05-31 07:43:05   CbV2kQ9eRz1Tn5Lw0   10.20.3.60     203.0.113.185   443    ssl
```

**Cara membaca hasil:** epoch `1811723892` adalah 00:38:12 UTC, ditampilkan sebagai 07:38:12 WIB. Pasangan baris yang berjarak milidetik adalah dua hop dari satu permintaan. Timeline di write-up disusun dari baris seperti ini, ditambah log proxy, alert Suricata, dan MDE; setiap baris diberi kolom sumber (bagian 2.8).

**Variasi:** di Splunk, timeline gabungan cukup dengan `(index=zeek ...) OR (index=proxy ...) OR (index=suricata ...)` lalu `table _time index sourcetype ...`; `Timestamp` MDE dari advanced hunting adalah UTC dan harus dikonversi.

**Kapan gagal:** jam pcap (UTC) dan jam Splunk (WIB) dicampur di satu tabel, atau jam sensor dan host tidak sinkron. NIST SP 800-86 menyarankan sinkronisasi waktu supaya korelasi antarsumber mudah [S7]; selisih MDE dan Zeek untuk kasus ini kurang dari satu detik dan dicatat di bagian data dan metode.

### 2.7 Langkah 5c: korelasi host dan scoping

**Tujuan:** menjawab Q2 (apakah file dijalankan) dan Q3 (host lain), lalu memutuskan eskalasi.

Pola korelasi dari catatan lama memakai Sysmon Event ID 3 (network connection), yang mencatat `Image`, `SourceIp`, `DestinationIp`, dan `DestinationPort`:

```
(index=zeek sourcetype=<sourcetype conn dari TA> dest=203.0.113.50)
OR (index=sysmon EventCode=3 DestinationIp=203.0.113.50)
| eval host_ip=coalesce(src, SourceIp)
| eval proc=if(EventCode=3, Image, null())
| stats min(_time) as first max(_time) as last count values(proc) as process by host_ip
```

- Cara membaca: satu baris per host internal yang menghubungi IP itu, dengan daftar proses dari Sysmon bila ada. Host yang muncul di Zeek tetapi tanpa proses berarti Sysmon tidak terpasang atau tidak mencatat; itu batas, bukan bukti bersih.
- `stats` dipakai alih-alih `join` karena tidak terkena batas jumlah hasil subsearch dan lebih cepat di data besar.
- Kapan gagal: NAT atau proxy di antara host dan sensor membuat `src` di Zeek bukan IP host sebenarnya; korelasikan lewat log proxy dulu.

Di PT JAB, baris "kapan gagal" itu yang terjadi: workstation tidak pernah menghubungi `203.0.113.185` langsung, sehingga Sysmon dan Zeek hop egress sama-sama tidak memuat pasangan workstation dan tujuan. Telemetri host utama PT JAB adalah MDE, dan korelasinya memakai pola Day 11 bagian 2.8 (dijalankan 08:55; `Timestamp` UTC):

```
DeviceNetworkEvents
| where Timestamp between (datetime(2027-05-31 00:30:00) .. datetime(2027-05-31 01:55:00))
| where DeviceName startswith "jkt-ws-2063"
| where RemoteIP == "10.20.3.60" and RemotePort == 3128
| summarize n=count(), pertama=min(Timestamp), terakhir=max(Timestamp)
    by InitiatingProcessFileName, InitiatingProcessCommandLine
| order by n desc
```

Keluaran ilustrasi (diringkas):

```
InitiatingProcessFileName  InitiatingProcessCommandLine                                            n     pertama              terakhir
msedge.exe                 "msedge.exe" --type=utility ...                                         1688  2027-05-31 00:30:02  2027-05-31 01:54:57
rundll32.exe               rundll32.exe C:\Users\ratih.kumalasari\Downloads\faktur-0531.dat,Start  36    2027-05-31 00:43:05  2027-05-31 01:53:19
```

**Cara membaca hasil:** `rundll32.exe` memuat file unduhan sebagai DLL, dan proses itu membuat 36 koneksi ke proxy dari 00:43:05 sampai 01:53:19 UTC (07:43:05 sampai 08:53:19 WIB). Zeek hop core pada jendela yang sama mencatat 36 `CONNECT` ke `update.raksasoft.example`. Jumlah dan waktu yang sama dari dua sumber independen menaikkan "kandidat beacon" menjadi "kanal berkala dari proses yang memuat file unduhan", keyakinan tinggi. Apa yang dikirim di dalam `POST /v2/poll` dan apa kemampuan file itu adalah pertanyaan IR.

Scoping memakai log proxy 30 hari:

```
index=proxy (host="berkas-faktur.example" OR host="*.raksasoft.example") earliest="05/01/2027:00:00:00" latest="05/31/2027:08:55:00"
| stats count min(_time) AS pertama max(_time) AS terakhir values(status) AS status BY src user host
| convert ctime(pertama) ctime(terakhir)
```

Keluaran ilustrasi:

```
src           user              host                      count  pertama              terakhir             status
10.10.60.131  dedi.kurniawan    berkas-faktur.example     1      05/31/2027 07:51:30  05/31/2027 07:51:30  200
10.10.60.133  ratih.kumalasari  berkas-faktur.example     1      05/31/2027 07:38:12  05/31/2027 07:38:12  200
10.10.60.133  ratih.kumalasari  update.raksasoft.example  72     05/31/2027 07:43:05  05/31/2027 08:53:19  200
```

**Cara membaca hasil:** dua pengguna Keuangan mengunduh file yang sama; hanya `10.10.60.133` yang kemudian menghubungi `update.raksasoft.example` (72 baris log proxy = 36 `CONNECT` ditambah 36 `POST` yang terlihat karena bump). Tidak ada catatan untuk kedua domain sebelum Senin pagi. `SOC-2027-0663` menjelaskan host kedua: MDE mengarantina `faktur-0531.dat` di `JKT-WS-2061` pukul 07:51:31, satu detik setelah ditulis, dan tidak ada koneksi lanjutan dari host itu. `index=firewall` 30 hari untuk kedua IP luar hanya memuat `10.20.3.60` (`allowed`), jadi tidak ada percobaan langsung dari workstation. Tim email menemukan pesan bertema faktur Mei ke 14 alamat Keuangan pukul 07:31; itu ditulis sebagai informasi dari tim email.

Keputusan: pukul 09:05 kamu membuka `INC-2027-072`, dengan `SOC-2027-0660`, `0661` (menyala 09:02 untuk pasangan yang sama), `0662`, dan `0663` digabung ke dalamnya. Dimas menyetujui isolasi pukul 09:12, dan `JKT-WS-2063` diisolasi lewat MDE pukul 09:14:20. `CONNECT` terakhir tercatat 09:13:23, tunnel ke-46; tidak ada lagi sesudahnya. Proxy memblokir kedua domain pukul 09:20, dan firewall memblokir `203.0.113.184` dan `.185` pukul 09:22.

**Kapan gagal:** scoping hanya memakai hop egress sehingga host kedua tidak terlihat; atau host tanpa MDE (seperti `JKT-WS-2021` di Day 05) tidak punya data proses, dan triage host langsung menjadi satu-satunya jalan.

### 2.8 Langkah 6: write-up `INC-2027-072`

**Tujuan:** menulis temuan dengan kerangka bagian 1.6, ringkasan ditulis paling akhir.

Timeline (WIB, Senin 2027-05-31). Tabel ini adalah inti write-up; kolom sumber memungkinkan setiap baris dicek ulang.

| Waktu (WIB) | Kejadian | Sumber |
|---|---|---|
| 07:31 | Email bertema faktur Mei ke 14 alamat Keuangan | Tim email |
| 07:38:12 | `JKT-WS-2063` (`ratih.kumalasari`) mengunduh `faktur-0531.dat` (PE, 1.284.608 byte) dari `berkas-faktur.example` (`203.0.113.184`) lewat proxy | Zeek `http.log` dan `files.log` kedua hop, log proxy, pcap egress |
| 07:41 | `SOC-2027-0660` | Suricata |
| 07:42:31 | `rundll32.exe` memuat `faktur-0531.dat`; `SOC-2027-0662` pukul 07:44 | MDE |
| 07:43:05 | `CONNECT` pertama ke `update.raksasoft.example` (`203.0.113.185`), lalu tiap sekitar 120 detik | Zeek hop core, log proxy, MDE |
| 07:51:30 | `JKT-WS-2061` (`dedi.kurniawan`) mengunduh file yang sama; dikarantina 07:51:31 (`SOC-2027-0663`) | Log proxy, MDE |
| 09:02 | `SOC-2027-0661` (beacon, 24 interval atau lebih) | Saved search |
| 09:05 | `INC-2027-072` dibuka | Tiket |
| 09:13:23 | `CONNECT` terakhir (ke-46) | Zeek hop core |
| 09:14:20 | `JKT-WS-2063` diisolasi | MDE |
| 09:20 sampai 09:22 | Blokir domain di proxy dan IP di firewall | Change log |

Ringkasan yang dikirim ke Dimas dan Yoga (IR):

```
INC-2027-072  Ringkasan dari data jaringan (Senin 2027-05-31 10:05 WIB)
Ringkasan   : JKT-WS-2063 menjalankan file PE yang diunduh lewat tautan email (07:38), lalu membuka kanal
              berkala tiap ~120 detik ke update.raksasoft.example sampai diisolasi 09:14:20. Keyakinan tinggi
              untuk unduhan, eksekusi, dan kanal (Zeek + proxy + MDE). Fungsi file dan isi kanal belum diketahui.
Host        : JKT-WS-2063 10.10.60.133 (ratih.kumalasari, Keuangan) terdampak ; JKT-WS-2061 10.10.60.131
              (dedi.kurniawan) menerima file, dikarantina MDE, tanpa koneksi lanjutan
Volume      : 46 tunnel, orig_bytes 1.902-1.968 per tunnel (~89 KB total dari host); tidak ada unggahan besar
Data/metode : pcap egress 07:30-08:25 dan 08:25-09:30 (SHA-256 di tiket), arsip Zeek 00-02 UTC, log proxy 30 hari,
              index=firewall 30 hari, MDE DeviceNetworkEvents ; selisih jam MDE dan Zeek < 1 detik
Batas       : isi POST hanya terlihat di proxy (bump), tidak disimpan isinya ; trafik antar workstation
              di switch akses tidak terlihat ; host lain yang membuka email di luar kantor tidak lewat sensor
Rekomendasi : reimage JKT-WS-2063 setelah IR ; hunting 90 hari di index=zeek untuk kedua domain dan hash ;
              cek 12 penerima email lain di MDE ; tinjau rule proxy untuk unduhan PE dari domain baru
Terbuka     : fungsi faktur-0531.dat dan isi kanal (IR) ; apakah ada kredensial yang dipakai dari host ini (IR)
```

**Cara membaca hasil:** setiap kalimat ringkasan bisa ditunjuk ke baris timeline. Kata "C2" tidak dipakai: yang terbukti adalah kanal berkala dari proses yang memuat file unduhan; label C2 menunggu IR menyatakan fungsi file. Volume 46 kali median 1.931 byte adalah sekitar 88.826 byte; angka itu dicatat untuk menjawab pertanyaan "apa yang keluar" sebelum ada yang bertanya. Bagian batas dan terbuka dipisah, sesuai bagian 1.6.

**Kapan gagal:** ringkasan ditulis sebelum korelasi host, sehingga kalimat pertama mengandung kesimpulan yang belum dibuktikan; atau bagian batas dikosongkan karena "kasusnya jelas". Kasus yang jelas tetap punya blind spot.

### 2.9 Zeek di Splunk: validasi CIM dan correlation search yang tidak pernah menyala

**Tujuan:** menjawab pertanyaan keenam Sari dengan memeriksa lapisan pipeline satu per satu, dari input sampai data model.

Konfigurasi input dari catatan lama memantau seluruh direktori:

```
# inputs.conf di universal forwarder sensor
[monitor:///opt/zeek/logs/current]
index = zeek
whitelist = \.log$
```

- Bagian `[monitor://...]` memantau direktori log Zeek yang sedang ditulis; `index` menentukan tujuan. Sourcetype dibiarkan ditentukan TA bila TA mendukung deteksi otomatis per nama berkas; bila tidak, set per berkas sesuai panduan TA.
- Validasi pertama setelah data masuk:

```
index=zeek earliest=-15m
| stats count by sourcetype
```

- Cara membaca: harus muncul satu sourcetype per jenis log (conn, dns, http, ssl, files, dan seterusnya). Bila hanya ada satu sourcetype generik, TA belum mem-parse dengan benar.

PT JAB memakai stanza eksplisit per log dengan sourcetype `bro:<log>:json` (Day 08 bagian 2.11), dan validasi itu lolos: raw search Sari berjalan. Pertanyaan exfiltration Day 12 dalam SPL dari catatan lama juga berjalan di atas field CIM yang diisi TA pada event mentah:

```
index=zeek sourcetype=<sourcetype conn dari TA> earliest=-24h
| stats sum(bytes_out) as out sum(bytes_in) as in count by src dest
| where out > 10*in AND out > 100000000
| sort - out
```

- `stats ... by src dest` menjumlahkan byte per pasangan; `where` menyaring pasangan yang upload-nya lebih dari sepuluh kali unduhan dan lebih dari 100 MB. Kedua angka itu titik awal; ganti dengan baseline lingkunganmu.
- Kapan gagal: bila field CIM belum terpetakan, ganti `bytes_out`/`bytes_in`/`src`/`dest` dengan `orig_bytes`/`resp_bytes`/`'id.orig_h'`/`'id.resp_h'` (nama field bertitik perlu kutip tunggal di `eval`/`where`).

Correlation search Sari berbeda: ia membaca data model, bukan event mentah.

```
| tstats summariesonly=true sum(All_Traffic.bytes_out) AS out sum(All_Traffic.bytes_in) AS in
    from datamodel=Network_Traffic.All_Traffic
    by All_Traffic.src All_Traffic.dest
| rename All_Traffic.* AS *
| where cidrmatch("10.0.0.0/8", src) AND out > 500000000 AND out > 10*in
```

Pemeriksaan dilakukan berlapis, dari bawah ke atas. Tabel berikut adalah urutannya; setiap baris menjawab satu kemungkinan sebab, dan berhenti di baris pertama yang gagal.

| Lapisan | Pemeriksaan | Hasil di PT JAB (ilustrasi) |
|---|---|---|
| Event mentah | `index=zeek sourcetype=bro:conn:json \| head 1 \| table src_ip dest_ip bytes_out conn_state_meaning` | Field CIM ada: TA terpasang di search head |
| Tag | `index=zeek sourcetype=bro:conn:json \| head 5 \| table sourcetype eventtype tag` | `tag` memuat `network` dan `communicate`: event memenuhi syarat `All_Traffic` [S8] |
| Data model tanpa summary | `\| tstats summariesonly=false count from datamodel=Network_Traffic.All_Traffic where index=zeek` | 0, sedangkan `where index=firewall` memberi jutaan |
| Index constraint | Settings > Advanced search > Search macros, `cim_Network_Traffic_indexes` | Definisi `(index=firewall OR index=netops)`: daftar disusun saat ES dipasang 2026, sebelum index `zeek` ada [S9][S10] |
| Summary | Ulangi baris ketiga dengan `summariesonly=true` setelah index ditambahkan | Data sejak perubahan muncul setelah summary dibangun; jendela lama perlu dicek |

**Cara membaca hasil:** sebab pertama adalah index constraint. Data model tidak pernah membaca `zeek`, sehingga correlation search menghitung nol tanpa pesan galat. Perbaikannya: Agung menambahkan `zeek` di halaman CIM Setup (Indexes whitelist) untuk Network_Traffic, Network_Resolution, dan Web dengan tiket perubahan; acceleration tetap diatur Enterprise Security [S9]. Apakah summary untuk data sebelum perubahan ikut dibangun bergantung versi dan setelan; cek dengan `tstats` atas jendela lama, dan bila kosong, putar ulang dengan `summariesonly=false` [S11].

Setelah perbaikan, Sari memutar ulang search di malam `INC-2027-071` (Selasa 2027-05-25 18:00 sampai Rabu 03:00 WIB) dengan `summariesonly=false`:

```
src            dest          out          in
10.10.60.125   10.20.3.60    6412880512   198336511
10.10.60.127   10.20.3.60    1310547961   406298
```

**Cara membaca hasil:** sekarang ada hasil, tetapi `dest` keduanya `10.20.3.60`, proxy. Ini sebab kedua, yang tidak bisa diperbaiki konfigurasi: CIM menyamakan nama, bukan titik pandang (bagian 1.8). Logika "tujuan baru" tidak akan pernah menyala untuk workstation, karena proxy bukan tujuan baru, dan migrasi OneDrive `JKT-WS-2055` berada di baris yang sama dengan exfiltration `JKT-WS-2057`. Keputusan tim: correlation search CIM dipertahankan untuk server data center yang keluar lewat NAT sendiri (di hop egress, `src` adalah server), dengan filter `dest` bukan alamat internal; untuk workstation dipakai saved search hop core yang menggabungkan `CONNECT` dan `conn.log` per `uid` (Day 12 bagian 2.1). Angka di laporan tetap diambil dari field asli Zeek (bagian 1.3).

**Variasi:** urutan pemeriksaan yang sama berlaku untuk `index=suricata` dan data model Intrusion_Detection (Day 09 bagian 1.10).

**Kapan gagal:** search diuji hanya dengan raw search lalu dipindah ke `tstats` tanpa uji ulang; index baru ditambahkan tanpa memperbarui daftar index data model; atau `summariesonly=true` dipakai untuk replay jendela lama yang belum punya summary.

### 2.10 Latihan L1 dengan pcap publik: `SOC-2027-0664` dan aturan lab

**Tujuan:** menjawab pertanyaan ketujuh Sari, dan menutup alert yang lahir dari latihan itu sendiri.

Pukul 10:20, MDE membuat `SOC-2027-0664` di `JKT-WS-2060` (`10.10.60.130`), workstation Gilang: berkas malware terdeteksi dan dikarantina di folder ekstraksi sebuah arsip latihan yang diunduh dari situs pcap publik pukul 10:12. Gilang ingin menyiapkan bahan latihan untuk dirinya dan Dwi setelah pesan Sari. Log proxy menunjukkan satu unduhan arsip dari situs latihan, tidak ada koneksi baru dari host itu setelah ekstraksi, dan MDE tidak mencatat eksekusi. Disposisi: bukan insiden; pelanggaran prosedur latihan. Isi arsip semacam ini memang sesuai peringatan sumbernya: banyak arsip berisi sampel malware dan sebagian pcap ditandai antivirus [S12].

Aturan latihan L1 yang disepakati Dimas, Sari, dan Agung siang itu:

| Aturan | Isi |
|---|---|
| Tempat | Hanya VM latihan `jkt-nsm-lab01` (`10.20.72.10`) di VLAN latihan terisolasi, tanpa rute ke kantor, data center, atau segmen sensor; keluar internet langsung lewat NAT `198.51.100.213`, bukan lewat `jkt-proxy01`; kembali ke snapshot bersih setelah setiap sesi |
| Sumber | Pcap publik dari sumber di bagian 1.9; nama file, URL, tanggal unduh, dan hash dicatat di log latihan |
| Lisensi | Ketentuan tiap sumber dibaca sebelum unduh; pcap latihan tidak disalin ke repo, wiki, atau tiket |
| Metode | Langkah 0 sampai 6 untuk setiap pcap latihan, dengan template bagian 1.6; pembahasan resmi dibaca setelah write-up selesai |
| Larangan | Tidak menjalankan sampel, tidak membuka hasil Export Objects di luar VM, tidak memakai pcap kerja PT JAB untuk latihan di luar `jkt-nsm-ws01` |

**Cara membaca hasil:** risiko pcap publik diperlakukan sama dengan risiko sampel. NAT terpisah membuat trafik latihan tidak bercampur dengan trafik kantor di log proxy dan firewall. Rencana dua minggu untuk Gilang dan Dwi: satu pcap protokol per hari dari SampleCaptures (langkah 1 sampai 3), dua pcap infeksi per minggu (langkah 0 sampai 6), dan satu write-up per minggu yang dibaca Sari.

**Kapan gagal:** VM latihan diberi akses ke share kantor "supaya mudah memindahkan write-up", sehingga isolasinya hilang; atau latihan dikerjakan tanpa pertanyaan tertulis dan berubah menjadi menonton paket.

### 2.11 Metode kerja v1.0 untuk Dimas

Ringkasan berikut dikirim pukul 15:00 sebagai metode kerja tim, setelah diuji pada antrean pagi. Setiap baris merujuk bagian supaya alasannya bisa dibaca ulang.

| Pertanyaan Dimas dan Sari | Jawaban singkat | Bagian |
|---|---|---|
| Apa yang dibakukan | Urutan langkah, sumber per pertanyaan, format IOC dan timeline, label keyakinan, kerangka write-up | 1.1 |
| Langkah dan kapan berhenti | Langkah 0 sampai 6; berhenti di jinak terkonfirmasi, eskalasi, atau data tidak cukup, ketiganya tertulis | 1.2, 2.1 sampai 2.4 |
| Sumber per pertanyaan | Workstation dari hop core dan proxy; isi polos dari `files.log` dan pcap; proses dari MDE; volume dari Zeek dan flow | 1.3, 1.4 |
| IOC, timeline, keyakinan | Lima kolom IOC, timeline WIB dengan sumber, rendah/sedang/tinggi dengan dasar | 1.5, 2.5 sampai 2.7 |
| Kerangka write-up | Ringkasan (ditulis terakhir), timeline, temuan, IOC, data dan metode, batas, pertanyaan terbuka, rekomendasi | 1.6, 2.8 |
| Correlation search CIM nol | Index `zeek` tidak ada di constraint data model; setelah diperbaiki, `dest` workstation tetap proxy, jadi rule workstation memakai hop core | 1.7, 1.8, 2.9 |
| Latihan L1 | VM terisolasi `jkt-nsm-lab01`, NAT terpisah, snapshot, metode penuh untuk setiap pcap latihan | 1.9, 2.10 |
| Hasil uji pagi ini | Lima alert, satu insiden (`INC-2027-072`) diisolasi 96 menit setelah unduhan; langkah 2 paling sering salah (hop egress) | 2.1 sampai 2.10 |

Satu kalimat untuk latihan Kamis: metode ini tidak menambah sensor, tetapi membuat setiap kesimpulan bisa ditunjuk ke baris data, dan setiap "tidak tahu" ditulis dengan alasannya.

## 3. Lab praktik (di VM lab terisolasi)

**Prasyarat:** Wireshark 4.6.x dan/atau Zeek; satu pcap publik latihan (cek lisensi; jangan jalankan sampel); akses Splunk lab opsional untuk integrasi; tidak ada pcap kerja. Semua dikerjakan di jaringan host-only `192.168.56.0/24`: VM analisis `192.168.56.10` (Wireshark, Zeek, `jq`), VM Splunk lab `192.168.56.20` dengan TA for Zeek dan CIM add-on, dan VM unduhan `192.168.56.30` yang satu-satunya boleh keluar internet, dengan snapshot sebelum setiap unduhan.

1. **Pilih pcap.** Dari sumber publik sah (bagian 1.9); catat sumber, URL, tanggal unduh, lisensi, dan SHA-256 arsip.
2. **Pertanyaan.** Tetapkan pertanyaan investigasi (bagian 1.3) sebelum membuka data; tulis jendela waktu pcap dalam UTC dan zona lokal-mu.
3. **Orientasi.** Jalankan orientasi (bagian 2.2); catat komposisi dan pihak dalam tiga sampai lima kalimat.
4. **Dalami.** Batasi dan dalami koneksi kunci per protokol (bagian 2.3 dan 2.4); terapkan deteksi pola (scan, anomali, beacon, exfil) bila relevan.
5. **IOC + timeline.** Ekstrak IOC dan bangun timeline (bagian 2.5 dan 2.6); defang; tandai sumber dan zona waktu per baris; beri label keyakinan (bagian 1.5).
6. **Integrasi (opsional/teks).** Rencanakan atau jalankan di lab integrasi Zeek ke Splunk (bagian 2.9 dan 2.7). Bila Splunk lab tersedia, kirim log Zeek ke index `zeek_lab`, jalankan `| tstats count from datamodel=Network_Traffic.All_Traffic where index=zeek_lab` sebelum dan sesudah index itu dimasukkan ke index constraint, dengan `summariesonly=true` dan `false`.
7. **Write-up.** Tulis temuan lengkap (bagian 2.8, 1.6); pisahkan bukti dari kesimpulan; nyatakan batas, data dan metode, dan pertanyaan terbuka. Baru setelah itu baca pembahasan resmi pcap itu, dan catat perbedaannya.

**Hasil yang sebaiknya tersimpan:**

- Pertanyaan investigasi ditetapkan sebelum membuka data, dengan jendela waktu dua zona.
- Orientasi memberi komposisi dan pihak; pembatasan sesuai pertanyaan.
- Deteksi pola Minggu 1-2 diterapkan sesuai relevansi.
- IOC diekstrak dan di-defang dengan lima kolom; timeline bersumber, satu zona per tabel, berurutan.
- Integrasi Zeek ke Splunk direncanakan dengan pemetaan CIM; hasil `tstats` sebelum dan sesudah index constraint dicatat.
- Write-up memisahkan bukti dari kesimpulan, menyatakan keyakinan, batas, dan rekomendasi.
- Daftar perbedaan antara write-up-mu dan pembahasan resmi, dengan langkah metode tempat perbedaan itu muncul.

**Variasi tantangan:** kerjakan dua pcap publik berbeda jenis (misalnya satu infeksi malware, satu scan atau brute force) dengan alur yang sama, lalu bandingkan: bagaimana alur menyesuaikan dengan pertanyaan dan data berbeda. Simpan dua write-up ringkas sebagai portofolio latihan, dengan IOC ter-defang dan batas yang dinyatakan. Tantangan kedua: hapus pcap dan kerjakan ulang pcap yang sama hanya dari log Zeek, lalu tulis pertanyaan mana yang tidak lagi bisa dijawab (bagian 1.4). Ini latihan langsung untuk capstone (Day 14).

## 4. Troubleshooting

Tabel ini menggabungkan masalah metode dan masalah pipeline. Cari gejalanya di kolom kiri.

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Tersesat di detail | Tanpa pertanyaan/alur | Mulai dari pertanyaan tertulis dan orientasi (bagian 1.2, 2.1) |
| pcap terlalu besar | Wireshark lambat | Olah dengan Zeek; analisis log |
| IOC tak jelas konteks | Tak dicatat saat temukan | Catat sumber dan keyakinan tiap IOC (bagian 2.5) |
| Workstation tidak ada di pcap egress | Proxy dan resolver di antara host dan sensor | Cari di Zeek hop core dan log proxy (bagian 2.3) |
| Field Zeek tak ter-map di Splunk | TA tidak terpasang di search head, atau format log tidak dikenali | Pasang TA for Zeek di search head dan indexer; cek `stats count by sourcetype` |
| Pencarian data model kosong | Field CIM tidak terisi, tag tidak ada, index tidak ada di constraint, atau data model belum dipercepat | Cek field dan tag di event mentah, lalu macro `cim_<datamodel>_indexes`, lalu `summariesonly=false` (bagian 2.9) |
| Correlation search CIM menyala untuk semua workstation ke satu tujuan | `dest` adalah proxy | Pakai rule hop core per `uid` untuk workstation (bagian 2.9) |
| Timeline rancu | Zona waktu/sumber campur | Normalkan zona waktu; tandai sumber (bagian 1.5, 2.6) |
| Jam MDE dan Zeek berselisih | `Timestamp` MDE UTC, atau jam host tidak sinkron | Konversi ke WIB, ukur selisih pada satu kejadian yang sama, tulis di data dan metode |
| Hash file ekspor tidak cocok dengan `files.log` | Segmen hilang di pcap, atau file terpotong | Cek `seen_bytes` vs `total_bytes` dan Expert Information; pakai hash dari `files.log` |
| Dataset lisensi tak jelas | Tak dicek | Cek ketentuan situs sebelum memakai |

## 5. Kesalahan umum dan jebakan

- **Mulai dari alat, bukan pertanyaan.** Tetapkan pertanyaan dulu; alat mengikuti.
- **Melewati langkah 0.** Bukti yang tertimpa ring buffer tidak bisa diambil lagi; potong pcap kasus dan catat hash sebelum analisis panjang.
- **Tidak mencatat sumber IOC/timeline.** Konteks dan keyakinan hilang; catat saat menemukan.
- **Mencampur bukti dan kesimpulan.** Pisahkan tegas; nyatakan keyakinan per kalimat kesimpulan.
- **Menulis ringkasan pertama, atau mencampur UTC dan WIB.** Dua kesalahan yang paling sering di write-up lama (bagian 1.1).
- **Membaca "nol di data model" sebagai "tidak ada kejadian".** Cek index constraint, tag, dan `summariesonly` sebelum menyimpulkan.
- **Mengira CIM menyamakan titik pandang.** `dest` hop core tetap proxy; nama field yang sama tidak membuat sensornya melihat hal yang sama.
- **Menjalankan sampel malware dari dataset.** Jangan; analisis trafik, bukan eksekusi.
- **Menyimpan pcap kerja/klien di repo.** Hanya lab/publik; defang IOC.
- **Membaca pembahasan resmi pcap latihan sebelum menulis.** Latihan berubah menjadi mencocokkan jawaban, bukan melatih metode.
- `[komunitas, belum terkonfirmasi]` Analis berpengalaman mengikuti alur orientasi, pembatasan, pendalaman, korelasi, dan penulisan, serta memandu investigasi dengan pertanyaan, bukan alat; berlatih dengan pcap publik membangun refleks. Pendekatan ini umum dan selaras dengan fase collection, examination, analysis, dan reporting di NIST SP 800-86 [S7]; struktur write-up spesifik mengikuti kebijakan organisasi, perlu dicek.

## 6. Catatan terkini

Bagian ini menampung status versi dan perubahan yang perlu diingat saat memakai metode ini per Oktober 2026.

- TA for Zeek (Splunkbase 5466) kini dirawat Corelight dan menggantikan "Splunk Add-on for Zeek aka Bro" (1617); versi 1.0.11 bertanggal 21 Agustus 2025 masih yang terbaru per 2026-10-29, dengan kompatibilitas Splunk sampai 10.7 [S5]. Panduan lama dengan sourcetype `bro:*` berasal dari TA lama, tetapi pola `bro:<log>:json` tetap dipakai TA baru (Day 08 bagian 1.9).
- Dokumentasi CIM kini di help.splunk.com per versi (misalnya 6.2) [S8]; nama field bisa bergeser antarversi, jadi cek versi yang terpasang.
- Zeek 9.0.1 LTS terbit 26 Oktober 2026 dengan 8.0.11 sebagai LTS sebelumnya [S15]; `jkt-zeek01` dalam cerita memakai 9.0.0, dan pembaruan ke 9.0.1 diperlakukan sebagai perubahan yang memerlukan validasi sourcetype ulang. Suricata 8.0.7 masih rilis stabil, cabang 7.0.x EOL [S16]. Wireshark 4.6.9 stabil, 4.4.19 old stable, 5.0.0rc1 rilis pengembangan [S14].
- NIST SP 800-86 (2006) belum diganti dan tetap menjadi rujukan fase proses forensik dan langkah analisis data jaringan [S7].
- Dataset latihan publik (malware-traffic-analysis.net, CTF DFIR) tetap cara utama berlatih; selalu cek lisensi dan jangan jalankan sampel.
- Dengan enkripsi meluas, metode bergeser ke korelasi metadata lintas sumber (jaringan dan host) di SIEM, bukan hanya membaca isi pcap.
- Day 14 (capstone) memakai metode ini pada kasus end-to-end, dengan template write-up dan template integrasi Zeek ke Splunk yang lebih lengkap.

## 7. Cheat sheet

```
ALUR       0 pertanyaan+bukti -> 1 orientasi (Day02) -> 2 pembatasan -> 3 protokol (Day03-06) -> 4 pola (Day04-05,11-12)
           -> 5 korelasi (UID/flow/alert/proxy/MDE) -> 6 write-up
BERHENTI   jinak terkonfirmasi | eskalasi (INC) | data tidak cukup -- ketiganya ditulis dengan dasar
PANDU      pertanyaan memandu, bukan alat ; Wireshark=detail, Zeek=korelasi, flow=volume, Suricata=alert, MDE=proses
TITIK      egress: web = proxy 10.20.3.60, DNS = resolver ; workstation dari Zeek hop core + log proxy
BUKTI      tcpdump -r BPF -> mergecap -> capinfos -M -c -u -S -H -> sha256sum ; arsip Zeek per tanggal UTC
IOC        nilai (defang) | tipe | ditemukan di | keyakinan | pemakaian ; fingerprint egress setelah bump = proxy
TIMELINE   satu zona per tabel (WIB) + sumber per baris ; TZ=Asia/Jakarta date -d @<ts> ; MDE Timestamp = UTC
YAKIN      rendah: 1 sinyal ; sedang: beberapa sinyal + jinak diuji ; tinggi: + host/pemilik atau 2 sumber independen
WRITE-UP   ringkasan (TERAKHIR) | timeline | temuan | IOC | data+metode | batas | terbuka | rekomendasi
SPLUNK     Zeek JSON -> UF monitor -> index=zeek -> TA for Zeek (app 5466, 1.0.11) -> CIM Network_Traffic (All_Traffic)
           src dest dest_port transport app bytes_out(orig) bytes_in(resp) duration ; tag network communicate
CIM NOL    field CIM di raw? -> tag? -> | tstats summariesonly=false ... where index=zeek -> cim_Network_Traffic_indexes
           CIM menyamakan NAMA, bukan titik pandang ; angka laporan dari field asli Zeek
VALIDASI   index=zeek | stats count by sourcetype ; | metadata type=sourcetypes index=zeek ; korelasi pakai stats, bukan join
DATASET    malware-traffic-analysis.net | Wireshark SampleCaptures | Netresec | CTF ; CEK LISENSI ; VM terisolasi + snapshot
           jangan jalankan sampel ; pembahasan dibaca SETELAH write-up
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** Correlation search "upload besar ke tujuan baru" di atas data model Network_Traffic tidak pernah menyala selama sepekan. Bolehkah disimpulkan bahwa tidak ada upload besar?

<details><summary>Jawaban</summary>

Tidak. Nol dari data model bisa berarti index `zeek` tidak ada di index constraint data model, event tidak bertag `network` dan `communicate`, atau `summariesonly=true` melewatkan data yang belum punya summary. Periksa berlapis dari event mentah ke data model. Di PT JAB, setelah index ditambahkan pun `dest` workstation tetap proxy, sehingga logika "tujuan baru" tidak pernah menyala untuk workstation.

Lihat bagian 1.8 dan 2.9.

</details>

**2. Skenario keputusan.** Gilang memfilter pcap egress dengan `ip.addr == 10.10.60.133` dan mendapat nol paket, padahal alert menyebut host itu. Apa langkah berikutnya?

- A. Tutup alert: host tidak menghubungi tujuan itu.
- B. Cari host di Zeek hop core dan log proxy, karena di egress semua web bersumber proxy.
- C. Minta pcap dengan jendela lebih panjang.

<details><summary>Jawaban</summary>

B. Pcap egress berada setelah proxy dan resolver, jadi workstation memang tidak pernah terlihat di sana. A keliru karena "tidak ada di data" berarti tidak sampai ke sensor, bukan tidak terjadi. C tidak membantu: jendela yang lebih panjang dari titik yang sama tetap tidak memuat workstation.

Lihat bagian 1.3 dan 2.3.

</details>

**3. Pertanyaan jebakan.** "Ringkasan adalah bagian yang paling dibaca, jadi tulis paling awal supaya pembaca cepat paham." Apa yang keliru?

<details><summary>Jawaban</summary>

Letaknya memang paling atas, tetapi ditulis paling akhir. Ringkasan yang ditulis di awal memuat dugaan saat itu, misalnya "C2", sebelum korelasi host selesai, dan kalimat pertama itulah yang dibawa pembaca ke rapat. Ringkasan yang ditulis terakhir bisa ditunjuk ke baris timeline dan temuan.

Lihat bagian 1.1, 1.6, dan 2.8.

</details>

**4. Skenario keputusan.** Dwi ingin mengunduh arsip pcap latihan ke workstation-nya karena VM latihan lambat. Mana yang tepat?

- A. Boleh, asal arsip tidak diekstrak.
- B. Tidak; unduh dan ekstrak hanya di VM latihan terisolasi dengan snapshot, dan catat sumber serta hash.
- C. Boleh, karena MDE akan mengarantina bila ada malware.

<details><summary>Jawaban</summary>

B. Banyak arsip latihan berisi sampel malware asli, dan pcap-nya sendiri bisa ditandai antivirus. A keliru karena arsip yang tersimpan di workstation tetap risiko dan godaan untuk diekstrak. C menjadikan EDR sebagai kontrol utama, persis kejadian `SOC-2027-0664`; karantina setelah ekstraksi bukan rencana latihan.

Lihat bagian 1.9 dan 2.10.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Gilang, dalam tiga kalimat, kenapa langkah 0 (pertanyaan dan pengamanan bukti) dikerjakan sebelum orientasi.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Pertanyaan yang ditulis di awal menentukan data apa yang dipotong dan kapan kita boleh berhenti, jadi tanpa pertanyaan kita hanya menonton paket. Ring buffer egress menimpa dirinya dalam beberapa hari, dan unduhan Kamis di `INC-2027-064` hilang karena baru dicari Senin, jadi pcap kasus dipotong dan di-hash dulu. Hash dan jendela waktu dua zona di tiket juga membuat orang lain bisa mengulang analisis kita persis."

Kesalahan yang sering muncul:
- Menulis "analisis alert" sebagai pertanyaan.
- Menganggap langkah 0 hanya perlu untuk insiden besar.
- Lupa menulis jendela dalam UTC, sehingga file ring yang dipilih meleset tujuh jam.

</details>

**6. Pertanyaan jebakan.** Pukul 08:25, rangkaian `CONNECT` dari `10.10.60.133` punya 21 koneksi dengan median 120,4 detik dan CV 0,06. Rekan menulis di tiket: "C2 terkonfirmasi, keyakinan tinggi". Apa yang salah?

<details><summary>Jawaban</summary>

Pada titik itu yang ada baru pola jaringan: kandidat beacon, keyakinan sedang, karena penjelasan jinak (agent pembaruan) belum disingkirkan dan belum ada korroborasi host. Keyakinan naik menjadi tinggi setelah MDE menunjukkan `rundll32.exe` yang memuat file unduhan membuat jumlah koneksi yang sama dengan `CONNECT` di Zeek (36 dan 36). Label "C2" sendiri menunggu IR menyatakan fungsi file.

Lihat bagian 1.5, 2.4, dan 2.7.

</details>

**7. Interview question (English).** "Walk me through how you approach a packet capture you've never seen before."

<details><summary>Sample answer</summary>

"I start by writing down the question I need to answer and the time window in UTC and local time, and before anything else I make a case copy of the capture and the related logs and hash them, because ring buffers overwrite. Then I orient: capture summary, protocol hierarchy, conversations, so I know what's in the data and what isn't. I narrow to the hosts, times, and protocols that answer the question, keeping in mind where the sensor sits; behind a proxy, the client is only in the proxy logs and the inside leg. I go deep on the key sessions, check for patterns like beaconing or large uploads, then correlate with endpoint telemetry and scope other hosts by prevalence. I write the report last: a timeline with one time zone and a source on every line, defanged IOCs with context, each conclusion labelled with a confidence level, and an explicit section on limits. I stop when it's confirmed benign, escalated, or when the data can't answer, and I say which."

What makes this answer strong: it shows a repeatable sequence, preserves evidence first, accounts for sensor vantage point, separates indicators from conclusions with confidence levels, and treats "the data can't answer this" as a valid, documented outcome.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Wireshark User's Guide (Statistics, orientasi) | https://www.wireshark.org/docs/wsug_html_chunked/ | primer | diakses 2026-10-09 (Day 02) | Tinggi. Alur orientasi |
| S2 | Zeek docs: Logs (ekstraksi IOC, UID) | https://docs.zeek.org/en/current/logs/index.html | primer | diakses 2026-10-09 (Day 08) | Tinggi. Data investigasi |
| S3 | malware-traffic-analysis.net (dataset latihan, metode) | https://www.malware-traffic-analysis.net/ | sekunder | diakses 2026-10-09 (Day 02) | Sedang-tinggi. Latihan; cek lisensi |
| S4 | Netresec: publicly available PCAP files | https://www.netresec.com/?page=PcapFiles | sekunder | diakses 2026-10-09, dicek ulang 2026-10-29 | Sedang-tinggi. Kurasi pcap publik per kategori; peringatan malware asli di arsip berkata sandi; tanpa satu lisensi untuk semua file |
| S5 | Splunkbase: TA for Zeek (app 5466) dan Splunk Add-on for Zeek aka Bro (app 1617) | https://splunkbase.splunk.com/app/5466 | primer | diakses 2026-10-10, dicek ulang 2026-10-29 | Tinggi untuk status TA, perawat, dukungan JSON/TSV, dan pemetaan ke CIM; versi 1.0.11 (21 Agustus 2025), Splunk 9.3 sampai 10.7, CIM 6.x. Daftar sourcetype tidak dirangkum di halaman itu |
| S6 | Splunk documentation: Common Information Model (data model Network_Traffic) | https://docs.splunk.com/ | primer | 2026-10-10 | Tinggi untuk nama field CIM; situs menolak akses otomatis, cari judul halamannya bila perlu; halaman versi baru di S8 |
| S7 | NIST SP 800-86: Guide to Integrating Forensic Techniques into Incident Response | https://csrc.nist.gov/pubs/sp/800/86/final | primer | Agustus 2006; diakses 2026-10-29 | Tinggi. Empat fase (collection, examination, analysis, reporting); bagian 6.4: event of interest, pemeriksaan sumber, fidelity, false negative, kesimpulan dari data dan asumsi, fokus pada dampak; sinkronisasi waktu |
| S8 | Splunk Help: CIM 6.2 data model Network Traffic | https://help.splunk.com/en/data-management/common-information-model/6.2/data-models/network-traffic | primer | diakses 2026-10-29 | Tinggi. Dataset `All_Traffic`, tag `network` dan `communicate`, definisi `src`, `dest`, `dest_port`, `transport`, `app`, `bytes_in`, `bytes_out`, `duration` |
| S9 | Splunk Help: Set up the Splunk Common Information Model Add-on (ES 8, CIM 6.0) | https://help.splunk.com/en/splunk-enterprise-security-8/common-information-model/6.0/introduction/set-up-the-splunk-common-information-model-add-on | primer | diakses 2026-10-29 | Tinggi. Index constraint per data model (bawaan semua index), acceleration mati secara bawaan, ES bisa memaksakan acceleration lewat modular input |
| S10 | Splunk Blog: Splunking Netflow with Splunk Stream, Part 2 | https://splunk.com/en_us/blog/tips-and-tricks/splunking-netflow-with-splunk-stream-part-2-basic-netflow-analytics.html | sekunder (blog vendor) | 28 Oktober 2021; diakses 2026-10-29 | Sedang-tinggi. Constraint bawaan data model Network Traffic memuat macro `cim_Network_Traffic_indexes` dan tag; contoh membatasi ke satu index |
| S11 | Splunk Help: SPL search reference, `tstats` (Splunk Enterprise 10.0) | https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.0/search-commands/tstats | primer | diakses 2026-10-29 | Tinggi. `summariesonly` bawaan `false`; `true` hanya membaca summary acceleration; sintaks `datamodel=<model>.<root dataset>` |
| S12 | malware-traffic-analysis.net: About | https://www.malware-traffic-analysis.net/about.html | sekunder | diakses 2026-10-29 | Sedang-tinggi. Pemakaian atas risiko sendiri, banyak arsip berisi sampel malware, sebagian pcap ditandai antivirus; tanpa lisensi eksplisit |
| S13 | Wireshark Wiki: SampleCaptures | https://wiki.wireshark.org/SampleCaptures | primer | diakses 2026-10-29 | Tinggi untuk isi halaman. Katalog per protokol; tanpa satu lisensi untuk semua file; sebagian berisi trafik malware atau exploit dan material sensitif |
| S14 | Wireshark: Download | https://www.wireshark.org/download.html | primer | diakses 2026-10-29 | Tinggi. 4.6.9 stabil, 4.4.19 old stable, 5.0.0rc1 pengembangan |
| S15 | Zeek: Get Zeek | https://zeek.org/get-zeek/ | primer | diakses 2026-10-29 | Tinggi. 9.0.1 LTS dan 8.0.11 LTS sebelumnya, keduanya 26 Oktober 2026 |
| S16 | Suricata: Download | https://suricata.io/download/ | primer | diakses 2026-10-29 | Tinggi. 8.0.7 (15 September 2026); 7.0.17 EOL |
| S17 | Network-Forensics Day 01-12 (lokal) | (lokal) | rujukan internal | 2026-10-09, diperbarui 2026-10-29 | Alat, pola, sensor, dan insiden PT JAB sebelumnya |

**Catatan sumber:** alur investigasi dan struktur write-up adalah praktik DFIR/NSM umum dan disesuaikan dengan kebijakan organisasi; pemetaan ke fase NIST SP 800-86 [S7] adalah penafsiran catatan ini, bukan struktur yang ditetapkan dokumen itu untuk NSM. Pemetaan field Zeek ke CIM di bagian 1.8 adalah pola umum; hasil persisnya bergantung versi TA dan perlu dicek di lab. Nama sourcetype selain `bro:conn:json`, `bro:http:json`, dan `bro:ssl:json` tidak tercantum di sumber yang diperiksa dan divalidasi dengan `| metadata`. Nama macro `cim_Network_Traffic_indexes` berasal dari blog vendor [S10], bukan dari halaman setup resmi [S9]; apakah summary untuk data lama ikut dibangun setelah index constraint diubah tidak dikonfirmasi sumber primer dan perlu dicek di lingkunganmu. Label keyakinan rendah, sedang, dan tinggi adalah konvensi tim PT JAB, bukan standar eksternal. Lisensi dataset publik dicek sendiri sebelum dipakai [S4][S12][S13]. Seluruh isi PT JAB (alert `SOC-2027-0660` sampai `0664`, `INC-2027-072`, host, domain, hash terpotong, dan angka) fiktif dan merupakan keluaran ilustrasi.
