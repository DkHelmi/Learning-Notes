---
day: 27
title: 'SSE dan ES menilai sumber data: Data Inventory, sourcetype umum on-prem dan cloud, menemukan content per sourcetype'
researched_on: 2026-10-07
versions_checked: Splunk Security Essentials 3.8 (Data Inventory, Security Content, Analytics Advisor/MITRE ATT&CK dashboard); Splunk Enterprise Security 8.7 (Detection Studio); Splunk Add-on for AWS, Microsoft Office 365, Microsoft Cloud Services (dokumentasi sourcetype, versi "latest"); Splunk Enterprise 10.6
---

# Day 27: SSE dan ES menilai sumber data

Cakupan: bagaimana Splunk Security Essentials dan ES dapat dipakai menilai sumber data, termasuk sourcetype umum on-prem dan cloud, serta cara menemukan content untuk sebuah sourcetype.

## Ide inti

Pertanyaan yang dijawab Day ini hanya satu: dari data yang sudah masuk, deteksi apa yang sebenarnya bisa jalan sekarang? Jawabannya bukan daftar sourcetype, karena sebuah content baru bekerja bila tiga hal terpenuhi bersamaan, yaitu jenis event yang tepat benar-benar ada di dalam data, field-nya sudah dinormalisasi ke nama CIM, dan ada content yang memang memakainya. SSE dan ES menyediakan jalur untuk memeriksa ketiganya secara sistematis: Data Inventory mendaftarkan product beserta sourcetype, volume, dan CIM compliance; data source category menjadi bahasa penghubung antara event yang ada dan content yang membutuhkannya; Analytics Advisor dan Detection Studio menunjukkan content yang bisa diaktifkan sekarang, content yang masih kekurangan data, dan detection yang sudah aktif tetapi sebenarnya tidak sehat. Day 45 menjawab di mana konten berada dan Day 21 menjawab data apa yang ada, lalu Day ini menghubungkan keduanya menjadi satu laporan kesiapan data. Laporan itu yang dipakai sebagai dasar argumen kenapa sebuah log perlu di-ingest, sekaligus dasar menolak ingest yang tidak menambah deteksi apa pun.

Analoginya adalah titik monitoring di jaringan: gangguan hanya terlihat di segmen yang benar-benar dipantau, dan daftar perangkat yang sudah dipasangi titik ukur bukan jaminan sebuah gangguan bisa dibuktikan. Batas analoginya ada di langkah setelah data masuk. Di NMS, perangkat yang sudah dipantau langsung muncul di grafik, sedangkan di SIEM sumber yang sudah masuk index belum tentu terpakai: tanpa kategori event dan field yang benar, data model tetap kosong dan content yang bergantung padanya tidak pernah fire. Di PT JAB keadaannya persis begitu. Sepuluh index sudah terisi dan volumenya besar, tetapi ES baru dipasang di search head terpisah, Asset & Identity belum lengkap, dan sebagian add-on belum menormalisasi field yang dibutuhkan, sehingga "lognya sudah masuk" belum berarti alert yang dibangun di atasnya bisa dipercaya.

**Kapan relevan:** sebelum menjanjikan sebuah detection ke SOC lead, saat menyusun usulan sumber data berikutnya beserta alasannya, saat ditanya kenapa skor cakupan ATT&CK rendah padahal log yang masuk banyak, dan saat harus memilih mana yang lebih dulu dikerjakan antara menambah sumber baru dan membenahi normalisasi sumber yang sudah ada.
**Kapan bukan jawaban:** angka cakupan bukan ukuran kemampuan deteksi. Skor ATT&CK yang tinggi bisa berisi detection yang tidak kompatibel dengan data yang ada, dan status "Available" di SSE hanya berarti kategori event-nya terlihat ada, bukan bahwa field dan macro-nya sudah benar. Day ini juga bukan tempat memperbaiki datanya: kalau kategori event yang kurang disebabkan audit policy, konfigurasi agent, atau add-on yang belum dipasang, yang harus diubah ada di sumber dan di onboarding (Day 28), bukan di dashboard penilaian.

## 1. Konsep inti

### 1.1 SSE Data Inventory

Data Inventory di SSE (menu Data > Data Inventory) dipakai untuk mendaftarkan product yang ada di lingkunganmu [S1]:
- Setiap product memuat metadata: sourcetype, volume event, dan CIM compliance. Product terhubung ke data source category [S1].
- Automated Introspection mengumpulkan metadata secara otomatis lewat lima langkah. Fitur ini butuh SSE terpasang di search head produksi (tempat data bisa dicari). Ada juga jalur Manually Configure [S1].
- Tabel product menampilkan vendor/produk, status data, coverage, dan base search yang terisi otomatis. Baris yang dibuka menunjukkan jumlah host, rata-rata ukuran event, volume harian, dan CIM coverage [S1].
- Data > Data Inventory Overview merangkum jumlah data source yang teramati, kategori yang punya data, product yang punya data, dan tabel pemetaan berwarna [S1].

Data source category adalah jenis event spesifik yang harus ada agar sebuah content bekerja, misalnya "Windows process launch with command line" atau "authentication". Setiap content SSE dipetakan ke kategori ini [S2]. Content juga memakai input (pre-filter) macro untuk konfigurasi spesifik lingkungan (index, source, sourcetype) [S2], cek nama macro per content.

### 1.2 Menemukan content di SSE

- **Security Content page**: katalog content (SSE + ESCU) dengan filter. Bagian "Review your content with the Security Content page" di dokumentasi 3.8 [S3].
- **Analytics Advisor**:
  - MITRE ATT&CK Framework dashboard memperhitungkan data dan content aktif di lingkunganmu. Matriks bisa diwarnai menurut Total, Active, Available (bisa dipakai dengan data yang ada), atau Needs data. Filter Highlight Data Source menyorot satu data source di matriks [S4].
  - **MITRE ATT&CK-Driven Content Recommendation**: rekomendasi berdasarkan kategori isu, dengan filter ketersediaan data [S2].
  - Analytics Advisor dirancang untuk menunjukkan celah cakupan, memetakan content ke ATT&CK dan Kill Chain, serta menunjukkan kematangan terhadap Security Data Journey [S2].
- SSE 3.8 menambah dashboard MITRE ATT&CK Benchmark (20 teknik teratas di laporan ancaman) dan Security Data Journey 4 level (Day 45).

### 1.3 Menilai di ES 8.7: Detection Studio

ES 8.x menyediakan Detection Studio, dengan jalur menu Splunk Enterprise Security > Security content > Detection Studio > Launchpad [S5]:
- **Detection coverage**: skor cakupan teknik MITRE ATT&CK untuk detection yang aktif, perubahan cakupan dari waktu ke waktu, dan detection berprioritas tinggi yang tersedia untuk diaktifkan [S5].
- **Detection health**: memantau detection aktif dan menandai yang perlu di-tune, diinvestigasi, atau dinonaktifkan, berdasarkan KPI Performance, Compatibility, Impact, Confidence [S5].
- Rekomendasi diurutkan dengan skor prioritas yang mempertimbangkan, antara lain, performa dan kompatibilitas dengan data yang ada [S5].
- Halaman content juga punya filter Content Enabled dan Data Availability [S4]; cek apakah filter itu ada di SSE, di ES 8, atau keduanya di versi-mu.

Selain itu, di ES: Data Model Audit (Day 25/26), daftar aset/identitas (Day 26), dan inventaris tstats (Day 21) membantu menilai kesiapan data.

**Tanpa ES:** SSE adalah app gratis, jadi Data Inventory, Security Content page, dan dashboard MITRE ATT&CK Framework bisa dipakai di Splunk Enterprise biasa tanpa Enterprise Security. Yang hanya ada di ES adalah Detection Studio beserta skor cakupan dan kesehatan detection (ES 8.x) [S5], ditambah Data Model Audit dan daftar aset serta identitas yang terkelola. Tanpa ES, padanannya dikerjakan sendiri: inventaris sourcetype dan volume dengan `tstats` seperti di bagian 2.1, pemeriksaan kesiapan satu kategori event seperti di bagian 2.2, dan matriks celah di bagian 2.4 yang diisi manual.

### 1.4 Sourcetype umum

On-prem (sourcetype bergantung add-on dan versinya; nilai di bawah adalah konvensi umum, cek di instance Splunk-mu):

| Sumber | Sourcetype umum | Add-on | Data model CIM |
|---|---|---|---|
| Windows Security | `WinEventLog:Security` atau `XmlWinEventLog:Security` | Splunk Add-on for Microsoft Windows | Authentication, Change, Endpoint |
| Sysmon | `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` | Splunk Add-on for Sysmon | Endpoint, Network_Traffic, Network_Resolution |
| Linux auth | `linux_secure` | Splunk Add-on for Unix and Linux | Authentication |
| Syslog umum | `syslog` | (bergantung perangkat) | bervariasi |
| Palo Alto | `pan:traffic`, `pan:threat` | Splunk Add-on for Palo Alto Networks | Network_Traffic, Intrusion_Detection, Web |
| Cisco ASA | `cisco:asa` | Splunk Add-on for Cisco ASA | Network_Traffic |
| Fortinet | `fgt_traffic`, `fgt_utm` (BOTS v1, add-on lama) | Fortinet add-on | Network_Traffic, Intrusion_Detection |
| Suricata | `suricata` | Suricata add-on | Intrusion_Detection, Network_Traffic |
| Splunk Stream | `stream:http`, `stream:dns`, `stream:tcp`, dll. | Splunk Stream | Web, Network_Resolution, Network_Traffic |
| Web server | `access_combined`, `iis` | bawaan / add-on IIS | Web |

Contoh dari BOTS v1 (Day 20): Windows event log, Sysmon, Fortigate, IIS, Nessus, Stream, Suricata, registry Windows [S8].

**Cloud:**

| Sumber | Sourcetype | Add-on | Catatan |
|---|---|---|---|
| AWS CloudTrail | `aws:cloudtrail` | Splunk Add-on for AWS | Riwayat API call AWS [S6] |
| AWS VPC Flow Logs | `aws:cloudwatchlogs:vpcflow` | Splunk Add-on for AWS | Splunk tidak menyarankan add-on AWS untuk mengumpulkan CloudWatch Logs; disarankan lewat Kinesis Firehose add-on [S6] |
| Microsoft 365 audit | `o365:management:activity` | Splunk Add-on for Microsoft Office 365 | Autentikasi, akun, akses data, audit lain [S7] |
| Entra ID (Azure AD), Azure | `azure:monitor:aad`, `azure:monitor:activity`, `azure:monitor:resource`, `mscs:azure:eventhub` | Splunk Add-on for Microsoft Cloud Services | Add-on Office 365 lebih aktif dikembangkan dan dapat menggantikan beberapa sourcetype lama [S7] |
| Okta, GCP, CrowdStrike, dll. | (bervariasi menurut add-on) | add-on vendor | cek di halaman add-on masing-masing |

**Prinsip:** sourcetype adalah label dari add-on. Nama yang sama bisa berubah antar versi (contoh: `ms:o365:management` berganti menjadi `o365:management:activity` [S7]). Jangan menghardcode sourcetype di detection. Gunakan data model CIM (Day 23/24).

## 2. Contoh SPL dan langkah di ES

> Keluaran berlabel ilustrasi.

### 2.1 Daftar product kasar dari data yang ada (pra-introspeksi)

```
| tstats count dc(host) AS hosts where index=* earliest=-7d by index sourcetype
| eval daily_events=round(count/7, 0)
| sort - daily_events
```

Ini mirip informasi yang dikumpulkan introspeksi SSE (sourcetype, host, volume) [S1]. Gunakan untuk memverifikasi hasil introspeksi.

### 2.2 Cek kesiapan data untuk satu data source category

Contoh kategori "Windows process launch with command line":

```
| tstats count dc(Processes.dest) AS hosts from datamodel=Endpoint.Processes where earliest=-24h by sourcetype
| append [ search index=* sourcetype="XmlWinEventLog:Security" EventCode=4688 earliest=-1h
           | eval has_cmd=if(isnotnull(Process_Command_Line) OR isnotnull(CommandLine), 1, 0)
           | stats count AS ev_4688 sum(has_cmd) AS with_cmdline ]
```

- Bagian pertama: sumber yang mengisi Endpoint.Processes dan jumlah host-nya.
- Bagian kedua: apakah event 4688 punya command line. Tanpa command line, banyak content proses tidak berguna. Nama field command line bergantung TA dan format XML/klasik, perlu dicek.
- **Cara membaca hasil:** host di Endpoint jauh lebih sedikit dari total workstation berarti cakupan agent/Sysmon belum merata.

### 2.3 Dari sourcetype ke content: tiga jalur

1. **SSE > Security Content**: filter data source, product, atau sourcetype (bagian 1.2) [S3].
2. **research.splunk.com**: navigasi Data Sources, pilih sumber (mis. Sysmon EventID 1), lalu lihat daftar detection (Day 45).
3. **ES 8.7 > Security content > Detection Studio**: lihat detection tersedia berprioritas tinggi dan statusnya [S5].

### 2.4 Matriks data, content, dan celah (template laporan)

```
| Data source category                | Product / sourcetype           | Status  | CIM | Content tersedia | Aktif | Celah utama                 |
|-------------------------------------|--------------------------------|---------|-----|------------------|-------|-----------------------------|
| Windows process launch w/ cmdline   | Sysmon (XmlWinEventLog:...)    | ada     | ya  | (angka dari SSE) | x     | 30% host belum Sysmon       |
| Authentication                      | WinEventLog:Security, linux_secure | ada | ya  | ...              | ...   | VPN belum di-onboard        |
| Cloud audit                         | o365:management:activity       | tidak   | -   | ...              | 0     | belum ada add-on O365       |
```

Template ini menjadi deliverable yang bagus untuk manajemen dan untuk portofolio.

### 2.5 Langkah di ES/SSE (generik)

1. Pasang SSE di search head yang punya akses data (atau lab).
2. Data > Data Inventory > Launch Automated Introspection [S1]. Periksa hasilnya dan perbaiki tanda X/? dengan Update.
3. Data > Data Inventory Overview untuk ringkasan [S1].
4. **Analytics Advisor > MITRE ATT&CK Framework**: ubah pewarnaan ke "Available" dan "Needs data" [S4].
5. Di ES 8.7: Security content > Detection Studio > Launchpad. Catat skor cakupan dan detection yang ditandai tidak sehat [S5].

## 3. Lab praktik

1. Pasang SSE 3.8.x di Splunk lab. Jalankan Automated Introspection [S1].
2. Bandingkan hasil introspeksi dengan bagian 2.1. Perbaiki product yang salah kategori.
3. Buka MITRE ATT&CK Framework dashboard. Catat 5 teknik dengan status "Available" (bisa diaktifkan sekarang) dan 5 dengan "Needs data" [S4].
4. Untuk satu teknik "Needs data", tentukan data source category yang kurang dan sourcetype yang akan menyediakannya (bagian 1.4).
5. Isi matriks bagian 2.4 untuk lab-mu.
6. (Opsional, bila ada ES 8.7) Buka Detection Studio. Catat skor cakupan dan 3 rekomendasi teratas [S5].

**Hasil yang sebaiknya tersimpan:**
- Introspeksi SSE selesai dan diperbaiki.
- Daftar 5 Available + 5 Needs data.
- Matriks data, content, dan celah terisi.
- Rekomendasi satu sumber data baru dengan alasan berbasis cakupan.

**Variasi tantangan:** pilih satu sumber cloud yang bisa kamu dapatkan secara gratis untuk lab, misalnya log dari akun cloud uji milikmu sendiri (bukan akun kerja). Rencanakan onboarding: add-on, sourcetype, data model target, dan 3 content yang menjadi "Available" setelahnya. Cek biaya dan syarat layanan cloud tersebut.

## 4. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Introspeksi SSE tidak menemukan data | SSE di search head tanpa akses index; peran user tidak bisa membaca index | Pasang di search head produksi/lab dengan akses yang benar [S1] |
| Product salah kategori | Heuristik introspeksi | Manually Configure / Update [S1] |
| Content "Available" tapi tidak menghasilkan apa pun | Data ada, tapi CIM/field tidak lengkap; macro input belum disesuaikan | Cek CIM coverage di Data Inventory; sesuaikan pre-filter macro [S2] |
| Data AWS CloudWatch tidak stabil lewat add-on AWS | Metode koleksi tidak disarankan | Pakai Kinesis Firehose add-on [S6] |
| Sourcetype O365 berbeda dari panduan | Pergantian add-on/sourcetype | Cek dokumentasi add-on yang terpasang [S7] |
| Skor cakupan Detection Studio rendah padahal banyak detection aktif | Detection aktif tidak bisa jalan (kompatibilitas data) | Lihat KPI Compatibility/Health [S5] |

## 5. Kesalahan umum dan jebakan

- Menganggap "ada sourcetype" = "content bisa jalan". Butuh kategori event dan field yang tepat (CIM) [S1][S2].
- Menghardcode sourcetype di detection. Sourcetype berubah antar versi add-on [S7].
- Mengejar skor cakupan ATT&CK tanpa melihat kualitas dan kesehatan detection. Detection Studio sengaja menampilkan keduanya [S5].
- Menjalankan introspeksi di search head yang tidak melihat data produksi [S1].
- Mengumpulkan log cloud dengan metode yang tidak disarankan [S6].
- `[komunitas, belum terkonfirmasi]` Thread Splunk Community soal definisi sourcetype Microsoft Cloud Services [S7] menunjukkan bahwa nama sourcetype add-on ini sering membingungkan. Selalu cek sourcetype yang benar-benar masuk dengan `| tstats count where index=<idx> by sourcetype`.

## 6. Catatan terkini

- ES 8.x Detection Studio (dokumentasi tersedia sejak setidaknya 8.4, kini 8.7): cakupan ATT&CK + kesehatan detection + rekomendasi berprioritas [S5]. Repo contentctl (alat build security_content) tidak lagi menerima PR karena investasi dialihkan ke Detection Studio (Day 45). Hubungan resmi keduanya perlu dicek di README contentctl.
- SSE 3.8 memakai endpoint API ESCU baru. SSE 3.7.1 ke bawah tertahan di ESCU 4.22.0 (Day 45).
- **Microsoft 365:** add-on Office 365 lebih aktif dikembangkan dibanding Microsoft Cloud Services untuk data audit M365 [S7].
- **AWS:** rekomendasi Firehose untuk CloudWatch Logs dan VPC Flow [S6].

## 7. Cheat sheet

```
SSE  Data > Data Inventory : Automated Introspection (search head produksi) | Manually Configure
     product = sourcetype + volume + CIM compliance -> data source category -> content
     Data > Data Inventory Overview | Security Content page | Analytics Advisor > MITRE ATT&CK Framework
     (warna: Total / Active / Available / Needs data ; Highlight Data Source) | ATT&CK-Driven Content Recommendation
ES8  Security content > Detection Studio > Launchpad : coverage ATT&CK (aktif) + health (Performance, Compatibility, Impact, Confidence)
ON-PREM  WinEventLog:Security / XmlWinEventLog:Security | XmlWinEventLog:Microsoft-Windows-Sysmon/Operational | linux_secure
         pan:traffic pan:threat | cisco:asa | suricata | stream:* | access_combined | iis
CLOUD    aws:cloudtrail | aws:cloudwatchlogs:vpcflow (pakai Firehose) | o365:management:activity
         azure:monitor:aad | azure:monitor:activity | mscs:azure:eventhub
PRINSIP  sourcetype = label add-on (bisa berubah) -> tulis detection di atas CIM
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** Data Inventory menampilkan product Sysmon dengan status data ada dan volume harian terbesar di lingkunganmu, dan sebuah content yang membutuhkan kategori "Windows process launch with command line" berstatus Available. Apakah itu cukup untuk menyimpulkan content-nya akan bekerja?

<details><summary>Jawaban</summary>

Belum. Status Available berarti data yang dibutuhkan terlihat ada, bukan bahwa content-nya siap jalan. Dua hal masih bisa menggagalkannya: CIM compliance yang tidak lengkap, sehingga field yang dipakai content tidak terisi walaupun event-nya ada, dan input atau pre-filter macro yang belum disesuaikan ke index, source, serta sourcetype lingkunganmu. Untuk kategori yang membutuhkan command line ada syarat tambahan di sisi sumber: event 4688 tanpa command line tidak berguna untuk content proses, dan nama field command line berbeda antar add-on dan antar format XML atau klasik, jadi perlu dicek. Cara memeriksanya adalah menghitung dari data model dan dari field command line secara langsung, seperti di bagian 2.2, bukan dari volume index. Lihat bagian 1.1, 1.2, 2.2, dan 4.

</details>

**2. Skenario keputusan.** Detection Studio menunjukkan skor cakupan ATT&CK yang rendah, padahal daftar detection di ES memperlihatkan banyak detection berstatus aktif. Apa langkah pertama yang paling tepat?

- A. Aktifkan semua detection berprioritas tinggi yang masih tersedia supaya skornya naik.
- B. Buka sisi health di halaman yang sama dan periksa KPI Compatibility detection yang aktif, karena detection aktif yang tidak bisa jalan di atas data yang ada tidak menyumbang cakupan.
- C. Abaikan skornya, karena cakupan ATT&CK hanya angka untuk laporan manajemen.

<details><summary>Jawaban</summary>

B. Detection Studio memang dirancang menampilkan dua hal sekaligus, yaitu cakupan teknik untuk detection yang aktif dan kesehatan detection lewat KPI Performance, Compatibility, Impact, dan Confidence, dan skor prioritas rekomendasinya ikut mempertimbangkan performa serta kompatibilitas dengan data yang ada. Jadi skor rendah dengan banyak detection aktif adalah gejala khas detection yang aktif tetapi tidak kompatibel, dan diagnosisnya ada di halaman itu juga. A menambah beban search tanpa membuktikan datanya mendukung, dan itu pola yang persis dihindari di bagian 5. C membuang informasi yang sebenarnya bisa ditindaklanjuti. Lihat bagian 1.3, 4, dan 5.

</details>

**3. Pertanyaan jebakan.** Sebuah detection internal kamu tulis dengan filter `sourcetype="ms:o365:management"` dan sudah setahun berjalan. Setelah add-on diperbarui, detection itu berhenti fire padahal log M365 tetap masuk. Apa yang terjadi, dan bagaimana menulisnya supaya tidak terulang?

<details><summary>Jawaban</summary>

Sourcetype adalah label yang diberikan add-on, dan namanya bisa berganti antar versi: `ms:o365:management` berganti menjadi `o365:management:activity` [S7]. Detection yang menghardcode sourcetype ikut mati tanpa pesan error, karena secara sintaks searchnya tetap sah dan hasilnya nol. Perbaikannya ada dua lapis: tulis detection di atas data model CIM (Day 23 dan Day 24) atau lewat satu macro input yang isinya tinggal diganti di satu tempat, lalu verifikasi apa yang benar-benar masuk dengan `| tstats count where index=<idx> by sourcetype` sebelum menyimpulkan datanya hilang. Lihat bagian 1.4 dan 5.

</details>

**4. Jelaskan ulang.** Jelaskan ke SOC lead, dalam tiga kalimat, kenapa permintaan ingest satu sumber log baru sebaiknya datang bersama daftar content yang akan hidup karenanya, bukan hanya nama sumbernya.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh jawaban: "Nilai sebuah sumber baru diukur dari deteksi dan pertanyaan investigasi yang sebelumnya tidak bisa kita jawab, jadi saya menuliskannya sebagai kategori event yang kurang dan content yang berubah status dari butuh data menjadi bisa diaktifkan. Dengan begitu permintaannya bisa dinilai: berapa content yang hidup, teknik ATT&CK mana yang tertutup, dan apa yang masih kosong setelah sumber itu masuk. Kalau daftarnya kosong, yang kita beli hanya biaya ingest, dan uang yang sama biasanya lebih berguna untuk membenahi normalisasi sumber yang sudah ada supaya content yang sudah terpasang mulai bekerja."

Kesalahan yang sering muncul: memakai volume atau jumlah sumber sebagai bukti kemajuan; menjanjikan deteksi hanya karena sourcetype akan muncul, padahal field CIM dan macro masih harus disesuaikan; dan lupa menyebutkan celah yang tetap terbuka setelah sumber itu masuk, sehingga manajemen menganggap satu pembelian menutup seluruh teknik. Lihat bagian 1.1, 1.2, 2.4, dan 5.

</details>

**5. Interview question (English).** "How do you check whether the data in your SIEM actually supports the detection coverage you claim?"

<details><summary>Sample answer</summary>

"I separate three questions that people tend to merge: what data arrives, whether it is normalised, and whether any content uses it. For the first I build an inventory of index, sourcetype, host count and daily volume, which is roughly what the Security Essentials data inventory collects through its automated introspection, and I run that introspection on a search head that can actually see production data, otherwise the result is empty for the wrong reason. For the second I stop counting from the index and start counting from the data model, because a source can be large and still leave the model empty when the add-on has not mapped the fields and tags the content needs. For the third I work from data source categories, the specific event types a piece of content requires, and I use the ATT&CK coverage views to see what is available with today's data versus what needs data, and in Enterprise Security the Detection Studio view also tells me whether the detections I already enabled are healthy and compatible. The deliverable is a short matrix: category, product and sourcetype, whether the data is present, CIM status, content available, content enabled, and the main gap, which is also the document I take into a budget conversation."

What makes this answer strong: it treats arrival, normalisation and content as three separate tests instead of one, names the concrete artefacts that answer each test, and ends with a deliverable a manager can act on rather than a coverage percentage.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | SSE 3.8: Configure the products you have in your environment with the Data Inventory dashboard | https://help.splunk.com/en/splunk-enterprise-security-8/security-essentials/use-splunk-security-essentials/3.8/use-data-in-splunk-security-essentials | primer | diakses 2026-10-07 | Tinggi |
| S2 | SSE: ATT&CK-Driven Content Recommendation (3.7) dan blog "Introducing Analytics Advisor" | https://help.splunk.com/en/splunk-enterprise-security-8/security-essentials/use-splunk-security-essentials/3.7/use-the-analytics-advisor-in-splunk-security-essentials/find-content-with-the-mitre-attck-driven-content-recommendation-dashboard | primer | tanggal tidak tercatat | Sedang-tinggi. Blog Analytics Advisor dari 2019 (>3 tahun) |
| S3 | SSE 3.8: Review your content with the Security Content page | https://help.splunk.com/en/splunk-enterprise-security-8/security-essentials/use-splunk-security-essentials/3.8/use-content-in-splunk-security-essentials/review-your-content-with-the-security-content-page | primer | tanggal tidak tercatat | Sedang-tinggi |
| S4 | SSE 3.8: The MITRE ATT&CK Framework dashboard | https://help.splunk.com/en/splunk-enterprise-security-8/security-essentials/use-splunk-security-essentials/3.8/use-the-analytics-advisor-in-splunk-security-essentials/the-mitre-attck-framework-dashboard | primer | tanggal tidak tercatat | Sedang-tinggi |
| S5 | ES 8.7: Monitor detection coverage and health using Detection Studio | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.7/detections/identify-optimal-detections-for-your-security-environment-using-detection-studio-in-splunk-enterprise-security/monitor-detection-coverage-and-health-using-detection-studio-in-splunk-enterprise-security | primer | diakses 2026-10-07 | Tinggi |
| S6 | Splunk Add-on for AWS: Source types | https://docs.splunk.com/Documentation/AddOns/latest/AWS/DataTypes | primer | tanggal tidak tercatat | Sedang-tinggi. Tautan docs.splunk.com lama; versi terbaru ada di help.splunk.com |
| S7 | Splunk Add-on for Microsoft Office 365: Source types; blog "Splunking Microsoft Cloud Data"; thread komunitas MSCS sourcetype | https://docs.splunk.com/Documentation/AddOns/latest/MSO365/Sourcetypes | primer/sekunder/komunitas | tanggal tidak tercatat | Sedang |
| S8 | GitHub splunk/botsv1 (lihat Day 20) | https://github.com/splunk/botsv1 | primer | diakses 2026-10-07 | Tinggi |

**Catatan sumber:** sourcetype on-prem selain BOTS v1 ditulis dari konvensi add-on yang umum dan perlu dicek di add-on versi-mu. Halaman SSE [S2][S3][S4] dan daftar sourcetype add-on cloud [S6][S7] bisa berubah antar versi; cocokkan nama dashboard dan sourcetype dengan instalasi lab.
