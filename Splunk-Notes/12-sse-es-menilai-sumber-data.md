---
day: 12
title: 'SSE dan ES menilai sumber data: Data Inventory, sourcetype umum on-prem dan cloud, menemukan content per sourcetype'
researched_on: 2026-10-07
versions_checked: Splunk Security Essentials 3.8 (Data Inventory, Security Content, Analytics Advisor/MITRE ATT&CK dashboard); Splunk Enterprise Security 8.7 (Detection Studio); Splunk Add-on for AWS, Microsoft Office 365, Microsoft Cloud Services (dokumentasi sourcetype, versi "latest"); Splunk Enterprise 10.6
---

# Day 12: SSE dan ES menilai sumber data

Cakupan: bagaimana Splunk Security Essentials dan ES dapat dipakai menilai sumber data, termasuk sourcetype umum on-prem dan cloud, serta cara menemukan content untuk sebuah sourcetype.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- menjalankan alur Data Inventory di SSE: introspeksi otomatis, product, data source category, CIM coverage.
- menemukan content untuk sebuah sourcetype atau data source di SSE (Security Content, MITRE ATT&CK dashboard) dan di ES 8.7 (Detection Studio).
- menyebut sourcetype umum untuk sumber on-prem dan cloud, serta add-on yang menghasilkannya.
- menyusun "laporan kesiapan data" yang menghubungkan data yang ada, content yang bisa diaktifkan, dan celahnya.

## 2. Konteks singkat

Day 06 menjawab "di mana konten berada". Day 08 menjawab "data apa yang ada". Hari ini keduanya dihubungkan secara sistematis, karena itulah fungsi SSE dan fitur penilaian di ES: memberi tahu content mana yang bisa jalan dengan data yang kamu punya, dan data apa yang perlu ditambah untuk menutup celah.

Di pekerjaan, ini dasar argumen "kenapa kita perlu ingest log X", dan dasar untuk menolak ingest yang tidak menambah deteksi apa pun.

## 3. Konsep inti

### 3.1 SSE Data Inventory

Data Inventory di SSE (menu Data > Data Inventory) dipakai untuk mendaftarkan product yang ada di lingkunganmu [S1]:
- Setiap product memuat metadata: sourcetype, volume event, dan CIM compliance. Product terhubung ke data source category [S1].
- Automated Introspection mengumpulkan metadata secara otomatis lewat lima langkah. Fitur ini butuh SSE terpasang di search head produksi (tempat data bisa dicari). Ada juga jalur Manually Configure [S1].
- Tabel product menampilkan vendor/produk, status data, coverage, dan base search yang terisi otomatis. Baris yang dibuka menunjukkan jumlah host, rata-rata ukuran event, volume harian, dan CIM coverage [S1].
- Data > Data Inventory Overview merangkum jumlah data source yang teramati, kategori yang punya data, product yang punya data, dan tabel pemetaan berwarna [S1].

Data source category adalah jenis event spesifik yang harus ada agar sebuah content bekerja, misalnya "Windows process launch with command line" atau "authentication". Setiap content SSE dipetakan ke kategori ini [S2]. Content juga memakai input (pre-filter) macro untuk konfigurasi spesifik lingkungan (index, source, sourcetype) [S2], cek nama macro per content.

### 3.2 Menemukan content di SSE

- **Security Content page**: katalog content (SSE + ESCU) dengan filter. Bagian "Review your content with the Security Content page" di dokumentasi 3.8 [S3].
- **Analytics Advisor**:
  - MITRE ATT&CK Framework dashboard memperhitungkan data dan content aktif di lingkunganmu. Matriks bisa diwarnai menurut Total, Active, Available (bisa dipakai dengan data yang ada), atau Needs data. Filter Highlight Data Source menyorot satu data source di matriks [S4].
  - **MITRE ATT&CK-Driven Content Recommendation**: rekomendasi berdasarkan kategori isu, dengan filter ketersediaan data [S2].
  - Analytics Advisor dirancang untuk menunjukkan celah cakupan, memetakan content ke ATT&CK dan Kill Chain, serta menunjukkan kematangan terhadap Security Data Journey [S2].
- SSE 3.8 menambah dashboard MITRE ATT&CK Benchmark (20 teknik teratas di laporan ancaman) dan Security Data Journey 4 level (Day 06).

### 3.3 Menilai di ES 8.7: Detection Studio

ES 8.x menyediakan Detection Studio, dengan jalur menu Splunk Enterprise Security > Security content > Detection Studio > Launchpad [S5]:
- **Detection coverage**: skor cakupan teknik MITRE ATT&CK untuk detection yang aktif, perubahan cakupan dari waktu ke waktu, dan detection berprioritas tinggi yang tersedia untuk diaktifkan [S5].
- **Detection health**: memantau detection aktif dan menandai yang perlu di-tune, diinvestigasi, atau dinonaktifkan, berdasarkan KPI Performance, Compatibility, Impact, Confidence [S5].
- Rekomendasi diurutkan dengan skor prioritas yang mempertimbangkan, antara lain, performa dan kompatibilitas dengan data yang ada [S5].
- Halaman content juga punya filter Content Enabled dan Data Availability [S4]; cek apakah filter itu ada di SSE, di ES 8, atau keduanya di versi-mu.

Selain itu, di ES: Data Model Audit (Day 01/10), daftar aset/identitas (Day 10), dan inventaris tstats (Day 08) membantu menilai kesiapan data.

### 3.4 Sourcetype umum

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

Contoh dari BOTS v1 (Day 07): Windows event log, Sysmon, Fortigate, IIS, Nessus, Stream, Suricata, registry Windows [S8].

**Cloud:**

| Sumber | Sourcetype | Add-on | Catatan |
|---|---|---|---|
| AWS CloudTrail | `aws:cloudtrail` | Splunk Add-on for AWS | Riwayat API call AWS [S6] |
| AWS VPC Flow Logs | `aws:cloudwatchlogs:vpcflow` | Splunk Add-on for AWS | Splunk tidak menyarankan add-on AWS untuk mengumpulkan CloudWatch Logs; disarankan lewat Kinesis Firehose add-on [S6] |
| Microsoft 365 audit | `o365:management:activity` | Splunk Add-on for Microsoft Office 365 | Autentikasi, akun, akses data, audit lain [S7] |
| Entra ID (Azure AD), Azure | `azure:monitor:aad`, `azure:monitor:activity`, `azure:monitor:resource`, `mscs:azure:eventhub` | Splunk Add-on for Microsoft Cloud Services | Add-on Office 365 lebih aktif dikembangkan dan dapat menggantikan beberapa sourcetype lama [S7] |
| Okta, GCP, CrowdStrike, dll. | (bervariasi menurut add-on) | add-on vendor |, cek di halaman add-on masing-masing |

**Prinsip:** sourcetype adalah label dari add-on. Nama yang sama bisa berubah antar versi (contoh: `ms:o365:management` berganti menjadi `o365:management:activity` [S7]). Jangan menghardcode sourcetype di detection. Gunakan data model CIM (Day 09/11).

### 3.5 Enterprise vs ES

| Kemampuan | Tanpa ES | Dengan ES |
|---|---|---|
| SSE (Data Inventory, Security Content, ATT&CK dashboard) | Ya (app gratis) | Ya |
| Detection Studio (coverage + health) | Tidak | Ya, ES 8.x [S5] |
| Data Model Audit, A&I | Sebagian (manual) | Ya |

## 4. Contoh SPL dan langkah di ES

> Keluaran berlabel ilustrasi.

### 4.1 Daftar product kasar dari data yang ada (pra-introspeksi)

```
| tstats count dc(host) AS hosts where index=* earliest=-7d by index sourcetype
| eval daily_events=round(count/7, 0)
| sort - daily_events
```

Ini mirip informasi yang dikumpulkan introspeksi SSE (sourcetype, host, volume) [S1]. Gunakan untuk memverifikasi hasil introspeksi.

### 4.2 Cek kesiapan data untuk satu data source category

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

### 4.3 Dari sourcetype ke content: tiga jalur

1. **SSE > Security Content**: filter data source, product, atau sourcetype (bagian 3.2) [S3].
2. **research.splunk.com**: navigasi Data Sources, pilih sumber (mis. Sysmon EventID 1), lalu lihat daftar detection (Day 06).
3. **ES 8.7 > Security content > Detection Studio**: lihat detection tersedia berprioritas tinggi dan statusnya [S5].

### 4.4 Matriks data, content, dan celah (template laporan)

```
| Data source category                | Product / sourcetype           | Status  | CIM | Content tersedia | Aktif | Celah utama                 |
|-------------------------------------|--------------------------------|---------|-----|------------------|-------|-----------------------------|
| Windows process launch w/ cmdline   | Sysmon (XmlWinEventLog:...)    | ada     | ya  | (angka dari SSE) | x     | 30% host belum Sysmon       |
| Authentication                      | WinEventLog:Security, linux_secure | ada | ya  | ...              | ...   | VPN belum di-onboard        |
| Cloud audit                         | o365:management:activity       | tidak   | -   | ...              | 0     | belum ada add-on O365       |
```

Template ini menjadi deliverable yang bagus untuk manajemen dan untuk portofolio.

### 4.5 Langkah di ES/SSE (generik)

1. Pasang SSE di search head yang punya akses data (atau lab).
2. Data > Data Inventory > Launch Automated Introspection [S1]. Periksa hasilnya dan perbaiki tanda X/? dengan Update.
3. Data > Data Inventory Overview untuk ringkasan [S1].
4. **Analytics Advisor > MITRE ATT&CK Framework**: ubah pewarnaan ke "Available" dan "Needs data" [S4].
5. Di ES 8.7: Security content > Detection Studio > Launchpad. Catat skor cakupan dan detection yang ditandai tidak sehat [S5].

## 5. Lab praktik

1. Pasang SSE 3.8.x di Splunk lab. Jalankan Automated Introspection [S1].
2. Bandingkan hasil introspeksi dengan bagian 4.1. Perbaiki product yang salah kategori.
3. Buka MITRE ATT&CK Framework dashboard. Catat 5 teknik dengan status "Available" (bisa diaktifkan sekarang) dan 5 dengan "Needs data" [S4].
4. Untuk satu teknik "Needs data", tentukan data source category yang kurang dan sourcetype yang akan menyediakannya (bagian 3.4).
5. Isi matriks bagian 4.4 untuk lab-mu.
6. (Opsional, bila ada ES 8.7) Buka Detection Studio. Catat skor cakupan dan 3 rekomendasi teratas [S5].

**Hasil yang sebaiknya tersimpan:**
- Introspeksi SSE selesai dan diperbaiki.
- Daftar 5 Available + 5 Needs data.
- Matriks data, content, dan celah terisi.
- Rekomendasi satu sumber data baru dengan alasan berbasis cakupan.

**Variasi tantangan:** pilih satu sumber cloud yang bisa kamu dapatkan secara gratis untuk lab, misalnya log dari akun cloud uji milikmu sendiri (bukan akun kerja). Rencanakan onboarding: add-on, sourcetype, data model target, dan 3 content yang menjadi "Available" setelahnya. Cek biaya dan syarat layanan cloud tersebut.

## 6. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Introspeksi SSE tidak menemukan data | SSE di search head tanpa akses index; peran user tidak bisa membaca index | Pasang di search head produksi/lab dengan akses yang benar [S1] |
| Product salah kategori | Heuristik introspeksi | Manually Configure / Update [S1] |
| Content "Available" tapi tidak menghasilkan apa pun | Data ada, tapi CIM/field tidak lengkap; macro input belum disesuaikan | Cek CIM coverage di Data Inventory; sesuaikan pre-filter macro [S2] |
| Data AWS CloudWatch tidak stabil lewat add-on AWS | Metode koleksi tidak disarankan | Pakai Kinesis Firehose add-on [S6] |
| Sourcetype O365 berbeda dari panduan | Pergantian add-on/sourcetype | Cek dokumentasi add-on yang terpasang [S7] |
| Skor cakupan Detection Studio rendah padahal banyak detection aktif | Detection aktif tidak bisa jalan (kompatibilitas data) | Lihat KPI Compatibility/Health [S5] |

## 7. Kesalahan umum dan jebakan

- Menganggap "ada sourcetype" = "content bisa jalan". Butuh kategori event dan field yang tepat (CIM) [S1][S2].
- Menghardcode sourcetype di detection. Sourcetype berubah antar versi add-on [S7].
- Mengejar skor cakupan ATT&CK tanpa melihat kualitas dan kesehatan detection. Detection Studio sengaja menampilkan keduanya [S5].
- Menjalankan introspeksi di search head yang tidak melihat data produksi [S1].
- Mengumpulkan log cloud dengan metode yang tidak disarankan [S6].
- `[komunitas, belum terkonfirmasi]` Thread Splunk Community soal definisi sourcetype Microsoft Cloud Services [S7] menunjukkan bahwa nama sourcetype add-on ini sering membingungkan. Selalu cek sourcetype yang benar-benar masuk dengan `| tstats count where index=<idx> by sourcetype`.

## 8. Catatan terkini

- ES 8.x Detection Studio (dokumentasi tersedia sejak setidaknya 8.4, kini 8.7): cakupan ATT&CK + kesehatan detection + rekomendasi berprioritas [S5]. Repo contentctl (alat build security_content) tidak lagi menerima PR karena investasi dialihkan ke Detection Studio (Day 06). Hubungan resmi keduanya perlu dicek di README contentctl.
- SSE 3.8 memakai endpoint API ESCU baru. SSE 3.7.1 ke bawah tertahan di ESCU 4.22.0 (Day 06).
- **Microsoft 365:** add-on Office 365 lebih aktif dikembangkan dibanding Microsoft Cloud Services untuk data audit M365 [S7].
- **AWS:** rekomendasi Firehose untuk CloudWatch Logs dan VPC Flow [S6].

## 9. Cheat sheet

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

## 10. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | SSE 3.8: Configure the products you have in your environment with the Data Inventory dashboard | https://help.splunk.com/en/splunk-enterprise-security-8/security-essentials/use-splunk-security-essentials/3.8/use-data-in-splunk-security-essentials | primer | diakses 2026-10-07 | Tinggi |
| S2 | SSE: ATT&CK-Driven Content Recommendation (3.7) dan blog "Introducing Analytics Advisor" | https://help.splunk.com/en/splunk-enterprise-security-8/security-essentials/use-splunk-security-essentials/3.7/use-the-analytics-advisor-in-splunk-security-essentials/find-content-with-the-mitre-attck-driven-content-recommendation-dashboard | primer | tanggal tidak tercatat | Sedang-tinggi. Blog Analytics Advisor dari 2019 (>3 tahun) |
| S3 | SSE 3.8: Review your content with the Security Content page | https://help.splunk.com/en/splunk-enterprise-security-8/security-essentials/use-splunk-security-essentials/3.8/use-content-in-splunk-security-essentials/review-your-content-with-the-security-content-page | primer | tanggal tidak tercatat | Sedang-tinggi |
| S4 | SSE 3.8: The MITRE ATT&CK Framework dashboard | https://help.splunk.com/en/splunk-enterprise-security-8/security-essentials/use-splunk-security-essentials/3.8/use-the-analytics-advisor-in-splunk-security-essentials/the-mitre-attck-framework-dashboard | primer | tanggal tidak tercatat | Sedang-tinggi |
| S5 | ES 8.7: Monitor detection coverage and health using Detection Studio | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.7/detections/identify-optimal-detections-for-your-security-environment-using-detection-studio-in-splunk-enterprise-security/monitor-detection-coverage-and-health-using-detection-studio-in-splunk-enterprise-security | primer | diakses 2026-10-07 | Tinggi |
| S6 | Splunk Add-on for AWS: Source types | https://docs.splunk.com/Documentation/AddOns/latest/AWS/DataTypes | primer | tanggal tidak tercatat | Sedang-tinggi. Tautan docs.splunk.com lama; versi terbaru ada di help.splunk.com |
| S7 | Splunk Add-on for Microsoft Office 365: Source types; blog "Splunking Microsoft Cloud Data"; thread komunitas MSCS sourcetype | https://docs.splunk.com/Documentation/AddOns/latest/MSO365/Sourcetypes | primer/sekunder/komunitas | tanggal tidak tercatat | Sedang |
| S8 | GitHub splunk/botsv1 (lihat Day 07) | https://github.com/splunk/botsv1 | primer | diakses 2026-10-07 | Tinggi |

**Catatan sumber:** sourcetype on-prem selain BOTS v1 ditulis dari konvensi add-on yang umum dan perlu dicek di add-on versi-mu. Halaman SSE [S2][S3][S4] dan daftar sourcetype add-on cloud [S6][S7] bisa berubah antar versi; cocokkan nama dashboard dan sourcetype dengan instalasi lab.
