---
day: 06
title: 'Sumber daya SPL di ES, Splunk Security Essentials, dan Splunk Lantern: cara menemukan dan memakai content'
researched_on: 2026-10-10
versions_checked: Splunk Enterprise Security 8.7.0 (2 Sep 2026; glosarium ES 8.7); ES Content Update (ESCU) v6.7.0 (research.splunk.com, "Latest Update"); Splunk Security Essentials 3.8.3 (versi default; 3.8.0 memperkenalkan endpoint API ESCU baru); Splunk Lantern (Use Case Explorer for Security); Splunk Enterprise 10.6
---

# Day 06: Sumber daya SPL di ES, SSE, dan Lantern

Cakupan: memetakan sumber konten dan panduan SPL (research.splunk.com/ESCU, Splunk Security Essentials, Splunk Lantern, content management ES) serta istilah ES 7 dan ES 8.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- menjelaskan peran masing-masing: ESCU / research.splunk.com, Splunk Security Essentials (SSE), Splunk Lantern, dan content management di ES.
- menemukan detection yang relevan untuk sebuah sumber data atau teknik ATT&CK, lalu membaca bagian kuncinya (search, required fields, how to implement, known false positives).
- memetakan istilah ES 7.x (yang masih dipakai banyak dokumentasi dan tulisan lama) ke istilah ES 8.x (yang dipakai produk sekarang).
- memeriksa dari SPL apakah prasyarat sebuah detection terpenuhi di lingkunganmu.

## 2. Konteks singkat

Analyst yang efektif tidak menulis semua detection dari nol. Splunk menyediakan ribuan konten siap pakai. Kemampuan yang menentukan di sini adalah tahu di mana mencarinya dan bagaimana menilainya sebelum mengaktifkan. Di pekerjaan, ini juga cara cepat menjawab pertanyaan seperti "kita punya log Okta, deteksi apa yang bisa langsung jalan?".

**Peringatan versi:** produk keamanan Splunk berubah cepat. Banyak dokumentasi, blog, dan materi pelatihan masih memakai istilah ES 7.x (*notable event*, *correlation search*), sedangkan ES 8.x memakai istilah baru (*finding*, *detection*). Dua-duanya perlu dikenali supaya tidak bingung saat membaca tulisan lama. Tabel pemetaan ada di bagian 3.5.

## 3. Konsep inti

### 3.1 Splunk Security Content: ESCU dan research.splunk.com

- research.splunk.com adalah katalog publik konten Splunk Threat Research Team (STRT). Saat diakses, situs ini mencantumkan sekitar 2.176 detection, 365 analytic story, dan 86 playbook, serta navigasi per data source, MITRE ATT&CK, dan produk. Rilis terbaru yang disebut adalah v6.7.0 [S1].
- Konten yang sama dipaketkan sebagai app ES Content Update (ESCU) di Splunkbase untuk dipasang di ES [S1].
- Sumbernya adalah repo splunk/security_content di GitHub (YAML detection, macro, lookup), yang kamu lihat di Day 01 [S7].
- Analytic story mengelompokkan detection, investigasi, dan respons untuk satu ancaman atau kampanye (mis. "Windows Persistence Techniques").

Setiap detection di research.splunk.com memuat bagian yang wajib dibaca sebelum diaktifkan:

| Bagian | Kenapa penting |
|---|---|
| Search (SPL) | Logika yang sebenarnya, biasanya `tstats` + data model + macro |
| Data source | Sourcetype/produk yang dibutuhkan (mis. Sysmon EID 1, Windows 4688) |
| How to implement | TA yang diperlukan, pemetaan CIM, data model yang harus terakselerasi |
| Known false positives | Ekspektasi noise dan saran filter |
| Macros / filter macro (`*_filter`) | Titik tuning tanpa mengubah logika inti |
| ATT&CK mapping, analytic story | Konteks dan cakupan |
| Test dataset (attack data) | Data uji untuk memvalidasi di lab, cek ketersediaan per detection |

Status konten berubah: sebagian detection ESCU (sejak versi 5.4.0) ditandai deprecated, dan ES menyediakan dashboard Deprecation Assistant untuk melihat detection deprecated yang masih aktif [S3].

### 3.2 Splunk Security Essentials (SSE)

SSE adalah app gratis untuk perencanaan dan penemuan konten: memetakan data yang kamu punya ke konten yang bisa dijalankan, serta melihat cakupan ATT&CK. Fakta terkini:
- 3.8.3 adalah versi default (21 Jan 2026), kompatibel dengan Splunk 9.0-10.6 [S2].
- 3.8.0 memperkenalkan:
  - dashboard MITRE ATT&CK Benchmark (20 teknik teratas di laporan ancaman, untuk mengevaluasi cakupan);
  - Security Data Journey yang disederhanakan menjadi 4 level;
  - endpoint API ESCU baru. Konsekuensinya, SSE 3.7.1 ke bawah tidak bisa memperbarui konten melewati ESCU 4.22.0 [S2].

Fitur SSE untuk menilai sumber data dan konten per sourcetype dibahas lebih dalam di Day 12. Untuk hari ini, cukup tahu bahwa SSE adalah tempat menjawab "konten apa yang cocok untuk data saya". Cek nama halaman (Security Content, Data Inventory, Analytics Advisor) di SSE 3.8.x lab-mu.

### 3.3 Splunk Lantern

Lantern adalah basis pengetahuan resmi berisi panduan praktis: cara melakukan sesuatu, use case, dan tips produk. Untuk keamanan, Use Case Explorer for Security menyusun panduan ke beberapa area [S4], misalnya:
- deteksi ancaman lanjutan;
- ancaman orang dalam dengan deteksi anomali;
- penemuan aset dan identitas berkelanjutan;
- respons insiden dengan otomasi dan orkestrasi;
- kepatuhan;
- security monitoring;
- threat hunting proaktif;
- investigasi ancaman.

Lantern juga memuat panduan teknis yang sudah kamu pakai: mengelola data model di ES (Day 01) dan optimasi search (Day 05).

Bedanya dengan research.splunk.com: Lantern menjelaskan cara (prosedur, konfigurasi, praktik terbaik), sedangkan research.splunk.com menyediakan konten (detection siap pakai). Lantern juga memuat contoh SPL per use case.

Beberapa artikel Lantern lama dipindahkan ke arsip, misalnya salinan lama "Use Case Explorer for Security" di jalur `KC_Sandbox/Archive` [S4]. Pakai versi aktif di `lantern.splunk.com/Security/UCE`; bila sebuah artikel berada di jalur arsip, anggap isinya mungkin sudah tidak diperbarui.

### 3.4 Content di dalam ES

Di ES 8.x:
- Detection dikelola sebagai event-based detection (mengevaluasi raw event untuk membuat finding atau intermediate finding) dan finding-based detection (mengevaluasi finding di risk index untuk membuat finding group) [S5][S6].
- Detection bisa dibuat, diedit, dikloning, diaktifkan/dinonaktifkan, dan diversikan [S5].
- Konten ESCU bisa diperkaya dengan annotations: Analytic Story, Confidence, Context, Impact. Ada *managed annotations* (bawaan ES/ESCU) dan *unmanaged* (kustom) yang ditambahkan dari halaman Content management [S3].

Cek jalur menu persis di ES 8.7 lab-mu: halaman dokumentasi detections tidak mencantumkan jalur menu secara eksplisit [S5]. Annotation dibahas lebih dalam di Day 16.

### 3.5 Pemetaan istilah ES 7.x ke ES 8.x

Menurut glosarium ES 8.7 [S6] dan ringkasan rilis ES 8.0 [S8]:

| Istilah ES 7.x | Istilah ES 8.x | Catatan singkat |
|---|---|---|
| Correlation search (juga risk rule, threat match search) | Detection (event-based) | Search terjadwal yang menghasilkan finding |
| Risk incident rule | Finding-based detection | Mengevaluasi finding/intermediate finding -> finding group [S8] |
| Notable event | Finding | Muncul di analyst queue |
| Risk notable | Finding (menurut glosarium); dalam praktik berupa finding group yang dibuat finding-based detection | Glosarium 8.7 memetakan risk notable ke "finding", sedangkan dokumentasi findings menyebut output finding-based detection sebagai finding group. Pahami keduanya |
| Risk event / contributing events | Intermediate finding | Tidak tampil di analyst queue |
| Incident Review | Analyst queue | Daftar finding dan investigation untuk triage |
| Incident (Mission Control) / ES investigation | Investigation | Kasus kolaboratif |
| Risk object / asset / identity | Entity | Memiliki risk score |
| Threat object / indicator | Observable | Hostname, IP, URL, hash |
| Comment / risk message | Note | |
| Correlation search editor | Detection editor | |
| Intelligence workflow | Threat list | |

**Cara memakai tabel ini:** saat membaca dokumentasi atau tulisan lama, terjemahkan ke istilah ES 8 di kepala. Saat berbicara di pekerjaan atau interview, pakai istilah baru dan sebut istilah lama sebagai jembatan bila lawan bicaramu masih memakainya.

### 3.6 Enterprise vs ES vs app gratis

| Sumber | Butuh ES? | Butuh lisensi khusus? |
|---|---|---|
| research.splunk.com (baca) | Tidak | Tidak |
| security_content (GitHub) | Tidak | Tidak (cek lisensi repo perlu dicek) |
| ESCU app | Dirancang untuk ES; macro/lookup bisa dipakai di Enterprise dengan penyesuaian, perlu dicek | Gratis di Splunkbase |
| SSE | Tidak (jalan di Splunk Enterprise/Cloud) | Gratis |
| Lantern | Tidak | Tidak |
| Content management, detection editor, analyst queue | Ya (ES) | Lisensi ES |

## 4. Contoh SPL dan langkah di ES

> Keluaran berlabel ilustrasi. Sebagian query memakai endpoint REST. Cek nama endpoint dan atribut di versi lab-mu, dan jalankan hanya dengan hak yang sesuai.

### 4.1 Menilai sebuah detection sebelum mengaktifkannya (alur kerja)

Ambil contoh detection "Attacker Tools On Endpoint" dari Day 01:

1. **Baca "How to implement":** butuh log EDR/Sysmon/4688 yang dipetakan ke `Endpoint.Processes`.
2. Cek data source di lingkunganmu (lihat bagian 4.2).
3. Cek data model terakselerasi dan cakupan summary (Day 01 bagian 4.4).
4. Cek lookup dan macro yang dibutuhkan (mis. `attacker_tools`, `security_content_summariesonly`).
5. Jalankan search secara manual di rentang 7 hari. Hitung hasil dan perkirakan FP.
6. Tuning lewat filter macro (`attacker_tools_on_endpoint_filter`), bukan mengubah logika inti, agar pembaruan ESCU tidak menimpa perubahanmu, cek perilaku pembaruan filter macro.
7. Aktifkan, lalu pantau volume finding/notable seminggu pertama.

### 4.2 Apakah data saya memenuhi syarat detection?

```
| tstats count from datamodel=Endpoint.Processes by sourcetype, Processes.vendor_product
| rename Processes.vendor_product AS vendor_product
| sort - count
```

- Menunjukkan sumber apa yang mengisi `Endpoint.Processes`. Jika kosong, detection berbasis Endpoint tidak akan pernah fire.
- Lakukan hal sama untuk data model lain yang diminta detection (Authentication, Network_Traffic, Web, dll.).

Keluaran ilustrasi:

```
sourcetype                                          vendor_product                 count
XmlWinEventLog:Microsoft-Windows-Sysmon/Operational Microsoft Sysmon               1.2 jt
XmlWinEventLog:Security                             Microsoft Windows              340 rb
```

### 4.3 Melihat detection ESCU yang terpasang dan statusnya

```
| rest /servicesNS/-/-/saved/searches splunk_server=local count=0
| search eai:acl.app="DA-ESS-ContentUpdate"
| eval enabled=if(disabled=0, "yes", "no")
| stats count BY enabled
```

- `rest`: membaca konfigurasi saved search lewat REST API di search head.
- `eai:acl.app="DA-ESS-ContentUpdate"`: nama folder app ESCU (nama tampilannya "ES Content Update").
- Hasil: jumlah detection ESCU yang aktif vs tidak.
- Cek di ES 8, detection mungkin punya atribut/representasi berbeda dari saved search klasik. Gunakan halaman content management ES sebagai acuan utama.

### 4.4 Membaca definisi macro security_content

```
| rest /servicesNS/-/-/configs/conf-macros splunk_server=local count=0
| search title="security_content_*" OR title="*_filter"
| table title definition eai:acl.app
```

- Menunjukkan isi macro (mis. `security_content_summariesonly` berkembang menjadi `summariesonly=... allow_old_summaries=... fillnull_value=...`, sesuai Day 01 [S7]).
- Berguna saat menjalankan SPL ESCU di luar ES. Kamu bisa mengganti macro dengan nilai eksplisit.
- Cek endpoint `configs/conf-macros` dan hak akses yang dibutuhkan.

### 4.5 Memakai SPL dari research.splunk.com di lab tanpa ES

1. Salin SPL dari halaman detection.
2. Ganti macro:
   - `` `security_content_summariesonly` `` diganti `summariesonly=false allow_old_summaries=true`. Untuk lab kecil, `false` memastikan hasil lengkap (Day 01).
   - `` `drop_dm_object_name(Processes)` `` diganti `rename Processes.* AS *`.
   - `` `security_content_ctime(firstTime)` `` diganti `convert ctime(firstTime)`.
   - `` `<detection>_filter` `` dihapus, atau diganti dengan `search *`.
3. Jalankan di data lab (BOTS atau Sysmon + Atomic Red Team).
4. Catat hasil dan bandingkan dengan "Known false positives".

### 4.6 Menggunakan Lantern dalam investigasi

Contoh alur: kamu perlu memperbaiki akselerasi data model yang lambat. cari di Lantern, baca panduannya (Day 01 [S6] dan "Optimizing search" di Day 05), terapkan constraint index, lalu verifikasi dengan `tstats` dan Data Model Audit.

## 5. Lab praktik

1. Buka research.splunk.com. Filter per data source Sysmon atau Windows Security, lalu pilih 3 detection yang relevan untuk lab-mu.
2. Untuk masing-masing, isi tabel: nama | data source | data model | macro/lookup | known FP | teknik ATT&CK.
3. Jalankan bagian 4.2 untuk data model yang diminta. Tandai detection mana yang bisa jalan di lab.
4. Jalankan satu detection dengan langkah bagian 4.5. Bila perlu, picu dengan Atomic Red Team untuk teknik terkait di VM Windows lab (snapshot dulu).
5. Pasang SSE di Splunk lab (app gratis). Temukan konten yang cocok dengan data yang kamu punya. Bandingkan hasilnya dengan langkah 3.
6. Cari di Lantern satu artikel tentang Risk-Based Alerting dan satu tentang Asset & Identity. Simpan tautannya untuk Day 10 dan Day 22.
7. Buat kartu hafalan pemetaan istilah ES 7 ke ES 8 (bagian 3.5).

**Hasil yang sebaiknya tersimpan:**
- Tabel 3 detection lengkap.
- Minimal 1 detection dijalankan dan hasilnya ditafsirkan.
- SSE terpasang dan dipakai untuk menemukan konten.
- Kartu pemetaan istilah ES 7 ke ES 8.

**Variasi tantangan:** pilih satu analytic story (mis. persistence Windows). Hitung berapa detection-nya yang bisa jalan di lab, berapa yang butuh data yang tidak kamu punya, dan apa sumber data yang paling "murah" untuk menutup celah terbesar.

## 6. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| SPL ESCU error "macro not found" | ESCU tidak terpasang; macro tidak dibagikan ke app tempat search dijalankan | Pasang ESCU atau ganti macro (bagian 4.5); cek permission macro |
| Detection aktif tapi tidak pernah fire | Data model kosong/tidak terakselerasi; field tidak ter-normalisasi | bagian 4.2; Day 01 bagian 4.4 |
| SSE tidak bisa memperbarui konten | SSE <=3.7.1 dengan endpoint ESCU lama | Upgrade ke SSE >=3.8.0 [S2] |
| Detection lama hilang/berubah setelah update | Ditandai deprecated | Deprecation Assistant [S3] |
| Tuning hilang setelah update ESCU | Mengubah search inti, bukan filter macro | Tuning di filter macro, perlu dicek |
| Bingung istilah di dokumentasi vs soal | ES 7 vs ES 8 | Tabel bagian 3.5 [S6] |

## 7. Kesalahan umum dan jebakan

- Mengaktifkan detection massal tanpa memeriksa prasyarat data, sehingga ratusan detection "hijau" tetapi tidak pernah bisa fire. Ini rasa aman palsu.
- Mengaktifkan tanpa membaca known false positives. Akibatnya banjir finding/notable.
- Mengedit logika inti detection vendor. Perubahan hilang saat update. Gunakan filter macro atau kloning.
- Mengabaikan perbedaan istilah ES 7/8 saat membaca dokumentasi atau menjawab soal.
- Menganggap Lantern = konten detection. Lantern adalah panduan cara; kontennya di ESCU/research.
- `[komunitas]` Belum ada klaim komunitas yang dipakai di Day ini.

## 8. Catatan terkini

- ES 8.x memperkenalkan perubahan istilah besar, yang menurut ringkasan praktisi diselaraskan dengan Open Cybersecurity Schema Framework (OCSF) [S8], cek klaim OCSF di dokumentasi resmi.
- ES 8.6.1 (Agu 2026) dan 8.7.0 (Sep 2026) menambahkan agen AI, misalnya untuk membantu membuat detection, menulis playbook, dan "AI SOC Analyst". Nama dan cakupan fitur ini masih sering berubah, jadi cek di release notes resmi versi-mu.
- ESCU v6.7.0 adalah rilis terbaru menurut research.splunk.com [S1]. Dokumentasi ESCU sudah sampai seri 6.x.
- SSE 3.8.0 memaksa upgrade untuk menerima ESCU baru (batas ESCU 4.22.0 bagi SSE 3.7.1 ke bawah) [S2].
- Repo contentctl (alat build untuk security_content, yang mengubah file YAML detection menjadi paket app ESCU) tidak lagi menerima PR baru, karena Splunk mengalihkan investasi ke Detection Studio di ES. Yang paling terdampak adalah tim yang membangun konten kustom dengan contentctl; apakah ritme rilis ESCU ikut berubah perlu dicek di README repo contentctl dan release notes ESCU.

## 9. Cheat sheet

```
research.splunk.com = katalog konten STRT (detections, analytic stories, playbooks; filter data source/ATT&CK/produk)
ESCU app            = konten yang sama untuk ES (Splunkbase)   | sumber: github splunk/security_content
SSE                 = app gratis: cocokkan data <-> konten, cakupan ATT&CK (3.8.x; >=3.8.0 utk ESCU baru)
Lantern             = panduan "cara" (Use Case Explorer for Security, tips produk)
ES content mgmt     = kelola detection (event-based / finding-based), annotations, versi

SEBELUM AKTIFKAN: how to implement -> data model terisi? (tstats ... by sourcetype) -> macro/lookup ada?
                  -> jalankan manual 7 hari -> baca known FP -> tuning via *_filter macro -> pantau

ES7 -> ES8: correlation search->detection | notable->finding | risk event/contributing->intermediate finding
            Incident Review->analyst queue | risk object->entity | threat object->observable | risk incident rule->finding-based detection
```

## 10. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Splunk Security Content: research.splunk.com | https://research.splunk.com/ | primer | diakses 2026-10-07 | Tinggi. Jumlah konten dan v6.7.0 saat diakses |
| S2 | What's new in Splunk Security Essentials (3.8) | https://help.splunk.com/en/splunk-enterprise-security-8/security-essentials/release-notes-and-resources/3.8/splunk-security-essentials-release-notes/whats-new-in-splunk-security-essentials | primer | halaman diperbarui 2025-07-22; diakses 2026-10-07 | Tinggi. Tanggal rilis 3.8.3 (21 Jan 2026) perlu dicocokkan dengan Splunkbase |
| S3 | ES 8: Add ESCU annotations; Deprecated analytics in ESCU | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.6/managing-security-content/add-escu-annotations-to-detections-and-analytics-stories-in-splunk-enterprise-security | primer | tanggal tidak tercatat | Sedang-tinggi |
| S4 | Splunk Lantern: Use Case Explorer for Security | https://lantern.splunk.com/Security/UCE | primer | diakses 2026-10-07 | Tinggi |
| S5 | ES 8.7: Use detections to search for threats | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.7/detections | primer | diakses 2026-10-07 | Tinggi untuk tipe detection; jalur menu tidak tercantum |
| S6 | ES 8.7: Glossary | https://help.splunk.com/en/splunk-enterprise-security-8/release-notes-and-resources/8.7/where-to-find-help/glossary | primer | diakses 2026-10-07 | Tinggi. Pemetaan istilah |
| S7 | GitHub splunk/security_content (macro dan detection, lihat Day 01) | https://github.com/splunk/security_content | primer | diakses 2026-10-07 (Day 01) | Tinggi |
| S8 | Somerford Associates: What's new for Splunk Enterprise Security v8 | https://somerfordassociates.com/blog/whats-new-for-splunk-enterprise-security-v8 | sekunder (partner) | tanggal tidak tercatat | Sedang. Klaim OCSF dan risk incident rule perlu dicek |

**Catatan sumber:** fitur SSE untuk Security Content dan Data Inventory dibahas dan bersumber di Day 12. Jalur menu content management di ES 8.7 dan atribut REST detection ES 8 belum terkonfirmasi dokumentasi; cek di instance ES-mu. Klaim OCSF [S8] dan fitur agen AI di ES 8.6.1/8.7.0 perlu dicocokkan dengan release notes resmi. Status contentctl perlu dicek di README repo-nya.
