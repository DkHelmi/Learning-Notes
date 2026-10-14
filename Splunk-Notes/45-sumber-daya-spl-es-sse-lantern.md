---
day: 45
title: 'Sumber daya SPL di ES, Splunk Security Essentials, dan Splunk Lantern: cara menemukan dan memakai content'
researched_on: 2026-10-10
versions_checked: Splunk Enterprise Security 8.7.0 (2 Sep 2026; glosarium ES 8.7); ES Content Update (ESCU) v6.7.0 (research.splunk.com, "Latest Update"); Splunk Security Essentials 3.8.3 (versi default; 3.8.0 memperkenalkan endpoint API ESCU baru); Splunk Lantern (Use Case Explorer for Security); Splunk Enterprise 10.6
---

# Day 45: Sumber daya SPL di ES, SSE, dan Lantern

Cakupan: memetakan sumber konten dan panduan SPL (research.splunk.com/ESCU, Splunk Security Essentials, Splunk Lantern, content management ES) dan cara menilai sebuah detection vendor sebelum diaktifkan.

## Ide inti

Analyst yang efektif tidak menulis semua detection dari nol. Splunk sudah menerbitkan ribuan konten siap pakai, jadi kemampuan yang menentukan bukan menulis SPL, melainkan tahu di mana konten itu disimpan, bagaimana membacanya, dan bagaimana menilai apakah ia bisa hidup di lingkunganmu sebelum diaktifkan. Ada empat tempat yang perlu dibedakan: research.splunk.com beserta app ESCU sebagai katalog detection dan analytic story dari Splunk Threat Research Team, Splunk Security Essentials sebagai app gratis untuk mencocokkan data yang kamu punya dengan konten yang bisa jalan, Splunk Lantern sebagai panduan cara melakukan sesuatu, dan content management di ES sebagai tempat detection benar-benar dikelola, diversikan, dan diberi annotation. Tiga yang pertama bisa dibaca tanpa lisensi apa pun; yang terakhir hanya ada di ES.

Yang memisahkan pemakaian konten vendor yang sehat dari yang asal pasang adalah satu pertanyaan: apakah prasyarat datanya terpenuhi. Setiap detection menyebut sumber data, data model, macro, dan lookup yang dibutuhkannya, dan detection yang diaktifkan tanpa itu akan tampak aktif di daftar tanpa pernah bisa menyala sekali pun. Karena itu alur kerjanya selalu sama: baca "how to implement", buktikan data model yang diminta benar-benar terisi, jalankan search-nya secara manual, baca known false positives, lalu tuning lewat filter macro supaya pembaruan konten tidak menghapus pekerjaanmu. Di pekerjaan, ini juga cara cepat menjawab pertanyaan seperti "sumber log ini baru masuk, deteksi apa yang bisa langsung jalan?".

Padanannya di NOC adalah template alarm bawaan NMS beserta knowledge base vendor: ada ratusan template yang bisa diimpor, ada matriks kompatibilitas yang menyebut counter dan versi firmware yang dibutuhkan, dan ada artikel how-to untuk pekerjaan yang berulang. Batas analogi: template bawaan tidak tahu topologi dan sumber data milikmu, jadi alarm yang sudah terpasang tetap diam selamanya bila counter yang dipakainya tidak pernah dikirim perangkat, dan di layar hal itu terlihat seperti jaringan yang tenang.

Di PT Jaringan Anak Bangsa (PT JAB, ISP menengah fiktif), Sysmon baru masuk dari sekitar 40 persen workstation ke index `sysmon`, dan log identitas cloud masuk ke index `o365`. SOC lead bertanya deteksi apa yang bisa langsung jalan minggu ini tanpa menambah sumber data baru. Day ini adalah cara menjawab pertanyaan itu dengan bukti, bukan dengan jumlah detection yang diaktifkan.

**Kapan relevan:** saat sumber data baru masuk dan perlu diketahui konten apa yang bisa langsung dipakai, saat harus menilai satu detection vendor sebelum mengaktifkannya, saat mencari panduan prosedur resmi untuk pekerjaan yang berulang, dan saat harus membuktikan ke SOC lead bahwa daftar detection yang aktif memang bisa menyala di data yang ada.
**Kapan bukan jawaban:** konten siap pakai tidak menutup celah onboarding, parsing, dan normalisasi (Day 23 dan Day 28), tidak menggantikan detection kustom untuk risiko khas organisasimu, dan tidak menentukan ambang maupun daftar pengecualian yang hanya bisa dihitung dari datamu sendiri (Day 36).

## 1. Konsep inti

### 1.1 Splunk Security Content: ESCU dan research.splunk.com

- research.splunk.com adalah katalog publik konten Splunk Threat Research Team (STRT). Saat diakses, situs ini mencantumkan sekitar 2.176 detection, 365 analytic story, dan 86 playbook, serta navigasi per data source, MITRE ATT&CK, dan produk. Rilis terbaru yang disebut adalah v6.7.0 [S1].
- Konten yang sama dipaketkan sebagai app ES Content Update (ESCU) di Splunkbase untuk dipasang di ES [S1].
- Sumbernya adalah repo splunk/security_content di GitHub (YAML detection, macro, lookup), yang kamu lihat di Day 25 [S7].
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

### 1.2 Splunk Security Essentials (SSE)

SSE adalah app gratis untuk perencanaan dan penemuan konten: memetakan data yang kamu punya ke konten yang bisa dijalankan, serta melihat cakupan ATT&CK. Fakta terkini:
- 3.8.3 adalah versi default (21 Jan 2026), kompatibel dengan Splunk 9.0-10.6 [S2].
- 3.8.0 memperkenalkan:
  - dashboard MITRE ATT&CK Benchmark (20 teknik teratas di laporan ancaman, untuk mengevaluasi cakupan);
  - Security Data Journey yang disederhanakan menjadi 4 level;
  - endpoint API ESCU baru. Konsekuensinya, SSE 3.7.1 ke bawah tidak bisa memperbarui konten melewati ESCU 4.22.0 [S2].

Fitur SSE untuk menilai sumber data dan konten per sourcetype dibahas lebih dalam di Day 27. Untuk hari ini, cukup tahu bahwa SSE adalah tempat menjawab "konten apa yang cocok untuk data saya". Cek nama halaman (Security Content, Data Inventory, Analytics Advisor) di SSE 3.8.x lab-mu.

### 1.3 Splunk Lantern

Lantern adalah basis pengetahuan resmi berisi panduan praktis: cara melakukan sesuatu, use case, dan tips produk. Untuk keamanan, Use Case Explorer for Security menyusun panduan ke beberapa area [S4], misalnya:
- deteksi ancaman lanjutan;
- ancaman orang dalam dengan deteksi anomali;
- penemuan aset dan identitas berkelanjutan;
- respons insiden dengan otomasi dan orkestrasi;
- kepatuhan;
- security monitoring;
- threat hunting proaktif;
- investigasi ancaman.

Lantern juga memuat panduan teknis yang sudah kamu pakai: mengelola data model di ES (Day 25) dan optimasi search (Day 14).

Bedanya dengan research.splunk.com: Lantern menjelaskan cara (prosedur, konfigurasi, praktik terbaik), sedangkan research.splunk.com menyediakan konten (detection siap pakai). Lantern juga memuat contoh SPL per use case.

Beberapa artikel Lantern lama dipindahkan ke arsip, misalnya salinan lama "Use Case Explorer for Security" di jalur `KC_Sandbox/Archive` [S4]. Pakai versi aktif di `lantern.splunk.com/Security/UCE`; bila sebuah artikel berada di jalur arsip, anggap isinya mungkin sudah tidak diperbarui.

### 1.4 Content di dalam ES

Di ES 8.x:
- Detection dikelola sebagai event-based detection (mengevaluasi raw event untuk membuat finding atau intermediate finding) dan finding-based detection (mengevaluasi finding di risk index untuk membuat finding group) [S5][S6].
- Detection bisa dibuat, diedit, dikloning, diaktifkan/dinonaktifkan, dan diversikan [S5].
- Konten ESCU bisa diperkaya dengan annotations: Analytic Story, Confidence, Context, Impact. Ada *managed annotations* (bawaan ES/ESCU) dan *unmanaged* (kustom) yang ditambahkan dari halaman Content management [S3].

Cek jalur menu persis di ES 8.7 lab-mu: halaman dokumentasi detections tidak mencantumkan jalur menu secara eksplisit [S5]. Annotation dibahas lebih dalam di Day 33 bagian 1.10.

Banyak halaman detection, artikel Lantern, dan tulisan lama masih memakai istilah ES 7 (correlation search, notable event, Incident Review), dan pemetaannya ke istilah ES 8 ada di Day 31 bagian 1.2.

**Tanpa ES:** sebagian besar sumber di Day ini bisa dipakai tanpa Enterprise Security. research.splunk.com dan Lantern cukup dibaca, tanpa ES dan tanpa lisensi khusus. Repo security_content di GitHub juga tidak butuh ES, walaupun ketentuan lisensi repo-nya perlu dicek. SSE jalan di Splunk Enterprise maupun Splunk Cloud tanpa ES dan gratis. App ESCU gratis di Splunkbase dan dirancang untuk ES; macro dan lookup-nya bisa dipakai di Splunk Enterprise dengan penyesuaian seperti di bagian 2.5, tetapi sejauh mana hal itu berjalan perlu dicek di lab-mu. Yang benar-benar butuh ES beserta lisensinya adalah content management, detection editor, dan analyst queue.

## 2. Contoh SPL dan langkah di ES

> Keluaran berlabel ilustrasi. Sebagian query memakai endpoint REST. Cek nama endpoint dan atribut di versi lab-mu, dan jalankan hanya dengan hak yang sesuai.

### 2.1 Menilai sebuah detection sebelum mengaktifkannya (alur kerja)

Ambil contoh detection "Attacker Tools On Endpoint" dari Day 25 bagian 2.5:

1. **Baca "How to implement":** butuh log EDR/Sysmon/4688 yang dipetakan ke `Endpoint.Processes`.
2. Cek data source di lingkunganmu (lihat bagian 2.2).
3. Cek data model terakselerasi dan cakupan summary (Day 25 bagian 2.4).
4. Cek lookup dan macro yang dibutuhkan (mis. `attacker_tools`, `security_content_summariesonly`).
5. Jalankan search secara manual di rentang 7 hari. Hitung hasil dan perkirakan FP.
6. Tuning lewat filter macro (`attacker_tools_on_endpoint_filter`), bukan mengubah logika inti, agar pembaruan ESCU tidak menimpa perubahanmu, cek perilaku pembaruan filter macro.
7. Aktifkan, lalu pantau volume finding/notable seminggu pertama.

### 2.2 Apakah data saya memenuhi syarat detection?

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

### 2.3 Melihat detection ESCU yang terpasang dan statusnya

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

### 2.4 Membaca definisi macro security_content

```
| rest /servicesNS/-/-/configs/conf-macros splunk_server=local count=0
| search title="security_content_*" OR title="*_filter"
| table title definition eai:acl.app
```

- Menunjukkan isi macro (mis. `security_content_summariesonly` berkembang menjadi `summariesonly=... allow_old_summaries=... fillnull_value=...`, sesuai Day 25 [S7]).
- Berguna saat menjalankan SPL ESCU di luar ES. Kamu bisa mengganti macro dengan nilai eksplisit.
- Cek endpoint `configs/conf-macros` dan hak akses yang dibutuhkan.

### 2.5 Memakai SPL dari research.splunk.com di lab tanpa ES

1. Salin SPL dari halaman detection.
2. Ganti macro:
   - `` `security_content_summariesonly` `` diganti `summariesonly=false allow_old_summaries=true`. Untuk lab kecil, `false` memastikan hasil lengkap (Day 25).
   - `` `drop_dm_object_name(Processes)` `` diganti `rename Processes.* AS *`.
   - `` `security_content_ctime(firstTime)` `` diganti `convert ctime(firstTime)`.
   - `` `<detection>_filter` `` dihapus, atau diganti dengan `search *`.
3. Jalankan di data lab (BOTS atau Sysmon + Atomic Red Team).
4. Catat hasil dan bandingkan dengan "Known false positives".

### 2.6 Menggunakan Lantern dalam investigasi

Contoh alur: kamu perlu memperbaiki akselerasi data model yang lambat. Cari di Lantern dan baca panduan tentang mengelola data model di ES (dipakai di Day 25 bagian 2.4) serta "Optimizing search" (Day 14), terapkan constraint index, lalu verifikasi dengan `tstats` dan Data Model Audit.

## 3. Lab praktik

1. Buka research.splunk.com. Filter per data source Sysmon atau Windows Security, lalu pilih 3 detection yang relevan untuk lab-mu.
2. Untuk masing-masing, isi tabel: nama | data source | data model | macro/lookup | known FP | teknik ATT&CK.
3. Jalankan bagian 2.2 untuk data model yang diminta. Tandai detection mana yang bisa jalan di lab.
4. Jalankan satu detection dengan langkah bagian 2.5. Bila perlu, picu dengan Atomic Red Team untuk teknik terkait di VM Windows lab (snapshot dulu).
5. Pasang SSE di Splunk lab (app gratis). Temukan konten yang cocok dengan data yang kamu punya. Bandingkan hasilnya dengan langkah 3.
6. Cari di Lantern satu artikel tentang Risk-Based Alerting dan satu tentang Asset & Identity. Simpan tautannya untuk Day 26 dan Day 35.

**Hasil yang sebaiknya tersimpan:**
- Tabel 3 detection lengkap.
- Minimal 1 detection dijalankan dan hasilnya ditafsirkan.
- SSE terpasang dan dipakai untuk menemukan konten.

**Variasi tantangan:** pilih satu analytic story (mis. persistence Windows). Hitung berapa detection-nya yang bisa jalan di lab, berapa yang butuh data yang tidak kamu punya, dan apa sumber data yang paling "murah" untuk menutup celah terbesar.

## 4. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| SPL ESCU error "macro not found" | ESCU tidak terpasang; macro tidak dibagikan ke app tempat search dijalankan | Pasang ESCU atau ganti macro (bagian 2.5); cek permission macro |
| Detection aktif tapi tidak pernah fire | Data model kosong/tidak terakselerasi; field tidak ter-normalisasi | bagian 2.2; Day 25 bagian 2.4 |
| SSE tidak bisa memperbarui konten | SSE <=3.7.1 dengan endpoint ESCU lama | Upgrade ke SSE >=3.8.0 [S2] |
| Detection lama hilang/berubah setelah update | Ditandai deprecated | Deprecation Assistant [S3] |
| Tuning hilang setelah update ESCU | Mengubah search inti, bukan filter macro | Tuning di filter macro, perlu dicek |

## 5. Kesalahan umum dan jebakan

- Mengaktifkan detection massal tanpa memeriksa prasyarat data, sehingga ratusan detection "hijau" tetapi tidak pernah bisa fire. Ini rasa aman palsu.
- Mengaktifkan tanpa membaca known false positives. Akibatnya banjir finding/notable.
- Mengedit logika inti detection vendor. Perubahan hilang saat update. Gunakan filter macro atau kloning.
- Mengabaikan perbedaan istilah ES 7/8 saat membaca dokumentasi atau menjawab soal (pemetaannya di Day 31 bagian 1.2).
- Menganggap Lantern = konten detection. Lantern adalah panduan cara; kontennya di ESCU/research.
- `[komunitas]` Belum ada klaim komunitas yang dipakai di Day ini.

## 6. Catatan terkini

- ES 8.x memperkenalkan perubahan istilah besar, yang menurut ringkasan praktisi diselaraskan dengan Open Cybersecurity Schema Framework (OCSF) [S8], cek klaim OCSF di dokumentasi resmi.
- ES 8.6.1 (Agu 2026) dan 8.7.0 (Sep 2026) menambahkan agen AI, misalnya untuk membantu membuat detection, menulis playbook, dan "AI SOC Analyst". Nama dan cakupan fitur ini masih sering berubah, jadi cek di release notes resmi versi-mu.
- ESCU v6.7.0 adalah rilis terbaru menurut research.splunk.com [S1]. Dokumentasi ESCU sudah sampai seri 6.x.
- SSE 3.8.0 memaksa upgrade untuk menerima ESCU baru (batas ESCU 4.22.0 bagi SSE 3.7.1 ke bawah) [S2].
- Repo contentctl (alat build untuk security_content, yang mengubah file YAML detection menjadi paket app ESCU) tidak lagi menerima PR baru, karena Splunk mengalihkan investasi ke Detection Studio di ES. Yang paling terdampak adalah tim yang membangun konten kustom dengan contentctl; apakah ritme rilis ESCU ikut berubah perlu dicek di README repo contentctl dan release notes ESCU.

## 7. Cheat sheet

```
research.splunk.com = katalog konten STRT (detections, analytic stories, playbooks; filter data source/ATT&CK/produk)
ESCU app            = konten yang sama untuk ES (Splunkbase)   | sumber: github splunk/security_content
SSE                 = app gratis: cocokkan data <-> konten, cakupan ATT&CK (3.8.x; >=3.8.0 utk ESCU baru)
Lantern             = panduan "cara" (Use Case Explorer for Security, tips produk)
ES content mgmt     = kelola detection (event-based / finding-based), annotations, versi

SEBELUM AKTIFKAN: how to implement -> data model terisi? (tstats ... by sourcetype) -> macro/lookup ada?
                  -> jalankan manual 7 hari -> baca known FP -> tuning via *_filter macro -> pantau
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** Setelah ESCU dipasang di ES PT JAB, rekanmu mengaktifkan ratusan detection sekaligus lalu melapor ke SOC lead bahwa cakupan workstation sekarang lengkap, karena semuanya berstatus aktif. Apa yang keliru, dan apa yang kamu periksa lebih dulu?

<details><summary>Jawaban</summary>

Status aktif tidak berarti detection bisa menyala. Setiap detection menyebut sumber data, data model, macro, dan lookup yang dibutuhkannya, dan bila data model yang diminta kosong atau tidak terakselerasi, detection itu tidak akan pernah fire walaupun tampak hijau di daftar, sehingga laporan rekanmu adalah rasa aman palsu. Yang diperiksa lebih dulu adalah isi data model per detection, misalnya `tstats count from datamodel=Endpoint.Processes by sourcetype, Processes.vendor_product` untuk detection berbasis Endpoint, lalu hal yang sama untuk Authentication, Network_Traffic, atau Web sesuai kebutuhan detection-nya. Di PT JAB ada lapisan kedua: Sysmon baru masuk dari sekitar 40 persen workstation, jadi detection yang bergantung pada Sysmon hanya melihat sebagian workstation walaupun data modelnya terisi. Lihat bagian 2.1, 2.2, dan 5.

</details>

**2. Skenario keputusan.** Detection "Attacker Tools On Endpoint" menyala setiap hari karena tool administrasi sah yang dipakai tim infra PT JAB dari `JKT-JUMP01`. Apa yang kamu lakukan?

- A. Edit search inti detection dan tambahkan pengecualian langsung di SPL-nya.
- B. Tambahkan pengecualian di macro `attacker_tools_on_endpoint_filter`.
- C. Nonaktifkan detection sampai ESCU merilis versi yang lebih sedikit noise-nya.

<details><summary>Jawaban</summary>

B. Filter macro (`*_filter`) memang disediakan sebagai titik tuning tanpa mengubah logika inti, sehingga pembaruan ESCU tidak menimpa pekerjaanmu; perilaku pembaruan filter macro tetap perlu dicek di versi-mu. A bekerja hari ini, tetapi perubahan di logika inti detection vendor hilang saat konten diperbarui; bila memang perlu mengubah logika, kloning detection-nya. C membuang cakupan untuk semua host lain demi satu sumber noise, padahal known false positives memang bagian yang harus dibaca dan ditangani sebelum dan sesudah detection diaktifkan. Lihat bagian 1.1, 2.1, 4, dan 5.

</details>

**3. Pertanyaan jebakan.** SSE di Splunk lab-mu masih versi 3.7.1 dan kontennya berhenti diperbarui di ESCU 4.22.0. Rekanmu menyimpulkan ESCU sudah tidak dirilis lagi. Kenapa kesimpulan itu salah, dan apa perbaikannya?

<details><summary>Jawaban</summary>

ESCU masih dirilis; research.splunk.com menyebut v6.7.0 sebagai rilis terbaru. Penyebabnya ada di SSE: versi 3.8.0 memperkenalkan endpoint API ESCU baru, dan SSE 3.7.1 ke bawah tidak bisa memperbarui konten melewati ESCU 4.22.0. Perbaikannya upgrade SSE ke 3.8.0 atau lebih baru; 3.8.3 adalah versi default dan kompatibel dengan Splunk 9.0 sampai 10.6. Lihat bagian 1.2, 4, dan 6.

</details>

**4. Jelaskan ulang.** Jelaskan ke analyst L1 baru, dalam tiga kalimat, beda research.splunk.com (beserta ESCU), SSE, Lantern, dan content management di ES, serta kapan membuka masing-masing.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh jawaban: "research.splunk.com adalah katalog detection dan analytic story dari Splunk Threat Research Team, dan ESCU adalah paket app berisi konten yang sama untuk dipasang di ES, jadi buka itu saat mencari detection siap pakai beserta data source, how to implement, dan known false positives-nya. SSE adalah app gratis yang mencocokkan data yang sudah kita punya dengan konten yang bisa jalan, sedangkan Lantern berisi panduan cara melakukan sesuatu, seperti prosedur, konfigurasi, dan praktik terbaik, bukan detection. Content management di ES adalah tempat detection benar-benar dikelola, diaktifkan, diversikan, dan diberi annotation, dan hanya bagian ini yang butuh ES beserta lisensinya."

Kesalahan yang sering muncul: menganggap Lantern sebagai sumber detection, padahal kontennya ada di ESCU dan research.splunk.com; mengira semua sumber butuh ES, padahal research.splunk.com, Lantern, dan SSE bisa dipakai tanpa ES; dan memperlakukan ESCU sebagai konten yang berbeda dari research.splunk.com, padahal keduanya berasal dari repo security_content yang sama. Lihat bagian 1.1, 1.2, 1.3, dan 1.4.

</details>

**5. Interview question (English).** "A new log source has just been onboarded. How do you decide which out-of-the-box detections to turn on?"

<details><summary>Sample answer</summary>

"I start from the data, not from the catalog. I filter the vendor content, in Splunk's case research.splunk.com or Security Essentials, by the data source we just onboarded, and shortlist the detections that match our threats. For each one I read the implementation notes to see which add-on, CIM data model, macros and lookups it needs, and then I prove those prerequisites in our environment: I run a tstats count against the data model split by sourcetype to confirm our new source actually lands there, and I check that acceleration covers the time range the search uses. Then I run the search manually over about a week, count the results, and compare them with the known false positives listed on the detection page. Any tuning goes into the detection's filter macro rather than the core logic, so a content update does not wipe out my work, and if I need a different logic I clone it. After enabling, I watch the finding volume for the first week, and I periodically check for deprecated content that is still enabled. What I report back to my lead is which detections can actually fire on our data and where the gaps are, not how many detections are switched on, because an enabled detection with an empty data model looks green and never alerts."

What makes this answer strong: it treats data prerequisites as something to prove rather than assume, names a concrete check, keeps tuning out of the vendor's core logic so updates are safe, and reports coverage in terms of detections that can fire instead of a count of enabled rules.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Splunk Security Content: research.splunk.com | https://research.splunk.com/ | primer | diakses 2026-10-07 | Tinggi. Jumlah konten dan v6.7.0 saat diakses |
| S2 | What's new in Splunk Security Essentials (3.8) | https://help.splunk.com/en/splunk-enterprise-security-8/security-essentials/release-notes-and-resources/3.8/splunk-security-essentials-release-notes/whats-new-in-splunk-security-essentials | primer | halaman diperbarui 2025-07-22; diakses 2026-10-07 | Tinggi. Tanggal rilis 3.8.3 (21 Jan 2026) perlu dicocokkan dengan Splunkbase |
| S3 | ES 8: Add ESCU annotations; Deprecated analytics in ESCU | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.6/managing-security-content/add-escu-annotations-to-detections-and-analytics-stories-in-splunk-enterprise-security | primer | tanggal tidak tercatat | Sedang-tinggi |
| S4 | Splunk Lantern: Use Case Explorer for Security | https://lantern.splunk.com/Security/UCE | primer | diakses 2026-10-07 | Tinggi |
| S5 | ES 8.7: Use detections to search for threats | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.7/detections | primer | diakses 2026-10-07 | Tinggi untuk tipe detection; jalur menu tidak tercantum |
| S6 | ES 8.7: Glossary | https://help.splunk.com/en/splunk-enterprise-security-8/release-notes-and-resources/8.7/where-to-find-help/glossary | primer | diakses 2026-10-07 | Tinggi. Pemetaan istilah |
| S7 | GitHub splunk/security_content (macro dan detection, lihat Day 25) | https://github.com/splunk/security_content | primer | diakses 2026-10-07 (Day 25) | Tinggi |
| S8 | Somerford Associates: What's new for Splunk Enterprise Security v8 | https://somerfordassociates.com/blog/whats-new-for-splunk-enterprise-security-v8 | sekunder (partner) | tanggal tidak tercatat | Sedang. Klaim OCSF dan risk incident rule perlu dicek |

**Catatan sumber:** fitur SSE untuk Security Content dan Data Inventory dibahas dan bersumber di Day 27. Jalur menu content management di ES 8.7 dan atribut REST detection ES 8 belum terkonfirmasi dokumentasi; cek di instance ES-mu. Klaim OCSF [S8] dan fitur agen AI di ES 8.6.1/8.7.0 perlu dicocokkan dengan release notes resmi. Status contentctl perlu dicek di README repo-nya.
