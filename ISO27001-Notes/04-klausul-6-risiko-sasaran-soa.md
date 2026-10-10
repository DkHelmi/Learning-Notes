---
day: 04
title: 'Klausul 6: risk assessment, risk treatment, Statement of Applicability, sasaran, dan perencanaan perubahan'
researched_on: 2026-10-10
versions_checked: 'ISO/IEC 27001:2022 + Amd 1:2024; ISO/IEC 27002:2022; ISO/IEC 27005:2022 (edisi 4, terbit 25 Okt 2022; opsi revisi sedang dibahas working group per Agustus 2026)'
---

# Day 04: Klausul 6, risiko, sasaran, dan Statement of Applicability

> Catatan pribadi, bukan materi resmi ISO, dan bukan nasihat hukum atau audit. Catatan ini hanya menyebut nomor dan judul singkat klausul dan kontrol, lalu menjelaskannya dengan kata-kata sendiri.

Cakupan: klausul 6.1.1-6.1.3, 6.2, dan 6.3 ISO/IEC 27001:2022, dengan konsep pendukung dari ISO/IEC 27005:2022. Praktik risk register yang lebih dalam (risk appetite, skenario, pelaporan) ada di Day 09; struktur Annex A di Day 08.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- membedakan risiko dan peluang ISMS di 6.1.1 dari risiko keamanan informasi di 6.1.2.
- merancang kriteria risiko (skala, cara menghitung level, kriteria penerimaan) yang menghasilkan penilaian konsisten dan bisa dibandingkan.
- memilih opsi treatment (modify, retain, avoid, share) dan menjelaskan peran risk owner dalam menyetujui risiko sisa.
- menyusun Statement of Applicability yang bisa ditelusuri ke risk register, termasuk alasan pengecualian yang bisa dipertahankan.
- menulis sasaran keamanan yang terukur untuk SOC dan menjelaskan kapan perubahan butuh perencanaan menurut 6.3.

## 2. Konteks singkat

Klausul 6 menjawab pertanyaan yang paling sering diajukan pimpinan: "kenapa kita butuh kontrol ini?" Jawaban yang diterima auditor bukan "karena best practice" atau "karena vendor menyarankan", tetapi "karena risiko R-xx bernilai sekian, melebihi kriteria penerimaan kita, dan kontrol ini menurunkannya ke level yang disetujui risk owner".

Bagi analyst SOC, rule deteksi baru, perluasan sumber log, atau target MTTR sering lahir dari risk treatment plan dan sasaran 6.2. Bila bisa membaca risk register, kamu bisa berargumen dengan bahasa manajemen, misalnya: "cakupan log server in-scope baru 85%, padahal risiko R-09 mengandalkan kontrol 8.15 dan 8.16".

Kapan dipakai: saat ISMS dibangun, saat risk assessment berkala (8.2), saat ada perubahan besar, dan saat menyiapkan audit.
Kapan tidak cukup: klausul 6 menetapkan proses. Menjalankannya dan menyimpan hasilnya adalah klausul 8.2 dan 8.3 (Day 02 bagian 3.4).

## 3. Konsep inti

### 3.1 Dua jenis risiko di klausul 6

- **6.1.1 risiko dan peluang ISMS:** hal yang bisa membuat ISMS gagal mencapai hasilnya atau justru membantunya. Sumbernya isu di 4.1 dan persyaratan di 4.2. Contoh risiko: pimpinan berganti dan dukungan anggaran hilang. Contoh peluang: SOAR bisa mengotomasi pengumpulan bukti insiden.
- **6.1.2 risiko keamanan informasi:** kemungkinan hilangnya confidentiality, integrity, atau availability informasi di dalam scope. Risiko jenis ini yang masuk risk register dan menentukan kontrol.

Keduanya harus ditangani, tetapi hanya 6.1.2 yang wajib memakai proses risk assessment formal. Risiko dan peluang 6.1.1 cukup direncanakan tindakannya dan dipantau efektivitasnya.

### 3.2 Klausul 6.1.2: proses risk assessment

Organisasi menetapkan dan menerapkan proses risk assessment yang [S1]:

1. menetapkan dan memelihara kriteria risiko, yaitu kriteria penerimaan risiko dan kriteria untuk melakukan penilaian;
2. memastikan penilaian berulang menghasilkan hasil yang konsisten, valid, dan bisa dibandingkan;
3. mengidentifikasi risiko terhadap confidentiality, integrity, dan availability informasi di dalam scope, serta menunjuk risk owner;
4. menganalisis risiko: menilai konsekuensi bila terjadi, menilai kemungkinan terjadinya secara realistis, lalu menentukan level risiko;
5. mengevaluasi risiko: membandingkan hasil analisis dengan kriteria, lalu memprioritaskan risiko untuk ditangani.

Informasi tentang proses ini wajib disimpan sebagai informasi terdokumentasi. Bentuk umumnya adalah dokumen metodologi risiko.

Butir 2 sering diremehkan. Bila tahun ini risiko dinilai dengan skala 1-3 dan tahun depan dengan skala 1-5, hasilnya tidak bisa dibandingkan, dan auditor akan mempertanyakan apakah risiko benar-benar turun atau hanya skalanya yang berubah. Auditor juga mencari skor yang tidak konsisten tanpa alasan tertulis dan risk register yang terputus dari treatment dan SoA [S1].

### 3.3 Cara mengidentifikasi risiko: berbasis aset atau berbasis kejadian

ISO 27001 tidak menentukan metode identifikasi. Edisi 2005 mengarahkan identifikasi lewat aset, ancaman, dan kerentanan; sejak 2013 tidak lagi. ISO/IEC 27005:2022 (panduan, bukan persyaratan) menjelaskan dua pendekatan [S3]:

| Pendekatan | Cara kerja | Cocok untuk |
|---|---|---|
| Berbasis kejadian (event-based) | Mulai dari sumber risiko dan skenario strategis: siapa yang bisa menyerang, apa tujuannya, dampaknya ke pihak berkepentingan | Penilaian tingkat tinggi, organisasi yang baru memulai, diskusi dengan pimpinan |
| Berbasis aset (asset-based) | Mulai dari daftar aset, lalu ancaman dan kerentanan masing-masing | Penilaian operasional yang rinci untuk sistem penting |

27005:2022 juga memperkenalkan konsep risk scenario, memakai istilah "consequence" (bukan "impact") agar selaras dengan ISO 31000:2018, dan menambahkan teknik semi-kuantitatif di samping kualitatif dan kuantitatif [S3]. Edisi keempat ini terbit 25 Oktober 2022 [S7].

Bagi analyst SOC, pendekatan berbasis kejadian terasa alami karena mirip threat modeling. Skenario seperti "operator ransomware masuk lewat panel manajemen yang terekspos" bisa dipetakan ke teknik ATT&CK dan langsung menunjukkan kontrol deteksi yang dibutuhkan.

### 3.4 Merancang kriteria risiko

Kriteria terdiri dari dua bagian: cara menilai (skala kemungkinan, skala konsekuensi, rumus level) dan kriteria penerimaan (level berapa yang boleh diterima tanpa treatment). Tidak ada satu bentuk yang benar. Yang penting, kriteria cocok dengan cara menghitung risiko dan konteks bisnis [S5].

Contoh yang umum adalah matriks 5x5 dengan level = kemungkinan x konsekuensi. Secara teknis ini pendekatan semi-kuantitatif: angkanya membantu mengurutkan, tetapi bukan nilai uang atau probabilitas nyata. Perhatikan bahwa hasil perkalian dua bilangan 1-5 hanya bisa bernilai 1, 2, 3, 4, 5, 6, 8, 9, 10, 12, 15, 16, 20, atau 25. Batas pita level harus dibuat dengan menyadari celah ini (7, 11, 13, 14 tidak mungkin muncul).

Kriteria penerimaan yang baik juga menyebut siapa yang boleh menerima risiko di tiap level. Contohnya: risiko rendah boleh diterima risk owner, sedangkan risiko tinggi yang tetap ingin diterima harus disetujui direksi.

### 3.5 Risk owner

Risk owner adalah orang yang punya akuntabilitas dan wewenang untuk mengelola sebuah risiko. Ia belum tentu pemilik aset atau orang teknis. Untuk risiko "log VM pelanggan tidak masuk SIEM", pemilik yang wajar adalah Lead SOC atau Head of Platform. Analyst L1 bukan pilihan yang wajar, karena ia tidak punya wewenang anggaran atau keputusan.

Risk owner punya dua tugas eksplisit di 6.1.3: menyetujui risk treatment plan dan menerima risiko sisa (residual risk) [S1]. Tanpa tanda tangan risk owner, risk treatment plan dianggap belum selesai.

### 3.6 Klausul 6.1.3: proses risk treatment

Urutan langkahnya kira-kira seperti ini:

1. pilih opsi treatment untuk setiap risiko yang perlu ditangani;
2. tentukan semua kontrol yang dibutuhkan untuk menjalankan opsi itu, dari sumber mana pun;
3. bandingkan kontrol itu dengan Annex A untuk memastikan tidak ada kontrol yang terlewat;
4. susun Statement of Applicability;
5. susun risk treatment plan;
6. minta persetujuan risk owner atas rencana dan penerimaan risiko sisa.

Informasi tentang proses ini juga wajib disimpan.

Opsi treatment yang dikenal di 27005 [S6]:

| Opsi | Artinya | Contoh SOC/hosting |
|---|---|---|
| Modify (modifikasi) | Menambah, mengubah, atau menghapus kontrol untuk menurunkan kemungkinan atau konsekuensi | Menambah rule deteksi dan memperluas logging |
| Retain (pertahankan/terima) | Menerima risiko tanpa kontrol tambahan karena sudah di dalam kriteria | Risiko rendah yang diterima risk owner |
| Avoid (hindari) | Menghentikan aktivitas atau kondisi penyebab risiko | Mencabut akses internet panel manajemen |
| Share (bagi) | Membagi konsekuensi dengan pihak lain | Asuransi siber; kontrak dengan penyedia colocation |

Komentar di situs ISO27k mengkritik 27005:2022 karena sangat berfokus pada modifikasi lewat kontrol, sementara opsi lain hampir tidak dibahas [S6]. Di praktik, "avoid" sering menjadi opsi termurah dan paling efektif.

Tentang Annex A: kontrol boleh dirancang sendiri atau diambil dari sumber lain (misalnya CIS Controls atau NIST). Annex A dipakai sebagai daftar pembanding agar tidak ada kontrol penting yang terlewat, dan daftarnya tidak lengkap secara mutlak. Edisi 2022 tidak lagi memakai istilah "control objectives" seperti edisi 2013. Cek bunyi catatan tentang Annex A di 6.1.3 pada teks standar atau SNI resmi.

### 3.7 Statement of Applicability

SoA adalah dokumen wajib yang memuat [S4]:

- kontrol yang dibutuhkan (hasil langkah 2 dan 3 di bagian 3.6);
- alasan setiap kontrol dimasukkan;
- apakah kontrol itu sudah diterapkan;
- alasan setiap kontrol Annex A yang dikecualikan.

Auditor membaca SoA bersama risk register. Kedua dokumen itu harus "bercerita sama": setiap kontrol yang dipilih bisa ditelusuri ke risiko, kontrak, atau regulasi, dan setiap pengecualian punya alasan yang bisa dipertahankan [S4]. Konsultan URM menambahkan bahwa atribut kontrol di 27002:2022 (misalnya jenis kontrol preventive, detective, corrective) jarang dimanfaatkan, padahal bisa memperkuat alasan pemilihan [S8].

Auditor NQA (Maret 2026) mencatat lima kesalahan yang sering muncul: semua kontrol ditandai berlaku secara defensif, risiko terlalu umum sehingga tidak tersambung ke kontrol, SoA disalin dari organisasi lain, alasan pengecualian lemah, dan SoA tidak diperbarui saat risiko berubah [S4].

### 3.8 Klausul 6.2: sasaran keamanan informasi

Sasaran harus konsisten dengan kebijakan, terukur bila praktis, mempertimbangkan persyaratan dan hasil risk assessment, dipantau, dikomunikasikan, dan diperbarui bila perlu. Edisi 2022 menambahkan dua hal secara eksplisit: sasaran harus dipantau, dan sasaran harus tersedia sebagai informasi terdokumentasi [S2]. Rencana pencapaiannya menyebut apa yang dikerjakan, sumber dayanya, penanggung jawab, tenggat, dan cara mengevaluasi hasil.

Akibatnya, auditor akan mencari jalur yang jelas dari sasaran ke metrik, cara pengukuran, dan laporan rutin [S2]. Sasaran seperti "meningkatkan keamanan" tidak bisa diaudit. Sasaran seperti "cakupan log server in-scope minimal 98% setiap bulan mulai Q2 2026" bisa diaudit.

### 3.9 Klausul 6.3: perencanaan perubahan

Bila organisasi memutuskan perlu mengubah ISMS, perubahan itu harus dijalankan secara terencana [S2]. Standar tidak menentukan formatnya. Rencana yang wajar menyebut tujuan perubahan, dampaknya ke ISMS, risiko selama transisi, sumber daya, penanggung jawab, dan kriteria selesai.

Bedakan dengan kontrol 8.32 Change management, yang mengatur perubahan pada sistem dan fasilitas pemrosesan informasi. Memindahkan sumber log dari Splunk ke Wazuh adalah perubahan teknis (8.32). Perubahan itu juga mengubah cara ISMS membuktikan kontrol logging dan monitoring, sehingga perlu direncanakan menurut 6.3.

## 4. Contoh dokumen / artefak (organisasi fiktif)

Organisasi fiktif: PT Awan Nusantara (PT AN). Semua angka di bawah adalah ilustrasi.

### 4.1 Kriteria risiko PT AN (cuplikan metodologi)

| Skor | Kemungkinan (dalam 12 bulan) | Konsekuensi |
|---|---|---|
| 1 | Hampir tidak mungkin | Tidak ada dampak ke pelanggan |
| 2 | Jarang | Gangguan internal kurang dari 4 jam |
| 3 | Mungkin | Gangguan layanan atau kebocoran data terbatas pada 1 pelanggan |
| 4 | Sering | Gangguan atau kebocoran pada beberapa pelanggan; wajib lapor ke klien |
| 5 | Hampir pasti | Gangguan luas lebih dari 24 jam atau kebocoran data massal; dampak regulasi |

```
Level = Kemungkinan x Konsekuensi
Rendah  : 1-6    boleh diterima risk owner; ditinjau tahunan
Sedang  : 8-12   treatment atau penerimaan oleh risk owner dengan alasan tertulis; ditinjau per kuartal
Tinggi  : 15-25  wajib treatment; penerimaan tanpa treatment hanya dengan persetujuan direksi
(nilai 7, 11, 13, 14 tidak mungkin muncul pada perkalian dua skala 1-5)
```

### 4.2 Cuplikan risk register

| ID | Skenario risiko | Risk owner | K | C | Level awal | Opsi | Kontrol (Annex A) | K sisa | C sisa | Level sisa |
|---|---|---|---|---|---|---|---|---|---|---|
| R-04 | Akun default pada image VM dipakai penyerang untuk masuk ke VM pelanggan | Head of Platform | 4 | 4 | 16 Tinggi | Modify | 8.9 configuration management; 8.16 monitoring | 2 | 4 | 8 Sedang |
| R-09 | Log VM pelanggan tidak masuk SIEM selama migrasi, sehingga serangan tidak terdeteksi | Lead SOC | 3 | 3 | 9 Sedang | Modify | 8.15 logging; 8.16 monitoring; rencana perubahan CH-02 | 1 | 3 | 3 Rendah |
| R-11 | Ransomware masuk lewat panel manajemen hypervisor yang terekspos ke internet | Head of Platform | 3 | 5 | 15 Tinggi | Avoid | Panel dipindah ke belakang VPN; 8.20 networks security | 1 | 5 | 5 Rendah |
| R-15 | Banjir membuat DC Jakarta-1 tidak tersedia lebih dari 24 jam | Direktur Ops | 2 | 5 | 10 Sedang | Share + Modify | Asuransi; kontrak colocation; 7.5; 5.30 ICT readiness | 2 | 4 | 8 Sedang |
| R-20 | Alert prioritas rendah salah ditriage pada shift malam | Lead SOC | 3 | 2 | 6 Rendah | Retain | Kontrol yang ada cukup; QA sampling bulanan | 3 | 2 | 6 Rendah |

Cara membaca:

- **Level dihitung, bukan ditebak:** 4x4 = 16, 3x3 = 9, 3x5 = 15, 2x5 = 10, 3x2 = 6. Level sisa: 2x4 = 8, 1x3 = 3, 1x5 = 5, 2x4 = 8, 3x2 = 6.
- **R-11 memakai avoid:** memindahkan panel ke belakang VPN menghilangkan paparan ke internet. Konsekuensinya tetap 5 bila terjadi, tetapi kemungkinannya turun ke 1.
- **R-15 tetap Sedang setelah treatment:** asuransi membagi beban finansial, tetapi tidak membuat layanan tetap tersedia. Direktur Ops menerima level 8 dengan alasan tertulis, sesuai kriteria pita Sedang.
- **R-20 diterima apa adanya:** levelnya sudah di pita Rendah. Retain tetap keputusan yang harus dicatat, bukan risiko yang dilupakan.
- **R-09 tersambung ke perubahan CH-02 (6.3):** risiko itu muncul justru karena perubahan yang direncanakan.

Nama kontrol (8.9 Configuration management, 8.20 Networks security, 7.5 Protecting against physical and environmental threats, 5.30 ICT readiness for business continuity) mengikuti penomoran 27002:2022. Detailnya dibahas di Day 08.

### 4.3 Cuplikan Statement of Applicability

| Kontrol | Berlaku? | Alasan | Status | Rujukan |
|---|---|---|---|---|
| 5.7 Threat intelligence | Ya | Prioritas deteksi untuk skenario ransomware | Sebagian (feed ada, belum ada proses review) | R-11 |
| 5.24 Incident management planning and preparation | Ya | Kewajiban lapor insiden ke klien perbankan | Diterapkan | K-03, R-04 |
| 8.15 Logging | Ya | Deteksi dan bukti insiden pada VM pelanggan | Diterapkan | R-04, R-09 |
| 8.16 Monitoring activities | Ya | Deteksi akses tidak sah | Diterapkan | R-04, R-09 |
| 8.17 Clock synchronization | Ya | Korelasi log lintas sumber dan nilai bukti timeline | Diterapkan | R-09 |
| 7.5 Protecting against physical and environmental threats | Ya | Risiko banjir di DC Jakarta-1 | Sebagian | R-15 |
| 8.30 Outsourced development | Tidak | PT AN tidak mengalihdayakan pengembangan perangkat lunak; ditinjau ulang bila ada kontrak pengembangan | Tidak berlaku | Scope v1.0 |

**Kenapa ada kolom rujukan:** setiap baris "Ya" harus menunjuk ke risiko, persyaratan, atau keputusan konteks. Baris yang tidak punya rujukan adalah tanda kontrol dipilih secara defensif [S4].

**Kenapa alasan 8.30 bisa dipertahankan:** alasannya berupa fakta yang bisa diverifikasi (tidak ada kontrak pengembangan) dan menyebut kondisi untuk ditinjau ulang. Alasan "mahal" atau "tidak relevan" tanpa penjelasan akan dipertanyakan.

### 4.4 Sasaran keamanan SOC (6.2)

| Sasaran | Metrik | Target | Pemilik | Frekuensi ukur | Sumber data |
|---|---|---|---|---|---|
| S-01 Cakupan log server in-scope | Server in-scope yang mengirim log dalam 24 jam terakhir dibagi total server in-scope | >= 98% per bulan mulai Q2 2026 | Lead SOC | Bulanan | SIEM dan daftar aset |
| S-02 Kecepatan respons insiden prioritas tinggi | Median waktu dari alert sampai containment | <= 4 jam | Lead SOC | Bulanan | Tiket insiden |
| S-03 Sinkronisasi waktu | Host in-scope dengan selisih waktu lebih dari 1 detik dari NTP internal | 0 host selama 3 bulan berturut-turut | Head of Platform | Mingguan | Laporan NTP |

Setiap sasaran punya rumus, target, dan sumber data, sehingga bisa dipantau (6.2) dan dilaporkan sebagai hasil monitoring (9.1).

## 5. Lab praktik

Latihan untuk organisasi fiktifmu. Simpan di `ISO27001-note/latihan/day04-<nama-org-fiktif>.md`.

1. Tulis kriteria risiko: skala kemungkinan dan konsekuensi 1-5 dengan deskripsi yang cocok untuk organisasimu, rumus level, dan tiga pita penerimaan beserta siapa yang boleh menerima di tiap pita.
2. Identifikasi 6 risiko. Pakai minimal dua skenario berbasis kejadian (mulai dari pelaku dan tujuannya) dan dua berbasis aset (mulai dari sistem tertentu). Setiap risiko punya risk owner dengan jabatan yang masuk akal.
3. Hitung level awal dan level sisa. Hitung ulang setiap perkalian sekali lagi sebelum lanjut.
4. Pilih opsi treatment. Minimal satu risiko memakai avoid, satu share, dan satu retain.
5. Susun SoA berisi minimal 10 kontrol, termasuk 2 pengecualian beserta alasan yang bisa diverifikasi. Setiap baris "Ya" wajib punya rujukan ke risiko atau persyaratan.
6. Tulis 3 sasaran keamanan untuk SOC dengan format bagian 4.4.
7. Tulis satu rencana perubahan menurut 6.3, misalnya migrasi sebagian log ke Wazuh. Isinya tujuan, dampak ke ISMS, risiko selama transisi (sambungkan ke register), penanggung jawab, jadwal, dan kriteria selesai.
8. Hubungkan ke lab (opsional, dijalankan sendiri di Splunk lab): ukur sasaran S-01 dengan search di bawah. Siapkan dulu lookup `inscope_assets.csv` berisi kolom `host` dengan nama host lab yang kamu anggap in-scope.

```
| tstats latest(_time) as last_seen where index=* by host
| append [| inputlookup inscope_assets.csv | eval in_scope=1]
| stats max(last_seen) as last_seen max(in_scope) as in_scope by host
| where in_scope=1
| eval status=if(isnull(last_seen) OR last_seen < relative_time(now(), "-24h"), "tidak terlihat 24 jam", "ok")
| stats count by status
```

**Tujuan:** menghitung berapa host in-scope yang mengirim data ke Splunk dalam 24 jam terakhir.

**Penjelasan:**
- `tstats ... by host` mengambil waktu event terakhir per host dari index yang bisa dibaca role-mu. `index=*` tidak mencakup index internal yang diawali garis bawah.
- `append` dan `inputlookup` menambahkan daftar host in-scope, lalu `stats max(...) by host` menggabungkan keduanya per host tanpa `join`.
- `where in_scope=1` membuang host yang mengirim log tetapi tidak ada di daftar in-scope.
- `eval status` menandai host yang tidak pernah terlihat (`last_seen` kosong) atau terakhir terlihat lebih dari 24 jam lalu.

**Keluaran ilustrasi** (bukan hasil eksekusi nyata):

```
status                  count
ok                         49
tidak terlihat 24 jam       1
```

**Cara membaca:** cakupan = 49 / (49 + 1) = 98%, tepat di target S-01. Host yang tidak terlihat langsung menjadi bahan tindak lanjut, dan bila berulang menjadi nonconformity terhadap sasaran (10.2).

**Variasi:** ganti `-24h` dengan `-7d` untuk melihat host yang mati lebih lama, atau hilangkan `| stats count by status` untuk melihat daftar host per status.

**Kapan gagal:** nama host di lookup berbeda format dengan field `host` di Splunk (huruf besar/kecil, FQDN vs nama pendek), sehingga host tampak "tidak terlihat" padahal mengirim log. Normalisasi keduanya dengan `lower()` dan aturan FQDN yang sama. Host yang datanya masuk ke index yang tidak bisa dibaca role-mu juga akan tampak hilang. Di Wazuh, padanan kasarnya adalah status agent disconnected di dashboard. Cek nama menu status agent di versi Wazuh lab-mu.

**Hasil yang seharusnya teramati:** register risiko, SoA, dan sasaran yang saling merujuk. Setiap kontrol di SoA bisa ditelusuri ke risiko, dan setiap sasaran punya sumber data.

**Hasil yang sebaiknya tersimpan:**
- Semua perkalian level awal dan level sisa dihitung ulang dan benar.
- Setiap risiko punya risk owner yang punya wewenang, bukan staf pelaksana.
- Opsi avoid, share, dan retain masing-masing dipakai minimal sekali.
- Setiap baris SoA "Ya" punya rujukan; setiap pengecualian punya alasan yang bisa diverifikasi.
- Ketiga sasaran punya rumus, target, pemilik, dan sumber data.
- Rencana perubahan menyebut risiko selama transisi dan tersambung ke register.

**Variasi tantangan:** hitung ulang register memakai skala 1-3. Bandingkan urutan prioritasnya dengan skala 1-5, lalu tulis satu paragraf kenapa mengganti skala di tengah siklus melanggar semangat "konsisten, valid, dan bisa dibandingkan".

## 6. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Hampir semua risiko jatuh di pita Tinggi | Deskripsi skala konsekuensi terlalu sensitif | Kalibrasi skala dengan dua atau tiga kejadian nyata (fiktif) yang disepakati bersama |
| SoA dan register tidak cocok | Disusun oleh orang atau waktu berbeda | Tambahkan kolom rujukan di SoA; tinjau keduanya dalam satu sesi |
| Risk owner menolak menandatangani penerimaan risiko | Pita penerimaan tidak menyebut kewenangan | Tetapkan di kriteria siapa yang boleh menerima di tiap pita |
| Sasaran tidak bisa diukur | Tidak ada sumber data atau rumus | Tulis rumus dan sumber data dulu; bila tidak ada, sasaran pertamanya adalah membangun pengukurannya |

## 7. Kesalahan umum dan jebakan

- Memperlakukan Annex A sebagai daftar wajib, lalu menulis "berlaku" untuk semua 93 kontrol. Yang diminta adalah keputusan berbasis risiko [S4].
- Risk register yang terputus dari risk treatment plan dan SoA. Ini ketidaksesuaian yang sering ditemukan [S1].
- Tidak punya kriteria tertulis untuk menjalankan risk assessment, sehingga hasil tiap siklus tidak konsisten. URM melaporkan temuan ini di audit 2026 [S8].
- Menganggap retain berarti "tidak ada tindakan". Retain adalah keputusan yang dicatat, disetujui, dan ditinjau ulang.
- `[komunitas, belum terkonfirmasi]` Di forum tanya-jawab Advisera, contoh kriteria penerimaan berupa ambang angka (misalnya level di atas 7 wajib treatment) disebut sebagai salah satu pendekatan yang sah [S5]. Pilihan ambang tetap keputusan organisasi.

## 8. Catatan terkini

- ISO/IEC 27005:2022 (edisi 4) masih edisi berlaku. Situs ISO27k (diperbarui Agustus 2026) melaporkan working group sedang membahas pendekatan revisi, termasuk kemungkinan menjadi standar multi-bagian [S6]. Cek status proyek revisi di katalog ISO.
- 27005:2022 menyelaraskan istilah dengan ISO 31000:2018 ("consequence", risk scenario) dan menyederhanakan enam annex menjadi satu annex teknik penilaian [S3].
- Klausul 6.2 dan 6.3 adalah bagian yang paling berubah di klausul 6 edisi 2022. Auditor kini mengharapkan jalur yang jelas dari sasaran ke metrik dan laporan [S2].
- Auditor NQA (Maret 2026) dan URM (April 2026) sama-sama menyoroti keterkaitan register dan SoA serta kriteria risiko yang konsisten sebagai area temuan utama [S4][S8].

## 9. Cheat sheet

```
6.1.1  risiko & peluang ISMS (dari 4.1/4.2)  -- rencanakan tindakan, pantau efektivitas
6.1.2  proses RA: kriteria (penerimaan + cara menilai) | konsisten, valid, bisa dibandingkan
       | identifikasi risiko CIA + risk owner | analisis (konsekuensi, kemungkinan, level) | evaluasi & prioritas
6.1.3  proses RT: opsi -> kontrol (sumber apa pun) -> bandingkan Annex A -> SoA -> RTP -> risk owner setuju + terima sisa
6.2    sasaran: konsisten kebijakan, terukur bila praktis, DIPANTAU, TERDOKUMENTASI (eksplisit 2022)
6.3    perubahan ISMS direncanakan (baru 2022)  != 8.32 change management teknis
8.2/8.3 = menjalankan RA/RT dan menyimpan hasilnya

Opsi (27005): modify | retain | avoid | share
SoA wajib: kontrol yang dibutuhkan | alasan masuk | status penerapan | alasan pengecualian
Matriks 5x5: K x C, hasil mungkin 1-6,8,9,10,12,15,16,20,25 (tidak ada 7,11,13,14)
Event-based = skenario dari sumber risiko | Asset-based = aset, ancaman, kerentanan (27005:2022)
27005:2022 ed.4 (25 Okt 2022): "consequence" bukan "impact"; selaras ISO 31000:2018
```

## 10. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | HighTable: ISO 27001 clause 6.1.2 information security risk assessment (lead auditor guide) | https://hightable.io/iso-27001-clause-6-1-2-information-security-risk-assessment | sekunder (konsultan) | diperbarui 2026-09-14; diakses 2026-10-08 | Sedang. Struktur 6.1.2 a-e, yang dicek auditor, ketidaksesuaian umum |
| S2 | GRC Solutions: ISO 27001:2022 clause 6, what's changed | https://grcsolutions.io/iso-270012022-clause-6-whats-changed-and-what-you-need-to-do-about-it | sekunder (konsultan) | 2025-10-21; diakses 2026-10-08 | Sedang. Perubahan 6.2 dan 6.3 |
| S3 | PECB: ISO/IEC 27005:2022 main changes and implications | https://pecb.com/en/article/iso-iec-270052022-main-changes-and-implications | sekunder (lembaga pelatihan) | sekitar 2022; diakses 2026-10-08 | Sedang-tinggi. Event-based vs asset-based, istilah, teknik |
| S4 | NQA: ISO 27001, the SoA, the risk register, and where people go wrong | https://www.nqa.com/en-ca/resources/blog/March-2026/iso-27001-soa-risk-register-mistakes | sekunder (auditor lembaga sertifikasi) | Maret 2026; diakses 2026-10-08 | Sedang-tinggi. Lima kesalahan SoA dan register |
| S5 | Advisera Expert Advice Community: ISO 27001:2022 implementation issue (risk acceptance criteria) | https://community.advisera.com/topic/iso-270012022-implementation-issue/ | komunitas (forum tanya-jawab dengan konsultan) | 2023-05-26; diakses 2026-10-08 | Rendah-sedang. Contoh ambang penerimaan; opini satu konsultan |
| S6 | ISO27k (iso27001security.com): ISO/IEC 27005 | https://www.iso27001security.com/html/27005 | sekunder (komentar praktisi) | diperbarui 2026-08-19; diakses 2026-10-08 | Sedang. Struktur, opsi treatment, status pembahasan revisi; berisi opini penulis |
| S7 | IEC Webstore: ISO/IEC 27005:2022 | https://webstore.iec.ch/publication/79713 | primer (katalog penerbit) | 2022-10-25; diakses 2026-10-08 | Tinggi untuk judul, edisi, tanggal, abstrak |
| S8 | URM Consulting: Common issues identified during audits of ISO 27001:2022 | https://urmconsulting.com/blog/common-issues-identified-during-audits-of-iso-27001-2022 | sekunder (praktisi audit) | 2026-04-09; diakses 2026-10-08 | Sedang. Kriteria risiko di 8.1 dan atribut kontrol untuk SoA |

**Catatan sumber:** isi 6.1.2 dan 6.1.3 di bagian 3.2 dan 3.6 disusun dari beberapa ringkasan sekunder yang saling cocok, bukan dari teks standar; cocokkan urutan butir dan bunyi catatan tentang Annex A di 6.1.3 dengan teks ISO/IEC 27001:2022 atau SNI resmi. Beberapa ringkasan vendor menyebut Annex A sebagai "persyaratan minimum"; itu keliru, karena Annex A adalah daftar pembanding. Status revisi 27005 [S6] berasal dari komentar praktisi, jadi cek di katalog ISO sebelum dikutip. Query SPL di bagian 5 belum dijalankan; keluarannya ilustrasi, dan nama field serta perilaku `tstats` perlu dicoba di Splunk lab-mu.
