---
day: 04
title: 'Klausul 6: risk assessment, risk treatment, Statement of Applicability, sasaran, dan perencanaan perubahan'
researched_on: 2026-10-10
versions_checked: 'ISO/IEC 27001:2022 + Amd 1:2024; ISO/IEC 27002:2022; ISO/IEC 27005:2022 (edisi 4, terbit 25 Okt 2022; katalog ISO belum menampilkan proyek revisi per Okt 2026)'
---

# Day 04: Klausul 6, risiko, sasaran, dan Statement of Applicability

Cakupan: klausul 6.1.1-6.1.3, 6.2, dan 6.3 ISO/IEC 27001:2022 sebagai jalur yang membuat setiap kontrol punya alasan, dari kriteria risiko sampai SoA dan sasaran terukur, beserta konsep pendukung dari ISO/IEC 27005:2022. Praktik risk register lanjutan ada di Day 09 dan struktur Annex A di Day 08.

## Ide inti

Klausul 6 menjawab pertanyaan "kenapa kita butuh kontrol ini?". Jawaban yang diterima auditor bukan "karena best practice", tetapi "karena risiko R-xx melebihi kriteria penerimaan, kontrol ini menurunkannya, dan risk owner sudah menyetujui risiko yang tersisa". Setiap kontrol harus bisa ditelusuri mundur ke risiko yang dinilai dengan kriteria tetap, dan setiap risiko penting harus bisa ditelusuri maju ke kontrol, sasaran, dan orang yang bertanggung jawab.

Kamu sudah mengenal rantai ini dari detection engineering. Threat model menentukan skenario mana yang berbahaya, severity matrix menentukan seberapa parah, backlog menentukan rule apa yang dibuat dan siapa yang mengerjakan, coverage matrix mencatat skenario mana yang sudah tertutup dan mana yang sengaja dibiarkan, lalu KPI menunjukkan apakah semuanya berjalan. Klausul 6 adalah rantai yang sama, ditulis formal supaya bisa diaudit.

```
6.1.2 kriteria risiko (skala + ambang penerimaan)
  -> identifikasi, analisis, evaluasi risiko        -> risk register + risk owner
  -> 6.1.3 pilih opsi treatment dan kontrol          -> bandingkan dengan Annex A
  -> SoA (kontrol apa, kenapa, sudah jalan atau belum)
  -> risk treatment plan, disetujui risk owner beserta risiko sisanya
  -> 6.2 sasaran terukur untuk memantau hasilnya
6.3 bila ISMS sendiri berubah, perubahan itu direncanakan
```

Situasi yang dipakai sepanjang Day ini: PT Awan Nusantara (PT AN, penyedia hosting fiktif) sedang memindahkan sekitar 40% sumber log dari Splunk ke Wazuh (register konteks K-09 di Day 03). Di rapat anggaran Q2 2026, Lead SOC meminta tambahan waktu engineer dan storage untuk proyek itu. Direktur Operasional menjawab:

> "Semua tim minta anggaran dengan alasan best practice. Tunjukkan risikonya, seberapa besar, apa yang turun kalau kita bayar, siapa yang menanggung sisanya, dan bagaimana kita tahu proyek ini berhasil."

Lima permintaan itu adalah isi klausul 6: risiko (6.1.2), level menurut kriteria (6.1.2 a dan d), treatment dan kontrol (6.1.3), risk owner dan risiko sisa (6.1.3 f), serta sasaran terukur (6.2). Karena proyeknya mengubah cara ISMS membuktikan logging, 6.3 ikut tersentuh.

Bagi SOC, rule deteksi baru, perluasan sumber log, atau target MTTR sering lahir dari risk treatment plan dan sasaran 6.2. Dengan membaca risk register, kamu bisa berargumen: "cakupan log server in-scope baru 85%, padahal risiko R-09 mengandalkan 8.15 dan 8.16".

**Kapan relevan:** saat ISMS dibangun, saat risk assessment berkala (8.2), saat ada perubahan besar, menjelang audit, dan saat mengusulkan anggaran atau proyek keamanan.
**Kapan bukan jawaban:** klausul 6 menetapkan proses. Menjalankannya dan menyimpan hasilnya adalah klausul 8.2 dan 8.3 (Day 02 bagian 1.5).

## 1. Konsep inti

### 1.0 Istilah di Day ini

Tabel ini memuat istilah yang muncul di Day ini. Kolom padanan memakai analogi SOC yang sama di semua Day. Risiko, kontrol, Annex A, dan SoA sudah dijelaskan di Day 01; risk assessment, risk treatment, risk treatment plan, dan sasaran di Day 02. Istilah itu hanya diulang bila Day ini menambah artinya.

| Istilah | Arti singkat | Padanan di SOC |
|---|---|---|
| Risiko ISMS (6.1.1) | Hal yang bisa menghambat atau membantu ISMS mencapai hasilnya | Risiko terhadap program SOC: anggaran hilang, sponsor berganti |
| Risiko keamanan informasi (6.1.2) | Kemungkinan hilangnya confidentiality, integrity, atau availability informasi di dalam scope | Skenario di threat model |
| Kriteria risiko | Cara menilai (skala, rumus) dan kriteria penerimaan (level yang boleh diterima, oleh siapa) | Severity matrix alert |
| Kemungkinan (likelihood) dan konsekuensi (consequence) | Seberapa mungkin terjadi dan seberapa parah dampaknya | Dua sumbu severity matrix |
| Level risiko | Hasil penggabungan kemungkinan dan konsekuensi menurut rumus kriteria | Prioritas P1-P4 |
| Berbasis kejadian vs berbasis aset | Identifikasi dari skenario sumber risiko vs dari daftar aset, ancaman, kerentanan | Hunting berbasis TTP vs berbasis crown jewels |
| Risk owner | Orang dengan akuntabilitas dan wewenang mengelola sebuah risiko | Approver yang boleh menerima gap coverage atau mendanai perbaikan |
| Opsi treatment | Modify, retain, avoid, share | Perbaiki rule, terima known gap, matikan layanan terekspos, alihkan ke MSSP atau asuransi |
| Risiko sisa (residual risk) | Level risiko setelah treatment | Known gap setelah tuning |
| Risk treatment plan (RTP) | Rencana pelaksanaan treatment: kontrol, pemilik, tenggat | Backlog detection engineering |
| Sasaran keamanan (objectives) | Target terukur dengan rumus, sumber data, pemilik | KPI SOC |
| Perencanaan perubahan (6.3) | Perubahan pada ISMS dijalankan terencana | Rencana migrasi SIEM |

### 1.1 Dua jenis risiko di klausul 6

Saat Direktur Operasional berkata "kalau Lead SOC resign, proyek migrasi ini berhenti", itu juga risiko. Tetapi jenisnya berbeda dengan "log VM pelanggan tidak masuk SIEM". Klausul 6 memisahkan keduanya.

**Risiko dan peluang ISMS (6.1.1).** Organisasi memakai isu 4.1 dan persyaratan 4.2 untuk menentukan risiko dan peluang yang perlu ditangani agar ISMS mencapai hasilnya, efek yang tidak diinginkan berkurang, dan perbaikan berkelanjutan tercapai. Lalu organisasi merencanakan tindakan, cara memasukkannya ke proses ISMS, dan cara menilai efektivitasnya [S1]. Contoh risiko ISMS: pimpinan berganti dan anggaran hilang; contoh peluang: SOAR mengotomasi pengumpulan bukti.

**Risiko keamanan informasi (6.1.2).** Kemungkinan hilangnya confidentiality, integrity, atau availability informasi di dalam scope. Risiko inilah yang masuk risk register dan menentukan kontrol.

Risiko ISMS tidak wajib dinilai dengan metodologi 6.1.2. Kalau keduanya dicampur di satu register, kontrol Annex A akan terlihat menangani "Lead SOC resign", padahal itu urusan perencanaan sumber daya.

### 1.2 Klausul 6.1.2: proses risk assessment

Permintaan pertama Direktur Operasional adalah "tunjukkan risikonya dan seberapa besar". Jawaban yang meyakinkan butuh proses yang sama setiap kali dijalankan, sama seperti severity alert yang tidak boleh bergantung pada siapa analyst yang sedang shift.

Organisasi menetapkan dan menerapkan proses risk assessment yang [S1]:

- a. menetapkan dan memelihara kriteria risiko, yaitu kriteria penerimaan risiko dan kriteria untuk menjalankan penilaian;
- b. memastikan penilaian berulang menghasilkan hasil yang konsisten, valid, dan bisa dibandingkan;
- c. mengidentifikasi risiko hilangnya C, I, atau A informasi di dalam scope, serta risk owner tiap risiko;
- d. menganalisis risiko: konsekuensi bila terjadi, kemungkinan realistisnya, lalu level risikonya;
- e. mengevaluasi risiko: membandingkan hasil analisis dengan kriteria di butir a, lalu memprioritaskan risiko untuk treatment.

Informasi tentang proses ini wajib disimpan, biasanya sebagai dokumen metodologi risiko. Butir b sering diremehkan: bila skala berganti dari 1-3 ke 1-5 di tengah siklus, tidak terlihat lagi apakah risiko benar-benar turun atau hanya skalanya yang berubah [S1]. Masalahnya sama dengan mengganti definisi P1 di tengah tahun lalu melaporkan "jumlah P1 turun 40%".

### 1.3 Cara mengidentifikasi risiko: berbasis kejadian atau berbasis aset

Untuk proyek migrasi, ada dua cara mulai mencari risiko: dari skenario ("apa yang bisa salah saat cutover?") atau dari daftar aset ("VM pelanggan mana saja yang lognya ikut pindah?"). Keduanya sah.

ISO 27001 tidak menentukan metode identifikasi. ISO/IEC 27005:2022, sebuah panduan, menjelaskan dua pendekatan [S3]:

- **Berbasis kejadian (event-based):** mulai dari sumber risiko dan skenario (siapa menyerang, tujuannya, dampaknya). Cocok untuk penilaian tingkat tinggi.
- **Berbasis aset (asset-based):** mulai dari daftar aset, lalu ancaman dan kerentanannya. Cocok untuk penilaian rinci sistem penting.

Bedanya mirip hunting berbasis TTP dan hunting berbasis crown jewels. Pendekatan berbasis kejadian terasa alami bagi SOC karena mirip threat modeling: skenario "operator ransomware masuk lewat panel manajemen yang terekspos" langsung menunjukkan kontrol deteksi yang dibutuhkan.

27005:2022 memakai istilah "consequence" (bukan "impact") agar selaras dengan ISO 31000:2018 [S3]. Kalau menemukan "impact" di dokumen lain, maksudnya sama.

### 1.4 Merancang kriteria risiko dan memilih risk owner

Permintaan "siapa yang menanggung sisanya" menuntut dua hal yang ditetapkan sebelum penilaian dimulai: ambang level yang boleh diterima, dan orang yang berwenang menerimanya.

**Kriteria risiko.** Kriteria terdiri dari cara menilai (skala kemungkinan, skala konsekuensi, rumus level) dan kriteria penerimaan (level yang boleh diterima tanpa treatment, dan oleh siapa). Bentuknya bebas asalkan cocok dengan konteks bisnis [S5].

Contoh umum adalah matriks 5x5 (level = kemungkinan x konsekuensi), pendekatan semi-kuantitatif yang angkanya hanya mengurutkan. Perkalian dua bilangan 1-5 tidak pernah menghasilkan 7, 11, 13, atau 14, jadi batas pita level dibuat dengan menyadari celah itu.

**Risk owner.** Risk owner adalah orang yang punya akuntabilitas dan wewenang mengelola sebuah risiko, belum tentu pemilik aset. Untuk risiko "log VM pelanggan tidak masuk SIEM", pemilik yang wajar adalah Lead SOC atau Head of Platform, bukan analyst L1 tanpa wewenang anggaran. Risk owner ditunjuk di 6.1.2 c dan di 6.1.3 f menyetujui risk treatment plan serta menerima risiko sisa (residual risk) [S1][S8].

### 1.5 Klausul 6.1.3: proses risk treatment

Permintaan "apa yang turun kalau kita bayar" adalah pertanyaan treatment: opsi apa yang dipilih, kontrol apa yang dibutuhkan, dan berapa level sisanya.

Organisasi menetapkan dan menerapkan proses risk treatment untuk [S8]:

- a. memilih opsi treatment berdasarkan hasil risk assessment;
- b. menentukan semua kontrol yang dibutuhkan untuk menjalankan opsi itu;
- c. membandingkan kontrol itu dengan Annex A untuk memastikan tidak ada yang terlewat;
- d. menyusun Statement of Applicability (bagian 1.6);
- e. merumuskan risk treatment plan;
- f. meminta persetujuan risk owner atas rencana itu dan penerimaan risiko sisa.

Informasi tentang proses ini juga wajib disimpan.

**Posisi Annex A.** Catatan di 6.1.3 menjelaskan posisi Annex A [S8]. Kontrol boleh dirancang sendiri atau diambil dari sumber mana pun (CIS Controls, NIST). Annex A adalah daftar kontrol yang mungkin dipakai, tempat memeriksa agar tidak ada kontrol penting yang terlewat, dan daftarnya tidak lengkap secara mutlak sehingga kontrol tambahan boleh dimasukkan. Catatan terakhir menyebut proses treatment ini selaras dengan prinsip ISO 31000. Annex A bukan "persyaratan minimum" seperti yang kadang ditulis ringkasan vendor. Dalam bahasa SOC: rule bawaan Wazuh atau repo Sigma dipakai untuk mengecek apakah ada skenario penting yang belum tertutup, bukan daftar yang wajib diaktifkan semua, dan rule buatan sendiri tetap sah.

**Opsi treatment.** 27005 mengenal empat opsi treatment [S6]. Padanannya adalah empat cara merespons gap deteksi.

- **Modify:** mengubah kontrol untuk menurunkan kemungkinan atau konsekuensi, misalnya rule deteksi baru.
- **Retain:** menerima risiko tanpa kontrol tambahan, misalnya risiko rendah yang diterima risk owner.
- **Avoid:** menghentikan aktivitas penyebab risiko, misalnya mencabut akses internet panel manajemen.
- **Share:** membagi konsekuensi dengan pihak lain, misalnya asuransi siber atau kontrak colocation.

ISO27k mengkritik 27005:2022 karena hampir hanya membahas modify [S6], padahal avoid sering menjadi opsi termurah. Batas analoginya: share membagi konsekuensi, tidak memindahkan akuntabilitas, dan risiko sisa dari opsi apa pun tetap harus disetujui risk owner.

### 1.6 Statement of Applicability

Setelah treatment dipilih, kontrol yang dipakai dicatat di SoA, padanannya coverage matrix. Auditor yang ingin tahu kenapa PT AN memakai 8.16 Monitoring activities akan membuka SoA lalu mengikuti rujukannya ke risk register.

Menurut 6.1.3 d, SoA memuat [S4][S8]:

- kontrol yang dibutuhkan (hasil butir b dan c);
- alasan setiap kontrol dimasukkan;
- apakah kontrol itu sudah diterapkan atau belum;
- alasan setiap kontrol Annex A yang dikecualikan.

Auditor membaca SoA bersama risk register: setiap kontrol harus bisa ditelusuri ke risiko, kontrak, atau regulasi. Auditor NQA (Maret 2026) mencatat lima kesalahan umum [S4]:

1. semua kontrol ditandai berlaku secara defensif;
2. risiko terlalu umum sehingga tidak tersambung ke kontrol;
3. SoA disalin dari organisasi lain;
4. alasan pengecualian lemah;
5. SoA tidak diperbarui saat risiko berubah.

Atribut kontrol 27002:2022 (misalnya control type) bisa memperkuat alasan pemilihan, tetapi jarang dimanfaatkan [S7].

### 1.7 Klausul 6.2: sasaran keamanan informasi

Permintaan terakhir Direktur Operasional, "bagaimana kita tahu proyek ini berhasil", dijawab dengan sasaran terukur. Padanannya KPI SOC, dengan syarat tambahan dari standar.

Sasaran ditetapkan pada fungsi dan level yang relevan, dan harus [S2]: (a) konsisten dengan kebijakan keamanan informasi; (b) terukur bila praktis; (c) mempertimbangkan persyaratan keamanan yang berlaku serta hasil risk assessment dan risk treatment; (d) dipantau; (e) dikomunikasikan; (f) diperbarui bila perlu; (g) tersedia sebagai informasi terdokumentasi.

Rencana pencapaiannya menyebut apa yang dikerjakan, sumber daya, penanggung jawab, tenggat, dan cara mengevaluasi hasil. Auditor mencari jalur dari sasaran ke metrik dan laporan rutin: "meningkatkan keamanan" tidak bisa diaudit, sedangkan "cakupan log server in-scope minimal 98% per bulan" bisa.

### 1.8 Klausul 6.3: perencanaan perubahan

Proyek migrasi PT AN sendiri adalah perubahan pada ISMS, sehingga selain risikonya dinilai, perubahannya juga harus direncanakan.

6.3 pendek: bila organisasi memutuskan ISMS perlu diubah, perubahan dijalankan secara terencana [S2]. Formatnya bebas; rencana yang wajar menyebut tujuan, dampak ke ISMS, risiko selama transisi, sumber daya, penanggung jawab, dan kriteria selesai.

Bedakan dengan kontrol 8.32 Change management untuk perubahan sistem. Memindahkan sumber log dari Splunk ke Wazuh adalah perubahan teknis (8.32), tetapi juga mengubah cara ISMS membuktikan logging dan monitoring, sehingga perlu direncanakan menurut 6.3.

## 2. Contoh dokumen / artefak (organisasi fiktif)

Organisasi fiktif: PT Awan Nusantara (PT AN). Semua angka di bawah adalah ilustrasi. Keempat artefak ini adalah bahan jawaban Lead SOC untuk Direktur Operasional di bagian Ide inti.

### 2.1 Kriteria risiko PT AN (cuplikan metodologi)

Kriteria ini menjawab "seberapa besar" dengan cara yang sama setiap siklus. Baca kolom konsekuensi untuk melihat bagaimana dampak bisnis diterjemahkan ke angka.

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

### 2.2 Cuplikan risk register

Register ini menjawab "apa risikonya, apa yang turun, dan siapa yang menanggung sisanya". Baris R-09 adalah risiko proyek migrasi; baris lain menunjukkan keempat opsi treatment.

| ID | Skenario risiko | Risk owner | K | C | Level awal | Opsi | Kontrol (Annex A) | K sisa | C sisa | Level sisa |
|---|---|---|---|---|---|---|---|---|---|---|
| R-04 | Akun default di image VM dipakai penyerang masuk ke VM pelanggan | Head of Platform | 4 | 4 | 16 Tinggi | Modify | 8.9; 8.16 | 2 | 4 | 8 Sedang |
| R-09 | Log VM pelanggan tidak masuk SIEM selama migrasi | Lead SOC | 3 | 3 | 9 Sedang | Modify | 8.15; 8.16; rencana perubahan CH-02 | 1 | 3 | 3 Rendah |
| R-11 | Ransomware masuk lewat panel hypervisor yang terekspos ke internet | Head of Platform | 3 | 5 | 15 Tinggi | Avoid | Panel dipindah ke belakang VPN; 8.20 | 1 | 5 | 5 Rendah |
| R-15 | Banjir membuat DC Jakarta-1 tidak tersedia lebih dari 24 jam | Direktur Ops | 2 | 5 | 10 Sedang | Share + Modify | Asuransi; kontrak colocation; 7.5; 5.30 | 2 | 4 | 8 Sedang |
| R-20 | Alert prioritas rendah salah ditriage pada shift malam | Lead SOC | 3 | 2 | 6 Rendah | Retain | Kontrol yang ada cukup; QA sampling bulanan | 3 | 2 | 6 Rendah |

Cara membaca:

- **Level dihitung, bukan ditebak:** level awal 4x4 = 16, 3x3 = 9, 3x5 = 15, 2x5 = 10, 3x2 = 6; level sisa 2x4 = 8, 1x3 = 3, 1x5 = 5, 2x4 = 8, 3x2 = 6. Semua jatuh di pita yang benar menurut bagian 2.1.
- **R-11 memakai avoid:** paparan ke internet dihentikan, jadi kemungkinan turun ke 1 walaupun konsekuensi tetap 5.
- **R-15 tetap Sedang:** asuransi membagi beban finansial tetapi tidak menjaga layanan tetap tersedia, dan 7.5 serta 5.30 hanya menurunkan konsekuensi ke 4. Direktur Ops menerima level 8 dengan alasan tertulis.
- **R-20 memakai retain:** keputusan tetap dicatat.
- **R-09 tersambung ke perubahan CH-02 (6.3):** risiko muncul justru karena perubahan yang direncanakan.

### 2.3 Cuplikan Statement of Applicability

SoA ini menunjukkan ke auditor kenapa setiap kontrol ada. Perhatikan kolom Rujukan.

| Kontrol | Berlaku? | Alasan | Status | Rujukan |
|---|---|---|---|---|
| 5.7 Threat intelligence | Ya | Prioritas deteksi skenario ransomware | Sebagian (feed ada, review belum) | R-11 |
| 5.24 Incident management planning and preparation | Ya | Kewajiban lapor insiden ke klien perbankan | Diterapkan | K-03, R-04 |
| 8.15 Logging | Ya | Deteksi dan bukti insiden VM pelanggan | Diterapkan | R-04, R-09 |
| 8.16 Monitoring activities | Ya | Deteksi akses tidak sah | Diterapkan | R-04, R-09 |
| 8.17 Clock synchronization | Ya | Korelasi log dan nilai bukti timeline | Diterapkan | R-09 |
| 7.5 Protecting against physical and environmental threats | Ya | Risiko banjir DC Jakarta-1 | Sebagian | R-15 |
| 8.30 Outsourced development | Tidak | Tidak ada pengembangan yang dialihdayakan; tinjau ulang bila ada kontrak | Tidak berlaku | Scope v1.0 |

Kolom rujukan membuat setiap baris "Ya" bisa ditelusuri; baris tanpa rujukan adalah tanda kontrol dipilih secara defensif [S4]. Alasan pengecualian 8.30 bisa dipertahankan karena berupa fakta yang bisa diverifikasi dan menyebut kondisi tinjau ulang, berbeda dengan alasan "mahal" atau "tidak relevan".

### 2.4 Sasaran keamanan SOC (6.2)

Sasaran ini menjawab "bagaimana kita tahu berhasil". S-01 adalah ukuran keberhasilan proyek migrasi.

| Sasaran | Metrik | Target | Pemilik | Frekuensi ukur | Sumber data |
|---|---|---|---|---|---|
| S-01 Cakupan log server in-scope | Server in-scope yang mengirim log 24 jam terakhir dibagi total server in-scope | >= 98% per bulan mulai Q2 2026 | Lead SOC | Bulanan | SIEM, daftar aset |
| S-02 Respons insiden prioritas tinggi | Median waktu alert sampai containment | <= 4 jam | Lead SOC | Bulanan | Tiket insiden |
| S-03 Sinkronisasi waktu | Host in-scope dengan selisih lebih dari 1 detik dari NTP internal | 0 host, 3 bulan berturut-turut | Head of Platform | Mingguan | Laporan NTP |

Rumus, target, dan sumber data membuat sasaran memenuhi butir b dan d di 6.2 dan bisa dilaporkan sebagai hasil monitoring (9.1).

## 3. Lab praktik

Latihan untuk organisasi fiktifmu. Simpan di `latihan/day04-<nama-org-fiktif>.md`.

1. Tulis kriteria risiko: skala kemungkinan dan konsekuensi 1-5, rumus level, dan tiga pita penerimaan beserta siapa yang boleh menerima.
2. Identifikasi 6 risiko, minimal dua berbasis kejadian dan dua berbasis aset, masing-masing dengan risk owner yang punya wewenang.
3. Hitung level awal dan level sisa, lalu hitung ulang setiap perkalian.
4. Pilih opsi treatment; avoid, share, dan retain masing-masing dipakai minimal sekali.
5. Susun SoA minimal 10 kontrol, termasuk 2 pengecualian; setiap baris "Ya" punya rujukan.
6. Tulis 3 sasaran SOC dengan format bagian 2.4 dan cek butir 6.2 a-g untuk tiap sasaran.
7. Tulis satu rencana perubahan menurut 6.3 (misalnya migrasi sebagian log ke Wazuh) dengan risiko transisi yang tersambung ke register.
8. Opsional di Splunk lab: ukur S-01 dengan search di bawah, memakai lookup `inscope_assets.csv` berkolom `host` berisi host lab yang kamu anggap in-scope.

```
| tstats latest(_time) as last_seen where index=* by host
| append [| inputlookup inscope_assets.csv | eval in_scope=1]
| stats max(last_seen) as last_seen max(in_scope) as in_scope by host
| where in_scope=1
| eval status=if(isnull(last_seen) OR last_seen < relative_time(now(), "-24h"), "tidak terlihat 24 jam", "ok")
| stats count by status
```

**Penjelasan:** `tstats ... by host` mengambil waktu event terakhir per host dari index yang bisa dibaca role-mu (`index=*` tidak mencakup index internal berawalan garis bawah). `append` dan `inputlookup` menambahkan daftar in-scope, lalu `stats max(...) by host` menggabungkan keduanya tanpa `join`. `where in_scope=1` membuang host di luar daftar, dan `eval status` menandai host yang tidak pernah terlihat atau terakhir terlihat lebih dari 24 jam lalu.

**Keluaran ilustrasi** (bukan hasil eksekusi nyata):

```
status                  count
ok                         49
tidak terlihat 24 jam       1
```

**Cara membaca:** cakupan = 49 / (49 + 1) = 98%, tepat di target S-01. Host yang tidak terlihat ditindaklanjuti; bila berulang, menjadi nonconformity (10.2).

**Kapan gagal:** format nama host di lookup berbeda dengan field `host` (huruf besar/kecil, FQDN); normalisasi dengan `lower()`. Host yang datanya masuk ke index di luar hak role-mu juga tampak hilang.

**Hasil yang sebaiknya tersimpan:**
- Register risiko, SoA, dan sasaran yang saling merujuk.
- Perkalian level awal dan level sisa yang sudah dihitung ulang.
- Pengecualian SoA dengan alasan yang bisa diverifikasi.
- Rencana perubahan 6.3 yang tersambung ke register.
- Hasil search S-01 (bila dijalankan) beserta daftar host yang tidak terlihat.

**Variasi tantangan:** hitung ulang register dengan skala 1-3, bandingkan urutan prioritasnya, dan jelaskan kenapa mengganti skala di tengah siklus melanggar 6.1.2 b.

## 4. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Hampir semua risiko jatuh di pita Tinggi | Skala konsekuensi terlalu sensitif | Kalibrasi skala dengan dua atau tiga kejadian contoh yang disepakati |
| SoA dan register tidak cocok | Disusun oleh orang atau waktu berbeda | Tambahkan kolom rujukan di SoA; tinjau keduanya dalam satu sesi |
| Sasaran tidak bisa diukur | Tidak ada sumber data atau rumus | Tulis rumus dan sumber data; bila belum ada, sasaran pertamanya membangun pengukuran |

## 5. Kesalahan umum dan jebakan

- Menandai semua 93 kontrol "berlaku" atau memutus register dari SoA; keduanya dibahas di bagian 1.6 [S4].
- Tidak punya kriteria tertulis untuk menjalankan risk assessment, sehingga hasil tiap siklus tidak konsisten. URM melaporkan temuan ini di audit 2026 [S7].
- Lupa meminta persetujuan risk owner (6.1.3 f), sehingga risk treatment plan secara formal belum selesai.
- `[komunitas, belum terkonfirmasi]` Di forum tanya-jawab Advisera, ambang angka (misalnya level di atas 7 wajib treatment) disebut sebagai salah satu bentuk kriteria penerimaan yang sah [S5]. Pilihan ambang tetap keputusan organisasi.

## 6. Catatan terkini

Bagian ini menampung detail edisi dan perubahan dari edisi lama. Berguna saat membaca metodologi risiko atau SoA yang disusun untuk edisi sebelumnya.

- Edisi 2005 masih mengarahkan identifikasi risiko ke aset, ancaman, dan kerentanan; edisi sekarang tidak menentukan metode [S3]. Materi lama yang menyebut pendekatan berbasis aset sebagai kewajiban memakai pola edisi 2005.
- Edisi 2022 tidak lagi memakai istilah control objectives di 6.1.3 [S8]. SoA lama yang disusun per control objective perlu disesuaikan.
- Butir d (dipantau) dan g (tersedia sebagai informasi terdokumentasi) di 6.2 eksplisit sejak 2022 [S2]. 6.3 adalah klausul baru di 2022 [S2].
- ISO/IEC 27005:2022 adalah edisi 4, terbit 25 Oktober 2022 [S9]. Per Oktober 2026, katalog ISO menampilkannya sebagai edisi berlaku tanpa tahap revisi [S9]. Situs ISO27k (Agustus 2026) melaporkan working group sedang membahas pendekatan revisi, termasuk kemungkinan menjadi standar multi-bagian [S6]; itu baru pembahasan, belum proyek resmi.

## 7. Cheat sheet

```
6.1.1  risiko & peluang ISMS (dari 4.1/4.2): rencanakan tindakan, integrasikan, nilai efektivitas
6.1.2  a kriteria (penerimaan + cara menilai) | b konsisten, valid, bisa dibandingkan
       c identifikasi risiko CIA + risk owner | d analisis (konsekuensi, kemungkinan, level)
       e evaluasi vs kriteria + prioritas
6.1.3  a opsi | b kontrol (sumber apa pun) | c bandingkan Annex A | d SoA | e RTP
       f risk owner setujui RTP + terima risiko sisa
       Annex A = daftar kontrol yang mungkin, tidak lengkap mutlak; boleh tambah kontrol
SoA    kontrol yang dibutuhkan | alasan masuk | diterapkan atau belum | alasan pengecualian
       tiap baris "Ya" punya rujukan ke risiko, kontrak, atau regulasi
6.2    a konsisten kebijakan | b terukur bila praktis | c pertimbangkan persyaratan + hasil RA/RT
       d dipantau | e dikomunikasikan | f diperbarui | g terdokumentasi
       rencana: apa, sumber daya, siapa, kapan, cara evaluasi
6.3    perubahan ISMS direncanakan (baru 2022)  != 8.32 change management teknis
8.2/8.3 = menjalankan RA/RT dan menyimpan hasilnya

Opsi (27005): modify | retain | avoid | share   (share membagi konsekuensi, bukan akuntabilitas)
Matriks 5x5: K x C, hasil mungkin 1-6,8,9,10,12,15,16,20,25 (tidak ada 7,11,13,14)
Event-based = skenario dari sumber risiko | Asset-based = aset, ancaman, kerentanan
27005:2022 ed.4 (25 Okt 2022): "consequence" bukan "impact"; selaras ISO 31000:2018
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** Untuk risiko R-09 (log VM pelanggan tidak masuk SIEM selama migrasi), seorang analyst L1 ditunjuk sebagai risk owner karena dialah yang setiap hari memantau dashboard cakupan log. Apakah penunjukan itu tepat?

<details><summary>Jawaban</summary>

Tidak. Risk owner adalah orang yang punya akuntabilitas dan wewenang mengelola risiko, belum tentu orang yang paling dekat dengan datanya. Risk owner menyetujui risk treatment plan dan menerima risiko sisa (6.1.3 f), sehingga butuh wewenang, termasuk atas anggaran. Untuk R-09, pemilik yang wajar adalah Lead SOC atau Head of Platform. Analyst L1 tetap bisa memantau dan melaporkan, tetapi bukan pemilik risikonya. Lihat bagian 1.4.

</details>

**2. Pertanyaan jebakan.** Di tengah siklus, PT AN mengganti skala risiko dari 1-3 ke 1-5 karena dianggap lebih rinci, lalu mengonversi register lama dengan perkiraan. Laporan berikutnya menunjukkan banyak risiko "turun". Apa masalahnya?

<details><summary>Jawaban</summary>

6.1.2 b meminta penilaian berulang menghasilkan hasil yang konsisten, valid, dan bisa dibandingkan. Setelah skala diganti di tengah siklus, tidak terlihat lagi apakah risiko benar-benar turun atau hanya skalanya yang berubah. Perubahan kriteria sebaiknya dilakukan di awal siklus, didokumentasikan di metodologi, dan seluruh risiko dinilai ulang dengan skala baru. Lihat bagian 1.2.

</details>

**3. Skenario keputusan.** Untuk risiko R-11 (ransomware masuk lewat panel hypervisor yang terekspos ke internet, level 15 Tinggi), tiga usulan masuk. Mana yang paling menurunkan level risiko?

- A. Tambah rule deteksi untuk login mencurigakan ke panel (modify).
- B. Pindahkan panel ke belakang VPN sehingga tidak lagi terekspos ke internet (avoid).
- C. Beli asuransi siber yang menanggung biaya pemulihan ransomware (share).

<details><summary>Jawaban</summary>

B. Menghentikan paparan ke internet menurunkan kemungkinan ke 1, sehingga level sisa menjadi 1x5 = 5 (Rendah), dan avoid sering menjadi opsi termurah. A tetap berguna sebagai lapisan tambahan, tetapi panel masih terekspos, jadi kemungkinan serangan tidak turun sebanyak itu. C hanya membagi beban finansial; seperti di R-15, asuransi tidak menjaga layanan tetap tersedia dan tidak mengubah kemungkinan terjadinya serangan. Lihat bagian 1.5 dan 2.2.

</details>

**4. Pertanyaan jebakan.** Supaya aman saat audit, ISMS Manager menandai semua 93 kontrol Annex A sebagai "berlaku" di SoA tanpa kolom rujukan. Apakah itu strategi yang aman?

<details><summary>Jawaban</summary>

Tidak. Auditor membaca SoA bersama risk register, dan setiap kontrol harus bisa ditelusuri ke risiko, kontrak, atau regulasi. Menandai semua kontrol berlaku secara defensif adalah kesalahan pertama dalam daftar lima kesalahan yang dicatat auditor NQA. Baris tanpa rujukan menunjukkan kontrol tidak dipilih berdasarkan risiko. SoA juga mencatat apakah setiap kontrol sudah diterapkan, sehingga klaim "berlaku" tanpa penerapan mudah terlihat. Lihat bagian 1.6 dan 2.3.

</details>

**5. Skenario keputusan.** Direktur Operasional meminta satu sasaran untuk mengukur keberhasilan proyek migrasi log. Mana yang paling memenuhi 6.2?

- A. "Meningkatkan kualitas monitoring keamanan."
- B. "MTTR turun."
- C. "Cakupan log server in-scope minimal 98% per bulan mulai Q2 2026, diukur bulanan dari SIEM dan daftar aset, pemilik Lead SOC."

<details><summary>Jawaban</summary>

C. Sasaran ini terukur (butir b), punya sumber data dan frekuensi sehingga bisa dipantau (butir d), punya pemilik, dan bisa dilaporkan sebagai hasil monitoring di 9.1. A tidak bisa diaudit karena tidak ada ukuran. B menyebut metrik tetapi tanpa rumus, target, sumber data, pemilik, atau tenggat, dan MTTR juga bukan ukuran langsung keberhasilan migrasi log. Lihat bagian 1.7 dan 2.4.

</details>

**6. Jelaskan ulang.** Jelaskan kepada Direktur Operasional dalam tiga kalimat kenapa "best practice" bukan alasan yang diterima auditor untuk sebuah kontrol, tanpa memakai kata "klausul" atau "Annex".

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Auditor ingin melihat bahwa setiap kontrol dipilih karena ada risiko nyata di organisasi kita yang dinilai dengan ukuran yang sama setiap tahun. Jadi alasan yang diterima berbunyi 'risiko ini terlalu tinggi menurut ambang kita, kontrol ini menurunkannya, dan pemilik risikonya sudah menyetujui sisanya'. Dengan cara itu kita juga tahu kontrol mana yang tidak perlu, sehingga anggaran tidak habis untuk hal yang tidak menurunkan risiko kita."

Kesalahan yang sering muncul:
- Menjawab "karena ISO mewajibkan semua kontrol". Kontrol dipilih berdasarkan risiko; daftar acuannya tidak wajib dipakai seluruhnya.
- Lupa menyebut pemilik risiko dan risiko sisa, seolah risiko hilang setelah kontrol dipasang.
- Menganggap best practice salah. Best practice boleh menjadi sumber ide kontrol; yang diminta adalah alasan berbasis risiko organisasi sendiri.

</details>

**7. Interview question (English).** "How would you justify a new detection use case in ISO 27001 terms?"

<details><summary>Sample answer</summary>

"I'd tie it to the risk register. First I'd point to the risk it addresses, for example 'customer VM logs not reaching the SIEM during migration', and show its level under our risk criteria. Then I'd explain which treatment option we chose, usually modify, which controls it supports, such as 8.15 Logging and 8.16 Monitoring activities, and how it reduces the likelihood or consequence. The risk owner approves the treatment plan and accepts the residual risk, the Statement of Applicability references the risk, and I'd propose a measurable objective, like log coverage of in-scope servers, so we can show in monitoring reports that it actually works."

What makes this answer strong: it follows the chain from risk to treatment, SoA, risk owner approval, and measurable objective, instead of arguing from best practice.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | HighTable: ISO 27001 clause 6.1.2 information security risk assessment (lead auditor guide) | https://hightable.io/iso-27001-clause-6-1-2-information-security-risk-assessment | sekunder (konsultan) | diperbarui 2026-09-14; diakses 2026-10-08 | Sedang. Butir 6.1.2 a-e, temuan umum |
| S2 | GRC Solutions: ISO 27001:2022 clause 6, what's changed | https://grcsolutions.io/iso-270012022-clause-6-whats-changed-and-what-you-need-to-do-about-it | sekunder (konsultan) | 2025-10-21; diakses 2026-10-10 | Sedang. Butir 6.2, rencana pencapaian sasaran, 6.3 |
| S3 | PECB: ISO/IEC 27005:2022 main changes and implications | https://pecb.com/en/article/iso-iec-270052022-main-changes-and-implications | sekunder (lembaga pelatihan) | sekitar 2022; diakses 2026-10-08 | Sedang-tinggi. Pendekatan identifikasi, istilah |
| S4 | NQA: ISO 27001, the SoA, the risk register, and where people go wrong | https://www.nqa.com/en-ca/resources/blog/March-2026/iso-27001-soa-risk-register-mistakes | sekunder (auditor lembaga sertifikasi) | Maret 2026; diakses 2026-10-08 | Sedang-tinggi. Isi SoA, lima kesalahan SoA dan register |
| S5 | Advisera Expert Advice Community: ISO 27001:2022 implementation issue (risk acceptance criteria) | https://community.advisera.com/topic/iso-270012022-implementation-issue/ | komunitas (forum tanya-jawab dengan konsultan) | 2023-05-26; diakses 2026-10-08 | Rendah-sedang. Opini satu konsultan |
| S6 | ISO27k (iso27001security.com): ISO/IEC 27005 | https://www.iso27001security.com/html/27005 | sekunder (komentar praktisi) | diperbarui 2026-08-19; diakses 2026-10-08 | Sedang. Opsi treatment, pembahasan revisi; berisi opini |
| S7 | URM Consulting: Common issues identified during audits of ISO 27001:2022 | https://urmconsulting.com/blog/common-issues-identified-during-audits-of-iso-27001-2022 | sekunder (praktisi audit) | 2026-04-09; diakses 2026-10-08 | Sedang. Kriteria risiko dan atribut kontrol untuk SoA |
| S8 | HighTable: ISO 27001 clause 6.1.3 information security risk treatment | https://hightable.io/iso-27001-clause-6-1-3-information-security-risk-treatment/ | sekunder (konsultan) | diperbarui 2026-09-14; diakses 2026-10-10 | Sedang. Butir 6.1.3 a-f, isi SoA |
| S9 | ISO committee: ISO/IEC 27005:2022 | https://committee.iso.org/standard/80585.html | primer (katalog ISO) | 2022-10-25; diakses 2026-10-10 | Tinggi untuk edisi dan status |

**Catatan sumber:** rincian catatan Annex A di 6.1.3 hanya dikonfirmasi sebagian oleh ringkasan sekunder [S8]. Pembahasan revisi 27005 [S6] belum tercermin di katalog ISO [S9]. Keluaran SPL di bagian 3 adalah ilustrasi.
