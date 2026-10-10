---
day: 04
title: 'Klausul 6: risk assessment, risk treatment, Statement of Applicability, sasaran, dan perencanaan perubahan'
researched_on: 2026-10-10
versions_checked: 'ISO/IEC 27001:2022 + Amd 1:2024; ISO/IEC 27002:2022; ISO/IEC 27005:2022 (edisi 4, terbit 25 Okt 2022; katalog ISO belum menampilkan proyek revisi per Okt 2026)'
---

# Day 04: Klausul 6, risiko, sasaran, dan Statement of Applicability

Cakupan: klausul 6.1.1-6.1.3, 6.2, dan 6.3 ISO/IEC 27001:2022 beserta konsep pendukung dari ISO/IEC 27005:2022, dengan praktik risk register lanjutan di Day 09 dan struktur Annex A di Day 08.

> Catatan pribadi, bukan materi resmi ISO, dan bukan nasihat hukum atau audit. Catatan ini hanya menyebut nomor dan judul singkat klausul dan kontrol, lalu menjelaskannya dengan kata-kata sendiri.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- membedakan risiko dan peluang ISMS (6.1.1) dari risiko keamanan informasi (6.1.2).
- merancang kriteria risiko yang menghasilkan penilaian konsisten dan bisa dibandingkan.
- memilih opsi treatment dan menjelaskan peran risk owner atas risiko sisa.
- menyusun Statement of Applicability yang bisa ditelusuri ke risk register.
- menulis sasaran keamanan terukur untuk SOC dan merencanakan perubahan ISMS menurut 6.3.

## 2. Konteks singkat

Klausul 6 menjawab pertanyaan "kenapa kita butuh kontrol ini?" Jawaban yang diterima auditor bukan "karena best practice", tetapi "karena risiko R-xx melebihi kriteria penerimaan, dan kontrol ini menurunkannya ke level yang disetujui risk owner".

Bagi SOC, rule deteksi baru, perluasan sumber log, atau target MTTR sering lahir dari risk treatment plan dan sasaran 6.2. Dengan membaca risk register, kamu bisa berargumen: "cakupan log server in-scope baru 85%, padahal risiko R-09 mengandalkan 8.15 dan 8.16".

Kapan dipakai: saat ISMS dibangun, saat risk assessment berkala (8.2), saat perubahan besar, dan menjelang audit.
Kapan tidak cukup: klausul 6 menetapkan proses. Menjalankannya dan menyimpan hasilnya adalah klausul 8.2 dan 8.3 (Day 02 bagian 3.4).

## 3. Konsep inti

### 3.1 Klausul 6.1.1: risiko dan peluang ISMS

Organisasi memakai isu 4.1 dan persyaratan 4.2 untuk menentukan risiko dan peluang yang perlu ditangani agar ISMS mencapai hasilnya, efek yang tidak diinginkan berkurang, dan perbaikan berkelanjutan tercapai. Lalu organisasi merencanakan tindakan, cara memasukkannya ke proses ISMS, dan cara menilai efektivitasnya [S1].

Contoh risiko ISMS: pimpinan berganti dan anggaran hilang; contoh peluang: SOAR mengotomasi pengumpulan bukti. Risiko ini tidak wajib dinilai dengan metodologi 6.1.2. Yang masuk risk register dan menentukan kontrol adalah risiko keamanan informasi: kemungkinan hilangnya confidentiality, integrity, atau availability informasi di dalam scope.

### 3.2 Klausul 6.1.2: proses risk assessment

Organisasi menetapkan dan menerapkan proses risk assessment yang [S1]:

- a. menetapkan dan memelihara kriteria risiko, yaitu kriteria penerimaan risiko dan kriteria untuk menjalankan penilaian;
- b. memastikan penilaian berulang menghasilkan hasil yang konsisten, valid, dan bisa dibandingkan;
- c. mengidentifikasi risiko hilangnya C, I, atau A informasi di dalam scope, serta risk owner tiap risiko;
- d. menganalisis risiko: konsekuensi bila terjadi, kemungkinan realistisnya, lalu level risikonya;
- e. mengevaluasi risiko: membandingkan hasil analisis dengan kriteria di butir a, lalu memprioritaskan risiko untuk treatment.

Informasi tentang proses ini wajib disimpan, biasanya sebagai dokumen metodologi risiko. Butir b sering diremehkan: bila skala berganti dari 1-3 ke 1-5 di tengah siklus, tidak terlihat lagi apakah risiko benar-benar turun atau hanya skalanya yang berubah [S1].

### 3.3 Cara mengidentifikasi risiko: berbasis kejadian atau berbasis aset

ISO 27001 tidak menentukan metode identifikasi (edisi 2005 masih mengarahkan ke aset, ancaman, dan kerentanan). ISO/IEC 27005:2022, sebuah panduan, menjelaskan dua pendekatan [S3]:

- **Berbasis kejadian (event-based):** mulai dari sumber risiko dan skenario (siapa menyerang, tujuannya, dampaknya). Cocok untuk penilaian tingkat tinggi.
- **Berbasis aset (asset-based):** mulai dari daftar aset, lalu ancaman dan kerentanannya. Cocok untuk penilaian rinci sistem penting.

27005:2022 juga memakai istilah "consequence" (bukan "impact") agar selaras dengan ISO 31000:2018 [S3]. Pendekatan berbasis kejadian terasa alami bagi SOC karena mirip threat modeling: skenario "operator ransomware masuk lewat panel manajemen yang terekspos" langsung menunjukkan kontrol deteksi yang dibutuhkan.

### 3.4 Merancang kriteria risiko dan memilih risk owner

Kriteria terdiri dari cara menilai (skala kemungkinan, skala konsekuensi, rumus level) dan kriteria penerimaan (level yang boleh diterima tanpa treatment, dan oleh siapa). Bentuknya bebas asalkan cocok dengan konteks bisnis [S5].

Contoh umum adalah matriks 5x5 (level = kemungkinan x konsekuensi), pendekatan semi-kuantitatif yang angkanya hanya mengurutkan. Perkalian dua bilangan 1-5 tidak pernah menghasilkan 7, 11, 13, atau 14, jadi batas pita level dibuat dengan menyadari celah itu.

Risk owner adalah orang yang punya akuntabilitas dan wewenang mengelola sebuah risiko, belum tentu pemilik aset. Untuk risiko "log VM pelanggan tidak masuk SIEM", pemilik yang wajar adalah Lead SOC atau Head of Platform, bukan analyst L1 tanpa wewenang anggaran. Risk owner ditunjuk di 6.1.2 c dan di 6.1.3 f menyetujui risk treatment plan serta menerima risiko sisa (residual risk) [S1][S8].

### 3.5 Klausul 6.1.3: proses risk treatment

Organisasi menetapkan dan menerapkan proses risk treatment untuk [S8]:

- a. memilih opsi treatment berdasarkan hasil risk assessment;
- b. menentukan semua kontrol yang dibutuhkan untuk menjalankan opsi itu;
- c. membandingkan kontrol itu dengan Annex A untuk memastikan tidak ada yang terlewat;
- d. menyusun Statement of Applicability (bagian 3.6);
- e. merumuskan risk treatment plan;
- f. meminta persetujuan risk owner atas rencana itu dan penerimaan risiko sisa.

Informasi tentang proses ini juga wajib disimpan.

Catatan di 6.1.3 menjelaskan posisi Annex A [S8]. Kontrol boleh dirancang sendiri atau diambil dari sumber mana pun (CIS Controls, NIST). Annex A adalah daftar kontrol yang mungkin dipakai, tempat memeriksa agar tidak ada kontrol penting yang terlewat, dan daftarnya tidak lengkap secara mutlak sehingga kontrol tambahan boleh dimasukkan. Catatan terakhir menyebut proses treatment ini selaras dengan prinsip ISO 31000. Edisi 2022 tidak lagi memakai istilah control objectives, dan Annex A bukan "persyaratan minimum" seperti yang kadang ditulis ringkasan vendor.

Opsi treatment di 27005 [S6]:

- **Modify:** mengubah kontrol untuk menurunkan kemungkinan atau konsekuensi, misalnya rule deteksi baru.
- **Retain:** menerima risiko tanpa kontrol tambahan, misalnya risiko rendah yang diterima risk owner.
- **Avoid:** menghentikan aktivitas penyebab risiko, misalnya mencabut akses internet panel manajemen.
- **Share:** membagi konsekuensi dengan pihak lain, misalnya asuransi siber atau kontrak colocation.

ISO27k mengkritik 27005:2022 karena hampir hanya membahas modify [S6], padahal avoid sering menjadi opsi termurah.

### 3.6 Statement of Applicability

Menurut 6.1.3 d, SoA memuat [S4][S8]:

- kontrol yang dibutuhkan (hasil butir b dan c);
- alasan setiap kontrol dimasukkan;
- apakah kontrol itu sudah diterapkan atau belum;
- alasan setiap kontrol Annex A yang dikecualikan.

Auditor membaca SoA bersama risk register: setiap kontrol harus bisa ditelusuri ke risiko, kontrak, atau regulasi. Auditor NQA (Maret 2026) mencatat lima kesalahan umum: semua kontrol ditandai berlaku secara defensif, risiko terlalu umum sehingga tidak tersambung ke kontrol, SoA disalin dari organisasi lain, alasan pengecualian lemah, dan SoA tidak diperbarui saat risiko berubah [S4]. Atribut kontrol 27002:2022 (misalnya control type) bisa memperkuat alasan pemilihan, tetapi jarang dimanfaatkan [S7].

### 3.7 Klausul 6.2: sasaran keamanan informasi

Sasaran ditetapkan pada fungsi dan level yang relevan, dan harus [S2]: (a) konsisten dengan kebijakan keamanan informasi; (b) terukur bila praktis; (c) mempertimbangkan persyaratan keamanan yang berlaku serta hasil risk assessment dan risk treatment; (d) dipantau; (e) dikomunikasikan; (f) diperbarui bila perlu; (g) tersedia sebagai informasi terdokumentasi.

Butir d dan g eksplisit sejak 2022 [S2]. Rencana pencapaiannya menyebut apa yang dikerjakan, sumber daya, penanggung jawab, tenggat, dan cara mengevaluasi hasil. Auditor mencari jalur dari sasaran ke metrik dan laporan rutin: "meningkatkan keamanan" tidak bisa diaudit, sedangkan "cakupan log server in-scope minimal 98% per bulan" bisa.

### 3.8 Klausul 6.3: perencanaan perubahan

Klausul baru di 2022 ini pendek: bila organisasi memutuskan ISMS perlu diubah, perubahan dijalankan secara terencana [S2]. Formatnya bebas; rencana yang wajar menyebut tujuan, dampak ke ISMS, risiko selama transisi, sumber daya, penanggung jawab, dan kriteria selesai. Bedakan dengan kontrol 8.32 Change management untuk perubahan sistem. Memindahkan sumber log dari Splunk ke Wazuh adalah perubahan teknis (8.32), tetapi juga mengubah cara ISMS membuktikan logging dan monitoring, sehingga perlu direncanakan menurut 6.3.

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
| R-04 | Akun default di image VM dipakai penyerang masuk ke VM pelanggan | Head of Platform | 4 | 4 | 16 Tinggi | Modify | 8.9; 8.16 | 2 | 4 | 8 Sedang |
| R-09 | Log VM pelanggan tidak masuk SIEM selama migrasi | Lead SOC | 3 | 3 | 9 Sedang | Modify | 8.15; 8.16; rencana perubahan CH-02 | 1 | 3 | 3 Rendah |
| R-11 | Ransomware masuk lewat panel hypervisor yang terekspos ke internet | Head of Platform | 3 | 5 | 15 Tinggi | Avoid | Panel dipindah ke belakang VPN; 8.20 | 1 | 5 | 5 Rendah |
| R-15 | Banjir membuat DC Jakarta-1 tidak tersedia lebih dari 24 jam | Direktur Ops | 2 | 5 | 10 Sedang | Share + Modify | Asuransi; kontrak colocation; 7.5; 5.30 | 2 | 4 | 8 Sedang |
| R-20 | Alert prioritas rendah salah ditriage pada shift malam | Lead SOC | 3 | 2 | 6 Rendah | Retain | Kontrol yang ada cukup; QA sampling bulanan | 3 | 2 | 6 Rendah |

Cara membaca:

- **Level dihitung, bukan ditebak:** level awal 4x4 = 16, 3x3 = 9, 3x5 = 15, 2x5 = 10, 3x2 = 6; level sisa 2x4 = 8, 1x3 = 3, 1x5 = 5, 2x4 = 8, 3x2 = 6. Semua jatuh di pita yang benar menurut bagian 4.1.
- **R-11 memakai avoid:** paparan ke internet dihentikan, jadi kemungkinan turun ke 1 walaupun konsekuensi tetap 5.
- **R-15 tetap Sedang:** asuransi membagi beban finansial tetapi tidak menjaga layanan tetap tersedia, dan 7.5 serta 5.30 hanya menurunkan konsekuensi ke 4. Direktur Ops menerima level 8 dengan alasan tertulis.
- **R-20 memakai retain:** keputusan tetap dicatat.
- **R-09 tersambung ke perubahan CH-02 (6.3):** risiko muncul justru karena perubahan yang direncanakan.

### 4.3 Cuplikan Statement of Applicability

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

### 4.4 Sasaran keamanan SOC (6.2)

| Sasaran | Metrik | Target | Pemilik | Frekuensi ukur | Sumber data |
|---|---|---|---|---|---|
| S-01 Cakupan log server in-scope | Server in-scope yang mengirim log 24 jam terakhir dibagi total server in-scope | >= 98% per bulan mulai Q2 2026 | Lead SOC | Bulanan | SIEM, daftar aset |
| S-02 Respons insiden prioritas tinggi | Median waktu alert sampai containment | <= 4 jam | Lead SOC | Bulanan | Tiket insiden |
| S-03 Sinkronisasi waktu | Host in-scope dengan selisih lebih dari 1 detik dari NTP internal | 0 host, 3 bulan berturut-turut | Head of Platform | Mingguan | Laporan NTP |

Rumus, target, dan sumber data membuat sasaran memenuhi butir b dan d di 6.2 dan bisa dilaporkan sebagai hasil monitoring (9.1).

## 5. Lab praktik

Latihan untuk organisasi fiktifmu. Simpan di `latihan/day04-<nama-org-fiktif>.md`.

1. Tulis kriteria risiko: skala kemungkinan dan konsekuensi 1-5, rumus level, dan tiga pita penerimaan beserta siapa yang boleh menerima.
2. Identifikasi 6 risiko, minimal dua berbasis kejadian dan dua berbasis aset, masing-masing dengan risk owner yang punya wewenang.
3. Hitung level awal dan level sisa, lalu hitung ulang setiap perkalian.
4. Pilih opsi treatment; avoid, share, dan retain masing-masing dipakai minimal sekali.
5. Susun SoA minimal 10 kontrol, termasuk 2 pengecualian; setiap baris "Ya" punya rujukan.
6. Tulis 3 sasaran SOC dengan format bagian 4.4 dan cek butir 6.2 a-g untuk tiap sasaran.
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

## 6. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Hampir semua risiko jatuh di pita Tinggi | Skala konsekuensi terlalu sensitif | Kalibrasi skala dengan dua atau tiga kejadian contoh yang disepakati |
| SoA dan register tidak cocok | Disusun oleh orang atau waktu berbeda | Tambahkan kolom rujukan di SoA; tinjau keduanya dalam satu sesi |
| Sasaran tidak bisa diukur | Tidak ada sumber data atau rumus | Tulis rumus dan sumber data; bila belum ada, sasaran pertamanya membangun pengukuran |

## 7. Kesalahan umum dan jebakan

- Menandai semua 93 kontrol "berlaku" atau memutus register dari SoA; keduanya dibahas di bagian 3.6 [S4].
- Tidak punya kriteria tertulis untuk menjalankan risk assessment, sehingga hasil tiap siklus tidak konsisten. URM melaporkan temuan ini di audit 2026 [S7].
- Lupa meminta persetujuan risk owner (6.1.3 f), sehingga risk treatment plan secara formal belum selesai.
- `[komunitas, belum terkonfirmasi]` Di forum tanya-jawab Advisera, ambang angka (misalnya level di atas 7 wajib treatment) disebut sebagai salah satu bentuk kriteria penerimaan yang sah [S5]. Pilihan ambang tetap keputusan organisasi.

## 8. Catatan terkini

- Per Oktober 2026, katalog ISO menampilkan ISO/IEC 27005:2022 (edisi 4) sebagai edisi berlaku tanpa tahap revisi [S9]. Situs ISO27k (Agustus 2026) melaporkan working group sedang membahas pendekatan revisi, termasuk kemungkinan menjadi standar multi-bagian [S6]; itu baru pembahasan, belum proyek resmi.

## 9. Cheat sheet

```
6.1.1  risiko & peluang ISMS (dari 4.1/4.2): rencanakan tindakan, integrasikan, nilai efektivitas
6.1.2  a kriteria (penerimaan + cara menilai) | b konsisten, valid, bisa dibandingkan
       c identifikasi risiko CIA + risk owner | d analisis (konsekuensi, kemungkinan, level)
       e evaluasi vs kriteria + prioritas
6.1.3  a opsi | b kontrol (sumber apa pun) | c bandingkan Annex A | d SoA | e RTP
       f risk owner setujui RTP + terima risiko sisa
       Annex A = daftar kontrol yang mungkin, tidak lengkap mutlak; boleh tambah kontrol
SoA    kontrol yang dibutuhkan | alasan masuk | diterapkan atau belum | alasan pengecualian
6.2    a konsisten kebijakan | b terukur bila praktis | c pertimbangkan persyaratan + hasil RA/RT
       d dipantau | e dikomunikasikan | f diperbarui | g terdokumentasi
       rencana: apa, sumber daya, siapa, kapan, cara evaluasi
6.3    perubahan ISMS direncanakan (baru 2022)  != 8.32 change management teknis
8.2/8.3 = menjalankan RA/RT dan menyimpan hasilnya

Opsi (27005): modify | retain | avoid | share
Matriks 5x5: K x C, hasil mungkin 1-6,8,9,10,12,15,16,20,25 (tidak ada 7,11,13,14)
Event-based = skenario dari sumber risiko | Asset-based = aset, ancaman, kerentanan
27005:2022 ed.4 (25 Okt 2022): "consequence" bukan "impact"; selaras ISO 31000:2018
```

## 10. Sumber

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

**Catatan sumber:** rincian catatan Annex A di 6.1.3 hanya dikonfirmasi sebagian oleh ringkasan sekunder [S8]. Pembahasan revisi 27005 [S6] belum tercermin di katalog ISO [S9]. Keluaran SPL di bagian 5 adalah ilustrasi.
