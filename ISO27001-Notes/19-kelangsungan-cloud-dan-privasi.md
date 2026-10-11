---
day: 19
title: 'Memperluas ISMS: kelangsungan layanan, cloud, dan privasi'
researched_on: 2026-10-10
versions_checked: 'ISO 22301:2019 edisi 2 + Amd 1:2024 (stage 90.92, akan direvisi; ISO/CD 22301 sedang disusun); ISO/IEC 27031:2025 edisi 2, terbit 2025-05-16, menggantikan 27031:2011; ISO/IEC 27017:2026 edisi 2, terbit 2026-07-27, menggantikan 27017:2015; ISO/IEC 27018:2025 edisi 3, terbit 2025-08-26, menggantikan 27018:2019; ISO/IEC 27701:2025 edisi 2, terbit 2025-10-14, standar sistem manajemen mandiri; ISO/IEC 27706:2025 edisi 1, terbit 2025-10-14, menggantikan ISO/IEC TS 27006-2:2021'
---

# Day 19: Memperluas ISMS

Cakupan: standar yang paling sering ditambahkan di atas ISO 27001 untuk kelangsungan (22301, 27031), cloud (27017, 27018), dan privasi (27701), apa yang masing-masing tambahkan, sifat dan edisi berlakunya, dan cara memutuskan apakah organisasimu perlu menambah standar atau cukup memperluas ISMS tanpa menggandakan pekerjaan.

## Ide inti

Annex A hanya menyentuh secara umum tiga hal: kesiapan layanan menghadapi gangguan (kontrol 5.29 dan 5.30), pembagian tanggung jawab antara penyedia dan pengguna layanan cloud (5.23), dan kewajiban terhadap data pribadi di luar soal keamanan (5.34). Untuk ketiganya ada standar tambahan dengan rincian yang jauh lebih dalam. Gagasan inti Day ini: standar tambahan adalah alat untuk menutup celah tertentu di ISMS, bukan koleksi sertifikat. Pertanyaannya selalu berurutan: celah apa yang tidak tertutup ISMS, apakah ada pihak luar yang meminta sertifikat, dan apakah ISMS yang ada sudah stabil. Untuk organisasi menengah, jawabannya paling sering memperluas ISMS dengan standar itu sebagai panduan, dengan satu register risiko, satu program audit, dan satu management review.

Ada masalah praktis yang menyertainya: empat dari standar itu direvisi dalam rentang Mei 2025 sampai Juli 2026, sehingga banyak artikel, templat, dan materi pelatihan yang beredar masih merujuk edisi yang sudah ditarik, lengkap dengan penomoran kontrol 27002:2013. Sebelum memakai perbandingan kontrol apa pun, periksa edisinya.

Kamu sudah mengenal pola ini dari SIEM. Saat organisasi mulai memakai cloud, tim SOC tidak membangun SIEM kedua; mereka memasang content pack atau app khusus cloud di SIEM yang sama, yang memperdalam deteksi untuk domain itu dengan memakai pipeline, dashboard, dan proses triage yang sudah ada. Standar tambahan bekerja dengan cara yang sama terhadap ISMS. Batas analoginya: 22301 dan 27701 juga bisa menjadi sistem manajemen sendiri dengan sertifikat terpisah, sedangkan 27031, 27017, dan 27018 hanya panduan.

```
Kewajiban atau permintaan baru (klien, regulator, risiko)
  -> apakah Annex A sudah menutupnya? (5.29/5.30, 5.23, 5.34 hanya umum)
  -> pilih standar yang memperdalam celah itu
       kelangsungan: 22301 (persyaratan), 27031 (panduan)
       cloud:        27017, 27018 (panduan kontrol)
       privasi:      27701:2025 (persyaratan, sistem manajemen mandiri)
  -> empat pertanyaan keputusan: diminta? tanpa padanan? ISMS stabil? beban sebanding?
  -> paling sering: perluas ISMS dengan standar sebagai panduan
       satu register, satu program audit, satu management review
       terpisah hanya bila memang perlu (SoA untuk katalog kontrol baru)
```

Situasi yang dipakai sepanjang Day ini: April 2027, Direktur Operasional PT Awan Nusantara (PT AN, penyedia hosting fiktif) meneruskan tiga hal ke ISMS Manager dan Lead SOC dalam satu pesan:

> "1. Klien sektor kesehatan menanyakan apakah kita punya sertifikat ISO/IEC 27701, dan akan mensyaratkannya di pengadaan tahun depan.
> 2. Klien bank bertanya bagaimana layanan managed VM tetap berjalan bila DC Jakarta-1 terganggu, dan kapan rencana pemulihan kita terakhir diuji.
> 3. Tim Platform bilang backup aplikasi internal kita di penyedia cloud sudah aman karena penyedianya bersertifikat ISO/IEC 27017.
> Apakah artinya kita butuh tiga sertifikat baru?"

Pertanyaan pertama menyangkut privasi (bagian 1.4), kedua kelangsungan (bagian 1.2), dan ketiga pembagian tanggung jawab cloud (bagian 1.3). Pertanyaan penutupnya dijawab oleh cara memutuskan dan menambah tanpa menggandakan (bagian 1.5 dan 1.6). Peta standar dan sifatnya ada di bagian 1.1.

**Kapan relevan:** klien atau regulator menanyakan kelangsungan layanan, sertifikat privasi, atau pembagian tanggung jawab cloud; kewajiban yang kamu petakan di Day 18 tidak punya padanan di ISMS; kamu menilai penyedia cloud (Day 12).
**Kapan bukan jawaban:** standar tambahan tidak memperbaiki ISMS yang belum stabil, dan sertifikat penyedia cloud tidak memindahkan tanggung jawab sisi pengguna. Day ini juga tidak menjelaskan isi kewajiban UU PDP (Day 18).

## 1. Konsep inti

### 1.0 Istilah di Day ini

Tabel ini memuat istilah yang muncul di Day ini. Istilah UU PDP (PPDP, DPIA, subjek data) dijelaskan di Day 18, dan aturan badan sertifikasi (17021-1, akreditasi) di Day 17.

| Istilah | Arti singkat | Padanan di SOC |
|---|---|---|
| Standar persyaratan vs panduan | Persyaratan (shall) bisa disertifikasi; panduan (should) hanya membantu penerapan | Requirement vs runbook |
| Edisi ditarik (withdrawn) | Edisi lama yang sudah diganti dan tidak lagi berlaku di katalog ISO | Ruleset versi lama yang sudah deprecated |
| BCMS | Business continuity management system, sistem manajemen kelangsungan bisnis (22301) | Program DR yang punya pemilik, target, latihan, dan review |
| BIA (business impact analysis) | Analisis dampak gangguan per aktivitas dan seberapa cepat dampaknya bertambah | Menentukan layanan mana yang paling parah bila mati dan berapa lama boleh mati |
| RTO / RPO | Target waktu pemulihan / batas data yang boleh hilang | SLA pemulihan SIEM / berapa jam log yang boleh hilang bila indexer rusak |
| Kesiapan ICT | Kemampuan ICT mencegah, merespons, dan pulih dari gangguan (27031) | Uji failover dan restore yang benar-benar dijalankan |
| Cloud service customer / provider | Pengguna dan penyedia layanan cloud | Tim SOC dan vendor SIEM SaaS |
| Matriks pembagian tanggung jawab | Daftar siapa menangani tiap kontrol untuk tiap layanan cloud | RACI dengan vendor SIEM SaaS: platform di vendor, rule dan onboarding log di kamu |
| PII controller / processor | Pihak yang menentukan tujuan pemrosesan data pribadi / pihak yang memprosesnya atas nama controller | Klien MSSP pemilik log / MSSP yang memproses log itu |
| PIMS | Privacy information management system, sistem manajemen informasi privasi (27701) | Proses privasi yang dikelola seperti ISMS |
| ISO/IEC 27706 | Persyaratan untuk badan sertifikasi PIMS, di atas 17021-1 | Padanan 27006-1 untuk privasi (Day 17) |

### 1.1 Peta standar tambahan: celah, sifat, dan edisi berlaku

Pesan Direktur Operasional menyebut tiga standar sekaligus, dan tidak semuanya bisa disertifikasi. Sebelum menjawab, kamu perlu tahu standar mana yang menutup celah apa dan apa sifatnya. Tabel berikut adalah petanya; cari kolom Sifat untuk tahu mana yang bisa menghasilkan sertifikat, dan kolom Edisi berlaku untuk menolak materi yang memakai edisi lama. Pemetaan ke kontrol Annex A di kolom kedua adalah cara baca Day ini, bukan pemetaan resmi.

| Standar | Celah Annex A yang diperdalam | Sifat | Edisi berlaku |
|---|---|---|---|
| ISO 22301 | 5.29, 5.30 kelangsungan | Persyaratan, bisa disertifikasi | ISO 22301:2019 + Amd 1:2024 [S6] |
| ISO/IEC 27031 | 5.30 kesiapan ICT | Panduan | ISO/IEC 27031:2025 [S7] |
| ISO/IEC 27017 | 5.23 layanan cloud | Panduan kontrol | ISO/IEC 27017:2026 [S8] |
| ISO/IEC 27018 | 5.23 dan 5.34, PII di public cloud | Panduan kontrol | ISO/IEC 27018:2025 [S9] |
| ISO/IEC 27701 | 5.34 privasi | Persyaratan, sistem manajemen mandiri | ISO/IEC 27701:2025 [S5] |

Konsekuensinya untuk pekerjaanmu:

- Perbandingan kontrol dan templat dari internet hampir pasti merujuk edisi lama. Periksa tanggal terbit tulisannya dan edisi yang dirujuk. Tanggal penarikan tiap edisi lama ada di bagian 6.
- Edisi baru 27017 dan 27018 kini dibangun di atas 27002:2022 (empat tema, 93 kontrol), sehingga pemetaan lama berbasis nomor 2013 (misalnya A.12.4.1) perlu dipetakan ulang [S8][S9].
- Bila organisasimu atau pemasokmu tersertifikasi 27701:2019, ada masa transisi yang ditetapkan badan akreditasi (bagian 1.4 dan 6).

### 1.2 Kesiapan layanan menghadapi gangguan: 22301 dan 27031

Pertanyaan klien bank tentang DC Jakarta-1 punya dua bagian: apa rencananya, dan kapan terakhir diuji. Annex A 27001:2022 sudah punya dua kontrol kelangsungan: 5.29 meminta keamanan informasi tetap terjaga saat gangguan, dan 5.30 meminta kesiapan ICT direncanakan, diterapkan, dipelihara, dan diuji berdasarkan sasaran kelangsungan bisnis. Kontrol pendukungnya 8.13 (backup) dan 8.14 (redundansi fasilitas pemrosesan). Dua standar di bawah ini memperdalamnya dari arah berbeda.

**ISO 22301:2019** adalah standar persyaratan sistem manajemen kelangsungan bisnis (BCMS) dengan struktur klausul 4-10 yang sama dengan 27001 [S6]. Yang ia tambahkan ada di klausul 8 [S10]. Tabel berikut menunjukkan subklausul itu; perhatikan bahwa 8.5 dan 8.6 menuntut latihan dan evaluasi, bukan hanya dokumen rencana.

| Klausul | Isi |
|---|---|
| 8.2 | Business impact analysis (BIA) dan penilaian risiko: aktivitas yang mendukung produk dan layanan, bagaimana dampak bertambah seiring lamanya gangguan, prioritas waktu pemulihan (RTO), serta ketergantungan dan sumber daya pendukung |
| 8.3 | Strategi dan solusi kelangsungan, termasuk kebutuhan sumber dayanya |
| 8.4 | Rencana dan prosedur: struktur respons, peringatan dan komunikasi, rencana kelangsungan, pemulihan |
| 8.5 | Program latihan (exercise) |
| 8.6 | Evaluasi dokumentasi dan kemampuan kelangsungan |

Amd 1:2024 menambah pertimbangan perubahan iklim, sejalan dengan amandemen 27001. Status revisi 22301 dicatat di bagian 6, dan perlu diperhitungkan bila kamu merencanakan BCMS.

**ISO/IEC 27031:2025** adalah panduan kesiapan ICT untuk kelangsungan bisnis: kerangka metode dan proses untuk membuat ICT siap mencegah, merespons, dan pulih dari gangguan, dari serangan siber sampai kegagalan sistem [S7]. Ia melengkapi 27001 di sisi kontinuitas ICT dan mendukung 22301 dengan menyelaraskan kesiapan ICT ke sasaran kelangsungan bisnis. 27031:2025 juga membahas ketergantungan pada layanan eksternal seperti penyedia cloud [S7].

Untuk organisasi menengah, jalur yang masuk akal biasanya memperkuat kontrol 5.29, 5.30, 8.13, dan 8.14 di dalam ISMS memakai 27031 sebagai panduan, lalu mempertimbangkan BCMS 22301 tersendiri hanya bila pelanggan atau regulator memintanya. Apa pun jalurnya, periksa dulu apakah sudah ada BIA yang nyata dan apakah rencana pemulihan pernah diuji dengan pemulihan sungguhan. Di Indonesia, sebagian regulasi sektor menuntut uji ini secara eksplisit, misalnya DRP bank yang diuji minimal setahun sekali (Day 18). Bagi klien bank yang terikat kewajiban seperti itu, tanggal uji terakhir lebih bermakna daripada keberadaan rencana. Daftar periksa dasarnya ada di bagian 2.3.

### 1.3 Cloud: 27017 dan 27018

Klaim tim Platform ("backup aman karena penyedianya bersertifikat 27017") mencampur dua hal: apa yang dijamin sertifikat penyedia dan apa yang tetap menjadi tugas pengguna. Polanya sama dengan mengelola vendor SIEM SaaS: vendor menjaga platform tetap hidup, tetapi rule, onboarding log, dan tinjauan alert tetap tugas tim SOC, dan akuntabilitasnya tetap di organisasimu.

**ISO/IEC 27017:2026** adalah panduan kontrol keamanan informasi untuk layanan cloud berbasis 27002 [S8]. Yang ia tambahkan:

- panduan tambahan untuk kontrol 27002:2022 yang relevan, ditulis berdampingan untuk cloud service customer dan cloud service provider;
- kontrol tambahan khusus cloud, untuk risiko dan tanggung jawab yang tidak ada di 27002;
- penjelasan cara kontrol berlaku ketika tanggung jawab, infrastruktur, dan operasi terbagi antara beberapa pihak;
- cakupan public, private, dan hybrid cloud; untuk private cloud, kontrol perlu disesuaikan dengan hubungan antar departemen internal.

Menurut ringkasan iso27001security.com, edisi 2026 menambah empat kontrol di atas 93 kontrol 27002: 5.38 dan 5.39 (peran dan tanggung jawab bersama yang disepakati), 8.35 (segregasi di lingkungan komputasi virtual), dan 8.36 (mendeteksi dan mencegah pemakaian layanan cloud yang tidak sah), ditambah Annex A pemetaan edisi 2015 ke 2026 dan Annex B tentang pemantauan keamanan cloud [S11]. Nomor dan judul kontrol edisi 2026 perlu dicocokkan dengan teks standar sebelum dipakai di SoA. Kontrol edisi 2015 yang masih beredar di templat dicatat di bagian 6.

**ISO/IEC 27018:2025** adalah panduan pelindungan PII di public cloud yang bertindak sebagai PII processor [S9]. Ia menyesuaikan kontrol 27002 untuk pemrosesan PII di cloud, mencakup pengumpulan, penyimpanan, pemrosesan, transmisi, dan penghapusan, dan dirancang melengkapi ISMS berbasis 27001. Contoh kontrol tambahannya: penyedia memberi tahu pelanggan bila memakai subkontraktor untuk memproses PII [S12].

Nilai terbesar keduanya ada pada kerangka pembagian tanggung jawab, bukan pada sertifikatnya. Banyak kegagalan di lingkungan cloud berasal dari asumsi bahwa penyedia menangani sesuatu yang sebenarnya tanggung jawab pengguna, atau sebaliknya. Dua pemakaian yang paling langsung:

1. **Daftar periksa saat menilai penyedia** (Day 12): tanyakan sisi mana yang mereka tangani untuk kontrol yang penting bagimu, dan apakah sertifikat 27017/27018 mereka sudah memakai edisi baru.
2. **Dasar matriks tanggung jawab internal** (bagian 2.2): siapa menangani apa untuk tiap layanan cloud, lalu uji asumsinya.

Sertifikasi penyedia tidak memindahkan tanggung jawabmu. Kontrol 5.23 tetap menuntut organisasimu sendiri menetapkan proses pemakaian layanan cloud, dan sisi pengguna tetap akan ditanyakan auditor maupun regulator. Untuk backup di pesan Direktur Operasional, matriks di bagian 2.2 menunjukkan jawabannya: backup data aplikasi adalah tanggung jawab pengguna kecuali penyedia menyatakan sebaliknya.

### 1.4 Privasi: 27701:2025 sebagai sistem manajemen mandiri

Klien sektor kesehatan meminta sertifikat 27701. Untuk menjawabnya, kamu perlu tahu apa 27701 sekarang, karena banyak materi yang beredar masih menggambarkan edisi yang sudah ditarik. ISO/IEC 27701:2025 berjudul sistem manajemen informasi privasi, persyaratan dan panduan, dan katalog ISO menyebutnya standar sistem manajemen yang independen dan bisa dipakai sendiri, untuk PII controller maupun PII processor [S5]. Edisi 2019 berjudul perluasan (extension) terhadap 27001 dan 27002 [S4], sehingga hanya bisa diterapkan dan disertifikasi bersama ISMS; perubahan ini menentukan apakah privasi bisa disertifikasi tanpa ISMS. Isi 27701:2025 [S13]:

- klausul 4-10 sendiri dengan struktur sistem manajemen yang sama seperti 27001 (konteks, kepemimpinan, perencanaan, dukungan, operasi, evaluasi kinerja, perbaikan);
- Annex A berupa katalog kontrol privasi untuk controller dan processor, bergaya seperti Annex A 27001;
- tetap bisa diintegrasikan dengan ISMS untuk mengurangi duplikasi.

Sertifikasinya dilakukan badan sertifikasi yang memenuhi ISO/IEC 27706:2025, yang menambah persyaratan di atas 17021-1 (Day 17) [S14]. Saat menanyakan perkiraan audit, tanyakan ke badan sertifikasi yang berakreditasi untuk 27706. Masa transisi sertifikat 27701:2019 ditetapkan per badan akreditasi; contoh tenggat dan status di KAN dicatat di bagian 6.

Kapan ini relevan bagimu: ketika kewajiban yang kamu petakan di Day 18 memuat hal yang tidak punya padanan di ISMS, terutama dasar pemrosesan, DPIA, dan hak subjek data dengan tenggat 3 x 24 jam. Karena 27701:2025 bisa berdiri sendiri, organisasi yang tidak butuh ISMS tersertifikasi pun kini bisa memakainya. Kapan belum relevan: ketika ISMS-mu sendiri belum stabil. Menambahkan sistem manajemen kedua di atas yang pertama yang masih goyah menggandakan beban tanpa menambah kepatuhan.

### 1.5 Memutuskan: tambah standar atau perluas ISMS

Pertanyaan penutup Direktur Operasional ("tiga sertifikat baru?") dijawab dengan urutan pertanyaan yang sama untuk tiap standar. Pertanyaan yang menentukan, berurutan:

```
1. Apakah ada pihak luar yang MEMINTA sertifikat terhadap standar itu?
   ya  -> pertimbangkan sertifikasi; hitung biayanya (Day 17)
   tidak -> lanjut

2. Apakah ada kewajiban yang TIDAK PUNYA PADANAN di ISMS-mu? (Day 18 bagian 2.2)
   ya  -> perluas ISMS dengan kerangka dari standar itu, tanpa sertifikasi
   tidak -> lanjut

3. Apakah ISMS yang ada SUDAH STABIL? (audit internal berjalan, temuan ditutup efektif)
   tidak -> perbaiki itu dulu; jangan menambah sistem kedua
   ya  -> lanjut

4. Apakah penambahan ini akan menambah BEBAN TATA KELOLA yang tidak sebanding?
   ya  -> pakai standarnya sebagai panduan, bukan sebagai sistem manajemen baru
```

Untuk organisasi menengah, jalur yang paling sering tepat adalah memakai standar tambahan sebagai panduan untuk memperkuat ISMS. Sertifikasi tambahan masuk akal ketika ada permintaan pasar yang nyata, dan itu keputusan bisnis. Untuk PT AN, hanya pertanyaan pertama di pesan Direktur yang memuat permintaan sertifikat; hasil empat pertanyaan untuk 27701 ada di lembar keputusan bagian 2.1.

### 1.6 Menambah tanpa menggandakan

Bila PT AN memutuskan menambah, pertanyaan berikutnya adalah bagaimana caranya tanpa membuat tim yang sama mengerjakan dua kali. Prinsip yang sama seperti Day 18 berlaku: satu register risiko (risiko privasi dan kelangsungan masuk register yang sama), satu program audit dengan lingkup diperluas, satu management review dengan agenda ditambah, satu jalur tindakan korektif, dan prosedur yang diperluas, bukan diduplikasi. Seperti content pack di SIEM yang sama, yang ditambah adalah isinya, bukan platformnya.

Yang memang perlu terpisah: pernyataan keberlakuan untuk lingkup baru (27701:2025 punya Annex A sendiri), bukti spesifik yang diminta auditor untuk standar itu, dan peran baru bila standarnya menuntutnya.

Uji sederhananya: bila orang yang sama diminta memberikan bukti yang sama kepada dua proses berbeda, kamu sedang menggandakan. Rencana per unsur ISMS ada di bagian 2.4.

## 2. Contoh dokumen / artefak (organisasi fiktif)

> Seluruh isi di bawah adalah contoh untuk organisasi fiktif PT AN. Nomor kontrol tambahan 27017:2026 hanya dipakai sebagai ilustrasi; cocokkan dengan teks standar.

### 2.1 Lembar keputusan penambahan standar

Lembar ini menjalankan empat pertanyaan di bagian 1.5 untuk permintaan klien sektor kesehatan di pesan Direktur Operasional.

```
LEMBAR KEPUTUSAN                              Nomor: KS-2027-002
Standar yang dipertimbangkan : ISO/IEC 27701:2025 (PIMS)
Disusun oleh                 : <nama>          Tanggal: 2027-04-10

1. PERMINTAAN PASAR
   Dua pelanggan menanyakan; satu mensyaratkan dalam proses pengadaan tahun depan.
   Nilai kontrak terkait: <angka>

2. CELAH YANG TIDAK TERTUTUP ISMS  (dari Day 18 bagian 2.2)
   dasar pemrosesan dan persetujuan   : belum ada proses
   hak subjek data (3 x 24 jam)       : belum ada proses
   DPIA (UU PDP Pasal 34)             : belum ada proses

3. KESTABILAN ISMS SAAT INI
   audit internal berjalan sesuai program          : ya
   temuan siklus terakhir ditutup dan diverifikasi : 7 dari 9; 2 masih berjalan
   penilaian                                       : cukup stabil, dengan catatan

4. PERKIRAAN BEBAN
   peran baru            : PPDP (sudah ada, perlu diperjelas perannya)
   dokumen baru          : 4 prosedur, 1 SoA PIMS terhadap Annex A 27701:2025
   audit tambahan        : <perkiraan hari, tanyakan ke badan sertifikasi berakreditasi 27706>
   biaya berkelanjutan   : <perkiraan>

REKOMENDASI
  Tahap 1 (2027): perluas ISMS dengan tiga proses di butir 2, tanpa sertifikasi.
  Tahap 2 (2028): tinjau ulang sertifikasi berdasarkan permintaan pasar nyata.
  Alasan: celah di butir 2 harus ditutup apa pun keputusan sertifikasinya, dan menutupnya
  lebih dulu membuat sertifikasi nanti jauh lebih murah.

CATATAN EDISI
  Jangan memulai dengan 27701:2019; edisi itu sudah ditarik dan sertifikatnya sedang
  ditransisikan.
```

Pola dua tahap itu sering tepat: tutup celahnya dulu, putuskan sertifikasinya kemudian.

### 2.2 Matriks pembagian tanggung jawab cloud

Matriks ini menjawab klaim tim Platform tentang backup. Baca kolom Pengguna dan dua kolom terakhir: di sanalah terlihat apa yang tetap menjadi tugas PT AN dan apakah asumsinya sudah diuji.

| Kontrol | Penyedia | Pengguna (kami) | Bukti yang kami punya | Diuji? |
|---|---|---|---|---|
| 7.1-7.4 keamanan fisik pusat data | penuh | tidak ada | laporan audit penyedia, lingkup dibaca | tidak perlu |
| 8.24 kriptografi (data saat disimpan) | menyediakan kemampuan | mengaktifkan dan mengelola kunci | konfigurasi; prosedur kunci | ya, 2027-02 |
| 5.15, 8.2 akses ke konsol | menyediakan kemampuan | konfigurasi, tinjauan berkala | hasil tinjauan hak akses | ya, 2027-01 |
| 8.13 backup data aplikasi | tidak, kecuali dinyatakan | penuh | konfigurasi backup; uji pemulihan | belum diuji |
| 8.15 logging aktivitas konsol | menyediakan kemampuan | mengaktifkan, mengumpulkan, meninjau | konfigurasi; catatan tinjauan | ya, 2027-03 |
| 5.24-5.26 respons insiden di lapis layanan | sebagian | penuh di lapis kami | prosedur IR-01 | ya, latihan meja |
| Peran dan tanggung jawab bersama (27017:2026) | menyatakan di perjanjian | memeriksa dan menyetujui | perjanjian layanan, lampiran tanggung jawab | ya, 2027-01 |

Dua kolom terakhir yang membuat matriks ini bisa diaudit. Baris backup yang belum diuji adalah temuan, dan akan muncul di audit bila kamu tidak menemukannya lebih dulu. Laporan audit penyedia hanya sah sebagai bukti bila kamu benar-benar membaca lingkupnya (Day 17 bagian 1.5).

### 2.3 Daftar periksa kesiapan layanan

Daftar ini dipakai sebelum memutuskan menambah standar kelangsungan, dan menjadi bahan jawaban untuk pertanyaan klien bank tentang DC Jakarta-1.

```
DASAR YANG HARUS ADA LEBIH DULU (padanan 22301 klausul 8.2-8.6; kontrol 5.29, 5.30)
  1. Daftar layanan dengan tingkat kepentingannya terhadap bisnis       (BIA, 8.2)
  2. Untuk tiap layanan kritis: RTO dan RPO yang disepakati pemilik bisnis
  3. Ketergantungan tiap layanan: sistem lain, pemasok, cloud, orang, lokasi
  4. Rencana pemulihan tertulis untuk layanan kritis                    (8.4)
  5. Rencana itu PERNAH DIJALANKAN, bukan hanya dibaca                  (8.5)
  6. Hasil uji dicatat, termasuk yang gagal
  7. Selisih antara target dan hasil uji ditindaklanjuti                 (8.6)

STATUS TIAP BUTIR: ada / belum

BILA ADA BUTIR YANG BELUM
  kerjakan itu dulu; menambah standar tidak akan menambah ketahanan
```

Butir kelima yang membedakan organisasi yang siap dari yang merasa siap. Rencana yang tidak pernah dijalankan hampir selalu memuat asumsi keliru, dan asumsi itu baru ketahuan saat benar-benar dibutuhkan.

### 2.4 Rencana penambahan yang tidak menggandakan

Tabel ini menerapkan bagian 1.6 ke unsur ISMS PT AN yang sudah ada. Kolom kanan adalah daftar hal yang sengaja tidak dilakukan.

| Unsur ISMS yang ada | Yang dilakukan | Yang tidak dilakukan |
|---|---|---|
| Register risiko | Tambahkan kategori risiko privasi dan kelangsungan | Membuat register kedua |
| Program audit internal | Perluas lingkup area yang diaudit | Membuat program audit kedua |
| Management review | Tambahkan masukan ke agenda | Membuat rapat tinjauan kedua |
| Tindakan korektif | Pakai jalur yang sama | Membuat sistem tiket kedua |
| Prosedur insiden | Tambahkan jalur untuk kegagalan pelindungan data pribadi | Membuat prosedur insiden kedua |
| Pernyataan keberlakuan | Buat yang terpisah untuk Annex A 27701 | Menggabungkan paksa ke yang lama |
| Peran | Perjelas peran yang sudah ada | Membuat struktur paralel |

Baris pernyataan keberlakuan adalah pengecualian yang disengaja: katalog kontrolnya berbeda, dan menggabungkannya justru menyulitkan audit.

### 2.5 Menjelaskan ke manajemen

Halaman ini menjawab pertanyaan penutup Direktur Operasional untuk kasus privasi, dalam bentuk dua pilihan dengan rekomendasi.

```
USULAN: MEMPERLUAS ISMS UNTUK PRIVASI

MASALAH YANG DISELESAIKAN
  Tiga kewajiban UU PDP dari pemetaan regulasi (Day 18) tidak punya proses sama sekali:
  dasar pemrosesan, hak subjek data dengan tenggat 3 x 24 jam, dan DPIA.
  ISMS kita memang tidak dirancang untuk itu.

DUA PILIHAN
  A. Perluas ISMS dengan tiga proses baru memakai 27701:2025 sebagai panduan, tanpa sertifikasi
     biaya: waktu tim, tanpa biaya audit tambahan
     hasil: kewajiban terpenuhi; tidak ada sertifikat untuk ditunjukkan pelanggan
  B. Perluas lalu sertifikasi 27701:2025
     biaya: pilihan A ditambah biaya audit dan biaya berkelanjutan
     hasil: kewajiban terpenuhi; ada sertifikat untuk pengadaan

REKOMENDASI
  A sekarang, tinjau B pada 2028 berdasarkan permintaan pasar yang nyata.

YANG PERLU DIPUTUSKAN HARI INI
  Persetujuan untuk pilihan A dan penunjukan pemilik ketiga proses baru.
```

Pola dua pilihan dengan rekomendasi jauh lebih mudah diputuskan daripada presentasi tentang isi standar.

## 3. Lab praktik

**Prasyarat:** hasil Day 12 (pemasok), Day 17 (sertifikasi), dan Day 18 (regulasi). Seluruh lab bersifat memeriksa katalog, menilai, dan menulis.

1. Buka halaman katalog committee.iso.org untuk kelima standar di bagian 1.1 dan catat bila ada status yang berubah sejak catatan ini ditulis, terutama 22301 yang sedang direvisi (bagian 6).
2. Cari tiga artikel online tentang 27017 atau 27701, lalu catat edisi yang dirujuk, apakah edisi itu masih berlaku, dan apakah penomoran kontrolnya memakai 27002:2013 atau 2022.
3. Isi daftar periksa kesiapan layanan bagian 2.3 untuk PT AN, lengkap dengan RTO dan RPO fiktif untuk tiga layanan, dan tandai butir yang statusnya belum.
4. Susun matriks pembagian tanggung jawab bagian 2.2 untuk tiga layanan cloud fiktif (IaaS, SaaS email, platform database terkelola). Perhatikan bagaimana kolom penyedia berubah antar model layanan.
5. Untuk satu baris matriks, uji asumsinya: baca dokumentasi shared responsibility penyedia yang kamu pakai di lab dan buktikan siapa yang bertanggung jawab. Catat bila asumsimu keliru.
6. Ambil hasil pemetaan Day 18 bagian 2.2 dan daftarkan kewajiban yang tidak punya padanan di ISMS, lalu tulis klausul atau kontrol Annex A 27701:2025 mana yang akan kamu pakai sebagai kerangka untuk tiap kewajiban.
7. Jalankan empat pertanyaan di bagian 1.5 untuk PT AN dan tulis jawabannya satu per satu, lalu susun lembar keputusan bagian 2.1.
8. Susun rencana penambahan bagian 2.4 untuk pilihan yang kamu rekomendasikan, dan pastikan tidak ada unsur yang digandakan.
9. Tulis usulan satu halaman bagian 2.5, bacakan ke rekan yang berperan sebagai manajemen, dan catat pertanyaan yang tidak bisa kamu jawab.

**Hasil yang sebaiknya tersimpan:**
- Status terkini kelima standar dari katalog.
- Catatan edisi dan penomoran kontrol tiga artikel online.
- Daftar periksa kesiapan layanan dengan RTO dan RPO fiktif.
- Matriks tanggung jawab untuk tiga model layanan cloud.
- Hasil pengujian satu asumsi tanggung jawab.
- Daftar kewajiban tanpa padanan beserta kerangka 27701:2025 untuk tiap kewajiban.
- Jawaban empat pertanyaan keputusan dan lembar keputusan.
- Rencana penambahan tanpa penggandaan.
- Usulan satu halaman beserta pertanyaan yang belum terjawab.

## 4. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa |
|---|---|---|
| Nomor kontrol di artikel tidak cocok dengan standar | Artikel merujuk edisi yang sudah ditarik atau penomoran 2013 | Periksa edisi di katalog sebelum memakai perbandingan apa pun |
| Kontrol CLD.x dari 27017:2015 masih ada di SoA | SoA belum dipetakan ke edisi 2026 | Pakai annex pemetaan di 27017:2026 |
| Penambahan standar menambah beban tanpa hasil | ISMS dasar belum stabil | Jalankan pertanyaan 3 di bagian 1.5 lebih dulu |
| Orang yang sama diminta bukti yang sama dua kali | Sistem digandakan | Pakai tabel bagian 2.4 untuk menyatukan |
| Asumsi tanggung jawab cloud ternyata keliru | Tidak pernah diuji ke dokumentasi penyedia | Uji tiap baris matriks |
| Sertifikasi penyedia dianggap menutup kewajiban kita | Sisi pengguna tetap milik kita (kontrol 5.23) | Pisahkan kolom penyedia dan pengguna (bagian 2.2) |
| Rencana pemulihan gagal saat dibutuhkan | Tidak pernah dijalankan sungguhan | Jalankan uji pemulihan; catat yang gagal |
| Sertifikat 27701:2019 pemasok mendekati tenggat transisi | Transisi ke edisi 2025 belum dijadwalkan | Tanyakan rencana transisinya; cek tenggat badan akreditasinya |

## 5. Kesalahan umum dan jebakan

- Memakai perbandingan kontrol dari internet tanpa memeriksa edisi yang dirujuknya.
- Menganggap 27701 masih harus menempel pada 27001; sejak edisi 2025 ia bisa berdiri sendiri.
- Menambahkan sistem manajemen kedua sementara yang pertama belum stabil.
- Menggandakan register, program audit, dan jalur tindakan korektif.
- Menganggap sertifikasi penyedia cloud menutup tanggung jawab sisi pengguna.
- Mengisi matriks tanggung jawab tanpa mengujinya ke dokumentasi penyedia.
- Melupakan backup dan pemulihan sebagai tanggung jawab pengguna.
- Menambahkan standar kelangsungan sebelum punya BIA dan uji pemulihan.
- Menunda menutup celah kewajiban sambil menunggu keputusan sertifikasi.

## 6. Catatan terkini

Bagian ini menampung edisi lama yang sudah ditarik, tanggal terbit edisi baru, dan tenggat transisi. Detail ini dibutuhkan saat memeriksa templat, sertifikat pemasok, atau rencana jangka menengah, dan paling cepat usang; cek katalog ISO sebelum mengutipnya.

**Edisi lama dan penggantinya.** Tabel berikut dipakai untuk mengenali materi yang merujuk edisi yang sudah ditarik.

| Standar | Edisi lama dan statusnya | Edisi berlaku | Sifat |
|---|---|---|---|
| ISO 22301 | 2019 masih berlaku, ditandai akan direvisi [S6] | ISO 22301:2019 + Amd 1:2024 | Persyaratan, bisa disertifikasi |
| ISO/IEC 27031 | 2011 ditarik 2025-05-16 [S1] | ISO/IEC 27031:2025 edisi 2, terbit 2025-05-16 [S7] | Panduan |
| ISO/IEC 27017 | 2015 ditarik 2026-07-27 [S2] | ISO/IEC 27017:2026 edisi 2, terbit 2026-07-27 [S8] | Panduan kontrol |
| ISO/IEC 27018 | 2019 ditarik 2025-08-26 [S3] | ISO/IEC 27018:2025 edisi 3, terbit 2025-08-26 [S9] | Panduan kontrol |
| ISO/IEC 27701 | 2019 ditarik [S4] | ISO/IEC 27701:2025 edisi 2, terbit 2025-10-14 [S5] | Persyaratan, sistem manajemen mandiri |

**Kelangsungan:**

- ISO 22301:2019 berstatus akan direvisi sejak Desember 2025, dengan ISO/CD 22301 sedang disusun [S6]. Bila kamu merencanakan BCMS, perhitungkan kemungkinan edisi baru dalam rencana jangka menengahmu.
- Judul ISO/IEC 27031:2025 kini diawali "Cybersecurity" [S7].

**Cloud:**

- ISO/IEC 27017:2015 ditarik dan digantikan edisi 2026 pada 27 Juli 2026 [S2][S8]. Bila organisasimu atau penyedia cloud-mu diaudit terhadap 27017, tanyakan ke badan sertifikasi kapan audit beralih ke edisi baru.
- Edisi 2015 memakai tujuh kontrol berawalan CLD dengan penomoran 2013. Edisi 2026 menyediakan annex pemetaan edisi 2015 ke 2026 [S11].
- ISO/IEC 27018:2025 diselaraskan dengan 27002:2022 dan menambah Annex B berisi panduan penerapan yang lebih rinci [S9].

**Privasi:**

- ISO/IEC 27701:2025 dan ISO/IEC 27706:2025 terbit 14 Oktober 2025 [S5][S14]. ISO/IEC 27706:2025 menggantikan ISO/IEC TS 27006-2:2021 [S14].
- Masa transisi sertifikat 27701:2019 ditetapkan per badan akreditasi. Contohnya SAC Singapura mewajibkan badan sertifikasi selesai bertransisi ke 27701:2025 dan 27706:2025 paling lambat 31 Oktober 2027 dan memindahkan seluruh kliennya paling lambat 31 Oktober 2028, serta akan menerbitkan sertifikat PIMS dan ISMS secara terpisah [S15]. Tenggat di badan akreditasi lain, termasuk KAN, perlu dicek di masing-masing.

## 7. Cheat sheet

```
STATUS (cek katalog; bagian ini paling cepat usang)
  ISO 22301:2019 + Amd 1:2024   berlaku, AKAN DIREVISI (ISO/CD 22301)      persyaratan BCMS
  ISO/IEC 27031:2025 (ed 2)     2011 ditarik 16 Mei 2025                   panduan kesiapan ICT
  ISO/IEC 27017:2026 (ed 2)     2015 ditarik 27 Jul 2026                   panduan kontrol cloud
  ISO/IEC 27018:2025 (ed 3)     2019 ditarik 26 Agu 2025                   panduan PII di public cloud
  ISO/IEC 27701:2025 (ed 2)     2019 ditarik; terbit 14 Okt 2025           PIMS MANDIRI, bisa disertifikasi
  ISO/IEC 27706:2025            ganti TS 27006-2:2021                       aturan badan sertifikasi PIMS
  => banyak artikel/templat merujuk edisi DITARIK dan nomor kontrol 2013

KELANGSUNGAN  Annex A: 5.29, 5.30, 8.13, 8.14
  22301 klausul 8: 8.2 BIA + risiko | 8.3 strategi | 8.4 rencana | 8.5 latihan | 8.6 evaluasi
  27031 = panduan kesiapan ICT, termasuk ketergantungan cloud
  syarat sebelum menambah: BIA nyata + rencana PERNAH DIJALANKAN

CLOUD  Annex A: 5.23
  27017:2026 = panduan 27002:2022 untuk customer + provider, plus kontrol tambahan khusus cloud
              (menurut ringkasan sekunder: 5.38, 5.39 peran bersama; 8.35 segregasi virtual;
               8.36 pemakaian cloud tidak sah)
  27018:2025 = PII di public cloud sebagai processor; selaras 27002:2022; Annex B baru
  SERTIFIKASI PENYEDIA TIDAK MEMINDAHKAN TANGGUNG JAWABMU; uji matriks ke dokumentasi penyedia

PRIVASI  Annex A: 5.34
  27701:2025 = klausul 4-10 sendiri + Annex A kontrol controller/processor; bisa tanpa ISMS
  sertifikasi via badan berakreditasi 27706:2025; transisi per badan akreditasi (SAC: klien 31 Okt 2028)
  pakai untuk: dasar pemrosesan, DPIA, hak subjek data (Day 18)

EMPAT PERTANYAAN KEPUTUSAN
  1 ada pihak luar MEMINTA sertifikat? | 2 ada kewajiban TANPA PADANAN di ISMS?
  3 ISMS SUDAH STABIL?                  | 4 beban tata kelola SEBANDING?
  pola yang sering tepat: TUTUP CELAHNYA DULU, putuskan sertifikasinya kemudian

JANGAN GANDAKAN  satu register risiko | satu program audit | satu management review
  yang MEMANG terpisah: SoA untuk katalog kontrol baru + bukti khusus auditor
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** Penyedia cloud tempat PT AN menyimpan aplikasi internal tersertifikasi ISO/IEC 27017. Apakah backup data aplikasi itu otomatis menjadi tanggung jawab penyedia?

<details><summary>Jawaban</summary>

Tidak. Sertifikasi penyedia tidak memindahkan tanggung jawab pengguna, dan kontrol 5.23 tetap menuntut PT AN menetapkan proses pemakaian layanan cloud sendiri. Di matriks PT AN, backup data aplikasi (8.13) adalah tanggung jawab penuh pengguna kecuali penyedia menyatakan sebaliknya, dan baris itu belum diuji, sehingga menjadi temuan yang perlu ditangani sebelum auditor menemukannya. Nilai terbesar 27017 adalah kerangka pembagian tanggung jawabnya, bukan sertifikatnya. Lihat bagian 1.3 dan 2.2.

</details>

**2. Skenario keputusan.** Klien sektor kesehatan akan mensyaratkan sertifikat 27701 di pengadaan tahun depan. ISMS PT AN cukup stabil (7 dari 9 temuan siklus terakhir ditutup), tetapi dasar pemrosesan, hak subjek data, dan DPIA belum punya proses. Apa rekomendasimu?

- A. Segera sertifikasi 27701:2019, karena templat dan materi pelatihannya paling banyak tersedia.
- B. Tahap 1: perluas ISMS dengan tiga proses itu memakai 27701:2025 sebagai panduan; tahap 2: tinjau sertifikasi berdasarkan permintaan pasar yang nyata.
- C. Tidak perlu apa-apa, karena kontrol 5.34 di Annex A sudah mencakup privasi.

<details><summary>Jawaban</summary>

B. Celah tiga proses itu harus ditutup apa pun keputusan sertifikasinya, dan menutupnya lebih dulu membuat sertifikasi nanti jauh lebih murah. A keliru karena 27701:2019 sudah ditarik dan sertifikatnya sedang ditransisikan ke edisi 2025; banyaknya templat justru tanda materi lama. C keliru karena 5.34 hanya menyentuh privasi secara umum, sedangkan dasar pemrosesan, DPIA, dan hak subjek data tidak punya padanan di ISMS. Lihat bagian 1.4, 1.5, dan 2.1.

</details>

**3. Pertanyaan jebakan.** Tim GRC menemukan templat SoA cloud di internet yang memuat kontrol CLD.x dan rujukan A.12.4.1. Templat itu terlihat lengkap. Bisakah langsung dipakai?

<details><summary>Jawaban</summary>

Tidak langsung. Kontrol berawalan CLD berasal dari 27017:2015 yang sudah ditarik, dan A.12.4.1 adalah penomoran 27002:2013. 27017:2026 dibangun di atas 27002:2022 dan menyediakan annex pemetaan dari edisi 2015, jadi templat itu perlu dipetakan ulang. Nomor dan judul kontrol tambahan edisi 2026 juga perlu dicocokkan dengan teks standar sebelum masuk SoA, karena daftar empat kontrol tambahannya berasal dari ringkasan sekunder. Lihat bagian 1.1, 1.3, dan 6.

</details>

**4. Skenario keputusan.** Klien bank menanyakan kapan rencana pemulihan PT AN untuk DC Jakarta-1 terakhir diuji. PT AN punya dokumen DRP yang sudah disetujui, tetapi belum pernah dijalankan sebagai pemulihan sungguhan. Apa langkah yang tepat?

- A. Kirim dokumen DRP dan sampaikan bahwa PT AN akan mengejar sertifikasi 22301.
- B. Jalankan uji pemulihan sungguhan, catat hasilnya termasuk yang gagal, tindak lanjuti selisih antara target dan hasil, dan perkuat 5.29, 5.30, 8.13, dan 8.14 dengan 27031 sebagai panduan.
- C. Jawab bahwa uji tidak perlu karena DC Jakarta-1 punya redundansi fasilitas (8.14).

<details><summary>Jawaban</summary>

B. Rencana yang tidak pernah dijalankan hampir selalu memuat asumsi keliru, dan klien bank sendiri terikat regulasi sektor yang menuntut DRP diuji minimal setahun sekali, sehingga tanggal uji lebih bermakna baginya daripada dokumen. A keliru karena dokumen tanpa uji tidak menjawab pertanyaan, dan menambah standar tidak menambah ketahanan bila dasarnya belum ada. C keliru karena redundansi tanpa uji tetap hanya asumsi; 5.30 sendiri meminta kesiapan ICT diuji. Lihat bagian 1.2 dan 2.3.

</details>

**5. Jelaskan ulang.** Jelaskan kepada Direktur Operasional PT AN dalam tiga kalimat kenapa tiga pertanyaan di pesannya tidak berarti PT AN butuh tiga sertifikat baru.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Dari tiga standar yang disebut, hanya satu yang benar-benar diminta sertifikatnya oleh klien, yaitu 27701 untuk privasi; 27017 untuk cloud hanya panduan, dan pertanyaan klien bank tentang kelangsungan dijawab dengan uji pemulihan, bukan sertifikat. Untuk ketiganya, langkah pertama adalah menutup celahnya di dalam ISMS yang sudah ada, dengan register risiko, audit internal, dan management review yang sama. Sertifikasi tambahan kita putuskan belakangan berdasarkan permintaan pasar yang nyata, karena celah itu harus ditutup apa pun keputusan sertifikasinya."

Kesalahan yang sering muncul:
- Menyebut 27017 atau 27031 bisa disertifikasi; keduanya panduan.
- Mengusulkan sistem manajemen terpisah untuk tiap standar, dengan register dan rapat sendiri.
- Melupakan pertanyaan kestabilan ISMS sebelum menambah sistem kedua.

</details>

**6. Pertanyaan jebakan.** ISMS Manager mengusulkan dua hal untuk persiapan 27701: membuat register risiko privasi terpisah, dan membuat SoA terpisah untuk Annex A 27701. Apakah keduanya tepat?

<details><summary>Jawaban</summary>

Hanya yang kedua. Risiko privasi masuk ke register risiko yang sama sebagai kategori baru; register kedua menggandakan pekerjaan dan memecah gambaran risiko. SoA terpisah justru pengecualian yang disengaja, karena 27701:2025 punya katalog kontrol sendiri di Annex A, dan menggabungkannya paksa ke SoA ISMS menyulitkan audit. Uji sederhananya: bila orang yang sama diminta bukti yang sama untuk dua proses berbeda, itu tanda penggandaan. Lihat bagian 1.6 dan 2.4.

</details>

**7. Interview question (English).** "Your company is ISO 27001 certified. A customer asks whether you also plan to get ISO 27701. How would you approach that decision?"

<details><summary>Sample answer</summary>

"I'd start with the gap, not the certificate. ISO 27001 covers privacy only at a general level through control 5.34, so I'd check which privacy obligations, such as legal basis for processing, data subject rights, and privacy impact assessments, have no matching process in our ISMS. Those gaps need closing whatever we decide about certification. Then I'd ask whether a customer actually requires the certificate, whether our ISMS is stable enough to carry a second management system, and whether the governance overhead is proportionate. Often the right path is two stages: extend the ISMS using ISO 27701:2025 as guidance, with one risk register, one audit programme, and one management review, then revisit certification when the market demand is real. I'd also make sure we use the 2025 edition, which is now a standalone management system standard, because a lot of material online still describes the withdrawn 2019 extension."

What makes this answer strong: it treats the standard as a tool for closing specific gaps, follows a clear decision order, avoids duplicating the ISMS, and shows awareness of the current edition.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | ISO/IEC 27031:2011 (katalog) | https://committee.iso.org/standard/44374.html | primer (katalog ISO) | diakses 2026-10-10 | Tinggi untuk status withdrawn 2025-05-16 dan penggantinya |
| S2 | ISO/IEC 27017:2015 (katalog) | https://committee.iso.org/standard/43757.html | primer (katalog ISO) | diakses 2026-10-10 | Tinggi untuk status withdrawn 2026-07-27 dan penggantinya |
| S3 | ISO/IEC 27018:2019 (katalog) | https://committee.iso.org/standard/76559.html | primer (katalog ISO) | diakses 2026-10-10 | Tinggi untuk status withdrawn 2025-08-26 dan penggantinya |
| S4 | ISO/IEC 27701:2019 Extension to ISO/IEC 27001 and ISO/IEC 27002 for privacy information management (katalog) | https://committee.iso.org/standard/71670.html | primer (katalog ISO) | dilihat 2026-10-09 | Tinggi untuk judul yang menyatakan posisinya sebagai perluasan, dan status withdrawn |
| S5 | ISO/IEC 27701:2025 Privacy information management systems, requirements and guidance (katalog) | https://committee.iso.org/standard/85819.html | primer (katalog ISO) | diakses 2026-10-10 | Tinggi untuk edisi 2, tanggal terbit 2025-10-14, dan pernyataan sebagai standar sistem manajemen independen |
| S6 | ISO 22301:2019 Business continuity management systems, requirements (katalog) | https://committee.iso.org/standard/75106.html | primer (katalog ISO) | diakses 2026-10-10 | Tinggi untuk edisi 2, stage 90.92 (akan direvisi), ISO/CD 22301, dan Amd 1:2024 |
| S7 | ISO/IEC 27031:2025 Cybersecurity, ICT readiness for business continuity (katalog) | https://committee.iso.org/standard/80975.html | primer (katalog ISO) | diakses 2026-10-10 | Tinggi untuk edisi 2, tanggal terbit, dan ringkasan cakupan (hubungan dengan 27001 dan 22301, ketergantungan cloud) |
| S8 | ISO/IEC 27017:2026 Information security controls based on ISO/IEC 27002 for cloud services (katalog) | https://committee.iso.org/standard/82878.html | primer (katalog ISO) | diakses 2026-10-10 | Tinggi untuk edisi 2, tanggal 2026-07-27, dan ringkasan isi; jumlah kontrol tambahan tidak disebut |
| S9 | ISO/IEC 27018:2025 Guidelines for protection of PII in public clouds acting as PII processors (katalog) | https://committee.iso.org/standard/88150.html | primer (katalog ISO) | diakses 2026-10-10 | Tinggi untuk edisi 3, tanggal 2025-08-26, keselarasan dengan 27002:2022, dan Annex B baru |
| S10 | GlocertInternational, ISO 22301 requirements overview | https://www.glocertinternational.com/resources/articles/iso-22301-requirements-overview/ | sekunder (lembaga sertifikasi) | diakses 2026-10-10 | Sedang untuk judul subklausul 8.1-8.6 dan isi BIA |
| S11 | ISO27001security.com, ISO/IEC 27017 | https://www.iso27001security.com/html/27017 | sekunder (situs praktisi) | diakses 2026-10-10 | Sedang untuk struktur edisi 2026 dan empat kontrol tambahan; situs ini menyebut terbit Agustus 2026, katalog ISO menyebut 27 Juli 2026 |
| S12 | ISO27001security.com, ISO/IEC 27018 | https://www.iso27001security.com/html/27018 | sekunder (situs praktisi) | diakses 2026-10-10 | Sedang untuk contoh kontrol tambahan (pemberitahuan subkontraktor) |
| S13 | ISO27001security.com, ISO/IEC 27701 | https://www.iso27001security.com/html/27701 | sekunder (situs praktisi) | diakses 2026-10-10 | Sedang untuk struktur klausul 4-10, Annex A, dan sertifikasi lewat 27706 |
| S14 | ISO/IEC 27706:2025 Requirements for bodies providing audit and certification of privacy information management systems (katalog) | https://committee.iso.org/standard/82894.html | primer (katalog ISO) | diakses 2026-10-10 | Tinggi untuk edisi 1, tanggal terbit 2025-10-14, dan penggantian TS 27006-2:2021 |
| S15 | SAC, SAC announces transition to new privacy information management system standard | https://www.sac-accreditation.gov.sg/media/sac-announces-transition-to-new-privacy-information-management-system-standard/ | primer (badan akreditasi Singapura) | 20 April 2026; diakses 2026-10-10 | Tinggi untuk tenggat transisi SAC dan sertifikat PIMS terpisah; tenggat badan akreditasi lain bisa berbeda |

**Catatan sumber:** judul, edisi, tanggal, dan status diambil dari katalog ISO. Daftar kontrol tambahan 27017:2026, struktur Annex A 27701:2025, dan judul subklausul 22301 berasal dari sumber sekunder [S10][S11][S13] dan perlu dicocokkan dengan teks standar sebelum dipakai di SoA atau dokumen audit. Tenggat transisi 27701:2025 di KAN belum ditemukan. Seluruh angka, nama, dan isi di bagian 2 adalah fiktif.
