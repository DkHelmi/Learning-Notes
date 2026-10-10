---
day: 19
title: 'Memperluas ISMS: kelangsungan layanan, cloud, dan privasi'
researched_on: 2026-10-10
versions_checked: 'ISO 22301:2019 edisi 2 + Amd 1:2024 (stage 90.92, akan direvisi; ISO/CD 22301 sedang disusun); ISO/IEC 27031:2025 edisi 2, terbit 2025-05-16, menggantikan 27031:2011; ISO/IEC 27017:2026 edisi 2, terbit 2026-07-27, menggantikan 27017:2015; ISO/IEC 27018:2025 edisi 3, terbit 2025-08-26, menggantikan 27018:2019; ISO/IEC 27701:2025 edisi 2, terbit 2025-10-14, standar sistem manajemen mandiri; ISO/IEC 27706:2025 edisi 1, terbit 2025-10-14, menggantikan ISO/IEC TS 27006-2:2021'
---

# Day 19: Memperluas ISMS

Cakupan: empat standar yang paling sering ditambahkan di atas ISO 27001 (kelangsungan, cloud, dan privasi), apa yang masing-masing tambahkan, status edisinya, dan cara memutuskan apakah organisasimu membutuhkannya.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- menyebutkan celah yang ditutup masing-masing standar tambahan dan kapan ia relevan.
- membedakan standar persyaratan yang bisa disertifikasi dari standar panduan.
- menjelaskan apa yang 22301, 27031, 27017, 27018, dan 27701 tambahkan di atas kontrol Annex A yang sudah ada.
- mengenali panduan online yang masih merujuk edisi yang sudah ditarik.
- memutuskan apakah organisasimu perlu menambah standar atau cukup memperluas ISMS yang ada.
- menyusun rencana penambahan yang tidak menggandakan pekerjaan.

## 2. Konteks singkat

ISO 27001 menetapkan sistem manajemen keamanan informasi, dan Annex A menyediakan kontrol untuk menurunkan risiko. Ada tiga hal yang hanya disentuh secara umum oleh Annex A: kesiapan layanan menghadapi gangguan (kontrol 5.29 dan 5.30), pembagian tanggung jawab antara penyedia dan pengguna layanan cloud (5.23), dan kewajiban terhadap data pribadi di luar soal keamanan (5.34). Untuk ketiganya ada standar tambahan dengan rincian yang jauh lebih dalam.

Masalah praktisnya: empat dari standar itu direvisi antara Mei 2025 dan Juli 2026, sehingga banyak artikel, templat, dan materi pelatihan yang beredar masih merujuk edisi yang sudah ditarik, lengkap dengan penomoran kontrol 27002:2013. Day ini memberi status terbarunya dan cara menilai apakah kamu benar-benar membutuhkannya.

## 3. Konsep inti

### 3.1 Status terbaru

| Standar | Edisi lama dan statusnya | Edisi berlaku | Sifat |
|---|---|---|---|
| ISO 22301 | 2019 masih berlaku, ditandai akan direvisi [S6] | ISO 22301:2019 + Amd 1:2024 | Persyaratan, bisa disertifikasi |
| ISO/IEC 27031 | 2011 ditarik 2025-05-16 [S1] | ISO/IEC 27031:2025 edisi 2, terbit 2025-05-16 [S7] | Panduan |
| ISO/IEC 27017 | 2015 ditarik 2026-07-27 [S2] | ISO/IEC 27017:2026 edisi 2, terbit 2026-07-27 [S8] | Panduan kontrol |
| ISO/IEC 27018 | 2019 ditarik 2025-08-26 [S3] | ISO/IEC 27018:2025 edisi 3, terbit 2025-08-26 [S9] | Panduan kontrol |
| ISO/IEC 27701 | 2019 ditarik [S4] | ISO/IEC 27701:2025 edisi 2, terbit 2025-10-14 [S5] | Persyaratan, sistem manajemen mandiri |

Konsekuensinya untuk pekerjaanmu:

- Perbandingan kontrol dan templat dari internet hampir pasti merujuk edisi lama. Periksa tanggal terbit tulisannya dan edisi yang dirujuk.
- Edisi baru 27017 dan 27018 kini dibangun di atas 27002:2022 (empat tema, 93 kontrol), sehingga pemetaan lama berbasis nomor 2013 (misalnya A.12.4.1) perlu dipetakan ulang [S8][S9].
- Bila organisasimu tersertifikasi 27701:2019, ada masa transisi yang ditetapkan badan akreditasi (bagian 3.4).

### 3.2 Kesiapan layanan menghadapi gangguan: 22301 dan 27031

Annex A 27001:2022 sudah punya dua kontrol kelangsungan: 5.29 meminta keamanan informasi tetap terjaga saat gangguan, dan 5.30 meminta kesiapan ICT direncanakan, diterapkan, dipelihara, dan diuji berdasarkan sasaran kelangsungan bisnis. Kontrol pendukungnya 8.13 (backup) dan 8.14 (redundansi fasilitas pemrosesan). Dua standar di bawah ini memperdalamnya dari arah berbeda.

**ISO 22301:2019** adalah standar persyaratan sistem manajemen kelangsungan bisnis (BCMS) dengan struktur klausul 4-10 yang sama dengan 27001 [S6]. Yang ia tambahkan ada di klausul 8 [S10]:

| Klausul | Isi |
|---|---|
| 8.2 | Business impact analysis (BIA) dan penilaian risiko: aktivitas yang mendukung produk dan layanan, bagaimana dampak bertambah seiring lamanya gangguan, prioritas waktu pemulihan (RTO), serta ketergantungan dan sumber daya pendukung |
| 8.3 | Strategi dan solusi kelangsungan, termasuk kebutuhan sumber dayanya |
| 8.4 | Rencana dan prosedur: struktur respons, peringatan dan komunikasi, rencana kelangsungan, pemulihan |
| 8.5 | Program latihan (exercise) |
| 8.6 | Evaluasi dokumentasi dan kemampuan kelangsungan |

Amd 1:2024 menambah pertimbangan perubahan iklim, sejalan dengan amandemen 27001. Katalog ISO mencatat 22301:2019 akan direvisi dan drafnya (ISO/CD 22301) sedang disusun [S6].

**ISO/IEC 27031:2025** (judul edisi baru diawali "Cybersecurity") adalah panduan kesiapan ICT untuk kelangsungan bisnis: kerangka metode dan proses untuk membuat ICT siap mencegah, merespons, dan pulih dari gangguan, dari serangan siber sampai kegagalan sistem [S7]. Ia melengkapi 27001 di sisi kontinuitas ICT dan mendukung 22301 dengan menyelaraskan kesiapan ICT ke sasaran kelangsungan bisnis. Edisi 2025 juga membahas ketergantungan pada layanan eksternal seperti penyedia cloud [S7].

Untuk organisasi menengah, jalur yang masuk akal biasanya memperkuat kontrol 5.29, 5.30, 8.13, dan 8.14 di dalam ISMS memakai 27031 sebagai panduan, lalu mempertimbangkan BCMS 22301 tersendiri hanya bila pelanggan atau regulator memintanya. Apa pun jalurnya, periksa dulu apakah sudah ada BIA yang nyata dan apakah rencana pemulihan pernah diuji dengan pemulihan sungguhan. Di Indonesia, sebagian regulasi sektor menuntut uji ini secara eksplisit, misalnya DRP bank yang diuji minimal setahun sekali (Day 18).

### 3.3 Cloud: 27017 dan 27018

**ISO/IEC 27017:2026** adalah panduan kontrol keamanan informasi untuk layanan cloud berbasis 27002 [S8]. Yang ia tambahkan:

- panduan tambahan untuk kontrol 27002:2022 yang relevan, ditulis berdampingan untuk cloud service customer dan cloud service provider;
- kontrol tambahan khusus cloud, untuk risiko dan tanggung jawab yang tidak ada di 27002;
- penjelasan cara kontrol berlaku ketika tanggung jawab, infrastruktur, dan operasi terbagi antara beberapa pihak;
- cakupan public, private, dan hybrid cloud; untuk private cloud, kontrol perlu disesuaikan dengan hubungan antar departemen internal.

Menurut ringkasan iso27001security.com, edisi 2026 menambah empat kontrol di atas 93 kontrol 27002: 5.38 dan 5.39 (peran dan tanggung jawab bersama yang disepakati), 8.35 (segregasi di lingkungan komputasi virtual), dan 8.36 (mendeteksi dan mencegah pemakaian layanan cloud yang tidak sah), ditambah Annex A pemetaan edisi 2015 ke 2026 dan Annex B tentang pemantauan keamanan cloud [S11]. Edisi 2015 memakai tujuh kontrol berawalan CLD dengan penomoran 2013. Nomor dan judul kontrol edisi 2026 perlu dicocokkan dengan teks standar sebelum dipakai di SoA.

**ISO/IEC 27018:2025** adalah panduan pelindungan PII di public cloud yang bertindak sebagai PII processor [S9]. Ia menyesuaikan kontrol 27002 untuk pemrosesan PII di cloud, mencakup pengumpulan, penyimpanan, pemrosesan, transmisi, dan penghapusan, dan dirancang melengkapi ISMS berbasis 27001. Edisi 2025 diselaraskan dengan 27002:2022 dan menambah Annex B berisi panduan penerapan yang lebih rinci [S9]. Contoh kontrol tambahannya: penyedia memberi tahu pelanggan bila memakai subkontraktor untuk memproses PII [S12].

Nilai terbesar keduanya ada pada kerangka pembagian tanggung jawab, bukan pada sertifikatnya. Banyak kegagalan di lingkungan cloud berasal dari asumsi bahwa penyedia menangani sesuatu yang sebenarnya tanggung jawab pengguna, atau sebaliknya. Dua pemakaian yang paling langsung:

1. **Daftar periksa saat menilai penyedia** (Day 12): tanyakan sisi mana yang mereka tangani untuk kontrol yang penting bagimu, dan apakah sertifikat 27017/27018 mereka sudah memakai edisi baru.
2. **Dasar matriks tanggung jawab internal** (bagian 4.2): siapa menangani apa untuk tiap layanan cloud, lalu uji asumsinya.

Sertifikasi penyedia tidak memindahkan tanggung jawabmu. Kontrol 5.23 tetap menuntut organisasimu sendiri menetapkan proses pemakaian layanan cloud, dan sisi pengguna tetap akan ditanyakan auditor maupun regulator.

### 3.4 Privasi: 27701:2025 sebagai sistem manajemen mandiri

ISO/IEC 27701:2019 berjudul perluasan (extension) terhadap 27001 dan 27002 [S4], sehingga hanya bisa diterapkan dan disertifikasi bersama ISMS. Edisi 2025 berjudul sistem manajemen informasi privasi, persyaratan dan panduan, dan katalog ISO menyebutnya standar sistem manajemen yang independen dan bisa dipakai sendiri, untuk PII controller maupun PII processor [S5]. Perubahan isinya [S13]:

- klausul 4-10 sendiri dengan struktur sistem manajemen yang sama seperti 27001 (konteks, kepemimpinan, perencanaan, dukungan, operasi, evaluasi kinerja, perbaikan);
- Annex A berupa katalog kontrol privasi untuk controller dan processor, bergaya seperti Annex A 27001;
- tetap bisa diintegrasikan dengan ISMS untuk mengurangi duplikasi.

Sertifikasinya kini punya standar badan sertifikasi sendiri, ISO/IEC 27706:2025, yang menggantikan ISO/IEC TS 27006-2:2021 dan menambah persyaratan di atas 17021-1 (Day 17) [S14]. Badan akreditasi menetapkan transisinya; contohnya SAC Singapura mewajibkan badan sertifikasi selesai bertransisi ke 27701:2025 dan 27706:2025 paling lambat 31 Oktober 2027 dan memindahkan seluruh kliennya paling lambat 31 Oktober 2028, serta akan menerbitkan sertifikat PIMS dan ISMS secara terpisah [S15]. Tenggat di badan akreditasi lain, termasuk KAN, perlu dicek di masing-masing.

Kapan ini relevan bagimu: ketika kewajiban yang kamu petakan di Day 18 memuat hal yang tidak punya padanan di ISMS, terutama dasar pemrosesan, DPIA, dan hak subjek data dengan tenggat 3 x 24 jam. Karena 27701:2025 bisa berdiri sendiri, organisasi yang tidak butuh ISMS tersertifikasi pun kini bisa memakainya. Kapan belum relevan: ketika ISMS-mu sendiri belum stabil. Menambahkan sistem manajemen kedua di atas yang pertama yang masih goyah menggandakan beban tanpa menambah kepatuhan.

### 3.5 Memutuskan: tambah standar atau perluas ISMS

Pertanyaan yang menentukan, berurutan:

```
1. Apakah ada pihak luar yang MEMINTA sertifikat terhadap standar itu?
   ya  -> pertimbangkan sertifikasi; hitung biayanya (Day 17)
   tidak -> lanjut

2. Apakah ada kewajiban yang TIDAK PUNYA PADANAN di ISMS-mu? (Day 18 bagian 4.2)
   ya  -> perluas ISMS dengan kerangka dari standar itu, tanpa sertifikasi
   tidak -> lanjut

3. Apakah ISMS yang ada SUDAH STABIL? (audit internal berjalan, temuan ditutup efektif)
   tidak -> perbaiki itu dulu; jangan menambah sistem kedua
   ya  -> lanjut

4. Apakah penambahan ini akan menambah BEBAN TATA KELOLA yang tidak sebanding?
   ya  -> pakai standarnya sebagai panduan, bukan sebagai sistem manajemen baru
```

Untuk organisasi menengah, jalur yang paling sering tepat adalah memakai standar tambahan sebagai panduan untuk memperkuat ISMS. Sertifikasi tambahan masuk akal ketika ada permintaan pasar yang nyata, dan itu keputusan bisnis.

### 3.6 Menambah tanpa menggandakan

Bila kamu memutuskan menambah, prinsip yang sama seperti Day 18 berlaku: satu register risiko (risiko privasi dan kelangsungan masuk register yang sama), satu program audit dengan lingkup diperluas, satu management review dengan agenda ditambah, satu jalur tindakan korektif, dan prosedur yang diperluas, bukan diduplikasi.

Yang memang perlu terpisah: pernyataan keberlakuan untuk lingkup baru (27701:2025 punya Annex A sendiri), bukti spesifik yang diminta auditor untuk standar itu, dan peran baru bila standarnya menuntutnya.

Uji sederhananya: bila orang yang sama diminta memberikan bukti yang sama kepada dua proses berbeda, kamu sedang menggandakan.

## 4. Contoh dokumen / artefak (organisasi fiktif)

> Seluruh isi di bawah adalah contoh untuk organisasi fiktif PT AN. Nomor kontrol tambahan 27017:2026 hanya dipakai sebagai ilustrasi; cocokkan dengan teks standar.

### 4.1 Lembar keputusan penambahan standar

```
LEMBAR KEPUTUSAN                              Nomor: KS-2027-002
Standar yang dipertimbangkan : ISO/IEC 27701:2025 (PIMS)
Disusun oleh                 : <nama>          Tanggal: 2027-04-10

1. PERMINTAAN PASAR
   Dua pelanggan menanyakan; satu mensyaratkan dalam proses pengadaan tahun depan.
   Nilai kontrak terkait: <angka>

2. CELAH YANG TIDAK TERTUTUP ISMS  (dari Day 18 bagian 4.2)
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

### 4.2 Matriks pembagian tanggung jawab cloud

| Kontrol | Penyedia | Pengguna (kami) | Bukti yang kami punya | Diuji? |
|---|---|---|---|---|
| 7.1-7.4 keamanan fisik pusat data | penuh | tidak ada | laporan audit penyedia, lingkup dibaca | tidak perlu |
| 8.24 kriptografi (data saat disimpan) | menyediakan kemampuan | mengaktifkan dan mengelola kunci | konfigurasi; prosedur kunci | ya, 2027-02 |
| 5.15, 8.2 akses ke konsol | menyediakan kemampuan | konfigurasi, tinjauan berkala | hasil tinjauan hak akses | ya, 2027-01 |
| 8.13 backup data aplikasi | tidak, kecuali dinyatakan | penuh | konfigurasi backup; uji pemulihan | belum diuji |
| 8.15 logging aktivitas konsol | menyediakan kemampuan | mengaktifkan, mengumpulkan, meninjau | konfigurasi; catatan tinjauan | ya, 2027-03 |
| 5.24-5.26 respons insiden di lapis layanan | sebagian | penuh di lapis kami | prosedur IR-01 | ya, latihan meja |
| Peran dan tanggung jawab bersama (27017:2026) | menyatakan di perjanjian | memeriksa dan menyetujui | perjanjian layanan, lampiran tanggung jawab | ya, 2027-01 |

Dua kolom terakhir yang membuat matriks ini bisa diaudit. Baris backup yang belum diuji adalah temuan, dan akan muncul di audit bila kamu tidak menemukannya lebih dulu. Laporan audit penyedia hanya sah sebagai bukti bila kamu benar-benar membaca lingkupnya (Day 17 bagian 3.5).

### 4.3 Daftar periksa kesiapan layanan

Dipakai sebelum memutuskan menambah standar kelangsungan:

```
DASAR YANG HARUS ADA LEBIH DULU (padanan 22301 klausul 8.2-8.6; kontrol 5.29, 5.30)
  [ ] Daftar layanan dengan tingkat kepentingannya terhadap bisnis       (BIA, 8.2)
  [ ] Untuk tiap layanan kritis: RTO dan RPO yang disepakati pemilik bisnis
  [ ] Ketergantungan tiap layanan: sistem lain, pemasok, cloud, orang, lokasi
  [ ] Rencana pemulihan tertulis untuk layanan kritis                    (8.4)
  [ ] Rencana itu PERNAH DIJALANKAN, bukan hanya dibaca                  (8.5)
  [ ] Hasil uji dicatat, termasuk yang gagal
  [ ] Selisih antara target dan hasil uji ditindaklanjuti                 (8.6)

BILA ADA YANG BELUM TERCENTANG
  kerjakan itu dulu; menambah standar tidak akan menambah ketahanan
```

Butir kelima yang membedakan organisasi yang siap dari yang merasa siap. Rencana yang tidak pernah dijalankan hampir selalu memuat asumsi keliru, dan asumsi itu baru ketahuan saat benar-benar dibutuhkan.

### 4.4 Rencana penambahan yang tidak menggandakan

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

### 4.5 Menjelaskan ke manajemen

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

## 5. Lab praktik

**Prasyarat:** hasil Day 12 (pemasok), Day 17 (sertifikasi), dan Day 18 (regulasi). Seluruh lab bersifat memeriksa katalog, menilai, dan menulis.

1. Buka halaman katalog committee.iso.org untuk kelima standar di bagian 3.1 dan catat bila ada status yang berubah sejak catatan ini ditulis, terutama 22301 yang sedang direvisi.
2. Cari tiga artikel online tentang 27017 atau 27701, lalu catat edisi yang dirujuk, apakah edisi itu masih berlaku, dan apakah penomoran kontrolnya memakai 27002:2013 atau 2022.
3. Isi daftar periksa kesiapan layanan bagian 4.3 untuk PT AN, lengkap dengan RTO dan RPO fiktif untuk tiga layanan, dan tandai butir yang belum tercentang.
4. Susun matriks pembagian tanggung jawab bagian 4.2 untuk tiga layanan cloud fiktif (IaaS, SaaS email, platform database terkelola). Perhatikan bagaimana kolom penyedia berubah antar model layanan.
5. Untuk satu baris matriks, uji asumsinya: baca dokumentasi shared responsibility penyedia yang kamu pakai di lab dan buktikan siapa yang bertanggung jawab. Catat bila asumsimu keliru.
6. Ambil hasil pemetaan Day 18 bagian 4.2 dan daftarkan kewajiban yang tidak punya padanan di ISMS, lalu tulis bagian 27701:2025 mana (klausul atau Annex A) yang akan kamu pakai sebagai kerangka untuk tiap kewajiban.
7. Jalankan empat pertanyaan di bagian 3.5 untuk PT AN dan tulis jawabannya satu per satu, lalu susun lembar keputusan bagian 4.1.
8. Susun rencana penambahan bagian 4.4 untuk pilihan yang kamu rekomendasikan, dan pastikan tidak ada unsur yang digandakan.
9. Tulis usulan satu halaman bagian 4.5, bacakan ke rekan yang berperan sebagai manajemen, dan catat pertanyaan yang tidak bisa kamu jawab.

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

## 6. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa |
|---|---|---|
| Nomor kontrol di artikel tidak cocok dengan standar | Artikel merujuk edisi yang sudah ditarik atau penomoran 2013 | Periksa edisi di katalog sebelum memakai perbandingan apa pun |
| Kontrol CLD.x dari 27017:2015 masih ada di SoA | SoA belum dipetakan ke edisi 2026 | Pakai annex pemetaan di 27017:2026 |
| Penambahan standar menambah beban tanpa hasil | ISMS dasar belum stabil | Jalankan pertanyaan 3 di bagian 3.5 lebih dulu |
| Orang yang sama diminta bukti yang sama dua kali | Sistem digandakan | Pakai tabel bagian 4.4 untuk menyatukan |
| Asumsi tanggung jawab cloud ternyata keliru | Tidak pernah diuji ke dokumentasi penyedia | Uji tiap baris matriks |
| Sertifikasi penyedia dianggap menutup kewajiban kita | Sisi pengguna tetap milik kita (kontrol 5.23) | Pisahkan kolom penyedia dan pengguna (bagian 4.2) |
| Rencana pemulihan gagal saat dibutuhkan | Tidak pernah dijalankan sungguhan | Jalankan uji pemulihan; catat yang gagal |
| Sertifikat 27701:2019 pemasok mendekati tenggat transisi | Transisi ke edisi 2025 belum dijadwalkan | Tanyakan rencana transisinya; cek tenggat badan akreditasinya |

## 7. Kesalahan umum dan jebakan

- Memakai perbandingan kontrol dari internet tanpa memeriksa edisi yang dirujuknya.
- Menganggap 27701 masih harus menempel pada 27001; sejak edisi 2025 ia bisa berdiri sendiri.
- Menambahkan sistem manajemen kedua sementara yang pertama belum stabil.
- Menggandakan register, program audit, dan jalur tindakan korektif.
- Menganggap sertifikasi penyedia cloud menutup tanggung jawab sisi pengguna.
- Mengisi matriks tanggung jawab tanpa mengujinya ke dokumentasi penyedia.
- Melupakan backup dan pemulihan sebagai tanggung jawab pengguna.
- Menambahkan standar kelangsungan sebelum punya BIA dan uji pemulihan.
- Menunda menutup celah kewajiban sambil menunggu keputusan sertifikasi.

## 8. Catatan terkini

- ISO/IEC 27017:2015 ditarik dan digantikan edisi 2026 pada 27 Juli 2026 [S2][S8]. Bila organisasimu atau penyedia cloud-mu diaudit terhadap 27017, tanyakan ke badan sertifikasi kapan audit beralih ke edisi baru.
- ISO/IEC 27701:2025 dan ISO/IEC 27706:2025 terbit 14 Oktober 2025 [S5][S14]. Masa transisi sertifikat 27701:2019 ditetapkan per badan akreditasi; contoh SAC: badan sertifikasi selesai 31 Oktober 2027, klien selesai 31 Oktober 2028 [S15].
- ISO 22301:2019 berstatus akan direvisi sejak Desember 2025, dengan ISO/CD 22301 sedang disusun [S6]. Bila kamu merencanakan BCMS, perhitungkan kemungkinan edisi baru dalam rencana jangka menengahmu.

## 9. Cheat sheet

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

## 10. Sumber

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

**Catatan sumber:** judul, edisi, tanggal, dan status diambil dari katalog ISO. Daftar kontrol tambahan 27017:2026, struktur Annex A 27701:2025, dan judul subklausul 22301 berasal dari sumber sekunder [S10][S11][S13] dan perlu dicocokkan dengan teks standar sebelum dipakai di SoA atau dokumen audit. Tenggat transisi 27701:2025 di KAN belum ditemukan. Seluruh angka, nama, dan isi di bagian 4 adalah fiktif.
