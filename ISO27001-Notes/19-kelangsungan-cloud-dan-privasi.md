---
day: 19
title: 'Memperluas ISMS: kelangsungan layanan, cloud, dan privasi'
researched_on: 2026-10-10
versions_checked: 'ISO/IEC 27031:2011 ditarik pada 2025-05-16 dan digantikan ISO/IEC 27031:2025; ISO/IEC 27017:2015 ditarik dan digantikan ISO/IEC 27017:2026; ISO/IEC 27018:2019 ditarik dan digantikan ISO/IEC 27018:2025; ISO/IEC 27701:2019 ditarik dan digantikan ISO/IEC 27701:2025 edisi 2 yang terbit 2025-10-14; ISO 22301:2019 published dan ditandai sedang ditinjau; rujukan Day 01, 02, 08, 12, 18'
---

# Day 19: Memperluas ISMS

Cakupan: empat standar yang paling sering ditambahkan di atas ISO 27001, apa yang masing-masing tutup, dan kenapa hampir semua panduan daring tentangnya sekarang sudah usang.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- menyebutkan celah apa yang ditutup masing-masing standar tambahan dan kapan ia relevan.
- membedakan standar yang bisa disertifikasi dari yang berupa panduan.
- memutuskan apakah organisasimu membutuhkan tambahan itu atau cukup memperluas ISMS yang ada.
- mengenali bahwa edisi yang dirujuk panduan daring kemungkinan besar sudah ditarik.
- menyusun rencana penambahan yang tidak menggandakan pekerjaan.
- menjelaskan ke manajemen apa yang didapat dan apa biayanya.

## 2. Konteks singkat

ISO 27001 menetapkan sistem manajemen keamanan informasi, dan Annex A menyediakan kendali untuk menurunkan risiko. Tetapi ada beberapa hal yang tidak ditanganinya secara khusus, dan tiga yang paling sering muncul di pekerjaan nyata adalah kesiapan layanan menghadapi gangguan, hubungan khusus antara penyedia dan pengguna layanan awan, dan kewajiban terhadap data pribadi yang sifatnya bukan sekadar keamanan.

Untuk ketiganya ada standar tambahan, dan di situlah masalah praktis dimulai. Keempat standar yang dibahas di Day ini direvisi dalam waktu yang berdekatan, sehingga hampir semua artikel, templat, dan materi pelatihan yang beredar masih merujuk edisi yang sudah ditarik. Day ini menyebutkan status terbarunya, dan sekaligus menunjukkan cara menilai apakah kamu benar-benar membutuhkannya.

Judul, edisi, tanggal, dan status setiap standar di Day ini berasal dari katalog ISO. Penjelasan isinya adalah penilaian praktis yang disusun dari judul resmi, struktur keluarga standar, dan praktik umum; cocokkan dengan teks standarnya sebelum dipakai sebagai dasar keputusan sertifikasi.

## 3. Konsep inti

### 3.1 Status terbaru keempatnya

Ini bagian yang paling cepat usang, jadi periksa sendiri saat membacanya kembali.

| Standar | Edisi lama | Status edisi lama | Edisi baru |
|---|---|---|---|
| ISO/IEC 27031 | 2011 | ditarik pada 2025-05-16 [S1] | ISO/IEC 27031:2025 [S1] |
| ISO/IEC 27017 | 2015 | ditarik [S2] | ISO/IEC 27017:2026 [S2] |
| ISO/IEC 27018 | 2019 | ditarik [S3] | ISO/IEC 27018:2025 [S3] |
| ISO/IEC 27701 | 2019 | ditarik [S4] | ISO/IEC 27701:2025, edisi 2, terbit 2025-10-14 [S5] |

Empat revisi dalam rentang waktu yang berdekatan. Konsekuensinya untuk pekerjaanmu:

- Panduan daring, perbandingan kendali, dan templat yang kamu temukan hampir pasti merujuk edisi lama. Periksa tanggal terbit tulisannya sebelum memakainya.
- Bila organisasimu sudah tersertifikasi terhadap salah satunya, ada masa transisi yang perlu kamu tanyakan ke badan sertifikasi.
- Pelatihan yang pernah kamu ikuti sebelum 2025 membahas edisi yang sudah ditarik, termasuk nomor kendalinya.

Bila kamu hanya mengambil satu hal dari Day ini, ambil ini: jangan memakai perbandingan kendali dari internet tanpa memeriksa edisi yang dirujuknya.

### 3.2 Kesiapan layanan menghadapi gangguan

Dua standar yang sering tertukar:

| Standar | Sifat | Cakupan |
|---|---|---|
| ISO 22301 | Sistem manajemen, bisa disertifikasi | Kelangsungan bisnis secara keseluruhan |
| ISO/IEC 27031 | Panduan, tidak disertifikasi | Kesiapan teknologi informasi dan komunikasi untuk mendukung kelangsungan bisnis [S1] |

Perbedaan praktisnya besar. Yang pertama adalah sistem manajemen tersendiri dengan klausulnya sendiri, dan menambahkannya berarti menambah beban tata kelola. Yang kedua adalah panduan yang bisa kamu pakai untuk memperkuat kendali kelangsungan di dalam ISMS yang sudah ada, tanpa sistem baru.

Untuk sebagian besar organisasi menengah, jalur yang masuk akal adalah memperkuat kendali kelangsungan di ISMS memakai panduan, lalu mempertimbangkan sistem manajemen tersendiri hanya bila pelanggan atau regulator memintanya.

Yang perlu kamu periksa lebih dulu, apa pun jalurnya: apakah organisasimu sudah punya analisis dampak terhadap bisnis yang nyata, dan apakah rencana pemulihan pernah diuji dengan pemulihan sungguhan, bukan hanya dibaca. Tanpa keduanya, menambah standar tidak akan menambah ketahanan.

### 3.3 Hubungan penyedia dan pengguna layanan awan

Dua standar yang berpasangan:

- **ISO/IEC 27017** memberi panduan kendali keamanan informasi untuk layanan awan [S2]. Yang khas darinya adalah pembagian tanggung jawab antara penyedia dan pengguna: untuk banyak kendali, ada sisi yang menjadi tanggung jawab penyedia dan sisi yang menjadi tanggung jawab pengguna.
- **ISO/IEC 27018** memberi panduan pelindungan informasi pribadi yang dapat diidentifikasi pada layanan awan publik yang bertindak sebagai pemroses [S3].

Nilai terbesar keduanya bukan pada sertifikasinya, melainkan pada kerangka pembagian tanggung jawab. Banyak kegagalan di lingkungan awan berasal dari asumsi bahwa penyedia menangani sesuatu yang sebenarnya tanggung jawab pengguna, atau sebaliknya.

Untuk pekerjaanmu, dua pemakaian yang paling langsung:

1. **Sebagai daftar periksa saat menilai penyedia** (Day 12). Tanyakan sisi mana yang mereka tangani untuk kendali yang penting bagimu.
2. **Sebagai dasar menyusun pembagian tanggung jawab internal.** Buat matriks yang menyatakan siapa menangani apa untuk tiap layanan awan yang kamu pakai, lalu uji asumsinya.

Perlu diingat bahwa sertifikasi penyedia terhadap standar ini tidak memindahkan tanggung jawabmu. Sisi pengguna tetap milikmu, dan auditor maupun regulator akan menanyakannya.

### 3.4 Privasi di atas keamanan

ISO/IEC 27701 adalah standar sistem manajemen informasi privasi, dan edisi keduanya terbit pada Oktober 2025 [S5]. Posisinya berubah antara edisi lama dan baru, dan itu perlu kamu perhatikan.

Edisi lama disusun sebagai perluasan terhadap ISO/IEC 27001 dan ISO/IEC 27002 untuk manajemen informasi privasi [S4], sehingga ia menempel pada ISMS. Edisi baru berjudul sistem manajemen informasi privasi dengan persyaratan dan panduan [S5], yang menandakan posisinya sebagai standar persyaratan tersendiri. Perbedaan ini mempengaruhi apakah kamu bisa menerapkannya tanpa ISMS, dan bagaimana sertifikasinya bekerja. Periksa ke badan sertifikasi, karena pertanyaan itu tidak bisa dijawab dari halaman katalog.

Kapan ini relevan bagimu: ketika kewajiban yang kamu petakan di Day 18 memuat hal-hal yang tidak punya padanan di ISMS, terutama dasar pemrosesan, persetujuan, dan hak subjek data. Standar privasi menyediakan kerangka untuk hal-hal itu, sehingga kamu tidak merancangnya dari nol.

Kapan belum relevan: ketika ISMS-mu sendiri belum berjalan stabil. Menambahkan sistem manajemen kedua di atas yang pertama yang masih goyah akan menggandakan beban tanpa menambah kepatuhan.

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

Jalur yang paling sering benar untuk organisasi menengah adalah memakai standar tambahan sebagai panduan untuk memperkuat ISMS yang ada, bukan sebagai sistem manajemen terpisah. Sertifikasi tambahan masuk akal ketika ada permintaan pasar yang nyata, dan itu keputusan bisnis, bukan keputusan teknis.

### 3.6 Menambah tanpa menggandakan

Bila kamu memutuskan menambah, prinsip yang sama seperti Day 18 berlaku:

- **Satu register risiko.** Risiko privasi dan risiko kelangsungan masuk ke register yang sama.
- **Satu program audit.** Lingkup audit internal diperluas, bukan program kedua.
- **Satu management review.** Agenda ditambah, bukan rapat baru.
- **Satu jalur tindakan korektif.** Temuan dari lingkup baru masuk ke jalur yang sama.
- **Dokumen yang menyatu.** Prosedur yang sudah ada diperluas bila memungkinkan, bukan diduplikasi.

Yang memang perlu terpisah: pernyataan keberlakuan untuk lingkup baru, bukti spesifik yang diminta auditor untuk standar itu, dan peran baru bila standarnya menuntutnya.

Satu uji sederhana untuk mengetahui apakah kamu menggandakan: bila orang yang sama diminta memberikan bukti yang sama kepada dua proses berbeda, kamu sedang menggandakan.

## 4. Contoh dokumen / artefak (organisasi fiktif)

> Seluruh isi di bawah adalah contoh untuk organisasi fiktif PT AN. Nomor kendali dan rincian standar tidak dikutip dari teksnya; isi dari hasil pembacaanmu sendiri bila kamu memiliki aksesnya.

### 4.1 Lembar keputusan penambahan standar

```
LEMBAR KEPUTUSAN                              Nomor: KS-2027-002
Standar yang dipertimbangkan : sistem manajemen informasi privasi
Disusun oleh                 : <nama>          Tanggal: 2027-04-10

1. PERMINTAAN PASAR
   Dua pelanggan menanyakan; satu mensyaratkan dalam proses pengadaan tahun depan.
   Nilai kontrak terkait: <angka>

2. CELAH YANG TIDAK TERTUTUP ISMS  (dari Day 18 bagian 4.2)
   dasar pemrosesan dan persetujuan   : belum ada proses
   hak subjek data                    : belum ada proses
   penilaian dampak pelindungan data  : belum ada proses

3. KESTABILAN ISMS SAAT INI
   audit internal berjalan sesuai program          : ya
   temuan siklus terakhir ditutup dan diverifikasi : 7 dari 9; 2 masih berjalan
   penilaian                                       : cukup stabil, dengan catatan

4. PERKIRAAN BEBAN
   peran baru            : pejabat pelindungan data (sudah ada, perlu diperjelas perannya)
   dokumen baru          : 4 prosedur, 1 pernyataan keberlakuan
   audit tambahan        : <perkiraan hari, tanyakan ke badan sertifikasi>
   biaya berkelanjutan   : <perkiraan>

REKOMENDASI
  Tahap 1 (2027): perluas ISMS dengan tiga proses di butir 2, tanpa sertifikasi.
  Tahap 2 (2028): tinjau ulang kebutuhan sertifikasi berdasarkan permintaan pasar nyata.
  Alasan: celah di butir 2 harus ditutup apa pun keputusan sertifikasinya, dan menutupnya
  lebih dulu membuat sertifikasi nanti jauh lebih murah.

CATATAN EDISI
  Pastikan rujukan memakai edisi terbaru; edisi sebelumnya sudah ditarik.
```

Blok rekomendasi dua tahap itu pola yang sering tepat: tutup celahnya dulu, putuskan sertifikasinya kemudian.

### 4.2 Matriks pembagian tanggung jawab awan

| Kendali | Penyedia | Pengguna (kami) | Bukti yang kami punya | Diuji? |
|---|---|---|---|---|
| Keamanan fisik pusat data | penuh | tidak ada | laporan audit penyedia | tidak perlu |
| Enkripsi data saat disimpan | menyediakan kemampuan | mengaktifkan dan mengelola kunci | konfigurasi; prosedur kunci | ya, 2027-02 |
| Manajemen akses ke konsol | menyediakan kemampuan | konfigurasi, tinjauan berkala | hasil tinjauan hak akses | ya, 2027-01 |
| Pencadangan data aplikasi | tidak, kecuali dinyatakan | penuh | konfigurasi pencadangan; uji pemulihan | belum diuji |
| Pencatatan aktivitas konsol | menyediakan kemampuan | mengaktifkan, mengumpulkan, meninjau | konfigurasi; catatan tinjauan | ya, 2027-03 |
| Respons insiden di lapis layanan | sebagian | penuh di lapis kami | prosedur IR-01 | ya, latihan meja |

Dua kolom terakhir yang membuat matriks ini bukan sekadar teori. Baris pencadangan yang belum diuji adalah temuan, dan ia akan muncul di audit bila kamu tidak menemukannya lebih dulu.

Catatan penting: menyebut laporan audit penyedia sebagai bukti hanya sah bila kamu benar-benar membacanya dan memeriksa lingkupnya (Day 17 bagian 3.4).

### 4.3 Daftar periksa kesiapan layanan

Dipakai sebelum memutuskan menambah standar kelangsungan:

```
DASAR YANG HARUS ADA LEBIH DULU
  [ ] Daftar layanan dengan tingkat kepentingannya terhadap bisnis
  [ ] Untuk tiap layanan kritis: berapa lama boleh berhenti, dan berapa banyak data boleh hilang
  [ ] Ketergantungan tiap layanan: sistem lain, pemasok, orang, lokasi
  [ ] Rencana pemulihan tertulis untuk layanan kritis
  [ ] Rencana itu PERNAH DIJALANKAN, bukan hanya dibaca
  [ ] Hasil uji dicatat, termasuk yang gagal
  [ ] Perbedaan antara target dan hasil uji ditindaklanjuti

BILA ADA YANG BELUM TERCENTANG
  kerjakan itu dulu; menambah standar tidak akan menambah ketahanan
```

Butir kelima yang membedakan organisasi yang siap dari yang merasa siap. Rencana yang tidak pernah dijalankan hampir selalu memuat asumsi yang keliru, dan asumsi itu baru ketahuan saat benar-benar dibutuhkan.

### 4.4 Rencana penambahan yang tidak menggandakan

| Unsur ISMS yang ada | Yang dilakukan | Yang tidak dilakukan |
|---|---|---|
| Register risiko | Tambahkan kategori risiko baru | Membuat register kedua |
| Program audit internal | Perluas lingkup area yang diaudit | Membuat program audit kedua |
| Management review | Tambahkan masukan ke agenda | Membuat rapat tinjauan kedua |
| Tindakan korektif | Pakai jalur yang sama | Membuat sistem tiket kedua |
| Prosedur insiden | Tambahkan jalur untuk jenis insiden baru | Membuat prosedur insiden kedua |
| Pernyataan keberlakuan | Buat yang terpisah untuk lingkup baru | Menggabungkan paksa ke yang lama |
| Peran | Perjelas peran yang sudah ada | Membuat struktur paralel |

Baris keenam adalah pengecualian yang disengaja: pernyataan keberlakuan memang perlu terpisah karena lingkupnya berbeda, dan menggabungkannya justru menyulitkan audit.

### 4.5 Menjelaskan ke manajemen

```
USULAN: MEMPERLUAS ISMS UNTUK PRIVASI

MASALAH YANG DISELESAIKAN
  Tiga kewajiban dari pemetaan regulasi (Day 18) tidak punya proses sama sekali di
  organisasi kita: dasar pemrosesan, hak subjek data, dan penilaian dampak.
  Ini bukan masalah keamanan; ISMS kita memang tidak dirancang untuk itu.

DUA PILIHAN
  A. Perluas ISMS dengan tiga proses baru, tanpa sertifikasi
     biaya: waktu tim, tanpa biaya audit tambahan
     hasil: kewajiban terpenuhi; tidak ada sertifikat untuk ditunjukkan pelanggan
  B. Perluas lalu sertifikasi
     biaya: pilihan A ditambah biaya audit dan biaya berkelanjutan
     hasil: kewajiban terpenuhi; ada sertifikat untuk pengadaan

REKOMENDASI
  A sekarang, tinjau B pada 2028 berdasarkan permintaan pasar yang nyata.

YANG PERLU DIPUTUSKAN HARI INI
  Persetujuan untuk pilihan A dan penunjukan pemilik ketiga proses baru.
```

Pola dua pilihan dengan rekomendasi ini jauh lebih mudah diputuskan daripada presentasi tentang isi standar.

## 5. Lab praktik

**Prasyarat:** hasil Day 12 (pemasok), Day 17 (sertifikasi), dan Day 18 (regulasi). Seluruh lab bersifat memeriksa katalog, menilai, dan menulis.

1. Periksa sendiri status terkini keempat standar di bagian 3.1 lewat katalog, dan catat bila ada yang sudah berubah lagi sejak catatan ini ditulis.
2. Cari tiga artikel daring tentang salah satu standar itu, lalu catat edisi mana yang dirujuk masing-masing dan apakah edisi itu masih berlaku.
3. Isi daftar periksa kesiapan layanan bagian 4.3 untuk organisasi fiktif PT AN, dan tandai butir yang belum tercentang.
4. Susun matriks pembagian tanggung jawab bagian 4.2 untuk tiga layanan awan yang benar-benar dipakai organisasi fiktifmu.
5. Untuk satu baris di matriks itu, uji asumsinya: cari dokumentasi penyedia dan buktikan siapa sebenarnya yang bertanggung jawab. Catat bila asumsimu keliru.
6. Ambil hasil pemetaan Day 18 bagian 4.2, lalu daftarkan kewajiban yang tidak punya padanan di ISMS.
7. Jalankan empat pertanyaan di bagian 3.5 untuk organisasi fiktifmu, dan tulis jawabannya satu per satu.
8. Susun lembar keputusan bagian 4.1 berdasarkan jawaban langkah 7.
9. Susun rencana penambahan bagian 4.4 untuk pilihan yang kamu rekomendasikan, dan pastikan tidak ada unsur yang digandakan.
10. Tulis usulan satu halaman bagian 4.5, lalu bacakan ke rekan yang berperan sebagai manajemen dan catat pertanyaan yang tidak bisa kamu jawab.

**Hasil yang sebaiknya tersimpan:**
- Status terkini keempat standar hasil pemeriksaan sendiri.
- Catatan edisi yang dirujuk tiga artikel daring beserta status edisi itu.
- Daftar periksa kesiapan layanan dengan penandaan butir yang belum tercentang.
- Matriks pembagian tanggung jawab untuk tiga layanan awan.
- Hasil pengujian satu asumsi tanggung jawab terhadap dokumentasi penyedia.
- Daftar kewajiban yang tidak punya padanan di ISMS.
- Jawaban atas empat pertanyaan keputusan.
- Lembar keputusan penambahan standar.
- Rencana penambahan tanpa penggandaan.
- Usulan satu halaman beserta daftar pertanyaan yang belum terjawab.

## 6. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa |
|---|---|---|
| Nomor kendali di artikel tidak cocok dengan standar | Artikel merujuk edisi yang sudah ditarik | Periksa edisi di katalog sebelum memakai perbandingan apa pun |
| Materi pelatihan membahas isi yang berbeda | Pelatihan sebelum revisi | Periksa tanggal materi; minta versi terbaru |
| Penambahan standar menambah beban tanpa hasil | ISMS dasar belum stabil | Jalankan pertanyaan 3 di bagian 3.5 lebih dulu |
| Orang yang sama diminta bukti yang sama dua kali | Sistem digandakan | Pakai tabel bagian 4.4 untuk menyatukan |
| Asumsi tanggung jawab awan ternyata keliru | Tidak pernah diuji ke dokumentasi penyedia | Uji tiap baris matriks, jangan hanya mengisi |
| Sertifikasi penyedia dianggap menutup kewajiban kita | Sisi pengguna tetap milik kita | Pisahkan kolom penyedia dan pengguna (bagian 4.2) |
| Rencana pemulihan gagal saat dibutuhkan | Tidak pernah dijalankan sungguhan | Jalankan uji pemulihan; catat yang gagal |
| Tidak jelas apakah standar privasi bisa berdiri sendiri | Posisinya berubah antar edisi | Tanyakan ke badan sertifikasi; katalog tidak menjawabnya |
| Manajemen menolak usulan | Diajukan sebagai isi standar, bukan sebagai masalah | Pakai bentuk bagian 4.5 |

## 7. Kesalahan umum dan jebakan

- Memakai perbandingan kendali dari internet tanpa memeriksa edisi yang dirujuknya.
- Menambahkan sistem manajemen kedua sementara yang pertama belum stabil.
- Menggandakan register, program audit, dan jalur tindakan korektif.
- Menganggap sertifikasi penyedia awan menutup tanggung jawab sisi pengguna.
- Mengisi matriks tanggung jawab tanpa menguji asumsinya ke dokumentasi penyedia.
- Melupakan pencadangan dan pemulihan sebagai tanggung jawab pengguna.
- Menambahkan standar kelangsungan sebelum punya analisis dampak dan uji pemulihan.
- Memperlakukan rencana pemulihan yang belum pernah dijalankan sebagai kesiapan.
- Mengajukan usulan ke manajemen dalam bentuk penjelasan isi standar.
- Menunda menutup celah kewajiban sambil menunggu keputusan sertifikasi.

## 8. Catatan terkini

- Keempat standar yang dibahas di Day ini direvisi dalam rentang waktu berdekatan, dan edisi lamanya sudah ditarik [S1][S2][S3][S4][S5]. Ini berarti sebagian besar materi daring tentangnya, termasuk perbandingan kendali dan templat, merujuk edisi yang tidak lagi berlaku.
- ISO/IEC 27031:2011 ditarik pada 16 Mei 2025 dan digantikan edisi 2025 [S1]. Bila panduan kelangsungan internalmu menyebut edisi 2011, perbarui rujukannya.
- ISO/IEC 27701 edisi kedua terbit pada 14 Oktober 2025, dan judulnya menandakan posisi yang berbeda dari edisi pertama yang disusun sebagai perluasan terhadap ISO/IEC 27001 dan 27002 [S4][S5]. Apakah ia kini bisa diterapkan tanpa ISMS adalah pertanyaan yang perlu kamu tanyakan ke badan sertifikasi.
- ISO 22301:2019 berstatus published dan ditandai sedang ditinjau [S6]. Bila kamu merencanakan sistem manajemen kelangsungan, perhitungkan kemungkinan edisi baru dalam rencana jangka menengahmu.
- ISO/IEC 27017 edisi 2026 terbit 27 Juli 2026 dan diselaraskan dengan 27002:2022 (Day 12). Templat pembagian tanggung jawab cloud yang masih memakai penomoran kontrol 2013 perlu dipetakan ulang.

## 9. Cheat sheet

```
STATUS (periksa sendiri; bagian ini paling cepat usang)
  ISO/IEC 27031  2011 DITARIK 16 Mei 2025  -> edisi 2025
  ISO/IEC 27017  2015 DITARIK              -> edisi 2026
  ISO/IEC 27018  2019 DITARIK              -> edisi 2025
  ISO/IEC 27701  2019 DITARIK              -> edisi 2 terbit 14 Okt 2025
  ISO 22301      2019 published, SEDANG DITINJAU
  => hampir semua artikel/templat/pelatihan daring merujuk EDISI YANG SUDAH DITARIK
  => JANGAN pakai perbandingan kendali dari internet tanpa memeriksa edisinya

KELANGSUNGAN  ISO 22301 = SISTEM MANAJEMEN, bisa disertifikasi, menambah beban tata kelola
              ISO/IEC 27031 = PANDUAN kesiapan TIK, TIDAK disertifikasi
  jalur masuk akal untuk organisasi menengah: perkuat kendali kelangsungan DI DALAM ISMS
  SYARAT SEBELUM MENAMBAH APA PUN: ada analisis dampak + rencana PERNAH DIJALANKAN sungguhan
  rencana yang hanya dibaca selalu memuat asumsi keliru

CLOUD  27017 panduan kendali keamanan untuk layanan awan
       27018 pelindungan data pribadi pada layanan awan publik sebagai pemroses
  nilai terbesarnya = KERANGKA PEMBAGIAN TANGGUNG JAWAB penyedia vs pengguna
  SERTIFIKASI PENYEDIA TIDAK MEMINDAHKAN TANGGUNG JAWABMU; sisi pengguna tetap milikmu
  isi matriks + UJI asumsinya ke dokumentasi penyedia; jangan hanya mengisi
  yang sering terlewat: PENCADANGAN dan PEMULIHAN = tanggung jawab pengguna

PRIVASI  27701 untuk kewajiban yang TIDAK punya padanan di ISMS:
         dasar pemrosesan, persetujuan, HAK SUBJEK DATA, penilaian dampak
  posisinya BERUBAH antar edisi (perluasan 27001/27002 -> standar persyaratan tersendiri)
  bisa berdiri sendiri atau tidak: TANYAKAN KE BADAN SERTIFIKASI, katalog tidak menjawabnya
  JANGAN tambahkan bila ISMS sendiri belum stabil

EMPAT PERTANYAAN KEPUTUSAN
  1 ada pihak luar yang MEMINTA sertifikat? -> pertimbangkan sertifikasi, hitung biaya
  2 ada kewajiban TANPA PADANAN di ISMS?    -> perluas ISMS, tanpa sertifikasi
  3 ISMS yang ada SUDAH STABIL?             -> kalau belum, perbaiki itu dulu
  4 beban tata kelola sebanding?            -> kalau tidak, pakai sebagai PANDUAN saja
  pola yang sering tepat: TUTUP CELAHNYA DULU, putuskan sertifikasinya kemudian

JANGAN GANDAKAN  satu register risiko | satu program audit | satu management review
                 satu jalur tindakan korektif | perluas prosedur, jangan duplikasi
  yang MEMANG terpisah: pernyataan keberlakuan lingkup baru + bukti khusus auditor
  UJI PENGGANDAAN: orang yang sama diminta bukti yang sama oleh dua proses = kamu menggandakan
```

## 10. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | ISO/IEC 27031:2011 Guidelines for information and communication technology readiness for business continuity (katalog) | https://committee.iso.org/standard/44374.html | primer (katalog ISO) | dilihat 2026-10-09 | Tinggi untuk judul, edisi pertama Maret 2011, status withdrawn pada 2025-05-16, dan keterangan bahwa versi baru ISO/IEC 27031:2025 tersedia |
| S2 | ISO/IEC 27017:2015 Code of practice for information security controls for cloud services (katalog) | https://committee.iso.org/standard/43757.html | primer (katalog ISO) | dilihat 2026-10-09 | Tinggi untuk status withdrawn dan keterangan bahwa edisi penggantinya ISO/IEC 27017:2026 |
| S3 | ISO/IEC 27018:2019 Protection of personally identifiable information (PII) in public clouds acting as PII processors (katalog) | https://committee.iso.org/standard/76559.html | primer (katalog ISO) | dilihat 2026-10-09 | Tinggi untuk status withdrawn dan keterangan bahwa edisi penggantinya ISO/IEC 27018:2025 |
| S4 | ISO/IEC 27701:2019 Extension to ISO/IEC 27001 and ISO/IEC 27002 for privacy information management (katalog) | https://committee.iso.org/standard/71670.html | primer (katalog ISO) | dilihat 2026-10-09 | Tinggi untuk judul edisi lama yang menyatakan posisinya sebagai perluasan, dan untuk status withdrawn |
| S5 | ISO/IEC 27701:2025 Privacy information management systems, requirements and guidance (katalog) | https://committee.iso.org/standard/85819.html | primer (katalog ISO) | dilihat 2026-10-09 | Tinggi untuk judul, edisi 2, tanggal terbit 2025-10-14, dan status published pada stage 60.60 |
| S6 | ISO 22301:2019 Business continuity management systems (katalog) | https://committee.iso.org/standard/75106.html | primer (katalog ISO) | dilihat 2026-10-09 | Tinggi untuk edisi dan keterangan bahwa standar ini sedang ditinjau |
| S7 | ISO27001-note Day 01, 02, 08, 12, 15, 16, 17, 18 | (lokal) | rujukan internal | 2026-10-09 | Keterkaitan antar Day |

**Catatan sumber:** dari katalog ISO hanya diambil judul, edisi, tanggal, dan status. Penjelasan isi masing-masing standar, termasuk kerangka pembagian tanggung jawab cloud dan cakupan standar privasi, disusun dari judul resmi dan praktik umum, bukan parafrase teksnya. Tanggal terbit ISO/IEC 27031:2025 dan 27018:2025 perlu dicek di halaman katalog edisi barunya. Apakah ISO/IEC 27701:2025 bisa disertifikasi tanpa ISMS 27001 dan bagaimana transisi sertifikat edisi 2019 diatur perlu ditanyakan ke badan sertifikasi. Seluruh angka, nama, dan isi di bagian 4 adalah fiktif.
