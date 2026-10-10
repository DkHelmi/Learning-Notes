---
day: 17
title: 'Sistem sertifikasi dan akreditasi: siapa mengaudit auditor, dan apa arti sertifikat'
researched_on: 2026-10-10
versions_checked: 'ISO/IEC 17021-1:2015 Conformity assessment, requirements for bodies providing audit and certification of management systems (published, stage 60.60, ditandai under review); ISO/IEC 27006-1:2024 edisi 1, terbit Maret 2024; International Accreditation Forum (iaf.nu); IAF CertSearch; rujukan Day 01, 06, 13, 15, 16'
---

# Day 17: Sistem sertifikasi dan akreditasi

Cakupan: memahami rantai kepercayaan di balik sertifikat ISO 27001, cara memilih badan sertifikasi, dan apa yang sebenarnya dijamin maupun tidak dijamin oleh sebuah sertifikat.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- menjelaskan rantai akreditasi dari badan sertifikasi sampai pengakuan internasional.
- membedakan sertifikat terakreditasi dari sertifikat yang tidak terakreditasi.
- menyebutkan standar yang mengatur badan sertifikasi dan apa yang diaturnya.
- memverifikasi keabsahan sebuah sertifikat yang ditunjukkan pemasok.
- memilih badan sertifikasi dengan pertimbangan yang bisa dipertanggungjawabkan.
- menjelaskan batas makna sertifikat kepada pelanggan atau manajemen tanpa melebih-lebihkan.

## 2. Konteks singkat

Day 13 membahas siklus sertifikasi tiga tahun dari sisi organisasi yang diaudit. Day ini melihat satu lapis di atasnya: siapa yang mengawasi badan sertifikasi, dan kenapa hal itu menentukan nilai sertifikat yang kamu pegang maupun yang ditunjukkan pemasokmu.

Pertanyaan ini bukan akademis. Dua organisasi bisa sama-sama memegang sertifikat ISO 27001 dengan nilai yang sangat berbeda, karena lingkupnya berbeda, badan sertifikasinya berbeda, atau salah satunya tidak terakreditasi sama sekali. Analis yang menilai risiko pemasok (Day 12) perlu bisa membedakannya, dan praktisi yang menyiapkan organisasinya sendiri perlu tahu apa yang ia beli.

Isi Day ini adalah penjelasan praktik tentang sistem akreditasi dan sertifikasi. Rincian angka (misalnya jumlah hari audit) bergantung pada standar untuk badan sertifikasi dan aturan badan akreditasi, jadi cocokkan dengan badan akreditasi dan badan sertifikasi di wilayahmu sebelum dipakai untuk keputusan pengadaan.

## 3. Konsep inti

### 3.1 Rantai kepercayaan

Sertifikat ISO 27001 bernilai karena ada rantai yang bisa ditelusuri ke atas:

```
organisasi yang disertifikasi
  diaudit oleh  ->  badan sertifikasi (certification body)
  yang diakreditasi oleh  ->  badan akreditasi nasional
  yang saling mengakui lewat  ->  pengaturan pengakuan multilateral internasional
```

Tiap lapis punya aturannya sendiri. Badan sertifikasi tunduk pada persyaratan untuk lembaga yang melakukan audit dan sertifikasi sistem manajemen, yaitu ISO/IEC 17021-1 yang edisi 2015-nya berstatus published dan ditandai sedang ditinjau [S1]. Untuk sertifikasi ISMS secara khusus, ada persyaratan tambahan dalam ISO/IEC 27006-1:2024, edisi pertama yang terbit Maret 2024 [S2].

Lapis paling atas adalah pengaturan pengakuan antar badan akreditasi, yaitu IAF MLA (Multilateral Recognition Arrangement) yang dikelola International Accreditation Forum [S3]. Fungsinya membuat sertifikat yang diterbitkan di satu negara diakui di negara lain, dan itulah yang membuat sertifikat punya arti lintas batas. Di Indonesia, badan akreditasi nasionalnya adalah KAN (Komite Akreditasi Nasional), yang sekretariatnya berada di BSN. Badan sertifikasi yang menerbitkan sertifikat ISO 27001 terakreditasi KAN menempatkan logo atau nomor akreditasi KAN di sertifikatnya; badan sertifikasi asing bisa diakreditasi badan akreditasi negaranya sendiri, misalnya UKAS (Inggris) atau JAS-ANZ (Australia dan Selandia Baru).

Bila satu lapis hilang, nilainya runtuh. Sertifikat dari badan yang tidak terakreditasi tidak punya pengawas di atasnya, sehingga tidak ada yang memastikan auditnya memenuhi aturan apa pun.

### 3.2 Terakreditasi dan tidak terakreditasi

Keduanya sama-sama menghasilkan dokumen yang bertuliskan ISO 27001, dan di situlah kebingungan muncul.

| Aspek | Terakreditasi | Tidak terakreditasi |
|---|---|---|
| Pengawas badan sertifikasi | Badan akreditasi, dengan audit berkala | Tidak ada |
| Aturan yang mengikat auditnya | Persyaratan untuk badan sertifikasi [S1][S2] | Aturan badan itu sendiri |
| Kompetensi auditor | Diatur dan diperiksa | Tidak dijamin |
| Pengakuan lintas negara | Lewat pengaturan pengakuan [S3] | Tidak ada |
| Harga | Lebih tinggi | Sering jauh lebih murah |

Cara mengenali di lapangan: sertifikat terakreditasi mencantumkan logo atau nomor badan akreditasi, bukan hanya logo badan sertifikasi. Bila yang ada hanya logo badan sertifikasi, periksa lebih jauh.

Perlu kehati-hatian dalam menyampaikannya. Sertifikat tidak terakreditasi tidak otomatis berarti auditnya buruk, tetapi berarti tidak ada pihak ketiga yang menjaminnya. Dalam penilaian pemasok, itu perbedaan yang perlu kamu catat apa adanya, bukan dijadikan tuduhan.

### 3.3 Apa yang diatur tentang badan sertifikasi

Tanpa membaca teksnya, yang bisa kamu ketahui dari judul dan cakupan kedua standar adalah jenis hal yang diatur [S1][S2]: persyaratan bagi lembaga yang melakukan audit dan sertifikasi sistem manajemen, ditambah persyaratan khusus untuk sertifikasi sistem manajemen keamanan informasi.

Hal-hal yang diatur dan berguna kamu ketahui:

- **Imparsialitas.** Badan sertifikasi tidak boleh mengaudit sesuatu yang ia konsultasikan sendiri. Inilah alasan konsultan ISMS-mu tidak boleh menjadi badan sertifikasimu.
- **Kompetensi auditor.** Ada persyaratan tentang pengetahuan dan pengalaman auditor untuk lingkup yang diaudit.
- **Waktu audit.** Standar persyaratan khusus ISMS memuat tabel dasar jumlah hari audit berdasarkan jumlah personel efektif di dalam lingkup, lalu disesuaikan naik atau turun menurut kompleksitas (jumlah lokasi, kerumitan TI, kegiatan yang dialihdayakan). Ini penting bagi pembeli, karena penawaran dengan jumlah hari yang jauh lebih sedikit dari badan lain patut dipertanyakan. Angka di tabelnya perlu dicek di teks ISO/IEC 27006-1.
- **Proses sertifikasi.** Tahapan, keputusan sertifikasi yang terpisah dari tim audit, dan penanganan ketidaksesuaian.

Selain standar ISO, badan sertifikasi terakreditasi juga terikat dokumen wajib IAF (IAF Mandatory Documents), misalnya aturan audit multi-lokasi dan pemakaian teknologi untuk audit jarak jauh. Untuk rincian angka dan bunyi persyaratannya, cocokkan dengan teks standar atau tanyakan ke badan akreditasi.

### 3.4 Memverifikasi sertifikat yang ditunjukkan pemasok

Ini keterampilan praktis yang langsung dipakai di penilaian pemasok (Day 12). Langkahnya:

```
1. Baca LINGKUP di sertifikat, bukan hanya namanya.
   Lingkup bisa jauh lebih sempit dari yang disangka, misalnya hanya satu kantor
   atau hanya satu layanan.
2. Periksa TANGGAL berlaku dan tanggal terbit.
   Sertifikat yang masa berlakunya hampir habis perlu ditanyakan status surveillance-nya.
3. Periksa BADAN AKREDITASI yang tercantum, bukan hanya badan sertifikasi.
4. VERIFIKASI ke basis data badan sertifikasi, badan akreditasi, atau IAF CertSearch,
   bukan ke dokumen yang diberikan pemasok.
5. Minta STATEMENT OF APPLICABILITY bila relevan, atau setidaknya daftar kendali yang
   dikecualikan beserta alasannya.
6. Tanyakan TEMUAN terbuka dari audit terakhir bila hubungannya memungkinkan.
```

Langkah keempat yang paling sering dilewat dan paling penting. Dokumen bisa dipalsukan; basis data penerbitnya tidak. IAF CertSearch adalah basis data global sertifikat terakreditasi yang diisi oleh badan sertifikasi peserta [S6]. Tidak semua badan sertifikasi mengunggah datanya, jadi bila sertifikat tidak ditemukan di sana, lanjutkan ke basis data badan sertifikasi penerbitnya sebelum menyimpulkan apa pun.

Langkah kelima sering ditolak dengan alasan kerahasiaan, dan penolakan itu wajar. Yang bisa kamu minta sebagai gantinya adalah pernyataan tertulis bahwa kendali tertentu yang relevan bagimu termasuk dalam lingkup.

### 3.5 Memilih badan sertifikasi

Pertimbangan yang bisa dipertanggungjawabkan, selain harga:

| Pertimbangan | Kenapa penting |
|---|---|
| Akreditasi untuk lingkup yang kamu butuhkan | Akreditasi diberikan per lingkup; tidak otomatis mencakup semuanya |
| Pengalaman auditor di sektormu | Auditor yang tidak memahami sektormu menghabiskan waktu pada hal yang salah |
| Jumlah hari audit yang ditawarkan | Jauh lebih sedikit dari penawaran lain patut dipertanyakan [S2] |
| Pengakuan di pasar pelangganmu | Beberapa pelanggan mensyaratkan badan akreditasi tertentu |
| Kontinuitas tim audit | Auditor yang sama lintas siklus menghemat waktu penjelasan |
| Kejelasan aturan tenggat temuan | Berbeda antar badan; tanyakan di muka (Day 13) |

Satu hal yang perlu disepakati di awal dan sering terlupakan: siapa yang menanggung biaya bila audit perlu diulang karena ketidaksesuaian mayor. Tanyakan sebelum menandatangani.

Dan satu batas yang tegas: badan sertifikasi tidak boleh menjadi konsultan yang membangun ISMS-mu, dan tidak boleh menjalankan audit internalmu (Day 13). Bila sebuah penawaran menjanjikan keduanya sekaligus, itu tanda bahaya.

### 3.6 Apa yang dijamin sertifikat, dan apa yang tidak

Bagian ini yang paling sering salah dipahami oleh manajemen maupun pelanggan.

**Yang dijamin.** Pada tanggal audit, untuk lingkup yang tertulis, sebuah sistem manajemen keamanan informasi ada dan memenuhi persyaratan standar menurut penilaian auditor berdasarkan sampel.

**Yang tidak dijamin.** Bahwa organisasi itu aman. Bahwa tidak akan terjadi insiden. Bahwa seluruh sistemnya tercakup. Bahwa kendali tertentu diterapkan, kecuali kamu memeriksa pernyataan keberlakuannya. Dan bahwa keadaan hari ini sama dengan keadaan saat audit.

Tiga kata kuncinya adalah tanggal, lingkup, dan sampel. Ketiganya membatasi makna sertifikat, dan ketiganya perlu kamu sebut saat menjelaskan ke siapa pun.

Cara menyampaikannya tanpa terdengar meremehkan: sertifikat membuktikan ada sistem yang dijalankan dan diperiksa pihak ketiga secara berkala, dan itu berbeda jauh dari tidak ada apa-apa. Yang ia tidak lakukan adalah menggantikan penilaian risikomu sendiri terhadap pemasok itu.

## 4. Contoh dokumen / artefak (organisasi fiktif)

> Seluruh isi di bawah adalah contoh untuk organisasi fiktif PT AN. Nama badan, nomor, dan tanggal adalah fiktif. Rincian aturan badan sertifikasi perlu kamu verifikasi ke badan yang sebenarnya.

### 4.1 Lembar verifikasi sertifikat pemasok

```
VERIFIKASI SERTIFIKAT PEMASOK                 Nomor: VSP-2027-009
Pemasok   : PT Contoh Layanan          Dinilai oleh : <nama>, tanggal 2027-03-04

DOKUMEN YANG DITERIMA
  Sertifikat ISO/IEC 27001:2022, nomor <fiktif>, terbit 2025-08-12, berlaku sampai 2028-08-11

PEMERIKSAAN
  [x] Lingkup dibaca
      Tertulis: "Penyediaan layanan hosting aplikasi di pusat data Jakarta"
      CATATAN: layanan yang kami pakai berjalan di pusat data Surabaya. DI LUAR LINGKUP.
  [x] Tanggal berlaku diperiksa          -> masih berlaku
  [x] Surveillance terakhir ditanyakan   -> dinyatakan 2026-09, bukti belum diberikan
  [x] Badan akreditasi tercantum         -> ya, nomor <fiktif>
  [x] Diverifikasi ke basis data penerbit -> ya, cocok, status aktif
  [ ] Statement of Applicability diminta  -> ditolak dengan alasan kerahasiaan
  [x] Pernyataan tertulis pengganti       -> diminta untuk kendali A.5.23, A.8.15, A.8.16

KESIMPULAN
  Sertifikat sah dan terverifikasi, TETAPI lingkupnya tidak mencakup layanan yang kami pakai.
  Nilai jaminan terhadap risiko kami: RENDAH.

TINDAK LANJUT
  Minta konfirmasi tertulis apakah pusat data Surabaya mengikuti sistem manajemen yang sama.
  Bila tidak, perlakukan sebagai pemasok tanpa sertifikasi untuk layanan ini (Day 12).
```

Baris lingkup itu adalah temuan yang paling sering muncul di dunia nyata dan paling sering terlewat. Sertifikat sah, tetapi tidak menjamin apa pun untuk layanan yang benar-benar kamu pakai.

### 4.2 Daftar pertanyaan saat memilih badan sertifikasi

```
PERTANYAAN KE CALON BADAN SERTIFIKASI

AKREDITASI
  1. Badan akreditasi mana yang mengakreditasi Anda, dan untuk lingkup apa?
  2. Apakah lingkup akreditasi Anda mencakup sektor kami?
  3. Bagaimana kami memverifikasi status akreditasi Anda secara mandiri?

AUDITOR
  4. Berapa pengalaman auditor yang akan ditugaskan di sektor kami?
  5. Apakah tim audit akan sama lintas siklus?
  6. Bagaimana Anda memastikan auditor tidak pernah terlibat konsultasi pada kami?

WAKTU DAN BIAYA
  7. Berapa hari audit untuk tahap 1 dan tahap 2, dan apa dasar perhitungannya?
  8. Berapa hari untuk surveillance tahunan dan untuk recertification?
  9. Siapa menanggung biaya bila audit perlu diulang karena ketidaksesuaian mayor?
 10. Apa yang termasuk dan tidak termasuk dalam harga?

PROSES
 11. Berapa tenggat penyelesaian untuk ketidaksesuaian mayor dan minor?
 12. Apa yang terjadi bila tenggat tidak terpenuhi?
 13. Bagaimana keputusan sertifikasi dibuat, dan apakah terpisah dari tim audit?
 14. Bagaimana prosedur banding bila kami tidak setuju dengan temuan?

JAWABAN DICATAT DAN DIBANDINGKAN ANTAR PENAWARAN, bukan hanya harganya.
```

Pertanyaan ketujuh dan kedelapan yang paling membedakan penawaran. Penawaran dengan jumlah hari yang jauh lebih kecil biasanya bukan efisiensi.

### 4.3 Menjelaskan arti sertifikat ke manajemen

Satu halaman yang bisa kamu pakai berulang:

```
APA YANG KITA PEROLEH DARI SERTIFIKASI

YANG DIBUKTIKAN
  Pada tanggal audit, untuk lingkup "<tulis lingkup persisnya>", ada sistem manajemen
  keamanan informasi yang dijalankan dan memenuhi persyaratan standar, menurut penilaian
  auditor pihak ketiga berdasarkan sampel.

YANG TIDAK DIBUKTIKAN
  Bahwa kita aman dari serangan.
  Bahwa tidak akan terjadi insiden.
  Bahwa seluruh sistem kita tercakup; yang tercakup hanya yang ada di lingkup.
  Bahwa keadaan hari ini sama dengan keadaan saat audit.

NILAI NYATANYA
  Ada disiplin yang dijalankan dan diperiksa pihak luar secara berkala.
  Ada jalur perbaikan yang tercatat ketika sesuatu tidak berjalan.
  Ada bahasa bersama saat pelanggan menanyakan keamanan kita.

BIAYA BERKELANJUTAN YANG PERLU DIANGGARKAN
  audit surveillance tahunan, audit internal, waktu tim untuk menyiapkan bukti,
  dan tindakan korektif yang muncul dari keduanya
```

Blok terakhir sering tidak dibicarakan sampai tahun kedua, dan ketidaksiapan di situ adalah penyebab umum sertifikasi berubah menjadi beban.

### 4.4 Membandingkan dua penawaran

| Aspek | Badan A | Badan B | Catatan |
|---|---|---|---|
| Badan akreditasi | tercantum, terverifikasi | tercantum, tidak ditemukan di basis data | B perlu diklarifikasi |
| Lingkup akreditasi mencakup sektor | ya | tidak jelas | |
| Hari audit tahap 1 dan 2 | 3 dan 7 | 1 dan 3 | Selisih besar; tanyakan dasarnya |
| Pengalaman auditor di sektor | 2 auditor, masing-masing lebih dari 5 tahun | tidak dijawab | |
| Tenggat ketidaksesuaian mayor | 60 hari | 90 hari | Keduanya wajar; pastikan tertulis |
| Biaya audit ulang | ditanggung kami | tidak dijawab | Klarifikasi sebelum tanda tangan |
| Harga total tiga tahun | lebih tinggi | lebih rendah | Selisih sebagian dijelaskan oleh hari audit |

Tabel semacam ini mengubah keputusan dari perbandingan harga menjadi perbandingan yang bisa dipertanggungjawabkan. Simpan sebagai lampiran keputusan pengadaan.

## 5. Lab praktik

**Prasyarat:** hasil Day 12 (penilaian pemasok) dan Day 13 (audit dan bukti). Seluruh lab bersifat membaca, memverifikasi, dan menulis.

1. Cari situs badan akreditasi di negaramu, lalu catat bagaimana cara memverifikasi status akreditasi sebuah badan sertifikasi di sana.
2. Cari basis data atau direktori yang memungkinkan verifikasi sertifikat yang diterbitkan, lalu coba verifikasi satu sertifikat yang dipublikasikan terbuka oleh sebuah organisasi.
3. Ambil satu sertifikat ISO 27001 yang dipublikasikan di situs perusahaan mana pun, lalu baca lingkupnya dan tulis apa yang sebenarnya dijamin dan tidak.
4. Isi lembar verifikasi bagian 4.1 untuk sertifikat itu, sejauh informasi publik memungkinkan, dan tandai bagian yang tidak bisa kamu verifikasi.
5. Susun daftar pertanyaan bagian 4.2 dalam bentuk yang siap dikirim, lalu tandai lima pertanyaan yang paling menentukan bagi organisasi fiktif PT AN.
6. Cari informasi publik dari dua badan sertifikasi tentang proses mereka, lalu isi tabel perbandingan bagian 4.4 sejauh informasinya tersedia.
7. Tulis satu halaman penjelasan arti sertifikat memakai bentuk bagian 4.3, lalu bacakan ke rekan non-teknis dan catat bagian yang disalahpahami.
8. Tulis paragraf untuk laporan penilaian pemasok yang menjelaskan temuan lingkup seperti di bagian 4.1, dengan nada faktual dan tanpa menuduh.
9. Periksa apakah standar yang mengatur badan sertifikasi sudah punya edisi baru sejak catatan ini ditulis, lalu perbarui catatanmu bila ada [S1][S2].

**Hasil yang sebaiknya tersimpan:**
- Cara memverifikasi akreditasi badan sertifikasi di negaramu.
- Hasil percobaan verifikasi satu sertifikat ke basis data penerbitnya.
- Analisis lingkup satu sertifikat publik beserta batas jaminannya.
- Lembar verifikasi terisi dengan penandaan bagian yang tidak terverifikasi.
- Daftar pertanyaan siap kirim dengan lima pertanyaan yang ditandai paling menentukan.
- Tabel perbandingan dua badan sertifikasi dari informasi publik.
- Satu halaman penjelasan arti sertifikat beserta catatan bagian yang disalahpahami.
- Paragraf laporan pemasok tentang temuan lingkup.
- Catatan status edisi standar yang mengatur badan sertifikasi.

## 6. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa |
|---|---|---|
| Sertifikat terlihat sah tetapi tidak ditemukan di basis data | Tidak terakreditasi, atau basis data yang salah | Verifikasi ke badan akreditasi yang tercantum [S3] |
| Hanya logo badan sertifikasi, tanpa logo akreditasi | Kemungkinan tidak terakreditasi | Tanyakan langsung; catat jawabannya apa adanya |
| Pemasok menolak memberi pernyataan keberlakuan | Alasan kerahasiaan yang wajar | Minta pernyataan tertulis untuk kendali tertentu saja |
| Lingkup sertifikat tidak mencakup layanan yang dipakai | Hal yang sangat umum | Perlakukan sebagai tanpa sertifikasi untuk layanan itu (Day 12) |
| Penawaran hari audit jauh lebih sedikit | Dasar perhitungan berbeda, atau lingkup berbeda | Tanyakan dasarnya; bandingkan lingkup yang ditawarkan [S2] |
| Badan menawarkan konsultasi sekaligus sertifikasi | Imparsialitas terancam | Hindari; pisahkan kedua peran |
| Tenggat temuan berbeda antar penawaran | Memang berbeda antar badan | Pastikan tertulis di kontrak (Day 13) |
| Manajemen menganggap sertifikat berarti aman | Batas makna tidak dijelaskan | Pakai satu halaman bagian 4.3 |
| Biaya tahun kedua mengejutkan | Biaya berkelanjutan tidak dianggarkan | Masukkan ke anggaran sejak awal (bagian 4.3) |

## 7. Kesalahan umum dan jebakan

- Membaca nama standar di sertifikat tanpa membaca lingkupnya.
- Menerima dokumen sertifikat dari pemasok tanpa memverifikasi ke penerbitnya.
- Menganggap semua sertifikat ISO 27001 setara.
- Tidak memeriksa apakah badan sertifikasinya terakreditasi.
- Memakai badan sertifikasi yang juga menjadi konsultan atau auditor internalmu.
- Memilih badan sertifikasi hanya berdasarkan harga.
- Tidak menanyakan dasar perhitungan hari audit.
- Tidak menyepakati siapa menanggung biaya audit ulang.
- Menyampaikan sertifikat kepada pelanggan sebagai jaminan keamanan.
- Tidak menganggarkan biaya berkelanjutan sejak tahun pertama.

## 8. Catatan terkini

- Persyaratan untuk badan yang melakukan audit dan sertifikasi sistem manajemen, ISO/IEC 17021-1:2015, berstatus published tetapi ditandai sedang ditinjau [S1]. Perkirakan akan ada edisi baru; periksa statusnya sebelum mengutip rinciannya di dokumen resmi.
- Persyaratan khusus untuk badan yang menyertifikasi ISMS terbit sebagai ISO/IEC 27006-1:2024, edisi pertama pada Maret 2024 [S2]. Penomoran dengan akhiran satu menandakan keluarga dokumen yang bisa bertambah bagiannya, jadi periksa apakah ada bagian lain yang relevan bagimu.
- Pengakuan lintas negara bersandar pada pengaturan antar badan akreditasi yang dikelola forum akreditasi internasional [S3]. Bila pelangganmu berada di negara lain, periksa apakah badan akreditasi badan sertifikasimu termasuk dalam pengaturan itu.
- Temuan lingkup yang tidak mencakup layanan yang benar-benar dipakai adalah hal yang sangat sering ditemukan di penilaian pemasok. Jadikan pembacaan lingkup langkah pertama yang wajib, bukan langkah tambahan.

## 9. Cheat sheet

```
RANTAI KEPERCAYAAN
  organisasi -> badan sertifikasi -> badan akreditasi nasional -> pengakuan multilateral internasional
  satu lapis hilang = nilainya runtuh
  aturan badan sertifikasi : ISO/IEC 17021-1:2015 (published, UNDER REVIEW)
  tambahan khusus ISMS     : ISO/IEC 27006-1:2024 (edisi 1, Maret 2024)

TERAKREDITASI vs TIDAK
  cek LOGO/NOMOR BADAN AKREDITASI di sertifikat, bukan hanya logo badan sertifikasi
  tidak terakreditasi = tidak ada pengawas di atas badan sertifikasi
  bukan otomatis "auditnya buruk", tapi "tidak ada yang menjamin" -> catat apa adanya

VERIFIKASI SERTIFIKAT PEMASOK (urut)
  1 BACA LINGKUPNYA (paling sering jadi temuan; sering TIDAK mencakup layanan yang kamu pakai)
  2 tanggal berlaku + status surveillance terakhir
  3 badan akreditasi yang tercantum
  4 VERIFIKASI KE BASIS DATA PENERBIT, bukan ke dokumen dari pemasok  <- paling penting
  5 minta Statement of Applicability; kalau ditolak, minta pernyataan tertulis per kendali
  6 tanyakan temuan terbuka bila hubungannya memungkinkan

MEMILIH BADAN SERTIFIKASI (bukan cuma harga)
  akreditasi UNTUK LINGKUPMU | pengalaman auditor di sektormu | JUMLAH HARI AUDIT + dasarnya
  pengakuan di pasar pelangganmu | kontinuitas tim | kejelasan tenggat temuan
  sepakati DI MUKA: siapa menanggung biaya audit ulang karena mayor
  TIDAK BOLEH: badan sertifikasi yang juga konsultan atau auditor internalmu
  hari audit jauh lebih sedikit dari penawaran lain = tanyakan dasarnya, bukan hemat

ARTI SERTIFIKAT  3 kata kunci: TANGGAL, LINGKUP, SAMPEL
  DIJAMIN      : pada tanggal audit, untuk lingkup tertulis, ada ISMS yang memenuhi standar
                 menurut penilaian auditor berdasarkan sampel
  TIDAK DIJAMIN: organisasi itu aman | tidak akan ada insiden | seluruh sistem tercakup
                 | kendali tertentu diterapkan (cek SoA) | keadaan hari ini sama
  cara menyampaikan: ada disiplin yang dijalankan dan diperiksa pihak luar secara berkala,
  dan itu TIDAK menggantikan penilaian risikomu sendiri

ANGGARKAN  surveillance tahunan + audit internal + waktu tim menyiapkan bukti + tindakan korektif
```

## 10. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | ISO/IEC 17021-1:2015 Conformity assessment, requirements for bodies providing audit and certification of management systems (katalog) | https://committee.iso.org/standard/61651.html | primer (katalog ISO) | dilihat 2026-10-09 | Tinggi untuk judul, edisi, dan status: published pada stage 60.60 dan ditandai under review |
| S2 | ISO/IEC 27006-1:2024 Requirements for bodies providing audit and certification of information security management systems (katalog) | https://committee.iso.org/standard/82908.html | primer (katalog ISO) | dilihat 2026-10-09 | Tinggi untuk judul, edisi pertama, dan tanggal terbit Maret 2024 |
| S3 | International Accreditation Forum | https://iaf.nu/ | primer (situs forum akreditasi) | dilihat 2026-10-09 | Sedang-tinggi untuk keberadaan pengaturan pengakuan antar badan akreditasi; rincian cakupan dan daftar anggota perlu kamu periksa di situsnya |
| S4 | ISO/IEC 27001:2022 (katalog) | https://www.iso.org/standard/27001 | primer (katalog ISO) | dirujuk 2026-10-09 | Tinggi untuk keberadaan standar |
| S5 | ISO27001-note Day 01, 06, 12 (penilaian pemasok), 13 (audit dan bukti), 15, 16 | (lokal) | rujukan internal | 2026-10-09 | Keterkaitan antar Day |
| S6 | IAF CertSearch | https://www.iafcertsearch.org/ | primer (basis data IAF) | diakses 2026-10-10 | Sedang-tinggi untuk verifikasi sertifikat; cakupan data bergantung pada badan sertifikasi yang ikut mengunggah |

**Catatan sumber:** dari ISO/IEC 17021-1 dan ISO/IEC 27006-1 hanya diambil judul, edisi, tanggal, dan status dari katalog ISO. Penjelasan tentang imparsialitas, kompetensi auditor, dan dasar perhitungan hari audit adalah praktik umum yang dikenal luas, bukan kutipan teksnya; angka di tabel hari audit perlu dicek di teks 27006-1. Cara memverifikasi sertifikat dan daftar pertanyaan ke badan sertifikasi adalah susunan sendiri, bukan prosedur baku. Seluruh nama, nomor, dan tanggal di bagian 4 adalah fiktif.
