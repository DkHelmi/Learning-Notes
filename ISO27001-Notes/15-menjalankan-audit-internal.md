---
day: 15
title: 'Menjalankan audit internal: dari program sampai laporan, dari sisi auditor'
researched_on: 2026-10-10
versions_checked: 'ISO 19011:2026 Guidelines for auditing management systems (terbit, stage 60.60; ISO 19011:2018 berstatus withdrawn); ISO/IEC 27007:2020 Guidelines for information security management systems auditing (published, stage 90.92 yang menandakan sedang ditinjau); ISO/IEC 27001:2022 klausul 9.2; rujukan Day 06, 09, 11, 12, 13'
---

# Day 15: Menjalankan audit internal

Cakupan: menyiapkan dan menjalankan audit internal dari kursi auditor, mulai dari program tahunan sampai laporan yang bisa ditindaklanjuti.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- menyusun program audit internal yang cakupannya bisa dipertanggungjawabkan, bukan sekadar merata.
- menulis rencana dan daftar periksa audit untuk satu area teknis.
- menjalankan wawancara audit yang menghasilkan bukti, bukan hanya jawaban.
- mengambil sampel dengan cara yang bisa dijelaskan dan diulang.
- menulis temuan yang memuat pernyataan, bukti, dan kriteria secara terpisah.
- menjaga objektivitas dan independensi auditor dalam organisasi kecil.

## 2. Konteks singkat

Day 06 membahas klausul 9.2 sebagai persyaratan, dan Day 13 membahas bagaimana rasanya diaudit beserta cara menyiapkan bukti. Day ini melihat dari kursi sebaliknya: kamu yang menjadi auditor internal.

Posisi ini sering jatuh ke orang teknis di organisasi kecil, justru karena ia memahami sistemnya. Masalahnya, pemahaman teknis tanpa disiplin audit menghasilkan dua kegagalan khas: audit berubah menjadi sesi perbaikan teknis sehingga temuan tidak tercatat, atau audit berubah menjadi pemeriksaan dokumen sehingga keadaan sebenarnya tidak tersentuh.

Day ini membangun disiplin di antara keduanya. Panduan untuk mengaudit sistem manajemen ada di ISO 19011, yang edisi terbarunya terbit sebagai ISO 19011:2026 sementara edisi 2018 berstatus ditarik [S1]. Panduan khusus untuk audit sistem manajemen keamanan informasi ada di ISO/IEC 27007:2020, yang statusnya published tetapi berada di tahap yang menandakan sedang ditinjau [S2]. Isi Day ini adalah praktik audit internal yang umum dipakai, disusun dengan kata sendiri dan dibangun di atas Day 06 dan 13. Bila organisasimu perlu menunjukkan kesesuaian formal dengan panduan 19011 atau 27007, cocokkan langkah-langkah di sini dengan teks standarnya.

## 3. Konsep inti

### 3.1 Program audit, bukan daftar audit

Program audit adalah rencana beberapa periode, biasanya satu siklus sertifikasi, yang memastikan seluruh lingkup tersentuh dengan frekuensi yang sesuai risikonya. Yang membedakannya dari daftar audit biasa adalah dasar penentuan frekuensi.

Dasar yang bisa dipertanggungjawabkan:

| Faktor | Pengaruh pada frekuensi |
|---|---|
| Risiko area terhadap sasaran ISMS | Risiko tinggi diaudit lebih sering |
| Hasil audit sebelumnya | Area dengan temuan sebelumnya diaudit lebih cepat |
| Perubahan besar | Sistem baru, pemasok baru, atau reorganisasi memicu audit tambahan |
| Insiden | Area yang terlibat insiden masuk ke jadwal berikutnya |
| Kewajiban eksternal | Area yang disorot regulator atau pelanggan |

Yang perlu dihindari adalah membagi klausul secara merata ke dalam dua belas bulan tanpa alasan. Itu memenuhi persyaratan di atas kertas, tetapi auditor eksternal akan menanyakan dasar pemilihannya, dan tidak adanya dasar itu sendiri bisa menjadi temuan.

Satu kebiasaan yang membantu: catat alasan di sebelah tiap baris program. Satu kalimat per baris sudah cukup, dan kalimat itulah yang kamu bacakan saat ditanya.

### 3.2 Independensi dalam organisasi kecil

Prinsipnya auditor tidak mengaudit pekerjaannya sendiri. Di organisasi kecil, ini sering tampak mustahil karena orang yang paham sistem adalah orang yang membangunnya.

Tiga jalan keluar yang biasa dipakai:

- **Pertukaran antar fungsi.** Orang infrastruktur mengaudit area aplikasi dan sebaliknya, dengan pendamping yang paham areanya.
- **Auditor dari luar yang bukan badan sertifikasi.** Konsultan atau auditor independen bisa menjalankan audit internal; yang tidak boleh adalah badan sertifikasimu sendiri yang menjalankannya.
- **Audit berpasangan.** Dua orang mengaudit bersama, satu memahami area dan satu menjaga disiplin audit, dengan pembagian peran yang tertulis.

Apa pun yang dipilih, tuliskan pengaturan independensinya di rencana audit. Auditor eksternal akan menanyakannya, dan jawaban lisan tidak cukup.

### 3.3 Dari kriteria ke pertanyaan

Audit memeriksa kesesuaian terhadap kriteria, dan kriteria pada audit internal ISMS biasanya tiga lapis:

1. Persyaratan standar, yaitu klausul yang berlaku.
2. Dokumen internal organisasi, yaitu kebijakan dan prosedur yang kamu tetapkan sendiri.
3. Kewajiban eksternal yang relevan, misalnya kontrak dan regulasi.

Lapis kedua sering menghasilkan temuan paling banyak, karena organisasi menuliskan prosedur yang lebih ketat daripada yang benar-benar dijalankan. Perlu diingat bahwa ketidaksesuaian terhadap prosedur sendiri tetap ketidaksesuaian.

Cara menurunkan kriteria menjadi pertanyaan: untuk setiap kriteria, tanyakan tiga hal berurutan.

```
1. Apakah ada aturannya?        -> periksa dokumen
2. Apakah dijalankan?           -> minta bukti pelaksanaan
3. Apakah berjalan efektif?     -> periksa hasilnya, bukan hanya pelaksanaannya
```

Lapis ketiga yang membedakan auditor yang baik. Prosedur tinjauan hak akses yang dijalankan rutin tetapi tidak pernah menghasilkan pencabutan hak adalah bukti yang perlu dipertanyakan, bukan bukti yang menenangkan.

### 3.4 Wawancara yang menghasilkan bukti

Kesalahan paling umum adalah bertanya dengan cara yang jawabannya ya atau tidak. Jawaban itu bukan bukti.

Pola bertanya yang bekerja:

| Alih-alih | Tanyakan |
|---|---|
| Apakah kalian meninjau hak akses? | Tunjukkan tinjauan hak akses terakhir dan hasilnya |
| Apakah log dipantau? | Siapa yang memeriksa alert kemarin pagi, dan apa yang dilakukannya |
| Apakah ada prosedur insiden? | Ceritakan insiden terakhir dan tunjukkan jejaknya |
| Apakah backup diuji? | Kapan terakhir pemulihan diuji dan apa hasilnya |

Pola kedua di tabel itu menunjukkan teknik yang paling produktif: minta satu kejadian nyata yang baru, lalu telusuri jejaknya dari awal sampai akhir. Penelusuran satu kasus mengungkap lebih banyak daripada memeriksa sepuluh dokumen.

Tiga aturan sikap: catat apa yang dikatakan dan siapa yang mengatakannya; jangan memperbaiki apa pun selama audit, karena itu mengubah bukti dan mengaburkan temuan; dan jangan berdebat, karena tugasmu mengumpulkan bukti, bukan meyakinkan.

### 3.5 Sampling yang bisa dijelaskan

Day 13 membahas sampling dari sisi yang diaudit. Dari sisi auditor, yang penting adalah metodenya bisa dijelaskan dan diulang.

Tiga cara yang sah, dan masing-masing dipakai untuk tujuan berbeda:

| Cara | Kapan dipakai | Kelemahan |
|---|---|---|
| Acak | Ingin memperkirakan keadaan populasi | Bisa melewatkan kasus penting |
| Terarah | Ingin memeriksa kasus berisiko tinggi | Tidak bisa dipakai menyimpulkan populasi |
| Menyeluruh | Populasi kecil | Mahal pada populasi besar |

Yang harus kamu tulis di kertas kerja: ukuran populasi, jumlah sampel, cara pemilihan, dan alasan. Tanpa keempatnya, temuanmu bisa dibantah dengan mengatakan sampelnya kebetulan buruk.

Satu catatan jujur: tidak ada angka sampel baku yang berlaku umum. Aturan yang beredar berasal dari praktik tiap badan sertifikasi dan tiap organisasi. Tetapkan aturanmu sendiri secara tertulis, lalu konsisten, dan sebutkan bahwa itu aturan internal.

### 3.6 Menulis temuan

Temuan yang baik memisahkan tiga hal dan tidak mencampurnya:

```
PERNYATAAN : apa yang tidak sesuai, dalam satu kalimat
BUKTI      : apa yang kamu lihat, dengan identitas dan tanggal
KRITERIA   : klausul atau dokumen internal yang dilanggar
```

Yang sering salah adalah mencampurkan rekomendasi ke dalam temuan. Tugas auditor menyatakan apa yang tidak sesuai; menentukan cara memperbaikinya adalah tugas pemilik area, dan auditor yang menentukan perbaikan kehilangan independensinya untuk memeriksa perbaikan itu nanti.

Bila kamu melihat sesuatu yang baik, catat juga. Observasi positif membuat laporan lebih jujur dan membuat penerima lebih mau membaca bagian yang negatif.

### 3.7 Kertas kerja

Kertas kerja adalah catatan yang memungkinkan orang lain menelusuri bagaimana kamu sampai pada kesimpulan. Isinya: siapa yang diwawancarai dan kapan, dokumen apa yang diperiksa dengan versinya, sampel apa yang diambil dan bagaimana dipilih, apa yang dilihat, dan kesimpulan per kriteria.

Simpan terpisah dari laporan. Laporan untuk pembaca, kertas kerja untuk penelusuran, dan auditor eksternal kadang meminta yang kedua untuk menilai mutu audit internalmu.

## 4. Contoh dokumen / artefak (organisasi fiktif)

> Seluruh isi di bawah adalah contoh untuk organisasi fiktif PT AN. Angka, nama, dan aturan di dalamnya adalah aturan internal fiktif, bukan persyaratan standar.

### 4.1 Program audit internal dengan alasan

| Periode | Area | Kriteria utama | Alasan pemilihan |
|---|---|---|---|
| 2026 Q4 | Manajemen akses | A.5.15, A.5.18, prosedur AKS-01 | Dua temuan minor pada audit sebelumnya belum terverifikasi efektif |
| 2027 Q1 | Logging dan pemantauan | A.8.15, A.8.16, prosedur LOG-02 | Sumber log baru ditambahkan pada Q3 2026; belum pernah diaudit |
| 2027 Q1 | Manajemen pemasok | A.5.19 sampai A.5.22 | Dua pemasok baru dengan akses jaringan |
| 2027 Q2 | Respons insiden | Klausul 10, A.5.24 sampai A.5.28 | Satu insiden nyata pada Q4 2026; menguji pembelajarannya |
| 2027 Q3 | Klausul 4 sampai 7 | Konteks, kepemimpinan, risiko, dukungan | Siklus wajib; persiapan audit surveillance |
| 2027 Q4 | Kelangsungan dan pemulihan | A.5.29, A.5.30 | Belum pernah diuji sejak sistem dipindahkan ke cloud |

Kolom terakhir yang membuat program ini bisa dipertahankan. Tanpa kolom itu, tabel di atas hanya jadwal.

### 4.2 Rencana audit satu area

```
RENCANA AUDIT INTERNAL                     Nomor: AI-2027-01
Area        : Logging dan pemantauan
Tanggal     : 12 sampai 13 Februari 2027
Auditor     : <nama>, tidak terlibat dalam pengelolaan platform logging
Pendamping  : <nama>, memahami area tetapi tidak menilai
Independensi: auditor berasal dari fungsi aplikasi; pengaturan ini disepakati oleh <jabatan>

KRITERIA
  ISO/IEC 27001:2022 klausul 9.1; Annex A 8.15 dan 8.16
  Prosedur internal LOG-02 versi 3.1
  Kontrak pelanggan X pasal retensi log

LINGKUP
  Termasuk : platform SIEM, sumber log produksi, proses peninjauan alert harian
  Tidak termasuk : sistem pengembangan, log aplikasi pihak ketiga yang tidak terintegrasi

JADWAL
  Hari 1 pagi  : pembukaan, tinjauan dokumen
  Hari 1 siang : wawancara pengelola platform, pengambilan sampel
  Hari 2 pagi  : wawancara analyst, penelusuran satu alert nyata
  Hari 2 siang : verifikasi bukti, rapat penutup

ATURAN SAMPEL (internal)
  alert : 10 dari populasi 30 hari terakhir, acak, ditambah 3 terarah pada alert berprioritas tinggi
  sumber log : seluruh sumber yang ditambahkan setelah 1 Juli 2026
```

### 4.3 Daftar periksa yang berlapis tiga

| Kriteria | 1. Ada aturannya? | 2. Dijalankan? | 3. Efektif? |
|---|---|---|---|
| Sumber log yang wajib dikumpulkan ditetapkan | LOG-02 pasal 4 | Daftar sumber aktual vs daftar wajib | Ada sumber wajib yang tidak mengirim sejak kapan |
| Alert ditinjau setiap hari kerja | LOG-02 pasal 7 | Catatan peninjauan 30 hari terakhir | Berapa alert yang ditutup tanpa catatan alasan |
| Jam sistem diselaraskan | LOG-02 pasal 5 | Konfigurasi sumber waktu | Selisih waktu antar sumber pada satu kejadian nyata |
| Retensi sesuai kontrak | Kontrak pelanggan X | Konfigurasi retensi | Log tertua yang benar-benar ada |

Kolom ketiga yang membedakan audit ini dari pemeriksaan dokumen. Dua baris terakhir memakai teknik dari Day 11, yaitu memeriksa keadaan nyata, bukan konfigurasi yang diklaim.

### 4.4 Catatan wawancara

```
WAWANCARA                                   AI-2027-01 / W-03
Tanggal   : 13 Februari 2027, 09:10 sampai 09:55
Narasumber: <nama>, analyst SOC
Auditor   : <nama>

PERTANYAAN DAN JAWABAN (ringkas, bukan transkrip)
  Q: Tunjukkan alert yang kamu tangani kemarin pagi dan ceritakan langkahnya.
  A: Menunjukkan tiket #4412. Alert login tidak lazim. Diperiksa, ditutup sebagai false positive.
  Catatan auditor: tiket tidak memuat alasan penutupan; hanya status.

  Q: Kalau alert ini benar, apa langkah berikutnya?
  A: Eskalasi ke lead, lalu ikuti IR-01.
  Catatan auditor: jawaban sesuai prosedur; tidak diverifikasi karena tidak ada kasus nyata.

BUKTI YANG DIAMBIL
  tangkapan layar tiket #4412 (disimpan di kertas kerja, bukan di laporan)
  daftar 10 tiket sampel dengan kolom alasan penutupan
```

Perhatikan dua hal. Catatan auditor dipisahkan dari jawaban narasumber. Dan satu jawaban ditandai tidak terverifikasi, bukan diterima begitu saja; kejujuran semacam itu yang membuat kertas kerja bernilai.

### 4.5 Temuan dengan tiga bagian terpisah

```
TEMUAN AI-2027-01 / T-01                            Klasifikasi: minor

PERNYATAAN
  Penutupan alert tidak selalu disertai alasan, sehingga peninjauan ulang tidak dimungkinkan.

BUKTI
  Dari 10 tiket sampel periode 14 Januari sampai 12 Februari 2027, 6 ditutup tanpa
  catatan alasan (tiket #4380, #4391, #4402, #4412, #4418, #4425).
  Diperiksa pada 13 Februari 2027 bersama <nama>.

KRITERIA
  Prosedur internal LOG-02 versi 3.1 pasal 7.3 mewajibkan alasan penutupan dicatat.

CATATAN
  Tidak ada rekomendasi perbaikan di sini; penentuan tindakan adalah tanggung jawab pemilik area
  dan akan dicatat di lembar tindakan korektif (Day 16).
```

Baris catatan terakhir sengaja ada untuk mengingatkan pembaca, dan untuk melindungi independensimu saat memverifikasi perbaikannya nanti.

### 4.6 Ringkasan laporan audit

```
LAPORAN AUDIT INTERNAL                      AI-2027-01
Area, tanggal, auditor, kriteria, lingkup   : (lihat rencana)

KESIMPULAN
  ISMS pada area ini secara umum berjalan sesuai kriteria, dengan 1 temuan minor
  dan 2 observasi. Tidak ditemukan ketidaksesuaian mayor.

TEMUAN
  T-01 minor : penutupan alert tanpa alasan tercatat

OBSERVASI
  O-01 : dua sumber log yang ditambahkan Juli 2026 belum masuk daftar sumber wajib di LOG-02,
         walaupun sudah dikumpulkan; dokumen tertinggal dari praktik
  O-02 : peninjauan harian dilakukan konsisten termasuk pada hari libur nasional (positif)

CAKUPAN SAMPEL
  alert   : 13 dari sekitar 240 (10 acak, 3 terarah)
  sumber  : 4 dari 4 sumber baru (menyeluruh)

TIDAK DIPERIKSA
  log aplikasi pihak ketiga yang tidak terintegrasi (di luar lingkup; dicatat untuk program berikutnya)
```

Blok terakhir penting dan sering dihilangkan. Menyatakan apa yang tidak diperiksa mencegah laporan dibaca sebagai jaminan menyeluruh.

## 5. Lab praktik

**Prasyarat:** dokumen fiktif dari Day sebelumnya, terutama hasil Day 06, Day 09, dan Day 11. Seluruh lab bersifat menulis dan melatih wawancara dengan rekan.

1. Susun program audit internal satu siklus untuk PT AN memakai bentuk bagian 4.1, dan pastikan setiap baris punya alasan yang berbeda satu sama lain.
2. Tulis pengaturan independensi untuk organisasi dengan delapan orang di tim TI, lalu minta rekan menilai apakah pengaturan itu akan diterima auditor eksternal.
3. Susun rencana audit satu area memakai bentuk bagian 4.2, lengkap dengan aturan sampel internal dan alasannya.
4. Buat daftar periksa berlapis tiga bagian 4.3 untuk area yang sama, minimal delapan baris, dan pastikan kolom ketiga benar-benar menguji efektivitas, bukan pelaksanaan.
5. Latih wawancara dengan rekan yang berperan sebagai pemilik area. Pakai pola pertanyaan bagian 3.4, dan catat hasilnya dalam bentuk bagian 4.4.
6. Tinjau catatan wawancaramu: tandai mana yang bukti dan mana yang pernyataan lisan tanpa bukti. Hitung perbandingannya.
7. Ambil sampel dari populasi fiktif memakai ketiga cara di bagian 3.5, lalu tulis bagaimana kesimpulan yang bisa kamu tarik berbeda untuk masing-masing.
8. Tulis tiga temuan memakai bentuk bagian 4.5, lalu periksa apakah ada rekomendasi yang tercampur ke dalamnya dan buang bila ada.
9. Susun laporan ringkas bagian 4.6, termasuk blok tidak diperiksa.
10. Minta rekan membaca laporanmu dan menandai kalimat yang bisa dibantah karena buktinya tidak cukup. Perbaiki kalimat itu.

**Hasil yang sebaiknya tersimpan:**
- Program audit satu siklus dengan alasan per baris.
- Pengaturan independensi beserta penilaian rekan.
- Rencana audit satu area dengan aturan sampel.
- Daftar periksa berlapis tiga, minimal delapan baris.
- Catatan wawancara dengan pemisahan jawaban dan catatan auditor.
- Perbandingan jumlah bukti dan pernyataan lisan tanpa bukti.
- Perbandingan kesimpulan dari tiga cara sampling.
- Tiga temuan dengan tiga bagian terpisah.
- Laporan ringkas dengan blok tidak diperiksa.
- Daftar kalimat yang diperbaiki setelah ditinjau rekan.

## 6. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa |
|---|---|---|
| Audit berubah jadi sesi perbaikan teknis | Auditor memperbaiki selama audit | Catat, jangan perbaiki; perbaikan masuk jalur tindakan korektif |
| Semua jawaban ya tetapi tidak ada bukti | Pertanyaan berbentuk ya atau tidak | Pakai pola bagian 3.4; minta tunjukkan, bukan jelaskan |
| Temuan dibantah dengan alasan sampel buruk | Metode sampling tidak tercatat | Tulis populasi, jumlah, cara, dan alasan di kertas kerja |
| Auditor eksternal mempertanyakan program audit | Tidak ada dasar pemilihan frekuensi | Tambahkan kolom alasan (bagian 4.1) |
| Independensi dipertanyakan | Auditor mengaudit areanya sendiri | Pakai salah satu pengaturan di bagian 3.2 dan tuliskan |
| Laporan dianggap jaminan menyeluruh | Tidak ada blok tidak diperiksa | Tambahkan blok itu di setiap laporan |
| Temuan sulit ditindaklanjuti | Pernyataan, bukti, dan kriteria tercampur | Pisahkan menjadi tiga bagian (bagian 4.5) |
| Audit internal selalu bersih tanpa temuan | Lapis efektivitas tidak diuji | Tambahkan kolom ketiga di daftar periksa |
| Dokumen tertinggal dari praktik tidak terdeteksi | Hanya memeriksa dokumen, bukan keadaan nyata | Bandingkan daftar di dokumen dengan keadaan sistem |

## 7. Kesalahan umum dan jebakan

- Membagi klausul merata ke dalam setahun tanpa dasar risiko.
- Tidak menuliskan alasan pemilihan di program audit.
- Mengaudit area yang kamu kelola sendiri tanpa pengaturan independensi tertulis.
- Bertanya dengan pertanyaan yang jawabannya ya atau tidak.
- Menerima penjelasan lisan sebagai bukti.
- Memperbaiki masalah selama audit berlangsung.
- Mencampurkan rekomendasi ke dalam pernyataan temuan.
- Tidak mencatat metode sampling, sehingga temuan mudah dibantah.
- Hanya menguji keberadaan aturan dan pelaksanaannya, tanpa menguji efektivitasnya.
- Menulis laporan tanpa menyatakan apa yang tidak diperiksa.

## 8. Catatan terkini

- Panduan untuk mengaudit sistem manajemen terbit dalam edisi baru sebagai ISO 19011:2026, dan edisi 2018 berstatus ditarik [S1]. Materi pelatihan dan templat internal yang masih merujuk edisi lama perlu ditinjau, termasuk milik penyedia pelatihan.
- Panduan khusus audit ISMS, ISO/IEC 27007:2020, berstatus published tetapi berada pada tahap yang menandakan sedang ditinjau [S2]. Perkirakan akan ada edisi baru, dan jangan membangun templat yang terlalu terikat pada rincian edisi sekarang.
- Praktik di Day ini bukan parafrase 19011 atau 27007. Bila organisasimu memerlukan kesesuaian formal dengan panduannya, sesuaikan templat setelah mencocokkan dengan teks standar.
- Tidak ada angka sampel baku yang berlaku umum untuk audit internal. Yang beredar adalah praktik badan sertifikasi dan aturan internal organisasi. Tetapkan aturanmu sendiri secara tertulis dan konsisten.
- Audit internal yang tidak pernah menemukan apa pun hampir selalu berarti lapis efektivitas tidak diuji. Auditor eksternal mengenali pola itu, dan audit internal yang terlalu bersih justru menimbulkan pertanyaan.

## 9. Cheat sheet

```
PROGRAM AUDIT (bukan sekadar jadwal)
  dasar frekuensi: RISIKO area | hasil audit sebelumnya | perubahan besar | insiden | kewajiban eksternal
  TULIS ALASAN di sebelah tiap baris; tanpa itu, auditor eksternal akan mempertanyakannya
  membagi klausul merata tanpa alasan = memenuhi di atas kertas saja

INDEPENDENSI (organisasi kecil)
  pertukaran antar fungsi | auditor luar yang BUKAN badan sertifikasimu | audit berpasangan
  TULISKAN pengaturannya di rencana audit; jawaban lisan tidak cukup

KRITERIA 3 LAPIS  persyaratan standar | DOKUMEN INTERNAL SENDIRI | kewajiban eksternal
  lapis kedua sering paling banyak menghasilkan temuan (prosedur lebih ketat dari praktik)

TIGA PERTANYAAN BERURUTAN
  1 ada aturannya?  -> dokumen
  2 dijalankan?     -> bukti pelaksanaan
  3 EFEKTIF?        -> hasilnya, bukan pelaksanaannya
  audit yang selalu bersih = lapis 3 tidak diuji

WAWANCARA  jangan tanya ya/tidak; minta "TUNJUKKAN", bukan "jelaskan"
  teknik terbaik: ambil SATU kejadian nyata yang baru, telusuri dari awal sampai akhir
  catat siapa yang bicara | JANGAN memperbaiki selama audit | jangan berdebat

SAMPLING  acak (perkirakan populasi) | terarah (kasus berisiko) | menyeluruh (populasi kecil)
  WAJIB dicatat: ukuran populasi, jumlah sampel, cara pemilihan, ALASAN
  tidak ada angka baku yang berlaku umum; tetapkan aturan internal dan konsisten

TEMUAN  pisahkan: PERNYATAAN | BUKTI (identitas + tanggal) | KRITERIA
  JANGAN masukkan rekomendasi; itu tugas pemilik area, dan mencampurnya merusak independensimu
  catat juga observasi POSITIF

LAPORAN  selalu sertakan blok APA YANG TIDAK DIPERIKSA
         kertas kerja DIPISAH dari laporan; auditor eksternal kadang memintanya
```

## 10. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | ISO 19011:2026 Guidelines for auditing management systems (katalog) | https://committee.iso.org/standard/88984.html | primer (katalog ISO) | dilihat 2026-10-09 | Tinggi untuk edisi dan status: edisi 2026 terbit pada stage 60.60, dan ISO 19011:2018 ditandai withdrawn |
| S2 | ISO/IEC 27007:2020 Guidelines for information security management systems auditing (katalog) | https://committee.iso.org/standard/77802.html | primer (katalog ISO) | dilihat 2026-10-09 | Tinggi untuk edisi dan status: published dengan stage 90.92 yang menandakan sedang ditinjau |
| S3 | ISO/IEC 27001:2022 (katalog) | https://www.iso.org/standard/27001 | primer (katalog ISO) | dirujuk 2026-10-09 | Tinggi untuk keberadaan dan judul klausul 9.2 |
| S4 | ISO27001-note Day 06 (klausul 9 dan 10), Day 09 (manajemen risiko), Day 11 (logging dan waktu), Day 12 (pemasok), Day 13 (audit dan bukti) | (lokal) | rujukan internal | 2026-10-09 | Keterkaitan antar Day |

**Catatan sumber:** dari sumber primer hanya diambil edisi dan status ISO 19011:2026 dan ISO/IEC 27007:2020; isi Day ini adalah praktik audit internal yang umum, bukan parafrase kedua standar itu. Kode tahapan ISO (60.60 berarti standar sudah terbit, 90.92 berarti standar terbit yang diputuskan untuk direvisi) bisa dicek di penjelasan tahapan pengembangan standar ISO. Seluruh nomor prosedur, tiket, temuan, dan aturan sampel di bagian 4 adalah fiktif dan bukan persyaratan standar.
