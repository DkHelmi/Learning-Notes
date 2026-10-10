---
day: 18
title: 'Regulasi Indonesia dan ISMS: memetakan kewajiban ke kendali, menjalankan satu sistem'
researched_on: 2026-10-10
versions_checked: 'UU No. 27 Tahun 2022 tentang Pelindungan Data Pribadi (ditetapkan dan diundangkan 17 Oktober 2022); PP No. 71 Tahun 2019 tentang Penyelenggaraan Sistem dan Transaksi Elektronik (ditetapkan 4 Oktober 2019, berstatus berlaku); Peraturan BSSN No. 1 Tahun 2024 tentang Pengelolaan Insiden Siber (ditetapkan 10 Januari 2024); PP No. 33 Tahun 2026 sebagai peraturan pelaksana UU PDP menurut ringkasan pihak ketiga; rujukan Day 03, 04, 09, 10, 12, 16'
---

# Day 18: Regulasi Indonesia dan ISMS

Cakupan: menempatkan kewajiban regulasi Indonesia ke dalam ISMS yang sudah kamu bangun, sehingga satu sistem melayani beberapa kewajiban sekaligus.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- menyebutkan lapisan regulasi yang relevan bagi organisasi di Indonesia dan dasar hukumnya.
- memetakan kewajiban regulasi ke klausul dan kendali yang sudah ada di ISMS-mu.
- menyusun register kewajiban kepatuhan yang bisa ditinjau berkala.
- menghindari membangun sistem terpisah untuk tiap kewajiban.
- mengenali titik di mana kewajiban regulasi melampaui persyaratan standar.
- menuliskan status kepatuhan dengan jujur, termasuk ketidakpastian yang masih ada.

## 2. Konteks singkat

Day 03 membahas konteks dan pihak berkepentingan, dan salah satu masukan utamanya adalah kewajiban hukum. Day 16 di topik CTI membahas sisi pelaporan insiden dan batas berbagi informasi. Day ini mengerjakan sisi yang berbeda: bagaimana kewajiban regulasi masuk ke dalam ISMS sebagai persyaratan yang dikelola, bukan sebagai proyek terpisah setiap kali ada aturan baru.

Masalah yang hendak dicegah sederhana dan mahal. Organisasi yang memperlakukan setiap regulasi sebagai proyek sendiri akan punya beberapa daftar kendali, beberapa jadwal audit, dan beberapa tim yang menanyakan bukti yang sama kepada orang yang sama. ISMS yang dirancang baik menjadi tempat tunggal untuk semuanya.

Peringatan yang sama seperti di CTI Day 16 berlaku penuh di sini: catatan ini bukan nasihat hukum. Regulasi di wilayah ini bergerak cepat, dan sebagian informasi tentang perkembangan terbaru berasal dari ringkasan pihak ketiga. Verifikasi setiap kewajiban ke teks resmi dan libatkan penasihat hukum organisasimu untuk keputusan yang mengikat.

## 3. Konsep inti

### 3.1 Lapisan kewajiban

| Lapisan | Contoh | Sifat |
|---|---|---|
| Undang-undang | UU No. 27 Tahun 2022 tentang Pelindungan Data Pribadi [S1] | Mengikat umum |
| Peraturan pemerintah | PP No. 71 Tahun 2019 tentang Penyelenggaraan Sistem dan Transaksi Elektronik [S2] | Mengikat umum |
| Peraturan lembaga | Peraturan BSSN tentang pengelolaan insiden siber [S3] | Mengikat pada lingkup lembaga |
| Peraturan sektor | Ketentuan otoritas sektor keuangan, kesehatan, dan lainnya | Mengikat pada sektornya |
| Kontrak | Perjanjian dengan pelanggan dan pemasok | Mengikat para pihak |

Dua kesalahan yang berulang. Pertama, hanya memperhatikan lapisan pertama dan kedua, lalu terkejut oleh kewajiban sektor yang ternyata lebih rinci. Kedua, melupakan lapisan kelima, padahal kontrak sering memuat kewajiban keamanan yang lebih ketat daripada regulasi, lengkap dengan hak audit pelanggan.

Untuk ISMS, seluruh lapisan ini masuk sebagai persyaratan pihak berkepentingan di klausul 4 dan menjadi masukan bagi penilaian risiko di klausul 6 (Day 03 dan Day 04).

### 3.2 Dua regulasi yang menyentuh hampir semua organisasi

**Pelindungan data pribadi.** UU No. 27 Tahun 2022 ditetapkan dan diundangkan pada 17 Oktober 2022 [S1]. Ia memuat kewajiban bagi pengendali dan prosesor data pribadi, termasuk kewajiban memberitahukan kegagalan pelindungan data pribadi. Day 10 bagian 3.6 merangkum Pasal 46: pemberitahuan tertulis paling lambat 3 x 24 jam kepada subjek data dan lembaga, dengan isi minimum data yang terungkap, kapan dan bagaimana terungkap, serta upaya penanganan. Titik mulai hitungan jam itu yang paling sering diperdebatkan, jadi register dan prosedur di bagian 4 sengaja meminta kamu mengisinya dari teks resmi. Peraturan pelaksananya terbit sebagai PP No. 33 Tahun 2026 menurut ringkasan pihak ketiga, dengan tanggal mulai berlaku yang perlu kamu verifikasi sendiri ke teks resmi [S5].

**Penyelenggaraan sistem dan transaksi elektronik.** PP No. 71 Tahun 2019 ditetapkan 4 Oktober 2019 dan berstatus berlaku [S2]. Ia mengatur penyelenggaraan sistem elektronik, termasuk kewajiban bagi penyelenggara sistem elektronik. Bila organisasimu menyediakan layanan elektronik kepada publik, periksa apakah kewajiban pendaftaran dan kewajiban lain di dalamnya berlaku bagimu.

Keduanya punya irisan besar dengan ISMS, tetapi tidak identik dengannya. Yang perlu kamu lakukan adalah memetakan, bukan mengasumsikan bahwa sertifikasi ISO 27001 otomatis memenuhi keduanya.

### 3.3 Di mana kewajiban bertemu kendali

Pemetaan yang umum dan bisa kamu jadikan titik awal:

| Jenis kewajiban | Klausul dan kendali yang biasanya relevan |
|---|---|
| Identifikasi data pribadi yang diproses | Klausul 4, inventaris aset dan informasi |
| Dasar pemrosesan dan persetujuan | Di luar kendali teknis; perlu proses hukum tersendiri |
| Keamanan pemrosesan | Sebagian besar Annex A, terutama kendali teknologi |
| Pemberitahuan kegagalan pelindungan | Klausul 10 dan kendali manajemen insiden (Day 10) |
| Hak subjek data | Proses baru yang biasanya belum ada di ISMS |
| Perpindahan data ke luar negeri | Kendali pemasok dan hubungan awan (Day 12) |
| Pelaporan insiden siber | Kendali manajemen insiden dan jalur eskalasi |
| Pencatatan dan retensi | Kendali logging dan retensi (Day 11) |

Dua baris yang perlu perhatian khusus. Baris dasar pemrosesan dan baris hak subjek data biasanya tidak punya padanan di ISMS, karena keduanya bukan persoalan keamanan melainkan persoalan tata kelola data pribadi. Keduanya menjadi alasan utama kenapa organisasi menambahkan sistem manajemen informasi privasi di atas ISMS-nya (Day 19).

### 3.4 Satu sistem, beberapa kewajiban

Prinsip yang menghemat paling banyak usaha: perlakukan kewajiban regulasi sebagai sumber persyaratan tambahan bagi ISMS, bukan sebagai sistem paralel.

Cara menerapkannya:

- **Satu register kewajiban.** Semua kewajiban dari seluruh lapisan dicatat di satu tempat, dengan rujukan ke klausul atau kendali yang memenuhinya.
- **Satu penilaian risiko.** Risiko kepatuhan masuk ke register risiko yang sama, bukan ke register terpisah.
- **Satu program audit.** Area yang punya kewajiban regulasi mendapat frekuensi lebih tinggi di program audit internal (Day 15).
- **Satu jalur tindakan korektif.** Temuan kepatuhan masuk ke jalur yang sama dengan temuan audit (Day 16).
- **Satu management review.** Status kepatuhan menjadi salah satu masukan, bukan rapat tersendiri.

Yang perlu tetap terpisah: bukti yang spesifik untuk satu regulator, dan dokumen yang formatnya ditentukan regulator. Jangan memaksakan format ISMS pada dokumen yang bentuknya sudah ditetapkan.

### 3.5 Ketika kewajiban melampaui standar

Ada titik di mana regulasi menuntut lebih dari yang diminta standar, dan mengenalinya mencegah rasa aman yang keliru.

Pola yang umum:

- **Tenggat yang spesifik.** Standar meminta proses insiden yang terdefinisi; regulasi bisa menetapkan tenggat pemberitahuan dalam jam. Proses yang memenuhi standar belum tentu cukup cepat.
- **Penerima laporan yang ditentukan.** Standar meminta komunikasi dengan pihak berkepentingan; regulasi menentukan ke lembaga mana dan dengan format apa.
- **Lokasi data.** Standar tidak menentukan di mana data boleh disimpan; sebagian regulasi menentukannya.
- **Hak pihak ketiga.** Hak subjek data tidak punya padanan di persyaratan standar.
- **Sanksi.** Standar tidak punya sanksi; regulasi punya.

Untuk tiap pola, tindakan yang benar adalah menambahkan persyaratan itu ke dalam ISMS sebagai persyaratan yang harus dipenuhi, lalu memastikan ada bukti pemenuhannya. Bukan membangun proses kedua.

### 3.6 Menulis status kepatuhan dengan jujur

Status kepatuhan sering ditulis sebagai hijau atau merah, dan itu menyembunyikan informasi yang justru paling dibutuhkan manajemen.

Bentuk yang lebih berguna memakai empat status:

```
TERPENUHI        : ada kewajiban, ada proses, ada bukti pelaksanaan
TERPENUHI SEBAGIAN: ada proses tetapi belum lengkap atau belum ada bukti
BELUM            : belum ada proses
BELUM PASTI      : kewajibannya sendiri belum jelas karena aturan pelaksana belum ada
                   atau lembaga pengawasnya belum terbentuk
```

Status keempat penting di Indonesia saat ini. Sebagian kewajiban teknis menunggu aturan lanjutan, dan menuliskan hal itu sebagai belum terpenuhi akan menyesatkan, sementara menuliskannya sebagai terpenuhi akan berbahaya. Status yang jujur adalah belum pasti, dengan catatan apa yang ditunggu.

## 4. Contoh dokumen / artefak (organisasi fiktif)

> Seluruh isi di bawah adalah contoh untuk organisasi fiktif PT AN dan bukan nasihat hukum. Kolom dasar hukum harus kamu isi dari hasil verifikasimu sendiri ke teks resmi, bukan disalin dari catatan ini.

### 4.1 Register kewajiban kepatuhan

```
REGISTER KEWAJIBAN KEPATUHAN                 PT AN      versi 2.0, ditinjau 2027-01-15
Disusun bersama: tim hukum, pejabat pelindungan data, pemilik risiko

KW-01
  kewajiban      : memberitahukan kegagalan pelindungan data pribadi
  dasar hukum    : <UU dan pasal, hasil verifikasi sendiri>
  berlaku karena : kami memproses data pribadi pelanggan
  tenggat        : <verifikasi sendiri>
  dipenuhi oleh  : prosedur IR-01 pasal 9; jalur eskalasi hukum; templat pemberitahuan
  bukti          : catatan uji tabletop 2026-11; daftar kontak eskalasi
  pemilik        : Manajer Kepatuhan
  status         : terpenuhi sebagian  (templat ada, belum pernah dipakai pada kejadian nyata)
  tinjau         : 2027-07-15

KW-02
  kewajiban      : pendaftaran sebagai penyelenggara sistem elektronik, bila berlaku
  dasar hukum    : PP No. 71 Tahun 2019 <pasal, verifikasi sendiri>
  berlaku karena : kami menyediakan layanan elektronik kepada publik
  dipenuhi oleh  : proses pendaftaran; pemantauan perubahan data pendaftaran
  bukti          : bukti pendaftaran; catatan pembaruan terakhir
  pemilik        : Sekretaris Perusahaan
  status         : terpenuhi
  tinjau         : 2027-10-01

KW-03
  kewajiban      : pelaporan insiden siber sesuai kategori yang ditetapkan
  dasar hukum    : Peraturan BSSN <nomor dan pasal, verifikasi sendiri>
  dipenuhi oleh  : prosedur IR-01 pasal 10; pohon keputusan pelaporan
  bukti          : pohon keputusan; catatan uji
  pemilik        : Manajer Operasi Keamanan
  status         : terpenuhi sebagian  (kanal pelaporan belum diverifikasi ulang tahun ini)
  tinjau         : 2027-04-01

KW-04
  kewajiban      : memenuhi ketentuan teknis pelindungan data pribadi
  dasar hukum    : peraturan pelaksana UU PDP
  status         : BELUM PASTI
  catatan        : sebagian ketentuan menunggu aturan lanjutan; pantau sebagai kebutuhan
                   intelijen (Day 12): sumber resmi JDIH dan pengumuman lembaga
  pemilik        : Manajer Kepatuhan
  tinjau         : setiap kuartal sampai jelas
```

Kolom dipenuhi oleh yang membuat register ini menyatu dengan ISMS. Ia menunjuk ke prosedur yang sudah ada, bukan ke proyek baru.

### 4.2 Matriks kewajiban ke kendali

| Kewajiban | Klausul | Kendali Annex A yang relevan | Celah |
|---|---|---|---|
| KW-01 pemberitahuan kegagalan | 10.2 | manajemen insiden, komunikasi | Tenggat spesifik belum diuji pada kejadian nyata |
| KW-02 pendaftaran | 4, 7.5 | pengelolaan informasi terdokumentasi | tidak ada |
| KW-03 pelaporan insiden | 10.2 | manajemen insiden, pelaporan peristiwa | Kanal perlu diverifikasi berkala |
| Hak subjek data | tidak ada padanan langsung | tidak ada padanan langsung | Proses baru diperlukan |
| Perpindahan data ke luar negeri | 6.1, 8 | hubungan pemasok, layanan awan | Perlu pemetaan lokasi data per layanan |

Dua baris terakhir yang paling berguna dibaca manajemen, karena keduanya menunjukkan bahwa ISMS saja tidak cukup dan ada pekerjaan tambahan yang perlu sumber daya.

### 4.3 Pemetaan lokasi data

Dokumen pendukung yang hampir selalu diminta, dan sering belum ada:

| Layanan | Jenis data | Lokasi pemrosesan | Lokasi penyimpanan | Pemasok | Dasar perpindahan |
|---|---|---|---|---|---|
| Surel korporat | data pribadi karyawan | luar negeri | luar negeri | Pemasok A | <perlu diisi tim hukum> |
| Sistem pelanggan | data pribadi pelanggan | dalam negeri | dalam negeri | sendiri | tidak berpindah |
| Pencadangan | data pribadi pelanggan | dalam negeri | luar negeri | Pemasok B | <perlu diisi tim hukum> |
| Analitik situs | data perilaku | luar negeri | luar negeri | Pemasok C | <perlu diisi tim hukum> |

Baris pencadangan adalah temuan yang sangat sering muncul: data utamanya di dalam negeri, tetapi salinannya tidak. Periksa ini sebelum seseorang dari luar yang menemukannya.

### 4.4 Menambahkan tenggat regulasi ke prosedur insiden

Cuplikan perubahan pada prosedur IR-01 agar memenuhi kewajiban yang tenggatnya spesifik:

```
IR-01 pasal 9  PEMBERITAHUAN KEPADA PIHAK LUAR

9.1  Begitu insiden divalidasi, Koordinator Insiden menjalankan pohon keputusan pelaporan
     (lampiran 3) untuk menentukan kewajiban mana yang berlaku.
9.2  Bila ada data pribadi terdampak, jam mulai dihitung sejak <titik yang ditetapkan
     regulasi; verifikasi sendiri>, BUKAN sejak insiden selesai ditangani.
9.3  Pemberitahuan awal dikirim walaupun informasi belum lengkap, dengan menyebut
     apa yang belum diketahui dan kapan pembaruan dikirim.
9.4  Isi pemberitahuan mengikuti templat lampiran 4 dan disahkan oleh <jabatan>.
9.5  Bila tenggat tidak dapat dipenuhi, alasannya dicatat dan dilaporkan ke management review.

CATATAN PERANCANGAN
  Pasal 9.2 ada karena tenggat regulasi dihitung dari saat tertentu, bukan dari selesainya
  penanganan. Proses yang menunggu penanganan selesai akan selalu terlambat.
```

Blok catatan perancangan itu layak ada di prosedur, karena ia menjelaskan kenapa aturannya dibuat demikian dan mencegah orang berikutnya menyederhanakannya.

Lampiran 3 yang dirujuk pasal 9.1 bisa berbentuk pohon keputusan sederhana. Tujuannya memilah dua kewajiban yang berbeda: pemberitahuan kegagalan pelindungan data pribadi (UU PDP) dan pelaporan insiden siber ke lembaga (peraturan BSSN dan ketentuan sektor). Satu insiden bisa memicu keduanya, salah satunya, atau tidak keduanya.

```
LAMPIRAN 3  POHON KEPUTUSAN PELAPORAN (fiktif, PT AN)

Q1  Apakah insiden sudah divalidasi (bukan lagi dugaan)?
      tidak -> lanjutkan investigasi; catat waktu, ulangi Q1 setiap pembaruan
      ya    -> catat WAKTU VALIDASI, lanjut Q2 dan Q4 (keduanya dijalankan)

Q2  Apakah data pribadi terdampak (terungkap, diubah, hilang, atau tidak tersedia)?
      tidak / belum diketahui -> catat alasan; tinjau ulang tiap pembaruan investigasi
      ya    -> lanjut Q3

Q3  Kewajiban UU PDP berlaku:
      - libatkan DPO dan Legal SEKARANG, bukan setelah investigasi selesai
      - hitung tenggat dari titik mulai yang ditetapkan di prosedur IR-01 pasal 9.2
      - siapkan pemberitahuan ke subjek data dan lembaga memakai templat lampiran 4

Q4  Apakah sistem yang terdampak membuat PT AN wajib melapor insiden siber
    (sebagai penyelenggara sistem elektronik, sektor tertentu, atau karena kontrak)?
      tidak -> catat alasan di tiket
      ya    -> lapor sesuai kanal dan tenggat di register kewajiban (KW-03),
               terpisah dari pemberitahuan UU PDP

Q5  Apakah kontrak pelanggan mewajibkan notifikasi?
      ya    -> kirim notifikasi sesuai tenggat kontrak; Account Manager diberi tahu

Setiap jawaban, termasuk "tidak", dicatat di tiket beserta waktu dan nama pengambil keputusan.
```

Yang membuat pohon ini berguna saat audit adalah baris terakhirnya: keputusan "tidak perlu melapor" yang tercatat beserta alasannya adalah bukti bahwa kewajiban dipertimbangkan, sama seperti keputusan "tidak relevan" di proses threat intelligence (Day 12).

### 4.5 Satu halaman status kepatuhan untuk management review

```
STATUS KEPATUHAN                              Semester 1 2027

RINGKASAN
  terpenuhi            : 6 dari 11 kewajiban
  terpenuhi sebagian   : 3
  belum                : 0
  belum pasti          : 2   (menunggu aturan pelaksana dan pembentukan lembaga pengawas)

YANG PERLU KEPUTUSAN
  1. Pemetaan lokasi data (bagian 4.3) menunjukkan salinan cadangan berada di luar negeri.
     Pilihan: (i) pindahkan, (ii) lengkapi dasar perpindahan, (iii) terima risiko sementara
  2. Hak subjek data belum punya proses. Pilihan: (i) bangun proses sendiri,
     (ii) tambahkan sistem manajemen informasi privasi di atas ISMS (Day 19)

PERUBAHAN REGULASI YANG DIPANTAU
  <daftar, dengan tanggal pemantauan terakhir>

YANG TIDAK BISA KAMI PASTIKAN
  Dua kewajiban berstatus belum pasti karena aturannya belum lengkap. Kami memantau dan
  akan melaporkan perubahannya. Risiko ini tercatat sebagai R-0xx.
```

Blok terakhir adalah cara menuliskan ketidakpastian tanpa menyembunyikannya, dan sekaligus cara meminta waktu tanpa terdengar menunda.

## 5. Lab praktik

**Prasyarat:** hasil Day 03 (konteks dan pihak berkepentingan), Day 04 (risiko dan SoA), Day 10 (insiden), dan Day 12 (pemasok). Seluruh lab bersifat membaca sumber resmi dan menulis.

1. Cari teks resmi UU No. 27 Tahun 2022 dan temukan sendiri pasal yang mengatur pemberitahuan kegagalan pelindungan data pribadi beserta tenggatnya. Catat nomor pasalnya.
2. Cari teks resmi PP No. 71 Tahun 2019 dan tentukan apakah organisasi fiktif PT AN termasuk penyelenggara sistem elektronik yang terkena kewajiban pendaftaran.
3. Periksa status peraturan pelaksana UU PDP dan status pembentukan lembaga pengawasnya saat kamu mengerjakan ini, lalu catat dasar temuanmu.
4. Identifikasi apakah sektor organisasimu punya ketentuan keamanan informasi tersendiri, lalu catat sumbernya.
5. Susun register kewajiban bagian 4.1 dengan minimal delapan kewajiban dari minimal tiga lapisan di bagian 3.1.
6. Isi matriks bagian 4.2 untuk seluruh kewajiban itu, dan tandai yang tidak punya padanan di ISMS.
7. Susun pemetaan lokasi data bagian 4.3 untuk lima layanan yang benar-benar dipakai organisasi fiktifmu, termasuk pencadangan.
8. Ubah prosedur insidenmu dari Day 10 agar memuat tenggat regulasi, memakai bentuk bagian 4.4, dan pastikan titik mulai penghitungan jam ditetapkan dengan jelas.
9. Jalankan latihan meja singkat: satu skenario insiden dengan data pribadi terdampak, lalu ukur berapa lama dari validasi sampai pemberitahuan awal siap dikirim.
10. Susun satu halaman status kepatuhan bagian 4.5 dengan angka nyata dari register yang kamu buat.

**Hasil yang sebaiknya tersimpan:**
- Nomor pasal dan tenggat pemberitahuan hasil verifikasi sendiri.
- Kesimpulan apakah kewajiban pendaftaran berlaku, beserta dasarnya.
- Catatan status peraturan pelaksana dan lembaga pengawas pada tanggal pengerjaan.
- Sumber ketentuan sektor bila ada.
- Register kewajiban dengan minimal delapan baris dari tiga lapisan.
- Matriks kewajiban ke kendali dengan penandaan celah.
- Pemetaan lokasi data lima layanan termasuk pencadangan.
- Prosedur insiden yang sudah memuat tenggat dan titik mulai penghitungan.
- Hasil latihan meja beserta waktu dari validasi sampai pemberitahuan siap.
- Satu halaman status kepatuhan dengan empat kategori status.

## 6. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa |
|---|---|---|
| Kewajiban sektor baru ketahuan saat audit | Hanya memperhatikan undang-undang dan peraturan pemerintah | Tambahkan lapisan sektor dan kontrak ke register (bagian 3.1) |
| Ada beberapa daftar kendali untuk regulasi berbeda | Tiap regulasi diperlakukan sebagai proyek sendiri | Satukan ke register kewajiban dan ISMS (bagian 3.4) |
| Pemberitahuan selalu terlambat pada latihan | Jam dihitung dari selesainya penanganan | Tetapkan titik mulai penghitungan di prosedur (bagian 4.4) |
| Status kepatuhan hanya hijau atau merah | Tidak ada kategori untuk yang belum pasti | Pakai empat status (bagian 3.6) |
| Pemasok tidak bisa menjelaskan lokasi data | Pemetaan lokasi belum pernah dibuat | Minta sebagai bagian penilaian pemasok (Day 12) |
| Salinan cadangan ternyata di luar negeri | Pencadangan tidak masuk pemetaan | Masukkan pencadangan sebagai layanan tersendiri (bagian 4.3) |
| Hak subjek data tidak ada yang menangani | Tidak punya padanan di ISMS | Bangun proses, atau pertimbangkan sistem manajemen privasi (Day 19) |
| Prosedur usang dalam hitungan bulan | Perubahan regulasi tidak dipantau | Jadikan pemantauan regulasi kebutuhan intelijen (PIR, Day 12) dengan pemilik dan jadwal tinjau |
| Tenggat dan kewajiban berbeda antar sumber | Mengutip ringkasan pihak ketiga | Verifikasi ke teks resmi sebelum masuk prosedur |

## 7. Kesalahan umum dan jebakan

- Menganggap sertifikasi ISO 27001 otomatis memenuhi kewajiban regulasi.
- Membangun sistem manajemen terpisah untuk tiap regulasi.
- Melupakan lapisan kontrak, yang sering lebih ketat daripada regulasi.
- Menyalin tenggat dan kewajiban dari ringkasan pihak ketiga ke dalam prosedur.
- Menghitung tenggat pemberitahuan dari selesainya penanganan insiden.
- Menunda pemberitahuan awal sampai informasi lengkap.
- Menuliskan kewajiban yang aturannya belum lengkap sebagai sudah terpenuhi.
- Melupakan pencadangan dan layanan pendukung dalam pemetaan lokasi data.
- Membiarkan hak subjek data tanpa pemilik karena tidak ada padanannya di ISMS.
- Tidak memantau perubahan regulasi sebagai kegiatan rutin.

## 8. Catatan terkini

- UU No. 27 Tahun 2022 ditetapkan dan diundangkan pada 17 Oktober 2022 [S1], dan peraturan pelaksananya terbit belakangan. Karena sebagian ketentuan teknis masih menunggu aturan lanjutan, status belum pasti adalah status yang sah untuk sebagian kewajiban, dan menuliskannya apa adanya lebih baik daripada memaksakan kepastian.
- PP No. 71 Tahun 2019 ditetapkan 4 Oktober 2019 dan berstatus berlaku [S2]. Kewajiban di dalamnya sering luput dari perhatian tim keamanan karena dianggap urusan legal atau korporat, padahal sebagian bersinggungan langsung dengan pengelolaan sistem elektronik.
- Kerangka pengelolaan insiden siber bersandar pada peraturan lembaga [S3], dan kewajiban pelaporannya terpisah dari kewajiban pemberitahuan kegagalan pelindungan data pribadi. Satu insiden bisa memicu keduanya; pohon keputusan di bagian 4.4 adalah alat untuk memilahnya.
- Informasi tentang peraturan pelaksana UU PDP yang beredar sebagian besar berasal dari kantor hukum dan media [S5], bukan dari pengumuman resmi. Perlakukan sebagai peringatan dini yang berguna, lalu verifikasi sendiri sebelum mengubah prosedur.
- Pemetaan lokasi data adalah dokumen yang paling sering diminta dan paling sering belum ada. Membuatnya lebih dulu, sebelum ada yang meminta, mengubah percakapan dengan regulator maupun pelanggan.

## 9. Cheat sheet

```
PERINGATAN  BUKAN nasihat hukum. Regulasi bergerak cepat; sebagian info dari ringkasan
            pihak ketiga. VERIFIKASI ke teks resmi + libatkan penasihat hukum.

LIMA LAPIS KEWAJIBAN
  undang-undang | peraturan pemerintah | peraturan lembaga | peraturan SEKTOR | KONTRAK
  dua yang sering dilupakan: SEKTOR (lebih rinci) dan KONTRAK (sering lebih ketat + hak audit)
  semuanya masuk sebagai persyaratan pihak berkepentingan (klausul 4) dan masukan risiko (klausul 6)

DUA YANG MENYENTUH HAMPIR SEMUA
  UU No. 27/2022 Pelindungan Data Pribadi (ditetapkan+diundangkan 17 Okt 2022)
    peraturan pelaksana terbit belakangan -> sebagian ketentuan teknis masih menunggu
  PP No. 71/2019 Penyelenggaraan Sistem dan Transaksi Elektronik (4 Okt 2019, berlaku)
  SERTIFIKASI ISO 27001 TIDAK OTOMATIS MEMENUHI KEDUANYA -> PETAKAN, jangan asumsikan

YANG TIDAK PUNYA PADANAN DI ISMS
  dasar pemrosesan & persetujuan | HAK SUBJEK DATA
  -> ini alasan utama orang menambahkan sistem manajemen informasi privasi di atas ISMS (Day 19)

SATU SISTEM, BUKAN SISTEM PARALEL
  satu REGISTER kewajiban | satu penilaian RISIKO | satu PROGRAM AUDIT
  satu jalur TINDAKAN KOREKTIF | satu MANAGEMENT REVIEW
  yang tetap terpisah: bukti khusus regulator + dokumen yang formatnya ditentukan regulator

KETIKA REGULASI MELAMPAUI STANDAR
  TENGGAT spesifik (jam) | penerima laporan yang DITENTUKAN | LOKASI data
  HAK pihak ketiga | SANKSI
  -> tambahkan sebagai persyaratan DI DALAM ISMS, jangan bangun proses kedua

TENGGAT INSIDEN  jam dihitung dari TITIK YANG DITETAPKAN REGULASI, BUKAN dari selesainya penanganan
  proses yang menunggu penanganan selesai akan SELALU terlambat
  kirim pemberitahuan AWAL walau belum lengkap; sebut apa yang belum diketahui + kapan pembaruan

EMPAT STATUS KEPATUHAN (jangan cuma hijau/merah)
  terpenuhi | terpenuhi sebagian | belum | BELUM PASTI (aturan pelaksana / lembaga belum ada)
  status keempat penting di Indonesia saat ini; menulisnya jujur lebih baik daripada memaksakan

PEMETAAN LOKASI DATA  paling sering diminta, paling sering belum ada
  jangan lupa PENCADANGAN dan layanan pendukung; temuan khas: data di dalam negeri,
  salinannya tidak
```

## 10. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Undang-Undang Nomor 27 Tahun 2022 tentang Pelindungan Data Pribadi | https://peraturan.bpk.go.id/Details/229798/uu-no-27-tahun-2022 | primer | ditetapkan dan diundangkan 17 Oktober 2022; halaman dilihat 2026-10-09 | Tinggi untuk tanggal penetapan dan pengundangan. Bunyi Pasal 46 (Day 10) perlu dicocokkan dengan salinan resmi |
| S2 | Peraturan Pemerintah Nomor 71 Tahun 2019 tentang Penyelenggaraan Sistem dan Transaksi Elektronik | https://peraturan.bpk.go.id/Details/122030/pp-no-71-tahun-2019 | primer | ditetapkan 2019-10-04, berstatus berlaku; dilihat 2026-10-09 | Tinggi untuk judul, tanggal, dan status berlaku. Rincian kewajiban per pasal perlu dicek di teks resmi |
| S3 | Peraturan BSSN Nomor 1 Tahun 2024 tentang Pengelolaan Insiden Siber | https://peraturan.bpk.go.id/Details/291240/peraturan-bssn-no-1-tahun-2024 | primer | ditetapkan 10 Januari 2024; dirujuk 2026-10-09 | Sedang-tinggi untuk keberadaan dan materi pokok; kategori insiden dan tenggat pelaporan perlu dicek di teks resmi |
| S4 | JDIH BSSN | https://jdih.bssn.go.id/ | primer | dirujuk 2026-10-09 | Tinggi sebagai tempat memverifikasi teks peraturan lembaga |
| S5 | Ringkasan dan analisis pihak ketiga tentang peraturan pelaksana UU Pelindungan Data Pribadi | (beberapa, kantor hukum dan media) | sekunder | dirujuk 2026-10-09 | Rendah-sedang. Dipakai hanya sebagai penanda bahwa peraturan pelaksana sudah terbit; nomor, tanggal, dan isinya harus kamu verifikasi ke sumber resmi |
| S6 | ISO27001-note Day 03, 04, 09, 10, 11, 12, 15, 16 | (lokal) | rujukan internal | 2026-10-09 | Keterkaitan antar Day |

**Catatan sumber:** Day ini adalah kerangka kerja, bukan rujukan hukum. Yang perlu dicocokkan dengan teks resmi: titik mulai hitungan tenggat 3 x 24 jam di UU PDP; ruang lingkup kewajiban PP No. 71 Tahun 2019, termasuk kewajiban pendaftaran dan kepada siapa berlaku; kategori insiden dan tenggat pelaporan di Peraturan BSSN No. 1 Tahun 2024; serta nomor, tanggal, dan isi peraturan pelaksana UU PDP, yang sejauh ini hanya diketahui dari ringkasan kantor hukum dan media [S5]. Pemetaan kewajiban ke klausul dan kontrol di bagian 3.3 dan 4.2 serta pohon keputusan di bagian 4.4 adalah susunan sendiri, bukan pemetaan resmi lembaga mana pun. Ketentuan sektor sengaja tidak dirinci karena berbeda antar sektor. Seluruh nomor dokumen, nama, dan angka di bagian 4 adalah fiktif.
