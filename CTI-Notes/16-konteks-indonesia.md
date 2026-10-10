---
day: 16
title: 'Konteks Indonesia: lembaga, kewajiban pelaporan, dan batas berbagi'
researched_on: 2026-10-10
versions_checked: 'UU No. 27 Tahun 2022 tentang Pelindungan Data Pribadi (ditetapkan dan diundangkan 17 Oktober 2022); PP No. 33 Tahun 2026 sebagai peraturan pelaksana (ditetapkan 16 Juli 2026, dinyatakan berlaku 16 Januari 2027 menurut ringkasan pihak ketiga); Peraturan BSSN No. 1 Tahun 2024 tentang Pengelolaan Insiden Siber (ditetapkan 10 Januari 2024); Perpres No. 82 Tahun 2022 tentang Pelindungan Infrastruktur Informasi Vital; rujukan Day 02, 05, 10, 11, 13, 15'
---

# Day 16: Konteks Indonesia

Cakupan: lembaga dan aturan yang menentukan ke mana insiden dilaporkan di Indonesia, apa yang berubah dengan peraturan pelaksana UU PDP, dan bagaimana semua itu membentuk pekerjaan analis CTI di sini.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- menyebutkan lembaga dan peran yang relevan dalam penanganan insiden siber di Indonesia.
- menjelaskan kerangka pengelolaan insiden siber dan posisi tim tanggap insiden organisasi di dalamnya.
- menyebutkan perubahan penting pada rezim pelindungan data pribadi dan tanggal yang perlu kamu catat.
- menyusun daftar kewajiban pelaporan untuk organisasimu sendiri beserta sumber hukumnya.
- menetapkan batas berbagi informasi yang memperhitungkan aturan pelindungan data.
- menyusun rencana pengumpulan yang memakai sumber lokal, bukan hanya sumber berbahasa Inggris.

## 2. Konteks singkat

Seluruh Day sebelumnya di topik ini memakai kerangka dan sumber internasional. Itu wajar, karena di situlah sebagian besar materinya. Tetapi pekerjaan nyata terjadi di yurisdiksi tertentu, dan di Indonesia ada tiga hal yang mengubah cara kerja: lembaga yang berbeda dari yang disebut di laporan internasional, kewajiban pelaporan yang punya dasar hukum sendiri, dan aturan pelindungan data yang membatasi apa yang boleh kamu kumpulkan dan bagikan.

Day ini menyusun ketiganya. Satu peringatan sejak awal, dan ini berlaku ke seluruh isi Day: catatan ini bukan nasihat hukum. Regulasi di wilayah ini sedang bergerak cepat, dan sebagian sumber yang tersedia saat penulisan berupa ringkasan pihak ketiga, bukan teks resmi. Verifikasi setiap kewajiban ke teks aslinya di JDIH lembaga terkait atau peraturan.bpk.go.id, dan libatkan penasihat hukum organisasimu untuk keputusan yang mengikat.

## 3. Konsep inti

### 3.1 Siapa mengurus apa

| Lembaga atau entitas | Peran yang relevan bagi analis |
|---|---|
| BSSN | Lembaga yang mengatur pengelolaan insiden siber dan mengukuhkan tim tanggap insiden |
| Gov-CSIRT Indonesia | Pengelola tim tanggap insiden sektor pemerintah, berada di lingkungan BSSN |
| Tim tanggap insiden organisasi | Pihak pertama yang menangani insiden di organisasinya sendiri |
| ID-SIRTII/CC | Entitas dengan tugas sosialisasi, pemantauan, pendeteksian, dan peringatan dini pada jaringan telekomunikasi |
| Lembaga pelindungan data pribadi | Lembaga pengawas yang diamanatkan UU PDP; pembentukannya perlu kamu cek statusnya |

Baris terakhir yang paling sering menimbulkan kebingungan: lembaga pengawas pelindungan data pribadi diamanatkan untuk dibentuk, tetapi pembentukannya berada di tahap yang perlu kamu verifikasi sendiri statusnya saat membaca catatan ini. Jangan menuliskan kewajiban pelaporan ke lembaga itu dalam prosedurmu tanpa memastikan lembaganya sudah ada dan kanalnya sudah jelas.

### 3.2 Kerangka pengelolaan insiden siber

Pengelolaan insiden siber diatur dalam Peraturan BSSN Nomor 1 Tahun 2024, yang ditetapkan pada 10 Januari 2024 sebagai pelaksanaan Pasal 17 Peraturan Presiden Nomor 82 Tahun 2022 tentang Pelindungan Infrastruktur Informasi Vital, dan mencabut peraturan sebelumnya tentang tim tanggap insiden siber [S1][S2]. Materi pokoknya mencakup tim tanggap insiden siber, pelaporan insiden siber, penanganan insiden siber, dan pelaksanaan kesiapan terhadap insiden [S1].

Prinsip yang perlu kamu pegang adalah penanganan berjenjang: organisasi menjadi pihak pertama yang melakukan identifikasi dan validasi, membatasi dampak, mengambil langkah awal, lalu melakukan eskalasi bila diperlukan.

Konsekuensinya untuk pekerjaanmu cukup langsung. Kemampuan organisasi untuk mengidentifikasi dan memvalidasi sendiri adalah syarat, bukan pilihan, dan di situlah seluruh materi deteksi dan hunting di repo ini bertemu dengan kerangka regulasi. Organisasi yang tidak bisa memvalidasi sendiri akan selalu terlambat melapor, karena ia bahkan tidak tahu ada yang perlu dilaporkan.

Tim tanggap insiden organisasi perlu dikukuhkan dan didaftarkan, dan ada tenggat yang disebut dalam pemberitaan untuk pendaftarannya. Angka dan tenggatnya perlu kamu verifikasi ke sumber resmi, karena yang beredar berasal dari berita dan bukan dari teks peraturannya.

### 3.3 Rezim pelindungan data pribadi dan tanggal yang perlu dicatat

UU Nomor 27 Tahun 2022 tentang Pelindungan Data Pribadi ditetapkan dan diundangkan pada 17 Oktober 2022 [S3]. Undang-undang ini memuat kewajiban bagi pengendali dan prosesor data pribadi, termasuk kewajiban memberitahukan kegagalan pelindungan data pribadi.

Ketentuannya ada di Pasal 46 UU Nomor 27 Tahun 2022 [S7]. Ayat (1) mewajibkan pengendali data pribadi menyampaikan pemberitahuan tertulis paling lambat 3 x 24 jam kepada subjek data pribadi dan kepada lembaga bila terjadi kegagalan pelindungan data pribadi. Ayat (2) menyebut isi minimal pemberitahuan: data pribadi yang terungkap, kapan dan bagaimana data itu terungkap, serta upaya penanganan dan pemulihan. Ayat (3) menambahkan bahwa dalam hal tertentu pengendali juga wajib memberi tahu masyarakat. Penjelasan pasalnya mengartikan kegagalan pelindungan sebagai kegagalan menjaga kerahasiaan, integritas, dan ketersediaan data pribadi, baik karena kesengajaan maupun tidak.

Dua hal yang tidak dijawab teks pasal dan perlu diputuskan di kebijakan internal bersama tim hukum: sejak kapan hitungan 3 x 24 jam dimulai (saat kejadian, saat terdeteksi, atau saat kegagalan dipastikan), dan kapan "hal tertentu" yang mewajibkan pemberitahuan ke masyarakat terpenuhi. Pemberitahuan ke lembaga juga bergantung pada keberadaan lembaga pengawas dan kanalnya, yang dibahas di bawah.

Yang baru dan penting: peraturan pelaksananya terbit dalam bentuk Peraturan Pemerintah Nomor 33 Tahun 2026. Menurut ringkasan pihak ketiga, PP itu ditetapkan pada 16 Juli 2026 dan dinyatakan berlaku pada 16 Januari 2027, serta memuat pengaturan teknis kewajiban pengendali dan prosesor [S4]. Sejumlah ringkasan juga menyebut bahwa banyak ketentuan di dalamnya masih menunggu aturan lanjutan dari lembaga pengawas yang belum terbentuk [S4].

Tiga hal praktis dari situ. Pertama, ada tanggal yang perlu masuk ke kalender kepatuhan organisasimu. Kedua, selama aturan lanjutan belum ada, sebagian kewajiban teknisnya belum bisa dipenuhi secara pasti, dan itu perlu dinyatakan sebagai risiko yang diketahui, bukan disembunyikan. Ketiga, karena seluruh informasi tentang PP ini di catatan ini berasal dari ringkasan pihak ketiga, perlakukan sebagai petunjuk arah dan bukan sebagai rujukan hukum.

### 3.4 Dua kewajiban yang berbeda

Ini pembedaan yang sering dicampur dan menimbulkan kesalahan prosedur:

| Aspek | Pelaporan insiden siber | Pemberitahuan kegagalan pelindungan data pribadi |
|---|---|---|
| Dasar | Kerangka pengelolaan insiden siber [S1] | UU PDP dan peraturan pelaksananya [S3][S4] |
| Pemicu | Insiden siber sesuai kategori yang ditetapkan | Kegagalan pelindungan data pribadi |
| Tujuan laporan | Jalur tim tanggap insiden dan lembaga terkait | Subjek data dan lembaga pengawas |
| Isi | Teknis: apa yang terjadi, dampak, penanganan | Dampak pada subjek data dan langkah penanganannya |

Satu insiden bisa memicu keduanya, salah satunya, atau tidak sama sekali. Yang perlu kamu siapkan sebelum insiden adalah pohon keputusan yang menentukan mana yang berlaku, dan siapa yang berwenang memutuskannya. Membuat pohon keputusan itu saat insiden sedang berjalan adalah cara yang pasti untuk melewatkan tenggat.

### 3.5 Batas berbagi informasi

Pekerjaan CTI bertumpu pada berbagi, dan di sinilah aturan pelindungan data mengikat. Tiga batas yang perlu kamu terapkan, melanjutkan prinsip etika di Day 05:

- **Jangan membagikan data pribadi sebagai indikator.** Alamat surel, nama, dan nomor identitas adalah data pribadi, dan membagikannya ke komunitas atau platform luar punya konsekuensi tersendiri. Bila harus, agregasikan atau samarkan.
- **Perhatikan perpindahan data ke luar negeri.** Mengunggah artefak ke layanan analisis luar negeri memindahkan data, dan bila artefak itu memuat data pribadi, aturan perpindahan data berlaku. Ini mengenai praktik sehari-hari seperti mengunggah berkas ke layanan pemindaian publik Cari berdasarkan hash lebih dulu, dan unggah berkas hanya bila sudah dipastikan tidak memuat data pribadi atau data klien.
- **Simpan seperlunya dan sebentar.** Day 14 sudah menyebutnya untuk data bocoran; prinsip yang sama berlaku untuk seluruh koleksi intelijenmu.

Satu kebiasaan sederhana yang menyelesaikan sebagian besar masalah: sebelum membagikan apa pun keluar, tanyakan apakah isinya bisa dipakai mengenali seseorang. Bila ya, berhenti dan tanyakan ke penasihat hukum atau pejabat pelindungan data organisasimu.

### 3.6 Sumber lokal untuk rencana pengumpulan

Rencana pengumpulanmu (Day 02 dan Day 15) akan timpang bila hanya berisi sumber berbahasa Inggris. Jenis sumber lokal yang layak masuk:

- **Terbitan lembaga.** Peringatan, panduan teknis, dan laporan lanskap dari lembaga yang berwenang.
- **Berbagi antar organisasi sektor.** Jalur berbagi di sektor yang sama sering memberi informasi yang paling relevan dan paling cepat.
- **Komunitas tim tanggap insiden.** Jaringan tim yang sudah dikukuhkan adalah jalur yang sah dan berguna.
- **Pemberitaan dan riset lokal.** Berguna untuk konteks dan untuk memahami apa yang menjadi perhatian publik, dengan keandalan yang perlu dinilai seperti sumber lain.

Perlakukan sumber lokal dengan kriteria penilaian yang sama seperti sumber lain (Day 15 bagian 3.3). Relevansi tinggi tidak menghapus kebutuhan menilai ketepatan waktu dan keandalannya.

Satu catatan yang sering diabaikan: kemampuan bahasa adalah bagian dari kapabilitas pengumpulan. Tim yang hanya bisa membaca bahasa Inggris punya celah pengumpulan yang nyata di wilayah ini, dan itu layak ditulis sebagai celah di lembar metrikmu, bukan dibiarkan tak terlihat.

## 4. Contoh artefak intelijen

> Seluruh isi bagian ini adalah kerangka kerja, bukan nasihat hukum. Isi kolom dasar hukum dengan hasil verifikasimu sendiri ke teks resmi, bukan dengan menyalin dari catatan ini.

### 4.1 Daftar kewajiban pelaporan organisasi

```
ORGANISASI: <nama>            disusun: <tanggal>        ditinjau: <tanggal>
DISUSUN BERSAMA: tim hukum / pejabat pelindungan data / pemilik risiko

KEWAJIBAN 1
  jenis            : pelaporan insiden siber
  dasar hukum      : <verifikasi sendiri; sebutkan peraturan dan pasalnya>
  pemicu           : <kategori insiden yang mewajibkan>
  tenggat          : <verifikasi sendiri>
  tujuan           : <lembaga atau jalur>
  kanal            : <verifikasi ke situs resmi; kanal berubah>
  penanggung jawab : <nama jabatan>
  pengganti        : <nama jabatan>

KEWAJIBAN 2
  jenis            : pemberitahuan kegagalan pelindungan data pribadi
  dasar hukum      : UU No. 27 Tahun 2022 Pasal 46
  pemicu           : <definisi kegagalan pelindungan data pribadi>
  tenggat          : 3 x 24 jam (Pasal 46 ayat 1) ; titik mulai hitungan menurut kebijakan internal
  tujuan           : subjek data dan lembaga pengawas
  kanal            : <verifikasi; cek apakah lembaga pengawas sudah terbentuk>
  penanggung jawab : <nama jabatan>

KEWAJIBAN LAIN (sektor)
  <sektor keuangan, kesehatan, dan lain-lain punya kewajiban tersendiri; daftarkan di sini>
```

Kolom pengganti ada karena insiden tidak memilih hari kerja. Kolom kanal ditandai perlu diverifikasi karena kanal pelaporan berubah dan dokumen panduan yang beredar sering sudah lama.

### 4.2 Pohon keputusan pelaporan

```
Insiden terdeteksi dan tervalidasi
  |
  +-- Apakah ada data pribadi yang terdampak?
  |      ya  -> jalur pemberitahuan kegagalan pelindungan data pribadi (KEWAJIBAN 2)
  |             + siapkan isi pemberitahuan untuk subjek data
  |      tidak -> lanjut
  |
  +-- Apakah memenuhi kategori insiden siber yang wajib dilaporkan?
  |      ya  -> jalur pelaporan insiden siber (KEWAJIBAN 1)
  |      tidak -> catat internal, tidak melapor keluar
  |
  +-- Apakah organisasi termasuk sektor dengan kewajiban tambahan?
  |      ya  -> jalur sektor (KEWAJIBAN LAIN)
  |
  +-- Apakah ada pihak ketiga yang perlu diberi tahu secara kontraktual?
         ya  -> jalur kontrak

SIAPA MEMUTUSKAN: <jabatan>      SIAPA MENGESAHKAN ISI LAPORAN: <jabatan>
JAM BERAPA PUN  : <jalur eskalasi di luar jam kerja>
```

Yang membuat pohon ini berguna adalah dua baris terakhir. Tanpa kejelasan siapa memutuskan dan bagaimana menghubunginya tengah malam, pohon sebagus apa pun tidak akan terpakai.

### 4.3 Templat isi laporan teknis

Susun sekali, pakai berulang. Isinya mengikuti apa yang biasanya ditanyakan, dan menyiapkannya lebih dulu menghemat waktu saat tenggat berjalan:

```
1. Identitas pelapor dan organisasi, beserta kontak yang bisa dihubungi 24 jam
2. Waktu kejadian, waktu terdeteksi, dan waktu validasi  (ketiganya berbeda, tulis ketiganya)
3. Ringkasan apa yang terjadi, dalam bahasa yang bisa dibaca non-teknis
4. Sistem dan layanan yang terdampak, beserta perkiraan jumlah pengguna
5. Jenis data yang terdampak, dan apakah termasuk data pribadi
6. Indikator teknis yang sudah diketahui
7. Langkah penanganan yang sudah dilakukan dan yang sedang berjalan
8. Dugaan penyebab awal, dengan tingkat keyakinan (Day 03)
9. Apa yang belum diketahui, dan kapan pembaruan berikutnya akan dikirim
```

Butir kedua sering salah ditulis. Waktu kejadian, waktu terdeteksi, dan waktu validasi adalah tiga hal berbeda, dan selisih di antaranya adalah informasi yang berguna bagi penerima laporan maupun bagi evaluasi internalmu, misalnya untuk menghitung berapa lama penyerang berada di jaringan sebelum terdeteksi.

Butir kesembilan yang membuat laporan awal bisa dikirim cepat tanpa menunggu lengkap. Laporan yang jujur menyebut apa yang belum diketahui lebih baik daripada laporan yang terlambat.

### 4.4 Lembar batas berbagi

```
SEBELUM MEMBAGIKAN KELUAR, PERIKSA:

  [ ] Apakah isinya memuat data yang bisa mengenali seseorang?
      ya -> hentikan, konsultasikan
  [ ] Apakah artefak akan diunggah ke layanan di luar negeri?
      ya -> periksa aturan perpindahan data; pertimbangkan analisis lokal
  [ ] Apakah penerimanya jelas dan jalurnya sah?
  [ ] Apakah penanda TLP sudah sesuai (Day 11)?
  [ ] Apakah asal setiap klaim tercatat (Day 14)?
  [ ] Apakah ada persetujuan yang diperlukan, dan siapa yang memberinya?

CATATAN: daftar ini bukan pengganti nasihat hukum; ia alat agar pertanyaan yang benar
diajukan sebelum, bukan sesudah.
```

### 4.5 Rencana pengumpulan sumber lokal

| Kebutuhan | Sumber lokal | Jenis | Ritme | Penilaian |
|---|---|---|---|---|
| Ancaman yang menyasar sektor kami | Terbitan lembaga berwenang | Resmi | Saat terbit | Relevansi tinggi, ketepatan waktu perlu diukur |
| Peringatan dini | Jalur berbagi sektor | Komunitas resmi | Berkelanjutan | Perlu keanggotaan; nilai setelah satu kuartal |
| Konteks publik dan perhatian regulator | Pemberitaan dan riset lokal | Terbuka | Mingguan | Keandalan dinilai per kasus |
| Perubahan regulasi | JDIH lembaga terkait | Resmi | Bulanan | Keandalan tinggi; pantau perubahan |

Baris terakhir sering tidak ada di rencana pengumpulan tim CTI, padahal perubahan regulasi mengubah kewajiban dan karenanya mengubah prioritas. Perlakukan sebagai kebutuhan intelijen tersendiri (Day 15).

## 5. Lab praktik

**Prasyarat:** akses ke situs JDIH dan peraturan resmi, serta hasil Day 15 (register kebutuhan dan rencana pengumpulan). Seluruh lab bersifat membaca dan menulis.

1. Baca Pasal 46 UU Nomor 27 Tahun 2022 beserta penjelasannya di teks resmi, lalu tulis keputusan kebijakan internal untuk dua hal yang tidak diatur pasalnya: titik mulai hitungan 3 x 24 jam dan kriteria pemberitahuan ke masyarakat.
2. Cari status peraturan pelaksananya dan catat tanggal penetapan serta tanggal mulai berlaku dari sumber resmi, bukan dari ringkasan.
3. Periksa apakah lembaga pengawas pelindungan data pribadi sudah terbentuk saat kamu mengerjakan ini, dan catat apa dasar temuanmu.
4. Cari teks Peraturan BSSN Nomor 1 Tahun 2024 di sumber resmi, lalu catat ketentuan tentang pelaporan insiden: kategori apa yang wajib dilaporkan dan dengan tenggat berapa.
5. Isi daftar kewajiban bagian 4.1 untuk organisasi tempatmu bekerja atau untuk organisasi fiktif, dengan seluruh kolom dasar hukum diisi hasil verifikasimu sendiri.
6. Verifikasi kanal pelaporan ke situs resmi lembaga terkait, dan bandingkan dengan kanal yang disebut di dokumen panduan lama yang kamu temukan. Catat perbedaannya.
7. Susun pohon keputusan bagian 4.2, lalu ujikan ke tiga skenario: insiden tanpa data pribadi, insiden dengan data pribadi, dan insiden di pihak ketiga.
8. Isi templat laporan teknis bagian 4.3 untuk satu skenario fiktif, lengkap dengan tiga waktu yang berbeda di butir kedua.
9. Tambahkan baris pemantauan perubahan regulasi ke register kebutuhan intelijenmu dari Day 15, lengkap dengan sumber dan ritmenya.
10. Tulis setengah halaman untuk pimpinan yang menjelaskan tanggal-tanggal penting di kalender kepatuhan dan apa yang perlu disiapkan sebelum masing-masing.

**Hasil yang sebaiknya tersimpan:**
- Nomor pasal dan tenggat pemberitahuan hasil verifikasimu sendiri ke teks resmi.
- Tanggal penetapan dan mulai berlaku peraturan pelaksana dari sumber resmi.
- Catatan status lembaga pengawas beserta dasar temuannya.
- Ketentuan pelaporan insiden hasil pembacaan teks peraturannya.
- Daftar kewajiban pelaporan organisasi dengan dasar hukum terverifikasi.
- Perbandingan kanal pelaporan resmi dan kanal di dokumen panduan lama.
- Pohon keputusan yang sudah diuji ke tiga skenario.
- Templat laporan teknis yang sudah diisi untuk satu skenario.
- Baris pemantauan regulasi di register kebutuhan intelijen.
- Setengah halaman kalender kepatuhan untuk pimpinan.

## 6. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa |
|---|---|---|
| Tenggat pelaporan berbeda antar sumber | Ringkasan pihak ketiga tidak seragam | Baca teks resminya; jangan mengutip ringkasan di prosedur |
| Kanal pelaporan tidak merespons | Dokumen panduan yang dipakai sudah lama | Verifikasi ke situs resmi lembaga; perbarui daftar kontak berkala |
| Tidak jelas apakah insiden wajib dilaporkan | Kategori insiden tidak dipetakan ke konteks organisasi | Petakan kategori di peraturan ke jenis sistem yang kamu punya |
| Keputusan melapor tertunda | Tidak ada yang berwenang memutuskan di luar jam kerja | Tetapkan jalur eskalasi di pohon keputusan (bagian 4.2) |
| Laporan ditolak karena tidak lengkap | Isi tidak mengikuti format yang diminta | Pakai templat bagian 4.3 dan sesuaikan dengan format resmi |
| Ragu boleh membagikan artefak ke layanan luar | Aturan perpindahan data | Pakai lembar bagian 4.4; konsultasikan sebelum mengunggah |
| Kewajiban sektor terlewat | Hanya memperhatikan aturan umum | Daftarkan kewajiban sektor di bagian 4.1 |
| Prosedur usang dalam hitungan bulan | Regulasi sedang bergerak cepat | Jadikan pemantauan regulasi sebagai kebutuhan intelijen (Day 15) |

## 7. Kesalahan umum dan jebakan

- Menyalin tenggat dan kewajiban dari ringkasan pihak ketiga ke dalam prosedur resmi organisasi.
- Menuliskan pelaporan ke lembaga yang belum terbentuk atau yang kanalnya belum jelas.
- Mencampur kewajiban pelaporan insiden siber dengan kewajiban pemberitahuan kegagalan pelindungan data pribadi.
- Menyusun pohon keputusan tanpa menetapkan siapa yang berwenang memutuskan di luar jam kerja.
- Menulis satu waktu saja di laporan, padahal waktu kejadian, terdeteksi, dan validasi berbeda.
- Menunda laporan awal sampai informasinya lengkap.
- Mengunggah artefak yang memuat data pribadi ke layanan luar tanpa memeriksa aturan perpindahan data.
- Membagikan data pribadi sebagai indikator ke komunitas.
- Menyusun rencana pengumpulan tanpa sumber lokal sama sekali.
- Tidak memantau perubahan regulasi, sehingga prosedur menjadi usang tanpa ada yang tahu.

## 8. Catatan terkini

- Peraturan pelaksana UU Pelindungan Data Pribadi terbit sebagai Peraturan Pemerintah Nomor 33 Tahun 2026, dengan penetapan 16 Juli 2026 dan mulai berlaku 16 Januari 2027 menurut ringkasan yang beredar [S4]. Masukkan tanggal berlakunya ke kalender kepatuhan organisasimu setelah kamu verifikasi sendiri ke teks resmi.
- Sejumlah ringkasan menyebut banyak ketentuan di peraturan pelaksana itu masih menunggu aturan lanjutan dari lembaga pengawas yang pembentukannya belum selesai [S4]. Artinya sebagian kewajiban teknis belum bisa dipenuhi dengan kepastian, dan itu sebaiknya dicatat sebagai risiko yang diketahui, bukan diabaikan.
- Kerangka pengelolaan insiden siber yang berlaku bersandar pada Peraturan BSSN Nomor 1 Tahun 2024, yang merupakan pelaksanaan dari peraturan presiden tentang pelindungan infrastruktur informasi vital [S1][S2]. Posisi tim tanggap insiden organisasi sebagai pihak pertama menegaskan bahwa kemampuan deteksi dan validasi internal adalah syarat kepatuhan, bukan hanya praktik baik.
- Jumlah tim tanggap insiden yang dikukuhkan terus bertambah dan target nasionalnya masih jauh. Bila organisasimu belum punya tim yang dikukuhkan, itu pekerjaan yang layak diusulkan, dan materi di repo ini adalah bahan untuk membangunnya.
- Sebagian besar informasi tentang perkembangan regulasi yang beredar berasal dari kantor hukum dan media, bukan dari pengumuman resmi. Perlakukan sebagai peringatan dini yang berguna, lalu verifikasi ke sumber resmi sebelum dipakai.

## 9. Cheat sheet

```
PERINGATAN  Day ini BUKAN nasihat hukum. Regulasi bergerak cepat dan sebagian sumber berupa
            ringkasan pihak ketiga. VERIFIKASI ke teks resmi (JDIH / peraturan.bpk.go.id)
            dan libatkan penasihat hukum untuk keputusan yang mengikat.

LEMBAGA     BSSN (mengatur pengelolaan insiden, mengukuhkan tim tanggap)
            Gov-CSIRT Indonesia (sektor pemerintah) | tim tanggap insiden ORGANISASI (pihak PERTAMA)
            ID-SIRTII/CC (pemantauan dan peringatan dini jaringan telekomunikasi)
            lembaga pengawas pelindungan data pribadi (CEK statusnya sebelum menulis prosedur)

INSIDEN SIBER  Peraturan BSSN No. 1 Tahun 2024 (10 Jan 2024), pelaksanaan Pasal 17 Perpres 82/2022
            materi: tim tanggap | PELAPORAN | penanganan | kesiapan
            prinsip BERJENJANG: organisasi identifikasi + validasi + batasi dampak, baru eskalasi
            -> kemampuan deteksi internal = SYARAT KEPATUHAN, bukan sekadar praktik baik

DATA PRIBADI  UU No. 27 Tahun 2022, ditetapkan + diundangkan 17 Oktober 2022
            peraturan pelaksana: PP No. 33 Tahun 2026 (ditetapkan 16 Jul 2026, berlaku 16 Jan 2027)
            Pasal 46: pemberitahuan tertulis maks 3 x 24 jam ke subjek data + lembaga ; titik mulai tidak diatur
            banyak ketentuan masih menunggu aturan lanjutan lembaga pengawas

DUA KEWAJIBAN BERBEDA (jangan dicampur)
            pelaporan INSIDEN SIBER : dasar kerangka BSSN | tujuan jalur tim tanggap | isi teknis
            pemberitahuan KEGAGALAN PELINDUNGAN DATA PRIBADI : dasar UU PDP |
                tujuan SUBJEK DATA + lembaga pengawas | isi dampak ke subjek data
            satu insiden bisa memicu keduanya, salah satu, atau tidak sama sekali
            siapkan POHON KEPUTUSAN sebelum insiden, lengkap dengan SIAPA MEMUTUSKAN DI LUAR JAM KERJA

LAPORAN  tulis TIGA waktu berbeda: kejadian | terdeteksi | VALIDASI
         sebut apa yang BELUM diketahui + kapan pembaruan berikutnya
         -> laporan awal cepat lebih baik daripada laporan lengkap yang terlambat

BERBAGI  memuat data yang bisa mengenali seseorang? -> BERHENTI, konsultasikan
         unggah artefak ke layanan LUAR NEGERI = perpindahan data -> periksa aturannya
         simpan seperlunya dan sebentar

PENGUMPULAN LOKAL  terbitan lembaga | berbagi sektor | komunitas tim tanggap | berita & riset lokal
         nilai dengan kriteria yang SAMA seperti sumber lain (Day 15)
         kemampuan BAHASA = bagian dari kapabilitas pengumpulan; tulis sebagai celah bila kurang
         PANTAU PERUBAHAN REGULASI sebagai kebutuhan intelijen tersendiri
```

## 10. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Peraturan BSSN Nomor 1 Tahun 2024 tentang Pengelolaan Insiden Siber | https://peraturan.bpk.go.id/Details/291240/peraturan-bssn-no-1-tahun-2024 | primer | ditetapkan 10 Januari 2024; halaman dirujuk 2026-10-09 | Sedang-tinggi untuk keberadaan, tanggal, dan materi pokok. Kategori insiden dan tenggat pelaporan di batang tubuhnya perlu dicocokkan sendiri |
| S2 | Peraturan Presiden Nomor 82 Tahun 2022 tentang Pelindungan Infrastruktur Informasi Vital | https://peraturan.bpk.go.id/ | primer | dirujuk 2026-10-09 | Sedang. Disebut sebagai dasar Peraturan BSSN Nomor 1 Tahun 2024; halaman spesifiknya perlu kamu cari sendiri di JDIH |
| S3 | Undang-Undang Nomor 27 Tahun 2022 tentang Pelindungan Data Pribadi | https://peraturan.bpk.go.id/Details/229798/uu-no-27-tahun-2022 | primer | ditetapkan dan diundangkan 17 Oktober 2022; halaman dirujuk 2026-10-09 | Tinggi untuk tanggal penetapan dan pengundangan. Teks resmi untuk Pasal 46 |
| S4 | Ringkasan dan analisis pihak ketiga tentang Peraturan Pemerintah Nomor 33 Tahun 2026 | (beberapa, kantor hukum dan media) | sekunder | dirujuk 2026-10-09 | Rendah-sedang. Tanggal penetapan 16 Juli 2026 dan mulai berlaku 16 Januari 2027, serta keterangan bahwa banyak ketentuan menunggu aturan lanjutan, berasal dari ringkasan pihak ketiga yang saling menguatkan tetapi bukan sumber resmi |
| S5 | JDIH BSSN | https://jdih.bssn.go.id/ | primer | dirujuk 2026-10-09 | Tinggi sebagai tempat memverifikasi teks peraturan BSSN |
| S6 | CTI-note Day 02, 03, 05, 10, 11, 13, 14, 15 | (lokal) | rujukan internal | 2026-10-09 | Keterkaitan antar Day |
| S7 | Pasal.id: UU Nomor 27 Tahun 2022, Pasal 46 | https://pasal.id/peraturan/uu/uu-no-27-tahun-2022/pasal-46 | sekunder (salinan teks peraturan) | diakses 2026-10-10 | Sedang-tinggi. Bunyi Pasal 46 dan penjelasannya; cocokkan dengan teks resmi di S3 |

**Catatan sumber:** Day ini ditulis sebagai kerangka kerja, bukan rujukan hukum. Bunyi Pasal 46 UU Nomor 27 Tahun 2022 diambil dari salinan teks peraturan dan sebaiknya dicocokkan dengan teks resmi sebelum dikutip di prosedur. Yang masih lemah dan perlu kamu cocokkan sendiri: isi lengkap Peraturan Pemerintah Nomor 33 Tahun 2026 termasuk tanggal berlakunya; kategori insiden dan tenggat pelaporan di Peraturan BSSN Nomor 1 Tahun 2024; status pembentukan lembaga pengawas pelindungan data pribadi; serta kanal pelaporan yang berlaku saat ini. Angka jumlah tim tanggap insiden yang dikukuhkan dan target nasionalnya berasal dari pemberitaan dan sengaja tidak dituliskan sebagai angka di catatan ini. Seluruh templat di bagian 4 adalah susunan sendiri dan harus disesuaikan dengan format resmi yang berlaku saat kamu memakainya.
