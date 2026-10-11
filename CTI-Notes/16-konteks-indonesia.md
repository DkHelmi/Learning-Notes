---
day: 16
title: 'Konteks Indonesia: lembaga, kewajiban pelaporan, dan batas berbagi'
researched_on: 2026-10-10
versions_checked: 'UU No. 27 Tahun 2022 tentang Pelindungan Data Pribadi (ditetapkan dan diundangkan 17 Oktober 2022); PP No. 33 Tahun 2026 sebagai peraturan pelaksana (ditetapkan 16 Juli 2026, dinyatakan berlaku 16 Januari 2027 menurut ringkasan pihak ketiga); Peraturan BSSN No. 1 Tahun 2024 tentang Pengelolaan Insiden Siber (ditetapkan 10 Januari 2024); Perpres No. 82 Tahun 2022 tentang Pelindungan Infrastruktur Informasi Vital; rujukan Day 02, 05, 10, 11, 13, 15'
---

# Day 16: Konteks Indonesia

Cakupan: lembaga dan aturan yang menentukan ke mana insiden dilaporkan di Indonesia, dua kewajiban pelaporan yang berbeda (insiden siber dan kegagalan pelindungan data pribadi), apa yang berubah dengan peraturan pelaksana UU PDP, batas berbagi informasi, dan sumber lokal untuk rencana pengumpulan.

## Ide inti

Seluruh Day sebelumnya di topik ini memakai kerangka dan sumber internasional. Itu wajar, karena di situlah sebagian besar materinya. Tetapi pekerjaan nyata terjadi di yurisdiksi tertentu, dan di Indonesia ada tiga hal yang mengubah cara kerja: lembaga yang berbeda dari yang disebut di laporan internasional, kewajiban pelaporan yang punya dasar hukum sendiri, dan aturan pelindungan data yang membatasi apa yang boleh kamu kumpulkan dan bagikan. Day ini menyusun ketiganya, ditambah satu akibat yang sering terlewat: sumber lokal dan perubahan regulasi harus masuk ke rencana pengumpulan.

Satu peringatan sejak awal, dan ini berlaku ke seluruh isi Day: catatan ini bukan nasihat hukum. Regulasi di wilayah ini sedang bergerak cepat, dan sebagian sumber yang tersedia saat penulisan berupa ringkasan pihak ketiga, bukan teks resmi. Verifikasi setiap kewajiban ke teks aslinya di JDIH lembaga terkait atau peraturan.bpk.go.id, dan libatkan penasihat hukum organisasimu untuk keputusan yang mengikat.

Kamu sudah mengenal versi kecil pekerjaan ini di SOC. Playbook IR punya escalation matrix: siapa diberi tahu, dalam berapa lama, lewat kanal apa, dan siapa yang berwenang memutuskan di luar jam kerja. Analyst L1 memvalidasi alert dulu sebelum mengeskalasi ke L2. Sebelum mengirim sampel log ke vendor support atau MSSP, kamu meredaksi nama user dan alamat surel. Konteks Indonesia adalah versi formal ketiganya: matriks eskalasinya punya dasar hukum dan tenggat yang ditetapkan peraturan, organisasi menjadi tingkat pertama yang wajib memvalidasi sebelum eskalasi keluar, dan aturan redaksinya ditentukan pelindungan data pribadi. Bedanya, tenggat dan pemicunya bukan SLA internal yang bisa kamu ubah sendiri, dan keputusan akhirnya melibatkan tim hukum.

```
Insiden terdeteksi di organisasi
  -> tim tanggap insiden organisasi (pihak pertama): identifikasi, validasi, batasi dampak
  -> pohon keputusan, disiapkan SEBELUM insiden:
       data pribadi terdampak?          -> pemberitahuan kegagalan pelindungan data pribadi
                                           (UU PDP Pasal 46, 3 x 24 jam) -> subjek data + lembaga
       kategori insiden siber wajib?    -> pelaporan insiden siber (Peraturan BSSN No. 1/2024)
       kewajiban sektor / kontrak?      -> jalur sektor / jalur kontrak
  -> berbagi intel keluar: cek data pribadi, perpindahan data ke luar negeri, TLP
  -> pantau perubahan regulasi sebagai kebutuhan intelijen -> perbarui daftar kewajiban
```

Situasi yang dipakai sepanjang Day ini: pertengahan Oktober 2026 di PT Logistik Contoh (PT LC, perusahaan logistik fiktif dengan gudang di Jakarta, Surabaya, dan Medan, serta portal pelanggan yang menyimpan data pelanggan). Kepala Legal PT LC membaca berita bahwa peraturan pelaksana UU PDP sudah terbit, lalu mengirim pesan ke CISO, yang meneruskannya ke tim CTI:

> "Saya perlu peta kewajiban kita sebelum akhir bulan. Tolong jawab:
> 1. Lembaga mana mengurus apa, dan kalau kita kena insiden, siapa yang menangani pertama kali?
> 2. Kalau data pelanggan dari portal bocor, apa kewajiban kita dan berapa tenggatnya?
> 3. Peraturan pelaksana UU PDP katanya sudah terbit. Apa yang berubah, dan tanggal apa yang harus masuk kalender kepatuhan?
> 4. Laporan insiden siber dan pemberitahuan kebocoran data pribadi itu satu laporan yang sama, kan?
> 5. Saya dengar tim IR biasa mengunggah lampiran ke layanan pemindaian di luar negeri dan berbagi indikator ke komunitas sektor. Ada batasnya?
> 6. Rencana pengumpulan tim CTI isinya sumber berbahasa Inggris semua. Apa yang kurang?"

Pertanyaan 1 dijawab di bagian 1.1 dan 1.2, pertanyaan 2 di bagian 1.3, pertanyaan 3 di bagian 1.4, pertanyaan 4 di bagian 1.5, pertanyaan 5 di bagian 1.6, dan pertanyaan 6 di bagian 1.7. Artefak yang dikirim balik ke Kepala Legal ada di bagian 2.

**Kapan relevan:** saat menyusun prosedur pelaporan insiden, menyiapkan pohon keputusan sebelum insiden, memutuskan apakah sebuah artefak boleh dibagikan atau diunggah keluar, dan menyusun rencana pengumpulan untuk organisasi yang beroperasi di Indonesia.
**Kapan bukan jawaban:** saat keputusan mengikat harus diambil. Day ini kerangka kerja, bukan rujukan hukum: kewajiban, tenggat, dan kanal diambil dari teks resmi dan diputuskan bersama penasihat hukum, bukan disalin dari catatan ini.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Tabel ini memuat istilah yang muncul di Day ini. Kolom padanan memakai analogi SOC yang sama di semua Day CTI. Istilah dari Day sebelumnya (PIR, collection plan, TLP, bahasa keyakinan) tidak diulang, dan nama lembaga dijelaskan di bagian 1.1.

| Istilah | Arti singkat | Padanan di SOC |
|---|---|---|
| Penanganan berjenjang | Organisasi menangani insidennya lebih dulu (identifikasi, validasi, batasi dampak), baru eskalasi bila diperlukan | L1 memvalidasi alert sebelum eskalasi ke L2 dan L3 |
| Pelaporan insiden siber | Laporan teknis lewat jalur tim tanggap insiden menurut kerangka pengelolaan insiden siber | Eskalasi keluar sesuai escalation matrix di playbook IR |
| Pengendali data pribadi | Pihak yang menentukan tujuan pemrosesan data pribadi dan memikul kewajiban pemberitahuan | Pemilik data di register aset |
| Prosesor data pribadi | Pihak yang memproses data pribadi atas nama pengendali | MSSP atau vendor yang memegang log atas nama kita |
| Subjek data pribadi | Orang yang data pribadinya diproses | Pelanggan pemilik akun di portal |
| Kegagalan pelindungan data pribadi | Kegagalan menjaga kerahasiaan, integritas, dan ketersediaan data pribadi, sengaja maupun tidak | Insiden yang mengenai CIA data pribadi, tidak hanya kebocoran |
| Peraturan pelaksana | Aturan turunan yang mengatur teknis sebuah undang-undang | Runbook turunan dari kebijakan: requirement di atas, cara di bawah |
| Perpindahan data ke luar negeri | Data berpindah ke luar wilayah, termasuk lewat unggahan ke layanan di luar negeri | Mengirim sampel ke sandbox publik yang servernya di luar negeri |
| Pohon keputusan pelaporan | Alur yang menentukan kewajiban pelaporan mana yang berlaku untuk satu insiden | Escalation matrix yang ditulis sebelum insiden |
| JDIH | Jaringan Dokumentasi dan Informasi Hukum: situs resmi tempat teks peraturan sebuah lembaga diterbitkan | Dokumentasi resmi vendor, bukan blog pihak ketiga |

### 1.1 Siapa mengurus apa

Pertanyaan pertama Kepala Legal terdengar sederhana, tetapi laporan internasional yang biasa dibaca tim CTI PT LC menyebut lembaga negara lain. Sebelum menulis prosedur, petakan dulu lembaga di sini dan peran masing-masing.

Tabel berikut adalah peta itu. Perhatikan baris tim tanggap insiden organisasi, karena itu posisi PT LC sendiri, dan baris terakhir, karena statusnya yang paling tidak pasti.

| Lembaga atau entitas | Peran yang relevan bagi analis |
|---|---|
| BSSN | Lembaga yang mengatur pengelolaan insiden siber dan mengukuhkan tim tanggap insiden |
| Gov-CSIRT Indonesia | Pengelola tim tanggap insiden sektor pemerintah, berada di lingkungan BSSN |
| Tim tanggap insiden organisasi | Pihak pertama yang menangani insiden di organisasinya sendiri |
| ID-SIRTII/CC | Entitas dengan tugas sosialisasi, pemantauan, pendeteksian, dan peringatan dini pada jaringan telekomunikasi |
| Lembaga pelindungan data pribadi | Lembaga pengawas yang diamanatkan UU PDP; pembentukannya perlu kamu cek statusnya |

Baris terakhir yang paling sering menimbulkan kebingungan: lembaga pengawas pelindungan data pribadi diamanatkan untuk dibentuk, tetapi pembentukannya berada di tahap yang perlu kamu verifikasi sendiri statusnya saat membaca catatan ini. Jangan menuliskan kewajiban pelaporan ke lembaga itu dalam prosedurmu tanpa memastikan lembaganya sudah ada dan kanalnya sudah jelas.

### 1.2 Kerangka pengelolaan insiden siber dan penanganan berjenjang

Bagian kedua pertanyaan pertama ("siapa yang menangani pertama kali?") dijawab oleh kerangka pengelolaan insiden siber. Jawabannya: PT LC sendiri.

Pengelolaan insiden siber diatur dalam Peraturan BSSN Nomor 1 Tahun 2024, yang ditetapkan pada 10 Januari 2024 sebagai pelaksanaan Pasal 17 Peraturan Presiden Nomor 82 Tahun 2022 tentang Pelindungan Infrastruktur Informasi Vital [S1][S2]. Materi pokoknya mencakup tim tanggap insiden siber, pelaporan insiden siber, penanganan insiden siber, dan pelaksanaan kesiapan terhadap insiden [S1].

Prinsip yang perlu kamu pegang adalah penanganan berjenjang: organisasi menjadi pihak pertama yang melakukan identifikasi dan validasi, membatasi dampak, mengambil langkah awal, lalu melakukan eskalasi bila diperlukan.

Konsekuensinya untuk pekerjaanmu cukup langsung. Kemampuan organisasi untuk mengidentifikasi dan memvalidasi sendiri adalah syarat, bukan pilihan, dan di situlah seluruh materi deteksi dan hunting di repo ini bertemu dengan kerangka regulasi. Organisasi yang tidak bisa memvalidasi sendiri akan selalu terlambat melapor, karena ia bahkan tidak tahu ada yang perlu dilaporkan. Bagi PT LC, yang EDR-nya belum menjangkau semua endpoint, ini berarti celah telemetri juga celah kepatuhan.

Tim tanggap insiden organisasi perlu dikukuhkan dan didaftarkan, dan ada tenggat yang disebut dalam pemberitaan untuk pendaftarannya. Angka dan tenggatnya perlu kamu verifikasi ke sumber resmi, karena yang beredar berasal dari berita dan bukan dari teks peraturannya.

### 1.3 Pemberitahuan kegagalan pelindungan data pribadi (UU PDP Pasal 46)

Pertanyaan kedua menyangkut portal pelanggan PT LC. Bila data pelanggan bocor, kewajibannya datang dari rezim pelindungan data pribadi, bukan dari kerangka insiden siber di bagian 1.2.

UU Nomor 27 Tahun 2022 tentang Pelindungan Data Pribadi ditetapkan dan diundangkan pada 17 Oktober 2022 [S3]. Undang-undang ini memuat kewajiban bagi pengendali dan prosesor data pribadi, termasuk kewajiban memberitahukan kegagalan pelindungan data pribadi.

Ketentuannya ada di Pasal 46 UU Nomor 27 Tahun 2022 [S7]. Ayat (1) mewajibkan pengendali data pribadi menyampaikan pemberitahuan tertulis paling lambat 3 x 24 jam kepada subjek data pribadi dan kepada lembaga bila terjadi kegagalan pelindungan data pribadi. Ayat (2) menyebut isi minimal pemberitahuan: data pribadi yang terungkap, kapan dan bagaimana data itu terungkap, serta upaya penanganan dan pemulihan. Ayat (3) menambahkan bahwa dalam hal tertentu pengendali juga wajib memberi tahu masyarakat. Penjelasan pasalnya mengartikan kegagalan pelindungan sebagai kegagalan menjaga kerahasiaan, integritas, dan ketersediaan data pribadi, baik karena kesengajaan maupun tidak.

Dua hal yang tidak dijawab teks pasal dan perlu diputuskan di kebijakan internal bersama tim hukum: sejak kapan hitungan 3 x 24 jam dimulai (saat kejadian, saat terdeteksi, atau saat kegagalan dipastikan), dan kapan "hal tertentu" yang mewajibkan pemberitahuan ke masyarakat terpenuhi. Pemberitahuan ke lembaga juga bergantung pada keberadaan lembaga pengawas dan kanalnya (bagian 1.1).

### 1.4 Peraturan pelaksana dan tanggal yang perlu dicatat

Pertanyaan ketiga dipicu berita yang dibaca Kepala Legal. Yang perlu ia dapat adalah tanggal untuk kalender kepatuhan beserta seberapa kuat dasar tanggal itu.

Peraturan pelaksana UU PDP terbit dalam bentuk Peraturan Pemerintah Nomor 33 Tahun 2026. Menurut ringkasan pihak ketiga, PP itu ditetapkan pada 16 Juli 2026 dan dinyatakan berlaku pada 16 Januari 2027, serta memuat pengaturan teknis kewajiban pengendali dan prosesor [S4]. Sejumlah ringkasan juga menyebut bahwa banyak ketentuan di dalamnya masih menunggu aturan lanjutan dari lembaga pengawas yang belum terbentuk [S4].

Tiga hal praktis dari situ. Pertama, ada tanggal yang perlu masuk ke kalender kepatuhan organisasimu. Kedua, selama aturan lanjutan belum ada, sebagian kewajiban teknisnya belum bisa dipenuhi secara pasti, dan itu perlu dinyatakan sebagai risiko yang diketahui, bukan disembunyikan. Ketiga, karena seluruh informasi tentang PP ini di catatan ini berasal dari ringkasan pihak ketiga, perlakukan sebagai petunjuk arah dan bukan sebagai rujukan hukum.

### 1.5 Dua kewajiban yang berbeda

Pertanyaan keempat Kepala Legal ("satu laporan yang sama, kan?") adalah pembedaan yang sering dicampur dan menimbulkan kesalahan prosedur. Jawabannya: tidak.

Tabel berikut membandingkan keduanya baris per baris. Perhatikan baris tujuan laporan: pelaporan insiden siber mengalir ke jalur tim tanggap insiden, sedangkan pemberitahuan kegagalan pelindungan data pribadi mengalir ke orang yang datanya terdampak.

| Aspek | Pelaporan insiden siber | Pemberitahuan kegagalan pelindungan data pribadi |
|---|---|---|
| Dasar | Kerangka pengelolaan insiden siber [S1] | UU PDP dan peraturan pelaksananya [S3][S4] |
| Pemicu | Insiden siber sesuai kategori yang ditetapkan | Kegagalan pelindungan data pribadi |
| Tujuan laporan | Jalur tim tanggap insiden dan lembaga terkait | Subjek data dan lembaga pengawas |
| Isi | Teknis: apa yang terjadi, dampak, penanganan | Dampak pada subjek data dan langkah penanganannya |

Satu insiden bisa memicu keduanya, salah satunya, atau tidak sama sekali. Yang perlu kamu siapkan sebelum insiden adalah pohon keputusan yang menentukan mana yang berlaku, dan siapa yang berwenang memutuskannya. Membuat pohon keputusan itu saat insiden sedang berjalan adalah cara yang pasti untuk melewatkan tenggat. Pohon keputusan untuk PT LC ada di bagian 2.2.

### 1.6 Batas berbagi informasi

Pertanyaan kelima menyentuh dua kebiasaan tim IR PT LC: mengunggah lampiran ke layanan pemindaian di luar negeri dan berbagi indikator ke komunitas sektor. Keduanya praktik CTI yang wajar, dan keduanya bisa melanggar aturan pelindungan data bila isinya tidak diperiksa.

Pekerjaan CTI bertumpu pada berbagi, dan di sinilah aturan pelindungan data mengikat. Tiga batas yang perlu kamu terapkan, melanjutkan prinsip etika di Day 05:

- **Jangan membagikan data pribadi sebagai indikator.** Alamat surel, nama, dan nomor identitas adalah data pribadi, dan membagikannya ke komunitas atau platform luar punya konsekuensi tersendiri. Bila harus, agregasikan atau samarkan.
- **Perhatikan perpindahan data ke luar negeri.** Mengunggah artefak ke layanan analisis luar negeri memindahkan data, dan bila artefak itu memuat data pribadi, aturan perpindahan data berlaku. Ini mengenai praktik sehari-hari seperti mengunggah berkas ke layanan pemindaian publik. Cari berdasarkan hash lebih dulu, dan unggah berkas hanya bila sudah dipastikan tidak memuat data pribadi atau data klien.
- **Simpan seperlunya dan sebentar.** Day 14 sudah menyebutnya untuk data bocoran; prinsip yang sama berlaku untuk seluruh koleksi intelijenmu.

Satu kebiasaan sederhana yang menyelesaikan sebagian besar masalah: sebelum membagikan apa pun keluar, tanyakan apakah isinya bisa dipakai mengenali seseorang. Bila ya, berhenti dan tanyakan ke penasihat hukum atau pejabat pelindungan data organisasimu. Lembar periksanya ada di bagian 2.4.

### 1.7 Sumber lokal untuk rencana pengumpulan

Pertanyaan keenam menunjuk celah yang nyata: rencana pengumpulan tim CTI PT LC hanya berisi sumber berbahasa Inggris, padahal lembaga, regulasi, dan sebagian ancaman yang relevan diterbitkan dalam bahasa Indonesia.

Rencana pengumpulanmu (Day 02 dan Day 15) akan timpang bila hanya berisi sumber berbahasa Inggris. Jenis sumber lokal yang layak masuk:

- **Terbitan lembaga.** Peringatan, panduan teknis, dan laporan lanskap dari lembaga yang berwenang.
- **Berbagi antar organisasi sektor.** Jalur berbagi di sektor yang sama sering memberi informasi yang paling relevan dan paling cepat.
- **Komunitas tim tanggap insiden.** Jaringan tim yang sudah dikukuhkan adalah jalur yang sah dan berguna.
- **Pemberitaan dan riset lokal.** Berguna untuk konteks dan untuk memahami apa yang menjadi perhatian publik, dengan keandalan yang perlu dinilai seperti sumber lain.

Perlakukan sumber lokal dengan kriteria penilaian yang sama seperti sumber lain (Day 15 bagian 1.3). Relevansi tinggi tidak menghapus kebutuhan menilai ketepatan waktu dan keandalannya.

Satu catatan yang sering diabaikan: kemampuan bahasa adalah bagian dari kapabilitas pengumpulan. Tim yang hanya bisa membaca bahasa Inggris punya celah pengumpulan yang nyata di wilayah ini, dan itu layak ditulis sebagai celah di lembar metrikmu, bukan dibiarkan tak terlihat.

## 2. Contoh artefak intelijen

Seluruh isi bagian ini adalah kerangka kerja untuk PT LC (fiktif), bukan nasihat hukum: isi kolom dasar hukum dengan hasil verifikasimu sendiri ke teks resmi, bukan dengan menyalin dari catatan ini. Kelima artefak di bawah adalah bahan jawaban tim CTI untuk pesan Kepala Legal di bagian Ide inti.

### 2.1 Daftar kewajiban pelaporan organisasi

Daftar ini menjawab pertanyaan 1 sampai 4 sekaligus dalam bentuk yang bisa ditempel di prosedur PT LC, dengan kolom yang sengaja dibiarkan kosong sampai diverifikasi.

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

### 2.2 Pohon keputusan pelaporan

Pohon ini jawaban untuk pertanyaan keempat dalam bentuk yang bisa dipakai tengah malam: dari satu insiden tervalidasi ke kewajiban yang berlaku.

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

### 2.3 Templat isi laporan teknis

Templat ini disiapkan supaya tim IR PT LC tidak menyusun laporan dari nol. Susun sekali, pakai berulang. Isinya mengikuti apa yang biasanya ditanyakan, dan menyiapkannya lebih dulu menghemat waktu saat tenggat berjalan:

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

### 2.4 Lembar batas berbagi

Lembar ini jawaban untuk pertanyaan kelima, dipakai tim IR dan CTI PT LC setiap kali akan mengunggah artefak atau berbagi indikator keluar.

```
SEBELUM MEMBAGIKAN KELUAR, PERIKSA:

  1. Apakah isinya memuat data yang bisa mengenali seseorang?
     ya -> hentikan, konsultasikan
  2. Apakah artefak akan diunggah ke layanan di luar negeri?
     ya -> periksa aturan perpindahan data; pertimbangkan analisis lokal
  3. Apakah penerimanya jelas dan jalurnya sah?
  4. Apakah penanda TLP sudah sesuai (Day 11)?
  5. Apakah asal setiap klaim tercatat (Day 14)?
  6. Apakah ada persetujuan yang diperlukan, dan siapa yang memberinya?

CATATAN: daftar ini bukan pengganti nasihat hukum; ia alat agar pertanyaan yang benar
diajukan sebelum, bukan sesudah.
```

### 2.5 Rencana pengumpulan sumber lokal

Rencana ini jawaban untuk pertanyaan keenam, sebagai tambahan pada rencana pengumpulan tim CTI PT LC. Baca kolom penilaian: setiap sumber lokal tetap dinilai, tidak diterima begitu saja karena relevan.

| Kebutuhan | Sumber lokal | Jenis | Ritme | Penilaian |
|---|---|---|---|---|
| Ancaman yang menyasar sektor kami | Terbitan lembaga berwenang | Resmi | Saat terbit | Relevansi tinggi, ketepatan waktu perlu diukur |
| Peringatan dini | Jalur berbagi sektor | Komunitas resmi | Berkelanjutan | Perlu keanggotaan; nilai setelah satu kuartal |
| Konteks publik dan perhatian regulator | Pemberitaan dan riset lokal | Terbuka | Mingguan | Keandalan dinilai per kasus |
| Perubahan regulasi | JDIH lembaga terkait | Resmi | Bulanan | Keandalan tinggi; pantau perubahan |

Baris terakhir sering tidak ada di rencana pengumpulan tim CTI, padahal perubahan regulasi mengubah kewajiban dan karenanya mengubah prioritas. Perlakukan sebagai kebutuhan intelijen tersendiri (Day 15).

## 3. Lab praktik

**Prasyarat:** akses ke situs JDIH dan peraturan resmi, serta hasil Day 15 (register kebutuhan dan rencana pengumpulan). Seluruh lab bersifat membaca dan menulis.

1. Baca Pasal 46 UU Nomor 27 Tahun 2022 beserta penjelasannya di teks resmi, lalu tulis keputusan kebijakan internal untuk dua hal yang tidak diatur pasalnya: titik mulai hitungan 3 x 24 jam dan kriteria pemberitahuan ke masyarakat.
2. Cari status peraturan pelaksananya dan catat tanggal penetapan serta tanggal mulai berlaku dari sumber resmi, bukan dari ringkasan.
3. Periksa apakah lembaga pengawas pelindungan data pribadi sudah terbentuk saat kamu mengerjakan ini, dan catat apa dasar temuanmu.
4. Cari teks Peraturan BSSN Nomor 1 Tahun 2024 di sumber resmi, lalu catat ketentuan tentang pelaporan insiden: kategori apa yang wajib dilaporkan dan dengan tenggat berapa.
5. Isi daftar kewajiban bagian 2.1 untuk PT LC atau organisasi fiktif pilihanmu, dengan seluruh kolom dasar hukum diisi hasil verifikasimu sendiri.
6. Verifikasi kanal pelaporan ke situs resmi lembaga terkait, dan bandingkan dengan kanal yang disebut di dokumen panduan lama yang kamu temukan. Catat perbedaannya.
7. Susun pohon keputusan bagian 2.2, lalu ujikan ke tiga skenario: insiden tanpa data pribadi, insiden dengan data pribadi, dan insiden di pihak ketiga.
8. Isi templat laporan teknis bagian 2.3 untuk satu skenario fiktif, lengkap dengan tiga waktu yang berbeda di butir kedua.
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

## 4. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa |
|---|---|---|
| Tenggat pelaporan berbeda antar sumber | Ringkasan pihak ketiga tidak seragam | Baca teks resminya; jangan mengutip ringkasan di prosedur |
| Kanal pelaporan tidak merespons | Dokumen panduan yang dipakai sudah lama | Verifikasi ke situs resmi lembaga; perbarui daftar kontak berkala |
| Tidak jelas apakah insiden wajib dilaporkan | Kategori insiden tidak dipetakan ke konteks organisasi | Petakan kategori di peraturan ke jenis sistem yang kamu punya |
| Keputusan melapor tertunda | Tidak ada yang berwenang memutuskan di luar jam kerja | Tetapkan jalur eskalasi di pohon keputusan (bagian 2.2) |
| Laporan ditolak karena tidak lengkap | Isi tidak mengikuti format yang diminta | Pakai templat bagian 2.3 dan sesuaikan dengan format resmi |
| Ragu boleh membagikan artefak ke layanan luar | Aturan perpindahan data | Pakai lembar bagian 2.4; konsultasikan sebelum mengunggah |
| Kewajiban sektor terlewat | Hanya memperhatikan aturan umum | Daftarkan kewajiban sektor di bagian 2.1 |
| Prosedur usang dalam hitungan bulan | Regulasi sedang bergerak cepat | Jadikan pemantauan regulasi sebagai kebutuhan intelijen (Day 15) |

## 5. Kesalahan umum dan jebakan

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

## 6. Catatan terkini

Bagian ini menampung status regulasi dan kelembagaan yang sedang bergerak. Isinya menentukan kapan prosedur perlu ditinjau ulang, dan semuanya perlu diverifikasi ke teks resmi sebelum dipakai.

- Peraturan pelaksana UU Pelindungan Data Pribadi terbit sebagai Peraturan Pemerintah Nomor 33 Tahun 2026, dengan penetapan 16 Juli 2026 dan mulai berlaku 16 Januari 2027 menurut ringkasan yang beredar [S4]. Masukkan tanggal berlakunya ke kalender kepatuhan organisasimu setelah kamu verifikasi sendiri ke teks resmi.
- Sejumlah ringkasan menyebut banyak ketentuan di peraturan pelaksana itu masih menunggu aturan lanjutan dari lembaga pengawas yang pembentukannya belum selesai [S4]. Artinya sebagian kewajiban teknis belum bisa dipenuhi dengan kepastian, dan itu sebaiknya dicatat sebagai risiko yang diketahui, bukan diabaikan.
- Kerangka pengelolaan insiden siber yang berlaku bersandar pada Peraturan BSSN Nomor 1 Tahun 2024, yang merupakan pelaksanaan dari peraturan presiden tentang pelindungan infrastruktur informasi vital, dan mencabut peraturan sebelumnya tentang tim tanggap insiden siber [S1][S2]. Dokumen panduan yang masih merujuk peraturan lama perlu dicocokkan ulang. Posisi tim tanggap insiden organisasi sebagai pihak pertama menegaskan bahwa kemampuan deteksi dan validasi internal adalah syarat kepatuhan, bukan hanya praktik baik.
- Jumlah tim tanggap insiden yang dikukuhkan terus bertambah dan target nasionalnya masih jauh. Bila organisasimu belum punya tim yang dikukuhkan, itu pekerjaan yang layak diusulkan, dan materi di repo ini adalah bahan untuk membangunnya.
- Sebagian besar informasi tentang perkembangan regulasi yang beredar berasal dari kantor hukum dan media, bukan dari pengumuman resmi. Perlakukan sebagai peringatan dini yang berguna, lalu verifikasi ke sumber resmi sebelum dipakai.

## 7. Cheat sheet

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
            -> kemampuan deteksi internal = SYARAT KEPATUHAN, bukan hanya praktik baik

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

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** Draf prosedur PT LC menulis: "Sesuai UU PDP Pasal 46, pemberitahuan dikirim paling lambat 3 x 24 jam sejak insiden terdeteksi." Apakah frasa "sejak insiden terdeteksi" berasal dari teks pasal?

<details><summary>Jawaban</summary>

Tidak. Ayat (1) menetapkan pemberitahuan tertulis paling lambat 3 x 24 jam kepada subjek data pribadi dan lembaga, tetapi teks pasal tidak menjawab sejak kapan hitungan dimulai: saat kejadian, saat terdeteksi, atau saat kegagalan dipastikan. Titik mulai itu keputusan kebijakan internal yang diambil bersama tim hukum, dan prosedur sebaiknya menyebutnya sebagai keputusan internal, bukan sebagai bunyi pasal. Hal yang sama berlaku untuk kriteria "hal tertentu" yang mewajibkan pemberitahuan ke masyarakat. Lihat bagian 1.3 dan 2.1.

</details>

**2. Skenario keputusan.** Tim IR PT LC memvalidasi bahwa nama dan alamat surel pelanggan dari portal terunggah ke luar. Apa langkah yang tepat?

- A. Kirim satu laporan insiden siber lewat jalur tim tanggap insiden, karena kejadiannya insiden siber dan laporan itu sudah mencakup semuanya.
- B. Kirim pemberitahuan kegagalan pelindungan data pribadi saja, karena yang terdampak data pribadi.
- C. Jalankan pohon keputusan yang sudah disiapkan: data pribadi terdampak membuka jalur pemberitahuan kegagalan pelindungan data pribadi, lalu periksa juga apakah kejadiannya memenuhi kategori insiden siber yang wajib dilaporkan, kewajiban sektor, dan kewajiban kontrak.

<details><summary>Jawaban</summary>

C. Pelaporan insiden siber dan pemberitahuan kegagalan pelindungan data pribadi adalah dua kewajiban berbeda dengan dasar, pemicu, tujuan, dan isi yang berbeda, dan satu insiden bisa memicu keduanya, salah satunya, atau tidak sama sekali. A keliru karena laporan insiden siber berisi hal teknis dan mengalir ke jalur tim tanggap insiden, sedangkan pemberitahuan data pribadi ditujukan ke subjek data dan lembaga pengawas dengan isi tentang dampak pada subjek data. B keliru karena berhenti di satu cabang tanpa memeriksa kategori insiden siber, sektor, dan kontrak. Lihat bagian 1.5 dan 2.2.

</details>

**3. Pertanyaan jebakan.** "UU PDP mengamanatkan lembaga pengawas, jadi prosedur kita cukup menulis: laporkan ke lembaga pengawas lewat kanal resminya." Apa masalahnya?

<details><summary>Jawaban</summary>

Lembaga pengawas pelindungan data pribadi memang diamanatkan untuk dibentuk, tetapi status pembentukannya perlu diverifikasi sendiri saat prosedur ditulis. Jangan menuliskan kewajiban pelaporan ke lembaga itu tanpa memastikan lembaganya sudah ada dan kanalnya sudah jelas. Di daftar kewajiban, kolom kanal untuk pemberitahuan data pribadi sengaja ditulis "verifikasi; cek apakah lembaga pengawas sudah terbentuk". Lihat bagian 1.1, 1.3, dan 2.1.

</details>

**4. Jelaskan ulang.** Jelaskan kepada Kepala Legal PT LC dalam tiga kalimat kenapa kemampuan deteksi dan validasi internal adalah urusan kepatuhan, bukan hanya urusan teknis tim SOC.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Kerangka pengelolaan insiden siber memakai prinsip penanganan berjenjang: organisasi sendiri yang pertama mengidentifikasi, memvalidasi, dan membatasi dampak insiden sebelum eskalasi ke luar. Kalau kita tidak bisa mendeteksi dan memvalidasi sendiri, kita tidak akan tahu ada yang perlu dilaporkan, sehingga kita pasti terlambat melapor. Karena itu celah telemetri, misalnya endpoint yang belum terpasang EDR, juga celah kepatuhan."

Kesalahan yang sering muncul:
- Menganggap pelaporan cukup diserahkan ke lembaga, seolah lembaga yang mendeteksi insiden untuk kita.
- Menyamakan penanganan berjenjang dengan langsung melapor ke luar tanpa validasi.
- Menyebut angka atau tenggat pendaftaran tim tanggap insiden dari berita seolah berasal dari teks peraturan.

</details>

**5. Skenario keputusan.** Analis IR PT LC menerima lampiran email mencurigakan berupa spreadsheet yang tampaknya berisi daftar pelanggan. Ia ingin tahu apakah berkas itu berbahaya. Apa yang sebaiknya dilakukan?

- A. Unggah berkas ke layanan pemindaian publik di luar negeri, karena itu cara tercepat dan semua tim melakukannya.
- B. Cari berdasarkan hash lebih dulu; jangan unggah berkasnya selama belum dipastikan tidak memuat data pribadi atau data klien, pertimbangkan analisis lokal, dan konsultasikan bila ragu.
- C. Abaikan berkas itu, karena pelindungan data pribadi melarang menganalisis artefak yang memuat data pribadi.

<details><summary>Jawaban</summary>

B. Mengunggah artefak ke layanan analisis luar negeri memindahkan data, dan bila artefak memuat data pribadi, aturan perpindahan data berlaku. Mencari berdasarkan hash lebih dulu tidak memindahkan isi berkas. A keliru karena berkas yang tampaknya berisi daftar pelanggan hampir pasti memuat data pribadi, dan kebiasaan tim bukan dasar hukum. C keliru karena batasnya ada pada cara berbagi dan memindahkan data, bukan larangan menganalisis; analisis lokal tetap terbuka. Lihat bagian 1.6 dan 2.4.

</details>

**6. Pertanyaan jebakan.** Kepala Legal meneruskan ringkasan dari kantor hukum yang menyebut PP Nomor 33 Tahun 2026 berlaku 16 Januari 2027, lalu meminta tanggal itu langsung dicantumkan di prosedur resmi sebagai rujukan. Tepatkah?

<details><summary>Jawaban</summary>

Belum. Tanggal penetapan 16 Juli 2026 dan mulai berlaku 16 Januari 2027 di catatan ini berasal dari ringkasan pihak ketiga yang saling menguatkan, bukan dari teks resmi. Tanggal itu berguna sebagai petunjuk arah dan peringatan dini, tetapi harus diverifikasi ke teks resmi sebelum masuk kalender kepatuhan atau prosedur. Selain itu, ringkasan yang sama menyebut banyak ketentuan masih menunggu aturan lanjutan dari lembaga pengawas, sehingga sebagian kewajiban teknis sebaiknya dicatat sebagai risiko yang diketahui. Lihat bagian 1.4 dan 6.

</details>

**7. Interview question (English).** "Your company operates in Indonesia. How do you make sure the team meets its incident reporting obligations, especially when personal data may be involved?"

<details><summary>Sample answer</summary>

"First, I separate the two obligations, because they're often mixed up. Cyber incident reporting follows the national incident management framework and goes through the incident response channel with technical content, while notifying a personal data protection failure under the PDP Law goes to the affected data subjects and the supervisory authority, with a written notice within three times twenty-four hours. One incident can trigger both, one, or neither, so I build a decision tree before any incident happens, and I make sure it names who decides and who can be reached outside working hours. I also prepare a report template that records three different timestamps, when it happened, when it was detected, and when it was validated, and that states what we don't know yet, so the first report can go out on time. Finally, I verify every deadline and reporting channel against the official regulation text with our legal counsel, because summaries vary and the regulations are changing quickly."

What makes this answer strong: it distinguishes the two obligations clearly, shows preparation before the incident rather than during it, covers decision authority and practical reporting details, and treats legal verification as part of the process instead of guessing at the law.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Peraturan BSSN Nomor 1 Tahun 2024 tentang Pengelolaan Insiden Siber | https://peraturan.bpk.go.id/Details/291240/peraturan-bssn-no-1-tahun-2024 | primer | ditetapkan 10 Januari 2024; halaman dirujuk 2026-10-09 | Sedang-tinggi untuk keberadaan, tanggal, dan materi pokok. Kategori insiden dan tenggat pelaporan di batang tubuhnya perlu dicocokkan sendiri |
| S2 | Peraturan Presiden Nomor 82 Tahun 2022 tentang Pelindungan Infrastruktur Informasi Vital | https://peraturan.bpk.go.id/ | primer | dirujuk 2026-10-09 | Sedang. Disebut sebagai dasar Peraturan BSSN Nomor 1 Tahun 2024; halaman spesifiknya perlu kamu cari sendiri di JDIH |
| S3 | Undang-Undang Nomor 27 Tahun 2022 tentang Pelindungan Data Pribadi | https://peraturan.bpk.go.id/Details/229798/uu-no-27-tahun-2022 | primer | ditetapkan dan diundangkan 17 Oktober 2022; halaman dirujuk 2026-10-09 | Tinggi untuk tanggal penetapan dan pengundangan. Teks resmi untuk Pasal 46 |
| S4 | Ringkasan dan analisis pihak ketiga tentang Peraturan Pemerintah Nomor 33 Tahun 2026 | (beberapa, kantor hukum dan media) | sekunder | dirujuk 2026-10-09 | Rendah-sedang. Tanggal penetapan 16 Juli 2026 dan mulai berlaku 16 Januari 2027, serta keterangan bahwa banyak ketentuan menunggu aturan lanjutan, berasal dari ringkasan pihak ketiga yang saling menguatkan tetapi bukan sumber resmi |
| S5 | JDIH BSSN | https://jdih.bssn.go.id/ | primer | dirujuk 2026-10-09 | Tinggi sebagai tempat memverifikasi teks peraturan BSSN |
| S6 | CTI-note Day 02, 03, 05, 10, 11, 13, 14, 15 | (lokal) | rujukan internal | 2026-10-09 | Keterkaitan antar Day |
| S7 | Pasal.id: UU Nomor 27 Tahun 2022, Pasal 46 | https://pasal.id/peraturan/uu/uu-no-27-tahun-2022/pasal-46 | sekunder (salinan teks peraturan) | diakses 2026-10-10 | Sedang-tinggi. Bunyi Pasal 46 dan penjelasannya; cocokkan dengan teks resmi di S3 |

**Catatan sumber:** Day ini ditulis sebagai kerangka kerja, bukan rujukan hukum. Bunyi Pasal 46 UU Nomor 27 Tahun 2022 diambil dari salinan teks peraturan dan sebaiknya dicocokkan dengan teks resmi sebelum dikutip di prosedur. Yang masih lemah dan perlu kamu cocokkan sendiri: isi lengkap Peraturan Pemerintah Nomor 33 Tahun 2026 termasuk tanggal berlakunya; kategori insiden dan tenggat pelaporan di Peraturan BSSN Nomor 1 Tahun 2024; status pembentukan lembaga pengawas pelindungan data pribadi; serta kanal pelaporan yang berlaku saat ini. Angka jumlah tim tanggap insiden yang dikukuhkan dan target nasionalnya berasal dari pemberitaan dan sengaja tidak dituliskan sebagai angka di catatan ini. Seluruh templat di bagian 2 adalah susunan sendiri dan harus disesuaikan dengan format resmi yang berlaku saat kamu memakainya.
