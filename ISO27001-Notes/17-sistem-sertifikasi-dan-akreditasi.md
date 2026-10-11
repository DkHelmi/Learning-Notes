---
day: 17
title: 'Sistem sertifikasi dan akreditasi: siapa mengaudit auditor, dan apa arti sertifikat'
researched_on: 2026-10-10
versions_checked: 'ISO/IEC 17021-1:2015 edisi 1 (published, terakhir dikonfirmasi 2020, tinjauan sistematis 2025-2026 tanpa hasil yang diumumkan di katalog); ISO/IEC 27006-1:2024 edisi 1, Maret 2024, menggantikan ISO/IEC 27006:2015 dan Amd 1:2020, transisi selesai 31 Maret 2026 menurut IAF MD 29:2024; Global Accreditation Cooperation Incorporated (Global ACI) menggantikan IAF dan ILAC sejak 1 Januari 2026; IAF CertSearch; KAN (cakupan IAF MLA untuk ISO/IEC 27006 dan 27001 sejak resolusi IAF 2019-23); Peraturan BSSN No. 8 Tahun 2020'
---

# Day 17: Sistem sertifikasi dan akreditasi

Cakupan: rantai kepercayaan di balik sertifikat ISO 27001 (akreditasi, pengakuan internasional, dan pengakuan BSSN), cara membaca dan memverifikasi sertifikat, cara memilih badan sertifikasi, dan apa yang dijamin maupun tidak dijamin oleh sebuah sertifikat.

## Ide inti

Sertifikat ISO 27001 hanya bernilai sejauh rantai di belakangnya bisa ditelusuri dan isinya relevan dengan yang kamu butuhkan. Nilai itu ditentukan tiga hal: siapa yang mengawasi penerbitnya (akreditasi), apa yang benar-benar tertulis di sertifikat (lingkup, situs, tanggal, edisi), dan apakah statusnya dikonfirmasi ke penerbit, bukan hanya ke dokumen yang dikirim pemasok. Bahkan sertifikat yang sah dan relevan hanya menjamin satu hal terbatas: pada tanggal audit, untuk lingkup yang tertulis, auditor menemukan ISMS yang memenuhi standar berdasarkan sampel.

Day 13 membahas siklus sertifikasi tiga tahun dari sisi organisasi yang diaudit. Day ini melihat satu lapis di atasnya: siapa yang mengawasi badan sertifikasi, dan kenapa hal itu menentukan nilai sertifikat yang kamu pegang maupun yang ditunjukkan pemasokmu. Dua organisasi bisa sama-sama memegang sertifikat ISO 27001 dengan nilai yang sangat berbeda, karena lingkupnya berbeda, badan sertifikasinya berbeda, atau salah satunya tidak terakreditasi.

Kamu sudah mengenal pola ini dari sertifikat TLS:

```
TLS                                      Sertifikasi ISMS
root store yang dipercaya browser    ~   badan akreditasi (di Indonesia: KAN),
                                         saling diakui lewat Global ACI MRA
aturan yang wajib diikuti CA         ~   ISO/IEC 17021-1 + ISO/IEC 27006-1
CA                                   ~   badan sertifikasi (CB)
sertifikat untuk domain tertentu     ~   sertifikat untuk lingkup dan situs tertentu
self-signed certificate              ~   sertifikat dari CB yang tidak terakreditasi
cek status ke CA, bukan file .crt    ~   konfirmasi status ke CB atau basis datanya
```

Batas analogi: tidak ada verifikasi kriptografis. Kepercayaan dibangun lewat audit berkala, dan dokumen sertifikat bisa dipalsukan tanpa jejak. Karena itu langkah konfirmasi ke penerbit justru lebih penting daripada di TLS.

Alur yang dijelaskan Day ini:

```
Sertifikat yang kamu terima (dokumen dari pemasok)
  -> baca isinya: lingkup, situs, tanggal, edisi, tanda akreditasi
  -> konfirmasi status ke penerbit (CB), bukan ke dokumen
  -> CB diawasi badan akreditasi terhadap 17021-1 + 27006-1
  -> badan akreditasi diakui lintas negara lewat Global ACI MRA (dahulu IAF MLA)
  -> sistem elektronik kategori strategis di Indonesia: CB juga harus diakui BSSN
  -> hasilnya: jaminan terbatas pada TANGGAL, LINGKUP, dan SAMPEL
```

Situasi yang dipakai sepanjang Day ini: Maret 2027, Direktur Operasional PT Awan Nusantara (PT AN, penyedia hosting fiktif) mengirim pesan ke ISMS Manager dan Lead SOC sebelum rapat direksi:

> "Tiga hal untuk Jumat ini.
> 1. PT Contoh Layanan, pemasok hosting aplikasi kita, mengirim sertifikat ISO 27001 yang masih berlaku. Apakah itu cukup untuk penilaian pemasok?
> 2. Procurement menerima dua penawaran badan sertifikasi untuk siklus sertifikasi kita berikutnya. Penawaran B jauh lebih murah. Kenapa tidak ambil yang murah saja?
> 3. Tim marketing ingin menulis di brosur: 'Tersertifikasi ISO 27001, layanan kami terbukti aman.' Boleh?"

Pertanyaan pertama dijawab oleh rantai kepercayaan dan cara memverifikasi sertifikat (bagian 1.1-1.3 dan 1.5), pertanyaan kedua oleh aturan yang mengikat CB dan cara memilihnya (bagian 1.4 dan 1.6), dan pertanyaan ketiga oleh batas makna sertifikat (bagian 1.7). Lapis pengakuan BSSN (bagian 1.2) menyentuh pertanyaan pertama dan kedua sekaligus.

**Kapan relevan:** menilai sertifikat pemasok atau calon mitra (Day 12), memilih atau berganti badan sertifikasi, menjawab pertanyaan klien tentang sertifikat sendiri, dan menulis klaim sertifikasi di brosur atau kontrak.
**Kapan bukan jawaban:** verifikasi sertifikat menjawab "apakah sertifikat ini sah dan relevan untuk layanan yang kami pakai", bukan "apakah pemasok ini aman". Sertifikat tidak menggantikan penilaian risiko pemasok, dan Day ini tidak membahas cara menjalani audit sertifikasi (Day 13).

## 1. Konsep inti

### 1.0 Istilah di Day ini

Tabel ini memuat istilah yang muncul di Day ini. CB, badan akreditasi, scope, dan SoA sudah dijelaskan di Day 01; siklus tahap 1, tahap 2, surveillance, dan resertifikasi di Day 13. Kolom padanan memakai analogi TLS yang sama dengan Day 01.

| Istilah | Arti singkat | Padanan di SOC |
|---|---|---|
| Akreditasi | Pengakuan formal bahwa CB kompeten dan imparsial untuk skema tertentu | CA yang dimasukkan ke root store |
| ISO/IEC 17021-1 | Persyaratan umum untuk CB sistem manajemen apa pun | Aturan yang wajib diikuti semua CA |
| ISO/IEC 27006-1 | Persyaratan tambahan untuk CB yang menyertifikasi ISMS | Aturan tambahan untuk jenis sertifikat tertentu |
| KAN (Komite Akreditasi Nasional) | Badan akreditasi Indonesia; sekretariatnya di BSN | Root store nasional |
| Global ACI MRA (dahulu IAF MLA) | Pengaturan saling pengakuan antar badan akreditasi | Root store yang saling mengakui |
| Dokumen wajib (IAF MD) | Aturan tambahan yang mengikat CB terakreditasi, misalnya multi-site dan audit jarak jauh | Kebijakan tambahan root program |
| Imparsialitas | CB tidak boleh menilai pekerjaan yang ia bantu bangun | Auditor QA tidak memeriksa tiketnya sendiri |
| Waktu audit (audit days) | Jumlah hari audit yang dihitung dari orang di dalam lingkup dan kompleksitas | Estimasi effort assessment dari jumlah aset |
| Isi minimum sertifikat | Butir yang wajib tercantum di dokumen sertifikasi menurut 17021-1 | Field sertifikat X.509 (subject, validity, issuer) |
| IAF CertSearch | Basis data global sertifikat terakreditasi yang diisi CB peserta | Log publik sertifikat, tetapi tidak wajib diisi |
| Sertifikat tidak terakreditasi | Sertifikat dari CB yang tidak diawasi badan akreditasi | Self-signed certificate |
| Pengakuan BSSN | Pengakuan BSSN atas lembaga sertifikasi SMPI untuk penyelenggara sistem elektronik | Daftar CA yang diwajibkan regulator untuk sistem tertentu |
| Audit khusus | Audit di luar jadwal setelah insiden pada sistem yang tersertifikasi (Peraturan BSSN 8/2020) | Review mendadak setelah insiden mayor |

### 1.1 Rantai kepercayaan

Pertanyaan pertama Direktur Operasional ("apakah sertifikat pemasok cukup?") tidak bisa dijawab dari dokumennya saja. Sertifikat ISO 27001 bernilai karena ada rantai yang bisa ditelusuri ke atas:

```
organisasi yang disertifikasi
  diaudit oleh  ->  badan sertifikasi (certification body, CB)
  yang diakreditasi oleh  ->  badan akreditasi nasional (di Indonesia: KAN)
  yang saling mengakui lewat  ->  pengaturan pengakuan multilateral
                                  (IAF MLA sampai 2025, Global ACI MRA sejak 2026)
```

Tiap lapis punya aturannya sendiri:

- **Badan sertifikasi** tunduk pada ISO/IEC 17021-1:2015, persyaratan umum untuk lembaga yang mengaudit dan menyertifikasi sistem manajemen apa pun. Isinya prinsip dan persyaratan tentang kompetensi, konsistensi, dan imparsialitas [S1].
- **Untuk ISMS secara khusus**, ada persyaratan tambahan di ISO/IEC 27006-1:2024, yang melengkapi 17021-1 [S2]. Edisi yang digantikannya dicatat di bagian 6.
- **Badan akreditasi** menilai badan sertifikasi terhadap kedua standar itu. Di Indonesia perannya dijalankan KAN (Komite Akreditasi Nasional), yang sekretariatnya berada di BSN. Badan sertifikasi asing diakreditasi badan akreditasi negaranya sendiri, misalnya UKAS (Inggris) atau JAS-ANZ (Australia dan Selandia Baru).
- **Pengakuan antar badan akreditasi** kini dikelola Global Accreditation Cooperation Incorporated (Global ACI) lewat Global ACI MRA, menggantikan peran IAF dan IAF MLA [S3][S6]. Sertifikat dan dokumen yang menyebut IAF MLA masih akan kamu temui; sejarah peralihannya ada di bagian 6.

KAN termasuk dalam pengaturan pengakuan itu untuk sertifikasi ISMS [S8], sehingga sertifikat ISMS dari badan sertifikasi terakreditasi KAN diakui setara oleh badan akreditasi lain di pengaturan tersebut. Cakupan KAN saat ini perlu dicek di daftar penanda tangan Global ACI; rincian resolusi asalnya ada di bagian 6.

Bila satu lapis hilang, nilainya runtuh. Sertifikat dari badan yang tidak terakreditasi tidak punya pengawas di atasnya, sehingga tidak ada yang memastikan auditnya memenuhi 17021-1 dan 27006-1.

### 1.2 Lapis tambahan di Indonesia: pengakuan BSSN

Penawaran CB di pertanyaan kedua dan sertifikat pemasok di pertanyaan pertama sama-sama perlu dilihat dari sisi regulasi. Untuk penyelenggara sistem elektronik di Indonesia ada lapis regulasi di atas akreditasi. Peraturan BSSN No. 8 Tahun 2020 mewajibkan penerapan SNI ISO/IEC 27001 untuk sistem elektronik kategori strategis, dan menjadikannya salah satu pilihan untuk kategori tinggi dan rendah (Pasal 9) [S10].

Tabel berikut memuat ketentuan sertifikasi di peraturan itu yang relevan untuk Day ini. Cari dua baris yang paling sering terlewat: siapa yang menyertifikasi dan audit khusus setelah insiden.

| Ketentuan | Isi | Pasal |
|---|---|---|
| Siapa yang menyertifikasi | Lembaga sertifikasi yang diakui BSSN | 26 |
| Masa berlaku sertifikat SMPI | Paling lama 3 tahun sejak terbit; diperbarui paling lambat 3 bulan sebelum berakhir | 28 |
| Laporan lembaga sertifikasi | Minimal dua kali setahun ke Kepala BSSN | 31 |
| Audit pengawasan | Minimal sekali setahun, plus audit khusus bila terjadi insiden pada sistem yang tersertifikasi | 33 |
| Bila hasil pengawasan tidak memenuhi | Diberi waktu paling lama 90 hari kalender; bila tetap tidak terpenuhi, sertifikat dapat dicabut | 34 |
| Peralihan | Lembaga yang sebelumnya diakui menteri bidang komunikasi dan informatika tetap diakui sepanjang tidak bertentangan | 43 ayat (4) |

Untuk sistem elektronik kategori strategis, pertanyaan "terakreditasi KAN?" belum cukup; tanyakan juga apakah lembaga sertifikasinya diakui BSSN. Audit khusus setelah insiden (Pasal 33) perlu masuk rencana IR karena bisa datang di luar jadwal surveillance. Cara kategori sistem ditentukan dibahas di Day 18.

### 1.3 Terakreditasi dan tidak terakreditasi

Sertifikat PT Contoh Layanan mencantumkan nama standar yang benar. Itu belum memberi tahu apakah penerbitnya diawasi. Tabel berikut membandingkan kedua jenis sertifikat; perhatikan baris pengawas dan pengakuan lintas negara, karena dua baris itulah yang hilang pada sertifikat tidak terakreditasi.

| Aspek | Terakreditasi | Tidak terakreditasi |
|---|---|---|
| Pengawas badan sertifikasi | Badan akreditasi, dengan asesmen berkala | Tidak ada |
| Aturan yang mengikat auditnya | 17021-1, 27006-1, dokumen wajib IAF/Global ACI [S1][S2] | Aturan badan itu sendiri |
| Kompetensi auditor | Diatur dan diperiksa | Tidak dijamin |
| Pengakuan lintas negara | Lewat Global ACI MRA (dahulu IAF MLA) [S6] | Tidak ada |
| Harga | Lebih tinggi | Sering jauh lebih murah |

Cara mengenali di lapangan: sertifikat terakreditasi mencantumkan tanda atau nomor badan akreditasi, bukan hanya logo badan sertifikasi. Selama masa peralihan, tanda IAF MLA masih bisa muncul pada sertifikat; tanda Global ACI MRA baru akan dipakai setelah diputuskan dan tersedia di tiap negara [S6]. Jadi tanda IAF MLA pada sertifikat baru belum menjadi alasan untuk menolaknya.

Sertifikat tidak terakreditasi tidak otomatis berarti auditnya buruk, tetapi tidak ada pihak ketiga yang menjaminnya, persis seperti self-signed certificate yang isinya bisa saja benar. Catat perbedaan itu apa adanya di penilaian pemasok.

### 1.4 Apa yang diatur tentang badan sertifikasi

Penawaran B di pertanyaan kedua jauh lebih murah. Untuk menilai apakah selisih itu wajar, kamu perlu tahu apa saja yang diatur standar tentang cara CB bekerja, terutama soal waktu audit.

- **Imparsialitas.** Salah satu pilar 17021-1 [S1]. Badan sertifikasi tidak boleh menyertifikasi sistem yang ia bantu bangun lewat konsultasi.
- **Kompetensi auditor.** Ada persyaratan pengetahuan dan pengalaman auditor untuk lingkup yang diaudit, ditambah persyaratan khusus ISMS di 27006-1 [S2].
- **Waktu audit.** Untuk ISMS, dasar perhitungan hari audit ada di Annex C 27006-1:2024, berangkat dari jumlah orang yang bekerja di dalam lingkup lalu disesuaikan menurut kompleksitas [S11]. Orang yang bekerja untuk organisasi dihitung walaupun bukan karyawannya (misalnya freelancer di dalam lingkup). Waktu audit multi-site dihitung dari total orang lalu dibagi ke situs menurut relevansi dan risiko, dan ada aturan untuk perluasan lingkup [S11]. Angka di tabelnya perlu dicek di teks 27006-1. IAF MD 5 yang sering disebut di diskusi audit time berlaku untuk QMS, EMS, dan OH&SMS, bukan ISMS.
- **Isi sertifikat dan informasi publik.** 17021-1 menetapkan isi minimum dokumen sertifikasi dan mewajibkan badan sertifikasi memberikan, bila diminta, status sertifikasi seorang klien beserta nama, standar, lingkup, dan lokasinya [S9]. Ketentuan ini yang membuat verifikasi langsung ke penerbit selalu mungkin (bagian 1.5).
- **Proses sertifikasi.** Keputusan sertifikasi dibuat pihak yang terpisah dari tim audit (Day 13).

Selain standar ISO, badan sertifikasi terakreditasi terikat dokumen wajib IAF (IAF Mandatory Documents), yang tetap dipakai selama masa peralihan ke Global ACI [S6]. Tabel berikut memuat dua dokumen yang paling sering relevan untuk ISMS; cari yang sesuai bila organisasimu punya banyak situs atau diaudit jarak jauh.

| Dokumen | Isi |
|---|---|
| IAF MD 1 | Audit dan sertifikasi organisasi multi-site, termasuk sampling situs |
| IAF MD 4 | Pemakaian ICT dalam audit, termasuk audit jarak jauh |

Dokumen IAF kini disimpan di situs Global ACI. Dokumen transisi ke 27006-1:2024 (IAF MD 29:2024) dan status edisi MD 1 serta MD 4 dicatat di bagian 6.

### 1.5 Membaca dan memverifikasi sertifikat

Kembali ke sertifikat PT Contoh Layanan. Membaca sertifikat seperti membaca field sertifikat X.509: yang menentukan bukan logonya, tetapi subject, masa berlaku, penerbit, dan untuk domain apa sertifikat itu berlaku. Menurut 17021-1, dokumen sertifikasi minimal memuat [S9]:

```
a  nama dan lokasi klien (untuk multi-site: kantor pusat dan situs di dalam lingkup)
b  tanggal efektif pemberian, perluasan/pengurangan, atau pembaruan sertifikasi
c  tanggal kedaluwarsa atau jatuh tempo resertifikasi
d  kode identifikasi unik
e  standar yang dipakai beserta edisinya (mis. ISO/IEC 27001:2022)
f  lingkup sertifikasi menurut jenis kegiatan, produk, dan layanan di tiap situs
g  nama, alamat, dan tanda badan sertifikasi; tanda lain (mis. tanda akreditasi)
   boleh dipakai bila tidak menyesatkan
h  informasi lain yang diminta standar khusus skemanya
```

Untuk ISMS, sertifikat di praktiknya juga menyebut versi dan tanggal Statement of Applicability yang menjadi dasar sertifikasi. Rujukan versi SoA ini berguna: bila SoA yang ditunjukkan pemasok berbeda versinya, kamu tahu ada perubahan sejak audit. Bunyi persyaratannya di 27006-1 perlu dicek di teks standar.

Langkah verifikasi yang dipakai di penilaian pemasok (Day 12):

```
1. Baca LINGKUP (butir f), bukan hanya nama standarnya.
   Lingkup bisa jauh lebih sempit dari yang disangka: satu kantor atau satu layanan.
2. Cocokkan SITUS (butir a) dengan lokasi layanan yang kamu pakai.
3. Periksa TANGGAL (butir b dan c) dan tanyakan status surveillance terakhir.
4. Periksa EDISI standar (butir e). Sertifikat ISO/IEC 27001:2013 sudah tidak sah
   sejak masa transisi berakhir 31 Oktober 2025 (Day 01).
5. Periksa TANDA atau NOMOR AKREDITASI (butir g), bukan hanya logo badan sertifikasi.
6. VERIFIKASI ke penerbit: IAF CertSearch, basis data badan sertifikasi, atau minta
   konfirmasi status langsung ke badan sertifikasi. Jangan ke dokumen dari pemasok.
7. Minta SoA versi yang dirujuk sertifikat, atau setidaknya pernyataan tertulis
   untuk kontrol yang relevan bagimu.
8. Tanyakan TEMUAN terbuka dari audit terakhir bila hubungannya memungkinkan.
```

Langkah keenam yang paling sering dilewat dan paling penting. Dokumen bisa dipalsukan; basis data penerbitnya tidak. IAF CertSearch adalah basis data global sertifikat terakreditasi yang diisi badan sertifikasi peserta [S5]. Tidak semua badan sertifikasi mengunggah datanya, jadi bila sertifikat tidak ditemukan di sana, minta konfirmasi status ke badan sertifikasi penerbitnya. Badan sertifikasi wajib memberikan informasi itu bila diminta [S9]. Global ACI juga menyarankan jalur yang sama: penerbit sertifikat, badan akreditasinya, lalu daftar penanda tangan MRA [S6].

Langkah ketujuh sering ditolak dengan alasan kerahasiaan, dan penolakan itu wajar. Penggantinya adalah pernyataan tertulis bahwa kontrol tertentu yang relevan bagimu termasuk dalam lingkup dan diterapkan.

Hasil langkah-langkah ini untuk PT Contoh Layanan ada di bagian 2.1.

### 1.6 Memilih badan sertifikasi

Pertanyaan kedua menuntut keputusan pengadaan yang bisa dipertanggungjawabkan di depan direksi, bukan hanya perbandingan harga. Tabel berikut memuat pertimbangan selain harga beserta alasannya; gunakan kolom kanan untuk menjelaskan ke procurement kenapa tiap pertimbangan perlu ditanyakan.

| Pertimbangan | Kenapa penting |
|---|---|
| Akreditasi untuk ISMS, dan pengakuan BSSN bila sistemmu kategori strategis | Akreditasi diberikan per skema; tidak otomatis mencakup ISMS |
| Pengalaman auditor di sektormu | Auditor yang tidak memahami sektormu menghabiskan waktu pada hal yang salah |
| Jumlah hari audit dan dasar perhitungannya | Harus bisa dijelaskan dari Annex C 27006-1 [S2][S11] |
| Pengakuan di pasar pelangganmu | Beberapa pelanggan mensyaratkan badan akreditasi tertentu |
| Kontinuitas tim audit | Auditor yang sama lintas siklus menghemat waktu penjelasan |
| Kejelasan aturan tenggat temuan | Berbeda antar badan; tanyakan di muka (Day 13) |

Sepakati di awal siapa yang menanggung biaya bila audit perlu diulang karena ketidaksesuaian mayor. Badan sertifikasi tidak boleh menjadi konsultan yang membangun ISMS-mu atau menjalankan audit internalmu (Day 13); penawaran yang menjanjikan keduanya adalah tanda bahaya.

Daftar pertanyaan siap kirim ada di bagian 2.2, dan contoh perbandingan dua penawaran di bagian 2.4.

### 1.7 Apa yang dijamin sertifikat, dan apa yang tidak

Pertanyaan ketiga (brosur "terbukti aman") adalah salah paham yang paling umum tentang sertifikat, baik di internal maupun di pihak pelanggan.

**Yang dijamin.** Pada tanggal audit, untuk lingkup dan situs yang tertulis, sebuah ISMS ada dan memenuhi persyaratan standar edisi yang disebut, menurut penilaian auditor berdasarkan sampel, dan dipertahankan lewat surveillance minimal sekali setahun.

**Yang tidak dijamin.** Bahwa organisasi itu aman. Bahwa tidak akan terjadi insiden. Bahwa seluruh sistemnya tercakup. Bahwa kontrol tertentu diterapkan, kecuali kamu memeriksa SoA-nya. Dan bahwa keadaan hari ini sama dengan keadaan saat audit.

Tiga kata kuncinya adalah tanggal, lingkup, dan sampel. Cara menyampaikannya tanpa terdengar meremehkan: sertifikat membuktikan ada sistem yang dijalankan dan diperiksa pihak ketiga secara berkala, dan itu berbeda jauh dari tidak ada apa-apa, tetapi ia tidak menggantikan penilaian risikomu sendiri terhadap pemasok itu. Kalimat yang sama berlaku untuk sertifikat PT AN sendiri saat ditulis di brosur; versi satu halamannya untuk manajemen ada di bagian 2.3.

## 2. Contoh dokumen / artefak (organisasi fiktif)

> Seluruh isi di bawah adalah contoh untuk organisasi fiktif PT AN. Nama badan, nomor, dan tanggal adalah fiktif.

### 2.1 Lembar verifikasi sertifikat pemasok

Lembar ini menjawab pertanyaan pertama Direktur Operasional dengan menjalankan delapan langkah di bagian 1.5 terhadap sertifikat PT Contoh Layanan.

```
VERIFIKASI SERTIFIKAT PEMASOK                 Nomor: VSP-2027-009
Pemasok   : PT Contoh Layanan          Dinilai oleh : <nama>, tanggal 2027-03-04

DOKUMEN YANG DITERIMA
  Sertifikat ISO/IEC 27001:2022, nomor <fiktif>, terbit 2025-08-12, berlaku sampai 2028-08-11
  Dasar: Statement of Applicability versi 3.1 tanggal 2025-06-30

PEMERIKSAAN (huruf merujuk isi minimum sertifikat, bagian 1.5)
  (f) Lingkup                    : tertulis "Penyediaan layanan hosting aplikasi"
  (a) Situs                      : tertulis pusat data Jakarta. Layanan yang kami pakai
                                   berjalan di Surabaya. DI LUAR LINGKUP.
  (b)(c) Tanggal berlaku         : masih berlaku
  Surveillance terakhir          : dinyatakan 2026-09, bukti belum diberikan
  (e) Edisi standar              : 2022, sesuai
  (g) Tanda/nomor akreditasi     : ada, KAN, nomor <fiktif>
  Verifikasi ke penerbit         : email konfirmasi badan sertifikasi, status aktif
  SoA v3.1                       : diminta, ditolak dengan alasan kerahasiaan
  Pernyataan tertulis pengganti  : diminta untuk kontrol 5.23, 8.15, 8.16
  Pengakuan BSSN                 : ditanyakan (sistem kami strategis), belum dijawab

KESIMPULAN
  Sertifikat sah dan terverifikasi, TETAPI situs yang melayani kami tidak termasuk lingkup.
  Nilai jaminan terhadap risiko kami: RENDAH.

TINDAK LANJUT
  Minta konfirmasi tertulis apakah pusat data Surabaya mengikuti ISMS yang sama dan kapan
  akan masuk lingkup. Bila tidak, perlakukan sebagai pemasok tanpa sertifikasi untuk
  layanan ini (Day 12).
```

Baris situs itu adalah temuan yang paling sering muncul dan paling sering terlewat: sertifikat sah, tetapi tidak menjamin apa pun untuk layanan yang benar-benar kamu pakai. Dalam bahasa TLS, sertifikatnya valid, tetapi untuk domain lain.

### 2.2 Daftar pertanyaan saat memilih badan sertifikasi

Daftar ini dikirim procurement PT AN ke kedua calon CB di pertanyaan kedua, supaya jawabannya bisa dibandingkan baris per baris.

```
PERTANYAAN KE CALON BADAN SERTIFIKASI

AKREDITASI DAN PENGAKUAN
  1. Badan akreditasi mana yang mengakreditasi Anda untuk skema ISMS (ISO/IEC 27006-1)?
  2. Apakah Anda sudah bertransisi ke ISO/IEC 27006-1:2024? Sejak kapan?
  3. Apakah Anda diakui BSSN sebagai lembaga sertifikasi SMPI?
  4. Bagaimana kami memverifikasi status akreditasi Anda secara mandiri?

AUDITOR
  5. Berapa pengalaman auditor yang akan ditugaskan di sektor kami?
  6. Apakah tim audit akan sama lintas siklus?
  7. Bagaimana Anda memastikan auditor tidak pernah terlibat konsultasi pada kami?

WAKTU DAN BIAYA
  8. Berapa hari audit untuk tahap 1, tahap 2, surveillance, dan resertifikasi?
  9. Berapa jumlah orang di dalam lingkup yang Anda pakai sebagai dasar, dan faktor
     penyesuaian apa yang diterapkan?
 10. Siapa menanggung biaya bila audit perlu diulang karena ketidaksesuaian mayor?

PROSES
 11. Berapa tenggat penyelesaian untuk ketidaksesuaian mayor dan minor?
 12. Bagaimana keputusan sertifikasi dibuat, dan apakah terpisah dari tim audit?
 13. Apakah sertifikat mencantumkan versi SoA dan seluruh situs di dalam lingkup?
 14. Bagaimana prosedur banding bila kami tidak setuju dengan temuan?

JAWABAN DICATAT DAN DIBANDINGKAN ANTAR PENAWARAN, bukan hanya harganya.
```

Pertanyaan kedelapan dan kesembilan yang paling membedakan penawaran. Penawaran dengan jumlah hari yang jauh lebih kecil biasanya memakai jumlah orang atau lingkup yang berbeda, bukan efisiensi.

### 2.3 Menjelaskan arti sertifikat ke manajemen

Halaman ini menjawab pertanyaan ketiga: bahan untuk direksi dan tim marketing sebelum klaim sertifikasi ditulis di brosur.

```
APA YANG KITA PEROLEH DARI SERTIFIKASI

YANG DIBUKTIKAN
  Pada tanggal audit, untuk lingkup "<tulis lingkup persisnya>" di situs "<daftar situs>",
  ada ISMS yang dijalankan dan memenuhi ISO/IEC 27001:2022, menurut penilaian auditor
  pihak ketiga berdasarkan sampel, dan diperiksa ulang minimal sekali setahun.

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
  tindakan korektif, dan kemungkinan audit khusus setelah insiden (sistem kategori strategis)
```

Blok terakhir sering baru dibicarakan di tahun kedua, ketika sertifikasi mulai terasa sebagai beban.

### 2.4 Membandingkan dua penawaran

Tabel ini merangkum jawaban kedua CB atas daftar di bagian 2.2. Baca kolom Catatan untuk melihat dari mana selisih harga di pertanyaan kedua berasal.

| Aspek | Badan A | Badan B | Catatan |
|---|---|---|---|
| Badan akreditasi untuk ISMS | KAN, terverifikasi | tercantum, tidak ditemukan di direktori | B perlu diklarifikasi |
| Sudah transisi ke 27006-1:2024 | ya | tidak dijawab | Transisi seharusnya selesai 31 Maret 2026 |
| Pengakuan BSSN | ya | tidak | Relevan bila sistem kategori strategis |
| Dasar orang dalam lingkup | 120 orang termasuk 15 kontraktor | 80 orang, kontraktor tidak dihitung | Selisih dasar menjelaskan selisih hari |
| Hari audit tahap 1 dan 2 | 3 dan 7 | 1 dan 3 | Tanyakan dasar perhitungan B |
| Tenggat ketidaksesuaian mayor | 60 hari | 90 hari | Keduanya wajar; pastikan tertulis |
| Biaya audit ulang | ditanggung kami | tidak dijawab | Klarifikasi sebelum tanda tangan |
| Harga total tiga tahun | lebih tinggi | lebih rendah | Selisih sebagian dijelaskan oleh hari audit |

Baris "dasar orang dalam lingkup" sering menjadi penjelasan selisih hari audit. Badan B yang tidak menghitung kontraktor tidak sejalan dengan cara 27006-1:2024 menghitung orang di dalam lingkup [S11]. Simpan tabel ini sebagai lampiran keputusan pengadaan.

## 3. Lab praktik

**Prasyarat:** hasil Day 12 (penilaian pemasok) dan Day 13 (audit dan bukti). Seluruh lab bersifat membaca, memverifikasi, dan menulis.

1. Di direktori lembaga terakreditasi KAN, cari dua badan sertifikasi berakreditasi skema ISMS; catat nomor akreditasi, ruang lingkup, dan masa berlakunya.
2. Di daftar penanda tangan Global ACI, pastikan KAN tercantum dan catat apakah sub-scope ISMS disebut.
3. Ambil satu sertifikat ISO 27001 yang dipublikasikan terbuka, isi delapan butir isi minimum (bagian 1.5), dan tandai butir yang tidak ada.
4. Cari sertifikat itu di IAF CertSearch. Bila tidak ada, tulis draf email permintaan konfirmasi status ke badan sertifikasinya dengan dasar kewajiban di 17021-1.
5. Isi lembar verifikasi bagian 2.1 untuk sertifikat itu dan tulis kesimpulan nilai jaminannya terhadap satu layanan fiktif PT AN.
6. Untuk dua skenario lingkup PT AN, (a) 120 orang di satu situs dan (b) 120 orang di tiga situs dengan 20 kontraktor, tulis faktor hari audit yang akan kamu tanyakan berdasarkan cara 27006-1:2024 menghitung orang dan situs (bagian 1.4).
7. Susun daftar pertanyaan bagian 2.2 siap kirim, lalu tandai lima yang paling menentukan bagi PT AN beserta alasannya.
8. Isi tabel perbandingan bagian 2.4 dari informasi publik dua badan sertifikasi; tandai sel yang tidak bisa diisi.
9. Tulis satu halaman arti sertifikat (bagian 2.3), bacakan ke rekan non-teknis, dan catat bagian yang disalahpahami.
10. Tulis paragraf laporan pemasok tentang temuan situs di luar lingkup dengan nada faktual.

**Hasil yang sebaiknya tersimpan:**
- Data akreditasi dua badan sertifikasi dari direktori KAN.
- Catatan status KAN di daftar penanda tangan Global ACI.
- Tabel isi minimum satu sertifikat publik dengan butir yang hilang.
- Hasil pencarian di IAF CertSearch atau draf email konfirmasi status.
- Lembar verifikasi terisi beserta kesimpulan nilai jaminan.
- Daftar faktor hari audit untuk dua skenario lingkup.
- Daftar pertanyaan siap kirim dengan lima pertanyaan yang ditandai.
- Tabel perbandingan dua badan sertifikasi.
- Satu halaman penjelasan arti sertifikat beserta catatan bagian yang disalahpahami.
- Paragraf laporan pemasok tentang temuan lingkup.

## 4. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa |
|---|---|---|
| Sertifikat terlihat sah tetapi tidak ada di IAF CertSearch | Badan sertifikasi tidak mengunggah, atau tidak terakreditasi | Minta konfirmasi status ke penerbit; cek badan akreditasinya [S5][S9] |
| Hanya logo badan sertifikasi, tanpa tanda akreditasi | Kemungkinan tidak terakreditasi | Tanyakan langsung; catat jawabannya apa adanya |
| Sertifikat bertanda IAF MLA terbit 2026 | Masa peralihan ke Global ACI | Wajar selama tanda Global ACI belum tersedia di negara itu [S6] |
| Sertifikat masih menyebut ISO/IEC 27001:2013 | Transisi tidak dilakukan | Sertifikat edisi 2013 tidak sah lagi sejak 31 Oktober 2025; edisi yang berlaku adalah ISO/IEC 27001:2022 [S4] |
| Pemasok menolak memberi SoA | Alasan kerahasiaan yang wajar | Minta pernyataan tertulis untuk kontrol tertentu saja |
| Situs layanan tidak tercantum di sertifikat | Lingkup sempit; sangat umum | Perlakukan sebagai tanpa sertifikasi untuk layanan itu (Day 12) |
| Penawaran hari audit jauh lebih sedikit | Dasar jumlah orang atau lingkup berbeda | Tanyakan dasar perhitungan Annex C 27006-1 [S11] |
| Manajemen menganggap sertifikat berarti aman | Batas makna tidak dijelaskan | Pakai satu halaman bagian 2.3 |

## 5. Kesalahan umum dan jebakan

- Membaca nama standar di sertifikat tanpa membaca lingkup dan daftar situsnya.
- Menerima dokumen sertifikat dari pemasok tanpa memverifikasi ke penerbitnya.
- Menganggap sertifikat yang tidak ada di IAF CertSearch pasti palsu.
- Mengabaikan pengakuan BSSN untuk sistem elektronik kategori strategis.
- Memakai badan sertifikasi yang juga menjadi konsultan atau auditor internalmu.
- Memilih badan sertifikasi hanya berdasarkan harga, tanpa menanyakan dasar hari audit.
- Menyampaikan sertifikat kepada pelanggan sebagai jaminan keamanan.

## 6. Catatan terkini

Bagian ini menampung perubahan kelembagaan, edisi standar, dan tenggat transisi di balik rantai sertifikasi. Detail ini dibutuhkan saat menulis kriteria pengadaan atau mengutip dokumen resmi, tetapi tidak perlu dihafal untuk memverifikasi sertifikat.

**Dari IAF ke Global ACI:**

- Pengakuan antar badan akreditasi selama ini dikelola International Accreditation Forum (IAF) lewat IAF MLA. IAF berhenti beroperasi pada 1 Januari 2026 dan perannya, bersama peran ILAC, diambil alih Global Accreditation Cooperation Incorporated (Global ACI) [S3][S6].
- Badan akreditasi yang per 31 Desember 2025 sudah menjadi penanda tangan IAF MLA dan bergabung ke Global ACI menjadi penanda tangan Global ACI MRA untuk cakupan yang sama [S6].
- Keputusan tentang pemakaian tanda Global ACI MRA dijadwalkan pada rapat Oktober 2026 [S3][S6]. Pantau perubahan ini sebelum menulis kriteria pengadaan yang menyebut "IAF MLA".
- Dokumen wajib IAF tetap dipakai sampai Global ACI mengadopsi penggantinya [S6]. Edisi terbaru MD 1 dan MD 4 perlu dicek di situs Global ACI sebelum dikutip.
- KAN mendapat perluasan cakupan IAF MLA untuk sertifikasi ISMS (ISO/IEC 27006 di level 4, ISO/IEC 27001 di level 5) lewat resolusi IAF 2019-23 [S8]. Cakupan KAN saat ini perlu dicek di daftar penanda tangan Global ACI.

**Edisi standar untuk badan sertifikasi:**

- ISO/IEC 27006-1:2024 (edisi 1, Maret 2024) menggantikan ISO/IEC 27006:2015 beserta Amd 1:2020 [S2].
- Transisi ke ISO/IEC 27006-1:2024 menurut IAF MD 29:2024: badan akreditasi dan badan sertifikasi harus selesai paling lambat 31 Maret 2026, sehingga semua audit ISMS terakreditasi kini memakai edisi 2024 [S7].
- Di edisi 2015, dasar perhitungan hari audit ada di Annex B; di 27006-1:2024 pindah ke Annex C [S11]. Edisi 2024 menegaskan bahwa orang yang bekerja untuk organisasi dihitung walaupun bukan karyawannya, menghitung waktu audit multi-site dari total orang, dan menambah aturan untuk perluasan lingkup [S11]. Ringkasan lama yang memakai Annex B dan tidak menghitung kontraktor merujuk edisi 2015.
- ISO/IEC 17021-1:2015 terakhir dikonfirmasi pada 2020; katalog ISO mencatat tinjauan sistematis 2025 sampai 2026 tanpa hasil yang diumumkan [S1]. Periksa statusnya sebelum mengutip rinciannya di dokumen resmi.

## 7. Cheat sheet

```
RANTAI KEPERCAYAAN
  organisasi -> badan sertifikasi -> badan akreditasi (KAN) -> Global ACI MRA (dahulu IAF MLA)
  satu lapis hilang = nilainya runtuh
  aturan badan sertifikasi : ISO/IEC 17021-1:2015 (umum)
  tambahan khusus ISMS     : ISO/IEC 27006-1:2024 (ganti 27006:2015 + Amd 1:2020;
                             transisi selesai 31 Mar 2026, IAF MD 29)
  IAF berhenti 1 Jan 2026 -> Global ACI; dokumen IAF tetap dipakai sampai ada pengganti
  KAN: cakupan IAF MLA ISMS (27006 level 4, 27001 level 5) sejak resolusi IAF 2019-23

INDONESIA (Peraturan BSSN 8/2020, sistem elektronik kategori strategis wajib SNI ISO/IEC 27001)
  lembaga sertifikasi DIAKUI BSSN (Ps 26) | sertifikat maks 3 th, perbarui 3 bln sebelum habis (Ps 28)
  audit pengawasan min 1x/th + AUDIT KHUSUS bila insiden (Ps 33) | 90 hari perbaikan (Ps 34)

ISI MINIMUM SERTIFIKAT (17021-1)
  a nama + lokasi/situs | b tgl efektif | c tgl kedaluwarsa | d kode unik
  e standar + EDISI | f LINGKUP per situs | g badan sertifikasi + tanda akreditasi | h lain
  ISMS: versi SoA biasanya disebut

VERIFIKASI SERTIFIKAT PEMASOK (urut)
  1 LINGKUP  2 SITUS  3 TANGGAL + surveillance  4 EDISI (2013 tidak sah sejak 31 Okt 2025)
  5 TANDA AKREDITASI  6 VERIFIKASI KE PENERBIT (CertSearch / tanya CB, CB wajib menjawab)
  7 SoA atau pernyataan tertulis per kontrol  8 temuan terbuka

HARI AUDIT ISMS: Annex C 27006-1:2024 (BUKAN IAF MD 5)
  hitung semua orang di lingkup termasuk kontraktor | multi-site dari total orang
  selisih hari antar penawaran = tanyakan dasar orang dan lingkup

MEMILIH BADAN SERTIFIKASI
  akreditasi ISMS + pengakuan BSSN bila perlu | auditor paham sektor | dasar hari audit
  sepakati di muka biaya audit ulang | TIDAK BOLEH merangkap konsultan/auditor internal

ARTI SERTIFIKAT  3 kata kunci: TANGGAL, LINGKUP, SAMPEL
  DIJAMIN      : ISMS memenuhi standar pada tanggal audit, untuk lingkup dan situs tertulis
  TIDAK DIJAMIN: aman | tanpa insiden | semua sistem tercakup | kontrol tertentu (cek SoA)
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** Sertifikat ISO 27001 yang dikirim seorang calon pemasok tidak ditemukan di IAF CertSearch. Apakah sertifikat itu pasti palsu?

<details><summary>Jawaban</summary>

Tidak pasti. IAF CertSearch diisi oleh badan sertifikasi peserta, dan tidak semua badan sertifikasi mengunggah datanya. Langkah yang benar adalah meminta konfirmasi status langsung ke badan sertifikasi penerbitnya; 17021-1 mewajibkan CB memberikan status sertifikasi klien beserta nama, standar, lingkup, dan lokasinya bila diminta. Periksa juga apakah sertifikat mencantumkan tanda atau nomor badan akreditasi, karena ketiadaan di CertSearch bisa juga berarti CB-nya tidak terakreditasi. Lihat bagian 1.3 dan 1.5.

</details>

**2. Skenario keputusan.** Sertifikat PT Contoh Layanan berlaku, edisi 2022, bertanda akreditasi KAN, dan statusnya dikonfirmasi aktif oleh CB. Lingkupnya menyebut pusat data Jakarta, sedangkan layanan yang dipakai PT AN berjalan di Surabaya. Apa kesimpulanmu?

- A. Terima sebagai bukti, karena sertifikatnya sah dan sudah diverifikasi ke penerbit.
- B. Catat sertifikat sah tetapi nilai jaminannya rendah untuk layanan ini, minta konfirmasi tertulis apakah Surabaya mengikuti ISMS yang sama dan kapan masuk lingkup, dan bila tidak, perlakukan sebagai pemasok tanpa sertifikasi untuk layanan itu.
- C. Tolak pemasok, karena sertifikat yang tidak menyebut Surabaya pasti dipalsukan.

<details><summary>Jawaban</summary>

B. Sertifikat hanya menjamin lingkup dan situs yang tertulis. A keliru karena sah dan relevan adalah dua pertanyaan berbeda: sertifikatnya valid, tetapi untuk "domain" lain. C keliru karena tidak ada indikasi pemalsuan; lingkup yang sempit justru sangat umum, dan keputusan menolak pemasok bergantung pada penilaian risiko, bukan pada sertifikat saja. Lihat bagian 1.5 dan 2.1.

</details>

**3. Pertanyaan jebakan.** Sertifikat yang terbit Mei 2026 masih bertanda IAF MLA, padahal IAF berhenti beroperasi 1 Januari 2026. Apakah sertifikat itu otomatis patut dicurigai?

<details><summary>Jawaban</summary>

Tidak. Selama masa peralihan, tanda IAF MLA masih bisa muncul pada sertifikat, karena tanda Global ACI MRA baru dipakai setelah diputuskan dan tersedia di tiap negara. Badan akreditasi yang menjadi penanda tangan IAF MLA per 31 Desember 2025 dan bergabung ke Global ACI menjadi penanda tangan Global ACI MRA untuk cakupan yang sama. Yang tetap perlu diperiksa adalah isi sertifikatnya dan status ke penerbit. Lihat bagian 1.3 dan 6.

</details>

**4. Skenario keputusan.** Dua penawaran CB untuk PT AN: Badan A memakai dasar 120 orang termasuk 15 kontraktor dan mengusulkan 3 dan 7 hari untuk tahap 1 dan 2. Badan B memakai 80 orang tanpa kontraktor dan mengusulkan 1 dan 3 hari, dengan harga jauh lebih rendah. Apa langkahmu?

- A. Pilih Badan B, karena hari audit yang lebih sedikit menunjukkan auditor yang lebih efisien.
- B. Tanyakan dasar perhitungan Badan B; 27006-1:2024 menghitung orang yang bekerja untuk organisasi di dalam lingkup walaupun bukan karyawan, jadi dasar 80 orang tanpa kontraktor tidak sejalan dengan standar. Bandingkan juga akreditasi, pengakuan BSSN, dan biaya audit ulang sebelum memutuskan.
- C. Pilih Badan A tanpa bertanya, karena harga yang lebih mahal selalu berarti audit yang lebih baik.

<details><summary>Jawaban</summary>

B. Selisih hari audit antar penawaran biasanya berasal dari dasar jumlah orang atau lingkup yang berbeda, bukan efisiensi. Dasar perhitungannya harus bisa dijelaskan dari Annex C 27006-1. A keliru karena menganggap selisih hari sebagai efisiensi tanpa memeriksa dasarnya. C keliru karena harga bukan ukuran mutu; keputusan harus bisa dipertanggungjawabkan lewat pertimbangan yang tercatat, seperti akreditasi untuk ISMS dan aturan tenggat temuan. Lihat bagian 1.4, 1.6, dan 2.4.

</details>

**5. Jelaskan ulang.** Jelaskan kepada direksi PT AN dalam tiga kalimat kenapa brosur tidak sebaiknya menulis "Tersertifikasi ISO 27001, layanan kami terbukti aman", tanpa membuat sertifikasi terdengar tidak berharga.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Sertifikat membuktikan bahwa pada tanggal audit, untuk layanan dan lokasi yang tertulis di sertifikat, pihak ketiga memeriksa sampel dan menemukan sistem pengelolaan keamanan kita memenuhi standar, lalu memeriksanya ulang setiap tahun. Sertifikat tidak membuktikan bahwa kita kebal serangan, bahwa tidak akan ada insiden, atau bahwa semua layanan kita tercakup. Klaim yang tepat adalah bahwa keamanan layanan dalam lingkup kita dikelola dengan sistem yang diaudit pihak ketiga secara berkala, dan itu jauh lebih bernilai daripada tidak punya sistem sama sekali."

Kesalahan yang sering muncul:
- Meremehkan sertifikat ("hanya kertas"), padahal ia membuktikan ada disiplin yang diperiksa pihak luar secara berkala.
- Lupa menyebut lingkup, sehingga pelanggan mengira semua layanan tercakup.
- Lupa bahwa penilaian auditor berbasis sampel dan berlaku pada tanggal audit.

</details>

**6. Pertanyaan jebakan.** Sistem elektronik sebuah organisasi termasuk kategori strategis menurut Peraturan BSSN No. 8 Tahun 2020. CB yang dipilih terakreditasi KAN untuk ISMS. Apakah itu sudah cukup dari sisi sertifikasi?

<details><summary>Jawaban</summary>

Belum. Untuk kategori strategis, sertifikasinya harus dilakukan lembaga sertifikasi yang diakui BSSN (Pasal 26), jadi akreditasi KAN saja belum menjawab pertanyaannya. Selain itu, audit pengawasan bisa ditambah audit khusus bila terjadi insiden pada sistem yang tersertifikasi (Pasal 33), sehingga kemungkinan audit di luar jadwal surveillance perlu masuk rencana IR dan anggaran. Lihat bagian 1.2.

</details>

**7. Interview question (English).** "A vendor sends you their ISO 27001 certificate as part of a security review. What do you check?"

<details><summary>Sample answer</summary>

"First I read the scope and the sites, because a valid certificate may only cover one data center or one service, and that might not be the one we use. Then I check the dates, ask about the last surveillance audit, and confirm the standard edition is 2022, since 2013 certificates are no longer valid after the transition ended in October 2025. I look for an accreditation mark or number, not just the certification body's logo. Most importantly, I verify the status with the issuer, through IAF CertSearch or directly with the certification body, which is required to confirm a client's status on request. Finally, I ask for the Statement of Applicability, or at least a written statement for the controls that matter to us. And I remember that a certificate tells me a management system was audited on a sample at a point in time; it doesn't replace our own vendor risk assessment."

What makes this answer strong: it follows a clear order, puts scope and issuer verification above the logo, and states the limits of what a certificate proves.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | ISO/IEC 17021-1:2015 Conformity assessment, requirements for bodies providing audit and certification of management systems, Part 1 (katalog) | https://committee.iso.org/standard/61651.html | primer (katalog ISO) | Juni 2015; diakses 2026-10-10 | Tinggi untuk edisi, status (dikonfirmasi 2020, tinjauan 2025-2026), dan ringkasan isi (kompetensi, konsistensi, imparsialitas) |
| S2 | ISO/IEC 27006-1:2024 Requirements for bodies providing audit and certification of information security management systems, Part 1: General (katalog) | https://committee.iso.org/standard/82908.html | primer (katalog ISO) | Maret 2024; diakses 2026-10-10 | Tinggi untuk edisi, tanggal, dan dokumen yang digantikan (27006:2015 dan Amd 1:2020) |
| S3 | International Accreditation Forum (situs arsip) | https://iaf.nu/ | primer (forum akreditasi) | diakses 2026-10-10 | Tinggi untuk pernyataan bahwa IAF berhenti beroperasi 1 Januari 2026 dan digantikan Global ACI |
| S4 | ISO committee: ISO/IEC 27001:2022 | https://committee.iso.org/standard/82875.html | primer (katalog ISO) | diakses 2026-10-10 | Tinggi untuk keberadaan standar |
| S5 | IAF CertSearch | https://www.iafcertsearch.org/ | primer (basis data sertifikat) | diakses 2026-10-10 | Sedang-tinggi; cakupan data bergantung pada badan sertifikasi yang mengunggah |
| S6 | Global Accreditation Cooperation Incorporated, FAQ | https://global-aci.org/en/faq/ | primer (organisasi akreditasi internasional) | diakses 2026-10-10 | Tinggi untuk tanggal operasi penuh, peralihan penanda tangan IAF MLA, keberlakuan dokumen IAF, tanda MRA, dan jalur verifikasi sertifikat |
| S7 | IAF publishes MD for transition to ISO/IEC 27006-1:2024 (IAF MD 29:2024) | https://iaf.nu/en/news/iaf-publishes-md-for-transition-to-iso-iec-27006-12024/ | primer (arsip IAF) | 21 Mei 2024; diakses 2026-10-10 | Tinggi untuk tenggat 31 Desember 2024, 31 Maret 2025, dan 31 Maret 2026 |
| S8 | IAF Resolution 2019-23, AB IAF MLA Scope Extensions | https://iaf.nu/?p=2080 | primer (arsip IAF) | 2019; diakses 2026-10-10 | Tinggi untuk perluasan cakupan KAN ke ISO/IEC 27006 (level 4) dan ISO/IEC 27001 (level 5) |
| S9 | IAS, ISO/IEC 17021-1:2015 Section 8: Information Requirements (materi pelatihan) | https://cdn-v2.iasonline.org/wp-content/uploads/2021/02/17021-1-2015-Section-8-1.pdf | sekunder (badan akreditasi, materi pelatihan) | 2016; diakses 2026-10-10 | Sedang-tinggi untuk isi 8.1.2 (informasi status bila diminta) dan 8.2.2 (isi minimum dokumen sertifikasi) |
| S10 | Peraturan BSSN Nomor 8 Tahun 2020 tentang Sistem Pengamanan dalam Penyelenggaraan Sistem Elektronik (Berita Negara 2020 No. 1375) | https://peraturan.go.id/files/bn1375-2020.pdf | primer (teks resmi) | diundangkan 23 November 2020; diakses 2026-10-10 | Tinggi untuk Pasal 9, 26, 28, 31, 33, 34, 43. Status berlaku dicatat di https://peraturan.bpk.go.id/Details/174285/peraturan-bssn-no-8-tahun-2020 |
| S11 | usd AG, New requirements of ISO/IEC 27006-1:2024 | https://www.usd.de/en/news-new-iso-iec-27006-requirements/ | sekunder (lembaga audit) | diakses 2026-10-10 | Sedang untuk perubahan cara menghitung orang, multi-site, audit jarak jauh, dan perluasan lingkup; nomor Annex C dari ringkasan transisi badan akreditasi |

**Catatan sumber:** isi minimum sertifikat diambil dari materi pelatihan IAS yang mengutip 17021-1:2015 [S9], bukan dari teks standar yang dibeli. Kewajiban mencantumkan versi SoA di sertifikat ISMS dan angka tabel hari audit di Annex C 27006-1:2024 perlu dicek di teks 27006-1. Penomoran Annex C (dahulu Annex B) berasal dari ringkasan transisi pihak ketiga. Edisi terbaru IAF MD 1 dan MD 4 serta cakupan KAN di daftar Global ACI MRA perlu dicek di situs Global ACI. BPK mencatat tanggal penetapan Peraturan BSSN 8/2020 sebagai 16 November 2020, sedangkan salinan Berita Negara mencantumkan 19 November 2020; tanggal pengundangan 23 November 2020 sama di keduanya. Seluruh nama, nomor, dan tanggal di bagian 2 adalah fiktif.
