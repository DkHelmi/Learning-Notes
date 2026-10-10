---
day: 17
title: 'Sistem sertifikasi dan akreditasi: siapa mengaudit auditor, dan apa arti sertifikat'
researched_on: 2026-10-10
versions_checked: 'ISO/IEC 17021-1:2015 edisi 1 (published, terakhir dikonfirmasi 2020, tinjauan sistematis 2025-2026 tanpa hasil yang diumumkan di katalog); ISO/IEC 27006-1:2024 edisi 1, Maret 2024, menggantikan ISO/IEC 27006:2015 dan Amd 1:2020, transisi selesai 31 Maret 2026 menurut IAF MD 29:2024; Global Accreditation Cooperation Incorporated (Global ACI) menggantikan IAF dan ILAC sejak 1 Januari 2026; IAF CertSearch; KAN (cakupan IAF MLA untuk ISO/IEC 27006 dan 27001 sejak resolusi IAF 2019-23); Peraturan BSSN No. 8 Tahun 2020'
---

# Day 17: Sistem sertifikasi dan akreditasi

Cakupan: rantai kepercayaan di balik sertifikat ISO 27001, cara membaca dan memverifikasi sertifikat, cara memilih badan sertifikasi, dan apa yang dijamin maupun tidak dijamin oleh sebuah sertifikat.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- menjelaskan rantai akreditasi dari badan sertifikasi sampai pengakuan internasional, termasuk perubahan dari IAF ke Global ACI.
- membedakan sertifikat terakreditasi dari sertifikat yang tidak terakreditasi.
- menyebutkan standar dan dokumen wajib yang mengatur badan sertifikasi ISMS dan apa yang diaturnya.
- membaca isi sertifikat (lingkup, situs, tanggal, edisi standar, versi SoA, tanda akreditasi) dan memverifikasinya ke sumber yang tepat.
- memilih badan sertifikasi dengan pertimbangan yang bisa dipertanggungjawabkan.
- menjelaskan batas makna sertifikat kepada pelanggan atau manajemen tanpa melebih-lebihkan.

## 2. Konteks singkat

Day 13 membahas siklus sertifikasi tiga tahun dari sisi organisasi yang diaudit. Day ini melihat satu lapis di atasnya: siapa yang mengawasi badan sertifikasi, dan kenapa hal itu menentukan nilai sertifikat yang kamu pegang maupun yang ditunjukkan pemasokmu.

Dua organisasi bisa sama-sama memegang sertifikat ISO 27001 dengan nilai yang sangat berbeda, karena lingkupnya berbeda, badan sertifikasinya berbeda, atau salah satunya tidak terakreditasi. Analyst yang menilai risiko pemasok (Day 12) perlu bisa membedakannya, dan praktisi yang menyiapkan organisasinya sendiri perlu tahu apa yang ia beli.

## 3. Konsep inti

### 3.1 Rantai kepercayaan

Sertifikat ISO 27001 bernilai karena ada rantai yang bisa ditelusuri ke atas:

```
organisasi yang disertifikasi
  diaudit oleh  ->  badan sertifikasi (certification body, CB)
  yang diakreditasi oleh  ->  badan akreditasi nasional (di Indonesia: KAN)
  yang saling mengakui lewat  ->  pengaturan pengakuan multilateral
                                  (IAF MLA sampai 2025, Global ACI MRA sejak 2026)
```

Tiap lapis punya aturannya sendiri:

- **Badan sertifikasi** tunduk pada ISO/IEC 17021-1:2015, persyaratan umum untuk lembaga yang mengaudit dan menyertifikasi sistem manajemen apa pun. Isinya prinsip dan persyaratan tentang kompetensi, konsistensi, dan imparsialitas [S1].
- **Untuk ISMS secara khusus**, ada persyaratan tambahan di ISO/IEC 27006-1:2024 (edisi 1, Maret 2024), yang melengkapi 17021-1 dan menggantikan ISO/IEC 27006:2015 beserta Amd 1:2020 [S2].
- **Badan akreditasi** menilai badan sertifikasi terhadap kedua standar itu. Di Indonesia perannya dijalankan KAN (Komite Akreditasi Nasional), yang sekretariatnya berada di BSN. Badan sertifikasi asing diakreditasi badan akreditasi negaranya sendiri, misalnya UKAS (Inggris) atau JAS-ANZ (Australia dan Selandia Baru).
- **Pengakuan antar badan akreditasi** selama ini dikelola International Accreditation Forum (IAF) lewat IAF MLA. IAF berhenti beroperasi pada 1 Januari 2026 dan perannya, bersama peran ILAC, diambil alih Global Accreditation Cooperation Incorporated (Global ACI) [S3][S6]. Badan akreditasi yang per 31 Desember 2025 sudah menjadi penanda tangan IAF MLA dan bergabung ke Global ACI menjadi penanda tangan Global ACI MRA untuk cakupan yang sama [S6].

KAN mendapat perluasan cakupan IAF MLA untuk sertifikasi ISMS (ISO/IEC 27006 di level 4, ISO/IEC 27001 di level 5) lewat resolusi IAF 2019-23 [S8], sehingga sertifikat ISMS dari badan sertifikasi terakreditasi KAN diakui setara oleh badan akreditasi lain di pengaturan itu. Cakupan KAN saat ini perlu dicek di daftar penanda tangan Global ACI.

Bila satu lapis hilang, nilainya runtuh. Sertifikat dari badan yang tidak terakreditasi tidak punya pengawas di atasnya, sehingga tidak ada yang memastikan auditnya memenuhi 17021-1 dan 27006-1.

### 3.2 Lapis tambahan di Indonesia: pengakuan BSSN

Untuk penyelenggara sistem elektronik di Indonesia ada lapis regulasi di atas akreditasi. Peraturan BSSN No. 8 Tahun 2020 mewajibkan penerapan SNI ISO/IEC 27001 untuk sistem elektronik kategori strategis, dan menjadikannya salah satu pilihan untuk kategori tinggi dan rendah (Pasal 9) [S10]. Ketentuan sertifikasinya yang relevan untuk Day ini:

| Ketentuan | Isi | Pasal |
|---|---|---|
| Siapa yang menyertifikasi | Lembaga sertifikasi yang diakui BSSN | 26 |
| Masa berlaku sertifikat SMPI | Paling lama 3 tahun sejak terbit; diperbarui paling lambat 3 bulan sebelum berakhir | 28 |
| Laporan lembaga sertifikasi | Minimal dua kali setahun ke Kepala BSSN | 31 |
| Audit pengawasan | Minimal sekali setahun, plus audit khusus bila terjadi insiden pada sistem yang tersertifikasi | 33 |
| Bila hasil pengawasan tidak memenuhi | Diberi waktu paling lama 90 hari kalender; bila tetap tidak terpenuhi, sertifikat dapat dicabut | 34 |
| Peralihan | Lembaga yang sebelumnya diakui menteri bidang komunikasi dan informatika tetap diakui sepanjang tidak bertentangan | 43 ayat (4) |

Untuk sistem elektronik kategori strategis, pertanyaan "terakreditasi KAN?" belum cukup; tanyakan juga apakah lembaga sertifikasinya diakui BSSN. Audit khusus setelah insiden (Pasal 33) perlu masuk rencana IR karena bisa datang di luar jadwal surveillance.

### 3.3 Terakreditasi dan tidak terakreditasi

| Aspek | Terakreditasi | Tidak terakreditasi |
|---|---|---|
| Pengawas badan sertifikasi | Badan akreditasi, dengan asesmen berkala | Tidak ada |
| Aturan yang mengikat auditnya | 17021-1, 27006-1, dokumen wajib IAF/Global ACI [S1][S2] | Aturan badan itu sendiri |
| Kompetensi auditor | Diatur dan diperiksa | Tidak dijamin |
| Pengakuan lintas negara | Lewat Global ACI MRA (dahulu IAF MLA) [S6] | Tidak ada |
| Harga | Lebih tinggi | Sering jauh lebih murah |

Cara mengenali di lapangan: sertifikat terakreditasi mencantumkan tanda atau nomor badan akreditasi, bukan hanya logo badan sertifikasi. Selama masa peralihan, tanda IAF MLA masih bisa muncul pada sertifikat; tanda Global ACI MRA baru akan dipakai setelah diputuskan dan tersedia di tiap negara [S6].

Sertifikat tidak terakreditasi tidak otomatis berarti auditnya buruk, tetapi tidak ada pihak ketiga yang menjaminnya. Catat perbedaan itu apa adanya di penilaian pemasok.

### 3.4 Apa yang diatur tentang badan sertifikasi

- **Imparsialitas.** Salah satu pilar 17021-1 [S1]. Badan sertifikasi tidak boleh menyertifikasi sistem yang ia bantu bangun lewat konsultasi.
- **Kompetensi auditor.** Ada persyaratan pengetahuan dan pengalaman auditor untuk lingkup yang diaudit, ditambah persyaratan khusus ISMS di 27006-1 [S2].
- **Waktu audit.** Untuk ISMS, dasar perhitungan hari audit ada di Annex C 27006-1:2024 (di edisi 2015 ada di Annex B), berangkat dari jumlah orang yang bekerja di dalam lingkup lalu disesuaikan menurut kompleksitas [S11]. Edisi 2024 menegaskan bahwa orang yang bekerja untuk organisasi dihitung walaupun bukan karyawannya (misalnya freelancer di dalam lingkup), menghitung waktu audit multi-site dari total orang lalu membaginya ke situs menurut relevansi dan risiko, dan menambah aturan untuk perluasan lingkup [S11]. Angka di tabelnya perlu dicek di teks 27006-1. IAF MD 5 yang sering disebut di diskusi audit time berlaku untuk QMS, EMS, dan OH&SMS, bukan ISMS.
- **Isi sertifikat dan informasi publik.** 17021-1 menetapkan isi minimum dokumen sertifikasi dan mewajibkan badan sertifikasi memberikan, bila diminta, status sertifikasi seorang klien beserta nama, standar, lingkup, dan lokasinya [S9]. Ketentuan ini yang membuat verifikasi langsung ke penerbit selalu mungkin (bagian 3.5).
- **Proses sertifikasi.** Keputusan sertifikasi dibuat pihak yang terpisah dari tim audit (Day 13).

Selain standar ISO, badan sertifikasi terakreditasi terikat dokumen wajib IAF (IAF Mandatory Documents). Yang paling sering relevan untuk ISMS:

| Dokumen | Isi |
|---|---|
| IAF MD 1 | Audit dan sertifikasi organisasi multi-site, termasuk sampling situs |
| IAF MD 4 | Pemakaian ICT dalam audit, termasuk audit jarak jauh |
| IAF MD 29:2024 | Transisi ke 27006-1:2024: badan akreditasi dan badan sertifikasi harus selesai paling lambat 31 Maret 2026 [S7] |

Dokumen IAF kini disimpan di situs Global ACI (bagian 8).

### 3.5 Membaca dan memverifikasi sertifikat

Menurut 17021-1, dokumen sertifikasi minimal memuat [S9]:

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

### 3.6 Memilih badan sertifikasi

Pertimbangan yang bisa dipertanggungjawabkan, selain harga:

| Pertimbangan | Kenapa penting |
|---|---|
| Akreditasi untuk ISMS, dan pengakuan BSSN bila sistemmu kategori strategis | Akreditasi diberikan per skema; tidak otomatis mencakup ISMS |
| Pengalaman auditor di sektormu | Auditor yang tidak memahami sektormu menghabiskan waktu pada hal yang salah |
| Jumlah hari audit dan dasar perhitungannya | Harus bisa dijelaskan dari Annex C 27006-1 [S2][S11] |
| Pengakuan di pasar pelangganmu | Beberapa pelanggan mensyaratkan badan akreditasi tertentu |
| Kontinuitas tim audit | Auditor yang sama lintas siklus menghemat waktu penjelasan |
| Kejelasan aturan tenggat temuan | Berbeda antar badan; tanyakan di muka (Day 13) |

Sepakati di awal siapa yang menanggung biaya bila audit perlu diulang karena ketidaksesuaian mayor. Badan sertifikasi tidak boleh menjadi konsultan yang membangun ISMS-mu atau menjalankan audit internalmu (Day 13); penawaran yang menjanjikan keduanya adalah tanda bahaya.

### 3.7 Apa yang dijamin sertifikat, dan apa yang tidak

**Yang dijamin.** Pada tanggal audit, untuk lingkup dan situs yang tertulis, sebuah ISMS ada dan memenuhi persyaratan standar edisi yang disebut, menurut penilaian auditor berdasarkan sampel, dan dipertahankan lewat surveillance minimal sekali setahun.

**Yang tidak dijamin.** Bahwa organisasi itu aman. Bahwa tidak akan terjadi insiden. Bahwa seluruh sistemnya tercakup. Bahwa kontrol tertentu diterapkan, kecuali kamu memeriksa SoA-nya. Dan bahwa keadaan hari ini sama dengan keadaan saat audit.

Tiga kata kuncinya adalah tanggal, lingkup, dan sampel. Cara menyampaikannya tanpa terdengar meremehkan: sertifikat membuktikan ada sistem yang dijalankan dan diperiksa pihak ketiga secara berkala, dan itu berbeda jauh dari tidak ada apa-apa, tetapi ia tidak menggantikan penilaian risikomu sendiri terhadap pemasok itu.

## 4. Contoh dokumen / artefak (organisasi fiktif)

> Seluruh isi di bawah adalah contoh untuk organisasi fiktif PT AN. Nama badan, nomor, dan tanggal adalah fiktif.

### 4.1 Lembar verifikasi sertifikat pemasok

```
VERIFIKASI SERTIFIKAT PEMASOK                 Nomor: VSP-2027-009
Pemasok   : PT Contoh Layanan          Dinilai oleh : <nama>, tanggal 2027-03-04

DOKUMEN YANG DITERIMA
  Sertifikat ISO/IEC 27001:2022, nomor <fiktif>, terbit 2025-08-12, berlaku sampai 2028-08-11
  Dasar: Statement of Applicability versi 3.1 tanggal 2025-06-30

PEMERIKSAAN (huruf merujuk isi minimum sertifikat, bagian 3.5)
  [x] (f) Lingkup dibaca
      Tertulis: "Penyediaan layanan hosting aplikasi"
  [x] (a) Situs dicocokkan
      Tertulis: pusat data Jakarta. Layanan yang kami pakai berjalan di Surabaya. DI LUAR LINGKUP.
  [x] (b)(c) Tanggal berlaku                  -> masih berlaku
  [x] Surveillance terakhir ditanyakan        -> dinyatakan 2026-09, bukti belum diberikan
  [x] (e) Edisi standar                       -> 2022, sesuai
  [x] (g) Tanda/nomor akreditasi              -> ada, KAN, nomor <fiktif>
  [x] Diverifikasi ke penerbit                -> email konfirmasi badan sertifikasi, status aktif
  [ ] SoA v3.1 diminta                        -> ditolak dengan alasan kerahasiaan
  [x] Pernyataan tertulis pengganti           -> diminta untuk kontrol 5.23, 8.15, 8.16
  [x] Pengakuan BSSN (sistem kami strategis)  -> belum dijawab

KESIMPULAN
  Sertifikat sah dan terverifikasi, TETAPI situs yang melayani kami tidak termasuk lingkup.
  Nilai jaminan terhadap risiko kami: RENDAH.

TINDAK LANJUT
  Minta konfirmasi tertulis apakah pusat data Surabaya mengikuti ISMS yang sama dan kapan
  akan masuk lingkup. Bila tidak, perlakukan sebagai pemasok tanpa sertifikasi untuk
  layanan ini (Day 12).
```

Baris situs itu adalah temuan yang paling sering muncul dan paling sering terlewat: sertifikat sah, tetapi tidak menjamin apa pun untuk layanan yang benar-benar kamu pakai.

### 4.2 Daftar pertanyaan saat memilih badan sertifikasi

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

### 4.3 Menjelaskan arti sertifikat ke manajemen

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

### 4.4 Membandingkan dua penawaran

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

## 5. Lab praktik

**Prasyarat:** hasil Day 12 (penilaian pemasok) dan Day 13 (audit dan bukti). Seluruh lab bersifat membaca, memverifikasi, dan menulis.

1. Di direktori lembaga terakreditasi KAN, cari dua badan sertifikasi berakreditasi skema ISMS; catat nomor akreditasi, ruang lingkup, dan masa berlakunya.
2. Di daftar penanda tangan Global ACI, pastikan KAN tercantum dan catat apakah sub-scope ISMS disebut.
3. Ambil satu sertifikat ISO 27001 yang dipublikasikan terbuka, isi delapan butir isi minimum (bagian 3.5), dan tandai butir yang tidak ada.
4. Cari sertifikat itu di IAF CertSearch. Bila tidak ada, tulis draf email permintaan konfirmasi status ke badan sertifikasinya dengan dasar kewajiban di 17021-1.
5. Isi lembar verifikasi bagian 4.1 untuk sertifikat itu dan tulis kesimpulan nilai jaminannya terhadap satu layanan fiktif PT AN.
6. Untuk dua skenario lingkup PT AN, (a) 120 orang di satu situs dan (b) 120 orang di tiga situs dengan 20 kontraktor, tulis faktor hari audit yang akan kamu tanyakan berdasarkan perubahan di 27006-1:2024.
7. Susun daftar pertanyaan bagian 4.2 siap kirim, lalu tandai lima yang paling menentukan bagi PT AN beserta alasannya.
8. Isi tabel perbandingan bagian 4.4 dari informasi publik dua badan sertifikasi; tandai sel yang tidak bisa diisi.
9. Tulis satu halaman arti sertifikat (bagian 4.3), bacakan ke rekan non-teknis, dan catat bagian yang disalahpahami.
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

## 6. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa |
|---|---|---|
| Sertifikat terlihat sah tetapi tidak ada di IAF CertSearch | Badan sertifikasi tidak mengunggah, atau tidak terakreditasi | Minta konfirmasi status ke penerbit; cek badan akreditasinya [S5][S9] |
| Hanya logo badan sertifikasi, tanpa tanda akreditasi | Kemungkinan tidak terakreditasi | Tanyakan langsung; catat jawabannya apa adanya |
| Sertifikat bertanda IAF MLA terbit 2026 | Masa peralihan ke Global ACI | Wajar selama tanda Global ACI belum tersedia di negara itu [S6] |
| Sertifikat masih menyebut ISO/IEC 27001:2013 | Transisi tidak dilakukan | Sertifikat edisi 2013 tidak sah lagi sejak 31 Oktober 2025; edisi yang berlaku adalah ISO/IEC 27001:2022 [S4] |
| Pemasok menolak memberi SoA | Alasan kerahasiaan yang wajar | Minta pernyataan tertulis untuk kontrol tertentu saja |
| Situs layanan tidak tercantum di sertifikat | Lingkup sempit; sangat umum | Perlakukan sebagai tanpa sertifikasi untuk layanan itu (Day 12) |
| Penawaran hari audit jauh lebih sedikit | Dasar jumlah orang atau lingkup berbeda | Tanyakan dasar perhitungan Annex C 27006-1 [S11] |
| Manajemen menganggap sertifikat berarti aman | Batas makna tidak dijelaskan | Pakai satu halaman bagian 4.3 |

## 7. Kesalahan umum dan jebakan

- Membaca nama standar di sertifikat tanpa membaca lingkup dan daftar situsnya.
- Menerima dokumen sertifikat dari pemasok tanpa memverifikasi ke penerbitnya.
- Menganggap sertifikat yang tidak ada di IAF CertSearch pasti palsu.
- Mengabaikan pengakuan BSSN untuk sistem elektronik kategori strategis.
- Memakai badan sertifikasi yang juga menjadi konsultan atau auditor internalmu.
- Memilih badan sertifikasi hanya berdasarkan harga, tanpa menanyakan dasar hari audit.
- Menyampaikan sertifikat kepada pelanggan sebagai jaminan keamanan.

## 8. Catatan terkini

- IAF berhenti beroperasi pada 1 Januari 2026; Global ACI mengambil alih perannya bersama peran ILAC. Penanda tangan IAF MLA per 31 Desember 2025 yang bergabung menjadi penanda tangan Global ACI MRA. Keputusan tentang pemakaian tanda Global ACI MRA dijadwalkan pada rapat Oktober 2026 [S3][S6]. Pantau perubahan ini sebelum menulis kriteria pengadaan yang menyebut "IAF MLA".
- Transisi ke ISO/IEC 27006-1:2024 menurut IAF MD 29:2024 seharusnya selesai pada 31 Maret 2026, sehingga semua audit ISMS terakreditasi kini memakai edisi 2024 [S7].
- ISO/IEC 17021-1:2015 terakhir dikonfirmasi pada 2020; katalog ISO mencatat tinjauan sistematis 2025 sampai 2026 tanpa hasil yang diumumkan [S1]. Periksa statusnya sebelum mengutip rinciannya di dokumen resmi.
- Dokumen wajib IAF tetap dipakai sampai Global ACI mengadopsi penggantinya [S6]. Edisi terbaru MD 1 dan MD 4 perlu dicek di situs Global ACI sebelum dikutip.

## 9. Cheat sheet

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

## 10. Sumber

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

**Catatan sumber:** isi minimum sertifikat diambil dari materi pelatihan IAS yang mengutip 17021-1:2015 [S9], bukan dari teks standar yang dibeli. Kewajiban mencantumkan versi SoA di sertifikat ISMS dan angka tabel hari audit di Annex C 27006-1:2024 perlu dicek di teks 27006-1. Penomoran Annex C (dahulu Annex B) berasal dari ringkasan transisi pihak ketiga. Edisi terbaru IAF MD 1 dan MD 4 serta cakupan KAN di daftar Global ACI MRA perlu dicek di situs Global ACI. BPK mencatat tanggal penetapan Peraturan BSSN 8/2020 sebagai 16 November 2020, sedangkan salinan Berita Negara mencantumkan 19 November 2020; tanggal pengundangan 23 November 2020 sama di keduanya. Seluruh nama, nomor, dan tanggal di bagian 4 adalah fiktif.
