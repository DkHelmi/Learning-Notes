---
day: 15
title: 'Menjalankan audit internal: dari program sampai laporan, dari sisi auditor'
researched_on: 2026-10-10
versions_checked: 'ISO/IEC 27001:2022 + Amd 1:2024 klausul 9.2; ISO 19011:2026 (edisi 4, 27 Mei 2026; edisi 2018 withdrawn); ISO/IEC 27007:2020 (90.92, akan direvisi); ISO/IEC DIS 27007 (edisi 4, stage 40.60 per 2026-09-23); ISO/IEC 17021-1:2015'
---

# Day 15: Menjalankan audit internal

Cakupan: menyiapkan dan menjalankan audit internal dari kursi auditor, mulai dari persyaratan 9.2 dan program audit sampai laporan yang bisa ditindaklanjuti.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- menjelaskan apa yang dituntut klausul 9.2.1 dan 9.2.2 dari program dan pelaksanaan audit internal.
- menyusun program audit internal yang frekuensinya punya dasar, bukan dibagi rata.
- menulis rencana dan daftar periksa audit untuk satu area teknis.
- menjalankan wawancara audit yang menghasilkan bukti, bukan hanya jawaban.
- mengambil sampel dengan cara yang bisa dijelaskan dan diulang.
- menulis temuan yang memuat pernyataan, bukti, dan kriteria secara terpisah.
- menjaga objektivitas dan imparsialitas auditor dalam organisasi kecil, dan menjelaskan kenapa badan sertifikasi tidak boleh menjadi auditor internalmu.

## 2. Konteks singkat

Day 06 membahas klausul 9.2 sebagai persyaratan, dan Day 13 membahas rasanya diaudit beserta cara menyiapkan bukti. Day ini melihat dari kursi sebaliknya: kamu yang menjadi auditor internal.

Posisi ini sering jatuh ke orang teknis di organisasi kecil karena ia memahami sistemnya. Tanpa disiplin audit, hasilnya dua kegagalan khas: audit berubah menjadi sesi perbaikan teknis sehingga temuan tidak tercatat, atau menjadi pemeriksaan dokumen sehingga keadaan sebenarnya tidak tersentuh.

Persyaratannya datang dari klausul 9.2 ISO/IEC 27001:2022 [S3][S4]. Cara mengauditnya mengikuti panduan ISO 19011:2026 [S1] dan, khusus ISMS, ISO/IEC 27007:2020 yang sedang direvisi [S2][S5]. Kedua panduan itu tidak disertifikasi; yang diperiksa CB adalah apakah audit internalmu memenuhi 9.2.

## 3. Konsep inti

### 3.1 Apa yang dituntut klausul 9.2

Klausul 9.2.1 meminta audit internal dijalankan pada interval terencana untuk memberi informasi apakah ISMS sesuai dengan persyaratan organisasi sendiri dan persyaratan standar, serta apakah ISMS diterapkan dan dipelihara secara efektif [S4].

Klausul 9.2.2 mengatur programnya. Dengan kata sendiri, organisasi harus [S4]:

| Unsur 9.2.2 | Artinya dalam praktik | Dibahas di |
|---|---|---|
| Program audit dengan frekuensi, metode, tanggung jawab, persyaratan perencanaan, dan pelaporan | Satu dokumen program, bukan hanya kalender | 3.2, 4.1 |
| Program mempertimbangkan pentingnya proses dan hasil audit sebelumnya | Frekuensi punya dasar risiko dan riwayat temuan | 3.2 |
| Kriteria dan lingkup ditetapkan untuk tiap audit | Setiap audit punya rencana tertulis | 3.5, 4.2 |
| Auditor dipilih dan audit dijalankan sehingga objektif dan imparsial | Auditor tidak mengaudit pekerjaannya sendiri | 3.3, 3.4 |
| Hasil dilaporkan kepada manajemen terkait | Laporan sampai ke pemilik area dan manajemen yang bisa bertindak | 4.6 |
| Informasi terdokumentasi disimpan sebagai bukti program dan hasil audit | Program, rencana, kertas kerja, dan laporan diarsipkan | 3.9 |

Tiga hal sering salah dibaca. "Interval terencana" tidak berarti tiap klausul tiap tahun; program boleh bergulir asalkan seluruh lingkup tercakup dalam siklus. Persyaratan organisasi sendiri ikut menjadi kriteria. Dan 9.2 tidak mewajibkan auditor bersertifikat; yang dituntut objektivitas, imparsialitas, dan kompetensi yang bisa ditunjukkan (7.2).

### 3.2 Program audit, bukan daftar audit

Program audit adalah rencana beberapa periode, biasanya satu siklus sertifikasi, yang memastikan seluruh lingkup tersentuh dengan frekuensi sesuai risikonya. Dasar frekuensi yang bisa dipertanggungjawabkan, turunan dari frasa "pentingnya proses dan hasil audit sebelumnya" di 9.2.2:

| Faktor | Pengaruh pada frekuensi |
|---|---|
| Risiko area terhadap sasaran ISMS | Risiko tinggi diaudit lebih sering |
| Hasil audit sebelumnya | Area dengan temuan sebelumnya diaudit lebih cepat |
| Perubahan besar | Sistem baru, pemasok baru, atau reorganisasi memicu audit tambahan |
| Insiden | Area yang terlibat insiden masuk ke jadwal berikutnya |
| Kewajiban eksternal | Area yang disorot regulator atau pelanggan |

Membagi klausul merata ke dua belas bulan tanpa alasan akan ditanyakan auditor eksternal. Catat satu kalimat alasan di sebelah tiap baris program.

### 3.3 Prinsip audit menurut ISO 19011

ISO 19011:2018 merumuskan tujuh prinsip audit [S7]:

1. **Integritas:** jujur, cermat, dan tidak mengubah temuan karena tekanan.
2. **Penyajian yang adil (fair presentation):** laporan mencerminkan keadaan sebenarnya, termasuk hambatan dan perbedaan pendapat yang belum selesai.
3. **Kecermatan profesional (due professional care):** memakai pertimbangan dan skeptisisme yang sepadan dengan pentingnya audit.
4. **Kerahasiaan:** informasi yang diperoleh selama audit dilindungi.
5. **Independensi:** bebas dari bias dan konflik kepentingan; sejauh praktis, auditor terpisah dari kegiatan yang diaudit.
6. **Pendekatan berbasis bukti:** kesimpulan bertumpu pada bukti yang bisa diverifikasi dari proses sampling yang sistematis.
7. **Pendekatan berbasis risiko:** perencanaan dan pelaksanaan audit difokuskan pada hal yang paling berpengaruh.

Edisi 2026 tetap memuat bagian prinsip audit [S1]. Ringkasan pihak ketiga menyebut fondasi prinsipnya pada dasarnya tidak berubah dan penekanan pada risiko diperkuat [S8]. Rumusan persis tiap prinsip di edisi 2026, termasuk kalimat tentang independensi auditor internal, perlu dicek di teks standarnya. Prinsip 5 dan 6 adalah dasar praktik di bagian 3.4, 3.6, dan 3.7; prinsip 2 adalah alasan laporan memuat blok "tidak diperiksa" (bagian 4.6).

### 3.4 Objektivitas dalam organisasi kecil, dan batas peran badan sertifikasi

Auditor tidak mengaudit pekerjaannya sendiri. Di organisasi kecil ini tampak sulit karena orang yang paham sistem adalah yang membangunnya. Tiga jalan keluar yang biasa dipakai:

- **Pertukaran antar fungsi.** Orang infrastruktur mengaudit area aplikasi dan sebaliknya, dengan pendamping yang paham areanya.
- **Auditor dari luar yang bukan badan sertifikasi.** Konsultan atau auditor independen boleh menjalankan audit internal.
- **Audit berpasangan.** Satu orang memahami area dan satu menjaga disiplin audit, dengan pembagian peran tertulis.

Yang tidak boleh adalah badan sertifikasi (CB) yang menyertifikasimu menjalankan audit internalmu. ISO/IEC 17021-1:2015 klausul 5.2.6 melarang CB menawarkan audit internal kepada klien yang disertifikasinya; konsensus badan akreditasi Eropa menambahkan bahwa CB boleh mengaudit internal organisasi lain, tetapi perlu jeda sekitar dua tahun sebelum menyertifikasinya [S6]. Alasannya imparsialitas: CB akan menilai hasil kerjanya sendiri saat audit sertifikasi. Klausul 5.2 yang sama juga melarang CB memberi konsultasi sistem manajemen.

Apa pun pengaturannya, tuliskan di rencana audit beserta siapa yang menyetujuinya. Itu bukti langsung untuk tuntutan objektivitas dan imparsialitas di 9.2.2.

### 3.5 Dari kriteria ke pertanyaan

9.2.2 meminta kriteria dan lingkup ditetapkan untuk tiap audit. Kriteria audit internal ISMS biasanya tiga lapis:

1. Persyaratan standar, yaitu klausul yang berlaku.
2. Dokumen internal organisasi, yaitu kebijakan dan prosedur yang kamu tetapkan sendiri.
3. Kewajiban eksternal yang relevan, misalnya kontrak dan regulasi.

Lapis kedua sering menghasilkan temuan paling banyak, karena organisasi menuliskan prosedur yang lebih ketat daripada yang dijalankan. Karena 9.2.1 menyebut persyaratan organisasi sendiri, ketidaksesuaian terhadap prosedur internal tetap nonconformity.

Untuk setiap kriteria, tanyakan tiga hal berurutan. Urutan ini mengikuti dua tuntutan 9.2.1: sesuai persyaratan, lalu diterapkan dan dipelihara secara efektif.

```
1. Apakah ada aturannya?        -> periksa dokumen
2. Apakah dijalankan?           -> minta bukti pelaksanaan
3. Apakah berjalan efektif?     -> periksa hasilnya, bukan hanya pelaksanaannya
```

Pertanyaan ketiga yang membedakan auditor yang baik. Tinjauan hak akses yang rutin dijalankan tetapi tidak pernah menghasilkan pencabutan hak adalah bukti yang perlu dipertanyakan, bukan yang menenangkan.

### 3.6 Wawancara yang menghasilkan bukti

Prinsip pendekatan berbasis bukti berarti jawaban lisan belum menjadi bukti sampai ditunjukkan rekamannya. Kesalahan paling umum adalah bertanya dengan cara yang jawabannya ya atau tidak. Pola yang bekerja:

| Alih-alih | Tanyakan |
|---|---|
| Apakah kalian meninjau hak akses? | Tunjukkan tinjauan hak akses terakhir dan hasilnya |
| Apakah log dipantau? | Siapa yang memeriksa alert kemarin pagi, dan apa yang dilakukannya |
| Apakah ada prosedur insiden? | Ceritakan insiden terakhir dan tunjukkan jejaknya |
| Apakah backup diuji? | Kapan terakhir pemulihan diuji dan apa hasilnya |

Teknik paling produktif: minta satu kejadian nyata yang baru, lalu telusuri jejaknya dari awal sampai akhir. Penelusuran satu kasus mengungkap lebih banyak daripada memeriksa sepuluh dokumen.

Tiga aturan sikap: catat apa yang dikatakan dan oleh siapa; jangan memperbaiki apa pun selama audit karena itu mengubah bukti; dan jangan berdebat, karena tugasmu mengumpulkan bukti, bukan meyakinkan.

### 3.7 Sampling yang bisa dijelaskan

Day 13 bagian 3.3 menjelaskan dua pendekatan sampling di ISO 19011: berbasis pertimbangan dan statistik. Dari kursi auditor internal, yang penting metodenya bisa dijelaskan dan diulang. Dalam praktik ada tiga cara:

| Cara | Kapan dipakai | Kelemahan |
|---|---|---|
| Acak (statistik) | Ingin memperkirakan keadaan populasi | Bisa melewatkan kasus penting |
| Terarah (berbasis pertimbangan) | Ingin memeriksa kasus berisiko tinggi | Tidak bisa dipakai menyimpulkan populasi |
| Menyeluruh | Populasi kecil | Mahal pada populasi besar |

Yang harus kamu tulis di kertas kerja: ukuran populasi, jumlah sampel, cara pemilihan, dan alasan. Tanpa keempatnya, temuanmu bisa dibantah dengan mengatakan sampelnya kebetulan buruk.

Tidak ada angka sampel baku untuk audit internal di 27001 maupun 19011. Tetapkan aturanmu secara tertulis, pakai konsisten, dan sebutkan bahwa itu aturan internal.

### 3.8 Menulis temuan

Temuan yang baik memisahkan tiga hal. "Pernyataan" di sini sama dengan "kondisi" di Day 13.

```
PERNYATAAN : apa yang tidak sesuai, dalam satu kalimat
BUKTI      : apa yang kamu lihat, dengan identitas dan tanggal
KRITERIA   : klausul atau dokumen internal yang dilanggar
```

Yang sering salah adalah mencampurkan rekomendasi ke dalam temuan. Tugas auditor menyatakan apa yang tidak sesuai; menentukan cara memperbaikinya adalah tugas pemilik area, dan auditor yang menentukan perbaikan kehilangan independensinya untuk memeriksa perbaikan itu nanti.

Catat juga hal yang baik; observasi positif membuat laporan lebih jujur dan lebih mau dibaca.

### 3.9 Kertas kerja

Kertas kerja memungkinkan orang lain menelusuri bagaimana kamu sampai pada kesimpulan. Isinya: siapa yang diwawancarai dan kapan, dokumen apa yang diperiksa dengan versinya, sampel apa yang diambil dan bagaimana dipilih, apa yang dilihat, dan kesimpulan per kriteria.

Simpan terpisah dari laporan. Laporan untuk pembaca, kertas kerja untuk penelusuran. Bersama program, rencana, dan laporan, kertas kerja adalah informasi terdokumentasi yang diminta 9.2.2 sebagai bukti program dan hasil audit, dan auditor eksternal kadang memintanya untuk menilai mutu audit internalmu.

## 4. Contoh dokumen / artefak (organisasi fiktif)

> Seluruh isi di bawah adalah contoh untuk organisasi fiktif PT AN. Angka, nama, dan aturan di dalamnya adalah aturan internal fiktif, bukan persyaratan standar.

### 4.1 Program audit internal dengan alasan

Kolom program memuat unsur 9.2.2: frekuensi, metode, tanggung jawab, dan dasar pemilihan. Aturan perencanaan dan pelaporan ditulis di pengantar program: tiap audit punya rencana tertulis (bentuk 4.2), dan laporannya dikirim ke pemilik area serta ISMS Manager dalam 10 hari kerja.

| Periode | Area | Kriteria utama | Metode | Auditor | Alasan pemilihan |
|---|---|---|---|---|---|
| 2026 Q4 | Manajemen akses | 5.15, 5.18, prosedur AKS-01 | Sampling tiket akses, wawancara | Tim GRC | Dua temuan minor pada audit sebelumnya belum terverifikasi efektif |
| 2027 Q1 | Logging dan pemantauan | 9.1; 8.15, 8.16; prosedur LOG-02 | Penelusuran alert, cek konfigurasi | Fungsi aplikasi | Sumber log baru ditambahkan pada Q3 2026; belum pernah diaudit |
| 2027 Q1 | Manajemen pemasok | 5.19 sampai 5.22 | Tinjauan kontrak, wawancara | Tim GRC | Dua pemasok baru dengan akses jaringan |
| 2027 Q2 | Respons insiden | Klausul 10.2; 5.24 sampai 5.28 | Penelusuran satu insiden | Konsultan independen | Satu insiden nyata pada Q4 2026; menguji pembelajarannya |
| 2027 Q3 | Klausul 4 sampai 10 kecuali 9.2 | Konteks, kepemimpinan, risiko, dukungan, operasi, evaluasi | Tinjauan dokumen, wawancara pimpinan | Tim GRC | Seluruh klausul harus tercakup dalam siklus; persiapan surveillance |
| 2027 Q3 | Klausul 9.2 (proses audit internal itu sendiri) | 9.2.1, 9.2.2 | Tinjauan program dan laporan | Konsultan independen | Tim GRC tidak boleh mengaudit pekerjaannya sendiri |
| 2027 Q4 | Kelangsungan dan pemulihan | 5.29, 5.30 | Observasi uji pemulihan | Fungsi infrastruktur | Belum pernah diuji sejak sistem dipindahkan ke cloud |

Kolom alasan yang membuat program ini bisa dipertahankan; tanpanya tabel di atas hanya jadwal. Baris audit atas klausul 9.2 sering terlupa: proses audit internal juga harus diaudit, dan pelakunya tidak boleh tim yang menjalankannya.

### 4.2 Rencana audit satu area

```
RENCANA AUDIT INTERNAL                     Nomor: AI-2027-01
Area        : Logging dan pemantauan
Tanggal     : 11 sampai 12 Februari 2027
Auditor     : <nama>, tidak terlibat dalam pengelolaan platform logging
Pendamping  : <nama>, memahami area tetapi tidak menilai
Independensi: auditor berasal dari fungsi aplikasi; pengaturan ini disetujui oleh <jabatan>
Pelaporan  : laporan ke Lead SOC dan ISMS Manager paling lambat 10 hari kerja setelah rapat penutup

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

Kolom ketiga yang membedakan audit ini dari pemeriksaan dokumen. Dua baris terakhir memakai teknik Day 11: memeriksa keadaan nyata, bukan konfigurasi yang diklaim.

### 4.4 Catatan wawancara

```
WAWANCARA                                   AI-2027-01 / W-03
Tanggal   : 12 Februari 2027, 09:10 sampai 09:55
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

Catatan auditor dipisahkan dari jawaban narasumber, dan satu jawaban ditandai tidak terverifikasi, bukan diterima begitu saja. Kejujuran semacam itu yang membuat kertas kerja bernilai.

### 4.5 Temuan dengan tiga bagian terpisah

```
TEMUAN AI-2027-01 / T-01                            Klasifikasi: minor

PERNYATAAN
  Penutupan alert tidak selalu disertai alasan, sehingga peninjauan ulang tidak dimungkinkan.

BUKTI
  Dari 10 tiket sampel acak periode 13 Januari sampai 11 Februari 2027, 6 ditutup tanpa
  catatan alasan (tiket #4380, #4391, #4402, #4412, #4418, #4425).
  Diperiksa pada 12 Februari 2027 bersama <nama>.

KRITERIA
  Prosedur internal LOG-02 versi 3.1 pasal 7.3 mewajibkan alasan penutupan dicatat.

ALASAN KLASIFIKASI
  Alert tetap ditinjau dan ditangani; yang hilang adalah rekaman alasannya. Kemampuan ISMS
  mencapai hasilnya belum terganggu, sehingga minor. Bila pola yang sama ditemukan di area lain,
  pertimbangkan major karena menunjukkan kegagalan sistemik (Day 13 bagian 3.4).

CATATAN
  Tidak ada rekomendasi perbaikan di sini; penentuan tindakan adalah tanggung jawab pemilik area
  dan akan dicatat di lembar tindakan korektif (Day 16).
```

Baris catatan terakhir melindungi independensimu saat memverifikasi perbaikannya nanti.

### 4.6 Ringkasan laporan audit

```
LAPORAN AUDIT INTERNAL                      AI-2027-01
Area, tanggal, auditor, kriteria, lingkup   : (lihat rencana)
Dikirim kepada                              : Lead SOC, ISMS Manager (9.2.2: manajemen terkait)

KESIMPULAN
  ISMS pada area ini secara umum berjalan sesuai kriteria, dengan 1 temuan minor
  dan 2 observasi. Tidak ditemukan major nonconformity.

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

Blok terakhir sering dihilangkan. Menyatakan apa yang tidak diperiksa (prinsip penyajian yang adil) mencegah laporan dibaca sebagai jaminan menyeluruh.

## 5. Lab praktik

**Prasyarat:** dokumen fiktif dari Day sebelumnya, terutama hasil Day 06, Day 09, dan Day 11. Seluruh lab bersifat menulis dan melatih wawancara dengan rekan.

1. Susun program audit internal satu siklus untuk PT AN memakai bentuk bagian 4.1. Cocokkan dengan tabel 9.2.2 di bagian 3.1: apakah frekuensi, metode, tanggung jawab, perencanaan, dan pelaporan semuanya tertulis, dan apakah seluruh klausul 4-10 serta kontrol di SoA tercakup dalam siklus?
2. Tulis pengaturan objektivitas untuk organisasi dengan delapan orang di tim TI, termasuk siapa yang mengaudit proses audit internal itu sendiri, lalu minta rekan menilai apakah pengaturan itu akan diterima auditor eksternal.
3. Susun rencana audit satu area memakai bentuk bagian 4.2, lengkap dengan aturan sampel internal dan alasannya.
4. Buat daftar periksa berlapis tiga bagian 4.3 untuk area yang sama, minimal delapan baris, dan pastikan kolom ketiga benar-benar menguji efektivitas, bukan pelaksanaan.
5. Latih wawancara dengan rekan yang berperan sebagai pemilik area. Pakai pola pertanyaan bagian 3.6, dan catat hasilnya dalam bentuk bagian 4.4.
6. Tinjau catatan wawancaramu: tandai mana yang bukti dan mana yang pernyataan lisan tanpa bukti. Hitung perbandingannya.
7. Ambil sampel dari populasi fiktif memakai ketiga cara di bagian 3.7, lalu tulis bagaimana kesimpulan yang bisa kamu tarik berbeda untuk masing-masing.
8. Tulis tiga temuan memakai bentuk bagian 4.5, lalu periksa apakah ada rekomendasi yang tercampur ke dalamnya dan buang bila ada.
9. Susun laporan ringkas bagian 4.6, termasuk blok tidak diperiksa.
10. Minta rekan membaca laporanmu dan menandai kalimat yang bisa dibantah karena buktinya tidak cukup. Perbaiki kalimat itu.

**Hasil yang sebaiknya tersimpan:**
- Program audit satu siklus dengan alasan per baris dan cek kelengkapan unsur 9.2.2.
- Pengaturan objektivitas beserta penilaian rekan.
- Rencana audit, daftar periksa tiga lapis, dan catatan wawancara untuk satu area.
- Rasio bukti terhadap pernyataan lisan, dan perbandingan kesimpulan dari tiga cara sampling.
- Tiga temuan tanpa rekomendasi dan laporan ringkas dengan blok tidak diperiksa.
- Daftar kalimat yang diperbaiki setelah ditinjau rekan.

## 6. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa |
|---|---|---|
| Semua jawaban ya tetapi tidak ada bukti | Pertanyaan berbentuk ya atau tidak | Pakai pola bagian 3.6; minta tunjukkan, bukan jelaskan |
| Temuan dibantah dengan alasan sampel buruk | Metode sampling tidak tercatat | Tulis populasi, jumlah, cara, dan alasan di kertas kerja |
| Objektivitas dipertanyakan | Auditor mengaudit areanya sendiri | Pakai salah satu pengaturan di bagian 3.4 dan tuliskan |
| CB menawarkan audit internal sekaligus sertifikasi | Tidak paham batas imparsialitas | Tolak; pakai auditor internal atau konsultan yang bukan bagian CB (bagian 3.4) |
| Dokumen tertinggal dari praktik tidak terdeteksi | Hanya memeriksa dokumen, bukan keadaan nyata | Bandingkan daftar di dokumen dengan keadaan sistem |

## 7. Kesalahan umum dan jebakan

- Membagi klausul merata ke dalam setahun tanpa dasar risiko atau alasan tertulis.
- Mengaudit area yang kamu kelola sendiri, atau tidak pernah mengaudit proses audit internal itu sendiri.
- Meminta badan sertifikasi yang sama menjalankan audit internal.
- Menerima penjelasan lisan sebagai bukti, atau memperbaiki masalah selama audit berlangsung.
- Mencampurkan rekomendasi ke dalam pernyataan temuan.
- Hanya menguji keberadaan aturan dan pelaksanaannya, tanpa menguji efektivitasnya. Audit internal yang tidak pernah menemukan apa pun biasanya tanda lapis ini terlewat, dan auditor eksternal mengenali pola itu.
- Laporan tidak sampai ke manajemen yang bisa bertindak, sehingga tuntutan pelaporan 9.2.2 tidak terpenuhi.

## 8. Catatan terkini

- ISO 19011:2026 (edisi 4) terbit 27 Mei 2026 dan edisi 2018 berstatus withdrawn [S1]. Tidak ada masa transisi karena 19011 adalah panduan, tetapi templat dan materi pelatihan yang masih merujuk edisi 2018 sebaiknya ditinjau.
- ISO/IEC 27007:2020 berada di stage 90.92 (diputuskan untuk direvisi) setelah systematic review 2025 [S2]. Penggantinya, ISO/IEC DIS 27007 (edisi 4), menutup pemungutan suara DIS pada 23 September 2026 (stage 40.60) [S5]. Pantau terbitnya; isinya kemungkinan menyesuaikan 19011:2026.
- ISO/IEC 17021-1:2015, sumber larangan audit internal oleh CB, sedang dalam systematic review (Day 13 bagian 8).

## 9. Cheat sheet

```
9.2.1  interval terencana; sesuai persyaratan SENDIRI + standar; diterapkan dan dipelihara efektif
9.2.2  program: frekuensi | metode | tanggung jawab | perencanaan | pelaporan
       pertimbangkan pentingnya proses + hasil audit sebelumnya
       tiap audit: kriteria + lingkup | auditor objektif dan imparsial | lapor ke manajemen terkait
       simpan bukti program dan hasil
19011:2018 prinsip: integritas | penyajian adil | kecermatan profesional | kerahasiaan
                    independensi | berbasis bukti | berbasis risiko

PROGRAM AUDIT (lebih dari jadwal)
  dasar frekuensi: RISIKO area | hasil audit sebelumnya | perubahan besar | insiden | kewajiban eksternal
  TULIS ALASAN di sebelah tiap baris; tanpa itu, auditor eksternal akan mempertanyakannya
  membagi klausul merata tanpa alasan = memenuhi di atas kertas saja

INDEPENDENSI (organisasi kecil)
  pertukaran antar fungsi | auditor luar yang BUKAN badan sertifikasimu | audit berpasangan
  CB dilarang audit internal klien yang disertifikasinya (17021-1 5.2.6; jeda 2 tahun)
  proses audit internal juga diaudit, oleh pihak lain
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
| S1 | ISO committee: ISO 19011:2026 Guidelines for auditing management systems | https://committee.iso.org/standard/88984.html | primer (katalog ISO) | 2026-05-27; diakses 2026-10-10 | Tinggi untuk edisi dan status; edisi 2018 withdrawn |
| S2 | ISO committee: ISO/IEC 27007:2020 Guidelines for ISMS auditing | https://committee.iso.org/standard/77802.html | primer (katalog ISO) | 2020-01-21; diakses 2026-10-10 | Tinggi. Stage 90.92 sejak 2025-06-10 |
| S3 | ISO committee: ISO/IEC 27001:2022 | https://committee.iso.org/standard/82875.html | primer (katalog ISO) | Oktober 2022; diakses 2026-10-10 | Tinggi untuk edisi dan status |
| S4 | Hicomply: ISO 27001 clause 9.2 internal audit (2022) | https://hicomply.com/hub/iso-27001-clause-9-2-internal-audit-2022 | sekunder (vendor) | 2026-07-15; diakses 2026-10-10 | Sedang. Ringkasan isi 9.2.1 dan 9.2.2, konsisten dengan Day 06 |
| S5 | ISO committee: ISO/IEC DIS 27007 | https://committee.iso.org/standard/92416.html | primer (katalog ISO) | stage 40.60 pada 2026-09-23; diakses 2026-10-10 | Tinggi untuk status draf |
| S6 | European Accreditation FAQ: Question CW2017 3 (ISO/IEC 17021-1:2015 klausul 5.2.6) | https://european-accreditation.org/?p=43180 | primer (konsensus badan akreditasi) | jawaban Maret 2018; diakses 2026-10-10 | Tinggi. Larangan audit internal oleh CB, jeda 2 tahun |
| S7 | Open Exam Prep: ISO 19011 audit principles and framework | https://open-exam-prep.com/study-guides/iso-27001-lead-auditor/fundamental-audit-concepts-and-principles/iso-19011-audit-principles-and-framework | sekunder (materi studi) | diakses 2026-10-10 | Sedang. Tujuh prinsip ISO 19011:2018 |
| S8 | TRECCERT: ISO 19011:2026 is here | https://treccert.com/iso-19011-2026-is-here-what-the-new-standard-means-for-management-system-auditing/ | sekunder (lembaga sertifikasi) | 2026-05-28; diakses 2026-10-10 | Rendah-sedang. Ringkasan perubahan; tidak merinci prinsip |

**Catatan sumber:** isi 9.2.1 dan 9.2.2 diparafrasekan dari ringkasan sekunder [S4] yang cocok dengan Day 06, bukan dari teks standar. Daftar tujuh prinsip berasal dari edisi 2018 [S7]; rumusan prinsip di edisi 2026 belum dicocokkan dengan teks standar. Larangan konsultasi oleh CB (17021-1 klausul 5.2) belum punya sumber terbuka terpisah. Praktik wawancara, daftar periksa tiga lapis, dan format kertas kerja adalah praktik audit umum yang disusun sendiri. Seluruh nomor prosedur, tiket, temuan, dan aturan sampel di bagian 4 adalah fiktif.
