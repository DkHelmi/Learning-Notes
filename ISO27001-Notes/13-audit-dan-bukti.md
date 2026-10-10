---
day: 13
title: 'Audit dan bukti: alur audit internal dan sertifikasi, sampling, grading temuan, dan penyiapan bukti SOC/IR'
researched_on: 2026-10-10
versions_checked: 'ISO/IEC 27001:2022 + Amd 1:2024; ISO/IEC 27006-1:2024 (edisi 1, Mar 2024, menggantikan 27006:2015 + Amd 2020); ISO/IEC 17021-1:2015 (systematic review, 90.60 per 2026-03-05); ISO 19011:2026 (edisi 4, 27 Mei 2026)'
---

# Day 13: Audit dan bukti

Cakupan: jenis audit, siklus sertifikasi tiga tahun, aturan untuk lembaga sertifikasi (ISO/IEC 17021-1 dan 27006-1), metode dan sampling bukti, grading temuan, penulisan temuan, penyiapan paket bukti SOC/IR, proteksi data saat audit, dan sikap analyst saat diwawancarai.

> Catatan pribadi, bukan materi resmi ISO, dan bukan nasihat hukum atau audit. Aturan rinci (tenggat, jumlah sampel) ditetapkan masing-masing lembaga sertifikasi; angka di contoh PT AN adalah fiktif.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- menjelaskan siklus sertifikasi (tahap 1, tahap 2, surveillance, resertifikasi) dan dokumen yang mengatur lembaga sertifikasi.
- membedakan conformity, nonconformity major dan minor, observation, serta opportunity for improvement.
- menulis temuan audit dengan struktur kondisi, kriteria, dan bukti.
- menyusun populasi dan rencana sampling untuk proses SOC, serta paket bukti yang bisa diserahkan dengan cepat.
- menjaga integritas bukti dan data pribadi selama audit, dan bersikap profesional saat diwawancarai.

## 2. Konteks singkat

Banyak analyst SOC pertama kali bersentuhan dengan ISO 27001 saat auditor datang dan meminta "tunjukkan lima insiden terakhir dan bukti penanganannya". Bila daftar lengkap dan bukti konsisten bisa diserahkan dalam hitungan menit, audit lancar. Bila buktinya tersebar di chat pribadi, temuan hampir pasti muncul walaupun pekerjaan teknisnya bagus.

Kapan dipakai: audit internal (9.2), audit sertifikasi dan surveillance, audit dari klien (second party), dan due diligence pemasok.
Kapan tidak cukup: Day ini tidak membuatmu menjadi auditor tersertifikasi; kompetensi auditor diatur lembaga sertifikasi personel.

## 3. Konsep inti

### 3.1 Jenis audit

| Jenis | Siapa mengaudit | Contoh |
|---|---|---|
| First party (internal) | Organisasi sendiri atau pihak yang ditunjuknya | Internal audit 9.2 (Day 06) |
| Second party | Pihak yang punya kepentingan, misalnya klien | Klien perbankan mengaudit PT AN sesuai kontrak |
| Third party | Lembaga sertifikasi (CB) independen yang terakreditasi | Audit sertifikasi ISO 27001 |

CB tidak boleh menjalankan audit internal untuk klien yang disertifikasinya. Alasannya imparsialitas: CB akan menilai hasil kerjanya sendiri saat audit sertifikasi (ancaman self-review). Menurut konsensus badan akreditasi Eropa (EA) atas ISO/IEC 17021-1:2015 klausul 5.2.6, CB boleh mengaudit internal organisasi yang tidak ia sertifikasi, tetapi perlu jeda sekitar dua tahun sebelum CB itu menyertifikasinya [S6]. Klausul 5.2 juga melarang CB memberi konsultasi sistem manajemen. Konsultan independen yang bukan bagian dari CB tetap boleh menjalankan audit internal.

### 3.2 Siklus sertifikasi tiga tahun

```
Tahun 0: Tahap 1 (kesiapan, dokumen, scope) -> Tahap 2 (efektivitas penerapan) -> keputusan sertifikasi
Tahun 1: Surveillance 1 (paling lambat 12 bulan setelah tanggal keputusan sertifikasi)
Tahun 2: Surveillance 2 (minimal sekali per tahun kalender)
Tahun 3: Resertifikasi (keputusan harus keluar sebelum sertifikat habis) -> siklus baru
```

- **Tahap 1** menilai apakah ISMS siap diaudit: scope, kebijakan, metodologi risiko, SoA, apakah audit internal dan management review sudah direncanakan dan dijalankan, serta pemahaman organisasi atas persyaratan. Hasilnya bisa berupa daftar hal yang harus diselesaikan sebelum tahap 2.
- **Tahap 2** menilai apakah ISMS benar-benar diterapkan dan efektif. Di sinilah sampling tiket, wawancara analyst, dan observasi dilakukan.
- **Surveillance** wajib minimal sekali per tahun kalender, kecuali di tahun resertifikasi. Penundaan hanya diterima sebagai pengecualian yang didokumentasikan dan tidak boleh berantai [S9]. Surveillance pertama paling lambat 12 bulan sejak tanggal keputusan sertifikasi [S12]. Surveillance mencakup sebagian ISMS, tetapi tiap kunjungan wajib memeriksa audit internal, management review, tindak lanjut temuan, keluhan, perubahan, dan pengendalian operasional; surveillance yang hanya memeriksa dokumen tidak memenuhi 17021-1 [S11].
- **Resertifikasi** menilai ulang seluruh ISMS (klausul 4-10 dan kontrol di SoA) di tahun ketiga. Keputusannya, termasuk verifikasi major yang ditemukan saat itu, harus selesai sebelum sertifikat habis. Bila terlambat, sertifikat berakhir dan pemulihannya mengikuti prosedur CB [S12].

Aturan untuk CB ada di dua dokumen. ISO/IEC 17021-1:2015 berisi persyaratan umum untuk lembaga yang mengaudit dan menyertifikasi sistem manajemen apa pun [S13]. ISO/IEC 27006-1:2024 (edisi 1, Maret 2024) berisi tambahan khusus ISMS, misalnya kompetensi auditor ISMS dan cara menghitung durasi audit, dan menggantikan ISO/IEC 27006:2015 beserta amandemen 2020 [S1]. Artinya, aturan main CB bukan karangan auditor perorangan, dan CB sendiri diperiksa badan akreditasi terhadap aturan itu.

### 3.3 Metode dan sampling bukti

Auditor mengumpulkan bukti dengan beberapa metode:

- **tinjauan dokumen:** kebijakan, prosedur, SoA;
- **sampling rekaman:** tiket, log, laporan;
- **wawancara:** analyst, Lead SOC, pimpinan;
- **observasi:** melihat analyst melakukan triage, atau melihat ruang SOC;
- **verifikasi teknis terbatas:** meminta ditunjukkan konfigurasi retensi atau daftar role.

Auditor tidak memeriksa semua rekaman. Ia mengambil sampel dari populasi. Panduan audit sistem manajemen ISO 19011 (edisi 2018, Annex A) membedakan dua pendekatan [S14]:

- **sampling berbasis pertimbangan (judgement-based):** sampel dipilih dari pengalaman auditor dan area berisiko, misalnya insiden terbesar atau rule yang paling sering diubah. Hasilnya tidak bisa dinyatakan sebagai estimasi statistik untuk seluruh populasi.
- **sampling statistik:** sampel dipilih acak berbasis probabilitas, sehingga kesimpulan bisa digeneralisasi dengan tingkat keyakinan tertentu. Cocok untuk populasi besar yang seragam, misalnya ribuan tiket alert.

Keduanya membawa sampling risk, yaitu kemungkinan kesimpulan dari sampel berbeda dengan kesimpulan bila seluruh populasi diperiksa. Satu pengecualian di sampel biasanya membuat auditor memperluas sampel atau menelusuri penyebabnya [S14]. ISO 19011:2026 menggantikan edisi 2018 [S5]; apakah panduan sampling di Annex A ikut berubah perlu dicek di teks edisi 2026.

Konsekuensi untuk SOC:

1. **Populasi harus lengkap dan bisa diekspor.** Auditor meminta daftar lengkap ("semua insiden P1 dan P2 sejak audit terakhir") lalu memilih sendiri.
2. **Setiap sampel harus bisa ditelusuri end-to-end.** Satu tiket harus tersambung ke alert, keputusan klasifikasi, tindakan, bukti, dan bila perlu PIR serta CA.
3. **Konsistensi antar sumber diuji.** Jumlah insiden di laporan bulanan harus cocok dengan jumlah tiket di sistem.

### 3.4 Grading temuan

| Grading | Arti | Dampak |
|---|---|---|
| Conformity | Persyaratan terpenuhi | Tidak ada tindakan |
| Major nonconformity | Nonconformity yang memengaruhi kemampuan sistem manajemen mencapai hasil yang diharapkan [S2] | Sertifikasi atau resertifikasi tertahan sampai CB meninjau, menerima, dan memverifikasi correction serta corrective action-nya [S3][S10] |
| Minor nonconformity | Nonconformity yang tidak memengaruhi kemampuan tersebut [S3] | CB meninjau dan menerima rencana correction dan corrective action; sertifikat bisa diberikan setelah rencana diterima, dan pelaksanaannya diperiksa pada audit berikutnya [S3][S4] |
| Observation | Bukan nonconformity, tetapi berpotensi menjadi nonconformity | Disarankan ditindaklanjuti |
| Opportunity for improvement (OFI) | Saran perbaikan | Tidak wajib |

Dua kondisi yang biasanya membuat temuan menjadi major [S2]:

- ada keraguan signifikan bahwa pengendalian proses efektif;
- beberapa minor nonconformity pada persyaratan yang sama menunjukkan kegagalan sistemik.

Contoh major yang sering disebut: tidak ada internal audit sama sekali, atau risk assessment hanya ada di kertas [S7].

Ada satu batas yang datang dari 17021-1 sendiri: pada sertifikasi awal, bila CB tidak bisa memverifikasi pelaksanaan correction dan corrective action untuk major dalam 6 bulan setelah hari terakhir tahap 2, CB harus menjalankan tahap 2 ulang sebelum merekomendasikan sertifikasi [S10]. Di dalam batas itu, tenggat ditetapkan oleh masing-masing CB. Pola yang sering dilaporkan adalah rencana tindakan dalam sekitar 30 hari, dan penyelesaian major dalam sekitar 90 hari dengan verifikasi [S7]. Cara melaporkan penanganan minor juga berbeda antar CB, jadi konfirmasi prosedurnya langsung ke CB yang mengaudit organisasimu [S4].

Istilah observation dan OFI tidak seragam; sebagian CB hanya memakai salah satunya.

### 3.5 Menulis temuan yang baik

Temuan yang baik punya tiga unsur:

- **Kondisi:** apa yang ditemukan, secara faktual dan spesifik.
- **Kriteria:** persyaratan yang dirujuk (klausul, kontrol di SoA, atau prosedur internal).
- **Bukti:** dokumen, rekaman, atau wawancara yang menunjukkan kondisi itu.

Temuan yang buruk: "Logging tidak memadai."
Temuan yang baik: "Dari 5 server in-scope yang disampel, 2 (db-07 dan app-12) tidak mengirim log ke SIEM sejak 2026-07-14. Standar STD-LOG-01 butir 1 mewajibkan semua server in-scope mengirim log, dan kontrol 8.15 dinyatakan diterapkan di SoA v1.1. Bukti: hasil query cakupan log tanggal 2026-09-30 dan wawancara dengan Lead SOC."

### 3.6 Menyiapkan bukti SOC dan IR

Paket bukti yang disiapkan sebelum audit berisi:

- **Indeks bukti per kontrol:** kontrol, dokumen, rekaman, lokasi, dan pemilik.
- **Populasi siap ekspor:** daftar insiden, alert, perubahan rule, sumber log, akun dengan hak istimewa.
- **Konsistensi angka:** laporan bulanan dicocokkan dengan sistem sumber sebelum audit.
- **Snapshot konfigurasi:** retensi, role, dan sumber waktu, lengkap dengan tanggal pengambilan.

Saat audit, ada dua hal yang sering terlupa:

1. **Proteksi sistem saat audit (kontrol 8.34).** Bila auditor perlu melihat SIEM, beri akun read-only yang sementara dan tercatat, atau tunjukkan layar lewat analyst. Jangan beri akun admin.
2. **Minimasi data pribadi (5.34, UU PDP).** Tiket insiden bisa memuat data pelanggan. Tunjukkan yang perlu saja dan samarkan bila bisa, walaupun auditor terikat kerahasiaan.

### 3.7 Chain of custody untuk bukti audit dan forensik

Bukti audit cukup bisa ditelusuri: dari mana diambil, kapan, oleh siapa, dan versi berapa, misalnya ekspor CSV tiket dengan tanggal dan nama pengambil. Bukti forensik butuh chain of custody formal: hash, serah terima tercatat, dan penyimpanan dengan akses terbatas (ISO/IEC 27037, Day 10). Untuk insiden dengan bukti forensik, auditor biasanya hanya memeriksa bahwa formulir chain of custody ada dan terisi, bukan membuka image disk-nya.

### 3.8 Sikap saat diwawancarai

- Jawab yang ditanyakan, dengan fakta, dan tunjukkan buktinya ("saya tunjukkan tiketnya").
- Bila tidak tahu, katakan tidak tahu dan sebutkan siapa yang tahu atau kapan kamu bisa menyusulkan. Mengarang jawaban lebih berbahaya daripada mengaku tidak tahu.
- Jelaskan pekerjaan sesuai prosedur yang berlaku. Bila praktik berbeda dari prosedur, sampaikan jujur.

## 4. Contoh dokumen / artefak (organisasi fiktif)

Organisasi fiktif: PT Awan Nusantara (PT AN). Semua angka adalah ilustrasi.

### 4.1 Agenda audit tahap 2 untuk area SOC (cuplikan)

| Waktu | Area | Auditee | Kriteria |
|---|---|---|---|
| 09.00-09.45 | Proses insiden: kriteria, sampel 5 tiket P1/P2 | Incident manager, Lead SOC | 5.24-5.28, prosedur IR v2 |
| 09.45-10.30 | Logging dan monitoring: cakupan, retensi, peran admin | Lead SOC, SIEM admin | 8.15-8.17, STD-LOG-01 |
| 10.30-11.00 | Threat intelligence dan kerentanan: brief, SLA | Lead SOC, Head of Platform | 5.7, 8.8 |
| 11.00-11.20 | Wawancara analyst on-duty: awareness dan triage | Analyst L1 | 7.3, 5.25 |
| 11.20-11.40 | Kompetensi tim SOC | Lead SOC, HR | 7.2 |

### 4.2 Rencana sampling internal (aturan fiktif PT AN untuk audit internal)

| Populasi | Ukuran populasi | Sampel | Cara memilih | Yang dicek di tiap sampel |
|---|---|---|---|---|
| Insiden P1/P2 Jan-Sep 2026 | 23 | 5 | Pertimbangan: 2 terbesar, 3 acak | Klasifikasi, timeline, bukti, PIR |
| Perubahan rule deteksi | 140 | 10 | Setiap urutan ke-14 dari daftar yang diurutkan berdasarkan tanggal | Tiket, review, persetujuan |
| Server in-scope | 50 | 5 | Acak | Log ada di SIEM 24 jam terakhir; waktu sinkron |
| Analyst SOC | 9 | 3 | Satu per shift | Wawancara 7.3; bukti kompetensi 7.2 |

Pada baris perubahan rule, 140 / 10 = 14, jadi memilih setiap urutan ke-14 menghasilkan tepat 10 sampel. Aturan jumlah sampel di tabel ini adalah aturan internal fiktif. CB punya aturannya sendiri.

### 4.3 Contoh temuan dengan grading berbeda

```
TEMUAN A (minor nonconformity)
Kondisi : 1 dari 5 tiket insiden P2 (INC-2026-044) tidak memuat alasan klasifikasi.
Kriteria: Prosedur IR v2 butir 3.2; kontrol 5.25 dinyatakan diterapkan di SoA.
Bukti   : tiket INC-2026-044; wawancara analyst L1.
Alasan grading: kasus tunggal, 4 tiket lain lengkap; proses berjalan.

TEMUAN B (major nonconformity)
Kondisi : Tidak ada internal audit atas proses SOC sejak sertifikasi awal (2024); program audit 2025-2026
          tidak mencantumkan kontrol 5.24-5.28 dan 8.15-8.17.
Kriteria: Klausul 9.2.1 dan 9.2.2.
Bukti   : program audit 2025 dan 2026; laporan audit internal 2025.
Alasan grading: area penting tidak diaudit dalam lebih dari satu siklus; memengaruhi kemampuan ISMS
                mendeteksi kelemahannya sendiri.

TEMUAN C (opportunity for improvement)
Kondisi : Brief intel bulanan belum memuat bagian "advisori yang dinilai tidak relevan".
Kriteria: Praktik baik untuk kontrol 5.7.
Bukti   : TI-BRIEF 2026-07 sampai 2026-09.
```

A adalah kesalahan terisolasi dalam proses yang berjalan; B adalah elemen sistem yang hilang.

### 4.4 Rencana tindakan untuk temuan A

| Unsur | Isi |
|---|---|
| Correction | Alasan klasifikasi INC-2026-044 dilengkapi dari catatan analyst (2026-10-12) |
| Akar masalah | Field alasan di sistem tiket tidak wajib diisi |
| Cek kasus serupa | Seluruh 23 tiket P1/P2 dicek; 2 tiket lain juga kosong |
| Corrective action | Field dibuat wajib untuk P1-P3; QA sampling bulanan menambahkan cek field ini |
| Bukti efektivitas | QA sampling November 2026: 0 tiket tanpa alasan |
| Pemilik dan tenggat | Lead SOC, 2026-11-30 |

Klausul 10.2 meminta organisasi memeriksa apakah nonconformity serupa ada atau bisa terjadi di tempat lain. Dua tiket tambahan yang ditemukan justru bagus dilaporkan, karena menunjukkan pemeriksaan itu sungguh dilakukan.

## 5. Lab praktik

Latihan untuk organisasi fiktifmu. Simpan di `latihan/day13-<nama-org-fiktif>.md`.

1. Buat timeline siklus sertifikasi tiga tahun untuk organisasimu dengan tanggal fiktif. Tandai tanggal keputusan sertifikasi, batas 12 bulan surveillance pertama, dan kapan internal audit dan management review harus selesai sebelum tiap audit eksternal.
2. Susun indeks paket bukti untuk 10 kontrol yang paling dekat dengan SOC (pakai daftar kerja SOC dari Day 08). Untuk tiap kontrol tulis dokumen, rekaman, lokasi, dan pemilik.
3. Tentukan 4 populasi dan rencana sampling seperti bagian 4.2. Hitung ulang cara memilih sampel.
4. Lakukan audit internal mini atas latihanmu sendiri dari Day 04-12. Tulis 3 temuan dengan grading berbeda (minor, major, OFI) memakai struktur kondisi, kriteria, bukti, dan alasan grading.
5. Tulis rencana tindakan lengkap untuk temuan minor, termasuk cek kasus serupa.
6. Tulis 6 pertanyaan yang mungkin diajukan auditor ke analyst L1, beserta jawaban yang jujur dan menunjuk bukti.
7. Hubungkan ke lab:
   - ekspor daftar alert 30 hari terakhir dari Splunk atau Wazuh lab sebagai contoh populasi, lalu catat jumlahnya, tanggal ekspor, dan siapa yang mengekspor;
   - rancang role auditor read-only di SIEM lab: apa yang bisa dilihat, apa yang tidak, dan bagaimana aktivitasnya tercatat.
   Cukup rancangan; membuat role boleh di sesi lab terpisah.

**Hasil yang sebaiknya tersimpan:**
- Timeline yang memenuhi aturan surveillance (12 bulan pertama, minimal sekali per tahun kalender) dan menempatkan internal audit serta management review sebelum audit eksternal.
- Indeks paket bukti 10 kontrol SOC dengan dokumen, rekaman, lokasi, dan pemilik.
- Setiap populasi bisa diekspor, jumlahnya tercatat, dan cara memilih sampelnya dihitung ulang.
- Setiap temuan punya kondisi, kriteria, bukti, dan alasan grading.
- Rencana tindakan membedakan correction dari corrective action dan memuat cek kasus serupa.
- Role auditor read-only tidak memberi akses untuk mengubah atau menghapus data.

**Variasi tantangan:** auditor CB menilai temuan B di bagian 4.3 sebagai minor, sedangkan auditor internal menilainya major. Tulis argumen untuk masing-masing grading memakai definisi di bagian 3.4, lalu putuskan versimu.

## 6. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Tidak bisa membuat daftar lengkap insiden | Insiden tersebar di chat, email, dan tiket | Satu sistem tiket wajib untuk semua insiden; impor data lama |
| Angka di laporan bulanan berbeda dengan sistem | Laporan dibuat manual | Buat laporan dari query yang sama setiap bulan; simpan query-nya |
| Auditor minta akses admin SIEM | Tidak ada role read-only | Siapkan role audit sementara; atau analyst yang mengoperasikan layar |
| Tiket memuat data pribadi pelanggan | Tidak ada praktik masking | Samarkan saat ekspor; tunjukkan hanya field yang relevan |
| Temuan minor berulang di area yang sama | Corrective action tidak menyentuh akar masalah | Ulangi analisis akar masalah; waspadai eskalasi menjadi major |

## 7. Kesalahan umum dan jebakan

- Menyiapkan bukti di hari audit. Paket bukti seharusnya hasil samping operasi rutin.
- Memberi auditor sampel pilihan sendiri. Auditor memilih dari populasi lengkap.
- Berdebat soal grading tanpa memakai definisi. Gunakan definisi major dan minor di 17021-1 [S2].
- Mengabaikan OFI; ia bisa menjadi nonconformity di audit berikutnya.
- Menunjukkan data pelanggan lebih dari yang dibutuhkan.
- Mengarang jawaban saat wawancara.

## 8. Catatan terkini

- ISO/IEC 27006-1:2024 (edisi 1) terbit Maret 2024 dan menggantikan 27006:2015 serta amandemen 2020 [S1].
- ISO 19011:2026 (edisi 4) terbit 27 Mei 2026; edisi 2018 berstatus withdrawn [S5].
- Transisi sertifikat ke 27001:2022 berakhir 31 Oktober 2025. Audit 2026 sepenuhnya memakai edisi 2022 [S8].
- ISO/IEC 17021-1:2015 sedang dalam systematic review; tahap terakhir di katalog ISO adalah close of review (90.60) pada 5 Maret 2026, dan belum ada dokumen pengganti yang disebut [S13]. Definisi major dan minor, aturan surveillance, dan batas 6 bulan di Day ini berasal dari edisi 2015, jadi pantau apakah edisi berikutnya mengubahnya.

## 9. Cheat sheet

```
Audit: first party (internal 9.2) | second party (klien) | third party (CB terakreditasi)
CB tidak boleh audit internal / konsultasi untuk klien yang disertifikasinya (17021-1 5.2; jeda 2 tahun)
Siklus: Tahap 1 (siap? dokumen, scope, IA dan MR sudah jalan?) -> Tahap 2 (efektif?) -> keputusan
        -> SV1 (maks 12 bln dari keputusan) -> SV2 (min. 1x per tahun kalender) -> Resertifikasi thn 3
        surveillance wajib: IA, MR, tindak lanjut NC, keluhan, perubahan, kontrol operasional
Aturan CB: ISO/IEC 17021-1:2015 (umum, sedang direview) + ISO/IEC 27006-1:2024 (ISMS)
Panduan audit: ISO 19011:2026 ed.4 (+ 27007 khusus ISMS)
Sampling: judgement-based (risiko, tidak bisa digeneralisasi) | statistik (acak, ada tingkat keyakinan)
Metode bukti: dokumen | sampling rekaman | wawancara | observasi | verifikasi teknis terbatas
Grading: major (ganggu kemampuan capai hasil; atau minor berulang = sistemik)
           -> CB verifikasi correction + CA sebelum sertifikat; awal: > 6 bln setelah tahap 2 = tahap 2 ulang
         minor (tidak ganggu) -> CB terima rencana, pelaksanaan dicek audit berikut
         observation | OFI (tidak wajib) ; tenggat lain: aturan CB (pola umum 30 hari rencana, 90 hari major)
Temuan = kondisi + kriteria + bukti (+ alasan grading)
SOC siap audit: indeks bukti per kontrol | populasi bisa diekspor | angka konsisten | snapshot konfigurasi
Saat audit: 8.34 akun read-only tercatat | 5.34 minimasi data pribadi | jujur bila tidak tahu
Bukti audit = bisa ditelusuri ; bukti forensik = chain of custody formal (27037)
```

## 10. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | ISO committee: ISO/IEC 27006-1:2024 | https://committee.iso.org/standard/82908.html | primer (katalog ISO) | Maret 2024; diakses 2026-10-10 | Tinggi |
| S2 | ERA terminology collection: major nonconformity (definisi ISO/IEC 17021-1:2015) | https://www.era.europa.eu/era-railway-terminology-collection/majornonconformity/term/international_standard | sekunder (kutipan definisi standar oleh lembaga UE) | diakses 2026-10-10 | Sedang-tinggi. Definisi major |
| S3 | Open Exam Prep: Nonconformity classification framework (materi studi lead auditor) | https://open-exam-prep.com/study-guides/iso-27001-lead-auditor/closing-an-iso-27001-audit-and-nonconformity-management/nonconformity-classification-framework | sekunder (materi studi) | diakses 2026-10-10 | Sedang. Definisi minor, dampak grading |
| S4 | Advisera Expert Advice Community: ISO 27001 and minor non-conformities | https://community.advisera.com/topic/iso-27001-and-minor-non-conformities/ | komunitas (forum tanya-jawab) | 2023-07-20; diakses 2026-10-08 | Rendah-sedang. Praktik pelaporan minor |
| S5 | ISO committee: ISO 19011:2026 | https://committee.iso.org/standard/88984.html | primer (katalog ISO) | 2026-05-27; diakses 2026-10-10 | Tinggi |
| S6 | European Accreditation FAQ: Question CW2017 3 (ISO/IEC 17021-1:2015 klausul 5.2.6) | https://european-accreditation.org/?p=43180 | primer (konsensus badan akreditasi) | jawaban Maret 2018; diakses 2026-10-10 | Tinggi. Larangan audit internal oleh CB |
| S7 | ISMS.online: What happens if you fail an ISO 27001 audit | https://www.isms.online/iso-27001/certification/failed-audit/ | sekunder (vendor) | diakses 2026-10-08 | Rendah-sedang. Pola tenggat 30/90 hari |
| S8 | Konfirmity: ISO 27001 in 2026, what changed | https://www.konfirmity.com/blog/iso-27001-what-changed-in-2026 | sekunder (vendor) | diperbarui 2026-08-31; diakses 2026-10-08 | Sedang. Akhir transisi 31 Okt 2025 |
| S9 | European Accreditation FAQ: Question 37.12 ISO 17021-1:2015 clause 9.1.3 | https://european-accreditation.org/?p=43034 | primer (konsensus badan akreditasi) | jawaban Maret 2019; diakses 2026-10-10 | Tinggi. Surveillance per tahun kalender |
| S10 | European Accreditation FAQ: Question 36.14 Corrections and corrective actions | https://european-accreditation.org/?p=43020 | primer (konsensus badan akreditasi) | jawaban September 2018; diakses 2026-10-10 | Tinggi. Klausul 9.5.3.2, batas 6 bulan |
| S11 | European Accreditation FAQ: Question 44.2 ISO 17021-1 clause 9.1 | https://european-accreditation.org/?p=43110 | primer (konsensus badan akreditasi) | jawaban Maret 2022; diakses 2026-10-10 | Tinggi. Klausul 9.6.2.2, isi surveillance |
| S12 | Open Exam Prep: Surveillance audits, recertification cycle and scope changes | https://open-exam-prep.com/study-guides/iso-27001-lead-auditor/managing-an-iso-27001-audit-program-and-recertification/surveillance-audits-and-recertification-cycle | sekunder (materi studi) | diakses 2026-10-10 | Sedang. Batas 12 bulan, resertifikasi |
| S13 | ISO committee: ISO/IEC 17021-1:2015 | https://committee.iso.org/standard/61651.html | primer (katalog ISO) | Juni 2015; diakses 2026-10-10 | Tinggi |
| S14 | Open Exam Prep: Audit sampling methodologies in ISMS auditing | https://open-exam-prep.com/study-guides/iso-27001-lead-auditor/conducting-an-iso-27001-audit/audit-sampling-methodologies | sekunder (materi studi) | diakses 2026-10-10 | Sedang. Sampling menurut ISO 19011:2018 |

**Catatan sumber:** definisi major dan minor berasal dari kutipan 17021-1:2015 oleh lembaga UE [S2] dan materi studi [S3], bukan dari teks standar; cocokkan dengan teks 17021-1 bila dipakai dalam sengketa grading. Batas 12 bulan surveillance pertama hanya dari materi studi [S12]. Larangan konsultasi oleh CB (klausul 5.2) belum punya sumber terbuka terpisah. Tenggat 30/90 hari bervariasi antar CB.
