---
day: 13
title: 'Audit dan bukti: alur audit internal dan sertifikasi, sampling, grading temuan, dan penyiapan bukti SOC/IR'
researched_on: 2026-10-10
versions_checked: 'ISO/IEC 27001:2022 + Amd 1:2024; ISO/IEC 27006-1:2024 (edisi 1, Mar 2024, menggantikan 27006:2015 + Amd 2020); ISO/IEC 17021-1:2015 (systematic review, 90.60 per 2026-03-05); ISO 19011:2026 (edisi 4, 27 Mei 2026)'
---

# Day 13: Audit dan bukti

Cakupan: jenis audit, siklus sertifikasi tiga tahun, aturan untuk lembaga sertifikasi (ISO/IEC 17021-1 dan 27006-1), metode dan sampling bukti, grading temuan, penulisan temuan, penyiapan paket bukti SOC/IR, proteksi data saat audit, dan sikap analyst saat diwawancarai.

## Ide inti

Audit tidak memeriksa semua pekerjaanmu. Auditor meminta daftar lengkap rekaman, memilih sampel sendiri, lalu menelusuri setiap sampel sampai ke buktinya. Hasilnya ditulis sebagai temuan yang di-grading dengan definisi yang sudah ditetapkan, dan grading itu menentukan apa yang terjadi pada sertifikat. Karena itu kesiapan audit ditentukan jauh sebelum auditor datang: apakah populasi bisa diekspor, apakah setiap tiket tersambung end-to-end, dan apakah angka di laporan cocok dengan sistem sumber.

Banyak analyst SOC pertama kali bersentuhan dengan ISO 27001 saat auditor datang dan meminta "tunjukkan lima insiden terakhir dan bukti penanganannya". Bila daftar lengkap dan bukti yang konsisten bisa diserahkan dalam hitungan menit, audit lancar. Bila buktinya tersebar di chat pribadi, temuan hampir pasti muncul walaupun pekerjaan teknisnya bagus.

Kamu sudah mengenal polanya dari QA tiket di SOC: reviewer mengambil sampel tiket, mencocokkannya dengan SOP, dan menulis finding bila ada langkah yang tidak dijalankan. Audit ISO bekerja dengan cara yang sama, dengan dua tambahan. Auditor eksternal independen dan terakreditasi, dan severity temuannya tidak ditentukan selera: satu tiket yang langkahnya terlewat di proses yang berjalan berbeda kelas dengan proses yang tidak pernah dijalankan sama sekali.

```
Sebelum audit: indeks bukti per kontrol | populasi siap ekspor | angka konsisten | snapshot konfigurasi
  -> auditor memilih sampel dari populasi lengkap
  -> tiap sampel ditelusuri end-to-end (alert -> tiket -> tindakan -> bukti -> PIR/CA)
  -> wawancara dan observasi menguji apakah praktik sesuai prosedur
  -> temuan ditulis: kondisi + kriteria + bukti, lalu di-grading
  -> major: CB memverifikasi correction + CA dulu | minor: CB menerima rencana, cek di audit berikut
  -> rencana tindakan dijalankan (10.2) dan diperiksa lagi di surveillance berikutnya
```

Situasi yang dipakai sepanjang Day ini: ISMS Manager PT Awan Nusantara (PT AN, penyedia hosting fiktif) meneruskan email dari lembaga sertifikasi (CB) ke Lead SOC dengan catatan:

> "Surveillance audit tahun ini sudah dijadwalkan. Seperti waktu sertifikasi awal, auditor akan menghabiskan satu pagi di area SOC. Sebelum hari H mereka minta daftar lengkap insiden P1/P2 sejak audit terakhir, karena sampelnya akan mereka pilih sendiri. Auditor juga ingin melihat SIEM secara langsung dan mewawancarai analyst on-duty. Tolong siapkan, lalu jelaskan ke saya: kalau nanti ada temuan, apa bedanya major dan minor untuk sertifikat kita? Satu lagi, klien bank mengabarkan akan mengaudit kita sesuai kontrak. Apakah itu audit yang sama?"

Pesan itu memuat lima pertanyaan: jenis audit dan isi surveillance (bagian 1.1 dan 1.2), cara auditor memilih sampel dari daftar insiden (bagian 1.3), arti major dan minor serta bentuk temuannya (bagian 1.4 dan 1.5), cara memberi akses SIEM tanpa membuka data berlebihan (bagian 1.6 dan 1.7), dan sikap analyst saat diwawancarai (bagian 1.8).

**Kapan relevan:** audit internal (9.2), audit sertifikasi dan surveillance, audit dari klien (second party), dan due diligence pemasok.
**Kapan bukan jawaban:** Day ini tidak membuatmu menjadi auditor tersertifikasi; kompetensi auditor diatur lembaga sertifikasi personel. Aturan rinci seperti tenggat dan jumlah sampel juga ditetapkan masing-masing CB, sehingga angka di contoh PT AN adalah fiktif dan prosedur CB-mu tetap yang berlaku.

## 1. Konsep inti

### 1.0 Istilah di Day ini

Tabel ini memuat istilah audit yang muncul di Day ini. Audit, bukti, nonconformity, dan lembaga sertifikasi (CB) sudah diperkenalkan di Day 01, sedangkan correction dan corrective action di Day 06, jadi tidak diulang di sini. Kolom padanan memakai analogi SOC yang sama di semua Day.

| Istilah | Arti singkat | Padanan di SOC |
|---|---|---|
| First, second, third party audit | Audit oleh organisasi sendiri, oleh pihak yang berkepentingan seperti klien, atau oleh CB terakreditasi | QA tiket internal, audit dari klien MSSP, assessment independen |
| Imparsialitas (ancaman self-review) | Penilai tidak boleh menilai hasil kerjanya sendiri | Penulis rule tidak meng-QA rule buatannya sendiri |
| Tahap 1 dan tahap 2 | Audit kesiapan dan dokumen, lalu audit efektivitas penerapan | Review desain playbook, lalu uji playbook pada tiket nyata |
| Surveillance | Audit CB minimal sekali per tahun kalender di antara sertifikasi dan resertifikasi | QA berkala setelah proses go-live |
| Resertifikasi | Audit ulang seluruh ISMS di tahun ketiga | Assessment penuh ulang |
| Populasi | Daftar lengkap rekaman tempat auditor memilih sampel | Hasil ekspor seluruh tiket P1/P2 dalam satu periode |
| Sampling berbasis pertimbangan vs statistik | Sampel dipilih dari pengalaman dan risiko vs dipilih acak berbasis probabilitas | Memilih insiden terbesar untuk QA vs sampel acak dari ribuan alert |
| Sampling risk | Kemungkinan kesimpulan dari sampel berbeda dengan kesimpulan bila seluruh populasi diperiksa | Lima tiket yang di-QA lolos, padahal tiket keenam bermasalah |
| Major dan minor nonconformity | Nonconformity yang memengaruhi atau tidak memengaruhi kemampuan sistem manajemen mencapai hasil yang diharapkan | Proses yang tidak pernah dijalankan vs satu langkah terlewat di proses yang berjalan |
| Observation dan OFI | Potensi nonconformity; saran perbaikan yang tidak wajib | Catatan QA "perlu diperhatikan" dan saran tuning |
| Kondisi, kriteria, bukti | Tiga unsur temuan yang baik | Finding QA: apa yang terjadi, SOP mana yang dirujuk, tiket mana buktinya |
| Paket bukti | Indeks bukti per kontrol, populasi, dan snapshot yang disiapkan sebelum audit | Evidence folder per kasus yang sudah rapi sebelum diminta |
| Chain of custody | Catatan formal siapa memegang bukti forensik, kapan, dan bagaimana integritasnya dijaga | Formulir chain of custody di DFIR |

### 1.1 Jenis audit

Pertanyaan terakhir ISMS Manager ("apakah audit klien bank itu audit yang sama?") dijawab dengan melihat siapa yang mengaudit. Surveillance dari CB dan audit dari klien bank memakai teknik yang mirip, tetapi kedudukannya berbeda.

Tabel berikut membedakan tiga jenis audit berdasarkan auditornya. Cari kolom "Siapa mengaudit" untuk menempatkan setiap permintaan audit yang datang.

| Jenis | Siapa mengaudit | Contoh |
|---|---|---|
| First party (internal) | Organisasi sendiri atau pihak yang ditunjuknya | Internal audit 9.2 (Day 06) |
| Second party | Pihak yang punya kepentingan, misalnya klien | Klien perbankan mengaudit PT AN sesuai kontrak |
| Third party | Lembaga sertifikasi (CB) independen yang terakreditasi | Audit sertifikasi ISO 27001 |

CB tidak boleh menjalankan audit internal untuk klien yang disertifikasinya. Alasannya imparsialitas: CB akan menilai hasil kerjanya sendiri saat audit sertifikasi (ancaman self-review). Menurut konsensus badan akreditasi Eropa (EA) atas ISO/IEC 17021-1:2015 klausul 5.2.6, CB boleh mengaudit internal organisasi yang tidak ia sertifikasi, tetapi perlu jeda sekitar dua tahun sebelum CB itu menyertifikasinya [S6]. Klausul 5.2 juga melarang CB memberi konsultasi sistem manajemen. Konsultan independen yang bukan bagian dari CB tetap boleh menjalankan audit internal.

### 1.2 Siklus sertifikasi tiga tahun

ISMS Manager menyebut "seperti waktu sertifikasi awal". Sertifikasi awal dan surveillance adalah dua titik di siklus yang sama, dan isi pemeriksaannya berbeda.

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

Untuk surveillance PT AN, artinya auditor akan melihat hasil audit internal, notulen management review terakhir, dan tindak lanjut temuan sebelumnya, bukan hanya dokumen kebijakan.

Aturan siklus ini datang dari dua dokumen untuk CB. ISO/IEC 17021-1:2015 berisi persyaratan umum untuk lembaga yang mengaudit dan menyertifikasi sistem manajemen apa pun [S13]. ISO/IEC 27006-1:2024 berisi tambahan khusus ISMS, misalnya kompetensi auditor ISMS dan cara menghitung durasi audit [S1]. Artinya, aturan main CB bukan karangan auditor perorangan, dan CB sendiri diperiksa badan akreditasi terhadap aturan itu. Status edisi kedua dokumen ada di bagian 6.

### 1.3 Metode dan sampling bukti

Auditor meminta "daftar lengkap insiden P1/P2 sejak audit terakhir" karena ia akan memilih sampel sendiri dari daftar itu. Sebelum membahas sampling, kenali dulu cara auditor mengumpulkan bukti:

- **tinjauan dokumen:** kebijakan, prosedur, SoA;
- **sampling rekaman:** tiket, log, laporan;
- **wawancara:** analyst, Lead SOC, pimpinan;
- **observasi:** melihat analyst melakukan triage, atau melihat ruang SOC;
- **verifikasi teknis terbatas:** meminta ditunjukkan konfigurasi retensi atau daftar role.

Auditor tidak memeriksa semua rekaman. Ia mengambil sampel dari populasi. Panduan audit sistem manajemen ISO 19011 (edisi 2018, Annex A) membedakan dua pendekatan [S14]:

- **sampling berbasis pertimbangan (judgement-based):** sampel dipilih dari pengalaman auditor dan area berisiko, misalnya insiden terbesar atau rule yang paling sering diubah. Hasilnya tidak bisa dinyatakan sebagai estimasi statistik untuk seluruh populasi.
- **sampling statistik:** sampel dipilih acak berbasis probabilitas, sehingga kesimpulan bisa digeneralisasi dengan tingkat keyakinan tertentu. Cocok untuk populasi besar yang seragam, misalnya ribuan tiket alert.

Keduanya membawa sampling risk, yaitu kemungkinan kesimpulan dari sampel berbeda dengan kesimpulan bila seluruh populasi diperiksa. Satu pengecualian di sampel biasanya membuat auditor memperluas sampel atau menelusuri penyebabnya [S14]. Edisi 2018 sudah digantikan edisi 2026; apakah panduan sampling ini ikut berubah perlu dicek di teks edisi 2026 (bagian 6).

Konsekuensi untuk SOC:

1. **Populasi harus lengkap dan bisa diekspor.** Auditor meminta daftar lengkap ("semua insiden P1 dan P2 sejak audit terakhir") lalu memilih sendiri.
2. **Setiap sampel harus bisa ditelusuri end-to-end.** Satu tiket harus tersambung ke alert, keputusan klasifikasi, tindakan, bukti, dan bila perlu PIR serta CA.
3. **Konsistensi antar sumber diuji.** Jumlah insiden di laporan bulanan harus cocok dengan jumlah tiket di sistem.

### 1.4 Grading temuan

Pertanyaan ISMS Manager "apa bedanya major dan minor untuk sertifikat kita?" dijawab oleh definisi, bukan oleh perasaan auditor. Padanannya severity finding QA: satu tiket yang langkahnya terlewat berbeda kelas dengan proses QA yang tidak pernah dijalankan.

Tabel berikut adalah lima kemungkinan hasil penilaian. Perhatikan kolom "Dampak": di sanalah major dan minor berbeda untuk sertifikat.

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

### 1.5 Menulis temuan yang baik

Temuan yang akan diterima PT AN, dan temuan yang kamu tulis sendiri saat audit internal, harus bisa diperiksa ulang oleh orang lain. Itu hanya mungkin bila temuannya punya tiga unsur:

- **Kondisi:** apa yang ditemukan, secara faktual dan spesifik.
- **Kriteria:** persyaratan yang dirujuk (klausul, kontrol di SoA, atau prosedur internal).
- **Bukti:** dokumen, rekaman, atau wawancara yang menunjukkan kondisi itu.

Temuan yang buruk: "Logging tidak memadai."
Temuan yang baik: "Dari 5 server in-scope yang disampel, 2 (db-07 dan app-12) tidak mengirim log ke SIEM sejak 2026-07-14. Standar STD-LOG-01 butir 1 mewajibkan semua server in-scope mengirim log, dan kontrol 8.15 dinyatakan diterapkan di SoA v1.1. Bukti: hasil query cakupan log tanggal 2026-09-30 dan wawancara dengan Lead SOC."

Versi kedua menyebut sampel dan jumlahnya, persyaratan yang dilanggar, dan bukti yang bisa dibuka lagi. Versi pertama hanya opini.

### 1.6 Menyiapkan bukti SOC dan IR

Permintaan daftar insiden dan akses SIEM baru terasa ringan bila bukti sudah disiapkan sebagai hasil samping operasi rutin. Paket bukti yang disiapkan sebelum audit berisi:

- **Indeks bukti per kontrol:** kontrol, dokumen, rekaman, lokasi, dan pemilik.
- **Populasi siap ekspor:** daftar insiden, alert, perubahan rule, sumber log, akun dengan hak istimewa.
- **Konsistensi angka:** laporan bulanan dicocokkan dengan sistem sumber sebelum audit.
- **Snapshot konfigurasi:** retensi, role, dan sumber waktu, lengkap dengan tanggal pengambilan.

Saat audit, ada dua hal yang sering terlupa. Keduanya menjawab permintaan auditor untuk "melihat SIEM secara langsung":

1. **Proteksi sistem saat audit (kontrol 8.34).** Bila auditor perlu melihat SIEM, beri akun read-only yang sementara dan tercatat, atau tunjukkan layar lewat analyst. Jangan beri akun admin.
2. **Minimasi data pribadi (5.34, UU PDP).** Tiket insiden bisa memuat data pelanggan. Tunjukkan yang perlu saja dan samarkan bila bisa, walaupun auditor terikat kerahasiaan.

### 1.7 Chain of custody untuk bukti audit dan forensik

Bila salah satu tiket yang dipilih auditor melibatkan akuisisi forensik, Lead SOC perlu tahu apa yang sebenarnya akan diperiksa. Bukti audit dan bukti forensik punya standar ketelusuran yang berbeda.

Bukti audit cukup bisa ditelusuri: dari mana diambil, kapan, oleh siapa, dan versi berapa, misalnya ekspor CSV tiket dengan tanggal dan nama pengambil. Bukti forensik butuh chain of custody formal: hash, serah terima tercatat, dan penyimpanan dengan akses terbatas (ISO/IEC 27037, Day 10). Untuk insiden dengan bukti forensik, auditor biasanya hanya memeriksa bahwa formulir chain of custody ada dan terisi, bukan membuka image disk-nya.

### 1.8 Sikap saat diwawancarai

Analyst on-duty yang diwawancarai auditor tidak sedang diuji hafalan klausul. Auditor menguji apakah praktik sesuai prosedur, dan jawaban analyst adalah salah satu buktinya.

- Jawab yang ditanyakan, dengan fakta, dan tunjukkan buktinya ("saya tunjukkan tiketnya").
- Bila tidak tahu, katakan tidak tahu dan sebutkan siapa yang tahu atau kapan kamu bisa menyusulkan. Mengarang jawaban lebih berbahaya daripada mengaku tidak tahu.
- Jelaskan pekerjaan sesuai prosedur yang berlaku. Bila praktik berbeda dari prosedur, sampaikan jujur.

## 2. Contoh dokumen / artefak (organisasi fiktif)

Organisasi fiktif: PT Awan Nusantara (PT AN). Semua angka adalah ilustrasi. Keempat artefak ini adalah bahan yang disiapkan Lead SOC untuk menjawab pesan ISMS Manager di bagian Ide inti.

### 2.1 Agenda audit tahap 2 untuk area SOC (cuplikan)

Lead SOC membuka kembali agenda tahap 2 area SOC dari sertifikasi awal sebagai gambaran pagi yang akan dihabiskan auditor di SOC. Baca kolom Kriteria: itulah kontrol dan prosedur yang buktinya harus siap.

| Waktu | Area | Auditee | Kriteria |
|---|---|---|---|
| 09.00-09.45 | Proses insiden: kriteria, sampel 5 tiket P1/P2 | Incident manager, Lead SOC | 5.24-5.28, prosedur IR v2 |
| 09.45-10.30 | Logging dan monitoring: cakupan, retensi, peran admin | Lead SOC, SIEM admin | 8.15-8.17, STD-LOG-01 |
| 10.30-11.00 | Threat intelligence dan kerentanan: brief, SLA | Lead SOC, Head of Platform | 5.7, 8.8 |
| 11.00-11.20 | Wawancara analyst on-duty: awareness dan triage | Analyst L1 | 7.3, 5.25 |
| 11.20-11.40 | Kompetensi tim SOC | Lead SOC, HR | 7.2 |

### 2.2 Rencana sampling internal (aturan fiktif PT AN untuk audit internal)

Sebelum CB datang, PT AN menguji dirinya sendiri dengan cara yang sama seperti auditor: menyusun populasi lalu memilih sampel. Baca kolom "Cara memilih" untuk melihat campuran sampling berbasis pertimbangan dan acak.

| Populasi | Ukuran populasi | Sampel | Cara memilih | Yang dicek di tiap sampel |
|---|---|---|---|---|
| Insiden P1/P2 Jan-Sep 2026 | 23 | 5 | Pertimbangan: 2 terbesar, 3 acak | Klasifikasi, timeline, bukti, PIR |
| Perubahan rule deteksi | 140 | 10 | Setiap urutan ke-14 dari daftar yang diurutkan berdasarkan tanggal | Tiket, review, persetujuan |
| Server in-scope | 50 | 5 | Acak | Log ada di SIEM 24 jam terakhir; waktu sinkron |
| Analyst SOC | 9 | 3 | Satu per shift | Wawancara 7.3; bukti kompetensi 7.2 |

Pada baris perubahan rule, 140 / 10 = 14, jadi memilih setiap urutan ke-14 menghasilkan tepat 10 sampel. Aturan jumlah sampel di tabel ini adalah aturan internal fiktif. CB punya aturannya sendiri.

### 2.3 Contoh temuan dengan grading berbeda

Tiga contoh berikut menjawab pertanyaan major dan minor dari ISMS Manager dengan kasus konkret. Bandingkan baris "Alasan grading" di temuan A dan B.

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

### 2.4 Rencana tindakan untuk temuan A

Temuan minor tetap butuh rencana yang diterima CB dan dijalankan sebelum audit berikutnya. Baris "Cek kasus serupa" adalah bagian yang paling sering dilewati.

| Unsur | Isi |
|---|---|
| Correction | Alasan klasifikasi INC-2026-044 dilengkapi dari catatan analyst (2026-10-12) |
| Akar masalah | Field alasan di sistem tiket tidak wajib diisi |
| Cek kasus serupa | Seluruh 23 tiket P1/P2 dicek; 2 tiket lain juga kosong |
| Corrective action | Field dibuat wajib untuk P1-P3; QA sampling bulanan menambahkan cek field ini |
| Bukti efektivitas | QA sampling November 2026: 0 tiket tanpa alasan |
| Pemilik dan tenggat | Lead SOC, 2026-11-30 |

Klausul 10.2 meminta organisasi memeriksa apakah nonconformity serupa ada atau bisa terjadi di tempat lain. Dua tiket tambahan yang ditemukan justru bagus dilaporkan, karena menunjukkan pemeriksaan itu sungguh dilakukan.

## 3. Lab praktik

Latihan untuk organisasi fiktifmu. Simpan di `latihan/day13-<nama-org-fiktif>.md`.

1. Buat timeline siklus sertifikasi tiga tahun untuk organisasimu dengan tanggal fiktif. Tandai tanggal keputusan sertifikasi, batas 12 bulan surveillance pertama, dan kapan internal audit dan management review harus selesai sebelum tiap audit eksternal.
2. Susun indeks paket bukti untuk 10 kontrol yang paling dekat dengan SOC (pakai daftar kerja SOC dari Day 08). Untuk tiap kontrol tulis dokumen, rekaman, lokasi, dan pemilik.
3. Tentukan 4 populasi dan rencana sampling seperti bagian 2.2. Hitung ulang cara memilih sampel.
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

**Variasi tantangan:** auditor CB menilai temuan B di bagian 2.3 sebagai minor, sedangkan auditor internal menilainya major. Tulis argumen untuk masing-masing grading memakai definisi di bagian 1.4, lalu putuskan versimu.

## 4. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Tidak bisa membuat daftar lengkap insiden | Insiden tersebar di chat, email, dan tiket | Satu sistem tiket wajib untuk semua insiden; impor data lama |
| Angka di laporan bulanan berbeda dengan sistem | Laporan dibuat manual | Buat laporan dari query yang sama setiap bulan; simpan query-nya |
| Auditor minta akses admin SIEM | Tidak ada role read-only | Siapkan role audit sementara; atau analyst yang mengoperasikan layar |
| Tiket memuat data pribadi pelanggan | Tidak ada praktik masking | Samarkan saat ekspor; tunjukkan hanya field yang relevan |
| Temuan minor berulang di area yang sama | Corrective action tidak menyentuh akar masalah | Ulangi analisis akar masalah; waspadai eskalasi menjadi major |

## 5. Kesalahan umum dan jebakan

- Menyiapkan bukti di hari audit. Paket bukti seharusnya hasil samping operasi rutin.
- Memberi auditor sampel pilihan sendiri. Auditor memilih dari populasi lengkap.
- Berdebat soal grading tanpa memakai definisi. Gunakan definisi major dan minor di 17021-1 [S2].
- Mengabaikan OFI; ia bisa menjadi nonconformity di audit berikutnya.
- Menunjukkan data pelanggan lebih dari yang dibutuhkan.
- Mengarang jawaban saat wawancara.

## 6. Catatan terkini

Bagian ini menampung status edisi dokumen audit dan aturan CB. Berguna saat memilih rujukan atau membaca prosedur CB yang lama.

- ISO/IEC 27006-1:2024 (edisi 1) terbit Maret 2024 dan menggantikan 27006:2015 serta amandemen 2020 [S1].
- ISO 19011:2026 (edisi 4) terbit 27 Mei 2026; edisi 2018 berstatus withdrawn [S5]. Panduan sampling di bagian 1.3 bersumber dari Annex A edisi 2018; apakah panduan itu ikut berubah perlu dicek di teks edisi 2026.
- Transisi sertifikat ke 27001:2022 berakhir 31 Oktober 2025. Audit 2026 sepenuhnya memakai edisi 2022 [S8].
- ISO/IEC 17021-1:2015 sedang dalam systematic review; tahap terakhir di katalog ISO adalah close of review (90.60) pada 5 Maret 2026, dan belum ada dokumen pengganti yang disebut [S13]. Definisi major dan minor, aturan surveillance, dan batas 6 bulan di Day ini berasal dari edisi 2015, jadi pantau apakah edisi berikutnya mengubahnya.

## 7. Cheat sheet

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

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** Saat surveillance, auditor CB menemukan 1 dari 5 tiket P2 yang disampel tidak memuat alasan klasifikasi. Empat tiket lainnya lengkap. Apakah sertifikat PT AN otomatis tertahan?

<details><summary>Jawaban</summary>

Tidak. Kasus tunggal dalam proses yang berjalan biasanya di-grading minor, karena tidak memengaruhi kemampuan ISMS mencapai hasil yang diharapkan. Untuk minor, CB meninjau dan menerima rencana correction dan corrective action, lalu pelaksanaannya diperiksa pada audit berikutnya. Sertifikat tertahan bila temuannya major, misalnya ada keraguan signifikan bahwa pengendalian proses efektif, atau beberapa minor pada persyaratan yang sama menunjukkan kegagalan sistemik. Bila pola yang sama ternyata berulang, grading-nya bisa naik. Lihat bagian 1.4 dan 2.3.

</details>

**2. Skenario keputusan.** Auditor meminta daftar insiden P1/P2 sejak audit terakhir. Seorang analyst mengusulkan cara yang menurutnya paling aman. Mana yang tepat?

- A. Serahkan lima tiket yang dokumentasinya paling rapi, supaya kesan pertama auditor baik.
- B. Serahkan daftar lengkap hasil ekspor dari sistem tiket, dengan jumlah dan tanggal ekspor tercatat, lalu biarkan auditor memilih sampelnya.
- C. Serahkan ekspor seluruh isi tiket, termasuk data pelanggan, supaya auditor tidak perlu meminta lagi.

<details><summary>Jawaban</summary>

B. Auditor memilih sampel dari populasi yang lengkap, dan populasi itu harus bisa diekspor serta jumlahnya cocok dengan laporan bulanan. A keliru karena memberi auditor sampel pilihan sendiri merusak dasar sampling dan termasuk kesalahan umum yang dicatat di Day ini. C keliru karena yang diminta adalah daftar untuk memilih sampel; isi tiket ditunjukkan sebatas yang perlu, dan data pribadi pelanggan disamarkan bila bisa (5.34). Lihat bagian 1.3, 1.6, dan 5.

</details>

**3. Pertanyaan jebakan.** "Sertifikat kita sudah terbit. Surveillance cukup dijawab dengan kebijakan dan SoA versi terbaru." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Surveillance memang hanya mencakup sebagian ISMS, tetapi setiap kunjungan wajib memeriksa audit internal, management review, tindak lanjut temuan, keluhan, perubahan, dan pengendalian operasional. Surveillance yang hanya memeriksa dokumen tidak memenuhi 17021-1. Untuk PT AN, itu berarti hasil audit internal, notulen management review, dan tindak lanjut temuan sebelumnya harus siap. Lihat bagian 1.2.

</details>

**4. Skenario keputusan.** Sebuah organisasi menjalani sertifikasi awal. Hari terakhir tahap 2 jatuh pada 1 Maret, dengan satu major nonconformity. CB baru bisa memverifikasi correction dan corrective action-nya pada 15 September. Apa yang terjadi?

- A. Sertifikat langsung terbit, karena corrective action sudah selesai.
- B. CB harus menjalankan tahap 2 ulang sebelum merekomendasikan sertifikasi.
- C. Tergantung tenggat 90 hari milik CB; batas lain tidak berlaku.

<details><summary>Jawaban</summary>

B. Menurut 17021-1, bila CB tidak bisa memverifikasi pelaksanaan correction dan corrective action untuk major dalam 6 bulan setelah hari terakhir tahap 2, CB harus menjalankan tahap 2 ulang. Dari 1 Maret ke 15 September lebih dari 6 bulan. A keliru karena selesainya tindakan tidak menghapus batas waktu verifikasi. C keliru karena pola 30/90 hari adalah aturan masing-masing CB yang berlaku di dalam batas 6 bulan itu, bukan penggantinya. Lihat bagian 1.4.

</details>

**5. Pertanyaan jebakan.** "Auditor terikat perjanjian kerahasiaan, jadi tiket insiden boleh ditunjukkan utuh, dan akun admin SIEM boleh dipinjamkan supaya auditor bisa mencari sendiri." Benarkah?

<details><summary>Jawaban</summary>

Tidak, dua-duanya keliru. Kontrol 8.34 meminta sistem dilindungi selama audit: beri akun read-only yang sementara dan tercatat, atau tunjukkan layar lewat analyst, dan jangan beri akun admin. Minimasi data pribadi (5.34 dan UU PDP) tetap berlaku walaupun auditor terikat kerahasiaan, jadi tunjukkan yang perlu saja dan samarkan bila bisa. Lihat bagian 1.6.

</details>

**6. Jelaskan ulang.** Seorang auditor internal baru menulis temuan "Logging tidak memadai." Tulis ulang menjadi temuan yang baik untuk kasus fiktif pilihanmu, lalu jelaskan dalam dua kalimat kenapa versi barumu lebih kuat.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Dari 5 server in-scope yang disampel, 2 tidak mengirim log ke SIEM sejak tanggal tertentu. Standar logging internal mewajibkan semua server in-scope mengirim log, dan kontrol 8.15 dinyatakan diterapkan di SoA. Bukti: hasil query cakupan log pada tanggal pemeriksaan dan wawancara dengan Lead SOC." Versi ini lebih kuat karena menyebut kondisi yang spesifik (sampel, jumlah, nama host, sejak kapan), kriteria yang dilanggar, dan bukti yang bisa dibuka lagi oleh orang lain. Versi lama hanya opini yang tidak bisa diperiksa ulang.

Kesalahan yang sering muncul:
- Menulis kondisi tanpa angka atau sampel, misalnya "beberapa server tidak mengirim log".
- Tidak menyebut kriteria, sehingga tidak jelas persyaratan mana yang tidak dipenuhi.
- Menyebut bukti yang tidak bisa dibuka ulang, misalnya "berdasarkan pengamatan auditor".
- Mencampur rekomendasi perbaikan ke dalam kondisi.

</details>

**7. Interview question (English).** "An auditor asks you to show the last five incidents and how they were handled. How do you prepare and respond?"

<details><summary>Sample answer</summary>

"I wouldn't pick five tickets myself. I'd provide the complete population, for example all P1 and P2 incidents since the last audit, exported from the ticketing system with the count and export date recorded, and let the auditor choose the sample. Each sampled ticket should trace end to end: the alert, the classification decision, the actions taken, the evidence, and where relevant the post-incident review and corrective action. Before the audit I'd check that the numbers in our monthly report match the ticketing system. If the auditor wants to see the SIEM, I'd give a temporary, logged read-only account or drive the screen myself, and I'd mask customer personal data that isn't needed. If I'm asked something I don't know, I say so and name who does."

What makes this answer strong: it shows that the auditor samples from a complete population, describes end-to-end traceability, and covers protecting systems and personal data during the audit, ending with honesty in interviews.

</details>

## 9. Sumber

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
