---
day: 13
title: 'Audit dan bukti: alur audit internal dan sertifikasi, sampling, grading temuan, dan penyiapan bukti SOC/IR'
researched_on: 2026-10-10
versions_checked: 'ISO/IEC 27001:2022 + Amd 1:2024; ISO/IEC 27006-1:2024 (edisi 1, Mar 2024, menggantikan 27006:2015 + Amd 2020); ISO/IEC 17021-1:2015; ISO 19011:2026 (edisi 4)'
---

# Day 13: Audit dan bukti

> Catatan pribadi, bukan materi resmi ISO, dan bukan nasihat hukum atau audit. Aturan rinci (tenggat, jumlah sampel) ditetapkan masing-masing lembaga sertifikasi; angka di contoh PT AN adalah fiktif.

Cakupan: jenis audit, siklus sertifikasi tiga tahun, aturan untuk lembaga sertifikasi (ISO/IEC 17021-1 dan 27006-1), metode dan sampling bukti, grading temuan, penulisan temuan, penyiapan paket bukti SOC/IR, proteksi data saat audit, dan sikap analyst saat diwawancarai.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- menjelaskan siklus sertifikasi (tahap 1, tahap 2, surveillance, resertifikasi) dan dokumen yang mengatur lembaga sertifikasi.
- membedakan conformity, nonconformity major dan minor, observation, serta opportunity for improvement.
- menulis temuan audit dengan struktur kondisi, kriteria, dan bukti.
- menyusun populasi dan rencana sampling untuk proses SOC, serta paket bukti yang bisa diserahkan dengan cepat.
- menjaga integritas bukti dan data pribadi selama audit, dan bersikap profesional saat diwawancarai.

## 2. Konteks singkat

Banyak analyst SOC pertama kali bersentuhan dengan ISO 27001 saat auditor datang dan meminta "tunjukkan lima insiden terakhir dan bukti penanganannya". Bila SOC bisa menyerahkan daftar lengkap, sampel yang diminta, dan bukti yang konsisten dalam hitungan menit, audit berjalan lancar. Bila daftar tidak lengkap atau buktinya tersebar di chat pribadi, temuan hampir pasti muncul, walaupun pekerjaan teknisnya sebenarnya bagus.

Kapan dipakai: audit internal (9.2), audit sertifikasi dan surveillance, audit dari klien (second party), dan due diligence pemasok.
Kapan tidak cukup: Day ini tidak membuatmu menjadi auditor tersertifikasi. Kompetensi auditor diatur terpisah, misalnya oleh lembaga sertifikasi personel.

## 3. Konsep inti

### 3.1 Jenis audit

| Jenis | Siapa mengaudit | Contoh |
|---|---|---|
| First party (internal) | Organisasi sendiri atau pihak yang ditunjuknya | Internal audit 9.2 (Day 06) |
| Second party | Pihak yang punya kepentingan, misalnya klien | Klien perbankan mengaudit PT AN sesuai kontrak |
| Third party | Lembaga sertifikasi (CB) independen yang terakreditasi | Audit sertifikasi ISO 27001 |

Lembaga sertifikasi tidak boleh menjadi internal auditor kliennya, karena aturan imparsialitas [S6].

### 3.2 Siklus sertifikasi tiga tahun

```
Tahun 0: Tahap 1 (kesiapan, dokumen, scope) -> Tahap 2 (efektivitas penerapan) -> keputusan sertifikasi
Tahun 1: Surveillance audit
Tahun 2: Surveillance audit
Tahun 3: Resertifikasi (sebelum sertifikat habis) -> siklus baru
```

- **Tahap 1** menilai apakah ISMS siap diaudit: scope, kebijakan, metodologi risiko, SoA, bukti audit internal dan management review, serta pemahaman organisasi atas persyaratan. Hasilnya bisa berupa daftar hal yang harus diselesaikan sebelum tahap 2.
- **Tahap 2** menilai apakah ISMS benar-benar diterapkan dan efektif. Di sinilah sampling tiket, wawancara analyst, dan observasi dilakukan.
- **Surveillance** biasanya tahunan dan mencakup sebagian ISMS, ditambah area wajib seperti internal audit, management review, dan tindak lanjut temuan sebelumnya.
- **Resertifikasi** menilai ulang seluruh ISMS sebelum sertifikat tiga tahunnya habis.

Aturan untuk CB ada di dua dokumen. ISO/IEC 17021-1 berisi persyaratan umum untuk lembaga yang mengaudit dan menyertifikasi sistem manajemen apa pun. ISO/IEC 27006-1:2024 (edisi 1, Maret 2024) berisi tambahan khusus ISMS dan menggantikan ISO/IEC 27006:2015 beserta amandemen 2020 [S1]. Untuk audit sertifikasi, kedua dokumen ini menentukan kompetensi auditor, durasi audit, dan cara menangani temuan. Organisasi tidak perlu membaca keduanya secara rinci, tetapi perlu tahu bahwa aturan main CB bukan karangan auditor perorangan.

### 3.3 Metode dan sampling bukti

Auditor mengumpulkan bukti dengan beberapa metode:

- **tinjauan dokumen:** kebijakan, prosedur, SoA;
- **sampling rekaman:** tiket, log, laporan;
- **wawancara:** analyst, Lead SOC, pimpinan;
- **observasi:** melihat analyst melakukan triage, atau melihat ruang SOC;
- **verifikasi teknis terbatas:** meminta ditunjukkan konfigurasi retensi atau daftar role.

Auditor tidak memeriksa semua rekaman. Ia mengambil sampel dari populasi. Panduan audit sistem manajemen (ISO 19011) membahas sampling berbasis pertimbangan dan sampling statistik. Edisi terbarunya, 19011:2026, terbit Mei 2026 [S5]. Cek isi bagian sampling di edisi 2026.

Konsekuensi untuk SOC:

1. **Populasi harus lengkap dan bisa diekspor.** Auditor biasanya meminta daftar lengkap ("semua insiden P1 dan P2 sejak audit terakhir") lalu memilih sendiri. Bila daftar tidak bisa dibuat, auditor tidak yakin sampelnya representatif.
2. **Setiap sampel harus bisa ditelusuri end-to-end.** Satu tiket harus tersambung ke alert, keputusan klasifikasi, tindakan, bukti, dan bila perlu PIR serta CA.
3. **Konsistensi antar sumber diuji.** Jumlah insiden di laporan bulanan harus cocok dengan jumlah tiket di sistem.

### 3.4 Grading temuan

| Grading | Arti | Dampak |
|---|---|---|
| Conformity | Persyaratan terpenuhi | Tidak ada tindakan |
| Major nonconformity | Nonconformity yang memengaruhi kemampuan sistem manajemen mencapai hasil yang diharapkan [S2] | Sertifikasi atau resertifikasi tertahan sampai diselesaikan dan diverifikasi [S3] |
| Minor nonconformity | Nonconformity yang tidak memengaruhi kemampuan tersebut [S3] | Organisasi menyerahkan rencana koreksi dan corrective action; efektivitasnya dicek pada audit berikutnya [S4] |
| Observation | Bukan nonconformity, tetapi berpotensi menjadi nonconformity | Disarankan ditindaklanjuti |
| Opportunity for improvement (OFI) | Saran perbaikan | Tidak wajib |

Dua kondisi yang biasanya membuat temuan menjadi major [S2]:

- ada keraguan signifikan bahwa pengendalian proses efektif;
- beberapa minor nonconformity pada persyaratan yang sama menunjukkan kegagalan sistemik.

Contoh major yang sering disebut: tidak ada internal audit sama sekali, atau risk assessment hanya ada di kertas [S7].

Tenggat ditetapkan oleh masing-masing CB. Pola yang sering dilaporkan adalah rencana tindakan dalam sekitar 30 hari, dan penyelesaian major dalam sekitar 90 hari dengan verifikasi [S7]. Untuk minor, hasil penanganannya biasanya diperiksa pada audit berikutnya, tetapi organisasi sebaiknya mengonfirmasi prosedurnya langsung ke CB [S4]. Cek tenggat di aturan CB yang mengaudit organisasimu.

Istilah observation dan OFI tidak seragam antar CB. Sebagian CB hanya memakai satu dari keduanya.

### 3.5 Menulis temuan yang baik

Temuan yang baik punya tiga unsur:

- **Kondisi:** apa yang ditemukan, secara faktual dan spesifik.
- **Kriteria:** persyaratan yang dirujuk (klausul, kontrol di SoA, atau prosedur internal).
- **Bukti:** dokumen, rekaman, atau wawancara yang menunjukkan kondisi itu.

Temuan yang buruk: "Logging tidak memadai."
Temuan yang baik: "Dari 5 server in-scope yang diambil sampelnya, 2 (db-07 dan app-12) tidak mengirim log ke SIEM sejak 2026-07-14. Standar STD-LOG-01 butir 1 mewajibkan semua server in-scope mengirim log, dan kontrol 8.15 dinyatakan diterapkan di SoA v1.1. Bukti: hasil query cakupan log tanggal 2026-09-30 dan wawancara dengan Lead SOC."

Temuan yang baik memudahkan auditee mencari akar masalah, dan mencegah perdebatan soal "apa sebenarnya masalahnya".

### 3.6 Menyiapkan bukti SOC dan IR

Paket bukti yang disiapkan sebelum audit menghemat waktu dan mengurangi kepanikan. Isinya:

- **Indeks bukti per kontrol:** kontrol, dokumen, rekaman, lokasi, dan pemilik.
- **Populasi siap ekspor:** daftar insiden, alert, perubahan rule, sumber log, akun dengan hak istimewa.
- **Konsistensi angka:** laporan bulanan dicocokkan dengan sistem sumber sebelum audit.
- **Snapshot konfigurasi:** retensi, role, dan sumber waktu, lengkap dengan tanggal pengambilan.

Saat audit, ada dua hal yang sering terlupa:

1. **Proteksi sistem saat audit (kontrol 8.34).** Bila auditor perlu melihat SIEM, beri akun read-only yang sementara dan tercatat, atau tunjukkan layar lewat analyst. Jangan beri akun admin.
2. **Minimasi data pribadi (5.34, UU PDP).** Tiket insiden bisa memuat data pelanggan. Tunjukkan yang perlu saja, dan samarkan bila bisa. Auditor juga terikat kerahasiaan, tetapi prinsip minimasi tetap berlaku.

### 3.7 Chain of custody untuk bukti audit dan forensik

Kedua istilah ini sering dicampur:

- **Bukti audit** cukup bisa ditelusuri: dari mana diambil, kapan, oleh siapa, dan versi berapa. Contohnya ekspor CSV tiket dengan tanggal dan nama pengambil.
- **Bukti forensik** butuh chain of custody formal: hash, serah terima tercatat, dan penyimpanan terkendali (ISO/IEC 27037, Day 10).

Bila sebuah insiden yang diaudit punya bukti forensik, auditor biasanya hanya memeriksa bahwa formulir chain of custody ada dan terisi. Auditor tidak akan membuka image disk-nya.

### 3.8 Sikap saat diwawancarai

- Jawab yang ditanyakan, dengan fakta, dan tunjukkan buktinya ("saya tunjukkan tiketnya").
- Bila tidak tahu, katakan tidak tahu dan sebutkan siapa yang tahu atau kapan kamu bisa menyusulkan. Mengarang jawaban lebih berbahaya daripada mengaku tidak tahu.
- Jangan berspekulasi tentang area di luar tanggung jawabmu.
- Jelaskan pekerjaan sesuai prosedur yang berlaku. Bila praktik berbeda dari prosedur, sampaikan jujur. Perbedaan itu lebih baik ditemukan dan diperbaiki daripada disembunyikan.

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

Perhatikan perbedaan B dan A. A adalah kesalahan terisolasi dalam proses yang berjalan, sedangkan B adalah elemen sistem yang hilang.

### 4.4 Rencana tindakan untuk temuan A

| Unsur | Isi |
|---|---|
| Correction | Alasan klasifikasi INC-2026-044 dilengkapi dari catatan analyst (2026-10-12) |
| Akar masalah | Field alasan di sistem tiket tidak wajib diisi |
| Cek kasus serupa | Seluruh 23 tiket P1/P2 dicek; 2 tiket lain juga kosong |
| Corrective action | Field dibuat wajib untuk P1-P3; QA sampling bulanan menambahkan cek field ini |
| Bukti efektivitas | QA sampling November 2026: 0 tiket tanpa alasan |
| Pemilik dan tenggat | Lead SOC, 2026-11-30 |

Cek kasus serupa menemukan 2 tiket lain dengan masalah yang sama. Menurut 10.2, ini justru hasil yang baik untuk dilaporkan, karena menunjukkan pemeriksaan dilakukan dengan sungguh-sungguh.

## 5. Lab praktik

Latihan untuk organisasi fiktifmu. Simpan di `ISO27001-note/latihan/day13-<nama-org-fiktif>.md`.

1. Buat timeline siklus sertifikasi tiga tahun untuk organisasimu dengan tanggal fiktif. Tandai kapan internal audit dan management review harus selesai sebelum tiap audit eksternal.
2. Susun indeks paket bukti untuk 10 kontrol yang paling dekat dengan SOC (pakai daftar kerja SOC dari Day 08). Untuk tiap kontrol tulis dokumen, rekaman, lokasi, dan pemilik.
3. Tentukan 4 populasi dan rencana sampling seperti bagian 4.2. Hitung ulang cara memilih sampel.
4. Lakukan audit internal mini atas latihanmu sendiri dari Day 04-12. Tulis 3 temuan dengan grading berbeda (minor, major, OFI) memakai struktur kondisi, kriteria, bukti, dan alasan grading.
5. Tulis rencana tindakan lengkap untuk temuan minor, termasuk cek kasus serupa.
6. Tulis 6 pertanyaan yang mungkin diajukan auditor ke analyst L1, beserta jawaban yang jujur dan menunjuk bukti.
7. Hubungkan ke lab:
   - ekspor daftar alert 30 hari terakhir dari Splunk atau Wazuh lab sebagai contoh populasi, lalu catat jumlahnya, tanggal ekspor, dan siapa yang mengekspor;
   - rancang role auditor read-only di SIEM lab: apa yang bisa dilihat, apa yang tidak, dan bagaimana aktivitasnya tercatat.
   Cukup rancangan; membuat role boleh di sesi lab terpisah.

**Hasil yang seharusnya teramati:** paket bukti yang siap dipakai, rencana sampling yang dihitung, temuan yang ditulis dengan benar, dan contoh populasi dari lab-mu.

**Hasil yang sebaiknya tersimpan:**
- Timeline menunjukkan internal audit dan management review sebelum audit eksternal.
- Setiap populasi bisa diekspor dan jumlahnya tercatat.
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
- Menganggap OFI tidak penting. OFI yang diabaikan bisa menjadi nonconformity di audit berikutnya.
- Menunjukkan data pelanggan lebih dari yang dibutuhkan.
- Mengarang jawaban saat wawancara. Itu merusak kepercayaan dan bisa memperberat temuan.
- `[komunitas]` Konsultan di forum Advisera menyarankan agar organisasi mengonfirmasi langsung ke CB cara melaporkan penanganan minor, karena praktik antar CB berbeda [S4].

## 8. Catatan terkini

- ISO/IEC 27006-1:2024 terbit Maret 2024 dan menggantikan 27006:2015 serta amandemen 2020 [S1].
- ISO 19011:2026 (edisi 4) terbit Mei 2026 [S5].
- Transisi sertifikat ke 27001:2022 berakhir 31 Oktober 2025. Audit 2026 sepenuhnya memakai edisi 2022 [S8].
- Definisi major dan minor nonconformity berasal dari ISO/IEC 17021-1:2015 [S2]. Katalog ISO menandai 17021-1:2015 sedang ditinjau (Day 17), jadi pantau apakah definisinya berubah di edisi berikutnya.

## 9. Cheat sheet

```
Audit: first party (internal 9.2) | second party (klien) | third party (CB terakreditasi)
Siklus: Tahap 1 (siap? dokumen, scope) -> Tahap 2 (efektif?) -> sertifikat
        -> Surveillance thn 1 -> Surveillance thn 2 -> Resertifikasi thn 3
Aturan CB: ISO/IEC 17021-1 (umum) + ISO/IEC 27006-1:2024 (ISMS; ganti 27006:2015 + Amd 2020)
Panduan audit: ISO 19011:2026 ed.4 (+ 27007 khusus ISMS)
Metode bukti: dokumen | sampling rekaman | wawancara | observasi | verifikasi teknis terbatas
Grading: major (ganggu kemampuan capai hasil; atau minor berulang = sistemik) -> tahan sertifikasi
         minor (tidak ganggu) -> rencana tindakan, dicek audit berikut
         observation | OFI (tidak wajib)   ; tenggat: aturan CB (pola umum 30 hari rencana, 90 hari major)
Temuan = kondisi + kriteria + bukti (+ alasan grading)
SOC siap audit: indeks bukti per kontrol | populasi bisa diekspor | angka konsisten | snapshot konfigurasi
Saat audit: 8.34 akun read-only tercatat | 5.34 minimasi data pribadi | jujur bila tidak tahu
Bukti audit = bisa ditelusuri ; bukti forensik = chain of custody formal (27037)
```

## 10. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | ISO committee: ISO/IEC 27006-1:2024 | https://committee.iso.org/standard/82908.html | primer (katalog ISO) | Maret 2024; diakses 2026-10-08 | Tinggi. Edisi, status, dan dokumen yang digantikan |
| S2 | ERA terminology collection: major nonconformity (definisi ISO/IEC 17021-1:2015) | https://www.era.europa.eu/era-railway-terminology-collection/majornonconformity/term/international_standard | sekunder (kutipan definisi standar oleh lembaga UE) | diakses 2026-10-08 | Sedang-tinggi. Definisi major dan dua kondisi klasifikasi |
| S3 | Open Exam Prep: Nonconformity classification framework (materi studi lead auditor) | https://open-exam-prep.com/study-guides/iso-27001-lead-auditor/closing-an-iso-27001-audit-and-nonconformity-management/nonconformity-classification-framework | sekunder (materi studi) | diakses 2026-10-08 | Sedang. Definisi minor dan dampak major terhadap sertifikasi |
| S4 | Advisera Expert Advice Community: ISO 27001 and minor non-conformities | https://community.advisera.com/topic/iso-27001-and-minor-non-conformities/ | komunitas (forum tanya-jawab) | 2023-07-20; diakses 2026-10-08 | Rendah-sedang. Praktik pelaporan minor; disarankan konfirmasi ke CB |
| S5 | ISO committee: ISO 19011:2026 | https://committee.iso.org/standard/88984.html | primer (katalog ISO) | Mei 2026; diakses 2026-10-08 | Tinggi untuk edisi dan tanggal |
| S6 | Sensiba: ISO 27001 internal audits, key things to know | https://knowledge.sensiba.com/iso-27001-internal-audits-key-things-to-know | sekunder (firma audit) | 2026; diakses 2026-10-08 | Sedang. CB tidak boleh menjadi internal auditor |
| S7 | ISMS.online: What happens if you fail an ISO 27001 audit | https://www.isms.online/iso-27001/certification/failed-audit/ | sekunder (vendor) | diakses 2026-10-08 | Rendah-sedang. Pola tenggat 30/90 hari bervariasi antar CB |
| S8 | Konfirmity: ISO 27001 in 2026, what changed | https://www.konfirmity.com/blog/iso-27001-what-changed-in-2026 | sekunder (vendor) | diperbarui 2026-08-31; diakses 2026-10-08 | Sedang. Akhir transisi 31 Okt 2025 |

**Catatan sumber:** definisi major dan minor nonconformity berasal dari kutipan definisi ISO/IEC 17021-1:2015 oleh lembaga UE [S2] dan materi studi [S3], bukan dari teks standar; cocokkan dengan teks 17021-1 bila dipakai dalam sengketa grading. Tenggat 30/90 hari dan jumlah sampel berbeda antar CB, sehingga angka di catatan ini hanya pola umum atau aturan fiktif. Isi bagian sampling di ISO 19011:2026 perlu dicek di teks standarnya.
