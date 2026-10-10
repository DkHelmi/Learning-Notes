---
day: 06
title: 'Klausul 9-10: monitoring, internal audit, management review, nonconformity, dan perbaikan berkelanjutan'
researched_on: 2026-10-10
versions_checked: 'ISO/IEC 27001:2022 + Amd 1:2024; ISO 19011:2026 (edisi 4, Mei 2026, menggantikan 2018); NIST SP 800-55 Vol. 1 dan Vol. 2 (Des 2024)'
---

# Day 06: Klausul 9-10, evaluasi kinerja dan perbaikan

> Catatan pribadi, bukan materi resmi ISO, dan bukan nasihat hukum atau audit. Catatan ini hanya menyebut nomor dan judul singkat klausul, lalu menjelaskannya dengan kata-kata sendiri.

Cakupan: klausul 9.1-9.3 dan 10.1-10.2 ISO/IEC 27001:2022. Audit sertifikasi eksternal, sampling, dan grading temuan dibahas di Day 13.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- merancang metrik 9.1 yang menyebut apa yang diukur, metode, waktu, pelaksana, dan siapa yang mengevaluasi.
- menjelaskan tujuan internal audit, isi program audit, dan syarat objektivitas auditor internal.
- menyusun agenda management review yang mencakup semua input 9.3.2 dan menghasilkan keputusan yang bisa ditindaklanjuti.
- membedakan correction dari corrective action, dan menjalankan analisis akar masalah untuk satu nonconformity.
- menjelaskan kapan insiden keamanan merupakan nonconformity dan kapan bukan.

## 2. Konteks singkat

Klausul 9 menjawab pertanyaan "apakah ISMS bekerja, dan bagaimana kita tahu?" Klausul 10 menjawab "apa yang kita lakukan saat tidak bekerja?" Keduanya mengubah ISMS dari tumpukan dokumen menjadi sistem yang belajar.

SOC punya posisi istimewa di sini. Banyak data yang dibutuhkan 9.1 sudah ada di SIEM dan sistem tiket: cakupan log, waktu deteksi, waktu respons, dan tren insiden. Banyak nonconformity juga ditemukan SOC lebih dulu, misalnya kontrol yang ternyata tidak berjalan saat insiden. Analyst yang paham klausul 9-10 bisa mengubah temuan teknis menjadi bahan keputusan manajemen.

Kapan dipakai: laporan bulanan, persiapan audit, setelah insiden besar, dan rapat management review.
Kapan tidak cukup: klausul 9-10 tidak menentukan nilai target. Target datang dari sasaran 6.2 dan kriteria risiko 6.1.2.

## 3. Konsep inti

### 3.1 Klausul 9.1: monitoring, pengukuran, analisis, dan evaluasi

Organisasi menentukan [S1]:

- apa yang dipantau dan diukur, termasuk proses dan kontrol keamanan;
- metode yang menghasilkan hasil valid;
- kapan pemantauan dan pengukuran dilakukan, dan oleh siapa;
- kapan hasilnya dianalisis dan dievaluasi, dan oleh siapa.

Bukti hasilnya wajib disimpan. Organisasi juga mengevaluasi kinerja keamanan dan efektivitas ISMS secara keseluruhan.

Standar memberi catatan bahwa metode yang dipilih sebaiknya menghasilkan hasil yang bisa dibandingkan dan diulang. Ini prinsip yang sama dengan risk assessment di 6.1.2: metrik yang definisinya berubah tiap bulan tidak bisa menunjukkan tren.

Ada dua jenis metrik yang sebaiknya dibedakan (pembagian ini interpretasi, bukan istilah standar):

| Jenis | Pertanyaan | Contoh SOC |
|---|---|---|
| Metrik pelaksanaan | Apakah kontrol berjalan? | Persentase server in-scope yang mengirim log; persentase alert yang ditriage dalam SLA |
| Metrik hasil | Apakah risiko benar-benar turun? | Median waktu sampai containment insiden prioritas tinggi; jumlah insiden berulang dengan akar masalah yang sama |

Konsultan URM (Agustus 2026) mengingatkan agar organisasi tidak mengumpulkan data hanya karena tersedia. Laporan sederhana yang menghubungkan kinerja, risiko, dan tindakan lebih berguna daripada dashboard rinci yang tidak dipakai siapa pun [S1]. URM juga menyarankan bukti disimpan minimal 12 bulan agar tren terlihat [S1]. Angka itu saran praktisi, bukan persyaratan standar.

Untuk merancang program pengukuran, NIST merilis SP 800-55 dalam dua volume pada 4 Desember 2024. Volume 1 membahas cara memilih dan memprioritaskan ukuran, sedangkan Volume 2 membahas cara membangun program pengukuran [S2]. Dokumen NIST bukan bagian dari keluarga ISO, tetapi bisa dipakai sebagai panduan metode untuk 9.1.

### 3.2 Klausul 9.2: internal audit

Internal audit dijalankan pada interval terencana untuk memastikan ISMS:

- sesuai dengan persyaratan organisasi sendiri dan persyaratan standar;
- diterapkan dan dipelihara secara efektif.

9.2.2 meminta organisasi menyusun program audit yang mencakup frekuensi, metode, tanggung jawab, persyaratan perencanaan, dan pelaporan. Program itu mempertimbangkan pentingnya proses dan hasil audit sebelumnya. Untuk setiap audit, organisasi menetapkan kriteria dan lingkupnya, memilih auditor yang menjamin objektivitas dan imparsialitas, dan melaporkan hasilnya kepada manajemen yang relevan. Bukti pelaksanaan program dan hasil audit wajib disimpan [S4].

Hal praktis yang perlu diingat:

- **Auditor tidak boleh mengaudit pekerjaannya sendiri.** Lead SOC tidak mengaudit proses SOC. Alasan pemilihan auditor sebaiknya dicatat [S7].
- **Lembaga sertifikasi tidak boleh menjadi internal auditor** kliennya sendiri, karena aturan imparsialitas ISO/IEC 17021-1 [S7].
- **Program bergulir boleh dipakai.** Sebelum sertifikasi awal, seluruh ISMS diaudit. Setelahnya, cakupan penuh boleh disebar dalam siklus sertifikat tiga tahun [S7].
- **Prioritas berbasis risiko.** URM melaporkan temuan audit 2026 berupa program audit yang tidak memakai hasil risk assessment untuk menentukan frekuensi, dan tidak bisa menunjukkan cakupan seluruh klausul dan kontrol [S6].

Panduan umum cara mengaudit sistem manajemen ada di ISO 19011. Edisi keempatnya, ISO 19011:2026, terbit Mei 2026 dan menggantikan edisi 2018 [S3]. Untuk ISMS ada panduan khusus ISO/IEC 27007 (edisi yang beredar luas adalah 27007:2020), yang menambahkan konteks keamanan informasi di atas 19011. Cek di katalog ISO apakah 27007 sedang direvisi untuk menyesuaikan 19011:2026.

### 3.3 Klausul 9.3: management review

Top management meninjau ISMS pada interval terencana untuk memastikan ISMS tetap sesuai, memadai, dan efektif. Input yang harus dipertimbangkan (9.3.2) [S4]:

1. status tindakan dari review sebelumnya;
2. perubahan isu internal dan eksternal;
3. perubahan kebutuhan dan harapan pihak berkepentingan (baru di 2022);
4. umpan balik kinerja: tren nonconformity dan corrective action, hasil monitoring dan pengukuran, hasil audit, dan pencapaian sasaran;
5. umpan balik dari pihak berkepentingan;
6. hasil risk assessment dan status risk treatment plan;
7. peluang perbaikan.

Hasilnya (9.3.3) mencakup keputusan tentang peluang perbaikan dan kebutuhan perubahan ISMS. Bukti hasilnya wajib disimpan.

Notulen yang hanya berisi "semua berjalan baik" adalah tanda bahaya. Auditor mencari keputusan: anggaran disetujui, sasaran diubah, risiko diterima, atau tindakan ditugaskan beserta pemilik dan tenggatnya. URM melaporkan input nomor 3 sering terlewat [S6].

### 3.4 Klausul 10.1: continual improvement

Organisasi terus meningkatkan kesesuaian, kecukupan, dan efektivitas ISMS. Peningkatan tidak harus menunggu nonconformity. Sumbernya bisa hasil metrik, ide tim, pelajaran dari insiden, atau hasil hunting yang menunjukkan celah deteksi.

### 3.5 Klausul 10.2: nonconformity dan corrective action

Nonconformity adalah tidak terpenuhinya sebuah persyaratan. Persyaratannya bisa dari standar, kebijakan organisasi, prosedur, kontrak, atau regulasi. Saat nonconformity terjadi, organisasi harus:

1. bereaksi: mengendalikan dan memperbaikinya, serta menangani akibatnya;
2. menilai perlunya tindakan untuk menghilangkan penyebab, dengan meninjau nonconformity, menentukan penyebabnya, dan memeriksa apakah nonconformity serupa sudah ada atau bisa terjadi di tempat lain;
3. menjalankan tindakan yang dibutuhkan;
4. meninjau efektivitas corrective action;
5. mengubah ISMS bila perlu.

Corrective action harus sepadan dengan dampak nonconformity-nya. Kesalahan kecil tidak butuh investigasi besar. Bukti tentang sifat nonconformity, tindakan yang diambil, dan hasil corrective action wajib disimpan [S5].

**Correction dan corrective action:**
- **Correction** memperbaiki gejala yang terdeteksi, misalnya menonaktifkan akun default yang ditemukan di satu VM.
- **Corrective action** menghilangkan akar masalah supaya tidak terulang, misalnya mengubah image VM dan checklist provisioning [S5].

Laporan yang hanya berisi correction akan ditanya auditor: "kenapa ini tidak akan terjadi lagi?"

**Insiden tidak otomatis nonconformity.** Serangan yang berhasil walaupun semua kontrol berjalan sesuai rencana adalah insiden, dan pelajarannya masuk ke risk assessment (8.2) dan improvement (10.1). Insiden menjadi nonconformity bila ada persyaratan yang tidak dipenuhi, misalnya langkah provisioning dilewati, log tidak dikirim padahal kebijakan mewajibkan, atau tenggat pelaporan ke klien terlewat. Sumber nonconformity lainnya: hasil audit, management review, dan temuan monitoring [S5].

Metode analisis akar masalah tidak diwajibkan. Yang umum dipakai adalah 5 whys dan diagram fishbone. Untuk SOC, 5 whys biasanya cukup, asalkan berhenti pada penyebab yang bisa dikendalikan organisasi, bukan pada "human error".

## 4. Contoh dokumen / artefak (organisasi fiktif)

Organisasi fiktif: PT Awan Nusantara (PT AN). Semua angka dan nama adalah ilustrasi.

### 4.1 Katalog metrik 9.1

| ID | Metrik | Metode | Kapan diukur | Pengukur | Kapan dan siapa evaluasi | Target (dari 6.2) |
|---|---|---|---|---|---|---|
| M-01 | Cakupan log server in-scope | Search SIEM dibandingkan daftar aset | Harian otomatis, rekap bulanan | Analyst on-duty | Bulanan, Lead SOC | minimal 98% |
| M-02 | Median waktu alert sampai containment (prioritas tinggi) | Data tiket: selisih waktu alert dan status contained | Per insiden, rekap bulanan | Incident manager | Bulanan, Lead SOC dan ISMS Manager | maksimal 4 jam |
| M-03 | Alert prioritas tinggi yang ditriage dalam 15 menit | Data tiket | Bulanan | Lead SOC | Bulanan, ISMS Manager | minimal 95% |
| M-04 | Host dengan selisih waktu lebih dari 1 detik | Laporan NTP | Mingguan | Platform Engineering | Bulanan, Head of Platform | 0 |
| M-05 | Insiden berulang dengan akar masalah sama | Register NC dan insiden | Kuartalan | ISMS Manager | Kuartalan, management review | 0 |

M-01 sampai M-04 adalah metrik pelaksanaan, sedangkan M-05 adalah metrik hasil. Kolom "Kapan dan siapa evaluasi" sering dilupakan, padahal standar memisahkan siapa yang mengukur dari siapa yang mengevaluasi.

### 4.2 Program audit internal 2026-2027 (cuplikan)

| Kuartal | Area yang diaudit | Alasan prioritas | Auditor | Tidak boleh mengaudit |
|---|---|---|---|---|
| Q4 2026 | Klausul 4-6, SoA, risk register | Persiapan surveillance; risk register berubah setelah migrasi | Konsultan eksternal | - |
| Q1 2027 | Proses SOC: kontrol 5.24-5.28, 8.15-8.17 | Risiko R-04 dan R-09 tinggi; insiden besar Q3 2026 | Auditor internal dari tim GRC | Lead SOC, analyst SOC |
| Q2 2027 | Klausul 7, kontrol people dan physical | Tidak diaudit tahun lalu | Auditor internal dari tim GRC | HR (untuk kontrol people) |
| Q3 2027 | Klausul 9-10, kontrol pemasok 5.19-5.23 | Rencana MSSP; temuan management review | Konsultan eksternal | - |

Program ini menunjukkan tiga hal yang dicari auditor eksternal: prioritas berbasis risiko dan hasil sebelumnya, cakupan penuh dalam satu siklus, dan objektivitas auditor.

### 4.3 Agenda management review (9.3)

```
Management Review ISMS PT AN, 2026-11-20
Hadir: Direktur Operasional (pimpinan), ISMS Manager, Lead SOC, Head of Platform, Legal

1. Status tindakan MR 2026-05 (3 selesai, 1 terlambat: evaluasi MSSP)          [9.3.2 a]
2. Perubahan konteks: migrasi log ke Wazuh 40% selesai; klien baru sektor kesehatan [9.3.2 b, c]
3. Kinerja: M-01 97,1% (di bawah target 98%); M-02 3 jam 10 menit; 2 NC baru     [9.3.2 d]
4. Hasil audit internal Q3: 1 NC minor proses provisioning, 2 peluang perbaikan   [9.3.2 d]
5. Umpan balik klien: 1 keluhan keterlambatan laporan insiden                    [9.3.2 e]
6. Risiko: R-11 turun ke Rendah setelah avoid; R-15 tetap Sedang                  [9.3.2 f]
7. Peluang perbaikan: otomasi pengumpulan bukti lewat SOAR                         [9.3.2 g]

Keputusan:
D-1 Tambah 1 FTE analyst L2 mulai Q1 2027 (anggaran disetujui)
D-2 Target M-01 tetap 98%; Lead SOC menyerahkan rencana perbaikan sebelum 2026-12-15
D-3 Persyaratan klien sektor kesehatan masuk register pihak berkepentingan; ISMS Manager, 2026-12-31
D-4 Pilot SOAR untuk pengumpulan bukti; Lead SOC, Q2 2027
```

Setiap butir agenda dipetakan ke input 9.3.2, dan setiap keputusan punya pemilik dan tenggat. Butir 2 menyebut klien baru, yang memenuhi input "perubahan kebutuhan pihak berkepentingan" yang sering terlewat.

### 4.4 Catatan nonconformity dengan 5 whys (10.2)

```
ID           : CA-2026-014
Sumber       : Insiden INC-2026-031 (akses tidak sah ke VM pelanggan lewat akun default)
Persyaratan  : Prosedur provisioning PRV-02 v2.1 langkah 6 (nonaktifkan akun default)
Nonconformity: Langkah 6 tidak dijalankan pada 14 dari 60 VM yang dibuat Juli-Agustus 2026
Correction   : Akun default dinonaktifkan di 14 VM (selesai 2026-09-03)

5 whys:
  1. Kenapa akun default aktif?            Langkah 6 tidak dijalankan.
  2. Kenapa tidak dijalankan?               Engineer memakai template VM baru yang belum ada di checklist.
  3. Kenapa template baru tidak di checklist? Checklist tidak ikut diperbarui saat template ditambah.
  4. Kenapa tidak ikut diperbarui?          Proses penambahan template tidak mewajibkan update checklist.
  5. Kenapa tidak diwajibkan?               Prosedur perubahan template (8.32) tidak menyebut dokumen terkait.

Akar masalah     : prosedur perubahan template tidak menautkan dokumen operasional terkait
Serupa di tempat lain? Dicek: template database dan template container; 1 template container punya pola sama
Corrective action: (a) akun default dihapus dari semua image; (b) prosedur 8.32 menambah langkah
                   "perbarui dokumen terkait"; (c) RB-SOC-007 v1.3 menambah langkah cek akun default
Efektivitas      : audit sampel 20 VM baru pada 2026-11 -> 0 akun default aktif. Ditutup 2026-11-25
```

Cara membaca:

- Correction dan corrective action dipisah dengan jelas.
- Pemeriksaan "serupa di tempat lain" menemukan satu masalah tambahan. Langkah ini sering dilewati.
- Penutupan didasarkan pada bukti efektivitas, bukan pada "tindakan sudah dikerjakan".
- Angka 14 dari 60 VM berarti sekitar 23% VM di periode itu terdampak, dan angka itu yang dilaporkan ke management review.

## 5. Lab praktik

Latihan untuk organisasi fiktifmu. Simpan di `ISO27001-note/latihan/day06-<nama-org-fiktif>.md`.

1. Buat katalog 6 metrik dengan format bagian 4.1. Minimal 2 metrik pelaksanaan dan 2 metrik hasil. Setiap metrik terhubung ke sasaran 6.2 yang kamu tulis di Day 04.
2. Susun program audit internal 12 bulan yang mencakup seluruh klausul 4-10 dan kontrol yang kamu pilih di SoA Day 04. Untuk setiap audit tulis alasan prioritas, auditor, dan siapa yang tidak boleh mengaudit.
3. Tulis rencana audit untuk satu audit proses SOC, berisi lingkup, kriteria, 6 pertanyaan audit, dan bukti yang akan diambil sampelnya. Contoh: "ambil 5 tiket insiden prioritas tinggi bulan lalu, cocokkan dengan langkah runbook".
4. Tulis agenda dan notulen fiktif management review dengan format bagian 4.3. Pastikan ketujuh input 9.3.2 muncul dan minimal 3 keputusan punya pemilik dan tenggat.
5. Tulis satu catatan NC lengkap dengan 5 whys, pemeriksaan "serupa di tempat lain", corrective action, dan bukti efektivitas.
6. Tulis dua kejadian: satu insiden yang merupakan nonconformity dan satu insiden yang bukan. Jelaskan alasannya dengan menyebut persyaratan yang dilanggar atau tidak dilanggar.
7. Hubungkan ke lab: rancang dashboard metrik bulanan di Splunk atau Wazuh lab untuk 3 metrik dari langkah 1. Tulis judul panel, sumber data, dan periode waktunya. Query cakupan log dari Day 04 bagian 5 bisa dipakai untuk M-01. Cukup rancangan; implementasi boleh dikerjakan di sesi lab terpisah.

**Hasil yang seharusnya teramati:** satu paket dokumen yang menutup siklus: metrik memberi data, audit menguji, review memutuskan, dan NC memperbaiki.

**Hasil yang sebaiknya tersimpan:**
- Setiap metrik punya metode, waktu, pengukur, dan pengevaluasi.
- Program audit mencakup seluruh klausul dan auditor tidak mengaudit area sendiri.
- Ketujuh input 9.3.2 muncul di agenda, dan keputusan punya pemilik serta tenggat.
- Catatan NC membedakan correction dari corrective action dan punya bukti efektivitas.
- Contoh insiden yang bukan NC dijelaskan dengan benar.
- Tidak ada kalimat yang disalin dari teks standar.

**Variasi tantangan:** auditor internal menemukan bahwa M-01 dihitung dengan daftar aset yang berbeda setiap bulan. Tulis temuan audit itu (kondisi, kriteria, bukti) dan jelaskan klausul mana yang tidak dipenuhi.

## 6. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Dashboard penuh angka tetapi tidak ada keputusan | Metrik tidak terhubung ke sasaran atau risiko | Setiap metrik wajib menunjuk ke sasaran 6.2 atau risiko; hapus yang tidak |
| Tidak ada orang independen untuk mengaudit SOC | Organisasi kecil | Tukar auditor antar tim, atau pakai konsultan eksternal |
| Management review hanya presentasi | Tidak ada agenda berbasis input 9.3.2 | Pakai template agenda dengan tujuh input dan bagian keputusan |
| NC ditutup tetapi terulang | Hanya correction, akar masalah tidak dicari | Wajibkan 5 whys dan bukti efektivitas sebelum NC ditutup |
| Setiap insiden dicatat sebagai NC | Tidak membedakan insiden dan nonconformity | Tanyakan "persyaratan mana yang tidak dipenuhi?"; bila tidak ada, catat sebagai insiden dan pelajaran |

## 7. Kesalahan umum dan jebakan

- Mengumpulkan metrik karena datanya tersedia, bukan karena berguna untuk keputusan [S1].
- Program audit yang tidak berbasis risiko dan tidak menunjukkan cakupan penuh [S6].
- Melewatkan input "perubahan kebutuhan pihak berkepentingan" di management review [S6].
- Menutup NC setelah tindakan dikerjakan, tanpa meninjau efektivitasnya.
- Menulis "human error" sebagai akar masalah. Pertanyaan berikutnya selalu "kenapa sistem membiarkan kesalahan itu terjadi?"
- Menganggap ISO 19011 sebagai persyaratan. Itu panduan, dan organisasi tidak disertifikasi terhadapnya [S3].

## 8. Catatan terkini

- ISO 19011:2026 (edisi 4) terbit Mei 2026 dan menggantikan edisi 2018 [S3]. Rincian perubahannya (fokus pada audit jarak jauh, teknologi digital, pengelolaan program audit, dan kompetensi auditor) berasal dari ringkasan pihak ketiga; cocokkan dengan bagian pendahuluan teks standar bila tersedia.
- NIST SP 800-55 Vol. 1 dan Vol. 2 terbit 4 Desember 2024 dan menggantikan SP 800-55 Rev. 1 [S2].
- Artikel URM tentang 9.1 (Agustus 2026) menekankan laporan sederhana yang menghubungkan kinerja, risiko, dan tindakan [S1].
- Struktur 9.2 dan 9.3 dipecah menjadi subklausul di edisi 2022 (lihat Day 02 bagian 3.6 untuk konflik sumber soal 9.2) [S8].

## 9. Cheat sheet

```
9.1  apa | metode (valid, bisa dibandingkan) | kapan ukur | siapa ukur | kapan & siapa evaluasi | simpan bukti
     metrik pelaksanaan (kontrol berjalan?) vs metrik hasil (risiko turun?)
9.2  tujuan: sesuai persyaratan organisasi + standar; efektif
     9.2.2 program: frekuensi, metode, tanggung jawab, perencanaan, pelaporan; berbasis risiko + hasil lalu
     per audit: kriteria + lingkup; auditor objektif (tidak audit kerja sendiri); lapor ke manajemen
     CB tidak boleh jadi internal auditor (ISO/IEC 17021-1)
9.3  7 input: tindakan lalu | isu | pihak berkepentingan (baru) | kinerja (NC, metrik, audit, sasaran)
     | umpan balik pihak | risiko & RTP | peluang perbaikan
     output: keputusan perbaikan + perubahan ISMS (simpan bukti)
10.1 terus tingkatkan kesesuaian, kecukupan, efektivitas
10.2 reaksi (kendalikan, perbaiki, tangani akibat) -> cari penyebab + cek serupa -> tindakan
     -> tinjau efektivitas -> ubah ISMS bila perlu; sepadan dengan dampak; simpan bukti
correction = gejala   corrective action = akar masalah
insiden != NC kecuali ada persyaratan yang dilanggar
ISO 19011:2026 ed.4 (panduan audit)   NIST SP 800-55 v1/v2 (Des 2024, panduan pengukuran)
```

## 10. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | URM Consulting: ISO 27001 clause 9.1 monitoring, measurement, analysis and evaluation explained | https://urmconsulting.com/blog/iso-27001-clause-9-1-monitoring-measurement-analysis-and-evaluation | sekunder (praktisi) | 2026-08-13; diakses 2026-10-08 | Sedang. Isi 9.1, saran laporan dan retensi bukti |
| S2 | NIST CSRC: NIST releases volumes 1 and 2 of SP 800-55 | https://csrc.nist.gov/News/2024/nist-releases-volumes-1-and-2-of-sp-800-55 | primer (NIST) | 2024-12-04; diakses 2026-10-08 | Tinggi untuk tanggal rilis dan isi tiap volume. Status Rev. 1 sebagai edisi yang digantikan perlu dicocokkan di halaman publikasi NIST |
| S3 | ISO committee: ISO 19011:2026 Guidelines for auditing management systems | https://committee.iso.org/standard/88984.html | primer (katalog ISO) | Mei 2026; diakses 2026-10-08 | Tinggi untuk edisi dan tanggal |
| S4 | Hicomply: ISO 27001:2022 clause 9.3 management review | https://hicomply.com/hub/iso-27001-clause-9-3-management-review-2022 | sekunder (vendor) | diakses 2026-10-08 | Sedang. Ringkasan isi 9.2.2 dan 9.3.2, konsisten dengan S6 |
| S5 | Advisera: ISO 27001 clause 10.2 nonconformity and corrective action | https://advisera.com/iso27001/clause-10-2-nonconformity-and-corrective-action/ | sekunder (konsultan) | 2024-12-19; diakses 2026-10-08 | Sedang. Correction vs corrective action, sumber nonconformity |
| S6 | URM Consulting: Common issues identified during audits of ISO 27001:2022 | https://urmconsulting.com/blog/common-issues-identified-during-audits-of-iso-27001-2022 | sekunder (praktisi audit) | 2026-04-09; diakses 2026-10-08 | Sedang |
| S7 | Sensiba: ISO 27001 internal audits, key things to know | https://knowledge.sensiba.com/iso-27001-internal-audits-key-things-to-know | sekunder (firma audit) | 2026 (tanpa tanggal artikel); diakses 2026-10-08 | Sedang. Objektivitas, program bergulir, larangan CB |
| S8 | HighTable: ISO 27001 2013 vs 2022 explained | https://hightable.io/iso-27001-2013-vs-2022/ | sekunder (konsultan) | diperbarui 2026-09-14; diakses 2026-10-08 | Sedang. Struktur 9.2 dan 9.3 |

**Catatan sumber:** isi 9.1-10.2 disusun dari ringkasan sekunder yang saling cocok, bukan dari teks standar; daftar input 9.3.2 dan urutan butir 10.2 perlu dicocokkan dengan teks ISO/IEC 27001:2022 atau SNI resmi sebelum dikutip di dokumen audit. Rincian perubahan ISO 19011:2026 berasal dari ringkasan pihak ketiga. Saran retensi bukti 12 bulan [S1] adalah saran praktisi, bukan persyaratan.
