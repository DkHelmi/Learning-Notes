---
day: 07
title: 'Review Minggu 1: klausul 4-10, peta konsep, glosarium, dan paket mini-ISMS'
researched_on: 2026-10-10
versions_checked: 'ISO/IEC 27001:2022 edisi 3 + Amd 1:2024; ISO/IEC 27000:2026 (edisi 6, 3 Jul 2026); ISO 19011:2026 (edisi 4, Mei 2026); SNI ISO/IEC 27001:2022/Amd.1:2024'
---

# Day 07: Review Minggu 1, klausul 4-10

Cakupan: ringkasan Day 01-06 (ISMS dan klausul 4-10), peta konsep, glosarium, dan lab gabungan berupa paket mini-ISMS untuk organisasi fiktif.

> Catatan pribadi, bukan materi resmi ISO, dan bukan nasihat hukum atau audit. Catatan ini hanya menyebut nomor dan judul singkat klausul, lalu menjelaskannya dengan kata-kata sendiri.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- menjelaskan klausul 4-10 berurutan dalam lima menit tanpa catatan, termasuk perubahan edisi 2022 dan Amd 1:2024.
- menggambar peta konsep yang menghubungkan konteks, risiko, SoA, operasi, evaluasi, dan perbaikan.
- mendefinisikan istilah inti ISMS dengan kata-kata sendiri dan membedakan pasangan istilah yang sering tertukar.
- menyusun paket mini-ISMS untuk organisasi fiktif dan menguji keterlacakan antar dokumennya.
- menentukan titik lemahmu sendiri dan rencana memperbaikinya sebelum masuk Annex A.

## 2. Konteks singkat

Day 01-06 membangun kerangka sistem manajemen. Day 08-12 mengisinya dengan kontrol Annex A yang paling dekat dengan SOC: struktur Annex A (Day 08), risiko (Day 09), insiden (Day 10), logging dan monitoring (Day 11), serta threat intelligence dan kerentanan (Day 12). Bila kerangkanya belum kokoh, pemetaan kontrol akan terasa seperti hafalan nomor.

Ukuran keberhasilan review ini sederhana: kamu bisa mengambil satu artefak SOC (tiket insiden, laporan metrik, atau runbook), lalu menjelaskan klausul mana yang ia dukung, dari mana asalnya, dan ke mana ia mengalir.

## 3. Ringkasan per klausul

### Day 01: ISMS dan keluarga 27000

- ISMS adalah sistem manajemen berbasis risiko untuk confidentiality, integrity, dan availability, bukan alat.
- 27001 berisi persyaratan dan satu-satunya yang disertifikasi. 27002 panduan kontrol, 27005 panduan risiko, 27035 panduan insiden, dan 27000 gambaran umum.
- Annex A 2022 berisi 93 kontrol: 37 Organizational, 8 People, 14 Physical, 34 Technological.
- PDCA tidak lagi diwajibkan secara eksplisit sejak 2013. Yang diwajibkan adalah continual improvement.
- Sertifikat diterbitkan lembaga sertifikasi terakreditasi untuk scope tertentu, bukan untuk individu. Masa transisi sertifikat 2013 ke 2022 berakhir 31 Oktober 2025.

### Day 02: peta klausul

- Klausul 4-10 mengikuti Harmonized Structure (Annex SL), sehingga urutannya sama dengan ISO 9001 dan 14001 [S4].
- Klausul 6 menetapkan proses, sedangkan klausul 8 menjalankannya dan menyimpan hasilnya.
- Ada 15 tempat di klausul 4-10 yang eksplisit meminta informasi terdokumentasi, termasuk 7.5.1 b yang terbuka untuk dokumen tambahan. "Maintain" lazim dibaca sebagai dokumen hidup; "retain" sebagai rekaman bukti.
- Perubahan 2022: 4.2 c, 4.4 proses, catatan Annex A di 6.1.3, 6.2 d dan g, 6.3 baru, 7.4 disederhanakan, 8.1 pihak eksternal, pemecahan 9.2 dan 9.3, input baru 9.3.2 c, dan urutan 10.1/10.2 dibalik.

### Day 03: klausul 4-5

- 4.1 berisi isu internal dan eksternal. Sejak Amd 1:2024, organisasi juga menentukan apakah perubahan iklim relevan [S6].
- 4.2 berisi pihak berkepentingan, persyaratannya, dan persyaratan mana yang ditangani lewat ISMS. Note 2 dari Amd 1 bersifat informatif.
- 4.3 scope mempertimbangkan 4.1, 4.2, interface, dan dependency, dan wajib terdokumentasi.
- 5.1 berisi kepemimpinan nyata (butir a sampai h), 5.2 kebijakan dengan empat unsur isi, dan 5.3 dua tanggung jawab wajib (kesesuaian dan pelaporan kinerja).
- IAF menyatakan Amd 1 adalah klarifikasi tanpa program transisi penuh dan tanpa penerbitan ulang sertifikat. CB menerbitkan temuan yang sesuai bila pertimbangan iklim tidak bisa ditunjukkan [S3].

### Day 04: klausul 6

- 6.1.1 berisi risiko dan peluang ISMS; 6.1.2 berisi risiko keamanan informasi dengan kriteria, risk owner, analisis, dan evaluasi.
- 6.1.3 berisi opsi treatment, kontrol dari sumber mana pun, pembandingan dengan Annex A, SoA (butir d), risk treatment plan (butir e), serta persetujuan risk owner (butir f).
- SoA memuat kontrol yang dibutuhkan, alasan pemilihan, status penerapan, dan alasan pengecualian kontrol Annex A.
- 6.2 sasaran harus terukur bila praktis, dipantau, dan terdokumentasi. 6.3 mewajibkan perubahan ISMS direncanakan.

### Day 05: klausul 7-8

- 7.1 sumber daya, 7.2 kompetensi beserta penilaian efektivitas dan bukti, 7.3 awareness (berbeda dari pelatihan), 7.4 komunikasi (apa, kapan, kepada siapa, bagaimana).
- 7.5 mengatur identitas, tinjauan, persetujuan, dan pengendalian dokumen, termasuk dokumen dari luar.
- 8.1 berisi kriteria proses, perubahan terencana dan dampak perubahan tidak terencana, serta pengendalian pihak eksternal.
- 8.2/8.3 menjalankan risk assessment dan treatment secara berkala dan saat ada perubahan signifikan.

### Day 06: klausul 9-10

- 9.1: apa yang diukur, metode, kapan, siapa yang mengukur, kapan dianalisis, dan siapa yang mengevaluasi.
- 9.2: internal audit dengan program berbasis risiko dan auditor yang objektif.
- 9.3: tujuh input (9.3.2 a sampai g) dan keputusan sebagai output.
- 10.2: reaksi, akar masalah, cek kasus serupa, corrective action, tinjau efektivitas, dan ubah ISMS bila perlu. Correction berbeda dari corrective action, dan insiden tidak otomatis nonconformity.

## 3b. Peta konsep

```
                         +-----------------------------+
                         | 5 LEADERSHIP (memayungi)    |
                         | 5.1 komitmen  5.2 kebijakan |
                         | 5.3 peran (a) sesuai (b) lapor|
                         +--------------+--------------+
                                        |
 4.1 isu (+iklim) --+                   v
 4.2 pihak + (c) ---+--> 4.3 SCOPE --> 6.1.1 risiko/peluang ISMS
 4.4 proses ISMS    |                  6.1.2 RA: kriteria, risk owner, analisis, evaluasi
                    |                  6.1.3 RT: opsi -> kontrol -> Annex A -> SoA -> RTP -> setuju
                    |                  6.2 sasaran (terukur, dipantau)   6.3 perubahan
                    |                          |
   7 SUPPORT -------+------------------------> 8 OPERATION
   7.1 sumber daya  7.2 kompetensi              8.1 kriteria, perubahan, pihak eksternal
   7.3 awareness    7.4 komunikasi              8.2 RA berkala   8.3 jalankan RTP
   7.5 dokumen (maintain / retain)                      |
                                                        v
                     9.1 metrik --> 9.2 audit internal --> 9.3 management review
                                                        |
                                                        v
                     10.2 NC: koreksi -> akar masalah -> CA -> efektivitas
                     10.1 continual improvement
                                                        |
                          kembali ke 4.1/4.2 (konteks) dan 6.1 (risiko)
```

Ada tiga benang yang biasa dipakai auditor untuk menguji peta ini:

1. **Benang risiko:** satu baris risk register, lalu kontrol di SoA, lalu bukti operasi (8.3), lalu metrik (9.1).
2. **Benang insiden:** satu tiket, lalu prosedur (8.1), lalu metrik (9.1), lalu NC bila ada persyaratan dilanggar (10.2), lalu risk assessment ulang (8.2).
3. **Benang sasaran:** satu sasaran (6.2), lalu metrik (9.1), lalu management review (9.3), lalu keputusan dan tindakan.

## 3c. Glosarium

Definisi di bawah ditulis dengan kata sendiri untuk keperluan belajar, bukan definisi resmi.

| Istilah | Penjelasan singkat | Sering tertukar dengan |
|---|---|---|
| ISMS | Bagian sistem manajemen untuk mengelola risiko keamanan informasi | Alat keamanan (SIEM, firewall) |
| Interested party | Pihak yang bisa memengaruhi, dipengaruhi, atau merasa dipengaruhi keputusan organisasi | Pelanggan saja |
| Scope | Batas ISMS: organisasi, lokasi, teknologi, layanan, dan pengecualian | Scope sertifikat yang lebih sempit |
| Interface | Titik temu antara yang di dalam dan di luar scope | Dependency |
| Dependency | Hal di luar scope yang dibutuhkan ISMS | Interface |
| Top management | Orang atau kelompok yang mengarahkan organisasi di level tertinggi untuk scope ISMS | Manajer TI |
| Risk owner | Orang dengan akuntabilitas dan wewenang mengelola sebuah risiko | Asset owner |
| Risk criteria | Acuan untuk menilai dan menerima risiko | Risk appetite (dibahas Day 09) |
| Residual risk | Risiko yang tersisa setelah treatment | Risiko awal |
| Risk treatment plan | Rencana menjalankan treatment: tindakan, pemilik, jadwal | SoA |
| SoA | Daftar kontrol yang dibutuhkan, alasan, status, dan pengecualian | Risk register |
| Documented information | Informasi yang harus dikendalikan dan dipelihara, termasuk media penyimpannya | Hanya dokumen kertas |
| Competence | Kemampuan menerapkan pengetahuan dan keterampilan untuk hasil yang diharapkan | Awareness |
| Awareness | Pemahaman tentang kebijakan, kontribusi, dan akibat tidak patuh | Pelatihan teknis |
| Nonconformity | Tidak terpenuhinya sebuah persyaratan | Insiden |
| Correction | Tindakan memperbaiki nonconformity yang terdeteksi | Corrective action |
| Corrective action | Tindakan menghilangkan penyebab nonconformity agar tidak terulang | Correction |
| Audit programme | Rencana rangkaian audit dalam periode tertentu | Rencana satu audit (audit plan) |
| Management review | Tinjauan pimpinan atas kesesuaian, kecukupan, dan efektivitas ISMS | Rapat status proyek |
| Harmonized Structure | Kerangka klausul bersama untuk standar sistem manajemen ISO | Annex A |
| Annex A | Daftar 93 kontrol pembanding di 27001:2022 | Klausul wajib |
| Certification body (CB) | Lembaga yang mengaudit dan menerbitkan sertifikat | Badan akreditasi (KAN) |
| Pasal / subpasal | Istilah SNI untuk clause / subclause [S6] | - |

Catatan istilah: ISO/IEC 27000:2026 (edisi 6, terbit 3 Juli 2026, menggantikan edisi 2018) [S8] tidak lagi berfungsi sebagai kamus besar. Edisi ini fokus pada gambaran umum, konsep, dan hubungan antar standar; istilah bersama dikelola lewat annex, dan tiap standar boleh mendefinisikan istilahnya sendiri [S1]. Situs ISO27k menghitung definisi berkurang dari 65 menjadi 12 dan jumlah halaman dari 34 menjadi 11 [S2]. Akibatnya, rujukan definisi resmi untuk istilah seperti risk owner atau nonconformity bisa berpindah ke standar masing-masing (27001, 27005, 27035) atau ke dokumen istilah bersama yang dirujuk 27000:2026. Bagian istilah dan definisi sebuah standar biasanya bisa dibaca gratis di ISO Online Browsing Platform (OBP). Untuk interview dan pekerjaan harian, parafrase di tabel ini sudah cukup.

## 4-6. Lab gabungan dan troubleshooting

Lab ini merapikan latihan Day 01-06 menjadi satu paket mini-ISMS, lalu mengujinya seperti auditor tahap 1 menguji dokumen. Bila latihan sebelumnya belum lengkap, kerjakan dulu bagian yang kosong.

### Bagian A: daftar isi paket

Susun daftar isi paket dengan nomor dokumen dan status. Minimal berisi:

| No | Dokumen | Klausul | Asal latihan | Status |
|---|---|---|---|---|
| 1 | Register konteks (termasuk keputusan iklim) | 4.1 | Day 03 | draf/final |
| 2 | Register pihak berkepentingan | 4.2 | Day 03 | |
| 3 | Scope ISMS v1.0 | 4.3 | Day 01, 03 | |
| 4 | Peta proses ISMS | 4.4 | Day 02 | |
| 5 | Kebijakan keamanan informasi | 5.2 | Day 03 | |
| 6 | Matriks peran (RACI) | 5.3 | Day 03 | |
| 7 | Metodologi risiko dan kriteria | 6.1.2 | Day 04 | |
| 8 | Risk register | 8.2 | Day 04 | |
| 9 | SoA | 6.1.3 | Day 04 | |
| 10 | Risk treatment plan | 6.1.3, 8.3 | Day 04 | |
| 11 | Sasaran keamanan | 6.2 | Day 04 | |
| 12 | Matriks kompetensi dan komunikasi | 7.2, 7.4 | Day 05 | |
| 13 | Register informasi terdokumentasi | 7.5 | Day 02 | |
| 14 | Katalog metrik | 9.1 | Day 06 | |
| 15 | Program audit internal | 9.2 | Day 06 | |
| 16 | Notulen management review | 9.3 | Day 06 | |
| 17 | Register NC dan CA | 10.2 | Day 06 | |

### Bagian B: matriks keterlacakan

Pilih 3 risiko dari risk register-mu. Untuk setiap risiko, isi satu baris:

```
Risiko | Isu/persyaratan asal (4.1/4.2) | Kontrol di SoA | Tindakan di RTP | Sasaran (6.2) | Metrik (9.1) | Pemilik
```

Lalu pilih satu insiden fiktif dan telusuri dengan format Day 02 bagian 4.2 sampai ke 9.3 dan 10.2.

Setiap kolom seharusnya terisi. Kolom yang kosong menunjukkan putusnya rantai, dan itu temuanmu sendiri.

### Bagian C: simulasi tinjauan dokumen tahap 1

Bertindaklah sebagai auditor yang membaca paketmu. Untuk setiap dokumen, tanyakan:

- apakah dokumen punya identitas, versi, pemilik, dan persetujuan (7.5.2);
- apakah isinya konsisten dengan dokumen lain (misalnya pemilik risiko di register ada di RACI);
- apakah ada kalimat yang menyalin teks standar.

Tulis minimal 3 temuan dengan format: kondisi (apa yang ditemukan), kriteria (klausul atau kebijakan yang dirujuk), dan bukti (dokumen dan bagian). Untuk setiap temuan, tentukan apakah ia nonconformity (persyaratan 4-10 atau kebijakanmu sendiri tidak dipenuhi) atau peluang perbaikan, dengan logika yang sama seperti Day 06.

### Bagian D: uji lisan lima menit

Rekam dirimu menjelaskan klausul 4-10 berurutan dalam lima menit dengan peta konsep di bagian 3b sebagai satu-satunya bantuan. Lalu jawab tiga pertanyaan interview tanpa catatan:

- "Apa beda SoA dan risk treatment plan?" (6.1.3 d lawan 6.1.3 e)
- "Apakah setiap insiden adalah nonconformity?" (Day 06 bagian 3.5)
- "Apa yang berubah di Amd 1:2024 dan apa yang harus ditunjukkan ke auditor?" (Day 03 bagian 3.3)

Catat bagian yang membuatmu ragu; itu daftar yang perlu diulang sebelum masuk Day 08.

**Hasil yang sebaiknya tersimpan:**
- Paket mini-ISMS di `latihan/day07-paket-mini-isms.md` dengan daftar isi bagian A, setiap dokumen bernomor, berversi, dan berpemilik.
- Matriks keterlacakan tiga risiko tanpa kolom kosong, atau dengan kolom kosong yang sudah ditulis sebagai temuan.
- Satu jejak insiden fiktif yang berakhir di 9.3 dan 10.2 lalu kembali ke risk assessment.
- Minimal tiga temuan tinjauan dokumen dengan format kondisi, kriteria, bukti, dan klasifikasinya.
- Daftar topik yang masih lemah dari uji lisan, beserta Day yang perlu diulang.

### Troubleshooting paket

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Kontrol di SoA tidak muncul di risk register | Kontrol dipilih defensif | Tambahkan rujukan risiko atau persyaratan; bila tidak ada, pertimbangkan pengecualian beralasan |
| Pemilik risiko tidak ada di RACI | Dokumen ditulis terpisah | Samakan daftar jabatan di satu tempat |
| Sasaran tidak punya metrik | 6.2 dan 9.1 ditulis di hari berbeda | Tambahkan metrik dan sumber data, atau ubah sasaran |
| Notulen review tidak menyebut perubahan pihak berkepentingan | Agenda tidak berbasis 9.3.2 | Pakai template agenda Day 06 bagian 4.3 yang memetakan butir a sampai g |
| Scope menyebut SOC tetapi tidak ada bukti operasi SOC | Latihan Day 05 belum selesai | Lengkapi daftar proses operasional dan rekamannya |

## 7. Kesalahan umum dan jebakan (review)

- Menghafal nomor klausul tanpa bisa menjelaskan alirannya. Auditor dan pewawancara menguji alur, bukan hafalan.
- Menyamakan SoA dengan risk register, atau risk treatment plan dengan SoA.
- Menganggap Annex A wajib seluruhnya, padahal yang wajib adalah klausul 4-10.
- Menyebut "tersertifikasi ISO 27001" untuk diri sendiri. Sertifikat dimiliki organisasi untuk scope tertentu.
- Menyalin teks standar ke dokumen latihan atau repo. Pakai kata-kata sendiri.
- Melewatkan perubahan 2022 dan Amd 1:2024 karena belajar dari materi lama.

## 8. Catatan terkini

- ISO/IEC 27001:2022 (edisi 3) dengan Amd 1:2024 masih edisi berlaku per 2026-10-10 [S9].
- ISO/IEC 27000:2026 (edisi 6) terbit 3 Juli 2026 [S8] dan diadopsi Eropa 15 Juli 2026. Judulnya kini memakai pola "Information security, cybersecurity and privacy protection". Sertifikat 27001 yang ada tetap valid [S1]. Edisi ini jauh lebih ramping [S2].
- ISO 19011:2026 (edisi 4) terbit 27 Mei 2026 dan menjadi panduan audit sistem manajemen terbaru, menggantikan edisi 2018 [S7].
- Temuan audit 2026 yang dilaporkan satu konsultan masih seputar program audit, input management review 9.3.2 c, dan kebijakan yang belum dibaca pihak terkait [S5].

## 9. Cheat sheet minggu 1

```
ISMS = sistem manajemen risiko CIA | 27001 persyaratan (disertifikasi) | 27002 kontrol | 27005 risiko | 27035 insiden
4  Context    isu(+iklim) | pihak(+c) | scope(interface, dependency) | proses
5  Leadership komitmen | kebijakan (4 unsur) | peran: (a) sesuai standar (b) lapor kinerja
6  Planning   RA (kriteria, owner, analisis, evaluasi) | RT (opsi, kontrol, Annex A, SoA, RTP, setuju) | sasaran | perubahan
7  Support    sumber daya | kompetensi(+efektivitas) | awareness | komunikasi | dokumen (maintain/retain)
8  Operation  kriteria proses | perubahan (+tidak terencana) | pihak eksternal | RA berkala | jalankan RTP
9  Evaluation metrik (siapa ukur != siapa evaluasi) | audit internal objektif | review: 7 input -> keputusan
10 Improvement continual improvement | NC: koreksi -> akar -> CA -> efektivitas
Benang audit: risiko -> SoA -> RTP -> metrik | insiden -> prosedur -> metrik -> NC -> RA | sasaran -> metrik -> review
Baru 2022: 4.2c, 4.4, 6.1.3 note, 6.2 d/g, 6.3, 7.4, 8.1, 9.2/9.3 dipecah, 9.3.2c, 10.1/10.2 ditukar
Amd1:2024 (23 Feb 2024): iklim di 4.1 + Note 2 di 4.2 | Info terdokumentasi wajib: 15 tempat (termasuk 7.5.1b)
```

## 10. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | DQS: ISO/IEC 27000:2026 released | https://www.dqsglobal.com/en/explore/blog/iso-iec-27000-2026-released | sekunder (lembaga sertifikasi) | 2026; diakses 2026-10-08 | Sedang-tinggi. Tanggal terbit, perubahan judul, pengelolaan istilah |
| S2 | ISO27k: Slimline ISO/IEC 27000 published | https://www.iso27001security.com/post/slimline-iso-iec-27000-published | sekunder (komentar praktisi) | Juli 2026; diakses 2026-10-08 | Sedang. Hitungan definisi dan halaman; berisi opini penulis |
| S3 | IAF: IAF-ISO Joint Communique on Addition of Climate Change Considerations to MSS (memuat IAF TC Final Decision) | https://iaf.nu/wp-content/uploads/2024/02/IAF-ISO-Joint-Communique-_2024F.pdf | primer (IAF) | 2024-02-23; diakses 2026-10-10 | Tinggi. Ekspektasi untuk organisasi dan CB |
| S4 | IAF news: New 2021 edition of Annex SL | https://iaf.news/2021/07/02/new-2021-edition-of-annex-sl-for-management-system-standards/ | sekunder (situs berita IAF) | 2021-07-02; diakses 2026-10-08 | Sedang-tinggi |
| S5 | URM Consulting: Common issues identified during audits of ISO 27001:2022 | https://urmconsulting.com/blog/common-issues-identified-during-audits-of-iso-27001-2022 | sekunder (praktisi audit) | 2026-04-09; diakses 2026-10-08 | Sedang |
| S6 | BSN: RSNI3 ISO/IEC 27001:2022/Amd.1:2024 | https://bsn.go.id/uploads/attachment/rsni_iso_iec_27001-2022-amd1_1.pdf | primer | 2024; diakses 2026-10-08 | Tinggi. Istilah "subpasal" dan teks amandemen |
| S7 | ISO committee: ISO 19011:2026 | https://committee.iso.org/standard/88984.html | primer (katalog ISO) | terbit 2026-05-27; diakses 2026-10-10 | Tinggi untuk edisi 4 dan tanggal |
| S8 | ISO committee: ISO/IEC 27000:2026 | https://committee.iso.org/standard/84257.html | primer (katalog ISO) | terbit 2026-07-03; diakses 2026-10-10 | Tinggi untuk edisi 6, judul, dan tanggal |
| S9 | ISO committee: ISO/IEC 27001:2022 | https://committee.iso.org/standard/82875.html | primer (katalog ISO) | terbit 2022-10-25; diakses 2026-10-10 | Tinggi untuk edisi 3, status, dan Amd 1:2024 |

**Catatan sumber:** rincian isi 27000:2026 (pengelolaan istilah, jumlah definisi dan halaman) berasal dari lembaga sertifikasi [S1] dan komentar praktisi [S2], bukan dari teks standar; katalog ISO hanya mengonfirmasi edisi, judul, dan tanggal terbit [S8]. Di mana definisi resmi istilah inti ISMS kini ditempatkan perlu dicek di bagian istilah ISO/IEC 27000:2026. Definisi di glosarium adalah parafrase untuk belajar, bukan definisi resmi.
