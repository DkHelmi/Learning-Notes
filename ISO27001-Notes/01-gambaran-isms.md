---
day: 01
title: 'Gambaran besar ISMS: PDCA, keluarga ISO/IEC 27000, sertifikasi vs kepatuhan'
researched_on: 2026-10-10
versions_checked: 'ISO/IEC 27001:2022 edisi 3 + Amd 1:2024 (masih edisi berlaku per 2026-10-10); ISO/IEC 27002:2022 edisi 3; ISO/IEC 27005:2022 edisi 4; ISO/IEC 27035-1:2023 edisi 2; ISO/IEC 27000:2026 edisi 6 (3 Jul 2026); SNI ISO/IEC 27001:2022 dan SNI ISO/IEC 27001:2022/Amd.1:2024 (BSN)'
---

# Day 01: Gambaran besar ISMS (PDCA, keluarga ISO/IEC 27000, sertifikasi vs kepatuhan)

Cakupan: pengertian ISMS, pembagian peran standar keluarga ISO/IEC 27000, struktur klausul 4-10 dan Annex A, posisi PDCA, beda selaras dan tersertifikasi, serta letak pekerjaan SOC/IR/forensik di dalam ISMS.

> Catatan pribadi, bukan materi resmi ISO, dan bukan nasihat hukum atau audit. Teks standar ISO berhak cipta: catatan ini hanya menyebut nomor dan judul singkat klausul/kontrol, lalu menjelaskannya dengan kata-kata sendiri.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- menjelaskan apa itu ISMS dalam satu paragraf, dan kenapa ISO/IEC 27001 disebut standar persyaratan (requirements).
- membedakan peran 27000, 27001, 27002, 27005, dan 27035, serta memilih standar mana yang dirujuk untuk sebuah pertanyaan.
- menjelaskan hubungan PDCA dengan klausul 4-10, termasuk fakta bahwa sejak 2013 PDCA tidak lagi diwajibkan secara eksplisit.
- membedakan "selaras/patuh" dari "tersertifikasi", dan menyebut aktor dalam rantai sertifikasi.
- memetakan pekerjaan SOC/IR/forensik ke gambaran besar ISMS.

## 2. Konteks singkat

Di lowongan kerja, frasa "familiar with ISO 27001" biasanya berarti hal-hal berikut:
- Kamu paham bahwa pekerjaan SOC menghasilkan bukti untuk ISMS, misalnya log review, insiden yang tercatat, dan sinkronisasi waktu.
- Kamu bisa berbicara dengan bahasa auditor.
- Kamu tidak kaget saat diminta menjelaskan "kontrol apa yang didukung proses ini".

Kamu tidak perlu menjadi implementer atau auditor. Day ini membangun peta. Detail klausul ada di Day 02-06 dan kontrol di Day 08-12.

**Kapan relevan:** organisasi tempatmu bekerja tersertifikasi atau sedang menuju sertifikasi; klien meminta bukti kepatuhan; regulator sektor merujuk ISO 27001.
**Kapan bukan jawaban:** ISO 27001 tidak memberi tahu *cara* mengonfigurasi Splunk atau Wazuh. Ia menetapkan apa yang harus dikelola dan dibuktikan, bukan resep teknis.

## 3. Konsep inti

### 3.1 Apa itu ISMS

ISMS (information security management system) adalah bagian dari sistem manajemen organisasi yang memakai pendekatan risiko bisnis untuk menetapkan, menerapkan, mengoperasikan, memantau, meninjau, memelihara, dan meningkatkan keamanan informasi. Isinya meliputi struktur, kebijakan, perencanaan, tanggung jawab, prosedur, proses, dan sumber daya. Fokusnya adalah confidentiality, integrity, dan availability (CIA) [S1].

Intinya: ISMS adalah sistem manajemen, bukan produk atau alat. Firewall dan SIEM adalah kontrol, sedangkan ISMS adalah cara organisasi memutuskan kontrol apa yang dibutuhkan (berdasarkan risiko), memastikan kontrol itu berjalan, mengukurnya, dan memperbaikinya.

### 3.2 Keluarga ISO/IEC 27000: siapa melakukan apa

| Standar | Peran | Bisa disertifikasi? | Edisi berlaku (dicek 2026-10-10) |
|---|---|---|---|
| ISO/IEC 27000 | Gambaran umum dan kosakata keluarga ISMS | Tidak | Edisi 6 terbit 3 Jul 2026, menggantikan edisi 2018 [S9]; tidak memengaruhi validitas sertifikat [S2] |
| ISO/IEC 27001 | Persyaratan ISMS (klausul 4-10 + Annex A berisi daftar kontrol) | Ya | 27001:2022 (edisi 3, terbit Okt 2022) + Amd 1:2024 (terbit 23 Feb 2024, perubahan terkait aksi iklim di 4.1 dan 4.2) [S11][S3][S4] |
| ISO/IEC 27002 | Panduan penerapan kontrol (penjelasan tiap kontrol di Annex A) | Tidak | 27002:2022; 93 kontrol dalam 4 tema [S5] |
| ISO/IEC 27005 | Panduan manajemen risiko keamanan informasi | Tidak | 27005:2022 (edisi 4, terbit 25 Okt 2022) [S10] |
| ISO/IEC 27035 (seri) | Panduan manajemen insiden keamanan informasi | Tidak | 27035-1:2023, edisi 2, terbit 13 Feb 2023 [S6] |

**Aturan praktis:**
- "Kita harus apa?": 27001 (shall).
- "Bagaimana menerapkan kontrol X?": 27002 (should).
- "Bagaimana menilai risiko?": 27005.
- "Bagaimana proses IR?": 27035.

Hanya 27001 yang diaudit untuk sertifikasi. Organisasi tidak "tersertifikasi 27002".

### 3.3 Struktur 27001: klausul 4-10 dan Annex A

Sejak edisi 2013, 27001 memakai struktur tingkat tinggi yang sama dengan standar sistem manajemen ISO lain (dulu disebut Annex SL, kini Harmonized Structure). Akibatnya, ISMS mudah diintegrasikan dengan ISO 9001, 22301, dan lainnya [S1][S7]. Klausul yang wajib dipenuhi:

| Klausul | Judul (singkat) | Gagasan inti (kata sendiri) |
|---|---|---|
| 4 | Context of the organization | Pahami organisasi, pihak berkepentingan, dan tetapkan scope ISMS |
| 5 | Leadership | Komitmen pimpinan, kebijakan, peran dan wewenang |
| 6 | Planning | Penilaian dan penanganan risiko, sasaran keamanan, SoA |
| 7 | Support | Sumber daya, kompetensi, awareness, komunikasi, informasi terdokumentasi |
| 8 | Operation | Menjalankan rencana dan risk treatment |
| 9 | Performance evaluation | Pemantauan/pengukuran, internal audit, management review |
| 10 | Improvement | Perbaikan berkelanjutan, nonconformity, dan tindakan korektif |

Klausul 0-3 bersifat pengantar (pendahuluan, ruang lingkup standar, acuan, istilah).

Annex A (27001:2022) berisi 93 kontrol dalam empat tema:

| Tema | Jumlah kontrol |
|---|---|
| Organizational | 37 |
| People | 8 |
| Physical | 14 |
| Technological | 34 |

Ini menggantikan 114 kontrol dalam 14 domain di edisi 2013 [S5][S1]. Annex A adalah daftar acuan. Organisasi memilih kontrol berdasarkan risiko, lalu mencatat pilihan dan alasannya di Statement of Applicability (SoA) [S1].

Pembagian 37/8/14/34 cocok dengan penomoran kontrolnya: 5.1-5.37 (Organizational), 6.1-6.8 (People), 7.1-7.14 (Physical), dan 8.1-8.34 (Technological) [S5]. Bila menemukan artikel dengan pembagian lain, cocokkan dengan penomoran ini.

### 3.4 PDCA: dulu wajib, sekarang kerangka berpikir

- 27001:2005 menyatakan eksplisit bahwa ISMS mengikuti model PDCA [S1].
- 27001:2013 (dan dipertahankan di 2022) tidak menetapkan model proses tertentu. Yang diwajibkan adalah continual improvement. PDCA tetap sah, tetapi organisasi boleh memakai model lain [S1].
- Banyak materi pelatihan tetap memetakan klausul ke PDCA: Plan = 4-6, Do = 7-8, Check = 9, Act = 10 [S7]. Pemetaan ini berguna untuk memahami alurnya, tetapi itu interpretasi, bukan teks persyaratan.
- Perubahan kecil di 2022: urutan klausul 10 dibalik (10.1 continual improvement, 10.2 nonconformity and corrective action) agar seragam dengan standar sistem manajemen lain [S7].

**Kenapa ini penting di interview:** jika ditanya "apakah ISO 27001 mewajibkan PDCA?", jawaban yang tepat: "Tidak lagi secara eksplisit sejak 2013. Yang diwajibkan adalah continual improvement, dan PDCA tetap cara umum untuk memahaminya."

### 3.5 Sertifikasi vs kepatuhan

- **Selaras/patuh (aligned/compliant):** organisasi menerapkan praktik sesuai 27001, tetapi tidak diaudit pihak ketiga terakreditasi. Ini klaim internal.
- **Tersertifikasi:** lembaga sertifikasi (certification body, CB) yang terakreditasi mengaudit ISMS terhadap 27001 dan menerbitkan sertifikat untuk scope tertentu. ISO sendiri tidak menerbitkan sertifikat. Akreditasi CB dilakukan badan akreditasi nasional; di Indonesia badan itu adalah KAN (Komite Akreditasi Nasional). Badan akreditasi nasional saling mengakui hasil akreditasinya lewat pengaturan multilateral yang selama ini dikenal sebagai IAF MLA, sehingga sertifikat dari CB terakreditasi di satu negara diakui di negara lain. IAF berhenti beroperasi pada 1 Januari 2026 dan fungsinya dilanjutkan Global Accreditation Cooperation Incorporated (Global ACI), yang menjalankan pengaturan multilateralnya sendiri [S12]. Dokumen lama tetap menyebut IAF MLA dan IAF MD; cakupan pengakuan KAN untuk sertifikasi ISMS saat ini perlu dicek di direktori KAN atau daftar penanda tangan Global ACI.
- **Siklus umum:** audit tahap 1 (kesiapan dan dokumen), audit tahap 2 (efektivitas penerapan), lalu surveillance audit minimal sekali setahun selama siklus sertifikat tiga tahun, diakhiri recertification audit. Aturan audit untuk CB ada di ISO/IEC 17021-1 (semua sistem manajemen) dan ISO/IEC 27006-1:2024 (tambahan khusus ISMS). Detailnya di Day 13 dan 17.
- Scope itu krusial. Sertifikat bisa hanya mencakup satu data center atau satu layanan. "Perusahaan X tersertifikasi ISO 27001" tidak otomatis berarti SOC atau semua sistemnya ada di dalam scope.

Di CV, tulis "berkontribusi pada bukti kontrol logging/insiden untuk ISMS yang tersertifikasi ISO/IEC 27001", bukan "certified ISO 27001". Sertifikat dimiliki organisasi, bukan individu. Sertifikasi individu (lead implementer/auditor) adalah hal yang berbeda.

### 3.6 Kenapa perusahaan melakukannya

- **Tuntutan pasar/kontrak:** klien dan mitra (terutama layanan TI/cloud/keuangan) meminta bukti.
- **Regulasi:** beberapa regulator sektor merujuk atau mendorong standar ini. Di Indonesia, BSN mengadopsi 27001:2022 secara identik sebagai SNI ISO/IEC 27001:2022, dan Amd 1:2024 diadopsi sebagai amandemen pertamanya (SNI ISO/IEC 27001:2022/Amd.1:2024, ditetapkan 2024) [S4]. Nomor keputusan penetapan SNI ISO/IEC 27001:2022 dan masa transisi dari SNI edisi 2013 perlu dicek di JDIH BSN (jdih.bsn.go.id). Untuk sertifikat terakreditasi, masa transisi global dari edisi 2013 sudah berakhir 31 Oktober 2025: sejak 30 April 2024 sertifikasi awal dan resertifikasi harus memakai edisi 2022, dan sertifikat edisi 2013 yang belum ditransisikan gugur setelah tanggal itu [S13].
- **Tata kelola internal:** keputusan keamanan berbasis risiko yang terdokumentasi, bukan berbasis selera atau vendor.
- Bahasa bersama dengan standar sistem manajemen lain (struktur seragam) [S1].

### 3.7 Di mana SOC/IR/forensik berada

Gambaran kasar (detail di Day 10-13):
- **Klausul 6/8:** risiko yang ditangani dengan kontrol deteksi dan respons.
- **Annex A tema Technological:** misalnya kontrol 8.15 Logging, 8.16 Monitoring activities, 8.17 Clock synchronization. Kontrol-kontrol ini adalah "rumah" alami SIEM [S8].
- **Annex A tema Organizational:** 5.7 Threat intelligence, serta kelompok manajemen insiden 5.24 sampai 5.28 (perencanaan, penilaian, respons, pembelajaran, dan pengumpulan bukti). Detail di Day 10 dan 12.
- **Klausul 9:** metrik SOC (MTTD/MTTR, cakupan log) bisa menjadi bagian dari monitoring & measurement. Insiden dan temuan forensik menjadi input management review dan tindakan korektif (klausul 10).

Auditor tidak bertanya "SIEM apa yang kalian pakai". Mereka bertanya "tunjukkan bahwa log yang relevan dibuat, dilindungi, dan ditinjau, dan bahwa hasil tinjauan ditindaklanjuti" [S8].

## 4. Contoh dokumen / artefak (organisasi fiktif)

> Fiktif: "PT Awan Nusantara" (PT AN), penyedia layanan hosting kecil di Jakarta, 120 karyawan.

### 4.1 Pernyataan scope ISMS (draf)

```
Scope ISMS PT Awan Nusantara (draf v0.1)
Mencakup: pengelolaan keamanan informasi untuk layanan "AN-Hosting" (managed VM),
termasuk operasi SOC 24x7, data center Jakarta-1, dan tim Platform Engineering.
Tidak mencakup: divisi pemasaran, kantor cabang Surabaya.
Antarmuka: penyedia colocation (pihak ketiga) untuk listrik dan pendinginan Jakarta-1.
Acuan persyaratan: ISO/IEC 27001:2022 + Amd 1:2024.
```

| Elemen | Kenapa ada |
|---|---|
| Layanan yang dicakup | Klien membeli layanan ini, jadi sertifikasi harus relevan dengan yang mereka beli |
| SOC masuk scope | Bukti logging dan insiden dihasilkan SOC. Jika di luar scope, kontrol deteksi sulit dibuktikan |
| Pengecualian eksplisit | Mencegah salah klaim. Pengecualian harus beralasan |
| Antarmuka pihak ketiga | Risiko yang tidak dikendalikan langsung tetap harus dikelola |
| Acuan versi + amandemen | Amd 1:2024 mengubah 4.1/4.2 (isu iklim) [S3][S4] |

### 4.2 Tabel pertanyaan dan standar rujukan

| Pertanyaan di kantor | Standar yang dirujuk | Alasan |
|---|---|---|
| "Kontrol apa yang wajib kita punya?" | 27001 klausul 6 + SoA | Pemilihan berbasis risiko; Annex A sebagai pembanding |
| "Bagaimana sebaiknya log review dijalankan?" | 27002 (panduan kontrol logging) | Panduan penerapan |
| "Skala likelihood/impact apa yang dipakai?" | 27005 | Panduan risiko |
| "Bagaimana tahapan penanganan insiden?" | 27035-1 | Prinsip dan proses manajemen insiden [S6] |
| "Istilah 'nonconformity' artinya apa?" | 27000 | Kosakata [S2] |

### 4.3 Peta PDCA untuk SOC PT AN (interpretasi)

| Fase | Klausul (pemetaan umum) | Contoh aktivitas SOC | Bukti yang dihasilkan |
|---|---|---|---|
| Plan | 4-6 | Ikut workshop risk assessment: "log server hosting tidak dipantau" | Entri risk register, rencana treatment |
| Do | 7-8 | Onboard log VM ke Wazuh/Splunk; training analyst | Daftar sumber log, catatan pelatihan |
| Check | 9 | Laporan bulanan cakupan log dan MTTR; ikut diaudit internal | Laporan metrik, temuan audit |
| Act | 10 | Perbaiki gap (mis. clock drift di 5 host) | Catatan tindakan korektif |

## 5. Lab praktik (latihan dokumen; organisasi fiktif)

Latihan ISO berupa dokumen, bukan lab teknis.

1. Buat organisasi fiktifmu sendiri (sektor, ukuran, 2-3 layanan). Jangan memakai tempat kerja nyata.
2. Tulis pernyataan scope seperti bagian 4.1, termasuk minimal satu pengecualian beralasan dan satu antarmuka pihak ketiga.
3. Isi tabel bagian 4.2 dengan 5 pertanyaan yang sering kamu dengar di SOC.
4. Buat peta PDCA bagian 4.3 untuk SOC fiktifmu.
5. **Hubungkan ke lab:** di Splunk/Wazuh lab, identifikasi tiga artefak yang bisa menjadi bukti. Contohnya: dashboard jumlah sumber log aktif, laporan alert yang ditriage per bulan, dan status sinkronisasi NTP host. Tulis tiap artefak, kontrol/klausul yang mungkin didukung, dan pemilik (nomor kontrol dibahas lebih rinci di Day 11).
6. Tulis dua baris CV yang jujur tentang keterlibatanmu dengan ISMS (atau rencana keterlibatan), tanpa mengklaim sertifikasi pribadi.

**Hasil yang sebaiknya tersimpan:**
- Satu dokumen 1-2 halaman di `latihan/day01-<nama-org-fiktif>.md`.
- Scope menyebut yang masuk, yang tidak, dan antarmuka.
- Setiap baris tabel menunjuk standar yang tepat (27001 vs 27002 vs 27005 vs 27035).
- Tidak ada kalimat yang disalin dari teks standar.
- Baris CV tidak menyiratkan sertifikasi individu.

**Variasi tantangan:** jelaskan dalam 5 kalimat kepada manajer non-teknis kenapa "kita pakai Splunk" bukan jawaban atas pertanyaan auditor tentang logging.

## 6. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Bingung apakah sesuatu "wajib" | Mencampur 27001 (shall) dan 27002 (guidance) | Cek: apakah ada di klausul 4-10 atau dipilih lewat SoA? |
| Scope terlalu luas/sempit | Tidak dikaitkan dengan layanan/klien | Mulai dari "apa yang dibeli klien dan apa yang diminta regulator" |
| Jumlah kontrol berbeda di berbagai artikel | Artikel memakai edisi 2013 (114) atau salah hitung | Pastikan edisi 2022 (93; 37/8/14/34) [S5] |
| Ragu apakah PDCA wajib | Materi lama (2005) | Sejak 2013 tidak eksplisit; continual improvement yang wajib [S1] |
| Tidak tahu versi SNI yang berlaku | Dokumen lama masih menyebut SNI edisi 2013 | Acuan saat ini SNI ISO/IEC 27001:2022 + Amd.1:2024 [S4]; nomor keputusan penetapan dicek di JDIH BSN |

## 7. Kesalahan umum dan jebakan

- "Kami tersertifikasi 27002." Hanya 27001 yang dapat disertifikasi. 27002 adalah panduan.
- Menganggap Annex A sebagai checklist wajib semua. Kontrol dipilih berdasarkan risiko dan dicatat di SoA [S1].
- Mengira ISO menerbitkan sertifikat. Sertifikat diterbitkan lembaga sertifikasi yang terakreditasi.
- Mengabaikan scope. Sertifikat perusahaan belum tentu mencakup sistem yang kamu pegang.
- Mengutip teks standar di dokumen atau repo publik. Itu pelanggaran hak cipta. Cukup nomor, judul singkat, dan kata-katamu sendiri.
- Menyebut PDCA sebagai "persyaratan". Sudah tidak eksplisit sejak 2013 [S1].
- `[komunitas, belum terkonfirmasi]` Praktisi sering menekankan bahwa auditor mencari disiplin operasional (log benar-benar ditinjau dan ditindaklanjuti), bukan hanya kebijakan tertulis [S8]. Ini sejalan dengan klausul 9, tetapi sumbernya sekunder/vendor.

## 8. Catatan terkini

- ISO/IEC 27000:2026 (edisi 6) terbit 3 Jul 2026 [S9]; adopsi Eropa (EN) menyusul 15 Jul 2026. Sertifikat 27001 yang ada tetap valid [S2]. Per 2026-10-10 katalog ISO masih mencantumkan 27001:2022 dengan satu amandemen sebagai edisi berlaku [S11]; cek katalog yang sama bila ada kabar revisi 27001.
- Amd 1:2024 (Climate action changes) terbit 23 Feb 2024 dan menambah pertimbangan isu iklim di konteks organisasi (4.1) dan pihak berkepentingan (4.2) [S3][S4]. Rinciannya di Day 03.
- SNI ISO/IEC 27001:2022/Amd.1:2024 diadopsi identik, disusun Komtek 35-04 (sekretariat di BSSN), konsensus 21 Jun 2024, jajak pendapat 18 Jul sampai 1 Agu 2024, dan ditetapkan BSN tahun 2024 [S4].
- Masa transisi sertifikat dari 27001:2013 ke 2022 berakhir 31 Oktober 2025 [S13]. Sertifikat edisi 2013 yang masih ditunjukkan pemasok setelah tanggal itu sudah tidak berlaku.
- Sejak 1 Januari 2026, IAF dan ILAC digantikan Global ACI [S12]. Situs iaf.nu kini berstatus arsip.
- ISO/IEC 27035-1:2023 (edisi 2) adalah acuan manajemen insiden terbaru untuk Day 10 [S6].

## 9. Cheat sheet

```
ISMS   = sistem manajemen berbasis risiko untuk CIA informasi (bukan alat)
27000  kosakata (2026, ed.6)   27001 PERSYARATAN, satu-satunya yang disertifikasi (2022 + Amd1:2024)
27002  panduan kontrol (2022)  27005 risiko   27035 insiden (27035-1:2023)

Klausul 4 Context | 5 Leadership | 6 Planning | 7 Support | 8 Operation | 9 Perf. evaluation | 10 Improvement
PDCA (interpretasi): Plan 4-6 | Do 7-8 | Check 9 | Act 10  -- PDCA tidak eksplisit wajib sejak 2013
Annex A 2022: 93 kontrol = Organizational 37 + People 8 + Physical 14 + Technological 34
SoA   = daftar kontrol Annex A: dipakai/tidak + alasan
Sertifikat: diterbitkan CB terakreditasi, untuk SCOPE tertentu; ISO tidak menerbitkan sertifikat
SNI ISO/IEC 27001:2022 (+ Amd.1:2024) = adopsi identik oleh BSN
```

## 10. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | IT Governance Ltd: Comparing ISO 27001:2005 to ISO 27001:2013 (whitepaper) | tautan asli tidak lagi tersedia | sekunder (konsultan) | Okt 2013 | Sedang-tinggi untuk fakta perubahan 2005 ke 2013 (PDCA tidak lagi eksplisit, struktur seragam, peran SoA) |
| S2 | DQS: ISO/IEC 27000:2026 released | https://www.dqsglobal.com/en/explore/blog/iso-iec-27000-2026-released | sekunder (lembaga sertifikasi) | 2026; diakses 2026-10-10 | Sedang-tinggi. Tanggal adopsi EN dan dampak ke sertifikat |
| S3 | ISO committee: ISO/IEC 27001:2022/Amd 1:2024 Climate action changes | https://committee.iso.org/standard/88435.html | primer (katalog ISO) | terbit 2024-02-23; diakses 2026-10-10 | Tinggi untuk judul dan tanggal terbit |
| S4 | BSN: RSNI3 ISO/IEC 27001:2022/Amd.1:2024 | https://bsn.go.id/uploads/attachment/rsni_iso_iec_27001-2022-amd1_1.pdf | primer | 2024; diakses 2026-10-10 | Tinggi. Prakata (adopsi identik, amandemen pertama SNI ISO/IEC 27001:2022, tanggal konsensus dan jajak pendapat) dan susunan komite |
| S5 | Pivot Point Security: The new ISO 27002:2022: what are themes | https://www.pivotpointsecurity.com/the-new-iso-270022022-what-are-themes-and-why-are-they-cool | sekunder (konsultan) | 2022-03-15, diperbarui 2025-02-12; diakses 2026-10-07 | Sedang. Angka 37/8/14/34, cocok dengan penomoran kontrol |
| S6 | ISO committee: ISO/IEC 27035-1:2023 | https://committee.iso.org/standard/78973.html | primer (katalog ISO) | terbit 2023-02-13; diakses 2026-10-10 | Tinggi untuk edisi dan tanggal terbit |
| S7 | BSI: The final stretch of the ISO/IEC 27001 version transition (materi webinar) | https://www.bsigroup.com/globalassets/localfiles/en-th/webinars/document/material/the-final-stretch-of-the-isoiec-27001-version-transition-3-aug-24.pdf | sekunder (lembaga sertifikasi) | Agu 2024 | Sedang. Harmonized Structure dan urutan klausul 10; pemetaan PDCA ke klausul adalah interpretasi |
| S8 | Advisera: ISO 27001 control 8.15 Logging | https://advisera.com/iso27001/control-8-15-logging/ | sekunder (konsultan) | diakses 2026-10-07 | Sedang. Nomor dan judul 8.15 serta gambaran ekspektasi auditor |
| S9 | ISO committee: ISO/IEC 27000:2026 | https://committee.iso.org/standard/84257.html | primer (katalog ISO) | terbit 2026-07-03; diakses 2026-10-10 | Tinggi untuk edisi 6 dan tanggal terbit |
| S10 | ISO committee: ISO/IEC 27005:2022 | https://committee.iso.org/standard/80585.html | primer (katalog ISO) | terbit 2022-10-25; diakses 2026-10-10 | Tinggi untuk edisi 4 dan tanggal terbit |
| S11 | ISO committee: ISO/IEC 27001:2022 | https://committee.iso.org/standard/82875.html | primer (katalog ISO) | terbit 2022-10-25; diakses 2026-10-10 | Tinggi untuk edisi 3, status published, dan satu amandemen (Amd 1:2024) |
| S12 | IAF (situs arsip): pemberitahuan penghentian operasi IAF dan pembentukan Global ACI | https://iaf.nu/en/home/ | primer (IAF) | diakses 2026-10-10 | Tinggi untuk tanggal 1 Januari 2026; tidak merinci nasib pengakuan IAF MLA yang lama |
| S13 | NSAI: ISO/IEC 27001:2022 transition policy | https://www.nsai.ie/certification/management-systems/iso-iec-27001-information-security-management-system/iso-iec-270012022-transition-policy/ | sekunder (lembaga sertifikasi) | diakses 2026-10-10 | Sedang-tinggi. Batas 30 April 2024 dan 31 Oktober 2025 menurut IAF MD 26 |

**Catatan sumber:** pemetaan PDCA ke klausul 4-10 adalah interpretasi materi pelatihan, bukan teks persyaratan. Batas transisi 2013 ke 2022 diambil dari kebijakan transisi satu lembaga sertifikasi yang merujuk IAF MD 26, bukan dari dokumen IAF MD 26 itu sendiri. Nomor keputusan penetapan SNI ISO/IEC 27001:2022 belum ditemukan di sumber yang dipakai, sehingga ditulis sebagai hal yang perlu dicek di JDIH BSN.
