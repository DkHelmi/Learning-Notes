---
day: 14
title: 'Capstone dan interview: pemetaan aktivitas SOC/IR/forensik ke klausul dan kontrol, 10 pertanyaan interview, dan baris CV yang jujur'
researched_on: 2026-10-10
versions_checked: 'ISO/IEC 27001:2022 + Amd 1:2024 (masih edisi berlaku; transisi 2013 berakhir 31 Okt 2025); ISO/IEC 27002:2022; ISO/IEC 27035-1:2023; ISO/IEC 27006-1:2024; NIST CSF 2.0 Informative Reference ISO/IEC 27001:2022'
---

# Day 14: Capstone dan interview

Cakupan: ringkasan Minggu 2 (Day 08-13), peta konsep dan glosarium, tabel pemetaan aktivitas SOC/IR/forensik ke klausul, kontrol, dan bukti, 10 pertanyaan interview dengan jawaban contoh (Indonesia dan versi singkat English), 5 baris CV yang jujur, serta rencana lanjutan.

## Ide inti

Bagi analyst SOC, "familiar with ISO 27001" berarti tiga kemampuan: memetakan pekerjaan yang benar-benar kamu lakukan ke klausul dan kontrol, menyebut bukti yang dihasilkan pekerjaan itu, dan berbicara jujur tentang batas pengalamanmu. Day 01-13 sudah memberi semua bahannya. Capstone ini merangkumnya menjadi satu tabel pemetaan, sepuluh jawaban interview, dan lima baris CV yang bisa dipertahankan saat ditanya lebih dalam.

Lowongan SOC dan security analyst sering menyebut ISO 27001 dalam bentuk "mendukung audit ISO 27001", "memelihara bukti audit", atau "pengalaman dengan ISO 27001, SOC 2, PCI DSS" [S1]. Pewawancara jarang menguji hafalan klausul; biasanya mereka menguji tiga hal:

- apakah kamu paham bahwa pekerjaan SOC menghasilkan bukti untuk ISMS;
- apakah kamu bisa berbicara dengan bahasa audit;
- apakah kamu jujur tentang batas pengalamanmu.

Kamu sudah mengenal cara berpikir ini dari coverage mapping detection ke ATT&CK. Satu rule bisa menutup beberapa teknik, satu teknik dideteksi beberapa rule, dan mapping baru berguna bila setiap baris bisa ditunjukkan dengan data source yang benar-benar masuk. Tabel pemetaan di bagian 1.4 bekerja dengan cara yang sama: satu aktivitas SOC bisa membuktikan beberapa kontrol, dan setiap baris harus berujung pada rekaman yang bisa disampel auditor. Bukti tetap artefak yang bisa ditunjukkan (tiket, laporan, dashboard, log), bukan klaim.

```
Pekerjaan harian SOC/IR/forensik (triage, investigasi, onboarding log, hunting, PIR)
  -> rekaman yang dihasilkan (tiket, formulir chain of custody, repo rule, laporan metrik)
  -> klausul dan kontrol yang dibuktikan (5.24-5.28, 8.15-8.17, 9.1, 10.2, ...)
  -> jawaban interview: klausul/kontrol + contoh konkret + bukti + kejujuran
  -> baris CV yang hanya mengklaim yang benar-benar dilakukan
```

Situasi yang dipakai sepanjang Day ini: lowongan analyst L2 di PT Awan Nusantara (PT AN, penyedia hosting fiktif), hasil keputusan management review 2026-11-20, sudah tayang. Iklannya menulis "familiar with ISO 27001" dan "mendukung audit serta memelihara bukti audit". Lead SOC memintamu ikut panel interview:

> "Sebelum interview dimulai, tolong siapkan tiga hal. Pertama, tabel pekerjaan SOC kita beserta klausul, kontrol, dan bukti yang dihasilkannya, supaya panel punya acuan yang sama. Kedua, sepuluh pertanyaan ISO 27001 dengan jawaban yang kita harapkan. Ketiga, contoh baris CV yang jujur dan yang berlebihan, karena beberapa CV yang masuk menulis 'ISO 27001 certified'. Kamu sendiri juga harus bisa menjawab semuanya."

Permintaan pertama dijawab bagian 1.4 (dengan ringkasan, peta, dan glosarium di bagian 1.1-1.3 sebagai bahannya), permintaan kedua bagian 1.5, dan permintaan ketiga bagian 1.6. Lab di bagian 2-4 memintamu menerapkan ketiganya pada dirimu sendiri.

Catatan ini tidak membuatmu menjadi implementer atau auditor; syarat kredensial auditor ada di bagian 6. Yang bisa kamu klaim adalah pemahaman kerangka dan kemampuan memetakan pekerjaan teknis ke kerangka itu. Day 15-19 berikutnya memperdalam audit internal, penutupan temuan dan management review, sistem sertifikasi dan akreditasi, regulasi Indonesia, serta kelangsungan, cloud, dan privasi.

**Kapan relevan:** persiapan interview, menulis atau merapikan CV, menyusun daftar kerja SOC menjelang audit, dan saat menutup rangkaian Day 01-13.
**Kapan bukan jawaban:** capstone ini tidak menambah persyaratan atau kontrol baru. Bila ada yang terasa baru, kembali ke Day asalnya.

## 1. Ringkasan, peta konsep, dan pemetaan

### 1.1 Ringkasan Day 08-13

Ringkasan ini adalah bahan mentah tabel pemetaan di bagian 1.4. Bila salah satu butir terasa asing, ulangi Day asalnya sebelum masuk ke tabel.

- **Day 08, Annex A 2022:** 93 kontrol dalam empat tema (37/8/14/34), 11 kontrol baru (yang paling relevan untuk SOC adalah 5.7 dan 8.16), lima jenis atribut 27002 yang tidak wajib, dan mapping resmi NIST dari ISO/IEC 27001:2022 ke CSF 2.0 [S4].
- **Day 09, risiko praktik:** appetite, tolerance, dan kriteria penerimaan; skenario berbasis kejadian dan aset; estimasi kemungkinan dengan data; pengantar Open FAIR; KRI.
- **Day 10, insiden:** lima fase 27035 (plan and prepare, detect and report, assess and decide, respond, learn lessons) yang dipetakan ke 5.24-5.28 dan 6.8 [S6]; NIST SP 800-61r3; 27037 untuk bukti; tenggat 3 x 24 jam di UU PDP.
- **Day 11, logging:** 8.15 mencatat, 8.16 memantau dan menindaklanjuti, 8.17 waktu konsisten; retensi tanpa angka baku; konfigurasi retensi di Splunk dan Wazuh; panduan logging ASD/CISA [S7].
- **Day 12, intel dan kerentanan:** 5.7 dengan tiga tingkat intel dan keputusan yang tercatat; 8.8 dengan KEV, EPSS, dan CVSS v4.0; pemasok dan cloud (5.19-5.23, 27017:2026).
- **Day 13, audit:** siklus tiga tahun dengan surveillance minimal sekali per tahun kalender, aturan CB di 17021-1 dan 27006-1:2024 [S3], grading major dan minor, struktur temuan (kondisi, kriteria, bukti), paket bukti, dan sikap saat wawancara.

### 1.2 Peta konsep

Peta berikut menggabungkan Day 08-13 dalam satu gambar. Pakai sebagai satu-satunya bantuan saat simulasi interview di bagian 2-4.

```
Risiko (6.1.2, 8.2) --menentukan--> kontrol yang dipilih (SoA, 6.1.3)
        |                                   |
        |                    SOC menjalankan: 5.7 TI, 5.24-5.28 insiden, 6.8 lapor,
        |                                     8.8 kerentanan, 8.15-8.17 log/monitor/waktu
        |                                   |
        |                       rekaman (tiket, log, laporan, PIR) = BUKTI
        |                                   |
   KRI dan metrik (9.1) <------------------+-----> audit internal (9.2) dan CB (17021-1, 27006-1)
        |                                                   |
        +--------> management review (9.3) <---- temuan --> NC dan corrective action (10.2)
                              |
                        keputusan perubahan ISMS (10.1)
```

Kontrol dipilih karena risiko, rekaman kerja SOC menjadi bukti untuk metrik dan audit, dan hasil keduanya kembali ke management review serta corrective action.

### 1.3 Glosarium Minggu 2

Istilah berikut muncul di Day 08-13 dan dipakai di tabel pemetaan serta jawaban interview. Istilah Minggu 1 ada di glosarium Day 07 bagian 1.8.

| Istilah | Arti singkat |
|---|---|
| Atribut kontrol | Label di 27002 (lima jenis) untuk menyaring kontrol; tidak wajib |
| KRI | Key risk indicator: indikator yang memberi tanda awal bahwa level risiko berubah |
| PIR | Post-incident review: tinjauan setelah insiden, bukti untuk 5.27 |
| Chain of custody | Catatan siapa memegang bukti forensik, kapan, dan bagaimana integritasnya dijaga |
| Populasi | Daftar lengkap rekaman yang menjadi dasar auditor memilih sampel |
| Major nonconformity | Nonconformity yang memengaruhi kemampuan ISMS mencapai hasil yang diharapkan |
| Minor nonconformity | Nonconformity yang tidak memengaruhi kemampuan tersebut |
| OFI | Opportunity for improvement: saran perbaikan, tidak wajib |
| Surveillance | Audit CB minimal sekali per tahun kalender di antara sertifikasi dan resertifikasi |

### 1.4 Tabel pemetaan aktivitas, klausul, kontrol, dan bukti

Ini jawaban untuk permintaan pertama Lead SOC dan artefak utama capstone. Klausul dan kontrol dipisah karena nomornya bisa sama: klausul 8.2 adalah risk assessment, kontrol 8.2 adalah privileged access rights. Kolom bukti berisi rekaman yang akan disampel auditor, jadi baca tabel ini dari kiri ke kanan: aktivitas, lalu apa yang dibuktikannya, lalu rekaman yang bisa ditunjukkan.

| No | Aktivitas SOC/IR/forensik | Klausul | Kontrol Annex A | Bukti yang dihasilkan |
|---|---|---|---|---|
| 1 | Triage alert dan klasifikasi event | - | 5.25, 8.16 | Tiket dengan prioritas dan alasan klasifikasi |
| 2 | Investigasi, containment, eradikasi | - | 5.26 | Timeline tiket, catatan tindakan |
| 3 | Akuisisi bukti forensik (disk, memori, log) | - | 5.28 (panduan ISO/IEC 27037) | Formulir chain of custody, hash, lokasi simpan |
| 4 | Post-incident review | 10.2 | 5.27 | Laporan PIR, ID corrective action |
| 5 | Melaporkan event dari karyawan | - | 6.8 | Tiket yang berasal dari kanal pelaporan |
| 6 | Latihan tabletop IR | 7.2 | 5.24 | Skenario, daftar hadir, catatan pelajaran |
| 7 | Onboarding sumber log | 8.1 | 8.15, 5.9 | Inventaris sumber log yang terhubung ke inventaris aset, tiket validasi |
| 8 | Menulis dan tuning rule deteksi | - | 8.16, 8.32 | Repo rule dengan riwayat review dan persetujuan |
| 9 | Memeriksa sinkronisasi waktu | - | 8.17 | Laporan NTP atau laporan lag waktu SIEM |
| 10 | Mengelola retensi dan akses log | - | 8.15, 5.33, 8.10, 8.2 | Konfigurasi retensi, daftar role, audit trail admin |
| 11 | Brief threat intelligence | - | 5.7 | Brief berkala dengan keputusan dan tindakan |
| 12 | Prioritas kerentanan bersama tim platform | - | 8.8 | Tiket patch, laporan umur kerentanan, pengecualian SLA |
| 13 | Threat hunting | 10.1 | 8.16, 5.7 | Laporan hunt (termasuk hasil negatif), rule baru |
| 14 | Laporan metrik bulanan SOC | 9.1, 6.2 | - | Laporan dan query sumbernya |
| 15 | Masukan ke risk assessment | 6.1.2, 8.2 | - | Entri risk register dengan alasan berbasis data |
| 16 | Runbook dan prosedur | 7.5 | 5.37 | Runbook berversi dengan penyetuju |
| 17 | Pelatihan dan QA analyst | 7.2, 7.3 | 6.3 | Matriks kompetensi, skor QA, rekaman pelatihan |
| 18 | Notifikasi insiden ke klien atau regulator | 7.4 | 5.5, 5.26, 5.31, 5.34 | Salinan pemberitahuan dan waktu kirim |
| 19 | Kontak dengan CERT, ISAC, penegak hukum | - | 5.5, 5.6 | Daftar kontak, catatan komunikasi |
| 20 | Evaluasi MSSP atau SIEM cloud | - | 5.19-5.23 | Kuesioner, laporan SLA, notulen tinjauan |
| 21 | Tinjauan akses admin SIEM dan EDR | - | 8.2, 5.3, 5.18 | Hasil review akses berkala |
| 22 | Dukungan audit internal dan eksternal | 9.2 | 8.34 | Paket bukti, akun auditor read-only yang tercatat |

Cara memakai tabel ini:

- Untuk interview, pilih 3-4 baris yang pernah kamu kerjakan dan siapkan satu cerita konkret per baris. Bagi panel PT AN, tabel yang sama menjadi acuan untuk menilai apakah cerita kandidat menyebut bukti, bukan hanya alat.
- Untuk pekerjaan nyata, tabel ini menjadi daftar kerja SOC saat persiapan audit (Day 08 bagian 2.2, Day 13 bagian 1.6).

### 1.5 Sepuluh pertanyaan interview

Ini jawaban untuk permintaan kedua Lead SOC. Jawaban contoh ditulis untuk analyst SOC dan forensik yang belum pernah memegang peran GRC; sesuaikan dengan pengalamanmu.

**1. Apa itu ISO 27001, dan apa bedanya dengan 27002?**
ISO 27001 berisi persyaratan untuk membangun dan menjalankan ISMS, terdiri dari klausul 4-10 dan Annex A sebagai daftar kontrol pembanding. Hanya 27001 yang bisa disertifikasi. ISO 27002 adalah panduan cara menerapkan kontrol, termasuk atribut kontrol.
*EN:* "27001 sets the ISMS requirements and is certifiable; 27002 is implementation guidance for the Annex A controls."

**2. Bagaimana SOC mendukung ISMS?**
SOC menjalankan dan membuktikan sebagian besar kontrol deteksi dan respons: logging (8.15), monitoring (8.16), waktu (8.17), proses insiden (5.24-5.28), dan sebagian threat intelligence (5.7). SOC juga memberi data untuk metrik (9.1), risk assessment (8.2), dan management review (9.3).
*EN:* "The SOC operates and evidences the detection and response controls, and feeds metrics, risk data and lessons learned into the ISMS."

**3. Apa itu Statement of Applicability, dan kenapa penting?**
SoA mencantumkan kontrol yang dibutuhkan beserta alasannya, status penerapannya, dan alasan setiap kontrol Annex A yang dikecualikan. Auditor membacanya bersama risk register. Setiap kontrol harus bisa ditelusuri ke risiko atau persyaratan.
*EN:* "The SoA records which controls are needed and why, their implementation status, and justified exclusions; it must trace back to the risk assessment."

**4. Bukti apa yang akan kamu siapkan untuk kontrol logging dan monitoring?**
Untuk 8.15: inventaris sumber log yang terhubung ke daftar aset in-scope, konfigurasi retensi yang cocok dengan standar, dan daftar siapa yang bisa mengubah log. Untuk 8.16: daftar rule aktif yang terhubung ke risiko, statistik alert, dan sampel tiket dari alert. Untuk 8.17: laporan sinkronisasi waktu.
*EN:* "Log source inventory, retention settings matching the standard, admin access lists, active rules mapped to risks, alert-to-ticket samples, and a time-sync report."

**5. Bagaimana proses insiden dipetakan ke ISO?**
Saya memakai lima fase 27035: plan and prepare (5.24, ditambah 5.5 dan 5.6 untuk kontak eksternal), detect and report (6.8, 8.15, 8.16), assess and decide (5.25), respond (5.26, 5.28), dan learn lessons (5.27). Playbook bisa ditulis dengan struktur NIST 800-61, asalkan setiap fase punya rekaman.
*EN:* "I map our playbook to the 27035 phases and controls 5.24 to 5.28, with records for each phase."

**6. Apa beda correction dan corrective action?**
Correction memperbaiki gejala, misalnya menonaktifkan akun default yang ditemukan di satu VM. Corrective action menghilangkan akar masalah, misalnya memperbaiki image dan prosedur provisioning, lalu memeriksa apakah kasus serupa ada di tempat lain dan meninjau efektivitasnya.
*EN:* "Correction fixes the instance; corrective action removes the root cause and is checked for effectiveness."

**7. Pernahkah kamu terlibat audit? Apa yang diminta auditor?**
Jawab jujur sesuai pengalamanmu. Bila pernah: sebutkan apa yang kamu siapkan dan apa yang dipelajari. Bila belum: "Saya belum pernah menjadi auditee langsung, tetapi sudah berlatih menyiapkan paket bukti, populasi, dan sampel untuk proses SOC, karena auditor memilih sampel dari daftar lengkap lalu menelusurinya sampai ke bukti."
*EN:* "I haven't been audited directly yet, but I've practised preparing evidence packs and populations for SOC processes."

**8. Apa perubahan 27001:2022 yang relevan untuk SOC?**
Annex A disusun ulang menjadi 93 kontrol dalam empat tema. Ada kontrol baru 5.7 Threat intelligence dan 8.16 Monitoring activities. Klausul juga berubah, misalnya 6.3 perencanaan perubahan dan input baru di management review. Amandemen 2024 menambah pertimbangan perubahan iklim di 4.1 dan 4.2. Transisi dari edisi 2013 berakhir 31 Oktober 2025 [S5].
*EN:* "93 controls in four themes, new threat intelligence and monitoring controls, planning of changes, and the 2024 climate amendment."

**9. Bagaimana kamu memprioritaskan kerentanan?**
Saya menggabungkan KEV (sudah dieksploitasi), EPSS (peluang eksploitasi dalam 30 hari), CVSS (keparahan teknis), paparan aset ke internet, dan kritikalitas aset. Bila patch belum tersedia, saya mencatat mitigasi dan rule deteksi sebagai kontrol kompensasi, dan meminta persetujuan risk owner untuk pengecualian.
*EN:* "KEV first, then EPSS and CVSS, adjusted for exposure and asset criticality, with documented exceptions and compensating detections."

**10. Bagaimana menjelaskan risiko teknis ke manajemen?**
Saya menulis risiko sebagai skenario (siapa, lewat jalur apa, terhadap aset apa, dengan akibat apa), membandingkan levelnya dengan appetite, dan meminta satu keputusan yang jelas, bila perlu dengan perkiraan kerugian tahunan dan biaya kontrol.
*EN:* "As a scenario, compared against risk appetite, with one clear decision requested and, where useful, a simple cost comparison."

### 1.6 Lima baris CV yang jujur

Ini jawaban untuk permintaan ketiga Lead SOC. Baris di bawah adalah templat: ganti bagian dalam kurung siku dengan fakta milikmu, hapus baris yang tidak berlaku, dan tulis hanya yang benar-benar kamu lakukan.

1. "Menyiapkan bukti kontrol logging, monitoring, dan respons insiden (ISO/IEC 27001:2022 Annex A 8.15-8.16, 5.24-5.28) untuk [audit internal/eksternal] di [jenis organisasi]."
   *EN:* "Prepared evidence for logging, monitoring and incident response controls (ISO/IEC 27001:2022 Annex A 8.15-8.16, 5.24-5.28) for [internal/external] audits."
2. "Menyusun dan memelihara [jumlah] runbook SOC berversi dengan persetujuan, yang dipakai sebagai prosedur operasional terdokumentasi dalam ISMS."
   *EN:* "Wrote and maintained [number] version-controlled SOC runbooks used as documented operating procedures within the ISMS."
3. "Memberikan data insiden dan kerentanan untuk risk assessment tahunan dan laporan metrik bulanan ke management review."
   *EN:* "Provided incident and vulnerability data for annual risk assessments and monthly metrics reported to management review."
4. "Menangani bukti digital dengan prosedur chain of custody selama investigasi insiden di lingkungan [swasta]."
   *EN:* "Handled digital evidence under chain-of-custody procedures during incident investigations."
5. "Belajar mandiri ISO/IEC 27001:2022 (klausul 4-10, Annex A, ISO/IEC 27005 dan 27035) dengan fokus pemetaan pekerjaan SOC/DFIR ke klausul dan kontrol."
   *EN:* "Self-study of ISO/IEC 27001:2022 (clauses 4-10, Annex A, ISO/IEC 27005 and 27035), focused on mapping SOC/DFIR work to clauses and controls."

Tabel berikut adalah kebalikannya: frasa yang sering muncul di CV, termasuk CV yang diterima panel PT AN, beserta alasan dan penggantinya. Jangan tulis frasa di kolom pertama kecuali memang benar.

| Jangan tulis | Kenapa | Ganti dengan |
|---|---|---|
| "ISO 27001 certified" | Sertifikat milik organisasi untuk scope tertentu, bukan individu | "Supported an ISO/IEC 27001-certified ISMS" |
| "ISO 27001 Lead Auditor" | Kredensial personel dengan ujian dan syarat pengalaman | Tulis nama kredensial persis bila memang dimiliki |
| "Implemented ISO 27001" | Menyiratkan memimpin implementasi ISMS | "Contributed to [kontrol/proses tertentu]" |
| "Expert in ISO 27001" | Klaim keahlian yang sulit dipertahankan saat interview | "Familiar with ISO/IEC 27001:2022 structure and controls relevant to SOC" |

## 2-4. Lab gabungan dan troubleshooting

Lab ini menerapkan permintaan Lead SOC pada dirimu sendiri (bagian A dan C), lalu menutup rangkaian Day 01-13 dengan paket dokumen yang lengkap (bagian B) dan rencana untuk hal yang masih perlu dicek (bagian D).

### Bagian A: tabel pemetaan pribadi

Salin tabel bagian 1.4 ke `latihan/day14-pemetaan-pribadi.md`, lalu tambahkan kolom "Pernah saya lakukan? (ya/sebagian/belum)" dan "Cerita singkat (tanpa data kerja)". Baris yang belum pernah kamu lakukan menjadi rencana belajar, bukan bahan CV.

### Bagian B: paket mini-ISMS akhir

Lengkapi paket mini-ISMS dari Day 07 dengan hasil Minggu 2:

- SoA 93 baris (Day 08);
- risk register berbasis skenario dan KRI (Day 09);
- playbook, formulir chain of custody, dan template PIR (Day 10);
- standar logging dan rekaman tinjauan (Day 11);
- PIR intel dan kebijakan SLA kerentanan (Day 12);
- paket bukti dan rencana sampling (Day 13).

Pastikan indeks paket berisi semua dokumen dengan nomor, versi, pemilik, dan klausul.

### Bagian C: simulasi interview

Jawab 10 pertanyaan di bagian 1.5 dengan suara keras, sekitar satu setengah menit per jawaban, dan rekam bila bisa. Cek apakah tiap jawaban:

- menyebut minimal satu nomor klausul atau kontrol dengan benar;
- memberi satu contoh konkret;
- tidak mengklaim hal yang tidak kamu lakukan.

### Bagian D: rencana lanjutan

Kumpulkan semua hal yang masih perlu dicek dari Day 01-14, terutama yang bertanda "perlu dicek":

```
grep -n "perlu dicek" [0-9][0-9]-*.md
```

Kelompokkan menjadi tiga: dicek lewat teks standar atau SNI resmi, dicek di lab, dan dicek di sumber regulasi resmi. Tulis rencana 3 bulan untuk menutupnya.

**Hasil yang sebaiknya tersimpan:**
- Tabel pemetaan pribadi dengan status dan cerita singkat per baris.
- Indeks paket mini-ISMS dengan nomor, versi, pemilik, dan klausul tiap dokumen.
- Rekaman atau catatan simulasi interview beserta perbaikan jawabannya.
- Daftar hal yang perlu dicek, dikelompokkan, dengan rencana 3 bulan.

### Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Jawaban interview terdengar seperti hafalan | Tidak ada contoh konkret | Tambahkan satu cerita dari lab atau pekerjaan (tanpa data rahasia) |
| Bingung memilih nomor kontrol saat menjawab | Terlalu banyak yang dihafal | Fokus pada daftar SOC inti: 5.7, 5.24-5.28, 6.8, 8.8, 8.15-8.17 |
| Tergoda menulis "ISO 27001 certified" di CV | Kata kunci lowongan | Pakai "supported", "contributed", atau "familiar with" yang jujur |
| Banyak hal masih perlu dicek | Tidak punya akses teks standar | Cek perpustakaan BSN atau langganan perusahaan; catat sumber saat menutup |

## 5. Kesalahan umum dan jebakan

- Mengklaim sertifikasi organisasi sebagai sertifikasi pribadi.
- Menghafal 93 kontrol tetapi tidak bisa menjelaskan bukti untuk satu kontrol pun.
- Memakai contoh yang memuat data klien saat interview; pakai contoh lab atau yang sudah dianonimkan.
- Menjawab "ISO tidak relevan untuk SOC", padahal SOC menghasilkan sebagian besar bukti kontrol teknis.
- Menganggap belajar selesai setelah Day 14, padahal pertanyaan terbuka dan lab yang belum dijalankan masih menunggu.

## 6. Catatan terkini

Bagian ini menampung gambaran lowongan, syarat kredensial personel, dan status edisi. Detail ini cepat berubah, jadi cek ulang sebelum dipakai di CV atau interview.

- Contoh lowongan 2026 menggabungkan tugas SOC dengan dukungan audit ISO 27001 dan pemeliharaan repositori bukti audit; sebagian menyebut CISSP, Security+, SC-200, atau sertifikat auditor ISO sebagai nilai tambah [S1]. Ini contoh, bukan survei pasar.
- PECB membagi kredensial ISO/IEC 27001 Lead Auditor ke empat tingkat. Provisional Auditor tanpa syarat pengalaman; Auditor 2 tahun pengalaman (1 tahun di manajemen keamanan informasi) dan 200 jam audit; Lead Auditor 5 tahun (2 tahun) dan 300 jam; Senior Lead Auditor 10 tahun (7 tahun) dan 1.000 jam. Semua tingkat mensyaratkan lulus ujian [S2]. Lembaga lain (misalnya CQI/IRCA atau BSI) punya aturan sendiri; cek syarat terbaru di situs lembaga yang kamu pilih.
- ISO/IEC 27001:2022 (edisi 3) dengan Amd 1:2024 masih edisi berlaku di katalog ISO per Oktober 2026 [S9]. Transisi dari 2013 berakhir 31 Oktober 2025 [S5]. Pantau kemungkinan revisi setelah 27000:2026 terbit (Day 07).
- SNI ISO/IEC 27001:2022 dan Amd.1:2024 sudah diadopsi BSN secara identik [S8].

## 7. Cheat sheet

```
SOC inti di Annex A: 5.7 TI | 5.24 rencana | 5.25 nilai | 5.26 respons | 5.27 belajar | 5.28 bukti
                     6.8 lapor event | 8.8 kerentanan | 8.15 logging | 8.16 monitoring | 8.17 waktu
Klausul yang disentuh SOC: 6.1.2/8.2 risiko | 7.2 kompetensi | 7.5 dokumen | 8.1 operasi | 9.1 metrik | 9.3 review | 10.2 NC
Klausul 8.2 = risk assessment ; kontrol 8.2 = privileged access rights (jangan tertukar)
Jawaban interview = klausul/kontrol + contoh konkret + bukti + kejujuran
CV: supported / contributed / prepared evidence / familiar with ; JANGAN: certified / implemented / lead auditor (kecuali benar)
Kredensial personel (mis. PECB): tingkat berbeda, syarat pengalaman + jam audit
Setelah Day 14: tutup hal yang perlu dicek | jalankan lab | perbarui latihan | ulangi interview tiap bulan
```

## 8. Uji diri

Soal di bawah mencampur materi Day 08-13 dan hasil capstone. Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** Seorang kandidat berkata, "Klausul 8.2 dan kontrol 8.2 sama-sama tentang risiko, jadi buktinya sama: risk register." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Nomornya sama, tetapi isinya berbeda. Klausul 8.2 adalah risk assessment, dan buktinya antara lain entri risk register. Kontrol 8.2 di Annex A adalah privileged access rights, dan buktinya misalnya hasil review akses admin SIEM dan EDR atau daftar role dengan audit trail admin. Karena itu tabel pemetaan memisahkan kolom klausul dan kolom kontrol. Lihat bagian 1.4.

</details>

**2. Skenario keputusan.** Panel PT AN menerima CV kandidat yang tiga tahun bekerja di SOC sebuah perusahaan tersertifikasi ISO 27001 dan menyiapkan bukti logging untuk audit eksternal. Baris CV mana yang paling tepat untuk pengalaman itu?

- A. "ISO 27001 certified."
- B. "Implemented ISO 27001 for the SOC."
- C. "Prepared evidence for logging and monitoring controls (ISO/IEC 27001:2022 Annex A 8.15-8.16) for external audits; supported an ISO/IEC 27001-certified ISMS."

<details><summary>Jawaban</summary>

C. Baris itu menyebut apa yang benar-benar dilakukan, kontrol yang dibuktikan, dan konteks auditnya. A keliru karena sertifikat dimiliki organisasi untuk scope tertentu, bukan individu. B keliru karena "implemented" menyiratkan memimpin implementasi ISMS, padahal kandidat menyiapkan bukti untuk kontrol tertentu; penggantinya adalah "contributed to" kontrol atau proses yang spesifik. Lihat bagian 1.6.

</details>

**3. Pertanyaan jebakan.** "Threat hunting yang tidak menemukan apa-apa tidak menghasilkan bukti untuk ISMS." Benarkah?

<details><summary>Jawaban</summary>

Tidak. Di tabel pemetaan, threat hunting menyentuh klausul 10.1 serta kontrol 8.16 dan 5.7, dan buktinya adalah laporan hunt termasuk hasil negatif, ditambah rule baru bila ada. Hasil negatif yang terdokumentasi menunjukkan aktivitas pemantauan berjalan dan bisa menjadi masukan perbaikan. Lihat bagian 1.4.

</details>

**4. Skenario keputusan.** Dalam minggu yang sama, tim platform PT AN menerima dua temuan kerentanan. Kerentanan X punya skor CVSS tinggi di server internal, tanpa tanda eksploitasi. Kerentanan Y tercantum di KEV, ada di sistem yang terekspos internet, dan patch-nya belum tersedia. Apa langkah yang paling tepat?

- A. Patch X lebih dulu karena skor CVSS-nya lebih tinggi; Y ditunda sampai patch tersedia.
- B. Prioritaskan Y: catat mitigasi dan rule deteksi sebagai kontrol kompensasi, minta persetujuan risk owner untuk pengecualian, lalu tangani X sesuai SLA.
- C. Terima kedua risiko karena salah satunya belum punya patch.

<details><summary>Jawaban</summary>

B. Prioritas kerentanan menggabungkan KEV (sudah dieksploitasi), EPSS, CVSS, paparan ke internet, dan kritikalitas aset, dengan KEV di urutan pertama. Y tercantum di KEV dan terekspos internet, jadi didahulukan. Karena patch belum ada, mitigasi dan rule deteksi dicatat sebagai kontrol kompensasi dan pengecualiannya disetujui risk owner. A keliru karena CVSS hanya mengukur keparahan teknis dan menunda Y membiarkan kerentanan yang sudah dieksploitasi tetap terbuka. C keliru karena ketiadaan patch tidak menghapus pilihan mitigasi dan deteksi. Lihat bagian 1.5 (pertanyaan 9) dan ringkasan Day 12 di bagian 1.1.

</details>

**5. Jelaskan ulang.** Pewawancara bertanya, "Bagaimana satu insiden yang kamu tangani menjadi bukti untuk ISMS?" Jawab dalam lima kalimat, dari triage sampai management review, dengan menyebut nomor kontrol atau klausul seperlunya.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Saat alert masuk, saya mentriage dan mencatat prioritas serta alasan klasifikasinya di tiket, yang menjadi bukti untuk 5.25 dan 8.16. Investigasi dan containment tercatat di timeline tiket untuk 5.26, dan bila ada akuisisi forensik, formulir chain of custody dan hash disimpan untuk 5.28. Setelah insiden ditutup, post-incident review menghasilkan laporan PIR untuk 5.27 beserta ID corrective action yang ditindaklanjuti menurut 10.2. Insiden itu juga masuk laporan metrik bulanan SOC (9.1) dan bisa dipilih auditor sebagai sampel, karena tiketnya tersambung dari alert sampai PIR. Hasil metrik dan temuan itu akhirnya dibahas di management review (9.3), yang bisa memutuskan perubahan ISMS."

Kesalahan yang sering muncul:
- Berhenti di "tiket ditutup" tanpa menyebut PIR, metrik, dan management review.
- Menyebut alat (SIEM, EDR) sebagai bukti, bukan rekaman yang dihasilkan.
- Menyebut nomor kontrol tanpa rekaman yang membuktikannya, atau sebaliknya bercerita panjang tanpa satu nomor pun.

</details>

**6. Pertanyaan jebakan.** Seorang kandidat menjawab pertanyaan perubahan edisi 2022 dengan: "Edisi 2022 menambah kontrol 5.7 Threat intelligence dan 8.16 Monitoring activities. Sertifikat edisi 2013 masih boleh dipakai sampai resertifikasi berikutnya." Bagian mana yang keliru?

<details><summary>Jawaban</summary>

Kalimat kedua. Transisi dari edisi 2013 berakhir 31 Oktober 2025, jadi sertifikat edisi 2013 tidak lagi berlaku. Kalimat pertama benar, dan jawaban yang lengkap juga menyebut Annex A yang kini berisi 93 kontrol dalam empat tema, perubahan klausul seperti 6.3 perencanaan perubahan dan input baru di management review, serta Amd 1:2024 yang menambah pertimbangan perubahan iklim di 4.1 dan 4.2. Lihat bagian 1.5 (pertanyaan 8) dan 6.

</details>

**7. Interview question (English).** "Tell me about your experience with ISO 27001."

<details><summary>Sample answer</summary>

"I haven't held a GRC role, and I'm not personally certified, because ISO 27001 certificates belong to organisations. What I can speak to is how SOC work produces evidence for the ISMS. Triage tickets with classification reasons support 5.25 and 8.16, incident timelines and post-incident reviews support 5.26 and 5.27, and chain-of-custody forms support 5.28. Our monthly SOC metrics feed clause 9.1 and the management review. I've practised preparing evidence packs and complete ticket populations so an auditor can pick samples and trace them end to end. In short, I'm familiar with the structure of ISO/IEC 27001:2022 and the controls relevant to SOC, and I'm honest about where my experience stops."

What makes this answer strong: it states the limits of experience up front, avoids claiming personal certification, ties concrete SOC records to specific controls and clauses, and shows an understanding of how auditors sample evidence.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Remotive: lowongan SOC Compliance Analyst (contoh 2026) | https://remotive.com/remote/jobs/compliance/soc-compliance-analyst-5460214 | sekunder (iklan lowongan) | 2026 | Rendah-sedang. Contoh, bukan survei pasar |
| S2 | PECB: ISO/IEC 27001 Lead Auditor | https://pecb.com/en/education-and-certification-for-individuals/iso-iec-27001/iso-iec-27001-lead-auditor | primer (lembaga sertifikasi personel) | diakses 2026-10-10 | Tinggi untuk syarat PECB |
| S3 | ISO committee: ISO/IEC 27006-1:2024 | https://committee.iso.org/standard/82908.html | primer (katalog ISO) | Maret 2024; diakses 2026-10-08 | Tinggi |
| S4 | NIST: CSF 2.0 Informative References | https://www.nist.gov/cyberframework/csf-20-informative-references | primer (NIST) | diakses 2026-10-08 | Tinggi |
| S5 | Konfirmity: ISO 27001 in 2026, what changed | https://www.konfirmity.com/blog/iso-27001-what-changed-in-2026 | sekunder (vendor) | diperbarui 2026-08-31; diakses 2026-10-08 | Sedang |
| S6 | ISO committee: ISO/IEC 27035-1:2023 | https://committee.iso.org/standard/78973.html | primer (katalog ISO) | 2023-02-13; diakses 2026-10-08 | Tinggi |
| S7 | CISA: Best Practices for Event Logging and Threat Detection | https://cisa.gov/news-events/alerts/2024/08/21/asds-acsc-cisa-fbi-and-nsa-support-international-partners-release-best-practices-event-logging-and | primer (lembaga pemerintah) | 2024-08-21; diakses 2026-10-08 | Tinggi |
| S8 | BSN: RSNI3 ISO/IEC 27001:2022/Amd.1:2024 | https://bsn.go.id/uploads/attachment/rsni_iso_iec_27001-2022-amd1_1.pdf | primer | 2024; diakses 2026-10-08 | Tinggi |
| S9 | ISO committee: ISO/IEC 27001:2022 | https://committee.iso.org/standard/82875.html | primer (katalog ISO) | Oktober 2022; diakses 2026-10-10 | Tinggi. Edisi 3, stage 60.60, Amd 1:2024 |

**Catatan sumber:** Day capstone ini terutama merangkum Day 08-13; pemetaan klausul dan kontrol di bagian 1.4 mengikuti Day 08 dan Day 10. Gambaran lowongan [S1] berasal dari beberapa iklan, bukan survei pasar, dan iklan semacam itu cepat kedaluwarsa, jadi perlakukan sebagai ilustrasi. Syarat kredensial personel hanya berlaku untuk PECB [S2].
