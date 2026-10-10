---
day: 14
title: 'Capstone dan interview: pemetaan aktivitas SOC/IR/forensik ke klausul dan kontrol, 10 pertanyaan interview, dan baris CV yang jujur'
researched_on: 2026-10-10
versions_checked: 'ISO/IEC 27001:2022 + Amd 1:2024 (masih edisi berlaku; transisi 2013 berakhir 31 Okt 2025); ISO/IEC 27002:2022; ISO/IEC 27035-1:2023; ISO/IEC 27006-1:2024; NIST CSF 2.0 Informative Reference ISO/IEC 27001:2022'
---

# Day 14: Capstone dan interview

> Catatan pribadi, bukan materi resmi ISO, dan bukan nasihat hukum atau audit. Baris CV di Day ini adalah templat; tulis hanya yang benar-benar kamu lakukan.

Cakupan: ringkasan Minggu 2 (Day 08-13), tabel pemetaan aktivitas SOC/IR/forensik ke klausul, kontrol, dan bukti, 10 pertanyaan interview dengan jawaban contoh (Indonesia dan versi singkat English), 5 baris CV yang jujur, serta rencana lanjutan setelah catatan ini.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- memetakan pekerjaan SOC, IR, dan forensik yang kamu lakukan ke klausul dan kontrol 27001:2022 beserta bukti yang dihasilkannya.
- menjawab 10 pertanyaan interview yang umum tentang ISO 27001 dengan jawaban yang konkret, jujur, dan menunjuk bukti.
- menulis baris CV yang menggambarkan keterlibatanmu dengan ISMS tanpa mengklaim sertifikasi atau peran yang tidak kamu pegang.
- menyusun rencana lanjutan: area yang perlu diperdalam, lab yang perlu dijalankan, dan pertanyaan terbuka yang perlu ditutup.

## 2. Konteks singkat

Lowongan SOC dan security analyst sering menyebut ISO 27001 dalam bentuk "mendukung audit ISO 27001", "memelihara bukti audit", atau "pengalaman dengan ISO 27001, SOC 2, PCI DSS" [S1]. Pewawancara jarang menguji hafalan klausul. Biasanya mereka menguji tiga hal:

- apakah kamu paham bahwa pekerjaan SOC menghasilkan bukti untuk ISMS;
- apakah kamu bisa berbicara dengan bahasa audit;
- apakah kamu jujur tentang batas pengalamanmu.

Catatan ini tidak membuatmu menjadi implementer atau auditor. Kredensial personel seperti Lead Auditor punya syarat ujian, pengalaman kerja, dan jam audit tersendiri (bagian 8). Yang bisa kamu klaim setelah 14 Day ini adalah pemahaman kerangka dan kemampuan memetakan pekerjaan teknis ke kerangka itu.

## 3. Ringkasan Minggu 2

- **Day 08, Annex A 2022:** 93 kontrol dalam empat tema (37/8/14/34), 11 kontrol baru (yang paling relevan untuk SOC adalah 5.7 dan 8.16), lima jenis atribut 27002 yang tidak wajib, dan mapping resmi NIST dari ISO/IEC 27001:2022 ke CSF 2.0 [S4].
- **Day 09, risiko praktik:** appetite, tolerance, dan kriteria penerimaan; skenario berbasis kejadian dan aset; estimasi kemungkinan dengan data; pengantar Open FAIR; KRI.
- **Day 10, insiden:** lima fase 27035 (plan and prepare, detect and report, assess and decide, respond, learn lessons) yang dipetakan ke 5.24-5.28 dan 6.8 [S6]; NIST SP 800-61r3; 27037 untuk bukti; tenggat 3 x 24 jam di UU PDP.
- **Day 11, logging:** 8.15 mencatat, 8.16 memantau dan menindaklanjuti, 8.17 waktu konsisten; retensi tanpa angka baku; konfigurasi retensi di Splunk dan Wazuh; panduan logging ASD/CISA [S7].
- **Day 12, intel dan kerentanan:** 5.7 dengan tiga tingkat intel dan keputusan yang tercatat; 8.8 dengan KEV, EPSS, dan CVSS v4.0; pemasok dan cloud (5.19-5.23, 27017:2026).
- **Day 13, audit:** siklus tiga tahun, 17021-1 dan 27006-1:2024 [S3], grading temuan, struktur temuan (kondisi, kriteria, bukti), paket bukti, dan sikap saat wawancara.

## 3b. Tabel pemetaan aktivitas, klausul/kontrol, dan bukti

Tabel ini adalah artefak utama capstone. Kolom "bukti" adalah rekaman yang akan diambil sampelnya oleh auditor.

| No | Aktivitas SOC/IR/forensik | Klausul atau kontrol | Bukti yang dihasilkan |
|---|---|---|---|
| 1 | Triage alert dan klasifikasi event | 5.25, 8.16 | Tiket dengan prioritas dan alasan klasifikasi |
| 2 | Investigasi, containment, eradikasi | 5.26 | Timeline tiket, catatan tindakan |
| 3 | Akuisisi bukti forensik (disk, memori, log) | 5.28 (panduan ISO/IEC 27037) | Formulir chain of custody, hash, lokasi simpan |
| 4 | Post-incident review | 5.27, 10.2 | Laporan PIR, ID corrective action |
| 5 | Melaporkan event dari karyawan | 6.8 | Tiket yang berasal dari kanal pelaporan |
| 6 | Latihan tabletop IR | 5.24, 7.2 | Skenario, daftar hadir, catatan pelajaran |
| 7 | Onboarding sumber log | 8.15, 8.1 | Inventaris sumber log, tiket validasi |
| 8 | Menulis dan tuning rule deteksi | 8.16, 8.32 | Repo rule dengan riwayat review dan persetujuan |
| 9 | Memeriksa sinkronisasi waktu | 8.17 | Laporan NTP atau laporan lag waktu SIEM |
| 10 | Mengelola retensi dan akses log | 8.15, 5.33, 8.10, 8.2 | Konfigurasi retensi, daftar role, audit trail admin |
| 11 | Brief threat intelligence | 5.7 | Brief berkala dengan keputusan dan tindakan |
| 12 | Prioritas kerentanan bersama tim platform | 8.8 | Tiket patch, laporan umur kerentanan, pengecualian SLA |
| 13 | Threat hunting | 8.16, 5.7, 10.1 | Laporan hunt (termasuk hasil negatif), rule baru |
| 14 | Laporan metrik bulanan SOC | 9.1, 6.2 | Laporan dan query sumbernya |
| 15 | Masukan ke risk assessment | 6.1.2, 8.2 | Entri risk register dengan alasan berbasis data |
| 16 | Runbook dan prosedur | 5.37, 7.5 | Runbook berversi dengan penyetuju |
| 17 | Pelatihan dan QA analyst | 7.2, 7.3, 6.3 | Matriks kompetensi, skor QA, rekaman pelatihan |
| 18 | Notifikasi insiden ke klien atau regulator | 5.26, 5.31, 5.34, 7.4 | Salinan pemberitahuan dan waktu kirim |
| 19 | Kontak dengan CERT, ISAC, penegak hukum | 5.5, 5.6 | Daftar kontak, catatan komunikasi |
| 20 | Evaluasi MSSP atau SIEM cloud | 5.19-5.23 | Kuesioner, laporan SLA, notulen tinjauan |
| 21 | Tinjauan akses admin SIEM dan EDR | 8.2, 5.3, 5.18 | Hasil review akses berkala |
| 22 | Dukungan audit internal dan eksternal | 9.2, 8.34 | Paket bukti, akun auditor read-only yang tercatat |

Cara memakai tabel ini:

- Untuk interview, pilih 3-4 baris yang benar-benar pernah kamu kerjakan dan siapkan satu cerita konkret untuk tiap baris.
- Untuk pekerjaan nyata, tabel ini bisa menjadi daftar kerja SOC untuk persiapan audit (Day 08 bagian 4.2 dan Day 13 bagian 3.6).

## 3c. Sepuluh pertanyaan interview

Jawaban contoh ditulis untuk analyst dengan pengalaman SOC dan forensik yang belum pernah memegang peran GRC. Sesuaikan dengan pengalamanmu yang sebenarnya.

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
Saya memakai lima fase 27035: plan and prepare (5.24), detect and report (6.8, 8.16), assess and decide (5.25), respond (5.26, 5.28), dan learn lessons (5.27). Playbook bisa ditulis dengan struktur NIST 800-61, asalkan setiap fase punya rekaman.
*EN:* "I map our playbook to the 27035 phases and controls 5.24 to 5.28, with records for each phase."

**6. Apa beda correction dan corrective action?**
Correction memperbaiki gejala, misalnya menonaktifkan akun default yang ditemukan di satu VM. Corrective action menghilangkan akar masalah, misalnya memperbaiki image dan prosedur provisioning, lalu memeriksa apakah kasus serupa ada di tempat lain dan meninjau efektivitasnya.
*EN:* "Correction fixes the instance; corrective action removes the root cause and is checked for effectiveness."

**7. Pernahkah kamu terlibat audit? Apa yang diminta auditor?**
Jawab jujur sesuai pengalamanmu. Bila pernah: sebutkan apa yang kamu siapkan dan apa yang dipelajari. Bila belum: "Saya belum pernah menjadi auditee langsung. Saya sudah berlatih menyiapkan paket bukti, populasi, dan sampel untuk proses SOC, dan saya tahu auditor biasanya memilih sampel tiket dari daftar lengkap, lalu menelusurinya sampai ke bukti."
*EN:* "I haven't been audited directly yet, but I've practised preparing evidence packs and populations for SOC processes."

**8. Apa perubahan 27001:2022 yang relevan untuk SOC?**
Annex A disusun ulang menjadi 93 kontrol dalam empat tema. Ada kontrol baru 5.7 Threat intelligence dan 8.16 Monitoring activities. Klausul juga berubah, misalnya 6.3 perencanaan perubahan dan input baru di management review. Amandemen 2024 menambah pertimbangan perubahan iklim di 4.1 dan 4.2. Transisi dari edisi 2013 berakhir 31 Oktober 2025 [S5].
*EN:* "93 controls in four themes, new threat intelligence and monitoring controls, planning of changes, and the 2024 climate amendment."

**9. Bagaimana kamu memprioritaskan kerentanan?**
Saya menggabungkan KEV (sudah dieksploitasi), EPSS (peluang eksploitasi dalam 30 hari), CVSS (keparahan teknis), paparan aset ke internet, dan kritikalitas aset. Bila patch belum tersedia, saya mencatat mitigasi dan rule deteksi sebagai kontrol kompensasi, dan meminta persetujuan risk owner untuk pengecualian.
*EN:* "KEV first, then EPSS and CVSS, adjusted for exposure and asset criticality, with documented exceptions and compensating detections."

**10. Bagaimana menjelaskan risiko teknis ke manajemen?**
Saya menulis risiko sebagai skenario (siapa, lewat jalur apa, terhadap aset apa, dengan akibat apa), menyebut level saat ini dibanding appetite, dan meminta satu keputusan yang jelas. Bila perlu, saya memberi perkiraan kerugian tahunan sederhana dan biaya kontrol sebagai pembanding.
*EN:* "As a scenario, compared against risk appetite, with one clear decision requested and, where useful, a simple cost comparison."

## 3d. Lima baris CV yang jujur

Tulis hanya yang benar-benar kamu lakukan. Ganti bagian dalam kurung siku dengan fakta milikmu, dan hapus baris yang tidak berlaku.

1. "Menyiapkan bukti kontrol logging, monitoring, dan respons insiden (ISO/IEC 27001:2022 Annex A 8.15-8.16, 5.24-5.28) untuk [audit internal/eksternal] di [jenis organisasi]."
   *EN:* "Prepared evidence for logging, monitoring and incident response controls (ISO/IEC 27001:2022 Annex A 8.15-8.16, 5.24-5.28) for [internal/external] audits."
2. "Menyusun dan memelihara [jumlah] runbook SOC dengan kendali versi dan persetujuan, yang dipakai sebagai prosedur operasional terdokumentasi dalam ISMS."
   *EN:* "Wrote and maintained [number] version-controlled SOC runbooks used as documented operating procedures within the ISMS."
3. "Memberikan data insiden dan kerentanan untuk risk assessment tahunan dan laporan metrik bulanan ke management review."
   *EN:* "Provided incident and vulnerability data for annual risk assessments and monthly metrics reported to management review."
4. "Menangani bukti digital dengan prosedur chain of custody selama investigasi insiden di lingkungan [swasta]."
   *EN:* "Handled digital evidence under chain-of-custody procedures during incident investigations."
5. "Belajar mandiri ISO/IEC 27001:2022 (klausul 4-10, Annex A, ISO/IEC 27005 dan 27035) dengan fokus pemetaan pekerjaan SOC/DFIR ke klausul dan kontrol."
   *EN:* "Self-study of ISO/IEC 27001:2022 (clauses 4-10, Annex A, ISO/IEC 27005 and 27035), focused on mapping SOC/DFIR work to clauses and controls."

Yang tidak boleh ditulis kecuali benar:

| Jangan tulis | Kenapa | Ganti dengan |
|---|---|---|
| "ISO 27001 certified" | Sertifikat milik organisasi untuk scope tertentu, bukan individu | "Supported an ISO/IEC 27001-certified ISMS" |
| "ISO 27001 Lead Auditor" | Kredensial personel dengan ujian dan syarat pengalaman | Tulis nama kredensial persis bila memang dimiliki |
| "Implemented ISO 27001" | Menyiratkan memimpin implementasi ISMS | "Contributed to [kontrol/proses tertentu]" |
| "Expert in ISO 27001" | Klaim keahlian yang sulit dipertahankan saat interview | "Familiar with ISO/IEC 27001:2022 structure and controls relevant to SOC" |

## 4-6. Lab gabungan dan troubleshooting

### Bagian A: tabel pemetaan pribadi

Salin tabel bagian 3b ke `ISO27001-note/latihan/day14-pemetaan-pribadi.md`. Untuk setiap baris, tambahkan kolom "Pernah saya lakukan? (ya/sebagian/belum)" dan "Cerita singkat (tanpa data kerja)". Hapus atau tandai baris yang belum pernah kamu lakukan. Baris itu menjadi rencana belajar, bukan bahan CV.

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

Jawab 10 pertanyaan di bagian 3c dengan suara keras, masing-masing singkat (sekitar satu setengah menit bicara). Rekam bila bisa. Untuk setiap jawaban, cek apakah kamu:

- menyebut minimal satu nomor klausul atau kontrol dengan benar;
- memberi satu contoh konkret;
- tidak mengklaim hal yang tidak kamu lakukan.

### Bagian D: rencana lanjutan

Kumpulkan semua hal yang masih perlu dicek dari Day 01-14, terutama yang bertanda "perlu dicek":

```
grep -rn "perlu dicek" ISO27001-note/[0-9][0-9]-*.md
```

Kelompokkan menjadi tiga: dicek lewat teks standar atau SNI resmi, dicek di lab, dan dicek di sumber regulasi resmi. Tulis rencana 3 bulan untuk menutupnya.

### Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Jawaban interview terdengar seperti hafalan | Tidak ada contoh konkret | Tambahkan satu cerita dari lab atau pekerjaan (tanpa data rahasia) |
| Bingung memilih nomor kontrol saat menjawab | Terlalu banyak yang dihafal | Fokus pada daftar SOC inti: 5.7, 5.24-5.28, 6.8, 8.8, 8.15-8.17 |
| Tergoda menulis "ISO 27001 certified" di CV | Kata kunci lowongan | Pakai "supported", "contributed", atau "familiar with" yang jujur |
| Paket mini-ISMS tidak konsisten antar dokumen | Ditulis di hari berbeda | Pakai matriks keterlacakan Day 07 bagian B sekali lagi |
| Banyak hal masih bertanda perlu dicek | Tidak punya akses teks standar | Cek perpustakaan BSN atau langganan perusahaan; tandai sumber yang dipakai saat menutup |

## 7. Kesalahan umum dan jebakan

- Mengklaim sertifikasi organisasi sebagai sertifikasi pribadi.
- Menghafal 93 kontrol tetapi tidak bisa menjelaskan bukti untuk satu kontrol pun.
- Memakai contoh dari tempat kerja nyata yang memuat data klien saat interview. Gunakan contoh lab atau yang sudah dianonimkan dengan baik.
- Menjawab "ISO tidak relevan untuk SOC". Justru SOC menghasilkan sebagian besar bukti kontrol teknis.
- Menganggap belajar selesai setelah Day 14. Pertanyaan yang belum tertutup dan lab yang belum dijalankan adalah bagian dari pekerjaan.

## 8. Catatan terkini

- Contoh lowongan 2026 menggabungkan tugas SOC dengan dukungan audit ISO 27001, pemeliharaan dokumentasi dan bukti, serta repositori bukti audit. Sebagian menyebut kredensial seperti CISSP, Security+, SC-200, atau sertifikat auditor ISO sebagai nilai tambah [S1]. Ini contoh beberapa lowongan, bukan survei pasar.
- PECB membagi kredensial ISO/IEC 27001 Lead Auditor ke beberapa tingkat dengan syarat pengalaman yang berbeda. Contohnya, Provisional Auditor tanpa syarat pengalaman, sedangkan Lead Auditor mensyaratkan 5 tahun pengalaman (2 tahun di manajemen keamanan informasi) dan 300 jam aktivitas audit [S2]. Lembaga lain (misalnya yang terdaftar di CQI/IRCA atau BSI) punya aturan sendiri. Cek syarat terbaru di situs lembaga yang kamu pilih.
- ISO/IEC 27001:2022 dengan Amd 1:2024 masih edisi berlaku. Transisi dari 2013 berakhir 31 Oktober 2025 [S5]. Pantau kemungkinan revisi setelah 27000:2026 terbit (Day 07).
- SNI ISO/IEC 27001:2022 dan Amd.1:2024 sudah diadopsi BSN secara identik [S8].

## 9. Cheat sheet

```
SOC inti di Annex A: 5.7 TI | 5.24 rencana | 5.25 nilai | 5.26 respons | 5.27 belajar | 5.28 bukti
                     6.8 lapor event | 8.8 kerentanan | 8.15 logging | 8.16 monitoring | 8.17 waktu
Klausul yang disentuh SOC: 6.1.2/8.2 risiko | 7.2 kompetensi | 7.5 dokumen | 8.1 operasi | 9.1 metrik | 9.3 review | 10.2 NC
Jawaban interview = klausul/kontrol + contoh konkret + bukti + kejujuran
CV: supported / contributed / prepared evidence / familiar with ; JANGAN: certified / implemented / lead auditor (kecuali benar)
Kredensial personel (mis. PECB): tingkat berbeda, syarat pengalaman + jam audit
Setelah Day 14: tutup hal yang perlu dicek | jalankan lab | perbarui latihan | ulangi interview tiap bulan
```

## 10. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Remotive: lowongan SOC Compliance Analyst (contoh lowongan 2026; pola serupa di Greenhouse dan ITJobsWatch) | https://remotive.com/remote/jobs/compliance/soc-compliance-analyst-5460214 | sekunder (iklan lowongan) | 2026 | Rendah-sedang. Contoh, bukan survei pasar; iklan lowongan cepat kedaluwarsa |
| S2 | PECB: ISO/IEC 27001 Lead Auditor | https://pecb.com/de/education-and-certification-for-individuals/iso-iec-27001/iso-iec-27001-lead-auditor | primer (lembaga sertifikasi personel) | diakses 2026-10-08 | Tinggi untuk syarat PECB; tidak berlaku untuk lembaga lain |
| S3 | ISO committee: ISO/IEC 27006-1:2024 | https://committee.iso.org/standard/82908.html | primer (katalog ISO) | Maret 2024; diakses 2026-10-08 | Tinggi |
| S4 | NIST: CSF 2.0 Informative References | https://www.nist.gov/cyberframework/csf-20-informative-references | primer (NIST) | diakses 2026-10-08 | Tinggi |
| S5 | Konfirmity: ISO 27001 in 2026, what changed | https://www.konfirmity.com/blog/iso-27001-what-changed-in-2026 | sekunder (vendor) | diperbarui 2026-08-31; diakses 2026-10-08 | Sedang |
| S6 | ISO committee: ISO/IEC 27035-1:2023 | https://committee.iso.org/standard/78973.html | primer (katalog ISO) | 2023-02-13; diakses 2026-10-08 | Tinggi |
| S7 | CISA: Best Practices for Event Logging and Threat Detection | https://cisa.gov/news-events/alerts/2024/08/21/asds-acsc-cisa-fbi-and-nsa-support-international-partners-release-best-practices-event-logging-and | primer (lembaga pemerintah) | 2024-08-21; diakses 2026-10-08 | Tinggi |
| S8 | BSN: RSNI3 ISO/IEC 27001:2022/Amd.1:2024 | https://bsn.go.id/uploads/attachment/rsni_iso_iec_27001-2022-amd1_1.pdf | primer | 2024; diakses 2026-10-08 | Tinggi |

**Catatan sumber:** Day capstone ini terutama merangkum Day 01-13. Gambaran lowongan [S1] berasal dari beberapa iklan, bukan survei pasar, dan iklan semacam itu cepat kedaluwarsa. Syarat kredensial personel hanya untuk PECB [S2]; lembaga lain perlu dicek di situsnya masing-masing.
