# ISO27001-note: ISO/IEC 27001 untuk Praktisi SOC/DFIR

> Personal study notes. Not affiliated with or endorsed by any vendor or standards body mentioned. Not legal or audit advice.
>
> License: [CC BY 4.0](LICENSE).

## Tujuan

Familiar dengan ISO 27001 (bukan mengejar sertifikasi): menjelaskan struktur ISMS, memahami bahasa audit, memetakan pekerjaan SOC/IR/forensik ke klausul dan kontrol. Latihan memakai organisasi fiktif.

Aturan bahasa, format, dan penanda mengikuti standar penulisan pribadi (STANDAR-NOTE.md), yang tidak disertakan di repo ini.

## Versi acuan

Status standar dan dokumen acuan per Oktober 2026.

| Item | Status | Dipakai di |
|---|---|---|
| ISO/IEC 27001:2022 + Amd 1:2024 "Climate action changes" | Edisi berlaku; belum ada edisi baru. Amd 1 (23 Feb 2024) menambah satu kalimat tentang perubahan iklim di 4.1 dan Note 2 di 4.2. Transisi dari edisi 2013 berakhir 31 Okt 2025 | Day 01-08 |
| SNI ISO/IEC 27001:2022 dan SNI ISO/IEC 27001:2022/Amd.1:2024 | Adopsi identik oleh BSN; Amd.1 disusun Komtek 35-04 (sekretariat di BSSN), konsensus 21 Jun 2024. Nomor keputusan penetapan SNI 27001:2022 perlu dicek di JDIH BSN | Day 01-03 |
| ISO/IEC 27002:2022 | Acuan kontrol (93 kontrol, 4 tema, 5 jenis atribut); belum ada proyek revisi di katalog ISO | Day 08, 11, 12 |
| ISO/IEC 27000:2026 | Edisi 6 (3 Jul 2026), jauh lebih ramping; tidak memengaruhi sertifikat 27001 | Day 01, 07 |
| ISO/IEC 27005:2022 | Edisi 4 (25 Okt 2022); katalog ISO belum mencantumkan proyek revisi | Day 04, 09 |
| ISO 19011:2026 dan ISO/IEC 27007:2020 | 19011 edisi 4 (27 Mei 2026) menggantikan 2018; 27007:2020 akan diganti ISO/IEC DIS 27007 edisi 4 (tahap DIS per Sep 2026) | Day 06, 13, 15 |
| ISO/IEC 17021-1:2015 dan ISO/IEC 27006-1:2024 | Aturan untuk badan sertifikasi; 17021-1 dalam systematic review, 27006-1 menggantikan 27006:2015 + Amd 1:2020 dengan transisi selesai 31 Mar 2026 | Day 13, 17 |
| Global Accreditation Cooperation Incorporated (Global ACI) | Menggantikan IAF dan ILAC sejak 1 Jan 2026; IAF MLA beralih menjadi Global ACI MRA, dokumen wajib IAF tetap dipakai sampai ada pengganti | Day 01, 17 |
| ISO/IEC 27035-1:2023, 27035-2:2023, 27035-3:2020, 27035-4:2024, 27037:2012 | Insiden dan bukti digital | Day 10 |
| ISO/IEC 27017:2026, 27018:2025, 27031:2025, 27701:2025, ISO 22301:2019 + Amd 1:2024 | Edisi lama 27017, 27018, 27031, dan 27701 sudah ditarik; 27701:2025 kini standar sistem manajemen mandiri (sertifikasinya lewat ISO/IEC 27706:2025); 22301 akan direvisi | Day 12, 19 |
| NIST SP 800-61r3 (Apr 2025), SP 800-55 v1/v2 (Des 2024), SP 800-92r1 (masih initial public draft Okt 2023), Informative Reference ISO/IEC 27001:2022 ke CSF 2.0 v1.0.0 | Acuan pembanding | Day 06, 08, 10, 11 |
| CVSS v4.0, EPSS v4, CISA KEV, BOD 26-04 (10 Jun 2026, mencabut BOD 22-01 dan 19-02) | Prioritas kerentanan | Day 12 |
| UU No. 27 Tahun 2022 (PDP) | Pasal 46: pemberitahuan tertulis paling lambat 3 x 24 jam ke subjek data dan lembaga; titik mulai hitungan tidak disebut di teks UU. Peraturan pelaksana dilaporkan terbit sebagai PP No. 33 Tahun 2026 (berlaku 16 Jan 2027), belum dicocokkan dengan teks resmi | Day 03, 10, 18 |
| PP No. 71 Tahun 2019, Peraturan BSSN No. 8 Tahun 2020 dan No. 1 Tahun 2024, Perpres No. 82 Tahun 2022, POJK No. 11/POJK.03/2022 | Kewajiban PSE, SNI ISO/IEC 27001 per kategori sistem, pelaporan insiden siber dan IIV, contoh ketentuan sektor bank | Day 17, 18 |

## Temuan penting

- Amd 1:2024 adalah klarifikasi tanpa program transisi penuh. Menurut komunike IAF-ISO (22 Feb 2024), badan sertifikasi menilai pertimbangan perubahan iklim sejak amandemen terbit dan menerbitkan "temuan yang sesuai" bila tidak bisa ditunjukkan; tingkat temuannya tidak otomatis minor (Day 03).
- Edisi 2022 memecah 9.2 menjadi 9.2.1 dan 9.2.2 serta 9.3 menjadi 9.3.1-9.3.3; sebagian ringkasan sekunder menulisnya terbalik (Day 02).
- Sebagian daftar konsultan masih memakai judul kontrol 2013 untuk 8.20 dan 8.22; judul 2022 adalah "Networks security" dan "Segregation of networks" (Day 08).
- Halaman The Open Group masih menampilkan Open FAIR O-RA 2.0.1 dan O-RT 3.0.1; versi 2.1/3.1 hanya muncul di sumber sekunder (Day 09).
- Sebagian ringkasan vendor membalik label tactical dan operational pada kontrol 5.7; menurut 27002, tactical berisi TTP pelaku dan operational berisi serangan tertentu beserta indikatornya (Day 12).
- Informative Reference ISO/IEC 27001:2022 ke CSF 2.0 di katalog NIST berversi 1.0.0. Mapping di katalog itu melewati komentar publik, tetapi NIST tidak menguji kebenaran mapping kiriman pihak luar; perlakukan sebagai acuan yang lebih kuat daripada tabel vendor, bukan kebenaran mutlak (Day 08).
- IAF berhenti beroperasi 1 Januari 2026 dan digantikan Global ACI; dokumen dan tanda IAF MLA masih beredar selama masa peralihan (Day 17).
- Hampir semua materi daring tentang 27017, 27018, 27031, dan 27701 masih merujuk edisi yang sudah ditarik; 27701:2025 kini bisa disertifikasi tanpa 27001 (Day 19).
- Peraturan BSSN No. 8 Tahun 2020 adalah titik tempat regulasi Indonesia menyebut SNI ISO/IEC 27001 secara eksplisit, dengan kewajiban berbeda untuk sistem strategis, tinggi, dan rendah (Day 18).

Latihan semua Day memakai organisasi fiktif yang sama (PT Awan Nusantara) dan disimpan di `latihan/dayNN-<org>.md`.

## Struktur folder

| File | Isi |
|---|---|
| `README.md` | Tujuan, versi acuan, temuan penting, dan daftar isi |
| `SOURCES.md` | Indeks sumber yang dipakai di semua Day |
| `NN-<slug>.md` | Satu Day per file |
| `LICENSE` | Lisensi CC BY 4.0 |

## Daftar isi

| Day | Topik |
|---|---|
| 01 | [Gambaran besar ISMS: PDCA, keluarga 27000, sertifikasi vs kepatuhan](01-gambaran-isms.md) |
| 02 | [Peta klausul 4-10](02-peta-klausul-4-10.md) |
| 03 | [Klausul 4-5](03-klausul-4-5-konteks-kepemimpinan.md) |
| 04 | [Klausul 6: risiko, objectives, SoA](04-klausul-6-risiko-sasaran-soa.md) |
| 05 | [Klausul 7-8](05-klausul-7-8-support-operasi.md) |
| 06 | [Klausul 9-10](06-klausul-9-10-evaluasi-perbaikan.md) |
| 07 | [Review Minggu 1](07-review-minggu-1.md) |
| 08 | [Annex A 2022](08-annex-a-2022.md) |
| 09 | [Manajemen risiko praktik (27005)](09-manajemen-risiko-praktik.md) |
| 10 | [Kontrol insiden dan pelaporan event (27035)](10-insiden-dan-27035.md) |
| 11 | [Logging, monitoring, sinkronisasi waktu](11-logging-monitoring-waktu.md) |
| 12 | [Threat intelligence dan manajemen kerentanan](12-threat-intel-kerentanan-pemasok.md) |
| 13 | [Audit dan bukti](13-audit-dan-bukti.md) |
| 14 | [Capstone dan interview](14-capstone-dan-interview.md) |
| 15 | [Menjalankan audit internal: dari program sampai laporan](15-menjalankan-audit-internal.md) |
| 16 | [Menutup temuan dengan benar: koreksi, CAPA, management review](16-capa-dan-management-review.md) |
| 17 | [Sistem sertifikasi dan akreditasi: arti sebuah sertifikat](17-sistem-sertifikasi-dan-akreditasi.md) |
| 18 | [Regulasi Indonesia dan ISMS: memetakan kewajiban ke kendali](18-regulasi-indonesia-dan-isms.md) |
| 19 | [Memperluas ISMS: kelangsungan, cloud, dan privasi](19-kelangsungan-cloud-dan-privasi.md) |

## Catatan repo

Jangan commit: data/log/screenshot dari pekerjaan, kredensial, token API, sampel berbahaya, PDF standar, atau materi berbayar pihak lain.

