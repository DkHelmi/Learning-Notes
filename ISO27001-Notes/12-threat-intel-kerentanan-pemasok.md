---
day: 12
title: 'Threat intelligence dan manajemen kerentanan: kontrol 5.7 dan 8.8, bentuk bukti, serta pemasok dan cloud secara ringkas'
researched_on: 2026-10-10
versions_checked: 'ISO/IEC 27001:2022 + Amd 1:2024; ISO/IEC 27002:2022; ISO/IEC 27017:2026 (edisi 2, 27 Jul 2026); CVSS v4.0 (FIRST); EPSS (FIRST, model terbaru); CISA KEV (1.734 entri per 2026-10-08)'
---

# Day 12: Threat intelligence, manajemen kerentanan, dan pemasok

> Catatan pribadi, bukan materi resmi ISO, dan bukan nasihat hukum atau audit. Semua CVE, pemasok, dan angka di contoh PT AN adalah fiktif.

Cakupan: kontrol 5.7 Threat intelligence dan 8.8 Management of technical vulnerabilities, alat prioritas (CVSS v4.0, EPSS, KEV), hubungan dengan CTI, SOC, dan risk register, serta kontrol pemasok dan cloud (5.19-5.23) secara ringkas.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- menjelaskan tujuan kontrol 5.7, tiga tingkat intelijen, dan ciri intelijen yang berguna, beserta bukti yang diharapkan auditor.
- menjelaskan alur kontrol 8.8, dari inventaris aset sampai tindakan dan rekaman.
- memakai CVSS v4.0, EPSS, dan KEV bersama-sama untuk memprioritaskan kerentanan, serta memahami batas masing-masing.
- menghubungkan intel dan data kerentanan ke risk register (Day 09), deteksi (Day 11), dan respons (Day 10).
- menyebut kontrol pemasok dan cloud yang relevan untuk SOC yang memakai layanan pihak ketiga.

## 2. Konteks singkat

Kontrol 5.7 baru ada di edisi 2022. Sebelumnya, banyak organisasi tersertifikasi tanpa proses intelijen yang jelas. Sekarang auditor bisa bertanya: "intel apa yang kalian kumpulkan, dari mana, dan apa yang berubah karenanya?" Kontrol 8.8 sudah lama ada, tetapi masih sering menjadi sumber temuan, karena kerentanan kritis yang dibiarkan terbuka mudah dibuktikan.

Bagi analyst SOC, kedua kontrol ini sangat konkret. Advisori tentang VPN yang sedang dieksploitasi adalah intelijen (5.7). Keputusan memprioritaskan patch VPN itu adalah manajemen kerentanan (8.8). Rule deteksi tambahan untuk eksploitasi tersebut adalah monitoring (8.16). Bila semua langkah itu tercatat, satu kejadian menghasilkan bukti untuk tiga kontrol.

Kapan dipakai: brief intel rutin, triage advisori, rapat prioritas patch, dan persiapan audit.
Kapan tidak cukup: 5.7 tidak menentukan platform TI (MISP, OpenCTI) atau langganan feed. Pilihan itu bergantung pada risiko dan sumber daya.

## 3. Konsep inti

### 3.1 Kontrol 5.7: threat intelligence

Tujuan kontrol ini adalah memberi organisasi pemahaman tentang ancaman yang relevan, supaya bisa mengambil tindakan pencegahan dan deteksi yang tepat [S1].

Tiga tingkat intelijen [S1]:

| Tingkat | Isi | Pengguna utama | Contoh |
|---|---|---|---|
| Strategic | Gambaran tingkat tinggi tentang lanskap ancaman: jenis pelaku, tren serangan | Pimpinan, ISMS Manager | "Ransomware ke penyedia hosting di Asia Tenggara meningkat" |
| Operational | Taktik, teknik, prosedur, dan alat pelaku | Lead SOC, threat hunter | "Kelompok X memakai eksploitasi VPN lalu RMM tool untuk persistence" |
| Tactical | Indikator teknis serangan tertentu | Analyst SOC, engineer deteksi | Hash, domain, IP, signature |

Perhatikan bahwa pembagian di 27002 menempatkan TTP di operational dan IOC di tactical. Beberapa literatur CTI memakai urutan sebaliknya: tactical untuk TTP, dan operational untuk informasi tentang kampanye atau serangan tertentu yang akan datang. Saat membaca laporan atau kontrak layanan intel, cek definisi yang dipakai, bukan hanya labelnya. Untuk audit ISMS, pakai pembagian 27002 supaya bahasanya sama dengan auditor.

Intelijen yang berguna punya empat ciri: relevan, memberi wawasan (sebagian ringkasan menerjemahkannya "perceptive", sebagian "insightful"), kontekstual, dan bisa ditindaklanjuti [S1][S7]. Aktivitas yang disarankan meliputi menetapkan tujuan intelijen, mengidentifikasi dan memilih sumber, mengumpulkan, memproses, menganalisis, lalu mengomunikasikan hasilnya ke pihak yang tepat. Intelijen dipakai sebagai input proses risiko, pemilihan kontrol pencegahan dan deteksi, serta pengujian kontrol [S1]. Cek urutan aktivitas di teks 27002 5.7.

Bukti yang biasanya diminta auditor:

- daftar kebutuhan intelijen atau tujuan intel;
- daftar sumber beserta penilaian keandalannya;
- brief atau laporan berkala;
- catatan tindakan yang diambil karena intel, misalnya rule baru, patch dipercepat, atau risiko dinilai ulang.

Bukti terakhir paling penting. Feed yang hanya diimpor ke SIEM tanpa catatan keputusan sulit dibuktikan sebagai intelijen.

### 3.2 Kontrol 8.8: manajemen kerentanan teknis

Panduan 8.8 bisa diringkas menjadi alur berikut [S2]:

1. **Prasyarat:** inventaris aset yang lengkap dan mutakhir, termasuk vendor, versi, dan lokasi perangkat lunak (kontrol 5.9).
2. **Peran:** siapa yang memantau, menilai, dan memperbaiki.
3. **Identifikasi:** pemindaian otomatis, penetration test, advisori vendor, kewajiban pemasok melaporkan kerentanan, dan pemantauan library pihak ketiga.
4. **Evaluasi:** analisis laporan dan keputusan tindakan, dengan prioritas pada sistem kritis dan berisiko tinggi.
5. **Tindakan:** patch yang diuji lebih dulu. Bila patch belum ada, gunakan workaround vendor, nonaktifkan layanan, filter jaringan, atau perketat monitoring.
6. **Cloud:** praktik kerentanan penyedia layanan harus sesuai standar organisasi dan tertuang di perjanjian.
7. **Rekaman:** jejak semua aktivitas untuk respons insiden dan perbaikan proses.

Bila tidak ada patch, "perketat monitoring" adalah tindakan yang sah. Di sini SOC berperan langsung: rule deteksi khusus untuk eksploitasi kerentanan itu adalah kontrol kompensasi yang harus tercatat.

### 3.3 Alat prioritas: CVSS, EPSS, KEV

Ketiga alat ini menjawab pertanyaan yang berbeda:

| Alat | Pertanyaan yang dijawab | Catatan |
|---|---|---|
| CVSS v4.0 (FIRST) | Seberapa parah kerentanan ini secara teknis? | Kelompok metrik: Base, Threat (dulu Temporal), Environmental, dan Supplemental yang tidak memengaruhi skor [S3]. Skor Base saja bukan ukuran risiko |
| EPSS (FIRST) | Seberapa mungkin CVE ini dieksploitasi dalam 30 hari ke depan? | Model machine learning; skor probabilitas 0-1 dan persentil, diperbarui harian [S4] |
| KEV (CISA) | Apakah CVE ini sudah terbukti dieksploitasi? | Katalog otoritatif; 1.734 entri per 2026-10-08; tersedia dalam CSV dan JSON [S8] |

Cara menggabungkan yang umum: KEV sebagai pemicu tercepat (sudah dieksploitasi), EPSS untuk membedakan antar CVE yang belum masuk KEV, CVSS untuk dampak teknis, lalu kritikalitas aset dan paparan (menghadap internet atau tidak) dari inventaris sendiri. Tidak ada satu skor yang cukup sendirian.

Catatan versi: CVSS v4.0 dirilis FIRST pada November 2023 dan menggantikan v3.1 sebagai versi terbaru, walaupun banyak scanner dan database masih menampilkan skor v3.1 berdampingan. Model EPSS terbaru dilaporkan sumber sekunder sebagai versi 4 (Maret 2025); halaman utama EPSS tidak menyebut nomor versi, jadi cek di halaman model EPSS sebelum mengutipnya. Skor EPSS dari versi model berbeda tidak bisa dibandingkan langsung.

Halaman KEV per 2026-10-08 merujuk Binding Operational Directive 26-04 tentang prioritas update keamanan berbasis risiko [S8]. BOD hanya mengikat lembaga federal AS. Untuk PT AN, KEV dipakai sebagai sumber intel, bukan kewajiban. Cek hubungan BOD 26-04 dengan BOD 22-01 yang sebelumnya terkait KEV.

### 3.4 Alur intel, kerentanan, deteksi, dan risiko

```
Sumber intel (advisori, KEV, feed, laporan) --> 5.7 analisis: relevan untuk aset kita?
        |                                                 |
        |                       +-------------------------+-------------------------+
        |                       v                         v                         v
        |            8.8 prioritas patch        8.16 rule deteksi/hunt       8.2 risk register:
        |            (SLA, workaround)          (kontrol kompensasi)          ubah kemungkinan
        |                       |                         |                         |
        +---------------------> rekaman: tiket patch, ID rule, catatan risiko, brief intel
```

Satu advisori yang relevan sebaiknya menghasilkan minimal satu keputusan yang tercatat. Bila advisori dinilai tidak relevan (produk tidak dipakai), catat juga keputusan itu. Catatan "tidak relevan" adalah bukti bahwa proses 5.7 berjalan.

### 3.5 Pemasok dan cloud secara ringkas

SOC modern hampir selalu bergantung pada pihak ketiga: SIEM cloud, feed intel berbayar, MSSP, atau EDR berbasis SaaS. Kontrol yang relevan:

| Kontrol | Gagasan inti | Contoh SOC |
|---|---|---|
| 5.19 Supplier relationships | Proses dan prosedur untuk risiko pemasok | Penilaian keamanan sebelum memilih SIEM cloud |
| 5.20 Supplier agreements | Persyaratan keamanan di kontrak | Notifikasi insiden pemasok, lokasi data, hak audit |
| 5.21 ICT supply chain | Risiko rantai pasok TIK | Update agent dari vendor yang dikompromikan |
| 5.22 Monitoring of supplier services | Pemantauan, tinjauan, dan perubahan layanan pemasok | Laporan SLA MSSP, tinjauan tahunan |
| 5.23 Use of cloud services | Proses memperoleh, memakai, mengelola, dan mengakhiri layanan cloud | Rencana keluar (exit) bila ganti penyedia SIEM |

Standar pendukung:

- **ISO/IEC 27017:2026 (edisi 2)** terbit 27 Juli 2026. Isinya panduan kontrol keamanan berbasis 27002 untuk layanan cloud, bagi pelanggan maupun penyedia cloud, termasuk kejelasan pembagian tanggung jawab [S5]. Edisi ini menggantikan 27017:2015.
- **Seri ISO/IEC 27036** membahas keamanan hubungan dengan pemasok: bagian 1 berisi gambaran dan konsep, bagian 2 persyaratan, bagian 3 panduan rantai pasok perangkat keras, perangkat lunak, dan layanan TIK, dan bagian 4 panduan untuk layanan cloud. Bagian-bagiannya sedang diperbarui; katalog standar nasional Selandia Baru mencantumkan draft adopsi 27036-1 tahun 2025 [S6]. Cek edisi tiap bagian di katalog ISO.

Konsultan URM melaporkan temuan audit 2026 berupa tidak adanya ketentuan keluar (exit) untuk layanan cloud (5.23) (lihat Day 08). DBIR 2026 juga menyoroti peningkatan keterlibatan pihak ketiga dalam breach (Day 09).

## 4. Contoh dokumen / artefak (organisasi fiktif)

Organisasi fiktif: PT Awan Nusantara (PT AN). CVE di bawah memakai label fiktif (`CVE-FIKTIF-xx`) agar tidak tertukar dengan CVE nyata.

### 4.1 Kebutuhan intelijen prioritas (PIR) PT AN

| ID | Pertanyaan intelijen | Pengguna | Sumber utama |
|---|---|---|---|
| PIR-1 | Kerentanan apa pada produk perimeter kita (VPN, firewall, hypervisor) yang sedang dieksploitasi? | Head of Platform, Lead SOC | Advisori vendor, KEV, peringatan BSSN atau CSIRT sektor, feed komersial |
| PIR-2 | Kelompok ransomware mana yang menyasar penyedia hosting di kawasan ini, dan TTP apa yang mereka pakai? | Lead SOC, threat hunter | Laporan vendor publik, ISAC, The DFIR Report |
| PIR-3 | Apakah ada data atau kredensial PT AN yang beredar di luar? | ISMS Manager | Layanan pemantauan kebocoran (sesuai ToS dan hukum) |
| PIR-4 | Tren regulasi dan ancaman apa yang perlu diketahui pimpinan per kuartal? | Direksi | Laporan strategis, advisori pemerintah |

PIR membuat 5.7 bisa diaudit, karena setiap brief bisa dicek: pertanyaan mana yang dijawab, dan tindakan apa yang diambil.

### 4.2 Kebijakan SLA kerentanan (cuplikan)

| Kategori | Kriteria | Tenggat tindakan |
|---|---|---|
| Darurat | Ada di KEV atau intel menunjukkan eksploitasi aktif, dan aset menghadap internet | 72 jam (patch atau mitigasi) |
| Tinggi | CVSS Base minimal 7.0 dan EPSS minimal 0,1, atau aset kritis | 14 hari |
| Sedang | CVSS Base 4.0-6.9, atau CVSS tinggi pada aset internal non-kritis dengan EPSS rendah | 30 hari |
| Rendah | Sisanya | Siklus patch berikutnya (maks 90 hari) |

Bila tenggat tidak bisa dipenuhi, harus ada pengecualian tertulis dengan kontrol kompensasi (misalnya rule deteksi khusus) dan persetujuan risk owner.

### 4.3 Contoh keputusan prioritas

| CVE | Aset | Internet? | KEV | EPSS | CVSS Base | Kategori | Alasan |
|---|---|---|---|---|---|---|---|
| CVE-FIKTIF-01 | VPN appliance | Ya | Ya | 0,94 | 9.8 | Darurat | KEV dan menghadap internet |
| CVE-FIKTIF-02 | Hypervisor mgmt | Tidak (VPN) | Tidak | 0,32 | 8.1 | Tinggi | CVSS 8.1 dan EPSS 0,32 memenuhi kriteria Tinggi; juga aset kritis |
| CVE-FIKTIF-03 | Server build internal | Tidak | Tidak | 0,02 | 9.1 | Sedang | CVSS tinggi tetapi EPSS rendah dan aset internal non-kritis |
| CVE-FIKTIF-04 | Wiki dokumentasi internal | Tidak | Tidak | 0,04 | 5.3 | Sedang | CVSS 5.3 dan aset non-kritis |
| CVE-FIKTIF-05 | Laptop staf | Tidak | Ya | 0,71 | 7.8 | Tinggi | Di KEV tetapi tidak menghadap internet, jadi tidak memenuhi syarat Darurat; CVSS 7.8 dan EPSS 0,71 memenuhi Tinggi |

Periksa konsistensi baris CVE-FIKTIF-03. CVSS 9.1 memenuhi syarat pertama kategori Tinggi, tetapi EPSS 0,02 kurang dari 0,1 dan aset tidak kritis, sehingga kriteria Tinggi tidak terpenuhi. Kriteria Sedang di tabel 4.2 secara eksplisit mencakup kasus ini. Tanpa kalimat itu, CVE-FIKTIF-03 tidak masuk kategori mana pun. Menguji kebijakan dengan contoh nyata seperti ini adalah cara menemukan celah aturan.

Baris CVE-FIKTIF-05 menunjukkan keputusan yang bisa diperdebatkan. Laptop memang tidak menghadap internet, tetapi laptop berpindah jaringan. Tim bisa memutuskan menaikkannya ke Darurat. Apa pun keputusannya, alasannya harus tertulis.

### 4.4 Brief intel bulanan (kerangka)

```
TI-BRIEF 2026-09 (TLP:AMBER, distribusi: internal PT AN)
1. Ringkasan untuk pimpinan (PIR-4): 3 kalimat
2. Kerentanan dieksploitasi yang relevan (PIR-1): CVE-FIKTIF-01 -> tiket PATCH-2231, selesai 2026-09-04
3. TTP kelompok ransomware relevan (PIR-2): 2 teknik baru -> rule DET-118, hunt HUNT-2026-07
4. Indikasi kebocoran (PIR-3): tidak ditemukan
5. Keputusan dan tindakan: risiko R-21 kemungkinan tetap 4 sampai patch diverifikasi
6. Advisori yang dinilai tidak relevan: 4 (produk tidak dipakai), dicatat di log intel
```

Bagian 5 dan 6 adalah bukti terkuat untuk 5.7, karena menunjukkan intel menghasilkan keputusan, termasuk keputusan "tidak relevan". Label TLP mengikuti standar TLP 2.0 dari FIRST.

## 5. Lab praktik

Latihan untuk organisasi fiktifmu. Simpan di `ISO27001-note/latihan/day12-<nama-org-fiktif>.md`.

1. Tulis 4-5 PIR untuk organisasimu, masing-masing dengan pengguna dan sumber utama.
2. Buat daftar sumber intel minimal 6, berisi nama, jenis (gratis atau berbayar), tingkat (strategic, operational, tactical), penilaian keandalan, dan label TLP default.
3. Tulis kebijakan SLA kerentanan seperti bagian 4.2. Uji dengan 6 kerentanan fiktif dan pastikan setiap kerentanan masuk tepat satu kategori. Bila ada yang tidak masuk kategori mana pun, perbaiki kebijakannya.
4. Tulis brief intel bulanan dengan kerangka bagian 4.4. Minimal satu tindakan untuk 8.8, satu untuk 8.16, dan satu catatan advisori yang tidak relevan.
5. Tulis kuesioner singkat (10 pertanyaan) untuk menilai penyedia SIEM cloud: notifikasi insiden, lokasi data, retensi, akses admin penyedia, hak audit, ketentuan keluar, dan praktik kerentanan penyedia.
6. Hubungkan ke lab:
   - bila Wazuh lab-mu mengaktifkan deteksi kerentanan, ambil daftar kerentanan untuk satu VM lab dan klasifikasikan dengan kebijakan langkah 3. Cek nama modul dan menu di versi Wazuh lab-mu;
   - bila tidak, buat inventaris perangkat lunak 2 VM lab secara manual (nama dan versi).
   Cocokkan dengan KEV dalam format CSV atau JSON dari situs CISA; file ini hanya data teks, bukan biner.

**Hasil yang seharusnya teramati:** PIR, daftar sumber, kebijakan SLA yang sudah diuji, brief intel dengan keputusan, kuesioner pemasok, dan satu klasifikasi kerentanan dari lab-mu.

**Hasil yang sebaiknya tersimpan:**
- Setiap brief intel memuat keputusan dan tindakan, bukan hanya berita.
- Kebijakan SLA diuji dengan contoh dan tidak ada kerentanan yang jatuh di luar kategori.
- Pengecualian SLA butuh kontrol kompensasi dan persetujuan risk owner.
- Kuesioner pemasok mencakup ketentuan keluar (5.23).
- Data kerentanan dari lab hanya berasal dari VM lab.

**Variasi tantangan:** advisori baru menyebut eksploitasi aktif pada produk yang kamu pakai, tetapi patch baru tersedia 10 hari lagi. Tulis langkah lengkapnya: keputusan 5.7, mitigasi sementara 8.8, rule deteksi 8.16, perubahan kemungkinan di risk register, dan siapa yang menyetujui pengecualian SLA.

## 6. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Feed intel masuk SIEM tetapi auditor tidak puas | Tidak ada bukti analisis dan keputusan | Brief berkala dengan bagian "keputusan dan tindakan" |
| Ribuan temuan scanner, tidak tahu mulai dari mana | Prioritas hanya berdasarkan CVSS | Tambahkan KEV, EPSS, paparan internet, dan kritikalitas aset |
| Kerentanan "Tinggi" terbuka berbulan-bulan | Tidak ada SLA atau pengecualian tidak dikelola | SLA tertulis, laporan umur kerentanan bulanan, pengecualian dengan tenggat |
| Tidak tahu versi perangkat lunak di server | Inventaris aset (5.9) lemah | Perbaiki inventaris dulu; 8.8 bergantung padanya |
| Penyedia cloud menolak memberi informasi | Persyaratan tidak dimasukkan saat kontrak | Masukkan klausul di perpanjangan berikutnya; gunakan laporan audit pihak ketiga penyedia |

## 7. Kesalahan umum dan jebakan

- Menyamakan "berlangganan feed" dengan memenuhi 5.7. Kontrol ini menuntut analisis dan tindakan.
- Memakai skor CVSS Base sebagai satu-satunya ukuran prioritas.
- Membaca EPSS sebagai kepastian. EPSS adalah probabilitas, dan CVE dengan EPSS rendah tetap bisa dieksploitasi pada targetmu.
- Menganggap BOD CISA mengikat organisasi di luar pemerintah federal AS.
- Mengabaikan kerentanan pada layanan cloud karena "itu tanggung jawab penyedia". Pembagian tanggung jawab harus tertulis (5.23, 27017).
- Membagikan intel berlabel TLP:AMBER ke grup yang lebih luas dari yang diizinkan. Hormati label TLP.

## 8. Catatan terkini

- ISO/IEC 27017:2026 (edisi 2) terbit 27 Juli 2026 dan diselaraskan dengan 27002:2022 [S5].
- Katalog KEV CISA berisi 1.734 entri per 2026-10-08 dan merujuk BOD 26-04 tentang prioritas update keamanan berbasis risiko [S8].
- CVSS v4.0 memperkenalkan kelompok metrik Threat (pengganti Temporal) dan Supplemental [S3].
- EPSS dihitung harian untuk setiap CVE dengan jendela prediksi 30 hari [S4]. Nomor versi model terbaru perlu dicek di halaman model EPSS (lihat bagian 3.3).

## 9. Cheat sheet

```
5.7 TI: strategic (lanskap, pimpinan) | operational (TTP) | tactical (IOC)
    ciri: relevan, wawasan, kontekstual, bisa ditindaklanjuti
    alur: tujuan/PIR -> sumber -> kumpulkan -> proses -> analisis -> komunikasikan -> TINDAKAN TERCATAT
    bukti: PIR, daftar sumber, brief, keputusan (termasuk "tidak relevan")
8.8 Kerentanan: inventaris (5.9) -> peran -> identifikasi -> evaluasi -> tindakan (patch/workaround/filter/monitor) -> rekaman
    cloud: praktik penyedia di kontrak
Prioritas: KEV (sudah dieksploitasi) > EPSS (peluang 30 hari) + CVSS v4 (keparahan) + paparan + kritikalitas aset
CVSS v4.0: Base | Threat (eks Temporal) | Environmental | Supplemental (tidak ubah skor)
Pemasok: 5.19 hubungan | 5.20 kontrak | 5.21 rantai pasok TIK | 5.22 pantau & tinjau | 5.23 cloud (+ exit)
Standar: 27017:2026 ed.2 (cloud) | seri 27036 (pemasok) | TLP 2.0 (FIRST) untuk berbagi intel
```

## 10. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | ISMS.online: ISO 27002 control 5.7 threat intelligence | https://isms.online/iso-27002/control-5-7-threat-intelligence | sekunder (vendor) | diakses 2026-10-08 | Sedang. Tiga tingkat, ciri, aktivitas, pemakaian |
| S2 | ISMS.online: ISO 27002 control 8.8 management of technical vulnerabilities | https://www.isms.online/iso-27002/control-8-8-management-of-technical-vulnerabilities/ | sekunder (vendor) | 2025-07-25; diakses 2026-10-08 | Sedang. Alur 8.8 dari inventaris sampai rekaman |
| S3 | FIRST: CVSS v4.0 | https://www.first.org/cvss/v4-0/ | primer (pemilik standar) | diakses 2026-10-08 | Tinggi untuk kelompok metrik |
| S4 | FIRST: Exploit Prediction Scoring System | https://www.first.org/epss/ | primer (pemilik model) | diakses 2026-10-08 | Tinggi. Jendela 30 hari, pembaruan harian |
| S5 | ISO committee: ISO/IEC 27017:2026 | https://committee.iso.org/standard/27017 | primer (katalog ISO) | 2026-07-27; diakses 2026-10-08 | Tinggi |
| S6 | Standards New Zealand: DZ ISO/IEC 27036-1:2025 (draft adopsi) | https://www.standards.govt.nz/shop/DZ-ISOIEC-27036-12025 | sekunder (badan standar nasional) | diakses 2026-10-08 | Rendah-sedang. Petunjuk bahwa seri 27036 sedang direvisi; edisi tiap bagian perlu dicek di katalog ISO |
| S7 | Rapid7: ISO 27002 emphasizes need for threat intelligence | https://www.rapid7.com/blog/post/2022/07/25/iso-27002-emphasizes-need-for-threat-intelligence/ | sekunder (vendor) | 2022-07-25; diakses 2026-10-08 | Sedang. Ciri intelijen dan variasi istilahnya |
| S8 | CISA: Known Exploited Vulnerabilities Catalog | https://www.cisa.gov/known-exploited-vulnerabilities-catalog | primer (lembaga pemerintah) | diakses 2026-10-08 | Tinggi. Jumlah entri dan rujukan BOD 26-04 per tanggal akses |

**Catatan sumber:** isi 5.7, 8.8, dan 5.19-5.23 disusun dari ringkasan sekunder, bukan dari teks 27002; urutan aktivitas 5.7 dan langkah 8.8 perlu dicocokkan dengan teks standar sebelum dikutip. Nomor versi model EPSS dan isi BOD 26-04 serta hubungannya dengan BOD 22-01 perlu dicek di situs FIRST dan CISA. Jumlah entri KEV berubah hampir setiap minggu; angka 1.734 hanya berlaku per 2026-10-08.
