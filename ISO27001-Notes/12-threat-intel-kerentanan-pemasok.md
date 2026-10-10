---
day: 12
title: 'Threat intelligence dan manajemen kerentanan: kontrol 5.7 dan 8.8, bentuk bukti, serta pemasok dan cloud secara ringkas'
researched_on: 2026-10-10
versions_checked: 'ISO/IEC 27001:2022 + Amd 1:2024; ISO/IEC 27002:2022; ISO/IEC 27017:2026 (edisi 2, 27 Jul 2026); ISO/IEC 27036-3:2023 (edisi 2); CVSS v4.0 (FIRST, 1 Nov 2023, dokumen spesifikasi v1.2); EPSS v4 (Maret 2025); CISA KEV (1.739 entri per 2026-10-10); CISA BOD 26-04 (10 Jun 2026); TLP 2.0 (FIRST)'
---

# Day 12: Threat intelligence, manajemen kerentanan, dan pemasok

Cakupan: kontrol 5.7 Threat intelligence dan 8.8 Management of technical vulnerabilities, alat prioritas (CVSS v4.0, EPSS, KEV), hubungannya dengan SOC dan risk register, serta kontrol pemasok dan cloud (5.19-5.23) secara ringkas.

> Catatan pribadi, bukan materi resmi ISO, dan bukan nasihat hukum atau audit. Semua CVE, pemasok, dan angka di contoh PT AN adalah fiktif.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- menjelaskan tujuan kontrol 5.7, tiga tingkat intelijen, dan ciri intelijen yang berguna, beserta bukti yang diharapkan auditor.
- menjelaskan alur kontrol 8.8, dari inventaris aset sampai tindakan dan rekaman.
- memakai CVSS v4.0, EPSS, dan KEV bersama-sama untuk memprioritaskan kerentanan, serta memahami batas masing-masing.
- menghubungkan intel dan data kerentanan ke risk register (Day 09), deteksi (Day 11), dan respons (Day 10).
- menyebut kontrol pemasok dan cloud yang relevan untuk SOC yang memakai layanan pihak ketiga.

## 2. Konteks singkat

Kontrol 5.7 baru ada di edisi 2022, sehingga auditor bisa bertanya: "intel apa yang kalian kumpulkan, dari mana, dan apa yang berubah karenanya?" Kontrol 8.8 (dulu A.12.6.1) masih sering menjadi sumber temuan, karena kerentanan kritis yang terbuka mudah dibuktikan.

Bagi SOC, kedua kontrol ini konkret: advisori VPN yang sedang dieksploitasi adalah intelijen (5.7), keputusan mempercepat patch-nya manajemen kerentanan (8.8), dan rule deteksi eksploitasinya monitoring (8.16). Bila tercatat, satu kejadian menjadi bukti tiga kontrol.

Kapan dipakai: brief intel rutin, triage advisori, rapat prioritas patch, dan persiapan audit.
Kapan tidak cukup: 5.7 tidak menentukan platform intel (MISP, OpenCTI) atau langganan feed.

## 3. Konsep inti

### 3.1 Kontrol 5.7: threat intelligence

Tujuannya memberi pemahaman tentang ancaman yang relevan agar tindakan pencegahan dan deteksi tepat [S1].

Tiga tingkat intelijen menurut panduan 27002 [S6]:

| Tingkat | Isi | Pengguna utama | Contoh |
|---|---|---|---|
| Strategic | Informasi tingkat tinggi tentang lanskap ancaman yang berubah: jenis pelaku, jenis serangan | Pimpinan, ISMS Manager | "Ransomware ke penyedia hosting di Asia Tenggara meningkat" |
| Tactical | Metodologi, alat, dan teknologi pelaku (TTP) | Lead SOC, threat hunter | "Kelompok X memakai eksploitasi VPN lalu RMM tool untuk persistence" |
| Operational | Rincian serangan tertentu, termasuk indikator teknis | Analyst SOC, engineer deteksi | Hash, domain, IP, signature dari kampanye yang sedang berjalan |

Perhatian: sebagian ringkasan vendor (ISMS.online, Rapid7) membalik label, menaruh TTP di operational dan indikator di tactical [S1][S7], dan literatur CTI pun tidak seragam. Saat membaca kontrak layanan intel, cek definisinya, bukan labelnya; untuk audit, cocokkan dengan teks 27002 5.7 milik organisasimu.

Intelijen yang berguna itu relevan, memberi wawasan ("insightful" atau "perceptive" di ringkasan berbeda), kontekstual, dan bisa ditindaklanjuti [S6][S1]. Aktivitas yang disarankan [S6]:

1. menetapkan tujuan intelijen;
2. mengidentifikasi, memeriksa, dan memilih sumber internal dan eksternal;
3. mengumpulkan informasi;
4. memproses (menerjemahkan, memformat, menguatkan dengan sumber lain);
5. menganalisis dampaknya bagi organisasi;
6. mengomunikasikan ke orang yang tepat dalam format yang mudah dipahami.

Hasilnya menjadi input proses risiko, kontrol pencegahan dan deteksi tambahan, serta pengujian keamanan [S1].

Bukti yang biasa diminta auditor: kebutuhan intelijen, daftar sumber dengan penilaian keandalan, brief berkala, dan catatan tindakan karena intel (rule baru, patch dipercepat, risiko dinilai ulang). Yang terakhir paling penting; feed yang hanya diimpor ke SIEM tanpa catatan keputusan sulit dibuktikan sebagai intelijen.

### 3.2 Kontrol 8.8: manajemen kerentanan teknis

Panduan 8.8 bisa diringkas menjadi alur berikut [S2]:

1. **Prasyarat:** inventaris aset yang lengkap dan mutakhir, termasuk vendor, versi, dan lokasi perangkat lunak (5.9 Inventory of information and other associated assets).
2. **Peran:** siapa yang memantau, menilai, dan memperbaiki.
3. **Identifikasi:** pemindaian otomatis, penetration test, advisori vendor, kewajiban pemasok melaporkan kerentanan, dan pemantauan library pihak ketiga.
4. **Evaluasi:** analisis laporan dan keputusan tindakan, dengan prioritas pada sistem kritis dan berisiko tinggi.
5. **Tindakan:** patch yang diuji lebih dulu. Bila patch belum ada, gunakan workaround vendor, nonaktifkan layanan, filter jaringan, atau perketat monitoring.
6. **Cloud:** praktik kerentanan penyedia layanan harus sesuai standar organisasi dan tertuang di perjanjian.
7. **Rekaman:** jejak semua aktivitas untuk respons insiden dan perbaikan proses.

Bila patch belum ada, rule deteksi khusus dari SOC adalah kontrol kompensasi yang sah, asalkan tercatat.

### 3.3 Alat prioritas: CVSS, EPSS, KEV

Ketiga alat ini menjawab pertanyaan yang berbeda:

| Alat | Pertanyaan yang dijawab | Catatan |
|---|---|---|
| CVSS v4.0 (FIRST) | Seberapa parah kerentanan ini secara teknis? | Kelompok metrik Base, Threat (dulu Temporal), Environmental, dan Supplemental [S3]. Skor Base saja bukan ukuran risiko |
| EPSS (FIRST) | Seberapa mungkin CVE ini dieksploitasi dalam 30 hari ke depan? | Probabilitas 0-1 beserta persentil, diterbitkan setiap hari untuk setiap CVE [S4] |
| KEV (CISA) | Apakah CVE ini sudah terbukti dieksploitasi? | Katalog otoritatif; 1.739 entri per 2026-10-10; tersedia dalam CSV dan JSON [S8] |

**CVSS v4.0** dirilis FIRST pada 1 November 2023; dokumen spesifikasinya kini revisi v1.2 (Juni 2024) [S9]. Skor disebut bersama kelompok metriknya: CVSS-B (Base), CVSS-BT (Base dan Threat), CVSS-BE, atau CVSS-BTE. Metrik Supplemental seperti Safety, Automatable, dan Provider Urgency tidak mengubah skor, tetapi berguna untuk keputusan [S3]. Banyak scanner masih menampilkan skor v3.1, jadi cek versinya sebelum membandingkan angka.

**EPSS** versi model 4 dirilis Maret 2025 dengan tambahan data deteksi malware dan endpoint [S10]. Model dilatih ulang kira-kira setahun sekali bila performanya turun, dan baris komentar pertama file CSV EPSS menyebut model yang dipakai [S4]. Jangan membandingkan skor dari versi model berbeda.

**KEV dan BOD 26-04.** CISA menerbitkan BOD 26-04 (Prioritizing Security Updates Based on Risk) pada 10 Juni 2026, yang mencabut BOD 22-01 (asal katalog KEV) dan BOD 19-02 [S11]. Katalog KEV tetap berjalan, tetapi tenggat perbaikan kini ditentukan empat faktor: aset terekspos publik atau tidak, CVE ada di KEV atau tidak, eksploitasi bisa diotomasi atau tidak, dan seberapa jauh penyerang menguasai aset (sebagian atau total). Tingkat paling mendesak diberi 3 hari plus forensic triage [S11]; ringkasan sekunder menyebut tingkat lain 14 hari, 60 hari, atau ditunda ke upgrade berikutnya, jadi cek tabel tenggat di dokumen CISA. BOD hanya mengikat lembaga sipil federal AS; bagi PT AN, KEV dan logika empat faktor itu referensi praktik yang baik.

Cara menggabungkan yang umum: KEV sebagai pemicu tercepat, EPSS untuk membedakan CVE di luar KEV, CVSS untuk dampak teknis, lalu kritikalitas aset dan paparan internet dari inventaris sendiri.

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

Satu advisori yang relevan sebaiknya menghasilkan minimal satu keputusan tercatat. Advisori yang tidak relevan (produk tidak dipakai) juga dicatat, karena catatan itu bukti proses 5.7 berjalan.

### 3.5 Pemasok dan cloud secara ringkas

SOC hampir selalu bergantung pada pihak ketiga (SIEM cloud, feed intel, MSSP, EDR SaaS). Kontrol yang relevan:

| Kontrol | Gagasan inti | Contoh SOC |
|---|---|---|
| 5.19 Information security in supplier relationships | Proses dan prosedur untuk risiko pemakaian produk dan layanan pemasok | Penilaian keamanan sebelum memilih SIEM cloud |
| 5.20 Addressing information security within supplier agreements | Persyaratan keamanan yang disepakati di kontrak | Notifikasi insiden pemasok, lokasi data, hak audit |
| 5.21 Managing information security in the ICT supply chain | Risiko rantai pasok produk dan layanan TIK | Update agent dari vendor yang dikompromikan |
| 5.22 Monitoring, review and change management of supplier services | Pemantauan, tinjauan, dan perubahan layanan pemasok | Laporan SLA MSSP, tinjauan tahunan |
| 5.23 Information security for use of cloud services | Proses memperoleh, memakai, mengelola, dan mengakhiri layanan cloud | Rencana keluar (exit) bila ganti penyedia SIEM |

Standar pendukung:

- **ISO/IEC 27017:2026 (edisi 2)** terbit 27 Juli 2026 dan menggantikan 27017:2015. Isinya panduan kontrol keamanan berbasis 27002:2022 untuk layanan cloud, plus kontrol tambahan khusus cloud, bagi pelanggan maupun penyedia, untuk model public, private, dan hybrid [S5].
- **Seri ISO/IEC 27036** (hubungan dengan pemasok): bagian 1 konsep (edisi 2, 2021) [S12], bagian 2 persyaratan, bagian 3 rantai pasok perangkat keras, perangkat lunak, dan layanan (edisi 2, Juni 2023) [S13], bagian 4 layanan cloud. Edisi bagian 2 (2022) dan 4 (2016) perlu dicek di katalog ISO.

## 4. Contoh dokumen / artefak (organisasi fiktif)

Organisasi fiktif: PT Awan Nusantara (PT AN). CVE di bawah memakai label fiktif (`CVE-FIKTIF-xx`) agar tidak tertukar dengan CVE nyata.

### 4.1 Kebutuhan intelijen prioritas (PIR) PT AN

| ID | Pertanyaan intelijen | Pengguna | Sumber utama |
|---|---|---|---|
| PIR-1 | Kerentanan apa pada produk perimeter kita (VPN, firewall, hypervisor) yang sedang dieksploitasi? | Head of Platform, Lead SOC | Advisori vendor, KEV, peringatan BSSN atau CSIRT sektor, feed komersial |
| PIR-2 | Kelompok ransomware mana yang menyasar penyedia hosting di kawasan ini, dan TTP apa yang mereka pakai? | Lead SOC, threat hunter | Laporan vendor publik, ISAC, The DFIR Report |
| PIR-3 | Apakah ada data atau kredensial PT AN yang beredar di luar? | ISMS Manager | Layanan pemantauan kebocoran (sesuai ToS dan hukum) |
| PIR-4 | Tren regulasi dan ancaman apa yang perlu diketahui pimpinan per kuartal? | Direksi | Laporan strategis, advisori pemerintah |

PIR menjawab aktivitas pertama 5.7 (menetapkan tujuan) dan membuat setiap brief bisa diaudit terhadap pertanyaannya.

### 4.2 Kebijakan SLA kerentanan (cuplikan)

Kategori dievaluasi dari atas; kategori pertama yang kriterianya terpenuhi yang berlaku.

| Kategori | Kriteria | Tenggat tindakan |
|---|---|---|
| Darurat | Ada di KEV atau intel menunjukkan eksploitasi aktif, dan aset menghadap internet | 72 jam (patch atau mitigasi) |
| Tinggi | CVSS Base minimal 7.0 dan EPSS minimal 0,1, atau aset kritis | 14 hari |
| Sedang | CVSS Base 4.0-6.9, atau CVSS minimal 7.0 pada aset internal non-kritis dengan EPSS kurang dari 0,1 | 30 hari |
| Rendah | Sisanya | Siklus patch berikutnya (maks 90 hari) |

Tenggat yang tidak terpenuhi butuh pengecualian tertulis dengan kontrol kompensasi dan persetujuan risk owner.

### 4.3 Contoh keputusan prioritas

| CVE | Aset | Internet? | KEV | EPSS | CVSS Base | Kategori | Alasan |
|---|---|---|---|---|---|---|---|
| CVE-FIKTIF-01 | VPN appliance | Ya | Ya | 0,94 | 9.8 | Darurat | KEV dan menghadap internet |
| CVE-FIKTIF-02 | Hypervisor mgmt | Tidak (VPN) | Tidak | 0,32 | 8.1 | Tinggi | CVSS 8.1 dan EPSS 0,32; juga aset kritis |
| CVE-FIKTIF-03 | Server build internal | Tidak | Tidak | 0,02 | 9.1 | Sedang | CVSS tinggi, tetapi EPSS rendah dan aset internal non-kritis |
| CVE-FIKTIF-04 | Wiki dokumentasi internal | Tidak | Tidak | 0,04 | 5.3 | Sedang | CVSS 5.3 pada aset non-kritis |
| CVE-FIKTIF-05 | Laptop staf | Tidak | Ya | 0,71 | 7.8 | Tinggi | Di KEV tetapi tidak menghadap internet, jadi bukan Darurat; CVSS 7.8 dan EPSS 0,71 memenuhi Tinggi |

Uji CVE-FIKTIF-03: EPSS 0,02 dan aset non-kritis membuat Tinggi tidak terpenuhi. Tanpa kalimat kedua di kriteria Sedang, CVE dengan CVSS 9.1 ini jatuh ke Rendah ("sisanya") dengan tenggat 90 hari. Aturan "kategori pertama yang cocok" mencegah tumpang tindih, misalnya CVSS 5.0 di aset kritis yang memenuhi Tinggi sekaligus Sedang. Menguji kebijakan dengan contoh menemukan celah aturan.

Baris CVE-FIKTIF-05 bisa diperdebatkan: laptop tidak menghadap internet, tetapi berpindah jaringan. Apa pun keputusannya, alasannya harus tertulis.

### 4.4 Brief intel bulanan (kerangka)

```
TI-BRIEF 2026-09 (TLP:AMBER+STRICT, distribusi: internal PT AN saja)
1. Ringkasan untuk pimpinan (PIR-4): 3 kalimat
2. Kerentanan dieksploitasi yang relevan (PIR-1): CVE-FIKTIF-01 -> tiket PATCH-2231, selesai 2026-09-04
3. TTP kelompok ransomware relevan (PIR-2): 2 teknik baru -> rule DET-118, hunt HUNT-2026-07
4. Indikasi kebocoran (PIR-3): tidak ditemukan
5. Keputusan dan tindakan: risiko R-21 kemungkinan tetap 4 sampai patch diverifikasi
6. Advisori yang dinilai tidak relevan: 4 (produk tidak dipakai), dicatat di log intel
```

Bagian 5 dan 6 adalah bukti terkuat untuk 5.7, karena menunjukkan intel menghasilkan keputusan. Label mengikuti TLP 2.0 (FIRST, sejak Agustus 2022): RED hanya penerima yang disebut, AMBER organisasi penerima dan kliennya sebatas perlu tahu, AMBER+STRICT hanya organisasi penerima, GREEN komunitas tanpa kanal publik, CLEAR tanpa batas [S14]. Brief internal karena itu berlabel AMBER+STRICT.

## 5. Lab praktik

Latihan untuk organisasi fiktifmu. Simpan di `latihan/day12-<nama-org-fiktif>.md`.

1. Tulis 4-5 PIR, masing-masing dengan pengguna dan sumber utama.
2. Buat daftar minimal 6 sumber intel: nama, jenis (gratis atau berbayar), tingkat (strategic, tactical, operational), penilaian keandalan, dan label TLP default.
3. Tulis kebijakan SLA kerentanan seperti bagian 4.2. Uji dengan 6 kerentanan fiktif dan pastikan setiap kerentanan masuk tepat satu kategori; perbaiki kebijakan bila ada yang jatuh ke kategori yang tidak masuk akal.
4. Tulis brief intel bulanan dengan kerangka bagian 4.4. Minimal satu tindakan untuk 8.8, satu untuk 8.16, dan satu catatan advisori yang tidak relevan.
5. Tulis kuesioner 10 pertanyaan untuk penyedia SIEM cloud: notifikasi insiden, lokasi data, retensi, akses admin penyedia, hak audit, ketentuan keluar, dan praktik kerentanan.
6. Hubungkan ke lab:
   - bila Wazuh lab-mu mengaktifkan deteksi kerentanan, ambil daftar kerentanan untuk satu VM lab dan klasifikasikan dengan kebijakan langkah 3. Cek nama modul dan menu di versi Wazuh lab-mu;
   - bila tidak, buat inventaris perangkat lunak 2 VM lab secara manual (nama dan versi).
   Cocokkan dengan file KEV (CSV atau JSON) dari situs CISA.

**Hasil yang sebaiknya tersimpan:**
- PIR, daftar sumber, dan brief intel yang memuat keputusan dan tindakan, bukan hanya berita.
- Kebijakan SLA yang sudah diuji, termasuk aturan pengecualian dengan kontrol kompensasi dan persetujuan risk owner.
- Kuesioner pemasok yang mencakup ketentuan keluar (5.23), dan satu klasifikasi kerentanan dari VM lab.

**Variasi tantangan:** advisori baru menyebut eksploitasi aktif pada produk yang kamu pakai, tetapi patch baru tersedia 10 hari lagi. Tulis langkah lengkapnya: keputusan 5.7, mitigasi sementara 8.8, rule deteksi 8.16, perubahan kemungkinan di risk register, dan siapa yang menyetujui pengecualian SLA.

## 6. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| Feed intel masuk SIEM tetapi auditor tidak puas | Tidak ada bukti analisis dan keputusan | Brief berkala dengan bagian "keputusan dan tindakan" |
| Ribuan temuan scanner, tidak tahu mulai dari mana | Prioritas hanya berdasarkan CVSS | Tambahkan KEV, EPSS, paparan internet, dan kritikalitas aset |
| Kerentanan "Tinggi" terbuka berbulan-bulan | Tidak ada SLA atau pengecualian tidak dikelola | SLA tertulis, laporan umur kerentanan bulanan, pengecualian dengan tenggat |
| Tidak tahu versi perangkat lunak di server | Inventaris aset (5.9) lemah | Perbaiki inventaris dulu; 8.8 bergantung padanya |
| Skor CVSS satu CVE berbeda antar tool | Versi CVSS (3.1 vs 4.0) atau kelompok metrik berbeda | Cek label versi dan nomenklatur (CVSS-B, CVSS-BT) |
| Penyedia cloud menolak memberi informasi | Persyaratan tidak ada di kontrak | Masukkan klausul saat perpanjangan; minta laporan audit pihak ketiga |

## 7. Kesalahan umum dan jebakan

- Menyamakan "berlangganan feed" dengan memenuhi 5.7. Kontrol ini menuntut analisis dan tindakan.
- Membaca EPSS sebagai kepastian. EPSS adalah probabilitas, dan CVE dengan EPSS rendah tetap bisa dieksploitasi pada targetmu.
- Menganggap BOD CISA mengikat organisasi di luar lembaga federal AS, atau masih menyebut BOD 22-01 berlaku.
- Mengabaikan kerentanan layanan cloud sebagai "tanggung jawab penyedia" tanpa pembagian tanggung jawab tertulis (5.23, 27017).
- Memberi label TLP:AMBER pada dokumen khusus internal; AMBER masih boleh sampai ke klien penerima.

## 8. Catatan terkini

- BOD 26-04 (10 Juni 2026) mencabut BOD 22-01 dan 19-02 [S11]; halaman KEV kini menandai kebutuhan forensic triage per entri dan berisi 1.739 entri per 2026-10-10 [S8].
- EPSS v4 (Maret 2025) adalah model terakhir yang tercatat di sumber publik per Oktober 2026 [S10]; cek baris komentar file CSV EPSS.
- ISO/IEC 27017:2026 (edisi 2) terbit 27 Juli 2026 dan diselaraskan dengan 27002:2022 [S5].

## 9. Cheat sheet

```
5.7 TI (27002): strategic (lanskap, pimpinan) | tactical (TTP pelaku) | operational (serangan tertentu, IOC)
    ciri: relevan, wawasan, kontekstual, bisa ditindaklanjuti
    alur: tujuan/PIR -> pilih sumber -> kumpulkan -> proses -> analisis -> komunikasikan -> TINDAKAN TERCATAT
    bukti: PIR, daftar sumber, brief, keputusan (termasuk "tidak relevan")
8.8 Kerentanan: inventaris (5.9) -> peran -> identifikasi -> evaluasi -> tindakan (patch/workaround/filter/monitor) -> rekaman
    cloud: praktik penyedia di kontrak
Prioritas: KEV (sudah dieksploitasi) > EPSS (peluang 30 hari) + CVSS v4 (keparahan) + paparan + kritikalitas aset
CVSS v4.0 (Nov 2023): Base | Threat (eks Temporal) | Environmental | Supplemental (tidak ubah skor) ; CVSS-B/BT/BE/BTE
BOD 26-04 (Jun 2026, cabut 22-01 & 19-02): exposure | KEV | automatable | partial/total control ; tingkat teratas 3 hari + forensic triage
Pemasok: 5.19 hubungan | 5.20 kontrak | 5.21 rantai pasok TIK | 5.22 pantau & tinjau | 5.23 cloud (+ exit)
Standar: 27017:2026 ed.2 (cloud) | 27036-1:2021, -3:2023 (pemasok) | TLP 2.0: RED, AMBER, AMBER+STRICT, GREEN, CLEAR
```

## 10. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | ISMS.online: ISO 27002 control 5.7 threat intelligence | https://isms.online/iso-27002/control-5-7-threat-intelligence | sekunder (vendor) | diakses 2026-10-10 | Sedang. Tujuan dan pemakaian intel; label tingkat terbalik dibanding S6 |
| S2 | ISMS.online: ISO 27002 control 8.8 management of technical vulnerabilities | https://www.isms.online/iso-27002/control-8-8-management-of-technical-vulnerabilities/ | sekunder (vendor) | 2025-07-25; diakses 2026-10-08 | Sedang. Alur 8.8 dari inventaris sampai rekaman |
| S3 | FIRST: CVSS v4.0 | https://www.first.org/cvss/v4-0/ | primer (pemilik standar) | diakses 2026-10-10 | Tinggi. Kelompok metrik, nomenklatur, metrik Supplemental |
| S4 | FIRST: Exploit Prediction Scoring System (halaman utama dan FAQ) | https://www.first.org/epss/ | primer (pemilik model) | diakses 2026-10-10 | Tinggi. Jendela 30 hari, pembaruan harian, model tercantum di CSV |
| S5 | ISO committee: ISO/IEC 27017:2026 | https://committee.iso.org/standard/27017 | primer (katalog ISO) | 2026-07-27; diakses 2026-10-10 | Tinggi |
| S6 | GRC Solutions: Threat intelligence, ISO 27001:2022 control 5.7 explained | https://grcsolutions.io/threat-intelligence-iso-270012022-control-5-7-explained/ | sekunder (konsultan) | diakses 2026-10-10 | Sedang. Mengutip rumusan 27002 untuk tiga tingkat, ciri, dan aktivitas |
| S7 | Rapid7: ISO 27002 emphasizes need for threat intelligence | https://www.rapid7.com/blog/post/2022/07/25/iso-27002-emphasizes-need-for-threat-intelligence/ | sekunder (vendor) | 2022-07-25; diakses 2026-10-10 | Sedang. Contoh ringkasan dengan label tactical/operational terbalik |
| S8 | CISA: Known Exploited Vulnerabilities Catalog | https://www.cisa.gov/known-exploited-vulnerabilities-catalog | primer (lembaga pemerintah) | diakses 2026-10-10 | Tinggi. Jumlah entri dan rujukan BOD 26-04 per tanggal akses |
| S9 | FIRST: CVSS v4.0 Specification Document | https://www.first.org/cvss/v4.0/specification-document | primer (pemilik standar) | 2023-11-01, revisi dokumen v1.2 2024-06-18; diakses 2026-10-10 | Tinggi. Tanggal rilis |
| S10 | Empirical Security (Jay Jacobs): Introducing EPSS version 4 | https://research.empiricalsecurity.com/research/introducing-epss-version-4 | sekunder (penulis inti EPSS) | Maret 2025; diakses 2026-10-10 | Sedang-tinggi. Perubahan data model v4 |
| S11 | CISA: BOD 26-04 Prioritizing Security Updates Based on Risk | https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk | primer (lembaga pemerintah) | 2026-06-10; diakses 2026-10-10 | Tinggi. Cakupan, empat faktor, pencabutan BOD lama |
| S12 | ISO27k: ISO/IEC 27036-1 | https://www.iso27001security.com/html/27036 | sekunder (komentar praktisi) | diperbarui 2026-08-19; diakses 2026-10-10 | Sedang. Edisi 2 bagian 1 (2021) |
| S13 | ISO committee: ISO/IEC 27036-3:2023 | https://committee.iso.org/standard/82890.html | primer (katalog ISO) | 2023-06-13; diakses 2026-10-10 | Tinggi |
| S14 | FIRST: Traffic Light Protocol (TLP) | https://www.first.org/tlp/ | primer (pemilik standar) | TLP 2.0 berlaku sejak Agustus 2022; diakses 2026-10-10 | Tinggi. Definisi lima label |

**Catatan sumber:** isi 5.7, 8.8, dan 5.19-5.23 berasal dari ringkasan sekunder yang tidak sepakat soal label tactical dan operational; bagian 3.1 mengikuti sumber yang mengutip rumusan 27002. Tenggat BOD 26-04 selain 3 hari berasal dari ringkasan sekunder. Edisi 27036-2 dan 27036-4 belum dicek di katalog ISO.
