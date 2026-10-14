---
day: 29
title: 'Organisasi SOC: peran Analyst, Engineer, Architect, tier, dan fungsi pendukung'
researched_on: 2026-10-10
versions_checked: Splunk Tech Brief "Building a SOC with Splunk" (2017); MITRE "11 Strategies of a World-Class Cybersecurity Operations Center" (Mar 2022); NICE Workforce Framework Components v2.0.0 (Mar 2025); SANS 2026 SOC Survey (liputan 17 Jun 2026); ES 8.7
---

# Day 29: Organisasi SOC dan peran Analyst, Engineer, Architect

Cakupan: merangkum organisasi SOC tipikal dan tugas peran Analyst, Engineer, dan Architect.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- menjelaskan SOC sebagai kombinasi people, process, technology, dan kenapa ketiganya harus seimbang.
- membedakan tugas Analyst (tier 1-3), Engineer, dan Architect, termasuk dalam konteks Splunk.
- menjelaskan model tiered vs tierless dan fungsi pendukung (CTI, hunting, forensik, detection engineering).
- memetakan pengalamanmu sendiri ke peran-peran tersebut untuk interview.

## 2. Konteks singkat

Topik ini konseptual: intinya memetakan tugas ke peran. Kamu sudah bekerja di SOC dan forensik, jadi materi ini sebagian besar memberi kosakata dan kerangka. Nilai tambahnya ada di interview: kamu bisa menjelaskan posisimu dan arah pengembanganmu (mis. dari analyst ke detection engineer) dengan bahasa yang dipahami manajer perekrut.

## 3. Konsep inti

### 3.1 People, process, technology

Tech brief Splunk tentang membangun SOC menekankan bahwa SOC butuh investasi pada process, people, dan technology [S1]:
- Process dimulai dari threat modeling: ancaman apa yang dipedulikan organisasi, seperti apa jejaknya di data, bagaimana mendeteksi atau memblokirnya, dan playbook apa untuk tiap jenis ancaman [S1].
- **People:** personel beragam dengan jalur promosi yang jelas antar tier dan pelatihan berkelanjutan [S1].
- **Technology:** platform analitik keamanan yang mengindeks data mesin dari berbagai sumber dan memperkayanya dengan konteks (AD, database aset, threat feed). Ditambah ticketing dan alat IR lanjutan (packet capture, disk forensics, reverse engineering) untuk tier atas [S1].

MITRE "11 Strategies" (edisi 2022) merumuskan strategi yang sejalan [S2]:
- tahu apa yang dilindungi dan kenapa;
- beri SOC otoritas;
- bangun struktur SOC sesuai kebutuhan organisasi (tiered vs tierless, terpusat vs terdistribusi, outsourcing);
- rekrut dan kembangkan staf berkualitas;
- prioritaskan respons insiden;
- CTI;
- pilih dan kumpulkan data yang tepat;
- alat yang mendukung alur kerja analyst;
- komunikasi dan kolaborasi;
- ukur kinerja;
- perluas fungsi SOC.

### 3.2 Model tier analyst

Contoh tiga tier dari Splunk [S1]:

| Tier | Fokus | Contoh tugas |
|---|---|---|
| Tier 1 | Monitoring dan triage | Memantau alert, membuka tiket, menutup false positive, investigasi dan mitigasi dasar |
| Tier 2 | Investigasi mendalam | Menginvestigasi eskalasi, mitigasi, merekomendasikan perubahan |
| Tier 3 | Investigasi lanjutan dan proaktif | Investigasi lanjutan, pencegahan, threat hunting, forensik, counter-intelligence, reverse engineering malware |

Alert datang dari platform analitik, help desk, atau departemen TI lain. Kasus yang tidak terselesaikan dieskalasi ke tier berikutnya [S1].

**Tierless/kolaboratif:** MITRE membahas pilihan antara model tier dan tanpa tier sesuai kebutuhan organisasi [S2]. Model tanpa tier biasanya mengandalkan otomasi (SOAR) untuk triage awal, dan analyst menangani kasus end-to-end. Tidak ada satu model yang selalu benar.

### 3.3 Analyst, Engineer, Architect

Contoh struktur personel Splunk: SOC Director membawahi SOC Architect, Tier 1/2/3 Analyst, Forensics Specialist, dan Malware Engineer [S1]. Pembedaan yang umum dipakai:

| Peran | Pertanyaan utama | Tugas khas | Dalam konteks Splunk/ES |
|---|---|---|---|
| Analyst | "Apa yang terjadi, dan apa yang harus dilakukan?" | Triage, investigasi, eskalasi, disposisi, dokumentasi kasus, hunting (tier atas) | Bekerja di analyst queue (Incident Review di ES 7), menjalankan search/pivot, memakai dashboard investigasi, menulis catatan kasus |
| Engineer | "Apakah tools dan data bekerja dengan benar?" | Onboarding data, parsing/normalisasi, membuat dan tuning detection, integrasi, otomasi, kesehatan platform | TA/CIM (Day 23), akselerasi (Day 26), detection dan filter macro (Day 45/36), A&I, adaptive response dan SOAR (Day 41-42), skipped searches |
| Architect | "Bagaimana sistem keamanan ini dirancang agar memenuhi kebutuhan sekarang dan nanti?" | Desain arsitektur, skala dan ketersediaan, strategi data dan retensi, pemilihan teknologi, standar, roadmap | Topologi (indexer/search head cluster), kapasitas, strategi index dan data model, integrasi lintas produk, kebijakan retensi |

Sumber praktisi (2020, lebih dari 3 tahun) membedakan engineer/architect sebagai pihak yang bertanggung jawab atas arsitektur keamanan secara keseluruhan dan memastikan keamanan menjadi bagian siklus pengembangan, sedangkan analyst berfokus pada mengidentifikasi kerentanan dan menilai ancaman yang ada [S3].

Garis batas di dunia nyata kabur. Di SOC kecil, satu orang bisa menjadi analyst dan engineer sekaligus. Pegang orientasinya: Analyst = kejadian, Engineer = sistem dan konten, Architect = desain.

### 3.4 Fungsi pendukung

- **Threat intelligence (CTI):** memberi konteks dan prioritas (Day 30).
- **Threat hunting:** proaktif; sering tier 3 atau tim khusus (Day 38-39).
- **Forensik dan malware analysis:** dukungan IR mendalam [S1].
- **Detection engineering:** peran yang makin dikenal sebagai fungsi tersendiri. Survei SANS bersama Anvilogic 2026 tentang detection engineering menunjukkan banyak praktisi merasa hanya mampu mengikuti atau tertinggal dari perkembangan ancaman [S7] `[sekunder]`.
- **SOC manager/director:** operasi, staf, metrik, dan komunikasi ke manajemen [S1][S3].

### 3.5 Kerangka tenaga kerja: NICE

NICE Workforce Framework for Cybersecurity (NIST) memakai Work Role Categories, Work Roles, Competency Areas, dan pernyataan Task, Knowledge, Skill (TKS). Pembaruan komponen v2.0.0 dirilis Maret 2025 [S4]. Work role seperti *Defensive Cybersecurity* dan *Incident Response* berada di kategori perlindungan dan pertahanan [S4], cek nama kategori dan work role persis di v2.0.0.

Kerangka ini berguna untuk menulis CV dan rencana pengembangan karier, karena tugasmu bisa dipetakan ke TKS yang baku.

### 3.6 Keadaan SOC terkini (data)

SANS 2026 SOC Survey (444 praktisi + 69 CISO/eksekutif; liputan 17 Jun 2026) [S5]:
- SIEM adalah keterampilan yang paling dicari saat merekrut, hampir dua kali lipat EDR.
- 79% memakai alat AI/ML, tetapi hanya 36% yang sudah memasukkannya ke alur kerja SOC yang terdefinisi.
- Ada kesenjangan persepsi soal staffing: 59% pemimpin vs 32% praktisi merasa manajemen memperhatikan kebutuhan SOC.
- Kurang dari 45% memantau aset OT/IoT lewat SOC.

Penilaian untukmu: kombinasi kuat SIEM (Splunk) + forensik + kemampuan engineering konten adalah profil yang dicari pasar.

### 3.7 Satu kasus dilihat dari tiga peran

Contoh fiktif berikut menunjukkan bagaimana satu kejadian berpindah tangan. Detection password spraying memunculkan finding untuk host `WS-FIN-07` pada pukul 02.10.

- **Analyst (tier 1):** membuka finding, melihat 40 akun gagal login dari satu `src` dalam 6 menit, lalu memeriksa apakah ada login berhasil setelahnya. Ada satu login berhasil ke akun `svc-backup`. Kasus dieskalasi ke tier 2 dengan catatan timeline dan query yang dipakai.
- **Analyst (tier 2):** memastikan `WS-FIN-07` menjalankan proses tidak biasa setelah login itu, mengisolasi host lewat EDR sesuai playbook, dan meminta reset kredensial `svc-backup`. Disposisinya true positive.
- **Engineer:** saat review pasca-insiden, menemukan bahwa finding baru muncul 25 menit setelah aktivitas dimulai karena search terjadwal sering skipped (bagian 4.1). Ia memindahkan jadwal search, menambah filter untuk akun layanan yang memang berisik, dan menambah detection kedua untuk login berhasil setelah rangkaian gagal.
- **Architect:** melihat bahwa skipped search terjadi karena search head ES kehabisan slot konkurensi pada jam backup. Rekomendasinya: kapasitas scheduler ditambah dan akselerasi data model dipindah ke jam yang lebih sepi, masuk roadmap kuartal berikutnya.

Pola ini yang perlu kamu tunjukkan di interview: analyst menutup kejadian, engineer memperbaiki konten dan data yang membuat kejadian terlambat terlihat, architect memperbaiki desain yang membuat masalah itu bisa terjadi.

### 3.8 Enterprise vs ES

Peran SOC tidak bergantung produk. Di ES, pemisahan peran terlihat dari role dan capability (mis. role analyst ES vs admin ES), cek nama role bawaan ES 8.x (`ess_analyst`, `ess_admin`, dll.) di dokumentasi ES 8.7.

## 4. Contoh SPL dan langkah di ES

> Keluaran berlabel ilustrasi. Query ini menggambarkan jenis pertanyaan yang diajukan tiap peran.

### 4.1 Pertanyaan Engineer: apakah detection berjalan sehat?

```
index=_internal sourcetype=scheduler (status=skipped OR status=continued) earliest=-24h
| stats count BY app savedsearch_name status reason
| sort - count
```

- `sourcetype=scheduler` di `_internal` mencatat eksekusi scheduled search.
- `status=skipped` berarti search tidak dijalankan, mis. karena batas konkurensi. Detection yang terlewat berarti buta.
- **Cara membaca hasil:** search ES/ESCU yang sering skipped perlu dioptimalkan (Day 14) atau dijadwal ulang. Ini tugas engineer.
- Cek nilai `status` dan field `reason` di versi-mu, serta hak akses ke `_internal`.

### 4.2 Pertanyaan Analyst lead / manager: beban antrean

ES 7.x menyimpan notable di index `notable` dan menyediakan macro `` `notable` ``:

```
`notable`
| stats count BY status_label owner urgency
| sort - count
```

- Menunjukkan distribusi notable per status, pemilik, dan urgensi. Dipakai untuk menyeimbangkan beban tier.
- Cek di ES 8.x: finding dan investigation dikelola di analyst queue (Mission Control). Index, macro, dan field-nya bisa berbeda (Day 31, 32, dan 34).

### 4.3 Pertanyaan Architect: pertumbuhan data dan kapasitas

```
index=_internal source=*license_usage.log* type=Usage earliest=-30d
| eval GB=b/1024/1024/1024
| timechart span=1d sum(GB) AS daily_GB BY idx limit=10
```

- Tren ingest per index dari log lisensi. Dasar perencanaan kapasitas, retensi, dan biaya.
- Cek field (`b`, `idx`) dan lokasi log lisensi di deployment-mu (biasanya di license manager).

### 4.4 Di ES (generik)

- **Analyst:** analyst queue, investigation, catatan (note), disposisi.
- **Engineer:** content management, Detection Studio (Day 27), konfigurasi A&I dan data model.
- **Architect:** desain deployment ES (search head khusus, kapasitas scheduler, akselerasi). Lantern menyebut ES sebagai pemroses batch yang berat (Day 25 [S6]).

## 5. Lab praktik

1. Buat tabel 3 kolom (Analyst / Engineer / Architect). Isi masing-masing dengan 5 tugas yang pernah kamu kerjakan (disamarkan, tanpa data kerja).
2. Petakan setiap tugas ke work role NICE yang paling dekat [S4], cek nama work role.
3. Jalankan bagian 4.1 di Splunk lab. Bila ada search yang skipped, jelaskan penyebab dan perbaikannya.
4. Jalankan bagian 4.3 (bila punya akses log lisensi di lab). Proyeksikan kebutuhan disk 90 hari.
5. Tulis "elevator pitch" 60 detik untuk interview: posisimu sekarang, peran target (mis. detection engineer), dan bukti dari portofolio dari catatan ini.

**Hasil yang sebaiknya tersimpan:**
- Tabel tugas per peran (15 tugas).
- Pemetaan ke NICE.
- Hasil bagian 4.1 ditafsirkan.
- Elevator pitch tertulis.

**Variasi tantangan:** rancang struktur SOC untuk organisasi fiktif berukuran 800 karyawan dengan 6 FTE keamanan. Pilih tiered atau tierless, jam operasi (8x5 vs 24x7, lihat tech brief Splunk [S1]), apa yang di-outsource, dan alasannya.

## 6. Troubleshooting (konseptual)

| Gejala di organisasi | Kemungkinan penyebab | Perbaikan |
|---|---|---|
| Tier 1 kewalahan, eskalasi berkualitas rendah | Terlalu banyak alert berisik; playbook tidak jelas | Tuning detection (engineer), RBA (Day 35), otomasi (SOAR) |
| Detection "ada" tapi tidak pernah fire | Tidak ada pemilik engineering untuk data/konten | Tetapkan peran engineer dan metrik kesehatan (Detection Studio) |
| Platform lambat, search terlewat | Arsitektur tidak mengikuti pertumbuhan | Perencanaan kapasitas (architect) |
| Analyst stagnan | Tidak ada jalur promosi/pelatihan | Jalur karier antar tier [S1] |
| Kesenjangan persepsi manajemen-SOC | Komunikasi dan metrik lemah | Metrik kinerja (Day 34) [S2][S5] |

## 7. Kesalahan umum dan jebakan

- Menyamakan "engineer" dengan "analyst senior". Engineer berorientasi sistem dan konten, bukan kasus.
- Menganggap model tier selalu benar. MITRE menekankan struktur sesuai kebutuhan [S2].
- Mengabaikan proses. Teknologi tanpa playbook dan threat model menghasilkan noise [S1].
- Memakai sumber lama tanpa konteks. Tech brief Splunk (2017) dan artikel TechTarget (2020) masih berguna untuk konsep, tetapi produk dan istilahnya sudah berubah (ES 8).
- `[sekunder]` Data tren di Day ini berasal dari liputan survei SANS [S5][S7], bukan dari laporan lengkapnya. Angka persentase sebaiknya dicocokkan dengan laporan asli sebelum dikutip.

## 8. Catatan terkini

- **SANS 2026 SOC Survey (Jun 2026):** SIEM adalah skill paling dicari; adopsi AI tinggi tetapi integrasi workflow rendah [S5].
- NICE Framework Components v2.0.0 (Mar 2025) [S4].
- ES 8.6/8.7 memperkenalkan agen AI (mis. "AI SOC Analyst"), yang berpotensi menggeser sebagian tugas triage tier 1, cek di release notes (Day 45).
- MITRE "11 Strategies" edisi 2022 tetap menjadi rujukan desain SOC [S2].

## 9. Cheat sheet

```
SOC = People + Process + Technology  (process dimulai dari threat modeling)
TIER  T1 monitor/triage/tutup FP/eskalasi | T2 investigasi mendalam/mitigasi | T3 investigasi lanjut, hunting, forensik, RE
PERAN Analyst = KEJADIAN (triage, investigasi, disposisi, hunting)
      Engineer = SISTEM & KONTEN (onboarding data, TA/CIM, detection & tuning, integrasi, otomasi, kesehatan)
      Architect = DESAIN (topologi, skala, strategi data/retensi, pemilihan teknologi, roadmap)
PENDUKUNG CTI | hunting | forensik/malware | detection engineering | SOC manager/director
MODEL tiered vs tierless ; terpusat vs terdistribusi ; 8x5 vs 24x7 ; outsourcing (MITRE 11 Strategies)
NICE  Work Role Categories > Work Roles > Competency Areas > TKS (v2.0.0, Mar 2025)
```

## 10. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Splunk Tech Brief: Building a SOC with Splunk | https://www.splunk.com/en_us/pdfs/tech-brief/building-a-soc-with-splunk-tech-brief.pdf | primer (vendor) | 2017 (>3 tahun); diakses 2026-10-07 | Tinggi untuk konsep tier/peran; contoh produk usang |
| S2 | MITRE: 11 Strategies of a World-Class Cybersecurity Operations Center (rilis pers) | https://www.mitre.org/news-insights/news-release/mitre-publishes-11-strategies-world-class-cybersecurity-operations | primer | 2022-03-29 | Tinggi untuk daftar strategi |
| S3 | TechTarget: 5 key enterprise SOC team roles and responsibilities | https://techtarget.com/searchsecurity/tip/5-key-enterprise-SOC-roles-and-responsibilities | sekunder | 2020-09-23 (>3 tahun); diakses 2026-10-07 | Sedang |
| S4 | NIST: NICE Framework Components v2.0.0 | https://www.nist.gov/document/nice-framework-components-poster-march-2025 | primer | 2025-03 | Tinggi untuk struktur; nama work role perlu dicek |
| S5 | Infosecurity Magazine: Staffing is top SOC challenge even as AI proliferates, says SANS (SANS 2026 SOC Survey) | https://www.infosecurity-magazine.com/news/staffing-top-soc-challenge-ai/ | sekunder | 2026-06-17; diakses 2026-10-07 | Sedang-tinggi |
| S6 | SANS Blueprint podcast: Strategy 3: Build a SOC structure | https://sans.org/podcasts/blueprint/strategy-3-build-a-soc-structure-to-match-your-organizational-needs-41 | sekunder | tanggal tidak tercatat | Sedang |
| S7 | SANS x Anvilogic: State of Detection Engineering 2026 | https://www.anvilogic.com/report/state-of-detection-engineering | sekunder | 2026 | Sedang |

**Catatan sumber:** daftar 11 strategi MITRE [S2] dirujuk dari rilis persnya; uraian tiap strategi ada di buku lengkapnya. Nama role bawaan ES 8.x dan struktur index notable/finding di ES 8 belum terkonfirmasi dokumentasi, jadi cek di instance ES-mu. Angka survei SANS [S5][S7] berasal dari liputan, bukan laporan asli. Kasus di bagian 3.7 fiktif.
