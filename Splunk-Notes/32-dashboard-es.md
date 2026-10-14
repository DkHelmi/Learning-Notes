---
day: 32
title: Dashboard bawaan ES dan informasi dasarnya
researched_on: 2026-10-10
versions_checked: 'Splunk ES 8.7 User Guide: Analytics (Executive summary, Security posture, SOC operations; daftar dashboard Access/Endpoint/Network/Asset and identity/Threat intelligence/Web intelligence/Audit/Risk analysis/Predictive analytics); ES 7.3 dashboard reference (pembanding)'
---

# Day 32: Dashboard bawaan ES

Cakupan: mengidentifikasi dashboard bawaan umum di Enterprise Security dan informasi dasar yang dimuatnya.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- menyebut dashboard bawaan ES 8.7 dan pertanyaan yang dijawab masing-masing.
- membaca panel kunci Security posture, Executive summary, dan SOC operations, termasuk metrik dan disposisi (Day 34).
- memilih dashboard yang tepat untuk sebuah tugas: triage, investigasi domain, pelaporan manajemen, audit platform.
- memahami bahwa urgensi finding dihitung dari gabungan prioritas aset dan severity detection (Day 26).

## 2. Konteks singkat

Dashboard ES bukan hiasan. Masing-masing dirancang untuk audiens dan pertanyaan tertentu:
- manajer melihat tren dan metrik;
- analyst melihat finding per domain;
- engineer melihat kesehatan data dan konten.

Pertanyaan yang paling sering muncul di pekerjaan adalah "informasi X ada di dashboard mana". Mengetahui jawabannya menghemat waktu triage, dan mengetahui data model di balik setiap dashboard menjelaskan kenapa sebuah panel kosong.

## 3. Konsep inti

### 3.1 Peta dashboard ES 8.7

Bagian Analytics di dokumentasi ES 8.7 mencakup [S1][S2]:

| Dashboard | Audiens | Pertanyaan yang dijawab |
|---|---|---|
| Security posture | Analyst, SOC lead | Apa yang terjadi 24 jam terakhir? Finding per domain, urgensi, tren, top detection, top sumber |
| Executive summary | Manajer/CISO | Bagaimana kinerja SOC dan tren risiko? MTT triage/resolution, investigasi, finding per urgensi/domain, risk notable vs notable |
| SOC operations | SOC manager | Seberapa efisien alur kerja? Metrik, beban/penugasan, close rate per analyst, disposisi |
| Risk analysis | Analyst, detection engineer | Entity mana berisiko tinggi, dan dari detection apa? (Day 35) |
| Access dashboards | Analyst | Aktivitas autentikasi/akses (domain Access) |
| Endpoint dashboards | Analyst | Malware, proses, perubahan sistem (domain Endpoint) |
| Network dashboards | Analyst | Trafik, IDS, port/protokol (domain Network) |
| Asset and identity dashboards | Analyst | Konteks aset/identitas, investigasi per entity (Day 26) |
| Threat intelligence dashboards | Analyst/CTI | Aktivitas yang cocok dengan intel (Day 30) |
| Web intelligence dashboards | Analyst | Aktivitas web/proxy: kategori HTTP, user-agent, domain baru, ukuran trafik, panjang URL (bagian 3.7) |
| Audit dashboards | Engineer/admin | Kesehatan platform dan konten: forwarder, indexing, view, suppression, threat intel, adaptive response (bagian 3.7) |
| Predictive analytics | Analyst lanjutan | Analitik prediktif/anomali atas data model, cek isi di 8.7 |

Antrean kerja analyst sendiri (finding, investigation) berada di Mission Control > analyst queue, bukan di Analytics (Day 34/31).

### 3.2 Security posture

Panel [S2]:
1. **Key indicators**: jumlah finding per security domain dalam 24 jam terakhir.
2. **Findings by urgency**: urgensi dihitung dari prioritas aset dan severity detection. Panel ini terhubung ke analyst queue yang terfilter.
3. **Findings over time**: timeline per domain, dengan klik yang membuka analyst queue terfilter.
4. **Top findings**: nama detection paling sering, dengan sparkline.
5. **Top findings sources**: 10 teratas berdasarkan `src`, dengan hitungan per detection dan domain serta sparkline.

**Cara membaca:** lonjakan di satu domain + sumber yang sama di top sources adalah titik awal triage. Urgensi bergantung pada prioritas aset. Jika data A&I kosong, urgensi menjadi tidak informatif (Day 26).

### 3.3 Executive summary

Panel [S1]:
- **KPI:** Mean time to triage, Mean time to resolution (dengan tren vs periode sebelumnya), Investigations created.
- **Findings:** distribusi per urgensi (Critical, High, Medium, Low, Information, Unknown), per domain, finding yang belum di-triage per domain dan sumber, top 10 dan rare finding sources.
- **Risk analysis:** risk notable vs notable standar, event risiko yang berkontribusi ke risk notable, dan jenis event risiko yang tidak menghasilkan risk notable. Panel terakhir ini berguna untuk menilai apakah RBA disetel dengan baik.
- **Lainnya:** jumlah adaptive response yang dipicu, sumber dengan aksi notable vs aksi risk aktif, correlation search aktif vs nonaktif.
- **Capability:** KPI Investigations created butuh `manage_all_investigations`. Secara default hanya role `admin` dan `ess_admin` yang memilikinya [S1].

Perhatikan bahwa dokumentasi 8.7 di dashboard ini masih memakai istilah lama (*notable*, *risk notable*, *correlation search*) berdampingan dengan istilah baru. Jangan heran bila menu dan dokumentasi tidak konsisten.

### 3.4 SOC operations

Panel [S3]:
- **Key metrics:** Mean time to triage (rata-rata menit untuk memprioritaskan), Mean time to resolution (rata-rata menit sampai status akhir), Investigations created.
- **Workflow:** notable assigned vs unassigned, notable dalam status akhir, close rate per analyst.
- **Dispositions:** disposisi dari waktu ke waktu (FP vs TP), serta sumber yang menghasilkan disposisi tertentu (*incorrect logic*, *inaccurate data*, *suspicious activity*, *suspicious but expected*). Ini menghubungkan Day 34 langsung ke dashboard.

**Cara membaca:** detection yang dominan di panel "incorrect logic" adalah daftar kerja detection engineer. Yang dominan di "inaccurate data" adalah daftar kerja data engineer.

### 3.5 Domain dashboards dan data model

Dashboard domain (Access, Endpoint, Network, Web) dibangun di atas data model CIM (Day 23/24). Jika data model kosong atau tidak terakselerasi, dashboard kosong atau lambat. Itulah alasan engineer memantau Audit dashboards (status akselerasi, ukuran, kesehatan konten).

### 3.6 Enterprise vs ES

Dashboard di atas khusus ES. Di Splunk Enterprise, kamu membangun dashboard sendiri (Dashboard Studio/Classic) dari data model/CIM, dan Monitoring Console menyediakan kesehatan platform (Day 14).

### 3.7 Sub-dashboard domain dan data model di baliknya

Kelompok dashboard domain berisi banyak sub-dashboard. Tabel referensi ES 8.7 memetakan setiap sub-dashboard ke data model CIM yang dibacanya [S5]. Peta ini adalah alat diagnosis paling berguna: panel kosong hampir selalu berarti data model di kolom kanan kosong, belum terakselerasi, atau field-nya tidak ter-CIM.

| Kelompok | Sub-dashboard (ES 8.7) | Data model utama |
|---|---|---|
| Access | Access Center, Access Tracker, Access Anomalies, Default Account Activity, Account Management | Authentication; Change untuk Account Management |
| Endpoint | Malware Center, Malware Operations, System Center, Time Center, Endpoint Changes, Update Center | Malware; Performance dan Endpoint; Change; Updates |
| Network | Traffic Center, Protocol Center, Port & Protocol Tracker, Intrusion Center, Vulnerability Center, Vulnerability Operations, Network Changes, DNS Activity, Email Activity, Web Center | Network Traffic; Intrusion Detection; Vulnerabilities; Change; Network Resolution (DNS); Email; Web |
| Asset and identity | Asset Center, Identity Center, Session Center, Asset Investigator, Identity Investigator, User Activity | Assets and Identities; Network Sessions dan Certificates; User Activity memakai Risk Analysis, Web, Email, Authentication |
| Threat intelligence | Threat Activity, Threat Overview | Intrusion Detection, Network Traffic, Web (Threat Activity) |
| Web intelligence | HTTP Category Analysis, HTTP User Agent Analysis, New Domain Analysis, URL Length Analysis, Traffic Size Analysis | Web; Network Traffic untuk ukuran trafik |
| Audit | Forwarder Audit, Indexing Audit, View Audit, Incident Review Audit, Suppression Audit, Threat Intelligence Audit, Managed Lookups Audit, Adaptive Response Action Center | Sebagian besar tidak memakai data model; View Audit dan Adaptive Response Action Center memakai Splunk Audit Logs |
| Lainnya | Risk Analysis, Investigation Workbench, Data Protection | Risk Analysis; Workbench membaca hampir semua data model |

Cara memakainya saat sebuah panel kosong:

1. Cari sub-dashboard di tabel dan catat data model-nya.
2. Jalankan `| tstats summariesonly=false count from datamodel=<DM> where earliest=-24h` untuk memastikan data model punya data sama sekali.
3. Bila hasilnya ada tetapi panel tetap kosong, ulangi dengan `summariesonly=true`. Selisih besar berarti akselerasi belum selesai atau rentangnya di luar jendela summary (Day 26).
4. Bila `summariesonly=false` pun nol, masalahnya di onboarding atau tag CIM (Day 23), bukan di dashboard.

Beberapa sub-dashboard Audit tidak memakai data model sama sekali dan membaca index internal, lookup, atau REST. Panel Audit yang kosong biasanya soal izin role terhadap index internal, bukan soal CIM.

## 4. Contoh SPL dan langkah di ES

> Keluaran berlabel ilustrasi. Query membantu memahami sumber data panel. Panel aslinya mungkin memakai macro/data model ES berbeda, cek dengan "Open in Search" pada panel.

### 4.1 Membongkar panel: lihat SPL di balik panel

Di setiap panel ES, gunakan menu panel (mis. "Open in Search") untuk melihat SPL aslinya, cek tersedia di ES 8.7. Kebiasaan ini membantu:
- memahami sumber data (notable/finding, risk, data model);
- membuat varian panel untuk kebutuhan tim.

### 4.2 Meniru "Findings by urgency" (ES 7 pola)

```
`notable` earliest=-24h
| stats count BY urgency security_domain
| xyseries security_domain urgency count
```

- `security_domain` (access, endpoint, network, threat, identity, audit) dan `urgency` adalah field notable klasik, cek di ES 8.

### 4.3 Meniru "Top findings sources"

```
`notable` earliest=-24h
| stats count dc(rule_name) AS detections values(security_domain) AS domains BY src
| sort - count | head 10
```

### 4.4 Meniru panel SOC operations: close rate per analyst

```
`notable` earliest=-30d
| eval closed=if(in(status_label,"Resolved","Closed"),1,0)
| stats count sum(closed) AS closed BY owner
| eval close_rate=round(closed/count*100,1)
| sort - count
```

- Gunakan dengan hati-hati. Close rate tinggi tanpa memperhatikan kualitas bisa mendorong penutupan prematur (Day 34).

### 4.5 Lab tanpa ES: dashboard "security posture mini"

Buat dashboard Splunk (Dashboard Studio) dengan 4 panel dari data lab:
1. Jumlah alert per "domain" (Authentication, Endpoint, Network) dari `tstats` data model (Day 24).
2. Alert per jam (timechart).
3. Top 10 `src` dari Network_Traffic yang diblokir.
4. Top detection dari index alert lab (Day 31 lab).

### 4.6 Contoh membaca Security posture saat triage pagi

Skenario fiktif: Senin pukul 08.00, analyst membuka Security posture dengan rentang 24 jam. Keluaran ilustrasi dari panel-panelnya:

```
Key indicators     Access 412 (+380%)  Endpoint 37 (+5%)  Network 120 (-10%)  Threat 6 (+0%)
Findings by urgency  critical 2  high 31  medium 390  low 152
Top findings       Brute Force Access Behavior Detected   361
                   Excessive Failed Logins                  29
                   Malware Detected on Host                 12
Top sources        10.20.4.15   362 (Access)
                   10.20.7.33    14 (Endpoint)
```

Cara membacanya, berurutan:

1. **Lonjakan Access 380%** hampir seluruhnya berasal dari satu detection dan satu `src` (361 dan 362). Ini pola satu sumber berisik, bukan serangan luas. Pertanyaan pertama: apakah `10.20.4.15` adalah scanner atau aplikasi dengan kredensial kedaluwarsa? Cek di Asset Center atau lookup aset.
2. **Dua finding critical** lebih penting daripada 361 finding medium. Buka keduanya lebih dulu di analyst queue, walaupun volumenya kecil. Urgency critical berarti severity detection tinggi bertemu aset berprioritas tinggi.
3. **Malware Detected on Host 12** dari `10.20.7.33` (14 finding Endpoint): satu host dengan banyak finding malware layak diperiksa sebagai satu kasus, bukan dua belas tiket.
4. Setelah triage, catat untuk tuning: detection brute force yang dipicu ratusan kali oleh satu sumber yang ternyata jinak adalah kandidat allowlist sempit atau perubahan output ke risk (Day 35-36).

Kesalahan yang sering terjadi di skenario seperti ini adalah mulai dari detection dengan volume tertinggi karena terlihat paling "ramai". Volume menunjukkan di mana noise berada; urgency dan konteks aset menunjukkan di mana risiko berada.

## 5. Lab praktik

1. **Dengan ES:** buka Security posture, Executive summary, SOC operations, dan Risk analysis. Untuk setiap dashboard, catat 3 panel dan pertanyaan yang dijawabnya. Gunakan "Open in Search" pada 2 panel dan simpan SPL-nya.
2. **Tanpa ES:** bangun dashboard bagian 4.5.
3. Buat tabel tugas dan dashboard yang tepat:
   - triage pagi: Security posture;
   - laporan bulanan CISO: Executive summary;
   - evaluasi kualitas detection: SOC operations (Dispositions);
   - investigasi user: Asset and identity / Risk analysis;
   - data model kosong: Audit.
4. Identifikasi satu panel yang kosong di lab-mu, lalu jelaskan penyebabnya (data, CIM, akselerasi, A&I).

**Hasil yang sebaiknya tersimpan:**
- Ringkasan 4 dashboard utama.
- Tabel tugas dan dashboard.
- Diagnosis satu panel kosong.

**Variasi tantangan:** tambahkan panel "jenis event risiko yang tidak menghasilkan risk notable" (meniru Executive summary [S1]) dari risk index lab (Day 31 analog), lalu jelaskan arti panel itu untuk tuning RBA.

## 6. Troubleshooting

| Gejala | Kemungkinan penyebab | Perbaikan |
|---|---|---|
| Panel domain kosong | Data model terkait kosong/tidak terakselerasi | Audit dashboards; Day 23/26 |
| Urgensi semua "unknown/medium" | Prioritas aset kosong | Lengkapi A&I (Day 26) [S2] |
| KPI Investigations created tidak tampil | Tidak punya `manage_all_investigations` | Minta admin menambah capability [S1] |
| Panel disposisi tidak bermakna | Disposition tidak diisi/selalu Undetermined | Wajibkan disposition (Day 34) |
| Dashboard lambat | Rentang waktu besar, akselerasi belum selesai | Persempit waktu; cek akselerasi |

## 7. Kesalahan umum dan jebakan

- Mencari antrean kerja di Analytics. Antrean ada di Mission Control (analyst queue).
- Menganggap urgensi = severity. Urgensi menggabungkan severity dan prioritas aset [S2].
- Membaca close rate sebagai kualitas (bagian 4.4).
- Mengabaikan Audit dashboards. Dashboard keamanan hanya sebaik data dan akselerasinya.
- `[komunitas]` Tidak ada sumber komunitas. Konten dari dokumentasi ES 8.7.

## 8. Catatan terkini

- Dokumentasi ES 8.7 menempatkan dashboard di bagian Analytics User Guide [S1][S2][S3].
- Panel ES 8.7 masih memakai istilah ES 7 (notable, risk notable, correlation search) di beberapa tempat [S1][S3]. Jangan bingung saat membandingkan dengan glosarium.
- Predictive analytics dashboard terdaftar di navigasi 8.7 [S1], cek isinya.

## 9. Cheat sheet

```
SECURITY POSTURE   key indicators (24h per domain) | findings by urgency (aset prio x severity) | over time | top findings | top sources (src)
EXECUTIVE SUMMARY  MTT triage | MTT resolution | investigations created (cap manage_all_investigations: admin, ess_admin)
                   findings per urgensi/domain | untriaged | top & rare sources | risk notable vs notable | risk events tanpa risk notable
                   AR triggered | notable vs risk action | correlation search on/off
SOC OPERATIONS     MTT triage/resolution | assigned vs unassigned | end state | close rate per analyst | dispositions (FP logic/data, TP, BP)
RISK ANALYSIS      entity berisiko & detection penyumbang (Day 35)
DOMAIN             Access | Endpoint | Network | Asset and identity | Threat intelligence | Web intelligence  (berbasis data model CIM)
AUDIT              kesehatan data model/konten/platform ; PREDICTIVE analytics
ANTREAN            Mission Control > analyst queue (bukan Analytics)
```

## 10. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | ES 8.7 User Guide: Executive summary dashboard (termasuk daftar dashboard Analytics) | https://help.splunk.com/en/splunk-enterprise-security-8/user-guide/8.7/analytics/executive-summary-dashboard | primer | diakses 2026-10-07 | Tinggi |
| S2 | ES 8.7 User Guide: Security posture dashboard | https://help.splunk.com/en/splunk-enterprise-security-8/user-guide/8.7/analytics/security-posture-dashboard | primer | diakses 2026-10-07 | Tinggi |
| S3 | ES 8.7 User Guide: SOC operations dashboard | https://help.splunk.com/en/splunk-enterprise-security-8/user-guide/8.7/analytics/soc-operations-dashboard | primer | diakses 2026-10-07 | Tinggi |
| S4 | ES 7.3: Executive Summary dashboard (pembanding) | https://help.splunk.com/en/splunk-enterprise-security-7/user-guide/7.3/dashboard-reference/executive-summary-dashboard | primer | diakses 2026-10-07 | Sedang; konteks ES 7 |
| S5 | ES 8.7: Data model reference for dashboards in Splunk Enterprise Security | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.7/dashboards/data-model-reference-for-dashboards-in-splunk-enterprise-security | primer | diakses 2026-10-10 | Tinggi untuk nama dashboard dan data model-nya |

**Catatan sumber:** ketersediaan menu "Open in Search" di panel ES 8.7 dan nama field notable/finding di ES 8 perlu dicek di instance. Daftar sub-dashboard di bagian 3.7 berasal dari tabel referensi data model ES 8.7 [S5]; letak menunya di navigasi bisa berbeda antar versi. Angka di bagian 4.6 fiktif.
