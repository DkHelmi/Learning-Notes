---
day: 32
title: Dashboard bawaan ES dan informasi dasarnya
researched_on: 2026-10-10
versions_checked: 'Splunk ES 8.7 User Guide: Analytics (Executive summary, Security posture, SOC operations; daftar dashboard Access/Endpoint/Network/Asset and identity/Threat intelligence/Web intelligence/Audit/Risk analysis/Predictive analytics); ES 7.3 dashboard reference (pembanding)'
---

# Day 32: Dashboard bawaan ES

Cakupan: mengidentifikasi dashboard bawaan umum di Enterprise Security dan informasi dasar yang dimuatnya.

## Ide inti

Dashboard bawaan ES bukan hiasan dan bukan satu layar serbaguna. Masing-masing dibangun untuk satu audiens dan satu pertanyaan: manajer melihat tren dan metrik, analyst melihat finding per domain keamanan, dan engineer melihat kesehatan data serta konten. Karena itu keterampilan yang benar-benar dipakai di pekerjaan bukan menghafal nama panel, melainkan dua hal: menjawab "informasi ini ada di dashboard mana" dalam hitungan detik, dan mengetahui data model di balik setiap panel, karena itulah yang menjelaskan kenapa sebuah panel kosong. Satu hal lagi yang menghemat waktu sejak hari pertama: antrean kerja analyst tidak berada di Analytics, melainkan di Mission Control.

Analoginya layar besar di NOC, yang panelnya dibaca sekilas untuk tahu di mana harus menoleh. Batas analoginya ada di arti panel kosong. Di layar NOC, grafik yang rata biasanya berarti perangkatnya mati atau polling berhenti, dan setiap panel juga adalah search yang jalan setiap dibuka, sehingga dashboard berat ikut membebani search head. Di ES, panel kosong lebih sering berarti data model yang dibacanya kosong, belum selesai terakselerasi, atau field-nya belum ternormalisasi ke CIM, dan untuk kelompok Audit sering sekadar soal izin role terhadap index internal. Di PT JAB keadaan itu nyata: ES baru dinyalakan di search head terpisah dan daftar aset serta identitas belum lengkap, sehingga kolom urgensi di panel-panel triage belum bisa dipercaya sebelum data aset dibenahi.

**Kapan relevan:** triage pagi dan memilih dari mana mulai menoleh, menyusun laporan bulanan untuk manajemen, menilai kualitas detection lewat panel disposisi, dan mendiagnosis panel kosong sebelum menyimpulkan bahwa tidak ada aktivitas.
**Kapan bukan jawaban:** untuk mengerjakan kasus satu per satu, tempatnya analyst queue di Mission Control, bukan dashboard (Day 31 dan 33). Untuk menyetel ambang dan bobot risiko, dashboard hanya menampilkan akibatnya (Day 35). Dan bila yang bermasalah adalah datanya, perbaikannya di onboarding dan normalisasi, bukan di panel (Day 23 dan 28).

## 1. Konsep inti

### 1.1 Peta dashboard ES 8.7

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
| Threat intelligence dashboards | Analyst/CTI | Aktivitas yang cocok dengan intel (Day 33) |
| Web intelligence dashboards | Analyst | Aktivitas web/proxy: kategori HTTP, user-agent, domain baru, ukuran trafik, panjang URL (bagian 1.6) |
| Audit dashboards | Engineer/admin | Kesehatan platform dan konten: forwarder, indexing, view, suppression, threat intel, adaptive response (bagian 1.6) |
| Predictive analytics | Analyst lanjutan | Analitik prediktif/anomali atas data model, cek isi di 8.7 |

Antrean kerja analyst sendiri (finding, investigation) berada di Mission Control > analyst queue, bukan di Analytics (Day 33 dan 31).

### 1.2 Security posture

Panel [S2]:
1. **Key indicators**: jumlah finding per security domain dalam 24 jam terakhir.
2. **Findings by urgency**: urgensi dihitung dari prioritas aset dan severity detection. Panel ini terhubung ke analyst queue yang terfilter.
3. **Findings over time**: timeline per domain, dengan klik yang membuka analyst queue terfilter.
4. **Top findings**: nama detection paling sering, dengan sparkline.
5. **Top findings sources**: 10 teratas berdasarkan `src`, dengan hitungan per detection dan domain serta sparkline.

**Cara membaca:** lonjakan di satu domain + sumber yang sama di top sources adalah titik awal triage. Urgensi bergantung pada prioritas aset. Jika data A&I kosong, urgensi menjadi tidak informatif (Day 26).

### 1.3 Executive summary

Panel [S1]:
- **KPI:** Mean time to triage, Mean time to resolution (dengan tren vs periode sebelumnya), Investigations created.
- **Findings:** distribusi per urgensi (Critical, High, Medium, Low, Information, Unknown), per domain, finding yang belum di-triage per domain dan sumber, top 10 dan rare finding sources.
- **Risk analysis:** risk notable vs notable standar, event risiko yang berkontribusi ke risk notable, dan jenis event risiko yang tidak menghasilkan risk notable. Panel terakhir ini berguna untuk menilai apakah RBA disetel dengan baik.
- **Lainnya:** jumlah adaptive response yang dipicu, sumber dengan aksi notable vs aksi risk aktif, correlation search aktif vs nonaktif.
- **Capability:** KPI Investigations created butuh `manage_all_investigations`. Secara default hanya role `admin` dan `ess_admin` yang memilikinya [S1].

Perhatikan bahwa dokumentasi 8.7 di dashboard ini masih memakai istilah lama (*notable*, *risk notable*, *correlation search*) berdampingan dengan istilah baru. Jangan heran bila menu dan dokumentasi tidak konsisten.

### 1.4 SOC operations

Panel [S3]:
- **Key metrics:** Mean time to triage (rata-rata menit untuk memprioritaskan), Mean time to resolution (rata-rata menit sampai status akhir), Investigations created.
- **Workflow:** notable assigned vs unassigned, notable dalam status akhir, close rate per analyst.
- **Dispositions:** disposisi dari waktu ke waktu (FP vs TP), serta sumber yang menghasilkan disposisi tertentu (*incorrect logic*, *inaccurate data*, *suspicious activity*, *suspicious but expected*). Ini menghubungkan Day 34 langsung ke dashboard.

**Cara membaca:** detection yang dominan di panel "incorrect logic" adalah daftar kerja detection engineer. Yang dominan di "inaccurate data" adalah daftar kerja data engineer.

### 1.5 Domain dashboards dan data model

Dashboard domain (Access, Endpoint, Network, Web) dibangun di atas data model CIM (Day 23/24). Jika data model kosong atau tidak terakselerasi, dashboard kosong atau lambat. Itulah alasan engineer memantau Audit dashboards (status akselerasi, ukuran, kesehatan konten).

**Tanpa ES:** dashboard di atas khusus ES. Di Splunk Enterprise, kamu membangun dashboard sendiri (Dashboard Studio atau Classic) dari data model dan CIM, dan Monitoring Console menyediakan kesehatan platform (Day 14).

### 1.6 Sub-dashboard domain dan data model di baliknya

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

## 2. Contoh SPL dan langkah di ES

> Keluaran berlabel ilustrasi. Query membantu memahami sumber data panel. Panel aslinya mungkin memakai macro/data model ES berbeda, cek dengan "Open in Search" pada panel.

### 2.1 Membongkar panel: lihat SPL di balik panel

Di setiap panel ES, gunakan menu panel (mis. "Open in Search") untuk melihat SPL aslinya, cek tersedia di ES 8.7. Kebiasaan ini membantu:
- memahami sumber data (notable/finding, risk, data model);
- membuat varian panel untuk kebutuhan tim.

### 2.2 Meniru "Findings by urgency" (ES 7 pola)

```
`notable` earliest=-24h
| stats count BY urgency security_domain
| xyseries security_domain urgency count
```

- `security_domain` (access, endpoint, network, threat, identity, audit) dan `urgency` adalah field notable klasik, cek di ES 8.

### 2.3 Meniru "Top findings sources"

```
`notable` earliest=-24h
| stats count dc(rule_name) AS detections values(security_domain) AS domains BY src
| sort - count | head 10
```

### 2.4 Meniru panel SOC operations: close rate per analyst

```
`notable` earliest=-30d
| eval closed=if(in(status_label,"Resolved","Closed"),1,0)
| stats count sum(closed) AS closed BY owner
| eval close_rate=round(closed/count*100,1)
| sort - count
```

- Gunakan dengan hati-hati. Close rate tinggi tanpa memperhatikan kualitas bisa mendorong penutupan prematur (Day 34).

### 2.5 Lab tanpa ES: dashboard "security posture mini"

Buat dashboard Splunk (Dashboard Studio) dengan 4 panel dari data lab:
1. Jumlah alert per "domain" (Authentication, Endpoint, Network) dari `tstats` data model (Day 24).
2. Alert per jam (timechart).
3. Top 10 `src` dari Network_Traffic yang diblokir.
4. Top detection dari index alert lab (Day 31 lab).

### 2.6 Contoh membaca Security posture saat triage pagi

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

## 3. Lab praktik

1. **Dengan ES:** buka Security posture, Executive summary, SOC operations, dan Risk analysis. Untuk setiap dashboard, catat 3 panel dan pertanyaan yang dijawabnya. Gunakan "Open in Search" pada 2 panel dan simpan SPL-nya.
2. **Tanpa ES:** bangun dashboard bagian 2.5.
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

## 4. Troubleshooting

| Gejala | Kemungkinan penyebab | Perbaikan |
|---|---|---|
| Panel domain kosong | Data model terkait kosong/tidak terakselerasi | Audit dashboards; Day 23/26 |
| Urgensi semua "unknown/medium" | Prioritas aset kosong | Lengkapi A&I (Day 26) [S2] |
| KPI Investigations created tidak tampil | Tidak punya `manage_all_investigations` | Minta admin menambah capability [S1] |
| Panel disposisi tidak bermakna | Disposition tidak diisi/selalu Undetermined | Wajibkan disposition (Day 34) |
| Dashboard lambat | Rentang waktu besar, akselerasi belum selesai | Persempit waktu; cek akselerasi |

## 5. Kesalahan umum dan jebakan

- Mencari antrean kerja di Analytics. Antrean ada di Mission Control (analyst queue).
- Menganggap urgensi = severity. Urgensi menggabungkan severity dan prioritas aset [S2].
- Membaca close rate sebagai kualitas (bagian 2.4).
- Mengabaikan Audit dashboards. Dashboard keamanan hanya sebaik data dan akselerasinya.
- `[komunitas]` Tidak ada sumber komunitas. Konten dari dokumentasi ES 8.7.

## 6. Catatan terkini

- Dokumentasi ES 8.7 menempatkan dashboard di bagian Analytics User Guide [S1][S2][S3].
- Panel ES 8.7 masih memakai istilah ES 7 (notable, risk notable, correlation search) di beberapa tempat [S1][S3]. Jangan bingung saat membandingkan dengan glosarium.
- Predictive analytics dashboard terdaftar di navigasi 8.7 [S1], cek isinya.

## 7. Cheat sheet

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

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** Analyst PT JAB membuka Intrusion Center di kelompok Network dan panelnya kosong, lalu menulis di tiket "tidak ada aktivitas IDS dalam 24 jam terakhir". Apa yang keliru?

<details><summary>Jawaban</summary>

Panel kosong bukan pernyataan tentang aktivitas, melainkan pernyataan tentang data model yang dibaca panel itu. Intrusion Center membaca data model Intrusion Detection, jadi urutan pemeriksaannya: cari sub-dashboard itu di tabel pemetaan, jalankan `| tstats summariesonly=false count from datamodel=<DM>` untuk memastikan modelnya punya data sama sekali, lalu ulangi dengan `summariesonly=true`. Selisih besar antara keduanya berarti akselerasi belum selesai atau rentang waktunya di luar jendela summary, sedangkan nol di dua-duanya berarti masalahnya di onboarding atau tag CIM, bukan di dashboard. Kesimpulan "tidak ada aktivitas" baru sah setelah langkah itu dilakukan. Lihat bagian 1.5 dan 1.6.

</details>

**2. Skenario keputusan.** SOC lead meminta dua hal dalam satu minggu: bahan laporan bulanan untuk direksi, dan penilaian apakah detection brute force yang berisik itu layak dipertahankan. Dashboard mana yang kamu pakai?

- A. Security posture untuk keduanya, karena di situ semua finding dan top detection terlihat.
- B. Executive summary untuk laporan direksi (MTT triage, MTT resolution, investigasi, distribusi urgensi dan domain), dan SOC operations untuk menilai detection lewat panel disposisi.
- C. Risk analysis untuk keduanya, karena skor risiko entity adalah ukuran paling obyektif.

<details><summary>Jawaban</summary>

B. Executive summary memang dirancang untuk audiens manajemen: metrik waktu, jumlah investigasi, distribusi finding per urgensi dan domain, serta perbandingan risk notable dengan notable biasa. SOC operations memuat panel disposisi dari waktu ke waktu beserta sumber yang menghasilkan disposisi tertentu, sehingga detection yang dominan di "incorrect logic" langsung terbaca sebagai pekerjaan detection engineer, dan yang dominan di "inaccurate data" sebagai pekerjaan data engineer. A hanya memberi gambaran 24 jam terakhir tanpa metrik dan tanpa disposisi. C menjawab pertanyaan lain, yaitu entity mana yang berisiko tinggi. Lihat bagian 1.1, 1.3, dan 1.4.

</details>

**3. Pertanyaan jebakan.** Di Security posture PT JAB hampir semua finding berurgensi medium atau unknown, dan seorang rekan menyimpulkan "berarti severity detection kita semua medium". Apa yang perlu dikoreksi?

<details><summary>Jawaban</summary>

Urgensi bukan severity. Urgensi dihitung dari gabungan severity detection dan prioritas aset, jadi daftar aset dan identitas yang kosong atau belum lengkap membuat kolom urgensi menumpuk di satu nilai dan kehilangan daya pembeda. Di PT JAB hal ini memang sedang terjadi karena aset POP dan perangkat pelanggan belum masuk, sehingga perbaikannya ada di melengkapi data aset, bukan di menaikkan severity detection satu per satu. Lihat bagian 1.2 dan bagian 4.

</details>

**4. Skenario keputusan.** Manajemen ingin memakai panel close rate per analyst di SOC operations sebagai target bulanan per orang. Apa jawabanmu?

- A. Setuju, karena angkanya sudah disediakan dashboard bawaan dan mudah dibandingkan antar analyst.
- B. Tolak seluruh panel itu, karena metrik per analyst tidak pernah berguna.
- C. Setuju memakainya sebagai bahan diskusi beban kerja, tetapi tolak menjadikannya target, dan sarankan membacanya bersama panel disposisi serta kualitas penutupan.

<details><summary>Jawaban</summary>

C. Close rate tinggi bisa berarti analyst yang produktif, atau antrean yang ditutup prematur, dan dashboard tidak bisa membedakan keduanya. Panel itu berguna untuk melihat sebaran beban dan penugasan, sedangkan kualitasnya hanya terbaca lewat disposisi: detection yang dominan di "incorrect logic" dan "inaccurate data" menunjukkan di mana pekerjaan perbaikan berada. A mendorong perilaku yang justru merusak data metrik, karena disposisi yang diisi sembarangan membuat seluruh panel SOC operations tidak bermakna. B berlebihan: panelnya tetap berguna selama tidak dijadikan target. Lihat bagian 1.4 dan 2.4.

</details>

**5. Interview question (English).** "You open your SIEM in the morning and the dashboard shows a 380 percent spike in one domain. Walk me through what you do."

<details><summary>Sample answer</summary>

"I read the spike against the other panels before I touch a single case. If almost all of it comes from one detection and one source address, that is a noisy source pattern rather than a broad attack, so my first question is what that address actually is, which I answer from the asset and identity dashboards or the asset lookup: a scanner, or an application with expired credentials, behaves very differently from a workstation. Then I ignore volume for a moment and open the two critical findings first, because urgency combines detection severity with asset priority, so two critical findings on important assets outrank several hundred medium ones. If one host has a dozen malware findings, I work it as one case rather than twelve tickets. After triage I write the tuning note: a brute force detection fired hundreds of times by a single benign source is a candidate for a narrow allowlist or for sending its output into risk instead of straight into the queue. And if a panel I rely on is empty, I do not read that as quiet; I check the data model behind it, because an empty panel is usually missing data, missing CIM tags, or incomplete acceleration."

What makes this answer strong: it separates volume from risk, names urgency as a combination of severity and asset priority, groups findings per host into one case, closes the loop with a tuning decision, and treats an empty panel as a data question rather than good news.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | ES 8.7 User Guide: Executive summary dashboard (termasuk daftar dashboard Analytics) | https://help.splunk.com/en/splunk-enterprise-security-8/user-guide/8.7/analytics/executive-summary-dashboard | primer | diakses 2026-10-07 | Tinggi |
| S2 | ES 8.7 User Guide: Security posture dashboard | https://help.splunk.com/en/splunk-enterprise-security-8/user-guide/8.7/analytics/security-posture-dashboard | primer | diakses 2026-10-07 | Tinggi |
| S3 | ES 8.7 User Guide: SOC operations dashboard | https://help.splunk.com/en/splunk-enterprise-security-8/user-guide/8.7/analytics/soc-operations-dashboard | primer | diakses 2026-10-07 | Tinggi |
| S4 | ES 7.3: Executive Summary dashboard (pembanding) | https://help.splunk.com/en/splunk-enterprise-security-7/user-guide/7.3/dashboard-reference/executive-summary-dashboard | primer | diakses 2026-10-07 | Sedang; konteks ES 7 |
| S5 | ES 8.7: Data model reference for dashboards in Splunk Enterprise Security | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.7/dashboards/data-model-reference-for-dashboards-in-splunk-enterprise-security | primer | diakses 2026-10-10 | Tinggi untuk nama dashboard dan data model-nya |

**Catatan sumber:** ketersediaan menu "Open in Search" di panel ES 8.7 dan nama field notable/finding di ES 8 perlu dicek di instance. Daftar sub-dashboard di bagian 1.6 berasal dari tabel referensi data model ES 8.7 [S5]; letak menunya di navigasi bisa berbeda antar versi. Angka di bagian 2.6 fiktif.
