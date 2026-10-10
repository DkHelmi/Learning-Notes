---
day: 23
title: 'Correlation search (event-based detection): membuat dan menyetel di ES'
researched_on: 2026-10-10
versions_checked: Splunk ES 8.7 (Create event-based detections; Specify the time to run detections; annotations; adaptive response); Splunk Enterprise 10.6; CIM 6.4
---

# Day 23: Membuat dan menyetel correlation search (event-based detection) di ES

Cakupan: membuat correlation search di Enterprise Security.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- membuat event-based detection (ES 7: correlation search) di detection editor ES 8.7, dengan seluruh field penting: search, jadwal, trigger, throttling, output (finding dan/atau intermediate finding), threat object, annotation, adaptive response.
- memilih real-time vs continuous scheduling, schedule window, dan rentang waktu berjeda yang tepat.
- menyetel detection: throttling, filter/allowlist, mengubah output dari finding ke risk, dan kalibrasi ambang.
- menulis "kartu detection" yang terdokumentasi.

## 2. Konteks singkat

Ini puncaknya. Kamu menggabungkan:
- SPL efisien (Day 01-07);
- data model CIM (Day 09-11);
- A&I (Day 10);
- annotation (Day 14/16);
- RBA (Day 22);
- disposition (Day 19).

Di ES 8, istilah resminya detection. Dokumentasi lama dan banyak tulisan praktisi menyebut correlation search. Keduanya merujuk hal yang sama: search terjadwal yang menghasilkan finding/notable dan/atau event risiko.

## 3. Konsep inti

### 3.1 Membuat detection: jalur dan field

Jalur: Security content > Content management > + Content > Detection > Event-based detection > Submit untuk membuka detection editor [S1].

Field utama di editor [S1]:

| Bagian | Field | Catatan |
|---|---|---|
| Dasar | Name | Maks 83 karakter (99 dengan prefix/suffix) |
| | App | Lokasi penyimpanan. Menonaktifkan app ikut menonaktifkan detection |
| | UI dispatch context | App untuk tautan adaptive response |
| | Security domain | Threat, Access, Audit, Network, Endpoint, Identity |
| | Description | Apa yang dideteksi dan kenapa |
| | Mode | Guided (wizard) atau manual SPL |
| Search | Search | SPL, dengan preview dan validasi; preview time range default Last 24 hours; Open in search |
| Output | Output type | Finding, intermediate finding, atau keduanya |
| | Intermediate finding | Risk message, score, entity, entity type (Day 22) |
| | Finding | Name, description, entity, investigation type, severity, default owner, default status, next steps, recommended actions |
| Trigger | Conditions | Jumlah hasil/host/sumber, atau kustom |
| | Trigger frequency | Once atau for each result |
| Throttling | Window duration | Rentang throttling |
| | Fields to group by | Kunci throttling (mis. `src`, `user`) |
| Lainnya | Threat objects | Observable (domain, IP, hash, dll.) |
| | Annotations | ATT&CK, CIS, NIST, Kill Chain, dll. (Day 14/16) [S3] |
| | Adaptive response actions | Day 20/26 [S4] |

Field jadwal (cron, schedule window, priority) dijelaskan di bagian 3.2, cek letaknya di editor 8.7.

### 3.2 Menjadwalkan dengan benar

Menurut dokumentasi ES 8.7 [S2]:
- **Real-time schedule:** memprioritaskan data terkini dan performa. Detection di-skip bila tidak bisa berjalan tepat waktu, dan jendela yang terlewat tidak dipindai ulang.
- **Continuous schedule:** memprioritaskan kelengkapan. Detection tidak pernah di-skip.
- **Schedule window:** default auto, menggeser waktu mulai berdasarkan histori performa. Bisa diisi menit tertentu, atau 0 untuk menonaktifkan. Saat aktif, detection mendapat prioritas lebih rendah agar search lain jalan dulu.
- **Schedule priority:** Higher/Highest memaksa detection berjalan tepat waktu, mengesampingkan schedule window.
- **Cron:** mis. `*/15 * * * *` = tiap 15 menit.
- **Praktik terbaik:**
  - jangan jadwalkan semua detection di menit yang sama (staggering);
  - gunakan rentang waktu berjeda dan dibulatkan, mis. `earliest=-60m@m`;
  - pertimbangkan Index Time untuk data yang sering terlambat masuk, mis. sumber cloud [S2].

**Contoh pemilihan:** detection berbasis `tstats summariesonly=true` atas data model terakselerasi, berjalan tiap 15 menit dengan jendela 20 menit berjeda 5 menit (`earliest=-20m@m latest=-5m@m`). Jendelanya sedikit overlap untuk mengompensasi keterlambatan, sedangkan duplikasi dikendalikan throttling.

### 3.3 Mendesain output: finding, risk, atau keduanya

| Karakter detection | Output yang disarankan | Alasan |
|---|---|---|
| Fidelitas tinggi, butuh respons segera (mis. ransomware, credential dumping LSASS) | Finding (+ intermediate finding) | Harus langsung terlihat analyst |
| Fidelitas sedang/rendah, berguna sebagai konteks (mis. discovery commands, PowerShell anomali) | Intermediate finding saja | Masuk RBA; alert hanya bila menumpuk (Day 22) |
| Hanya untuk dashboard/hunting | Tidak keduanya; saved search biasa | Tidak membebani antrean |

### 3.4 Throttling vs suppression vs tuning

- Throttling (di editor): mencegah finding duplikat untuk kombinasi field yang sama dalam jendela tertentu [S1]. Contoh: satu finding per (`src`, `user`) per jam.
- **Tuning logika:** filter atau allowlist (lookup) di SPL. Pada konten ESCU, tuning dilakukan lewat filter macro (`*_filter`) agar tidak hilang saat update (Day 06).
- **Ubah output:** dari finding menjadi intermediate finding untuk detection yang terbukti berisik tetapi tetap bernilai (Day 22).
- Kalibrasi ambang dari data historis (bagian 4.3).
- ES 7 memiliki fitur *notable event suppression* (suppression berbasis search yang menyembunyikan notable dengan kriteria tertentu selama periode tertentu). Padanannya di ES 8.7 perlu dicek di instance.

### 3.5 Kartu detection (dokumentasi)

Setiap detection sebaiknya punya kartu, yaitu bentuk ringkas ADS (Alerting and Detection Strategy). ADS adalah template dokumentasi detection yang dipublikasikan tim incident response Palantir pada 2017. Bagian aslinya: goal, categorization (pemetaan ATT&CK), strategy abstract, technical context, blind spots and assumptions, false positives, validation (cara menguji), priority, dan response (langkah awal analyst). Tujuannya agar detection tidak dibuat sebelum alasan, batas, dan cara ujinya ditulis. Versi ringkas yang cukup untuk kartu:
- tujuan;
- teknik ATT&CK;
- data/data model;
- asumsi;
- blind spot;
- FP diketahui;
- cara uji;
- output (finding/risk);
- skor;
- throttling;
- jadwal;
- pemilik;
- riwayat versi. ES 8.3+ menambah manajemen versi detection (Day 16).

### 3.6 Enterprise vs ES

- **Tanpa ES:** saved search/alert dengan jadwal, trigger condition, throttling, dan alert action. Konsep jadwal dan throttling sama, tetapi tanpa finding, risk, annotation terkelola, atau analyst queue.
- **Dengan ES:** detection editor, output finding/intermediate finding, annotation, adaptive response, dan Detection Studio untuk kesehatan (Day 12).

## 4. Contoh SPL dan langkah di ES

> Keluaran berlabel ilustrasi. ID ATT&CK, cek di v19.

### 4.1 Detection lengkap: brute force diikuti login berhasil (CIM Authentication)

Search (catatan: `count(eval(...))` tidak didukung di `tstats` (Day 01), jadi hitung `count` per `action` lalu pisahkan dengan `stats`):

```
| tstats summariesonly=true allow_old_summaries=false count
    from datamodel=Authentication.Authentication
    where earliest=-20m@m latest=-5m@m
    by Authentication.src Authentication.user Authentication.dest Authentication.action
| rename Authentication.* AS *
| eval f=if(action="failure",count,0), s=if(action="success",count,0)
| stats sum(f) AS failures sum(s) AS successes values(dest) AS dest BY src user
| where failures >= 10 AND successes >= 1
| lookup lab_auth_allowlist.csv src OUTPUT allow
| where isnull(allow)
```

| Baris | Fungsi |
|---|---|
| `tstats ... by ... action` | Hitung per kombinasi termasuk `action` (cepat, data model; Day 01) |
| `earliest=-20m@m latest=-5m@m` | Jendela berjeda dan dibulatkan [S2] |
| `eval f/s` + `stats` | Memisahkan gagal dan sukses per (src, user) |
| `where failures>=10 AND successes>=1` | Logika inti. Ambang dikalibrasi (bagian 4.3). Catatan: jendela 15 menit tidak menjamin urutan (Day 02) |
| `lookup ... allowlist` | Tuning: sumber yang diizinkan (mis. scanner kerentanan) |

**Pengaturan editor (contoh):**

| Field | Nilai |
|---|---|
| Name | `Lab - Auth - Brute Force Followed By Success` |
| Security domain | Access |
| Schedule | Cron `*/15 * * * *`, continuous, schedule window auto |
| Trigger | Number of results > 0, for each result |
| Throttling | Window 1 jam; group by `src`, `user` |
| Output | Finding dan intermediate finding |
| Finding | Severity high; investigation type "Account Compromise"; next steps: cek login sukses dari `src`, reset kredensial bila perlu |
| Intermediate finding | Entity `user` (type user) score 40; entity `src` (type system) score 20; message `"$failures$ failures then success for $user$ from $src$"`, cek sintaks token |
| Threat objects | `src` (ip) bila eksternal |
| Annotations | ATT&CK T1110 Brute Force (Credential Access); untuk pola "gagal lalu sukses" tambahkan T1078 Valid Accounts |
| Adaptive response | Nslookup (src) ad hoc; opsional SOAR playbook akun (Day 27) |

### 4.2 Menguji sebelum mengaktifkan

```
| makeresults count=15
| streamstats count AS n
| eval src="198.51.100.9", user="alice", dest="vpn01",
       action=if(n<=12,"failure","success"), count=1
| eval f=if(action="failure",count,0), s=if(action="success",count,0)
| stats sum(f) AS failures sum(s) AS successes BY src user
| where failures >= 10 AND successes >= 1
```

Hasil yang diharapkan: satu baris (12 gagal, 3 sukses). Ini membuktikan logika pasca-`tstats` sebelum menunggu data nyata (Day 04).

### 4.3 Kalibrasi ambang dari data 30 hari

```
| tstats summariesonly=true count from datamodel=Authentication.Authentication
    where Authentication.action="failure" earliest=-30d@d
    by _time span=15m Authentication.src Authentication.user
| stats perc95(count) AS p95 perc99(count) AS p99 max(count) AS max
```

- Ambang `failures` sebaiknya di atas p99 perilaku normal, lalu disesuaikan dengan toleransi FP.
- Ulangi per segmen (VPN vs AD) bila polanya berbeda.

### 4.4 Memantau detection setelah aktif

- Skipped/terlambat: `index=_internal sourcetype=scheduler savedsearch_name="Lab - Auth*"` (Day 13 bagian 4.1), cek nama saved search detection ES 8 di scheduler log.
- Kualitas: disposition per detection (Day 19 bagian 4.1); kesehatan di Detection Studio (Day 12).

### 4.5 Lab tanpa ES

Buat saved search/alert dengan search bagian 4.1, jadwal `*/15 * * * *`, trigger "for each result", throttle 1 jam per `src,user`, dan alert action webhook ke Shuffle, yang kemudian membuat case di TheHive (lab-mu).

## 5. Lab praktik

1. Uji logika dengan bagian 4.2.
2. Buat `lab_auth_allowlist.csv` (kosong atau berisi IP scanner lab).
3. **Dengan ES:** buat detection bagian 4.1 lengkap di editor (Security content > Content management > + Content > Detection) [S1].
   **Tanpa ES:** buat alert bagian 4.5.
4. Picu dari VM Windows lab: login RDP/SMB gagal 12 kali lalu berhasil (akun uji).
5. Verifikasi:
   - finding di analyst queue (atau case di TheHive);
   - intermediate finding di risk index;
   - throttling bekerja: picu lagi dalam 1 jam, seharusnya tidak ada finding baru.
6. Jalankan bagian 4.3 dan tetapkan ambang final. Tulis kartu detection (bagian 3.5).
7. Ubah output menjadi "intermediate finding saja", ulangi pemicu, lalu amati perbedaannya di antrean dan Risk analysis.

**Hasil yang sebaiknya tersimpan:**
- Logika teruji dengan makeresults.
- Detection/alert terjadwal dengan jendela berjeda.
- Finding + event risiko muncul; throttling terbukti.
- Ambang dikalibrasi dari data.
- Kartu detection lengkap.

**Variasi tantangan:** buat detection kedua dengan output intermediate finding saja (mis. discovery commands `whoami`, `net group`, `nltest`, cek daftar). Tunjukkan bahwa kombinasi detection ini dan detection bagian 4.1 memicu finding group lewat RBA (Day 22).

## 6. Troubleshooting

| Gejala | Kemungkinan penyebab | Perbaikan |
|---|---|---|
| Detection tidak pernah fire | Data model tidak terakselerasi (summariesonly=true); jendela waktu tidak berisi data; ambang tinggi | Day 01 bagian 4.4; uji tanpa `summariesonly`; kalibrasi |
| Error saat menyimpan search | `count(eval())` di `tstats`; sintaks token | Pakai versi bagian 4.1 yang benar; cek preview [S1] |
| Finding duplikat | Throttling tidak diset/fields salah | Window + fields to group by [S1] |
| Detection sering skipped | Real-time schedule saat beban tinggi | Continuous; staggering; schedule window [S2] |
| Event terlambat tidak tertangkap | Jendela `_time` terlalu dekat sekarang | Jendela berjeda; Index Time [S2] |
| Tuning hilang setelah update ESCU | Mengedit search inti | Filter macro / kloning (Day 06) |

## 7. Kesalahan umum dan jebakan

- `count(eval(...))` di `tstats` (Day 01). Kesalahan klasik saat memindahkan logika dari `stats`.
- Semua detection di menit yang sama [S2].
- Jendela `earliest=-15m latest=now` tanpa jeda, sehingga event yang terlambat masuk hilang [S2].
- Semua detection menjadi finding. Ini membanjiri antrean. Pertimbangkan RBA (Day 22).
- Tanpa annotation dan kartu dokumentasi. Konteks dan cakupan hilang (Day 14/16).
- `[komunitas]` Praktik penjadwalan di Day ini berasal dari dokumentasi resmi [S2]; pengalaman praktisi soal jeda jendela waktu (5 sampai 10 menit) bervariasi menurut sumber data, jadi ukur ingest lag sendiri (Day 30).

## 8. Catatan terkini

- **ES 8.7:** pembuatan detection lewat Security content > Content management > + Content > Detection dengan editor yang mendukung mode guided/manual dan output finding/intermediate finding [S1].
- **Scheduling ES 8.7:** pilihan real-time vs continuous, schedule window auto, priority, dan Index Time untuk data terlambat [S2].
- **ES 8.3+:** manajemen versi detection (Day 16), cek cara memakainya di 8.7.
- Release notes ES 8.6/8.7 menyebut agen AI yang dapat membantu membuat detection. Hasil buatan AI tetap harus diuji seperti bagian 4.2-4.3.

## 9. Cheat sheet

```
BUAT   Security content > Content management > + Content > Detection > Event-based > Submit
FIELD  Name(<=83) | App | UI dispatch context | Security domain (Threat/Access/Audit/Network/Endpoint/Identity) | Description
       Mode guided|manual | Search (+preview 24h, Open in search)
       Output: finding | intermediate finding | keduanya
         finding: name, desc, entity, investigation type, severity, owner, status, next steps, recommended actions
         intermediate: risk message, score, entity, entity type
       Trigger: conditions + once|for each result | Throttling: window + fields to group by
       Threat objects | Annotations | Adaptive response
JADWAL real-time (bisa di-skip) vs continuous (tidak pernah di-skip) | schedule window auto | priority Higher/Highest
       cron */15 * * * * | stagger | earliest=-20m@m latest=-5m@m | Index Time untuk data terlambat
TUNING throttling | filter macro/allowlist lookup | finding -> risk | kalibrasi p95/p99 | disposition feedback
JEBAKAN tstats + count(eval()) TIDAK BISA
```

## 10. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | ES 8.7: Create event-based detections in Splunk Enterprise Security | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.7/detections/create-event-based-detections-in-splunk-enterprise-security | primer | diakses 2026-10-07 | Tinggi |
| S2 | ES 8.7: Specify the time to run detections in Splunk Enterprise Security | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.7/detections/specify-the-time-to-run-detections-in-splunk-enterprise-security | primer | diakses 2026-10-07 | Tinggi |
| S3 | ES 8.7: Add annotations to detections (lihat Day 14) | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.7/detections/add-annotations-to-detections-in-splunk-enterprise-security | primer | diakses 2026-10-07 | Tinggi |
| S4 | ES 8.7: Configure adaptive response actions (lihat Day 20) | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.7/detections/configure-adaptive-response-actions-for-detections-in-splunk-enterprise-security | primer | diakses 2026-10-07 | Tinggi |
| S5 | SPL Search Reference: tstats (batasan count(eval); lihat Day 01) | https://help.splunk.com/en/splunk-enterprise/spl-search-reference/10.2/search-commands/tstats | primer | diakses 2026-10-07 | Tinggi |
| S6 | Palantir: Alerting and Detection Strategy Framework | https://github.com/palantir/alerting-detection-strategy-framework | primer (penulis kerangka) | 2017; diakses 2026-10-10 | Tinggi untuk daftar bagian ADS |

**Catatan sumber:** letak field cron/schedule di editor 8.7, sintaks token risk message, padanan *notable event suppression* di ES 8, dan nama saved search detection di log scheduler perlu dicek di instance. Uraian bagian ADS mengikuti publikasi Palantir [S6].
