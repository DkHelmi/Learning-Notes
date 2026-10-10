---
day: 29
title: 'Review akhir: SPL gabungan, hunting, respons, dan rencana memperkuat kelemahan'
researched_on: 2026-10-10
versions_checked: Splunk Enterprise 10.6 (SPL 10.x); ES 8.7; SOAR 8.6
---

# Day 29: Review akhir SPL, hunting, dan respons

Cakupan: mengikat kembali command SPL dan search efisien (Day 01-07) dengan hunting dan respons (Day 24-27) lewat satu lab gabungan, lalu menyusun rencana memperkuat bagian yang masih lemah.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- menulis satu SPL gabungan yang memakai `tstats`, `transaction`, `rex`, `eval`, `foreach`, `lookup`, dan `makeresults` secara tepat dan efisien.
- menjelaskan hunting dan respons sebagai satu alur: hunt, temuan, detection, lalu adaptive response dan SOAR.
- menilai sendiri bagian mana yang masih lemah dan menyusun rencana memperkuatnya.

## 2. Konteks singkat

Dua kelompok materi ini sering dipelajari terpisah, padahal di pekerjaan keduanya satu rangkaian: hunting menghasilkan pertanyaan, SPL yang efisien menjawabnya, dan hasilnya berakhir di detection atau respons. Day ini dipakai untuk mengulang keduanya sekaligus, dalam satu lab yang panjang, lalu mencatat bagian yang masih goyah.

## 3. Ringkasan per topik

### SPL dan search efisien (Day 01-07)

| Topik | Inti | Day |
|---|---|---|
| `tstats` | tsidx/indexed field/data model; `summariesonly` default false; `prestats` untuk timechart; `fillnull_value`; tanpa `count(eval())`, tanpa wildcard di BY | 01 |
| `transaction`, first/last | `transaction` untuk ID dipakai ulang/penanda/raw; selain itu `stats`. `first`/`last` = urutan proses; `earliest`/`latest` = waktu | 02 |
| `rex`, `eval` | `rex` named group, `field=`, `max_match=0`, `mode=sed`; `eval` kutip tunggal = field, kutip ganda = string; `case`, `if`, `coalesce`, `cidrmatch`, `match`, `urldecode` | 03 |
| `foreach`, `lookup`, `makeresults` | `foreach` `'<<FIELD>>'`; `lookup` setelah `stats`, OUTPUT vs OUTPUTNEW, CIDR/WILDCARD; `makeresults` untuk uji logika | 04 |
| Search efisien | index/sourcetype/waktu/istilah spesifik; hindari `index=*`, leading wildcard, `NOT`; streaming -> transforming -> `sort`/`table`; ukur di Job Inspector | 05 |
| Sumber daya SPL | research.splunk.com/ESCU, SSE, Lantern, content management ES | 06 |

### Hunting dan respons (Day 24-27)

| Topik | Inti | Day |
|---|---|---|
| Teknik hunting | Configuration, modeling (anomali), indicator, behavior; atomic vs composite (Dragos) | 24 |
| Long tail, outlier, hypothesis | `rare`/stacking; z-score/IQR/`anomalydetection`; beaconing (jitter); PEAK Prepare/Execute/Act (15 langkah) | 25 |
| Adaptive response | 13 aksi bawaan ES 8.7; otomatis (detection editor) vs ad hoc (Mission Control); matriks keyakinan x reversibilitas x blast radius; relay Cloud->on-prem | 26 |
| SOAR playbook | Alur multi-langkah + approval; picu dari ES: automation rules, Run playbook manual, response plan task, AR ke SOAR; butuh pairing | 27 |

## 3b. Peta konsep

```
 PERTANYAAN HUNT (PEAK Prepare: topic->research->hypothesis->scope->plan)
          |
          v
 SPL EFISIEN (Day 05) ---- tstats (Day 01) untuk lebar | search sempit untuk detail
          |                           |
          v                           v
 TEKNIK (Day 24-25): config | modeling(long tail, outlier, beacon) | indicator(lookup) | behavior(TTP, composite)
          |        alat: stats/rare/eventstats/streamstats/anomalydetection/transaction/rex/eval/foreach/makeresults
          v
 HASIL: ditemukan -> escalate (IR) | tidak ditemukan (sah, catat scope) | data kurang (celah)
          |
          v
 ACT: preserve -> document -> CREATE DETECTION (Day 23) -> RBA/finding
          |
          v
 RESPON: AR (aksi tunggal, Day 26) | SOAR playbook (alur + approval, Day 27)
          |
          v
 KONTEN & SUMBER (Day 06): ESCU/research, SSE, Lantern  -> hunt berikutnya (backlog)
```

## 3c. Glosarium singkat

| Istilah | Arti |
|---|---|
| `prestats` | Format antara `tstats` -> `timechart`/`chart`/`stats` |
| `closed_txn` | 0 = transaksi di-evict |
| Named capture group | `(?<name>...)` di `rex` |
| `OUTPUTNEW` | Lookup tidak menimpa field yang ada |
| scanCount | Event yang dipindai (Job Inspector) |
| Long tail | Nilai paling jarang setelah stacking |
| Outlier | Nilai ekstrem terhadap distribusi/baseline |
| Jitter | Variasi interval koneksi (beaconing) |
| Composite detection | Gabungan event yang jinak sendiri-sendiri |
| Automation rule | Aturan ES yang menjalankan playbook saat finding dari detection tertentu dibuat |
| AR relay | Mekanisme menjalankan AR dari ES Cloud ke on-prem via heavy forwarder |

## 3d. Latihan skenario dengan pembahasan

Jawab dulu, baru baca pembahasannya. Semua skenario fiktif.

**Skenario 1: query hunting yang lambat.** Hunt long tail proses berjalan 14 menit:

```
index=* sourcetype=*sysmon* EventCode=1 | stats count dc(host) AS hosts BY Image | where hosts<=2
```

Apa yang diperbaiki tanpa mengubah pertanyaannya?

Pembahasan: `index=*` memaksa Splunk memeriksa semua index, dan wildcard di sourcetype mencegah pemangkasan awal (Day 05). Sebut index dan sourcetype persis. Bila data model Endpoint.Processes terakselerasi, versi `tstats ... by Processes.process_path` jauh lebih cepat (Day 01), tetapi pastikan `summariesonly=false` atau rentang waktunya tercakup summary, agar hasilnya sama. Bandingkan scanCount dan waktu di Job Inspector sebelum dan sesudah; jumlah baris hasil harus sama.

**Skenario 2: beacon yang tidak terlihat.** Hunt beaconing bagian 4.4 Day 25 tidak menemukan apa pun, padahal tim jaringan yakin ada host yang menghubungi tujuan aneh setiap lima menit. Apa saja kemungkinannya?

Pembahasan: (a) sumber data berupa flow teragregasi per beberapa menit, sehingga interval asli hilang; (b) beacon memakai jitter besar, sehingga koefisien variasi di atas ambang; pakai versi median dan MAD; (c) `dest_port` difilter 443 padahal beacon memakai port lain; (d) rentang 24 jam hanya memuat sedikit koneksi bila beacon tidur di malam hari. Catat mana yang benar, karena "tidak ditemukan" hanya sah bila celah datanya ditulis.

**Skenario 3: otomasi atau tidak.** Detection "Encoded PowerShell" punya FP rate 35% (sebagian besar skrip admin). Pimpinan ingin isolasi host otomatis. Apa rekomendasimu?

Pembahasan: dengan keyakinan sedang dan blast radius tinggi, matriks Day 26 menyarankan enrichment otomatis dan tindakan ad hoc atau lewat SOAR dengan persetujuan. Langkah realistis: turunkan detection ke output intermediate finding, tambah allowlist sempit untuk skrip admin yang dikenal, dan biarkan finding group RBA yang memicu playbook dengan prompt persetujuan.

**Skenario 4: `first` atau `earliest`.** Laporan menyebut "login pertama penyerang pukul 02.14" berdasarkan `stats first(_time)`. Kenapa itu berisiko?

Pembahasan: `first()` mengembalikan nilai dari event pertama yang diproses, dan secara default Splunk mengembalikan event terbaru lebih dulu, sehingga `first(_time)` biasanya adalah waktu terakhir, bukan pertama (Day 02). Untuk waktu paling awal, pakai `earliest(_time)` atau `min(_time)`.

## 4-6. Lab gabungan SPL + hunting + respons

**Tujuan:** satu hunt end-to-end di lab yang memakai semua command inti SPL.

1. **Prepare (PEAK):** hipotesis "Ada host lab yang menjalankan PowerShell terenkode lalu berkomunikasi berkala ke tujuan yang jarang".
2. **Uji logika dulu (`makeresults`, Day 04):** buat 5 baris CommandLine (positif/negatif). Uji `rex` + `eval` yang mengekstrak blob base64 dan menandai `-enc`.
3. **Cari proses (tstats + foreach, Day 01/04):**
   ```
   | tstats summariesonly=false count values(Processes.process) AS cmd from datamodel=Endpoint.Processes
       where Processes.process_name="powershell.exe" earliest=-7d by Processes.dest Processes.user
   | foreach Processes.* [eval <<MATCHSTR>>='<<FIELD>>']
   | fields - Processes.*
   | mvexpand cmd
   | rex field=cmd "(?i)\s[-/](?:ec|e[a-z]*)\s+(?<blob>[A-Za-z0-9+/=]{20,})"
   | where isnotnull(blob)
   | eval blob_len=len(blob)
   | stats count max(blob_len) AS max_len BY dest user
   ```
4. **Cari komunikasi berkala dari host itu (outlier/beacon, Day 25):** jalankan bagian 4.4 Day 25 untuk `src` = host temuan.
5. **Rare destination (long tail, Day 25):** `| tstats count dc(All_Traffic.src) AS srcs from datamodel=Network_Traffic.All_Traffic by All_Traffic.dest | where srcs=1 | sort count`.
6. **Konteks (lookup, Day 04/10):** enrichment `dest_priority`/owner setelah `stats`.
7. **Sesi (transaction vs stats, Day 02):** bangun sesi koneksi dari host ke tujuan dengan `transaction ... maxpause=5m`, lalu versi `stats`. Bandingkan dengan Job Inspector (Day 05).
8. **Timeline:** `earliest`/`latest` per tahap (bukan `first`/`last`).
9. **Act:** dokumentasikan hasil (ditemukan / tidak / data kurang). Buat detection composite dengan output intermediate finding (Day 22-23).
10. **Respons:** AR Nslookup otomatis + playbook Shuffle/SOAR dengan approval (Day 26-27).

**Data uji:** di VM Windows lab, jalankan PowerShell terenkode yang jinak (`Get-Date`) dan loop koneksi berkala ke server web lab (Day 25 bagian 5).

**Hasil yang sebaiknya tersimpan:**

- Uji `makeresults` dengan minimal dua kasus positif dan dua negatif, beserta hasilnya.
- Query langkah 3-5 dengan angka Job Inspector (waktu dan scanCount).
- Perbandingan `transaction` dan `stats` di langkah 7: jumlah sesi dan waktu eksekusi.
- Laporan hunt singkat dengan hasil (ditemukan, tidak ditemukan, atau data kurang) dan detection yang lahir dari hunt.

**Troubleshooting ringkas:**
- `foreach` gagal: cek kutip `'<<FIELD>>'`.
- `rex` tidak cocok: uji di `makeresults`.
- Beacon tidak muncul: pakai sumber data per koneksi (bukan flow agregat).
- Lambat: perbaiki filter awal dan rentang waktu (Day 05).

## 7. Kesalahan umum dan jebakan

- `first()` dipakai untuk "pertama kali" padahal yang dimaksud urutan waktu (Day 02).
- `summariesonly=true` saat hunting historis, sehingga data yang belum ter-summarize hilang (Day 01).
- `rex` dijalankan di `_raw` padahal field sudah ada; kutip tunggal dan ganda tertukar di `eval` (Day 03).
- `lookup` dipanggil sebelum `stats`; `OUTPUT` menimpa field CIM yang sudah benar (Day 04).
- `NOT` dan `!=` dianggap sama (Day 05).
- Menganggap langka berarti jahat, atau memakai baseline yang sudah tercemar aktivitas penyerang (Day 24-25).
- Containment otomatis dipasang pada detection yang masih tinggi false positive (Day 26).
- Lupa pairing ES dan SOAR; mengira satu detection bisa punya banyak automation rule (Day 27).

## 8. Catatan terkini

- **SPL 10.x:** `foreach` mendukung mode multivalue/json_array; `makeresults` mendukung `format=csv|json data=`; Evaluation functions punya kategori JSON (Day 03-04).
- **ES 8.7:** Detection Studio, 13 AR bawaan, automation rules (Configure > Splunk SOAR), Run playbook dari Mission Control (Day 12, 26-27).
- SOAR On-prem 8.6.0 (Agu 2026) adalah rilis terakhir dengan Python 3.9; otomasi perlu dimigrasi ke Python 3.13 (Day 27).

## 9. Cheat sheet

```
SPL  | tstats [summariesonly prestats fillnull_value] fn from datamodel=DM.Root where .. by .. [span]
     | transaction ids maxspan maxpause startswith endswith  (vs stats range(_time) BY id)
     first/last = urutan ; earliest/latest = waktu
     | rex field=F "(?<x>re)" [max_match=0] | rex mode=sed "s/a/b/g" ; | eval ' '=field " "=string
     | foreach X.* [eval <<MATCHSTR>>='<<FIELD>>'] ; | stats .. | lookup def k AS f OUTPUTNEW .. ; | makeresults format=csv data=".."
EFISIEN filter awal + waktu sempit + istilah spesifik ; hindari index=* *lead NOT ; streaming->stats->lookup/sort/table ; Job Inspector
SUMBER research.splunk.com/ESCU | SSE | Lantern | ES content mgmt / Detection Studio
HUNT config | modeling | indicator | behavior ; atomic vs composite
ANALITIK rare / stats|sort count ; z / IQR / anomalydetection ; jitter ; PEAK P(topic research hypothesis scope plan) E(gather preprocess analyze refine escalate) A(preserve document detect backlog communicate)
AR   otomatis (editor) vs ad hoc (Mission Control) ; guardrail ; relay
SOAR playbook ; automation rules (Configure > Splunk SOAR) | Run playbook | response plan task | AR->SOAR ; pairing
```

## Rencana memperkuat kelemahan

Isi kolom keyakinan (1 = sangat lemah, 5 = sangat yakin) setelah mencoba menjelaskan ulang setiap topik tanpa melihat catatan. Tabel ini template, jadi ganti dengan penilaian sendiri.

| Topik | Keyakinan (1-5) | Cara memperkuat | Target tanggal |
|---|---|---|---|
| Organisasi SOC | _ | Baca ulang Day 13 bagian 3.2-3.3; jelaskan lisan 2 menit | _ |
| Framework dan adopsinya di Splunk | _ | Kartu CSF/CIS/ATT&CK/Kill Chain; Day 14 bagian 3.3 | _ |
| CIA dan risiko | _ | Latihan 5 skenario CIA; matriks risiko Day 14 bagian 4.3 | _ |
| Serangan dan istilah | _ | Kartu glosarium Day 15; verifikasi ID ATT&CK v19 | _ |
| Tiers threat intel | _ | Pecah 1 laporan publik ke 4 tier (Day 16 bagian 5) | _ |
| Annotations | _ | Tambah annotation ke 2 detection lab; cek di risk index | _ |
| TTP | _ | Halaman T1053.005 + uji 2 procedure (Day 17 bagian 5) | _ |
| Pertahanan dan sumber data | _ | Matriks pertanyaan -> sumber -> DM (Day 08) | _ |
| CIM, data model, acceleration, Asset and Identity, field | _ | Mini TA labportal (Day 09) + A&I lab (Day 10) + kartu field (Day 11) | _ |
| Menilai sumber data dengan SSE dan ES | _ | Introspeksi SSE + matriks data->content->celah (Day 12) | _ |
| Continuous monitoring dan lima tahap investigasi | _ | Kasus lab lima tahap (Day 18) | _ |
| Metrik dan disposisi | _ | 8 skenario disposisi + hitung dwell time (Day 19) | _ |
| Istilah ES | _ | Kartu ES 7 vs ES 8 (Day 20/28) | _ |
| Dashboard ES | _ | Tabel tugas -> dashboard (Day 21) | _ |
| RBA dan detection | _ | RBA mini + detection lengkap (Day 22-23) | _ |
| Command SPL | _ | Lab gabungan Day 29 bagian 4-6; ulangi tanpa melihat catatan | _ |
| Search efisien | _ | 3 pasangan "sebelum/sesudah" dengan angka Job Inspector | _ |
| Sumber daya SPL | _ | Cari 3 detection per data source di research.splunk.com | _ |
| Teknik hunting | _ | 4 hunt per kategori (Day 24 bagian 5) | _ |
| Long tail, outlier, PEAK | _ | 1 hunt PEAK lengkap 15 langkah (Day 25) | _ |
| Adaptive response | _ | Matriks AR 3 detection + guardrail (Day 26) | _ |
| SOAR | _ | Playbook Shuffle 3 cabang (Day 27) | _ |

**Aturan rencana:**
- Kerjakan dulu topik yang paling sering dipakai di pekerjaan (SPL, CIM dan data model, detection, investigasi) dengan keyakinan 3 ke bawah.
- Untuk hal yang bergantung versi (ES 7 vs ES 8, ATT&CK v19), siapkan penjelasan dua versi karena dokumentasi lama masih beredar.
- Satu topik dianggap kuat bila kamu bisa menjelaskannya lisan dua menit dan menunjukkan satu bukti dari lab (query, angka Job Inspector, atau screenshot catatan sendiri).

## 10. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | SPL Search Reference 10.2 (tstats, transaction, rex, eval, foreach, lookup, makeresults, rare, anomalydetection; Day 01-05, 25) | https://help.splunk.com/en/splunk-enterprise/spl-search-reference/10.2/search-commands/tstats | primer | diakses 2026-10-07 | Tinggi |
| S2 | Splunk PEAK hypothesis hunting (Day 25) | https://www.splunk.com/en_us/blog/security/peak-hypothesis-driven-threat-hunting.html | primer | 2023-05-08 | Tinggi |
| S3 | ES 8.7 automation rules / adaptive response (Day 26-27) | https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.7/automation-with-playbooks/configure-automation-rules-to-run-playbooks-based-on-findings-in-splunk-enterprise-security | primer | diakses 2026-10-07 | Tinggi |

**Catatan sumber:** Day ini menyintesis Day 01-27 tanpa klaim teknis baru; hal yang masih perlu dicek di Day asalnya tetap berlaku. Skenario di bagian 3d fiktif.
