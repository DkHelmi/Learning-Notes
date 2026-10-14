---
day: 40
title: 'Summary index, KV store lookup, dan metrics: menyimpan baseline, first-seen, dan allowlist yang hidup'
researched_on: 2026-10-10
versions_checked: 'Splunk Enterprise 10.6 (Knowledge Manager Manual: summary indexing, lookups, KV store; SPL Search Reference: collect, sistats, mstats, mcatalog, inputlookup, outputlookup); rujukan Day 01, 04, 10, 23, 25'
---

# Day 40: Summary index, KV store lookup, dan metrics

Cakupan: tiga cara menyimpan hasil search supaya bisa dipakai berulang (summary index, lookup KV store, metrics index), kapan masing-masing tepat, dan pola pemakaiannya yang paling berguna untuk analyst: baseline jangka panjang, tabel first-seen, dan allowlist yang bisa diperbarui tanpa mengubah detection.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- memilih antara summary index, report acceleration, dan data model acceleration untuk sebuah kebutuhan.
- menulis scheduled search yang mengisi summary index dengan `sistats` dan `collect`, lalu membacanya kembali dengan benar.
- membedakan lookup CSV dan lookup KV store, dan menjelaskan kapan KV store wajib dipakai.
- membangun tabel first-seen (host, user, proses, domain) yang bertahan lebih lama daripada retensi data mentah.
- membuat allowlist yang bisa diperbarui tanpa menyentuh logika detection.
- memakai `mstats` untuk data metrics dan menyebut kapan metrics lebih tepat daripada event.
- mengenali cara summary dan lookup tercemar, lalu memperbaikinya.

## 2. Konteks singkat

Banyak pekerjaan analyst bersifat berulang dan bergantung pada sejarah: "apakah host ini pernah menjalankan proses ini sebelumnya", "apakah akun ini biasa login jam tiga pagi", "apakah domain ini baru pertama kali muncul di jaringan". Menjawabnya dengan search mentah ke 90 hari data setiap kali adalah pemborosan, dan sering tidak mungkin karena data mentah sudah frozen (Day 43).

Jawabannya adalah menyimpan hasil, bukan mengulang pekerjaan. Splunk memberi tiga wadah dengan sifat berbeda: summary index untuk agregat historis, lookup KV store untuk tabel keadaan yang diperbarui terus, dan metrics index untuk angka yang diambil berkala. Salah memilih wadah membuat solusi yang bekerja di lab tetapi tidak bertahan di produksi.

Day 39 memakai `rare` dan stacking untuk long tail, Day 26 memakai data model terakselerasi. Day ini melengkapi keduanya: bagaimana hasil hunt dan baseline tidak hilang ketika data mentahnya hilang.

**Kapan dipakai:** saat hunting butuh baseline berbulan-bulan; saat detection butuh konteks "pernah terlihat atau tidak"; saat tuning butuh allowlist yang sering berubah; saat dashboard operasional lambat karena menghitung ulang hal yang sama.

## 3. Konsep inti

### 3.1 Tiga wadah dan sifatnya

| Wadah | Isi | Diperbarui | Dibaca dengan | Cocok untuk |
|---|---|---|---|---|
| Summary index | Event agregat (hasil `stats` yang disimpan) | Ditambah oleh scheduled search | `search index=...`, `tstats` bila dipercepat | Baseline historis, laporan jangka panjang, metrik SOC |
| Lookup CSV | Tabel statis kecil | Diganti seluruhnya (`outputlookup`) | `lookup`, `inputlookup` | Daftar referensi yang jarang berubah |
| Lookup KV store | Tabel dengan baris ber-`_key` | Bisa ditambah atau diubah per baris | `lookup`, `inputlookup`, REST | First-seen, allowlist hidup, inventory |
| Metrics index | Pasangan nama metrik, nilai, dan dimensi | Ditulis oleh input metrics atau HEC | `mstats`, `mcatalog` | Angka berkala: EPS, CPU, jumlah agent |

Dua mekanisme percepatan yang berbeda dari summary index dan sering tertukar dengannya:

- **Report acceleration:** Splunk menyimpan sendiri summary untuk satu saved search yang memenuhi syarat. Tidak perlu menulis `collect`, tetapi kamu tidak memegang datanya.
- **Data model acceleration:** summary tsidx untuk seluruh data model, dipakai `tstats` (Day 26). Paling kuat untuk pencarian lebar, tetapi terikat pada struktur data model dan jendela akselerasi.

Aturan memilih yang cukup dipakai sehari-hari: butuh kecepatan untuk search lebar atas data CIM, pakai data model acceleration. Butuh menyimpan angka berbulan-bulan dengan bentuk yang kamu tentukan sendiri, pakai summary index. Butuh tabel keadaan yang berubah per baris, pakai KV store.

### 3.2 Summary index: `sistats` dan `collect`

Dua cara mengisi summary index:

```
# Cara 1: hasil stats biasa dikirim ke summary (sederhana, tetapi tidak bisa diagregasi ulang dengan benar)
index=lab_auth earliest=-1h@h latest=@h
| stats count AS login_count dc(src) AS src_count BY user
| collect index=summary_lab source="baseline_login_per_jam" marker="jenis=baseline_login"

# Cara 2: hasil si-command (bisa diagregasi ulang dengan benar)
index=lab_auth earliest=-1h@h latest=@h
| sistats count dc(src) BY user
| collect index=summary_lab source="si_baseline_login" marker="jenis=si_baseline_login"
```

Perbedaannya penting dan sering salah. `stats count` yang disimpan per jam tidak bisa dijumlahkan menjadi nilai harian untuk fungsi seperti `dc()` atau `avg()`, karena informasi antara sudah hilang. Command `sistats`, `sichart`, dan `sitimechart` menyimpan bentuk antara, sehingga hasilnya bisa diagregasi ulang [S1]:

```
index=summary_lab source="si_baseline_login" earliest=-30d
| stats count dc(src) BY user
```

Aturan praktis: bila summary hanya akan dibaca pada granularitas yang sama dengan saat disimpan, `stats` biasa cukup dan hasilnya lebih mudah dibaca manusia. Bila summary akan dijumlahkan ke periode lebih besar, pakai `sistats`.

Tiga disiplin wajib saat memakai `collect`:

1. **Rentang waktu rapi (snapped).** Pakai `earliest=-1h@h latest=@h`, bukan `-60m`. Tanpa snap, periode tumpang tindih atau bolong.
2. **Beri jeda terhadap ingest lag.** Bila p95 lag sourcetype itu 4 menit (Day 28 bagian 3.6), jalankan ringkasan jam 01:10 untuk periode 00:00 sampai 01:00, bukan tepat 01:00.
3. **Tandai asalnya.** `source` dan `marker` membuat satu summary index bisa menampung banyak jenis ringkasan tanpa saling tercampur, dan membuat pembersihan selektif mungkin.

Untuk mengisi periode yang sudah lewat, Splunk menyediakan skrip backfill (`fill_summary_index.py`) yang menjalankan saved search untuk rentang masa lalu [S1]. Jalankan dengan hati-hati: menjalankannya dua kali untuk periode yang sama menghasilkan data ganda.

### 3.3 Lookup KV store dan kekuatannya

Lookup CSV diganti seluruhnya setiap kali ditulis. Itu aman untuk daftar referensi, tetapi tidak cocok untuk tabel yang diperbarui terus oleh beberapa search, karena dua penulisan bersamaan bisa saling menimpa.

KV store menyimpan baris dalam koleksi (collection) dengan kunci unik `_key`. Dampaknya:

- `| outputlookup <lookup> append=true key_field=_key` memperbarui baris yang `_key`-nya sama dan menambah yang baru, bukan menimpa seluruh tabel.
- Baris bisa dihapus selektif lewat REST atau dengan menulis ulang hasil filter.
- Ukurannya jauh lebih nyaman daripada CSV besar, dan tidak perlu direplikasi sebagai file di search head cluster (Day 43 bagian 3.4).

Definisinya butuh dua bagian: koleksi di `collections.conf` dan definisi lookup di `transforms.conf`.

```
# collections.conf
[lab_first_seen]
field.entity = string
field.kind = string
field.first_seen = number
field.last_seen = number
field.count = number

# transforms.conf
[lab_first_seen_lookup]
external_type = kvstore
collection = lab_first_seen
fields_list = _key, entity, kind, first_seen, last_seen, count
```

Setelah itu `lab_first_seen_lookup` dipakai seperti lookup biasa di `lookup`, `inputlookup`, dan `outputlookup`.

### 3.4 Pola first-seen

First-seen adalah salah satu konteks paling berharga dan paling murah untuk investigasi. Pertanyaan yang dijawabnya: entitas ini (host, user, proses, domain, user agent) pertama kali terlihat kapan, dan apakah ia baru?

Pola yang dipakai:

1. Scheduled search setiap jam mengambil entitas yang muncul dalam satu jam terakhir.
2. Search itu menggabungkan dengan tabel KV store yang ada, menghitung `first_seen` sebagai nilai terkecil, dan menulis kembali dengan `append=true`.
3. Detection dan hunting membaca tabel itu untuk menandai entitas yang `first_seen`-nya lebih baru dari ambang tertentu.

Keunggulannya dibanding menghitung first-seen dari data mentah: tabelnya tetap benar walaupun data mentah sudah frozen, dan pencariannya instan karena hanya membaca satu tabel kecil.

### 3.5 Allowlist yang hidup

Masalah klasik tuning (Day 34, Day 36): setiap kali ada false positive, orang menambah `NOT` ke dalam search detection. Setelah enam bulan, detection berisi dua puluh pengecualian yang tidak ada yang tahu alasannya.

Pola yang lebih sehat: pengecualian disimpan sebagai baris di lookup KV store dengan metadata, dan detection memakai lookup itu lewat macro filter.

```
# transforms.conf
[lab_detection_exceptions_lookup]
external_type = kvstore
collection = lab_detection_exceptions
fields_list = _key, detection, entity, field_name, reason, owner, expires_at
```

Di dalam detection:

```
<search detection yang sebenarnya>
| lookup lab_detection_exceptions_lookup detection AS detection_name field_name AS match_field entity AS match_value OUTPUT reason expires_at
| where isnull(reason) OR expires_at < now()
```

Tiga kolom yang membuat perbedaan besar: `reason` (kenapa dikecualikan), `owner` (siapa yang memutuskan), dan `expires_at` (kapan ditinjau ulang). Pengecualian tanpa tanggal kedaluwarsa adalah lubang permanen yang akan terlupakan.

### 3.6 Metrics index dan `mstats`

Data metrics berbeda dari event: ia tidak punya teks, hanya nama metrik, nilai numerik, timestamp, dan dimensi. Karena itu penyimpanannya jauh lebih padat dan pencariannya lebih cepat untuk pertanyaan numerik [S2].

```
| mstats avg(_value) AS avg_eps WHERE index=lab_metrics metric_name="splunk.indexer.eps" span=5m BY host
```

```
| mcatalog values(metric_name) WHERE index=lab_metrics
```

Kapan metrics lebih tepat daripada event:

- Angka yang diambil berkala dan tidak butuh konteks teks: EPS, CPU, memori, jumlah agent yang aktif, panjang antrean.
- Dashboard operasional dengan rentang panjang (sebulan) dan granularitas kasar.

Kapan tetap pakai event: apa pun yang perlu diinvestigasi per kejadian. Metrics tidak bisa menjawab "siapa yang melakukannya", karena isinya bukan cerita, hanya angka.

### 3.7 Bagaimana summary dan lookup tercemar

Empat penyebab, semuanya pernah membuat baseline salah:

1. **Data terlambat.** Ringkasan jam 01:00 dijalankan tepat jam 01:00, lalu event jam 00:58 masuk jam 01:03. Angka jam itu kurang selamanya. Perbaikannya jeda jadwal.
2. **Jalan dua kali.** Backfill diulang, atau jadwal berubah dan periode tumpang tindih. Hasilnya angka ganda yang membuat baseline naik tanpa alasan.
3. **Baseline tercemar aktivitas penyerang.** Bila periode baseline memuat insiden, perilaku jahat menjadi "normal" (Day 39 bagian 7).
4. **Skema berubah.** Nama field di sumber berubah, summary lama memakai nama lama. Hasil gabungan menjadi setengah kosong tanpa error.

Mitigasi yang murah: simpan `source` dan `marker` yang jelas, jalankan pemeriksaan konsistensi berkala yang membandingkan summary dengan data mentah untuk periode yang masih tersedia, dan catat tanggal perubahan skema di catatanmu sendiri.

## 4. Contoh SPL dan langkah di ES

> Keluaran berlabel ilustrasi. Nama index, lookup, dan field mengikuti lab sendiri.

### 4.1 Baseline login per jam yang bertahan lama

**Tujuan:** menyimpan jumlah login per user per jam supaya bisa dipakai setahun ke depan, walaupun `index=lab_auth` hanya disimpan 90 hari.

Saved search, jadwal `12 * * * *` (jeda 12 menit untuk ingest lag):

```
index=lab_auth action=success earliest=-2h@h latest=-1h@h
| sistats count AS login_count dc(src) AS src_count BY user
| collect index=summary_lab source="si_baseline_login" marker="jenis=si_baseline_login,versi=1"
```

Membacanya kembali, untuk melihat pola jam kerja satu akun:

```
index=summary_lab source="si_baseline_login" earliest=-90d
| eval jam=strftime(_time,"%H")
| stats count AS login_count BY user jam
| eventstats avg(login_count) AS rata stdev(login_count) AS sd BY user
| eval z=round((login_count-rata)/sd,2)
| where z>3
| sort - z
```

Keluaran ilustrasi:

```
user    jam  login_count  rata   sd    z
svc_backup  03   48           2.10   1.90  24.15
alice       21   9            1.40   1.10  6.91
```

Cara membacanya: `svc_backup` biasanya tidak login jam 03, lalu tiba-tiba 48 kali. Ini sinyal hunting, bukan kesimpulan: akun service bisa saja memang dipindah jadwalnya. Langkah berikutnya memeriksa `src` dan proses yang mengikutinya.

**Variasi:** ganti `BY user` menjadi `BY user, src_category` setelah menambahkan lookup Asset and Identity (Day 26) supaya baseline terpisah antara workstation dan server.

**Kapan gagal:** bila `sistats` diganti `stats` saat menyimpan, kolom `dc(src)` tidak bisa dijumlahkan ulang dengan benar dan hasil 90 hari akan menyesatkan.

### 4.2 Mengisi periode yang sudah lewat

```
# dijalankan dari $SPLUNK_HOME/bin, di lab sendiri
splunk cmd python3 fill_summary_index.py -app search -name "Lab - baseline login per jam" \
  -et -30d@d -lt @d -dedup true -auth <user>:<password>
```

Opsi dedup penting: ia mencegah periode yang sudah ada diisi dua kali. Setelah backfill, selalu periksa jumlah per hari:

```
index=summary_lab source="si_baseline_login" earliest=-31d
| timechart span=1d count
```

Hari dengan jumlah dua kali lipat dari hari lain berarti ada duplikasi yang perlu dibersihkan sebelum baseline dipakai.

### 4.3 Tabel first-seen untuk proses per host

Saved search harian:

```
| tstats summariesonly=false count min(_time) AS first_min max(_time) AS last_max
    from datamodel=Endpoint.Processes where earliest=-1d@d latest=@d
    by Processes.dest Processes.process_name
| rename Processes.* AS *
| eval entity=dest.":".process_name, kind="proses_per_host"
| inputlookup append=true lab_first_seen_lookup where kind="proses_per_host"
| stats min(first_min) AS first_seen max(last_max) AS last_seen sum(count) AS count BY entity kind
| eval _key=entity
| outputlookup lab_first_seen_lookup append=true key_field=_key
```

Penjelasan tiap bagian:

- `tstats` mengambil proses per host untuk satu hari penuh dari data model terakselerasi (Day 25).
- `entity` dibentuk sebagai gabungan host dan nama proses, sehingga satu baris berarti satu kombinasi.
- `inputlookup append=true` menarik isi tabel lama sebagai baris tambahan, supaya `stats` berikutnya menggabungkan sejarah dengan hari ini.
- `min(first_min)` memastikan `first_seen` tidak pernah bergerak maju.
- `_key=entity` membuat penulisan bersifat upsert, bukan menambah baris ganda.

Memakainya saat investigasi:

```
| tstats summariesonly=false count from datamodel=Endpoint.Processes
    where earliest=-24h by Processes.dest Processes.process_name
| rename Processes.* AS *
| eval entity=dest.":".process_name
| lookup lab_first_seen_lookup entity OUTPUT first_seen count AS total_historis
| eval umur_hari=round((now()-first_seen)/86400,1)
| where isnull(first_seen) OR umur_hari<3
| table dest process_name count umur_hari total_historis
| sort umur_hari
```

Keluaran ilustrasi:

```
dest        process_name      count  umur_hari  total_historis
LAB-WS-02   rclone.exe        4      0.3        4
LAB-WS-05   7z.exe            12     2.1        34
```

Cara membacanya: `rclone.exe` baru pertama kali terlihat di seluruh lab. Itu bukan bukti exfiltration, tetapi layak diperiksa lebih dulu daripada `7z.exe` yang sudah lama ada. Ini cara memberi prioritas pada daftar panjang tanpa mengandalkan intuisi.

### 4.4 Allowlist dengan tanggal kedaluwarsa

Menambahkan satu pengecualian:

```
| makeresults
| eval detection="Lab - Proses dari folder user", field_name="process_path",
       entity="C:\\Users\\svc_deploy\\AppData\\Local\\Temp\\agent.exe",
       reason="Agent deployment resmi, tiket LAB-114", owner="dhika",
       expires_at=relative_time(now(),"+90d")
| eval _key=detection."|".entity
| table _key detection field_name entity reason owner expires_at
| outputlookup lab_detection_exceptions_lookup append=true key_field=_key
```

Meninjau pengecualian yang akan kedaluwarsa, dijadwalkan mingguan:

```
| inputlookup lab_detection_exceptions_lookup
| eval sisa_hari=round((expires_at-now())/86400,1)
| where sisa_hari<14
| table detection entity reason owner sisa_hari
| sort sisa_hari
```

Pola ini mengubah tuning dari pekerjaan sekali jalan menjadi daftar yang ditinjau. Tanpa `expires_at`, allowlist hanya bertambah.

### 4.5 Metrics untuk kesehatan lab

```
| mstats avg(_value) AS nilai WHERE index=lab_metrics metric_name IN ("splunk.indexer.queue.fill","splunk.indexer.eps") span=10m BY metric_name host
| timechart span=10m avg(nilai) BY metric_name
```

Bandingkan biaya pertanyaan yang sama bila disimpan sebagai event: untuk 30 hari data per 10 detik, metrics index biasanya jauh lebih kecil dan `mstats` jauh lebih cepat daripada `stats` atas event. Ukur sendiri di lab dengan Job Inspector (Day 14) supaya kamu punya angkanya.

### 4.6 Memeriksa summary masih benar

Dijadwalkan mingguan, selama data mentah masih ada:

```
index=lab_auth action=success earliest=-7d@d latest=@d
| stats count AS dari_mentah
| appendcols [ search index=summary_lab source="si_baseline_login" earliest=-7d@d latest=@d | stats count AS baris_summary ]
| eval catatan="bandingkan tren, bukan angka persis: summary menyimpan agregat"
```

Yang dicari bukan kesamaan angka, melainkan periode yang kosong atau ganda. Untuk itu lebih tajam memakai:

```
index=summary_lab source="si_baseline_login" earliest=-30d
| timechart span=1h count
| where count=0
```

Setiap jam yang kosong adalah ringkasan yang gagal, dan biasanya penyebabnya skipped search (Day 43 bagian 3.6).

## 5. Lab praktik

**Prasyarat:** Splunk lab dengan data autentikasi dan proses (Day 23 sampai Day 24), izin membuat index dan lookup, serta akses `index=_internal`.

1. Buat index `summary_lab` dan koleksi KV store `lab_first_seen` serta `lab_detection_exceptions` sesuai bagian 3.3 dan 3.5.
2. Buat dua saved search pengisi baseline: satu memakai `stats`, satu memakai `sistats`, keduanya untuk jam yang sama. Jalankan seminggu (atau backfill 7 hari), lalu coba hitung `dc(src)` 7 hari dari keduanya. Catat perbedaannya dan simpan sebagai bukti kenapa `sistats` dipakai.
3. Sengaja jalankan ringkasan tanpa jeda (`latest=now()`), lalu bandingkan angkanya dengan versi berjeda 12 menit untuk jam yang sama. Catat berapa event yang hilang akibat ingest lag.
4. Bangun tabel first-seen proses per host (bagian 4.3). Jalankan tiga hari berturut-turut, lalu buktikan `first_seen` tidak bergeser maju untuk entitas lama.
5. Jalankan satu proses baru yang jinak di VM lab (misalnya `7z.exe` versi portable), lalu buktikan ia muncul sebagai entitas baru di search investigasi bagian 4.3.
6. Tambahkan dua pengecualian ke `lab_detection_exceptions`, salah satunya dengan `expires_at` di masa lalu. Pasang lookup itu ke satu detection lab dan buktikan pengecualian kedaluwarsa tidak lagi menyembunyikan alert.
7. Buat metrics index lab dan kirim beberapa metrik sederhana (bisa dari input yang tersedia di instance-mu), lalu bandingkan kecepatan `mstats` dengan `stats` atas event untuk pertanyaan yang sama. Simpan angka Job Inspector keduanya.
8. Jalankan pemeriksaan jam kosong (bagian 4.6) dan hubungkan setiap lubang dengan catatan scheduler.

**Hasil yang sebaiknya tersimpan:**
- Perbandingan `stats` dan `sistats` untuk `dc()` 7 hari.
- Angka event yang hilang karena ringkasan tanpa jeda.
- Tabel first-seen lab-mu dan satu contoh temuan proses baru.
- Satu detection yang memakai lookup pengecualian, beserta isi tabel pengecualiannya.
- Perbandingan Job Inspector `mstats` dan `stats`.

## 6. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa |
|---|---|---|
| Summary kosong untuk sebagian jam | Scheduled search skipped, atau rentang tidak snapped | `index=_internal sourcetype=scheduler savedsearch_name=*baseline*`; cek `earliest`/`latest` |
| Angka summary dua kali lipat | Backfill diulang, atau dua saved search menulis `source` sama | `timechart span=1h count` di summary; cek daftar saved search |
| `dc()` dari summary tidak masuk akal | Disimpan dengan `stats`, bukan `sistats` | Lihat field di event summary; `sistats` menghasilkan field berawalan `psrsvd` |
| `outputlookup append=true` menambah baris ganda | `key_field` tidak diset atau `_key` tidak unik | `\| inputlookup <lookup> \| stats count BY entity \| where count>1` |
| Lookup KV store tidak bisa ditulis | Tipe field di `collections.conf` tidak cocok, atau izin app | Coba tulis satu baris dengan `makeresults`; cek `index=_internal` untuk error KV store |
| `mstats` mengembalikan kosong | Nama metrik salah, atau data masuk sebagai event, bukan metrics | `\| mcatalog values(metric_name) WHERE index=<idx>` |
| Lookup lambat dipakai di detection | Tabel terlalu besar untuk dipakai per event | Pindahkan filter sebelum `lookup`; pertimbangkan `inputlookup` dengan `stats` (Day 12) |
| Baseline menganggap aktivitas jahat normal | Periode baseline memuat insiden | Bandingkan dengan periode lain; kecualikan rentang insiden saat membangun baseline |

## 7. Kesalahan umum dan jebakan

- Memakai `stats` saat menyimpan summary yang nantinya akan diagregasi ulang.
- Menjadwalkan ringkasan tepat di batas jam tanpa jeda untuk ingest lag.
- Memakai rentang relatif tanpa snap (`-60m`), sehingga periode tumpang tindih atau bolong.
- Menulis ulang seluruh lookup CSV dari dua search berbeda, sehingga saling menimpa.
- Membuat allowlist tanpa `reason`, `owner`, dan `expires_at`.
- Menyimpan data yang perlu diinvestigasi per kejadian ke metrics index, lalu kehilangan konteksnya.
- Menganggap first-seen sebagai bukti kejahatan. Ia hanya alat prioritas.
- Lupa bahwa summary index juga punya retensi. Index yang dibuat untuk jangka panjang perlu `frozenTimePeriodInSecs` yang sesuai (Day 43).

## 8. Catatan terkini

- Summary indexing, `collect`, dan si-command adalah bagian lama SPL yang stabil. Yang berubah adalah tren pemakaiannya: untuk data CIM, data model acceleration lebih sering dipilih, dan summary index dipakai untuk hal yang bentuknya tidak pas di data model (metrik SOC, baseline khusus, hasil hunt).
- KV store berbasis MongoDB internal di Splunk Enterprise, dan versi engine-nya pernah berubah antar rilis mayor. Kalau instance lab tidak bisa memulai KV store setelah upgrade, itu area pertama yang dicek di `index=_internal`.
- Metrics index dan `mstats` terus berkembang, termasuk dukungan histogram dan integrasi OpenTelemetry di sisi observability Splunk. Cek ketersediaan fitur di versi yang kamu pakai bila ingin memakai tipe metrik selain gauge dan counter sederhana.
- Di ES 8, pendekatan menyimpan konteks juga tersedia lewat Asset and Identity framework (Day 26) dan threat list (Day 33). Untuk konteks yang bersifat keamanan dan dipakai banyak detection, dua mekanisme ES itu lebih rapi daripada lookup buatan sendiri.

## 9. Cheat sheet

```
PILIH   search lebar atas CIM -> data model acceleration (tstats, Day 26)
        agregat historis bentuk sendiri -> summary index (collect/sistats)
        tabel keadaan per baris -> lookup KV store (outputlookup append=true key_field=_key)
        angka berkala tanpa konteks -> metrics index (mstats/mcatalog)
SUMMARY | sistats count dc(x) BY y | collect index=summary_lab source="nama" marker="jenis=..."
        rentang snapped (-2h@h sampai -1h@h) + jeda jadwal >= p95 ingest lag
BACKFILL fill_summary_index.py -name "<saved search>" -et -30d@d -lt @d -dedup true
KVSTORE collections.conf (field.<nama> = string|number|bool) + transforms.conf (external_type=kvstore)
FIRSTSEEN tstats -> eval entity -> inputlookup append=true -> stats min(first)/max(last) -> outputlookup append=true
ALLOWLIST kolom wajib: detection, entity, reason, owner, expires_at ; filter: where isnull(reason) OR expires_at<now()
METRICS | mstats avg(_value) WHERE index=X metric_name="a.b.c" span=5m BY host   |   | mcatalog values(metric_name)
PERIKSA  summary: timechart span=1h count | where count=0   ;   lookup: stats count BY entity | where count>1
```

## 10. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Knowledge Manager Manual: "Use summary indexing for increased search efficiency", "Manage summary index gaps", skrip `fill_summary_index.py` | https://help.splunk.com/en/splunk-enterprise | primer | judul halaman dirujuk 2026-10-09 | Tinggi untuk konsep dan nama command. URL menunjuk ke situs dokumentasi; cari halaman dari judulnya |
| S2 | Metrics Manual dan SPL Search Reference: `mstats`, `mcatalog`, format metrics index | https://help.splunk.com/en/splunk-enterprise | primer | judul halaman dirujuk 2026-10-09 | Tinggi untuk konsep; dukungan tipe metrik bergantung versi |
| S3 | Knowledge Manager Manual: "About lookups", "Configure KV store lookups", spesifikasi `collections.conf` dan `transforms.conf` | https://help.splunk.com/en/splunk-enterprise | primer | judul halaman dirujuk 2026-10-09 | Tinggi untuk nama setting KV store |
| S4 | Splunk-Notes Day 25 (`tstats`), Day 12 (`lookup`, `inputlookup`, `makeresults`), Day 26 (acceleration, Asset and Identity), Day 39 (baseline dan outlier), Day 28 (ingest lag), Day 43 (scheduler dan retensi) | (lokal) | rujukan internal | 2026-10-09 | Keterkaitan antar Day |

**Catatan sumber:** nama field internal yang dihasilkan si-command (berawalan `psrsvd`) dan opsi persis `fill_summary_index.py` perlu dicek di versi yang kamu pakai. Perilaku `outputlookup append=true` dengan `key_field` sudah lama stabil, tetapi tetap diuji dulu di lab karena kesalahan di sini menghasilkan baris ganda yang sulit ditelusuri.
