---
day: 43
title: 'Arsitektur dan operasi Splunk: komponen, bucket dan retensi, cluster, biaya ingest, dan scheduler'
researched_on: 2026-10-10
versions_checked: 'Splunk Enterprise 10.6 (Distributed Deployment, Managing Indexers and Clusters of Indexers, Monitoring Splunk Enterprise, indexes.conf dan limits.conf spec); rujukan Day 14, 26, 27, 28, 36'
---

# Day 43: Arsitektur dan operasi Splunk yang perlu diketahui analyst

Cakupan: peran tiap komponen Splunk, siklus hidup bucket dan cara menghitung retensi, apa yang berubah ketika indexer dan search head dibuat cluster, dari mana biaya ingest datang, dan cara membaca scheduler supaya detection-mu tidak terlewat.

## Ide inti

Semua pekerjaan sebelum Day ini bertumpu pada tiga asumsi yang hampir tidak pernah diperiksa: data yang kamu cari benar-benar ada, search terjadwal benar-benar berjalan, dan hasil yang kembali benar-benar lengkap. Begitu salah satu asumsi itu runtuh, SPL yang paling rapi, data model yang paling bersih, dan detection yang paling matang tetap menghasilkan kesimpulan yang salah tanpa satu pesan error pun. Arsitektur sering dianggap urusan tim platform, padahal tiga kejadian berikut sepenuhnya terasa sebagai masalah analyst: detection penting tidak pernah fire selama tiga hari karena scheduler melewatkannya (skipped) dan bukan karena logikanya salah; hunting enam bulan ke belakang kosong karena retensi index itu hanya 90 hari; dan hasil search terlihat wajar tetapi sebenarnya tidak lengkap karena satu indexer sedang tidak tersambung. Ketiganya tidak bisa didiagnosis dari SPL saja.

Day ini memberi kosakata dan angka minimum supaya kamu bisa membedakan "deteksi saya salah" dari "platformnya sedang tidak sehat", dan supaya permintaanmu ke tim platform berbentuk angka, bukan keluhan. Di PT Jaringan Anak Bangsa (PT JAB, ISP menengah fiktif), Splunk Enterprise berjalan terdistribusi: dua search head (satu khusus ES), indexer cluster tiga node, heavy forwarder untuk syslog dan API cloud, serta deployment server. Ingest ilustrasinya sekitar 94 GB per hari dengan `dns` sebagai penyumbang terbesar sekitar 42 GB, jadi setiap percakapan tentang retensi dan biaya di sana selalu berakhir di index yang sama. Yang perlu kamu bisa jawab bukan cara mengelola semuanya, melainkan satu pertanyaan yang muncul di hampir setiap investigasi: apakah rentang waktu yang kamu klaim benar-benar tercakup, dan apa buktinya.

Dua analoginya sudah kamu pakai di NOC. Forwarder, indexer, dan search head adalah agen kolektor, server penyimpan, dan konsol query. Batasnya, satu instance bisa memegang beberapa peran sekaligus di lab sementara di produksi peran itu dipisah, sehingga "Splunk mati" hampir selalu berarti satu peran tertentu yang mati, dan gejalanya berbeda tergantung peran mana. Bucket dan retensi adalah rotasi file log di server syslog: hot, warm, cold, lalu frozen. Batasnya, data yang sudah frozen hilang dari pencarian kecuali sengaja diarsipkan, dan retensi diatur per index dan bukan satu kebijakan untuk seluruh deployment, jadi dua index di mesin yang sama bisa punya batas hunting yang jauh berbeda.

**Kapan relevan:** saat merancang lab sendiri; saat hunting menyentuh data lama; saat detection terjadwal tidak menghasilkan finding; saat ada tekanan menurunkan biaya ingest; saat hasil search terasa tidak konsisten antar percobaan; dan saat menulis bagian keterbatasan data di laporan investigasi.
**Kapan bukan jawaban:** pengetahuan arsitektur tidak memperbaiki logika deteksi yang keliru atau search yang ditulis boros, dan itu urusan Day 14. Ia juga tidak menambah cakupan sumber data yang memang belum pernah di-onboard (Day 27 dan Day 28), dan bukan izin menyentuh konfigurasi produksi: `indexes.conf` dan `limits.conf` tetap milik tim platform, sedangkan yang kamu bawa ke mereka adalah angka dan pertanyaan yang spesifik.

## 1. Konsep inti

### 1.1 Komponen dan akibat bila mati

| Komponen | Tugas | Bila mati atau salah konfigurasi |
|---|---|---|
| Universal forwarder (UF) | Membaca log di endpoint dan mengirim, tanpa parsing | Data satu host berhenti. Deteksi untuk host itu buta, tanpa alert apa pun |
| Heavy forwarder (HF) | Parsing, masking, routing, menjalankan modular input (API cloud) | Semua data yang lewat berhenti atau masuk tanpa parsing (Day 28) |
| Indexer | Menyimpan raw dan tsidx, menjalankan bagian search yang paralel | Sebagian data tidak bisa dicari; hasil search bisa tidak lengkap |
| Search head | Menjalankan search, menyimpan knowledge object, menjalankan scheduler | Semua search dan scheduled search berhenti |
| Manager node (cluster manager) | Mengatur replikasi bucket dan daftar peer | Replikasi tidak diperbaiki; search tetap jalan sementara |
| Deployment server | Mendistribusikan app dan konfigurasi ke forwarder | Perubahan konfigurasi tidak sampai ke endpoint |
| License manager | Mengelola kuota ingest | Peringatan pelanggaran lisensi; search bisa dibatasi bila berulang |
| Monitoring Console (MC) | Dashboard kesehatan platform | Kamu kehilangan alat diagnosis, bukan datanya |
| Deployer (untuk SHC) | Mendistribusikan app ke anggota search head cluster | App tidak seragam antar anggota |

Satu kebiasaan yang bagus: tahu jawaban pertanyaan "di deployment ini, data X masuk lewat jalur mana?" untuk tiga sumber paling penting di tempatmu. Jalurnya menentukan di mana kamu mencari saat data berhenti.

### 1.2 Bucket, retensi, dan hitungan disk

Data di sebuah index tersimpan dalam bucket yang bergerak melalui empat keadaan [S1]:

| Keadaan | Lokasi konfigurasi | Catatan |
|---|---|---|
| hot | `homePath` | Sedang ditulis. Jumlahnya dibatasi `maxHotBuckets` |
| warm | `homePath` | Sudah ditutup, masih di penyimpanan cepat |
| cold | `coldPath` | Dipindah saat `homePath` penuh (`maxDataSizeMB` atau jumlah bucket) |
| frozen | dibuang, atau diarsipkan ke `coldToFrozenDir` | Keluar dari pencarian. Default Splunk adalah menghapus |

Tiga setting yang menentukan retensi di `indexes.conf`:

```
[idx_security]
homePath   = $SPLUNK_DB/idx_security/db
coldPath   = $SPLUNK_DB/idx_security/colddb
thawedPath = $SPLUNK_DB/idx_security/thaweddb
frozenTimePeriodInSecs = 31536000          # 365 hari
maxTotalDataSizeMB     = 2000000           # batas ukuran total index
coldToFrozenDir        = /arsip/idx_security
```

Yang sering disalahpahami: bucket menjadi frozen karena **mana yang tercapai lebih dulu**, usia (`frozenTimePeriodInSecs`) atau ukuran (`maxTotalDataSizeMB`). Index dengan retensi 365 hari tetapi batas ukuran kecil akan membuang data jauh sebelum setahun. Itu alasan hunting "setahun ke belakang" kadang kosong padahal kebijakan tertulis mengatakan setahun.

Hitungan kasar yang cukup untuk perencanaan lab dan untuk mengajukan permintaan:

```
Disk per hari  = volume harian x (rasio raw terkompresi + rasio tsidx)
Pendekatan umum: raw ~15% dan index ~35% dari volume asli, jadi total ~50%
Contoh: 50 GB/hari ingest  -> ~25 GB/hari di disk
Retensi 180 hari          -> ~4,5 TB per salinan
Replication factor 2      -> ~9 TB total (raw tersalin; tsidx tergantung search factor)
```

Angka 15 dan 35 persen itu pendekatan yang dipakai luas di komunitas, bukan jaminan. Untuk data yang sangat berulang (log firewall) kompresi lebih baik; untuk JSON dengan banyak field unik, tsidx bisa jauh lebih besar. Ukur sendiri dengan `dbinspect` sebelum memesan disk.

### 1.3 Indexer cluster: replication factor dan search factor

Dua angka yang perlu kamu pahami [S2]:

- **Replication factor (RF):** berapa salinan raw data disimpan di peer berbeda. RF 3 berarti kehilangan dua indexer masih aman.
- **Search factor (SF):** berapa salinan yang juga punya tsidx sehingga bisa langsung dicari. SF selalu lebih kecil atau sama dengan RF. SF 1 dengan RF 3 berarti data tetap selamat, tetapi bila peer yang punya tsidx mati, cluster harus membangun ulang tsidx sebelum data itu bisa dicari lagi.

Yang kamu lihat sebagai analyst ketika cluster tidak sehat: pesan hasil mungkin tidak lengkap, jumlah event yang berbeda antara dua kali menjalankan search yang sama, dan di MC status bucket `fixup tasks pending`. Dalam keadaan itu, jangan menarik kesimpulan "tidak ada bukti". Ketiadaan hasil hanya bermakna bila platform sehat dan rentang waktu benar-benar tercakup.

Untuk deployment multi-site, ada setting site-aware (`site_replication_factor`, `site_search_factor`). Efek praktisnya: search bisa dilayani dari site terdekat, dan kegagalan satu site tidak mematikan pencarian. Detailnya urusan platform, tetapi istilahnya perlu kamu kenali saat membaca runbook.

### 1.4 Search head cluster dan knowledge object

Di search head cluster (SHC), satu anggota menjadi captain. Captain mengatur penjadwalan dan replikasi knowledge object antar anggota. Dampak praktis untuk analyst:

- Saved search, dashboard, lookup kecil, dan macro yang kamu buat akan direplikasi ke semua anggota. Jadi jangan heran bila objek muncul di anggota lain.
- Lookup besar (puluhan MB) lebih baik di-deploy sebagai app lewat deployer, bukan diunggah lewat UI, supaya tidak membebani replikasi.
- Penjadwalan didelegasikan captain, sehingga "kenapa search saya jalan di anggota lain" adalah hal normal.
- Permission knowledge object (private, app, global) adalah penyebab paling umum dari "dashboard saya kosong di akun lain".

### 1.5 Dari mana biaya datang

Model lisensi Splunk berkembang, tetapi dua pertanyaan yang menentukan biaya tetap sama: berapa banyak data yang masuk, dan berapa besar beban komputasi search. Model berbasis volume ingest harian masih yang paling umum di Enterprise, sementara Cloud juga menawarkan model berbasis workload. Yang perlu kamu cek di kontrak tempatmu: apakah dihitung dari volume ingest harian, dari kapasitas komputasi, atau kombinasi, karena itu menentukan optimasi yang masuk akal [S3].

Tiga cara menurunkan biaya tanpa mengorbankan deteksi, dari yang paling aman:

1. **Buang yang jelas tidak bernilai forensik** (health check, debug noise) dengan `nullQueue` di tempat parsing (Day 28 bagian 1.5).
2. **Pisahkan retensi.** Data volume besar dengan nilai investigasi jangka pendek (misalnya proxy) bisa diberi retensi lebih pendek di index sendiri, bukan dibuang.
3. **Turunkan di sumber.** Verbositas aplikasi dan audit policy Windows yang terlalu luas sering menyumbang puluhan persen volume tanpa menambah deteksi apa pun (Day 21).

Yang perlu dihindari: memangkas sumber yang justru menopang banyak deteksi (process creation, autentikasi, DNS). Hitungannya bukan gigabyte per rupiah, tetapi gigabyte per deteksi yang masih jalan. Day 27 memberi cara memetakan sumber data ke konten deteksi, dan itulah dasar argumen yang sehat saat ada tekanan memangkas.

### 1.6 Scheduler: skipped, deferred, dan concurrency

Setiap search head punya batas jumlah search bersamaan. Batas itu dihitung dari jumlah CPU dengan rumus di `limits.conf`, dan dibagi antara search ad hoc dan scheduled search. Ketika kuota penuh, scheduler punya dua pilihan: menunda (deferred) atau melewatkan (skipped) [S4].

Yang menentukan apakah sebuah detection bertahan saat platform sibuk:

- **Jadwal yang berjejal.** Banyak detection dijadwalkan pada menit 0 setiap jam. Pakai cron yang disebar (`3,33 * * * *`) atau `schedule_window` supaya scheduler boleh menggeser.
- **Durasi lebih panjang daripada interval.** Search 9 menit dengan jadwal 5 menit pasti menumpuk (Day 14).
- **Prioritas.** Real-time schedule mengunci slot; continuous schedule memakai antrean yang lebih sopan terhadap platform.
- **Search yang mahal milik orang lain.** Satu dashboard dengan sepuluh panel `index=*` bisa menghabiskan kuota untuk semua orang.

Kebiasaan yang layak dipasang sejak awal: satu alert yang memantau skipped search. Detection yang tidak jalan adalah kegagalan yang sunyi, dan satu-satunya jejaknya ada di `index=_internal`.

### 1.7 Mengenali hasil yang tidak lengkap

Empat tanda bahwa hasil search tidak boleh dipercaya penuh:

1. Peringatan hasil mungkin tidak lengkap di UI, atau pesan tentang peer yang tidak tersambung.
2. `scanCount` jauh lebih kecil daripada biasanya untuk rentang waktu yang sama (Job Inspector, Day 14).
3. Rentang waktu melewati batas retensi index (bagian 1.2).
4. Search memakai data model terakselerasi dengan `summariesonly=true` padahal summary belum selesai dibangun (Day 26).

Dalam laporan investigasi, keempat hal ini masuk ke bagian keterbatasan. Menulis "tidak ditemukan bukti X" tanpa memastikan cakupan data adalah kesalahan analitis yang bisa dihindari dengan satu menit pengecekan.

## 2. Contoh perintah dan search operasional

> Keluaran berlabel ilustrasi. Semua dijalankan di instance lab sendiri. Beberapa search memerlukan izin ke index internal.

### 2.1 Melihat kondisi index dan bucket

```
| dbinspect index=idx_security
| stats count AS buckets sum(sizeOnDiskMB) AS disk_mb min(startEpoch) AS oldest max(endEpoch) AS newest BY state
| eval oldest=strftime(oldest,"%F"), newest=strftime(newest,"%F")
```

Keluaran ilustrasi:

```
state  buckets  disk_mb    oldest      newest
hot    2        1840.22    2026-10-05  2026-10-09
warm   148      142300.51  2026-04-12  2026-10-05
cold   96       98120.08   2025-11-02  2026-04-12
```

Cara membacanya: tanggal `oldest` di cold adalah batas nyata hunting-mu di index itu, apa pun yang tertulis di kebijakan. Bandingkan dengan `frozenTimePeriodInSecs` untuk melihat apakah data dibuang karena usia atau karena ukuran.

**Variasi:** tambahkan `BY index` tanpa filter untuk membuat peta retensi nyata seluruh deployment lab. Simpan hasilnya, karena ini salah satu tabel yang paling sering kamu butuhkan saat merencanakan hunt.

**Kapan gagal:** `dbinspect` membutuhkan izin dan bisa berat pada deployment besar. Batasi per index.

### 2.2 Menemukan scheduled search yang terlewat

```
index=_internal sourcetype=scheduler earliest=-7d
| stats count BY status savedsearch_name
| where status!="success"
| sort - count
| head 20
```

Keluaran ilustrasi:

```
status     savedsearch_name                            count
skipped    Lab - Brute force lalu sukses               118
deferred   Lab - Proses mencurigakan dari folder user   34
continued  Lab - Baseline login per jam                 6
```

Cara membacanya: `skipped` berarti eksekusi itu hilang selamanya, bukan tertunda. Angka 118 dalam seminggu berarti deteksi itu praktis tidak berjalan. Untuk setiap nama yang muncul, periksa durasi rata-ratanya:

```
index=_internal sourcetype=scheduler savedsearch_name="Lab - Brute force lalu sukses" earliest=-7d
| stats avg(run_time) AS avg_sec max(run_time) AS max_sec avg(dispatch_time) AS avg_dispatch BY savedsearch_name
```

Bila `avg_sec` mendekati atau melebihi interval jadwalnya, perbaikannya ada di search (Day 14), bukan di jadwal.

### 2.3 Melihat beban search dan siapa penyumbangnya

```
index=_audit action=search info=completed earliest=-24h
| eval total_run_time=round(total_run_time,1)
| stats count AS jumlah sum(total_run_time) AS total_detik avg(total_run_time) AS rata BY user search_type
| sort - total_detik
| head 15
```

Search ini memakai audit log, jadi ia menunjukkan konsumsi nyata per user dan per tipe (ad hoc atau scheduled). Di lab sendiri hasilnya mungkin membosankan, tetapi polanya sama dengan di produksi: beberapa search menghabiskan sebagian besar waktu komputasi.

Monitoring Console menyediakan versi siap pakainya di dashboard Search Activity dan Scheduler Activity [S5]. Pakai MC lebih dulu, dan pakai search manual ketika kamu perlu memotong data dengan cara yang tidak disediakan dashboard.

### 2.4 Mengukur volume ingest per index dan sourcetype

```
index=_internal source=*license_usage.log* type=Usage earliest=-30d
| eval GB=b/1024/1024/1024
| timechart span=1d sum(GB) BY idx limit=10 useother=t
```

Lalu versi tabel untuk mengambil keputusan:

```
index=_internal source=*license_usage.log* type=Usage earliest=-30d
| stats sum(b) AS bytes BY idx st
| eval GB_per_hari=round(bytes/1024/1024/1024/30,2)
| sort - GB_per_hari
| head 20
```

**Cara memakainya:** gabungkan kolom `GB_per_hari` dengan jumlah detection aktif yang bergantung pada sourcetype itu (Day 27). Sourcetype mahal yang tidak menopang deteksi apa pun adalah kandidat pertama untuk retensi lebih pendek atau pemangkasan di sumber.

### 2.5 Memeriksa kesehatan cluster dari search

```
| rest /services/cluster/manager/indexes
| table title, is_searchable, searchable_copies_tracker, replicated_copies_tracker
| head 20
```

```
| rest /services/cluster/manager/peers
| table label, status, site, is_searchable, bucket_count
```

Nama endpoint REST untuk cluster berubah antar versi (istilah master diganti manager), jadi cek nama persisnya di versi yang kamu pakai bila perintah ini mengembalikan kosong. Alternatif yang lebih stabil: dashboard Indexer Clustering di Monitoring Console.

### 2.6 Membuktikan cakupan data sebelum menyimpulkan

Pola tiga langkah yang layak dijadikan kebiasaan sebelum menulis "tidak ada bukti":

```
| tstats count where index=idx_security earliest=-180d by _time span=1d
| where count=0
```

```
| dbinspect index=idx_security | stats min(startEpoch) AS oldest | eval oldest=strftime(oldest,"%F")
```

```
index=_internal sourcetype=splunkd component=TcpInputProc earliest=-7d
| stats count BY log_level
```

Yang pertama memperlihatkan hari tanpa data sama sekali, yang kedua memperlihatkan batas retensi nyata, yang ketiga memperlihatkan masalah input. Bila salah satu memberi kejutan, kalimat di laporanmu berubah dari "tidak ada aktivitas" menjadi "tidak ada data untuk rentang tersebut".

## 3. Lab praktik

**Prasyarat:** instance Splunk lab (satu mesin cukup), akses ke `index=_internal` dan `index=_audit`, serta beberapa index berisi data dari Day sebelumnya.

1. Buat peta retensi nyata lab-mu: jalankan `dbinspect` per index, catat tanggal tertua per index, dan bandingkan dengan `frozenTimePeriodInSecs` serta `maxTotalDataSizeMB` di `indexes.conf`.
2. Hitung rasio disk terhadap volume ingest untuk satu index: bandingkan `sum(b)` dari license usage selama 7 hari dengan `sizeOnDiskMB` dari `dbinspect`. Bandingkan dengan pendekatan 50 persen di bagian 1.2 dan catat selisihnya.
3. Buat index uji dengan `frozenTimePeriodInSecs` sangat kecil (misalnya 600 detik) dan `maxTotalDataSizeMB` kecil, kirim data uji, lalu amati bucket berpindah dan hilang. Ini melatih mengenali gejala data terbuang lebih cepat daripada kebijakan.
4. Buat tiga scheduled search yang semuanya dijadwalkan pada menit 0 dan masing-masing berdurasi lebih dari satu menit. Amati `index=_internal sourcetype=scheduler` untuk melihat deferred atau skipped muncul.
5. Perbaiki ketiganya: sebar cron, tambahkan `schedule_window`, lalu perbaiki search terburuk dengan teknik Day 14. Ukur ulang dan simpan perbandingan angkanya.
6. Buat satu alert yang memantau skipped search (`index=_internal sourcetype=scheduler status=skipped`) dengan ambang yang masuk akal, lalu uji dengan sengaja membuat search yang terlalu berat.
7. Ukur volume ingest per sourcetype selama 30 hari, lalu tulis satu paragraf keputusan: mana yang dipangkas, mana yang dipindah retensinya, mana yang tidak boleh disentuh, dan alasannya dalam bahasa deteksi.
8. Jalankan tiga search pembuktian cakupan di bagian 2.6 untuk satu index, lalu tulis satu kalimat keterbatasan data seperti yang akan kamu tulis di laporan investigasi.

**Hasil yang sebaiknya tersimpan:**
- Tabel retensi nyata per index lab (tanggal tertua, ukuran, state bucket).
- Angka rasio disk banding ingest milik lab-mu sendiri.
- Sebelum dan sesudah untuk skipped search, dengan jumlah skip per hari.
- Definisi alert pemantau scheduler.
- Satu paragraf keputusan biaya ingest beserta alasan deteksinya.

## 4. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa |
|---|---|---|
| Hunting data lama kosong | Bucket sudah frozen karena usia atau ukuran | `dbinspect` untuk tanggal tertua; cek `frozenTimePeriodInSecs` dan `maxTotalDataSizeMB` |
| Detection tidak pernah fire | Scheduled search skipped, bukan logika salah | `index=_internal sourcetype=scheduler status=skipped savedsearch_name=*` |
| Jumlah event berbeda tiap kali search | Peer indexer tidak tersambung atau bucket sedang fixup | MC dashboard Indexer Clustering; `\| rest /services/cluster/manager/peers` |
| Search lambat hanya pada jam tertentu | Jadwal berjejal, kuota concurrency penuh | MC Scheduler Activity; `index=_audit action=search info=completed` per jam |
| Data satu host berhenti | UF mati, disk endpoint penuh, atau file log dirotasi dengan cara yang membingungkan monitor | `index=_internal sourcetype=splunkd host=<host>`; cek `\| metadata type=hosts index=<idx>` |
| Lisensi terlampaui | Sourcetype baru atau debug logging aktif | `index=_internal source=*license_usage.log* type=Usage` dibandingkan minggu sebelumnya |
| Dashboard kosong untuk akun lain | Permission knowledge object masih private | Cek sharing objek; untuk SHC pastikan sudah direplikasi |
| `summariesonly=true` mengembalikan sedikit data | Acceleration belum selesai atau rentangnya di luar jendela summary | Dashboard acceleration data model (Day 26) |

## 5. Kesalahan umum dan jebakan

- Menyimpulkan "tidak ada bukti" tanpa memeriksa retensi dan kesehatan cluster.
- Mengira retensi hanya diatur waktu, padahal batas ukuran sering memotong lebih dulu.
- Menjadwalkan semua detection pada menit 0 setiap jam, lalu bingung melihat skipped.
- Memakai real-time schedule untuk detection yang tidak membutuhkannya, sehingga slot search terkunci.
- Mengunggah lookup besar lewat UI di lingkungan search head cluster.
- Menilai efisiensi biaya dari gigabyte saja, tanpa menghitung deteksi yang hilang bila sumber dipangkas.
- Mengandalkan satu alert tanpa memantau apakah alert itu sendiri berjalan.
- Menyalin angka kompresi 15 dan 35 persen sebagai kebenaran, tanpa mengukur data sendiri.

## 6. Catatan terkini

- Istilah cluster master diganti menjadi cluster manager, dan sebagian endpoint REST serta dokumentasi memakai nama baru sementara konfigurasi lama masih diterima. Cek nama yang dipakai versi-mu sebelum menyalin perintah `| rest`.
- Model harga Splunk mencakup opsi berbasis volume ingest dan berbasis workload, dan untuk Cloud ada pilihan penyimpanan arsip yang lebih murah dengan akses lebih lambat. Yang berlaku untuk tempatmu ada di kontrak, jadi jangan berasumsi dari blog.
- Untuk pencarian ke data arsip atau ke objek penyimpanan eksternal, Splunk punya fitur federated dan arsip terkelola yang detail dan batasannya berubah cepat. Perlu dicek langsung di dokumentasi versi yang kamu pakai bila kebutuhannya muncul.
- Monitoring Console tetap titik awal diagnosis di Enterprise. Di Cloud, sebagian dashboard digantikan Cloud Monitoring Console dengan metrik yang berbeda.

## 7. Cheat sheet

```
KOMPONEN  UF (kirim) | HF (parsing, modular input) | indexer (simpan+search) | SH (search, scheduler) | manager node | deployment server | license manager | MC | deployer (SHC)
BUCKET    hot -> warm (homePath) -> cold (coldPath) -> frozen (dibuang / coldToFrozenDir)
RETENSI   frozenTimePeriodInSecs ATAU maxTotalDataSizeMB, mana yang tercapai lebih dulu
DISK      ~ volume x 50% (raw ~15% + tsidx ~35%)  x retensi x salinan   (ukur sendiri!)
CLUSTER   RF = salinan raw | SF = salinan yang bisa dicari | SF <= RF | fixup = sedang diperbaiki
SHC       captain atur jadwal + replikasi KO ; lookup besar lewat deployer
SCHEDULER success | deferred (tertunda) | skipped (hilang) | continued
PERBAIKAN sebar cron, schedule_window, perbaiki search (Day 14), hindari real-time tanpa alasan
BIAYA     license_usage.log type=Usage -> GB per idx/st ; pangkas noise, pisah retensi, turunkan di sumber
CEK DATA  | dbinspect index=X  |  | tstats count by _time span=1d  |  index=_internal sourcetype=scheduler
LAPORAN   sebut cakupan: rentang retensi, kesehatan cluster, status acceleration
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** Kebijakan tertulis menyebut retensi index `firewall` satu tahun, dan `frozenTimePeriodInSecs` di `indexes.conf` memang 31536000. Hunting sepuluh bulan ke belakang tetap kosong, padahal tidak ada yang menghapus data. Apa yang paling mungkin terjadi, dan bagaimana membuktikannya?

<details><summary>Jawaban</summary>

Batas ukuran tercapai lebih dulu daripada batas usia. Bucket menjadi frozen karena mana yang tercapai lebih dulu antara usia (`frozenTimePeriodInSecs`) dan ukuran total index (`maxTotalDataSizeMB`), jadi index dengan retensi 365 hari tetapi batas ukuran kecil akan membuang data jauh sebelum setahun [S1]. Buktinya dibaca dari `| dbinspect index=firewall` lalu `stats min(startEpoch)` per state: tanggal tertua di cold adalah batas nyata hunting-mu, apa pun yang tertulis di kebijakan. Bandingkan ukuran total index dengan `maxTotalDataSizeMB` untuk memastikan ukuran yang memotong, bukan usia. Lihat bagian 1.2 dan 2.1.

</details>

**2. Skenario keputusan.** Sebuah detection yang kamu tulis sendiri tidak menghasilkan satu finding pun selama tiga hari, padahal data sumbernya jelas masuk dan search yang sama dijalankan manual memberi hasil. Apa langkah pertamamu?

- A. Perbaiki logika SPL-nya, karena hasil manual dan hasil terjadwal berbeda berarti ada yang salah di search.
- B. Periksa `index=_internal sourcetype=scheduler` untuk nama detection itu, lihat status `skipped` dan `deferred`, lalu bandingkan `run_time` rata-ratanya dengan interval jadwalnya.
- C. Ubah jadwalnya menjadi real-time schedule supaya pasti dieksekusi.

<details><summary>Jawaban</summary>

B. Hasil manual yang benar sudah mengesampingkan masalah logika, jadi yang tersisa adalah pertanyaan apakah eksekusi terjadwalnya pernah terjadi. `skipped` berarti eksekusi itu hilang selamanya dan bukan tertunda, sementara `deferred` berarti hanya tergeser, dan keduanya hanya terlihat di `index=_internal sourcetype=scheduler` [S4]. Setelah itu `run_time` menentukan letak perbaikannya: bila durasi rata-rata mendekati atau melebihi interval jadwalnya, perbaikannya ada di search (Day 14), bukan di jadwal. A keliru karena memperbaiki hal yang sudah terbukti benar. C justru memperburuk: real-time schedule mengunci slot search dan memperbesar kemungkinan search lain ikut skipped, sedangkan continuous schedule memakai antrean yang lebih sopan terhadap platform. Lihat bagian 1.6 dan 2.2.

</details>

**3. Pertanyaan jebakan.** Kamu akan menulis "tidak ditemukan bukti akses ke share itu dalam 180 hari terakhir" di laporan investigasi. Empat hal apa yang harus kamu periksa lebih dulu, dan kenapa keempatnya mengubah kalimat itu?

<details><summary>Jawaban</summary>

Pertama, peringatan hasil mungkin tidak lengkap di UI atau pesan tentang peer yang tidak tersambung, karena dalam keadaan itu jumlah event bisa berbeda antara dua kali menjalankan search yang sama. Kedua, `scanCount` yang jauh lebih kecil daripada biasanya untuk rentang waktu yang sama, dibaca dari Job Inspector (Day 14). Ketiga, apakah rentang 180 hari itu melewati batas retensi nyata index tersebut (bagian 1.2). Keempat, apakah search memakai data model terakselerasi dengan `summariesonly=true` padahal summary belum selesai dibangun (Day 26). Bila salah satu memberi kejutan, kalimatnya berubah dari "tidak ada aktivitas" menjadi "tidak ada data untuk rentang tersebut", dan itu dua pernyataan yang sangat berbeda nilainya di laporan. Keempatnya masuk ke bagian keterbatasan. Lihat bagian 1.7 dan 2.6.

</details>

**4. Jelaskan ulang.** Ada tekanan menurunkan biaya ingest dan usulan pertama yang masuk adalah memangkas sourcetype dengan volume terbesar. Jelaskan ke SOC lead, dalam tiga kalimat, kenapa ukuran itu salah dan apa yang dipakai sebagai gantinya.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh jawaban: "Hitungannya bukan gigabyte per rupiah, tetapi gigabyte per deteksi yang masih jalan, karena sumber termahal di daftar kita justru yang menopang paling banyak detection, misalnya process creation, autentikasi, dan DNS. Jadi yang saya ajukan adalah tiga langkah berurutan dari yang paling aman: membuang yang jelas tidak bernilai forensik seperti health check dan debug noise di tempat parsing, memisahkan retensi untuk data bervolume besar yang nilainya hanya jangka pendek sehingga datanya tidak hilang tetapi disimpan lebih singkat, dan menurunkan verbositas di sumber ketika audit policy atau logging aplikasi memang terlalu luas. Angkanya saya ambil dari `license_usage.log` per index dan sourcetype selama 30 hari, lalu saya tempelkan ke jumlah detection aktif yang bergantung pada tiap sourcetype, supaya keputusannya kelihatan sebagai pertukaran, bukan sebagai pemangkasan buta."

Kesalahan yang sering muncul: memangkas sumber bervolume besar tanpa memeriksa detection apa yang bergantung padanya, sehingga penghematannya nyata tetapi kehilangan deteksinya baru terasa saat ada insiden; menyamakan "dibuang" dengan "retensi lebih pendek", padahal yang kedua masih menyisakan jendela investigasi; dan menyebut angka volume tanpa menyebut rentang pengukurannya, sehingga satu hari tidak normal dipakai sebagai dasar keputusan setahun. Lihat bagian 1.5 dan 2.4.

</details>

**5. Interview question (English).** "An analyst tells you a search returned nothing, so there is no evidence of the activity. What would you check before you let that go into a report?"

<details><summary>Sample answer</summary>

"I treat an empty result as a claim about coverage, not as a finding, so I check four things before it becomes a sentence in a report. First, retention: I run dbinspect on the index and look at the oldest bucket, because an index can be configured for a year and still drop data much earlier, since buckets roll to frozen on whichever comes first, age or total index size. Second, gaps: a tstats count by day over the search window shows days with no data at all, which usually means an input or a forwarder stopped rather than that nothing happened. Third, platform health: an incomplete-results warning, a disconnected indexer peer, or buckets in fixup will quietly give me fewer events, and the tell is that the same search returns different counts on two runs. Fourth, the search path itself: if it used an accelerated data model with summariesonly, I may be reading a summary that has not finished building, which is not the same as reading the data. If all four are clean, the negative is meaningful and I will say so explicitly, naming the index, the time range and the known limitations. If any of them is not clean, the honest sentence is that there is no data for that range, which is a very different statement, and it usually turns into a platform ticket rather than a closed case."

What makes this answer strong: it separates "no activity" from "no data", names a concrete check for each failure mode instead of speaking in general terms, and ends with the reporting language that makes the distinction visible to whoever reads the case later.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Managing Indexers and Clusters of Indexers: "How the indexer stores indexes", spesifikasi `indexes.conf` | https://help.splunk.com/en/splunk-enterprise | primer | judul halaman dirujuk 2026-10-09 | Tinggi untuk siklus bucket. URL menunjuk ke situs dokumentasi; cari halaman dari judulnya |
| S2 | Managing Indexers and Clusters of Indexers: "Indexer cluster architecture", replication factor dan search factor | https://help.splunk.com/en/splunk-enterprise | primer | judul halaman dirujuk 2026-10-09 | Tinggi untuk konsep RF dan SF |
| S3 | Splunk: halaman harga dan model lisensi (ingest dan workload) | https://www.splunk.com/en_us/products/pricing.html | primer (pemasaran) | dirujuk 2026-10-09 | Sedang. Model yang berlaku untuk sebuah organisasi ada di kontraknya, bukan di halaman ini |
| S4 | Admin Manual: spesifikasi `limits.conf` bagian `[search]` dan concurrency scheduled search | https://help.splunk.com/en/splunk-enterprise | primer | judul halaman dirujuk 2026-10-09 | Tinggi untuk nama setting; nilai default bergantung versi dan jumlah CPU |
| S5 | Monitoring Splunk Enterprise: dashboard Search Activity, Scheduler Activity, Indexer Clustering | https://help.splunk.com/en/splunk-enterprise | primer | judul halaman dirujuk 2026-10-09 | Tinggi |
| S6 | Splunk-Notes Day 14 (search efisien), Day 26 (acceleration), Day 27 (sumber data ke konten), Day 36 (jadwal detection), Day 28 (onboarding) | (lokal) | rujukan internal | 2026-10-09 | Keterkaitan antar Day |

**Catatan sumber:** rasio kompresi dan ukuran tsidx adalah pendekatan yang dipakai luas, bukan angka resmi, jadi harus diukur sendiri dengan `dbinspect`. Nama endpoint REST untuk cluster berubah antar versi dan perlu dicek. Model lisensi dan fitur arsip bergantung kontrak serta jenis deployment (Enterprise atau Cloud).
