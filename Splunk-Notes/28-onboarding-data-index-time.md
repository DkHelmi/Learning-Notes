---
day: 28
title: 'Onboarding data: index-time vs search-time, line breaking, timestamp, masking, dan routing'
researched_on: 2026-10-10
versions_checked: 'Splunk Enterprise 10.6 (Getting Data In, props.conf dan transforms.conf spec); CIM 6.4; rujukan Day 14, 23, 24'
---

# Day 28: Onboarding data dan konfigurasi index-time

Cakupan: apa yang terjadi pada sebuah event sebelum kamu bisa men-search-nya, delapan setting `props.conf` yang menentukan kualitas data, cara memasking data sensitif dan membuang event sampah sebelum diindeks, serta cara menguji semuanya tanpa merusak index produksi.

## Ide inti

Setiap search yang kamu tulis bertumpu pada keputusan yang sudah diambil sebelum event itu bisa dicari: di mana satu event dimulai dan berakhir, angka mana yang dibaca sebagai waktu kejadian, zona waktu apa yang diasumsikan, berapa byte yang disimpan, dan apakah event itu disimpan sama sekali. Keputusan itu diambil saat parsing dan indexing, dan untuk data yang sudah masuk tidak bisa dibatalkan tanpa re-index. Di sini letak bedanya dengan Day 15 dan Day 16: field extraction, alias, dan calculated field berjalan saat search, jadi kesalahan di sana cukup diperbaiki lalu search dijalankan ulang dan perbaikannya langsung berlaku untuk data lama, sedangkan kesalahan index-time ikut tersimpan bersama datanya. Normalisasi CIM di Day 23 dan Day 24 juga bekerja di lapisan search itu, dan semua lapisan di atas tetap mengasumsikan satu hal yang sering salah, yaitu bahwa data yang masuk sudah benar. Tiga kegagalan yang paling sering ditemui analyst semuanya berakar di sini: satu stack trace Java menjadi 60 event terpisah sehingga `stats count` membengkak dan korelasi putus, timestamp log dibaca sebagai waktu ingest sehingga timeline investigasi salah dan scheduled search melewatkan event yang datang terlambat, dan field `user` tidak pernah terparse karena `sourcetype` salah sehingga detection yang memfilter `user=*` tidak pernah fire.

Analoginya adalah parsing yang dilakukan kolektor syslog sebelum log ditulis ke disk, dibandingkan dengan parsing yang dilakukan saat log dibaca. Batas analoginya ada pada sifatnya yang permanen: pada kolektor, file mentah biasanya masih utuh sehingga bisa diproses ulang, sedangkan di Splunk yang tersimpan adalah hasil keputusan index-time, termasuk event yang sudah dibuang. Di PT JAB, sumber yang paling rentan adalah syslog router dan switch POP yang masuk lewat heavy forwarder: perangkat seperti itu sering menulis waktu lokal tanpa offset, dan `TZ` yang salah menggeser seluruh timeline investigasi beberapa jam tanpa memberi gejala lain. Di banyak organisasi onboarding dikerjakan tim platform, tetapi analyst yang bisa membaca `props.conf` punya dua keuntungan: bisa mendiagnosis sendiri kenapa deteksinya buta, dan bisa menulis permintaan perubahan yang spesifik, bukan "lognya kelihatan aneh". Di lab pribadi, kamu memegang dua peran itu sekaligus.

**Kapan relevan:** saat sumber log baru masuk; saat field hilang atau ganda; saat timeline tidak masuk akal; saat biaya ingest perlu ditekan; saat ada data sensitif yang tidak boleh tersimpan apa adanya.
**Kapan bukan jawaban:** apa pun yang bisa dikerjakan saat search sebaiknya dikerjakan saat search, karena biaya salahnya jauh lebih murah. Indexed field baru dibenarkan untuk kasus tertentu, bukan untuk "biar cepat" tanpa pengukuran. `SEDCMD` juga bukan kontrol akses: pemegang akses index tetap melihat sisa event, dan pembatasan per role dibahas di Day 44. Membuang event ke `nullQueue` bukan sekadar keputusan biaya, karena event yang dibuang tidak bisa dipakai sebagai bukti enam bulan kemudian.

## 1. Konsep inti

### 1.1 Empat tahap pipeline dan tempat berjalannya

Sebuah event melewati empat tahap [S1]:

| Tahap | Yang terjadi | Berjalan di |
|---|---|---|
| Input | Membaca sumber (file, TCP/UDP, HEC, script, modular input), memberi metadata awal `host`, `source`, `sourcetype`, `index` | Forwarder atau indexer yang memegang input |
| Parsing | Memecah stream menjadi event (line breaking), mengekstrak timestamp, menerapkan transform index-time (masking, routing, `nullQueue`) | Heavy forwarder bila ada, kalau tidak di indexer |
| Indexing | Menulis raw data terkompresi dan tsidx, menetapkan `_time` dan `_indextime` | Indexer |
| Search | Field extraction, eventtype, tag, alias, lookup, calculated field | Search head dan indexer |

Yang perlu diingat: universal forwarder tidak melakukan parsing untuk data umum, ia hanya mengirim blok data. Jadi `props.conf` untuk line breaking dan timestamp harus ada di tempat parsing terjadi, yaitu heavy forwarder atau indexer, bukan di universal forwarder [S1]. Pengecualian yang sering membingungkan: `INDEXED_EXTRACTIONS` untuk CSV, TSV, dan JSON memang diproses di forwarder, sehingga konfigurasinya justru diletakkan di sana.

### 1.2 Delapan setting yang menentukan kualitas data

Urutannya sengaja: kalau salah satu di atas salah, yang di bawahnya ikut salah.

1. `sourcetype`. Kunci semua konfigurasi lain. Satu sourcetype berarti satu format. Menggabungkan dua format berbeda ke satu sourcetype adalah sumber masalah yang tidak akan selesai dengan tuning search.
2. `LINE_BREAKER`. Regex yang menentukan di mana satu event berakhir. Grup capture pertamanya adalah bagian yang dibuang sebagai pemisah.
3. `SHOULD_LINEMERGE`. Setel `false` bila kamu memakai `LINE_BREAKER`. Nilai `true` memakai mesin penggabung baris yang lebih lambat dan lebih sulit diprediksi.
4. `TIME_PREFIX`. Pola persis sebelum timestamp, supaya Splunk tidak menebak angka lain di event sebagai waktu.
5. `TIME_FORMAT`. Format strptime timestamp. Tanpa ini, Splunk memakai heuristik, dan heuristik salah pada format tanggal ambigu seperti `03/04/2026`.
6. `MAX_TIMESTAMP_LOOKAHEAD`. Batas jumlah karakter yang dibaca untuk mencari timestamp. Membantu kecepatan dan mencegah salah tangkap.
7. `TZ`. Zona waktu sumber bila timestamp tidak memuat offset. Salah di sini menggeser seluruh timeline investigasi beberapa jam.
8. `TRUNCATE`. Batas panjang satu event (default 10.000 byte). Command line yang sangat panjang, misalnya PowerShell terenkode, bisa terpotong dan membuat deteksi gagal.

Dua setting pendamping yang sering perlu: `EVENT_BREAKER` plus `EVENT_BREAKER_ENABLE` untuk distribusi event yang rapi dari forwarder ke beberapa indexer, dan `CHARSET` untuk log non-UTF-8.

### 1.3 Index-time atau search-time

Aturan praktisnya: apa pun yang bisa dikerjakan saat search, kerjakan saat search.

| Aspek | Index-time | Search-time |
|---|---|---|
| Kapan berlaku | Hanya untuk data yang masuk setelah perubahan | Langsung untuk semua data, termasuk data lama |
| Biaya perubahan | Perlu re-index bila ingin memperbaiki data lama | Ubah konfigurasi, jalankan ulang search |
| Biaya penyimpanan | Indexed field memperbesar tsidx | Tidak menambah penyimpanan |
| Kecepatan search | Lebih cepat untuk field yang dipakai sebagai filter utama | Ekstraksi dilakukan setiap search |
| Risiko | Salah konfigurasi berarti data rusak permanen | Salah konfigurasi bisa diperbaiki |

Indexed field hanya dibenarkan dalam kasus tertentu: nilai yang sering dipakai sebagai filter awal di banyak search, nilainya tidak muncul sebagai term biasa di raw data, atau datanya memang struktural (CSV, JSON) sehingga `INDEXED_EXTRACTIONS` lebih murah daripada parsing berulang. Day 14 bagian 1.2 memakai sintaks `field::value` yang memaksa pencarian ke tsidx; sintaks itu hanya berguna untuk indexed field.

### 1.4 Masking data sensitif

`SEDCMD` menjalankan skrip sed terhadap `_raw` saat index [S2]. Karena berjalan pada `_raw`, hasilnya permanen: nilai aslinya tidak pernah tersimpan.

```
# $SPLUNK_HOME/etc/system/local/props.conf (di tempat parsing)
[labapp:payment]
SEDCMD-maskpan = s/\b(\d{6})\d{6,9}(\d{4})\b/\1XXXXXXXX\2/g
SEDCMD-masktoken = s/(authorization:\s*Bearer\s+)\S+/\1[REDACTED]/ig
```

Yang perlu diingat tentang masking index-time:

- Hanya berlaku untuk event baru. Data yang sudah terindeks tidak berubah.
- Beberapa `SEDCMD-<nama>` dalam satu stanza dijalankan berurutan sesuai urutan leksikal namanya. Beri nama berawalan angka bila urutan penting (`SEDCMD-10mask`, `SEDCMD-20mask`), dan uji urutannya di lab karena perilaku ini mudah salah diasumsikan.
- Regex yang terlalu rakus bisa menghapus bagian penting event, termasuk timestamp. Masking selalu diuji dulu ke index terpisah.
- Masking bukan kontrol akses. Bila data perlu terlihat untuk sebagian orang saja, pakai pembatasan index dan `srchFilter` per role (Day 44), bukan `SEDCMD`.

Alternatif yang lebih aman bila memungkinkan: jangan kirim datanya. Mematikan field sensitif di sumber (level aplikasi atau agent) selalu lebih baik daripada menambalnya di Splunk.

### 1.5 Membuang dan merutekan event

Dua transform index-time yang paling sering memberi penghematan nyata:

```
# props.conf
[labapp:web]
TRANSFORMS-drop = drop_healthcheck
TRANSFORMS-route = route_audit_to_security

# transforms.conf
[drop_healthcheck]
REGEX = GET\s/healthz\s
DEST_KEY = queue
FORMAT = nullQueue

[route_audit_to_security]
REGEX = "event_category":"audit"
DEST_KEY = _MetaData:Index
FORMAT = idx_security_audit
```

`nullQueue` membuang event sebelum diindeks, sehingga tidak menghabiskan lisensi dan tidak memperbesar index. Pola yang umum: health check, keep-alive, debug noise, dan baris berulang dari satu aplikasi yang bicara terlalu banyak.

Perhatian: membuang event adalah keputusan keamanan, bukan hanya keputusan biaya. Sebelum membuang, tanyakan apakah event itu bisa menjadi bukti. Health check memang aman dibuang; log autentikasi yang berisik tidak boleh dibuang, melainkan dipindah ke index dengan retensi berbeda.

Routing berdasarkan isi membantu memisahkan data menurut sensitivitas dan retensi. Ini sekaligus prasyarat kontrol akses yang rapi, karena izin di Splunk diberikan per index.

### 1.6 Timestamp, timezone, dan lag

Tiga nilai waktu yang perlu kamu bedakan:

- `_time`: waktu kejadian menurut event. Dipakai semua search dan semua korelasi.
- `_indextime`: waktu event ditulis ke index. Tidak tampil otomatis, harus di-`eval`.
- Waktu di field aplikasi (misalnya `event_time` di JSON): bisa berbeda dari keduanya.

Selisih `_indextime` dikurangi `_time` adalah ingest lag. Lag penting untuk detection engineering: scheduled search dengan jendela waktu tanpa jeda akan melewatkan event yang datang terlambat (Day 36). Mengukur lag per sourcetype adalah pekerjaan rutin yang jarang dilakukan, padahal murah:

```
index=* earliest=-24h
| eval lag=_indextime-_time
| stats count p50(lag) AS p50 p95(lag) AS p95 max(lag) AS max_lag BY index sourcetype
| sort - p95
```

Masalah timezone paling sering muncul pada log perangkat jaringan dan appliance yang menulis waktu lokal tanpa offset. Setel `TZ` di stanza sourcetype atau host. Gejalanya khas: event yang seolah datang dari masa depan, atau alert yang selalu tertinggal beberapa jam.

### 1.7 Gejala dari sisi analyst dan penyebabnya

| Gejala yang kamu lihat saat search | Penyebab onboarding yang mungkin |
|---|---|
| Satu log multiline menjadi banyak event | `LINE_BREAKER` tidak diset atau `SHOULD_LINEMERGE=true` dengan pola salah |
| `linecount` selalu 1 padahal log multiline | Line breaking memecah per baris |
| Timeline bergeser rapi beberapa jam | `TZ` salah |
| Timestamp sama untuk banyak event | Timestamp gagal diparse, Splunk memakai waktu ingest |
| Field panjang terpotong di tengah | `TRUNCATE` terlalu kecil |
| Field tidak muncul padahal ada di raw | `sourcetype` salah, sehingga extraction tidak berlaku |
| Nilai field ganda (`user` punya dua nilai) | Extraction dobel di index-time dan search-time, atau sumber memang multivalue (Day 13) |
| `index=x` kosong padahal data dikirim | Event masuk ke index lain lewat routing, atau terbuang ke `nullQueue` |

Tabel ini layak dihafal. Ia mengubah keluhan "datanya aneh" menjadi hipotesis yang bisa diuji dalam lima menit.

## 2. Contoh konfigurasi dan langkah uji

> Keluaran berlabel ilustrasi. Semua konfigurasi dijalankan di instance lab sendiri.

### 2.1 Log aplikasi multiline dengan timestamp non-standar

Log sumber:

```
2026-10-09 14:03:11,482 [http-nio-8080-exec-3] ERROR c.lab.PaymentService - gagal memproses
java.lang.IllegalStateException: session expired
    at c.lab.PaymentService.charge(PaymentService.java:88)
    at c.lab.PaymentController.post(PaymentController.java:41)
2026-10-09 14:03:12,001 [http-nio-8080-exec-4] INFO  c.lab.PaymentService - ok
```

**Tujuan:** satu entri log (termasuk stack trace) menjadi satu event, dengan `_time` dari timestamp log.

```
# props.conf
[labapp:payment]
SHOULD_LINEMERGE = false
LINE_BREAKER = ([\r\n]+)\d{4}-\d{2}-\d{2}\s\d{2}:\d{2}:\d{2},\d{3}\s\[
TIME_PREFIX = ^
TIME_FORMAT = %Y-%m-%d %H:%M:%S,%3Q
MAX_TIMESTAMP_LOOKAHEAD = 23
TZ = Asia/Jakarta
TRUNCATE = 50000
category = Application
description = Log aplikasi payment lab
```

Penjelasan tiap bagian:

- `LINE_BREAKER` mencari baris baru yang diikuti pola timestamp dan `[`. Grup capture `([\r\n]+)` adalah yang dibuang, sehingga timestamp tetap menjadi awal event berikutnya.
- `TIME_PREFIX = ^` berarti timestamp ada di awal event, jadi tidak perlu mencari lebih jauh.
- `%3Q` membaca milidetik. Tanpa itu, `,482` bisa membuat parsing gagal.
- `MAX_TIMESTAMP_LOOKAHEAD = 23` cukup untuk `2026-10-09 14:03:11,482`. Hitung sendiri panjangnya, jangan menebak.
- `TRUNCATE` dinaikkan karena stack trace panjang.

**Kapan gagal:** bila aplikasi menulis baris tambahan tanpa timestamp di awal (misalnya banner saat start), event pertama akan menyerap banner itu. Itu bukan kesalahan fatal, tetapi perlu dicatat.

### 2.2 Menguji tanpa mengganggu index produksi

Empat langkah yang selalu sama:

```
# 1. pastikan setting yang aktif benar-benar yang kamu tulis
splunk cmd btool props list labapp:payment --debug

# 2. uji sekali ke index terpisah
splunk add oneshot /tmp/sample-payment.log -index idx_onboard_test -sourcetype labapp:payment

# 3. periksa hasil
#    (jalankan di Search)

# 4. bersihkan index uji saat sudah yakin
splunk clean eventdata -index idx_onboard_test
```

Search pemeriksa yang dipakai berulang:

```
index=idx_onboard_test sourcetype=labapp:payment
| eval lag=_indextime-_time, raw_len=len(_raw)
| table _time _indextime lag linecount raw_len punct
| sort _time
```

Keluaran ilustrasi:

```
_time                _indextime           lag  linecount  raw_len  punct
2026-10-09 14:03:11  2026-10-09 14:40:02  2211 4          268      ----_::,_[--__]__..-_-
2026-10-09 14:03:12  2026-10-09 14:40:02  2210 1          96       ----_::,_[--__]__..-_-
```

Cara membacanya:

- `linecount 4` pada event pertama membuktikan stack trace tergabung. Kalau nilainya 1 untuk semua baris, line breaking masih salah.
- `_time` berbeda dari `_indextime` membuktikan timestamp diambil dari event, bukan dari waktu ingest. Kalau keduanya identik untuk semua event, parsing timestamp gagal.
- `punct` berguna untuk membandingkan pola event: dua format berbeda dalam satu sourcetype akan terlihat sebagai dua nilai `punct` yang jauh berbeda.

`btool` adalah alat diagnosis paling berharga di sini karena menunjukkan file mana yang memenangkan konflik konfigurasi. Konflik antara app dan `system/local` adalah penyebab umum "sudah saya setel tapi tidak berubah".

### 2.3 Membuktikan masking berjalan

```
index=idx_onboard_test sourcetype=labapp:payment
| regex _raw="\b\d{13,19}\b"
| stats count
```

Hasil yang diharapkan nol. Bila ada hasil, regex masking belum menangkap semua variasi (spasi, tanda hubung, atau nomor di dalam JSON). Uji juga kasus negatif: nomor invoice 13 digit tidak boleh ikut termasking, jadi periksa satu event normal untuk memastikan isinya tidak rusak.

### 2.4 Mengukur apa yang layak dibuang

Sebelum menulis `nullQueue`, ukur dulu siapa penyumbang volume terbesar:

```
index=_internal source=*license_usage.log* type=Usage earliest=-7d
| stats sum(b) AS bytes BY idx st
| eval GB=round(bytes/1024/1024/1024,2)
| sort - GB
| head 20
```

Lalu di dalam sourcetype terbesar, cari pola berulang:

```
index=labweb sourcetype=labapp:web earliest=-24h
| stats count BY uri_path
| sort - count
| head 20
```

Keputusan yang masuk akal dari hasil seperti ini: `/healthz` dan `/metrics` dibuang, log debug diturunkan di aplikasi, dan audit dipindah ke index sendiri. Yang tidak masuk akal: membuang seluruh sourcetype hanya karena volumenya besar.

### 2.5 Memeriksa hasil routing

```
| tstats count where index=* earliest=-1h by index sourcetype
| sort - count
```

Bila event audit masih muncul di index lama, kemungkinan penyebabnya: transform tidak terpasang di tempat parsing, nama index di `FORMAT` salah, atau index tujuan belum dibuat di indexer.

## 3. Lab praktik

**Prasyarat:** satu instance Splunk lab, satu index uji (`idx_onboard_test`), dan satu file log contoh yang kamu buat sendiri.

1. Buat file log multiline tiruan (minimal 10 entri, 3 di antaranya dengan stack trace) plus satu entri yang memuat nomor 16 digit dan satu header `Authorization: Bearer ...`.
2. Onboard tanpa konfigurasi apa pun ke `idx_onboard_test` dengan sourcetype `uji:mentah`. Catat: berapa event terbentuk, berapa `linecount`, apakah `_time` benar.
3. Tulis `props.conf` seperti bagian 2.1 dengan sourcetype `uji:rapi`. Onboard ulang file yang sama. Bandingkan jumlah event dan `_time` dengan langkah 2, lalu simpan tabel perbandingannya.
4. Tambahkan dua `SEDCMD` (nomor kartu dan bearer token). Onboard ulang, lalu jalankan pembuktian di bagian 2.3, termasuk satu kasus negatif.
5. Ubah `TZ` menjadi zona lain (misalnya `UTC`), onboard ulang ke sourcetype ketiga, dan amati pergeseran `_time`. Ini melatih mengenali gejala timezone salah.
6. Buat satu transform `nullQueue` untuk entri `INFO` dan buktikan event itu tidak terindeks. Lalu kembalikan, karena membuang level INFO sepenuhnya biasanya keputusan yang buruk.
7. Ukur ingest lag di seluruh lab dengan search di bagian 1.6, dan catat sourcetype dengan p95 terburuk.
8. Turunkan `TRUNCATE` menjadi 200 untuk satu sourcetype uji, onboard ulang, dan lihat bagaimana event terpotong. Hubungkan temuan ini dengan deteksi PowerShell terenkode (Day 11).

**Hasil yang sebaiknya tersimpan:**
- Tabel perbandingan sebelum dan sesudah `props.conf` (jumlah event, `linecount`, `_time`).
- Potongan `props.conf` dan `transforms.conf` final milikmu, dengan komentar.
- Bukti masking (search yang mengembalikan nol) dan satu event utuh yang tidak rusak.
- Catatan p95 ingest lag per sourcetype lab.

## 4. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa |
|---|---|---|
| Perubahan `props.conf` tidak berefek | Konfigurasi ditaruh di mesin yang tidak melakukan parsing, atau ditimpa app lain | `splunk cmd btool props list <sourcetype> --debug` lalu lihat kolom file |
| Berefek untuk data baru saja | Memang sifat index-time | Onboard ulang sampel ke index uji untuk verifikasi |
| Event tetap terpecah | Grup capture `LINE_BREAKER` salah, atau `SHOULD_LINEMERGE` masih `true` | Uji regex terhadap sampel, pastikan grup pertama hanya pemisah |
| `_time` sama dengan waktu ingest | `TIME_FORMAT` tidak cocok, atau timestamp di luar `MAX_TIMESTAMP_LOOKAHEAD` | Cek `index=_internal sourcetype=splunkd component=DateParserVerbose` |
| Event hilang total | Terbuang `nullQueue`, atau dirutekan ke index yang tidak kamu cari | `\| tstats count where index=* by index sourcetype`; cek urutan `TRANSFORMS-` |
| Lisensi naik mendadak | Sourcetype baru, debug logging aktif, atau duplikasi input | `index=_internal source=*license_usage.log* type=Usage` dibandingkan minggu sebelumnya |
| Data terindeks dua kali | Dua input memonitor path yang sama, atau forwarder dan indexer dua-duanya memproses | Bandingkan `source` dan `host`, cek `inputs.conf` keduanya |

Satu kebiasaan yang menyelamatkan waktu: selalu cek `index=_internal` saat ada masalah ingest. `splunkd` menulis keluhan parsing di sana dengan nama sourcetype dan contoh event, jauh sebelum kamu menyadarinya dari search biasa.

## 5. Kesalahan umum dan jebakan

- Memperbaiki masalah index-time dengan `rex` saat search. Ini menyembunyikan gejala dan harus diulang di setiap search dan setiap detection.
- Memakai satu sourcetype untuk dua format log. Semua setting setelahnya menjadi kompromi yang salah untuk kedua format.
- Menambah indexed field karena "biar cepat" tanpa mengukur. Yang didapat adalah tsidx lebih besar dan search yang belum tentu lebih cepat.
- Mengandalkan `SEDCMD` sebagai kontrol privasi, padahal pemegang akses index tetap melihat sisanya dan data lama tetap utuh.
- Membuang event ke `nullQueue` tanpa mencatat keputusannya. Enam bulan kemudian, hunting gagal dan tidak ada yang tahu kenapa datanya tidak ada.
- Mengubah `props.conf` langsung di produksi tanpa uji oneshot. Kesalahan index-time tidak bisa dibatalkan tanpa re-index.
- Lupa `TZ` pada appliance jaringan, lalu menghabiskan satu jam menuduh jam endpoint salah.
- Mengabaikan ingest lag, lalu bingung kenapa detection dengan jendela ketat melewatkan event (Day 36 bagian 4).

## 6. Catatan terkini

- Di Splunk Enterprise 10.x, konfigurasi onboarding tetap berbasis `props.conf` dan `transforms.conf`. Yang berubah bertahap adalah antarmuka pembantunya (Data Preview di UI dan app ingest actions untuk masking dan routing lewat form). Cek ketersediaan ingest actions di versi dan jenis deployment yang kamu pakai, karena fiturnya berbeda antara Enterprise dan Cloud.
- Untuk Splunk Cloud, kamu tidak menyentuh indexer secara langsung. Perubahan parsing dikirim lewat app yang di-deploy atau lewat ingest actions, dan sebagian setting dibatasi. Prinsipnya sama, jalurnya berbeda.
- `INDEXED_EXTRACTIONS` untuk JSON semakin sering dipakai untuk log cloud. Konsekuensinya perlu disadari: field menjadi indexed field, ukuran tsidx naik, dan nama field bisa bertabrakan dengan extraction saat search.
- Untuk data metrics (bukan event), Splunk punya metrics index dan `mstats` yang dibahas di Day 40.

## 7. Cheat sheet

```
PIPELINE  input -> parsing (line break, timestamp, transform) -> indexing (_time, tsidx) -> search (extraction, CIM)
TEMPAT    UF: tidak parsing (kecuali INDEXED_EXTRACTIONS) | HF/indexer: parsing | SH: search-time
URUTAN    sourcetype > LINE_BREAKER > SHOULD_LINEMERGE=false > TIME_PREFIX > TIME_FORMAT > MAX_TIMESTAMP_LOOKAHEAD > TZ > TRUNCATE
MASK      SEDCMD-<nama> = s/pola/ganti/g   (hanya _raw, hanya data baru, urutan leksikal)
BUANG     props: TRANSFORMS-x = drop_y | transforms: REGEX + DEST_KEY=queue + FORMAT=nullQueue
ROUTE     DEST_KEY=_MetaData:Index + FORMAT=<index_tujuan>
UJI       btool props list <st> --debug | add oneshot -index idx_test | clean eventdata -index idx_test
BUKTI     linecount, _time vs _indextime, punct, len(_raw), regex pembuktian masking
LAG       | eval lag=_indextime-_time | stats p95(lag) BY index sourcetype
VOLUME    index=_internal source=*license_usage.log* type=Usage | stats sum(b) BY idx st
DIAGNOSA  index=_internal sourcetype=splunkd component=DateParserVerbose
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** "Karena universal forwarder yang membaca filenya, `props.conf` untuk line breaking dan timestamp dipasang di forwarder itu." Di mana sebenarnya setting itu harus ada, dan apa pengecualian yang sering membingungkan?

<details><summary>Jawaban</summary>

Untuk data umum, universal forwarder tidak melakukan parsing; ia hanya mengirim blok data. Jadi `LINE_BREAKER`, `SHOULD_LINEMERGE`, dan seluruh setting `TIME_*` harus ada di tempat parsing benar-benar terjadi, yaitu heavy forwarder bila ada, kalau tidak di indexer. Pengecualiannya `INDEXED_EXTRACTIONS` untuk CSV, TSV, dan JSON, yang memang diproses di forwarder sehingga konfigurasinya justru diletakkan di sana. Gejala khas salah tempat adalah perubahan yang tidak pernah berefek, dan cara membuktikannya `splunk cmd btool props list <sourcetype> --debug` untuk melihat file mana yang menang. Lihat bagian 1.1, 1.2, dan 4.

</details>

**2. Skenario keputusan.** Laporan license usage menunjukkan dua penyumbang terbesar: sourcetype web aplikasi yang didominasi request ke `/healthz`, dan log autentikasi portal pelanggan yang sangat berisik. Apa yang kamu lakukan?

- A. Buang keduanya ke `nullQueue`, karena dua-duanya berisik dan penghematannya paling besar.
- B. Buang `/healthz` ke `nullQueue`, rutekan log autentikasi ke index sendiri dengan retensi yang berbeda, lalu catat kedua keputusan itu beserta alasannya.
- C. Jangan buang apa pun, cukup turunkan retensi seluruh index supaya hemat tempat.

<details><summary>Jawaban</summary>

B. `nullQueue` membuang event sebelum diindeks sehingga tidak memakan lisensi dan tidak memperbesar index, dan health check termasuk pola yang aman dibuang. Log autentikasi beda urusannya: membuang event adalah keputusan keamanan, bukan hanya keputusan biaya, dan log autentikasi hampir selalu bisa menjadi bukti, jadi yang tepat adalah memindahkannya ke index sendiri dengan retensi berbeda. Routing berdasarkan isi sekaligus menjadi prasyarat kontrol akses yang rapi, karena izin di Splunk diberikan per index. Keputusannya dicatat supaya hunting enam bulan kemudian tidak gagal tanpa ada yang tahu kenapa datanya tidak ada. A membuang bukti, C mengorbankan seluruh data termasuk yang tidak bermasalah dan tidak menyentuh penyebab volumenya. Lihat bagian 1.5, 2.4, dan 5.

</details>

**3. Pertanyaan jebakan.** Setelah onboard ulang satu file sampel ke index uji, semua event punya `_time` yang identik dengan `_indextime`, dan `linecount` bernilai 1 untuk setiap baris. Dua kesimpulan apa yang bisa langsung kamu tarik, dan setting mana yang dicurigai?

<details><summary>Jawaban</summary>

Pertama, parsing timestamp gagal sehingga Splunk memakai waktu ingest sebagai `_time`. Yang dicurigai `TIME_PREFIX` dan `TIME_FORMAT` yang tidak cocok, atau `MAX_TIMESTAMP_LOOKAHEAD` yang terlalu kecil sehingga timestamp berada di luar jangkauan pembacaan, dan keluhannya bisa dibaca di `index=_internal sourcetype=splunkd component=DateParserVerbose`. Kedua, line breaking memecah per baris, jadi log multiline tidak tergabung: penyebabnya grup capture `LINE_BREAKER` yang salah atau `SHOULD_LINEMERGE` yang masih `true`. Pada sampel yang benar, event dengan stack trace akan menunjukkan `linecount` lebih dari satu dan `_time` yang berbeda dari `_indextime`. Lihat bagian 1.7, 2.2, dan 4.

</details>

**4. Jelaskan ulang.** Jelaskan ke tim platform, dalam tiga kalimat, kenapa permintaanmu berbentuk perubahan setting tertentu dan bukan keluhan bahwa lognya aneh.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh jawaban: "Gejalanya saya terjemahkan dulu ke setting: timeline yang bergeser rapi beberapa jam menunjuk `TZ`, event multiline yang terpecah menunjuk `LINE_BREAKER` dan `SHOULD_LINEMERGE`, dan command line yang terpotong menunjuk `TRUNCATE`. Saya sudah menguji usulan ini dengan oneshot ke index uji sendiri, jadi yang saya kirim adalah stanza yang sudah terbukti beserta bukti sebelum dan sesudahnya berupa jumlah event, `linecount`, dan selisih `_time` dengan `_indextime`. Saya juga menyebutkan di mesin mana stanza itu harus dipasang, karena untuk data umum parsing terjadi di heavy forwarder atau indexer, bukan di universal forwarder, dan perubahan ini hanya berlaku untuk data yang masuk setelahnya."

Kesalahan yang sering muncul: meminta perbaikan tanpa menyebut sourcetype, sehingga permintaannya tidak bisa dieksekusi; berharap perubahan ikut memperbaiki data lama; dan menambal masalah index-time dengan `rex` di setiap search, yang menyembunyikan gejala dan harus diulang di setiap detection. Lihat bagian 1.1, 1.7, 2.2, dan 5.

</details>

**5. Interview question (English).** "A log source was onboarded last week and the detections built on it are not firing. How do you troubleshoot?"

<details><summary>Sample answer</summary>

"I work down the pipeline rather than starting from the detection. First I check that the events are actually there and under the sourcetype I expect, because events can be routed to another index by a transform or dropped to nullQueue entirely, and a quick count by index and sourcetype settles that. Then I check parsing quality on a handful of events: linecount to see whether multiline entries were split, _time against _indextime to see whether the timestamp was parsed at all or ingest time was used instead, and the length of _raw in case truncation cut the field the detection depends on. If the sourcetype is wrong, none of the search-time extractions apply, so the fields the detection filters on are simply absent, and that single mistake explains most silent detections. I confirm which configuration file is actually winning with btool, since conflicts between an app and system local are a common cause of 'but I already changed that', and I read splunkd's own parsing complaints in the internal index. Finally I check normalisation and timing: whether the fields are mapped into the CIM data model the detection reads, and what the ingest lag looks like, because a detection with a tight time window will quietly miss events that arrive late. Anything I change at index time I test with a oneshot into a throwaway index first, because that layer cannot be undone without re-indexing."

What makes this answer strong: it follows the pipeline in order instead of guessing, names the specific evidence fields that distinguish each failure, separates index-time causes from search-time ones, and ends with a safe test habit rather than a change in production.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Getting Data In Manual: "How Splunk Enterprise handles your data" dan "Configure event line breaking", "Configure timestamp recognition" | https://help.splunk.com/en/splunk-enterprise | primer | judul halaman dirujuk 2026-10-09 | Tinggi untuk konsep pipeline. URL menunjuk ke situs dokumentasi; cari halaman dari judulnya |
| S2 | Admin Manual: spesifikasi `props.conf` (`SEDCMD`, `LINE_BREAKER`, `TIME_*`, `TRUNCATE`) dan `transforms.conf` (`DEST_KEY`, `FORMAT`) | https://help.splunk.com/en/splunk-enterprise | primer | judul halaman dirujuk 2026-10-09 | Tinggi. Nama dan default setting wajib dicek di versi yang kamu pakai |
| S3 | Splunk Community: diskusi masking dengan props dan transforms, termasuk perdebatan batas jumlah `SEDCMD` per stanza | https://community.splunk.com/t5/Getting-Data-In/Help-Using-Props-and-or-Transforms-to-Mask-sensitive-field-data/m-p/336734 | komunitas | dilihat 2026-10-09 | Sedang. Satu klaim di thread (hanya satu `SEDCMD` per stanza) dibantah anggota lain, jadi uji sendiri di lab |
| S4 | Splunk-Notes Day 14 (search efisien, `field::value`), Day 23 (CIM dan normalisasi search-time), Day 36 (jendela waktu detection) | (lokal) | rujukan internal | 2026-10-09 | Keterkaitan antar Day |

**Catatan sumber:** nama setting dan perilakunya stabil sejak lama, tetapi nilai default (`TRUNCATE`, `MAX_TIMESTAMP_LOOKAHEAD`) dan ketersediaan ingest actions bergantung versi dan jenis deployment, jadi dua hal itu perlu dicek sendiri. Urutan eksekusi beberapa `SEDCMD` dalam satu stanza diambil dari pemahaman umum komunitas dan perlu dibuktikan di lab.
