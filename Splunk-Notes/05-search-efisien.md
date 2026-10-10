---
day: 05
title: 'Search efisien: filter awal, urutan command, fields, rentang waktu, wildcard, dan Job Inspector'
researched_on: 2026-10-07
versions_checked: Splunk Enterprise Search Manual 9.4 (Write better searches) dan 10.2 (Types of commands, Difference between != and NOT); Splunk Lantern "Optimizing search"; Splunk Enterprise terbaru 10.6
---

# Day 05: Search efisien dengan filter awal, urutan command, dan Job Inspector

Cakupan: praktik menyusun search yang efisien (filter awal, urutan command, pengganti command mahal) dan cara mengukurnya dengan Job Inspector.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- menjelaskan kenapa sebuah search lambat dengan bahasa arsitektur: tsidx, indexer vs search head, streaming vs non-streaming.
- menerapkan aturan praktis: index/sourcetype eksplisit, rentang waktu sempit, istilah spesifik, hindari leading wildcard dan `NOT`, `fields` lebih awal, non-streaming di akhir.
- memilih mode search (Fast/Smart/Verbose), dan alternatif yang lebih murah untuk `join`, `transaction`, subsearch besar, dan `dedup`.
- membaca Job Inspector untuk membandingkan dua versi search secara objektif.

## 2. Konteks singkat

Search yang lambat tidak hanya membuatmu menunggu. Di SOC, dampaknya meluas:
- Scheduled search dan correlation search bisa terlewat (skipped).
- Dashboard timeout.
- Search head terbebani untuk semua orang.

Day 01-04 sudah menyentuh efisiensi (tstats, stats vs transaction, lookup setelah stats). Hari ini prinsip-prinsip itu dirangkum menjadi kerangka berpikir yang bisa kamu terapkan pada search apa pun.

Prinsip dasarnya dirumuskan Splunk sendiri: ambil sesedikit mungkin data dari disk, dan saring sedini mungkin [S1]. Lantern menambahkan bahwa search lambat bisa juga disebabkan kualitas data yang buruk (event breaking, timestamp yang salah), bukan hanya cara search ditulis [S2].

## 3. Konsep inti

### 3.1 Dua tahap: indexer lalu search head

Search berjalan dalam dua tahap besar:
1. **Di indexer (paralel):** mencari di tsidx, mengambil event dari bucket, menjalankan command distributable streaming (`eval`, `where`, `rex`, `fields`, `rename`, `lookup` streaming), dan pra-agregasi `stats`.
2. **Di search head (terpusat):** menggabungkan hasil, lalu menjalankan command yang butuh seluruh data atau urutan global.

Splunk mengelompokkan command ke enam tipe [S3]:

| Tipe | Contoh | Di mana | Implikasi |
|---|---|---|---|
| Distributable streaming | `eval`, `fields`, `rename`, `regex`, `where` | Indexer, paralel | Murah; taruh di awal |
| Centralized streaming | `head`, `streamstats`, sebagian mode `dedup` | Search head | Memaksa data pindah ke search head |
| Transforming | `stats`, `chart`, `timechart`, `top`, `rare` | Pra-agregasi di indexer, final di SH | Mengubah event menjadi tabel |
| Generating | `search`, `tstats`, `inputlookup`, `makeresults` | Awal search | Tidak menerima input |
| Orchestrating | `redistribute`, `noop`, `localop` | Mengatur eksekusi | Lanjutan |
| Dataset processing | `sort`, `eventstats`, sebagian `cluster` | Search head, butuh seluruh data | Mahal; taruh di akhir |

**Aturan inti:** begitu pemrosesan berpindah ke search head, ia tidak kembali ke indexer. Jadi taruh command non-streaming selambat mungkin [S1][S3]. Contoh: `sort` di tengah search berarti semua event dikirim ke search head lebih awal, dan setiap `eval` setelahnya berjalan di satu mesin.

### 3.2 Saring sedini mungkin

Dari dokumentasi dan Lantern [S1][S2]:

1. Selalu sebut `index=`. Jangan `index=*`. Pisahkan data ke index yang berbeda, lalu batasi search ke index yang relevan [S1][S2].
2. Gunakan `sourcetype`, `host`, `source` (field indexed bawaan) untuk menyaring lebih awal [S1].
3. Rentang waktu sesempit mungkin. Bucket di luar rentang tidak disentuh sama sekali. Lantern menyarankan jendela pendek (maksimal 15 menit untuk penelusuran awal) lalu perluas bila perlu [S2].
4. Istilah spesifik. Kata kunci dan pasangan field=value yang unik mengurangi event yang harus dibuka. Contoh Lantern: `index=firewall status=ERROR type=cisco model=asa datacenter=newyork` jauh lebih baik daripada filter generik [S2].
5. **Indexed field dengan `::`**: `field::value` memaksa pencarian langsung di tsidx untuk indexed field [S1]. Berguna untuk indexed field kustom.
6. `TERM()` mencegah major breaker (mis. titik, koma) memecah istilah, sehingga pencarian IP/URL lebih tepat dan lebih cepat, mis. `TERM(10.1.2.3)` [S2]. Detail breaker, cek di dokumentasi segmentation.

### 3.3 Wildcard dan negasi

- Leading wildcard (`*ccept`) mahal. tsidx menyimpan term yang bisa dicari dari depan. Wildcard di depan memaksa pemindaian lexicon yang jauh lebih luas. Pengujian Hurricane Labs menunjukkan trailing wildcard (`Acc*`) hampir secepat tanpa wildcard, sementara leading wildcard bisa sekitar 4x lebih lama [S4]. Angka itu pengukuran mereka, jadi cek di lingkunganmu, tetapi arahnya konsisten dengan dokumentasi yang menyarankan menghindari wildcard [S1].
- Wildcard di tengah (`C:\*\evil.exe`) juga mahal dan bisa berperilaku tak terduga terhadap breaker.
- `NOT` dan `!=` mahal, karena Splunk harus mencari lalu membuang. Lebih murah menyebut apa yang kamu cari [S5].
- Semantik berbeda [S5]:
  - `status!=200` mengembalikan event yang punya field `status` dengan nilai selain 200.
  - `NOT status=200` mengembalikan semua event kecuali yang `status=200`, termasuk event tanpa field `status`.
  
  Salah pilih bisa membuat hasil investigasi bolong.

### 3.4 Batasi field dan pilih mode

- `fields` di awal (`| fields host user src dest action`) mengurangi data yang dipindahkan dari indexer. `fields` adalah distributable streaming [S3]. `table` adalah perintah tampilan, jadi taruh di akhir [S2].
- Mode search [S2]:
  - **Fast:** hanya field yang disebut atau indexed; field discovery mati. Paling hemat.
  - **Smart:** platform memutuskan.
  - **Verbose:** semua field dan event. Sangat boros; pakai hanya untuk troubleshooting.

### 3.5 Pilih command yang lebih murah

| Hindari / waspadai | Alternatif lebih murah | Alasan |
|---|---|---|
| `transaction` dengan ID unik | `stats ... BY id` | Day 02 [S1] |
| `join` | `stats` atas gabungan dua sumber (`(index=a ...) OR (index=b ...) \| stats values(...) BY key`), atau `lookup` | `join` memakai subsearch dengan batas hasil dan waktu |
| Subsearch yang mengembalikan banyak nilai | `lookup`, atau `tstats` dengan filter | Subsearch dibatasi `maxout`/`maxtime` di limits.conf. Default umum 10.000 hasil dan 60 detik, cek di limits.conf versi-mu. Praktisi menyarankan mencari alternatif, bukan menaikkan batas [S6] |
| `dedup` atas data besar | `stats latest(...) BY key` | `dedup` sebagian mode berjalan terpusat [S3] |
| Raw search untuk statistik berulang | `tstats` + data model terakselerasi; summary indexing | Day 01 [S1][S2] |
| Real-time search | Scheduled search dengan jendela pendek | Real-time terus memegang sumber daya, cek panduan terbaru |

### 3.6 Ukur, jangan menebak: Job Inspector

Job > Inspect Job menunjukkan [S1]:
- Durasi total dan biaya per komponen (`command.search.*`, `command.stats`, `dispatch.*`).
- scanCount (event yang dipindai) vs resultCount (hasil). Rasio scan/result yang besar menandakan filter awal yang buruk.
- Search yang benar-benar dijalankan (setelah ekspansi macro dan optimasi otomatis). Ini berguna untuk melihat bagaimana macro ES berkembang.

Cek nama komponen persis di versi-mu. Bandingkan dua versi search di rentang waktu yang sama. Itulah satu-satunya bukti yang sah bahwa optimasi berhasil.

Di tingkat platform, Monitoring Console menyediakan dashboard Search Activity dan Scheduler Activity untuk melihat search yang paling mahal dan yang terlewat [S2].

### 3.7 Enterprise vs ES

Semua prinsip di atas berlaku di Splunk Enterprise. Di ES, efisiensi menjadi kritis karena ES menjalankan banyak search terjadwal (detection, akselerasi data model, threat intel). Lantern menyebut ES sebagai pemroses batch yang berat (lihat Day 01 [S6] di catatan Day 01). Itulah alasan detection ES ditulis dengan `tstats` + `summariesonly`.

## 4. Contoh SPL dan langkah di ES

> Keluaran berlabel ilustrasi. Data: BOTS v1 (`index=botsv1`). Cek nama field.

### 4.1 Sebelum dan sesudah: mencari download executable

**Versi lambat (jangan ditiru):**

```
index=* *.exe
| sort - _time
| eval file=lower(uri)
| search file="*.exe" NOT src_ip="192.168.250.*"
| dedup src_ip file
| table _time src_ip dest_ip file http_user_agent
```

Masalahnya:
- `index=*` dan rentang waktu tak terbatas.
- `*.exe` adalah leading wildcard di `_raw`.
- `sort` di awal memindahkan semua event ke search head.
- `search` setelah `eval` menyaring terlambat.
- `NOT` mahal.
- `dedup` atas semua event.

**Versi efisien (pertanyaan yang sama):**

```
index=botsv1 sourcetype=stream:http earliest="08/01/2016:00:00:00" latest="09/01/2016:00:00:00"
    uri="*.exe" NOT src_ip="192.168.250.*"
| fields _time src_ip dest_ip uri http_user_agent
| eval file=lower(uri)
| stats earliest(_time) AS first latest(_time) AS last count BY src_ip dest_ip file http_user_agent
| sort - count
```

Kenapa lebih baik:
- Index dan sourcetype spesifik.
- Rentang waktu eksplisit. Data BOTS v1 bertanggal Agustus 2016, jadi `earliest=-30d` justru akan mengembalikan nol hasil. Untuk data live, pakai rentang relatif seperti `earliest=-24h`. Cek rentang tanggal persis BOTS v1 di instance-mu (Day 07 Bagian A).
- Semua filter dipindah ke search awal, sehingga event dibuang di indexer sebelum diproses. `NOT` di sini tidak masalah karena didampingi filter positif yang sudah mempersempit data; yang mahal adalah search yang hanya berisi `NOT`.
- `uri="*.exe"` masih leading wildcard, tetapi pada field dan setelah data dipersempit. Bila kamu tahu nama file spesifik, pakai itu.
- `fields` mengurangi data yang berpindah.
- `stats` menggantikan `dedup` dan sekaligus memberi firstSeen/lastSeen.
- `sort` di akhir.

Prinsip penting: optimasi tidak boleh mengubah pertanyaan. Versi lambat bertanya "semua download `.exe` dari sumber non-internal", jadi versi efisien harus menjawab pertanyaan yang sama. Kalau kamu menyempitkan ke subnet tertentu, itu pertanyaan baru, dan perbandingan durasinya tidak lagi adil.

**Cara membandingkan:** jalankan keduanya di rentang waktu yang sama, lalu catat dari Job Inspector: durasi, scanCount, resultCount. Keluaran ilustrasi:

```
versi lambat : 41.2 s, scanCount 9.8 jt, resultCount 37
versi efisien:  2.9 s, scanCount 210 rb, resultCount 37
```

Angka ini ilustrasi. Hasilmu akan berbeda, tetapi arahnya seharusnya sama. Perhatikan `resultCount` yang harus sama di kedua versi; kalau berbeda, cek dulu apakah kedua search benar-benar menjawab pertanyaan yang sama (misalnya karena `dedup` dan `stats` mengelompokkan dengan kunci berbeda).

### 4.2 NOT vs != dalam investigasi

```
index=botsv1 sourcetype=stream:http status!=200 | stats count
index=botsv1 sourcetype=stream:http NOT status=200 | stats count
```

Hasil yang diharapkan: angka kedua sama atau lebih besar dari angka pertama. Selisihnya adalah event tanpa field `status` [S5]. Pertanyaan investigasi: apakah event tanpa `status` (koneksi gagal, parsing gagal) penting untuk kasusmu?

### 4.3 Mengganti join dengan stats

**Tujuan:** host yang punya alert IDS dan mengakses domain tertentu.

Dengan `join` (mahal, terbatas oleh subsearch):

```
index=botsv1 sourcetype=suricata | stats count AS ids_alerts BY src_ip
| join type=inner src_ip [ search index=botsv1 sourcetype=stream:dns query="*.example" | stats count AS dns_hits BY src_ip ]
```

Dengan `stats` atas dua sumber sekaligus:

```
index=botsv1 ((sourcetype=suricata) OR (sourcetype=stream:dns query="*.example"))
| eval ids=if(sourcetype="suricata",1,0), dns=if(sourcetype="stream:dns",1,0)
| stats sum(ids) AS ids_alerts sum(dns) AS dns_hits BY src_ip
| where ids_alerts>0 AND dns_hits>0
```

- Satu pass data. Tidak ada batas subsearch. Pra-agregasi bisa terjadi di indexer.
- **Syarat:** nama field kunci sama di kedua sourcetype (`src_ip`). Bila berbeda, normalisasi dengan `eval`/`coalesce` (Day 03) atau gunakan field CIM (Day 11). Cek nama field di sourcetype `suricata` di BOTS v1.

### 4.4 Rutinitas "search baru" untuk analyst

```
1. index=<spesifik> sourcetype=<spesifik> earliest=-15m       (lihat beberapa event, mode Smart/Fast)
2. tambah istilah/field=value spesifik; hindari *awal dan NOT
3. | fields <yang dibutuhkan>
4. | eval/rex/where (streaming)
5. | stats ... BY ...   (transforming)
6. | lookup (enrichment pada hasil agregasi) | sort | table   (paling akhir)
7. perluas rentang waktu; cek Job Inspector
```

### 4.5 Di ES (generik)

- Saat membuka detection bawaan, perhatikan pola: `tstats` + `summariesonly`, filter dengan field data model, `drop_dm_object_name`, lalu macro `*_filter` di akhir untuk tuning (Day 01 bagian 4.5). Macro filter itu tempat yang tepat untuk menambah pengecualian, dan biasanya lebih murah daripada `NOT` di awal karena dijalankan atas hasil agregasi, cek pola di ES 8.x.
- Gunakan Monitoring Console (Search/Scheduler Activity) untuk menemukan detection yang lambat atau terlewat [S2].

## 5. Lab praktik

1. Jalankan pasangan search bagian 4.1 di rentang yang sama. Isi tabel: durasi, scanCount, resultCount.
2. Ulangi versi lambat hanya dengan mengganti `index=*` menjadi `index=botsv1`, lalu ukur. Lanjutkan satu perubahan per langkah (hapus `sort` awal, ganti `dedup` dengan `stats`, dan seterusnya). Catat kontribusi tiap perubahan.
3. Jalankan bagian 4.2 dan jelaskan selisihnya.
4. Jalankan bagian 4.3 kedua versi. Bandingkan hasil dan durasinya.
5. Uji mode: jalankan satu search di Verbose, Smart, dan Fast. Catat durasi dan perbedaan field yang tampil.
6. Uji leading wildcard: `index=botsv1 *ccept*` vs `index=botsv1 Accept*` di rentang sama, cek istilah yang ada di data-mu. Bandingkan dengan klaim sekitar 4x [S4].

**Hasil yang sebaiknya tersimpan:**
- Tabel perbandingan bagian 4.1 dengan angka dari Job Inspector.
- Kontribusi tiap perubahan (langkah 2) tercatat.
- Penjelasan `NOT` vs `!=` dengan angka.
- Hasil uji leading wildcard di lab-mu.

**Variasi tantangan:** ambil satu search lambat yang sering kamu pakai (versi lab, bukan dari kantor). Optimalkan dengan prinsip hari ini, lalu tulis "sebelum/sesudah" beserta angka Job Inspector. Ini bagus untuk portofolio dan interview.

## 6. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| scanCount jauh lebih besar dari resultCount | Filter terlambat atau terlalu umum | Pindahkan filter ke search awal; istilah spesifik [S1] |
| Search lambat walau hasil sedikit | Leading wildcard, `NOT`, `index=*` | Ganti dengan filter positif dan spesifik [S4][S5] |
| Durasi didominasi search head | Non-streaming terlalu awal (`sort`, `dedup`, `eventstats`) | Pindahkan ke akhir [S3] |
| Hasil `join` terpotong | Batas subsearch | Ganti dengan `stats` atas dua sumber atau `lookup` [S6] |
| Dashboard lambat | Panel menjalankan raw search berat | `tstats`/base search/summary; batasi waktu |
| Search tetap lambat walau ditulis baik | Kualitas data (line breaking, timestamp) | Laporkan ke admin; lihat Lantern [S2] |

## 7. Kesalahan umum dan jebakan

- `index=*` "supaya aman". Mahal dan membuka data yang tidak perlu [S1][S2].
- `table` atau `sort` di tengah search [S2][S3].
- Mengira `NOT` dan `!=` sama [S5]. Ini masalah hasil, bukan hanya performa.
- Menaikkan batas subsearch alih-alih mengubah pendekatan [S6].
- Verbose mode untuk pekerjaan rutin [S2].
- Optimasi tanpa pengukuran. Selalu bandingkan di Job Inspector.
- `[komunitas]` Saran di Splunk Community untuk tidak menaikkan limit subsearch dan mencari alternatif [S6] konsisten dengan dokumentasi. Nilai default batas subsearch di `limits.conf` berbeda antar versi lama dan baru, jadi cek nilainya di instance-mu (`| rest /services/configs/conf-limits/subsearch`) sebelum mengandalkan angka tertentu.

## 8. Catatan terkini

- Panduan "Write better searches" dan "Types of commands" tetap sama dari versi 9.x hingga 10.x (tersedia untuk 10.2 dan Cloud 10.5.2605) [S1][S3].
- Lantern masih menekankan `tstats` dan `TERM()`/`PREFIX()` (PREFIX sejak 8.0) sebagai teknik utama [S2].
- Halaman "Difference between != and NOT" tersedia hingga Splunk Cloud 10.5.2605 tanpa perubahan semantik [S5].

## 9. Cheat sheet

```
PRINSIP   ambil data sesedikit mungkin, saring sedini mungkin
FILTER    index= sourcetype= host= source= + earliest/latest sempit + istilah spesifik + field::value + TERM()
HINDARI   index=*  |  *leading  |  NOT / !=  (sebut yang DICARI)  |  verbose mode
URUTAN    search -> fields -> eval/rex/where -> stats -> lookup -> sort -> table
GANTI     transaction->stats BY id | join->stats atas OR-sumber / lookup | dedup->stats latest() | raw->tstats
SEMANTIK  f!=x : hanya event yang PUNYA f   |   NOT f=x : termasuk event TANPA f
UKUR      Job Inspector: durasi, scanCount vs resultCount, komponen; Monitoring Console: Search/Scheduler Activity
```

## 10. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Search Manual: Write better searches (9.4) | https://help.splunk.com/en/splunk-enterprise/search/search-manual/9.4/optimizing-searches/write-better-searches | primer | diakses 2026-10-07 | Tinggi |
| S2 | Splunk Lantern: Optimizing search | https://lantern.splunk.com/Platform_Data_Management/Transform_Data/Optimizing_search | primer (Lantern resmi) | tanggal tidak terlihat; diakses 2026-10-07 | Tinggi |
| S3 | Search Manual: Types of commands (10.2) | https://help.splunk.com/en/splunk-enterprise/search/search-manual/10.2/search-overview/types-of-commands | primer | diakses 2026-10-07 | Tinggi |
| S4 | Hurricane Labs: Why you should never use leading wildcards in Splunk searches | https://www.hurricanelabs.com/blog/why-you-should-never-use-leading-wildcards-in-splunk-searches | sekunder (praktisi) | tanggal tidak tercatat | Sedang. Angka sekitar 4x adalah pengukuran mereka |
| S5 | Search Manual: Difference between != and NOT (10.2 / Cloud 10.5.2605) | https://help.splunk.com/en/splunk-enterprise/search/search-manual/10.2/expressions-and-predicates/difference-between-and-not | primer | tanggal tidak tercatat | Tinggi untuk semantik |
| S6 | Splunk Community: "How to increase the subsearch limit" | https://community.splunk.com/t5/Splunk-Search/How-to-increase-the-subsearch-limit/td-p/244448 | komunitas | tanggal tidak tercatat | Rendah-sedang. Angka default yang disebut di thread tidak konsisten antar versi |
| S7 | Splunk Lantern: Reducing search load | https://lantern.splunk.com/Splunk_Success_Framework/Reduce_Costs/Reducing_search_load | primer | tanggal tidak tercatat | Sedang |

**Catatan sumber:** angka percepatan dari menghindari leading wildcard [S4] adalah pengukuran satu praktisi, bukan angka umum; ukur sendiri di Job Inspector. Nilai default batas subsearch perlu dicek di versi-mu [S6].
