---
day: 14
title: 'Search efisien: filter awal, urutan command, fields, rentang waktu, wildcard, dan Job Inspector'
researched_on: 2026-10-07
versions_checked: Splunk Enterprise Search Manual 9.4 (Write better searches) dan 10.2 (Types of commands, Difference between != and NOT); Splunk Lantern "Optimizing search"; Splunk Enterprise terbaru 10.6
---

# Day 14: Search efisien dengan filter awal, urutan command, dan Job Inspector

Cakupan: praktik menyusun search yang efisien (filter awal, urutan command, pengganti command mahal) dan cara mengukurnya dengan Job Inspector.

## Ide inti

Search yang lambat bukan urusan kesabaran pribadi. Di SOC yang search head-nya dipakai bersama, satu search boros membuat scheduled search terlewat, dashboard timeout, dan antrean orang lain ikut melambat. Prinsipnya dirumuskan Splunk sendiri dalam satu kalimat: ambil sesedikit mungkin data dari disk, dan saring sedini mungkin [S1]. Yang membuat prinsip itu bisa dieksekusi adalah dua fakta arsitektur: tahap pertama search berjalan paralel di indexer, dan begitu pemrosesan berpindah ke search head ia tidak kembali ke indexer. Karena itu urutan command bukan soal kerapihan, melainkan penentu di mesin mana sisa pipeline dijalankan. Dasar SPL ada di Day 02, dan Day 11 sampai 13 sudah menyentuh efisiensi lewat `rex` yang diarahkan ke field kecil, `lookup` setelah agregasi, dan `stats` sebagai pengganti `transaction`; Day ini merangkumnya menjadi kerangka yang bisa dipakai pada search apa pun, lalu menambahkan cara mengukurnya.

Analoginya menarik log dari server syslog dengan shell: kamu memilih file hari yang tepat dan `grep` istilah yang spesifik lebih dulu, baru mengalirkan hasilnya ke `awk` dan `sort`, bukan membaca seluruh direktori lalu memilah di akhir. Rentang waktu dan `index=` adalah pemilihan file itu, dan keduanya filter termurah yang kamu punya. Batas analoginya ada di mesin: di shell semua tahap berjalan di satu host, sedangkan di Splunk tahap awal dipecah ke banyak indexer, sehingga `sort` atau `dedup` yang dipasang di tengah pipeline memaksa seluruh event pindah ke satu mesin dan membuat setiap command sesudahnya kehilangan paralelisme. Alat ukurnya adalah Job Inspector, yang perannya seperti membaca counter interface sebelum menyimpulkan kenapa sebuah link terasa lambat. Batasnya juga sama: angka hanya menunjukkan di mana waktu habis, dan perbandingan baru sah bila dua versi search menjawab pertanyaan yang sama di rentang waktu yang sama.

**Kapan relevan:** setiap search yang akan dipasang menjadi report, alert terjadwal, atau panel dashboard, search atas sumber bervolume besar seperti resolver DNS pelanggan dan log proxy, dan setiap kali ada keluhan bahwa Splunk lambat tanpa angka pendukung.
**Kapan bukan jawaban:** penulisan search tidak menyelamatkan search yang lambat karena kualitas data, misalnya event breaking atau timestamp yang salah [S2]; itu perbaikan di sisi onboarding (Day 28) atau arsitektur (Day 43). Optimasi juga bukan alasan mengubah pertanyaan: versi "sesudah" yang mengembalikan hasil lebih sedikit karena filternya dipersempit bukan search yang lebih cepat, melainkan search yang lain.

## 1. Konsep inti

### 1.1 Dua tahap: indexer lalu search head

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

### 1.2 Saring sedini mungkin

Dari dokumentasi dan Lantern [S1][S2]:

1. Selalu sebut `index=`. Jangan `index=*`. Pisahkan data ke index yang berbeda, lalu batasi search ke index yang relevan [S1][S2].
2. Gunakan `sourcetype`, `host`, `source` (field indexed bawaan) untuk menyaring lebih awal [S1].
3. Rentang waktu sesempit mungkin. Bucket di luar rentang tidak disentuh sama sekali. Lantern menyarankan jendela pendek (maksimal 15 menit untuk penelusuran awal) lalu perluas bila perlu [S2].
4. Istilah spesifik. Kata kunci dan pasangan field=value yang unik mengurangi event yang harus dibuka. Contoh Lantern: `index=firewall status=ERROR type=cisco model=asa datacenter=newyork` jauh lebih baik daripada filter generik [S2].
5. **Indexed field dengan `::`**: `field::value` memaksa pencarian langsung di tsidx untuk indexed field [S1]. Berguna untuk indexed field kustom.
6. `TERM()` mencegah major breaker (mis. titik, koma) memecah istilah, sehingga pencarian IP/URL lebih tepat dan lebih cepat, mis. `TERM(10.1.2.3)` [S2]. Detail breaker, cek di dokumentasi segmentation.

### 1.3 Wildcard dan negasi

- Leading wildcard (`*ccept`) mahal. tsidx menyimpan term yang bisa dicari dari depan. Wildcard di depan memaksa pemindaian lexicon yang jauh lebih luas. Pengujian Hurricane Labs menunjukkan trailing wildcard (`Acc*`) hampir secepat tanpa wildcard, sementara leading wildcard bisa sekitar 4x lebih lama [S4]. Angka itu pengukuran mereka, jadi cek di lingkunganmu, tetapi arahnya konsisten dengan dokumentasi yang menyarankan menghindari wildcard [S1].
- Wildcard di tengah (`C:\*\evil.exe`) juga mahal dan bisa berperilaku tak terduga terhadap breaker.
- `NOT` dan `!=` mahal, karena Splunk harus mencari lalu membuang. Lebih murah menyebut apa yang kamu cari [S5].
- Semantik berbeda [S5]:
  - `status!=200` mengembalikan event yang punya field `status` dengan nilai selain 200.
  - `NOT status=200` mengembalikan semua event kecuali yang `status=200`, termasuk event tanpa field `status`.
  
  Salah pilih bisa membuat hasil investigasi bolong.

### 1.4 Batasi field dan pilih mode

- `fields` di awal (`| fields host user src dest action`) mengurangi data yang dipindahkan dari indexer. `fields` adalah distributable streaming [S3]. `table` adalah perintah tampilan, jadi taruh di akhir [S2].
- Mode search [S2]:
  - **Fast:** hanya field yang disebut atau indexed; field discovery mati. Paling hemat.
  - **Smart:** platform memutuskan.
  - **Verbose:** semua field dan event. Sangat boros; pakai hanya untuk troubleshooting.

### 1.5 Pilih command yang lebih murah

| Hindari / waspadai | Alternatif lebih murah | Alasan |
|---|---|---|
| `transaction` dengan ID unik | `stats ... BY id` | Day 13 [S1] |
| `join` | `stats` atas gabungan dua sumber (`(index=a ...) OR (index=b ...) \| stats values(...) BY key`), atau `lookup` | `join` memakai subsearch dengan batas hasil dan waktu |
| Subsearch yang mengembalikan banyak nilai | `lookup`, atau `tstats` dengan filter | Subsearch dibatasi `maxout`/`maxtime` di limits.conf. Default umum 10.000 hasil dan 60 detik, cek di limits.conf versi-mu. Praktisi menyarankan mencari alternatif, bukan menaikkan batas [S6] |
| `dedup` atas data besar | `stats latest(...) BY key` | `dedup` sebagian mode berjalan terpusat [S3] |
| Raw search untuk statistik berulang | `tstats` + data model terakselerasi; summary indexing | Day 25 [S1][S2] |
| Real-time search | Scheduled search dengan jendela pendek | Real-time terus memegang sumber daya, cek panduan terbaru |

### 1.6 Ukur, jangan menebak: Job Inspector

Job > Inspect Job menunjukkan [S1]:
- Durasi total dan biaya per komponen (`command.search.*`, `command.stats`, `dispatch.*`).
- scanCount (event yang dipindai) vs resultCount (hasil). Rasio scan/result yang besar menandakan filter awal yang buruk.
- Search yang benar-benar dijalankan (setelah ekspansi macro dan optimasi otomatis). Ini berguna untuk melihat bagaimana macro ES berkembang.

Cek nama komponen persis di versi-mu. Bandingkan dua versi search di rentang waktu yang sama. Itulah satu-satunya bukti yang sah bahwa optimasi berhasil.

Di tingkat platform, Monitoring Console menyediakan dashboard Search Activity dan Scheduler Activity untuk melihat search yang paling mahal dan yang terlewat [S2].

**Tanpa ES:** semua prinsip di atas berlaku di Splunk Enterprise. Di ES, efisiensi menjadi kritis karena ES menjalankan banyak search terjadwal (detection, akselerasi data model, threat intel). Panduan Lantern tentang mengelola data model di ES, yang dipakai di Day 25 bagian 2.4, menyebut ES sebagai pemroses batch yang berat. Itulah alasan detection ES ditulis dengan `tstats` + `summariesonly`.

## 2. Contoh SPL dan langkah di ES

> Keluaran berlabel ilustrasi. Data: BOTS v1 (`index=botsv1`). Cek nama field.

### 2.1 Sebelum dan sesudah: mencari download executable

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
- Rentang waktu eksplisit. Data BOTS v1 berasal dari 2016, jadi `earliest=-30d` justru akan mengembalikan nol hasil; ukur rentang persisnya dengan cara Day 01 bagian 2.5. Untuk data live, pakai rentang relatif seperti `earliest=-24h`.
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

### 2.2 NOT vs != dalam investigasi

```
index=botsv1 sourcetype=stream:http status!=200 | stats count
index=botsv1 sourcetype=stream:http NOT status=200 | stats count
```

Hasil yang diharapkan: angka kedua sama atau lebih besar dari angka pertama. Selisihnya adalah event tanpa field `status` [S5]. Pertanyaan investigasi: apakah event tanpa `status` (koneksi gagal, parsing gagal) penting untuk kasusmu?

### 2.3 Mengganti join dengan stats

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
- **Syarat:** nama field kunci sama di kedua sourcetype (`src_ip`). Bila berbeda, normalisasi dengan `eval`/`coalesce` (Day 11) atau gunakan field CIM (Day 24). Cek nama field di sourcetype `suricata` di BOTS v1.

### 2.4 Rutinitas "search baru" untuk analyst

```
1. index=<spesifik> sourcetype=<spesifik> earliest=-15m       (lihat beberapa event, mode Smart/Fast)
2. tambah istilah/field=value spesifik; hindari *awal dan NOT
3. | fields <yang dibutuhkan>
4. | eval/rex/where (streaming)
5. | stats ... BY ...   (transforming)
6. | lookup (enrichment pada hasil agregasi) | sort | table   (paling akhir)
7. perluas rentang waktu; cek Job Inspector
```

### 2.5 Di ES (generik)

- Saat membuka detection bawaan, perhatikan pola: `tstats` + `summariesonly`, filter dengan field data model, `drop_dm_object_name`, lalu macro `*_filter` di akhir untuk tuning (Day 25 bagian 2.5). Macro filter itu tempat yang tepat untuk menambah pengecualian, dan biasanya lebih murah daripada `NOT` di awal karena dijalankan atas hasil agregasi, cek pola di ES 8.x.
- Gunakan Monitoring Console (Search/Scheduler Activity) untuk menemukan detection yang lambat atau terlewat [S2].

## 3. Lab praktik

1. Jalankan pasangan search bagian 2.1 di rentang yang sama. Isi tabel: durasi, scanCount, resultCount.
2. Ulangi versi lambat hanya dengan mengganti `index=*` menjadi `index=botsv1`, lalu ukur. Lanjutkan satu perubahan per langkah (hapus `sort` awal, ganti `dedup` dengan `stats`, dan seterusnya). Catat kontribusi tiap perubahan.
3. Jalankan bagian 2.2 dan jelaskan selisihnya.
4. Jalankan bagian 2.3 kedua versi. Bandingkan hasil dan durasinya.
5. Uji mode: jalankan satu search di Verbose, Smart, dan Fast. Catat durasi dan perbedaan field yang tampil.
6. Uji leading wildcard: `index=botsv1 *ccept*` vs `index=botsv1 Accept*` di rentang sama, cek istilah yang ada di data-mu. Bandingkan dengan klaim sekitar 4x [S4].

**Hasil yang sebaiknya tersimpan:**
- Tabel perbandingan bagian 2.1 dengan angka dari Job Inspector.
- Kontribusi tiap perubahan (langkah 2) tercatat.
- Penjelasan `NOT` vs `!=` dengan angka.
- Hasil uji leading wildcard di lab-mu.

**Variasi tantangan:** ambil satu search lambat yang sering kamu pakai (versi lab, bukan dari kantor). Optimalkan dengan prinsip hari ini, lalu tulis "sebelum/sesudah" beserta angka Job Inspector. Ini bagus untuk portofolio dan interview.

## 4. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| scanCount jauh lebih besar dari resultCount | Filter terlambat atau terlalu umum | Pindahkan filter ke search awal; istilah spesifik [S1] |
| Search lambat walau hasil sedikit | Leading wildcard, `NOT`, `index=*` | Ganti dengan filter positif dan spesifik [S4][S5] |
| Durasi didominasi search head | Non-streaming terlalu awal (`sort`, `dedup`, `eventstats`) | Pindahkan ke akhir [S3] |
| Hasil `join` terpotong | Batas subsearch | Ganti dengan `stats` atas dua sumber atau `lookup` [S6] |
| Dashboard lambat | Panel menjalankan raw search berat | `tstats`/base search/summary; batasi waktu |
| Search tetap lambat walau ditulis baik | Kualitas data (line breaking, timestamp) | Laporkan ke admin; lihat Lantern [S2] |

## 5. Kesalahan umum dan jebakan

- `index=*` "supaya aman". Mahal dan membuka data yang tidak perlu [S1][S2].
- `table` atau `sort` di tengah search [S2][S3].
- Mengira `NOT` dan `!=` sama [S5]. Ini masalah hasil, bukan hanya performa.
- Menaikkan batas subsearch alih-alih mengubah pendekatan [S6].
- Verbose mode untuk pekerjaan rutin [S2].
- Optimasi tanpa pengukuran. Selalu bandingkan di Job Inspector.
- `[komunitas]` Saran di Splunk Community untuk tidak menaikkan limit subsearch dan mencari alternatif [S6] konsisten dengan dokumentasi. Nilai default batas subsearch di `limits.conf` berbeda antar versi lama dan baru, jadi cek nilainya di instance-mu (`| rest /services/configs/conf-limits/subsearch`) sebelum mengandalkan angka tertentu.

## 6. Catatan terkini

- Panduan "Write better searches" dan "Types of commands" tetap sama dari versi 9.x hingga 10.x (tersedia untuk 10.2 dan Cloud 10.5.2605) [S1][S3].
- Lantern masih menekankan `tstats` dan `TERM()`/`PREFIX()` (PREFIX sejak 8.0) sebagai teknik utama [S2].
- Halaman "Difference between != and NOT" tersedia hingga Splunk Cloud 10.5.2605 tanpa perubahan semantik [S5].

## 7. Cheat sheet

```
PRINSIP   ambil data sesedikit mungkin, saring sedini mungkin
FILTER    index= sourcetype= host= source= + earliest/latest sempit + istilah spesifik + field::value + TERM()
HINDARI   index=*  |  *leading  |  NOT / !=  (sebut yang DICARI)  |  verbose mode
URUTAN    search -> fields -> eval/rex/where -> stats -> lookup -> sort -> table
GANTI     transaction->stats BY id | join->stats atas OR-sumber / lookup | dedup->stats latest() | raw->tstats
SEMANTIK  f!=x : hanya event yang PUNYA f   |   NOT f=x : termasuk event TANPA f
UKUR      Job Inspector: durasi, scanCount vs resultCount, komponen; Monitoring Console: Search/Scheduler Activity
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** Rekanmu bilang `status!=200` dan `NOT status=200` itu dua cara menulis hal yang sama, jadi pilih saja yang paling enak dibaca. Kenapa ini keliru, dan kapan bedanya berbahaya?

<details><summary>Jawaban</summary>

Keduanya berbeda hasil, bukan hanya berbeda gaya. `status!=200` hanya mengembalikan event yang punya field `status` dengan nilai selain 200, sedangkan `NOT status=200` mengembalikan semua event kecuali yang `status=200`, termasuk event yang tidak punya field `status` sama sekali. Selisihnya adalah event tanpa field itu, yang biasanya justru menarik: koneksi yang gagal sebelum ada status, atau event yang parsing-nya gagal. Jadi ini masalah hasil investigasi yang bolong, bukan masalah performa, walaupun keduanya memang lebih mahal daripada menyebut nilai yang kamu cari. Lihat bagian 1.3 dan 2.2.

</details>

**2. Skenario keputusan.** Sebuah search dengan `join` yang menggabungkan alert IDS dan query DNS memberi hasil yang jelas terpotong dibanding dugaanmu. Langkah mana yang paling tepat?

- A. Naikkan `maxout` subsearch di `limits.conf` sampai hasilnya lengkap.
- B. Tulis ulang tanpa `join`: ambil kedua sourcetype dalam satu search dengan `OR`, beri penanda dengan `eval`, lalu `stats` per kunci.
- C. Jalankan search yang sama di Verbose mode supaya semua field dan event ikut terbaca.

<details><summary>Jawaban</summary>

B. Hasil terpotong adalah gejala batas subsearch yang dipakai `join`, dan satu pass atas dua sourcetype dengan `stats` menghilangkan batas itu sekaligus membuka peluang pra-agregasi di indexer. Syaratnya nama field kunci sama di kedua sourcetype; bila berbeda, normalisasi dulu dengan `eval` atau pakai field CIM. A hanya menggeser batas, memperberat search head, dan membuat hasilmu bergantung pada konfigurasi instance; saran praktisi dan dokumentasi sama-sama mengarahkan ke penggantian pendekatan, bukan penaikan limit. C salah sasaran: mode search mengatur field dan event yang diekstrak serta boros sumber daya, dan tidak ada hubungannya dengan batas subsearch. Lihat bagian 1.5 dan 2.3.

</details>

**3. Pertanyaan jebakan.** "Aku taruh `| table _time host user src` di awal search supaya data yang dikirim dari indexer lebih sedikit." Apa yang salah?

<details><summary>Jawaban</summary>

`table` adalah perintah tampilan dan tempatnya di akhir; yang mengurangi data berpindah dari indexer adalah `fields`, karena ia distributable streaming dan bisa dijalankan paralel di indexer. Menaruh perintah tampilan di tengah pipeline juga berisiko membuang field yang masih dibutuhkan command sesudahnya. Pola yang benar: `search` spesifik lebih dulu, lalu `fields`, lalu command streaming seperti `eval` dan `rex`, lalu `stats`, dan baru `sort` serta `table` paling akhir. Lihat bagian 1.4 dan 2.4.

</details>

**4. Jelaskan ulang.** Jelaskan ke rekan NOC yang baru memakai Splunk, dalam tiga kalimat, kenapa urutan command memengaruhi kecepatan search.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh jawaban: "Tahap awal search dikerjakan paralel di beberapa indexer: pencarian di tsidx, pengambilan event, lalu command ringan seperti `eval`, `where`, dan `fields`. Begitu kamu memakai command yang butuh melihat seluruh data atau urutan global, misalnya `sort` atau `eventstats`, semua event harus dikumpulkan ke satu search head, dan pemrosesan tidak kembali lagi ke indexer. Jadi filter dan command murah ditaruh sedini mungkin, dan command yang memaksa data berkumpul ditaruh selambat mungkin, supaya kerja berat dilakukan atas data yang sudah jauh lebih kecil."

Kesalahan yang sering muncul: menyebut urutan command sebagai soal gaya penulisan; mengira rentang waktu hanya memotong tampilan hasil padahal bucket di luar rentang tidak disentuh sama sekali; dan menyimpulkan satu versi lebih cepat tanpa membandingkan durasi, scanCount, dan resultCount di Job Inspector pada rentang yang sama. Lihat bagian 1.1, 1.2, dan 1.6.

</details>

**5. Interview question (English).** "An analyst complains that Splunk is slow. How do you approach it?"

<details><summary>Sample answer</summary>

"First I separate the search from the platform, because they need different fixes. I open the job in Job Inspector and look at three numbers: total duration, scanCount against resultCount, and which components ate the time; a scan count in the millions for a handful of results tells me the filtering is too late or too generic, while time concentrated on the search head usually means a non-streaming command like sort or dedup sits too early in the pipeline. Then I rewrite it with the cheap things first: explicit index and sourcetype, the narrowest time range that still answers the question, specific terms instead of leading wildcards and NOT, fields before the heavy work, and stats instead of join or transaction where the question allows it. I measure the before and after over the same time range and check that the result count is identical, because an optimisation that changes the answer is not an optimisation. And if a well-written search is still slow, I stop tuning SPL and check data quality and the environment: bad line breaking, wrong timestamps, or a scheduler that is simply oversubscribed, which I can see in the Monitoring Console."

What makes this answer strong: it starts by framing a diagnosis rather than listing tips, grounds each step in a number someone else can verify, insists that the two versions answer the same question, and ends by naming the case where SPL tuning is the wrong lever.

</details>

## 9. Sumber

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
