---
day: 12
title: 'foreach, lookup, makeresults: pola iterasi, enrichment, dan membuat data uji'
researched_on: 2026-10-07
versions_checked: Splunk Enterprise SPL Search Reference 10.2 (foreach, lookup, makeresults); Splunk Enterprise terbaru 10.6
---

# Day 12: foreach, lookup, dan makeresults untuk iterasi, enrichment, dan data uji

Cakupan: mengulang logika atas banyak field dengan `foreach`, memperkaya hasil dengan `lookup` (termasuk CIDR dan wildcard), dan menguji logika deteksi dengan data sintetis dari `makeresults`.

## 1. Tujuan belajar

Setelah menyelesaikan Day ini, kamu bisa:

- memakai `foreach` (mode multifield dan multivalue) dengan token `<<FIELD>>`, `<<MATCHSTR>>`, dan `<<ITEM>>` untuk menghindari `eval` yang berulang-ulang.
- memperkaya event dengan `lookup` (OUTPUT vs OUTPUTNEW, penempatan setelah `stats`), dan menjelaskan lookup definition dengan match type CIDR/WILDCARD.
- membangun dan merawat baseline "first seen" dengan `inputlookup`/`outputlookup`.
- membuat data uji dengan `makeresults` untuk menguji regex, eval, dan logika deteksi tanpa menyentuh index.

## 2. Konteks singkat

Tiga command ini mewakili tiga kebiasaan analyst yang matang:
1. **`foreach`**: menulis SPL yang ringkas dan tahan perubahan. Satu template untuk banyak field, bukan sepuluh `eval` yang hampir sama.
2. **`lookup`**: konteks. Alert "10.1.2.3 login gagal" jauh lebih berguna setelah tahu bahwa 10.1.2.3 adalah server keuangan milik tim X. Di ES, konteks ini dibangun oleh Asset & Identity framework (Day 26) dan threat intel, yang keduanya adalah lookup.
3. **`makeresults`**: menguji sebelum menjalankan. Kamu bisa memeriksa regex, ambang, atau logika `case()` pada data yang kamu tentukan sendiri.

## 3. Konsep inti

### 3.1 foreach

`foreach` menjalankan sebuah template untuk setiap elemen [S1]. Mode yang tersedia di 10.2:

| Mode | Iterasi atas | Token | Command di template |
|---|---|---|---|
| `multifield` (default) | Field yang cocok dengan pola wildcard | `<<FIELD>>`, `<<MATCHSTR>>`, `<<MATCHSEG1>>`... | Command streaming apa pun |
| `multivalue` | Elemen dalam satu field multivalue | `<<ITEM>>`, `<<ITER>>` (indeks mulai 0) | Hanya satu `eval` (boleh banyak assignment) |
| `json_array` | Elemen array JSON | `<<ITEM>>`, `<<ITER>>` | Hanya satu `eval` |
| `auto_collections` | Otomatis multivalue/JSON | idem | idem |

Aturan penting [S1]:
- Jika nama field mengandung karakter non-alfanumerik (titik, misalnya `Processes.dest`), bungkus token dengan kutip tunggal: `'<<FIELD>>'`. Ini aturan yang sama dengan `eval` (Day 11).
- Pada mode array, semua elemen harus bertipe sama (semua angka atau semua string).
- Cek mode selain `multifield` relatif baru. Cek apakah versi Splunk lab-mu mendukungnya.

Pola komunitas yang sering muncul [S5]:
- Mengubah tabel menjadi persentase: `addtotals` lalu `foreach * [eval pct_<<FIELD>>=round('<<FIELD>>'/Total*100,1)]`.
- Menjumlahkan field yang jumlahnya tidak diketahui.

`foreach` juga menimpa field tujuan bila beberapa field cocok dan template menulis ke satu field yang sama [S5]. Inisialisasi akumulator (mis. `eval score=0`) sebelum `foreach`, karena operasi dengan null menghasilkan null (Day 11).

### 3.2 lookup

Sintaks [S2]:

```
lookup [local=<bool>] [update=<bool>] <lookup-name> <lookup-field> [AS <event-field>] ...
       [OUTPUT | OUTPUTNEW <lookup-destfield> [AS <event-destfield>] ...]
```

- **`OUTPUT`**: menimpa field event yang sudah ada.
- **`OUTPUTNEW`**: hanya mengisi bila field itu belum ada di event [S2]. Pilih ini bila tidak ingin enrichment menimpa nilai asli.
- Tanpa klausa OUTPUT, semua kolom lookup (selain kolom pencocok) ditambahkan.
- Jika tidak ada yang cocok, field output tidak terisi (null). Gunakan `fillnull` atau `coalesce` bila perlu.
- **Penempatan:** taruh `lookup` setelah command transformasi (`stats`) bila memungkinkan, sehingga yang di-lookup adalah baris hasil agregasi, bukan jutaan event [S2].
- `local=true`: jalankan hanya di search head [S2].
- Hindari siklus referensi (field yang sama dipakai sebagai pencocok sekaligus output) [S2].

Lookup definition dan match type. CSV yang diunggah perlu lookup definition agar bisa memakai opsi lanjutan. Di "Advanced options" UI ada Match type, berupa daftar `<match_type>(<field>)` yang dipisah spasi, dengan nilai `WILDCARD`, `CIDR`, atau `EXACT` [S6]. Contoh: `CIDR(subnet)` memungkinkan lookup tabel subnet (`10.20.0.0/16` ke `"Jakarta DC"`) dicocokkan dengan IP tunggal. Opsi lain seperti `max_matches` dan `case_sensitive_match` diatur di definition/transforms, cek nama opsi dan default di dokumentasi lookup definition versi lab-mu.

**Command saudara:**
- `inputlookup`: membaca isi lookup sebagai hasil search (generating command).
- `outputlookup`: menulis hasil search ke lookup.
- Kombinasi keduanya membentuk pola baseline yang diperbarui (bagian 4.4).

### 3.3 makeresults

`| makeresults [count=<n>] [annotate=<bool>]` membuat hasil sementara di memori, tanpa meng-index apa pun [S3]:
- `count` default 1. Setiap hasil mendapat `_time` (waktu eksekusi).
- `annotate=true` menambahkan `host`, `source`, `sourcetype`, `splunk_server`.
- Opsi `format=csv|json` dengan `data=` membuat event dari data inline. Batasnya 29.999 karakter [S3]. Cek versi yang mulai mendukung opsi ini.
- Di lingkungan terdistribusi atau federated, hasil bisa berlipat sesuai jumlah server bila `splunk_server` tidak dibatasi [S3].

### 3.4 Enterprise vs ES

- Ketiga command adalah fitur inti Splunk Enterprise.
- **ES memakai lookup secara masif**: daftar aset dan identitas, threat intelligence, dan banyak lookup pendukung detection. Kamu umumnya tidak mengedit lookup inti ES secara langsung, tetapi lewat menu konfigurasi ES, cek nama menu di ES 8.x.
- `makeresults` sering dipakai untuk menguji detection dan adaptive response di ES tanpa menunggu kejadian nyata.

## 4. Contoh SPL dan langkah di ES

> Keluaran berlabel ilustrasi. Lookup di bawah adalah fiktif dan dibuat sendiri di lab.

### 4.1 foreach multifield: merapikan hasil tstats

Hasil `tstats` atas data model memberi field berprefiks (`Processes.dest`, `Processes.user`, ...). Selain `rename Processes.* AS *` (Day 25), `foreach` bisa melakukan transformasi per field:

```
| tstats summariesonly=true count from datamodel=Endpoint.Processes
    where Processes.process_name="powershell.exe" by Processes.dest Processes.user Processes.parent_process_name
| foreach Processes.* [eval <<MATCHSTR>>='<<FIELD>>']
| fields - Processes.*
```

- `foreach Processes.*`: iterasi setiap field yang diawali `Processes.`.
- `<<MATCHSTR>>`: bagian yang cocok dengan `*` (mis. `dest`), sehingga field baru bernama `dest`.
- `'<<FIELD>>'`: kutip tunggal wajib karena nama field mengandung titik [S1].
- `fields - Processes.*`: buang field lama.

Di sini `rename` sebenarnya lebih sederhana. Contoh ini untuk memahami token. Gunakan `foreach` bila kamu juga perlu mengubah nilai, mis. `eval <<MATCHSTR>>=lower('<<FIELD>>')`.

### 4.2 foreach untuk skor dari banyak flag

Melanjutkan Day 11 bagian 4.3: ada beberapa field flag `f_*` bernilai 0/1.

```
... | eval f_sqli=..., f_traversal=..., f_scanner_ua=..., f_long_uri=...
| eval score=0
| foreach f_* [eval score = score + '<<FIELD>>']
| where score >= 2
```

- `eval score=0`: inisialisasi. Tanpanya, `null + 1 = null`.
- Template dijalankan untuk setiap field `f_*`. Menambah flag baru (`f_xss`) tidak perlu mengubah baris skor. Itulah keuntungan `foreach`.

### 4.3 lookup: enrichment aset dan IOC

Buat lookup fiktif `lab_assets.csv`:

```
ip,asset_name,owner,criticality
192.168.250.70,we8105desk,finance,high
192.168.250.100,web01,webteam,high
192.168.250.20,dc01,itops,critical
```

dan `lab_ioc_domains.csv`:

```
domain,ioc_source,expires
evil-update.example,lab-intel,2026-12-31
```

Enrichment setelah agregasi:

```
index=botsv1 sourcetype=stream:http
| stats count dc(site) AS sites BY src_ip
| lookup lab_assets.csv ip AS src_ip OUTPUTNEW asset_name owner criticality
| fillnull value="unknown" asset_name owner criticality
| sort - count
```

- `stats` dulu, `lookup` kemudian: yang di-lookup hanya satu baris per `src_ip` [S2].
- `ip AS src_ip`: kolom `ip` di CSV dicocokkan dengan field event `src_ip`.
- `OUTPUTNEW`: tidak menimpa field yang sudah ada [S2].
- `fillnull value="unknown"`: aset tak dikenal juga merupakan temuan (shadow IT, perangkat liar).

Keluaran ilustrasi:

```
src_ip            count   sites  asset_name   owner    criticality
192.168.250.70    5120    42     we8105desk   finance  high
40.80.148.42      9123    1      unknown      unknown  unknown
```

**Lookup subnet dengan CIDR:** buat `lab_subnets.csv` (header `subnet,zone`, isi `192.168.250.0/24,corp-lan`), lalu definisikan lookup definition `lab_subnets` dengan Match type `CIDR(subnet)` [S6]:

```
... | lookup lab_subnets subnet AS src_ip OUTPUT zone
```

Perhatikan bahwa yang dipanggil adalah nama definition (`lab_subnets`), bukan nama file `.csv`, karena match type melekat pada definition. Cek perilaku ini di versi lab-mu.

### 4.4 Baseline "first seen" dengan inputlookup/outputlookup

**Tujuan:** mendeteksi proses yang belum pernah terlihat di host mana pun. Ini pola klasik deteksi "new/rare".

Inisialisasi (sekali, rentang 30 hari):

```
index=botsv1 sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1
| stats min(_time) AS firstSeen max(_time) AS lastSeen BY Image
| outputlookup lab_process_baseline.csv
```

Pembaruan terjadwal (mis. tiap jam, rentang 1 jam terakhir). Data BOTS v1 bertanggal 2016, jadi `earliest=-1h` atas `botsv1` tidak akan menghasilkan apa pun. Pola ini ditujukan untuk data live dari VM Windows lab; ganti `index=sysmon` dengan index Sysmon-mu:

```
index=sysmon sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 earliest=-1h
| stats min(_time) AS firstSeen max(_time) AS lastSeen BY Image
| inputlookup append=true lab_process_baseline.csv
| stats min(firstSeen) AS firstSeen max(lastSeen) AS lastSeen BY Image
| outputlookup lab_process_baseline.csv
```

Deteksi:

```
| inputlookup lab_process_baseline.csv
| where firstSeen >= relative_time(now(), "-1h")
| convert ctime(firstSeen)
```

- `inputlookup append=true`: tambahkan isi lookup ke hasil yang sudah ada, bukan menggantinya. Tanpa `append=true`, `inputlookup` di tengah pipeline akan membuang hasil sebelumnya.
- Stats kedua menggabungkan: `min(firstSeen)` mempertahankan pertama kali terlihat.
- **Kapan gagal:** lookup tumbuh tanpa batas (tambahkan pembersihan berdasarkan `lastSeen`); dua jadwal menulis lookup yang sama secara bersamaan; path biner yang berisi nama user atau versi membuat semuanya tampak baru. Normalisasi dengan `rex mode=sed` (Day 11).

### 4.5 makeresults: menguji logika sebelum memakai data nyata

Uji regex `-enc` dari Day 11 terhadap kasus positif dan negatif:

```
| makeresults format=csv data="CommandLine
powershell.exe -NoP -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=
powershell.exe -File C:\scripts\backup.ps1
powershell -EncodedCommand ZwBlAHQALQBkAGEAdABlAA==
powershell -ec ZwBlAHQALQBkAGEAdABlAA==
powershell -enc ZwBlAHQA"
| rex field=CommandLine "(?i)\s[-/](?:ec|e[a-z]*)\s+(?<enc_blob>[A-Za-z0-9+/=]{20,})"
| eval detected=if(isnotnull(enc_blob), "yes", "no")
| table CommandLine detected enc_blob
```

Keluaran ilustrasi yang diharapkan:

| Baris | Hasil | Alasan |
|---|---|---|
| 1 `-enc` + blob 44 karakter | yes | Kasus positif standar |
| 2 `-File` | no | Bukan parameter encoded |
| 3 `-EncodedCommand` + blob 24 karakter | yes | Nama parameter lengkap |
| 4 `-ec` + blob 24 karakter | yes | Alias `-ec`. Regex versi lama yang hanya mendaftar `e`, `en`, `enc`, dan seterusnya akan melewatkan baris ini |
| 5 `-enc` + blob 8 karakter | no | Di bawah ambang `{20,}` |

Baris 4 dan 5 adalah inti latihan ini. Baris 4 menunjukkan celah regex yang hanya bisa ketahuan kalau kamu sengaja menulis kasus uji. Baris 5 menunjukkan bahwa ambang panjang blob adalah keputusan desain: terlalu tinggi bisa melewatkan perintah pendek, terlalu rendah memicu false positive.

Membuat deret waktu sintetis untuk menguji ambang deteksi:

```
| makeresults count=10
| streamstats count AS n
| eval _time = now() - n*60, user="alice", action=if(n<=6, "failure", "success")
| stats count(eval(action="failure")) AS fails count(eval(action="success")) AS ok BY user
| where fails >= 5 AND ok >= 1
```

- `streamstats count AS n`: memberi nomor 1..10.
- `_time = now() - n*60`: satu event per menit ke belakang.
- Hasil yang diharapkan: satu baris `alice` (6 gagal, 4 sukses). Jika tidak muncul, logikanya salah, bukan datanya.

### 4.6 Di ES (generik)

- Daftar aset/identitas dan threat intel di ES adalah lookup yang dikelola framework. Kamu menambah sumbernya lewat konfigurasi ES, tidak dengan `outputlookup` ke lookup inti, cek prosedur di ES 8.x (Day 26, Day 30).
- `makeresults` sering dipakai untuk memicu uji adaptive response atau notable/finding di lingkungan lab (Day 41).

## 5. Lab praktik

1. Unggah `lab_assets.csv` (Settings > Lookups > Lookup table files), lalu buat lookup definition-nya.
2. Jalankan bagian 4.3. Bandingkan durasi bila `lookup` ditaruh sebelum `stats` (pada semua event) vs sesudah.
3. Buat `lab_subnets.csv` + definition dengan Match type `CIDR(subnet)`. Uji dengan `| makeresults | eval src_ip="192.168.250.33" | lookup lab_subnets subnet AS src_ip OUTPUT zone`. Hasil yang diharapkan: `zone=corp-lan`.
4. Jalankan bagian 4.4 inisialisasi + deteksi. Di VM Windows lab, jalankan biner jinak yang belum pernah dijalankan (mis. salin `notepad.exe` ke folder lain dengan nama baru). Jalankan pembaruan dan deteksi. Hasil yang diharapkan: biner baru muncul.
5. Jalankan bagian 4.5, lalu ubah regex/ambang sampai ketiga baris berperilaku sesuai keinginanmu. Catat perubahannya.
6. Jalankan bagian 4.2 dengan menambah satu flag baru tanpa mengubah baris skor.

**Hasil yang sebaiknya tersimpan:**
- Lookup aset dan CIDR bekerja.
- Ada angka durasi lookup sebelum vs sesudah `stats`.
- Baseline first-seen menangkap biner baru di lab.
- Regex `-enc` diuji dengan kasus positif dan negatif lewat `makeresults`.

**Variasi tantangan:** tambahkan pembersihan baseline pada bagian 4.4, yaitu buang entri dengan `lastSeen` lebih tua dari 90 hari sebelum `outputlookup`. Jelaskan risikonya: proses langka yang sah akan dianggap "baru" lagi.

## 6. Troubleshooting

| Gejala | Kemungkinan penyebab | Cara memeriksa/memperbaiki |
|---|---|---|
| `foreach` tidak menghasilkan apa-apa | Pola wildcard tidak cocok; nama field bertitik tanpa kutip tunggal | `fieldsummary`/`table *` untuk melihat nama field; `'<<FIELD>>'` [S1] |
| Skor `foreach` selalu null | Akumulator tidak diinisialisasi | `eval score=0` sebelum `foreach` |
| `lookup` tidak cocok | Beda huruf besar/kecil, spasi, format IP | Normalisasi dengan `lower()`/`trim()`; cek opsi case sensitivity di definition |
| Lookup CIDR tidak cocok | Memanggil nama file, bukan definition; match type salah | Panggil nama definition; Match type `CIDR(subnet)` [S6] |
| Field asli tertimpa enrichment | `OUTPUT` | `OUTPUTNEW` atau `AS` ke nama lain [S2] |
| `makeresults` menghasilkan baris ganda | Dijalankan di beberapa server (distributed/federated) | `splunk_server=local` [S3] |
| `makeresults format=csv` error | Versi lama tidak mendukung; data > 29.999 karakter | Cek versi; pecah data [S3] |

## 7. Kesalahan umum dan jebakan

- Lookup sebelum agregasi pada jutaan event. Lambat tanpa manfaat [S2].
- `OUTPUT` menimpa field CIM (mis. `user`). Ini mengacaukan detection lain di search yang sama. Gunakan `OUTPUTNEW` atau alias [S2].
- Lookup baseline yang terus membesar dan tidak pernah dibersihkan, sehingga lambat dan berisi data basi.
- Menguji logika deteksi langsung di data produksi. Uji dulu dengan `makeresults`, karena hasilnya dapat diprediksi.
- Kutip tunggal di `foreach` terlupa untuk field bertitik [S1].
- `[komunitas]` Pola `addtotals` + `foreach` untuk persentase dan peringatan "foreach menimpa field tujuan" berasal dari thread Splunk Community [S5]. Perilaku itu konsisten dengan cara kerja `eval`: field tujuan yang sudah ada akan ditimpa tanpa peringatan.

## 8. Catatan terkini

- `foreach` 10.2 mendokumentasikan mode `multivalue`, `json_array`, dan `auto_collections` selain `multifield` [S1]. Ini berguna untuk log cloud JSON. Materi lama hanya mengenal mode multifield.
- `makeresults` mendukung `format=csv|json` + `data=` untuk data inline [S3]. Sebelumnya, data uji biasanya dibuat dengan `eval` + `makemv` + `mvexpand`.
- Fungsi eval `lookup()` (Day 11) memberi cara alternatif melakukan lookup CSV di dalam ekspresi, dengan hasil berupa objek JSON [S4].

## 9. Cheat sheet

```
foreach <wildcard> [eval <<MATCHSTR>>='<<FIELD>>']          multifield (default); token: <<FIELD>> <<MATCHSTR>> <<MATCHSEG1>>
foreach mode=multivalue <mvfield> [eval x=... <<ITEM>> ...]  hanya 1 eval; <<ITEM>> <<ITER>>
  * '<<FIELD>>' bila nama ada titik/spasi * inisialisasi akumulator

lookup <def|csv> <lkfield> AS <evfield> OUTPUT|OUTPUTNEW <cols>   OUTPUT=timpa, OUTPUTNEW=isi bila kosong
  * taruh SETELAH stats * match type di definition: CIDR(f) WILDCARD(f) EXACT(f) -> panggil nama definition
inputlookup <x> [append=true] | outputlookup <x>                   baseline first-seen

| makeresults [count=N] [annotate=t] [format=csv|json data="..."]  uji regex/logika; splunk_server=local
| makeresults count=10 | streamstats count AS n | eval _time=now()-n*60
```

## 10. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | SPL Search Reference: foreach (10.2) | https://help.splunk.com/en/splunk-enterprise/spl-search-reference/10.2/search-commands/foreach | primer | diakses 2026-10-07 | Tinggi. Mode, token, batasan |
| S2 | SPL Search Reference: lookup (10.2) | https://help.splunk.com/en/splunk-enterprise/spl-search-reference/10.2/search-commands/lookup | primer | diakses 2026-10-07 | Tinggi. OUTPUT/OUTPUTNEW, penempatan, local |
| S3 | SPL Search Reference: makeresults (10.2) | https://help.splunk.com/en/splunk-enterprise/spl-search-reference/10.2/search-commands/makeresults | primer | diakses 2026-10-07 | Tinggi. count, annotate, format/data, batas 29.999 |
| S4 | SPL Search Reference: Evaluation functions (10.2) | https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.2/evaluation-functions | primer | diakses 2026-10-07 | Tinggi. Fungsi `lookup()` |
| S5 | Splunk Community: foreach/addtotals persentase, "sum an unknown number of fields"; blog pixelchef "Splunk foreach command examples" | https://community.splunk.com/t5/Splunk-Search/Convert-a-table-to-a-percent-table/m-p/220394 | komunitas | tanggal tidak tercatat | Rendah-sedang |
| S6 | Splunk Community: "need help with UI based lookup wildcard/CIDR" | https://community.splunk.com:443/t5/Splunk-Search/need-help-with-UI-based-lookup-wildcard-CIDR/m-p/464538/highlight/true | komunitas | tanggal tidak tercatat | Sedang. Konsisten dengan fitur CIDR di S2 |

**Catatan sumber:** versi Splunk yang pertama kali memperkenalkan mode `foreach` baru (`multivalue`, `json_array`, `auto_collections`) dan `makeresults format=` belum dikonfirmasi. Bila lab-mu memakai versi 9.x lama, uji dulu apakah sintaks itu diterima.
