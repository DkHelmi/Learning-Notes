---
day: 02
title: 'SPL inti untuk triage: pipeline, search dan where, stats, dan command penyaji hasil'
researched_on: 2026-10-14
versions_checked: 'Splunk Enterprise 10.6 SPL Search Reference (search, where, stats, sort, top, rare, dedup, head, fields, table, rename, fillnull, Multivalue stats and chart functions, Comparison and Conditional functions; semua halaman diperbarui 2026-09-09); Splunk Enterprise 10.6 Search Tutorial "Use fields to search" (diperbarui 2026-08-25); Splunk Enterprise Security 8.7.0; CIM 6.4'
---

# Day 02: SPL inti untuk triage (pipeline, search dan where, stats, dan command penyaji hasil)

Cakupan: sepuluh command yang dipakai hampir setiap hari saat triage, apa yang masing-masing buang tanpa memberi tahu, dan cara menyusunnya menjadi satu tabel yang bisa diserahkan ke orang lain.

## Ide inti

SPL adalah pipeline: setiap command menerima hasil command sebelumnya, mengubahnya, lalu meneruskannya. Yang membuat analyst baru salah bukan jumlah command, tetapi apa yang hilang di setiap pipe. `stats` membuang event mentah dan hanya menyisakan kolom yang kamu minta. `top` hanya memberi sepuluh baris teratas dan membuang sisanya tanpa pesan apa pun. `sort` tanpa angka hanya mengurutkan sepuluh ribu hasil pertama. `dedup` menyimpan kejadian pertama menurut urutan hasil, bukan yang paling relevan. `table` memutus semua kolom yang tidak kamu sebut, termasuk kolom yang dibutuhkan command setelahnya. Triage yang bisa dipertanggungjawabkan berarti tahu angka yang kamu tulis di tiket berasal dari hasil penuh, bukan dari sebagian hasil yang kebetulan tampil.

Kamu sudah menulis pipeline seperti ini di shell. `grep` menyaring baris, `awk` menyaring dengan kondisi pada kolom, `sort | uniq -c` mengubah baris menjadi hitungan, `head` memotong, dan `cut` memilih kolom yang masuk laporan. Padanannya di SPL hampir satu lawan satu: `search` seperti `grep`, `where` seperti kondisi `awk`, `stats` seperti `sort | uniq -c` dengan agregasi per kolom, `head` tetap `head`, dan `fields` serta `table` seperti `cut`. Dua perbedaan yang perlu disadari. Pertama, setelah `stats` kamu tidak bisa lagi kembali ke isi baris aslinya di pipeline yang sama. Kedua, beberapa command punya batas bawaan yang tidak ada di shell, dan batas itu diam-diam memotong hasil.

Situasi yang dipakai sepanjang Day ini: pukul 06.40 di PT Jaringan Anak Bangsa (PT JAB), dua puluh menit sebelum handover shift pagi. SOC lead menulis di channel SOC:

> "Sebelum handover saya mau tiga hal dari shift malam ini, pukul 22.00 sampai 06.00. Satu, berapa host internal yang kena blok firewall dan siapa lima teratas. Dua, apakah ada host yang request ke domain yang belum pernah muncul seminggu ini, dan berapa banyak. Tiga, untuk tiket SOC-2026-0231 (andi.pratama mengunduh file executable lewat proxy) saya mau tabel kronologinya. Kirim satu tabel yang bisa saya baca, bukan tujuh screenshot, dan tulis angkanya apa adanya; kalau ada yang dipotong, bilang."

Pesan itu memuat enam pertanyaan:

1. Bagaimana satu search berubah dari daftar event menjadi tabel jawaban, dan apa yang hilang di jalan?
2. Menyaring dengan `search` atau dengan `where`, dan kenapa dua filter yang terlihat sama bisa memberi hasil berbeda?
3. Angka mana dihitung dengan apa: `count`, `dc`, `values`, atau `earliest`/`latest`?
4. Kolom apa yang dibawa ke tabel akhir, dengan nama apa, dan kapan kolom itu boleh dibuang?
5. "Lima teratas" dibuat dengan `top`, atau dengan `stats` lalu `sort` lalu `head`, dan apa bedanya?
6. Bagaimana menandai baris yang layak diperiksa dan mengisi sel yang kosong tanpa memalsukan data?

Pertanyaan 1 dijawab di bagian 1.1, pertanyaan 2 di bagian 1.2, pertanyaan 3 di bagian 1.3, pertanyaan 4 di bagian 1.4, pertanyaan 5 di bagian 1.5, dan pertanyaan 6 di bagian 1.6 dan 1.7. Bagian 1.8 menyusunnya menjadi urutan baku, dan bagian 2 mengerjakan ketiga permintaan SOC lead.

**Kapan relevan:** triage alert harian, menjawab pertanyaan "berapa banyak, siapa saja, sejak kapan" dari SOC lead atau NOC, menyiapkan rekap handover, dan menyusun kronologi untuk tiket.
**Kapan bukan jawaban:** saat field yang kamu butuhkan belum ada dan harus diekstrak dulu dari `_raw` (Day 11), saat pertanyaannya tentang satu sesi utuh yang terdiri dari banyak event (Day 13), saat hasilnya perlu grafik atau deret waktu (Day 08), dan saat search-nya terlalu mahal untuk dijalankan rutin sehingga perlu dibaca dari ringkasan (Day 25).

## 1. Konsep inti

### 1.0 Istilah di Day ini

Istilah dasar dari Day 01 (index, sourcetype, source, host, `_time`, `_indextime`, time modifier, search mode) tidak diulang. Tabel ini memuat istilah yang menjelaskan perilaku command di Day ini; kolom padanan memakai pekerjaan NOC dan shell Linux yang sudah kamu kenal.

| Istilah | Arti singkat | Padanan di SOC / NOC |
|---|---|---|
| Pipeline | Rangkaian command yang dipisahkan tanda pipe, dijalankan berurutan | `grep \| sort \| uniq -c` di shell |
| Result set | Isi yang mengalir di antara dua command: bisa event, bisa baris tabel | Keluaran sementara antar perintah di shell |
| Streaming command | Command yang mengolah satu hasil pada satu waktu dan bisa dijalankan di indexer | Filter yang bisa dijalankan di perangkat, bukan di pusat |
| Transforming command | Command yang mengubah event menjadi tabel statistik | Langkah yang mengubah log menjadi rekap |
| Aggregate function | Fungsi `stats` yang meringkas banyak nilai menjadi satu, misalnya `count`, `dc` | Kolom total di laporan trafik |
| BY clause (split-by) | Daftar field yang memecah hasil `stats` menjadi satu baris per nilai | "Per interface", "per pelanggan" di laporan NOC |
| Eval expression | Ekspresi logika atau hitungan yang dipakai `eval` dan `where` | Kondisi di `awk`, formula di spreadsheet |
| Hitung bersyarat | `count(eval(<kondisi>))`: menghitung hanya hasil yang memenuhi kondisi | Kolom "jumlah gagal" di samping kolom "jumlah total" |
| Multivalue | Satu field yang berisi lebih dari satu nilai dalam satu hasil | Satu kolom berisi dua nomor dalam satu baris CDR |
| Field null vs field tidak ada | Field yang ada tetapi kosong, dibandingkan field yang tidak pernah muncul di hasil | Kolom kosong di CSV, dibandingkan kolom yang tidak ada di header |
| Leksikografis | Urutan menurut karakter, bukan menurut besar angka | Urutan nama file di `ls`, di mana `10` datang sebelum `9` |
| Batas bawaan (limit) | Jumlah hasil maksimum yang dikembalikan sebuah command bila tidak disebut | `head` tersembunyi di akhir perintah |
| `top` dan `rare` | Command yang langsung memberi nilai terbanyak dan paling jarang beserta persentasenya | Laporan top talker dan interface paling jarang dipakai |
| `dedup` | Command yang menyisakan satu hasil per kombinasi nilai field | Mengambil satu baris per perangkat dari log yang berulang |
| `fillnull` | Command yang mengganti nilai kosong dengan nilai yang kamu tentukan | Mengisi sel kosong di rekap harian dengan 0 |
| `fields` dan `table` | Command yang memilih kolom; `fields` streaming, `table` menyajikan tabel | Memilih kolom yang masuk laporan |
| `rename` | Command yang mengganti nama kolom hasil | Mengganti header kolom di laporan sebelum dikirim |

### 1.1 Pipeline: apa yang mengalir, dan apa yang hilang

Permintaan pertama SOC lead ("berapa host internal yang kena blok") tidak bisa dijawab dengan daftar event. Ia harus melewati satu command yang mengubah event menjadi angka, dan di situlah sesuatu hilang.

Command `search` tersirat di awal setiap pipeline, jadi search paling sederhana hanyalah filter [S1]. Selama hasil yang mengalir masih berupa event, kamu masih punya `_raw`, `_time`, dan semua field hasil ekstraksi. Begitu hasil melewati command transforming seperti `stats`, yang mengalir adalah baris tabel: hanya kolom yang kamu minta yang ada, dan `_raw` tidak ikut.

Perbedaan jenis command ini juga menentukan di mana pekerjaannya dilakukan. `fields` adalah distributable streaming command, artinya bisa dijalankan di indexer satu hasil per satu hasil [S9]. `table` adalah transforming command dan non-streaming, sehingga hasilnya dikumpulkan dulu; dokumentasinya menyarankan menaruh `table` di akhir search, bukan di tengah [S10]. `dedup` berubah sifat begitu kamu memakai `sortby`: ia menjadi command yang mengumpulkan seluruh hasil sebelum mengurutkannya [S8].

Tiga akibat praktis yang perlu dibiasakan:

1. Saring dulu, ringkas kemudian. Filter yang ditulis sebelum command transforming mengurangi jumlah data yang harus diolah. Alasan teknisnya dan cara mengukurnya ada di Day 14 bagian 1.2.
2. Ambil semua yang kamu butuhkan sebelum meringkas. Kolom yang tidak kamu sebut di `stats` tidak bisa dipanggil lagi setelahnya; kalau butuh, bawa lewat `values()` atau tambahkan ke BY clause.
3. Taruh penyajian di akhir. `rename` dan `table` adalah langkah kosmetik; kalau dipasang di tengah, command setelahnya bisa kehilangan kolom yang dibutuhkannya.

### 1.2 `search` dan `where`: dua cara menyaring yang tidak setara

Pertanyaan kedua muncul setiap hari: dua filter yang terlihat sama memberi jumlah berbeda. Penyebabnya hampir selalu beda perilaku dua command ini.

`search` menyaring dengan kata kunci dan pasangan field-nilai. `where` menyaring dengan eval expression. Dokumentasi `where` menyebut beberapa beda yang menentukan [S2]:

- `where` bisa membandingkan dua field, misalnya `where ipaddress=clientip`; `search` tidak bisa.
- Eval expression di `where` peka huruf besar-kecil.
- `where` dan `eval` memperlakukan string dalam tanda kutip sebagai nilai literal, dan string tanpa kutip sebagai nama field. Jadi `where host="www2"` membandingkan nilai, sedangkan `where host=www2` membandingkan field `host` dengan field bernama `www2`.
- Urutan evaluasi boolean berbeda: `where` mengevaluasi `NOT`, lalu `AND`, lalu `OR`, lalu `XOR`, sedangkan `search` mengevaluasi `OR` sebelum `AND` dan tidak mendukung `XOR`.
- Wildcard di `where` hanya lewat fungsi `like`, dengan `%` sebagai wildcard: `where like(url, "%.exe")`.

Dari sisi `search` [S1]: operator `IN` dipakai untuk mencocokkan satu field dengan beberapa nilai, dan di command `search` nilainya boleh memakai wildcard, misalnya `status IN (4*, 5*)`. Nilai di command `search` dicocokkan tanpa membedakan huruf besar-kecil, kecuali kamu memakai directive `CASE()`. Nama field tetap peka huruf besar-kecil [S15].

Di `eval` dan `where`, padanan `IN` adalah fungsi `in()`, dan di sini ada dua aturan yang sering dilupakan [S14]:

- `in()` tidak menerima wildcard pada daftar nilainya. Bila butuh pola, pakai operator `IN` di command `search`.
- `eval` tidak bisa menerima nilai boolean secara langsung, jadi `in()` harus dibungkus fungsi yang menerima boolean: `case`, `if`, atau `validate`. Command `where` menerimanya langsung, misalnya `where in(status, "400", "401")`.

Tabel berikut memetakan kebutuhan penyaringan ke command yang tepat. Cari kolom paling kanan bila kamu pernah terjebak salah satu perilakunya.

| Yang ingin kamu lakukan | Tulis seperti ini | Jebakan yang perlu diingat |
|---|---|---|
| Saring kata kunci di awal pipeline | `index=proxy "andi.pratama"` | Paling murah; nilai tidak peka huruf besar-kecil [S1] |
| Saring satu field dengan beberapa nilai | `search user IN (andi.pratama, rina.wulandari)` | Boleh wildcard di command `search` [S1] |
| Saring dengan daftar nilai di tengah ekspresi eval | `where in(user, "andi.pratama", "rina.wulandari")` | Tidak boleh wildcard; di `eval` wajib dibungkus `if`, `case`, atau `validate` [S14] |
| Bandingkan dua field | `where src=dest` | Tidak bisa dengan `search` [S2] |
| Bandingkan hasil hitungan | `where percobaan >= 100` | Harus `where`, karena `search` tidak mengevaluasi ekspresi |
| Cari pola di dalam nilai | `where like(url, "%.exe")` atau `search url=*.exe` | Wildcard di `where` hanya lewat `like` dengan `%` [S2] |
| Buang event yang tidak punya sebuah field | `search NOT user=*` | `user!=*` tidak pernah mengembalikan apa pun [S1] |
| Buang nilai tertentu tetapi tetap mengambil event tanpa field itu | `search NOT action=allowed` | `action!=allowed` hanya mengambil event yang punya `action` dengan nilai lain [S1] |
| Cocokkan huruf besar-kecil persis | `search CASE(Error)` atau `where user="Andi"` | Eval expression memang peka huruf [S1][S2] |

### 1.3 `stats`: dari event menjadi angka yang bisa ditulis di tiket

Semua angka yang diminta SOC lead keluar dari satu command ini, jadi kenali fungsi dan batasnya.

`stats` butuh minimal satu fungsi statistik, dan BY clause bersifat opsional [S3]. Fungsi yang dipakai hampir setiap hari saat triage:

| Fungsi | Isinya | Catatan penting |
|---|---|---|
| `count` | Jumlah hasil | Bisa membungkus eval expression: `count(eval(action="blocked"))` [S3] |
| `dc(<field>)` atau `distinct_count(<field>)` | Jumlah nilai unik | Butuh memori jauh lebih besar daripada `count`; untuk perkiraan ada `estdc()` [S3] |
| `values(<field>)` | Daftar nilai distinct sebagai multivalue | Urutannya leksikografis: angka sebelum huruf, huruf besar sebelum huruf kecil. Tanpa batas bawaan, tetapi ada setelan `maxvalues` di `limits.conf` [S4] |
| `list(<field>)` | Daftar nilai mengikuti urutan event | Hanya 100 nilai pertama yang dikembalikan bila lebih dari 100 [S4] |
| `earliest(<field>)` dan `latest(<field>)` | Nilai field pada event paling awal dan paling akhir | Untuk hasil yang urut waktu, dokumentasi menyarankan ini, bukan `first()` dan `last()` [S3] |
| `min`, `max`, `avg`, `sum` | Nilai terkecil, terbesar, rata-rata, total | Pakai `allnum=true` bila ingin fungsi numerik hanya dihitung saat semua nilainya angka [S3] |

Beberapa perilaku yang perlu diingat sebelum menulis angka ke tiket [S3]:

- BY clause tidak menerima wildcard (`BY source*` tidak valid), hanya boleh satu BY clause, dan setiap field disebut terpisah.
- Fungsi waktu seperti `earliest()` dan `latest()` tetap mengembalikan hasil bila `_time` atau `_origtime` tidak ada, dan hasilnya bisa salah. Ada setelan `check_for_invalid_time` di `limits.conf` untuk menekan hasil semacam itu; di Splunk Cloud perubahannya diminta ke Splunk Support.
- `values()` dan `list()` bisa memakan banyak memori, begitu juga `dc` dengan split-by berkardinalitas tinggi.
- Pemisah nilai multivalue pada `values()` dan `list()` diatur `delim`, bawaannya satu spasi.
- `dedup_splitvals` (bawaan false) membuang nilai duplikat pada BY field yang multivalue. Ini berguna pada log Windows klasik yang memuat dua akun dalam satu event (Day 03).

Satu pola yang akan kamu pakai terus-menerus adalah hitung bersyarat: `count(eval(<kondisi>))`. Dengan itu, satu `stats` bisa menghasilkan beberapa kolom untuk kondisi berbeda tanpa menjalankan dua search. Contohnya ada di bagian 2.5.

### 1.4 Memilih dan menamai kolom: `fields`, `table`, `rename`

Permintaan "kirim satu tabel yang bisa saya baca" ditentukan tiga command ini, dan masing-masing punya jebakan sendiri.

`fields` memilih atau membuang kolom [S9]:

- `fields + <daftar>` hanya menyimpan field yang disebut; `fields - <daftar>` membuang field yang disebut. Tanpa tanda, perilakunya sama dengan `+`.
- Internal field `_raw` dan `_time` ikut ada di hasil secara bawaan di Splunk Web, dan `fields` tidak membuangnya kecuali kamu menyebutnya eksplisit. `fields - _*` membuang semua internal field, `fields - _raw` hanya membuang `_raw`.
- Dokumentasi memperingatkan agar hati-hati membuang `_time`, karena command seperti `timechart` dan `chart` tidak bisa menampilkan informasi tanggal atau waktu tanpa field itu.
- `fields` adalah distributable streaming command, jadi aman dipakai di tengah pipeline. Dampaknya terhadap biaya search dibahas di Day 14 bagian 1.4.

`table` mirip `fields` dalam hal memilih kolom, tetapi hasilnya berbentuk tabel [S10]:

- `table` adalah transforming command dan non-streaming; padanan streaming-nya adalah `fields`.
- `table` tidak bisa mengganti nama field. Bila kamu ingin mengganti nama, lakukan sebelum hasil dialirkan ke `table`.
- Wildcard didukung, misalnya `table value*` untuk semua field berawalan `value`.
- Dokumentasi menyarankan menaruhnya di akhir search, bukan di tengah.

`rename` mengganti nama kolom [S11]:

- Nama yang memuat spasi harus diberi tanda kutip: `rename count AS "Jumlah blok"`.
- Wildcard boleh, tetapi jumlah wildcard di kedua sisi harus sama; `rename EU* AS EMEA*` valid, jumlah yang tidak sama menghasilkan error. Karakter bintang di dalam nama field tidak bisa di-escape.
- Bila nama tujuan sudah ada, data di field tujuan itu hilang, tertimpa nilai dari field asal. Pada event yang tidak punya field asal, field tujuan terisi null.
- Satu field tidak bisa diberi dua nama, dan `rename` tidak menggabungkan dua field menjadi satu.

Kebiasaan yang aman: urutkan dan saring dulu dengan nama field aslinya, baru `rename` di akhir, lalu `table`. Dengan begitu kamu tidak perlu menulis nama berspasi di `sort` atau `where`.

### 1.5 Mengurangi baris: `sort`, `head`, `dedup`, `top`, dan `rare`

Permintaan "lima teratas" terlihat sepele, tetapi tiap command punya batas bawaan yang berbeda, dan batas itulah yang membuat angka di tiket bisa salah.

`sort` [S5]:

- Sintaksnya `sort [<count>] <sort-by-clause> [desc]`. Bila `count` tidak disebut, batas bawaannya 10000 hasil.
- `sort 0` mengembalikan semua hasil, dengan catatan bisa berdampak buruk pada kinerja tergantung jumlah hasilnya.
- Tanda minus mengurutkan menurun, tanda plus menaik. Kata kunci `desc` membalik urutan hasil.
- Jenis pengurutan dideteksi otomatis: field numerik diurutkan sebagai angka, field berisi IP sebagai IP, sisanya leksikografis. Bisa dipaksa dengan `num()`, `str()`, `ip()`, atau `auto()`.

`head` [S13]:

- Tanpa opsi atau batas, `head` mengembalikan 10 hasil pertama. `limit=<int>` adalah cara lain menyebut jumlahnya, dan memakai keduanya sekaligus menghasilkan error.
- Dengan eval expression, `head` mengembalikan semua hasil awal sampai hasil pertama yang ekspresinya bernilai false. `keeplast` (bawaan false) menentukan apakah hasil yang false itu ikut disimpan, dan `null` (bawaan false) menentukan perlakuan hasil null; keduanya hanya berpengaruh bila ada eval expression.

`dedup` [S8]:

- Tanpa angka, hanya kejadian pertama yang disimpan untuk setiap kombinasi nilai field. Pada search historis, event terbaru diproses lebih dulu, sehingga "pertama" biasanya berarti yang paling baru.
- `sortby` menentukan hasil mana yang bertahan, dan tandanya wajib ditulis untuk setiap field.
- `keepevents` (bawaan false) menyimpan semua event tetapi membuang field terpilih setelah kemunculan pertama. `keepempty` (bawaan false) menentukan apakah event yang salah satu field terpilihnya null tetap disimpan; bila butuh, jalankan `fillnull` lebih dulu.
- `consecutive=true` hanya membuang duplikat yang berurutan.
- Dokumentasi memperingatkan agar tidak memakai `dedup` pada `_raw` untuk volume data besar, karena menahan teks event di memori mahal. Hal yang sama berlaku untuk field besar berkardinalitas tinggi.
- Pada field multivalue, semua nilainya harus sama agar dianggap duplikat.

`top` dan `rare` [S6][S7]:

| Opsi | `top` | `rare` |
|---|---|---|
| Jumlah bawaan | 10 | 10 |
| Semua nilai | `limit=0` | `limit=0`, sampai batas `maxresultrows` |
| Nama kolom hitungan | `countfield`, bawaan `count` | sama |
| Nama kolom persentase | `percentfield`, bawaan `percent` | sama |
| Menyembunyikan kolom | `showcount=false`, `showperc=false` | sama |
| Baris sisa | `useother=true` menambah satu baris untuk nilai yang terbuang limit; labelnya `otherstr`, bawaan `OTHER` | tidak terdokumentasi di halaman `rare` |
| Batas maksimum | 50000 hasil, diatur `maxresultrows` di stanza `[top]` `limits.conf` | nilai di atas `maxresultrows` menghasilkan error; stanza `[rare]` |

Kesimpulan praktis untuk "lima teratas": `top limit=5 src` cepat dan langsung memberi persentase, tetapi diam-diam membuang sisanya. Bila angka yang kamu tulis harus jujur, pakai `top limit=5 src useother=true`, atau hitung penuh dengan `stats` lalu potong dengan `head` dan sebutkan totalnya. Perbandingannya ada di bagian 2.4.

### 1.6 `eval` untuk triage: menandai, menormalkan, menggolongkan

Permintaan keenam SOC lead, menandai baris yang layak diperiksa, dikerjakan `eval`. Day ini memakai lima fungsi saja; fungsi lain dan pembuatan skor dibahas di Day 11 bagian 1.3.

| Fungsi | Bentuk | Dipakai untuk |
|---|---|---|
| `if` | `if(<kondisi>, <nilai_true>, <nilai_false>)` [S14] | Dua kemungkinan: dalam atau di luar jam kerja, terdaftar atau tidak |
| `case` | `case(<kondisi1>, <nilai1>, <kondisi2>, <nilai2>, ...)` [S14] | Tingkatan: normal, pantau, periksa. Mengembalikan nilai pertama yang kondisinya benar, dan NULL bila tidak ada yang benar |
| `true()` | `case(..., true(), "lainnya")` [S14] | Nilai bawaan di akhir `case`, supaya tidak ada baris bernilai NULL |
| `in()` | `if(in(action, "blocked", "denied"), "blok", "lolos")` [S14] | Mencocokkan satu field dengan beberapa nilai; tanpa wildcard, dan di `eval` harus dibungkus `if`, `case`, atau `validate` |
| `lower()` | `eval user_norm=lower(user)` | Menyatukan `Andi.Pratama` dan `andi.pratama` sebelum `stats` atau `dedup`, karena eval expression peka huruf besar-kecil [S2] |

Dua fungsi pendamping yang sering dibutuhkan: `coalesce()` mengembalikan nilai pertama yang bukan NULL dari beberapa field, berguna saat dua sourcetype memakai nama field berbeda [S14]; `match()` mengembalikan TRUE bila regex menemukan kecocokan di sebuah string [S14].

Urutan yang penting: `eval` dijalankan pada hasil yang sedang mengalir. Bila kamu ingin menormalkan nilai sebelum diagregasi, `eval` harus berada sebelum `stats`. Bila kamu ingin menggolongkan hasil hitungan, `eval` harus berada sesudah `stats`.

### 1.7 Lubang di data: `fillnull`, dan beda null dengan field yang tidak ada

Rekap yang dikirim ke SOC lead akan punya sel kosong, dan sel kosong punya dua arti berbeda yang tidak boleh dicampur.

`fillnull` mengganti nilai null [S12]:

- Sintaksnya `fillnull [value=<string>] [<field-list>]`, dan keduanya opsional. Nilai pengganti bawaannya `0`.
- Bila daftar field tidak disebut, nilai itu diterapkan ke semua field. Di tabel hasil `stats` yang lebar, ini sering bukan yang kamu inginkan; sebut field-nya.
- Splunk tidak bisa membedakan nilai field yang null dari field yang memang tidak ada di kumpulan hasil. Sebuah field dianggap tidak ada bila tidak punya satu pun nilai bukan-null di kumpulan hasil itu, dan field semacam itu tidak bisa diproses command setelahnya.
- Contoh di dokumentasi memakai `fillnull` setelah `timechart` untuk mengisi lubang di grafik.

Konsekuensi untuk cara menulis rekap:

1. `fillnull value=0` mengubah "tidak ada data" menjadi "nol kejadian". Dua hal itu berbeda, dan untuk pertanyaan keamanan bedanya besar: tidak ada data bisa berarti forwarder mati. Untuk kolom hitungan, 0 biasanya benar; untuk kolom konteks seperti pemilik aset, lebih jujur mengisi teks seperti `tidak terdaftar`.
2. Bila sebuah field tidak pernah terisi di seluruh hasil, `fillnull` tidak akan membuatnya muncul. Gejala ini sudah dibahas di Day 01: buktikan dulu field itu ada dengan `stats` atau `fieldsummary`.
3. `dedup` membuang event yang field terpilihnya null kecuali `keepempty=true`; bila baris itu penting, jalankan `fillnull` sebelum `dedup` [S8].

### 1.8 Urutan baku yang dipakai saat triage

Semua bagian di atas selalu tersusun dalam urutan yang sama. Hafalkan urutannya, bukan command-nya.

```
1 saring      index, sourcetype, host, rentang waktu, kata kunci   (search)
2 saring lagi kondisi yang butuh ekspresi                          (where)
3 normalkan   lower(), coalesce(), penggolongan awal                (eval)
4 ringkas     count, dc, values, earliest/latest, BY                (stats)
5 golongkan   case() atas hasil hitungan                            (eval)
6 isi lubang  nilai kosong pada kolom hitungan dan kolom konteks    (fillnull)
7 urutkan     menurut kolom yang paling menentukan keputusan        (sort)
8 potong      ambil sebanyak yang memang dilaporkan                 (head)
9 sajikan     ganti nama kolom, pilih kolom akhir                   (rename, table)
```

Langkah 1 dan 2 menentukan kebenaran, langkah 4 menentukan angka, dan langkah 7 sampai 9 hanya penyajian. Bila hasilnya mencurigakan, periksa dari langkah 1, bukan dari langkah 9.

**Tanpa ES:** semua command di Day ini adalah SPL Splunk Enterprise biasa dan berjalan di app Search & Reporting tanpa Enterprise Security. Di ES, SPL yang sama dipakai di balik detection dan di panel investigasi, hanya saja datanya sering dibaca dari data model CIM dan ditulis sebagai finding, bukan sebagai tabel yang kamu baca sendiri (Day 23, Day 36). Di PT JAB, L1 masih mengerjakan rekap seperti bagian 2 di Search & Reporting, karena ES baru dipasang dan Asset & Identity-nya belum lengkap.

## 2. Contoh SPL dan langkah praktis

Semua keluaran di bagian ini adalah keluaran ilustrasi, bukan hasil eksekusi. Asumsi PT JAB: Splunk Enterprise 10.6, app Search & Reporting tanpa ES, index `firewall` dan `proxy`, zona waktu akun WIB. Rentang shift malam ditulis sebagai `earliest=-1d@d+22h latest=@d+6h`, yaitu pukul 22.00 kemarin sampai pukul 06.00 hari ini; cara membaca modifier ini ada di Day 01.

### 2.1 Satu pertanyaan, dua bentuk hasil

Mulai dari permintaan pertama SOC lead, supaya jelas apa yang berubah saat event menjadi tabel.

**Tujuan:** melihat blok firewall shift malam, pertama sebagai event, lalu sebagai angka.

Versi event:

```
index=firewall earliest=-1d@d+22h latest=@d+6h action=blocked
```

Versi angka:

```
index=firewall earliest=-1d@d+22h latest=@d+6h action=blocked
| stats count AS percobaan dc(src) AS host_internal dc(dest) AS tujuan_unik
```

- Versi pertama tidak memakai command apa pun selain `search` yang tersirat [S1]. Hasilnya event, lengkap dengan `_raw` dan daftar field di sidebar.
- Versi kedua melewati satu command transforming. Hasilnya satu baris, dan `_raw` tidak ada lagi di pipeline.
- `dc(src)` menjawab "berapa host internal", bukan `count`, yang menjawab "berapa percobaan".

Keluaran ilustrasi untuk versi kedua:

```
percobaan  host_internal  tujuan_unik
18442      37             2914
```

**Cara membaca hasil:** tiga angka ini yang ditulis di handover, dan ketiganya menjawab pertanyaan berbeda. 18.442 percobaan dari 37 host bukan hal yang sama dengan 18.442 percobaan dari 1 host. Kalimat yang dikirim ke SOC lead: "37 host internal kena blok, total 18.442 percobaan ke 2.914 tujuan berbeda."
**Variasi:** tambahkan `BY action` dan hapus filter `action=blocked` untuk melihat proporsi blok terhadap seluruh trafik yang tercatat.
**Kapan gagal:** `dc` di field berkardinalitas tinggi seperti `dest` mahal dari sisi memori; untuk pemakaian rutin ada `estdc()` yang memberi perkiraan [S3]. Nama field `action`, `src`, dan `dest` berasal dari normalisasi add-on; bila kosong, cek nama field asli vendor dulu (Day 01 bagian 2.6).

### 2.2 Dua filter yang terlihat sama, tiga hasil berbeda

Sebelum menyusun rekap, pastikan filter-mu menyaring seperti yang kamu bayangkan.

**Tujuan:** memperlihatkan perilaku `search`, `where`, dan negasi pada data yang sama.

```
index=proxy earliest=-1d@d+22h latest=@d+6h
| stats count AS total
        count(eval(searchmatch("user=andi.pratama"))) AS lewat_searchmatch
        count(eval(lower(user)="andi.pratama")) AS lewat_eval_lower
        count(eval(user="andi.pratama")) AS lewat_eval_persis
```

| Bagian | Penjelasan |
|---|---|
| `searchmatch(...)` | Mengembalikan TRUE bila event cocok dengan string search; di `eval` harus berada di dalam `if` atau fungsi sejenis, dan di sini dibungkus `count(eval(...))` [S14] |
| `lower(user)="andi.pratama"` | Menyamakan huruf dulu, karena eval expression peka huruf besar-kecil [S2] |
| `user="andi.pratama"` | Perbandingan persis, termasuk huruf besar-kecil |

Keluaran ilustrasi:

```
total   lewat_searchmatch  lewat_eval_lower  lewat_eval_persis
204118  1284               1284              1192
```

**Cara membaca hasil:** 92 event memakai ejaan huruf berbeda, misalnya `Andi.Pratama` dari satu agent proxy. Filter yang dibuat dengan `where user="andi.pratama"` akan melewatkan 92 event itu, sedangkan filter `search user=andi.pratama` tidak, karena nilai di command `search` tidak peka huruf besar-kecil [S1]. Untuk tiket SOC-2026-0231, selisih ini bisa berarti kronologi yang bolong.

Tiga perbandingan lain yang perlu diuji sekali supaya tidak lupa:

```
index=proxy earliest=-1d@d+22h latest=@d+6h
| stats count(eval(isnull(user))) AS tanpa_field_user
        count(eval(in(action, "blocked", "denied"))) AS diblokir
        count(eval(match(url, "\.(exe|dll|ps1)$"))) AS unduhan_biner
```

- `search NOT user=*` mengembalikan event yang `user`-nya null atau tidak ada, sedangkan `user!=*` tidak pernah mengembalikan apa pun [S1]. Di dalam `eval`, padanannya `isnull(user)`.
- `in()` tidak menerima wildcard; bila kamu butuh pola seperti `blok*`, pakai operator `IN` di command `search` [S1][S14].
- `match()` memakai regex, sehingga titik perlu di-escape. Regex yang lebih serius dibahas di Day 11.

**Kapan gagal:** `searchmatch` bekerja pada event, jadi tidak bisa dipakai setelah command transforming. `lower()` tidak membantu bila dua sourcetype memakai nama field berbeda; untuk itu pakai `coalesce()` [S14].

### 2.3 Rekap blok firewall per host internal

Ini isi utama permintaan pertama, dalam bentuk yang bisa dibaca orang.

**Tujuan:** satu baris per host internal, dengan jumlah, sebaran tujuan, port yang dicoba, dan jam pertama serta terakhir.

```
index=firewall earliest=-1d@d+22h latest=@d+6h action=blocked
| stats count AS blok dc(dest) AS tujuan_unik dc(dest_port) AS port_unik
        values(dest_port) AS port earliest(_time) AS mulai latest(_time) AS selesai
        BY src
| eval mulai=strftime(mulai, "%H:%M:%S"), selesai=strftime(selesai, "%H:%M:%S")
| sort - blok
```

| Bagian | Penjelasan |
|---|---|
| `values(dest_port) AS port` | Daftar port distinct, terurut leksikografis sehingga `1433` muncul sebelum `22` [S4] |
| `earliest(_time)` dan `latest(_time)` | Waktu event paling awal dan paling akhir untuk host itu; dokumentasi menyarankan fungsi ini, bukan `first()` dan `last()`, untuk hasil yang urut waktu [S3] |
| `BY src` | Satu baris per host internal; BY clause tidak menerima wildcard [S3] |
| `sort - blok` | Menurun. Tanpa angka, `sort` mengurutkan sampai batas bawaan 10000 hasil [S5] |

Keluaran ilustrasi (dipotong lima baris teratas):

```
src           blok   tujuan_unik  port_unik  port                      mulai     selesai
10.10.24.51   9820   2611         3          1433 3389 445             22:04:11  05:58:49
10.10.31.14   3140   1            1          443                       23:12:02  05:59:51
10.20.11.9    1877   412          2          22 23                     22:00:58  05:40:23
10.10.24.77   902    38           1          8080                      01:12:44  01:48:10
10.30.14.22   410    7            1          3389                      02:31:09  03:04:52
```

**Cara membaca hasil:** baris pertama adalah pola pemindaian internal, karena 9.820 percobaan menyebar ke 2.611 tujuan pada port 445, 1433, dan 3389. Baris kedua kebalikannya: 3.140 percobaan ke satu tujuan di port 443, lebih mirip aplikasi yang salah konfigurasi atau retry tanpa henti. Baris ketiga menyentuh port 22 dan 23 dari segmen data center, yang untuk ISP perlu dicocokkan dengan pekerjaan NOC. Jadi kolom yang menentukan bukan `blok`, melainkan perbandingan `blok` dengan `tujuan_unik`.
**Variasi:** tambahkan `| eval per_tujuan=round(blok/tujuan_unik, 1)` lalu `sort - per_tujuan` untuk memisahkan "banyak ke satu tujuan" dari "sedikit ke banyak tujuan".
**Kapan gagal:** host dengan IP dinamis membuat satu perangkat muncul sebagai beberapa baris. Bila port yang dicoba sangat banyak, `values(dest_port)` menghasilkan sel yang panjang dan memakan memori; batasi dengan `dc` saja, atau atur `maxvalues` [S3][S4].

### 2.4 "Lima teratas": `top` atau `stats` lalu `head`

Permintaannya "siapa lima teratas", dan di sini pilihan command menentukan apakah angkamu jujur.

**Tujuan:** memperlihatkan dua cara, beserta apa yang hilang di masing-masing.

Versi `top`:

```
index=firewall earliest=-1d@d+22h latest=@d+6h action=blocked
| top limit=5 src useother=true
```

Versi `stats`:

```
index=firewall earliest=-1d@d+22h latest=@d+6h action=blocked
| stats count AS blok BY src
| eventstats sum(blok) AS blok_semua dc(src) AS host_semua
| eval persen=round(blok/blok_semua*100, 2)
| sort - blok
| head 5
```

- `top` memberi kolom `count` dan `percent` secara bawaan, dan bawaan jumlah barisnya 10; `limit=5` memotongnya menjadi lima [S6].
- `useother=true` menambahkan satu baris berlabel `OTHER` untuk nilai yang terbuang oleh limit, sehingga totalnya tetap terlihat; labelnya bisa diganti dengan `otherstr` [S6].
- Versi `stats` menghitung semua host dulu, lalu memotong tampilannya. `eventstats` menambahkan total dan jumlah host sebagai kolom di setiap baris, sehingga persentasenya bisa dihitung sendiri dan konteksnya tidak hilang.

Keluaran ilustrasi versi `top` dengan `useother=true`:

```
src           count  percent
10.10.24.51   9820   53.25
10.10.31.14   3140   17.02
10.20.11.9    1877   10.17
10.10.24.77   902    4.89
10.30.14.22   410    2.22
OTHER         2293   12.43
```

**Cara membaca hasil:** lima host teratas menyumbang sekitar 87,55% blok, dan 32 host sisanya 12,43%. Tanpa `useother=true`, baris `OTHER` tidak ada dan pembaca tabel akan menyangka lima baris itu seluruh kejadian. Inilah yang dimaksud SOC lead dengan "kalau ada yang dipotong, bilang".
**Variasi:** `rare limit=5 src` untuk sisi sebaliknya, yaitu host yang hanya kena blok sekali atau dua kali. Bawaan jumlahnya juga 10 [S7].
**Kapan gagal:** `top` mengembalikan maksimum 50.000 hasil, diatur `maxresultrows` di stanza `[top]` [S6]. Pada `rare`, nilai di atas `maxresultrows` menghasilkan error, dan opsi `useother` tidak terdokumentasi di halaman command-nya, jadi jangan mengandalkannya di sana tanpa mengujinya [S7]. Persentase dari `top` dihitung terhadap hasil yang masuk ke command itu, bukan terhadap seluruh trafik; bila kamu sudah menyaring `action=blocked`, persentasenya adalah persentase terhadap blok, bukan terhadap semua koneksi.

### 2.5 Domain yang belum pernah muncul minggu ini

Permintaan kedua SOC lead. Polanya hitung bersyarat: satu search, dua periode, dua kolom.

**Tujuan:** menemukan domain yang hanya muncul di shift malam ini dan tidak muncul dalam tujuh hari sebelumnya.

```
index=proxy earliest=-7d@d+22h latest=@d+6h
| eval periode=if(_time >= relative_time(now(), "-1d@d+22h"), "malam_ini", "baseline")
| stats count(eval(periode="baseline")) AS n_baseline
        count(eval(periode="malam_ini")) AS n_malam
        dc(src) AS host values(src) AS daftar_host
        latest(user) AS user_terakhir BY dest_host
| where n_malam >= 5 AND n_baseline = 0
| sort - n_malam
| head 20
```

| Bagian | Penjelasan |
|---|---|
| `relative_time(now(), "-1d@d+22h")` | Batas awal shift malam sebagai epoch, memakai modifier yang sama dengan rentang search |
| `count(eval(periode="..."))` | Hitung bersyarat; `count` adalah satu-satunya fungsi `stats` yang bisa membungkus eval expression semacam ini [S3] |
| `where n_malam >= 5 AND n_baseline = 0` | Harus `where`, karena membandingkan hasil hitungan [S2] |
| `values(src) AS daftar_host` | Aman di sini karena baris yang lolos filter hanya punya trafik malam ini, jadi daftar host tidak tercampur baseline |
| `head 20` | Batas eksplisit supaya tabel handover tetap terbaca; totalnya tetap bisa dilaporkan dari `stats count` terpisah |

Keluaran ilustrasi:

```
dest_host                    n_baseline  n_malam  host  daftar_host     user_terakhir
unduhan-cepat.example.net    0           312      1     10.10.24.51     andi.pratama
cdn-paket3.example           0           41       2     10.10.24.51 ...  andi.pratama
api-sinkron.test             0           9        4     10.10.11.4 ...   rina.wulandari
```

**Cara membaca hasil:** baris pertama adalah domain yang sama sekali baru dengan 312 request dari satu host, dan host itu adalah 10.10.24.51 yang juga memimpin tabel blok firewall di bagian 2.3. Dua baris lain berjumlah kecil dan menyentuh beberapa host, lebih mirip layanan baru yang sah. Kesimpulan untuk handover: satu baris layak diperiksa, dua baris cukup dicatat.
**Variasi:** ganti `BY dest_host` dengan `BY src` untuk membalik pertanyaan menjadi "host mana yang paling banyak mengunjungi domain baru". Untuk pola yang lebih dalam, termasuk long tail dan outlier, lihat Day 39.
**Kapan gagal:** domain CDN yang namanya berisi angka acak akan selalu terlihat baru, sehingga tabel ini penuh derau; buang domain yang sudah dikenal lewat lookup (Day 12). Baseline tujuh hari juga tidak cukup bila sumber datanya sempat terputus; cek dulu kelengkapan data di periode baseline (Day 01 bagian 2.1).

### 2.6 Kronologi tiket SOC-2026-0231

Permintaan ketiga. Di sini hasilnya tetap berupa event, bukan agregasi, karena yang diminta adalah urutan kejadian.

**Tujuan:** tabel kronologi aktivitas proxy satu akun pada rentang waktu tiket, dengan kolom yang siap ditempel.

```
index=proxy earliest="10/13/2026:22:00:00" latest="10/14/2026:06:00:00"
    user IN (andi.pratama, Andi.Pratama)
| fields _time src user dest_host url status bytes_out action http_user_agent
| eval waktu=strftime(_time, "%Y-%m-%d %H:%M:%S"),
       ukuran_mb=round(bytes_out/1024/1024, 2),
       jenis=case(match(url, "\.(exe|msi|dll)$"), "biner",
                  match(url, "\.(zip|rar|7z)$"), "arsip",
                  true(), "lain")
| sort waktu
| rename waktu AS "Waktu", src AS "Host", dest_host AS "Domain", url AS "URL",
         status AS "Status", ukuran_mb AS "MB", action AS "Aksi", jenis AS "Jenis"
| table "Waktu" "Host" "Domain" "URL" "Status" "MB" "Aksi" "Jenis"
```

- Rentang absolut dipakai supaya hasilnya bisa diulang siapa pun yang membuka tiket (Day 01 bagian 1.5).
- `user IN (andi.pratama, Andi.Pratama)` ditulis di command `search`, yang nilainya tidak peka huruf besar-kecil; dua ejaan ditulis eksplisit hanya sebagai pengingat atas temuan di bagian 2.2 [S1].
- `fields` dipasang lebih awal untuk membawa kolom yang diperlukan saja, dan karena ia streaming command, aman di tengah pipeline [S9]. `_time` sengaja dibawa karena masih dibutuhkan `sort` dan `strftime`.
- `rename` dilakukan sebelum `table`, sesuai anjuran dokumentasi [S10][S11]. Nama berspasi diberi tanda kutip [S11].
- `table` ditaruh paling akhir karena ia transforming dan non-streaming [S10].

Keluaran ilustrasi:

```
Waktu                Host          Domain                     URL                            Status  MB     Aksi     Jenis
2026-10-14 01:12:44  10.10.24.51   unduhan-cepat.example.net  /files/pembaruan-klien.exe     200     42.18  allowed  biner
2026-10-14 01:13:02  10.10.24.51   unduhan-cepat.example.net  /files/konfig.zip              200     0.31   allowed  arsip
2026-10-14 01:48:10  10.10.24.51   cdn-paket3.example         /p/3f9a1c/payload              403     0.00   blocked  lain
```

**Cara membaca hasil:** satu unduhan executable 42,18 MB yang diizinkan proxy, diikuti arsip kecil, lalu satu permintaan yang diblokir ke domain lain. Tiga baris ini yang masuk ke tiket SOC-2026-0231, dengan catatan bahwa kolom MB adalah `bytes_out` dari sisi proxy, bukan ukuran file sebenarnya. Langkah berikutnya bukan lagi pekerjaan Day ini: apa yang dijalankan host itu setelah unduhan selesai dijawab dari log endpoint (Day 03 dan Day 04), dan keputusan disposisinya mengikuti alur triage L1 (Day 07).
**Variasi:** untuk kronologi lintas index, jalankan pola yang sama di `firewall` dan `proxy` lalu gabungkan dengan `append`, atau rangkai per sesi dengan `transaction` bila memang satu sesi utuh (Day 13 bagian 1.3).
**Kapan gagal:** tanda pipe di dalam nilai field, misalnya di user agent, akan merusak tabel saat kamu menempelkannya ke dokumen; escape dengan `\|` bila harus ditulis di sel tabel markdown. Bila `bytes_out` kosong untuk sebagian sourcetype, kolom MB akan kosong juga, dan `fillnull value=0` di kolom itu akan membuat unduhan besar terlihat seperti nol byte; biarkan kosong, atau beri label.

### 2.7 Satu tabel untuk handover

Langkah terakhir menggabungkan hasil bagian 2.3 dan penggolongan, lalu menyiapkannya untuk dikirim.

**Tujuan:** satu tabel handover yang memuat host, jumlah blok, tingkat perhatian, dan konteks pemilik aset.

```
index=firewall earliest=-1d@d+22h latest=@d+6h action=blocked
| stats count AS blok dc(dest) AS tujuan_unik values(dest_port) AS port BY src
| eval per_tujuan=round(blok/tujuan_unik, 1)
| eval tingkat=case(tujuan_unik >= 500, "periksa: pola pemindaian",
                    blok >= 1000, "periksa: volume tinggi",
                    blok >= 100, "pantau",
                    true(), "normal")
| lookup aset_jab.csv ip AS src OUTPUT pemilik lokasi
| fillnull value="tidak terdaftar" pemilik lokasi
| sort - blok
| head 10
| rename src AS "Host", blok AS "Blok", tujuan_unik AS "Tujuan unik",
         per_tujuan AS "Blok per tujuan", port AS "Port", tingkat AS "Tingkat",
         pemilik AS "Pemilik", lokasi AS "Lokasi"
| table "Host" "Blok" "Tujuan unik" "Blok per tujuan" "Port" "Tingkat" "Pemilik" "Lokasi"
```

- `case` dengan `true()` di akhir memastikan setiap baris punya label; tanpa itu, baris yang tidak memenuhi kondisi apa pun bernilai NULL [S14].
- Urutan kondisi di `case` menentukan hasilnya, karena nilai pertama yang kondisinya benar yang dipakai [S14]. Pola pemindaian diletakkan paling atas supaya host dengan banyak tujuan tidak sekadar dilabeli "volume tinggi".
- `lookup` menempelkan konteks dari tabel aset; cara membuat dan merawat lookup dibahas di Day 12.
- `fillnull value="tidak terdaftar" pemilik lokasi` hanya menyentuh dua kolom itu. Tanpa daftar field, nilai itu diterapkan ke semua field [S12], termasuk kolom hitungan, yang akan membuat tabel menyesatkan.
- `sort` dan `head` dijalankan sebelum `rename` supaya tidak perlu menulis nama berspasi di dua command itu.

Keluaran ilustrasi (dipotong tiga baris):

```
Host          Blok   Tujuan unik  Blok per tujuan  Port             Tingkat                     Pemilik          Lokasi
10.10.24.51   9820   2611         3.8              1433 3389 445    periksa: pola pemindaian    andi.pratama     Jakarta lt.4
10.10.31.14   3140   1            3140.0           443              periksa: volume tinggi      svc_billing      Data center
10.20.11.9    1877   412          4.6              22 23            pantau                      tidak terdaftar  tidak terdaftar
```

**Cara membaca hasil:** tiga baris pertama membutuhkan tiga tindakan berbeda, dan itulah gunanya kolom Tingkat. Baris pertama diserahkan ke L2 bersama temuan domain baru dari bagian 2.5 karena host-nya sama. Baris kedua milik service billing dan lebih mirip salah konfigurasi, jadi cukup tiket perbaikan ke pemilik aplikasi. Baris ketiga tidak terdaftar di tabel aset, dan "tidak terdaftar" di sini adalah temuan tersendiri: aset POP memang belum masuk inventaris, dan itu perlu dicatat sebagai celah konteks, bukan diabaikan.

**Isi yang dikirim ke SOC lead:** tabel di atas, tiga angka dari bagian 2.1, baris domain baru dari bagian 2.5, kronologi tiket SOC-2026-0231 dari bagian 2.6, dan satu kalimat jujur tentang pemotongan: "tabel menampilkan 10 dari 37 host; sisanya di bawah 100 blok per host."

## 3. Lab praktik (di VM lab terisolasi)

Lab ini tidak butuh dataset besar. Tujuh dari sembilan langkah memakai data sintetis yang kamu buat sendiri, supaya batas bawaan setiap command bisa kamu buktikan, bukan kamu percayai. Command `makeresults` dipakai sebagai pembuat data; pemakaian lanjutannya ada di Day 12.

1. **Batas bawaan `sort`.** Buat 15.000 baris sintetis dengan nilai acak, lalu jalankan `| sort - nilai | stats count` dan bandingkan dengan `| sort 0 - nilai | stats count`. Catat selisihnya dan kaitkan dengan batas bawaan 10000.
2. **Batas bawaan `top` dan `rare`.** Pada data yang punya 30 nilai berbeda, jalankan `| top src`, `| top limit=5 src`, `| top limit=5 src useother=true`, dan `| top limit=0 src`. Catat jumlah baris dan jumlah `count` di setiap versi, lalu buktikan bahwa jumlah `count` versi tanpa `useother` lebih kecil daripada total sebenarnya.
3. **`dedup` menyimpan yang mana.** Buat 10 baris dengan dua nilai `user` dan `_time` yang berbeda-beda. Jalankan `| dedup user`, lalu `| dedup user sortby + _time`, lalu `| dedup user sortby - _time`. Catat baris mana yang bertahan di tiap versi.
4. **`dedup` dan nilai null.** Tambahkan satu baris yang `user`-nya null, lalu bandingkan `| dedup user` dengan `| dedup user keepempty=true` dan dengan `| fillnull value="kosong" user | dedup user`.
5. **`values()` dan `list()`.** Buat satu grup dengan 120 nilai berulang dan tidak berurutan. Bandingkan `values(nilai)` dan `list(nilai)`: periksa urutannya dan hitung jumlah nilai yang keluar dari `list()`. Pastikan kamu melihat batas 100 nilai itu sendiri.
6. **`search` vs `where`.** Pada data lab yang punya nilai dengan huruf besar-kecil campuran, bandingkan hasil `search user=andi`, `where user="andi"`, dan `where lower(user)="andi"`. Lalu uji `search status IN (4*, 5*)` dan `where in(status, "4*", "5*")`. Catat mana yang jalan dan mana yang tidak, serta pesan errornya.
7. **`NOT` vs `!=`.** Pada data yang sebagian barisnya tidak punya field `user`, bandingkan jumlah hasil `search NOT user=*`, `search user!=*`, `search NOT user=andi`, dan `search user!=andi`. Tulis satu kalimat kesimpulan untuk masing-masing.
8. **`fields` dan `table`.** Jalankan satu search event, lalu coba `| fields - _time | timechart count` dan catat errornya. Ulangi dengan `_time` dipertahankan. Lalu buktikan `table` tidak bisa mengganti nama field, dan bahwa `rename` setelah `table` masih bekerja pada nama kolom yang ada.
9. **Rekap penuh.** Susun ulang rekap bagian 2.7 untuk data lab-mu dengan urutan sembilan langkah di bagian 1.8, lalu hapus satu langkah (misalnya `fillnull`) dan catat bagaimana tabelnya berubah.

**Hasil yang sebaiknya tersimpan:**

- Tabel batas bawaan yang kamu buktikan sendiri: `sort` 10000, `top` 10, `rare` 10, `head` 10, `list()` 100.
- Catatan baris mana yang bertahan untuk tiga variasi `dedup`.
- Perbandingan urutan `values()` (leksikografis) dan `list()` (urutan event).
- Tabel hasil enam variasi filter di langkah 6 dan 7, dengan jumlah hasilnya.
- Pesan error dari `where in()` dengan wildcard dan dari `timechart` tanpa `_time`.
- Satu search rekap siap pakai yang bisa kamu tempel di handover shift mana pun.

**Variasi tantangan:** ambil satu search rekap milik rekanmu yang memakai `top` tanpa `useother`, hitung berapa banyak kejadian yang hilang dari laporannya, lalu tulis versi perbaikannya beserta satu paragraf penjelasan kenapa angka lamanya menyesatkan. Setelah itu ukur biaya kedua versi di Job Inspector dan putuskan versi mana yang dipakai untuk rekap harian (Day 14).

## 4. Troubleshooting

Tabel ini untuk saat hasil search tidak seperti yang kamu harapkan. Mulai dari kolom gejala, dan perhatikan bahwa sebagian besar baris berakar pada batas bawaan atau pada beda `search` dan `where`.

| Gejala | Kemungkinan penyebab | Cara memeriksa atau memperbaiki |
|---|---|---|
| Jumlah di tabel lebih kecil daripada total yang kamu tahu | `top` atau `rare` memotong di 10 baris, atau `head` memotong | Tambahkan `useother=true`, naikkan `limit`, atau hitung penuh dengan `stats` [S6][S7] |
| Urutan hasil aneh setelah 10.000 baris | `sort` tanpa angka berhenti di batas bawaan 10000 | Pakai `sort 0`, dengan catatan kinerja [S5] |
| `where` tidak menemukan apa pun padahal nilainya ada | Eval expression peka huruf besar-kecil | Normalkan dengan `lower()`, atau saring dengan command `search` [S1][S2] |
| `where in(field, "abc*")` tidak cocok | `in()` tidak menerima wildcard | Pakai operator `IN` di command `search`, atau `match()` [S1][S14] |
| `eval` dengan `in()` menghasilkan error | `eval` tidak menerima boolean langsung | Bungkus dengan `if`, `case`, atau `validate` [S14] |
| `where host=www2` memberi hasil kosong | String tanpa kutip dianggap nama field | Tulis `where host="www2"` [S2] |
| Event tanpa field tertentu ikut terbuang | `!=` menuntut field-nya ada | Pakai `NOT field=nilai` [S1] |
| `field!=*` tidak pernah memberi hasil | Perilaku yang terdokumentasi | Pakai `NOT field=*` untuk mencari event tanpa field itu [S1] |
| Kolom hilang di tengah pipeline | `table` atau `fields +` membuang kolom yang dibutuhkan command setelahnya | Pindahkan `table` ke akhir search [S10] |
| `timechart` atau `chart` mengeluh soal waktu | `_time` terbuang oleh `fields -` | Pertahankan `_time` sampai setelah command charting [S9] |
| Nama kolom hasil `rename` menimpa data | Nama tujuan sudah ada | Ganti nama tujuan; data di field tujuan lama hilang saat ditimpa [S11] |
| `rename` dengan wildcard error | Jumlah wildcard di dua sisi tidak sama | Samakan jumlah wildcard [S11] |
| Semua kolom tiba-tiba berisi 0 | `fillnull` tanpa daftar field | Sebut field yang ingin diisi [S12] |
| Sebuah field tidak bisa diisi `fillnull` | Field tidak punya satu pun nilai bukan-null di hasil, jadi dianggap tidak ada | Buktikan field itu ada dulu dengan `stats` atau `fieldsummary` [S12] |
| Jumlah akun unik terlihat dua kali lipat | BY field berisi nilai multivalue | Pakai `dedup_splitvals=true`, atau pilih satu nilai lebih dulu [S3] |
| `earliest()` memberi waktu yang tidak masuk akal | `_time` atau `_origtime` tidak ada di hasil | Pastikan `_time` masih ada; ada setelan `check_for_invalid_time` di `limits.conf` [S3] |
| Search berjalan lambat setelah `dedup` | `dedup` pada `_raw` atau field besar, atau `sortby` mengumpulkan semua hasil | Dedup pada field kecil saja, atau pakai `stats` [S8] |
| `list()` kehilangan nilai | Hanya 100 nilai pertama yang dikembalikan | Pakai `values()` bila yang kamu butuhkan nilai distinct [S4] |

## 5. Kesalahan umum dan jebakan

- Menulis angka dari tabel yang dipotong tanpa menyebut pemotongannya. `top` tanpa `useother` dan `head` tanpa keterangan membuat laporan terlihat lengkap padahal tidak [S6].
- Memakai `count` untuk pertanyaan "berapa host". Yang menjawab itu `dc`, dan keduanya sering berbeda jauh [S3].
- Memakai `sort` tanpa angka lalu menyimpulkan tidak ada nilai di luar hasil yang terlihat. Batas bawaannya 10000 [S5].
- Mengira `dedup` menyimpan kejadian yang paling relevan. Yang disimpan adalah kejadian pertama menurut urutan hasil, kecuali kamu memakai `sortby` [S8].
- Memakai `dedup` sebagai pengganti `stats` untuk menghitung. `dedup` membuang event, sehingga angka setelahnya bukan lagi jumlah kejadian.
- Membandingkan nilai dengan `where` tanpa menormalkan huruf. Eval expression peka huruf besar-kecil [S2].
- Memakai wildcard di dalam `in()`. Fungsi itu tidak menerimanya; operator `IN` di command `search` menerimanya [S1][S14].
- Menulis `where field=nilai` tanpa kutip untuk nilai literal. Tanpa kutip, `nilai` diperlakukan sebagai nama field [S2].
- Memakai `!=` untuk membuang sesuatu dari hasil. Event yang tidak punya field itu ikut terbuang, dan `field!=*` tidak pernah mengembalikan apa pun [S1].
- Menaruh `table` di tengah pipeline. Command setelahnya kehilangan kolom yang dibuang, dan `table` memang dianjurkan di akhir [S10].
- Membuang `_time` terlalu dini. Command charting tidak bisa bekerja tanpanya [S9].
- Menjalankan `fillnull` tanpa daftar field pada tabel hasil `stats`. Semua kolom terisi, termasuk kolom konteks yang seharusnya tetap kosong [S12].
- Mengubah "tidak ada data" menjadi "nol" tanpa catatan. Untuk pertanyaan keamanan, dua hal itu berbeda; nol kejadian dan sumber log mati terlihat sama di tabel.
- Mengandalkan `list()` untuk daftar nilai yang panjang. Hanya 100 nilai pertama yang keluar [S4].
- Mengurutkan kolom yang sudah di-`rename` menjadi nama berspasi. Urutkan dulu, ganti nama di akhir.
- `[komunitas, belum terkonfirmasi]` Banyak praktisi menyarankan selalu mengganti `dedup` dengan `stats` di search terjadwal karena dianggap lebih murah dan lebih dapat diprediksi. Dokumentasi memang memperingatkan biaya `dedup` pada field besar dan pada pemakaian `sortby` [S8], tetapi klaim bahwa `stats` selalu lebih murah untuk semua kasus tidak dikonfirmasi halaman resmi yang dibuka untuk Day ini; ukur sendiri kedua versi di Job Inspector (Day 14).

## 6. Catatan terkini

Bagian ini menampung versi dan tanggal halaman dokumentasi yang dipakai, beserta setelan yang bisa berbeda antar lingkungan. Tidak ada yang mengubah cara menulis search di atas.

- Semua halaman SPL Search Reference yang dipakai di Day ini terbit sebagai versi 10.6 dengan tanggal pembaruan 9 September 2026, sedangkan Search Tutorial terbit 25 Agustus 2026 [S1] sampai [S15].
- Beberapa batas yang disebut di Day ini berasal dari `limits.conf` dan bisa berbeda di instance-mu: `maxresultrows` di stanza `[top]` (bawaan 50000) dan `[rare]`, `maxvalues` untuk `values()`, `check_for_invalid_time` untuk fungsi waktu `stats`, serta `default_partitions` untuk argumen `partitions` (bawaan 1) [S3][S4][S6][S7]. Di Splunk Cloud, perubahan setelan semacam ini diminta ke Splunk Support [S3][S7].
- Halaman `stats` menyebut `estdc()` sebagai pengganti `dc` yang lebih murah untuk split-by berkardinalitas rendah atau tanpa split-by [S3]. Ketelitiannya berbeda dari `dc`, jadi jangan dipakai untuk angka yang ditulis di laporan audit.
- Halaman `rare` tidak mendokumentasikan `useother` dan `otherstr`, berbeda dari halaman `top` [S6][S7]. Bila kamu membutuhkan baris sisa pada `rare`, ujilah di lab atau hitung dengan `stats`.
- Halaman `top` menyebut argumen `N` dan `limit` sebagai dua cara menulis hal yang sama [S6], sedangkan `head` justru error bila angka dan `limit` dipakai bersamaan [S13]. Perbedaan kecil ini mudah terlupa saat menyalin contoh.

## 7. Cheat sheet

```
PIPELINE      search (tersirat) -> where -> eval -> stats -> eval -> fillnull
              -> sort -> head -> rename -> table
              transforming (stats, table) membuang _raw; fields streaming, table tidak

SARING        search: kata kunci + field=nilai, nilai TIDAK peka huruf, CASE() bila perlu
              search: IN (4*, 5*) boleh wildcard
              where : eval expression, PEKA huruf, bisa bandingkan dua field
              where : in(f,"a","b") tanpa wildcard | like(f,"%.exe") untuk pola
              eval  : in() harus dibungkus if()/case()/validate()
              NOT field=*  -> event TANPA field itu
              field!=*     -> selalu kosong
              field!=nilai -> hanya event yang punya field itu

STATS         count | dc (mahal; estdc perkiraan) | values (distinct, leksikografis)
              list (urutan event, HANYA 100 pertama) | earliest()/latest() untuk waktu
              count(eval(<kondisi>)) = hitung bersyarat
              BY tanpa wildcard, satu BY clause | dedup_splitvals untuk BY multivalue
              delim mengatur pemisah values/list

BATAS BAWAAN  sort tanpa angka : 10000   (sort 0 = semua, hati-hati)
              top / rare       : 10      (limit=0 = semua; top maks 50000)
              head             : 10      (limit=<int>, bukan keduanya sekaligus)
              list()           : 100 nilai
              fillnull         : value=0, dan SEMUA field bila daftar tidak disebut

KOLOM         fields + simpan | fields - buang | tanpa tanda = +
              _raw dan _time hanya terbuang bila disebut (fields - _*)
              jangan buang _time sebelum chart/timechart
              table: di AKHIR, tidak bisa rename, boleh wildcard
              rename: kutip untuk nama berspasi, jumlah wildcard harus sama,
                      nama tujuan yang sudah ada akan tertimpa

DEDUP         simpan kejadian PERTAMA menurut urutan hasil
              sortby +/- menentukan yang bertahan (mengumpulkan semua hasil dulu)
              keepempty=true untuk field null | consecutive=true hanya duplikat berurutan
              jangan dedup _raw di data besar

EVAL TRIAGE   if(k, a, b) | case(k1,v1, k2,v2, true(),"lainnya")
              lower() sebelum stats/dedup | coalesce(f1, f2) untuk nama field berbeda
              match(url, "\.(exe|dll)$") untuk pola regex
```

## 8. Uji diri

Coba jawab dulu tanpa membuka bagian di atas. Bila jawabanmu berbeda dengan kunci, baca ulang bagian yang disebut di kunci.

**1. Pertanyaan jebakan.** Rekan shift menulis di handover: "Hanya ada 10 host yang kena blok firewall malam ini," berdasarkan hasil `index=firewall action=blocked | top src`. Benarkah angkanya?

<details><summary>Jawaban</summary>

Tidak. `top` mengembalikan 10 baris secara bawaan, jadi sepuluh host itu hanyalah sepuluh teratas, bukan seluruh host. Nilai yang terbuang oleh limit tidak muncul sama sekali kecuali kamu menambahkan `useother=true`, yang menambahkan satu baris berlabel `OTHER`. Cara yang benar: `top limit=10 src useother=true`, atau hitung penuh dengan `stats dc(src)` untuk jumlah host dan `stats count BY src` untuk sebarannya. Lihat bagian 1.5 dan 2.4.

</details>

**2. Skenario keputusan.** Kamu perlu menyaring hasil `stats` agar hanya menampilkan host dengan lebih dari 100 blok dan lebih dari 50 tujuan unik. Mana yang dipakai?

- A. `| search blok>100 tujuan_unik>50`
- B. `| where blok > 100 AND tujuan_unik > 50`
- C. `| top limit=100 src` lalu dibaca manual.

<details><summary>Jawaban</summary>

B. Membandingkan hasil hitungan butuh eval expression, dan itu wilayah `where`. A tidak tepat sebagai kebiasaan: command `search` dirancang untuk kata kunci dan pasangan field-nilai, bukan untuk mengevaluasi ekspresi, dan ia juga tidak bisa membandingkan dua field satu sama lain. C bukan penyaringan, hanya pemotongan jumlah baris, dan justru memperkenalkan batas baru. Ingat juga bahwa di `where` nilai literal harus diberi tanda kutip, karena string tanpa kutip dianggap nama field. Lihat bagian 1.2 dan 2.5.

</details>

**3. Pertanyaan jebakan.** "Untuk membuang semua event yang bukan milik `andi.pratama`, pakai `user!=andi.pratama`." Apa yang salah?

<details><summary>Jawaban</summary>

`!=` menuntut field itu ada dengan nilai berbeda, sehingga semua event yang tidak punya field `user` ikut terbuang, padahal bisa jadi justru event itu yang penting. Yang setara dengan "bukan milik akun ini, termasuk yang tidak punya akun" adalah `NOT user=andi.pratama`. Jebakan yang lebih ekstrem dari keluarga yang sama: `user!=*` tidak pernah mengembalikan apa pun, sedangkan `NOT user=*` mengembalikan event yang `user`-nya null atau tidak ada. Lihat bagian 1.2 dan 2.2.

</details>

**4. Skenario keputusan.** Rekap handover punya kolom `blok` (jumlah) dan kolom `pemilik` (dari lookup aset). Sebagian baris punya `pemilik` kosong karena aset POP belum masuk inventaris. Apa yang kamu lakukan?

- A. `| fillnull value=0` di akhir search.
- B. `| fillnull value="tidak terdaftar" pemilik` dan biarkan kolom jumlah apa adanya.
- C. Buang baris yang `pemilik`-nya kosong supaya tabelnya bersih.

<details><summary>Jawaban</summary>

B. `fillnull` tanpa daftar field menerapkan nilai ke semua field, sehingga pilihan A akan mengisi kolom konteks dengan angka 0 dan membuat tabel menyesatkan. C membuang justru informasi yang berguna: aset yang tidak terdaftar adalah temuan tersendiri, yaitu celah konteks yang perlu dilaporkan, bukan baris yang perlu dirapikan. Perlu diingat juga bahwa `fillnull` tidak bisa memunculkan field yang sama sekali tidak punya nilai bukan-null di kumpulan hasil, karena field seperti itu dianggap tidak ada. Lihat bagian 1.7 dan 2.7.

</details>

**5. Jelaskan ulang.** Jelaskan kepada analyst L1 yang baru, dalam tiga kalimat, apa yang hilang saat sebuah search melewati `stats`, dan kenapa itu penting saat menyusun kronologi tiket.

<details><summary>Contoh jawaban dan kesalahan yang sering muncul</summary>

Contoh: "Begitu hasil melewati `stats`, yang mengalir bukan event lagi melainkan baris tabel, jadi `_raw` dan semua field yang tidak kamu sebut di `stats` hilang dari pipeline itu. Artinya kamu tidak bisa lagi membaca isi event aslinya atau menyaring dengan field yang tidak kamu bawa, dan yang perlu diselamatkan harus diminta lebih dulu lewat `values()`, `earliest()`, `latest()`, atau ditambahkan ke BY clause. Untuk kronologi tiket, itu sebabnya saya tidak memakai `stats`: saya butuh urutan kejadian per event, jadi saya pakai `fields`, `eval`, `sort`, lalu `table` di akhir, dan `stats` hanya saya pakai untuk angka ringkasan di bagian atas tiket."

Kesalahan yang sering muncul:
- Mengira field yang hilang bisa dipanggil lagi setelah `stats` di pipeline yang sama.
- Memakai `stats` untuk pertanyaan yang sebenarnya meminta urutan kejadian.
- Lupa bahwa `table` juga membuang kolom, sehingga command setelahnya ikut kehilangan data; karena itu `table` ditaruh di akhir.

</details>

**6. Pertanyaan jebakan.** Seorang rekan memakai `| stats list(dest_port) AS port BY src` untuk mendaftar semua port yang dicoba setiap host, lalu menyimpulkan satu host hanya mencoba 100 port. Apa yang perlu diperiksa?

<details><summary>Jawaban</summary>

`list()` hanya mengembalikan 100 nilai pertama bila sebuah field punya lebih dari 100 nilai, dan urutannya mengikuti urutan event, bukan urutan nilai. Jadi angka 100 itu kemungkinan besar batas command, bukan temuan. Untuk pertanyaan "port apa saja yang dicoba", yang tepat adalah `values(dest_port)`, yang mengembalikan nilai distinct terurut leksikografis dan tidak punya batas bawaan, meski ada setelan `maxvalues` di `limits.conf`. Untuk pertanyaan "berapa banyak port", pakai `dc(dest_port)`. Lihat bagian 1.3 dan 2.3.

</details>

**7. Interview question (English).** "Which SPL commands do you use most during triage, and what do you watch out for in each?"

<details><summary>Sample answer</summary>

"Day to day it's a small set: `search` and `where` to filter, `eval` to normalise and classify, `stats` to answer the actual question, then `sort`, `head`, `rename` and `table` to present it. What I watch for is what each one quietly drops. `search` matches field values case-insensitively while `where` is case-sensitive, so I normalise with `lower()` before I compare or aggregate, and I keep in mind that `!=` throws away events that don't have the field at all, which `NOT` doesn't. In `stats` I'm careful to use `dc` rather than `count` when the question is 'how many hosts', and to pull everything I'll need later, because once I'm past a transforming command the raw event is gone. And I never report numbers straight out of `top`, because it returns ten rows by default and silently drops the rest, so I either add `useother=true` or compute the full picture with `stats` and state plainly how much the table is showing. Same discipline with `sort`, which only sorts ten thousand results unless I pass zero, and with `fillnull`, which fills every field if I don't name the ones I mean."

What makes this answer strong: it names a small, realistic command set, pairs each command with the specific failure mode it causes in a report, and shows the habit of reporting truncation honestly instead of presenting a partial table as a complete one.

</details>

## 9. Sumber

| ID | Judul | URL | Tipe | Terbit/diakses | Keandalan dan catatan |
|---|---|---|---|---|---|
| S1 | Splunk Enterprise 10.6 SPL Search Reference: search | https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.6/search-commands/search | primer | diperbarui 2026-09-09; diakses 2026-10-14 | Tinggi. `search` tersirat, operator `IN` dengan wildcard, kutip dan escape, urutan boolean, `NOT` vs `!=`, `CASE()` |
| S2 | Splunk Enterprise 10.6 SPL Search Reference: where | https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.6/search-commands/where | primer | diperbarui 2026-09-09; diakses 2026-10-14 | Tinggi. Eval expression peka huruf, perbandingan dua field, string berkutip sebagai literal, `like()` dengan `%` |
| S3 | Splunk Enterprise 10.6 SPL Search Reference: stats | https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.6/search-commands/stats | primer | diperbarui 2026-09-09; diakses 2026-10-14 | Tinggi. Fungsi agregasi, `count(eval(...))`, `dc` dan `estdc`, `earliest`/`latest`, BY tanpa wildcard, `delim`, `allnum`, `dedup_splitvals` |
| S4 | Splunk Enterprise 10.6 SPL Search Reference: Multivalue stats and chart functions | https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.6/statistical-and-charting-functions/multivalue-stats-and-chart-functions | primer | diperbarui 2026-09-09; diakses 2026-10-14 | Tinggi. `values()` distinct dan leksikografis, `list()` mengikuti urutan event dan dibatasi 100 nilai, `maxvalues` |
| S5 | Splunk Enterprise 10.6 SPL Search Reference: sort | https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.6/search-commands/sort | primer | diperbarui 2026-09-09; diakses 2026-10-14 | Tinggi. Batas bawaan 10000, `sort 0`, tanda minus dan plus, `num()`/`str()`/`ip()`/`auto()` |
| S6 | Splunk Enterprise 10.6 SPL Search Reference: top | https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.6/search-commands/top | primer | diperbarui 2026-09-09; diakses 2026-10-14 | Tinggi. Bawaan 10, `limit=0`, `countfield`, `percentfield`, `showcount`, `showperc`, `useother`, `otherstr`, `maxresultrows` 50000 |
| S7 | Splunk Enterprise 10.6 SPL Search Reference: rare | https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.6/search-commands/rare | primer | diperbarui 2026-09-09; diakses 2026-10-14 | Tinggi untuk bawaan 10 dan `maxresultrows`. Halaman ini tidak mendokumentasikan `useother` dan `otherstr` |
| S8 | Splunk Enterprise 10.6 SPL Search Reference: dedup | https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.6/search-commands/dedup | primer | diperbarui 2026-09-09; diakses 2026-10-14 | Tinggi. Kejadian pertama, `sortby`, `keepevents`, `keepempty`, `consecutive`, peringatan `dedup` pada `_raw` |
| S9 | Splunk Enterprise 10.6 SPL Search Reference: fields | https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.6/search-commands/fields | primer | diperbarui 2026-09-09; diakses 2026-10-14 | Tinggi. `+` dan `-`, internal field hanya terbuang bila disebut, peringatan membuang `_time`, distributable streaming |
| S10 | Splunk Enterprise 10.6 SPL Search Reference: table | https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.6/search-commands/table | primer | diperbarui 2026-09-09; diakses 2026-10-14 | Tinggi. Transforming dan non-streaming, tidak bisa rename, anjuran menaruhnya di akhir, wildcard |
| S11 | Splunk Enterprise 10.6 SPL Search Reference: rename | https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.6/search-commands/rename | primer | diperbarui 2026-09-09; diakses 2026-10-14 | Tinggi. Kutip untuk nama berspasi, jumlah wildcard harus sama, nama tujuan tertimpa, tidak bisa dua nama |
| S12 | Splunk Enterprise 10.6 SPL Search Reference: fillnull | https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.6/search-commands/fillnull | primer | diperbarui 2026-09-09; diakses 2026-10-14 | Tinggi. Bawaan `0`, berlaku ke semua field bila daftar tidak disebut, aturan field yang dianggap tidak ada |
| S13 | Splunk Enterprise 10.6 SPL Search Reference: head | https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.6/search-commands/head | primer | diperbarui 2026-09-09; diakses 2026-10-14 | Tinggi. Bawaan 10, `limit`, `keeplast`, `null`, perilaku dengan eval expression |
| S14 | Splunk Enterprise 10.6 SPL Search Reference: Comparison and Conditional functions | https://help.splunk.com/en/splunk-enterprise/search/spl-search-reference/10.6/evaluation-functions/comparison-and-conditional-functions | primer | diperbarui 2026-09-09; diakses 2026-10-14 | Tinggi. `if`, `case`, `true()`, `in()` tanpa wildcard dan harus dibungkus, `coalesce`, `like`, `match`, `searchmatch` |
| S15 | Splunk Enterprise 10.6 Search Tutorial: Use fields to search | https://help.splunk.com/en/splunk-enterprise/get-started/search-tutorial/10.6/part-4-searching-the-tutorial-data/use-fields-to-search | primer | diperbarui 2026-08-25; diakses 2026-10-14 | Tinggi. Nama field peka huruf besar-kecil sedangkan nilainya tidak |

**Catatan sumber:** semua klaim perilaku command di Day ini berasal dari halaman SPL Search Reference versi 10.6 yang dibuka langsung. Yang belum terkonfirmasi sumber primer: ketersediaan `useother` dan `otherstr` pada `rare` (tidak tercantum di halaman command-nya, jadi perlu diuji di lab) dan klaim komunitas bahwa `stats` selalu lebih murah daripada `dedup` di bagian 5. Nilai bawaan yang berasal dari `limits.conf` (`maxresultrows`, `maxvalues`, `default_partitions`, `check_for_invalid_time`) bisa berbeda di instance-mu; angka yang ditulis di sini adalah bawaan menurut dokumentasi. Keluaran ilustrasi, nama field vendor (`dest_host`, `bytes_out`, `http_user_agent`), dan nama lookup `aset_jab.csv` adalah contoh untuk PT JAB; cocokkan dengan add-on dan lookup di instance-mu.
